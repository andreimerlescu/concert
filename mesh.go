package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/sema"
	"github.com/gin-gonic/gin"
)

// Tiered Edge <-> Leaf Concert Mesh (direct or via HAProxy data plane).
//
// Node roles (-role / CONCERT_ROLE):
//   - standalone (default): single-tier Concert proxy (classic behavior).
//   - edge: front-tier Concert owning browser cookies, the single FIFO waiting
//     room, x402 fast-lane, and per-user asset caps. Signs Concert-Hop-Auth on
//     every outbound request to Leaf nodes, consumes piggybacked and polled
//     Leaf capacity telemetry, performs slot-aware / sticky routing + safe
//     backpressure redispatch, and optionally auto-sizes its capacity to match
//     the sum of healthy Leaf capacities (-edge-auto-cap).
//   - leaf: origin-guard Concert sitting directly in front of one app instance.
//     Never serves browser waiting-room HTML or sets browser cookies (preventing
//     double-queuing and cookie clobbering). Verifies Concert-Hop-Auth, enforces
//     a hard local ceiling (cap + priority-cap) in front of app, returns instant
//     503 + Concert-Backpressure when full or draining, forwards Concert-Priority
//     headers from app back up to Edge untouched, piggybacks Concert-Leaf-State
//     telemetry on every response, and exposes GET /_room/mesh/state.

const (
	nodeRoleStandalone = "standalone"
	nodeRoleEdge       = "edge"
	nodeRoleLeaf       = "leaf"

	hopAuthHeader      = "Concert-Hop-Auth"
	leafStateHeader    = "Concert-Leaf-State"
	backpressureHeader = "Concert-Backpressure"
	banSignalHeader    = "Concert-Ban-Signal"

	hopAuthMaxSkew = 60 * time.Second

	ctxHopTier = "concert.hop_tier" // "normal" | "priority"
	ctxHopPass = "concert.hop_pass" // passID hex string for sticky routing
	ctxHopRank = "concert.hop_rank" // priorityRank
)

func parseNodeRole(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", nodeRoleStandalone:
		return nodeRoleStandalone, nil
	case nodeRoleEdge:
		return nodeRoleEdge, nil
	case nodeRoleLeaf:
		return nodeRoleLeaf, nil
	default:
		return "", fmt.Errorf("invalid -role %q: must be standalone, edge, or leaf", s)
	}
}

func parseStickyMode(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "none":
		return "off", nil
	case "pass":
		return "pass", nil
	case "ip":
		return "ip", nil
	default:
		return "", fmt.Errorf("invalid -upstream-sticky %q: must be off, pass, or ip", s)
	}
}

// ─── Hop-to-Hop Cryptographic Authentication (HMAC-SHA256 + Dual-Key) ────────

type hopClaims struct {
	TS    int64  `json:"t"`
	Tier  string `json:"r"`           // "normal" | "priority" | "asset" | "stream" | "mesh"
	Rank  uint8  `json:"k,omitempty"` // priorityRank
	Pass  string `json:"p,omitempty"` // passID hex (for diagnostics/stickiness)
	Proto string `json:"v,omitempty"` // original client HTTP proto
}

type hopSigner struct {
	key     []byte
	prevKey []byte
}

func deriveHopKey(secret []byte) []byte {
	if len(secret) == 0 {
		return nil
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("concert/mesh/hop-auth-key"))
	return m.Sum(nil)
}

func newHopSigner(secret, prevSecret []byte) *hopSigner {
	return &hopSigner{
		key:     deriveHopKey(secret),
		prevKey: deriveHopKey(prevSecret),
	}
}

func (s *hopSigner) sign(c hopClaims) string {
	if s == nil || len(s.key) == 0 {
		return ""
	}
	raw, _ := json.Marshal(c)
	body := base64.RawURLEncoding.EncodeToString(raw)
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:16])
	return body + "." + sig
}

func (s *hopSigner) verify(token string, now time.Time) (hopClaims, bool) {
	if s == nil || len(s.key) == 0 || token == "" {
		return hopClaims{}, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return hopClaims{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(sig) != 16 {
		return hopClaims{}, false
	}
	checkKey := func(k []byte) bool {
		if len(k) == 0 {
			return false
		}
		m := hmac.New(sha256.New, k)
		m.Write([]byte(parts[0]))
		return hmac.Equal(sig, m.Sum(nil)[:16])
	}
	if !checkKey(s.key) && !checkKey(s.prevKey) {
		return hopClaims{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return hopClaims{}, false
	}
	var c hopClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return hopClaims{}, false
	}
	skew := now.Unix() - c.TS
	if skew < 0 {
		skew = -skew
	}
	if time.Duration(skew)*time.Second > hopAuthMaxSkew {
		return hopClaims{}, false
	}
	return c, true
}

func (s *hopSigner) signBanSignal(clientIP, reason string, now time.Time) string {
	return s.sign(hopClaims{
		TS:    now.Unix(),
		Tier:  "ban",
		Pass:  clientIP,
		Proto: reason,
	})
}

func (s *hopSigner) verifyBanSignal(token string, now time.Time) (netip.Addr, string, bool) {
	c, ok := s.verify(token, now)
	if !ok || c.Tier != "ban" {
		return netip.Addr{}, "", false
	}
	ip, err := netip.ParseAddr(c.Pass)
	if err != nil {
		return netip.Addr{}, "", false
	}
	return ip.Unmap(), c.Proto, true
}

// ─── Leaf Live Capacity Telemetry ────────────────────────────────────────────

type leafStateSnapshot struct {
	NodeID          string `json:"node_id"`
	Role            string `json:"role"`
	Cap             int    `json:"cap"`
	Occupancy       int    `json:"occupancy"`
	PriorityCap     int    `json:"priority_cap"`
	PriorityOcc     int    `json:"priority_occupancy"`
	AssetCap        int    `json:"asset_cap"`
	AssetInFlight   int    `json:"asset_in_flight"`
	StreamCap       int    `json:"stream_cap"`
	StreamActive    int    `json:"stream_active"`
	Draining        bool   `json:"draining"`
	UpstreamHealthy bool   `json:"upstream_healthy"`
	Ready           bool   `json:"ready"`
	TS              int64  `json:"ts"`
}

func (st leafStateSnapshot) formatHeader() string {
	d, h := 0, 0
	if st.Draining {
		d = 1
	}
	if st.UpstreamHealthy {
		h = 1
	}
	return fmt.Sprintf("cap=%d;occ=%d;pcap=%d;pocc=%d;drain=%d;healthy=%d;ts=%d",
		st.Cap, st.Occupancy, st.PriorityCap, st.PriorityOcc, d, h, st.TS)
}

func parseLeafStateHeader(hdr string) (leafStateSnapshot, bool) {
	if hdr == "" {
		return leafStateSnapshot{}, false
	}
	var st leafStateSnapshot
	var gotCap bool
	for _, part := range strings.Split(hdr, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			continue
		}
		switch strings.TrimSpace(k) {
		case "cap":
			st.Cap = n
			gotCap = true
		case "occ":
			st.Occupancy = n
		case "pcap":
			st.PriorityCap = n
		case "pocc":
			st.PriorityOcc = n
		case "drain":
			st.Draining = n != 0
		case "healthy":
			st.UpstreamHealthy = n != 0
		case "ts":
			st.TS = int64(n)
		}
	}
	if !gotCap || st.Cap < 1 {
		return leafStateSnapshot{}, false
	}
	st.Ready = !st.Draining && st.UpstreamHealthy
	return st, true
}

func (st leafStateSnapshot) freeSlots(priority bool) int {
	if st.Draining || !st.UpstreamHealthy {
		return 0
	}
	if priority {
		if f := st.PriorityCap - st.PriorityOcc; f > 0 {
			return f
		}
		return 0
	}
	if f := st.Cap - st.Occupancy; f > 0 {
		return f
	}
	return 0
}

// ─── Leaf Mode Origin-Guard Enforcement ──────────────────────────────────────

// leafGuard runs on -role leaf nodes. It replaces browser waiting rooms with
// hard semaphore admission + instant 503 backpressure + piggybacked telemetry.
type leafGuard struct {
	a       *app
	cfg     config
	normal  sema.Semaphore
	prio    sema.Semaphore
	assets  sema.Semaphore
	streams sema.Semaphore
	nodeID  string
}

func newLeafGuard(a *app, cfg config, prev *leafGuard) (*leafGuard, error) {
	var normal, prio, assets, streams sema.Semaphore
	var err error
	if prev != nil && prev.normal.Cap() == cfg.capacity {
		normal = prev.normal
	} else if normal, err = sema.New(cfg.capacity); err != nil {
		return nil, fmt.Errorf("leaf normal semaphore: %w", err)
	}
	pCap := cfg.effectivePriorityCap()
	if prev != nil && prev.prio.Cap() == pCap {
		prio = prev.prio
	} else if prio, err = sema.New(pCap); err != nil {
		return nil, fmt.Errorf("leaf priority semaphore: %w", err)
	}
	aCap := cfg.effectiveAssetCap()
	if prev != nil && prev.assets.Cap() == aCap {
		assets = prev.assets
	} else if assets, err = sema.New(aCap); err != nil {
		return nil, fmt.Errorf("leaf asset semaphore: %w", err)
	}
	if prev != nil && prev.streams.Cap() == cfg.streamCap {
		streams = prev.streams
	} else if streams, err = sema.New(cfg.streamCap); err != nil {
		return nil, fmt.Errorf("leaf stream semaphore: %w", err)
	}
	nodeID := randomHex(6)
	if prev != nil && prev.nodeID != "" {
		nodeID = prev.nodeID
	}
	return &leafGuard{
		a:       a,
		cfg:     cfg,
		normal:  normal,
		prio:    prio,
		assets:  assets,
		streams: streams,
		nodeID:  nodeID,
	}, nil
}

func (l *leafGuard) snapshot(g *generation) leafStateSnapshot {
	upHealthy := true
	if g != nil && g.upstreams != nil && len(g.upstreams.backends) > 0 {
		upHealthy = g.upstreams.healthyCount(time.Now()) > 0
	}
	draining := l.a.draining.Load()
	return leafStateSnapshot{
		NodeID:          l.nodeID,
		Role:            nodeRoleLeaf,
		Cap:             l.normal.Cap(),
		Occupancy:       l.normal.Len(),
		PriorityCap:     l.prio.Cap(),
		PriorityOcc:     l.prio.Len(),
		AssetCap:        l.assets.Cap(),
		AssetInFlight:   l.assets.Len(),
		StreamCap:       l.streams.Cap(),
		StreamActive:    l.streams.Len(),
		Draining:        draining,
		UpstreamHealthy: upHealthy,
		Ready:           !draining && upHealthy,
		TS:              time.Now().Unix(),
	}
}

func (l *leafGuard) writeStateHeader(c *gin.Context, g *generation) {
	c.Header(leafStateHeader, l.snapshot(g).formatHeader())
}

// verifyHop checks Concert-Hop-Auth when -leaf-require-edge-auth is enabled.
func (l *leafGuard) verifyHop(c *gin.Context) (hopClaims, bool) {
	tok := c.GetHeader(hopAuthHeader)
	if tok != "" {
		if claims, ok := l.a.hop.verify(tok, time.Now()); ok {
			return claims, true
		}
		if l.cfg.leafRequireEdgeAuth {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid edge hop authentication"})
			return hopClaims{}, false
		}
	}
	if l.cfg.leafRequireEdgeAuth {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "edge hop authentication required"})
		return hopClaims{}, false
	}
	return hopClaims{Tier: "normal"}, true
}

// handlePage enforces the Leaf's hard per-app concurrency ceiling and proxies
// directly to app without issuing any browser cookies or waiting-room HTML.
func (l *leafGuard) handlePage(g *generation) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := l.verifyHop(c)
		if !ok {
			return
		}
		if l.a.draining.Load() {
			l.writeStateHeader(c, g)
			c.Header(backpressureHeader, "draining")
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "leaf draining", "backpressure": "draining"})
			return
		}

		isPrio := claims.Tier == "priority"
		sem := l.normal
		tierLabel := "normal"
		if isPrio {
			sem = l.prio
			tierLabel = "priority"
		}

		// Non-blocking try-acquire: if full, immediately signal backpressure so
		// Edge can transparently redispatch to another healthy Leaf!
		if !sem.TryAcquire() {
			l.writeStateHeader(c, g)
			c.Header(backpressureHeader, "full; tier="+tierLabel)
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "leaf capacity full", "backpressure": "full", "tier": tierLabel})
			return
		}
		defer sem.Release()

		// Attach live telemetry header before proxy writes headers.
		l.writeStateHeader(c, g)
		g.forward(c)
	}
}

func (l *leafGuard) handleAsset(g *generation) gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := l.verifyHop(c); !ok {
			return
		}
		if l.a.draining.Load() {
			l.writeStateHeader(c, g)
			c.Header(backpressureHeader, "draining")
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "leaf draining"})
			return
		}
		if !l.assets.TryAcquire() {
			l.a.stats.assetGlobalThrottled.Add(1)
			l.writeStateHeader(c, g)
			c.Header(backpressureHeader, "full; tier=asset")
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "leaf asset capacity full"})
			return
		}
		defer l.assets.Release()
		l.a.stats.assetServed.Add(1)
		l.writeStateHeader(c, g)
		g.forward(c)
	}
}

func (l *leafGuard) handleStream(g *generation) gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := l.verifyHop(c); !ok {
			return
		}
		if l.a.draining.Load() {
			l.writeStateHeader(c, g)
			c.Header(backpressureHeader, "draining")
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "leaf draining"})
			return
		}
		if !l.streams.TryAcquire() {
			l.a.stats.streamThrottled.Add(1)
			l.writeStateHeader(c, g)
			c.Header(backpressureHeader, "full; tier=stream")
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "leaf stream capacity full"})
			return
		}
		defer l.streams.Release()
		l.a.stats.streamServed.Add(1)
		l.writeStateHeader(c, g)
		g.forward(c)
	}
}

// ─── Edge Mesh Controller (Red Dotted Control-Plane Arrows) ──────────────────

// edgeMesh polls Leaf nodes directly on /_room/mesh/state (even when data
// flows through HAProxy via -mesh-peers), updates upstreamPool slot telemetry,
// and optionally auto-sizes Edge's room capacity to match healthy Leaf totals.
type edgeMesh struct {
	a         *app
	peers     []*url.URL
	interval  time.Duration
	autoCap   bool
	client    *http.Client

	mu        sync.RWMutex
	states    map[string]peerTelemetry
	lastCapAt time.Time

	stop     chan struct{}
	stopOnce sync.Once
}

type peerTelemetry struct {
	URL       string            `json:"url"`
	State     leafStateSnapshot `json:"state"`
	UpdatedAt time.Time         `json:"updated_at"`
	Err       string            `json:"error,omitempty"`
	Fails     int               `json:"consecutive_failures"`
}

func newEdgeMesh(a *app, cfg config, transport *http.Transport) *edgeMesh {
	if cfg.role != nodeRoleEdge {
		return nil
	}
	var peers []*url.URL
	if strings.TrimSpace(cfg.meshPeers) != "" {
		if parsed, err := parseUpstreams(cfg.meshPeers); err == nil {
			peers = parsed
		}
	}
	if len(peers) == 0 {
		peers = cfg.targets
	}
	if len(peers) == 0 {
		return nil
	}
	iv := cfg.meshPollInterval
	if iv < 250*time.Millisecond {
		iv = 2 * time.Second
	}
	m := &edgeMesh{
		a:        a,
		peers:    peers,
		interval: iv,
		autoCap:  cfg.edgeAutoCap,
		client: &http.Client{
			Transport: transport,
			Timeout:   3 * time.Second,
		},
		states: make(map[string]peerTelemetry, len(peers)),
		stop:   make(chan struct{}),
	}
	go m.pollLoop()
	return m
}

func (m *edgeMesh) close() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() { close(m.stop) })
}

func (m *edgeMesh) pollLoop() {
	m.pollOnce()
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.pollOnce()
		}
	}
}

func (m *edgeMesh) pollOnce() {
	now := time.Now()
	g := m.a.current()
	var pool *upstreamPool
	if g != nil {
		pool = g.upstreams
	}

	for _, u := range m.peers {
		key := u.String()
		st, err := m.fetchLeafState(u, now)

		m.mu.Lock()
		prev := m.states[key]
		if err != nil {
			prev.URL = key
			prev.Err = err.Error()
			prev.Fails++
			// Graceful decay: require 2 consecutive poll failures before marking
			// Leaf unhealthy so transient network jitter never collapses capacity.
			if prev.Fails >= 2 {
				prev.State.UpstreamHealthy = false
				prev.State.Ready = false
			}
			m.states[key] = prev
			m.mu.Unlock()
			if pool != nil && prev.Fails >= 2 {
				pool.updateLeafTelemetry(key, prev.State, now)
			}
			continue
		}
		m.states[key] = peerTelemetry{
			URL:       key,
			State:     st,
			UpdatedAt: now,
			Fails:     0,
		}
		m.mu.Unlock()

		if pool != nil {
			pool.updateLeafTelemetry(key, st, now)
		}
	}

	if m.autoCap {
		m.recomputeEdgeCap(now)
	}
}

func (m *edgeMesh) fetchLeafState(u *url.URL, now time.Time) (leafStateSnapshot, error) {
	target := *u
	target.Path = "/_room/mesh/state"
	target.RawQuery = ""
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return leafStateSnapshot{}, err
	}
	req.Header.Set(hopAuthHeader, m.a.hop.sign(hopClaims{TS: now.Unix(), Tier: "mesh"}))
	req.Header.Set("User-Agent", "concert-edge-mesh/"+BinaryVersion())
	resp, err := m.client.Do(req)
	if err != nil {
		return leafStateSnapshot{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return leafStateSnapshot{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var st leafStateSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return leafStateSnapshot{}, err
	}
	return st, nil
}

// recomputeEdgeCap dynamically sets Edge's waiting room cap to the sum of
// healthy, non-draining Leaf capacities (clamped to >= 1 and guarded against
// startup race before any Leaf has reported).
func (m *edgeMesh) recomputeEdgeCap(now time.Time) {
	m.mu.Lock()
	var totalCap int
	var anySeen bool
	for _, pt := range m.states {
		if pt.UpdatedAt.IsZero() {
			continue
		}
		anySeen = true
		if pt.State.Ready && pt.State.Cap > 0 {
			totalCap += pt.State.Cap
		}
	}
	if !anySeen {
		m.mu.Unlock()
		return
	}
	if totalCap < 1 {
		totalCap = 1
	}
	// Debounce rapid flapping unless capacity is shrinking (shrink fast to
	// protect remaining Leafs immediately; grow at most once per poll interval).
	curCap := int(m.a.room.Cap())
	if totalCap == curCap {
		m.mu.Unlock()
		return
	}
	if totalCap > curCap && !m.lastCapAt.IsZero() && now.Sub(m.lastCapAt) < m.interval {
		m.mu.Unlock()
		return
	}
	m.lastCapAt = now
	m.mu.Unlock()

	if err := m.a.room.SetCap(int32(totalCap)); err != nil {
		log.Printf("mesh: auto-cap SetCap(%d): %v", totalCap, err)
	} else {
		log.Printf("mesh: edge auto-cap adjusted %d -> %d based on live leaf telemetry", curCap, totalCap)
	}
}

func (m *edgeMesh) view() []peerTelemetry {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]peerTelemetry, 0, len(m.peers))
	for _, u := range m.peers {
		if pt, ok := m.states[u.String()]; ok {
			out = append(out, pt)
		} else {
			out = append(out, peerTelemetry{URL: u.String()})
		}
	}
	return out
}

// ingestLeafResponseHeaders parses piggybacked Concert-Leaf-State and
// Concert-Ban-Signal headers from a Leaf response, strips internal mesh
// headers so browsers never see them, and applies live telemetry & bans.
func (a *app) ingestLeafResponseHeaders(resp *http.Response, backendURL string) {
	if resp == nil {
		return
	}
	if rawState := resp.Header.Get(leafStateHeader); rawState != "" {
		resp.Header.Del(leafStateHeader)
		if st, ok := parseLeafStateHeader(rawState); ok && backendURL != "" {
			if g := a.current(); g != nil && g.upstreams != nil {
				g.upstreams.updateLeafTelemetry(backendURL, st, time.Now())
			}
		}
	}
	if rawBan := resp.Header.Get(banSignalHeader); rawBan != "" {
		resp.Header.Del(banSignalHeader)
		if ip, reason, ok := a.hop.verifyBanSignal(rawBan, time.Now()); ok {
			if g := a.current(); g != nil && g.abuse != nil {
				if _, banned := g.abuse.banNow(ip, time.Now()); banned {
					log.Printf("mesh: edge applied leaf ban signal for %s (%s)", ip, reason)
					a.saveBansNow()
				}
			}
		}
	}
	resp.Header.Del(backpressureHeader)
}

// parsePassIDHex extracts hex passID string from request context for sticky routing.
func passIDHexFromContext(ctx context.Context) string {
	if id, ok := passIDFrom(ctx); ok && id != (passID{}) {
		return hex.EncodeToString(id[:])
	}
	return ""
}

// isBackpressureResponse reports whether resp is a Leaf 503 backpressure rejection
// emitted before the Leaf forwarded the request to its upstream app.
func isBackpressureResponse(resp *http.Response) bool {
	return resp != nil && resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get(backpressureHeader) != ""
}

var errAllBackendsFull = errors.New("all upstream leaf backends at capacity or draining")
