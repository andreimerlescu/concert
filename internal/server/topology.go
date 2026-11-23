//go:build enterprise

package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/concert/internal/bench"
	"github.com/andreimerlescu/concert/internal/capacity"
	"github.com/andreimerlescu/concert/internal/hop"
	"github.com/andreimerlescu/concert/internal/mailer"
	"github.com/andreimerlescu/sema"
	"github.com/gin-gonic/gin"
)

// Edge and leaf tiers.
//
// A standalone Concert is the whole of Concert: waiting room, fast lane,
// passes, assets, bans. The same binary can also run as two tiers:
//
//	www  ──▶ edge Concert ──▶ (haproxy, optional) ──▶ leaf Concert ──▶ app
//	i-01 ─────────────────────────────────────────────▶ leaf Concert ──▶ app
//
// The edge owns everything a browser sees. When it forwards a request it
// admitted, it signs a hop.Claim into the Concert-Hop header. A leaf that
// verifies the claim skips its room, passes, fast lane and per-visitor pools
// for that request (the edge already did that work) and only takes a slot
// in its host Gate, where hop traffic is served before the leaf's own
// direct traffic. Requests without a valid claim (the public reaching i-01)
// get the leaf's ordinary, full handling, including its own fast lane.
//
// The edge polls every leaf's state to size its room to the capacity the
// leaves really have, and pushes its ban list to them: the edge is the
// source of truth for bans, so an attack moved from www to i-01 is already
// banned there.
//
// See docs/TOPOLOGY.md.

// roleStandalone, roleEdge, and roleLeaf are declared in edition_core.go.

func checkRole(v any) error {
	switch v.(string) {
	case roleStandalone, roleEdge, roleLeaf:
		return nil
	}
	return errors.New("must be standalone, edge or leaf")
}

func checkNodeID(v any) error {
	if s := v.(string); s != "" && !hop.ValidNodeID(s) {
		return errors.New("must be 1-32 characters from A-Z, a-z, 0-9, '.', '_' and '-'")
	}
	return nil
}

// checkURLList validates a comma-separated list of http(s) base URLs.
func checkURLList(v any) error {
	_, err := parseURLList(v.(string))
	return err
}

func parseURLList(spec string) ([]*url.URL, error) {
	var out []*url.URL
	seen := map[string]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		u, err := url.Parse(part)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("entry %q must look like https://host:port", part)
		}
		u.Path = strings.TrimSuffix(u.Path, "/")
		if seen[u.String()] {
			return nil, fmt.Errorf("lists %q more than once", part)
		}
		seen[u.String()] = true
		out = append(out, u)
	}
	return out, nil
}

// derivedNodeID names a node from its hostname, or randomly when the
// hostname cannot be used.
func derivedNodeID() string {
	h, _ := os.Hostname()
	var b strings.Builder
	for _, r := range strings.ToLower(h) {
		if b.Len() == 32 {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	if id := strings.Trim(b.String(), ".-_"); hop.ValidNodeID(id) {
		return id
	}
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	return "node-" + hex.EncodeToString(rnd[:])
}

// normalizeTopology validates the tier settings and fills derived fields.
// Called from normalize; idempotent.
func (c *config) normalizeTopology() error {
	if c.role == "" {
		c.role = roleStandalone
	}
	if err := checkRole(c.role); err != nil {
		return fmt.Errorf("invalid -role %q: %w", c.role, err)
	}
	if c.nodeID == "" {
		c.nodeID = derivedNodeID()
	}
	if !hop.ValidNodeID(c.nodeID) {
		return fmt.Errorf("invalid -node-id %q", c.nodeID)
	}
	if c.hopMaxSkew == 0 {
		c.hopMaxSkew = hop.DefaultMaxSkew
	}
	if c.hopMaxSkew < time.Second || c.hopMaxSkew > 5*time.Minute {
		return fmt.Errorf("invalid -hop-max-skew %s: must be between 1s and 5m", c.hopMaxSkew)
	}
	if c.hopWait < 0 || c.hopWait > 30*time.Second {
		return fmt.Errorf("invalid -hop-wait %s: must be between 0s and 30s", c.hopWait)
	}
	if c.hopPoll == 0 {
		c.hopPoll = 2 * time.Second
	}
	if c.hopPoll < 500*time.Millisecond || c.hopPoll > time.Minute {
		return fmt.Errorf("invalid -hop-poll %s: must be between 500ms and 1m", c.hopPoll)
	}
	if c.hostCap < 0 || c.hostCap > 1<<31-1 {
		return fmt.Errorf("invalid -host-cap %d", c.hostCap)
	}
	if c.upstreamRetries < 0 || c.upstreamRetries > 5 {
		return fmt.Errorf("invalid -upstream-retries %d: must be between 0 and 5", c.upstreamRetries)
	}
	if c.benchP95 == 0 {
		c.benchP95 = 2 * time.Second
	}
	if c.benchMaxLemmings == 0 {
		c.benchMaxLemmings = 1024
	}
	var err error
	if c.hopPeerPrefixes, err = parsePrefixes(c.hopPeers); err != nil {
		return fmt.Errorf("invalid -hop-peers: %w", err)
	}
	if c.hopLeafURLs, err = parseURLList(c.hopLeaves); err != nil {
		return fmt.Errorf("invalid -hop-leaves: %w", err)
	}
	if len(c.hopSecretPrev) > 0 && len(c.hopSecretPrev) < hop.MinSecretLen {
		return fmt.Errorf("CONCERT_HOP_SECRET_PREV must be at least %d bytes", hop.MinSecretLen)
	}
	if c.role == roleStandalone {
		return nil
	}
	if len(c.hopSecret) < hop.MinSecretLen {
		return fmt.Errorf("-role %s needs CONCERT_HOP_SECRET of at least %d bytes, the same on every edge and leaf", c.role, hop.MinSecretLen)
	}
	if c.role == roleLeaf && len(c.hopPeerPrefixes) == 0 {
		return errors.New("-role leaf needs -hop-peers: the addresses of the edges, or of the load balancer between the tiers")
	}
	return nil
}

// controlURLs are the leaves an edge polls: -hop-leaves, or the upstreams
// when the edge balances across leaves itself.
func (c *config) controlURLs() []*url.URL {
	if len(c.hopLeafURLs) > 0 {
		return c.hopLeafURLs
	}
	if c.role != roleEdge {
		return nil
	}
	if len(c.targets) > 0 {
		return c.targets
	}
	if c.target != nil {
		return []*url.URL{c.target}
	}
	return nil
}

// ─── long-lived tier state ───────────────────────────────────────────────────

// topology is the tier state that lives as long as the process. Exactly one
// of the edge or leaf halves is set, by role; a standalone node has neither.
type topology struct {
	role string
	node string

	// Both roles: signer for the edge's claims and the control plane;
	// verifier for the leaf's.
	signer   *hop.Signer
	verifier *hop.Verifier

	edge *edgeState
	leaf *leafState
}

// newTopology builds the tier state for cfg. a must already have its abuse
// registry and counters.
func newTopology(cfg config) (*topology, error) {
	t := &topology{role: cfg.role, node: cfg.nodeID}
	if cfg.role == roleStandalone {
		return t, nil
	}
	var err error
	if t.signer, err = hop.NewSigner(cfg.hopSecret, cfg.nodeID); err != nil {
		return nil, err
	}
	if t.verifier, err = hop.NewVerifier(cfg.hopMaxSkew, cfg.hopSecret, cfg.hopSecretPrev); err != nil {
		return nil, err
	}
	t.verifier.SetReplayGuard(cfg.hopReplayGuard, cfg.hopRequireNonce)
	switch cfg.role {
	case roleEdge:
		t.edge = newEdgeState(cfg)
	case roleLeaf:
		t.leaf = newLeafState(cfg)
	}
	return t, nil
}

func (t *topology) isEdge() bool { return t != nil && t.edge != nil }
func (t *topology) isLeaf() bool { return t != nil && t.leaf != nil }

// ─── request context ─────────────────────────────────────────────────────────

// Gin context keys for tier state on a request (ctxHopRank & ctxHopPaid live in edition_core.go).
const (
	ctxHopIn    = "concert.hop_in"    // leaf: the verified hop.Claim the request carried
	ctxHopRaw   = "concert.hop_raw"   // leaf: the raw Concert-Hop value, for control requests
	ctxHopClass = "concert.hop_class" // edge: which tier admitted the request
)

type hopInKey struct{}  // request context: verified inbound hop.Claim (leaf)
type hopOutKey struct{} // request context: hop.Claim to sign on the way out (edge)

func withHopIn(ctx context.Context, c hop.Claim) context.Context {
	return context.WithValue(ctx, hopInKey{}, c)
}

func hopInFrom(ctx context.Context) (hop.Claim, bool) {
	c, ok := ctx.Value(hopInKey{}).(hop.Claim)
	return c, ok
}

func withHopOut(ctx context.Context, c hop.Claim) context.Context {
	return context.WithValue(ctx, hopOutKey{}, c)
}

func hopOutFrom(ctx context.Context) (hop.Claim, bool) {
	c, ok := ctx.Value(hopOutKey{}).(hop.Claim)
	return c, ok
}

// reservedHopPath reports paths a leaf always answers itself, claim or not.
// An edge answers these for its own visitors and never forwards them.
func reservedHopPath(p string) bool {
	return p == "/queue/status" || strings.HasPrefix(p, "/queue/status/") ||
		p == "/_room" || strings.HasPrefix(p, "/_room/") ||
		p == "/_concert" || strings.HasPrefix(p, "/_concert/")
}

// ─── identify ────────────────────────────────────────────────────────────────

// identifyHop runs in identify before the client address is used. On a leaf
// it verifies a Concert-Hop claim from a -hop-peers connection and, when
// valid, returns the client the edge resolved. Every role removes the
// header from the request, so it never reaches the application and a
// client can never smuggle one through an edge.
func (g *generation) identifyHop(c *gin.Context, ip netip.Addr) netip.Addr {
	r := c.Request
	raw := r.Header.Get(hop.Header)
	if raw == "" {
		return ip
	}
	r.Header.Del(hop.Header)
	t := g.a.topo
	if !t.isLeaf() {
		return ip // an edge or standalone node never trusts an inbound claim
	}
	peer, ok := remoteAddr(r)
	peerOK := ok && containsAddr(g.cfg.hopPeerPrefixes, peer)
	if !peerOK {
		// Only the tier in front may sign claims. Anyone else presenting
		// one is probing; it earns the forged-pass strike.
		t.leaf.rejected.Add(1)
		g.strike(c, strikeForgedPass)
		return ip
	}
	if strings.HasPrefix(r.URL.Path, "/_room/hop/") {
		// Control requests bind their body; the handler verifies them (and mTLS).
		c.Set(ctxHopRaw, raw)
		return ip
	}
	if g.cfg.hopRequireMTLS && (r.TLS == nil || len(r.TLS.VerifiedChains) == 0) {
		t.leaf.rejected.Add(1)
		t.leaf.mtlsRejected.Add(1)
		if t.leaf.rejectLog.Add(1) <= 20 {
			log.Printf("hop: rejected claim from %s for %s %s: missing verified mTLS client certificate", peer, r.Method, clip(r.URL.Path, 128))
		}
		return ip
	}
	claim, err := t.verifier.Verify(raw, r.Method, r.RequestURI, "")
	if err != nil || claim.Class == hop.ClassControl {
		t.leaf.rejected.Add(1)
		if errors.Is(err, hop.ErrReplay) {
			t.leaf.replayed.Add(1)
		}
		if t.leaf.rejectLog.Add(1) <= 20 {
			log.Printf("hop: rejected claim from %s for %s %s: %v", peer, r.Method, clip(r.URL.Path, 128), err)
		}
		return ip
	}
	t.leaf.sawEdgeTraffic(claim.Edge, time.Now())
	t.leaf.accepted.Add(1)
	c.Set(ctxHopIn, claim)
	c.Request = r.WithContext(withHopIn(r.Context(), claim))
	return claim.Client
}

// ─── leaf state ──────────────────────────────────────────────────────────────

type edgeActivity struct {
	lastSeen       time.Time
	reportedDemand float64 // smoothed demand (in_flight + live_queue) from edge poll
	ewmaHits       float64 // exponentially decayed hop request count (30s tau)
	lastHitAt      time.Time
}

const edgeDemandDecaySec = 30.0

func (ea *edgeActivity) decayedHits(now time.Time) float64 {
	if ea.ewmaHits <= 0 || ea.lastHitAt.IsZero() {
		return 0
	}
	dt := now.Sub(ea.lastHitAt).Seconds()
	if dt <= 0 {
		return ea.ewmaHits
	}
	v := ea.ewmaHits * math.Exp(-dt/edgeDemandDecaySec)
	if v < 1e-4 {
		return 0
	}
	return v
}

// leafState is a leaf's long-lived tier state.
type leafState struct {
	gate *capacity.Gate

	capMu     sync.Mutex
	capSource string // "flag", "bench" or "cap"
	capFile   *capacity.File

	edgesMu sync.Mutex
	edges   map[string]*edgeActivity // edge node ID → recent activity & demand

	bans banMirror

	accepted       atomic.Int64 // verified hop requests
	rejected       atomic.Int64 // claims refused (bad signature, skew, peer, replay, mTLS)
	replayed       atomic.Int64 // claims refused specifically as replayed single-use nonces
	mtlsRejected   atomic.Int64 // claims refused due to missing verified mTLS client cert
	backpressed    atomic.Int64 // hop requests refused for capacity
	rebenchTotal   atomic.Int64 // completed drained re-benchmarks
	rebenchmarking atomic.Bool  // true while drained for on-demand re-benchmark
	rejectLog      atomic.Int64

	monitor silenceMonitor
}

func newLeafState(cfg config) *leafState {
	l := &leafState{edges: map[string]*edgeActivity{}}
	l.bans.perEdge = map[string]*edgeBans{}
	if cfg.dataDir != "" {
		l.bans.path = filepath.Join(cfg.dataDir, mirrorFileName)
		l.bans.load()
	}
	n, src, file := hostCapacity(cfg)
	l.gate = capacity.NewGate(n)
	l.capSource, l.capFile = src, file
	return l
}

// hostCapacity is the leaf's host ceiling and where it came from: -host-cap,
// then the benchmark's capacity.json, then -cap.
func hostCapacity(cfg config) (int, string, *capacity.File) {
	if cfg.hostCap > 0 {
		return cfg.hostCap, "flag", nil
	}
	if cfg.dataDir != "" {
		f, err := capacity.Load(capacity.Path(cfg.dataDir))
		if err == nil {
			return f.HostCap, "bench", &f
		}
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("capacity: %v; using -cap", err)
		}
	}
	return cfg.capacity, "cap", nil
}

// applyConfig resizes the host gate after a settings change.
func (l *leafState) applyConfig(cfg config) {
	n, src, file := hostCapacity(cfg)
	l.capMu.Lock()
	l.capSource, l.capFile = src, file
	l.capMu.Unlock()
	if l.gate.Cap() != n {
		l.gate.SetCap(n)
		log.Printf("leaf: host capacity %d (%s)", n, src)
	}
}

func (l *leafState) edgeEntryLocked(edge string, now time.Time) *edgeActivity {
	ea := l.edges[edge]
	if ea == nil {
		ea = &edgeActivity{}
		l.edges[edge] = ea
	}
	ea.lastSeen = now
	return ea
}

func (l *leafState) sawEdge(edge string, now time.Time) {
	if edge == "" {
		return
	}
	l.edgesMu.Lock()
	l.edgeEntryLocked(edge, now)
	l.edgesMu.Unlock()
}

func (l *leafState) sawEdgeTraffic(edge string, now time.Time) {
	if edge == "" {
		return
	}
	l.edgesMu.Lock()
	ea := l.edgeEntryLocked(edge, now)
	ea.ewmaHits = ea.decayedHits(now) + 1.0
	ea.lastHitAt = now
	l.edgesMu.Unlock()
}

func (l *leafState) sawEdgePoll(edge string, demand int64, now time.Time) {
	if edge == "" {
		return
	}
	if demand < 0 {
		demand = 0
	}
	d := float64(demand)
	l.edgesMu.Lock()
	ea := l.edgeEntryLocked(edge, now)
	if d >= ea.reportedDemand {
		// Snap upward promptly when a surge arrives at this edge.
		ea.reportedDemand = d
	} else {
		// Smooth downward so brief lulls do not thrash shares.
		ea.reportedDemand = 0.5*ea.reportedDemand + 0.5*d
		if ea.reportedDemand < 0.05 {
			ea.reportedDemand = 0
		}
	}
	l.edgesMu.Unlock()
}

// edgesSeen counts edges heard from in the last minute, at least 1, and
// forgets older ones.
func (l *leafState) edgesSeen(now time.Time) int {
	n, _ := l.edgeShares(l.gate.Cap(), now)
	return n
}

// edgeShares prunes stale edges (>1m) and returns the active edge count (at
// least 1) together with each active edge's demand-weighted share of hostCap.
func (l *leafState) edgeShares(hostCap int, now time.Time) (int, map[string]int) {
	l.edgesMu.Lock()
	defer l.edgesMu.Unlock()
	weights := make(map[string]float64, len(l.edges))
	for id, ea := range l.edges {
		if now.Sub(ea.lastSeen) > time.Minute {
			delete(l.edges, id)
			continue
		}
		w := ea.decayedHits(now)
		if ea.reportedDemand > w {
			w = ea.reportedDemand
		}
		weights[id] = w
	}
	if len(weights) == 0 {
		return 1, nil
	}
	return len(weights), hop.AllocateShares(hostCap, weights)
}

// gateClass is where a hop request waits in the host gate: the edge's lane
// ranks and paid visitors first.
func gateClass(claim hop.Claim, laneRank int) capacity.Class {
	if claim.Paid || int(claim.Rank) >= laneRank {
		return capacity.HopPriority
	}
	return capacity.Hop
}

// backpressure answers a hop request the leaf cannot take. Nothing was sent
// to the application, so the edge may retry it on another leaf.
func (g *generation) backpressure(c *gin.Context) {
	g.a.topo.leaf.backpressed.Add(1)
	c.Header(hop.BackpressureHeader, "full")
	c.Header(hop.NodeHeader, g.a.topo.node)
	c.Header("Retry-After", "1")
	c.Header("Cache-Control", "no-store")
	c.AbortWithStatus(http.StatusServiceUnavailable)
}

// hopFastPath serves a leaf's verified hop requests: no room, no pass, no
// fast lane, no per-visitor pool. Page requests take a host-gate slot,
// assets the global asset pool, streams a stream slot, bypass paths
// nothing. Everything else (unclaimed requests, and the paths a leaf always
// answers itself) falls through to the ordinary chain.
func (g *generation) hopFastPath(c *gin.Context) {
	v, ok := c.Get(ctxHopIn)
	if !ok || reservedHopPath(c.Request.URL.Path) {
		return
	}
	claim := v.(hop.Claim)
	l := g.a.topo.leaf
	switch claim.Class {
	case hop.ClassPage:
		cls := gateClass(claim, g.cfg.priorityLaneRank)
		if !l.gate.Acquire(c.Request.Context(), cls, g.cfg.hopWait) {
			g.backpressure(c)
			return
		}
		defer l.gate.Release(cls)
	case hop.ClassAsset:
		prio := sema.PriorityNormal
		if claim.Paid || claim.Rank >= uint8(rankCheckout) {
			prio = sema.PriorityCritical
		} else if g.cfg.priorityLaneRank > 0 && int(claim.Rank) >= g.cfg.priorityLaneRank {
			prio = sema.PriorityHigh
		}
		if !acquirePriority(c.Request.Context(), g.assets.global, prio, g.cfg.assetWait) {
			g.a.stats.assetGlobalThrottled.Add(1)
			g.backpressure(c)
			return
		}
		defer func() { _ = g.assets.global.Release() }()
		g.a.stats.assetServed.Add(1)
		if g.tryStatic(c, true) {
			c.Abort()
			return
		}
	case hop.ClassStream:
		if !g.streams.sem.TryAcquire() {
			g.a.stats.streamThrottled.Add(1)
			g.backpressure(c)
			return
		}
		defer func() { _ = g.streams.sem.Release() }()
		g.a.stats.streamServed.Add(1)
	case hop.ClassBypass:
	default:
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	g.forward(c)
	c.Abort()
}

// gateDirect wraps a leaf's forward for its own admitted page requests:
// they take a host slot behind every hop request. A request that cannot get
// one before the upstream timeout is answered 503.
func (g *generation) gateDirect(next gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		l := g.a.topo.leaf
		if !l.gate.Acquire(c.Request.Context(), capacity.Direct, g.cfg.headerTimeout) {
			c.Header("Retry-After", "1")
			c.Header("Cache-Control", "no-store")
			c.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		defer l.gate.Release(capacity.Direct)
		next(c)
	}
}

// ─── edge forwarding ─────────────────────────────────────────────────────────

// forwardAs marks which tier admitted a request, so an edge's claim says
// so, then forwards it.
func (g *generation) forwardAs(class trafficClass) gin.HandlerFunc {
	hc := toHopClass(class)
	return func(c *gin.Context) {
		c.Set(ctxHopClass, hc)
		g.forward(c)
	}
}

// edgeClaim attaches the claim an edge signs for this request.
func (g *generation) edgeClaim(c *gin.Context, req *http.Request) *http.Request {
	if !g.a.topo.isEdge() {
		return req
	}
	claim := hop.Claim{Client: clientIPFrom(c), Class: hop.ClassPage}
	if !claim.Client.IsValid() {
		return req
	}
	if v, ok := c.Get(ctxHopClass); ok {
		claim.Class = v.(hop.Class)
	}
	if v, ok := c.Get(ctxHopRank); ok {
		claim.Rank = v.(uint8)
	}
	claim.Paid = c.GetBool(ctxHopPaid)
	if isMultiplexed(req, g.cfg.clientProtoHeader) {
		claim.Proto = "h2"
	} else {
		claim.Proto = "h1"
	}
	return req.WithContext(withHopOut(req.Context(), claim))
}

// signHop adds the edge's Concert-Hop header to an outgoing request.
// Called by the transport for every attempt, so a retry to another leaf is
// signed for that leaf's URL.
func (t *topology) signHop(req *http.Request) *http.Request {
	if !t.isEdge() {
		return req
	}
	claim, ok := hopOutFrom(req.Context())
	if !ok {
		return req
	}
	out := new(http.Request)
	*out = *req
	out.Header = req.Header.Clone()
	out.Header.Set(hop.Header, t.signer.Sign(claim, req.Method, req.URL.RequestURI(), ""))
	return out
}

// tierResponse is the proxy's response hook for the tiers. An edge removes
// every Concert cookie a leaf set (the edge owns the browser's cookies) and
// the tier headers. A leaf leaves Concert-Priority on its answers to hop
// requests so the edge turns it into the visitor's grant.
func (a *app) tierResponse(next func(*http.Response) error) func(*http.Response) error {
	t := a.topo
	switch {
	case t.isEdge():
		return func(resp *http.Response) error {
			stripTierHeaders(resp.Header)
			stripConcertSetCookies(resp.Header)
			return next(resp)
		}
	case t.isLeaf():
		return func(resp *http.Response) error {
			// Only the leaf itself may signal backpressure: an
			// application's 503 carrying the header was already served,
			// and the edge would send the request again elsewhere.
			stripTierHeaders(resp.Header)
			if resp.Request != nil {
				if _, ok := hopInFrom(resp.Request.Context()); ok {
					resp.Header.Set(hop.NodeHeader, t.node)
					return nil
				}
			}
			return next(resp)
		}
	}
	return func(resp *http.Response) error {
		stripTierHeaders(resp.Header)
		return next(resp)
	}
}

// stripTierHeaders and stripConcertSetCookies live in edition_core.go.

// ─── first start ─────────────────────────────────────────────────────────────

// benchStartTuning lets tests shorten the startup benchmark's stages.
var benchStartTuning = func(*bench.Options) {}

// benchOnStart measures a leaf's application before the leaf serves
// anything, when no capacity.json exists yet, and makes the result the host
// capacity. The leaf is not listening yet, so the benchmark is the only
// load the application sees. It is opt-in (-bench-on-start): it crawls the
// application hard on purpose.
func (a *app) benchOnStart(ctx context.Context) {
	cfg := a.current().cfg
	if cfg.hostCap > 0 {
		log.Printf("bench: -host-cap %d is set; skipping the startup benchmark", cfg.hostCap)
		return
	}
	if cfg.dataDir == "" {
		log.Printf("bench: -bench-on-start needs -data-dir to keep its result; skipping")
		return
	}
	path := capacity.Path(cfg.dataDir)
	if _, err := os.Stat(path); err == nil {
		log.Printf("bench: %s exists; skipping the startup benchmark (delete it to measure again)", path)
		return
	}
	target := *cfg.target
	if target.Path == "" {
		target.Path = "/"
	}
	log.Printf("bench: measuring %s before serving: p95 within %s, up to %d lemmings", target.Redacted(), cfg.benchP95, cfg.benchMaxLemmings)
	opts := bench.Options{
		Target:   &target,
		P95Limit: cfg.benchP95,
		Max:      cfg.benchMaxLemmings,
		Header:   http.Header{"User-Agent": {"concert-bench/" + BinaryVersion() + " (leaf " + a.topo.node + ")"}},
		Logf:     log.Printf,
	}
	benchStartTuning(&opts)
	rep, err := bench.Run(ctx, opts)
	if rep != nil {
		log.Printf("bench: %s", rep.Verdict)
	}
	if err != nil || rep == nil || rep.HostCap < 1 {
		log.Printf("bench: no capacity measured (%v); host capacity stays %d (%s)", err, a.topo.leaf.gate.Cap(), a.topo.leaf.capSource)
		return
	}
	reportPath := filepath.Join(cfg.dataDir, "bench-report.json")
	if b, err := json.MarshalIndent(rep, "", "  "); err == nil {
		if err := writeFileAtomic(reportPath, append(b, '\n')); err != nil {
			log.Printf("bench: cannot save %s: %v", reportPath, err)
		}
	}
	if err := bench.SaveCapacity(path, rep, reportPath); err != nil {
		log.Printf("bench: %v", err)
		return
	}
	a.topo.leaf.applyConfig(cfg)
}

// rebenchLeaf drains a leaf's active slots, runs the lemmings capacity
// benchmark against its local upstream, atomically persists bench-report.json
// and capacity.json (when -data-dir is set), updates the host gate, and
// rejoins traffic. Always clears the draining/rebenchmarking flag on return.
func (a *app) rebenchLeaf(ctx context.Context, drainWait time.Duration) (hop.RebenchResult, int, error) {
	var res hop.RebenchResult
	if !a.topo.isLeaf() {
		return res, http.StatusBadRequest, errors.New("re-benchmarking is only supported on leaf nodes (or from an edge targeting a leaf)")
	}
	l := a.topo.leaf
	if !l.rebenchmarking.CompareAndSwap(false, true) {
		return res, http.StatusConflict, errors.New("a re-benchmark is already running on this leaf")
	}
	defer l.rebenchmarking.Store(false)

	if drainWait <= 0 {
		drainWait = 5 * time.Second
	}
	if drainWait > 30*time.Second {
		drainWait = 30 * time.Second
	}

	// Wait briefly for in-flight hop/direct requests to drain while edges route
	// new traffic to sibling leaves (since LeafState.Draining is now true).
	deadline := time.Now().Add(drainWait)
	for time.Now().Before(deadline) {
		inUse := l.gate.InUse(capacity.HopPriority) + l.gate.InUse(capacity.Hop) + l.gate.InUse(capacity.Direct)
		if inUse == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return res, http.StatusRequestTimeout, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}

	cfg := a.current().cfg
	prevCap := l.gate.Cap()
	target := *cfg.target
	if target.Path == "" {
		target.Path = "/"
	}
	log.Printf("bench: drained re-benchmark on %s measuring %s (p95 <= %s, max %d lemmings)",
		a.topo.node, target.Redacted(), cfg.benchP95, cfg.benchMaxLemmings)
	opts := bench.Options{
		Target:   &target,
		P95Limit: cfg.benchP95,
		Max:      cfg.benchMaxLemmings,
		Header:   http.Header{"User-Agent": {"concert-bench/" + BinaryVersion() + " (leaf " + a.topo.node + ")"}},
		Logf:     log.Printf,
	}
	benchStartTuning(&opts)
	rep, err := bench.Run(ctx, opts)
	if err != nil {
		return res, http.StatusBadGateway, fmt.Errorf("benchmark failed: %w", err)
	}
	if rep == nil || rep.HostCap < 1 {
		verdict := "no capacity measured"
		if rep != nil && rep.Verdict != "" {
			verdict = rep.Verdict
		}
		return res, http.StatusBadGateway, fmt.Errorf("benchmark did not measure usable capacity: %s", verdict)
	}

	now := time.Now().UTC()
	var capFile capacity.File
	var reportPath string
	if cfg.dataDir != "" {
		reportPath = filepath.Join(cfg.dataDir, "bench-report.json")
		if b, merr := json.MarshalIndent(rep, "", "  "); merr == nil {
			if werr := writeFileAtomic(reportPath, append(b, '\n')); werr != nil {
				log.Printf("bench: cannot save %s: %v", reportPath, werr)
			}
		}
		capPath := capacity.Path(cfg.dataDir)
		if serr := bench.SaveCapacity(capPath, rep, reportPath); serr != nil {
			return res, http.StatusInternalServerError, fmt.Errorf("save capacity.json: %w", serr)
		}
		if loaded, lerr := capacity.Load(capPath); lerr == nil {
			capFile = loaded
		}
	}
	if capFile.HostCap == 0 {
		capFile = capacity.File{
			At:       now,
			Target:   target.Redacted(),
			HostCap:  rep.HostCap,
			Lemmings: rep.Lemmings,
			P95Ms:    rep.P95Ms,
			LimitMs:  float64(cfg.benchP95.Milliseconds()),
			Pages:    rep.Pages,
			Safety:   rep.Safety,
			Report:   reportPath,
		}
	}

	if cfg.hostCap > 0 {
		// Explicit -host-cap flag stays authoritative; still record benchmark metadata.
		l.capMu.Lock()
		l.capFile = &capFile
		l.capMu.Unlock()
	} else {
		l.capMu.Lock()
		l.capSource = "bench"
		l.capFile = &capFile
		l.capMu.Unlock()
		if l.gate.Cap() != rep.HostCap {
			l.gate.SetCap(rep.HostCap)
		}
	}
	l.rebenchTotal.Add(1)

	l.capMu.Lock()
	src := l.capSource
	l.capMu.Unlock()
	newCap := l.gate.Cap()

	res = hop.RebenchResult{
		Node:         a.topo.node,
		PreviousCap:  prevCap,
		NewCap:       newCap,
		CapSource:    src,
		Lemmings:     rep.Lemmings,
		P95Ms:        rep.P95Ms,
		PagesCovered: rep.Pages,
		Verdict:      rep.Verdict,
		At:           now,
	}
	a.notifyEvent(mailer.Event{
		Category:    mailer.CatCapacity,
		Severity:    mailer.SevInfo,
		Title:       "Leaf capacity re-benchmarked",
		Summary:     fmt.Sprintf("Leaf %s completed drained re-benchmark: host capacity %d -> %d (%d lemmings, p95 %.0fms).", a.topo.node, prevCap, newCap, rep.Lemmings, rep.P95Ms),
		Fingerprint: "rebench:" + a.topo.node,
		Details: map[string]string{
			"node":         a.topo.node,
			"previous_cap": fmt.Sprintf("%d", prevCap),
			"new_cap":      fmt.Sprintf("%d", newCap),
			"lemmings":     fmt.Sprintf("%d", rep.Lemmings),
			"p95_ms":       fmt.Sprintf("%.1f", rep.P95Ms),
		},
	})
	return res, http.StatusOK, nil
}
