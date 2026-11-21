package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/concert/internal/capacity"
	"github.com/andreimerlescu/concert/internal/hop"
	"github.com/gin-gonic/gin"
)

// The control plane between tiers.
//
// The edge initiates every exchange, so a leaf needs to know nothing about
// its edges and comes up first. Every -hop-poll the edge reads each leaf's
// hop.LeafState, plans its room's capacity from what the healthy leaves
// offer, and pushes its ban list to any leaf whose applied version differs.
// A new ban at the edge triggers a round at once. Both requests are signed
// claims of class ctl that bind the request body.
//
// If the link to a leaf drops, its last report fades out over the planner's
// Expire window instead of vanishing, and the leaf keeps enforcing the bans
// it already mirrored.

const (
	maxStateBody = 1 << 20 // a leaf's state
	maxBanBody   = 8 << 20 // a ban snapshot: ~100k bans
)

// ─── edge ────────────────────────────────────────────────────────────────────

// edgeState is an edge's long-lived tier state.
type edgeState struct {
	planner capacity.Planner
	kick    chan struct{}
	roundMu sync.Mutex // one round at a time, so pushes stay in order

	mu     sync.Mutex
	leaves map[string]*leafLink // by control URL

	lastPlan   atomic.Pointer[capacity.Plan]
	everUsable atomic.Bool

	backpressure atomic.Int64 // leaf 503s with Concert-Backpressure
	retries      atomic.Int64 // requests re-sent to another upstream
	polls        atomic.Int64
	pollErrors   atomic.Int64
	pushes       atomic.Int64
	pushErrors   atomic.Int64
}

// leafLink is what an edge knows about one leaf.
type leafLink struct {
	url   *url.URL
	state hop.LeafState
	at    time.Time // when the last successful read was sent; zero before the first
	err   string    // last error, "" after a success
}

func newEdgeState(cfg config) *edgeState {
	poll := cfg.hopPoll
	return &edgeState{
		planner: capacity.Planner{
			Stale:      3 * poll,
			Expire:     15 * poll,
			RaiseAfter: 2,
		},
		kick:   make(chan struct{}, 1),
		leaves: map[string]*leafLink{},
	}
}

// kickEdge asks the edge loop for a round now (after a new ban).
func (t *topology) kickEdge() {
	if !t.isEdge() {
		return
	}
	select {
	case t.edge.kick <- struct{}{}:
	default:
	}
}

// edgeCap is the room capacity commit should apply: the planned capacity on
// an edge sizing itself from its leaves (1 before any leaf has reported),
// otherwise -cap. Never below what the room has in flight; see
// capacity.SafeShrink.
func (a *app) edgeCap(cfg config) int32 {
	if !a.topo.isEdge() || !cfg.hopAutoCap {
		return int32(cfg.capacity)
	}
	n := a.topo.edge.planner.Current()
	if n < 1 {
		n = 1
	}
	if n > cfg.capacity {
		n = cfg.capacity
	}
	occupied := 0
	if a.room != nil {
		occupied = a.room.Len()
	}
	return int32(capacity.SafeShrink(n, occupied))
}

// edgeReady reports whether an auto-sizing edge has heard from at least one
// usable leaf, for /_room/readyz.
func (a *app) edgeReady(cfg config) bool {
	if !a.topo.isEdge() || !cfg.hopAutoCap {
		return true
	}
	p := a.topo.edge.lastPlan.Load()
	return p != nil && p.Leaves > 0
}

// runEdge polls the leaves until the app stops.
func (a *app) runEdge() {
	e := a.topo.edge
	for {
		cfg := a.current().cfg
		ctx, cancel := context.WithTimeout(context.Background(), cfg.hopPoll)
		a.edgeRound(ctx)
		cancel()
		t := time.NewTimer(cfg.hopPoll)
		select {
		case <-a.stop:
			t.Stop()
			return
		case <-e.kick:
			t.Stop()
		case <-t.C:
		}
	}
}

// controlClient talks to leaves over the generation's upstream transport,
// so the control plane uses the same CA and mTLS identity as the data plane.
func (g *generation) controlClient(timeout time.Duration) *http.Client {
	var rt http.RoundTripper = http.DefaultTransport
	if g.upstreams != nil && g.upstreams.transport != nil {
		rt = g.upstreams.transport
	}
	return &http.Client{
		Transport: rt,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// edgeRound reads every leaf, pushes bans where needed, plans capacity and
// applies it.
func (a *app) edgeRound(ctx context.Context) capacity.Plan {
	g := a.current()
	cfg := g.cfg
	e := a.topo.edge
	urls := cfg.controlURLs()
	e.roundMu.Lock()
	defer e.roundMu.Unlock()
	snap := a.banSnapshot(time.Now())
	client := g.controlClient(cfg.hopPoll)

	e.mu.Lock()
	want := map[string]bool{}
	for _, u := range urls {
		k := u.String()
		want[k] = true
		if e.leaves[k] == nil {
			e.leaves[k] = &leafLink{url: u}
		}
	}
	for k := range e.leaves {
		if !want[k] {
			delete(e.leaves, k)
		}
	}
	links := make([]*leafLink, 0, len(e.leaves))
	for _, l := range e.leaves {
		links = append(links, l)
	}
	e.mu.Unlock()

	var wg sync.WaitGroup
	for _, l := range links {
		wg.Add(1)
		go func(l *leafLink) {
			defer wg.Done()
			e.polls.Add(1)
			asked := time.Now()
			st, err := a.fetchLeafState(ctx, client, l.url)
			e.mu.Lock()
			if !l.at.IsZero() && !asked.After(l.at) {
				// An overlapping round already stored a newer answer.
				e.mu.Unlock()
				return
			}
			if err != nil {
				e.pollErrors.Add(1)
				if l.err != err.Error() {
					log.Printf("edge: leaf %s: %v", l.url.Redacted(), err)
				}
				l.err = err.Error()
				e.mu.Unlock()
				return
			}
			if l.err != "" || l.at.IsZero() {
				log.Printf("edge: leaf %s (%s) reachable, host capacity %d (%s)", l.url.Redacted(), st.Node, st.HostCap, st.CapSource)
			}
			l.state, l.at, l.err = st, asked, ""
			e.mu.Unlock()
			if st.BanVersions[a.topo.node] != snap.Version {
				e.pushes.Add(1)
				if err := a.pushBans(ctx, client, l.url, snap); err != nil {
					e.pushErrors.Add(1)
					log.Printf("edge: ban sync to %s: %v", l.url.Redacted(), err)
				}
			}
		}(l)
	}
	wg.Wait()

	now := time.Now()
	e.mu.Lock()
	reports := make([]capacity.Report, 0, len(e.leaves))
	shares := map[string]int{}
	for k, l := range e.leaves {
		r := capacity.Report{Leaf: k, Share: l.state.Share(), Usable: l.state.Usable(), At: l.at}
		reports = append(reports, r)
		if r.Usable && !l.at.IsZero() && now.Sub(l.at) <= e.planner.Expire {
			shares[hostKey(l.url)] = r.Share
		} else {
			shares[hostKey(l.url)] = 0
		}
	}
	e.mu.Unlock()

	e.planner.SetLimits(cfg.capacity, cfg.effectivePriorityCap())
	plan := e.planner.Plan(reports, now)
	e.lastPlan.Store(&plan)
	if plan.Leaves > 0 && !e.everUsable.Swap(true) {
		log.Printf("edge: %d leaf(s) usable, %d page slot(s); admitting up to %d", plan.Leaves, plan.Total, plan.Cap)
	}
	if cfg.hopAutoCap {
		target := a.edgeCap(cfg)
		if cur := a.room.Cap(); target != cur {
			if err := a.room.SetCap(target); err == nil && (target < cur/2 || target > cur*2 || target == 1) {
				log.Printf("edge: room capacity %d -> %d (leaves offer %d, lane %d)", cur, target, plan.Total, cfg.effectivePriorityCap())
			}
		}
	}
	// Leaves the edge balances across itself get slot-aware routing.
	if g.upstreams != nil {
		for _, b := range g.upstreams.backends {
			b.slots.Store(int64(shares[hostKey(b.target)]))
		}
	}
	return plan
}

// hostKey matches a control URL to an upstream target.
func hostKey(u *url.URL) string {
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// controlRequest signs a ctl claim for method on base+path with body.
func (a *app) controlRequest(ctx context.Context, method string, base *url.URL, path string, body []byte) (*http.Request, error) {
	u := *base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	claim := hop.Claim{Client: netip.IPv4Unspecified(), Class: hop.ClassControl}
	req.Header.Set(hop.Header, a.topo.signer.Sign(claim, method, req.URL.RequestURI(), hop.BodyHash(body)))
	req.Header.Set("User-Agent", "concert-edge/"+BinaryVersion())
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (a *app) fetchLeafState(ctx context.Context, client *http.Client, base *url.URL) (hop.LeafState, error) {
	var st hop.LeafState
	req, err := a.controlRequest(ctx, http.MethodGet, base, hop.StatePath, nil)
	if err != nil {
		return st, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxStateBody))
	if err != nil {
		return st, err
	}
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("state: HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("state: %w", err)
	}
	return st, nil
}

func (a *app) pushBans(ctx context.Context, client *http.Client, base *url.URL, snap hop.BanSnapshot) error {
	body, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	req, err := a.controlRequest(ctx, http.MethodPost, base, hop.BansPath, body)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxStateBody))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bans: HTTP %d", resp.StatusCode)
	}
	return nil
}

// banSnapshot is this edge's ban list as it pushes it.
func (a *app) banSnapshot(now time.Time) hop.BanSnapshot {
	views := a.abuse.bans(now)
	bans := make([]hop.Ban, 0, len(views))
	for _, v := range views {
		b := hop.Ban{Client: v.Client, Range: v.Range, Permanent: v.Permanent}
		if !v.Permanent {
			b.Until = v.Until.Truncate(time.Second)
		}
		bans = append(bans, b)
	}
	return hop.BanSnapshot{Edge: a.topo.node, Version: hop.BanVersion(bans), At: now.UTC(), Bans: bans}
}

// edgeView is the edge's tier status for /_room/stats.
func (a *app) edgeView() gin.H {
	e := a.topo.edge
	out := gin.H{
		"leaf_backpressure_total": e.backpressure.Load(),
		"upstream_retries_total":  e.retries.Load(),
		"leaf_polls_total":        e.polls.Load(),
		"leaf_poll_errors_total":  e.pollErrors.Load(),
		"ban_pushes_total":        e.pushes.Load(),
		"ban_push_errors_total":   e.pushErrors.Load(),
	}
	if p := e.lastPlan.Load(); p != nil {
		out["leaves_usable"] = p.Leaves
		out["leaf_slots"] = p.Total
		out["planned_cap"] = p.Cap
	}
	e.mu.Lock()
	leaves := make([]gin.H, 0, len(e.leaves))
	for _, l := range e.leaves {
		h := gin.H{"url": l.url.Redacted(), "node": l.state.Node, "host_cap": l.state.HostCap,
			"share": l.state.Share(), "usable": l.state.Usable(), "error": l.err}
		if !l.at.IsZero() {
			h["seen"] = l.at.UTC().Format(time.RFC3339)
		}
		leaves = append(leaves, h)
	}
	e.mu.Unlock()
	out["leaves"] = leaves
	return out
}

// ─── leaf ────────────────────────────────────────────────────────────────────

// registerHopControl adds the leaf's control endpoints. Other roles answer
// them 404 so they never reach the application.
func registerHopControl(r *gin.Engine, g *generation) {
	r.GET(hop.StatePath, g.hopState)
	r.POST(hop.BansPath, g.hopBans)
}

// hopControlAuth verifies a control request's claim against its body.
func (g *generation) hopControlAuth(c *gin.Context, body []byte) (hop.Claim, bool) {
	t := g.a.topo
	if !t.isLeaf() {
		c.AbortWithStatus(http.StatusNotFound)
		return hop.Claim{}, false
	}
	raw := c.GetString(ctxHopRaw)
	if raw == "" {
		// No claim, or one from outside -hop-peers (already struck).
		c.AbortWithStatus(http.StatusUnauthorized)
		return hop.Claim{}, false
	}
	claim, err := t.verifier.Verify(raw, c.Request.Method, c.Request.RequestURI, hop.BodyHash(body))
	if err != nil || claim.Class != hop.ClassControl {
		t.leaf.rejected.Add(1)
		c.AbortWithStatus(http.StatusUnauthorized)
		return hop.Claim{}, false
	}
	t.leaf.sawEdge(claim.Edge, time.Now())
	return claim, true
}

func (g *generation) hopState(c *gin.Context) {
	if _, ok := g.hopControlAuth(c, nil); !ok {
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, g.a.leafReport(time.Now()))
}

// leafReport is the leaf's hop.LeafState now.
func (a *app) leafReport(now time.Time) hop.LeafState {
	g := a.current()
	l := a.topo.leaf
	st := hop.LeafState{
		Node:           a.topo.node,
		Version:        BinaryVersion(),
		At:             now.UTC(),
		HostCap:        l.gate.Cap(),
		HopInFlight:    int64(l.gate.InUse(capacity.HopPriority) + l.gate.InUse(capacity.Hop)),
		DirectInFlight: int64(l.gate.InUse(capacity.Direct)),
		QueueDepth:     a.room.LiveQueueDepth(),
		AppHealthy:     g.upstreams == nil || g.upstreams.healthyCount(now) > 0,
		Draining:       a.draining.Load(),
		EdgesSeen:      l.edgesSeen(now),
		BanVersions:    l.bans.versions(),
	}
	l.capMu.Lock()
	st.CapSource = l.capSource
	if f := l.capFile; f != nil {
		st.Bench = &hop.BenchSummary{At: f.At, Lemmings: f.Lemmings, P95Ms: f.P95Ms, PagesCovered: f.Pages, Target: f.Target}
	}
	l.capMu.Unlock()
	st.LatencyMs, st.Silence = l.monitor.view()
	if st.Silence != nil && st.Silence.Recovered.IsZero() {
		st.AppHealthy = false
	}
	return st
}

func (g *generation) hopBans(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBanBody+1))
	if err != nil || len(body) > maxBanBody {
		c.AbortWithStatus(http.StatusRequestEntityTooLarge)
		return
	}
	claim, ok := g.hopControlAuth(c, body)
	if !ok {
		return
	}
	var snap hop.BanSnapshot
	if err := json.Unmarshal(body, &snap); err != nil || snap.Edge != claim.Edge {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad snapshot"})
		return
	}
	applied, lifted := g.a.mirrorBans(snap, time.Now())
	c.JSON(http.StatusOK, gin.H{"version": snap.Version, "applied": applied, "lifted": lifted})
}

// banMirror tracks, per edge, the bans a leaf applied because that edge
// listed them, so it can lift exactly those when the edge stops listing them.
type banMirror struct {
	mu      sync.Mutex
	perEdge map[string]*edgeBans
}

type edgeBans struct {
	version string
	at      time.Time        // the newest snapshot applied
	applied map[string]int64 // ban target → the until (unix nanos, banForever) applied
}

func (m *banMirror) versions() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.perEdge))
	for e, b := range m.perEdge {
		out[e] = b.version
	}
	return out
}

// mirrorBans applies snap from its edge: every listed ban not already in
// force with the same end is applied, and every ban this edge listed before
// but no longer lists is lifted, unless the leaf has since banned the client
// itself for a different time. Exempt clients (-abuse-allow and
// -trusted-proxies on the leaf) are skipped.
func (a *app) mirrorBans(snap hop.BanSnapshot, now time.Time) (applied, lifted int) {
	m := &a.topo.leaf.bans
	m.mu.Lock()
	defer m.mu.Unlock()
	eb := m.perEdge[snap.Edge]
	if eb == nil {
		eb = &edgeBans{applied: map[string]int64{}}
		m.perEdge[snap.Edge] = eb
	}
	if !snap.At.IsZero() && snap.At.Before(eb.at) {
		return 0, 0 // a delayed push older than one already applied
	}
	if snap.At.After(eb.at) {
		eb.at = snap.At
	}

	current := map[string]int64{}
	for _, v := range a.abuse.bans(now) {
		u := banForever
		if !v.Permanent {
			u = v.Until.UnixNano()
		}
		current[v.Client] = u
	}

	listed := map[string]bool{}
	for _, b := range snap.Bans {
		t, err := parseBanTarget(b.Client)
		if err != nil {
			continue
		}
		key := t.String()
		listed[key] = true
		until := banForever
		var d time.Duration // 0 is permanent
		if !b.Permanent {
			until = b.Until.UnixNano()
			d = b.Until.Sub(now)
			if d <= 0 {
				continue
			}
		}
		if cur, ok := current[key]; ok && (cur == banForever || cur/int64(time.Second) >= until/int64(time.Second)) {
			// Already banned at least as long here.
			if _, mine := eb.applied[key]; !mine {
				continue
			}
			eb.applied[key] = cur
			continue
		}
		if t.single {
			if _, err := a.abuse.banFor(t.prefix.Addr(), d, now); err != nil {
				continue
			}
		} else if err := a.abuse.banRange(t.prefix, d, now); err != nil {
			continue
		}
		after := until
		if !b.Permanent {
			// Re-read what the registry stored, so a later lift matches.
			for _, v := range a.abuse.bans(now) {
				if v.Client == key && !v.Permanent {
					after = v.Until.UnixNano()
					break
				}
			}
		}
		eb.applied[key] = after
		applied++
	}
	for key, until := range eb.applied {
		if listed[key] {
			continue
		}
		delete(eb.applied, key)
		cur, ok := current[key]
		if !ok || cur != until {
			continue // expired, lifted already, or re-banned locally
		}
		if t, err := parseBanTarget(key); err == nil && a.abuse.unbanTarget(t) {
			lifted++
		}
	}
	eb.version = snap.Version
	if applied+lifted > 0 {
		a.saveBansNow()
		log.Printf("leaf: mirrored edge %s bans: %d applied, %d lifted (%d listed)", snap.Edge, applied, lifted, len(snap.Bans))
	}
	return applied, lifted
}

// leafView is the leaf's tier status for /_room/stats.
func (a *app) leafView(now time.Time) gin.H {
	l := a.topo.leaf
	st := a.leafReport(now)
	return gin.H{
		"host_cap":               st.HostCap,
		"host_cap_source":        st.CapSource,
		"hop_in_flight":          st.HopInFlight,
		"direct_in_flight":       st.DirectInFlight,
		"hop_waiting":            l.gate.Waiting(capacity.HopPriority) + l.gate.Waiting(capacity.Hop),
		"direct_waiting":         l.gate.Waiting(capacity.Direct),
		"hop_accepted_total":     l.accepted.Load(),
		"hop_rejected_total":     l.rejected.Load(),
		"hop_backpressure_total": l.backpressed.Load(),
		"edges_seen":             st.EdgesSeen,
		"app_healthy":            st.AppHealthy,
		"last_silence":           st.Silence,
	}
}
