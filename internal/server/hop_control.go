//go:build enterprise

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/concert/internal/capacity"
	"github.com/andreimerlescu/concert/internal/hop"
	"github.com/andreimerlescu/concert/internal/mailer"
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
// otherwise -cap. room v1.6.0 / sema v1.2.0 preserve in-flight occupancy on
// shrink and grant no new slots until occupancy falls below the new cap.
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
	return int32(n)
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
				prevErr := l.err
				if prevErr != err.Error() {
					log.Printf("edge: leaf %s: %v", l.url.Redacted(), err)
				}
				l.err = err.Error()
				e.mu.Unlock()
				if prevErr == "" {
					a.notifyEvent(mailer.Event{
						Category:    mailer.CatCapacity,
						Severity:    mailer.SevWarn,
						Title:       "Leaf node unreachable",
						Summary:     fmt.Sprintf("Edge %s failed to poll leaf %s: %v", a.topo.node, l.url.Redacted(), err),
						Fingerprint: "leaf-down:" + l.url.Redacted(),
						Details:     map[string]string{"leaf": l.url.Redacted(), "error": err.Error()},
					})
				}
				return
			}
			prevErr := l.err
			if prevErr != "" || l.at.IsZero() {
				log.Printf("edge: leaf %s (%s) reachable, host capacity %d (%s)", l.url.Redacted(), st.Node, st.HostCap, st.CapSource)
			}
			l.state, l.at, l.err = st, asked, ""
			e.mu.Unlock()
			if prevErr != "" {
				a.notifyEvent(mailer.Event{
					Category:    mailer.CatCapacity,
					Severity:    mailer.SevInfo,
					Title:       "Leaf node recovered",
					Summary:     fmt.Sprintf("Leaf %s (%s) is reachable again with host capacity %d (%s).", l.url.Redacted(), st.Node, st.HostCap, st.CapSource),
					Fingerprint: "leaf-up:" + l.url.Redacted(),
					Details:     map[string]string{"leaf": l.url.Redacted(), "node": st.Node, "host_cap": fmt.Sprintf("%d", st.HostCap)},
				})
			}
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
	shares := map[string]int64{}
	for k, l := range e.leaves {
		r := capacity.Report{Leaf: k, Share: l.state.Share(), Usable: l.state.Usable(), At: l.at}
		reports = append(reports, r)
		if r.Usable && !l.at.IsZero() && now.Sub(l.at) <= e.planner.Expire {
			shares[hostKey(l.url)] = int64(r.Share)
		} else {
			shares[hostKey(l.url)] = leafUnusable
		}
	}
	e.mu.Unlock()

	e.planner.SetLimits(cfg.capacity, cfg.effectivePriorityCap())
	plan := e.planner.Plan(reports, now)
	e.lastPlan.Store(&plan)
	if plan.Leaves > 0 && !e.everUsable.Swap(true) {
		log.Printf("edge: %d leaf(s) usable, %d page slot(s); admitting up to %d", plan.Leaves, plan.Total, plan.Cap)
	} else if plan.Leaves == 0 && e.everUsable.Load() {
		a.notifyEvent(mailer.Event{
			Category:    mailer.CatCapacity,
			Severity:    mailer.SevCritical,
			Title:       "All leaf nodes unavailable",
			Summary:     fmt.Sprintf("Edge %s has 0 usable leaves remaining across %d configured target(s).", a.topo.node, len(urls)),
			Fingerprint: "edge:no-leaves",
			Details:     map[string]string{"edge": a.topo.node, "configured_leaves": fmt.Sprintf("%d", len(urls))},
		})
	}
	if cfg.hopAutoCap {
		target := a.edgeCap(cfg)
		if cur := a.room.Cap(); target != cur {
			if err := a.room.SetCap(target); err == nil && (target < cur/2 || target > cur*2 || target == 1) {
				log.Printf("edge: room capacity %d -> %d (leaves offer %d, lane %d)", cur, target, plan.Total, cfg.effectivePriorityCap())
				if target < cur/2 || (target == 1 && cur > 1) {
					a.notifyEvent(mailer.Event{
						Category:    mailer.CatCapacity,
						Severity:    mailer.SevWarn,
						Title:       "Edge room capacity reduced",
						Summary:     fmt.Sprintf("Edge %s reduced waiting room capacity from %d to %d (%d usable leaves offering %d slots).", a.topo.node, cur, target, plan.Leaves, plan.Total),
						Fingerprint: "edge:cap-drop",
						Details: map[string]string{
							"previous_cap": fmt.Sprintf("%d", cur),
							"new_cap":      fmt.Sprintf("%d", target),
							"leaves":       fmt.Sprintf("%d", plan.Leaves),
							"leaf_slots":   fmt.Sprintf("%d", plan.Total),
						},
					})
				}
			}
		}
	}
	// Leaves the edge balances across itself get slot-aware routing.
	if g.upstreams != nil {
		for _, b := range g.upstreams.backends {
			b.slots.Store(shares[hostKey(b.target)])
		}
	}
	return plan
}

// hostKey matches a control URL to an upstream target.
func hostKey(u *url.URL) string {
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// controlRequest signs a ctl claim for method on base+path with body.
// path may include a query string (e.g. "/_room/hop/state?demand=12"), which
// is bound into the HMAC via RequestURI.
func (a *app) controlRequest(ctx context.Context, method string, base *url.URL, path string, body []byte) (*http.Request, error) {
	u := *base
	p, q, _ := strings.Cut(path, "?")
	u.Path = strings.TrimSuffix(u.Path, "/") + p
	u.RawQuery = q
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
	var demand int64
	if a.room != nil {
		demand = int64(a.room.Len()) + a.room.LiveQueueDepth()
	}
	path := hop.StatePath
	if demand > 0 {
		path = fmt.Sprintf("%s?demand=%d", hop.StatePath, demand)
	}
	req, err := a.controlRequest(ctx, http.MethodGet, base, path, nil)
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
		h := gin.H{
			"url":              l.url.Redacted(),
			"node":             l.state.Node,
			"host_cap":         l.state.HostCap,
			"cap_source":       l.state.CapSource,
			"share":            l.state.Share(),
			"edges_seen":       l.state.EdgesSeen,
			"hop_in_flight":    l.state.HopInFlight,
			"direct_in_flight": l.state.DirectInFlight,
			"latency_ms":       l.state.LatencyMs,
			"app_healthy":      l.state.AppHealthy,
			"draining":         l.state.Draining,
			"rebenchmarking":   l.state.Rebenchmarking,
			"usable":           l.state.Usable(),
			"error":            l.err,
		}
		if l.state.Bench != nil {
			h["bench"] = l.state.Bench
		}
		if l.state.Silence != nil {
			h["last_silence"] = l.state.Silence
		}
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
	r.POST(hop.RebenchPath, g.hopRebench)
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
	if g.cfg.hopRequireMTLS && (c.Request.TLS == nil || len(c.Request.TLS.VerifiedChains) == 0) {
		t.leaf.rejected.Add(1)
		t.leaf.mtlsRejected.Add(1)
		c.AbortWithStatus(http.StatusUnauthorized)
		return hop.Claim{}, false
	}
	claim, err := t.verifier.Verify(raw, c.Request.Method, c.Request.RequestURI, hop.BodyHash(body))
	if err != nil || claim.Class != hop.ClassControl {
		t.leaf.rejected.Add(1)
		if errors.Is(err, hop.ErrReplay) {
			t.leaf.replayed.Add(1)
		}
		c.AbortWithStatus(http.StatusUnauthorized)
		return hop.Claim{}, false
	}
	t.leaf.sawEdge(claim.Edge, time.Now())
	return claim, true
}

func (g *generation) hopState(c *gin.Context) {
	claim, ok := g.hopControlAuth(c, nil)
	if !ok {
		return
	}
	now := time.Now()
	var demand int64
	if raw := c.Query("demand"); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil && v > 0 {
			demand = v
		}
	}
	g.a.topo.leaf.sawEdgePoll(claim.Edge, demand, now)
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, g.a.leafReportFor(claim.Edge, now))
}

// leafReport is the leaf's hop.LeafState now.
func (a *app) leafReport(now time.Time) hop.LeafState {
	return a.leafReportFor("", now)
}

func (a *app) leafReportFor(edge string, now time.Time) hop.LeafState {
	g := a.current()
	l := a.topo.leaf
	hostCap := l.gate.Cap()
	edgesSeen, shares := l.edgeShares(hostCap, now)
	st := hop.LeafState{
		Node:           a.topo.node,
		Version:        BinaryVersion(),
		At:             now.UTC(),
		HostCap:        hostCap,
		HopInFlight:    int64(l.gate.InUse(capacity.HopPriority) + l.gate.InUse(capacity.Hop)),
		DirectInFlight: int64(l.gate.InUse(capacity.Direct)),
		QueueDepth:     a.room.LiveQueueDepth(),
		AppHealthy:     g.upstreams == nil || g.upstreams.healthyCount(now) > 0,
		Draining:       a.draining.Load() || l.rebenchmarking.Load(),
		Rebenchmarking: l.rebenchmarking.Load(),
		EdgesSeen:      edgesSeen,
		EdgeShares:     shares,
		BanVersions:    l.bans.versions(),
	}
	if edge != "" && shares != nil {
		st.YourShare = shares[edge]
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

func (g *generation) hopRebench(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 4096))
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if _, ok := g.hopControlAuth(c, body); !ok {
		return
	}
	var req struct {
		DrainWaitSeconds int `json:"drain_wait_seconds"`
	}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &req)
	}
	drainWait := time.Duration(req.DrainWaitSeconds) * time.Second
	res, status, err := g.a.rebenchLeaf(c.Request.Context(), drainWait)
	if err != nil {
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, res)
}

// triggerLeafRebench sends a signed drained re-benchmark command from an edge
// to one configured leaf (matched by URL or node ID). Unless force is true,
// it refuses to drain the last currently usable leaf so live site capacity
// cannot accidentally drop to zero.
func (a *app) triggerLeafRebench(ctx context.Context, leafTarget string, force bool, drainWait time.Duration) (hop.RebenchResult, int, error) {
	var res hop.RebenchResult
	if !a.topo.isEdge() {
		return res, http.StatusBadRequest, errors.New("edge leaf targeting requires -role edge")
	}
	leafTarget = strings.TrimSpace(leafTarget)
	if leafTarget == "" {
		return res, http.StatusBadRequest, errors.New("leaf URL or node ID is required on edge nodes")
	}
	e := a.topo.edge
	var targetURL *url.URL
	var targetUsable bool
	usableCount := 0
	e.mu.Lock()
	for _, l := range e.leaves {
		u := l.state.Usable() && l.err == "" && !l.at.IsZero()
		if u {
			usableCount++
		}
		if l.url.Redacted() == leafTarget || l.url.String() == leafTarget || (l.state.Node != "" && l.state.Node == leafTarget) {
			cp := *l.url
			targetURL = &cp
			targetUsable = u
		}
	}
	e.mu.Unlock()

	if targetURL == nil {
		return res, http.StatusNotFound, fmt.Errorf("leaf %q is not in this edge's configured leaves", leafTarget)
	}
	if targetUsable && usableCount <= 1 && !force {
		return res, http.StatusConflict, errors.New("refusing to drain the last usable leaf; pass force=true to override")
	}

	g := a.current()
	timeout := max(2*time.Minute, g.cfg.benchP95*20)
	client := g.controlClient(timeout)
	body, _ := json.Marshal(map[string]int{"drain_wait_seconds": int(drainWait.Seconds())})
	req, err := a.controlRequest(ctx, http.MethodPost, targetURL, hop.RebenchPath, body)
	if err != nil {
		return res, http.StatusInternalServerError, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return res, http.StatusBadGateway, fmt.Errorf("contact leaf %s: %w", targetURL.Redacted(), err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxStateBody))
	if resp.StatusCode != http.StatusOK {
		var errObj struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &errObj) == nil && errObj.Error != "" {
			return res, resp.StatusCode, errors.New(errObj.Error)
		}
		return res, resp.StatusCode, fmt.Errorf("leaf returned HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return res, http.StatusBadGateway, fmt.Errorf("decode re-benchmark result: %w", err)
	}
	// Immediately refresh leaf state so the edge absorbs the new host capacity.
	pollCtx, cancel := context.WithTimeout(context.Background(), g.cfg.hopPoll)
	a.edgeRound(pollCtx)
	cancel()
	return res, http.StatusOK, nil
}

// banMirror tracks, per edge, the bans a leaf applied because that edge
// listed them, so it can lift exactly those when the edge stops listing them.
//
// With -data-dir the record is kept in hop-bans.json beside bans.json.
// bans.json keeps the bans across a restart; without this record a
// restarted leaf would hold the edge's bans as its own and never lift them.
// The applied version is not kept, so an edge pushes its list again after a
// leaf restarts.
type banMirror struct {
	mu      sync.Mutex
	perEdge map[string]*edgeBans
	path    string // hop-bans.json, or "" without -data-dir
}

// mirrorFileName is the leaf's record of mirrored bans in -data-dir.
const (
	mirrorFileName    = "hop-bans.json"
	mirrorFileVersion = 1
)

type mirrorFile struct {
	Version int                     `json:"version"`
	Edges   map[string]mirrorRecord `json:"edges"`
}

type mirrorRecord struct {
	At      time.Time        `json:"at"`
	Applied map[string]int64 `json:"applied"` // ban target → until (unix nanos, banForever)
}

// load restores the record at m.path. A missing file is an empty record. An
// unreadable or corrupt one is logged and ignored: the bans themselves are
// in bans.json, and an empty record only means the leaf lifts nothing it
// cannot prove an edge applied.
func (m *banMirror) load() {
	if m.path == "" {
		return
	}
	data, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	var f mirrorFile
	if err == nil {
		err = json.Unmarshal(data, &f)
	}
	if err == nil && f.Version > mirrorFileVersion {
		err = fmt.Errorf("written by a newer concert (version %d)", f.Version)
	}
	if err != nil {
		log.Printf("leaf: ignoring %s: %v; bans mirrored before this start are kept as the leaf's own", m.path, err)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for edge, r := range f.Edges {
		if !hop.ValidNodeID(edge) {
			continue
		}
		eb := &edgeBans{at: r.At, applied: map[string]int64{}}
		for key, until := range r.Applied {
			if t, err := parseBanTarget(key); err == nil && t.String() == key {
				eb.applied[key] = until
			}
		}
		m.perEdge[edge] = eb
	}
}

// saveLocked writes the record. Called with m.mu held, after bans.json.
func (m *banMirror) saveLocked() {
	if m.path == "" {
		return
	}
	f := mirrorFile{Version: mirrorFileVersion, Edges: make(map[string]mirrorRecord, len(m.perEdge))}
	for edge, eb := range m.perEdge {
		f.Edges[edge] = mirrorRecord{At: eb.at, Applied: eb.applied}
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err == nil {
		err = writeFileAtomic(m.path, append(data, '\n'))
	}
	if err != nil {
		log.Printf("leaf: cannot save %s: %v", m.path, err)
	}
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
	// Edges push only when a leaf's version differs, so this write is rare.
	m.saveLocked()
	return applied, lifted
}

// leafView is the leaf's tier status for /_room/stats.
func (a *app) leafView(now time.Time) gin.H {
	l := a.topo.leaf
	st := a.leafReport(now)
	out := gin.H{
		"host_cap":                   st.HostCap,
		"host_cap_source":            st.CapSource,
		"hop_in_flight":              st.HopInFlight,
		"direct_in_flight":           st.DirectInFlight,
		"hop_waiting":                l.gate.Waiting(capacity.HopPriority) + l.gate.Waiting(capacity.Hop),
		"direct_waiting":             l.gate.Waiting(capacity.Direct),
		"hop_accepted_total":         l.accepted.Load(),
		"hop_rejected_total":         l.rejected.Load(),
		"hop_replayed_total":         l.replayed.Load(),
		"hop_replay_evictions_total": l.replayEvictions.Load(),
		"hop_mtls_rejected_total":    l.mtlsRejected.Load(),
		"hop_backpressure_total":     l.backpressed.Load(),
		"edges_seen":                 st.EdgesSeen,
		"edge_shares":                st.EdgeShares,
		"app_healthy":                st.AppHealthy,
		"draining":                   st.Draining,
		"rebenchmarking":             st.Rebenchmarking,
		"rebench_total":              l.rebenchTotal.Load(),
		"latency_ms":                 st.LatencyMs,
		"last_silence":               st.Silence,
	}
	if st.Bench != nil {
		out["bench"] = st.Bench
	}
	return out
}
