package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/hop"
)

// startLeafIn starts a leaf whose state lives in dir, as a restart would.
func startLeafIn(t *testing.T, origin, dir string) *app {
	t.Helper()
	cfg := tierConfig(origin)
	cfg.role, cfg.hopPeers, cfg.nodeID = roleLeaf, "127.0.0.1/32", "leaf-restart"
	cfg.hostCap = 10
	cfg.dataDir = dir
	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func snapshotOf(at time.Time, bans ...hop.Ban) hop.BanSnapshot {
	s := hop.BanSnapshot{Edge: "edge-1", At: at, Bans: bans}
	s.Version = hop.BanVersion(bans)
	return s
}

// A ban a leaf mirrored from its edge is still the edge's after the leaf
// restarts: when the edge lifts it, the leaf lifts it too. Before, the
// restarted leaf treated every mirrored ban as its own and kept it forever,
// so a visitor the operator unbanned at the edge stayed locked out of every
// hop request (the leaf checks bans against the claim's client).
func TestTier_MirroredBansSurviveLeafRestart(t *testing.T) {
	origin := newTierOrigin(t, "app")
	dir := t.TempDir()
	bot := netip.MustParseAddr("203.0.113.9")
	own := netip.MustParseAddr("203.0.113.50")
	t0 := time.Now()

	leaf := startLeafIn(t, origin.srv.URL, dir)
	if applied, _ := leaf.mirrorBans(snapshotOf(t0, hop.Ban{Client: bot.String(), Permanent: true}), t0); applied != 1 {
		t.Fatalf("applied %d, want 1", applied)
	}
	if _, err := leaf.abuse.banFor(own, time.Hour, t0); err != nil {
		t.Fatal(err)
	}
	leaf.Close()

	leaf = startLeafIn(t, origin.srv.URL, dir)
	defer leaf.Close()
	if _, banned := leaf.abuse.banned(bot, time.Now()); !banned {
		t.Fatal("restart lost the mirrored ban")
	}
	if v := leaf.topo.leaf.bans.versions()["edge-1"]; v != "" {
		t.Fatalf("restored version %q: the edge must re-push after a restart", v)
	}
	// The edge re-pushes its unchanged list after the restart, then lifts.
	t1 := t0.Add(time.Second)
	if applied, lifted := leaf.mirrorBans(snapshotOf(t1, hop.Ban{Client: bot.String(), Permanent: true}), t1); applied != 0 || lifted != 0 {
		t.Fatalf("re-push applied %d lifted %d, want 0 0", applied, lifted)
	}
	t2 := t1.Add(time.Second)
	if _, lifted := leaf.mirrorBans(snapshotOf(t2), t2); lifted != 1 {
		t.Fatalf("lifted %d, want the edge's ban lifted", lifted)
	}
	if _, banned := leaf.abuse.banned(bot, time.Now()); banned {
		t.Fatal("leaf kept a ban the edge lifted after the leaf restarted")
	}
	if _, banned := leaf.abuse.banned(own, time.Now()); !banned {
		t.Fatal("leaf lost its own ban")
	}

	st, err := os.Stat(filepath.Join(dir, mirrorFileName))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode %v, want 0600", mirrorFileName, st.Mode().Perm())
	}
}

// Without the ownership record, the restarted leaf behaves as before: it
// keeps what it has and lifts nothing it cannot prove the edge applied. A
// corrupt record is reported and ignored, never fatal.
func TestTier_MirrorFileCorruptIsIgnored(t *testing.T) {
	origin := newTierOrigin(t, "app")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, mirrorFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	leaf := startLeafIn(t, origin.srv.URL, dir)
	defer leaf.Close()
	now := time.Now()
	if applied, _ := leaf.mirrorBans(snapshotOf(now, hop.Ban{Client: "203.0.113.7", Permanent: true}), now); applied != 1 {
		t.Fatalf("applied %d after a corrupt ownership file", applied)
	}
}

// Why a stuck mirrored ban matters: a leaf checks its bans against the
// client the edge's claim names, so a client banned on the leaf is refused
// on every request that comes through the edge, not only direct ones.
func TestTier_LeafBanRefusesClientThroughEdge(t *testing.T) {
	origin := newTierOrigin(t, "app")
	leafApp, leaf := newLeaf(t, origin.srv.URL, nil)
	edgeApp, edge := newEdge(t, []string{leaf.URL}, nil)
	round(t, edgeApp)
	client := tierClient(t)
	getOK(t, client, edge.URL+"/")

	visitor := netip.MustParseAddr("127.0.0.1") // the test client, as the edge's claim names it
	if _, err := leafApp.abuse.banFor(visitor, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(edge.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a client banned on the leaf was served through the edge")
	}
	if _, banned := edgeApp.abuse.banned(visitor, time.Now()); banned {
		t.Fatal("the edge itself banned the client; the refusal must come from the leaf")
	}
}

// Only a leaf may say Concert-Backpressure. An application's own 503 that
// happens to carry the header reached the application already, so the edge
// must not take it for a refusal and send the request again to another
// leaf; and the header never reaches a client of a leaf or standalone node.
func TestTier_ApplicationCannotSignalBackpressure(t *testing.T) {
	var hitsA, hitsB atomic.Int64
	app := func(hits *atomic.Int64) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.Header().Set(hop.BackpressureHeader, "full")
			w.Header().Set(hop.NodeHeader, "app")
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		t.Cleanup(s.Close)
		return s
	}
	originA, originB := app(&hitsA), app(&hitsB)
	_, leafA := newLeaf(t, originA.URL, nil)
	_, leafB := newLeaf(t, originB.URL, nil)
	edgeApp, edge := newEdge(t, []string{leafA.URL, leafB.URL}, func(c *config) { c.hopPoll = time.Minute })
	round(t, edgeApp)

	resp, err := tierClient(t).Get(edge.URL + "/busy")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want the application's 503", resp.StatusCode)
	}
	if n := hitsA.Load() + hitsB.Load(); n != 1 {
		t.Fatalf("the applications got the request %d times; the edge re-sent a request that was already served", n)
	}
	if n := edgeApp.topo.edge.retries.Load(); n != 0 {
		t.Fatalf("edge retried %d times on an application's answer", n)
	}

	// A direct client of the leaf never sees the tier header either.
	resp, err = http.Get(leafA.URL + "/busy")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if v := resp.Header.Get(hop.BackpressureHeader); v != "" {
		t.Fatalf("a leaf passed the application's %s: %q to its client", hop.BackpressureHeader, v)
	}
}

// On a standalone or leaf node with multiple application upstreams, an origin's
// 503 carrying Concert-Backpressure is still an application answer: it must
// not trigger a duplicate retry to another upstream and must still count
// toward the circuit breaker.
func TestTier_NonEdgeIgnoresOriginBackpressureMultiUpstream(t *testing.T) {
	for _, role := range []string{roleStandalone, roleLeaf} {
		t.Run(role, func(t *testing.T) {
			var hitsA, hitsB atomic.Int64
			mkApp := func(hits *atomic.Int64) *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					w.Header().Set(hop.BackpressureHeader, "full")
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				t.Cleanup(s.Close)
				return s
			}
			appA, appB := mkApp(&hitsA), mkApp(&hitsB)
			cfg := testConfig(appA.URL + "," + appB.URL)
			cfg.role = role
			cfg.upstreamRetries = 1
			cfg.upstreamCBFailures = 2
			cfg.upstreamCBCooldown = time.Minute
			if role == roleLeaf {
				cfg.hopSecret = testHopSecret
				cfg.hopPeers = "127.0.0.1/32"
				cfg.nodeID = "leaf-multi"
				cfg.hostCap = 10
			}
			a, srv := newTestApp(t, cfg, nil)

			resp, err := tierClient(t).Get(srv.URL + "/x")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("status %d, want 503", resp.StatusCode)
			}
			if got := hitsA.Load() + hitsB.Load(); got != 1 {
				t.Fatalf("%s retried application 503 with Concert-Backpressure: total origin hits %d, want 1", role, got)
			}
			if v := resp.Header.Get(hop.BackpressureHeader); v != "" {
				t.Fatalf("%s leaked %s: %q", role, hop.BackpressureHeader, v)
			}
			if a.stats.upstreamUnavail.Load() != 1 {
				t.Fatalf("upstreamUnavail %d, want 1", a.stats.upstreamUnavail.Load())
			}
			failures := 0
			for _, b := range a.current().upstreams.backends {
				b.mu.Lock()
				failures += b.failures
				b.mu.Unlock()
			}
			if failures != 1 {
				t.Fatalf("circuit-breaker failures %d, want 1", failures)
			}
		})
	}
}

// Application 500s mean the application is still answering: repeated 500s on
// a quiet site must not mark the leaf silent and pull its capacity from the
// edge. 502–504 or transport errors do mark it silent.
func TestTier_SilenceIgnoresApp500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bug" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	leafApp, leaf := newLeaf(t, srv.URL, func(c *config) {
		c.upstreamCBFailures = 0 // isolate silence monitor from circuit breaker
	})
	start := time.Now()
	leafApp.leafTick(start)

	client := tierClient(t)
	for i := 0; i < 5; i++ {
		resp, err := client.Get(leaf.URL + "/bug")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	leafApp.leafTick(start.Add(time.Second))
	if st := leafApp.leafReport(time.Now()); !st.AppHealthy || st.Silence != nil {
		t.Fatalf("app 500s tripped silence: healthy=%v silence=%+v", st.AppHealthy, st.Silence)
	}

	for i := 0; i < 5; i++ {
		resp, err := client.Get(leaf.URL + "/down")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	leafApp.leafTick(start.Add(2 * time.Second))
	if st := leafApp.leafReport(time.Now()); st.AppHealthy || st.Silence == nil {
		t.Fatalf("503s did not trip silence: healthy=%v silence=%+v", st.AppHealthy, st.Silence)
	}
}

// silence.jsonl rotates once it exceeds silenceLogMaxBytes and keeps 0600 mode.
func TestTier_SilenceLogRotates(t *testing.T) {
	defer func(old int64) { silenceLogMaxBytes = old }(silenceLogMaxBytes)
	silenceLogMaxBytes = 200

	origin := newTierOrigin(t, "app")
	dir := t.TempDir()
	leafApp, _ := newLeaf(t, origin.srv.URL, func(c *config) { c.dataDir = dir })
	now := time.Now()
	leafApp.leafTick(now)
	for i := 1; i <= 4; i++ {
		leafApp.stats.upstreamUnavail.Add(5)
		leafApp.stats.upstream5xx.Add(5)
		leafApp.leafTick(now.Add(time.Duration(2*i-1) * time.Second))
		leafApp.stats.upstream2xx.Add(1)
		leafApp.leafTick(now.Add(time.Duration(2*i) * time.Second))
	}
	for _, name := range []string{silenceFile, silenceFile + ".1"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s missing after rotation: %v", name, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v, want 0600", name, fi.Mode().Perm())
		}
	}
}

// Heterogeneous leaves report distinct capacities (e.g. 369, 434, 144). When
// one leaf becomes unusable (draining or silent), the edge stops routing to
// it immediately while keeping slot-aware routing across the remaining leaves.
func TestTier_HeterogeneousLeavesAndDrainingFailover(t *testing.T) {
	var hits1, hits2, hits3 atomic.Int64
	mkOrigin := func(hits *atomic.Int64) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(s.Close)
		return s
	}
	o1, o2, o3 := mkOrigin(&hits1), mkOrigin(&hits2), mkOrigin(&hits3)
	_, leaf1 := newLeaf(t, o1.URL, func(c *config) { c.hostCap = 369; c.nodeID = "leaf-369" })
	_, leaf2 := newLeaf(t, o2.URL, func(c *config) { c.hostCap = 434; c.nodeID = "leaf-434" })
	leafApp3, leaf3 := newLeaf(t, o3.URL, func(c *config) { c.hostCap = 144; c.nodeID = "leaf-144" })

	edgeApp, edge := newEdge(t, []string{leaf1.URL, leaf2.URL, leaf3.URL}, func(c *config) {
		c.capacity = 1000
		c.priorityCap = 47
		c.hopPoll = time.Minute
	})
	plan := round(t, edgeApp)
	if plan.Leaves != 3 || plan.Total != 369+434+144 || plan.Cap != 900 {
		t.Fatalf("plan %+v, want 3 leaves total 947 cap 900", plan)
	}
	// Transport pool scales up to hold keep-alive connections for high cap.
	tr := edgeApp.current().upstreams.transport
	if tr.MaxIdleConnsPerHost < 1047 || tr.MaxIdleConns < 3*1047 {
		t.Fatalf("transport idle pool too small: perHost=%d total=%d", tr.MaxIdleConnsPerHost, tr.MaxIdleConns)
	}

	// Mark the 144-slot leaf draining; the edge must stop routing to it and
	// preserve slot-aware routing across the 369-slot and 434-slot leaves.
	leafApp3.draining.Store(true)
	plan = round(t, edgeApp)
	if plan.Leaves != 2 || plan.Total != 369+434 {
		t.Fatalf("after drain: plan %+v, want 2 leaves total 803", plan)
	}
	if got := edgeApp.current().upstreams.backends[2].slots.Load(); got != leafUnusable {
		t.Fatalf("draining leaf slots %d, want leafUnusable (%d)", got, leafUnusable)
	}

	client := tierClient(t)
	for i := 0; i < 15; i++ {
		getOK(t, client, edge.URL+"/check")
	}
	if hits3.Load() != 0 {
		t.Fatalf("draining leaf received %d requests, want 0", hits3.Load())
	}
	if hits2.Load() == 0 {
		t.Fatalf("largest healthy leaf (434 slots) received 0 requests (hits1=%d hits2=%d)", hits1.Load(), hits2.Load())
	}
}
