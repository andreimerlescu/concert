package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/bench"
	"github.com/andreimerlescu/concert/internal/capacity"
	"github.com/andreimerlescu/concert/internal/hop"
	"github.com/andreimerlescu/concert/internal/testsite"
)

var testHopSecret = []byte("hop-test-secret-0123456789abcdef-xyz")

// tierOrigin is an application behind a leaf. It records what reached it.
type tierOrigin struct {
	srv  *httptest.Server
	hits atomic.Int64

	mu   sync.Mutex
	last http.Header
	path string
}

func newTierOrigin(t *testing.T, name string) *tierOrigin {
	t.Helper()
	o := &tierOrigin{}
	o.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.hits.Add(1)
		o.mu.Lock()
		o.last = r.Header.Clone()
		o.path = r.URL.RequestURI()
		o.mu.Unlock()
		switch {
		case r.URL.Path == "/prio":
			w.Header().Set("Concert-Priority", "checkout; ttl=30m")
		case r.URL.Path == "/fail":
			w.WriteHeader(http.StatusBadGateway)
			return
		case strings.HasPrefix(r.URL.Path, "/static/"):
			w.Header().Set("Content-Type", "text/css")
			_, _ = io.WriteString(w, "body{}")
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, name)
	}))
	t.Cleanup(o.srv.Close)
	return o
}

func (o *tierOrigin) lastHeader() http.Header {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.last
}

func tierConfig(upstream string) config {
	cfg := testConfig(upstream)
	cfg.hopSecret = testHopSecret
	cfg.hopPoll = 500 * time.Millisecond
	cfg.hopWait = 0
	cfg.upstreamRetries = 1
	cfg.priorityLaneRank = int(rankCustomer)
	return cfg
}

func newLeaf(t *testing.T, origin string, mutate func(*config)) (*app, *httptest.Server) {
	t.Helper()
	cfg := tierConfig(origin)
	cfg.role = roleLeaf
	cfg.nodeID = "leaf-" + strings.ReplaceAll(t.Name(), "/", "-")
	if len(cfg.nodeID) > 32 {
		cfg.nodeID = cfg.nodeID[:32]
	}
	cfg.hopPeers = "127.0.0.0/8,::1/128"
	cfg.hostCap = 10
	if mutate != nil {
		mutate(&cfg)
	}
	return newTestApp(t, cfg, nil)
}

func newEdge(t *testing.T, leaves []string, mutate func(*config)) (*app, *httptest.Server) {
	t.Helper()
	cfg := tierConfig(strings.Join(leaves, ","))
	cfg.role = roleEdge
	cfg.nodeID = "edge-1"
	cfg.hopAutoCap = true
	cfg.capacity = 100
	cfg.priorityCap = 2
	if mutate != nil {
		mutate(&cfg)
	}
	return newTestApp(t, cfg, nil)
}

func tierClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

func getOK(t *testing.T, c *http.Client, u string) *http.Response {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func round(t *testing.T, a *app) capacity.Plan {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return a.edgeRound(ctx)
}

func countSetCookie(h http.Header, name string) int {
	n := 0
	for _, v := range h.Values("Set-Cookie") {
		if strings.HasPrefix(v, name+"=") {
			n++
		}
	}
	return n
}

// The edge signs a claim, the leaf passes the request straight through, and
// the application sees the real client and nothing of the tiers.
func TestTier_EdgeToLeafPassThrough(t *testing.T) {
	origin := newTierOrigin(t, "app")
	leafApp, leaf := newLeaf(t, origin.srv.URL, nil)
	_, edge := newEdge(t, []string{leaf.URL}, nil)

	c := tierClient(t)
	resp, err := c.Get(edge.URL + "/products/42?x=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "app" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if n := countSetCookie(resp.Header, admitCookie); n != 1 {
		t.Fatalf("browser got %d %s cookies, want exactly the edge's one", n, admitCookie)
	}
	for _, h := range []string{hop.Header, hop.NodeHeader, hop.BackpressureHeader} {
		if resp.Header.Get(h) != "" {
			t.Errorf("browser saw %s", h)
		}
	}
	got := origin.lastHeader()
	if got.Get(hop.Header) != "" {
		t.Error("application saw the Concert-Hop header")
	}
	if xff := got.Get("X-Forwarded-For"); !strings.HasPrefix(xff, "127.0.0.1") {
		t.Errorf("application X-Forwarded-For %q does not start with the client", xff)
	}
	if strings.Contains(got.Get("Cookie"), admitCookie) {
		t.Error("application saw a Concert cookie")
	}
	if n := leafApp.topo.leaf.accepted.Load(); n != 1 {
		t.Errorf("leaf accepted %d claims, want 1", n)
	}
	if leafApp.room.Len() != 0 || leafApp.stats.queued.Load() != 0 {
		t.Error("leaf used its waiting room for a hop request")
	}
}

// The application's Concert-Priority header crosses the leaf untouched and
// becomes the edge's grant, bound to the edge's pass.
func TestTier_PriorityReachesEdge(t *testing.T) {
	origin := newTierOrigin(t, "app")
	leafApp, leaf := newLeaf(t, origin.srv.URL, nil)
	edgeApp, edge := newEdge(t, []string{leaf.URL}, nil)

	c := tierClient(t)
	resp := getOK(t, c, edge.URL+"/prio")
	if resp.Header.Get("Concert-Priority") != "" {
		t.Fatal("browser saw Concert-Priority")
	}
	if countSetCookie(resp.Header, priorityCookie) != 1 {
		t.Fatal("edge did not grant the rank")
	}
	if leafApp.prio.grants.issued.Load() != 0 {
		t.Fatal("leaf consumed the priority header")
	}
	u, _ := url.Parse(edge.URL)
	req := httptest.NewRequest(http.MethodGet, edge.URL+"/", nil)
	for _, ck := range c.Jar.Cookies(u) {
		req.AddCookie(ck)
	}
	if r := edgeApp.prio.grants.rankOf(req, time.Now()); r != rankCheckout {
		t.Fatalf("edge rank %v, want checkout", r)
	}
}

// A client cannot smuggle its own claim through an edge.
func TestTier_EdgeReplacesClientClaim(t *testing.T) {
	origin := newTierOrigin(t, "app")
	leafApp, leaf := newLeaf(t, origin.srv.URL, nil)
	_, edge := newEdge(t, []string{leaf.URL}, nil)

	s, _ := hop.NewSigner(testHopSecret, "edge-1")
	forged := s.Sign(hop.Claim{Client: netip.MustParseAddr("9.9.9.9"), Rank: 6, Paid: true, Class: hop.ClassPage}, "GET", "/", "")
	req, _ := http.NewRequest(http.MethodGet, edge.URL+"/", nil)
	req.Header.Set(hop.Header, forged)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if xff := origin.lastHeader().Get("X-Forwarded-For"); strings.Contains(xff, "9.9.9.9") {
		t.Fatalf("forged client reached the application: %q", xff)
	}
	if leafApp.topo.leaf.accepted.Load() != 1 {
		t.Fatal("leaf did not get the edge's own claim")
	}
}

// Without a claim a leaf is an ordinary Concert: its own pass, its own room.
func TestTier_DirectTrafficIsOrdinary(t *testing.T) {
	origin := newTierOrigin(t, "app")
	leafApp, leaf := newLeaf(t, origin.srv.URL, nil)
	resp := getOK(t, tierClient(t), leaf.URL+"/")
	if resp.StatusCode != http.StatusOK || countSetCookie(resp.Header, admitCookie) != 1 {
		t.Fatalf("direct request: status %d, admit cookies %d", resp.StatusCode, countSetCookie(resp.Header, admitCookie))
	}
	if leafApp.topo.leaf.accepted.Load() != 0 {
		t.Fatal("direct request counted as hop")
	}
}

// A claim from outside -hop-peers is ignored and struck; a bad signature
// from a peer is ignored. Both requests are still served as direct traffic.
func TestTier_LeafRejectsBadClaims(t *testing.T) {
	origin := newTierOrigin(t, "app")
	s, _ := hop.NewSigner(testHopSecret, "edge-1")
	good := func(path string) string {
		return s.Sign(hop.Claim{Client: netip.MustParseAddr("198.51.100.7"), Class: hop.ClassPage}, "GET", path, "")
	}

	notPeer, leafA := newLeaf(t, origin.srv.URL, func(c *config) { c.hopPeers = "10.0.0.0/8" })
	req, _ := http.NewRequest(http.MethodGet, leafA.URL+"/a", nil)
	req.Header.Set(hop.Header, good("/a"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if notPeer.topo.leaf.accepted.Load() != 0 || notPeer.topo.leaf.rejected.Load() != 1 {
		t.Fatal("claim from a non-peer was not rejected")
	}
	if notPeer.stats.abuseStrikes.Load() == 0 {
		t.Fatal("claim from a non-peer earned no strike")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("non-peer request status %d", resp.StatusCode)
	}

	peer, leafB := newLeaf(t, origin.srv.URL, nil)
	for _, h := range []string{good("/other"), "garbage", strings.Replace(good("/b"), ";r=0;", ";r=6;", 1)} {
		req, _ := http.NewRequest(http.MethodGet, leafB.URL+"/b", nil)
		req.Header.Set(hop.Header, h)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if origin.lastHeader().Get(hop.Header) != "" {
			t.Fatal("rejected header reached the application")
		}
	}
	if peer.topo.leaf.accepted.Load() != 0 || peer.topo.leaf.rejected.Load() != 3 {
		t.Fatalf("accepted %d rejected %d, want 0 and 3", peer.topo.leaf.accepted.Load(), peer.topo.leaf.rejected.Load())
	}
}

// A full leaf answers with backpressure and the edge sends the request to
// the other leaf; the visitor never sees the refusal. Leaf A advertises the
// most capacity, so slot-aware routing sends the first request there.
func TestTier_BackpressureRedispatch(t *testing.T) {
	originA, originB := newTierOrigin(t, "A"), newTierOrigin(t, "B")
	leafAApp, leafA := newLeaf(t, originA.srv.URL, func(c *config) { c.hostCap = 50 })
	_, leafB := newLeaf(t, originB.srv.URL, func(c *config) { c.hostCap = 5 })
	edgeApp, edge := newEdge(t, []string{leafA.URL, leafB.URL}, func(c *config) { c.hopPoll = time.Minute })
	round(t, edgeApp)

	gate := leafAApp.topo.leaf.gate
	for i := 0; i < 50; i++ {
		if !gate.TryAcquire(capacity.Hop) {
			t.Fatal("could not fill leaf A")
		}
	}
	defer func() {
		for i := 0; i < 50; i++ {
			gate.Release(capacity.Hop)
		}
	}()

	c := tierClient(t)
	for i := 0; i < 10; i++ {
		resp, err := c.Get(edge.URL + "/page")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "B" {
			t.Fatalf("request %d: status %d body %q", i, resp.StatusCode, body)
		}
	}
	if originA.hits.Load() != 0 {
		t.Fatal("a refused request reached leaf A's application")
	}
	if originB.hits.Load() != 10 {
		t.Fatalf("leaf B's application got %d requests, want 10", originB.hits.Load())
	}
	if leafAApp.topo.leaf.backpressed.Load() < 1 || edgeApp.topo.edge.retries.Load() < 1 || edgeApp.topo.edge.backpressure.Load() < 1 {
		t.Fatalf("backpressure %d, retries %d, seen %d: leaf A was never tried",
			leafAApp.topo.leaf.backpressed.Load(), edgeApp.topo.edge.retries.Load(), edgeApp.topo.edge.backpressure.Load())
	}
	// After one refusal the edge avoids leaf A instead of trying it first
	// every time.
	if n := leafAApp.topo.leaf.backpressed.Load(); n > 2 {
		t.Fatalf("leaf A refused %d requests; the edge kept routing there", n)
	}
}

// The edge sizes its room from what healthy leaves offer, less its lane,
// and drops a draining leaf at the next round.
func TestTier_EdgeAutoCapacity(t *testing.T) {
	oA, oB := newTierOrigin(t, "A"), newTierOrigin(t, "B")
	_, leafA := newLeaf(t, oA.srv.URL, func(c *config) { c.hostCap = 7 })
	leafBApp, leafB := newLeaf(t, oB.srv.URL, func(c *config) { c.hostCap = 5 })
	edgeApp, edge := newEdge(t, []string{leafA.URL, leafB.URL}, func(c *config) { c.hopPoll = time.Minute })

	plan := round(t, edgeApp)
	if plan.Total != 12 || plan.Leaves != 2 {
		t.Fatalf("plan %+v, want 12 slots over 2 leaves", plan)
	}
	if got := edgeApp.room.Cap(); got != 10 {
		t.Fatalf("edge room cap %d, want 12 - lane 2 = 10", got)
	}
	resp := getOK(t, http.DefaultClient, edge.URL+"/_room/readyz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz %d", resp.StatusCode)
	}

	leafBApp.draining.Store(true)
	round(t, edgeApp)
	if got := edgeApp.room.Cap(); got != 5 {
		t.Fatalf("after leaf B drained: edge room cap %d, want 7 - 2 = 5", got)
	}

	// Raising -cap is not enough to exceed the leaves; lowering it caps.
	next := edgeApp.current().cfg
	next.capacity = 3
	g, err := edgeApp.buildGeneration(next, edgeApp.current())
	if err != nil {
		t.Fatal(err)
	}
	if err := edgeApp.commit(g, nil); err != nil {
		t.Fatal(err)
	}
	round(t, edgeApp)
	if got := edgeApp.room.Cap(); got != 3 {
		t.Fatalf("edge room cap %d, want -cap 3", got)
	}
}

// An edge whose leaves have never answered admits one request at a time
// and is not ready.
func TestTier_EdgeWithoutLeavesIsNotReady(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "http://" + ln.Addr().String()
	ln.Close()
	edgeApp, edge := newEdge(t, []string{dead}, nil)
	round(t, edgeApp)
	if got := edgeApp.room.Cap(); got != 1 {
		t.Fatalf("edge room cap %d, want 1", got)
	}
	resp := getOK(t, http.DefaultClient, edge.URL+"/_room/readyz")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz %d, want 503", resp.StatusCode)
	}
}

// With a load balancer between the tiers the edge polls -hop-leaves and
// forwards to the balancer.
func TestTier_ThroughLoadBalancer(t *testing.T) {
	origin := newTierOrigin(t, "app")
	leafApp, leaf := newLeaf(t, origin.srv.URL, nil)
	leafURL, _ := url.Parse(leaf.URL)
	lb := httptest.NewServer(&lbProxy{target: leafURL})
	t.Cleanup(lb.Close)
	edgeApp, edge := newEdge(t, []string{lb.URL}, func(c *config) { c.hopLeaves = leaf.URL })

	plan := round(t, edgeApp)
	if plan.Leaves != 1 || plan.Total != 10 {
		t.Fatalf("plan %+v", plan)
	}
	resp := getOK(t, tierClient(t), edge.URL+"/x")
	if resp.StatusCode != http.StatusOK || leafApp.topo.leaf.accepted.Load() != 1 {
		t.Fatalf("status %d, accepted %d", resp.StatusCode, leafApp.topo.leaf.accepted.Load())
	}
}

// lbProxy is a minimal stand-in for haproxy: it forwards everything
// unchanged, appending X-Forwarded-For.
type lbProxy struct{ target *url.URL }

func (p *lbProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL.Scheme, out.URL.Host = p.target.Scheme, p.target.Host
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
		out.Header.Set("X-Forwarded-For", prior+", "+host)
	} else {
		out.Header.Set("X-Forwarded-For", host)
	}
	resp, err := http.DefaultTransport.RoundTrip(out)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// The edge is the source of truth for bans: what it bans, every leaf bans;
// what it lifts, they lift; what a leaf banned itself is left alone.
func TestTier_BanSync(t *testing.T) {
	origin := newTierOrigin(t, "app")
	leafApp, leaf := newLeaf(t, origin.srv.URL, nil)
	edgeApp, _ := newEdge(t, []string{leaf.URL}, func(c *config) { c.hopPoll = time.Minute })
	now := time.Now()

	bot := netip.MustParseAddr("203.0.113.9")
	own := netip.MustParseAddr("203.0.113.50")
	if _, err := edgeApp.abuse.banFor(bot, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if err := edgeApp.abuse.banRange(netip.MustParsePrefix("198.51.100.0/24"), 0, now); err != nil {
		t.Fatal(err)
	}
	if _, err := leafApp.abuse.banFor(own, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	round(t, edgeApp)
	if _, banned := leafApp.abuse.banned(bot, time.Now()); !banned {
		t.Fatal("leaf did not apply the edge's ban")
	}
	if left, banned := leafApp.abuse.banned(netip.MustParseAddr("198.51.100.77"), time.Now()); !banned || left != banForeverLeft {
		t.Fatal("leaf did not apply the edge's permanent range ban")
	}
	versions := leafApp.topo.leaf.bans.versions()
	if versions["edge-1"] != edgeApp.banSnapshot(time.Now()).Version {
		t.Fatalf("leaf reports version %q", versions["edge-1"])
	}

	// Once settled, a round with nothing new pushes nothing. (The bans
	// above kicked the background loop, which may still be finishing.)
	time.Sleep(100 * time.Millisecond)
	round(t, edgeApp)
	pushes := edgeApp.topo.edge.pushes.Load()
	round(t, edgeApp)
	if edgeApp.topo.edge.pushes.Load() != pushes {
		t.Fatal("unchanged bans were pushed again")
	}

	// Lifting at the edge lifts at the leaf; the leaf's own ban stays.
	tgt, _ := parseBanTarget(bot.String())
	edgeApp.abuse.unbanTarget(tgt)
	round(t, edgeApp)
	if _, banned := leafApp.abuse.banned(bot, time.Now()); banned {
		t.Fatal("leaf kept a ban the edge lifted")
	}
	if _, banned := leafApp.abuse.banned(own, time.Now()); !banned {
		t.Fatal("leaf lost its own ban")
	}
}

// A ban at the edge reaches the leaf without waiting for the next poll.
func TestTier_BanKicksSync(t *testing.T) {
	origin := newTierOrigin(t, "app")
	leafApp, leaf := newLeaf(t, origin.srv.URL, nil)
	edgeApp, _ := newEdge(t, []string{leaf.URL}, func(c *config) { c.hopPoll = time.Minute })
	time.Sleep(200 * time.Millisecond) // the first round runs at start
	bot := netip.MustParseAddr("203.0.113.99")
	if _, err := edgeApp.abuse.banFor(bot, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, banned := leafApp.abuse.banned(bot, time.Now()); banned {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("ban did not reach the leaf before the next poll")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTier_ControlPlaneAuth(t *testing.T) {
	origin := newTierOrigin(t, "app")
	_, leaf := newLeaf(t, origin.srv.URL, nil)
	s, _ := hop.NewSigner(testHopSecret, "edge-1")
	wrong, _ := hop.NewSigner([]byte("another-secret-0123456789abcdef-xyz"), "edge-1")
	ctl := hop.Claim{Client: netip.IPv4Unspecified(), Class: hop.ClassControl}

	do := func(method, path, header string, body string) int {
		req, _ := http.NewRequest(method, leaf.URL+path, strings.NewReader(body))
		if header != "" {
			req.Header.Set(hop.Header, header)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	empty := hop.BodyHash(nil)
	cases := []struct {
		name   string
		method string
		path   string
		header string
		body   string
		want   int
	}{
		{"no claim", "GET", hop.StatePath, "", "", 401},
		{"wrong secret", "GET", hop.StatePath, wrong.Sign(ctl, "GET", hop.StatePath, empty), "", 401},
		{"page class", "GET", hop.StatePath, s.Sign(hop.Claim{Client: netip.IPv4Unspecified(), Class: hop.ClassPage}, "GET", hop.StatePath, empty), "", 401},
		{"valid", "GET", hop.StatePath, s.Sign(ctl, "GET", hop.StatePath, empty), "", 200},
		{"body swapped", "POST", hop.BansPath, s.Sign(ctl, "POST", hop.BansPath, hop.BodyHash([]byte(`{"edge":"edge-1"}`))), `{"edge":"edge-1","bans":[{"client":"1.2.3.4","permanent":true}]}`, 401},
		{"other edge's snapshot", "POST", hop.BansPath, s.Sign(ctl, "POST", hop.BansPath, hop.BodyHash([]byte(`{"edge":"edge-2"}`))), `{"edge":"edge-2"}`, 400},
	}
	for _, tc := range cases {
		if got := do(tc.method, tc.path, tc.header, tc.body); got != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, got, tc.want)
		}
	}

	// Standalone and edge nodes never expose the control plane, and never
	// forward it to the application.
	sa, front := newTestApp(t, testConfig(origin.srv.URL), nil)
	_ = sa
	before := origin.hits.Load()
	resp := getOK(t, http.DefaultClient, front.URL+hop.StatePath)
	if resp.StatusCode != http.StatusNotFound || origin.hits.Load() != before {
		t.Fatalf("standalone control plane: status %d, forwarded %v", resp.StatusCode, origin.hits.Load() != before)
	}
}

// Assets through the chain need no pass at the leaf: the edge checked it.
// Directly at the leaf they still do.
func TestTier_AssetsThroughChain(t *testing.T) {
	origin := newTierOrigin(t, "app")
	assets := func(c *config) { c.assets = "/static/*" }
	_, leaf := newLeaf(t, origin.srv.URL, assets)
	_, edge := newEdge(t, []string{leaf.URL}, assets)

	c := tierClient(t)
	getOK(t, c, edge.URL+"/") // admission pass from the edge
	if resp := getOK(t, c, edge.URL+"/static/site.css"); resp.StatusCode != http.StatusOK {
		t.Fatalf("asset through the chain: %d", resp.StatusCode)
	}
	if resp := getOK(t, http.DefaultClient, leaf.URL+"/static/site.css"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("asset directly at the leaf without a pass: %d, want 403", resp.StatusCode)
	}
	if resp := getOK(t, http.DefaultClient, edge.URL+"/static/site.css"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("asset at the edge without a pass: %d, want 403", resp.StatusCode)
	}
}

// Paid and lane-ranked visitors wait ahead of others in the leaf's gate.
func TestTier_GateClass(t *testing.T) {
	lane := int(rankCustomer)
	cases := []struct {
		c    hop.Claim
		want capacity.Class
	}{
		{hop.Claim{Rank: uint8(rankGuest)}, capacity.Hop},
		{hop.Claim{Rank: uint8(rankProspect)}, capacity.Hop},
		{hop.Claim{Rank: uint8(rankCustomer)}, capacity.HopPriority},
		{hop.Claim{Paid: true}, capacity.HopPriority},
	}
	for _, tc := range cases {
		if got := gateClass(tc.c, lane); got != tc.want {
			t.Errorf("%+v: class %v, want %v", tc.c, got, tc.want)
		}
	}
}

// A leaf records the load it carried when its application went silent.
func TestTier_SilenceReport(t *testing.T) {
	origin := newTierOrigin(t, "app")
	dir := t.TempDir()
	leafApp, _ := newLeaf(t, origin.srv.URL, func(c *config) { c.dataDir = dir })
	l := leafApp.topo.leaf
	start := time.Now()
	leafApp.leafTick(start)
	l.gate.TryAcquire(capacity.Hop)
	l.gate.TryAcquire(capacity.Direct)
	leafApp.stats.upstream5xx.Add(5)
	leafApp.stats.upstreamUnavail.Add(5)
	leafApp.leafTick(start.Add(time.Second))
	_, rep := l.monitor.view()
	if rep == nil || rep.HopInFlight != 1 || rep.DirectInFlight != 1 || !rep.Recovered.IsZero() {
		t.Fatalf("report %+v", rep)
	}
	if st := leafApp.leafReport(time.Now()); st.AppHealthy {
		t.Fatal("silent leaf reported a healthy application")
	}
	leafApp.stats.upstream2xx.Add(1)
	leafApp.leafTick(start.Add(2 * time.Second))
	if _, rep := l.monitor.view(); rep.Recovered.IsZero() {
		t.Fatal("recovery not recorded")
	}
	b, err := os.ReadFile(filepath.Join(dir, silenceFile))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("silence log has %d lines, want 2", len(lines))
	}
	var r hop.SilenceReport
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil || r.Reason == "" {
		t.Fatalf("first line %q: %v", lines[0], err)
	}
}

// A leaf's host capacity comes from -host-cap, then capacity.json, then -cap.
func TestTier_HostCapacitySources(t *testing.T) {
	dir := t.TempDir()
	cfg := tierConfig("http://127.0.0.1:1")
	cfg.dataDir = dir
	cfg.capacity = 9
	if n, src, _ := hostCapacity(cfg); n != 9 || src != "cap" {
		t.Fatalf("%d %s", n, src)
	}
	if err := capacity.Save(capacity.Path(dir), capacity.File{At: time.Now(), HostCap: 33, Lemmings: 37, Safety: 0.9}); err != nil {
		t.Fatal(err)
	}
	if n, src, f := hostCapacity(cfg); n != 33 || src != "bench" || f == nil {
		t.Fatalf("%d %s", n, src)
	}
	cfg.hostCap = 4
	if n, src, _ := hostCapacity(cfg); n != 4 || src != "flag" {
		t.Fatalf("%d %s", n, src)
	}
}

func TestTier_ConfigValidation(t *testing.T) {
	base := func() config { return tierConfig("http://127.0.0.1:1") }
	cases := map[string]func(*config){
		"unknown role":        func(c *config) { c.role = "middle" },
		"leaf without peers":  func(c *config) { c.role = roleLeaf },
		"edge without secret": func(c *config) { c.role = roleEdge; c.hopSecret = nil },
		"short secret":        func(c *config) { c.role = roleEdge; c.hopSecret = []byte("short") },
		"bad node id":         func(c *config) { c.nodeID = "has space" },
		"bad leaves":          func(c *config) { c.hopLeaves = "ftp://x" },
		"retries":             func(c *config) { c.upstreamRetries = 9 },
		"poll":                func(c *config) { c.hopPoll = time.Millisecond },
		"short previous":      func(c *config) { c.hopSecretPrev = []byte("x") },
	}
	for name, mutate := range cases {
		c := base()
		mutate(&c)
		if err := c.normalize(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := base()
	if err := c.normalize(); err != nil || c.role != roleStandalone || !hop.ValidNodeID(c.nodeID) {
		t.Fatalf("defaults: %v %q %q", err, c.role, c.nodeID)
	}
}

func TestRetryable(t *testing.T) {
	bp := &http.Response{StatusCode: 503, Header: http.Header{hop.BackpressureHeader: {"full"}}}
	plain503 := &http.Response{StatusCode: 503, Header: http.Header{}}
	dial := &net.OpError{Op: "dial", Err: errors.New("refused")}
	read := &net.OpError{Op: "read", Err: errors.New("reset")}
	cases := []struct {
		resp *http.Response
		err  error
		want bool
	}{
		{bp, nil, true},
		{plain503, nil, false},
		{&http.Response{StatusCode: 200, Header: http.Header{}}, nil, false},
		{nil, dial, true},
		{nil, read, false},
		{nil, context.Canceled, false},
		{nil, errors.New("other"), false},
	}
	for i, tc := range cases {
		if got := retryable(tc.resp, tc.err); got != tc.want {
			t.Errorf("case %d: %v, want %v", i, got, tc.want)
		}
	}
}

func TestRetarget(t *testing.T) {
	from, _ := url.Parse("http://a:1")
	to, _ := url.Parse("https://b:2/base")
	req := httptest.NewRequest(http.MethodGet, "http://a:1/x/y?q=1", nil)
	req.Host = "a:1"
	out := retarget(req, from, to)
	if out.URL.String() != "https://b:2/base/x/y?q=1" || out.Host != "b:2" {
		t.Fatalf("retarget: %s host %s", out.URL, out.Host)
	}
	if req.URL.Host != "a:1" {
		t.Fatal("retarget changed the original")
	}
	req.Host = "www.example.com" // preserved client Host stays
	if out := retarget(req, from, to); out.Host != "www.example.com" {
		t.Fatalf("host %s", out.Host)
	}
}

// Without a body, a dial failure or backpressure moves the request to the
// next backend; with a body it never does.
func TestTransportRetries(t *testing.T) {
	var full atomic.Int64
	fullSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		full.Add(1)
		w.Header().Set(hop.BackpressureHeader, "full")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer fullSrv.Close()
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer okSrv.Close()

	cfg := testConfig(fullSrv.URL + "," + okSrv.URL)
	cfg.upstreamRetries = 1
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	_, pool, err := newEnterpriseProxy(cfg, &counters{}, nil, &topology{role: roleStandalone})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.close()
	tr := &trackedTransport{base: pool.transport, pool: pool, stats: &counters{}}
	first := pool.backends[0]

	send := func(body io.Reader) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, fullSrv.URL+"/x", body)
		req = req.WithContext(context.WithValue(req.Context(), ctxBackendKey{}, first))
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}
	if resp := send(nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("bodyless request not retried: %d", resp.StatusCode)
	}
	first.fullUntil.Store(0)
	if resp := send(strings.NewReader("form=1")); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("request with a body was retried: %d", resp.StatusCode)
	}
	if full.Load() != 2 {
		t.Fatalf("full backend hit %d times, want 2", full.Load())
	}
}

// Slot-aware picking prefers the leaf with the most free capacity once every
// healthy leaf reports slots, and avoids one that just pushed back.
func TestPickSlotAware(t *testing.T) {
	cfg := testConfig("http://a:1,http://b:2")
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	p := newUpstreamPool(cfg, &http.Transport{})
	defer p.close()
	a, b := p.backends[0], p.backends[1]
	a.slots.Store(10)
	b.slots.Store(100)
	a.inFlight.Store(0)
	b.inFlight.Store(50)
	now := time.Now()
	for i := 0; i < 5; i++ {
		if got, _ := p.pick(now); got != b {
			t.Fatal("did not prefer the leaf with 50 free slots")
		}
	}
	b.fullUntil.Store(now.Add(time.Second).UnixNano())
	if got, _ := p.pick(now); got != a {
		t.Fatal("did not avoid the leaf that pushed back")
	}
	a.slots.Store(0) // unknown: fall back to least in flight
	b.fullUntil.Store(0)
	if got, _ := p.pick(now); got != a {
		t.Fatal("without slots everywhere, least in flight should win")
	}
}

func TestStripConcertSetCookies(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "concert_admit=x; Path=/")
	h.Add("Set-Cookie", "session=app; Path=/")
	h.Add("Set-Cookie", "room_ticket=y")
	h.Add("Set-Cookie", "concert_admit_extra=keep")
	stripConcertSetCookies(h)
	got := h.Values("Set-Cookie")
	if len(got) != 2 || got[0] != "session=app; Path=/" || got[1] != "concert_admit_extra=keep" {
		t.Fatalf("kept %q", got)
	}
}

// A leaf started with -bench-on-start measures its application before
// serving and uses the result as its host capacity; a second start reuses
// the file.
func TestTier_BenchOnStart(t *testing.T) {
	site := testsite.New(testsite.Options{PageLimit: 4, PageDelay: 25 * time.Millisecond})
	srv := httptest.NewServer(site)
	t.Cleanup(srv.Close)
	defer func(f func(*bench.Options)) { benchStartTuning = f }(benchStartTuning)
	runs := 0
	benchStartTuning = func(o *bench.Options) {
		runs++
		o.StageDuration = 300 * time.Millisecond
		o.Cooldown = 150 * time.Millisecond
		o.Max = 16
	}
	dir := t.TempDir()
	cfg := tierConfig(srv.URL)
	cfg.role, cfg.hopPeers, cfg.nodeID = roleLeaf, "127.0.0.1/32", "leaf-bench"
	cfg.dataDir, cfg.benchOnStart = dir, true
	cfg.capacity = 50
	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.topo.leaf.gate.Cap() != 50 {
		t.Fatalf("before the benchmark host cap %d, want -cap 50", a.topo.leaf.gate.Cap())
	}
	a.benchOnStart(context.Background())
	f, err := capacity.Load(capacity.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if f.Lemmings != 4 || f.HostCap != 3 {
		t.Fatalf("capacity file %+v, want 4 lemmings and host cap 3", f)
	}
	if a.topo.leaf.gate.Cap() != 3 || a.topo.leaf.capSource != "bench" {
		t.Fatalf("host cap %d (%s) after the benchmark", a.topo.leaf.gate.Cap(), a.topo.leaf.capSource)
	}
	if st := a.leafReport(time.Now()); st.Bench == nil || st.Bench.Lemmings != 4 {
		t.Fatalf("leaf state does not report the benchmark: %+v", st.Bench)
	}
	if fi, err := os.Stat(filepath.Join(dir, "bench-report.json")); err != nil {
		t.Fatalf("bench-report.json missing: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("bench-report.json mode %v, want 0600", fi.Mode().Perm())
	}
	// The hook runs only when a benchmark starts. (Comparing the site's
	// served count raced: a page the first run cancelled can finish in the
	// server after Run returns.)
	a.benchOnStart(context.Background())
	if runs != 1 {
		t.Fatalf("benchmark ran %d times; the second start must use capacity.json", runs)
	}
}

// A delayed, older ban snapshot never undoes a newer one.
func TestTier_StaleSnapshotIgnored(t *testing.T) {
	origin := newTierOrigin(t, "app")
	leafApp, _ := newLeaf(t, origin.srv.URL, nil)
	now := time.Now()
	newer := hop.BanSnapshot{Edge: "edge-1", At: now, Bans: []hop.Ban{{Client: "203.0.113.5", Permanent: true}}}
	newer.Version = hop.BanVersion(newer.Bans)
	older := hop.BanSnapshot{Edge: "edge-1", At: now.Add(-time.Second), Version: hop.BanVersion(nil)}
	if applied, _ := leafApp.mirrorBans(newer, now); applied != 1 {
		t.Fatalf("applied %d", applied)
	}
	if _, lifted := leafApp.mirrorBans(older, now); lifted != 0 {
		t.Fatal("an older snapshot lifted a ban")
	}
	if _, banned := leafApp.abuse.banned(netip.MustParseAddr("203.0.113.5"), time.Now()); !banned {
		t.Fatal("ban lost")
	}
	if v := leafApp.topo.leaf.bans.versions()["edge-1"]; v != newer.Version {
		t.Fatalf("version %q, want the newer one", v)
	}
}

func TestTier_Metrics(t *testing.T) {
	origin := newTierOrigin(t, "app")
	leafApp, leaf := newLeaf(t, origin.srv.URL, nil)
	edgeApp, _ := newEdge(t, []string{leaf.URL}, nil)
	round(t, edgeApp)
	for app, want := range map[*app][]string{
		leafApp: {`concert_node_info{role="leaf"`, "concert_leaf_host_cap 10", "concert_leaf_app_silent 0"},
		edgeApp: {`concert_node_info{role="edge",node="edge-1"} 1`, "concert_edge_leaf_slots 10", "concert_edge_planned_cap 8"},
	} {
		m := app.renderPrometheusMetrics()
		for _, w := range want {
			if !strings.Contains(m, w) {
				t.Errorf("%s metrics lack %q", app.topo.role, w)
			}
		}
	}
}
