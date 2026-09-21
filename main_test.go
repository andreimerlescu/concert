package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// ─── fake upstream ───────────────────────────────────────────────────────────

type fakeUpstream struct {
	srv     *httptest.Server
	entered chan struct{}
	release chan struct{}
	once    sync.Once

	mu         sync.Mutex
	hits       map[string]int
	lastHost   string
	lastPath   string
	lastCookie string
	lastXFF    string
	total      atomic.Int64
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{
		entered: make(chan struct{}, 16),
		release: make(chan struct{}),
		hits:    map[string]int{},
	}
	u.srv = httptest.NewServer(http.HandlerFunc(u.handle))
	t.Cleanup(u.srv.Close)
	t.Cleanup(u.releaseAll) // LIFO: runs before srv.Close
	return u
}

func (u *fakeUpstream) URL() string { return u.srv.URL }

func (u *fakeUpstream) releaseAll() { u.once.Do(func() { close(u.release) }) }

func (u *fakeUpstream) handle(w http.ResponseWriter, r *http.Request) {
	u.total.Add(1)
	u.mu.Lock()
	u.hits[r.URL.Path]++
	u.lastHost = r.Host
	u.lastPath = r.URL.Path
	u.lastCookie = r.Header.Get("Cookie")
	u.lastXFF = r.Header.Get("X-Forwarded-For")
	u.mu.Unlock()

	switch r.URL.Path {
	case "/slow":
		u.entered <- struct{}{}
		select {
		case <-u.release:
		case <-r.Context().Done():
		}
		fmt.Fprint(w, "slow done")
	case "/sse":
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: hello\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-u.release:
		case <-r.Context().Done():
		}
	default:
		fmt.Fprint(w, "ok")
	}
}

func (u *fakeUpstream) hitsFor(path string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits[path]
}

func (u *fakeUpstream) seen() (host, path, cookie, xff string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastHost, u.lastPath, u.lastCookie, u.lastXFF
}

// ─── helpers ─────────────────────────────────────────────────────────────────

var testClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func testConfig(upstream string) config {
	return config{
		listen:        "127.0.0.1:0",
		upstream:      upstream,
		capacity:      10,
		maxQueue:      100,
		reaper:        30 * time.Second,
		cookiePath:    "/",
		preserveHost:  true,
		headerTimeout: 5 * time.Second,
		apiJSON:       true,
		retryAfter:    5,
		accessLog:     io.Discard,
	}
}

// newTestApp builds the app and fronts it with an httptest server.
// The upstream is released before the front server closes so that
// Close never blocks on a parked /slow request.
func newTestApp(t *testing.T, cfg config, up *fakeUpstream) (*app, *httptest.Server) {
	t.Helper()
	a, err := newApp(cfg)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	t.Cleanup(a.Close)
	front := httptest.NewServer(a.handler)
	t.Cleanup(front.Close)
	if up != nil {
		t.Cleanup(up.releaseAll)
	}
	return a, front
}

// fillSlot parks one request on the upstream, occupying a slot.
func fillSlot(t *testing.T, front *httptest.Server, up *fakeUpstream) {
	t.Helper()
	go func() {
		resp, err := testClient.Get(front.URL + "/slow")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	select {
	case <-up.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("slow request never reached the upstream")
	}
}

func doReq(t *testing.T, c *http.Client, method, url string, hdr map[string]string, body io.Reader) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func get(t *testing.T, url string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	return doReq(t, testClient, http.MethodGet, url, hdr, nil)
}

func eventually(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal(msg)
}

func hasCookie(resp *http.Response, name string) bool {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return true
		}
	}
	return false
}

// clearConcertEnv unsets every CONCERT_* variable for the duration of the
// test, so a developer's shell cannot leak into default assertions.
func clearConcertEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "CONCERT_") {
			t.Setenv(k, v) // registers restore
			os.Unsetenv(k)
		}
	}
}

func newFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// ─── parseConfig / normalize ─────────────────────────────────────────────────

func TestParseConfig_Defaults(t *testing.T) {
	clearConcertEnv(t)

	cfg, showVersion, err := parseConfig(newFlagSet(), nil)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if showVersion {
		t.Fatal("showVersion should default to false")
	}

	checks := []struct {
		name      string
		got, want any
	}{
		{"listen", cfg.listen, ":8080"},
		{"upstream", cfg.upstream, "http://127.0.0.1:3000"},
		{"capacity", cfg.capacity, 500},
		{"maxQueue", cfg.maxQueue, int64(10000)},
		{"reaper", cfg.reaper, 30 * time.Second},
		{"tokenTTL", cfg.tokenTTL, time.Duration(0)},
		{"secureCookie", cfg.secureCookie, false},
		{"cookiePath", cfg.cookiePath, "/"},
		{"preserveHost", cfg.preserveHost, true},
		{"bypass", cfg.bypass, "/favicon.ico"},
		{"headerTimeout", cfg.headerTimeout, 30 * time.Second},
		{"apiJSON", cfg.apiJSON, true},
		{"retryAfter", cfg.retryAfter, 5},
		{"adminToken", cfg.adminToken, ""},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
	}
	if cfg.target == nil || cfg.target.Host != "127.0.0.1:3000" {
		t.Errorf("target not derived from upstream: %v", cfg.target)
	}
}

func TestParseConfig_EnvOverridesDefaults(t *testing.T) {
	clearConcertEnv(t)
	t.Setenv("CONCERT_UPSTREAM", "http://origin.internal:9000")
	t.Setenv("CONCERT_CAPACITY", "42")
	t.Setenv("CONCERT_REAPER", "45s")
	t.Setenv("CONCERT_API_JSON", "false")
	t.Setenv("CONCERT_ADMIN_TOKEN", "s3cret")

	cfg, _, err := parseConfig(newFlagSet(), nil)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.target.Host != "origin.internal:9000" {
		t.Errorf("upstream: got %s", cfg.target.Host)
	}
	if cfg.capacity != 42 {
		t.Errorf("capacity: got %d, want 42", cfg.capacity)
	}
	if cfg.reaper != 45*time.Second {
		t.Errorf("reaper: got %s, want 45s", cfg.reaper)
	}
	if cfg.apiJSON {
		t.Error("apiJSON: env false was ignored")
	}
	if cfg.adminToken != "s3cret" {
		t.Errorf("adminToken: got %q", cfg.adminToken)
	}
}

func TestParseConfig_FlagBeatsEnv(t *testing.T) {
	clearConcertEnv(t)
	t.Setenv("CONCERT_CAPACITY", "42")

	cfg, _, err := parseConfig(newFlagSet(), []string{"-cap", "7"})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.capacity != 7 {
		t.Errorf("capacity: got %d, want 7", cfg.capacity)
	}
}

func TestParseConfig_VersionSkipsValidation(t *testing.T) {
	clearConcertEnv(t)

	_, showVersion, err := parseConfig(newFlagSet(), []string{"-version", "-upstream", "garbage"})
	if err != nil {
		t.Fatalf("-version must not validate: %v", err)
	}
	if !showVersion {
		t.Error("showVersion should be true")
	}
}

func TestParseConfig_UnknownFlag(t *testing.T) {
	clearConcertEnv(t)

	if _, _, err := parseConfig(newFlagSet(), []string{"-nope"}); err == nil {
		t.Error("expected error for unknown flag")
	}
}

func TestParseConfig_Invalid(t *testing.T) {
	cases := map[string][]string{
		"no scheme":     {"-upstream", "not a url"},
		"ftp scheme":    {"-upstream", "ftp://files.example"},
		"no host":       {"-upstream", "http://"},
		"zero cap":      {"-cap", "0"},
		"negative cap":  {"-cap", "-5"},
		"overflows i32": {"-cap", "3000000000"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			clearConcertEnv(t)
			if _, _, err := parseConfig(newFlagSet(), args); err == nil {
				t.Errorf("expected error for %v", args)
			}
		})
	}
}

func TestNormalize_ClampsRetryAfter(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.retryAfter = 0
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.retryAfter != 1 {
		t.Errorf("retryAfter: got %d, want 1", cfg.retryAfter)
	}
}

func TestNewApp_RejectsInvalidConfig(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.capacity = 0
	if _, err := newApp(cfg); err == nil {
		t.Error("expected error for cap=0")
	}
}

// ─── pure helpers ────────────────────────────────────────────────────────────

func TestStripCookies(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Cookie", "room_ticket=a; session=keep; room_pass=b; room_probe=1; theme=dark")

	stripCookies(req, roomCookies...)

	got := map[string]string{}
	for _, c := range req.Cookies() {
		got[c.Name] = c.Value
	}
	if len(got) != 2 || got["session"] != "keep" || got["theme"] != "dark" {
		t.Errorf("unexpected cookies after strip: %v", got)
	}
}

func TestStripCookies_NoCookieHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	stripCookies(req, roomCookies...)
	if _, ok := req.Header["Cookie"]; ok {
		t.Error("strip should not add a Cookie header")
	}
}

func TestWantsHTML(t *testing.T) {
	cases := map[string]bool{
		"":                                    false,
		"*/*":                                 false,
		"application/json":                    false,
		"text/event-stream":                   false,
		"image/avif,image/webp,*/*":           false,
		"text/html":                           true,
		"text/html,application/xhtml+xml,*/*": true,
	}
	for accept, want := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if got := wantsHTML(req); got != want {
			t.Errorf("Accept %q: got %v, want %v", accept, got, want)
		}
	}
}

// ─── proxying ────────────────────────────────────────────────────────────────

func TestProxy_ForwardsWhenRoomHasSpace(t *testing.T) {
	up := newFakeUpstream(t)
	_, front := newTestApp(t, testConfig(up.URL()), up)

	resp, body := get(t, front.URL+"/hello", nil)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	if up.hitsFor("/hello") != 1 {
		t.Error("upstream did not receive the request")
	}
}

func TestProxy_StripsRoomCookies(t *testing.T) {
	up := newFakeUpstream(t)
	_, front := newTestApp(t, testConfig(up.URL()), up)

	get(t, front.URL+"/c", map[string]string{
		"Cookie": "room_ticket=abc; room_pass=def; room_probe=1; session=keep",
	})

	_, _, cookie, _ := up.seen()
	if cookie != "session=keep" {
		t.Errorf("upstream saw Cookie %q, want only session=keep", cookie)
	}
}

func TestProxy_PreservesHostAndSetsForwarded(t *testing.T) {
	up := newFakeUpstream(t)
	_, front := newTestApp(t, testConfig(up.URL()), up)

	get(t, front.URL+"/h", map[string]string{"Host": "concert.example"})

	host, _, _, xff := up.seen()
	if host != "concert.example" {
		t.Errorf("upstream Host: got %q, want concert.example", host)
	}
	if xff == "" {
		t.Error("X-Forwarded-For not set")
	}
}

func TestProxy_RewritesHostWhenNotPreserved(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.preserveHost = false
	_, front := newTestApp(t, cfg, up)

	get(t, front.URL+"/h", map[string]string{"Host": "concert.example"})

	host, _, _, _ := up.seen()
	if host != up.srv.Listener.Addr().String() {
		t.Errorf("upstream Host: got %q, want %q", host, up.srv.Listener.Addr())
	}
}

func TestProxy_NoTrailingSlashRedirects(t *testing.T) {
	up := newFakeUpstream(t)
	_, front := newTestApp(t, testConfig(up.URL()), up)

	for _, p := range []string{"/foo/", "/_room/stats/"} {
		resp, _ := get(t, front.URL+p, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: got %d, want 200 (forwarded, not redirected)", p, resp.StatusCode)
		}
		if _, path, _, _ := up.seen(); path != p {
			t.Errorf("%s: upstream saw %q", p, path)
		}
	}
}

func TestProxy_UpstreamDownReturns502(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	_, front := newTestApp(t, testConfig("http://"+addr), nil)

	resp, _ := get(t, front.URL+"/x", nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("got %d, want 502", resp.StatusCode)
	}
}

func TestProxy_StreamsThroughInterceptor(t *testing.T) {
	up := newFakeUpstream(t)
	_, front := newTestApp(t, testConfig(up.URL()), up)

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/sse", nil)
	req.Header.Set("Accept", "text/event-stream") // non-HTML → wrapped writer
	resp, err := testClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	lineCh := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(resp.Body).ReadString('\n')
		lineCh <- line
	}()

	select {
	case line := <-lineCh:
		if line != "data: hello\n" {
			t.Errorf("got %q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first SSE event never flushed through the proxy")
	}
}

// ─── waiting room behaviour ──────────────────────────────────────────────────

func TestQueue_BrowserGetsWaitingRoomHTML(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	_, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	resp, _ := get(t, front.URL+"/page", map[string]string{"Accept": "text/html"})

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type: got %q", ct)
	}
	if !hasCookie(resp, "room_ticket") {
		t.Error("room_ticket cookie not issued")
	}
	if !hasCookie(resp, "room_probe") {
		t.Error("room_probe cookie not issued (room >= 1.2.1)")
	}
	if up.hitsFor("/page") != 0 {
		t.Error("queued request reached the upstream")
	}
}

func TestQueue_APIClientGetsJSON429(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	a, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	resp, body := get(t, front.URL+"/api/thing", nil)

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status: got %d, want 429 (body %q)", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type: got %q", ct)
	}
	if ra := resp.Header.Get("Retry-After"); ra != "5" {
		t.Errorf("Retry-After: got %q, want 5", ra)
	}
	if !hasCookie(resp, "room_ticket") {
		t.Error("room_ticket must survive the rewrite so clients can resume")
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("body is not JSON: %q", body)
	}
	if payload["queued"] != true {
		t.Errorf("queued: got %v", payload["queued"])
	}
	if up.hitsFor("/api/thing") != 0 {
		t.Error("queued request reached the upstream")
	}

	eventually(t, 2*time.Second, func() bool { return a.stats.queued.Load() == 1 },
		"EventQueue callback never incremented queued_total")
}

func TestQueue_APIJSONDisabledServesHTML(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.apiJSON = false
	_, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	resp, _ := get(t, front.URL+"/api/thing", nil)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("with -api-json=false expected room's HTML 200, got %d %s",
			resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

func TestQueue_BreakerReturnsJSON503(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.maxQueue = 1
	_, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	first, _ := get(t, front.URL+"/a", nil)
	if first.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("first queued request: got %d, want 429", first.StatusCode)
	}

	resp, body := get(t, front.URL+"/b", nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second request: got %d, want 503 (body %q)", resp.StatusCode, body)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("503 missing Retry-After")
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil || payload["queued"] != false {
		t.Errorf("unexpected 503 body: %q", body)
	}
}

func TestQueue_CookieJarClientResumesAfterSlotFrees(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	_, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	resp, _ := doReq(t, client, http.MethodGet, front.URL+"/api/resume", nil, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected to be queued, got %d", resp.StatusCode)
	}

	up.releaseAll() // frees the slot

	eventually(t, 5*time.Second, func() bool {
		r, _ := doReq(t, client, http.MethodGet, front.URL+"/api/resume", nil, nil)
		return r.StatusCode == http.StatusOK
	}, "cookie-jar client was never admitted after the slot freed")

	if up.hitsFor("/api/resume") != 1 {
		t.Errorf("upstream hits: got %d, want 1", up.hitsFor("/api/resume"))
	}
}

func TestQueue_BypassSkipsFullRoom(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.bypass = "/static/*, /robots.txt"
	_, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	for _, p := range []string{"/static/app.js", "/static/css/site.css", "/robots.txt"} {
		resp, body := get(t, front.URL+p, nil)
		if resp.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Errorf("%s: got %d %q, want upstream 200", p, resp.StatusCode, body)
		}
	}

	resp, _ := get(t, front.URL+"/gated", nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("/gated: got %d, want 429", resp.StatusCode)
	}
}

// ─── ops endpoints ───────────────────────────────────────────────────────────

func TestOps_HealthzUngatedWhenFull(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	_, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	resp, body := get(t, front.URL+"/_room/healthz", nil)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Errorf("got %d %q", resp.StatusCode, body)
	}
}

func TestOps_Stats(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	_, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	resp, body := get(t, front.URL+"/_room/stats", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d", resp.StatusCode)
	}
	var s map[string]any
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatalf("stats not JSON: %q", body)
	}
	for _, k := range []string{
		"upstream", "cap", "occupancy", "queue_depth", "live_queue_depth",
		"max_queue_depth", "utilization", "token_ttl",
		"queued_total", "evicted_total", "timeouts_total", "promoted_total",
	} {
		if _, ok := s[k]; !ok {
			t.Errorf("stats missing %q", k)
		}
	}
	if s["cap"] != float64(1) || s["occupancy"] != float64(1) {
		t.Errorf("cap/occupancy: got %v/%v, want 1/1", s["cap"], s["occupancy"])
	}
	if s["token_ttl"] != "5m0s" {
		t.Errorf("token_ttl: got %v, want room default 5m0s", s["token_ttl"])
	}
}

func TestOps_CapDisabledWithoutToken(t *testing.T) {
	up := newFakeUpstream(t)
	_, front := newTestApp(t, testConfig(up.URL()), up)

	resp, _ := doReq(t, testClient, http.MethodPost, front.URL+"/_room/cap", nil, strings.NewReader(`{"cap":3}`))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want 404", resp.StatusCode)
	}
}

func TestOps_CapAuthAndUpdate(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.adminToken = "secret"
	a, front := newTestApp(t, cfg, up)

	post := func(auth, body string) *http.Response {
		hdr := map[string]string{"Content-Type": "application/json"}
		if auth != "" {
			hdr["Authorization"] = auth
		}
		resp, _ := doReq(t, testClient, http.MethodPost, front.URL+"/_room/cap", hdr, strings.NewReader(body))
		return resp
	}

	if r := post("", `{"cap":3}`); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("no auth: got %d, want 401", r.StatusCode)
	}
	if r := post("Bearer wrong", `{"cap":3}`); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token: got %d, want 401", r.StatusCode)
	}
	if r := post("Bearer secret", `not json`); r.StatusCode != http.StatusBadRequest {
		t.Errorf("bad body: got %d, want 400", r.StatusCode)
	}
	if r := post("Bearer secret", `{"cap":3}`); r.StatusCode != http.StatusOK {
		t.Fatalf("valid: got %d, want 200", r.StatusCode)
	}
	if got := a.room.Cap(); got != 3 {
		t.Errorf("room cap: got %d, want 3", got)
	}
}

// ─── lifecycle ───────────────────────────────────────────────────────────────

func TestServe_ShutsDownOnContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln, h, 2*time.Second) }()

	resp, err := testClient.Get("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("got %d, want 204", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve returned %v, want nil on clean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after context cancel")
	}
}

func TestRun_ListenErrorIsReturned(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	cfg := testConfig("http://127.0.0.1:1")
	cfg.listen = busy.Addr().String()

	done := make(chan error, 1)
	go func() { done <- run(context.Background(), cfg) }()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "listen") {
			t.Errorf("got %v, want listen error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not fail on an occupied port")
	}
}

func TestRun_ServesAndStops(t *testing.T) {
	up := newFakeUpstream(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testConfig(up.URL())
	cfg.listen = addr

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()

	eventually(t, 3*time.Second, func() bool {
		resp, err := testClient.Get("http://" + addr + "/_room/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "run never started serving")

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop after cancel")
	}
}
