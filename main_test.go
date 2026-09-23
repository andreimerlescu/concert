package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
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
	lastProto  string
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
	u.lastXFF = strings.Join(r.Header.Values("X-Forwarded-For"), ", ")
	u.lastProto = r.Header.Get("X-Forwarded-Proto")
	u.mu.Unlock()

	switch r.URL.Path {
	case "/slow", "/assets/slow":
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

func (u *fakeUpstream) seenProto() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastProto
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
		listen:           "127.0.0.1:0",
		upstream:         upstream,
		capacity:         10,
		maxQueue:         100,
		reaper:           30 * time.Second,
		cookiePath:       "/",
		preserveHost:     true,
		headerTimeout:    5 * time.Second,
		apiJSON:          true,
		retryAfter:       5,
		assetWait:        2 * time.Second,
		assetUserCapH1:   8,
		assetUserCapH2:   128,
		assetUserWait:    2 * time.Second,
		admitTTL:         10 * time.Minute,
		admitSecret:      []byte("concert-test-secret-0123456789abcdef"),
		accessLogEnabled: false,
		accessLog:        io.Discard,
		streamCap:        64,
		trustedProxies:   "", // test clients are the real clients
		abuseEnabled:     true,
		abuseStrikes:     20,
		abuseWindow:      time.Minute,
		abuseCooldown:    5 * time.Minute,
		abuseMaxCooldown: 24 * time.Hour,
		abuseMaxEntries:  1000,
	}
}

// newTestApp builds the app and fronts it with an httptest server.
// The upstream is released before the front server closes so that
// Close never blocks on a parked request.
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

// park sends a request that blocks inside the upstream until released.
func park(t *testing.T, front *httptest.Server, up *fakeUpstream, path string, hdr map[string]string) {
	t.Helper()
	go func() {
		req, err := http.NewRequest(http.MethodGet, front.URL+path, nil)
		if err != nil {
			return
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := testClient.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	select {
	case <-up.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s never reached the upstream", path)
	}
}

// fillSlot parks one gated request, occupying a room slot.
func fillSlot(t *testing.T, front *httptest.Server, up *fakeUpstream) {
	t.Helper()
	park(t, front, up, "/slow", nil)
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

func cookieValue(resp *http.Response, name string) (string, bool) {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c.Value, true
		}
	}
	return "", false
}

func hasCookie(resp *http.Response, name string) bool {
	_, ok := cookieValue(resp, name)
	return ok
}

// admitPass loads a gated page and returns the concert_admit value it issued.
func admitPass(t *testing.T, front *httptest.Server) string {
	t.Helper()
	resp, _ := get(t, front.URL+"/page", map[string]string{"Accept": "text/html"})
	v, ok := cookieValue(resp, admitCookie)
	if !ok {
		t.Fatalf("admitted page did not issue %s (status %d)", admitCookie, resp.StatusCode)
	}
	return v
}

func withPass(pass string, extra map[string]string) map[string]string {
	hdr := map[string]string{"Cookie": admitCookie + "=" + pass}
	for k, v := range extra {
		hdr[k] = v
	}
	return hdr
}

func withXFF(ip string) map[string]string {
	return map[string]string{"X-Forwarded-For": ip}
}

// tamper flips one character inside the pass ID, keeping the key id intact.
func tamper(pass string) string {
	b := []byte(pass)
	if b[5] == 'A' {
		b[5] = 'B'
	} else {
		b[5] = 'A'
	}
	return string(b)
}

func isBlocked(resp *http.Response, body []byte) bool {
	return resp.StatusCode == http.StatusTooManyRequests && strings.Contains(string(body), "temporarily blocked")
}

func getStats(t *testing.T, front *httptest.Server) map[string]any {
	t.Helper()
	_, body := get(t, front.URL+"/_room/stats", nil)
	var s map[string]any
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatalf("stats not JSON: %q", body)
	}
	return s
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

func testRegistry(t *testing.T, mutate func(*config)) (*abuseRegistry, *counters) {
	t.Helper()
	cfg := testConfig("http://127.0.0.1:1")
	if mutate != nil {
		mutate(&cfg)
	}
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	stats := &counters{}
	return newAbuseRegistry(cfg, stats), stats
}

// ─── parseConfig / normalize ─────────────────────────────────────────────────

func TestParseConfig_EnvOverridesDefaults(t *testing.T) {
	clearConcertEnv(t)
	t.Setenv("CONCERT_UPSTREAM", "http://origin.internal:9000")
	t.Setenv("CONCERT_CAPACITY", "42")
	t.Setenv("CONCERT_REAPER", "45s")
	t.Setenv("CONCERT_API_JSON", "false")
	t.Setenv("CONCERT_ADMIN_TOKEN", "s3cret")
	t.Setenv("CONCERT_ASSET_USER_CAP_H2", "64")
	t.Setenv("CONCERT_ADMIT_SECRET", strings.Repeat("k", 40))
	t.Setenv("CONCERT_BAN_PATHS", "/.env,/.git/*")
	t.Setenv("CONCERT_ABUSE_ALLOW", "198.51.100.0/24")

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
	if cfg.effectiveAssetCap() != 42*64 {
		t.Errorf("derived asset cap: got %d, want %d", cfg.effectiveAssetCap(), 42*64)
	}
	if cfg.admitSecretGenerated || string(cfg.admitSecret) != strings.Repeat("k", 40) {
		t.Error("CONCERT_ADMIT_SECRET was not used")
	}
	if len(parsePaths(cfg.banPaths)) != 2 {
		t.Errorf("banPaths: got %q", cfg.banPaths)
	}
	if len(cfg.allow) != 1 {
		t.Errorf("allow: got %v", cfg.allow)
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
		"no scheme":              {"-upstream", "not a url"},
		"ftp scheme":             {"-upstream", "ftp://files.example"},
		"no host":                {"-upstream", "http://"},
		"zero cap":               {"-cap", "0"},
		"negative cap":           {"-cap", "-5"},
		"overflows i32":          {"-cap", "3000000000"},
		"negative asset cap":     {"-asset-cap", "-1"},
		"zero h1 user cap":       {"-asset-user-cap-h1", "0"},
		"zero h2 user cap":       {"-asset-user-cap-h2", "0"},
		"negative asset wait":    {"-asset-wait", "-1s"},
		"short admit ttl":        {"-admit-ttl", "5s"},
		"catch-all bypass":       {"-bypass", "/*"},
		"reserved asset":         {"-assets", "/_room/*"},
		"reserved status":        {"-asset-public", "/queue/status"},
		"reserved ban path":      {"-ban-paths", "/_room/stats"},
		"catch-all ban path":     {"-ban-paths", "/*"},
		"duplicate path":         {"-bypass", "/x", "-assets", "/x"},
		"ban overlaps asset":     {"-assets", "/x", "-ban-paths", "/x"},
		"stream overlaps bypass": {"-bypass", "/ws", "-stream-paths", "/ws"},
		"zero stream cap":        {"-stream-cap", "0"},
		"grace below room min":   {"-first-poll-grace", "5s"},
		"grace below retries":    {"-first-poll-grace", "10s", "-retry-after", "6"},
		"bad trusted proxy":      {"-trusted-proxies", "nope"},
		"bad allow cidr":         {"-abuse-allow", "10.0.0.0/99"},
		"zero strikes":           {"-abuse-strikes", "0"},
		"zero window":            {"-abuse-window", "0s"},
		"zero cooldown":          {"-abuse-cooldown", "0s"},
		"max below cooldown":     {"-abuse-cooldown", "10m", "-abuse-max-cooldown", "5m"},
		"zero max entries":       {"-abuse-max-entries", "0"},
		"ban paths w/o abuse":    {"-abuse=false", "-ban-paths", "/.env"},
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
func TestParseConfig_ShortSecretRejected(t *testing.T) {
	clearConcertEnv(t)
	t.Setenv("CONCERT_ADMIT_SECRET", "too-short")

	if _, _, err := parseConfig(newFlagSet(), nil); err == nil {
		t.Error("expected error for a secret under 32 bytes")
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

func TestEffectiveAssetCap(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.capacity, cfg.assetUserCapH2 = 1200, 200
	if got := cfg.effectiveAssetCap(); got != 240000 {
		t.Errorf("derived: got %d, want 240000", got)
	}

	cfg.assetCap = 7
	if got := cfg.effectiveAssetCap(); got != 7 {
		t.Errorf("override: got %d, want 7", got)
	}

	cfg.assetCap = 0
	cfg.capacity, cfg.assetUserCapH2 = math.MaxInt32, 128
	if got := cfg.effectiveAssetCap(); got != math.MaxInt32 {
		t.Errorf("clamp: got %d, want %d", got, math.MaxInt32)
	}
}

func TestNewApp_RejectsInvalidConfig(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.capacity = 0
	if _, err := newApp(cfg); err == nil {
		t.Error("expected error for cap=0")
	}
}

func TestNewApp_RouteConflictIsError(t *testing.T) {
	cases := map[string]func(*config){
		"prefix vs exact": func(c *config) { c.bypass, c.assets = "/static/*", "/static/app.js" },
		"shadows status":  func(c *config) { c.assets = "/queue/*" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig("http://127.0.0.1:1")
			mutate(&cfg)
			a, err := newApp(cfg)
			if err == nil {
				a.Close()
				t.Fatal("expected a route conflict error")
			}
		})
	}
}

// ─── pure helpers ────────────────────────────────────────────────────────────

func TestStripCookies(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Cookie", "room_ticket=a; session=keep; room_pass=b; room_probe=1; concert_admit=z; theme=dark")

	stripCookies(req, proxyCookies...)

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
	stripCookies(req, proxyCookies...)
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

func TestIsMultiplexed(t *testing.T) {
	const hdr = "X-Client-Proto"
	cases := []struct {
		name       string
		header     string
		value      string
		protoMajor int
		want       bool
	}{
		{"h1 connection, no header configured", "", "", 1, false},
		{"h2 connection, no header configured", "", "", 2, true},
		{"header says HTTP/1.1", hdr, "HTTP/1.1", 1, false},
		{"header says HTTP/2.0", hdr, "HTTP/2.0", 1, true},
		{"header says HTTP/3.0", hdr, "HTTP/3.0", 1, true},
		{"header beats connection", hdr, "HTTP/1.1", 2, false},
		{"unrecognised value falls back", hdr, "SPDY", 2, true},
		{"missing value falls back", hdr, "", 1, false},
		{"header ignored when not configured", "", "HTTP/2.0", 1, false},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.ProtoMajor = c.protoMajor
		if c.value != "" {
			req.Header.Set(hdr, c.value)
		}
		if got := isMultiplexed(req, c.header); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestParsePrefixes(t *testing.T) {
	got, err := parsePrefixes(" 10.0.0.0/8, 192.0.2.1 , ::1, 2001:db8::/32 ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d prefixes, want 4", len(got))
	}
	if got[1].Bits() != 32 || got[2].Bits() != 128 {
		t.Errorf("bare addresses should be single-address prefixes: %v", got)
	}
	for _, bad := range []string{"nope", "10.0.0.0/33", "1.2.3"} {
		if _, err := parsePrefixes(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name    string
		remote  string
		trusted string
		xff     []string
		want    string
	}{
		{"untrusted remote ignores xff", "203.0.113.7:1234", "", []string{"198.51.100.1"}, "203.0.113.7"},
		{"trusted hop uses xff", "127.0.0.1:1", "127.0.0.1/32", []string{"198.51.100.1"}, "198.51.100.1"},
		{"right-most untrusted wins", "127.0.0.1:1", "127.0.0.1/32", []string{"192.0.2.66, 198.51.100.1"}, "198.51.100.1"},
		{"skips trusted hops", "127.0.0.1:1", "127.0.0.1/32,10.0.0.0/8", []string{"198.51.100.1, 10.1.2.3"}, "198.51.100.1"},
		{"multiple header lines", "127.0.0.1:1", "127.0.0.1/32,10.0.0.0/8", []string{"198.51.100.1", "10.1.2.3"}, "198.51.100.1"},
		{"malformed falls back", "127.0.0.1:1", "127.0.0.1/32", []string{"not-an-ip"}, "127.0.0.1"},
		{"no xff uses remote", "127.0.0.1:1", "127.0.0.1/32", nil, "127.0.0.1"},
		{"all trusted returns left-most", "127.0.0.1:1", "127.0.0.1/32,10.0.0.0/8", []string{"10.0.0.5, 10.0.0.6"}, "10.0.0.5"},
		{"ipv6 remote", "[2001:db8::1]:443", "", nil, "2001:db8::1"},
		{"mapped v4 is unmapped", "[::ffff:203.0.113.7]:1", "", nil, "203.0.113.7"},
	}
	for _, c := range cases {
		trusted, err := parsePrefixes(c.trusted)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = c.remote
		for _, v := range c.xff {
			req.Header.Add("X-Forwarded-For", v)
		}
		if got := clientIP(req, trusted); got.String() != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestAbuseKey(t *testing.T) {
	a, _ := abuseKey(netip.MustParseAddr("2001:db8:1:2:aaaa::1"))
	b, _ := abuseKey(netip.MustParseAddr("2001:db8:1:2:ffff::9"))
	c, _ := abuseKey(netip.MustParseAddr("2001:db8:1:3::1"))
	if a != b {
		t.Error("addresses in the same /64 must share a key")
	}
	if a == c {
		t.Error("addresses in different /64s must not share a key")
	}
	if displayKey(a) != "2001:db8:1:2::/64" {
		t.Errorf("display: got %s", displayKey(a))
	}
	v4, _ := abuseKey(netip.MustParseAddr("::ffff:203.0.113.7"))
	if v4.String() != "203.0.113.7" {
		t.Errorf("mapped v4 key: got %s", v4)
	}
	if _, ok := abuseKey(netip.Addr{}); ok {
		t.Error("invalid address must not be tracked")
	}
}

// ─── abuse registry ──────────────────────────────────────────────────────────

func TestAbuse_StrikesBanAtThreshold(t *testing.T) {
	r, stats := testRegistry(t, func(c *config) { c.abuseStrikes = 3 })
	ip := netip.MustParseAddr("203.0.113.9")
	now := time.Now()

	if r.strike(ip, 1, now) || r.strike(ip, 1, now) {
		t.Fatal("banned before threshold")
	}
	if _, banned := r.banned(ip, now); banned {
		t.Fatal("banned before threshold")
	}
	if !r.strike(ip, 1, now) {
		t.Fatal("not banned at threshold")
	}
	left, banned := r.banned(ip, now)
	if !banned || left != 5*time.Minute {
		t.Errorf("ban: banned=%v left=%s, want 5m", banned, left)
	}
	if stats.abuseBans.Load() != 1 {
		t.Errorf("bans counter: got %d", stats.abuseBans.Load())
	}
	if _, banned := r.banned(ip, now.Add(5*time.Minute)); banned {
		t.Error("ban should expire after the cooldown")
	}
}

func TestAbuse_WindowResets(t *testing.T) {
	r, _ := testRegistry(t, func(c *config) { c.abuseStrikes = 3 })
	ip := netip.MustParseAddr("203.0.113.9")
	t0 := time.Now()

	r.strike(ip, 2, t0)
	if r.strike(ip, 1, t0.Add(2*time.Minute)) {
		t.Error("strikes from an expired window must not carry over")
	}
}

func TestAbuse_EscalatingCooldown(t *testing.T) {
	r, _ := testRegistry(t, func(c *config) {
		c.abuseCooldown = time.Minute
		c.abuseMaxCooldown = 3 * time.Minute
	})
	ip := netip.MustParseAddr("203.0.113.9")
	t0 := time.Now()

	want := []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute, 3 * time.Minute}
	at := t0
	for i, w := range want {
		got, banned := r.banNow(ip, at)
		if !banned || got != w {
			t.Errorf("ban %d: got %s (banned=%v), want %s", i+1, got, banned, w)
		}
		at = at.Add(got + time.Second)
	}
}

func TestAbuse_BanNowWhileBannedReportsRemaining(t *testing.T) {
	r, stats := testRegistry(t, nil)
	ip := netip.MustParseAddr("203.0.113.9")
	t0 := time.Now()

	r.banNow(ip, t0)
	left, banned := r.banNow(ip, t0.Add(time.Minute))
	if !banned || left != 4*time.Minute {
		t.Errorf("got %s banned=%v, want 4m remaining", left, banned)
	}
	if stats.abuseBans.Load() != 1 {
		t.Error("hitting a ban path while banned must not escalate")
	}
}

func TestAbuse_ExemptNeverBanned(t *testing.T) {
	r, _ := testRegistry(t, func(c *config) {
		c.abuseStrikes = 1
		c.abuseAllow = "198.51.100.0/24"
		c.trustedProxies = "10.0.0.1"
	})
	now := time.Now()
	for _, s := range []string{"198.51.100.20", "10.0.0.1"} {
		ip := netip.MustParseAddr(s)
		if r.strike(ip, 100, now) {
			t.Errorf("%s: exempt address was banned by strikes", s)
		}
		if _, banned := r.banNow(ip, now); banned {
			t.Errorf("%s: exempt address was banned by banNow", s)
		}
	}
	if r.tracked() != 0 {
		t.Errorf("exempt addresses must not be tracked: %d", r.tracked())
	}
}

func TestAbuse_Unban(t *testing.T) {
	r, _ := testRegistry(t, nil)
	ip := netip.MustParseAddr("203.0.113.9")
	now := time.Now()

	r.banNow(ip, now)
	if !r.unban(ip) {
		t.Fatal("unban returned false for a tracked client")
	}
	if _, banned := r.banned(ip, now); banned {
		t.Error("still banned after unban")
	}
	if got, _ := r.banNow(ip, now); got != 5*time.Minute {
		t.Errorf("offense history should reset on unban: next ban %s, want 5m", got)
	}
	if r.unban(netip.MustParseAddr("192.0.2.1")) {
		t.Error("unban of an untracked client returned true")
	}
}

func TestAbuse_SweepForgetsHistory(t *testing.T) {
	r, _ := testRegistry(t, func(c *config) {
		c.abuseCooldown = time.Minute
		c.abuseMaxCooldown = time.Hour
	})
	ip := netip.MustParseAddr("203.0.113.9")
	t0 := time.Now()
	r.banNow(ip, t0)

	if n := r.sweep(t0.Add(30 * time.Minute)); n != 0 {
		t.Errorf("history swept too early: %d", n)
	}
	if n := r.sweep(t0.Add(time.Minute + time.Hour + 2*time.Minute)); n != 1 {
		t.Errorf("history not swept after max cooldown of good behaviour: %d", n)
	}
	if r.tracked() != 0 {
		t.Errorf("tracked: got %d", r.tracked())
	}

	fresh := netip.MustParseAddr("203.0.113.10")
	r.strike(fresh, 1, t0)
	if n := r.sweep(t0.Add(2 * time.Minute)); n != 1 {
		t.Errorf("never-banned entry outside its window should be swept: %d", n)
	}
}

func TestAbuse_MaxEntriesDrops(t *testing.T) {
	r, stats := testRegistry(t, func(c *config) { c.abuseMaxEntries = 1 })
	now := time.Now()

	r.banNow(netip.MustParseAddr("203.0.113.1"), now) // banned: never evicted
	r.strike(netip.MustParseAddr("203.0.113.2"), 1, now)

	if r.tracked() != 1 {
		t.Errorf("tracked: got %d, want 1", r.tracked())
	}
	if stats.abuseDropped.Load() != 1 {
		t.Errorf("dropped: got %d, want 1", stats.abuseDropped.Load())
	}
}

// ─── admission pass ──────────────────────────────────────────────────────────

func TestAdmitter_RoundTrip(t *testing.T) {
	a := newAdmitter([]byte(strings.Repeat("s", 32)), time.Minute, "/", "", false)
	now := time.Now()
	id := passID{9, 8, 7}

	v := a.mint(id, now)
	got, exp, status := a.verify(v, now)
	if status != passValid || got != id {
		t.Fatalf("round trip failed: status=%v id=%v", status, got)
	}
	if exp.Unix() != now.Add(time.Minute).Unix() {
		t.Errorf("expiry: got %v", exp)
	}

	if _, _, s := a.verify(tamper(v), now); s != passForged {
		t.Errorf("tampered pass: got %v, want forged", s)
	}
	if _, _, s := a.verify(v, now.Add(time.Minute)); s != passExpired {
		t.Errorf("expired pass: got %v, want expired", s)
	}

	other := newAdmitter([]byte(strings.Repeat("x", 32)), time.Minute, "/", "", false)
	if _, _, s := a.verify(other.mint(id, now), now); s != passStale {
		t.Errorf("pass from another key: got %v, want stale", s)
	}

	for _, junk := range []string{"nope", v + "A", "!!!!"} {
		if _, _, s := a.verify(junk, now); s != passForged {
			t.Errorf("junk %q: got %v, want forged", junk, s)
		}
	}
	if _, _, s := a.verify("", now); s != passMissing {
		t.Errorf("empty value: got %v, want missing", s)
	}
}

func TestGate_IssuesPassOnAdmittedPage(t *testing.T) {
	up := newFakeUpstream(t)
	_, front := newTestApp(t, testConfig(up.URL()), up)

	resp, _ := get(t, front.URL+"/page", map[string]string{"Accept": "text/html"})
	var found *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == admitCookie {
			found = c
		}
	}
	if found == nil {
		t.Fatal("admitted page did not issue a pass")
	}
	if !found.HttpOnly || found.SameSite != http.SameSiteLaxMode || found.MaxAge != 600 {
		t.Errorf("pass attributes: HttpOnly=%v SameSite=%v MaxAge=%d", found.HttpOnly, found.SameSite, found.MaxAge)
	}
}

func TestGate_PassRefreshedOnlyPastHalfLife(t *testing.T) {
	up := newFakeUpstream(t)
	a, front := newTestApp(t, testConfig(up.URL()), up)

	pass := admitPass(t, front)
	resp, _ := get(t, front.URL+"/page", withPass(pass, nil))
	if hasCookie(resp, admitCookie) {
		t.Error("fresh pass should not be re-issued")
	}

	id, _, status := a.admit.verify(pass, time.Now())
	if status != passValid {
		t.Fatal("issued pass does not verify")
	}
	stale := a.admit.mint(id, time.Now().Add(-a.cfg.admitTTL*3/4))
	resp, _ = get(t, front.URL+"/page", withPass(stale, nil))
	renewed, ok := cookieValue(resp, admitCookie)
	if !ok {
		t.Fatal("pass past half-life was not refreshed")
	}
	if gotID, _, s := a.admit.verify(renewed, time.Now()); s != passValid || gotID != id {
		t.Error("refresh must keep the same pass ID")
	}
}

func TestGate_QueuedClientGetsNoPass(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	_, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	for _, hdr := range []map[string]string{nil, {"Accept": "text/html"}} {
		resp, _ := get(t, front.URL+"/page", hdr)
		if hasCookie(resp, admitCookie) {
			t.Errorf("queued response (Accept=%q) issued an admission pass", hdr["Accept"])
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

func TestProxy_StripsProxyCookies(t *testing.T) {
	up := newFakeUpstream(t)
	_, front := newTestApp(t, testConfig(up.URL()), up)

	get(t, front.URL+"/c", map[string]string{
		"Cookie": "room_ticket=abc; room_pass=def; room_probe=1; concert_admit=xyz; session=keep",
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

func TestProxy_ExtendsForwardedChainFromTrustedProxy(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.trustedProxies = "127.0.0.1/32"
	_, front := newTestApp(t, cfg, up)

	get(t, front.URL+"/h", map[string]string{
		"X-Forwarded-For":   "203.0.113.9",
		"X-Forwarded-Proto": "https",
	})

	_, _, _, xff := up.seen()
	if xff != "203.0.113.9, 127.0.0.1" {
		t.Errorf("X-Forwarded-For: got %q, want the client then concert's peer", xff)
	}
	if p := up.seenProto(); p != "https" {
		t.Errorf("X-Forwarded-Proto: got %q, want https from the trusted proxy", p)
	}
}

func TestProxy_DiscardsForwardedFromUntrustedPeer(t *testing.T) {
	up := newFakeUpstream(t)
	_, front := newTestApp(t, testConfig(up.URL()), up) // nothing trusted

	get(t, front.URL+"/h", map[string]string{
		"X-Forwarded-For":   "6.6.6.6",
		"X-Forwarded-Proto": "https",
	})

	_, _, _, xff := up.seen()
	if xff != "127.0.0.1" {
		t.Errorf("X-Forwarded-For: got %q, spoofed chain must be discarded", xff)
	}
	if p := up.seenProto(); p != "http" {
		t.Errorf("X-Forwarded-Proto: got %q, want http", p)
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
	cfg.bypass = "/webhooks/*, /robots.txt"
	_, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	for _, p := range []string{"/webhooks/stripe", "/webhooks/paypal/ipn", "/robots.txt"} {
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

// ─── asset tier ──────────────────────────────────────────────────────────────

func TestAssets_DeniedWithoutPass(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.assets = "/assets/*"
	_, front := newTestApp(t, cfg, up)

	for name, hdr := range map[string]map[string]string{
		"no cookie":     nil,
		"forged cookie": withPass("forged", nil),
	} {
		resp, _ := get(t, front.URL+"/assets/app.js", hdr)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403", name, resp.StatusCode)
		}
	}
	if up.hitsFor("/assets/app.js") != 0 {
		t.Error("denied asset request reached the upstream")
	}
}

func TestAssets_ServedWithPass(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.assets = "/assets/*"
	_, front := newTestApp(t, cfg, up)

	pass := admitPass(t, front)
	resp, body := get(t, front.URL+"/assets/app.js", withPass(pass, nil))
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	if _, _, cookie, _ := up.seen(); strings.Contains(cookie, admitCookie) {
		t.Error("admission pass leaked to the upstream")
	}
}

func TestAssets_ServedWhileRoomIsFull(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.assets = "/assets/*"
	_, front := newTestApp(t, cfg, up)

	pass := admitPass(t, front)
	fillSlot(t, front, up)

	resp, _ := get(t, front.URL+"/assets/app.css", withPass(pass, nil))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("admitted user's asset: got %d, want 200 while page slots are full", resp.StatusCode)
	}
}

func TestAssets_PublicNeedsNoPass(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.assets = "/assets/*"
	cfg.assetPublic = "/uploads/*"
	_, front := newTestApp(t, cfg, up)

	resp, _ := get(t, front.URL+"/uploads/og-image.png", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("public asset: got %d, want 200", resp.StatusCode)
	}
}

func TestAssets_PerUserLimitHTTP1(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.assets = "/assets/*"
	cfg.assetUserCapH1 = 1
	cfg.assetUserWait = 50 * time.Millisecond
	_, front := newTestApp(t, cfg, up)

	passA := admitPass(t, front)
	passB := admitPass(t, front)
	park(t, front, up, "/assets/slow", withPass(passA, nil))

	resp, _ := get(t, front.URL+"/assets/app.js", withPass(passA, nil))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("same pass over its cap: got %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("429 missing Retry-After")
	}

	resp, _ = get(t, front.URL+"/assets/app.js", withPass(passB, nil))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("other pass: got %d, want 200 (limits are per user)", resp.StatusCode)
	}
}

func TestAssets_PerUserLimitHTTP2ViaHeader(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.assets = "/assets/*"
	cfg.assetUserCapH1 = 1
	cfg.assetUserCapH2 = 2
	cfg.assetUserWait = 50 * time.Millisecond
	cfg.clientProtoHeader = "X-Client-Proto"
	_, front := newTestApp(t, cfg, up)

	pass := admitPass(t, front)
	h2 := withPass(pass, map[string]string{"X-Client-Proto": "HTTP/2.0"})
	h1 := withPass(pass, map[string]string{"X-Client-Proto": "HTTP/1.1"})

	park(t, front, up, "/assets/slow", h2)
	park(t, front, up, "/assets/slow", h2) // HTTP/2 rule allows a second

	resp, _ := get(t, front.URL+"/assets/app.js", h2)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("third HTTP/2 request: got %d, want 429", resp.StatusCode)
	}

	resp, _ = get(t, front.URL+"/assets/app.js", h1)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HTTP/1.1 pool should be separate: got %d, want 200", resp.StatusCode)
	}
}

func TestAssets_GlobalLimit(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.assets = "/assets/*"
	cfg.assetCap = 1
	cfg.assetWait = 50 * time.Millisecond
	_, front := newTestApp(t, cfg, up)

	passA := admitPass(t, front)
	passB := admitPass(t, front)
	park(t, front, up, "/assets/slow", withPass(passA, nil))

	resp, _ := get(t, front.URL+"/assets/app.js", withPass(passB, nil))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("global cap reached: got %d, want 503", resp.StatusCode)
	}
}

func TestAssets_PublicCountsAgainstGlobalLimit(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.assets = "/assets/*"
	cfg.assetPublic = "/uploads/*"
	cfg.assetCap = 1
	cfg.assetWait = 50 * time.Millisecond
	_, front := newTestApp(t, cfg, up)

	pass := admitPass(t, front)
	park(t, front, up, "/assets/slow", withPass(pass, nil))

	resp, _ := get(t, front.URL+"/uploads/og-image.png", nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("public asset with global cap full: got %d, want 503", resp.StatusCode)
	}
}

func TestAssets_Stats(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 3
	cfg.assetUserCapH2 = 16
	cfg.assets = "/assets/*"
	_, front := newTestApp(t, cfg, up)

	get(t, front.URL+"/assets/app.js", nil) // denied
	pass := admitPass(t, front)
	get(t, front.URL+"/assets/app.js", withPass(pass, nil)) // served

	s := getStats(t, front)
	checks := map[string]float64{
		"asset_cap":          48, // 3 × 16, derived
		"asset_users":        1,
		"asset_denied_total": 1,
		"asset_served_total": 1,
		"asset_in_flight":    0,
	}
	for k, want := range checks {
		if s[k] != want {
			t.Errorf("%s: got %v, want %v", k, s[k], want)
		}
	}
}

func TestUserStore_SeparateProtocolSemaphores(t *testing.T) {
	s := newUserStore(2, 5)
	id := passID{1}

	h1 := s.slot(id, false, 1)
	h2 := s.slot(id, true, 1)
	if h1.Cap() != 2 || h2.Cap() != 5 {
		t.Errorf("caps: h1=%d h2=%d, want 2 and 5", h1.Cap(), h2.Cap())
	}
	if s.slot(id, false, 2) != h1 || s.slot(id, true, 2) != h2 {
		t.Error("slot must return the same semaphore for the same pass and protocol")
	}
	if s.count.Load() != 1 {
		t.Errorf("count: got %d, want 1", s.count.Load())
	}
}

func TestUserStore_SweepEvictsOnlyIdle(t *testing.T) {
	s := newUserStore(2, 5)
	idle, busy, recent := passID{1}, passID{2}, passID{3}

	s.slot(idle, false, 100)
	busySem := s.slot(busy, true, 100)
	if !busySem.TryAcquire() {
		t.Fatal("could not acquire")
	}
	s.slot(recent, false, 1000)

	if n := s.sweep(500); n != 1 {
		t.Errorf("evicted %d, want 1", n)
	}
	if s.count.Load() != 2 {
		t.Errorf("remaining: got %d, want 2 (busy and recent)", s.count.Load())
	}

	_ = busySem.Release()
	if n := s.sweep(500); n != 1 {
		t.Errorf("after release evicted %d, want 1", n)
	}
}

// ─── abuse enforcement end to end ────────────────────────────────────────────

func TestAbuse_BanPathBansInstantly(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.banPaths = "/.env,/.git/*"
	_, front := newTestApp(t, cfg, up)

	resp, body := get(t, front.URL+"/.git/config", nil)
	if !isBlocked(resp, body) {
		t.Fatalf("ban path: got %d %q, want blocked 429", resp.StatusCode, body)
	}
	if ra := resp.Header.Get("Retry-After"); ra != "300" {
		t.Errorf("Retry-After: got %q, want 300", ra)
	}
	if up.hitsFor("/.git/config") != 0 {
		t.Error("ban path reached the upstream")
	}

	resp, body = get(t, front.URL+"/hello", nil)
	if !isBlocked(resp, body) {
		t.Errorf("banned client on a normal path: got %d, want blocked 429", resp.StatusCode)
	}
	resp, body = get(t, front.URL+"/_room/healthz", nil)
	if !isBlocked(resp, body) {
		t.Errorf("ban must cover everything, including ops routes: got %d", resp.StatusCode)
	}
}

func TestAbuse_AllowlistedClientNotBanned(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.banPaths = "/.env"
	cfg.abuseAllow = "127.0.0.1/32"
	_, front := newTestApp(t, cfg, up)

	resp, body := get(t, front.URL+"/.env", nil)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Errorf("allowlisted client on a ban path: got %d %q, want proxied", resp.StatusCode, body)
	}
}

func TestAbuse_BansRealClientBehindTrustedProxy(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.trustedProxies = "127.0.0.1/32"
	cfg.banPaths = "/.env"
	_, front := newTestApp(t, cfg, up)

	resp, body := get(t, front.URL+"/.env", withXFF("203.0.113.9"))
	if !isBlocked(resp, body) {
		t.Fatalf("got %d, want blocked", resp.StatusCode)
	}
	if resp, body := get(t, front.URL+"/hello", withXFF("203.0.113.9")); !isBlocked(resp, body) {
		t.Error("banned client should stay banned")
	}
	if resp, _ := get(t, front.URL+"/hello", withXFF("198.51.100.4")); resp.StatusCode != http.StatusOK {
		t.Errorf("other client behind the same proxy: got %d, want 200", resp.StatusCode)
	}
	if resp, _ := get(t, front.URL+"/hello", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("the proxy itself must never be banned: got %d", resp.StatusCode)
	}
}

func TestAbuse_AdminFailuresBan(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.adminToken = "secret"
	_, front := newTestApp(t, cfg, up)

	post := func() (*http.Response, []byte) {
		return doReq(t, testClient, http.MethodPost, front.URL+"/_room/cap",
			map[string]string{"Authorization": "Bearer wrong"}, strings.NewReader(`{"cap":3}`))
	}
	for i := 1; i <= 4; i++ { // 4 × weight 5 = threshold 20
		if resp, _ := post(); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i, resp.StatusCode)
		}
	}
	if resp, body := post(); !isBlocked(resp, body) {
		t.Errorf("fifth attempt: got %d, want blocked", resp.StatusCode)
	}
}

func TestAbuse_ForgedPassesBan(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.assets = "/assets/*"
	cfg.abuseStrikes = 10
	_, front := newTestApp(t, cfg, up)

	forged := tamper(admitPass(t, front))
	for i := 1; i <= 2; i++ { // 2 × weight 5 = threshold 10
		if resp, _ := get(t, front.URL+"/assets/app.js", withPass(forged, nil)); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("forged attempt %d: got %d, want 403", i, resp.StatusCode)
		}
	}
	if resp, body := get(t, front.URL+"/assets/app.js", withPass(forged, nil)); !isBlocked(resp, body) {
		t.Errorf("after forged passes: got %d, want blocked", resp.StatusCode)
	}
}

func TestAbuse_StalePassNoStrike(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.assets = "/assets/*"
	_, front := newTestApp(t, cfg, up)

	other := newAdmitter([]byte(strings.Repeat("o", 32)), 10*time.Minute, "/", "", false)
	stale := other.mint(passID{1}, time.Now())
	for i := 0; i < 5; i++ {
		if resp, _ := get(t, front.URL+"/assets/app.js", withPass(stale, nil)); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("stale pass: got %d, want 403", resp.StatusCode)
		}
	}
	if s := getStats(t, front); s["abuse_strikes_total"] != float64(0) {
		t.Errorf("stale passes must not earn strikes: %v", s["abuse_strikes_total"])
	}
}

func TestAbuse_TicketChurnBans(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.abuseStrikes = 3
	a, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	for i := 1; i <= 3; i++ {
		resp, body := get(t, front.URL+"/api/x", nil) // no cookie jar
		if resp.StatusCode != http.StatusTooManyRequests || isBlocked(resp, body) {
			t.Fatalf("churn %d: got %d %q, want a queued 429", i, resp.StatusCode, body)
		}
	}
	// Churn strikes come from room's EventQueue callback, which runs in its
	// own goroutine, so the ban lands a moment after the third arrival.
	eventually(t, 2*time.Second, func() bool {
		_, banned := a.abuse.banned(netip.MustParseAddr("127.0.0.1"), time.Now())
		return banned
	}, "three cookie-less arrivals never banned the client")
	if resp, body := get(t, front.URL+"/api/x", nil); !isBlocked(resp, body) {
		t.Errorf("after churn: got %d %q, want blocked", resp.StatusCode, body)
	}
}

func TestAbuse_CookieJarClientNotChurn(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.abuseStrikes = 3
	_, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	for i := 0; i < 6; i++ {
		resp, body := doReq(t, client, http.MethodGet, front.URL+"/api/x", nil, nil)
		if isBlocked(resp, body) {
			t.Fatalf("retry %d: a client that keeps its ticket was banned", i+1)
		}
	}
}

func TestAbuse_UserThrottleStrikes(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.assets = "/assets/*"
	cfg.assetUserCapH1 = 1
	cfg.assetUserWait = 20 * time.Millisecond
	cfg.abuseStrikes = 2
	_, front := newTestApp(t, cfg, up)

	pass := admitPass(t, front)
	park(t, front, up, "/assets/slow", withPass(pass, nil))

	for i := 1; i <= 2; i++ {
		resp, body := get(t, front.URL+"/assets/a.js", withPass(pass, nil))
		if resp.StatusCode != http.StatusTooManyRequests || isBlocked(resp, body) {
			t.Fatalf("throttle %d: got %d %q, want a throttled 429", i, resp.StatusCode, body)
		}
	}
	if resp, body := get(t, front.URL+"/assets/a.js", withPass(pass, nil)); !isBlocked(resp, body) {
		t.Errorf("after repeated throttling: got %d, want blocked", resp.StatusCode)
	}
}

func TestAbuse_Disabled(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.abuseEnabled = false
	cfg.adminToken = "secret"
	_, front := newTestApp(t, cfg, up)

	for i := 0; i < 10; i++ {
		doReq(t, testClient, http.MethodPost, front.URL+"/_room/cap",
			map[string]string{"Authorization": "Bearer wrong"}, strings.NewReader(`{}`))
	}
	if resp, _ := get(t, front.URL+"/hello", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("with -abuse=false nothing is banned: got %d", resp.StatusCode)
	}
	resp, _ := get(t, front.URL+"/_room/abuse", map[string]string{"Authorization": "Bearer secret"})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("abuse endpoint when disabled: got %d, want 404", resp.StatusCode)
	}
}

func TestAbuse_AdminListAndUnban(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.trustedProxies = "127.0.0.1/32" // admin calls come from the exempt proxy address
	cfg.banPaths = "/.env"
	cfg.adminToken = "secret"
	_, front := newTestApp(t, cfg, up)
	admin := map[string]string{"Authorization": "Bearer secret"}

	get(t, front.URL+"/.env", withXFF("203.0.113.9"))

	resp, body := get(t, front.URL+"/_room/abuse", admin)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: got %d", resp.StatusCode)
	}
	var list struct {
		Tracked int       `json:"tracked"`
		Bans    []banView `json:"bans"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("list not JSON: %q", body)
	}
	if len(list.Bans) != 1 || list.Bans[0].Client != "203.0.113.9" || list.Bans[0].Offenses != 1 {
		t.Fatalf("unexpected bans: %+v", list.Bans)
	}

	resp, _ = doReq(t, testClient, http.MethodDelete, front.URL+"/_room/abuse?client=203.0.113.9", admin, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unban: got %d", resp.StatusCode)
	}
	if resp, _ := get(t, front.URL+"/hello", withXFF("203.0.113.9")); resp.StatusCode != http.StatusOK {
		t.Errorf("after unban: got %d, want 200", resp.StatusCode)
	}

	resp, _ = doReq(t, testClient, http.MethodDelete, front.URL+"/_room/abuse?client=nope", admin, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad client param: got %d, want 400", resp.StatusCode)
	}
	resp, _ = doReq(t, testClient, http.MethodDelete, front.URL+"/_room/abuse?client=192.0.2.1", admin, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("untracked client: got %d, want 404", resp.StatusCode)
	}
}

func TestAbuse_IPv6BannedPerSlash64(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.trustedProxies = "127.0.0.1/32"
	cfg.banPaths = "/.env"
	_, front := newTestApp(t, cfg, up)

	get(t, front.URL+"/.env", withXFF("2001:db8:1:2::1"))
	if resp, body := get(t, front.URL+"/hello", withXFF("2001:db8:1:2:ffff::9")); !isBlocked(resp, body) {
		t.Error("another address in the same /64 should be banned")
	}
	if resp, _ := get(t, front.URL+"/hello", withXFF("2001:db8:1:3::1")); resp.StatusCode != http.StatusOK {
		t.Errorf("a different /64 should not be banned: got %d", resp.StatusCode)
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

	s := getStats(t, front)
	for _, k := range []string{
		"upstream", "cap", "occupancy", "queue_depth", "live_queue_depth",
		"max_queue_depth", "utilization", "token_ttl",
		"queued_total", "evicted_total", "timeouts_total", "promoted_total",
		"asset_cap", "asset_in_flight", "asset_users", "asset_user_cap_h1", "asset_user_cap_h2",
		"asset_served_total", "asset_denied_total", "asset_user_throttled_total", "asset_global_throttled_total",
		"abuse_enabled", "abuse_tracked", "abuse_strikes_total", "abuse_bans_total",
		"abuse_rejected_total", "abuse_dropped_total",
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
