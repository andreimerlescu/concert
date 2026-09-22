package main

import (
	"encoding/json"
	"io/fs"
	"math"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

const testPortalPass = "portal-test-pass-0123456789"

var (
	csrfMetaRe  = regexp.MustCompile(`name="csrf-token" content="([0-9a-f]+)"`)
	assetLinkRe = regexp.MustCompile(`(?:href|src)="(/assets/[^"]+)"`)
)

func portalTestConfig(upstream string) config {
	cfg := testConfig(upstream)
	cfg.portal = portalConfig{
		listen:     "127.0.0.1:0",
		allowSpec:  "127.0.0.1/32",
		sessionTTL: time.Hour,
		pass:       testPortalPass,
	}
	return cfg
}

func newTestPortal(t *testing.T, cfg config, up *fakeUpstream) (*app, *portal, *httptest.Server) {
	t.Helper()
	a, err := newApp(cfg)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	t.Cleanup(a.Close)
	p, err := newPortal(a)
	if err != nil {
		t.Fatalf("newPortal: %v", err)
	}
	if p == nil {
		t.Fatal("portal not enabled")
	}
	t.Cleanup(func() { _ = p.ln.Close() })
	front := httptest.NewServer(p.wrap(a.handler))
	t.Cleanup(front.Close)
	if up != nil {
		t.Cleanup(up.releaseAll)
	}
	return a, p, front
}

func portalDo(p *portal, method, target, body string, ck *http.Cookie, csrf string, form bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:40000"
	if body != "" {
		if form {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if ck != nil {
		req.AddCookie(ck)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	rec := httptest.NewRecorder()
	p.engine.ServeHTTP(rec, req)
	return rec
}

func portalLogin(t *testing.T, p *portal) (*http.Cookie, string) {
	t.Helper()
	rec := portalDo(p, http.MethodPost, "/login", "pass="+url.QueryEscape(testPortalPass), nil, "", true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: got %d, want 303", rec.Code)
	}
	var ck *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == portalCookie {
			ck = c
		}
	}
	if ck == nil {
		t.Fatal("login did not set a session cookie")
	}
	page := portalDo(p, http.MethodGet, "/", "", ck, "", false)
	m := csrfMetaRe.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatalf("dashboard has no CSRF meta tag: %s", page.Body.String())
	}
	return ck, m[1]
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("not JSON (%d): %s", rec.Code, rec.Body.String())
	}
	return v
}

// queueJarClient returns a cookie-keeping client that has been queued.
func queueJarClient(t *testing.T, front *httptest.Server) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: testClient.CheckRedirect}
	resp, _ := doReq(t, client, http.MethodGet, front.URL+"/api/wait", nil, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected to be queued, got %d", resp.StatusCode)
	}
	return client
}

// ticketOf returns the room_ticket a queued client is holding.
func ticketOf(t *testing.T, client *http.Client, front *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "room_ticket" && c.Value != "" {
			return c.Value
		}
	}
	t.Fatal("client holds no room_ticket")
	return ""
}

// ─── configuration ───────────────────────────────────────────────────────────

func TestPortalConfig_Normalize(t *testing.T) {
	disabled := portalConfig{listen: "127.0.0.1:8081", allowSpec: "127.0.0.1/32"}
	if err := disabled.normalize(); err != nil || disabled.enabled() {
		t.Errorf("no pass: err=%v enabled=%v, want disabled without error", err, disabled.enabled())
	}

	cases := map[string]portalConfig{
		"short pass":    {listen: "127.0.0.1:0", allowSpec: "127.0.0.1/32", sessionTTL: time.Hour, pass: "short"},
		"bad allow":     {listen: "127.0.0.1:0", allowSpec: "nope", sessionTTL: time.Hour, pass: testPortalPass},
		"empty allow":   {listen: "127.0.0.1:0", allowSpec: "", sessionTTL: time.Hour, pass: testPortalPass},
		"short session": {listen: "127.0.0.1:0", allowSpec: "127.0.0.1/32", sessionTTL: time.Minute, pass: testPortalPass},
	}
	for name, pc := range cases {
		if err := pc.normalize(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestPortal_DisabledReturnsNil(t *testing.T) {
	a, err := newApp(testConfig("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	p, err := newPortal(a)
	if err != nil || p != nil {
		t.Errorf("got portal=%v err=%v, want nil, nil", p, err)
	}
	if h := p.wrap(a.handler); h == nil {
		t.Error("nil portal must pass the handler through")
	}
}

func TestPortal_TemplatesAndAssetsEmbedded(t *testing.T) {
	for _, f := range []string{
		templateHeader, templateFooter, templateIndex,
		assetBootstrapCSS, assetIconsCSS, assetBootstrapJS,
		assetPortalLight, assetPortalDark, assetPortalJS,
	} {
		if _, err := fs.Stat(portalFS, "templates/"+f); err != nil {
			t.Errorf("templates/%s not embedded: %v", f, err)
		}
	}
}

// ─── rendering ───────────────────────────────────────────────────────────────

// Every stylesheet and script a rendered page links to must be served, so a
// renamed vendor file breaks this test instead of silently unstyling the portal.
func TestPortal_PagesLinkOnlyServedAssets(t *testing.T) {
	_, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)
	ck, _ := portalLogin(t, p)

	pages := map[string]*http.Cookie{"sign-in": nil, "dashboard": ck}
	for name, cookie := range pages {
		page := portalDo(p, http.MethodGet, "/", "", cookie, "", false)
		if page.Code != http.StatusOK {
			t.Fatalf("%s page: got %d", name, page.Code)
		}
		links := assetLinkRe.FindAllStringSubmatch(page.Body.String(), -1)
		if len(links) < 6 {
			t.Errorf("%s page links %d assets, want at least 6", name, len(links))
		}
		for _, m := range links {
			if rec := portalDo(p, http.MethodGet, m[1], "", nil, "", false); rec.Code != http.StatusOK {
				t.Errorf("%s page links %s, which returns %d", name, m[1], rec.Code)
			}
		}
	}
}

// ─── access control ──────────────────────────────────────────────────────────

func TestPortal_RejectsUnlistedAddress(t *testing.T) {
	_, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)
	for _, target := range []string{"/", "/assets/" + assetPortalLight, "/api/overview"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.RemoteAddr = "203.0.113.5:1234"
		rec := httptest.NewRecorder()
		p.engine.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s from an unlisted address: got %d, want 403", target, rec.Code)
		}
	}
}

func TestPortal_LoginFlow(t *testing.T) {
	_, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)

	page := portalDo(p, http.MethodGet, "/", "", nil, "", false)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `name="pass"`) {
		t.Fatalf("signed-out index should show the sign-in form: %d", page.Code)
	}
	if csp := page.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("missing CSP: %q", csp)
	}

	wrong := portalDo(p, http.MethodPost, "/login", "pass=wrong-pass-entirely", nil, "", true)
	if wrong.Code != http.StatusUnauthorized {
		t.Errorf("wrong pass: got %d, want 401", wrong.Code)
	}

	ck, csrf := portalLogin(t, p)
	if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie attributes: HttpOnly=%v SameSite=%v", ck.HttpOnly, ck.SameSite)
	}
	if len(csrf) != 32 {
		t.Errorf("csrf token length: %d", len(csrf))
	}
}

func TestPortal_LoginLockout(t *testing.T) {
	_, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)
	for i := 0; i < loginMaxFailures; i++ {
		portalDo(p, http.MethodPost, "/login", "pass=nope-nope-nope-nope", nil, "", true)
	}
	rec := portalDo(p, http.MethodPost, "/login", "pass="+url.QueryEscape(testPortalPass), nil, "", true)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("after %d failures the correct pass should be locked out: got %d", loginMaxFailures, rec.Code)
	}
}

func TestPortal_APIRequiresSession(t *testing.T) {
	_, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)
	if rec := portalDo(p, http.MethodGet, "/api/overview", "", nil, "", false); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: got %d, want 401", rec.Code)
	}
	ck, _ := portalLogin(t, p)
	bad := *ck
	bad.Value = bad.Value[:10] + "A" + bad.Value[11:]
	if rec := portalDo(p, http.MethodGet, "/api/overview", "", &bad, "", false); rec.Code != http.StatusUnauthorized {
		t.Errorf("tampered session: got %d, want 401", rec.Code)
	}
}

func TestPortal_APIRequiresCSRF(t *testing.T) {
	_, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)
	ck, csrf := portalLogin(t, p)
	if rec := portalDo(p, http.MethodPost, "/api/settings", `{"cap":3}`, ck, "", false); rec.Code != http.StatusForbidden {
		t.Errorf("missing CSRF: got %d, want 403", rec.Code)
	}
	if rec := portalDo(p, http.MethodPost, "/api/settings", `{"cap":3}`, ck, "0000", false); rec.Code != http.StatusForbidden {
		t.Errorf("wrong CSRF: got %d, want 403", rec.Code)
	}
	if rec := portalDo(p, http.MethodPost, "/api/settings", `{"cap":3}`, ck, csrf, false); rec.Code != http.StatusOK {
		t.Errorf("valid CSRF: got %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}

func TestPortal_AssetsServedOnlyFromAssetDirs(t *testing.T) {
	_, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)

	rec := portalDo(p, http.MethodGet, "/assets/"+assetPortalLight, "", nil, "", false)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/css") {
		t.Errorf("portal css: got %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	rec = portalDo(p, http.MethodGet, "/assets/"+assetBootstrapJS, "", nil, "", false)
	if rec.Code != http.StatusOK {
		t.Errorf("bootstrap js: got %d", rec.Code)
	}
	for _, target := range []string{
		"/assets/" + templateIndex,
		"/assets/" + templateHeader,
		"/assets/css/../" + templateIndex,
		"/assets/js/nope.js",
	} {
		if rec := portalDo(p, http.MethodGet, target, "", nil, "", false); rec.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", target, rec.Code)
		}
	}
}

// ─── settings ────────────────────────────────────────────────────────────────

func TestPortal_SettingsUpdate(t *testing.T) {
	a, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)
	ck, csrf := portalLogin(t, p)

	body := `{"cap":4,"max_queue":50,"rate":2.5,"surge":0.1,"skip_url":"/skip","pass_duration":"30m","token_ttl":"2m"}`
	rec := portalDo(p, http.MethodPost, "/api/settings", body, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("save: got %d %s", rec.Code, rec.Body.String())
	}
	if a.room.Cap() != 4 || a.room.MaxQueueDepth() != 50 || a.room.SkipURL() != "/skip" {
		t.Errorf("room settings not applied: cap=%d max=%d skip=%q", a.room.Cap(), a.room.MaxQueueDepth(), a.room.SkipURL())
	}
	if a.room.PassDuration() != 30*time.Minute || a.room.TokenTTL() != 2*time.Minute {
		t.Errorf("durations not applied: pass=%s ttl=%s", a.room.PassDuration(), a.room.TokenTTL())
	}
	if got := p.price(10); math.Abs(got-3.5) > 1e-9 {
		t.Errorf("price at depth 10: got %v, want 3.5", got)
	}

	bad := portalDo(p, http.MethodPost, "/api/settings", `{"cap":2,"rate":-1}`, ck, csrf, false)
	if bad.Code != http.StatusBadRequest {
		t.Errorf("invalid settings: got %d, want 400", bad.Code)
	}
	if a.room.Cap() != 4 {
		t.Error("an invalid update must not apply any field")
	}
}

// ─── bans ────────────────────────────────────────────────────────────────────

func TestPortal_BanCRUD(t *testing.T) {
	a, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)
	ck, csrf := portalLogin(t, p)
	ip := netip.MustParseAddr("203.0.113.9")

	rec := portalDo(p, http.MethodPost, "/api/bans", `{"client":"203.0.113.9","duration":"1h"}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: got %d %s", rec.Code, rec.Body.String())
	}
	if left, banned := a.abuse.banned(ip, time.Now()); !banned || left < 59*time.Minute {
		t.Errorf("after create: banned=%v left=%s", banned, left)
	}

	list := decodeJSON(t, portalDo(p, http.MethodGet, "/api/bans", "", ck, "", false))
	if bans, _ := list["bans"].([]any); len(bans) != 1 {
		t.Fatalf("list: %v", list)
	}

	rec = portalDo(p, http.MethodPost, "/api/bans", `{"client":"203.0.113.9","duration":"10m"}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("update: got %d", rec.Code)
	}
	if left, _ := a.abuse.banned(ip, time.Now()); left > 10*time.Minute {
		t.Errorf("update should replace the remaining time: %s", left)
	}
	if a.stats.abuseBans.Load() != 1 {
		t.Errorf("changing an active ban must not count as a new offense: %d", a.stats.abuseBans.Load())
	}

	rec = portalDo(p, http.MethodDelete, "/api/bans?client=203.0.113.9", "", ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: got %d", rec.Code)
	}
	if _, banned := a.abuse.banned(ip, time.Now()); banned {
		t.Error("still banned after delete")
	}

	for name, body := range map[string]string{
		"bad client":   `{"client":"nope","duration":"1h"}`,
		"bad duration": `{"client":"203.0.113.9","duration":"forever"}`,
		"too short":    `{"client":"203.0.113.9","duration":"5s"}`,
	} {
		if rec := portalDo(p, http.MethodPost, "/api/bans", body, ck, csrf, false); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, rec.Code)
		}
	}
}

func TestPortal_BanExemptClientRefused(t *testing.T) {
	cfg := portalTestConfig("http://127.0.0.1:1")
	cfg.abuseAllow = "203.0.113.0/24"
	_, p, _ := newTestPortal(t, cfg, nil)
	ck, csrf := portalLogin(t, p)

	rec := portalDo(p, http.MethodPost, "/api/bans", `{"client":"203.0.113.5","duration":"1h"}`, ck, csrf, false)
	if rec.Code != http.StatusConflict {
		t.Errorf("exempt client: got %d, want 409", rec.Code)
	}
}

// ─── queue management ────────────────────────────────────────────────────────

func TestPortal_TracksQueueAndKicks(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := portalTestConfig(up.URL())
	cfg.capacity = 1
	_, p, front := newTestPortal(t, cfg, up)
	fillSlot(t, front, up)

	client := queueJarClient(t, front)
	list := p.occupants.list(time.Now())
	if len(list) != 1 || list[0].Client != "127.0.0.1" || list[0].Path != "/api/wait" {
		t.Fatalf("occupants: %+v", list)
	}
	id := list[0].ID

	resp, _ := doReq(t, client, http.MethodGet, front.URL+"/queue/status", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status poll: %d", resp.StatusCode)
	}
	if occ, _ := p.occupants.find(id); occ.position < 1 {
		t.Errorf("position was not observed from the status reply: %d", occ.position)
	}

	ck, csrf := portalLogin(t, p)
	rec := portalDo(p, http.MethodPost, "/api/queue/kick", `{"id":"`+id+`"}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("kick: got %d %s", rec.Code, rec.Body.String())
	}
	if p.occupants.count() != 0 {
		t.Error("kicked visitor still listed")
	}

	_, body := doReq(t, client, http.MethodGet, front.URL+"/queue/status", nil, nil)
	if !strings.Contains(string(body), `"ready":true`) {
		t.Errorf("kicked poll should report ready so the page reloads: %s", body)
	}

	resp, body = doReq(t, client, http.MethodGet, front.URL+"/page", map[string]string{"Accept": "text/html"}, nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "removed from the line") {
		t.Errorf("kicked page load: got %d %s", resp.StatusCode, body)
	}

	resp, _ = doReq(t, client, http.MethodGet, front.URL+"/api/again", nil, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("a kicked visitor should be able to rejoin at the back: got %d", resp.StatusCode)
	}
	if p.occupants.count() != 1 {
		t.Errorf("rejoined visitor should be tracked with a new ticket: %d", p.occupants.count())
	}
}

func TestPortal_KickAndBan(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := portalTestConfig(up.URL())
	cfg.capacity = 1
	a, p, front := newTestPortal(t, cfg, up)
	fillSlot(t, front, up)

	queueJarClient(t, front)
	id := p.occupants.list(time.Now())[0].ID

	ck, csrf := portalLogin(t, p)
	rec := portalDo(p, http.MethodPost, "/api/queue/kick", `{"id":"`+id+`","ban":true}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("kick+ban: got %d %s", rec.Code, rec.Body.String())
	}
	if v := decodeJSON(t, rec); v["banned"] != true {
		t.Errorf("response: %v", v)
	}
	if _, banned := a.abuse.banned(netip.MustParseAddr("127.0.0.1"), time.Now()); !banned {
		t.Error("visitor's address was not banned")
	}
	if resp, body := get(t, front.URL+"/hello", nil); !isBlocked(resp, body) {
		t.Errorf("banned visitor: got %d", resp.StatusCode)
	}
}

// Promotes the second visitor in line past the first. A single queued visitor
// is already at position 1, where "move to front" has nothing to do.
func TestPortal_Promote(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := portalTestConfig(up.URL())
	cfg.capacity = 1
	_, p, front := newTestPortal(t, cfg, up)
	fillSlot(t, front, up)

	queueJarClient(t, front)           // position 1
	second := queueJarClient(t, front) // position 2
	id := occupantID(ticketOf(t, second, front))
	if _, ok := p.occupants.find(id); !ok {
		t.Fatal("second visitor is not tracked")
	}

	ck, csrf := portalLogin(t, p)
	rec := portalDo(p, http.MethodPost, "/api/queue/promote", `{"id":"`+id+`"}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("promote: got %d %s", rec.Code, rec.Body.String())
	}

	// First poll for this ticket, so room's one-poll-per-second limit
	// cannot interfere.
	resp, body := doReq(t, second, http.MethodGet, front.URL+"/queue/status", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status poll: got %d %s", resp.StatusCode, body)
	}
	var st struct {
		Ready    bool  `json:"ready"`
		Position int64 `json:"position"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("status not JSON: %s", body)
	}
	if !st.Ready && st.Position != 1 {
		t.Errorf("promoted visitor should be next in line: ready=%v position=%d", st.Ready, st.Position)
	}

	if rec := portalDo(p, http.MethodPost, "/api/queue/promote", `{"id":"nope"}`, ck, csrf, false); rec.Code != http.StatusNotFound {
		t.Errorf("unknown visitor: got %d, want 404", rec.Code)
	}
}

func TestPortal_Overview(t *testing.T) {
	_, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)
	ck, _ := portalLogin(t, p)
	v := decodeJSON(t, portalDo(p, http.MethodGet, "/api/overview", "", ck, "", false))
	for _, k := range []string{
		"cap", "occupancy", "live_queue_depth", "asset_cap", "asset_in_flight",
		"active_bans", "occupants_tracked", "kicked_active", "rate", "surge", "abuse_enabled",
	} {
		if _, ok := v[k]; !ok {
			t.Errorf("overview missing %q", k)
		}
	}
}

func TestOccupantStore_Bounded(t *testing.T) {
	s := newOccupantStore(1)
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	s.join("a", ip, "ua", "/", now)
	s.join("b", ip, "ua", "/", now)
	if s.count() != 1 || s.dropped.Load() != 1 {
		t.Errorf("count=%d dropped=%d, want 1 and 1", s.count(), s.dropped.Load())
	}
	if n := s.sweep(now.Add(time.Hour), time.Minute, time.Minute); n != 1 {
		t.Errorf("sweep: %d", n)
	}
}
