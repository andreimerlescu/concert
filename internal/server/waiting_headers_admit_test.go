package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// assertClearedAdmitCookie verifies that raw Set-Cookie headers in h contain
// an explicit concert_admit clearance with Max-Age=0 and empty value.
//
// # Parameters
//
//   - t: Active test handle.
//   - h: Response headers returned by the server.
//
// # Example
//
//	assertClearedAdmitCookie(t, resp.Header)
//
// # Used By
//
// Called by TestAdmitLifetimeAndClearOnRequeue in
// internal/server/waiting_headers_admit_test.go.
func assertClearedAdmitCookie(t *testing.T, h http.Header) {
	t.Helper()
	for _, raw := range h.Values("Set-Cookie") {
		if strings.HasPrefix(raw, admitCookie+"=;") && strings.Contains(raw, "Max-Age=0") {
			return
		}
	}
	t.Fatalf("expected Set-Cookie clearing %s with Max-Age=0, got Set-Cookie=%v", admitCookie, h.Values("Set-Cookie"))
}

// TestWaitingRoomSignalHeaders_HTMLAndAPIJSON verifies Lemmings checklist
// cases 1 & 2: queued HTML (200/429/503) and -api-json (200/503) waiting-room
// responses emit X-Concert-Queue: 1, Retry-After, X-Concert-Position,
// Cache-Control: no-store, omit default X-Concert-Status-Url (and emit it when
// non-default), while keeping HTML and JSON bodies backward compatible.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestWaitingRoomSignalHeaders_HTMLAndAPIJSON$' ./internal/server
//
// # Used By
//
// Invoked by the `go test` runner.
func TestWaitingRoomSignalHeaders_HTMLAndAPIJSON(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.retryAfter = 7
	cfg.apiJSON = true
	a, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	// 1. Queued HTML waiting-room response (status 200).
	htmlResp, htmlBody := get(t, front.URL+"/landing", map[string]string{"Accept": "text/html"})
	if htmlResp.StatusCode != http.StatusOK {
		t.Fatalf("HTML queued status = %d, want 200", htmlResp.StatusCode)
	}
	if got := htmlResp.Header.Get(headerConcertQueue); got != "1" {
		t.Errorf("HTML %s = %q, want 1", headerConcertQueue, got)
	}
	if got := htmlResp.Header.Get("Retry-After"); got != "7" {
		t.Errorf("HTML Retry-After = %q, want 7", got)
	}
	if got := htmlResp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("HTML Cache-Control = %q, want no-store", got)
	}
	if posStr := htmlResp.Header.Get(headerConcertPosition); posStr == "" {
		t.Errorf("HTML missing %s header", headerConcertPosition)
	} else if pos, err := strconv.Atoi(posStr); err != nil || pos < 0 {
		t.Errorf("HTML %s = %q, want non-negative integer", headerConcertPosition, posStr)
	}
	if got := htmlResp.Header.Get(headerConcertStatusURL); got != "" {
		t.Errorf("HTML %s = %q, want omitted for default /queue/status", headerConcertStatusURL, got)
	}
	htmlStr := string(htmlBody)
	if !strings.Contains(htmlStr, "/_concert/waiting.js") || !strings.Contains(htmlStr, `id="position"`) {
		t.Errorf("HTML waiting room body missing expected markers")
	}

	// 2. Queued -api-json response (status 429 from room 200).
	apiResp, apiBody := get(t, front.URL+"/api/items", map[string]string{"Accept": "application/json"})
	if apiResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("API queued status = %d, want 429", apiResp.StatusCode)
	}
	if got := apiResp.Header.Get(headerConcertQueue); got != "1" {
		t.Errorf("API %s = %q, want 1", headerConcertQueue, got)
	}
	if got := apiResp.Header.Get("Retry-After"); got != "7" {
		t.Errorf("API Retry-After = %q, want 7", got)
	}
	if got := apiResp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("API Cache-Control = %q, want no-store", got)
	}
	if posStr := apiResp.Header.Get(headerConcertPosition); posStr == "" {
		t.Errorf("API missing %s header", headerConcertPosition)
	} else if pos, err := strconv.Atoi(posStr); err != nil || pos < 0 {
		t.Errorf("API %s = %q, want non-negative integer", headerConcertPosition, posStr)
	}
	if got := apiResp.Header.Get(headerConcertStatusURL); got != "" {
		t.Errorf("API %s = %q, want omitted for default /queue/status", headerConcertStatusURL, got)
	}
	var payload map[string]any
	if err := json.Unmarshal(apiBody, &payload); err != nil {
		t.Fatalf("API body invalid JSON: %v (%q)", err, apiBody)
	}
	if payload["queued"] != true || payload["status_url"] != "/queue/status" {
		t.Errorf("API body = %v, want queued=true and status_url=/queue/status", payload)
	}

	// 3. Direct waitingRoomHeaderWriter verification for queued 503 and 429
	// responses and non-default X-Concert-Status-Url.
	tok, ok := cookieValue(htmlResp, "room_ticket")
	if !ok {
		t.Fatal("HTML queued response missing room_ticket")
	}
	for _, code := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests} {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/drop", nil)
		c.Request.Header.Set("Accept", "text/html")
		w := &waitingRoomHeaderWriter{
			ResponseWriter: c.Writer,
			a:              a,
			c:              c,
			retryAfter:     7,
			statusURL:      "/custom/queue/status",
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Add("Set-Cookie", "room_ticket="+tok+"; Path=/; HttpOnly")
		w.WriteHeader(code)
		_, _ = w.WriteString("<html>waiting</html>")

		if rec.Code != code {
			t.Errorf("queued HTML %d: status = %d", code, rec.Code)
		}
		if rec.Header().Get(headerConcertQueue) != "1" {
			t.Errorf("queued HTML %d: missing %s=1", code, headerConcertQueue)
		}
		if rec.Header().Get("Retry-After") != "7" {
			t.Errorf("queued HTML %d: Retry-After = %q, want 7", code, rec.Header().Get("Retry-After"))
		}
		if rec.Header().Get(headerConcertPosition) == "" {
			t.Errorf("queued HTML %d: missing %s", code, headerConcertPosition)
		}
		if rec.Header().Get(headerConcertStatusURL) != "/custom/queue/status" {
			t.Errorf("queued HTML %d: %s = %q, want /custom/queue/status", code, headerConcertStatusURL, rec.Header().Get(headerConcertStatusURL))
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("queued HTML %d: Cache-Control = %q, want no-store", code, rec.Header().Get("Cache-Control"))
		}
	}

	// 4. Direct apiQueueWriter verification when room emits a queued 503 (NOT ctxRoomFull).
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/drop", nil)
	inner := &waitingRoomHeaderWriter{ResponseWriter: c.Writer, a: a, c: c, retryAfter: 7}
	apiW := &apiQueueWriter{ResponseWriter: inner, a: a, c: c, retryAfter: 7}
	apiW.Header().Set("Content-Type", "text/html; charset=utf-8")
	apiW.Header().Add("Set-Cookie", "room_ticket="+tok+"; Path=/; HttpOnly")
	apiW.WriteHeader(http.StatusServiceUnavailable)
	_, _ = apiW.WriteString("<html>waiting</html>")

	if rec.Header().Get(headerConcertQueue) != "1" {
		t.Fatalf("apiQueueWriter queued 503 missing %s=1", headerConcertQueue)
	}
	if rec.Header().Get("Retry-After") != "7" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("apiQueueWriter queued 503 headers: Retry-After=%q Cache-Control=%q",
			rec.Header().Get("Retry-After"), rec.Header().Get("Cache-Control"))
	}
	if rec.Header().Get(headerConcertPosition) == "" {
		t.Fatalf("apiQueueWriter queued 503 missing %s", headerConcertPosition)
	}
	var q503 map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &q503); err != nil || q503["queued"] != true {
		t.Fatalf("apiQueueWriter queued 503 body = %q (err=%v), want queued=true", rec.Body.String(), err)
	}
}

// TestWaitingRoomSignalHeaders_StrictGuardrails verifies Lemmings checklist
// case 3: X-Concert-Queue is NEVER emitted on capacity-breaker 503s, 403
// denials, abuse/rate-limit 429 bans, refused forms, or upstream 503 errors.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestWaitingRoomSignalHeaders_StrictGuardrails$' ./internal/server
//
// # Used By
//
// Invoked by the `go test` runner.
func TestWaitingRoomSignalHeaders_StrictGuardrails(t *testing.T) {
	// 1. Upstream 503 (admitted request) must NOT carry X-Concert-Queue.
	errOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("upstream maintenance"))
	}))
	t.Cleanup(errOrigin.Close)

	cfgErr := testConfig(errOrigin.URL)
	_, frontErr := newTestApp(t, cfgErr, nil)
	upResp, _ := get(t, frontErr.URL+"/page", map[string]string{"Accept": "text/html"})
	if upResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("upstream 503 status = %d, want 503", upResp.StatusCode)
	}
	if got := upResp.Header.Get(headerConcertQueue); got != "" {
		t.Fatalf("upstream 503 unexpectedly emitted %s=%q", headerConcertQueue, got)
	}

	// 2. Capacity-breaker 503 (HTML & API), abuse 429 ban, asset 403, refused form 503.
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.maxQueue = 1
	cfg.retryAfter = 5
	cfg.assets = "/assets/*"
	cfg.trustedProxies = "127.0.0.1/32"
	cfg.priorityForms = true
	cfg.priorityCap = 1
	cfg.priorityWait = 0
	a, front := newTestApp(t, cfg, up)

	// Mint an admission pass before filling the room so we can test refused form.
	pass := admitPass(t, front)

	// Fill the single origin slot and the single queue slot.
	fillSlot(t, front, up)
	qResp, _ := doReq(t, jarClient(), http.MethodGet, front.URL+"/wait", map[string]string{
		"Accept":          "text/html",
		"X-Forwarded-For": "198.51.100.1",
	}, nil)
	if qResp.Header.Get(headerConcertQueue) != "1" {
		t.Fatalf("expected queued client to receive %s=1", headerConcertQueue)
	}

	// Capacity-breaker HTML 503 -> NO X-Concert-Queue.
	fullHTML, _ := get(t, front.URL+"/overflow", map[string]string{
		"Accept":          "text/html",
		"X-Forwarded-For": "198.51.100.2",
	})
	if fullHTML.StatusCode != http.StatusServiceUnavailable || fullHTML.Header.Get(headerConcertQueue) != "" {
		t.Fatalf("room-full HTML 503: status=%d %s=%q", fullHTML.StatusCode, headerConcertQueue, fullHTML.Header.Get(headerConcertQueue))
	}

	// Capacity-breaker API 503 -> NO X-Concert-Queue.
	fullAPI, fullBody := get(t, front.URL+"/api/overflow", map[string]string{
		"Accept":          "application/json",
		"X-Forwarded-For": "198.51.100.3",
	})
	if fullAPI.StatusCode != http.StatusServiceUnavailable || fullAPI.Header.Get(headerConcertQueue) != "" || !strings.Contains(string(fullBody), `"queued":false`) {
		t.Fatalf("room-full API 503: status=%d %s=%q body=%s", fullAPI.StatusCode, headerConcertQueue, fullAPI.Header.Get(headerConcertQueue), fullBody)
	}

	// Asset 403 denial -> NO X-Concert-Queue.
	assetResp, _ := get(t, front.URL+"/assets/app.js", withXFF("198.51.100.4"))
	if assetResp.StatusCode != http.StatusForbidden || assetResp.Header.Get(headerConcertQueue) != "" {
		t.Fatalf("asset 403: status=%d %s=%q", assetResp.StatusCode, headerConcertQueue, assetResp.Header.Get(headerConcertQueue))
	}

	// Abuse ban 429 -> NO X-Concert-Queue.
	if _, err := a.abuse.banFor(netip.MustParseAddr("198.51.100.5"), time.Hour, time.Now()); err != nil {
		t.Fatalf("banFor: %v", err)
	}
	banResp, _ := get(t, front.URL+"/page", withXFF("198.51.100.5"))
	if banResp.StatusCode != http.StatusTooManyRequests || banResp.Header.Get(headerConcertQueue) != "" {
		t.Fatalf("abuse ban 429: status=%d %s=%q", banResp.StatusCode, headerConcertQueue, banResp.Header.Get(headerConcertQueue))
	}

	// Refused form 503 when priority lane is busy -> NO X-Concert-Queue.
	g := a.current()
	if !g.lane.acquire(t.Context(), rankStaff, 0) {
		t.Fatal("could not occupy priority lane")
	}
	t.Cleanup(g.lane.release)
	formResp, _ := doReq(t, testClient, http.MethodPost, front.URL+"/checkout", map[string]string{
		"Cookie":          admitCookie + "=" + pass,
		"X-Forwarded-For": "198.51.100.6",
	}, strings.NewReader("item=1"))
	if formResp.StatusCode != http.StatusServiceUnavailable || formResp.Header.Get(headerConcertQueue) != "" {
		t.Fatalf("refused form 503: status=%d %s=%q", formResp.StatusCode, headerConcertQueue, formResp.Header.Get(headerConcertQueue))
	}
}

// TestAdmitSessionContinuity_BrowsingSlidingTTLAndPassCap verifies Lemmings
// checklist case 4: -admit-session-continuity defaults to true in parseConfig,
// active concert_admit holders bypass queue re-entry while the room is busy,
// slide both signed token expiry and cookie Max-Age past half-life, and are
// bounded by defaultAdmitPageCap (4) concurrent page requests per passID.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestAdmitSessionContinuity_BrowsingSlidingTTLAndPassCap$' ./internal/server
//
// # Used By
//
// Invoked by the `go test` runner.
func TestAdmitSessionContinuity_BrowsingSlidingTTLAndPassCap(t *testing.T) {
	// Verify default=true via parseConfig and override via CONCERT_ADMIT_SESSION_CONTINUITY.
	defCfg, _, err := parseConfig(newFlagSet(), []string{"-data-dir", ""})
	if err != nil {
		t.Fatalf("parseConfig default: %v", err)
	}
	if !defCfg.admitSessionContinuity {
		t.Fatal("default -admit-session-continuity = false, want true")
	}
	t.Setenv("CONCERT_ADMIT_SESSION_CONTINUITY", "false")
	offCfg, _, err := parseConfig(newFlagSet(), []string{"-data-dir", ""})
	if err != nil {
		t.Fatalf("parseConfig env override: %v", err)
	}
	if offCfg.admitSessionContinuity {
		t.Fatal("CONCERT_ADMIT_SESSION_CONTINUITY=false did not disable continuity")
	}

	// Start app with continuity enabled and capacity=1.
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.admitTTL = 2 * time.Minute
	cfg.admitSessionContinuity = true
	a, front := newTestApp(t, cfg, up)

	// Mint an admission pass before saturating the room.
	pass := admitPass(t, front)
	id, _, st := a.admit.verify(pass, time.Now())
	if st != passValid {
		t.Fatalf("initial pass status = %v, want passValid", st)
	}

	// Fill the single room slot so new visitors are queued.
	fillSlot(t, front, up)

	// Unadmitted visitor gets queued with X-Concert-Queue: 1.
	qResp, _ := get(t, front.URL+"/browse", map[string]string{"Accept": "text/html"})
	if qResp.Header.Get(headerConcertQueue) != "1" {
		t.Fatalf("unadmitted visitor missing %s=1", headerConcertQueue)
	}

	// Active concert_admit holder past half-life bypasses queue re-entry AND
	// slides both signed expiry and cookie Max-Age aligned to admitTTL (120s).
	pastHalf := a.admit.mint(id, time.Now().Add(-cfg.admitTTL*3/4))
	resp, body := get(t, front.URL+"/browse", withPass(pastHalf, map[string]string{"Accept": "text/html"}))
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("admitted continuity browse = %d %q, want 200 ok", resp.StatusCode, body)
	}
	if got := resp.Header.Get(headerConcertQueue); got != "" {
		t.Fatalf("admitted continuity response unexpectedly carried %s=%q", headerConcertQueue, got)
	}
	var refreshed *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == admitCookie {
			refreshed = ck
		}
	}
	if refreshed == nil {
		t.Fatal("past-half-life continuity request did not slide concert_admit cookie")
	}
	if refreshed.MaxAge != int(cfg.admitTTL/time.Second) {
		t.Errorf("refreshed MaxAge = %d, want %d", refreshed.MaxAge, int(cfg.admitTTL/time.Second))
	}
	gotID, gotExp, gotSt := a.admit.verify(refreshed.Value, time.Now())
	if gotSt != passValid || gotID != id {
		t.Fatalf("refreshed token verify = (id=%x, st=%v), want valid same passID", gotID, gotSt)
	}
	if remaining := time.Until(gotExp); remaining < cfg.admitTTL-10*time.Second {
		t.Errorf("refreshed token remaining TTL = %s, want close to %s", remaining, cfg.admitTTL)
	}

	// Bounded per-passID concurrent page semaphore (cap = defaultAdmitPageCap = 4):
	// park 4 concurrent continuity requests on /slow, synchronize via up.entered,
	// then confirm the 5th gets 429 without X-Concert-Queue while a different
	// passID is still admitted.
	otherPass := a.admit.mint(passID{9, 8, 7}, time.Now())
	var wg sync.WaitGroup
	for range defaultAdmitPageCap {
		wg.Go(func() {
			_, _ = get(t, front.URL+"/slow", withPass(pass, nil))
		})
	}
	for range defaultAdmitPageCap {
		select {
		case <-up.entered:
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for continuity request to enter upstream /slow")
		}
	}

	fifthResp, _ := get(t, front.URL+"/browse", withPass(pass, nil))
	if fifthResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("5th concurrent page for same passID = %d, want 429", fifthResp.StatusCode)
	}
	if fifthResp.Header.Get(headerConcertQueue) != "" {
		t.Fatalf("per-pass 429 throttle unexpectedly emitted %s", headerConcertQueue)
	}

	// Another passID is unaffected by the first passID's concurrency cap.
	otherResp, _ := get(t, front.URL+"/browse", withPass(otherPass, nil))
	if otherResp.StatusCode != http.StatusOK {
		t.Fatalf("distinct passID during first pass cap = %d, want 200", otherResp.StatusCode)
	}

	up.releaseAll()
	wg.Wait()
}

// TestAdmitLifetimeAndClearOnRequeue verifies Lemmings checklist case 5:
// concert_admit cookie Max-Age matches server-side admitTTL, and any request
// carrying an expired, stale, forged, or continuity-disabled concert_admit
// cookie receives Set-Cookie: concert_admit=; Max-Age=0 when re-queued.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestAdmitLifetimeAndClearOnRequeue$' ./internal/server
//
// # Used By
//
// Invoked by the `go test` runner.
func TestAdmitLifetimeAndClearOnRequeue(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.admitTTL = 90 * time.Second
	cfg.admitSessionContinuity = true
	a, front := newTestApp(t, cfg, up)

	// Cookie Max-Age matches server-side admitTTL.
	admitResp, _ := get(t, front.URL+"/start", map[string]string{"Accept": "text/html"})
	var issued *http.Cookie
	for _, ck := range admitResp.Cookies() {
		if ck.Name == admitCookie {
			issued = ck
		}
	}
	if issued == nil || issued.MaxAge != 90 {
		t.Fatalf("issued %s cookie = %+v, want MaxAge=90", admitCookie, issued)
	}
	id, _, status := a.admit.verify(issued.Value, time.Now())
	if status != passValid {
		t.Fatalf("issued pass status = %v, want passValid", status)
	}

	// Fill the room so subsequent non-continuous arrivals are re-queued.
	fillSlot(t, front, up)

	expiredPass := a.admit.mint(id, time.Now().Add(-cfg.admitTTL-time.Minute))
	staleAdmitter := newAdmitter([]byte("different-secret-0123456789abcdef"), cfg.admitTTL, "/", "", false)
	stalePass := staleAdmitter.mint(id, time.Now())
	forgedPass := "not-a-valid-pass-value"

	cases := []struct {
		name   string
		cookie string
		accept string
	}{
		{"expired pass HTML", expiredPass, "text/html"},
		{"expired pass API", expiredPass, "application/json"},
		{"stale-key pass HTML", stalePass, "text/html"},
		{"forged pass API", forgedPass, "application/json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := get(t, front.URL+"/requeue", map[string]string{
				"Accept": tc.accept,
				"Cookie": admitCookie + "=" + tc.cookie,
			})
			if resp.Header.Get(headerConcertQueue) != "1" {
				t.Fatalf("expected %s=1 on re-queued response, got %q", headerConcertQueue, resp.Header.Get(headerConcertQueue))
			}
			if !hasCookie(resp, "room_ticket") {
				t.Fatal("re-queued response missing room_ticket")
			}
			assertClearedAdmitCookie(t, resp.Header)
		})
	}

	// When continuity is explicitly OFF, even a valid concert_admit that gets
	// re-queued must be cleared with Max-Age=0 alongside room_ticket.
	upOff := newFakeUpstream(t)
	cfgOff := testConfig(upOff.URL())
	cfgOff.capacity = 1
	cfgOff.admitSessionContinuity = false
	_, frontOff := newTestApp(t, cfgOff, upOff)
	validPassOff := admitPass(t, frontOff)
	fillSlot(t, frontOff, upOff)

	requeueResp, _ := get(t, frontOff.URL+"/requeue", map[string]string{
		"Accept": "text/html",
		"Cookie": admitCookie + "=" + validPassOff,
	})
	if requeueResp.Header.Get(headerConcertQueue) != "1" || !hasCookie(requeueResp, "room_ticket") {
		t.Fatalf("continuity-off requeue: %s=%q room_ticket=%v",
			headerConcertQueue, requeueResp.Header.Get(headerConcertQueue), hasCookie(requeueResp, "room_ticket"))
	}
	assertClearedAdmitCookie(t, requeueResp.Header)
}
