package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andreimerlescu/room"
	"github.com/gin-gonic/gin"
)

func TestQueue_MaxQueueBurstSelfHealsAfterClientsDisconnect(t *testing.T) {
	t.Run("branded HTML 503, api-json 503, overview fields, and self-heal after disconnect", func(t *testing.T) {
		up := newFakeUpstream(t)
		cfg := portalTestConfig(up.URL())
		cfg.capacity = 2
		cfg.maxQueue = 2
		cfg.retryAfter = 2
		cfg.readyGrace = 5 * time.Second
		cfg.idlePollTTL = 10 * time.Second
		cfg.reaper = 5 * time.Second
		cfg.apiJSON = true
		cfg.trustedProxies = "127.0.0.1/32"

		a, p, front := newTestPortal(t, cfg, up)

		// Fill both origin slots so subsequent arrivals enter the waiting room.
		fillSlot(t, front, up)
		fillSlot(t, front, up)

		// Queue two browser clients that actively poll /queue/status (marking
		// seen=true so first_poll_grace alone would not reclaim them), then
		// disconnect mid-line by stopping all polls.
		c1 := jarClient()
		c2 := jarClient()
		for i, cl := range []*http.Client{c1, c2} {
			ip := "203.0.113.1"
			if i == 1 {
				ip = "203.0.113.2"
			}
			r, _ := doReq(t, cl, http.MethodGet, front.URL+"/landing", map[string]string{
				"Accept":          "text/html",
				"X-Forwarded-For": ip,
			}, nil)
			if r.StatusCode != http.StatusOK || !hasCookie(r, "room_ticket") {
				t.Fatalf("poller %d: got %d, want queued 200 with room_ticket", i, r.StatusCode)
			}
			sr, sb := doReq(t, cl, http.MethodGet, front.URL+"/queue/status", withXFF(ip), nil)
			if sr.StatusCode != http.StatusOK || !strings.Contains(string(sb), `"ready":false`) {
				t.Fatalf("poller %d status: got %d %s", i, sr.StatusCode, sb)
			}
		}
		if got := a.room.LiveQueueDepth(); got != 2 {
			t.Fatalf("live_queue_depth = %d, want 2", got)
		}

		// 1. Excess HTML browser receives branded 503 with Retry-After and strict CSP.
		htmlResp, htmlBody := get(t, front.URL+"/landing", map[string]string{
			"Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
			"X-Forwarded-For": "203.0.113.10",
		})
		if htmlResp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("HTML overflow status = %d, want 503 (body=%q)", htmlResp.StatusCode, htmlBody)
		}
		if got := htmlResp.Header.Get("Retry-After"); got != "2" {
			t.Errorf("HTML 503 Retry-After = %q, want %q", got, "2")
		}
		if got := htmlResp.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("HTML 503 Cache-Control = %q, want no-store", got)
		}
		if got := htmlResp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
			t.Errorf("HTML 503 Content-Type = %q, want text/html; charset=utf-8", got)
		}
		if got := htmlResp.Header.Get("Content-Security-Policy"); got != busyPageCSP {
			t.Errorf("HTML 503 CSP = %q, want %q", got, busyPageCSP)
		}
		if got := htmlResp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("HTML 503 X-Content-Type-Options = %q, want nosniff", got)
		}
		if got := htmlResp.Header.Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("HTML 503 Referrer-Policy = %q, want no-referrer", got)
		}
		htmlStr := string(htmlBody)
		for _, want := range []string{
			`data-retry-after="2"`,
			`href="/_concert/waiting.css"`,
			`src="/_concert/busy.js"`,
			`<noscript>`,
			`retry-now`,
		} {
			if !strings.Contains(htmlStr, want) {
				t.Errorf("HTML 503 body missing %q", want)
			}
		}
		for _, forbid := range []string{"{{.RetryAfter}}", "<style", "<script>"} {
			if strings.Contains(htmlStr, forbid) {
				t.Errorf("HTML 503 body must not contain %q", forbid)
			}
		}

		// 2. /_concert/busy.js is served outside room even while saturated.
		jsResp, jsBody := get(t, front.URL+"/_concert/busy.js", withXFF("203.0.113.10"))
		if jsResp.StatusCode != http.StatusOK {
			t.Fatalf("GET /_concert/busy.js status = %d, want 200", jsResp.StatusCode)
		}
		if got := jsResp.Header.Get("Content-Type"); got != "application/javascript; charset=utf-8" {
			t.Errorf("/_concert/busy.js Content-Type = %q, want application/javascript; charset=utf-8", got)
		}
		if got := jsResp.Header.Get("Cache-Control"); got != "public, max-age=300" {
			t.Errorf("/_concert/busy.js Cache-Control = %q, want public, max-age=300", got)
		}
		if got := jsResp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("/_concert/busy.js X-Content-Type-Options = %q, want nosniff", got)
		}
		if !strings.Contains(string(jsBody), "retryAfter") || !strings.Contains(string(jsBody), "window.location.reload") {
			t.Errorf("/_concert/busy.js body unexpected: %q", jsBody)
		}

		// 3. Excess -api-json non-HTML client receives JSON 503.
		apiResp, apiBody := get(t, front.URL+"/api/items", map[string]string{
			"Accept":          "application/json",
			"X-Forwarded-For": "203.0.113.11",
		})
		if apiResp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("API overflow status = %d, want 503 (body=%q)", apiResp.StatusCode, apiBody)
		}
		if got := apiResp.Header.Get("Retry-After"); got != "2" {
			t.Errorf("API 503 Retry-After = %q, want 2", got)
		}
		if got := apiResp.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("API 503 Cache-Control = %q, want no-store", got)
		}
		if got := apiResp.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Errorf("API 503 Content-Type = %q, want application/json; charset=utf-8", got)
		}
		const wantJSON = `{"error":"waiting room is full","queued":false,"retry_after_seconds":2}`
		if string(apiBody) != wantJSON {
			t.Errorf("API 503 body = %s, want %s", apiBody, wantJSON)
		}

		// EventReject callbacks are asynchronous; wait for both rejections to register.
		eventually(t, 2*time.Second, func() bool {
			return a.stats.rejected503.Load() == 2
		}, "rejected503 counter did not reach 2")

		if metrics := a.renderPrometheusMetrics(); !strings.Contains(metrics, "concert_room_rejected_503_total 2\n") {
			t.Errorf("metrics missing concert_room_rejected_503_total 2:\n%s", metrics)
		}

		// 4. Verify Portal GET /api/overview exposes all new room/timeout fields.
		ck, _ := portalLogin(t, p)
		ovRec := portalDo(p, http.MethodGet, "/api/overview", "", ck, "", false)
		if ovRec.Code != http.StatusOK {
			t.Fatalf("GET /api/overview = %d %s", ovRec.Code, ovRec.Body.String())
		}
		ov := decodeJSON(t, ovRec)
		if ov["token_ttl"] != a.room.TokenTTL().String() {
			t.Errorf("overview token_ttl = %v, want %s", ov["token_ttl"], a.room.TokenTTL())
		}
		if ov["ready_grace"] != "5s" {
			t.Errorf("overview ready_grace = %v, want 5s", ov["ready_grace"])
		}
		if ov["idle_poll_ttl"] != "10s" {
			t.Errorf("overview idle_poll_ttl = %v, want 10s", ov["idle_poll_ttl"])
		}
		if ov["reaper"] != "5s" {
			t.Errorf("overview reaper = %v, want 5s", ov["reaper"])
		}
		if ov["rejected_503_total"] != float64(2) {
			t.Errorf("overview rejected_503_total = %v, want 2", ov["rejected_503_total"])
		}
		if ov["cleared_total"] != float64(0) {
			t.Errorf("overview cleared_total = %v, want 0", ov["cleared_total"])
		}
		if ov["upstream_body_idle_timeouts_total"] != float64(0) {
			t.Errorf("overview upstream_body_idle_timeouts_total = %v, want 0", ov["upstream_body_idle_timeouts_total"])
		}

		// 5. Polling clients c1 and c2 are now disconnected; release upstream slots
		// and confirm a fresh visitor is admitted with 200 OK within ready_grace + 2s
		// with zero restart.
		up.releaseAll()
		eventually(t, 2*time.Second, func() bool { return a.room.Len() == 0 }, "origin slots did not drain")

		healStart := time.Now()
		deadline := healStart.Add(cfg.readyGrace + 2*time.Second)
		admitted := false
		for time.Now().Before(deadline) {
			resp, body := get(t, front.URL+"/fresh", map[string]string{
				"Accept":          "text/html",
				"X-Forwarded-For": "203.0.113.99",
			})
			if resp.StatusCode == http.StatusOK && string(body) == "ok" {
				admitted = true
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		elapsed := time.Since(healStart)
		if !admitted {
			t.Fatalf("fresh visitor was not admitted within ready_grace+2s (%s); live=%d depth=%d occ=%d",
				elapsed, a.room.LiveQueueDepth(), a.room.QueueDepth(), a.room.Len())
		}
		if a.room.LiveQueueDepth() != 0 {
			t.Errorf("live_queue_depth after self-heal = %d, want 0", a.room.LiveQueueDepth())
		}
	})

	t.Run("api-json disabled returns empty 503 for non-HTML and branded HTML for browsers", func(t *testing.T) {
		up := newFakeUpstream(t)
		cfg := testConfig(up.URL())
		cfg.capacity = 1
		cfg.maxQueue = 1
		cfg.retryAfter = 3
		cfg.apiJSON = false
		_, front := newTestApp(t, cfg, up)
		fillSlot(t, front, up)

		// Fill the single queue slot.
		qResp, _ := get(t, front.URL+"/q", map[string]string{"Accept": "text/html"})
		if qResp.StatusCode != http.StatusOK || !hasCookie(qResp, "room_ticket") {
			t.Fatalf("first queued request: got %d", qResp.StatusCode)
		}

		// Non-HTML with -api-json=false gets 503 with empty body and Retry-After.
		rawResp, rawBody := get(t, front.URL+"/api/raw", nil)
		if rawResp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("raw 503 status = %d, want 503", rawResp.StatusCode)
		}
		if len(rawBody) != 0 {
			t.Errorf("raw 503 body = %q, want empty", rawBody)
		}
		if got := rawResp.Header.Get("Retry-After"); got != "3" {
			t.Errorf("raw 503 Retry-After = %q, want 3", got)
		}
		if got := rawResp.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("raw 503 Cache-Control = %q, want no-store", got)
		}

		// HTML browser still gets branded HTML 503 even when -api-json=false.
		htmlResp, htmlBody := get(t, front.URL+"/page", map[string]string{"Accept": "text/html"})
		if htmlResp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("HTML 503 status = %d, want 503", htmlResp.StatusCode)
		}
		if got := htmlResp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
			t.Errorf("HTML 503 Content-Type = %q", got)
		}
		if !strings.Contains(string(htmlBody), `data-retry-after="3"`) {
			t.Errorf("HTML 503 body missing substituted retry-after: %q", htmlBody)
		}
	})

	t.Run("busy-html custom override substitutes RetryAfter", func(t *testing.T) {
		up := newFakeUpstream(t)
		customPath := filepath.Join(t.TempDir(), "custom-busy.html")
		const tpl = `<!doctype html><html><body data-retry-after="{{.RetryAfter}}">Custom Busy Retry {{.RetryAfter}}s</body></html>`
		if err := os.WriteFile(customPath, []byte(tpl), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := testConfig(up.URL())
		cfg.capacity = 1
		cfg.maxQueue = 1
		cfg.retryAfter = 7
		cfg.busyHTMLFile = customPath
		_, front := newTestApp(t, cfg, up)
		fillSlot(t, front, up)

		qResp, _ := get(t, front.URL+"/q", map[string]string{"Accept": "text/html"})
		if qResp.StatusCode != http.StatusOK {
			t.Fatalf("queue fill: got %d", qResp.StatusCode)
		}

		resp, body := get(t, front.URL+"/over", map[string]string{"Accept": "text/html"})
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("custom busy status = %d, want 503", resp.StatusCode)
		}
		const wantBody = `<!doctype html><html><body data-retry-after="7">Custom Busy Retry 7s</body></html>`
		if string(body) != wantBody {
			t.Errorf("custom busy body = %q, want %q", body, wantBody)
		}
		if got := resp.Header.Get("Retry-After"); got != "7" {
			t.Errorf("Retry-After = %q, want 7", got)
		}
		if got := resp.Header.Get("Content-Security-Policy"); got != busyPageCSP {
			t.Errorf("CSP = %q, want %q", got, busyPageCSP)
		}
	})

	t.Run("agentWaitWriter passes through ctxRoomFull JSON 503 without 429 misclassification", func(t *testing.T) {
		up := newFakeUpstream(t)
		cfg := testConfig(up.URL())
		cfg.retryAfter = 6
		a, err := newApp(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()

		var capturedMode agentWriteMode
		r := gin.New()
		r.GET("/drop", func(c *gin.Context) {
			c.Set(ctxAgentKey, "s:test-agent-session")
			w := &agentWaitWriter{ResponseWriter: c.Writer, c: c, retryAfter: cfg.retryAfter}
			c.Writer = w
			a.handleRoomFull(c, room.Snapshot{Event: room.EventReject})
			capturedMode = w.mode
			c.Writer = w.ResponseWriter
		})

		req := httptest.NewRequest(http.MethodGet, "/drop", nil)
		// Even if an agent sends Accept: text/html, ctxAgentKey takes precedence.
		req.Header.Set("Accept", "text/html")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if capturedMode != agentPassThrough {
			t.Fatalf("agentWaitWriter mode = %v, want agentPassThrough (must not misclassify JSON 503 as agentHeld)", capturedMode)
		}
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
		if got := rec.Header().Get("Retry-After"); got != "6" {
			t.Errorf("Retry-After = %q, want 6", got)
		}
		var payload map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("response not JSON: %q", rec.Body.String())
		}
		if payload["queued"] != false || payload["error"] != "waiting room is full" || payload["retry_after_seconds"] != float64(6) {
			t.Errorf("unexpected JSON payload: %+v", payload)
		}
	})
}
