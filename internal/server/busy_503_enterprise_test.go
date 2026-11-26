//go:build enterprise

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/mailer"
)

func TestQueue_MaxQueueBurstSelfHeals_EnterpriseAlertsAndKeyedAgent(t *testing.T) {
	mockProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ok"}`))
	}))
	defer mockProvider.Close()

	up := newFakeUpstream(t)
	cfg := agentTestConfig(t, up, true)
	cfg.maxQueue = 1
	cfg.retryAfter = 4
	cfg.apiJSON = true
	cfg.admitSecret = []byte("0123456789abcdef0123456789abcdef")
	cfg.admitSecretGenerated = false
	cfg.email = emailConfig{
		provider:           mailer.ProviderSendPanda,
		sendPandaURL:       mockProvider.URL + "/v1",
		sendPandaAPIKey:    "sp_test_key",
		fromName:           "Concert Ops",
		fromAddr:           "alerts@example.com",
		toAddrs:            "admin@example.com",
		cadenceMax:         4,
		cadenceWindowValue: 60,
		cadenceWindowUnit:  mailer.UnitMinutes,
		events:             mailer.CatQueue,
		orgName:            "Concert Enterprise",
		postalAddress:      "500 Market St, San Francisco, CA 94105",
		privacyURL:         "https://concert.example/privacy",
		termsURL:           "https://concert.example/terms",
		portalURL:          "https://portal.concert.example",
		publicBaseURL:      "https://shop.concert.example",
	}

	a, _, front := newTestPortal(t, cfg, up)
	if a.mailer == nil {
		t.Fatal("expected mailer to be initialized in enterprise test")
	}

	alertCount := func(fp string) int {
		for _, ev := range a.mailer.Status().Pending {
			if ev.Fingerprint == fp {
				return ev.Count
			}
		}
		return 0
	}

	fillSlot(t, front, up)
	// Fill the single queue slot with a cookie client.
	doReq(t, jarClient(), http.MethodGet, front.URL+"/api/wait", withXFF("198.51.100.2"), nil)
	if got := a.room.LiveQueueDepth(); got != 1 {
		t.Fatalf("live_queue_depth = %d, want 1", got)
	}

	// 1. HTML browser rejected with branded 503 fires exactly 1 queue:breaker-503 alert.
	htmlResp, htmlBody := get(t, front.URL+"/drop", map[string]string{
		"Accept":          "text/html",
		"X-Forwarded-For": "203.0.113.10",
	})
	if htmlResp.StatusCode != http.StatusServiceUnavailable || htmlResp.Header.Get("Retry-After") != "4" ||
		htmlResp.Header.Get("Content-Security-Policy") != busyPageCSP || !strings.Contains(string(htmlBody), `data-retry-after="4"`) {
		t.Fatalf("HTML 503: status=%d retry=%q csp=%q body=%q",
			htmlResp.StatusCode, htmlResp.Header.Get("Retry-After"), htmlResp.Header.Get("Content-Security-Policy"), htmlBody)
	}
	eventually(t, 2*time.Second, func() bool {
		return a.stats.rejected503.Load() == 1 && alertCount("queue:breaker-503") == 1
	}, "expected rejected503=1 and queue:breaker-503 alert count=1 after HTML 503")

	// 2. Enterprise /_concert/busy.js (fastlane.go) is served outside room while full.
	jsResp, jsBody := get(t, front.URL+"/_concert/busy.js", withXFF("203.0.113.10"))
	if jsResp.StatusCode != http.StatusOK ||
		jsResp.Header.Get("Content-Type") != "application/javascript; charset=utf-8" ||
		jsResp.Header.Get("Cache-Control") != "public, max-age=300" ||
		jsResp.Header.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(string(jsBody), "retryAfter") {
		t.Fatalf("enterprise /_concert/busy.js: status=%d ct=%q cc=%q nosniff=%q",
			jsResp.StatusCode, jsResp.Header.Get("Content-Type"), jsResp.Header.Get("Cache-Control"), jsResp.Header.Get("X-Content-Type-Options"))
	}

	// 3. -api-json non-HTML client rejected with JSON 503 fires strictly +1 alert (no duplicate from apiQueueWriter).
	const wantJSON = `{"error":"waiting room is full","queued":false,"retry_after_seconds":4}`
	apiResp, apiBody := get(t, front.URL+"/api/x", map[string]string{
		"Accept":          "application/json",
		"X-Forwarded-For": "203.0.113.11",
	})
	if apiResp.StatusCode != http.StatusServiceUnavailable || string(apiBody) != wantJSON || apiResp.Header.Get("Retry-After") != "4" {
		t.Fatalf("API 503: status=%d retry=%q body=%s", apiResp.StatusCode, apiResp.Header.Get("Retry-After"), apiBody)
	}
	eventually(t, 2*time.Second, func() bool {
		return a.stats.rejected503.Load() == 2 && alertCount("queue:breaker-503") == 2
	}, "expected rejected503=2 and single-counted queue:breaker-503 alert count=2 after API 503")
	// Confirm no delayed duplicate alert arrived.
	time.Sleep(150 * time.Millisecond)
	if got := alertCount("queue:breaker-503"); got != 2 {
		t.Fatalf("duplicate queue:breaker-503 alert detected after API 503: count=%d, want 2", got)
	}

	// 4. Keyed agent rejected with JSON 503 (never misclassified as 429) and leaks zero agent places.
	tok := session(t, front, "203.0.113.12")
	hdr := asAgent("203.0.113.12", tok)
	hdr["Accept"] = "text/html" // keyed agent must still receive JSON 503
	agResp, agBody := get(t, front.URL+"/drop", hdr)
	if agResp.StatusCode != http.StatusServiceUnavailable || string(agBody) != wantJSON ||
		agResp.Header.Get("Retry-After") != "4" || agResp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("keyed agent 503: status=%d retry=%q cc=%q body=%s",
			agResp.StatusCode, agResp.Header.Get("Retry-After"), agResp.Header.Get("Cache-Control"), agBody)
	}
	eventually(t, 2*time.Second, func() bool {
		return a.agents.held() == 0 && a.stats.rejected503.Load() == 3 && alertCount("queue:breaker-503") == 3
	}, "keyed agent 503 leaked agent place or missed EventReject alert")

	// 5. apiQueueWriter.translate(503) (used on sem.AcquireWith cancel/timeout) must NOT emit a false-positive breaker alert.
	w := &apiQueueWriter{retryAfter: 4}
	status, body := w.translate(http.StatusServiceUnavailable)
	if status != http.StatusServiceUnavailable || string(body) != wantJSON {
		t.Fatalf("translate(503) = %d %s, want 503 %s", status, body, wantJSON)
	}
	time.Sleep(100 * time.Millisecond)
	if got := alertCount("queue:breaker-503"); got != 3 {
		t.Fatalf("apiQueueWriter.translate(503) emitted false-positive alert: count=%d, want 3", got)
	}
}
