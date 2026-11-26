//go:build enterprise

package server

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQueue_ClearEndpointRBACAndAudit(t *testing.T) {
	up := newFakeUpstream(t)

	viewerHash, err := hashArgon2id("viewer-clear-secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	opHash, err := hashArgon2id("operator-clear-secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	usersJSON, err := json.Marshal([]portalUserSpec{
		{Username: "alice-viewer", PasswordHash: viewerHash, Role: "viewer"},
		{Username: "bob-operator", PasswordHash: opHash, Role: "operator"},
	})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	secret := []byte(strings.Repeat("q", 40))

	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.idlePollTTL = 30 * time.Second
	cfg.readyGrace = 0
	cfg.dataDir = dir
	cfg.admitSecret = secret
	cfg.adminTokensSpec = "prom:viewer:viewer-token-123456,ops:operator:operator-token-123456"
	cfg.portal = portalConfig{
		listen:     "127.0.0.1:0",
		allowSpec:  "127.0.0.1/32",
		sessionTTL: time.Hour,
		usersSpec:  string(usersJSON),
	}

	a, err := newApp(cfg)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	t.Cleanup(a.Close)

	p, err := newPortal(a)
	if err != nil || p == nil {
		t.Fatalf("newPortal: %v", err)
	}
	t.Cleanup(p.closeListener)

	front := httptest.NewServer(p.wrap(a.handler))
	t.Cleanup(front.Close)
	t.Cleanup(up.releaseAll)

	fillSlot(t, front, up)

	// Log in viewer and operator in Portal.
	loginUser := func(username, pass string) (*http.Cookie, string) {
		form := "user=" + url.QueryEscape(username) + "&pass=" + url.QueryEscape(pass)
		rec := portalDo(p, http.MethodPost, "/login", form, nil, "", true)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("login %s: got %d", username, rec.Code)
		}
		var ck *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == portalCookie {
				ck = c
			}
		}
		if ck == nil {
			t.Fatalf("login %s: missing session cookie", username)
		}
		page := portalDo(p, http.MethodGet, "/", "", ck, "", false)
		m := csrfMetaRe.FindStringSubmatch(page.Body.String())
		if m == nil {
			t.Fatalf("login %s: missing CSRF meta tag", username)
		}
		return ck, m[1]
	}

	viewerCK, viewerCSRF := loginUser("alice-viewer", "viewer-clear-secret-pass")
	opCK, opCSRF := loginUser("bob-operator", "operator-clear-secret-pass")

	// 1. Viewer gets 403 on BOTH POST /_room/queue/clear and POST /api/queue/clear.
	resp, _ := doReq(t, testClient, http.MethodPost, front.URL+"/_room/queue/clear", map[string]string{
		"Authorization": "Bearer viewer-token-123456",
		"Content-Type":  "application/json",
	}, strings.NewReader(`{"mode":"all"}`))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer Bearer POST /_room/queue/clear: got %d, want 403", resp.StatusCode)
	}

	rec := portalDo(p, http.MethodPost, "/api/queue/clear", `{"mode":"all"}`, viewerCK, viewerCSRF, false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer Portal POST /api/queue/clear: got %d, want 403", rec.Code)
	}

	// 2. Queue an older live visitor, wait >1s, then queue a fresh live visitor + reserve an agent key.
	queueJarClient(t, front)
	time.Sleep(1150 * time.Millisecond)
	queueJarClient(t, front)
	a.agents.reserve(a.room, agentKeyPrefix+"ent-agent", netip.MustParseAddr("203.0.113.45"), 4, time.Now())

	// Operator clears stale (explicit max_idle_seconds=1) via Bearer POST /_room/queue/clear.
	resp, raw := doReq(t, testClient, http.MethodPost, front.URL+"/_room/queue/clear", map[string]string{
		"Authorization": "Bearer operator-token-123456",
		"Content-Type":  "application/json",
	}, strings.NewReader(`{"mode":"stale","max_idle_seconds":1}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("operator API stale clear: got %d %s", resp.StatusCode, raw)
	}
	var apiOut map[string]any
	if err := json.Unmarshal(raw, &apiOut); err != nil {
		t.Fatal(err)
	}
	if apiOut["mode"] != "stale" || apiOut["removed"] != float64(1) || apiOut["live_queue_depth"] != float64(1) {
		t.Fatalf("operator API stale response: %v", apiOut)
	}
	if a.agents.held() != 0 {
		t.Errorf("agents.held after API clear = %d, want 0", a.agents.held())
	}

	// 3. Queue one more visitor and test operator via Portal POST /api/queue/clear (all).
	queueJarClient(t, front)
	if a.room.LiveQueueDepth() != 2 {
		t.Fatalf("pre-portal-clear live_queue_depth = %d, want 2", a.room.LiveQueueDepth())
	}

	rec = portalDo(p, http.MethodPost, "/api/queue/clear", `{"mode":"all"}`, opCK, opCSRF, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("operator Portal all clear: got %d %s", rec.Code, rec.Body.String())
	}
	portalOut := decodeJSON(t, rec)
	if portalOut["mode"] != "all" || portalOut["removed"] != float64(2) ||
		portalOut["live_queue_depth"] != float64(0) || portalOut["queue_depth"] != float64(0) {
		t.Fatalf("operator Portal all response: %v", portalOut)
	}
	if p.notes.count() != 0 {
		t.Errorf("notes after portal clear = %d, want 0", p.notes.count())
	}
	if p.kicked.count() != 0 {
		t.Errorf("kicked after portal clear = %d, want 0", p.kicked.count())
	}
	if a.stats.cleared.Load() != 3 {
		t.Errorf("stats.cleared = %d, want 3", a.stats.cleared.Load())
	}

	// 4. Verify audit.jsonl cryptographic chain and queue.clear entries (both api and portal, outcome ok).
	auditPath := filepath.Join(dir, auditLogName)
	n, err := verifyAuditFile(auditPath, secret)
	if err != nil || n == 0 {
		t.Fatalf("verifyAuditFile: n=%d err=%v", n, err)
	}

	f, err := os.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var sawAPI, sawPortal bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev auditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("audit line decode: %v", err)
		}
		if ev.Action != "queue.clear" {
			continue
		}
		if ev.Outcome != "ok" || ev.Role != "operator" || ev.ClientIP == "" {
			t.Errorf("unexpected queue.clear audit record: %+v", ev)
		}
		if ev.Source == "api" && ev.Actor == "api:ops" &&
			ev.Details["mode"] == "stale" && ev.Details["removed"] == float64(1) &&
			ev.Details["max_idle_seconds"] == float64(1) {
			sawAPI = true
		}
		if ev.Source == "portal" && ev.Actor == "bob-operator" &&
			ev.Details["mode"] == "all" && ev.Details["removed"] == float64(2) &&
			ev.Details["remaining_live"] == float64(0) {
			sawPortal = true
		}
	}
	if !sawAPI || !sawPortal {
		t.Fatalf("missing queue.clear audit entries: sawAPI=%v sawPortal=%v", sawAPI, sawPortal)
	}
}
