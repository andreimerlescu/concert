package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func importTicketsIntoRoom(t *testing.T, a *app, tickets []map[string]any) {
	t.Helper()
	snap := map[string]any{
		"version":     1,
		"exported_at": time.Now().UTC(),
		"tickets":     tickets,
		"passes":      []any{},
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.room.Import(bytes.NewReader(raw)); err != nil {
		t.Fatalf("room.Import: %v", err)
	}
}

func TestOps_Stats_RoomV19Fields(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.readyGrace = 20 * time.Second
	cfg.idlePollTTL = 35 * time.Second
	cfg.reaper = 10 * time.Second
	a, front := newTestApp(t, cfg, up)

	a.stats.rejected503.Add(4)
	a.stats.cleared.Add(9)
	a.stats.upstreamBodyIdleTimeouts.Add(2)

	s := getStats(t, front)
	if s["ready_grace"] != "20s" {
		t.Errorf("ready_grace = %v, want 20s", s["ready_grace"])
	}
	if s["idle_poll_ttl"] != "35s" {
		t.Errorf("idle_poll_ttl = %v, want 35s", s["idle_poll_ttl"])
	}
	if s["reaper"] != "10s" {
		t.Errorf("reaper = %v, want 10s", s["reaper"])
	}
	if s["rejected_503_total"] != float64(4) {
		t.Errorf("rejected_503_total = %v, want 4", s["rejected_503_total"])
	}
	if s["cleared_total"] != float64(9) {
		t.Errorf("cleared_total = %v, want 9", s["cleared_total"])
	}
	if s["upstream_body_idle_timeouts_total"] != float64(2) {
		t.Errorf("upstream_body_idle_timeouts_total = %v, want 2", s["upstream_body_idle_timeouts_total"])
	}
}

func TestQueue_ClearEndpointAndPortal(t *testing.T) {
	t.Run("ops endpoint auth, validation, live stale explicit, all clear, reconcile, no kicked 403", func(t *testing.T) {
		up := newFakeUpstream(t)
		cfg := portalTestConfig(up.URL())
		cfg.capacity = 1
		cfg.adminToken = "ops-clear-secret"
		cfg.idlePollTTL = 30 * time.Second
		cfg.readyGrace = 0
		a, p, front := newTestPortal(t, cfg, up)
		fillSlot(t, front, up)

		postOps := func(auth, body string) (*http.Response, []byte) {
			hdr := map[string]string{"Content-Type": "application/json"}
			if auth != "" {
				hdr["Authorization"] = auth
			}
			return doReq(t, testClient, http.MethodPost, front.URL+"/_room/queue/clear", hdr, strings.NewReader(body))
		}

		// Auth checks.
		if resp, _ := postOps("", `{"mode":"all"}`); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("missing bearer: got %d, want 401", resp.StatusCode)
		}
		if resp, _ := postOps("Bearer wrong", `{"mode":"all"}`); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong bearer: got %d, want 401", resp.StatusCode)
		}

		// Validation checks.
		for name, body := range map[string]string{
			"empty object":  `{}`,
			"empty mode":    `{"mode":""}`,
			"unknown mode":  `{"mode":"drop"}`,
			"invalid json":  `{not-json`,
			"negative idle": `{"mode":"stale","max_idle_seconds":-1}`,
		} {
			if resp, b := postOps("Bearer ops-clear-secret", body); resp.StatusCode != http.StatusBadRequest {
				t.Errorf("%s: got %d (%s), want 400", name, resp.StatusCode, string(b))
			}
		}

		// Queue an older visitor, wait >1s, then queue a fresh visitor so explicit max_idle_seconds=1
		// clears only the older one.
		olderVisitor := queueJarClient(t, front)
		time.Sleep(1150 * time.Millisecond)
		freshVisitor := queueJarClient(t, front)

		// Reserve an agent key to verify a.agents.reconcile(a.room) runs on queue clear.
		agentAddr := netip.MustParseAddr("203.0.113.77")
		a.agents.reserve(a.room, agentKeyPrefix+"agent-stale-1", agentAddr, 4, time.Now())

		resp, raw := postOps("Bearer ops-clear-secret", `{"mode":"stale","max_idle_seconds":1}`)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("stale explicit: got %d %s", resp.StatusCode, raw)
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out["mode"] != "stale" || out["removed"] != float64(1) || out["live_queue_depth"] != float64(1) {
			t.Fatalf("stale explicit response: %v, want mode=stale removed=1 live=1", out)
		}
		if a.agents.held() != 0 {
			t.Errorf("agents.held after reconcile = %d, want 0", a.agents.held())
		}

		// Clear all remaining tickets via POST /_room/queue/clear.
		resp, raw = postOps("Bearer ops-clear-secret", `{"mode":"all"}`)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("clear all: got %d %s", resp.StatusCode, raw)
		}
		out = map[string]any{}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out["mode"] != "all" || out["removed"] != float64(1) ||
			out["live_queue_depth"] != float64(0) || out["queue_depth"] != float64(0) {
			t.Fatalf("clear all response: %v", out)
		}
		if a.room.LiveQueueDepth() != 0 {
			t.Fatalf("live_queue_depth = %d, want 0", a.room.LiveQueueDepth())
		}
		if got := a.stats.cleared.Load(); got != 2 {
			t.Errorf("stats.cleared = %d, want 2", got)
		}
		if p.kicked.count() != 0 {
			t.Errorf("p.kicked.count() = %d, want 0 (bulk clear must not populate kicked list)", p.kicked.count())
		}

		// Release the occupied slot and verify cleared visitors transparently get 200 OK (NOT 403!).
		up.releaseAll()
		deadline := time.Now().Add(3 * time.Second)
		for a.room.Len() > 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		for name, cli := range map[string]*http.Client{"older": olderVisitor, "fresh": freshVisitor} {
			vResp, vBody := doReq(t, cli, http.MethodGet, front.URL+"/after-clear", map[string]string{"Accept": "text/html"}, nil)
			if vResp.StatusCode != http.StatusOK {
				t.Fatalf("cleared %s visitor got %d (%s), want 200 OK (must not get 403 kicked page)", name, vResp.StatusCode, string(vBody))
			}
		}

		// Verify /_room/stats reflects cleared_total.
		stats := getStats(t, front)
		if stats["cleared_total"] != float64(2) {
			t.Errorf("stats cleared_total = %v, want 2", stats["cleared_total"])
		}
	})

	t.Run("stale default uses idle_poll_ttl when configured", func(t *testing.T) {
		cfg := portalTestConfig("http://127.0.0.1:1")
		cfg.adminToken = "ops-idle-secret"
		cfg.idlePollTTL = 0 // disabled during Import so older tickets load into room
		cfg.readyGrace = 0
		cfg.reaper = time.Hour
		a, _, front := newTestPortal(t, cfg, nil)

		now := time.Now().UTC()
		importTicketsIntoRoom(t, a, []map[string]any{
			{
				"token": "tok-idle-25s", "created_at": now.Add(-30 * time.Second),
				"last_seen": now.Add(-25 * time.Second), "last_poll": now.Add(-25 * time.Second),
				"client_key": "203.0.113.1", "seen": true,
			},
			{
				"token": "tok-fresh-5s", "created_at": now.Add(-10 * time.Second),
				"last_seen": now.Add(-5 * time.Second), "last_poll": now.Add(-5 * time.Second),
				"client_key": "203.0.113.2", "seen": true,
			},
		})
		if err := a.room.SetIdlePollTTL(20 * time.Second); err != nil {
			t.Fatalf("SetIdlePollTTL: %v", err)
		}

		resp, raw := doReq(t, testClient, http.MethodPost, front.URL+"/_room/queue/clear", map[string]string{
			"Authorization": "Bearer ops-idle-secret",
			"Content-Type":  "application/json",
		}, strings.NewReader(`{"mode":"stale"}`))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("stale default: got %d %s", resp.StatusCode, raw)
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		if out["mode"] != "stale" || out["removed"] != float64(1) || out["live_queue_depth"] != float64(1) {
			t.Fatalf("stale default response: %v, want removed=1 live=1", out)
		}
		if _, ok := a.room.Ticket("tok-idle-25s"); ok {
			t.Error("tok-idle-25s should have been cleared using idle_poll_ttl=20s")
		}
		if _, ok := a.room.Ticket("tok-fresh-5s"); !ok {
			t.Error("tok-fresh-5s should remain")
		}
	})

	t.Run("stale default fallback 30s when idle_poll_ttl is 0 and portal POST /api/queue/clear", func(t *testing.T) {
		cfg := portalTestConfig("http://127.0.0.1:1")
		cfg.idlePollTTL = 0 // triggers 30s fallback on stale without max_idle_seconds
		cfg.readyGrace = 0
		cfg.reaper = time.Hour
		a, p, _ := newTestPortal(t, cfg, nil)

		// Import one ticket idle 45s (> 30s fallback) and one idle 10s (< 30s fallback) on fresh room.
		now := time.Now().UTC()
		importTicketsIntoRoom(t, a, []map[string]any{
			{
				"token": "tok-stale-45s", "created_at": now.Add(-50 * time.Second),
				"last_seen": now.Add(-45 * time.Second), "last_poll": now.Add(-45 * time.Second),
				"client_key": "203.0.113.10", "seen": true,
			},
			{
				"token": "tok-recent-10s", "created_at": now.Add(-15 * time.Second),
				"last_seen": now.Add(-10 * time.Second), "last_poll": now.Add(-10 * time.Second),
				"client_key": "203.0.113.11", "seen": true,
			},
		})
		p.notes.add("tok-stale-45s", "stale-ua", "/stale")
		p.notes.add("tok-recent-10s", "recent-ua", "/recent")

		ck, csrf := portalLogin(t, p)

		// CSRF required.
		if rec := portalDo(p, http.MethodPost, "/api/queue/clear", `{"mode":"stale"}`, ck, "", false); rec.Code != http.StatusForbidden {
			t.Fatalf("missing CSRF: got %d, want 403", rec.Code)
		}
		// Empty {} rejected with 400.
		if rec := portalDo(p, http.MethodPost, "/api/queue/clear", `{}`, ck, csrf, false); rec.Code != http.StatusBadRequest {
			t.Fatalf("empty body: got %d, want 400", rec.Code)
		}

		// Default stale mode uses 30s fallback: removes tok-stale-45s, keeps tok-recent-10s.
		rec := portalDo(p, http.MethodPost, "/api/queue/clear", `{"mode":"stale"}`, ck, csrf, false)
		if rec.Code != http.StatusOK {
			t.Fatalf("portal stale: got %d %s", rec.Code, rec.Body.String())
		}
		v := decodeJSON(t, rec)
		if v["mode"] != "stale" || v["removed"] != float64(1) || v["live_queue_depth"] != float64(1) {
			t.Fatalf("portal stale response: %v", v)
		}
		if _, ok := p.notes.get("tok-stale-45s"); ok {
			t.Error("stale ticket note should be pruned immediately")
		}
		if _, ok := p.notes.get("tok-recent-10s"); !ok {
			t.Error("recent ticket note should remain")
		}

		// Clear all via portal.
		rec = portalDo(p, http.MethodPost, "/api/queue/clear", `{"mode":"all"}`, ck, csrf, false)
		if rec.Code != http.StatusOK {
			t.Fatalf("portal all: got %d %s", rec.Code, rec.Body.String())
		}
		v = decodeJSON(t, rec)
		if v["mode"] != "all" || v["removed"] != float64(1) || v["live_queue_depth"] != float64(0) {
			t.Fatalf("portal all response: %v", v)
		}
		if p.notes.count() != 0 {
			t.Errorf("notes count after clear all = %d, want 0", p.notes.count())
		}
		if p.kicked.count() != 0 {
			t.Errorf("kicked count after clear all = %d, want 0", p.kicked.count())
		}
	})
}

func TestQueue_ClearMultiVhostAndFragQueue(t *testing.T) {
	upA := newFakeUpstream(t)
	upB := newFakeUpstream(t)
	t.Cleanup(upA.releaseAll)
	t.Cleanup(upB.releaseAll)

	cfPath := filepath.Join(t.TempDir(), "Concertfile")
	content := fmt.Sprintf(`
{
    listen 127.0.0.1:0
    portal_listen 127.0.0.1:0
    portal_allow 127.0.0.1/32, ::1/128
}

alpha.example.test {
    upstream %s
    cap 1
    idle_poll_ttl 30s
}

beta.example.test {
    upstream %s
    cap 1
    idle_poll_ttl 30s
}
`, upA.URL(), upB.URL())
	if err := os.WriteFile(cfPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	base := testConfig(upA.URL())
	base.configFile = cfPath
	base.trustedProxies = "127.0.0.1/32,::1/128"
	base.portal.pass = testPortalPass
	base.portal.sessionTTL = time.Hour

	vm, err := newVhostManager(base)
	if err != nil {
		t.Fatalf("newVhostManager: %v", err)
	}
	defer vm.Close()

	p, err := newVhostPortal(vm)
	if err != nil || p == nil {
		t.Fatalf("newVhostPortal: %v", err)
	}
	t.Cleanup(p.closeListener)

	srv := httptest.NewServer(vm)
	defer srv.Close()
	defer upB.releaseAll()
	defer upA.releaseAll()

	// Park 1 slot on alpha and 1 slot on beta so subsequent arrivals queue cleanly.
	parkHost := func(host string, up *fakeUpstream) {
		go func() {
			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/slow", nil)
			req.Host = host
			resp, err := testClient.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
		select {
		case <-up.entered:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s /slow never reached upstream", host)
		}
	}
	parkHost("alpha.example.test", upA)
	parkHost("beta.example.test", upB)

	// Queue 1 visitor on alpha (client 198.51.100.1) and 2 visitors on beta (client 203.0.113.21, .22).
	queueOn := func(host, xff string) {
		resp, _ := doReq(t, jarClient(), http.MethodGet, srv.URL+"/line", map[string]string{
			"Host":            host,
			"X-Forwarded-For": xff,
		}, nil)
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("queue on %s: got %d, want 429", host, resp.StatusCode)
		}
	}
	queueOn("alpha.example.test", "198.51.100.1")
	queueOn("beta.example.test", "203.0.113.21")
	queueOn("beta.example.test", "203.0.113.22")

	// Also create a ban only on beta so we verify fragBans honors ?site=.
	betaSite, ok := vm.siteByName("beta.example.test")
	if !ok {
		t.Fatal("missing beta site")
	}
	if _, err := betaSite.app.abuse.banFor(netip.MustParseAddr("203.0.113.99"), time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}

	ck, csrf := portalLogin(t, p)

	// fragQueue with ?site=beta.example.test must show beta's 2 visitors, NOT alpha's 1!
	fqBeta := frag(t, p, ck, "/api/frag/queue?site=beta.example.test")
	if fqBeta.Total != 2 || rowsIn(fqBeta.HTML) != 2 ||
		!strings.Contains(fqBeta.HTML, "203.0.113.21") ||
		!strings.Contains(fqBeta.HTML, "203.0.113.22") ||
		strings.Contains(fqBeta.HTML, "198.51.100.1") {
		t.Fatalf("fragQueue?site=beta mismatch: total=%d html=%s", fqBeta.Total, fqBeta.HTML)
	}

	// fragQueue with ?site=alpha.example.test shows alpha's 1 visitor only.
	fqAlpha := frag(t, p, ck, "/api/frag/queue?site=alpha.example.test")
	if fqAlpha.Total != 1 || rowsIn(fqAlpha.HTML) != 1 ||
		!strings.Contains(fqAlpha.HTML, "198.51.100.1") ||
		strings.Contains(fqAlpha.HTML, "203.0.113.21") {
		t.Fatalf("fragQueue?site=alpha mismatch: total=%d html=%s", fqAlpha.Total, fqAlpha.HTML)
	}

	// fragBans honors ?site=.
	fbAlpha := frag(t, p, ck, "/api/frag/bans?site=alpha.example.test")
	fbBeta := frag(t, p, ck, "/api/frag/bans?site=beta.example.test")
	if fbAlpha.Total != 0 || fbBeta.Total != 1 || !strings.Contains(fbBeta.HTML, "203.0.113.99") {
		t.Fatalf("fragBans ?site= isolation failed: alpha=%d beta=%d", fbAlpha.Total, fbBeta.Total)
	}

	// Unknown ?site= returns 404 on fragments and clear endpoint.
	if rec := portalDo(p, http.MethodGet, "/api/frag/queue?site=nope.example.test", "", ck, "", false); rec.Code != http.StatusNotFound {
		t.Errorf("unknown site fragQueue: got %d, want 404", rec.Code)
	}
	if rec := portalDo(p, http.MethodPost, "/api/queue/clear?site=nope.example.test", `{"mode":"all"}`, ck, csrf, false); rec.Code != http.StatusNotFound {
		t.Errorf("unknown site queue clear: got %d, want 404", rec.Code)
	}

	// Clear ONLY beta via Portal ?site=beta.example.test; alpha must stay untouched!
	rec := portalDo(p, http.MethodPost, "/api/queue/clear?site=beta.example.test", `{"mode":"all"}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear beta: got %d %s", rec.Code, rec.Body.String())
	}
	v := decodeJSON(t, rec)
	if v["removed"] != float64(2) || v["live_queue_depth"] != float64(0) {
		t.Fatalf("clear beta response: %v", v)
	}

	fqBetaAfter := frag(t, p, ck, "/api/frag/queue?site=beta.example.test")
	fqAlphaAfter := frag(t, p, ck, "/api/frag/queue?site=alpha.example.test")
	if fqBetaAfter.Total != 0 || fqAlphaAfter.Total != 1 {
		t.Fatalf("after clearing beta: beta=%d alpha=%d, want 0 and 1", fqBetaAfter.Total, fqAlphaAfter.Total)
	}
}

func TestFrag_QueueIdleThreshold(t *testing.T) {
	cases := []struct {
		ttl  time.Duration
		want int
	}{
		{0, 15},
		{10 * time.Second, 5},
		{15 * time.Second, 5},
		{30 * time.Second, 10},
		{45 * time.Second, 15},
		{90 * time.Second, 15},
	}
	for _, tc := range cases {
		if got := queueIdleThreshold(tc.ttl); got != tc.want {
			t.Errorf("queueIdleThreshold(%s) = %d, want %d", tc.ttl, got, tc.want)
		}
	}

	rowWaiting := newQueueRow(occupantView{Position: 2, IdleSeconds: 10, Ready: false}, 10)
	if rowWaiting.Idle {
		t.Error("expected Idle=false when IdleSeconds == thresh")
	}
	rowIdle := newQueueRow(occupantView{Position: 2, IdleSeconds: 11, Ready: false}, 10)
	if !rowIdle.Idle {
		t.Error("expected Idle=true when IdleSeconds > thresh and !Ready")
	}
	rowReady := newQueueRow(occupantView{Position: 0, IdleSeconds: 30, Ready: true}, 10)
	if rowReady.Idle {
		t.Error("expected Idle=false when Ready is true")
	}
}
