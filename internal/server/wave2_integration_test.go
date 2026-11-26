package server

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/bidding"
	"github.com/andreimerlescu/concert/internal/configfile"
	"github.com/andreimerlescu/concert/internal/notify"
	"github.com/andreimerlescu/concert/internal/telemetry"
	"github.com/andreimerlescu/concert/internal/waitingroom"
)

// TestWave2_PathRoutingHeadersAndRedirects exercises longest-prefix path-based
// upstream routing, strip_prefix, per-route bypass and rate_limit, 301/302/307/308
// redirects, and safe response header manipulation that never overrides
// security-critical headers on error or waiting-room pages.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestWave2_PathRoutingHeadersAndRedirects$' ./internal/server
//
// # Used By
//
// Invoked by the `go test` runner.
func TestWave2_PathRoutingHeadersAndRedirects(t *testing.T) {
	var apiHitPath atomic.Value
	apiOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiHitPath.Store(r.URL.Path)
		w.Header().Set("X-Powered-By", "SecretBackend/1.0")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"origin":"api"}`))
	}))
	t.Cleanup(apiOrigin.Close)

	adminOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"origin":"admin","path":"` + r.URL.Path + `"}`))
	}))
	t.Cleanup(adminOrigin.Close)

	errOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/boom" {
			w.Header().Set("Content-Security-Policy", "default-src 'none'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("boom"))
			return
		}
		w.Header().Set("X-Powered-By", "DefaultOrigin")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("default-ok"))
	}))
	t.Cleanup(errOrigin.Close)

	cfg := testConfig(errOrigin.URL)
	cfg.capacity = 2
	cfg.siteRoutes = []configfile.RouteConfig{
		{
			Path:        "/api/v1",
			Upstream:    apiOrigin.URL,
			StripPrefix: true,
			RateLimit:   "2/1m",
			Bypass:      true,
		},
		{
			Path:     "/api/v1/admin",
			Upstream: adminOrigin.URL,
			Bypass:   true,
		},
	}
	cfg.siteRedirects = []configfile.RedirectRule{
		{From: "/old-home", To: "/new-home", Status: http.StatusMovedPermanently},
		{From: "/temp-go", To: "https://example.com/landing", Status: http.StatusTemporaryRedirect},
	}
	cfg.siteHeaders = []configfile.HeaderRule{
		{Action: configfile.HeaderSet, Name: "X-Concert-Edge", Value: "wave2"},
		{Action: configfile.HeaderAdd, Name: "X-Trace-Note", Value: "routed"},
		{Action: configfile.HeaderRemove, Name: "X-Powered-By"},
		// Attempt to override CSP: must NOT override security-critical headers on 500 error responses.
		{Action: configfile.HeaderSet, Name: "Content-Security-Policy", Value: "default-src *"},
	}

	a, err := newApp(cfg)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	t.Cleanup(a.Close)
	front := httptest.NewServer(a.handler)
	t.Cleanup(front.Close)

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1. Redirects (301 and 307).
	resp, err := client.Get(front.URL + "/old-home")
	if err != nil {
		t.Fatalf("GET /old-home: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "/new-home" {
		t.Fatalf("GET /old-home: status=%d location=%q, want 301 /new-home", resp.StatusCode, resp.Header.Get("Location"))
	}

	resp, err = client.Get(front.URL + "/temp-go")
	if err != nil {
		t.Fatalf("GET /temp-go: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || resp.Header.Get("Location") != "https://example.com/landing" {
		t.Fatalf("GET /temp-go: status=%d location=%q, want 307 https://example.com/landing", resp.StatusCode, resp.Header.Get("Location"))
	}

	// 2. Longest-prefix match (/api/v1/admin beats /api/v1).
	resp, body := get(t, front.URL+"/api/v1/admin/panel", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"origin":"admin"`) {
		t.Fatalf("GET /api/v1/admin/panel: status=%d body=%q", resp.StatusCode, body)
	}

	// 3. Prefix strip (/api/v1/users -> /users) + safe headers set/add/remove + per-route rate limit (2/1m).
	for i := 1; i <= 2; i++ {
		resp, body = get(t, front.URL+"/api/v1/users", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("attempt %d GET /api/v1/users: status=%d body=%q", i, resp.StatusCode, body)
		}
		if got, _ := apiHitPath.Load().(string); got != "/users" {
			t.Fatalf("strip_prefix path = %q, want /users", got)
		}
		if got := resp.Header.Get("X-Concert-Edge"); got != "wave2" {
			t.Fatalf("X-Concert-Edge = %q, want wave2", got)
		}
		if got := resp.Header.Get("X-Trace-Note"); got != "routed" {
			t.Fatalf("X-Trace-Note = %q, want routed", got)
		}
		if got := resp.Header.Get("X-Powered-By"); got != "" {
			t.Fatalf("X-Powered-By = %q, want removed", got)
		}
	}
	// 3rd request hits per-route 2/1m rate limit -> 429.
	resp, _ = get(t, front.URL+"/api/v1/users", map[string]string{"Accept": "application/json"})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("3rd GET /api/v1/users: status=%d, want 429", resp.StatusCode)
	}

	// 4. Error response (>= 400) must NOT have security-critical CSP overridden by SiteConfig.Headers.
	resp, _ = get(t, front.URL+"/boom", nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("GET /boom: status=%d, want 500", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != "default-src 'none'" {
		t.Fatalf("GET /boom CSP = %q, want preserved default-src 'none'", got)
	}
}

// TestWave2_ScheduledDropsAndPortalLifecycle verifies GET/POST /_room/drop,
// Portal GET/POST /api/drop (with CSRF + RBAC), lobby arrival holding,
// /queue/status drop metadata, and sold_out short-circuiting.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestWave2_ScheduledDropsAndPortalLifecycle$' ./internal/server
//
// # Used By
//
// Invoked by the `go test` runner.
func TestWave2_ScheduledDropsAndPortalLifecycle(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.adminToken = "wave2-admin-secret-token-123456"
	cfg.portal.pass = "wave2-portal-pass-123456"
	cfg.portal.listen = ""
	cfg.portal.allowSpec = "127.0.0.1/32,::1/128"
	cfg.portal.sessionTTL = time.Hour

	a, err := newApp(cfg)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	t.Cleanup(a.Close)
	p, err := newPortal(a)
	if err != nil {
		t.Fatalf("newPortal: %v", err)
	}

	front := httptest.NewServer(a.handler)
	t.Cleanup(front.Close)
	portalSrv := httptest.NewServer(p.engine)
	t.Cleanup(portalSrv.Close)

	authHdr := map[string]string{
		"Authorization": "Bearer " + cfg.adminToken,
		"Content-Type":  "application/json",
	}

	// 1. Schedule an active lobby drop via POST /_room/drop.
	now := time.Now().UTC()
	schedBody := mustJSON(map[string]any{
		"action":           "schedule",
		"event_id":         "sneaker-drop-1",
		"lobby_at":         now.Add(-1 * time.Minute).Format(time.RFC3339),
		"opens_at":         now.Add(10 * time.Minute).Format(time.RFC3339),
		"sold_out_message": "All pairs claimed.",
	})
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/_room/drop", bytes.NewReader(schedBody))
	for k, v := range authHdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /_room/drop schedule: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_room/drop schedule: status=%d body=%s", resp.StatusCode, raw)
	}
	var dropResp map[string]any
	if err := json.Unmarshal(raw, &dropResp); err != nil {
		t.Fatalf("unmarshal drop resp: %v", err)
	}
	if dropResp["phase"] != "lobby" || dropResp["event_id"] != "sneaker-drop-1" {
		t.Fatalf("unexpected drop state after schedule: %v", dropResp)
	}

	// 2. Arrival during lobby is held out of origin and registered in lobby.
	lobbyResp, lobbyBody := get(t, front.URL+"/product", map[string]string{"Accept": "application/json"})
	if lobbyResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("lobby arrival status=%d, want 429 (body=%s)", lobbyResp.StatusCode, lobbyBody)
	}
	if lobbyResp.Header.Get(dropPhaseHeader) != "lobby" {
		t.Fatalf("lobby header %s=%q, want lobby", dropPhaseHeader, lobbyResp.Header.Get(dropPhaseHeader))
	}

	// 3. /queue/status reports drop_phase="lobby" and drop_countdown_seconds > 0.
	stResp, stBody := get(t, front.URL+"/queue/status", nil)
	if stResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /queue/status: status=%d body=%s", stResp.StatusCode, stBody)
	}
	var statusPayload map[string]any
	if err := json.Unmarshal(stBody, &statusPayload); err != nil {
		t.Fatalf("unmarshal /queue/status: %v", err)
	}
	if statusPayload["drop_phase"] != "lobby" {
		t.Fatalf("/queue/status drop_phase=%v, want lobby", statusPayload["drop_phase"])
	}
	if cd, _ := statusPayload["drop_countdown_seconds"].(float64); cd <= 0 {
		t.Fatalf("/queue/status drop_countdown_seconds=%v, want > 0", statusPayload["drop_countdown_seconds"])
	}

	// 4. GET /_room/drop reflects lobby_count >= 1.
	req, _ = http.NewRequest(http.MethodGet, front.URL+"/_room/drop", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.adminToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /_room/drop: %v", err)
	}
	raw, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"lobby_count":1`) {
		t.Fatalf("GET /_room/drop: status=%d body=%s", resp.StatusCode, raw)
	}

	// 5. Portal GET/POST /api/drop (pause -> resume -> sold_out -> reset) with CSRF.
	cookie, csrf := signInPortalForTest(t, p, portalSrv.URL)

	portalPostDrop := func(payload map[string]any) map[string]any {
		t.Helper()
		r, _ := http.NewRequest(http.MethodPost, portalSrv.URL+"/api/drop", bytes.NewReader(mustJSON(payload)))
		r.AddCookie(cookie)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatalf("POST /api/drop: %v", err)
		}
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("POST /api/drop %v: status=%d body=%s", payload, res.StatusCode, b)
		}
		var out map[string]any
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("unmarshal /api/drop: %v", err)
		}
		return out
	}

	if got := portalPostDrop(map[string]any{"action": "pause", "reason": "hold"}); got["phase"] != "paused" {
		t.Fatalf("after pause: phase=%v, want paused", got["phase"])
	}
	if got := portalPostDrop(map[string]any{"action": "resume"}); got["phase"] != "lobby" {
		t.Fatalf("after resume: phase=%v, want lobby", got["phase"])
	}
	if got := portalPostDrop(map[string]any{"action": "sold_out", "sold_out_message": "Gone in 60s!"}); got["phase"] != "sold_out" {
		t.Fatalf("after sold_out: phase=%v, want sold_out", got["phase"])
	}

	// 6. Sold-out short-circuits visitor arrival with 410 Gone and message.
	soResp, soBody := get(t, front.URL+"/product", map[string]string{"Accept": "application/json"})
	if soResp.StatusCode != http.StatusGone || !strings.Contains(string(soBody), "Gone in 60s!") {
		t.Fatalf("sold_out arrival: status=%d body=%s", soResp.StatusCode, soBody)
	}
	stResp, stBody = get(t, front.URL+"/queue/status", nil)
	if stResp.StatusCode != http.StatusOK || !strings.Contains(string(stBody), "Gone in 60s!") {
		t.Fatalf("sold_out /queue/status: status=%d body=%s", stResp.StatusCode, stBody)
	}

	// 7. Reset clears the drop so normal traffic reaches origin again.
	if got := portalPostDrop(map[string]any{"action": "reset"}); got["configured"] != false {
		t.Fatalf("after reset: configured=%v, want false", got["configured"])
	}
	okResp, _ := get(t, front.URL+"/product", nil)
	if okResp.StatusCode != http.StatusOK {
		t.Fatalf("post-reset arrival: status=%d, want 200", okResp.StatusCode)
	}
}

// recordingBiddingSettler is a concurrency-safe test PaymentSettler modeling
// real off-chain verification vs winner-only on-chain settlement.
type recordingBiddingSettler struct {
	mu          sync.Mutex
	verifyCalls map[string]int
	settleCalls map[string]int
}

func newRecordingBiddingSettler() *recordingBiddingSettler {
	return &recordingBiddingSettler{
		verifyCalls: map[string]int{},
		settleCalls: map[string]int{},
	}
}

func (s *recordingBiddingSettler) Verify(_ context.Context, bid bidding.BidSubmission) (bidding.VerifyReceipt, error) {
	s.mu.Lock()
	s.verifyCalls[bid.BidID]++
	s.mu.Unlock()
	return bidding.VerifyReceipt{
		Valid:    true,
		Payer:    "rPayer_" + bid.BidID,
		PolicyID: "pol-" + bid.BidID,
	}, nil
}

func (s *recordingBiddingSettler) Settle(_ context.Context, bid bidding.BidSubmission) (bidding.SettleReceipt, error) {
	s.mu.Lock()
	s.settleCalls[bid.BidID]++
	s.mu.Unlock()
	return bidding.SettleReceipt{
		Settled:     true,
		Transaction: "tx-" + bid.BidID,
		Network:     bid.Chain,
		Payer:       "rPayer_" + bid.BidID,
	}, nil
}

func (s *recordingBiddingSettler) counts(bidID string) (verifies, settles int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifyCalls[bidID], s.settleCalls[bidID]
}

// TestWave2_AgentBiddingLifecycleAndSettlement verifies live auction offer
// metadata in queued 429 responses, POST /_concert/bids off-chain verification,
// winner-only on-chain settlement (loser pays $0), GET /_concert/bids/status
// issuing signed priority + admission passes for winners, and Prometheus
// bidding counters.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestWave2_AgentBiddingLifecycleAndSettlement$' ./internal/server
//
// # Used By
//
// Invoked by the `go test` runner.
func TestWave2_AgentBiddingLifecycleAndSettlement(t *testing.T) {
	up := newFakeUpstream(t)
	settler := newRecordingBiddingSettler()

	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.apiJSON = true
	cfg.agentBidding = true
	cfg.agentBiddingFloorMicroUSD = 1_000_000 // $1.00
	cfg.agentBiddingEpoch = time.Hour         // deterministic clearing via ClearEpoch
	cfg.agentBiddingSlots = 1
	cfg.biddingSettler = settler

	a, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	// 1. Queued API agent receives 429 with live auction offer metadata.
	qResp, qBody := get(t, front.URL+"/drop-item", map[string]string{"Accept": "application/json"})
	if qResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("queued agent status=%d, want 429 (body=%s)", qResp.StatusCode, qBody)
	}
	var qPayload struct {
		Queued  bool           `json:"queued"`
		Auction *bidding.Offer `json:"auction"`
	}
	if err := json.Unmarshal(qBody, &qPayload); err != nil {
		t.Fatalf("unmarshal 429 body: %v (%s)", err, qBody)
	}
	if !qPayload.Queued || qPayload.Auction == nil {
		t.Fatalf("expected queued=true and non-nil auction offer, got %s", qBody)
	}
	if qPayload.Auction.Mode != bidding.ModeAuction {
		t.Fatalf("auction.mode=%q, want %q", qPayload.Auction.Mode, bidding.ModeAuction)
	}
	if qPayload.Auction.BidURL != biddingPublicBidURL || qPayload.Auction.StatusURL != biddingPublicStatURL {
		t.Fatalf("auction URLs = (%q, %q), want (%q, %q)",
			qPayload.Auction.BidURL, qPayload.Auction.StatusURL, biddingPublicBidURL, biddingPublicStatURL)
	}
	if len(qPayload.Auction.SupportedChains) != 4 {
		t.Fatalf("supported_chains=%v, want 4 crypto chains", qPayload.Auction.SupportedChains)
	}

	// 2. Submit two competing crypto bids: winner ($6.00 XRP = 3_000_000 drops) vs loser ($2.00 XRP = 1_000_000 drops).
	submitBid := func(bidID, agentKey, amountAtomic, nonce string) (int, map[string]any) {
		t.Helper()
		body := mustJSON(map[string]any{
			"bid_id":          bidID,
			"agent_key":       agentKey,
			"scope":           qPayload.Auction.Scope,
			"chain":           bidding.ChainXRPL,
			"asset":           "XRP",
			"amount_atomic":   amountAtomic,
			"payment_payload": map[string]any{"x402Version": 2, "nonce": nonce},
		})
		resp, err := http.Post(front.URL+biddingPublicBidURL, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST /_concert/bids (%s): %v", bidID, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return resp.StatusCode, out
	}

	codeWin, outWin := submitBid("bid-win-1", "agent-alpha", "3000000", "nonce-win-1")
	if codeWin != http.StatusAccepted || outWin["status"] != string(bidding.BidStatusPending) {
		t.Fatalf("winner submit: status=%d out=%v", codeWin, outWin)
	}
	codeLose, outLose := submitBid("bid-lose-1", "agent-beta", "1000000", "nonce-lose-1")
	if codeLose != http.StatusAccepted || outLose["status"] != string(bidding.BidStatusPending) {
		t.Fatalf("loser submit: status=%d out=%v", codeLose, outLose)
	}

	// Off-chain Verify ran for both; Settle has NOT run yet for either.
	wv, ws := settler.counts("bid-win-1")
	lv, ls := settler.counts("bid-lose-1")
	if wv != 1 || ws != 0 || lv != 1 || ls != 0 {
		t.Fatalf("pre-clear counts: win=(%d,%d) lose=(%d,%d), want (1,0) and (1,0)", wv, ws, lv, ls)
	}

	// 3. Clear epoch: only winner settles on-chain; loser is dropped at $0.
	if _, err := a.bidding.ClearEpoch(context.Background(), qPayload.Auction.Scope, time.Now().UTC().Add(2*time.Hour)); err != nil {
		t.Fatalf("ClearEpoch: %v", err)
	}
	wv, ws = settler.counts("bid-win-1")
	lv, ls = settler.counts("bid-lose-1")
	if ws != 1 || ls != 0 {
		t.Fatalf("post-clear settle counts: winner=%d loser=%d, want winner=1 loser=0 ($0)", ws, ls)
	}

	// 4. GET /_concert/bids/status?bid_id=bid-win-1 issues signed Priority + Admission pass!
	winResp, winBody := get(t, front.URL+biddingPublicStatURL+"?bid_id=bid-win-1", nil)
	if winResp.StatusCode != http.StatusOK {
		t.Fatalf("winner status HTTP=%d body=%s", winResp.StatusCode, winBody)
	}
	var winStatus map[string]any
	if err := json.Unmarshal(winBody, &winStatus); err != nil {
		t.Fatalf("unmarshal winner status: %v", err)
	}
	if winStatus["status"] != string(bidding.BidStatusSettled) || winStatus["pass_issued"] != true {
		t.Fatalf("winner status=%v, want settled + pass_issued=true", winStatus)
	}
	hasAdmit, hasPriority := false, false
	for _, ck := range winResp.Cookies() {
		if ck.Name == admitCookie && ck.Value != "" {
			hasAdmit = true
		}
		if ck.Name == priorityCookie && ck.Value != "" {
			hasPriority = true
		}
	}
	if !hasAdmit || !hasPriority {
		t.Fatalf("expected %s and %s cookies for settled winner, got %v", admitCookie, priorityCookie, winResp.Cookies())
	}

	// 5. GET /_concert/bids/status?bid_id=bid-lose-1 reports lost & pass_issued=false.
	loseResp, loseBody := get(t, front.URL+biddingPublicStatURL+"?bid_id=bid-lose-1", nil)
	if loseResp.StatusCode != http.StatusOK {
		t.Fatalf("loser status HTTP=%d body=%s", loseResp.StatusCode, loseBody)
	}
	var loseStatus map[string]any
	_ = json.Unmarshal(loseBody, &loseStatus)
	if loseStatus["status"] != string(bidding.BidStatusLost) || loseStatus["pass_issued"] != false {
		t.Fatalf("loser status=%v, want lost + pass_issued=false", loseStatus)
	}

	// 6. Prometheus counters expose concert_bidding_{submitted,settled,rejected}_total.
	metricsResp, metricsBody := get(t, front.URL+"/_room/metrics", nil)
	if metricsResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /_room/metrics: status=%d", metricsResp.StatusCode)
	}
	mText := string(metricsBody)
	for _, want := range []string{
		"concert_bidding_submitted_total 2",
		"concert_bidding_settled_total 1",
		"concert_bidding_rejected_total ",
	} {
		if !strings.Contains(mText, want) {
			t.Errorf("/_room/metrics missing %q", want)
		}
	}
}

// TestWave2_WaitingRoomStudioI18nYouTubeCSPAndLiveETA verifies Waiting Room
// Studio persistence (0600 waitingroom.json), Portal GET/PUT /api/waitingroom
// and POST /api/waitingroom/broadcast, strict YouTube CSP (frame-src 'none'
// unless layout=youtube with valid 11-char ID -> youtube-nocookie.com),
// ?lang=ar and ?lang=arc RTL rendering, and live ETA + broadcast on /queue/status.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestWave2_WaitingRoomStudioI18nYouTubeCSPAndLiveETA$' ./internal/server
//
// # Used By
//
// Invoked by the `go test` runner.
func TestWave2_WaitingRoomStudioI18nYouTubeCSPAndLiveETA(t *testing.T) {
	up := newFakeUpstream(t)
	dataDir := t.TempDir()

	cfg := testConfig(up.URL())
	cfg.dataDir = dataDir
	cfg.capacity = 1
	cfg.retryAfter = 5
	cfg.portal.pass = "wave2-studio-portal-pass-123456"
	cfg.portal.listen = ""
	cfg.portal.allowSpec = "127.0.0.1/32,::1/128"
	cfg.portal.sessionTTL = time.Hour

	a, front := newTestApp(t, cfg, up)
	p, err := newPortal(a)
	if err != nil {
		t.Fatalf("newPortal: %v", err)
	}
	portalSrv := httptest.NewServer(p.engine)
	t.Cleanup(portalSrv.Close)

	cookie, csrf := signInPortalForTest(t, p, portalSrv.URL)

	// Record several real admissions so live ETA estimator has medium/high throughput samples.
	base := time.Now().UTC().Add(-20 * time.Second)
	for i := range 6 {
		a.recordAdmission(base.Add(time.Duration(i*2) * time.Second))
	}

	// Saturate origin so subsequent HTML visitors enter the waiting room.
	fillSlot(t, front, up)

	// 1. Default layout enforces strict frame-src 'none' and supports ?lang=ar RTL.
	arResp, arBody := get(t, front.URL+"/concert?lang=ar", map[string]string{"Accept": "text/html"})
	if arResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /concert?lang=ar status=%d, want 200", arResp.StatusCode)
	}
	if csp := arResp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-src 'none'") {
		t.Fatalf("default layout CSP=%q, want frame-src 'none'", csp)
	}
	if got := arResp.Header.Get(headerConcertQueue); got != "1" {
		t.Fatalf("missing X-Concert-Queue: 1 (got %q)", got)
	}
	arHTML := string(arBody)
	if !strings.Contains(arHTML, `lang="ar"`) || !strings.Contains(arHTML, `dir="rtl"`) {
		t.Fatalf("expected Arabic RTL attributes in waiting room HTML")
	}
	if !strings.Contains(arHTML, `id="position"`) || !strings.Contains(arHTML, "/_concert/waiting.js") {
		t.Fatalf("waiting room HTML missing backward-compatible position/waiting.js markers")
	}

	// 2. Syriac (?lang=arc) also renders RTL with Syriac script.
	arcResp, arcBody := get(t, front.URL+"/concert?lang=arc", map[string]string{"Accept": "text/html"})
	if arcResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /concert?lang=arc status=%d, want 200", arcResp.StatusCode)
	}
	arcHTML := string(arcBody)
	if !strings.Contains(arcHTML, `lang="arc"`) || !strings.Contains(arcHTML, `dir="rtl"`) || !strings.Contains(arcHTML, "ܣܘܪܝܝܐ") {
		t.Fatalf("expected Syriac RTL rendering in waiting room HTML")
	}

	// 3. PUT /api/waitingroom switches to YouTube Cinema with full URL (parsed to 11-char ID) & Nord theme.
	putReq, _ := http.NewRequest(http.MethodPut, portalSrv.URL+"/api/waitingroom", bytes.NewReader(mustJSON(map[string]any{
		"layout":           waitingroom.LayoutYouTube,
		"theme":            waitingroom.ThemeNord,
		"brand_name":       "Arena Live",
		"accent_color":     "#36f9f6",
		"youtube_video_id": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
		"default_locale":   "en",
	})))
	putReq.AddCookie(cookie)
	putReq.Header.Set("X-CSRF-Token", csrf)
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatalf("PUT /api/waitingroom: %v", err)
	}
	putRaw, _ := io.ReadAll(putResp.Body)
	_ = putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/waitingroom status=%d body=%s", putResp.StatusCode, putRaw)
	}
	if !strings.Contains(string(putRaw), `"youtube_video_id":"dQw4w9WgXcQ"`) {
		t.Fatalf("expected parsed 11-char YouTube ID, got %s", putRaw)
	}

	// Verify waitingroom.json was persisted with 0600 permissions.
	info, err := os.Stat(filepath.Join(dataDir, waitingRoomFileName))
	if err != nil {
		t.Fatalf("stat waitingroom.json: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("waitingroom.json mode=%04o, want 0600", perm)
	}

	// 4. POST /api/waitingroom/broadcast publishes live operator message.
	bcReq, _ := http.NewRequest(http.MethodPost, portalSrv.URL+"/api/waitingroom/broadcast", bytes.NewReader(mustJSON(map[string]any{
		"message": "Gates open in 90 seconds!",
	})))
	bcReq.AddCookie(cookie)
	bcReq.Header.Set("X-CSRF-Token", csrf)
	bcReq.Header.Set("Content-Type", "application/json")
	bcResp, err := http.DefaultClient.Do(bcReq)
	if err != nil {
		t.Fatalf("POST /api/waitingroom/broadcast: %v", err)
	}
	_ = bcResp.Body.Close()
	if bcResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/waitingroom/broadcast status=%d, want 200", bcResp.StatusCode)
	}

	// 5. YouTube Cinema HTML carries frame-src https://www.youtube-nocookie.com and embeds youtube-nocookie iframe + broadcast.
	ytResp, ytBody := get(t, front.URL+"/concert", map[string]string{"Accept": "text/html"})
	if ytResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /concert youtube status=%d", ytResp.StatusCode)
	}
	if csp := ytResp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-src https://www.youtube-nocookie.com") {
		t.Fatalf("YouTube layout CSP=%q, want frame-src https://www.youtube-nocookie.com", csp)
	}
	ytHTML := string(ytBody)
	if !strings.Contains(ytHTML, "https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ") || !strings.Contains(ytHTML, "Gates open in 90 seconds!") {
		t.Fatalf("YouTube HTML missing embed iframe or broadcast banner")
	}

	// 6. /queue/status returns live ETA (eta_seconds, admissions_per_minute, eta_confidence) and broadcast.
	var ticketCookie *http.Cookie
	for _, ck := range ytResp.Cookies() {
		if ck.Name == "room_ticket" {
			ticketCookie = ck
			break
		}
	}
	if ticketCookie == nil {
		t.Fatalf("expected room_ticket cookie on queued waiting room response")
	}
	stReq, _ := http.NewRequest(http.MethodGet, front.URL+"/queue/status", nil)
	stReq.AddCookie(ticketCookie)
	stResp, err := http.DefaultClient.Do(stReq)
	if err != nil {
		t.Fatalf("GET /queue/status: %v", err)
	}
	stRaw, _ := io.ReadAll(stResp.Body)
	_ = stResp.Body.Close()
	if stResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /queue/status status=%d body=%s", stResp.StatusCode, stRaw)
	}
	var stJSON map[string]any
	if err := json.Unmarshal(stRaw, &stJSON); err != nil {
		t.Fatalf("unmarshal /queue/status: %v", err)
	}
	if _, ok := stJSON["eta_seconds"]; !ok {
		t.Fatalf("/queue/status missing eta_seconds: %s", stRaw)
	}
	if apm, _ := stJSON["admissions_per_minute"].(float64); apm <= 0 {
		t.Fatalf("/queue/status admissions_per_minute=%v, want > 0 (%s)", stJSON["admissions_per_minute"], stRaw)
	}
	if conf, _ := stJSON["eta_confidence"].(string); conf == "" {
		t.Fatalf("/queue/status missing eta_confidence: %s", stRaw)
	}
	bcObj, _ := stJSON["broadcast"].(map[string]any)
	if bcObj == nil || bcObj["message"] != "Gates open in 90 seconds!" {
		t.Fatalf("/queue/status missing live broadcast: %s", stRaw)
	}
}

// TestWave2_ChatOpsNotifyAndOTLPTracing verifies redacting secret parsing
// (CONCERT_NOTIFY_* / CONCERT_OTLP_AUTH_HEADER), ChatOps webhook delivery with
// HMAC signatures, W3C traceparent propagation to upstream origins, and clean
// OTLP/HTTP JSON span flushing on app.Close().
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestWave2_ChatOpsNotifyAndOTLPTracing$' ./internal/server
//
// # Used By
//
// Invoked by the `go test` runner.
func TestWave2_ChatOpsNotifyAndOTLPTracing(t *testing.T) {
	// 1. Verify flag/env parsing stores credentials in redacting S6 secrets.
	fakeWebhookSecret := "test-webhook-hmac-key-not-real-0123"
	fakeOTLPAuth := "Bearer test-otlp-token-not-real-0123"
	t.Setenv("CONCERT_NOTIFY_WEBHOOK_SECRET", fakeWebhookSecret)
	t.Setenv("CONCERT_OTLP_AUTH_HEADER", fakeOTLPAuth)

	fs := flag.NewFlagSet("wave2-obs", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	parsed, _, err := parseConfig(fs, []string{
		"-data-dir", "",
		"-upstream", "http://127.0.0.1:3000",
		"-notify-slack-url", "https://hooks.slack.com/services/T00/B00/NOTREAL",
		"-otlp-endpoint", "https://otel.example.com/v1/traces",
		"-otlp-sample-rate", "1.0",
	})
	if err != nil {
		t.Fatalf("parseConfig observability flags: %v", err)
	}
	if parsed.notifySlackURL.String() != "[REDACTED]" {
		t.Fatalf("notifySlackURL.String() = %q, want [REDACTED]", parsed.notifySlackURL.String())
	}
	if parsed.otlpAuthHeader.String() != "[REDACTED]" {
		t.Fatalf("otlpAuthHeader.String() = %q, want [REDACTED]", parsed.otlpAuthHeader.String())
	}

	// 2. Start loopback mock webhook receiver, mock OTLP collector, and upstream origin.
	webhookCh := make(chan struct {
		sig  string
		ts   string
		body []byte
	}, 4)
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		select {
		case webhookCh <- struct {
			sig  string
			ts   string
			body []byte
		}{
			sig:  r.Header.Get(notify.HeaderSignature),
			ts:   r.Header.Get(notify.HeaderTimestamp),
			body: b,
		}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(webhookSrv.Close)

	otlpCh := make(chan struct {
		auth string
		body []byte
	}, 4)
	otlpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		select {
		case otlpCh <- struct {
			auth string
			body []byte
		}{
			auth: r.Header.Get("Authorization"),
			body: b,
		}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(otlpSrv.Close)

	var upstreamTP atomic.Value
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamTP.Store(r.Header.Get(telemetry.TraceparentHeader))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("traced-ok"))
	}))
	t.Cleanup(origin.Close)

	cfg := testConfig(origin.URL)
	cfg.observabilityAllowLoopbackHTTP = true
	cfg.notifyDisableCoalesce = true
	cfg.notifyWebhookURL = notify.NewSecret(webhookSrv.URL)
	cfg.notifyWebhookSecret = notify.NewSecret(fakeWebhookSecret)
	cfg.otlpEndpoint = otlpSrv.URL + "/v1/traces"
	cfg.otlpSampleRate = 1.0
	cfg.otlpAuthHeader = telemetry.NewSecret(fakeOTLPAuth)

	a, err := newApp(cfg)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	front := httptest.NewServer(a.handler)
	t.Cleanup(front.Close)

	// 3. Send request carrying incoming W3C traceparent and verify propagation.
	incomingTraceID := "4bf92f3577b34da6a3ce929d0e0e4736"
	incomingTP := "00-" + incomingTraceID + "-00f067aa0ba902b7-01"
	resp, body := get(t, front.URL+"/trace-me", map[string]string{
		telemetry.TraceparentHeader: incomingTP,
	})
	if resp.StatusCode != http.StatusOK || string(body) != "traced-ok" {
		t.Fatalf("GET /trace-me: status=%d body=%q", resp.StatusCode, body)
	}
	respTP := resp.Header.Get(telemetry.TraceparentHeader)
	gotUpTP, _ := upstreamTP.Load().(string)
	for label, val := range map[string]string{"response": respTP, "upstream": gotUpTP} {
		sc, perr := telemetry.ParseTraceparent(val)
		if perr != nil {
			t.Fatalf("%s traceparent %q invalid: %v", label, val, perr)
		}
		if sc.TraceID.String() != incomingTraceID {
			t.Fatalf("%s trace_id=%q, want %q", label, sc.TraceID.String(), incomingTraceID)
		}
	}

	// 4. Trigger operational alert and close app cleanly to flush both dispatcher and tracer.
	a.notifyAlert(alertEvent{
		Category:    alertCatQueue,
		Severity:    alertSevCritical,
		Title:       "Wave 2 test alert",
		Summary:     "Verifying ChatOps dispatch",
		Fingerprint: "test:wave2",
		Details:     map[string]string{"env": "test"},
	})
	a.Close()

	// 5. Verify signed ChatOps webhook delivery.
	select {
	case got := <-webhookCh:
		if !notify.VerifyWebhookSignature(notify.NewSecret(fakeWebhookSecret), got.ts, got.sig, got.body) {
			t.Fatalf("ChatOps webhook HMAC signature verification failed (ts=%q sig=%q)", got.ts, got.sig)
		}
		if !strings.Contains(string(got.body), "Wave 2 test alert") {
			t.Fatalf("ChatOps webhook body missing alert title: %s", got.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for ChatOps webhook delivery")
	}

	// 6. Verify OTLP/HTTP JSON span batch export with auth header.
	select {
	case got := <-otlpCh:
		if got.auth != fakeOTLPAuth {
			t.Fatalf("OTLP Authorization header = %q, want %q", got.auth, fakeOTLPAuth)
		}
		if !strings.Contains(string(got.body), `"resourceSpans"`) || !strings.Contains(string(got.body), incomingTraceID) {
			t.Fatalf("OTLP payload missing resourceSpans or trace ID: %s", got.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for OTLP trace flush on app.Close()")
	}
}

// signInPortalForTest mints an authenticated admin portal session cookie and
// matching CSRF token for portal integration tests.
//
// # Parameters
//
//   - t: Active test handle.
//   - p: Target *portal instance.
//   - baseURL: Unused placeholder reserved for future cookie-domain assertions.
//
// # Returns
//
// An authenticated portal session *http.Cookie and its matching CSRF token.
//
// # Example
//
//	ck, csrf := signInPortalForTest(t, p, portalSrv.URL)
//
// # Used By
//
// Called by Wave 2 portal integration tests in internal/server/wave2_integration_test.go.
func signInPortalForTest(t *testing.T, p *portal, _ string) (*http.Cookie, string) {
	t.Helper()
	val, nonce := p.mintSession(time.Now(), time.Hour)
	return &http.Cookie{Name: portalCookie, Value: val}, p.csrfToken(nonce)
}
