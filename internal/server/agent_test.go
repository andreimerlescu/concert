//go:build enterprise

package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/fastlane"
	"github.com/andreimerlescu/room"
)

// ─── harness ─────────────────────────────────────────────────────────────────

// agentTestConfig is a full room (cap 1) with wallet access on, the agent
// queue on, and X-Forwarded-For trusted so tests choose client addresses.
func agentTestConfig(t *testing.T, up *fakeUpstream, offers bool) config {
	t.Helper()
	restore := newGateway
	newGateway = func(fastlane.Config, *config) (fastlane.Gateway, error) {
		return handlerGateway{http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/supported":
				_ = json.NewEncoder(w).Encode(map[string]any{"kinds": []any{map[string]any{"x402Version": 2, "scheme": "exact", "network": "xrpl:1"}}})
			case "/verify":
				_ = json.NewEncoder(w).Encode(map[string]any{"isValid": true, "payer": "rPayer"})
			case "/settle":
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "payer": "rPayer", "network": "xrpl:1", "transaction": "agent-test"})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})}, nil
	}
	t.Cleanup(func() { newGateway = restore })

	cfg := portalTestConfig(up.URL())
	cfg.capacity = 1
	cfg.trustedProxies = "127.0.0.1/32"
	cfg.agentQueue = true
	cfg.dataDir = t.TempDir()
	cfg.fastlaneFile = filepath.Join(cfg.dataDir, "fastlane.json")
	fc := fastlane.Config{Enabled: true, Origin: "http://127.0.0.1:8080", TestMode: true, Merchant: "Agent test",
		TermsURL: "http://127.0.0.1:8080/terms", PrivacyURL: "http://127.0.0.1:8080/privacy", RefundURL: "http://127.0.0.1:8080/refunds"}
	if offers {
		fc.Offers = []fastlane.Offer{{Label: "XRP", Requirements: agentTestOffer}}
	} else {
		// An NFT-only fast lane: sessions, but nothing to buy.
		fc.Collections = []fastlane.Collection{{ID: "club", Label: "Club", Network: "xrpl:1", Collection: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh:0"}}
	}
	b, err := json.Marshal(fc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.fastlaneFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

var agentTestOffer = fastlane.Requirements{Scheme: "exact", Network: "xrpl:1", Amount: "100", Asset: "XRP",
	PayTo: "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", MaxTimeoutSeconds: 60, Extra: map[string]any{"areFeesSponsored": false}}

// session starts a fast-lane session from ip and returns its token.
func session(t *testing.T, front *httptest.Server, ip string) string {
	t.Helper()
	resp, body := doReq(t, testClient, http.MethodPost, front.URL+"/_concert/session", withXFF(ip), strings.NewReader("{}"))
	var s struct {
		Session string `json:"session"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &s) != nil || s.Session == "" {
		t.Fatalf("session: %d %s", resp.StatusCode, body)
	}
	return s.Session
}

// asAgent is a request from ip carrying a Concert-Session header and no
// cookies.
func asAgent(ip, token string) map[string]string {
	return map[string]string{"X-Forwarded-For": ip, fastlane.SessionHeader: token}
}

// sessionKey is the room key Concert gives token's session.
func sessionKey(t *testing.T, a *app, token string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(fastlane.SessionHeader, token)
	id, ok := a.fastlane.SessionID(r)
	if !ok {
		t.Fatal("not a valid session")
	}
	return agentKeyPrefix + id
}

func keyedPlace(t *testing.T, a *app, token string) (room.TicketInfo, bool) {
	t.Helper()
	return a.room.TicketByKey(sessionKey(t, a, token))
}

func addrKey(s string) netip.Addr {
	k, _ := abuseKey(netip.MustParseAddr(s))
	return k
}

// ─── identity ────────────────────────────────────────────────────────────────

func TestAgent_KeepsOnePlacePerSessionWithoutCookies(t *testing.T) {
	up := newFakeUpstream(t)
	a, _, front := newTestPortal(t, agentTestConfig(t, up, true), up)
	fillSlot(t, front, up)
	tok := session(t, front, "203.0.113.20")

	for i := 0; i < 3; i++ {
		resp, body := get(t, front.URL+"/drop", asAgent("203.0.113.20", tok))
		if len(resp.Header.Values("Set-Cookie")) != 0 {
			t.Fatalf("retry %d: an agent must get no cookies: %v", i, resp.Header.Values("Set-Cookie"))
		}
		if !strings.Contains(string(body), `"position":1`) {
			t.Fatalf("retry %d: got %d %s, want position 1", i, resp.StatusCode, body)
		}
	}
	if n := a.room.LiveQueueDepth(); n != 1 {
		t.Errorf("three retries took %d places, want 1", n)
	}
	ti, ok := keyedPlace(t, a, tok)
	if !ok || ti.ClientKey != "203.0.113.20" {
		t.Fatalf("keyed place: %+v %v, want one recorded under the client's address", ti, ok)
	}

	// Renewing the session keeps its ID, and so its place.
	resp, body := doReq(t, testClient, http.MethodPost, front.URL+"/_concert/session", asAgent("203.0.113.20", tok), strings.NewReader("{}"))
	var renewed struct {
		Session string `json:"session"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &renewed) != nil {
		t.Fatalf("renew: %d %s", resp.StatusCode, body)
	}
	get(t, front.URL+"/drop", asAgent("203.0.113.20", renewed.Session))
	if n := a.room.LiveQueueDepth(); n != 1 {
		t.Errorf("a renewed session took a second place: %d", n)
	}
}

func TestAgent_OffByDefaultAndForBrowsers(t *testing.T) {
	clearConcertEnv(t)
	def, _, err := parseConfig(newFlagSet(), nil)
	if err != nil || def.agentQueue || def.agentPlaces != defaultAgentPlaces {
		t.Errorf("defaults: agent_queue=%v agent_places=%d %v, want false and %d", def.agentQueue, def.agentPlaces, err, defaultAgentPlaces)
	}

	up := newFakeUpstream(t)
	cfg := agentTestConfig(t, up, true)
	cfg.agentQueue = false
	a, p, front := newTestPortal(t, cfg, up)
	fillSlot(t, front, up)
	tok := session(t, front, "203.0.113.21")

	resp, _ := get(t, front.URL+"/drop", asAgent("203.0.113.21", tok))
	if !hasCookie(resp, "room_ticket") {
		t.Error("with -agent-queue off a Concert-Session request must keep the cookie flow")
	}

	// Turned on live from the portal.
	ck, csrf := portalLogin(t, p)
	if rec := portalDo(p, http.MethodPost, "/api/settings", `{"agent_queue":true}`, ck, csrf, false); rec.Code != http.StatusOK {
		t.Fatalf("enable agent_queue: %d %s", rec.Code, rec.Body.String())
	}
	resp, _ = get(t, front.URL+"/drop", asAgent("203.0.113.23", session(t, front, "203.0.113.23")))
	if hasCookie(resp, "room_ticket") {
		t.Error("with agent_queue on, a Concert-Session request gets no cookie")
	}

	// A browser carries the fast-lane cookie, not the header, and keeps the
	// cookie flow.
	resp, _ = get(t, front.URL+"/drop", map[string]string{"X-Forwarded-For": "203.0.113.22", "Cookie": fastlane.Cookie + "=" + tok})
	if !hasCookie(resp, "room_ticket") {
		t.Error("a browser with the concert_fastlane cookie must stay on the cookie flow")
	}
	// An invalid header is not an identity either.
	resp, _ = get(t, front.URL+"/drop", asAgent("203.0.113.24", tok+"x"))
	if !hasCookie(resp, "room_ticket") {
		t.Error("a forged Concert-Session must not key a place")
	}
	if n := a.agents.held(); n != 1 {
		t.Errorf("agent places tracked: %d, want 1", n)
	}
}

// Without wallet access there are no sessions, so -agent-queue does nothing.
func TestAgent_NeedsWalletAccess(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.agentQueue = true
	_, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)
	resp, _ := get(t, front.URL+"/drop", map[string]string{fastlane.SessionHeader: "a.b.c"})
	if !hasCookie(resp, "room_ticket") {
		t.Error("without wallet access every request keeps the cookie flow")
	}
}

// ─── abuse ───────────────────────────────────────────────────────────────────

func TestAgent_PlacesCappedPerAddress(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := agentTestConfig(t, up, true)
	cfg.agentPlaces = 2
	a, _, front := newTestPortal(t, cfg, up)
	fillSlot(t, front, up)

	first, second := session(t, front, "203.0.113.30"), session(t, front, "203.0.113.30")
	get(t, front.URL+"/drop", asAgent("203.0.113.30", first))
	get(t, front.URL+"/drop", asAgent("203.0.113.30", second))
	strikes := a.stats.abuseStrikes.Load()

	resp, body := get(t, front.URL+"/drop", asAgent("203.0.113.30", session(t, front, "203.0.113.30")))
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "5" ||
		!strings.Contains(string(body), `"error":"agent_places_exceeded"`) {
		t.Fatalf("third place from one address: got %d Retry-After=%q %s, want 429 agent_places_exceeded",
			resp.StatusCode, resp.Header.Get("Retry-After"), body)
	}
	if got := a.stats.abuseStrikes.Load(); got != strikes+1 {
		t.Errorf("strikes: %d, want %d (one for the refused place)", got, strikes+1)
	}
	if n := a.room.LiveQueueDepth(); n != 2 {
		t.Errorf("in line: %d, want the two allowed places", n)
	}

	// A session already in line keeps asking at the cap.
	if resp, body := get(t, front.URL+"/drop", asAgent("203.0.113.30", first)); !strings.Contains(string(body), `"position":1`) {
		t.Errorf("an existing place at the cap: got %d %s", resp.StatusCode, body)
	}
	// Another address is unaffected; IPv6 counts by /64.
	get(t, front.URL+"/drop", asAgent("2001:db8:1:2::1", session(t, front, "2001:db8:1:2::1")))
	get(t, front.URL+"/drop", asAgent("2001:db8:1:2::2", session(t, front, "2001:db8:1:2::2")))
	resp, _ = get(t, front.URL+"/drop", asAgent("2001:db8:1:2::3", session(t, front, "2001:db8:1:2::3")))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("a third place from one IPv6 /64: got %d, want 429", resp.StatusCode)
	}
	if n := a.agents.count(addrKey("2001:db8:1:2::9")); n != 2 {
		t.Errorf("places held by the /64: %d, want 2", n)
	}
}

// Keyed arrivals are capped by -agent-places, never churn-struck: room's
// keyed EventQueue carries the key and an empty ClientKey, and churnStrike
// ignores an empty key.
func TestAgent_ArrivalsEarnNoChurnStrikes(t *testing.T) {
	up := newFakeUpstream(t)
	a, _, front := newTestPortal(t, agentTestConfig(t, up, true), up)
	fillSlot(t, front, up)
	queued := make(chan room.Snapshot, 4)
	a.room.On(room.EventQueue, func(s room.Snapshot) { queued <- s })

	get(t, front.URL+"/drop", asAgent("203.0.113.40", session(t, front, "203.0.113.40")))
	select {
	case s := <-queued:
		if s.Key == "" || s.ClientKey != "" || s.Token != "" {
			t.Fatalf("keyed EventQueue: key=%q client=%q token set=%v, want key only", s.Key, s.ClientKey, s.Token != "")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no EventQueue for the keyed arrival")
	}
	before := a.stats.abuseStrikes.Load()
	a.churnStrike("")
	if a.stats.abuseStrikes.Load() != before {
		t.Error("churnStrike must ignore an empty client key")
	}
}

func TestAgent_BanDropsAgentPlaces(t *testing.T) {
	up := newFakeUpstream(t)
	a, _, front := newTestPortal(t, agentTestConfig(t, up, true), up)
	fillSlot(t, front, up)
	get(t, front.URL+"/drop", asAgent("203.0.113.50", session(t, front, "203.0.113.50")))
	get(t, front.URL+"/drop", asAgent("203.0.113.50", session(t, front, "203.0.113.50")))
	doReq(t, jarClient(), http.MethodGet, front.URL+"/api/wait", withXFF("198.51.100.50"), nil)
	if n := a.room.LiveQueueDepth(); n != 3 {
		t.Fatalf("in line: %d, want 3", n)
	}

	if _, err := a.abuse.banFor(netip.MustParseAddr("203.0.113.50"), time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	eventually(t, 2*time.Second, func() bool { return a.room.LiveQueueDepth() == 1 },
		"the ban never removed the address's agent places")
	if line := a.room.Queue(10); len(line) != 1 || line[0].ClientKey != "198.51.100.50" {
		t.Errorf("the wrong place was removed: %+v", line)
	}
	if n := a.agents.count(addrKey("203.0.113.50")); n != 0 {
		t.Errorf("the banned address still has %d tracked place(s)", n)
	}
}

// ─── admission, portal, restart ──────────────────────────────────────────────

func TestAgent_AdmittedOnceASlotFrees(t *testing.T) {
	up := newFakeUpstream(t)
	a, _, front := newTestPortal(t, agentTestConfig(t, up, true), up)
	fillSlot(t, front, up)
	tok := session(t, front, "203.0.113.60")
	get(t, front.URL+"/drop", asAgent("203.0.113.60", tok))

	up.releaseAll()
	eventually(t, 5*time.Second, func() bool {
		resp, body := get(t, front.URL+"/drop", asAgent("203.0.113.60", tok))
		return resp.StatusCode == http.StatusOK && string(body) == "ok"
	}, "the agent was never admitted")
	if _, ok := keyedPlace(t, a, tok); ok {
		t.Error("an admitted agent still has a place")
	}
	// The proxy flushes the response before agentGate forgets the key.
	eventually(t, 2*time.Second, func() bool { return a.agents.held() == 0 }, "an admitted agent is still tracked")
}

func TestAgent_PortalShowsAgentAndActsOnIt(t *testing.T) {
	up := newFakeUpstream(t)
	a, p, front := newTestPortal(t, agentTestConfig(t, up, true), up)
	fillSlot(t, front, up)
	doReq(t, jarClient(), http.MethodGet, front.URL+"/api/wait", withXFF("198.51.100.70"), nil)
	tok := session(t, front, "203.0.113.70")
	get(t, front.URL+"/drop", asAgent("203.0.113.70", tok))
	key := sessionKey(t, a, tok)
	ti, ok := keyedPlace(t, a, tok)
	if !ok || ti.Position != 2 {
		t.Fatalf("agent place: %+v %v, want position 2", ti, ok)
	}

	views := p.queueViews(time.Now())
	if len(views) != 2 || views[1].Agent != key[len(agentKeyPrefix):len(agentKeyPrefix)+8] || views[0].Agent != "" {
		t.Fatalf("queue views: %+v", views)
	}
	ck, csrf := portalLogin(t, p)
	f := frag(t, p, ck, "/api/frag/queue")
	if !strings.Contains(f.HTML, "agent "+views[1].Agent) || strings.Contains(f.HTML, ti.Token) {
		t.Errorf("the Queue tab must mark the agent and never show its token")
	}
	if rec := portalDo(p, http.MethodGet, "/api/queue", "", ck, "", false); strings.Contains(rec.Body.String(), ti.Token) {
		t.Error("the queue API leaked a keyed ticket's token")
	}

	if rec := portalDo(p, http.MethodPost, "/api/queue/promote", `{"id":"`+views[1].ID+`"}`, ck, csrf, false); rec.Code != http.StatusOK {
		t.Fatalf("promote: %d %s", rec.Code, rec.Body.String())
	}
	// AdminPromote ties the ticket with the one at the front (see room).
	if moved, ok := keyedPlace(t, a, tok); !ok || moved.Position != 1 || !moved.Promoted {
		t.Errorf("move to front did not move the agent: %+v", moved)
	}
	if rec := portalDo(p, http.MethodPost, "/api/queue/kick", `{"id":"`+views[1].ID+`"}`, ck, csrf, false); rec.Code != http.StatusOK {
		t.Fatalf("kick: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := keyedPlace(t, a, tok); ok || a.agents.held() != 0 {
		t.Errorf("removed agent: place kept=%v tracked=%d", ok, a.agents.held())
	}
}

// A restored line keeps counting an address's agent places.
func TestAgent_PlacesSurviveRestart(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := agentTestConfig(t, up, true)
	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(a.handler)
	fillSlot(t, front, up)
	get(t, front.URL+"/drop", asAgent("203.0.113.80", session(t, front, "203.0.113.80")))
	up.releaseAll()
	front.Close()
	a.Close()

	b, err := newApp(cfg)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	defer b.Close()
	if n := b.agents.count(addrKey("203.0.113.80")); n != 1 {
		t.Errorf("restored agent places for the address: %d, want 1", n)
	}
}

// Stale entries (tickets room reaped without telling anyone the key) are
// reconciled before they can refuse a new place.
func TestAgentPlaces_ReconcilesStaleKeys(t *testing.T) {
	wr := &room.WaitingRoom{}
	if err := wr.Init(1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wr.Stop)
	p := newAgentPlaces()
	addr := addrKey("203.0.113.90")
	now := time.Now()
	if fresh, ok := p.reserve(wr, "s:gone", addr, 1, now); !fresh || !ok {
		t.Fatal("first reservation refused")
	}
	if _, ok := p.reserve(wr, "s:gone", addr, 1, now); !ok {
		t.Error("the same key must always be allowed")
	}
	// s:gone has no ticket in room, so it does not count against the cap.
	if fresh, ok := p.reserve(wr, "s:next", addr, 1, now); !fresh || !ok {
		t.Error("a stale entry refused a new place")
	}
	if p.count(addr) != 1 {
		t.Errorf("tracked for the address: %d, want 1", p.count(addr))
	}
	p.forget("s:next")
	if p.held() != 0 {
		t.Errorf("held after forget: %d", p.held())
	}
}

// ─── the wait response ───────────────────────────────────────────────────────

type agentWait struct {
	Queued     bool   `json:"queued"`
	Position   int64  `json:"position"`
	QueueDepth int64  `json:"queue_depth"`
	StatusURL  string `json:"status_url"`
	RetryAfter int    `json:"retry_after_seconds"`
	Hint       string `json:"hint"`
	FastLane   *struct {
		PaymentURL  string              `json:"payment_url"`
		PassSeconds int                 `json:"pass_seconds"`
		Offers      []map[string]string `json:"offers"`
	} `json:"fast_lane"`
}

func waitBody(t *testing.T, resp *http.Response, body []byte) agentWait {
	t.Helper()
	var w agentWait
	if resp.StatusCode != http.StatusTooManyRequests || json.Unmarshal(body, &w) != nil || !w.Queued {
		t.Fatalf("queued agent: got %d %s, want 429 queued:true", resp.StatusCode, body)
	}
	return w
}

// A queued agent gets Concert's contract (429, Retry-After: -retry-after),
// an absolute status_url naming the same place, and the fast-lane offer.
func TestAgent_WaitResponseContract(t *testing.T) {
	up := newFakeUpstream(t)
	a, _, front := newTestPortal(t, agentTestConfig(t, up, true), up)
	fillSlot(t, front, up)
	doReq(t, jarClient(), http.MethodGet, front.URL+"/api/wait", withXFF("198.51.100.1"), nil)
	tok := session(t, front, "203.0.113.100")

	resp, body := get(t, front.URL+"/drop", asAgent("203.0.113.100", tok))
	w := waitBody(t, resp, body)
	if got := resp.Header.Get("Retry-After"); got != "5" {
		t.Errorf("Retry-After: %q, want -retry-after (5), not room's 3", got)
	}
	if resp.Header.Get("Cache-Control") != "no-store" || len(resp.Header.Values("Set-Cookie")) != 0 {
		t.Errorf("headers: Cache-Control=%q Set-Cookie=%v", resp.Header.Get("Cache-Control"), resp.Header.Values("Set-Cookie"))
	}
	if got, want := resp.Header.Get("Link"), `<http://127.0.0.1:8080/_concert/payment>; rel="payment"`; got != want {
		t.Errorf("Link: %q, want %q", got, want)
	}
	ti, ok := keyedPlace(t, a, tok)
	if !ok || w.Position != 2 || w.Position != ti.Place || w.QueueDepth != 2 || w.RetryAfter != 5 ||
		w.Hint != agentWaitHint || w.StatusURL != "http://127.0.0.1:8080/queue/status/"+ti.ID {
		t.Errorf("body: %+v (place %d, id %s)", w, ti.Place, ti.ID)
	}
	if w.FastLane == nil || w.FastLane.PaymentURL != "http://127.0.0.1:8080/_concert/payment" || w.FastLane.PassSeconds != 300 ||
		len(w.FastLane.Offers) != 1 || w.FastLane.Offers[0]["network"] != "xrpl:1" || w.FastLane.Offers[0]["asset"] != "XRP" ||
		w.FastLane.Offers[0]["amount"] != "100" || w.FastLane.Offers[0]["asset_symbol"] != "XRP" ||
		w.FastLane.Offers[0]["display_amount"] != "0.0001" || w.FastLane.Offers[0]["scheme"] != "exact" {
		t.Errorf("fast_lane: %+v", w.FastLane)
	}
	if _, hasPayTo := w.FastLane.Offers[0]["payTo"]; hasPayTo {
		t.Error("offer summary must not expose payTo")
	}
	if strings.Contains(string(body), agentTestOffer.PayTo) || strings.Contains(string(body), ti.Token) {
		t.Error("the wait response must carry neither the recipient nor the ticket's token")
	}

	// GET status_url shows the same place, by its public ID.
	sresp, sbody := get(t, front.URL+"/queue/status/"+ti.ID, nil)
	var st struct {
		Waiting  bool  `json:"waiting"`
		Position int64 `json:"position"`
	}
	if sresp.StatusCode != http.StatusOK || json.Unmarshal(sbody, &st) != nil || !st.Waiting || st.Position != w.Position {
		t.Errorf("status_url: %d %s, want position %d", sresp.StatusCode, sbody, w.Position)
	}
}

func TestAgent_NoOfferWithoutPaymentOffers(t *testing.T) {
	up := newFakeUpstream(t)
	_, _, front := newTestPortal(t, agentTestConfig(t, up, false), up)
	fillSlot(t, front, up)
	resp, body := get(t, front.URL+"/drop", asAgent("203.0.113.101", session(t, front, "203.0.113.101")))
	w := waitBody(t, resp, body)
	if w.FastLane != nil || resp.Header.Get("Link") != "" || strings.Contains(string(body), "fast_lane") {
		t.Errorf("an NFT-only fast lane has no offer: Link=%q %s", resp.Header.Get("Link"), body)
	}
}

// -api-json governs cookie clients; an agent always gets the JSON contract.
func TestAgent_ContractHoldsWithoutAPIJSON(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := agentTestConfig(t, up, true)
	cfg.apiJSON = false
	_, _, front := newTestPortal(t, cfg, up)
	fillSlot(t, front, up)
	resp, body := get(t, front.URL+"/drop", asAgent("203.0.113.102", session(t, front, "203.0.113.102")))
	waitBody(t, resp, body)
}

// room's queue-depth breaker sends a bare 503; agents and cookie API clients
// both get "waiting room is full", and no place is taken.
func TestAgent_BreakerStillSaysFull(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := agentTestConfig(t, up, true)
	cfg.maxQueue = 1
	a, _, front := newTestPortal(t, cfg, up)
	fillSlot(t, front, up)
	doReq(t, jarClient(), http.MethodGet, front.URL+"/api/wait", withXFF("198.51.100.2"), nil)

	const want = `{"error":"waiting room is full","queued":false,"retry_after_seconds":5}`
	resp, body := get(t, front.URL+"/drop", asAgent("203.0.113.103", session(t, front, "203.0.113.103")))
	if resp.StatusCode != http.StatusServiceUnavailable || string(body) != want || resp.Header.Get("Retry-After") != "5" {
		t.Errorf("agent at the breaker: got %d Retry-After=%q %s, want 503 %s", resp.StatusCode, resp.Header.Get("Retry-After"), body, want)
	}
	// The breaker's body is written before agentGate forgets the key.
	eventually(t, 2*time.Second, func() bool { return a.agents.held() == 0 }, "a refused arrival is still tracked")
	resp, body = get(t, front.URL+"/api/x", withXFF("198.51.100.3"))
	if resp.StatusCode != http.StatusServiceUnavailable || string(body) != want {
		t.Errorf("cookie API client at the breaker: got %d %s", resp.StatusCode, body)
	}
}

// With agents on, cookie API clients and browsers get exactly what they got
// before.
func TestAgent_CookieClientsUnchanged(t *testing.T) {
	up := newFakeUpstream(t)
	_, _, front := newTestPortal(t, agentTestConfig(t, up, true), up)
	fillSlot(t, front, up)
	get(t, front.URL+"/drop", asAgent("203.0.113.104", session(t, front, "203.0.113.104")))

	const want = `{"hint":"keep the room_ticket cookie and retry to hold your position","queued":true,"retry_after_seconds":5,"status_url":"/queue/status"}`
	resp, body := get(t, front.URL+"/api/x", withXFF("198.51.100.4"))
	if resp.StatusCode != http.StatusTooManyRequests || string(body) != want || !hasCookie(resp, "room_ticket") || resp.Header.Get("Link") != "" {
		t.Errorf("cookie API client: got %d %s", resp.StatusCode, body)
	}
	resp, body = get(t, front.URL+"/page", map[string]string{"X-Forwarded-For": "198.51.100.5", "Accept": "text/html"})
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") ||
		!hasCookie(resp, "room_ticket") || !strings.Contains(string(body), "<html") {
		t.Errorf("browser: got %d %s, want the waiting page", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

func TestAgent_TwoAgentsOneAddressOnePlace(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := agentTestConfig(t, up, true)
	cfg.agentPlaces = 1
	_, _, front := newTestPortal(t, cfg, up)
	fillSlot(t, front, up)
	r1, b1 := get(t, front.URL+"/drop", asAgent("203.0.113.105", session(t, front, "203.0.113.105")))
	waitBody(t, r1, b1)
	resp, body := get(t, front.URL+"/drop", asAgent("203.0.113.105", session(t, front, "203.0.113.105")))
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(body), "agent_places_exceeded") {
		t.Errorf("second agent from one address at -agent-places 1: got %d %s", resp.StatusCode, body)
	}
}

// A paid session goes through the priority lane before it is ever queued,
// exactly as a paid browser does.
func TestAgent_PaidAgentUsesPriorityLane(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := agentTestConfig(t, up, true)
	cfg.priorityCap, cfg.priorityWait = 1, 10*time.Millisecond
	a, _, front := newTestPortal(t, cfg, up)
	fillSlot(t, front, up)
	tok := session(t, front, "203.0.113.106")
	proof, _ := json.Marshal(map[string]any{"x402Version": 2, "accepted": agentTestOffer, "payload": map[string]string{"signedTxBlob": "agent-proof"}})
	hdr := asAgent("203.0.113.106", tok)
	hdr["PAYMENT-SIGNATURE"] = base64.StdEncoding.EncodeToString(proof)
	if resp, body := doReq(t, testClient, http.MethodPost, front.URL+"/_concert/payment", hdr, strings.NewReader("{}")); resp.StatusCode != http.StatusOK {
		t.Fatalf("payment: %d %s", resp.StatusCode, body)
	}

	resp, body := get(t, front.URL+"/drop", asAgent("203.0.113.106", tok))
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("paid agent while the room is full: got %d %s, want 200 through the lane", resp.StatusCode, body)
	}
	if a.prio.laneServed.Load() != 1 || a.room.LiveQueueDepth() != 0 || a.agents.held() != 0 {
		t.Errorf("lane served=%d in line=%d tracked=%d, want 1, 0, 0",
			a.prio.laneServed.Load(), a.room.LiveQueueDepth(), a.agents.held())
	}
}
