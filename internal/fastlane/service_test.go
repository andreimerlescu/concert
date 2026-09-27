package fastlane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type harness struct {
	s        *Service
	cfg      Config
	gateway  *httptest.Server
	settle   atomic.Int64
	verify   atomic.Int64
	fail     atomic.Bool
	bad      atomic.Bool
	nftBad   atomic.Bool
	onSettle atomic.Pointer[func()]
	dir      string
	now      time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{dir: t.TempDir(), now: time.Now().UTC()}
	h.gateway = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("g", 32) {
			t.Error("gateway auth missing")
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/supported":
			reply(w, 200, map[string]any{"kinds": []any{map[string]any{"x402Version": 2, "scheme": "exact", "network": "xrpl:1"}}})
		case "/verify":
			h.verify.Add(1)
			reply(w, 200, verification{Valid: true, Payer: "rPayer"})
		case "/settle":
			if hook := h.onSettle.Load(); hook != nil {
				(*hook)()
			}
			h.settle.Add(1)
			var in struct {
				Payload Payload `json:"paymentPayload"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			var p map[string]string
			_ = json.Unmarshal(in.Payload.Payload, &p)
			if h.fail.Load() {
				w.WriteHeader(503)
				return
			}
			payer := "rPayer"
			if h.bad.Load() {
				payer = "rWrong"
			}
			reply(w, 200, Settlement{Success: true, Network: "xrpl:1", Payer: payer, Transaction: p["signedTxBlob"]})
		case "/nft/verify":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			owner := in["address"]
			if h.nftBad.Load() {
				owner = "other"
			}
			reply(w, 200, map[string]any{"valid": true, "owner": owner, "network": in["network"], "collection": in["collection"], "token_id": "NFT1"})
		default:
			w.WriteHeader(404)
		}
	}))
	h.cfg = Config{Enabled: true, Origin: "http://127.0.0.1:8080", GatewayURL: h.gateway.URL, TestMode: true, Merchant: "Test merchant", TermsURL: "http://127.0.0.1:8080/terms", PrivacyURL: "http://127.0.0.1:8080/privacy", RefundURL: "http://127.0.0.1:8080/refunds", PassSeconds: 30, NFTPassSeconds: 5, MaxRecords: 100,
		Offers:      []Offer{{Label: "XRP", Requirements: Requirements{Scheme: "exact", Network: "xrpl:1", Amount: "100", Asset: "XRP", PayTo: "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", MaxTimeoutSeconds: 60, Extra: map[string]any{"areFeesSponsored": false}}}},
		Collections: []Collection{{ID: "club", Label: "Club", Network: "xrpl:1", Collection: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh:0"}}}
	h.open(t)
	t.Cleanup(func() { h.s.Close(); h.gateway.Close() })
	return h
}
func (h *harness) open(t *testing.T) {
	t.Helper()
	s, e := New(h.cfg, h.dir, []byte(strings.Repeat("k", 32)), strings.Repeat("g", 32), strings.Repeat("p", 32))
	if e != nil {
		t.Fatal(e)
	}
	h.s = s
	s.now = func() time.Time { return h.now }
}
func request(s *Service, path, session, body, payment string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", Prefix+path, strings.NewReader(body))
	r.Header.Set(SessionHeader, session)
	if payment != "" {
		r.Header.Set("PAYMENT-SIGNATURE", payment)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func newSession(t *testing.T, s *Service) string {
	t.Helper()
	w := request(s, "/session", "", "{}", "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var data map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &data)
	return data["session"]
}
func signed(h *harness, tx string) string {
	b, _ := json.Marshal(Payload{Version: 2, Accepted: h.cfg.Offers[0].Requirements, Payload: json.RawMessage(`{"signedTxBlob":"` + tx + `"}`)})
	return base64.StdEncoding.EncodeToString(b)
}
func eligible(s *Service, session string) bool {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set(SessionHeader, session)
	return s.Eligible(r)
}

func TestPaymentChallengeSettlementReplayAndRestart(t *testing.T) {
	h := newHarness(t)
	s := newSession(t, h.s)
	w := request(h.s, "/payment", s, "{}", "")
	if w.Code != 402 || w.Header().Get("PAYMENT-REQUIRED") == "" {
		t.Fatalf("no x402 challenge: %d", w.Code)
	}
	proof := signed(h, "TX1")
	w = request(h.s, "/payment", s, "{}", proof)
	if w.Code != 200 || !eligible(h.s, s) || w.Header().Get("PAYMENT-RESPONSE") == "" {
		t.Fatal(w.Body.String())
	}
	request(h.s, "/payment", s, "{}", proof)
	if h.settle.Load() != 1 {
		t.Fatal("duplicate settlement")
	}
	other := newSession(t, h.s)
	if w = request(h.s, "/payment", other, "{}", proof); w.Code != 409 || eligible(h.s, other) {
		t.Fatal("cross-session payment replay")
	}
	h.s.Close()
	h.open(t)
	if !eligible(h.s, s) {
		t.Fatal("lost paid pass after restart")
	}
	h.now = h.now.Add(31 * time.Second)
	if eligible(h.s, s) {
		t.Fatal("expired receipt granted")
	}
	request(h.s, "/payment", s, "{}", proof)
	if eligible(h.s, s) {
		t.Fatal("retry extended expired pass")
	}
	// A newer purchase must not make an older payment reusable in the same session.
	request(h.s, "/payment", s, "{}", signed(h, "TX2"))
	h.now = h.now.Add(31 * time.Second)
	request(h.s, "/payment", s, "{}", proof)
	if eligible(h.s, s) || h.settle.Load() != 2 {
		t.Fatal("historical payment renewed a lease")
	}
}
func TestTamperedRequirementsNeverReachFacilitator(t *testing.T) {
	h := newHarness(t)
	s := newSession(t, h.s)
	p := Payload{Version: 2, Accepted: h.cfg.Offers[0].Requirements, Payload: json.RawMessage(`{"signedTxBlob":"a"}`)}
	p.Accepted.Amount = "1"
	b, _ := json.Marshal(p)
	w := request(h.s, "/payment", s, "{}", base64.StdEncoding.EncodeToString(b))
	if w.Code != 400 || h.verify.Load() != 0 || h.settle.Load() != 0 {
		t.Fatal("untrusted amount reached gateway")
	}
}
func TestUncertainSettlementBlocksDifferentPayment(t *testing.T) {
	h := newHarness(t)
	s := newSession(t, h.s)
	h.fail.Store(true)
	p := signed(h, "TX1")
	w := request(h.s, "/payment", s, "{}", p)
	if w.Code != 503 || eligible(h.s, s) {
		t.Fatal("uncertain payment admitted")
	}
	w = request(h.s, "/payment", s, "{}", signed(h, "TX2"))
	if w.Code != 409 || h.settle.Load() != 1 {
		t.Fatal("second payment submitted while unresolved")
	}
	h.fail.Store(false)
	w = request(h.s, "/payment", s, "{}", p)
	if w.Code != 200 || !eligible(h.s, s) {
		t.Fatal("same authorization recovery failed")
	}
}
func TestSettlementMustNameVerifiedPayer(t *testing.T) {
	h := newHarness(t)
	h.bad.Store(true)
	s := newSession(t, h.s)
	w := request(h.s, "/payment", s, "{}", signed(h, "TX1"))
	if w.Code != 503 || eligible(h.s, s) {
		t.Fatal("mismatched payer accepted")
	}
}
func TestPolicyFailsClosedBeforeSettlement(t *testing.T) {
	h := newHarness(t)
	policy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, assessment{Decision: "deny", ID: "case1", Expires: h.now.Add(time.Minute)})
	}))
	defer policy.Close()
	h.s.cfg.PolicyURL = policy.URL
	h.s.cfg.TestMode = false
	s := newSession(t, h.s)
	w := request(h.s, "/payment", s, "{}", signed(h, "TX1"))
	if w.Code != 403 || h.settle.Load() != 0 {
		t.Fatal("denied wallet was charged")
	}
}
func TestSessionAndCSRF(t *testing.T) {
	h := newHarness(t)
	s := newSession(t, h.s)
	if eligible(h.s, s+"tampered") {
		t.Fatal("forged session")
	}
	r := httptest.NewRequest("POST", Prefix+"/payment", strings.NewReader("{}"))
	r.AddCookie(&http.Cookie{Name: Cookie, Value: s})
	w := httptest.NewRecorder()
	h.s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cookie request without CSRF accepted")
	}
	r = httptest.NewRequest("POST", Prefix+"/session", strings.NewReader("{}"))
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	h.s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin session accepted")
	}
}
func TestNFTChallengeIsBoundSingleUseAndExpires(t *testing.T) {
	h := newHarness(t)
	s := newSession(t, h.s)
	other := newSession(t, h.s)
	challenge := request(h.s, "/nft/challenge", s, `{"rule":"club","address":"rHolder","token_id":""}`, "")
	var ch map[string]any
	_ = json.Unmarshal(challenge.Body.Bytes(), &ch)
	proof, _ := json.Marshal(map[string]any{"nonce": ch["nonce"], "signature": "sig", "public_key": "pub"})
	w := request(h.s, "/nft/verify", other, string(proof), "")
	if w.Code != 401 {
		t.Fatal("challenge moved to another session")
	}
	w = request(h.s, "/nft/verify", s, string(proof), "")
	if w.Code != 200 || !eligible(h.s, s) {
		t.Fatal(w.Body.String())
	}
	w = request(h.s, "/nft/verify", s, string(proof), "")
	if w.Code != 401 {
		t.Fatal("challenge reused")
	}
	h.now = h.now.Add(6 * time.Second)
	if eligible(h.s, s) {
		t.Fatal("stale NFT lease survived")
	}
}
func TestNFTVerifierMustReturnSameOwner(t *testing.T) {
	h := newHarness(t)
	s := newSession(t, h.s)
	w := request(h.s, "/nft/challenge", s, `{"rule":"club","address":"rHolder","token_id":""}`, "")
	var ch map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &ch)
	b, _ := json.Marshal(map[string]any{"nonce": ch["nonce"], "signature": "sig", "public_key": "pub"})
	h.nftBad.Store(true)
	w = request(h.s, "/nft/verify", s, string(b), "")
	if w.Code != 403 || eligible(h.s, s) {
		t.Fatal("NFT owner mismatch accepted")
	}
}
func TestConcurrentPaymentOnlyOneSettlement(t *testing.T) {
	h := newHarness(t)
	s := newSession(t, h.s)
	proof := signed(h, "TX1")
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); request(h.s, "/payment", s, "{}", proof) }()
	}
	wg.Wait()
	if h.settle.Load() != 1 {
		t.Fatalf("settlements = %d", h.settle.Load())
	}
}
func TestJournalCorruptionAndExclusiveLock(t *testing.T) {
	h := newHarness(t)
	if l, e := openLedger(h.dir, 100); e == nil {
		l.close()
		t.Fatal("second writer allowed")
	}
	h.s.Close()
	if e := os.WriteFile(filepath.Join(h.dir, "fastlane.jsonl"), []byte(`{"unfinished":`), 0600); e != nil {
		t.Fatal(e)
	}
	if l, e := openLedger(h.dir, 100); e == nil {
		l.close()
		t.Fatal("corrupt journal accepted")
	}
	h.s.ledger.file = nil
	h.s.ledger.lock = nil
}
func TestConfigurationRejectsMainnetTestModeAndMissingPolicy(t *testing.T) {
	h := newHarness(t)
	c := h.cfg
	c.TestMode = false
	if c.Validate() == nil {
		t.Fatal("production without policy allowed")
	}
	c = h.cfg
	c.Offers = append([]Offer(nil), c.Offers...)
	c.Offers[0].Requirements.Network = "xrpl:0"
	if c.Validate() == nil {
		t.Fatal("mainnet accepted in test mode")
	}
}
func TestUnknownPaymentJournalCannotBeSilentlyReset(t *testing.T) {
	h := newHarness(t)
	h.fail.Store(true)
	s := newSession(t, h.s)
	request(h.s, "/payment", s, "{}", signed(h, "TX1"))
	h.s.Close()
	h.open(t)
	if eligible(h.s, s) {
		t.Fatal("pending payment granted after restart")
	}
	if w := request(h.s, "/payment", s, "{}", signed(h, "TX2")); w.Code != 409 {
		t.Fatal("restart allowed another payment")
	}
}
func TestServiceDoesNotFollowRedirects(t *testing.T) {
	h := newHarness(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("credentials followed redirect") }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	var out any
	if h.s.call(context.Background(), time.Second, redirect.URL, "secret", map[string]string{}, &out) == nil {
		t.Fatal("redirect accepted")
	}
}
