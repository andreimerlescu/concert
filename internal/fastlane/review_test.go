package fastlane

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Regression tests for defects found while integrating the fast lane.

func renew(t *testing.T, s *Service, token string) string {
	t.Helper()
	w := request(s, "/session", token, "{}", "")
	if w.Code != 200 {
		t.Fatalf("renew: %d %s", w.Code, w.Body.String())
	}
	var data map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &data)
	return data["session"].(string)
}

func TestSessionRenewalKeepsIDAndPassNeverOutlivesToken(t *testing.T) {
	h := newHarness(t)
	s := newSession(t, h.s)
	// Close to expiry, authenticated operations ask for renewal first, before
	// any payment is requested or signed.
	h.now = h.now.Add(sessionLifetime - renewBefore + time.Minute)
	if w := request(h.s, "/payment", s, "{}", ""); w.Code != 409 || !strings.Contains(w.Body.String(), "session_renewal_required") {
		t.Fatalf("near-expiry payment: %d %s", w.Code, w.Body.String())
	}
	renewed := renew(t, h.s, s)
	if renewed == s {
		t.Fatal("renewal must issue a fresh expiry")
	}
	proof := signed(h, "TX1")
	if w := request(h.s, "/payment", renewed, "{}", proof); w.Code != 200 {
		t.Fatalf("payment after renewal: %d %s", w.Code, w.Body.String())
	}
	// The ID survives renewal: the old token (still unexpired) sees the same
	// pass, and a later renewal still finds the receipt.
	if !eligible(h.s, s) || !eligible(h.s, renew(t, h.s, renewed)) {
		t.Fatal("renewal lost the session's receipt")
	}
	// A pass is bought with at least renewBefore of token lifetime left, which
	// exceeds the longest configurable pass.
	if time.Duration(3600)*time.Second+300*time.Second >= renewBefore {
		t.Fatal("renewBefore must exceed the longest pass plus settlement time")
	}
}

func TestSettlementIsRecordedWhenTheVisitorDisconnects(t *testing.T) {
	h := newHarness(t)
	s := newSession(t, h.s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	hook := func() {
		cancel() // the visitor's tab closes while the chain settles
		<-release
	}
	h.onSettle.Store(&hook)
	r := httptest.NewRequest("POST", Prefix+"/payment", strings.NewReader("{}")).WithContext(ctx)
	r.Header.Set(SessionHeader, s)
	r.Header.Set("PAYMENT-SIGNATURE", signed(h, "TX1"))
	done := make(chan int)
	go func() { w := httptest.NewRecorder(); h.s.ServeHTTP(w, r); done <- w.Code }()
	time.Sleep(50 * time.Millisecond)
	close(release)
	if code := <-done; code != 200 {
		t.Fatalf("detached settlement: %d", code)
	}
	if !eligible(h.s, s) {
		t.Fatal("a payment that settled after the visitor disconnected was not recorded")
	}
}

func TestConcurrentSameAuthorizationAcrossSessionsSettlesOnce(t *testing.T) {
	h := newHarness(t)
	proof := signed(h, "TX1")
	sessions := make([]string, 16)
	for i := range sessions {
		sessions[i] = newSession(t, h.s)
	}
	var wg sync.WaitGroup
	var ok atomic.Int64
	for _, s := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if request(h.s, "/payment", s, "{}", proof).Code == 200 {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	winners := 0
	for _, s := range sessions {
		if eligible(h.s, s) {
			winners++
		}
	}
	if h.settle.Load() != 1 || ok.Load() != 1 || winners != 1 {
		t.Fatalf("settlements=%d ok=%d eligible=%d", h.settle.Load(), ok.Load(), winners)
	}
}

func TestNFTTokenRulesMatchWhatTheGatewayVerifies(t *testing.T) {
	h := newHarness(t)
	h.s.cfg.Collections = append(h.s.cfg.Collections,
		Collection{ID: "sol", Label: "Sol", Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", Collection: "11111111111111111111111111111111"},
		Collection{ID: "xlm", Label: "Xlm", Network: "stellar:testnet", Collection: "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"})
	s := newSession(t, h.s)
	if w := request(h.s, "/nft/challenge", s, `{"rule":"sol","address":"11111111111111111111111111111111","token_id":""}`, ""); w.Code != 400 || !strings.Contains(w.Body.String(), "nft_mint_required") {
		t.Fatalf("Solana rule without a mint: %d %s", w.Code, w.Body.String())
	}
	if w := request(h.s, "/nft/challenge", s, `{"rule":"xlm","address":"GABC","token_id":"7"}`, ""); w.Code != 400 {
		t.Fatalf("Stellar token-specific rule: %d %s", w.Code, w.Body.String())
	}
	// The harness gateway always proves token NFT1; a request for NFT2 must
	// not be granted on a proof of a different token.
	w := request(h.s, "/nft/challenge", s, `{"rule":"club","address":"rHolder","token_id":"NFT2"}`, "")
	var ch map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &ch)
	b, _ := json.Marshal(map[string]any{"nonce": ch["nonce"], "signature": "sig", "public_key": "pub"})
	if w = request(h.s, "/nft/verify", s, string(b), ""); w.Code != 403 || eligible(h.s, s) {
		t.Fatalf("token mismatch granted: %d %s", w.Code, w.Body.String())
	}
}

func TestWalletPostsAreRateLimitedPerAddress(t *testing.T) {
	h := newHarness(t)
	post := func(remote string) int {
		r := httptest.NewRequest("POST", Prefix+"/session", strings.NewReader("{}"))
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.s.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < postsPerMinute; i++ {
		if code := post("2001:db8:1:2::1"); code != 200 {
			t.Fatalf("request %d: %d", i, code)
		}
	}
	if post("2001:db8:1:2::ffff") != 429 {
		t.Fatal("addresses in one IPv6 /64 must share a limit")
	}
	if post("198.51.100.7") != 200 {
		t.Fatal("another client was limited")
	}
	h.now = h.now.Add(time.Minute)
	if post("2001:db8:1:2::1") != 200 {
		t.Fatal("limit did not reset")
	}
}

func TestConfigurationChecksRecipientsAndHederaSponsor(t *testing.T) {
	h := newHarness(t)
	base := h.cfg
	base.Collections = nil
	bad := func(r Requirements) bool {
		c := base
		c.Offers = []Offer{{Label: "x", Requirements: r}}
		return c.Validate() != nil
	}
	x := base.Offers[0].Requirements
	x.PayTo = "not-an-address"
	hbar := Requirements{Scheme: "exact", Network: "hedera:testnet", Amount: "100", Asset: "0.0.0", PayTo: "0.0.789", MaxTimeoutSeconds: 60, Extra: map[string]any{}}
	sponsorIsRecipient := hbar
	sponsorIsRecipient.Extra = map[string]any{"feePayer": "0.0.789"}
	good := hbar
	good.Extra = map[string]any{"feePayer": "0.0.123"}
	if !bad(x) || !bad(hbar) || !bad(sponsorIsRecipient) || bad(good) {
		t.Fatal("recipient or Hedera sponsor validation is wrong")
	}
}

func TestClosedJournalFailsClosed(t *testing.T) {
	h := newHarness(t)
	s := newSession(t, h.s)
	h.s.ledger.close()
	if w := request(h.s, "/payment", s, "{}", signed(h, "TX1")); w.Code == 200 || eligible(h.s, s) {
		t.Fatalf("closed journal admitted a payment: %d", w.Code)
	}
	if h.settle.Load() != 0 {
		t.Fatal("closed journal still settled a payment")
	}
}
