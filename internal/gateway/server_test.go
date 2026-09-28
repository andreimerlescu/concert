package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/fastlane"
	"github.com/andreimerlescu/concert/internal/x402"
)

const (
	xrp    = "xrpl:1"
	devnet = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
)

// fake is a payment mechanism whose settlement can be held open.
type fake struct {
	verifies, settles atomic.Int32
	hold              chan struct{}
	started           chan struct{}
	fail              bool
}

func (f *fake) Verify(context.Context, x402.Payload, x402.Requirements) x402.VerifyResponse {
	f.verifies.Add(1)
	return x402.Valid("payer")
}

func (f *fake) Settle(_ context.Context, _ x402.Payload, r x402.Requirements) (x402.SettleResponse, error) {
	f.settles.Add(1)
	if f.started != nil {
		f.started <- struct{}{}
	}
	if f.hold != nil {
		<-f.hold
	}
	if f.fail {
		return x402.SettleResponse{}, context.DeadlineExceeded
	}
	return x402.SettleResponse{Success: true, Transaction: "tx", Network: r.Network, Payer: "payer"}, nil
}

func offer(network, scheme, asset string) fastlane.Offer {
	return fastlane.Offer{Label: network, Requirements: fastlane.Requirements{
		Scheme: scheme, Network: network, Amount: "100", Asset: asset, PayTo: "merchant", MaxTimeoutSeconds: 60,
	}}
}

func config() fastlane.Config {
	return fastlane.Config{
		Enabled: true, Origin: "https://concert.example",
		Offers: []fastlane.Offer{offer(xrp, "exact", "XRP"), offer(devnet, "concert-native-sol", "SOL")},
	}
}

func networks() map[string]Network {
	return map[string]Network{xrp: {RPC: "http://127.0.0.1:1/"}, devnet: {RPC: "http://127.0.0.1:1/"}}
}

type harness struct {
	t     *testing.T
	dir   string
	j     *Journal
	s     *Server
	mechs map[string]*fake
}

func newHarness(t *testing.T, dir string) *harness {
	t.Helper()
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newServer(config(), networks(), j, func(string) string { return "" }, true)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, dir: dir, j: j, s: s, mechs: map[string]*fake{}}
	for n, c := range s.chains {
		f := &fake{}
		c.pay, h.mechs[n] = f, f
	}
	t.Cleanup(j.Close)
	return h
}

// post runs op the way Concert does and reports it HTTP-style: 200 with the
// result, or 400 with verification_failed for an error.
func (h *harness) post(op string, body any) (int, map[string]any) {
	h.t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		h.t.Fatal(err)
	}
	res, err := h.s.Handle(context.Background(), op, b)
	if err != nil {
		return http.StatusBadRequest, map[string]any{"error": "verification_failed"}
	}
	raw, _ := json.Marshal(res)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return http.StatusOK, out
}

func payment(network, blob string) map[string]any {
	var r fastlane.Requirements
	for _, o := range config().Offers {
		if o.Requirements.Network == network {
			r = o.Requirements
		}
	}
	return map[string]any{
		"x402Version":         2,
		"paymentRequirements": r,
		"paymentPayload": map[string]any{
			"x402Version": 2,
			"resource":    map[string]any{"url": "https://concert.example/_concert/payment"},
			"accepted":    r,
			"payload":     map[string]any{"signedTxBlob": blob},
		},
	}
}

func TestOperations(t *testing.T) {
	h := newHarness(t, t.TempDir())
	code, out := h.post("/supported", nil)
	if code != http.StatusOK || len(out["kinds"].([]any)) != 2 {
		t.Fatalf("supported: %d %v", code, out)
	}
	if code, _ := h.post("/unknown", map[string]any{}); code != http.StatusBadRequest {
		t.Fatalf("unknown operation: %d", code)
	}
	if code, _ := h.post("/verify", []int{1}); code != http.StatusBadRequest {
		t.Fatalf("malformed request: %d", code)
	}
}

func TestOnlyConfiguredAcceptedTermsAreVerified(t *testing.T) {
	h := newHarness(t, t.TempDir())
	if code, out := h.post("/verify", payment(xrp, "A")); code != http.StatusOK || out["isValid"] != true {
		t.Fatalf("configured terms: %d %v", code, out)
	}
	mutate := map[string]func(map[string]any){
		"amount changed in both": func(p map[string]any) {
			r := p["paymentRequirements"].(fastlane.Requirements)
			r.Amount = "1"
			p["paymentRequirements"] = r
			p["paymentPayload"].(map[string]any)["accepted"] = r
		},
		"accepted differs": func(p map[string]any) {
			r := p["paymentRequirements"].(fastlane.Requirements)
			r.PayTo = "attacker"
			p["paymentPayload"].(map[string]any)["accepted"] = r
		},
		"resource elsewhere": func(p map[string]any) {
			p["paymentPayload"].(map[string]any)["resource"] = map[string]any{"url": "https://evil.example/_concert/payment"}
		},
		"version 1": func(p map[string]any) { p["x402Version"] = 1 },
		"empty payload": func(p map[string]any) {
			delete(p["paymentPayload"].(map[string]any), "payload")
		},
	}
	for name, m := range mutate {
		p := payment(xrp, "A")
		m(p)
		if code, out := h.post("/verify", p); code != http.StatusBadRequest || out["error"] != "verification_failed" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
}

func TestSettlementIsJournaledAndNeverRepeated(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, dir)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if code, out := h.post("/settle", payment(xrp, "A")); code != http.StatusOK || out["success"] != true {
				t.Errorf("settle: %d %v", code, out)
			}
		}()
	}
	wg.Wait()
	if n := h.mechs[xrp].settles.Load(); n != 1 {
		t.Fatalf("concurrent retries submitted %d times", n)
	}
	// A settled authorization is a replay to /verify, never a new pass.
	if _, out := h.post("/verify", payment(xrp, "A")); out["isValid"] != false || out["invalidReason"] != "payment_already_settled" {
		t.Fatalf("verify after settle: %v", out)
	}
	h.j.Close()

	h2 := newHarness(t, dir)
	if code, out := h2.post("/settle", payment(xrp, "A")); code != http.StatusOK || out["success"] != true || out["transaction"] != "tx" {
		t.Fatalf("settled result after restart: %d %v", code, out)
	}
	if h2.mechs[xrp].settles.Load() != 0 {
		t.Fatal("restart resubmitted a settled authorization")
	}
}

func TestUnknownSettlementRequiresReconciliation(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, dir)
	h.mechs[xrp].fail = true
	if _, out := h.post("/settle", payment(xrp, "B")); out["success"] != false || out["errorReason"] != "settlement_unknown" {
		t.Fatalf("failed settle: %v", out)
	}
	h.j.Close()
	h2 := newHarness(t, dir)
	if _, out := h2.post("/settle", payment(xrp, "B")); out["errorReason"] != "reconciliation_required" {
		t.Fatalf("after restart: %v", out)
	}
	if h2.mechs[xrp].settles.Load() != 0 {
		t.Fatal("unknown settlement was resubmitted")
	}
	// Reordering keys does not make a new authorization.
	raw := `{"x402Version":2,"paymentPayload":{"payload":{"signedTxBlob":"B"},"accepted":` + mustJSON(t, payment(xrp, "B")["paymentRequirements"]) +
		`,"x402Version":2},"paymentRequirements":` + mustJSON(t, payment(xrp, "B")["paymentRequirements"]) + `}`
	if _, out := h2.post("/settle", json.RawMessage(raw)); out["errorReason"] != "reconciliation_required" {
		t.Fatalf("reordered payload: %v", out)
	}
}

func mustJSON(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSettlementQueuesArePerNetwork(t *testing.T) {
	h := newHarness(t, t.TempDir())
	slow := h.mechs[xrp]
	slow.hold, slow.started = make(chan struct{}), make(chan struct{}, 4)
	done := make(chan struct{})
	go func() { h.post("/settle", payment(xrp, "slow")); close(done) }()
	<-slow.started

	fast := make(chan struct{})
	go func() { h.post("/settle", payment(devnet, "fast")); close(fast) }()
	select {
	case <-fast:
	case <-time.After(5 * time.Second):
		t.Fatal("a slow network delayed another network's settlement")
	}
	// A second payload on the slow network waits its turn.
	second := make(chan struct{})
	go func() { h.post("/settle", payment(xrp, "second")); close(second) }()
	select {
	case <-second:
		t.Fatal("same-network settlements were not serialized")
	case <-time.After(100 * time.Millisecond):
	}
	close(slow.hold)
	<-done
	<-second
}

func TestJournalLockPartialLineAndRegression(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(dir); err == nil {
		t.Fatal("a second process opened a locked journal")
	}
	rec := Record{ID: "a", Terms: json.RawMessage(`{}`), Payload: json.RawMessage(`{}`), State: "settled"}
	if err := j.Write(rec); err != nil {
		t.Fatal(err)
	}
	rec.State = "unknown"
	if err := j.Write(rec); err == nil {
		t.Fatal("overwrote a settled record")
	}
	j.Close()

	path := filepath.Join(dir, "settlements.jsonl")
	good, _ := os.ReadFile(path)
	line, _ := json.Marshal(rec)
	if err := os.WriteFile(path, append(append([]byte{}, good...), line...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(dir); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("partial final line: %v", err)
	}
	if err := os.WriteFile(path, append(append(append([]byte{}, good...), line...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(dir); err == nil || !strings.Contains(err.Error(), "regresses") {
		t.Fatalf("regression: %v", err)
	}
	if err := os.WriteFile(path, []byte("{nope}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(dir); err == nil {
		t.Fatal("accepted a corrupt journal")
	}
}

func TestNFTChallengeBinding(t *testing.T) {
	cfg := config()
	cfg.Collections = []fastlane.Collection{{ID: "c", Network: devnet, Collection: "Col1111111111111111111111111111111111111111"}}
	j, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	s, err := newServer(cfg, networks(), j, func(string) string { return "" }, true)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, s: s, j: j}
	addr := "Wal1111111111111111111111111111111111111111"
	msg := func(wallet, collection string) string {
		return "Concert NFT admission v1\nOrigin: https://concert.example\nNetwork: " + devnet + "\nWallet: " + wallet +
			"\nCollection: " + collection + "\nToken: \nNonce: n\n"
	}
	sig := base64.StdEncoding.EncodeToString(make([]byte, 64))
	cases := map[string]map[string]any{
		"unknown collection": {"network": devnet, "address": addr, "collection": "Other", "message": msg(addr, "Other"), "signature": sig},
		"other wallet":       {"network": devnet, "address": addr, "collection": cfg.Collections[0].Collection, "message": msg("Else", cfg.Collections[0].Collection), "signature": sig},
		"bad signature":      {"network": devnet, "address": addr, "collection": cfg.Collections[0].Collection, "message": msg(addr, cfg.Collections[0].Collection), "signature": sig},
	}
	for name, body := range cases {
		if code, out := h.post("/nft/verify", body); code != http.StatusBadRequest || out["error"] != "verification_failed" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
}

func TestConfigurationIsValidated(t *testing.T) {
	get := func(string) string { return "" }
	cases := map[string]func(*fastlane.Config, map[string]Network){
		"plain HTTP endpoint": func(_ *fastlane.Config, n map[string]Network) { n[xrp] = Network{RPC: "http://rpc.example/"} },
		"websocket only":      func(_ *fastlane.Config, n map[string]Network) { n[xrp] = Network{WS: "wss://rpc.example"} },
		"credentials in URL":  func(_ *fastlane.Config, n map[string]Network) { n[xrp] = Network{RPC: "https://u:p@rpc.example/"} },
		"missing network":     func(_ *fastlane.Config, n map[string]Network) { delete(n, devnet) },
		"stellar without sponsor": func(c *fastlane.Config, n map[string]Network) {
			c.Offers = append(c.Offers, offer("stellar:testnet", "exact", "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"))
			n["stellar:testnet"] = Network{RPC: "https://rpc.example/"}
		},
		"stellar non-native asset": func(c *fastlane.Config, n map[string]Network) {
			c.Offers = append(c.Offers, offer("stellar:testnet", "exact", "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
			n["stellar:testnet"] = Network{RPC: "https://rpc.example/"}
		},
		"hedera fee payer mismatch": func(c *fastlane.Config, n map[string]Network) {
			o := offer("hedera:testnet", "exact", "0.0.0")
			o.Requirements.Extra = map[string]any{"feePayer": "0.0.2"}
			c.Offers = append(c.Offers, o)
			n["hedera:testnet"] = Network{Mirror: "https://mirror.example", FeePayer: "0.0.3"}
		},
		"invalid max fee": func(_ *fastlane.Config, n map[string]Network) {
			n[xrp] = Network{RPC: "https://rpc.example/", MaxFee: "-1"}
		},
	}
	for name, mutate := range cases {
		c, n := config(), networks()
		mutate(&c, n)
		if _, err := build(c, n, get, false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := build(config(), map[string]Network{xrp: {RPC: "https://rpc.example/"}, devnet: {RPC: "https://api.devnet.solana.com"}}, get, false); err != nil {
		t.Fatal(err)
	}
	cfg := config()
	cfg.Enabled = false
	if _, err := New(cfg, networks(), nil, get); err == nil {
		t.Error("started with the fast lane disabled")
	}
	path := filepath.Join(t.TempDir(), "networks.json")
	os.WriteFile(path, []byte(`{"xrpl:1":{"rpc":"https://x/","typo":1}}`), 0o600)
	if _, err := LoadNetworks(path); err == nil {
		t.Error("accepted an unknown networks field")
	}
	os.WriteFile(path, []byte(`{"hedera:testnet":{"mirror":"https://m/","max_fee_tinybars":"100000000"}}`), 0o600)
	if n, err := LoadNetworks(path); err != nil || n["hedera:testnet"].MaxFeeHB != "100000000" {
		t.Errorf("quoted max fee: %v %v", n, err)
	}
}

func TestCloseWaitsForSettlementsInFlight(t *testing.T) {
	h := newHarness(t, t.TempDir())
	m := h.mechs[xrp]
	m.hold, m.started = make(chan struct{}), make(chan struct{}, 1)
	go h.post("/settle", payment(xrp, "inflight"))
	<-m.started
	closed := make(chan struct{})
	go func() { h.s.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned while a settlement was in flight")
	case <-time.After(100 * time.Millisecond):
	}
	close(m.hold)
	<-closed
	id, _ := Fingerprint(toX402(config().Offers[0].Requirements), json.RawMessage(`{"signedTxBlob":"inflight"}`))
	if rec, ok := h.j.Get(id); !ok || rec.State != "settled" {
		t.Fatalf("settlement not journaled before close: %+v", rec)
	}
}
