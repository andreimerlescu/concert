package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/base58"
	"github.com/andreimerlescu/concert/internal/chain/solana"
	"github.com/andreimerlescu/concert/internal/fastlane"
)

// solanaRPC is a devnet stand-in: a transfer is unknown until sent, then
// finalized once final is set.
type solanaRPC struct {
	mu    sync.Mutex
	sent  int
	final bool
}

func (f *solanaRPC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     any    `json:"id"`
		Method string `json:"method"`
		Params []json.RawMessage
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	defer f.mu.Unlock()
	ctx := map[string]any{"slot": 1}
	var result any
	switch req.Method {
	case "getGenesisHash":
		result = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1WcaWoxPkrZBG"
	case "getSignatureStatuses":
		var st any
		if f.sent > 0 {
			st = map[string]any{"confirmationStatus": "confirmed", "err": nil}
			if f.final {
				st = map[string]any{"confirmationStatus": "finalized", "err": nil}
			}
		}
		result = map[string]any{"context": ctx, "value": []any{st}}
	case "getLatestBlockhash":
		result = map[string]any{"context": ctx, "value": map[string]any{"blockhash": base58.Bitcoin.Encode(make([]byte, 32)), "lastValidBlockHeight": 9}}
	case "isBlockhashValid":
		result = map[string]any{"context": ctx, "value": true}
	case "simulateTransaction":
		result = map[string]any{"context": ctx, "value": map[string]any{"err": nil}}
	case "sendTransaction":
		f.sent++
		var enc string
		_ = json.Unmarshal(req.Params[0], &enc)
		raw, _ := base64.StdEncoding.DecodeString(enc)
		result = base58.Bitcoin.Encode(raw[1:65])
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
}

// TestNativeSOLThroughGateway drives the real Solana scheme through the HTTP
// API: verify, a settlement whose finality is not observed (unknown), then
// operator reconciliation once the ledger shows it finalized.
func TestNativeSOLThroughGateway(t *testing.T) {
	rpc := &solanaRPC{}
	srv := httptest.NewServer(rpc)
	defer srv.Close()

	pub, priv, _ := ed25519.GenerateKey(nil)
	to, _, _ := ed25519.GenerateKey(nil)
	var from, dest solana.PublicKey
	copy(from[:], pub)
	copy(dest[:], to)
	cfg := config()
	cfg.Offers = []fastlane.Offer{offer(devnet, solana.SchemeName, "SOL")}
	cfg.Offers[0].Requirements.PayTo = dest.String()
	nets := map[string]Network{devnet: {RPC: srv.URL}}

	dir := t.TempDir()
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newServer(cfg, nets, j, token, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	sol := s.chains[devnet].sol
	sol.PollInterval, sol.ConfirmWithin = time.Millisecond, 50*time.Millisecond
	h := &harness{t: t, s: s, j: j}

	code, out := h.post("/solana/prepare", map[string]string{"network": devnet, "address": from.String()})
	if code != http.StatusOK {
		t.Fatalf("prepare: %d %v", code, out)
	}
	unsigned, _ := base64.StdEncoding.DecodeString(out["transaction"].(string))
	tx := base64.StdEncoding.EncodeToString(solana.Sign(unsigned, priv))
	r := cfg.Offers[0].Requirements
	body := map[string]any{"x402Version": 2, "paymentRequirements": r, "paymentPayload": map[string]any{
		"x402Version": 2, "accepted": r, "payload": map[string]any{"transaction": tx},
	}}

	if _, out := h.post("/verify", body); out["isValid"] != true || out["payer"] != from.String() {
		t.Fatalf("verify: %v", out)
	}
	if _, out := h.post("/settle", body); out["success"] != false || out["errorReason"] != "settlement_unknown" {
		t.Fatalf("unobserved finality must be unknown: %v", out)
	}
	if _, out := h.post("/settle", body); out["errorReason"] != "reconciliation_required" || rpc.sent != 1 {
		t.Fatalf("retry: %v, sent %d", out, rpc.sent)
	}
	j.Close()

	j2, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j2.Close()
	var id string
	for k := range j2.records {
		id = k
	}
	if _, err := reconcile(context.Background(), j2, nets, id, "", true); err == nil {
		t.Fatal("reconciled a payment that is not finalized")
	}
	rpc.final = true
	if _, err := Reconcile(context.Background(), j2, nets, id, ""); err == nil {
		t.Fatal("reconcile accepted a plain HTTP endpoint")
	}
	res, err := reconcile(context.Background(), j2, nets, id, "", true)
	if err != nil || !res.Success || res.Payer != from.String() {
		t.Fatalf("reconcile: %v %v", res, err)
	}
	if rec, _ := j2.Get(id); rec.State != "settled" || rpc.sent != 1 {
		t.Fatalf("journal %v, sent %d", rec.State, rpc.sent)
	}
}
