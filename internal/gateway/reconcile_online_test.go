package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/solana"
	"github.com/andreimerlescu/concert/internal/fastlane"
)

func TestOnlineReconcile_SolanaWithoutStoppingGateway(t *testing.T) {
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

	j, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := newServer(cfg, nets, j, nil, true)
	if err != nil {
		j.Close()
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

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
	payload := json.RawMessage(`{"transaction":"` + tx + `"}`)
	body := map[string]any{"x402Version": 2, "paymentRequirements": r, "paymentPayload": map[string]any{
		"x402Version": 2, "accepted": r, "payload": payload,
	}}

	if _, out := h.post("/settle", body); out["success"] != false || out["errorReason"] != "settlement_unknown" {
		t.Fatalf("expected settlement_unknown: %v", out)
	}
	id, err := Fingerprint(toX402(r), payload)
	if err != nil {
		t.Fatal(err)
	}

	// Before finality, online reconcile must fail without modifying state or re-sending.
	reqBody, _ := json.Marshal(map[string]string{"id": id})
	if _, err := s.Handle(context.Background(), "/reconcile", reqBody); err == nil {
		t.Fatal("expected online reconcile to fail while transaction is not finalized")
	}

	// Once finalized on-chain, online reconcile succeeds on the live Server without stopping or re-broadcasting.
	rpc.mu.Lock()
	rpc.final = true
	rpc.mu.Unlock()

	res, err := s.Handle(context.Background(), "/reconcile", reqBody)
	if err != nil {
		t.Fatalf("online reconcile failed after finality: %v", err)
	}
	raw, _ := json.Marshal(res)
	var settled map[string]any
	_ = json.Unmarshal(raw, &settled)
	if settled["success"] != true || settled["payer"] != from.String() || settled["network"] != devnet {
		t.Fatalf("unexpected online reconcile result: %v", settled)
	}
	if rpc.sent != 1 {
		t.Fatalf("reconcile re-broadcast transaction: sent=%d, want 1", rpc.sent)
	}
	rec, ok := j.Get(id)
	if !ok || rec.State != "settled" {
		t.Fatalf("journal not marked settled after online reconcile: %+v", rec)
	}
}
