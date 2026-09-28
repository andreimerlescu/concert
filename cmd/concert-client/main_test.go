package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/andreimerlescu/concert/internal/chain/base58"
	"github.com/andreimerlescu/concert/internal/chain/solana"
	"github.com/andreimerlescu/concert/internal/x402"
)

const devnet = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"

func solanaRPC() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var result any
		switch req.Method {
		case "getGenesisHash":
			result = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1WcaWoxPkrZBG"
		case "getLatestBlockhash":
			result = map[string]any{"context": map[string]any{"slot": 1}, "value": map[string]any{"blockhash": base58.Bitcoin.Encode(make([]byte, 32))}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
}

// concert fakes the fast-lane endpoints. It remembers every payment header
// it saw and fails the first settlement when failFirst is set.
type concert struct {
	mu        sync.Mutex
	payTo     string
	amount    string
	session   string
	payments  []string
	failFirst bool
	message   string
	proof     map[string]string
}

func (c *concert) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	reply := func(code int, v any) { w.WriteHeader(code); _ = json.NewEncoder(w).Encode(v) }
	switch r.URL.Path {
	case "/_concert/session":
		reply(200, map[string]any{"session": c.session})
	case "/_concert/payment":
		h := r.Header.Get("PAYMENT-SIGNATURE")
		if h == "" {
			req := x402.Requirements{Scheme: solana.SchemeName, Network: devnet, Amount: c.amount, Asset: "SOL", PayTo: c.payTo, MaxTimeoutSeconds: 60}
			reply(402, map[string]any{"x402Version": 2, "resource": x402.Resource{URL: "http://127.0.0.1/_concert/payment"}, "accepts": []any{req}})
			return
		}
		c.payments = append(c.payments, h)
		if c.failFirst && len(c.payments) == 1 {
			reply(502, map[string]string{"error": "settlement_pending"})
			return
		}
		reply(200, map[string]any{"access": true})
	case "/_concert/nft/challenge":
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		c.message = "Concert NFT admission v1\nWallet: " + in["address"]
		reply(200, map[string]any{"nonce": "n1", "message": c.message})
	case "/_concert/nft/verify":
		_ = json.NewDecoder(r.Body).Decode(&c.proof)
		reply(200, map[string]any{"valid": true})
	}
}

type setup struct {
	env    map[string]string
	c      *concert
	pub    ed25519.PublicKey
	file   string
	origin string
}

func newSetup(t *testing.T) *setup {
	rpc := solanaRPC()
	t.Cleanup(rpc.Close)
	pub, priv, _ := ed25519.GenerateKey(nil)
	to, _, _ := ed25519.GenerateKey(nil)
	var dest solana.PublicKey
	copy(dest[:], to)
	c := &concert{payTo: dest.String(), amount: "5000", session: "abc.1.mac"}
	srv := httptest.NewServer(c)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	nets := filepath.Join(dir, "networks.json")
	os.WriteFile(nets, []byte(`{"`+devnet+`":{"rpc":"`+rpc.URL+`"}}`), 0o600)
	file := filepath.Join(dir, "state", "client.json")
	origin := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	t.Setenv("CONCERT_ORIGIN", origin)
	t.Setenv("CONCERT_NETWORKS_CONFIG", nets)
	t.Setenv("CONCERT_CLIENT_STATE", file)
	return &setup{c: c, pub: pub, file: file, origin: origin, env: map[string]string{
		"CONCERT_CLIENT_NETWORK":    devnet,
		"CONCERT_CLIENT_SOL_KEY":    base64.StdEncoding.EncodeToString(priv),
		"CONCERT_MAX_ATOMIC_AMOUNT": "5000",
		"CONCERT_EXPECT_PAY_TO":     dest.String(),
		"CONCERT_ACCEPT_TERMS":      "yes",
	}}
}

func (s *setup) run(args ...string) error {
	return run(context.Background(), args, func(k string) string { return s.env[k] })
}

func TestPaymentIsSavedBeforeSendingAndNeverReplaced(t *testing.T) {
	s := newSetup(t)
	s.c.failFirst = true
	if err := s.run(); err == nil || !strings.Contains(err.Error(), "retain this state file") {
		t.Fatalf("failed settlement: %v", err)
	}
	st, err := loadState(s.file, s.origin, devnet)
	if err != nil || st.Payment == "" || st.Payment != s.c.payments[0] {
		t.Fatalf("state after failure: %+v %v", st, err)
	}
	// The retry sends the identical authorization, even with terms withdrawn.
	delete(s.env, "CONCERT_ACCEPT_TERMS")
	if err := s.run(); err != nil {
		t.Fatal(err)
	}
	if len(s.c.payments) != 2 || s.c.payments[0] != s.c.payments[1] {
		t.Fatal("retry signed a new authorization")
	}
	raw, _ := base64.StdEncoding.DecodeString(s.c.payments[0])
	var p x402.Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	var body struct{ Transaction string }
	json.Unmarshal(p.Payload, &body)
	tr, err := solana.Inspect(body.Transaction, p.Accepted)
	if err != nil || tr.From.String() != base58.Bitcoin.Encode(s.pub) {
		t.Fatalf("signed transfer: %+v %v", tr, err)
	}
	if _, err := os.Stat(s.file + ".lock"); !os.IsNotExist(err) {
		t.Fatal("lock file left behind")
	}
}

func TestPaymentGuards(t *testing.T) {
	cases := map[string]func(*setup){
		"terms not accepted": func(s *setup) { delete(s.env, "CONCERT_ACCEPT_TERMS") },
		"over budget":        func(s *setup) { s.env["CONCERT_MAX_ATOMIC_AMOUNT"] = "4999" },
		"unexpected payee":   func(s *setup) { s.env["CONCERT_EXPECT_PAY_TO"] = "11111111111111111111111111111111" },
		"no budget":          func(s *setup) { delete(s.env, "CONCERT_MAX_ATOMIC_AMOUNT") },
		"locked": func(s *setup) {
			os.MkdirAll(filepath.Dir(s.file), 0o700)
			os.WriteFile(s.file+".lock", nil, 0o600)
		},
	}
	for name, mutate := range cases {
		s := newSetup(t)
		mutate(s)
		if err := s.run(); err == nil {
			t.Errorf("%s: paid", name)
		}
		if len(s.c.payments) != 0 {
			t.Errorf("%s: sent a payment", name)
		}
	}
}

func TestExpiredSessionWithUnresolvedPaymentStops(t *testing.T) {
	s := newSetup(t)
	s.c.failFirst = true
	_ = s.run()
	s.c.session = "other.2.mac"
	if err := s.run(); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired session: %v", err)
	}
	if len(s.c.payments) != 1 {
		t.Fatal("sent a payment under a new session")
	}
}

func TestNFTProofSignsTheChallenge(t *testing.T) {
	s := newSetup(t)
	if err := s.run("--nft"); err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.StdEncoding.DecodeString(s.c.proof["signature"])
	if s.c.proof["nonce"] != "n1" || !solana.VerifyMessage(base58.Bitcoin.Encode(s.pub), s.c.message, sig) {
		t.Fatalf("proof: %v", s.c.proof)
	}
}
