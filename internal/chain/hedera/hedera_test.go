package hedera

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/andreimerlescu/concert/internal/x402"
	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
)

// testdata/vectors.json: payloads built by @x402/hedera 2.27.0's client
// signer and @hiero-ledger/sdk 2.85.0, each judged by @x402/hedera's
// facilitator against a local mirror serving the recorded accounts.
// "concert" differs from "reference" only where Concert is deliberately
// stricter (one screened payer, capped sponsor fee).
type vectors struct {
	FeePayer string                     `json:"feePayer"`
	Accounts map[string]json.RawMessage `json:"accounts"`
	Cases    []struct {
		Name         string            `json:"name"`
		Transaction  string            `json:"transaction"`
		Requirements x402.Requirements `json:"requirements"`
		Reference    struct {
			Valid  bool   `json:"valid"`
			Reason string `json:"reason"`
			Payer  string `json:"payer"`
		} `json:"reference"`
		Concert struct {
			Valid  bool   `json:"valid"`
			Reason string `json:"reason"`
		} `json:"concert"`
		TransactionID string `json:"transactionId"`
	} `json:"cases"`
	Messages []struct {
		Account   string    `json:"account"`
		Key       MirrorKey `json:"key"`
		Message   string    `json:"message"`
		Signature string    `json:"signature"`
	} `json:"messages"`
	SponsorKey string `json:"sponsorKey"`
}

func load(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mirror(t *testing.T, accounts map[string]json.RawMessage, extra map[string]any) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a, ok := accounts[strings.TrimPrefix(r.URL.Path, "/api/v1/accounts/")]; ok && strings.HasPrefix(r.URL.Path, "/api/v1/accounts/") && !strings.Contains(strings.TrimPrefix(r.URL.Path, "/api/v1/accounts/"), "/") {
			_, _ = w.Write(a)
			return
		}
		if v, ok := extra[r.URL.RequestURI()]; ok {
			_ = json.NewEncoder(w).Encode(v)
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func scheme(t *testing.T, v vectors, m *httptest.Server) *Scheme {
	s, err := New(Testnet, m.URL, v.FeePayer, v.SponsorKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func payload(c string, r x402.Requirements) x402.Payload {
	return x402.Payload{Version: 2, Accepted: r, Payload: json.RawMessage(`{"transaction":"` + c + `"}`)}
}

func TestVerifyMatchesReferenceFacilitator(t *testing.T) {
	v := load(t)
	s := scheme(t, v, mirror(t, v.Accounts, nil))
	for _, c := range v.Cases {
		got := s.Verify(context.Background(), payload(c.Transaction, c.Requirements), c.Requirements)
		if got.Valid != c.Concert.Valid || got.Reason != c.Concert.Reason {
			t.Errorf("%s: got valid=%v %q, want valid=%v %q (reference %v %q)", c.Name, got.Valid, got.Reason, c.Concert.Valid, c.Concert.Reason, c.Reference.Valid, c.Reference.Reason)
		}
		if got.Valid && got.Payer != c.Reference.Payer {
			t.Errorf("%s: payer %s, reference %s", c.Name, got.Payer, c.Reference.Payer)
		}
	}
}

func TestTransactionIDsMatchReference(t *testing.T) {
	for _, c := range load(t).Cases {
		p, err := Parse(c.Transaction)
		if err != nil {
			continue
		}
		at, ts, _ := strings.Cut(c.TransactionID, "@")
		secs, nanos, _ := strings.Cut(ts, ".")
		want := at + "@" + secs + "." + strings.Repeat("0", 9-len(nanos)) + nanos
		if p.TransactionID != want {
			t.Errorf("%s: %s, reference %s", c.Name, p.TransactionID, c.TransactionID)
		}
	}
}

func TestSettleSubmitsOnlyVerifiedPayments(t *testing.T) {
	v := load(t)
	s := scheme(t, v, mirror(t, v.Accounts, nil))
	var submitted []string
	s.Submit = func(_ context.Context, p *Parsed, _ string) (string, error) {
		submitted = append(submitted, p.TransactionID)
		return p.TransactionID, nil
	}
	valid, bad := v.Cases[0], v.Cases[3]
	r, err := s.Settle(context.Background(), payload(valid.Transaction, valid.Requirements), valid.Requirements)
	if err != nil || !r.Success || r.Payer != valid.Reference.Payer || len(submitted) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	r, _ = s.Settle(context.Background(), payload(bad.Transaction, bad.Requirements), bad.Requirements)
	if r.Success || len(submitted) != 1 {
		t.Fatalf("invalid payment submitted: %+v", r)
	}
}

func TestParseRefusesAliasesApprovalsAndOtherTransactions(t *testing.T) {
	v := load(t)
	raw, _ := base64.StdEncoding.DecodeString(v.Cases[0].Transaction)
	if _, err := Parse(base64.StdEncoding.EncodeToString(append(raw, 0x08, 0x01))); err == nil {
		t.Error("unknown trailing field accepted")
	}
	if _, err := Parse("AAAA"); err == nil {
		t.Error("garbage accepted")
	}
}

func TestNewPaymentProducesAVerifiablePayerSignature(t *testing.T) {
	key, _ := hiero.PrivateKeyGenerateEd25519()
	r := x402.Requirements{Scheme: "exact", Network: Testnet, Asset: "0.0.0", Amount: "10000000", PayTo: "0.0.789", MaxTimeoutSeconds: 60, Extra: map[string]any{"feePayer": "0.0.123"}}
	accounts := map[string]json.RawMessage{"0.0.456": json.RawMessage(`{"key":{"_type":"ED25519","key":"` + key.PublicKey().StringRaw() + `"},"balance":{"balance":20000000}}`)}
	m := mirror(t, accounts, map[string]any{"/api/v1/network/nodes?limit=25": nodeList})
	enc, err := NewPayment(context.Background(), Mirror{URL: m.URL}, "0.0.456", key, r)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(enc)
	if err != nil || len(p.Nodes) != 3 {
		t.Fatalf("%v %v", p, err)
	}
	v := load(t)
	s := scheme(t, v, m)
	if got := s.Verify(context.Background(), payload(enc, r), r); !got.Valid || got.Payer != "0.0.456" {
		t.Fatalf("%+v", got)
	}
}

var nodeList = map[string]any{"nodes": []any{
	map[string]any{"node_account_id": "0.0.3", "service_endpoints": []any{map[string]any{"ip_address_v4": "10.0.0.3", "port": 50212}, map[string]any{"ip_address_v4": "10.0.0.3", "port": 50211}}},
	map[string]any{"node_account_id": "0.0.4", "service_endpoints": []any{map[string]any{"domain_name": "node4.example", "port": 50211}}},
	map[string]any{"node_account_id": "0.0.5", "service_endpoints": []any{map[string]any{"ip_address_v4": "10.0.0.5", "port": 50211}}},
	map[string]any{"node_account_id": "0.0.6", "service_endpoints": []any{map[string]any{"ip_address_v4": "10.0.0.6", "port": 443}}},
}, "links": map[string]any{"next": nil}}

func TestMirrorNodesUsePlaintextGRPCEndpoints(t *testing.T) {
	m := mirror(t, nil, map[string]any{"/api/v1/network/nodes?limit=25": nodeList})
	got, err := Mirror{URL: m.URL}.Nodes(context.Background())
	want := map[string]string{"0.0.3": "10.0.0.3:50211", "0.0.4": "node4.example:50211", "0.0.5": "10.0.0.5:50211"}
	if err != nil || len(got) != len(want) {
		t.Fatalf("%v %v", got, err)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s", k, got[k])
		}
	}
}

func TestMessageSignaturesMatchHieroSDK(t *testing.T) {
	for _, m := range load(t).Messages {
		sig, _ := base64.StdEncoding.DecodeString(m.Signature)
		k := m.Key
		if !VerifyMessage(&k, m.Message, sig) || VerifyMessage(&k, m.Message+"x", sig) {
			t.Errorf("%s (%s) message signature", m.Account, m.Key.Type)
		}
	}
}

func TestNFTOwnership(t *testing.T) {
	v := load(t)
	msg := v.Messages[0]
	sig, _ := base64.StdEncoding.DecodeString(msg.Signature)
	m := mirror(t, v.Accounts, map[string]any{
		"/api/v1/tokens/0.0.9000":                                             map[string]any{"type": "NON_FUNGIBLE_UNIQUE"},
		"/api/v1/tokens/0.0.9001":                                             map[string]any{"type": "FUNGIBLE_COMMON"},
		"/api/v1/tokens/0.0.9000/nfts/4":                                      map[string]any{"account_id": msg.Account},
		"/api/v1/tokens/0.0.9000/nfts/5":                                      map[string]any{"account_id": "0.0.999"},
		"/api/v1/accounts/" + msg.Account + "/nfts?token.id=0.0.9000&limit=1": map[string]any{"nfts": []any{map[string]any{"token_id": "0.0.9000", "account_id": msg.Account, "serial_number": 4}}},
	})
	s := scheme(t, v, m)
	ctx := context.Background()
	if got, err := s.OwnsNFT(ctx, msg.Account, "0.0.9000", "", msg.Message, sig); err != nil || got != "4" {
		t.Fatalf("%s %v", got, err)
	}
	if got, err := s.OwnsNFT(ctx, msg.Account, "0.0.9000", "4", msg.Message, sig); err != nil || got != "4" {
		t.Fatalf("serial: %s %v", got, err)
	}
	for _, c := range []struct{ coll, token, message string }{{"0.0.9000", "5", msg.Message}, {"0.0.9001", "", msg.Message}, {"0.0.9000", "", msg.Message + "x"}} {
		if _, err := s.OwnsNFT(ctx, msg.Account, c.coll, c.token, c.message, sig); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	if _, err := s.OwnsNFT(ctx, "0.0.458", "0.0.9000", "", msg.Message, sig); err == nil {
		t.Error("threshold-key account accepted a single signature")
	}
}
