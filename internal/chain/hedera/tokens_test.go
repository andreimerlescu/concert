package hedera

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/x402"
	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
)

func TestHedera_TLSNodesPreferredOverPlaintext(t *testing.T) {
	m := mirror(t, nil, map[string]any{"/api/v1/network/nodes?limit=25": nodeList})
	nodes, useTLS, err := Mirror{URL: m.URL}.TLSNodes(context.Background())
	if err != nil || !useTLS {
		t.Fatalf("expected TLS nodes, useTLS=%v err=%v", useTLS, err)
	}
	if nodes["0.0.3"] != "10.0.0.3:50212" {
		t.Fatalf("expected TLS port 50212 for 0.0.3, got %q", nodes["0.0.3"])
	}
}

func TestHedera_PayerPaidHTSAndDirectPayment(t *testing.T) {
	key, _ := hiero.PrivateKeyGenerateEd25519()
	payer := "0.0.456"
	merchant := "0.0.789"
	usdc := "0.0.456858"
	memo := "concert:hbar1"
	now := time.Now().UTC()

	accounts := map[string]json.RawMessage{
		payer: json.RawMessage(`{"key":{"_type":"ED25519","key":"` + key.PublicKey().StringRaw() + `"},"balance":{"balance":500000000}}`),
	}
	routes := map[string]any{
		"/api/v1/network/nodes?limit=25": nodeList,
		"/api/v1/accounts/" + payer + "/tokens?token.id=" + usdc + "&limit=1": map[string]any{
			"tokens": []map[string]any{{"token_id": usdc, "balance": 2500000, "freeze_status": "UNFROZEN"}},
		},
		"/api/v1/transactions?account.id=" + merchant + "&transactiontype=CRYPTOTRANSFER&result=success&order=desc&limit=50": map[string]any{
			"transactions": []map[string]any{
				{
					"transaction_id": "0.0.456-1700000000-000000001",
					"result":         "SUCCESS",
					"nonce":          0,
					"scheduled":      false,
					"memo_base64":    base64.StdEncoding.EncodeToString([]byte(memo)),
					"token_transfers": []map[string]any{
						{"token_id": usdc, "account": payer, "amount": -990000},
						{"token_id": usdc, "account": merchant, "amount": 990000},
					},
				},
			},
		},
	}
	m := mirror(t, accounts, routes)
	s, err := NewUnsponsored(Testnet, m.URL, 0)
	if err != nil {
		t.Fatalf("NewUnsponsored: %v", err)
	}
	// Token balance check
	ok, bal, err := s.MeetsMinBalance(context.Background(), payer, usdc, "1000000")
	if err != nil || !ok || bal != "2500000" {
		t.Fatalf("MeetsMinBalance HTS: ok=%v bal=%q err=%v", ok, bal, err)
	}
	// Payer-paid HTS transfer (zero sponsor key!)
	r := x402.Requirements{
		Scheme:            "exact",
		Network:           Testnet,
		Asset:             usdc,
		Amount:            "990000",
		PayTo:             merchant,
		MaxTimeoutSeconds: 60,
		Extra:             map[string]any{"areFeesSponsored": false, "memo": memo},
	}
	enc, err := NewPayment(context.Background(), Mirror{URL: m.URL}, payer, key, r)
	if err != nil {
		t.Fatalf("NewPayment HTS payer-paid: %v", err)
	}
	v := s.Verify(context.Background(), payload(enc, r), r)
	if !v.Valid || v.Payer != payer {
		t.Fatalf("Verify HTS payer-paid failed: %+v", v)
	}
	// Direct memo payment watcher
	txID, from, err := s.FindDirectPayment(context.Background(), payer, merchant, usdc, "990000", memo, time.Time{})
	if err != nil || txID != "0.0.456-1700000000-000000001" || from != payer {
		t.Fatalf("FindDirectPayment HTS: txID=%q from=%q err=%v (now=%v)", txID, from, err, now)
	}
}
