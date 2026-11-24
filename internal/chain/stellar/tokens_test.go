package stellar

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/x402"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
)

func TestStellar_PayerPaidClassicAndTrustline(t *testing.T) {
	payer, _ := keypair.Random()
	merchant, _ := keypair.Random()
	issuer, _ := keypair.Random()
	asset := "USDC:" + issuer.Address()
	now := time.Now().UTC()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			_ = json.NewEncoder(w).Encode(map[string]any{"network_passphrase": network.TestNetworkPassphrase})
		case r.URL.Path == "/accounts/"+payer.Address():
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sequence": "100",
				"balances": []map[string]any{
					{"asset_type": "native", "balance": "50.0000000"},
					{"asset_type": "credit_alphanum4", "asset_code": "USDC", "asset_issuer": issuer.Address(), "balance": "25.0000000", "is_authorized": true},
				},
			})
		case r.URL.Path == "/transactions" && r.Method == http.MethodPost:
			_ = json.NewEncoder(w).Encode(map[string]any{"hash": "abc123stellar", "successful": true})
		case r.URL.Path == "/accounts/"+merchant.Address()+"/payments":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"_embedded": map[string]any{
					"records": []map[string]any{
						{
							"id":                     "1",
							"type":                   "payment",
							"transaction_hash":       "txdirect99",
							"transaction_successful": true,
							"created_at":             now.Format(time.RFC3339),
							"from":                   payer.Address(),
							"to":                     merchant.Address(),
							"amount":                 "0.9900000",
							"asset_type":             "credit_alphanum4",
							"asset_code":             "USDC",
							"asset_issuer":           issuer.Address(),
						},
					},
				},
			})
		case r.URL.Path == "/transactions/txdirect99":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"hash":       "txdirect99",
				"successful": true,
				"memo_type":  "text",
				"memo":       "concert:xlm1",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s, err := NewUnsponsored(Testnet, "", srv.URL, 0)
	if err != nil {
		t.Fatalf("NewUnsponsored: %v", err)
	}
	// Trustline balance check
	ok, bal, err := s.MeetsMinBalance(context.Background(), payer.Address(), asset, "100000000")
	if err != nil || !ok || bal != "250000000" {
		t.Fatalf("MeetsMinBalance(10 USDC): ok=%v bal=%q err=%v", ok, bal, err)
	}
	// Classic NFT check (balance > 0)
	nftID, err := s.CheckNFTOwnership(context.Background(), payer.Address(), asset)
	if err != nil || nftID != asset {
		t.Fatalf("CheckNFTOwnership classic: id=%q err=%v", nftID, err)
	}
	// Payer-paid classic USDC x402 payment (zero sponsor key!)
	req := x402.Requirements{
		Scheme:            "exact",
		Network:           Testnet,
		Amount:            "9900000",
		Asset:             asset,
		PayTo:             merchant.Address(),
		MaxTimeoutSeconds: 60,
		Extra:             map[string]any{"areFeesSponsored": false, "memo": "concert:xlm1"},
	}
	envXDR, err := NewClassicPayment(context.Background(), s.Horizon, Testnet, payer, req)
	if err != nil {
		t.Fatalf("NewClassicPayment: %v", err)
	}
	p := x402.Payload{Version: 2, Accepted: req, Payload: json.RawMessage(`{"transaction":"` + envXDR + `"}`)}
	v := s.Verify(context.Background(), p, req)
	if !v.Valid || v.Payer != payer.Address() {
		t.Fatalf("Verify classic payer-paid failed: %+v", v)
	}
	res, err := s.Settle(context.Background(), p, req)
	if err != nil || !res.Success || res.Transaction != "abc123stellar" {
		t.Fatalf("Settle classic payer-paid failed: res=%+v err=%v", res, err)
	}
	// Direct payment watcher with memo
	hash, from, err := s.FindDirectPayment(context.Background(), payer.Address(), merchant.Address(), asset, "9900000", "concert:xlm1", now.Add(-time.Minute))
	if err != nil || hash != "txdirect99" || from != payer.Address() {
		t.Fatalf("FindDirectPayment: hash=%q from=%q err=%v", hash, from, err)
	}
}
