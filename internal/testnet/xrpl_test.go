package testnet

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/andreimerlescu/concert/internal/chain/xrpl"
	"github.com/andreimerlescu/concert/internal/x402"
)

const (
	xrplRPC    = "https://s.altnet.rippletest.net:51234/"
	xrplFaucet = "https://faucet.altnet.rippletest.net/accounts"
)

// xrplAccount asks the XRPL Testnet faucet for a new funded account.
func xrplAccount(ctx context.Context) (address, seed string, err error) {
	b, err := post(ctx, xrplFaucet, "application/json", "{}")
	if err != nil {
		return "", "", err
	}
	var out struct {
		Account struct {
			Classic string `json:"classicAddress"`
			Address string `json:"address"`
			Secret  string `json:"secret"`
		} `json:"account"`
	}
	if err = json.Unmarshal(b, &out); err != nil {
		return "", "", err
	}
	address = out.Account.Classic
	if address == "" {
		address = out.Account.Address
	}
	if address == "" || out.Account.Secret == "" {
		return "", "", errors.New("faucet returned no account: " + string(b))
	}
	return address, out.Account.Secret, nil
}

func xrplFlow(t *testing.T) flow {
	t.Helper()
	need(t)
	ctx := context.Background()
	payer, seed, err := xrplAccount(ctx)
	if err != nil {
		t.Fatalf("XRPL Testnet faucet unavailable: %v", err)
	}
	merchant, _, err := xrplAccount(ctx)
	if err != nil {
		t.Fatalf("XRPL Testnet faucet unavailable: %v", err)
	}
	key, err := xrpl.KeyFromSeed(seed)
	if err != nil || key.Address != payer {
		t.Fatalf("faucet seed does not match its address: %v", err)
	}
	ledger := xrpl.RPC{URL: xrplRPC}
	return flow{
		network:      "xrpl:1",
		networksJSON: `{"xrpl:1":{"rpc":"` + xrplRPC + `"}}`,
		payTo:        merchant,
		price:        "1000000", // 1 XRP
		send: func(ctx context.Context, amount string, ref *reference) error {
			extra := map[string]any{"areFeesSponsored": false}
			if ref != nil {
				extra["destinationTag"] = float64(ref.Tag)
			}
			blob, err := xrpl.NewPaymentBlob(ctx, ledger, key, x402.Requirements{Scheme: "exact", Network: "xrpl:1", Amount: amount, Asset: "XRP", PayTo: merchant, MaxTimeoutSeconds: 120, Extra: extra})
			if err != nil {
				return err
			}
			result, err := ledger.Submit(ctx, blob)
			if err != nil {
				return err
			}
			if result != "tesSUCCESS" && result != "terQUEUED" {
				return errors.New("rippled refused the payment: " + result)
			}
			return nil
		},
	}
}

// The visitor sends their exact amount and nothing else.
func TestXRPLTestnetDepositByExactAmount(t *testing.T) { xrplFlow(t).run(t, false) }

// The visitor sends the plain price with their destination tag.
func TestXRPLTestnetDepositByDestinationTag(t *testing.T) { xrplFlow(t).run(t, true) }
