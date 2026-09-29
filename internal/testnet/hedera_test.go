package testnet

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
)

// hederaOperator returns a funded Hedera Testnet account and its key.
//
// With CONCERT_TESTNET_HEDERA_PAT (a free Personal Access Token from
// https://portal.hedera.com/) it makes a new ECDSA key and asks the Hedera
// faucet API to fund that key's EVM address, which creates the account
// (auto account creation), then reads the account ID from the mirror node.
// The API allows 100 HBAR per rolling 24 hours per portal account, so this asks
// for 20. Alternatively, CONCERT_TESTNET_HEDERA_ACCOUNT (0.0.N) and
// CONCERT_TESTNET_HEDERA_KEY (DER private key) name an account you already have.
func hederaOperator(t *testing.T) (hiero.AccountID, hiero.PrivateKey) {
	t.Helper()
	if account, keyText := os.Getenv("CONCERT_TESTNET_HEDERA_ACCOUNT"), os.Getenv("CONCERT_TESTNET_HEDERA_KEY"); account != "" && keyText != "" {
		id, err := hiero.AccountIDFromString(account)
		if err != nil {
			t.Fatal(err)
		}
		key, err := hiero.PrivateKeyFromStringDer(keyText)
		if err != nil {
			t.Fatal(err)
		}
		return id, key
	}
	pat := os.Getenv("CONCERT_TESTNET_HEDERA_PAT")
	if pat == "" {
		t.Skip("set CONCERT_TESTNET_HEDERA_PAT (a free Personal Access Token from portal.hedera.com, used to call the Hedera faucet API), or CONCERT_TESTNET_HEDERA_ACCOUNT and CONCERT_TESTNET_HEDERA_KEY for an account you already have")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	key, err := hiero.PrivateKeyGenerateEcdsa()
	if err != nil {
		t.Fatal(err)
	}
	evm := "0x" + key.PublicKey().ToEvmAddress()
	reqBody, _ := json.Marshal(map[string]any{"address": evm, "amount": 20, "network": "testnet"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://portal.hedera.com/api/disbursement/cli", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+pat)
	req.Header.Set("Content-Type", "application/json")
	if b, err := roundTrip(req); err != nil {
		t.Fatalf("Hedera faucet API refused the request (%s): %v", string(b), err)
	}
	// The faucet transfer creates the account for the EVM address; the mirror
	// node learns its ID a few seconds later.
	for ctx.Err() == nil {
		b, err := get(ctx, "https://testnet.mirrornode.hedera.com/api/v1/accounts/"+evm)
		if err == nil {
			var acct struct {
				Account string `json:"account"`
			}
			if json.Unmarshal(b, &acct) == nil && acct.Account != "" {
				id, err := hiero.AccountIDFromString(acct.Account)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("faucet funded %s as account %s", evm, id)
				return id, key
			}
		}
		time.Sleep(4 * time.Second)
	}
	t.Fatalf("the faucet-funded account for %s never appeared on the mirror node", evm)
	return hiero.AccountID{}, hiero.PrivateKey{}
}

func hederaFlow(t *testing.T) flow {
	t.Helper()
	need(t)
	operator, key := hederaOperator(t)
	client := hiero.ClientForTestnet()
	client.SetOperator(operator, key)
	t.Cleanup(func() { _ = client.Close() })

	merchantKey, err := hiero.PrivateKeyGenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	created, err := hiero.NewAccountCreateTransaction().SetKeyWithoutAlias(merchantKey.PublicKey()).SetInitialBalance(hiero.HbarFromTinybar(100_000_000)).Execute(client)
	if err != nil {
		t.Fatalf("creating the merchant account: %v", err)
	}
	receipt, err := created.GetReceipt(client)
	if err != nil || receipt.AccountID == nil {
		t.Fatalf("merchant account receipt: %v", err)
	}
	merchant := *receipt.AccountID
	return flow{
		network:      "hedera:testnet",
		networksJSON: `{"hedera:testnet":{"mirror":"https://testnet.mirrornode.hedera.com"}}`,
		payTo:        merchant.String(),
		price:        "10000000", // 0.1 HBAR
		send: func(_ context.Context, amount string, ref *reference) error {
			tinybars, err := parseInt(amount)
			if err != nil {
				return err
			}
			tx := hiero.NewTransferTransaction().
				AddHbarTransfer(operator, hiero.HbarFromTinybar(-tinybars)).
				AddHbarTransfer(merchant, hiero.HbarFromTinybar(tinybars))
			if ref != nil {
				tx.SetTransactionMemo(ref.Memo)
			}
			resp, err := tx.Execute(client)
			if err != nil {
				return err
			}
			_, err = resp.GetReceipt(client)
			return err
		},
	}
}

func TestHederaTestnetDepositByExactAmount(t *testing.T) { hederaFlow(t).run(t, false) }

// The visitor sends the plain price with their memo.
func TestHederaTestnetDepositByMemo(t *testing.T) { hederaFlow(t).run(t, true) }
