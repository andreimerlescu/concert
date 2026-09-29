package testnet

import (
	"context"
	"os"
	"testing"

	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
)

// Hedera has no anonymous faucet, so this test needs a funded Testnet account
// of your own from https://portal.hedera.com/:
//
//	CONCERT_TESTNET_HEDERA_ACCOUNT=0.0.N  CONCERT_TESTNET_HEDERA_KEY=<DER private key>
//
// It creates a fresh merchant account from that account, then pays it.
func hederaFlow(t *testing.T) flow {
	t.Helper()
	need(t)
	accountText, keyText := os.Getenv("CONCERT_TESTNET_HEDERA_ACCOUNT"), os.Getenv("CONCERT_TESTNET_HEDERA_KEY")
	if accountText == "" || keyText == "" {
		t.Skip("set CONCERT_TESTNET_HEDERA_ACCOUNT and CONCERT_TESTNET_HEDERA_KEY (a funded Hedera Testnet account from portal.hedera.com)")
	}
	operator, err := hiero.AccountIDFromString(accountText)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hiero.PrivateKeyFromStringDer(keyText)
	if err != nil {
		t.Fatal(err)
	}
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
