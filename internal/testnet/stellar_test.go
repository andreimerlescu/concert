package testnet

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strconv"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/txnbuild"
)

const (
	stellarHorizon   = "https://horizon-testnet.stellar.org"
	stellarFriendbot = "https://friendbot.stellar.org/"
)

// stellarAccount creates a keypair and funds it with Friendbot.
func stellarAccount(ctx context.Context) (*keypair.Full, error) {
	kp, err := keypair.Random()
	if err != nil {
		return nil, err
	}
	if _, err = get(ctx, stellarFriendbot+"?addr="+url.QueryEscape(kp.Address())); err != nil {
		return nil, err
	}
	return kp, nil
}

// decimal7 formats stroops as Stellar's 7-decimal amount string.
func decimal7(stroops string) (string, error) {
	n, ok := new(big.Int).SetString(stroops, 10)
	if !ok {
		return "", errors.New("bad amount")
	}
	s := n.String()
	for len(s) <= 7 {
		s = "0" + s
	}
	return s[:len(s)-7] + "." + s[len(s)-7:], nil
}

func stellarFlow(t *testing.T) flow {
	t.Helper()
	need(t)
	ctx := context.Background()
	payer, err := stellarAccount(ctx)
	if err != nil {
		t.Fatalf("Stellar Friendbot unavailable: %v", err)
	}
	merchant, err := stellarAccount(ctx)
	if err != nil {
		t.Fatalf("Stellar Friendbot unavailable: %v", err)
	}
	return flow{
		network:      "stellar:testnet",
		networksJSON: `{"stellar:testnet":{"horizon":"` + stellarHorizon + `"}}`,
		payTo:        merchant.Address(),
		price:        "10000000", // 1 XLM
		send: func(ctx context.Context, amount string, ref *reference) error {
			dec, err := decimal7(amount)
			if err != nil {
				return err
			}
			b, err := get(ctx, stellarHorizon+"/accounts/"+payer.Address())
			if err != nil {
				return err
			}
			var acct struct {
				Sequence string `json:"sequence"`
			}
			if err = json.Unmarshal(b, &acct); err != nil {
				return err
			}
			seq, err := strconv.ParseInt(acct.Sequence, 10, 64)
			if err != nil {
				return err
			}
			src := txnbuild.NewSimpleAccount(payer.Address(), seq)
			params := txnbuild.TransactionParams{
				SourceAccount:        &src,
				IncrementSequenceNum: true,
				Operations:           []txnbuild.Operation{&txnbuild.Payment{Destination: merchant.Address(), Amount: dec, Asset: txnbuild.NativeAsset{}}},
				BaseFee:              txnbuild.MinBaseFee,
				Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewTimeout(120)},
			}
			if ref != nil {
				params.Memo = txnbuild.MemoText(ref.Memo)
			}
			tx, err := txnbuild.NewTransaction(params)
			if err != nil {
				return err
			}
			if tx, err = tx.Sign(network.TestNetworkPassphrase, payer); err != nil {
				return err
			}
			env, err := tx.Base64()
			if err != nil {
				return err
			}
			_, err = post(ctx, stellarHorizon+"/transactions", "application/x-www-form-urlencoded", "tx="+url.QueryEscape(env))
			return err
		},
	}
}

func TestStellarTestnetDepositByExactAmount(t *testing.T) { stellarFlow(t).run(t, false) }

// The visitor sends the plain price with their memo.
func TestStellarTestnetDepositByMemo(t *testing.T) {
	stellarFlow(t).run(t, true)
}
