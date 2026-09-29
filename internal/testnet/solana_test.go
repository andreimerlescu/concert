package testnet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/httpx"
	"github.com/andreimerlescu/concert/internal/chain/solana"
)

const solanaRPC = "https://api.devnet.solana.com"

func solanaPub(k ed25519.PrivateKey) solana.PublicKey {
	var p solana.PublicKey
	copy(p[:], k.Public().(ed25519.PublicKey))
	return p
}

// waitFinalized polls until signature finalizes or fails.
func waitFinalized(ctx context.Context, rpc solana.RPC, sig string) error {
	for ctx.Err() == nil {
		st, err := rpc.Status(ctx, sig)
		if err == nil && st != nil {
			if st.Err != nil {
				return errors.New("transaction failed on chain")
			}
			if st.ConfirmationStatus == "finalized" {
				return nil
			}
		}
		time.Sleep(3 * time.Second)
	}
	return ctx.Err()
}

// solanaPayer returns a funded Devnet key: CONCERT_TESTNET_SOLANA_KEY (base64
// of a 64-byte keypair) when set, otherwise a new key funded by an airdrop. The
// public airdrop faucet is rate limited, so a supplied key is more reliable.
func solanaPayer(ctx context.Context, rpc solana.RPC) (ed25519.PrivateKey, error) {
	if raw := os.Getenv("CONCERT_TESTNET_SOLANA_KEY"); raw != "" {
		b, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(b) != ed25519.PrivateKeySize {
			return nil, errors.New("CONCERT_TESTNET_SOLANA_KEY must be the base64 of a 64-byte keypair")
		}
		return ed25519.PrivateKey(b), nil
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var sig string
	if err = httpx.Call(ctx, solanaRPC, "requestAirdrop", []any{solanaPub(key).String(), 200_000_000}, &sig); err != nil {
		return nil, err
	}
	return key, waitFinalized(ctx, rpc, sig)
}

// The visitor sends their exact amount. Concert's Solana transfers carry no
// memo, so there is no reference-only variant.
func TestSolanaDevnetDepositByExactAmount(t *testing.T) {
	need(t)
	ctx := context.Background()
	rpc := solana.RPC{URL: solanaRPC}
	payer, err := solanaPayer(ctx, rpc)
	if err != nil {
		t.Fatalf("Solana Devnet funding failed (the public airdrop is rate limited; set CONCERT_TESTNET_SOLANA_KEY to a funded key): %v", err)
	}
	_, merchantKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	merchant := solanaPub(merchantKey)
	f := flow{
		network:      "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		networksJSON: `{"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1":{"rpc":"` + solanaRPC + `"}}`,
		payTo:        merchant.String(),
		price:        "2000000", // 0.002 SOL, above the rent-exempt minimum a new account needs
		send: func(ctx context.Context, amount string, _ *reference) error {
			lamports, err := parseUint(amount)
			if err != nil {
				return err
			}
			bh, err := rpc.LatestBlockhash(ctx)
			if err != nil {
				return err
			}
			signed := solana.Sign(solana.NewTransfer(solanaPub(payer), merchant, lamports, bh), payer)
			sig, err := rpc.Send(ctx, signed)
			if err != nil {
				return err
			}
			return waitFinalized(ctx, rpc, sig)
		},
	}
	f.run(t, false)
}
