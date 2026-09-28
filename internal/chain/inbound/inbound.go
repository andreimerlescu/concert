// Package inbound describes a payment received by a merchant's account, the
// common shape every chain's "who paid me recently" lookup returns.
package inbound

import (
	"context"
	"math/big"
	"time"
)

// Payment is one finalized, successful transfer of the chain's native coin.
type Payment struct {
	Hash   string
	Payer  string
	Amount *big.Int // atomic units actually received
	Memo   string   // Stellar/Hedera/Solana memo, when the chain carries one
	Tag    uint32   // XRPL destination tag
	HasTag bool
	Time   time.Time
}

// Lister lists native-coin payments received by an account since a time,
// newest first. A partial result may accompany an error.
type Lister interface {
	RecentPayments(ctx context.Context, account string, since time.Time) ([]Payment, error)
}
