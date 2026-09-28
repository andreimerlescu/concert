package solana

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/inbound"
)

// parsedSigs remembers finalized transactions already read, which never
// change, so a waiting room polling every few seconds fetches each once.
var parsedSigs = struct {
	sync.Mutex
	m map[string]*inbound.Payment // nil value: not a plain SOL transfer to the account
}{m: map[string]*inbound.Payment{}}

// RecentPayments lists finalized native SOL transfers received by an account,
// newest first: the account's latest signatures, each read once and decoded
// for a System Program transfer to the account.
func (c RPC) RecentPayments(ctx context.Context, account string, since time.Time) ([]inbound.Payment, error) {
	var sigs []struct {
		Signature string `json:"signature"`
		Err       any    `json:"err"`
		BlockTime *int64 `json:"blockTime"`
		Memo      string `json:"memo"`
	}
	if err := c.call(ctx, "getSignaturesForAddress", []any{account, map[string]any{"limit": 40, "commitment": "finalized"}}, &sigs); err != nil {
		return nil, err
	}
	var found []inbound.Payment
	for _, s := range sigs {
		if s.Err != nil || s.BlockTime == nil || time.Unix(*s.BlockTime, 0).Before(since) {
			continue
		}
		key := account + "/" + s.Signature
		parsedSigs.Lock()
		p, seen := parsedSigs.m[key]
		parsedSigs.Unlock()
		if !seen {
			var tx struct {
				Transaction struct {
					Message struct {
						Instructions []struct {
							Program string `json:"program"`
							Parsed  struct {
								Type string `json:"type"`
								Info struct {
									Source      string `json:"source"`
									Destination string `json:"destination"`
									Lamports    uint64 `json:"lamports"`
								} `json:"info"`
							} `json:"parsed"`
						} `json:"instructions"`
					} `json:"message"`
				} `json:"transaction"`
			}
			err := c.call(ctx, "getTransaction", []any{s.Signature, map[string]any{"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0, "commitment": "finalized"}}, &tx)
			if err != nil {
				return found, err
			}
			for _, in := range tx.Transaction.Message.Instructions {
				i := in.Parsed.Info
				if in.Program == "system" && in.Parsed.Type == "transfer" && i.Destination == account && i.Lamports > 0 {
					amount := new(big.Int).SetUint64(i.Lamports)
					p = &inbound.Payment{Hash: s.Signature, Payer: i.Source, Amount: amount, Time: time.Unix(*s.BlockTime, 0)}
					break
				}
			}
			parsedSigs.Lock()
			if len(parsedSigs.m) > 5000 {
				parsedSigs.m = map[string]*inbound.Payment{}
			}
			parsedSigs.m[key] = p
			parsedSigs.Unlock()
		}
		if p != nil {
			d := *p
			d.Memo = s.Memo
			found = append(found, d)
		}
	}
	return found, nil
}
