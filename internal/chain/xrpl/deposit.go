package xrpl

import (
	"context"
	"errors"
	"math/big"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/inbound"
)

// rippleEpoch is 2000-01-01T00:00:00Z, the origin of rippled's close times.
const rippleEpoch = 946684800

// maxDepositPages bounds one account_tx sweep (200 transactions per page).
const maxDepositPages = 5

// RecentPayments returns validated tesSUCCESS XRP payments received by account
// at or after since, newest first. Only the amount actually delivered counts,
// so a partial payment is never over-credited. Payments in issued currencies
// are ignored.
func (c RPC) RecentPayments(ctx context.Context, account string, since time.Time) ([]inbound.Payment, error) {
	var found []inbound.Payment
	var marker any
	for page := 0; page < maxDepositPages; page++ {
		var out struct {
			Transactions []struct {
				Validated bool `json:"validated"`
				Meta      struct {
					Result    string `json:"TransactionResult"`
					Delivered any    `json:"delivered_amount"`
				} `json:"meta"`
				Tx struct {
					Type    string `json:"TransactionType"`
					Account string `json:"Account"`
					Dest    string `json:"Destination"`
					Tag     *int64 `json:"DestinationTag"`
					Hash    string `json:"hash"`
					Date    int64  `json:"date"`
				} `json:"tx"`
			} `json:"transactions"`
			Marker any `json:"marker"`
		}
		p := map[string]any{"account": account, "ledger_index_min": -1, "ledger_index_max": -1, "limit": 200, "forward": false}
		if marker != nil {
			p["marker"] = marker
		}
		if err := c.call(ctx, "account_tx", p, &out); err != nil {
			return nil, err
		}
		reachedOld := false
		for _, t := range out.Transactions {
			at := time.Unix(t.Tx.Date+rippleEpoch, 0)
			if at.Before(since) {
				reachedOld = true
				continue
			}
			drops, isXRP := t.Meta.Delivered.(string)
			if !t.Validated || t.Meta.Result != "tesSUCCESS" || t.Tx.Type != "Payment" || t.Tx.Dest != account || !isXRP || t.Tx.Hash == "" {
				continue
			}
			n, ok := new(big.Int).SetString(drops, 10)
			if !ok || n.Sign() <= 0 {
				continue
			}
			d := inbound.Payment{Hash: t.Tx.Hash, Payer: t.Tx.Account, Amount: n, Time: at}
			if t.Tx.Tag != nil && *t.Tx.Tag >= 0 && *t.Tx.Tag <= 0xFFFFFFFF {
				d.Tag, d.HasTag = uint32(*t.Tx.Tag), true
			}
			found = append(found, d)
		}
		if reachedOld || out.Marker == nil {
			return found, nil
		}
		marker = out.Marker
	}
	return found, errors.New("deposit search incomplete")
}
