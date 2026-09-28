package stellar

import (
	"context"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/inbound"
)

// RecentPayments lists successful native XLM payments received by a classic
// G… account, newest first, from Horizon's payments feed with each
// transaction's memo joined in. The newest 200 operations are searched, which
// covers any realistic waiting-room window.
func (h Horizon) RecentPayments(ctx context.Context, account string, since time.Time) ([]inbound.Payment, error) {
	var out struct {
		Embedded struct {
			Records []struct {
				Type       string `json:"type"`
				AssetType  string `json:"asset_type"`
				From       string `json:"from"`
				To         string `json:"to"`
				Amount     string `json:"amount"`
				Successful bool   `json:"transaction_successful"`
				Hash       string `json:"transaction_hash"`
				CreatedAt  string `json:"created_at"`
				Tx         struct {
					Memo string `json:"memo"`
				} `json:"transaction"`
			} `json:"records"`
		} `json:"_embedded"`
	}
	if err := h.get(ctx, "/accounts/"+url.PathEscape(account)+"/payments?order=desc&limit=200&join=transactions", &out); err != nil {
		return nil, err
	}
	var found []inbound.Payment
	for _, r := range out.Embedded.Records {
		at, err := time.Parse(time.RFC3339, r.CreatedAt)
		if err != nil || at.Before(since) {
			continue
		}
		if r.Type != "payment" || r.AssetType != "native" || r.To != account || !r.Successful || r.Hash == "" {
			continue
		}
		stroops, ok := stroopsOf(r.Amount)
		if !ok {
			continue
		}
		found = append(found, inbound.Payment{Hash: r.Hash, Payer: r.From, Amount: stroops, Memo: r.Tx.Memo, Time: at})
	}
	return found, nil
}

// stroopsOf converts Horizon's 7-decimal amount string to stroops exactly.
func stroopsOf(s string) (*big.Int, bool) {
	whole, frac, _ := strings.Cut(s, ".")
	if len(frac) > 7 || whole == "" {
		return nil, false
	}
	n, ok := new(big.Int).SetString(whole+frac+strings.Repeat("0", 7-len(frac)), 10)
	return n, ok && n.Sign() > 0
}
