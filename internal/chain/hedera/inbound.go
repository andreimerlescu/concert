package hedera

import (
	"context"
	"encoding/base64"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/inbound"
)

// RecentPayments lists successful HBAR transfers credited to an account,
// newest first, from the mirror node. The payer is the account debited the
// most, which skips the network's node and fee accounts.
func (m Mirror) RecentPayments(ctx context.Context, account string, since time.Time) ([]inbound.Payment, error) {
	var out struct {
		Transactions []struct {
			ID        string `json:"transaction_id"`
			Consensus string `json:"consensus_timestamp"`
			Memo      string `json:"memo_base64"`
			Result    string `json:"result"`
			Transfers []struct {
				Account string `json:"account"`
				Amount  int64  `json:"amount"`
			} `json:"transfers"`
		} `json:"transactions"`
	}
	q := url.Values{"account.id": {account}, "transactiontype": {"cryptotransfer"}, "result": {"success"}, "order": {"desc"}, "limit": {"100"}, "timestamp": {"gte:" + strconv.FormatInt(since.Unix(), 10)}}
	if err := m.get(ctx, "/api/v1/transactions?"+q.Encode(), &out); err != nil {
		return nil, err
	}
	var found []inbound.Payment
	for _, t := range out.Transactions {
		if t.Result != "SUCCESS" || t.ID == "" {
			continue
		}
		var got, worst int64
		payer := ""
		for _, x := range t.Transfers {
			if x.Account == account {
				got += x.Amount
			}
			if x.Amount < worst {
				worst, payer = x.Amount, x.Account
			}
		}
		if got <= 0 || payer == "" || payer == account {
			continue
		}
		secs, _, _ := strings.Cut(t.Consensus, ".")
		unix, err := strconv.ParseInt(secs, 10, 64)
		if err != nil {
			continue
		}
		memo := ""
		if b, err := base64.StdEncoding.DecodeString(t.Memo); err == nil && len(b) <= 100 {
			memo = string(b)
		}
		found = append(found, inbound.Payment{Hash: t.ID, Payer: payer, Amount: big.NewInt(got), Memo: memo, Time: time.Unix(unix, 0)})
	}
	return found, nil
}
