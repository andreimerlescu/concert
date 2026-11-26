package hedera

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TokenBalance returns the account's exact balance in atomic units:
// tinybars for "0.0.0" (HBAR) or base units for an HTS fungible token "0.0.N".
func (s *Scheme) TokenBalance(ctx context.Context, address, tokenID string) (*big.Int, error) {
	if !ValidEntityID(address) || !ValidEntityID(tokenID) {
		return nil, errors.New("invalid Hedera entity ID")
	}
	if tokenID == "0.0.0" {
		a, err := s.Mirror.Account(ctx, address)
		if err != nil {
			return nil, err
		}
		if a.Deleted {
			return big.NewInt(0), nil
		}
		n, ok := new(big.Int).SetString(a.Balance.Balance.String(), 10)
		if !ok || n.Sign() < 0 {
			return nil, errors.New("invalid HBAR balance")
		}
		return n, nil
	}
	var out struct {
		Tokens []struct {
			TokenID      string      `json:"token_id"`
			Balance      json.Number `json:"balance"`
			FreezeStatus string      `json:"freeze_status"`
		} `json:"tokens"`
	}
	if err := s.Mirror.get(ctx, "/api/v1/accounts/"+url.PathEscape(address)+"/tokens?token.id="+url.PathEscape(tokenID)+"&limit=1", &out); err != nil {
		return nil, err
	}
	for _, tok := range out.Tokens {
		if tok.TokenID != tokenID {
			continue
		}
		if strings.EqualFold(tok.FreezeStatus, "FROZEN") {
			return big.NewInt(0), nil
		}
		n, ok := new(big.Int).SetString(tok.Balance.String(), 10)
		if !ok || n.Sign() < 0 {
			return nil, errors.New("invalid HTS token balance")
		}
		return n, nil
	}
	return big.NewInt(0), nil
}

// MeetsMinBalance checks whether address holds at least minAtomic units of tokenID.
func (s *Scheme) MeetsMinBalance(ctx context.Context, address, tokenID, minAtomic string) (bool, string, error) {
	want, ok := new(big.Int).SetString(strings.TrimSpace(minAtomic), 10)
	if !ok || want.Sign() < 0 {
		return false, "", errors.New("invalid minimum balance")
	}
	bal, err := s.TokenBalance(ctx, address, tokenID)
	if err != nil {
		return false, "", err
	}
	return bal.Cmp(want) >= 0, bal.String(), nil
}

// SponsorBalance returns the managed Hedera sponsor's HBAR balance in tinybars.
func (s *Scheme) SponsorBalance(ctx context.Context) (int64, error) {
	if !s.hasSponsor || s.FeePayer == "" {
		return 0, errors.New("no Hedera sponsor configured")
	}
	bal, err := s.TokenBalance(ctx, s.FeePayer, "0.0.0")
	if err != nil {
		return 0, err
	}
	return bal.Int64(), nil
}

// FindDirectPayment scans recent successful CRYPTOTRANSFER transactions on the
// Mirror Node for `to` matching optional `from`, `tokenID` ("0.0.0" HBAR or HTS
// "0.0.N"), exact `memoText`, and net amount >= minAtomic.
func (s *Scheme) FindDirectPayment(ctx context.Context, from, to, tokenID, minAtomic, memoText string, since time.Time) (txID, payer string, err error) {
	if !ValidEntityID(to) || (from != "" && !ValidEntityID(from)) || !ValidEntityID(tokenID) {
		return "", "", errors.New("invalid Hedera entity ID")
	}
	want, ok := new(big.Int).SetString(strings.TrimSpace(minAtomic), 10)
	if !ok || want.Sign() <= 0 {
		return "", "", errors.New("invalid minimum Hedera amount")
	}
	path := "/api/v1/transactions?account.id=" + url.PathEscape(to) + "&transactiontype=CRYPTOTRANSFER&result=success&order=desc&limit=50"
	if !since.IsZero() {
		ts := since.Add(-30 * time.Second).UTC().Unix()
		path += "&timestamp=gte:" + strconv.FormatInt(ts, 10) + ".000000000"
	}
	var data struct {
		Transactions []struct {
			TransactionID string `json:"transaction_id"`
			Result        string `json:"result"`
			Nonce         int    `json:"nonce"`
			Scheduled     bool   `json:"scheduled"`
			MemoBase64    string `json:"memo_base64"`
			Tokens        []struct {
				TokenID string      `json:"token_id"`
				Account string      `json:"account"`
				Amount  json.Number `json:"amount"`
			} `json:"token_transfers"`
			Transfers []struct {
				Account string      `json:"account"`
				Amount  json.Number `json:"amount"`
			} `json:"transfers"`
		} `json:"transactions"`
	}
	if err := s.Mirror.get(ctx, path, &data); err != nil {
		return "", "", err
	}
	isHBAR := tokenID == "0.0.0"
	for _, t := range data.Transactions {
		if t.Result != "SUCCESS" || t.Nonce != 0 || t.Scheduled {
			continue
		}
		if memoText != "" {
			rawMemo, derr := base64.StdEncoding.DecodeString(t.MemoBase64)
			if derr != nil || string(rawMemo) != memoText {
				continue
			}
		}
		var ts []Transfer
		if isHBAR {
			for _, x := range t.Transfers {
				n, perr := strconv.ParseInt(x.Amount.String(), 10, 64)
				if perr == nil {
					ts = append(ts, Transfer{x.Account, n})
				}
			}
		} else {
			for _, x := range t.Tokens {
				if x.TokenID != tokenID {
					continue
				}
				n, perr := strconv.ParseInt(x.Amount.String(), 10, 64)
				if perr == nil {
					ts = append(ts, Transfer{x.Account, n})
				}
			}
		}
		if net(ts, to).Cmp(want) < 0 {
			continue
		}
		// Identify payer (account debited for this transfer).
		foundPayer := from
		if foundPayer != "" {
			if net(ts, foundPayer).Cmp(new(big.Int).Neg(want)) > 0 {
				continue
			}
		} else {
			for _, x := range ts {
				if x.Amount < 0 && x.Account != to && big.NewInt(-x.Amount).Cmp(want) >= 0 {
					foundPayer = x.Account
					break
				}
			}
		}
		if foundPayer == "" {
			continue
		}
		return t.TransactionID, foundPayer, nil
	}
	return "", "", errors.New("matching Hedera payment not found yet")
}
