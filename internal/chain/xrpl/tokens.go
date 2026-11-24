package xrpl

import (
	"context"
	"errors"
	"math/big"
	"strings"
)

// TokenBalance returns the validated balance of asset ("XRP" in drops, or
// "CURRENCY:ISSUER" as a canonical decimal string) held by address.
// Frozen trustlines return "0".
func (s *Scheme) TokenBalance(ctx context.Context, address, asset string) (string, error) {
	if !ValidAddress(address) {
		return "", errors.New("invalid XRPL address")
	}
	if err := CheckNetwork(ctx, s.Ledger, s.Network); err != nil {
		return "", err
	}
	isNative, wantCurBytes, _, _, wantIssuer, err := ParseAsset(asset)
	if err != nil {
		return "", err
	}
	if isNative {
		info, err := s.Ledger.AccountInfo(ctx, address)
		if err != nil {
			return "", err
		}
		if info.Balance == "" {
			return "0", nil
		}
		return info.Balance, nil
	}
	tl, ok := s.Ledger.(TokenLedger)
	if !ok {
		return "", errors.New("XRPL ledger implementation does not support trustline queries")
	}
	var marker any
	for page := 0; page < 100; page++ {
		lines, next, err := tl.AccountLines(ctx, address, wantIssuer, marker)
		if err != nil {
			return "", err
		}
		for _, line := range lines {
			if line.Account != wantIssuer {
				continue
			}
			gotCur, _, err := NormalizeCurrency(line.Currency)
			if err != nil || gotCur != wantCurBytes {
				continue
			}
			if line.Freeze || line.FreezeP {
				return "0", nil
			}
			if strings.HasPrefix(strings.TrimSpace(line.Balance), "-") {
				return "0", nil
			}
			return strings.TrimSpace(line.Balance), nil
		}
		if next == nil {
			break
		}
		marker = next
	}
	return "0", nil
}

// MeetsMinBalance checks whether address holds at least minAmount of asset
// (drops for XRP, decimal string for CURRENCY:ISSUER).
func (s *Scheme) MeetsMinBalance(ctx context.Context, address, asset, minAmount string) (bool, string, error) {
	bal, err := s.TokenBalance(ctx, address, asset)
	if err != nil {
		return false, "", err
	}
	isNative, _, _, _, _, err := ParseAsset(asset)
	if err != nil {
		return false, "", err
	}
	if isNative {
		bInt, ok1 := new(big.Int).SetString(bal, 10)
		mInt, ok2 := new(big.Int).SetString(minAmount, 10)
		if !ok1 || !ok2 {
			return false, bal, errors.New("invalid XRP balance comparison")
		}
		return bInt.Cmp(mInt) >= 0, bal, nil
	}
	cmp, err := CompareDecimal(bal, minAmount)
	if err != nil {
		return false, bal, err
	}
	return cmp >= 0, bal, nil
}

// FindDirectPayment scans recent validated transactions on destination account
// `to` for an exact tesSUCCESS Payment from `from` (optional if empty) carrying
// `destTag` (when requireTag is true), `memoText` (when non-empty), and
// delivered_amount >= minAmount of `asset` ("XRP" drops or "CURRENCY:ISSUER").
// Returns the validated transaction hash and payer address when found.
func (s *Scheme) FindDirectPayment(ctx context.Context, from, to, asset, minAmount string, destTag uint32, requireTag bool, memoText string, minLedger uint32) (txHash, payer string, err error) {
	if !ValidAddress(to) || (from != "" && !ValidAddress(from)) {
		return "", "", errors.New("invalid XRPL address")
	}
	if err := CheckNetwork(ctx, s.Ledger, s.Network); err != nil {
		return "", "", err
	}
	isNative, wantCurBytes, _, _, wantIssuer, err := ParseAsset(asset)
	if err != nil {
		return "", "", err
	}
	tl, ok := s.Ledger.(TokenLedger)
	if !ok {
		return "", "", errors.New("XRPL ledger implementation does not support account_tx queries")
	}
	entries, err := tl.AccountTx(ctx, to, minLedger, 50)
	if err != nil {
		return "", "", err
	}
	for _, e := range entries {
		if !e.Validated || e.Result != "tesSUCCESS" || e.TxType != "Payment" {
			continue
		}
		if e.Destination != to || e.Flags&tfPartialPayment != 0 {
			continue
		}
		if from != "" && e.Account != from {
			continue
		}
		if requireTag {
			if e.DestinationTag == nil || *e.DestinationTag != destTag {
				continue
			}
		}
		if memoText != "" {
			matched := false
			for _, m := range e.Memos {
				if m == memoText {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if isNative {
			if e.DeliveredDrops == "" {
				continue
			}
			got, ok1 := new(big.Int).SetString(e.DeliveredDrops, 10)
			want, ok2 := new(big.Int).SetString(minAmount, 10)
			if !ok1 || !ok2 || got.Cmp(want) < 0 {
				continue
			}
		} else {
			gotCur, _, cerr := NormalizeCurrency(e.DeliveredCurrency)
			if cerr != nil || gotCur != wantCurBytes || e.DeliveredIssuer != wantIssuer {
				continue
			}
			cmp, cerr := CompareDecimal(e.DeliveredValue, minAmount)
			if cerr != nil || cmp < 0 {
				continue
			}
		}
		return e.Hash, e.Account, nil
	}
	return "", "", errors.New("matching on-ledger payment not found yet")
}
