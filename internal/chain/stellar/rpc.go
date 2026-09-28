// Package stellar implements the x402 "exact" Stellar scheme for native XLM
// through its Stellar Asset Contract, ported rule for rule from
// @x402/stellar, plus SEP-50 collection checks and payer-side signing.
// XDR comes from the official Stellar Go SDK.
package stellar

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/httpx"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// RPC is a minimal Stellar RPC (Soroban) client.
type RPC struct{ URL string }

func (c RPC) call(ctx context.Context, method string, params, out any) error {
	return httpx.Call(ctx, c.URL, method, params, out)
}

// Simulation is simulateTransaction's raw response.
type Simulation struct {
	Error           string   `json:"error"`
	TransactionData string   `json:"transactionData"`
	MinResourceFee  string   `json:"minResourceFee"`
	Events          []string `json:"events"`
	Results         []struct {
		Auth []string `json:"auth"`
		XDR  string   `json:"xdr"`
	} `json:"results"`
	RestorePreamble *struct {
		TransactionData string `json:"transactionData"`
	} `json:"restorePreamble"`
	LatestLedger uint32 `json:"latestLedger"`
}

func (s *Simulation) Success() bool {
	return s.Error == "" && s.TransactionData != "" && s.RestorePreamble == nil
}

func (c RPC) Simulate(ctx context.Context, envelope string) (*Simulation, error) {
	var s Simulation
	err := c.call(ctx, "simulateTransaction", map[string]any{"transaction": envelope}, &s)
	return &s, err
}

func (c RPC) LatestLedger(ctx context.Context) (uint32, error) {
	var out struct {
		Sequence uint32 `json:"sequence"`
	}
	err := c.call(ctx, "getLatestLedger", nil, &out)
	return out.Sequence, err
}

func (c RPC) Passphrase(ctx context.Context) (string, error) {
	var out struct {
		Passphrase string `json:"passphrase"`
	}
	err := c.call(ctx, "getNetwork", nil, &out)
	return out.Passphrase, err
}

// Sequence reads an account's current sequence number.
func (c RPC) Sequence(ctx context.Context, account xdr.AccountId) (int64, error) {
	key, err := xdr.MarshalBase64(xdr.LedgerKey{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.LedgerKeyAccount{AccountId: account}})
	if err != nil {
		return 0, err
	}
	var out struct {
		Entries []struct {
			XDR string `json:"xdr"`
		} `json:"entries"`
	}
	if err := c.call(ctx, "getLedgerEntries", map[string]any{"keys": []string{key}}, &out); err != nil {
		return 0, err
	}
	if len(out.Entries) != 1 {
		return 0, errors.New("account not found")
	}
	var data xdr.LedgerEntryData
	if err := xdr.SafeUnmarshalBase64(out.Entries[0].XDR, &data); err != nil {
		return 0, err
	}
	acct, ok := data.GetAccount()
	if !ok {
		return 0, errors.New("not an account entry")
	}
	return int64(acct.SeqNum), nil
}

type SendResult struct {
	Status string `json:"status"`
	Hash   string `json:"hash"`
}

func (c RPC) Send(ctx context.Context, envelope string) (SendResult, error) {
	var out SendResult
	err := c.call(ctx, "sendTransaction", map[string]any{"transaction": envelope}, &out)
	return out, err
}

type TxStatus struct {
	Status      string `json:"status"`
	EnvelopeXDR string `json:"envelopeXdr"`
}

func (c RPC) Transaction(ctx context.Context, hash string) (TxStatus, error) {
	var out TxStatus
	err := c.call(ctx, "getTransaction", map[string]any{"hash": hash}, &out)
	return out, err
}

// Horizon is the subset of Horizon REST the scheme uses.
type Horizon struct{ URL string }

type HorizonAccount struct {
	Sequence string `json:"sequence"`
	Signers  []struct {
		Key    string `json:"key"`
		Weight int    `json:"weight"`
	} `json:"signers"`
	Thresholds struct {
		Med int `json:"med_threshold"`
	} `json:"thresholds"`
}

func (h Horizon) get(ctx context.Context, path string, out any) error {
	return httpx.GetJSON(ctx, strings.TrimRight(h.URL, "/")+path, out)
}

func (h Horizon) Account(ctx context.Context, id string) (*HorizonAccount, error) {
	var a HorizonAccount
	return &a, h.get(ctx, "/accounts/"+id, &a)
}

func (h Horizon) Passphrase(ctx context.Context) (string, error) {
	var root struct {
		Passphrase string `json:"network_passphrase"`
	}
	err := h.get(ctx, "/", &root)
	return root.Passphrase, err
}

const defaultLedgerSeconds = 5

// LedgerSeconds estimates ledger close time from the last 20 ledgers, as
// @x402/stellar does (it asks the public Horizon; this uses the configured
// one). Any failure falls back to five seconds.
func (h Horizon) LedgerSeconds(ctx context.Context) int {
	if h.URL == "" {
		return defaultLedgerSeconds
	}
	var page struct {
		Embedded struct {
			Records []struct {
				ClosedAt time.Time `json:"closed_at"`
			} `json:"records"`
		} `json:"_embedded"`
	}
	if err := h.get(ctx, "/ledgers?limit=20&order=desc", &page); err != nil {
		return defaultLedgerSeconds
	}
	r := page.Embedded.Records
	if len(r) < 2 {
		return defaultLedgerSeconds
	}
	s := r[0].ClosedAt.Sub(r[len(r)-1].ClosedAt).Seconds() / float64(len(r)-1)
	if s <= 0 {
		return defaultLedgerSeconds
	}
	return int(math.Ceil(s))
}

func atoi64(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }

func decodeContract(c string) ([32]byte, error) {
	b, err := strkey.Decode(strkey.VersionByteContract, c)
	if err != nil || len(b) != 32 {
		return [32]byte{}, errors.New("invalid contract address")
	}
	return [32]byte(b), nil
}
