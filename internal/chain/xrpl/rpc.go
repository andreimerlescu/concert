package xrpl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/andreimerlescu/concert/internal/chain/httpx"
)

// AccountInfo is the validated account state the scheme consults.
type AccountInfo struct {
	Sequence   uint32
	Flags      uint32
	RegularKey string
}

// TxResult is a transaction lookup.
type TxResult struct {
	Found          bool
	Validated      bool
	Result         string
	DeliveredDrops string
	Blob           string
}

// Ledger is everything the scheme asks of the network; tests fake it.
type Ledger interface {
	NetworkID(ctx context.Context) (uint32, error)
	LedgerIndex(ctx context.Context) (uint32, error)
	AccountInfo(ctx context.Context, account string) (AccountInfo, error)
	TicketAvailable(ctx context.Context, account string, ticket uint32) (bool, error)
	Simulate(ctx context.Context, txJSON map[string]any) (string, error)
	Submit(ctx context.Context, blob string) (string, error)
	Tx(ctx context.Context, hash string) (TxResult, error)
	AccountNFTs(ctx context.Context, account string, marker any) ([]NFT, any, error)
	Fee(ctx context.Context) (uint64, error)
}

type NFT struct {
	Issuer       string `json:"Issuer"`
	NFTokenID    string `json:"NFTokenID"`
	NFTokenTaxon uint32 `json:"NFTokenTaxon"`
}

// RPC talks to rippled's JSON-RPC over HTTP(S).
type RPC struct{ URL string }

type rpcError struct{ Code, Message string }

func (e *rpcError) Error() string { return "rippled: " + e.Code }

func (c RPC) call(ctx context.Context, method string, params map[string]any, out any) error {
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	if err := httpx.PostJSON(ctx, c.URL, map[string]any{"method": method, "params": []any{params}}, &resp); err != nil {
		return err
	}
	var status struct {
		Status  string `json:"status"`
		Error   string `json:"error"`
		Message string `json:"error_message"`
	}
	if err := json.Unmarshal(resp.Result, &status); err != nil {
		return err
	}
	if status.Status != "success" {
		return &rpcError{status.Error, status.Message}
	}
	return json.Unmarshal(resp.Result, out)
}

func (c RPC) NetworkID(ctx context.Context) (uint32, error) {
	var out struct {
		Info struct {
			NetworkID *uint32 `json:"network_id"`
		} `json:"info"`
	}
	if err := c.call(ctx, "server_info", map[string]any{}, &out); err != nil {
		return 0, err
	}
	if out.Info.NetworkID == nil {
		return 0, nil // Mainnet servers may omit it
	}
	return *out.Info.NetworkID, nil
}

func (c RPC) LedgerIndex(ctx context.Context) (uint32, error) {
	var out struct {
		LedgerIndex uint32 `json:"ledger_index"`
		Validated   bool   `json:"validated"`
	}
	err := c.call(ctx, "ledger", map[string]any{"ledger_index": "validated"}, &out)
	return out.LedgerIndex, err
}

func (c RPC) AccountInfo(ctx context.Context, account string) (AccountInfo, error) {
	var out struct {
		Validated bool `json:"validated"`
		Data      struct {
			Sequence   uint32 `json:"Sequence"`
			Flags      uint32 `json:"Flags"`
			RegularKey string `json:"RegularKey"`
		} `json:"account_data"`
	}
	if err := c.call(ctx, "account_info", map[string]any{"account": account, "ledger_index": "validated"}, &out); err != nil {
		return AccountInfo{}, err
	}
	if !out.Validated {
		return AccountInfo{}, errors.New("unvalidated account data")
	}
	return AccountInfo{Sequence: out.Data.Sequence, Flags: out.Data.Flags, RegularKey: out.Data.RegularKey}, nil
}

func (c RPC) TicketAvailable(ctx context.Context, account string, ticket uint32) (bool, error) {
	var marker any
	for page := 0; page < 100; page++ {
		var out struct {
			Objects []struct {
				Type           string `json:"LedgerEntryType"`
				TicketSequence uint32 `json:"TicketSequence"`
			} `json:"account_objects"`
			Marker any `json:"marker"`
		}
		p := map[string]any{"account": account, "type": "ticket", "ledger_index": "validated"}
		if marker != nil {
			p["marker"] = marker
		}
		if err := c.call(ctx, "account_objects", p, &out); err != nil {
			return false, err
		}
		for _, o := range out.Objects {
			if o.Type == "Ticket" && o.TicketSequence == ticket {
				return true, nil
			}
		}
		if out.Marker == nil {
			return false, nil
		}
		marker = out.Marker
	}
	return false, errors.New("ticket search incomplete")
}

func (c RPC) Simulate(ctx context.Context, txJSON map[string]any) (string, error) {
	var out struct {
		EngineResult string `json:"engine_result"`
	}
	err := c.call(ctx, "simulate", map[string]any{"tx_json": txJSON}, &out)
	return out.EngineResult, err
}

func (c RPC) Submit(ctx context.Context, blob string) (string, error) {
	var out struct {
		EngineResult string `json:"engine_result"`
	}
	err := c.call(ctx, "submit", map[string]any{"tx_blob": blob, "fail_hard": true}, &out)
	return out.EngineResult, err
}

func (c RPC) Tx(ctx context.Context, hash string) (TxResult, error) {
	var out struct {
		Validated bool   `json:"validated"`
		Blob      string `json:"tx_blob"`
		Meta      *struct {
			Result    string `json:"TransactionResult"`
			Delivered any    `json:"delivered_amount"`
		} `json:"meta"`
		MetaBlob string `json:"meta_blob"`
	}
	err := c.call(ctx, "tx", map[string]any{"transaction": hash, "binary": false}, &out)
	var re *rpcError
	if errors.As(err, &re) && re.Code == "txnNotFound" {
		return TxResult{}, nil
	}
	if err != nil {
		return TxResult{}, err
	}
	r := TxResult{Found: true, Validated: out.Validated}
	if out.Meta != nil {
		r.Result = out.Meta.Result
		if s, ok := out.Meta.Delivered.(string); ok {
			r.DeliveredDrops = s
		}
	}
	return r, nil
}

func (c RPC) AccountNFTs(ctx context.Context, account string, marker any) ([]NFT, any, error) {
	var out struct {
		Validated bool  `json:"validated"`
		NFTs      []NFT `json:"account_nfts"`
		Marker    any   `json:"marker"`
	}
	p := map[string]any{"account": account, "ledger_index": "validated", "limit": 400}
	if marker != nil {
		p["marker"] = marker
	}
	if err := c.call(ctx, "account_nfts", p, &out); err != nil {
		return nil, nil, err
	}
	if !out.Validated {
		return nil, nil, errors.New("unvalidated NFT data")
	}
	return out.NFTs, out.Marker, nil
}

// Fee returns a payer fee in drops as xrpl.js autofill computes it: the
// validated base fee times the load factor, with a 1.2 cushion.
func (c RPC) Fee(ctx context.Context) (uint64, error) {
	var out struct {
		Info struct {
			LoadFactor float64 `json:"load_factor"`
			Validated  struct {
				BaseFeeXRP float64 `json:"base_fee_xrp"`
			} `json:"validated_ledger"`
		} `json:"info"`
	}
	if err := c.call(ctx, "server_info", map[string]any{}, &out); err != nil {
		return 0, err
	}
	load := out.Info.LoadFactor
	if load == 0 {
		load = 1
	}
	drops := out.Info.Validated.BaseFeeXRP * 1e6 * load * 1.2
	if drops <= 0 || drops > 2e6 {
		return 0, fmt.Errorf("unexpected fee %v", drops)
	}
	return uint64(drops + 0.999999), nil
}

// CheckNetwork refuses an endpoint on another network. XRPL networks up to
// 1024 carry no NetworkID in signed transactions, so the endpoint alone
// decides where a payment lands.
func CheckNetwork(ctx context.Context, l Ledger, network string) error {
	want, err := NetworkNumber(network)
	if err != nil {
		return err
	}
	got, err := l.NetworkID(ctx)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("XRPL endpoint is not on %s", network)
	}
	return nil
}

// NetworkNumber parses "xrpl:<id>".
func NetworkNumber(network string) (uint32, error) {
	if len(network) < 6 || network[:5] != "xrpl:" {
		return 0, errors.New("invalid XRPL network")
	}
	n, err := strconv.ParseUint(network[5:], 10, 32)
	if err != nil || strconv.FormatUint(n, 10) != network[5:] {
		return 0, errors.New("invalid XRPL network")
	}
	return uint32(n), nil
}
