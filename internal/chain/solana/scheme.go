package solana

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/httpx"
	"github.com/andreimerlescu/concert/internal/x402"
)

// RPC is a minimal Solana JSON-RPC client.
type RPC struct{ URL string }

type Status struct {
	Err                any    `json:"err"`
	ConfirmationStatus string `json:"confirmationStatus"`
}

func (c RPC) call(ctx context.Context, method string, params, out any) error {
	return httpx.Call(ctx, c.URL, method, params, out)
}

// Network returns the CAIP-2 identifier derived from the genesis hash.
func (c RPC) Network(ctx context.Context) (string, error) {
	var genesis string
	if err := c.call(ctx, "getGenesisHash", nil, &genesis); err != nil {
		return "", err
	}
	if len(genesis) < 32 {
		return "", errors.New("invalid genesis hash")
	}
	return "solana:" + genesis[:32], nil
}

func (c RPC) Status(ctx context.Context, signature string) (*Status, error) {
	var out struct {
		Value []*Status `json:"value"`
	}
	if err := c.call(ctx, "getSignatureStatuses", []any{[]string{signature}, map[string]any{"searchTransactionHistory": true}}, &out); err != nil {
		return nil, err
	}
	if len(out.Value) != 1 {
		return nil, errors.New("invalid status response")
	}
	return out.Value[0], nil
}

func (c RPC) BlockhashValid(ctx context.Context, blockhash PublicKey) (bool, error) {
	var out struct {
		Value bool `json:"value"`
	}
	err := c.call(ctx, "isBlockhashValid", []any{blockhash.String(), map[string]any{"commitment": "finalized"}}, &out)
	return out.Value, err
}

func (c RPC) Simulate(ctx context.Context, raw []byte) error {
	var out struct {
		Value struct {
			Err any `json:"err"`
		} `json:"value"`
	}
	opts := map[string]any{"encoding": "base64", "sigVerify": true, "commitment": "finalized"}
	if err := c.call(ctx, "simulateTransaction", []any{base64.StdEncoding.EncodeToString(raw), opts}, &out); err != nil {
		return err
	}
	if out.Value.Err != nil {
		return errors.New("simulation failed")
	}
	return nil
}

func (c RPC) Send(ctx context.Context, raw []byte) (string, error) {
	var sig string
	opts := map[string]any{"encoding": "base64", "skipPreflight": false, "preflightCommitment": "finalized", "maxRetries": 3}
	err := c.call(ctx, "sendTransaction", []any{base64.StdEncoding.EncodeToString(raw), opts}, &sig)
	return sig, err
}

func (c RPC) LatestBlockhash(ctx context.Context) (PublicKey, error) {
	var out struct {
		Value struct {
			Blockhash string `json:"blockhash"`
		} `json:"value"`
	}
	if err := c.call(ctx, "getLatestBlockhash", []any{map[string]any{"commitment": "finalized"}}, &out); err != nil {
		return PublicKey{}, err
	}
	return ParsePublicKey(out.Value.Blockhash)
}

// Account is getAccountInfo's value with base64 data decoded.
type Account struct {
	Owner PublicKey
	Data  []byte
}

func (c RPC) Account(ctx context.Context, key PublicKey) (*Account, error) {
	var out struct {
		Value *struct {
			Owner string   `json:"owner"`
			Data  []string `json:"data"`
		} `json:"value"`
	}
	if err := c.call(ctx, "getAccountInfo", []any{key.String(), map[string]any{"encoding": "base64", "commitment": "finalized"}}, &out); err != nil {
		return nil, err
	}
	if out.Value == nil {
		return nil, nil
	}
	owner, err := ParsePublicKey(out.Value.Owner)
	if err != nil || len(out.Value.Data) != 2 || out.Value.Data[1] != "base64" {
		return nil, errors.New("invalid account response")
	}
	data, err := base64.StdEncoding.DecodeString(out.Value.Data[0])
	if err != nil {
		return nil, err
	}
	return &Account{Owner: owner, Data: data}, nil
}

// Scheme settles concert-native-sol payments on one cluster.
type Scheme struct {
	Network       string
	RPC           RPC
	PollInterval  time.Duration
	ConfirmWithin time.Duration
}

func New(network, url string) *Scheme {
	return &Scheme{Network: network, RPC: RPC{URL: url}, PollInterval: 2 * time.Second, ConfirmWithin: 120 * time.Second}
}

func (s *Scheme) check(ctx context.Context, req x402.Requirements) error {
	if req.Scheme != SchemeName || req.Asset != "SOL" || req.Network != s.Network {
		return errors.New("wrong network or scheme")
	}
	n, err := s.RPC.Network(ctx)
	if err != nil {
		return err
	}
	if n != req.Network {
		return errors.New("RPC network mismatch")
	}
	return nil
}

func transaction(p x402.Payload) (string, error) {
	var body struct {
		Transaction string `json:"transaction"`
	}
	if err := json.Unmarshal(p.Payload, &body); err != nil || body.Transaction == "" {
		return "", errors.New("payload.transaction is required")
	}
	return body.Transaction, nil
}

func (s *Scheme) preflight(ctx context.Context, t Transfer) error {
	ok, err := s.RPC.BlockhashValid(ctx, t.Blockhash)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("blockhash expired")
	}
	return s.RPC.Simulate(ctx, t.Raw)
}

// Verify accepts only a transfer the network has not seen. A signed
// transfer is public once broadcast; accepting one already on chain would
// let anyone who observed it claim the payer's pass.
func (s *Scheme) Verify(ctx context.Context, p x402.Payload, req x402.Requirements) x402.VerifyResponse {
	invalid := x402.Invalid("invalid_native_sol_payment", "")
	if p.Version != 2 {
		return invalid
	}
	if s.check(ctx, req) != nil {
		return invalid
	}
	enc, err := transaction(p)
	if err != nil {
		return invalid
	}
	t, err := Inspect(enc, req)
	if err != nil {
		return invalid
	}
	if st, err := s.RPC.Status(ctx, t.SignatureString()); err != nil || st != nil {
		return invalid
	}
	if s.preflight(ctx, t) != nil {
		return invalid
	}
	return x402.Valid(t.From.String())
}

// Settle runs only after the gateway journaled the authorization, so a
// transfer already on chain is this payment landing. It broadcasts at most
// once and polls to finality; any error leaves the outcome unknown.
func (s *Scheme) Settle(ctx context.Context, p x402.Payload, req x402.Requirements) (x402.SettleResponse, error) {
	if err := s.check(ctx, req); err != nil {
		return x402.SettleResponse{}, err
	}
	enc, err := transaction(p)
	if err != nil {
		return x402.SettleResponse{}, err
	}
	t, err := Inspect(enc, req)
	if err != nil {
		return x402.SettleResponse{}, err
	}
	sig := t.SignatureString()
	st, err := s.RPC.Status(ctx, sig)
	if err != nil {
		return x402.SettleResponse{}, err
	}
	if st == nil {
		if err := s.preflight(ctx, t); err != nil {
			return x402.SettleResponse{}, err
		}
		got, err := s.RPC.Send(ctx, t.Raw)
		if err != nil {
			return x402.SettleResponse{}, err
		}
		if got != sig {
			return x402.SettleResponse{}, errors.New("RPC signature mismatch")
		}
	}
	deadline := time.Now().Add(s.ConfirmWithin)
	for {
		st, err := s.RPC.Status(ctx, sig)
		if err == nil && st != nil {
			if st.Err != nil {
				return x402.SettleResponse{}, errors.New("transfer failed")
			}
			if st.ConfirmationStatus == "finalized" {
				return x402.SettleResponse{Success: true, Transaction: sig, Network: req.Network, Payer: t.From.String()}, nil
			}
		}
		if time.Now().After(deadline) {
			return x402.SettleResponse{}, errors.New("finality not observed")
		}
		select {
		case <-ctx.Done():
			return x402.SettleResponse{}, ctx.Err()
		case <-time.After(s.PollInterval):
		}
	}
}

// Prepare returns the unsigned transfer a browser wallet signs. Concert
// never holds the payer's key.
func (s *Scheme) Prepare(ctx context.Context, address string, req x402.Requirements) ([]byte, error) {
	if err := s.check(ctx, req); err != nil {
		return nil, err
	}
	from, err := ParsePublicKey(address)
	if err != nil {
		return nil, err
	}
	to, err := ParsePublicKey(req.PayTo)
	if err != nil {
		return nil, err
	}
	if from == to {
		return nil, errors.New("self-payment is not accepted")
	}
	lamports, err := strconv.ParseUint(req.Amount, 10, 64)
	if err != nil {
		return nil, err
	}
	bh, err := s.RPC.LatestBlockhash(ctx)
	if err != nil {
		return nil, err
	}
	return NewTransfer(from, to, lamports, bh), nil
}

// Finalized reports whether signature finalized successfully (reconciliation).
func (s *Scheme) Finalized(ctx context.Context, signature string) (bool, error) {
	st, err := s.RPC.Status(ctx, signature)
	if err != nil {
		return false, err
	}
	return st != nil && st.Err == nil && st.ConfirmationStatus == "finalized", nil
}

// Reconcile confirms that a journaled transfer finalized successfully on
// this cluster. It never broadcasts anything.
func (s *Scheme) Reconcile(ctx context.Context, p x402.Payload, req x402.Requirements, _ string) (string, error) {
	if err := s.check(ctx, req); err != nil {
		return "", err
	}
	enc, err := transaction(p)
	if err != nil {
		return "", err
	}
	t, err := Inspect(enc, req)
	if err != nil {
		return "", err
	}
	ok, err := s.Finalized(ctx, t.SignatureString())
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("payment not finalized")
	}
	return t.SignatureString(), nil
}
