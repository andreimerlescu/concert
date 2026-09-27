package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/andreimerlescu/concert/internal/chain/hedera"
	"github.com/andreimerlescu/concert/internal/chain/solana"
	"github.com/andreimerlescu/concert/internal/chain/stellar"
	"github.com/andreimerlescu/concert/internal/chain/xrpl"
	"github.com/andreimerlescu/concert/internal/x402"
)

var fingerprintRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Reconcile is operator recovery after a gateway crash or timeout. It never
// signs, broadcasts, refunds or moves funds: it checks final ledger state and
// then records the settlement of an already journaled authorization. The
// journal's lock keeps a running gateway out while it works. stellarHash is
// the sponsor's transaction hash, required for Stellar only because the
// sponsor submits a fresh envelope.
func Reconcile(ctx context.Context, j *Journal, networks map[string]Network, id, stellarHash string) (x402.SettleResponse, error) {
	return reconcile(ctx, j, networks, id, stellarHash, false)
}

func reconcile(ctx context.Context, j *Journal, networks map[string]Network, id, stellarHash string, allowHTTP bool) (x402.SettleResponse, error) {
	var none x402.SettleResponse
	if !fingerprintRE.MatchString(id) {
		return none, errors.New("usage: concert reconcile <payment fingerprint> [Stellar transaction hash]")
	}
	rec, ok := j.Get(id)
	if !ok {
		return none, errors.New("receipt not found")
	}
	if rec.State == "settled" && rec.Response != nil {
		return *rec.Response, nil
	}
	var p x402.Payload
	var r x402.Requirements
	if err := json.Unmarshal(rec.Payload, &p); err != nil {
		return none, err
	}
	if err := json.Unmarshal(rec.Terms, &r); err != nil {
		return none, err
	}
	n, ok := networks[r.Network]
	if !ok {
		return none, errors.New("network configuration is missing")
	}
	for _, e := range []string{n.RPC, n.Horizon, n.Mirror} {
		if e != "" {
			if err := checkEndpoint(e, allowHTTP); err != nil {
				return none, err
			}
		}
	}
	var tx string
	var err error
	switch family(r.Network) {
	case "solana":
		tx, err = solana.New(r.Network, n.RPC).Reconcile(ctx, p, r, rec.Payer)
	case "xrpl":
		tx, err = xrpl.New(r.Network, n.RPC, 0).Reconcile(ctx, p, r, rec.Payer)
	case "hedera":
		tx, err = (&hedera.Scheme{Network: r.Network, Mirror: hedera.Mirror{URL: n.Mirror}}).Reconcile(ctx, p, r, rec.Payer)
	case "stellar":
		pass, perr := stellar.Passphrase(r.Network)
		if perr != nil {
			return none, perr
		}
		s := &stellar.Scheme{Network: r.Network, RPC: stellar.RPC{URL: n.RPC}}
		s.SetPassphrase(pass)
		tx, err = s.Reconcile(ctx, p, r, strings.ToLower(stellarHash))
	default:
		err = errors.New("unsupported network")
	}
	if err != nil {
		return none, err
	}
	res := x402.SettleResponse{Success: true, Transaction: tx, Network: r.Network, Payer: rec.Payer}
	rec.State, rec.Response = "settled", &res
	return res, j.Write(rec)
}
