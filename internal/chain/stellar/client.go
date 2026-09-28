package stellar

import (
	"context"
	"errors"
	"math/big"
	"time"

	"github.com/andreimerlescu/concert/internal/x402"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// nullAccount is the all-zero account stellar-sdk uses as the source of
// contract calls built without one; the facilitator replaces the source.
const nullAccount = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"

func i128(n *big.Int) (xdr.ScVal, error) {
	if n.Sign() < 0 || n.BitLen() > 127 {
		return xdr.ScVal{}, errors.New("amount out of range")
	}
	lo := new(big.Int).And(n, new(big.Int).SetUint64(^uint64(0)))
	hi := new(big.Int).Rsh(n, 64)
	p := xdr.Int128Parts{Hi: xdr.Int64(hi.Int64()), Lo: xdr.Uint64(lo.Uint64())}
	return xdr.ScVal{Type: xdr.ScValTypeScvI128, I128: &p}, nil
}

func invocation(asset string, args []xdr.ScVal, auth []xdr.SorobanAuthorizationEntry, timeout time.Duration) (string, error) {
	contract, err := contractAddress(asset)
	if err != nil {
		return "", err
	}
	src := xdr.MustMuxedAddress(nullAccount)
	bounds := xdr.TimeBounds{MaxTime: xdr.TimePoint(time.Now().Add(timeout).Unix())}
	tx := xdr.Transaction{SourceAccount: src, Fee: inclusionFeeStroops, SeqNum: 1,
		Cond: xdr.Preconditions{Type: xdr.PreconditionTypePrecondTime, TimeBounds: &bounds},
		Operations: []xdr.Operation{{Body: xdr.OperationBody{Type: xdr.OperationTypeInvokeHostFunction, InvokeHostFunctionOp: &xdr.InvokeHostFunctionOp{
			HostFunction: xdr.HostFunction{Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract, InvokeContract: &xdr.InvokeContractArgs{
				ContractAddress: contract, FunctionName: "transfer", Args: args}}, Auth: auth}}}}}
	return xdr.MarshalBase64(xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTx, V1: &xdr.TransactionV1Envelope{Tx: tx}})
}

// SignAuthEntry signs an address credential for key until expiration, as
// stellar-sdk's authorizeEntry does.
func SignAuthEntry(passphrase string, e xdr.SorobanAuthorizationEntry, key *keypair.Full, expiration uint32) (xdr.SorobanAuthorizationEntry, error) {
	c, ok := e.Credentials.GetAddress()
	if !ok {
		return e, errors.New("not an address credential")
	}
	c.SignatureExpirationLedger = xdr.Uint32(expiration)
	payload, err := AuthPayload(passphrase, c, e.RootInvocation)
	if err != nil {
		return e, err
	}
	sig, err := key.Sign(payload[:])
	if err != nil {
		return e, err
	}
	pkBytes := xdr.MustAddress(key.Address()).Ed25519
	sym := func(s string) xdr.ScVal {
		v := xdr.ScSymbol(s)
		return xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &v}
	}
	bytesVal := func(b []byte) xdr.ScVal {
		v := xdr.ScBytes(b)
		return xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &v}
	}
	m := xdr.ScMap{{Key: sym("public_key"), Val: bytesVal(pkBytes[:])}, {Key: sym("signature"), Val: bytesVal(sig)}}
	mp := &m
	vec := xdr.ScVec{{Type: xdr.ScValTypeScvMap, Map: &mp}}
	vp := &vec
	c.Signature = xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &vp}
	e.Credentials = xdr.SorobanCredentials{Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddress, Address: &c}
	return e, nil
}

// NewPayment builds the payer's x402 payload: a SAC transfer whose only
// authorization, signed by payer, expires within maxTimeoutSeconds.
func NewPayment(ctx context.Context, rpc RPC, horizon Horizon, network string, payer *keypair.Full, r x402.Requirements) (string, error) {
	pass, err := Passphrase(network)
	if err != nil {
		return "", err
	}
	amount, ok := new(big.Int).SetString(r.Amount, 10)
	if !ok || amount.Sign() <= 0 {
		return "", errors.New("invalid amount")
	}
	from, err := scAddress(payer.Address())
	if err != nil {
		return "", err
	}
	to, err := anyAddress(r.PayTo)
	if err != nil {
		return "", err
	}
	amt, err := i128(amount)
	if err != nil {
		return "", err
	}
	args := []xdr.ScVal{from, to, amt}
	current, err := rpc.LatestLedger(ctx)
	if err != nil {
		return "", err
	}
	secs := horizon.LedgerSeconds(ctx)
	maxLedger := current + uint32((r.MaxTimeoutSeconds+secs-1)/secs)
	env, err := invocation(r.Asset, args, nil, 5*time.Minute)
	if err != nil {
		return "", err
	}
	sim, err := rpc.Simulate(ctx, env)
	if err != nil || !sim.Success() || len(sim.Results) != 1 {
		return "", errors.New("simulation failed")
	}
	var auth []xdr.SorobanAuthorizationEntry
	for _, raw := range sim.Results[0].Auth {
		var e xdr.SorobanAuthorizationEntry
		if err := xdr.SafeUnmarshalBase64(raw, &e); err != nil {
			return "", err
		}
		c, ok := e.Credentials.GetAddress()
		if !ok {
			return "", errors.New("unexpected source-account authorization")
		}
		if a, _ := c.Address.String(); a != payer.Address() {
			return "", errors.New("unexpected signer required: " + a)
		}
		if e, err = SignAuthEntry(pass, e, payer, maxLedger); err != nil {
			return "", err
		}
		auth = append(auth, e)
	}
	if len(auth) != 1 {
		return "", errors.New("expected exactly one payer authorization")
	}
	if env, err = invocation(r.Asset, args, auth, 5*time.Minute); err != nil {
		return "", err
	}
	if sim, err = rpc.Simulate(ctx, env); err != nil || !sim.Success() {
		return "", errors.New("signed simulation failed")
	}
	var data xdr.SorobanTransactionData
	if err := xdr.SafeUnmarshalBase64(sim.TransactionData, &data); err != nil {
		return "", err
	}
	fee, err := atoi64(sim.MinResourceFee)
	if err != nil {
		return "", err
	}
	var out xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(env, &out); err != nil {
		return "", err
	}
	out.V1.Tx.Fee = xdr.Uint32(inclusionFeeStroops + fee)
	out.V1.Tx.Ext = xdr.TransactionExt{V: 1, SorobanData: &data}
	return xdr.MarshalBase64(out)
}

func anyAddress(s string) (xdr.ScVal, error) {
	if len(s) > 0 && s[0] == 'C' {
		a, err := contractAddress(s)
		if err != nil {
			return xdr.ScVal{}, err
		}
		return xdr.ScVal{Type: xdr.ScValTypeScvAddress, Address: &a}, nil
	}
	return scAddress(s)
}
