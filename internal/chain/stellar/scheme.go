package stellar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	"github.com/andreimerlescu/concert/internal/x402"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

const (
	Pubnet  = "stellar:pubnet"
	Testnet = "stellar:testnet"

	DefaultMaxFeeStroops  = 50000
	inclusionFeeStroops   = 100
	expirationTolerance   = 2
	defaultTimeoutSeconds = 60
)

func Passphrase(caip string) (string, error) {
	switch caip {
	case Pubnet:
		return network.PublicNetworkPassphrase, nil
	case Testnet:
		return network.TestNetworkPassphrase, nil
	}
	return "", errors.New("unknown Stellar network")
}

// NativeAsset is the canonical native XLM Stellar Asset Contract address.
func NativeAsset(passphrase string) (string, error) {
	id, err := xdr.MustNewNativeAsset().ContractID(passphrase)
	if err != nil {
		return "", err
	}
	return strkey.Encode(strkey.VersionByteContract, id[:])
}

// Scheme verifies and settles "exact" XLM payments with one fee sponsor.
type Scheme struct {
	Network    string
	passphrase string
	RPC        RPC
	Horizon    Horizon
	Sponsor    *keypair.Full
	MaxFee     int64
	Poll       time.Duration
}

func New(network, rpcURL, horizonURL, sponsorSecret string, maxFee int64) (*Scheme, error) {
	pass, err := Passphrase(network)
	if err != nil {
		return nil, err
	}
	kp, err := keypair.ParseFull(sponsorSecret)
	if err != nil {
		return nil, errors.New("invalid Stellar sponsor secret")
	}
	if maxFee == 0 {
		maxFee = DefaultMaxFeeStroops
	}
	return &Scheme{Network: network, passphrase: pass, RPC: RPC{URL: rpcURL}, Horizon: Horizon{URL: horizonURL}, Sponsor: kp, MaxFee: maxFee, Poll: time.Second}, nil
}

func invalid(reason, payer string) x402.VerifyResponse { return x402.Invalid(reason, payer) }

// addressOf mirrors scValToNative for addresses: a strkey, or "" otherwise.
func addressOf(v xdr.ScVal) string {
	a, ok := v.GetAddress()
	if !ok {
		return ""
	}
	s, err := a.String()
	if err != nil {
		return ""
	}
	return s
}

func i128Of(v xdr.ScVal) (*big.Int, bool) {
	p, ok := v.GetI128()
	if !ok {
		return nil, false
	}
	n := new(big.Int).Lsh(big.NewInt(int64(p.Hi)), 64)
	return n.Add(n, new(big.Int).SetUint64(uint64(p.Lo))), true
}

func muxedAddress(m *xdr.MuxedAccount) string {
	if m == nil {
		return ""
	}
	a := m.ToAccountId()
	return a.Address()
}

type parsed struct {
	env   xdr.TransactionEnvelope
	tx    xdr.Transaction
	op    xdr.InvokeHostFunctionOp
	opSrc *xdr.MuxedAccount
	from  string
}

func decodeEnvelope(s string) (xdr.TransactionEnvelope, error) {
	var env xdr.TransactionEnvelope
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != s {
		return env, errors.New("invalid transaction encoding")
	}
	err = xdr.SafeUnmarshal(raw, &env)
	return env, err
}

func payloadTransaction(p x402.Payload) (string, error) {
	var body struct {
		Transaction string `json:"transaction"`
	}
	if err := json.Unmarshal(p.Payload, &body); err != nil || body.Transaction == "" {
		return "", errors.New("malformed payload")
	}
	return body.Transaction, nil
}

// AuthPayload is the hash an address credential signs: the
// HashIDPreimage for Soroban authorization on this network.
func AuthPayload(passphrase string, c xdr.SorobanAddressCredentials, invocation xdr.SorobanAuthorizedInvocation) ([32]byte, error) {
	pre := xdr.HashIdPreimage{Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization, SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{
		NetworkId: sha256.Sum256([]byte(passphrase)), Nonce: c.Nonce, SignatureExpirationLedger: c.SignatureExpirationLedger, Invocation: invocation,
	}}
	b, err := pre.MarshalBinary()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// accountSignatures checks the standard account-credential signature: a
// vector of {public_key, signature} maps, every one valid over payload, and
// one of them by the account's own key. Signer weights are enforced by the
// network; accounts that authorize only through other signers are not
// supported.
func accountSignatures(sig xdr.ScVal, payload [32]byte, account []byte) bool {
	byAccount := false
	vec, ok := sig.GetVec()
	if !ok || vec == nil || len(*vec) == 0 {
		return false
	}
	for _, e := range *vec {
		m, ok := e.GetMap()
		if !ok || m == nil || len(*m) != 2 {
			return false
		}
		var pub, s []byte
		for _, kv := range *m {
			sym, _ := kv.Key.GetSym()
			b, ok := kv.Val.GetBytes()
			if !ok {
				return false
			}
			switch string(sym) {
			case "public_key":
				pub = b
			case "signature":
				s = b
			}
		}
		if len(pub) != ed25519.PublicKeySize || len(s) != ed25519.SignatureSize || !ed25519.Verify(pub, payload[:], s) {
			return false
		}
		byAccount = byAccount || bytes.Equal(pub, account)
	}
	return byAccount
}

func (s *Scheme) safety(addr string) bool { return s.Sponsor != nil && addr == s.Sponsor.Address() }

// SetPassphrase configures an NFT-only scheme, which has no sponsor.
func (s *Scheme) SetPassphrase(p string) { s.passphrase = p }

func (s *Scheme) verify(ctx context.Context, p x402.Payload, r x402.Requirements) (*parsed, *Simulation, x402.VerifyResponse) {
	fail := func(reason, payer string) (*parsed, *Simulation, x402.VerifyResponse) {
		return nil, nil, invalid(reason, payer)
	}
	switch {
	case p.Version != 2:
		return fail("invalid_x402_version", "")
	case p.Accepted.Scheme != "exact" || r.Scheme != "exact":
		return fail("unsupported_scheme", "")
	case r.Network != p.Accepted.Network:
		return fail("network_mismatch", "")
	case r.Network != s.Network:
		return fail("invalid_network", "")
	}
	enc, err := payloadTransaction(p)
	if err != nil {
		return fail("invalid_exact_stellar_payload_malformed", "")
	}
	env, err := decodeEnvelope(enc)
	if err != nil || env.Type != xdr.EnvelopeTypeEnvelopeTypeTx || env.V1 == nil {
		return fail("invalid_exact_stellar_payload_malformed", "")
	}
	tx := env.V1.Tx
	if len(tx.Operations) != 1 || tx.Operations[0].Body.Type != xdr.OperationTypeInvokeHostFunction {
		return fail("invalid_exact_stellar_payload_wrong_operation", "")
	}
	op := tx.Operations[0]
	if s.safety(muxedAddress(op.SourceAccount)) || s.safety(muxedAddress(&tx.SourceAccount)) {
		return fail("invalid_exact_stellar_payload_unsafe_tx_or_op_source", "")
	}
	ihf := op.Body.MustInvokeHostFunctionOp()
	if ihf.HostFunction.Type != xdr.HostFunctionTypeHostFunctionTypeInvokeContract {
		return fail("invalid_exact_stellar_payload_wrong_operation", "")
	}
	call := ihf.HostFunction.MustInvokeContract()
	contract, err := call.ContractAddress.String()
	if err != nil || contract != r.Asset {
		return fail("invalid_exact_stellar_payload_wrong_asset", "")
	}
	if string(call.FunctionName) != "transfer" || len(call.Args) != 3 {
		return fail("invalid_exact_stellar_payload_wrong_function_name", "")
	}
	from, to := addressOf(call.Args[0]), addressOf(call.Args[1])
	if from == "" {
		return fail("invalid_exact_stellar_payload_malformed", "")
	}
	if s.safety(from) {
		return fail("invalid_exact_stellar_payload_facilitator_is_payer", "")
	}
	if to != r.PayTo {
		return fail("invalid_exact_stellar_payload_wrong_recipient", from)
	}
	want, ok := new(big.Int).SetString(r.Amount, 10)
	amount, isI128 := i128Of(call.Args[2])
	if !ok || !isI128 || amount.Cmp(want) != 0 {
		return fail("invalid_exact_stellar_payload_wrong_amount", from)
	}
	sim, err := s.RPC.Simulate(ctx, enc)
	if err != nil || !sim.Success() {
		return fail("invalid_exact_stellar_payload_simulation_failed", from)
	}
	minFee, err := atoi64(sim.MinResourceFee)
	if err != nil || minFee+inclusionFeeStroops > s.MaxFee {
		return fail("invalid_exact_stellar_payload_fee_exceeds_maximum", from)
	}
	if reason := validateEvents(sim.Events, from, r.PayTo, want, r.Asset); reason != "" {
		return fail(reason, from)
	}
	current, err := s.RPC.LatestLedger(ctx)
	if err != nil {
		return fail("unexpected_verify_error", from)
	}
	timeout := r.MaxTimeoutSeconds
	if timeout == 0 {
		timeout = defaultTimeoutSeconds
	}
	secs := s.Horizon.LedgerSeconds(ctx)
	maxLedger := current + uint32((timeout+secs-1)/secs)
	if len(ihf.Auth) == 0 {
		return fail("invalid_exact_stellar_payload_no_auth_entries", from)
	}
	signed, pending := map[string]bool{}, map[string]bool{}
	for _, a := range ihf.Auth {
		c, ok := a.Credentials.GetAddress()
		if !ok { // AddressV2 and delegated credentials are not accepted
			return fail("invalid_exact_stellar_payload_unsupported_credential_type", from)
		}
		addr, err := c.Address.String()
		if err != nil {
			return fail("unexpected_verify_error", from)
		}
		if s.safety(addr) {
			return fail("invalid_exact_stellar_payload_facilitator_in_auth", from)
		}
		if uint32(c.SignatureExpirationLedger) > maxLedger+expirationTolerance {
			return fail("invalid_exact_stellar_signature_expiration_too_far", from)
		}
		if len(a.RootInvocation.SubInvocations) > 0 {
			return fail("invalid_exact_stellar_payload_has_subinvocations", from)
		}
		if c.Signature.Type == xdr.ScValTypeScvVoid {
			pending[addr] = true
			continue
		}
		signed[addr] = true
		// Stricter than @x402/stellar, which relies on simulation alone:
		// an account (G…) credential's signatures must verify here too.
		if c.Address.Type == xdr.ScAddressTypeScAddressTypeAccount {
			key := c.Address.AccountId.Ed25519
			payload, err := AuthPayload(s.passphrase, c, a.RootInvocation)
			if err != nil || key == nil || !accountSignatures(c.Signature, payload, key[:]) {
				return fail("invalid_exact_stellar_payload_bad_payer_signature", from)
			}
		}
	}
	if !signed[from] {
		return fail("invalid_exact_stellar_payload_missing_payer_signature", from)
	}
	if len(pending) > 0 {
		return fail("invalid_exact_stellar_payload_unexpected_pending_signatures", from)
	}
	return &parsed{env: env, tx: tx, op: ihf, opSrc: op.SourceAccount, from: from}, sim, x402.Valid(from)
}

func validateEvents(events []string, from, to string, amount *big.Int, asset string) string {
	transfers := 0
	for _, raw := range events {
		var d xdr.DiagnosticEvent
		if err := xdr.SafeUnmarshalBase64(raw, &d); err != nil {
			return "unexpected_verify_error"
		}
		e := d.Event
		if e.Type != xdr.ContractEventTypeContract {
			continue
		}
		body, ok := e.Body.GetV0()
		if !ok {
			return "unexpected_verify_error"
		}
		if len(body.Topics) < 3 {
			return "invalid_exact_stellar_payload_event_not_transfer"
		}
		sym, ok := body.Topics[0].GetSym()
		if !ok || string(sym) != "transfer" {
			return "invalid_exact_stellar_payload_event_not_transfer"
		}
		if e.ContractId == nil {
			return "invalid_exact_stellar_payload_event_missing_contract_id"
		}
		id := *e.ContractId
		addr, err := strkey.Encode(strkey.VersionByteContract, id[:])
		if err != nil || addr != asset {
			return "invalid_exact_stellar_payload_event_wrong_asset"
		}
		transfers++
		if transfers > 1 {
			continue
		}
		if addressOf(body.Topics[1]) != from {
			return "invalid_exact_stellar_payload_event_wrong_from"
		}
		if addressOf(body.Topics[2]) != to {
			return "invalid_exact_stellar_payload_event_wrong_to"
		}
		if n, ok := i128Of(body.Data); !ok || n.Cmp(amount) != 0 {
			return "invalid_exact_stellar_payload_event_wrong_amount"
		}
	}
	switch {
	case transfers == 0:
		return "invalid_exact_stellar_payload_no_transfer_events"
	case transfers > 1:
		return "invalid_exact_stellar_payload_multiple_transfers"
	}
	return ""
}

func (s *Scheme) Verify(ctx context.Context, p x402.Payload, r x402.Requirements) x402.VerifyResponse {
	_, _, v := s.verify(ctx, p, r)
	return v
}

// Rebuild is the sponsor's settlement transaction: the payer's operation and
// signed authorizations with the sponsor as source, the simulated resources,
// and the payer transaction's preconditions and memo, as @x402/stellar
// builds it.
func (s *Scheme) Rebuild(pt *parsed, sim *Simulation, sequence int64, timeout int, now time.Time) (xdr.TransactionEnvelope, error) {
	var data xdr.SorobanTransactionData
	if err := xdr.SafeUnmarshalBase64(sim.TransactionData, &data); err != nil {
		return xdr.TransactionEnvelope{}, err
	}
	src, err := xdr.AddressToMuxedAccount(s.Sponsor.Address())
	if err != nil {
		return xdr.TransactionEnvelope{}, err
	}
	if timeout == 0 {
		timeout = defaultTimeoutSeconds
	}
	bounds := xdr.TimeBounds{MinTime: 0, MaxTime: xdr.TimePoint(now.Unix() + int64(timeout))}
	cond := xdr.Preconditions{Type: xdr.PreconditionTypePrecondTime, TimeBounds: &bounds}
	if v2, ok := pt.tx.Cond.GetV2(); ok {
		v2.TimeBounds = &bounds
		cond = xdr.Preconditions{Type: xdr.PreconditionTypePrecondV2, V2: &v2}
	}
	tx := xdr.Transaction{
		SourceAccount: src,
		Fee:           xdr.Uint32(inclusionFeeStroops + int64(data.ResourceFee)),
		SeqNum:        xdr.SequenceNumber(sequence + 1),
		Cond:          cond,
		Memo:          pt.tx.Memo,
		Operations: []xdr.Operation{{SourceAccount: pt.opSrc, Body: xdr.OperationBody{
			Type: xdr.OperationTypeInvokeHostFunction, InvokeHostFunctionOp: &xdr.InvokeHostFunctionOp{HostFunction: pt.op.HostFunction, Auth: pt.op.Auth}}}},
		Ext: xdr.TransactionExt{V: 1, SorobanData: &data},
	}
	env := xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTx, V1: &xdr.TransactionV1Envelope{Tx: tx}}
	hash, err := network.HashTransactionInEnvelope(env, s.passphrase)
	if err != nil {
		return env, err
	}
	sig, err := s.Sponsor.SignDecorated(hash[:])
	if err != nil {
		return env, err
	}
	env.V1.Signatures = []xdr.DecoratedSignature{sig}
	return env, nil
}

// Settle re-verifies, rebuilds with the sponsor as source, submits and
// polls for up to maxTimeoutSeconds. Anything short of SUCCESS is reported
// as not successful, with the hash when one exists, for reconciliation.
func (s *Scheme) Settle(ctx context.Context, p x402.Payload, r x402.Requirements) (x402.SettleResponse, error) {
	if s.Sponsor == nil {
		return x402.SettleResponse{}, errors.New("no Stellar sponsor configured")
	}
	pt, sim, v := s.verify(ctx, p, r)
	if !v.Valid {
		return x402.SettleResponse{Network: r.Network, Payer: v.Payer, ErrorReason: v.Reason}, nil
	}
	fail := func(hash, reason string) (x402.SettleResponse, error) {
		return x402.SettleResponse{Network: r.Network, Payer: pt.from, Transaction: hash, ErrorReason: reason}, nil
	}
	seq, err := s.RPC.Sequence(ctx, xdr.MustAddress(s.Sponsor.Address()))
	if err != nil {
		return fail("", "settle_exact_stellar_account_unavailable")
	}
	env, err := s.Rebuild(pt, sim, seq, r.MaxTimeoutSeconds, time.Now())
	if err != nil {
		return fail("", "settle_exact_stellar_transaction_signing_failed")
	}
	b64, err := xdr.MarshalBase64(env)
	if err != nil {
		return fail("", "settle_exact_stellar_transaction_signing_failed")
	}
	sent, err := s.RPC.Send(ctx, b64)
	if err != nil || sent.Status != "PENDING" {
		return fail("", "settle_exact_stellar_transaction_submission_failed")
	}
	attempts := r.MaxTimeoutSeconds
	if attempts == 0 {
		attempts = defaultTimeoutSeconds
	}
	for i := 0; i < attempts; i++ {
		st, err := s.RPC.Transaction(ctx, sent.Hash)
		if err == nil && st.Status == "SUCCESS" {
			return x402.SettleResponse{Success: true, Transaction: sent.Hash, Network: r.Network, Payer: pt.from}, nil
		}
		if err == nil && st.Status == "FAILED" {
			return fail(sent.Hash, "settle_exact_stellar_transaction_failed")
		}
		select {
		case <-ctx.Done():
			return x402.SettleResponse{}, ctx.Err()
		case <-time.After(s.Poll):
		}
	}
	return fail(sent.Hash, "settle_exact_stellar_transaction_failed")
}

// Reconcile checks that the sponsor transaction hash is a successful
// transaction carrying exactly this payload's invocation and signed
// authorizations. It never submits anything.
func (s *Scheme) Reconcile(ctx context.Context, p x402.Payload, r x402.Requirements, hash string) (string, error) {
	if b, err := hex.DecodeString(hash); err != nil || len(b) != 32 {
		return "", errors.New("Stellar recovery requires the sponsor transaction hash")
	}
	enc, err := payloadTransaction(p)
	if err != nil {
		return "", err
	}
	original, err := decodeEnvelope(enc)
	if err != nil || original.V1 == nil || len(original.V1.Tx.Operations) != 1 {
		return "", errors.New("invalid journaled payload")
	}
	st, err := s.RPC.Transaction(ctx, hash)
	if err != nil {
		return "", err
	}
	if st.Status != "SUCCESS" {
		return "", errors.New("payment not finalized")
	}
	var env xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(st.EnvelopeXDR, &env); err != nil {
		return "", err
	}
	got, err := network.HashTransactionInEnvelope(env, s.passphrase)
	if err != nil || hex.EncodeToString(got[:]) != hash {
		return "", errors.New("transaction hash mismatch")
	}
	if env.Type == xdr.EnvelopeTypeEnvelopeTypeTxFeeBump {
		inner := env.FeeBump.Tx.InnerTx
		env = xdr.TransactionEnvelope{Type: inner.Type, V1: inner.V1}
	}
	if env.V1 == nil || len(env.V1.Tx.Operations) != 1 {
		return "", errors.New("unexpected settlement transaction")
	}
	a, _ := env.V1.Tx.Operations[0].Body.GetInvokeHostFunctionOp()
	b, _ := original.V1.Tx.Operations[0].Body.GetInvokeHostFunctionOp()
	ab, err1 := a.MarshalBinary()
	bb, err2 := b.MarshalBinary()
	if err1 != nil || err2 != nil || !bytes.Equal(ab, bb) {
		return "", errors.New("ledger transaction does not contain this signed authorization")
	}
	return hash, nil
}
