package xrpl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/andreimerlescu/concert/internal/x402"
)

// Constants from @x402/xrpl.
const (
	DefaultMaxFeeDrops   = 10000
	ledgerCloseSeconds   = 5
	ledgerTolerance      = 2
	tfPartialPayment     = 0x00020000
	lsfDisableMaster     = 0x00100000
	maxDestinationTag    = math.MaxUint32
	settlementTTL        = 120 * time.Second
	settleLedgerInterval = time.Second
)

// Scheme verifies and settles "exact" native XRP payments on one network.
type Scheme struct {
	Network     string
	Ledger      Ledger
	MaxFeeDrops uint64
	Poll        time.Duration

	mu      sync.Mutex
	pending map[string]time.Time // duplicate-settlement guard, like @x402/xrpl's cache
}

func New(network, url string, maxFeeDrops uint64) *Scheme {
	if maxFeeDrops == 0 {
		maxFeeDrops = DefaultMaxFeeDrops
	}
	return &Scheme{Network: network, Ledger: RPC{URL: url}, MaxFeeDrops: maxFeeDrops, Poll: settleLedgerInterval, pending: map[string]time.Time{}}
}

func extraString(r x402.Requirements, key string) (string, bool) {
	v, ok := r.Extra[key]
	if !ok {
		return "", false
	}
	s, _ := v.(string)
	return s, true
}

func extraEqual(a, b x402.Requirements, key string) bool {
	x, y := a.Extra[key], b.Extra[key]
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return string(xb) == string(yb)
}

func (s *Scheme) envelope(p x402.Payload, r x402.Requirements) string {
	a := p.Accepted
	switch {
	case p.Version != 2:
		return "invalid_x402_version"
	case a.Scheme != "exact" || r.Scheme != "exact":
		return "unsupported_scheme"
	case !strings.HasPrefix(r.Network, "xrpl:") || !strings.HasPrefix(a.Network, "xrpl:"):
		return "invalid_network"
	case a.Network != r.Network:
		return "invalid_exact_xrpl_network_mismatch"
	case a.Asset != r.Asset:
		return "invalid_exact_xrpl_asset_mismatch"
	case a.Amount != r.Amount:
		return "invalid_exact_xrpl_amount_mismatch"
	case a.PayTo != r.PayTo:
		return "invalid_exact_xrpl_pay_to_mismatch"
	case a.MaxTimeoutSeconds != r.MaxTimeoutSeconds:
		return "invalid_exact_xrpl_max_timeout_mismatch"
	case r.Extra["areFeesSponsored"] != false || a.Extra["areFeesSponsored"] != false:
		return "invalid_exact_xrpl_fees_sponsored_unsupported"
	case !extraEqual(a, r, "invoiceId"):
		return "invalid_exact_xrpl_invoice_mismatch"
	case !extraEqual(a, r, "destinationTag"):
		return "invalid_exact_xrpl_destination_tag_mismatch"
	case r.Asset != "XRP":
		return "invalid_exact_xrpl_asset_unsupported" // Concert settles native XRP only
	}
	return ""
}

func transferMethod(p x402.Payload, r x402.Requirements) (string, string) {
	valid := func(v any) bool { return v == "sequence" || v == "ticketSequence" }
	req, hasReq := r.Extra["assetTransferMethod"]
	acc, hasAcc := p.Accepted.Extra["assetTransferMethod"]
	if (hasReq && !valid(req)) || (hasAcc && !valid(acc)) {
		return "", "invalid_exact_xrpl_asset_transfer_method"
	}
	method := "sequence"
	if hasAcc {
		method = acc.(string)
	} else if hasReq {
		method = req.(string)
	}
	if hasReq && method != req {
		return "", "invalid_exact_xrpl_asset_transfer_method_mismatch"
	}
	return method, ""
}

func blobOf(p x402.Payload) (string, error) {
	var body map[string]json.RawMessage
	if err := json.Unmarshal(p.Payload, &body); err != nil {
		return "", err
	}
	var blob string
	if err := json.Unmarshal(body["signedTxBlob"], &blob); err != nil || blob == "" || len(body) != 1 {
		return "", errors.New("XRPL exact payload requires exactly signedTxBlob")
	}
	return blob, nil
}

// InvoiceIDField is SHA-256 of the invoice ID, uppercase hex.
func InvoiceIDField(invoiceID string) string {
	h := sha256.Sum256([]byte(invoiceID))
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

func (s *Scheme) structure(t *Tx, r x402.Requirements) string {
	dest, err := DecodeAddress(r.PayTo)
	if err != nil {
		return "invalid_exact_xrpl_payload_destination_mismatch"
	}
	if d, ok := t.Accounts["Destination"]; !ok || d != dest {
		return "invalid_exact_xrpl_payload_destination_mismatch"
	}
	if tag, ok := r.Extra["destinationTag"]; ok {
		n, isNum := tag.(float64)
		if !isNum || n != math.Trunc(n) || n < 0 || n > maxDestinationTag {
			return "invalid_exact_xrpl_destination_tag_malformed"
		}
		if got, ok := t.U32("DestinationTag"); !ok || float64(got) != n {
			return "invalid_exact_xrpl_payload_destination_tag_mismatch"
		}
	}
	if t.Has("Delegate") {
		return "invalid_exact_xrpl_payload_delegate_not_allowed"
	}
	if t.Has("Signers") {
		return "invalid_exact_xrpl_payload_multisig_not_supported"
	}
	id, err := NetworkNumber(r.Network)
	if err != nil {
		return "invalid_network"
	}
	nid, hasNID := t.U32("NetworkID")
	if id <= 1024 && hasNID {
		return "invalid_exact_xrpl_payload_network_id_for_standard_network"
	}
	if id > 1024 && nid != id {
		return "invalid_exact_xrpl_payload_network_id_mismatch"
	}
	amt, ok := t.Amounts["Amount"]
	if !ok || !amt.Native {
		return "invalid_exact_xrpl_payload_amount_xrp"
	}
	want, ok := new(big.Int).SetString(r.Amount, 10)
	if !ok || new(big.Int).SetUint64(amt.Drops).Cmp(want) != 0 {
		return "invalid_exact_xrpl_payload_amount_mismatch"
	}
	if t.Has("SendMax") {
		return "invalid_exact_xrpl_payload_sendmax_not_allowed"
	}
	if t.Has("Paths") {
		return "invalid_exact_xrpl_payload_paths_not_allowed"
	}
	if t.Has("DeliverMin") {
		return "invalid_exact_xrpl_payload_delivermin_not_allowed"
	}
	if f, _ := t.U32("Flags"); f&tfPartialPayment != 0 {
		return "invalid_exact_xrpl_payload_partial_payment_not_allowed"
	}
	if t.Has("Memos") {
		return "invalid_exact_xrpl_payload_memos_not_allowed"
	}
	if raw, ok := r.Extra["invoiceId"]; ok {
		inv, isStr := raw.(string)
		if !isStr || inv == "" {
			return "invalid_exact_xrpl_payload_invoice_missing"
		}
		if t.InvoiceID == nil {
			return "invalid_exact_xrpl_payload_invoice_missing"
		}
		if upperHex(t.InvoiceID) != InvoiceIDField(inv) {
			return "invalid_exact_xrpl_payload_invoice_id_mismatch"
		}
	}
	fee, ok := t.Amounts["Fee"]
	if !ok || !fee.Native {
		return "invalid_exact_xrpl_payload_fee_missing"
	}
	if fee.Drops > s.MaxFeeDrops {
		return "invalid_exact_xrpl_payload_fee_too_high"
	}
	// Stricter than @x402/xrpl: a field this codec cannot interpret is refused.
	if len(t.Unknown) > 0 {
		return "invalid_exact_xrpl_payload_unsupported_field"
	}
	return ""
}

func sequencingFields(t *Tx, method string) string {
	seq, hasSeq := t.U32("Sequence")
	_, hasTicket := t.U32("TicketSequence")
	if method == "sequence" {
		if hasTicket {
			return "invalid_exact_xrpl_payload_ticket_sequence_not_allowed"
		}
		if !hasSeq || seq == 0 {
			return "invalid_exact_xrpl_payload_sequence_missing"
		}
		return ""
	}
	if !hasSeq || seq != 0 {
		return "invalid_exact_xrpl_payload_sequence_must_be_zero"
	}
	if !hasTicket {
		return "invalid_exact_xrpl_payload_ticket_sequence_missing"
	}
	return ""
}

// MaxLastLedger is the latest LastLedgerSequence accepted for a timeout.
func MaxLastLedger(current uint32, maxTimeoutSeconds int) uint32 {
	return current + uint32((maxTimeoutSeconds+ledgerCloseSeconds-1)/ledgerCloseSeconds) + ledgerTolerance
}

// Verify applies every @x402/xrpl check, in the same order, without
// submitting anything.
func (s *Scheme) Verify(ctx context.Context, p x402.Payload, r x402.Requirements) x402.VerifyResponse {
	t, method, reason := s.verifyTx(ctx, p, r)
	payer := ""
	if t != nil {
		if a, ok := t.Accounts["Account"]; ok {
			payer = EncodeAccountID(a)
		}
	}
	if reason != "" {
		return x402.Invalid(reason, payer)
	}
	_ = method
	return x402.Valid(payer)
}

func (s *Scheme) verifyTx(ctx context.Context, p x402.Payload, r x402.Requirements) (*Tx, string, string) {
	if reason := s.envelope(p, r); reason != "" {
		return nil, "", reason
	}
	method, reason := transferMethod(p, r)
	if reason != "" {
		return nil, "", reason
	}
	blob, err := blobOf(p)
	if err != nil {
		return nil, "", "invalid_exact_xrpl_facilitator_error"
	}
	t, err := Decode(blob)
	if err != nil {
		return nil, "", "invalid_exact_xrpl_facilitator_error"
	}
	if !canonicalPubKey(t.SigningPubKey) {
		return nil, "", "invalid_exact_xrpl_payload_signing_pub_key"
	}
	if !t.VerifySignature() {
		return nil, "", "invalid_exact_xrpl_payload_signature"
	}
	if t.TransactionType == nil || *t.TransactionType != 0 {
		return nil, "", "invalid_exact_xrpl_payload_transaction_type"
	}
	if _, ok := t.Accounts["Account"]; !ok {
		return nil, "", "invalid_exact_xrpl_facilitator_error"
	}
	if reason := s.structure(t, r); reason != "" {
		return t, "", reason
	}
	if reason := sequencingFields(t, method); reason != "" {
		return t, "", reason
	}
	if err := CheckNetwork(ctx, s.Ledger, r.Network); err != nil {
		return t, "", "invalid_exact_xrpl_facilitator_error"
	}
	current, err := s.Ledger.LedgerIndex(ctx)
	if err != nil {
		return t, "", "invalid_exact_xrpl_facilitator_error"
	}
	last, ok := t.U32("LastLedgerSequence")
	switch {
	case !ok:
		return t, "", "invalid_exact_xrpl_payload_lastledgersequence_missing"
	case last <= current:
		return t, "", "invalid_exact_xrpl_payload_expired"
	case last > MaxLastLedger(current, r.MaxTimeoutSeconds):
		return t, "", "invalid_exact_xrpl_payload_lastledgersequence_too_large"
	}
	account := EncodeAccountID(t.Accounts["Account"])
	info, err := s.Ledger.AccountInfo(ctx, account)
	if err != nil {
		return t, "", "invalid_exact_xrpl_facilitator_error"
	}
	signer := AddressOf(t.SigningPubKey)
	if !(info.RegularKey == signer || (signer == account && info.Flags&lsfDisableMaster == 0)) {
		return t, "", "invalid_exact_xrpl_payload_signer_not_authorized"
	}
	if method == "sequence" {
		seq, _ := t.U32("Sequence")
		if seq != info.Sequence {
			return t, "", "invalid_exact_xrpl_payload_sequence_not_current"
		}
	} else {
		ticket, _ := t.U32("TicketSequence")
		ok, err := s.Ledger.TicketAvailable(ctx, account, ticket)
		if err != nil {
			return t, "", "invalid_exact_xrpl_facilitator_error"
		}
		if !ok {
			return t, "", "invalid_exact_xrpl_payload_ticket_not_available"
		}
	}
	engine, err := s.Ledger.Simulate(ctx, t.JSON("TxnSignature", "SigningPubKey", "Signers"))
	if err != nil {
		return t, "", "invalid_exact_xrpl_facilitator_error"
	}
	if engine != "tesSUCCESS" {
		return t, "", "invalid_exact_xrpl_payload_simulation_failed: " + engine
	}
	return t, method, ""
}

func (s *Scheme) duplicate(hash string, ttl time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, exp := range s.pending {
		if now.After(exp) {
			delete(s.pending, k)
		}
	}
	if _, ok := s.pending[hash]; ok {
		return true
	}
	s.pending[hash] = now.Add(ttl)
	return false
}

// Settle re-verifies, submits once and waits until the transaction is in a
// validated ledger or its LastLedgerSequence has passed. Any outcome other
// than validated tesSUCCESS is reported as not successful.
func (s *Scheme) Settle(ctx context.Context, p x402.Payload, r x402.Requirements) (x402.SettleResponse, error) {
	t, _, reason := s.verifyTx(ctx, p, r)
	payer := ""
	if t != nil {
		payer = EncodeAccountID(t.Accounts["Account"])
	}
	fail := func(tx, reason string) (x402.SettleResponse, error) {
		return x402.SettleResponse{Transaction: tx, Network: r.Network, Payer: payer, ErrorReason: reason}, nil
	}
	if reason != "" {
		return fail("", reason)
	}
	hash := t.Hash()
	if s.duplicate(hash, time.Duration(r.MaxTimeoutSeconds)*time.Second+settlementTTL) {
		return fail("", "duplicate_settlement")
	}
	blob, _ := blobOf(p)
	prelim, err := s.Ledger.Submit(ctx, blob)
	if err != nil {
		return fail(hash, "transaction_failed: submit")
	}
	if strings.HasPrefix(prelim, "tem") {
		return fail(hash, "transaction_failed: "+prelim)
	}
	last, _ := t.U32("LastLedgerSequence")
	for {
		select {
		case <-ctx.Done():
			return x402.SettleResponse{}, ctx.Err()
		case <-time.After(s.Poll):
		}
		latest, err := s.Ledger.LedgerIndex(ctx)
		if err == nil && latest > last {
			// Checked before the lookup, as xrpl.js does; the gateway records
			// this as unknown for reconciliation.
			return fail(hash, "transaction_failed: LastLedgerSequence passed; preliminary "+prelim)
		}
		res, err := s.Ledger.Tx(ctx, hash)
		if err != nil || !res.Validated {
			continue
		}
		if res.Result != "tesSUCCESS" {
			return fail(hash, "transaction_failed: "+res.Result)
		}
		return x402.SettleResponse{Success: true, Transaction: hash, Network: r.Network, Payer: payer}, nil
	}
}
