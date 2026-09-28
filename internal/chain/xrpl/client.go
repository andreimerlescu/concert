package xrpl

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"

	"github.com/andreimerlescu/concert/internal/x402"
)

// NewPaymentBlob builds and signs the payer's native XRP Payment for r as
// @x402/xrpl's client does with xrpl.js autofill: current Sequence, the
// widest LastLedgerSequence the facilitator accepts, the network fee, and
// InvoiceID, DestinationTag and NetworkID when the terms call for them.
// Only the "sequence" transfer method is supported; the reference client
// never creates tickets either. It returns the uppercase hex blob.
func NewPaymentBlob(ctx context.Context, l Ledger, key *Key, r x402.Requirements) (string, error) {
	if r.Scheme != "exact" || r.Asset != "XRP" {
		return "", errors.New("only exact native XRP payments are supported")
	}
	if m, ok := r.Extra["assetTransferMethod"]; ok && m != "sequence" {
		return "", errors.New("only the sequence transfer method is supported")
	}
	dest, err := DecodeAddress(r.PayTo)
	if err != nil {
		return "", err
	}
	amount, err := strconv.ParseUint(r.Amount, 10, 64)
	if err != nil || amount == 0 || amount > 1e17 {
		return "", errors.New("invalid XRP amount")
	}
	id, err := NetworkNumber(r.Network)
	if err != nil {
		return "", err
	}
	if err := CheckNetwork(ctx, l, r.Network); err != nil {
		return "", err
	}
	current, err := l.LedgerIndex(ctx)
	if err != nil {
		return "", err
	}
	info, err := l.AccountInfo(ctx, key.Address)
	if err != nil {
		return "", err
	}
	fee, err := l.Fee(ctx)
	if err != nil {
		return "", err
	}
	b := NewPayment().Account("Account", AccountID(key.Public)).Account("Destination", dest).
		Drops("Amount", amount).Drops("Fee", fee).U32("Flags", 0).U32("Sequence", info.Sequence).
		U32("LastLedgerSequence", MaxLastLedger(current, r.MaxTimeoutSeconds)).Blob("SigningPubKey", key.Public)
	if raw, ok := r.Extra["invoiceId"]; ok {
		inv, _ := raw.(string)
		if inv == "" {
			return "", errors.New("invalid invoiceId")
		}
		h, _ := hex.DecodeString(InvoiceIDField(inv))
		b.Hash256("InvoiceID", h)
	}
	if raw, ok := r.Extra["destinationTag"]; ok {
		n, isNum := raw.(float64)
		if !isNum || n != math.Trunc(n) || n < 0 || n > maxDestinationTag {
			return "", errors.New("extra.destinationTag must be a 32-bit unsigned integer")
		}
		b.U32("DestinationTag", uint32(n))
	}
	if id > 1024 {
		b.U32("NetworkID", id)
	}
	sig := key.Sign(append(append([]byte{}, prefixSign...), b.Bytes()...))
	return strings.ToUpper(hex.EncodeToString(b.Blob("TxnSignature", sig).Bytes())), nil
}
