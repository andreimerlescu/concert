package xrpl

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/andreimerlescu/concert/internal/x402"
)

// OwnsNFT verifies a ripple-keypairs signature over the challenge, checks
// that the signing key currently controls address (unless its master key is
// disabled, or as its RegularKey), and searches the validated account_nfts
// pages for collection "issuer:taxon" (and token, when given). Multisigned
// accounts are not supported. Returns the NFTokenID.
func (s *Scheme) OwnsNFT(ctx context.Context, address, collection, token, publicKeyHex, message string, signature []byte) (string, error) {
	signer, ok := VerifyMessage(publicKeyHex, message, signature)
	if !ok {
		return "", errors.New("invalid signature")
	}
	if err := CheckNetwork(ctx, s.Ledger, s.Network); err != nil {
		return "", err
	}
	info, err := s.Ledger.AccountInfo(ctx, address)
	if err != nil {
		return "", err
	}
	if !((signer == address && info.Flags&lsfDisableMaster == 0) || info.RegularKey == signer) {
		return "", errors.New("key is not currently authorized")
	}
	issuer, taxonText, found := strings.Cut(collection, ":")
	taxon, err := strconv.ParseUint(taxonText, 10, 32)
	if !found || err != nil || !ValidAddress(issuer) {
		return "", errors.New("invalid collection")
	}
	var marker any
	// Bounded pagination: an incomplete search never grants.
	for page := 0; page < 100; page++ {
		nfts, next, err := s.Ledger.AccountNFTs(ctx, address, marker)
		if err != nil {
			return "", err
		}
		for _, n := range nfts {
			if n.Issuer == issuer && uint64(n.NFTokenTaxon) == taxon && (token == "" || n.NFTokenID == token) {
				return n.NFTokenID, nil
			}
		}
		if next == nil {
			break
		}
		marker = next
	}
	return "", errors.New("no matching NFT")
}

// Reconcile confirms that a journaled authorization settled: the signed
// Payment pays exactly the requirement, and its hash is validated with
// tesSUCCESS and the exact delivered amount. It never submits anything.
func (s *Scheme) Reconcile(ctx context.Context, p x402.Payload, r x402.Requirements, payer string) (string, error) {
	blob, err := blobOf(p)
	if err != nil {
		return "", err
	}
	t, err := Decode(blob)
	if err != nil {
		return "", err
	}
	dest, err := DecodeAddress(r.PayTo)
	if err != nil {
		return "", err
	}
	amt := t.Amounts["Amount"]
	flags, _ := t.U32("Flags")
	if t.TransactionType == nil || *t.TransactionType != 0 || EncodeAccountID(t.Accounts["Account"]) != payer ||
		t.Accounts["Destination"] != dest || !amt.Native || strconv.FormatUint(amt.Drops, 10) != r.Amount || flags&tfPartialPayment != 0 {
		return "", errors.New("payment terms mismatch")
	}
	if err := CheckNetwork(ctx, s.Ledger, r.Network); err != nil {
		return "", err
	}
	res, err := s.Ledger.Tx(ctx, t.Hash())
	if err != nil {
		return "", err
	}
	if !res.Validated || res.Result != "tesSUCCESS" || res.DeliveredDrops != r.Amount {
		return "", errors.New("exact payment not finalized")
	}
	return t.Hash(), nil
}
