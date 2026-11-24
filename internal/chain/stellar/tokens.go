package stellar

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// AssetKind classifies a Stellar asset identifier.
type AssetKind int

const (
	AssetNative     AssetKind = iota // "XLM" or native SAC contract ID
	AssetClassic                     // "CODE:ISSUER"
	AssetSorobanSAC                  // "C..." non-native Soroban token contract
)

// ParsedAsset is a normalized Stellar asset descriptor.
type ParsedAsset struct {
	Kind       AssetKind
	Code       string // "XLM" or 1..12 char credit asset code
	Issuer     string // G... issuer for AssetClassic
	ContractID string // C... SAC contract ID when known
}

// ParseAsset parses "XLM", "CODE:ISSUER", or a Soroban contract "C...".
func ParseAsset(asset, passphrase string) (ParsedAsset, error) {
	asset = strings.TrimSpace(asset)
	if asset == "" {
		return ParsedAsset{}, errors.New("empty Stellar asset")
	}
	nativeSAC, _ := NativeAsset(passphrase)
	if strings.EqualFold(asset, "XLM") || (nativeSAC != "" && asset == nativeSAC) {
		return ParsedAsset{Kind: AssetNative, Code: "XLM", ContractID: nativeSAC}, nil
	}
	if strings.HasPrefix(asset, "C") && len(asset) == 56 {
		if _, err := decodeContract(asset); err != nil {
			return ParsedAsset{}, errors.New("invalid Stellar contract asset")
		}
		return ParsedAsset{Kind: AssetSorobanSAC, ContractID: asset}, nil
	}
	code, issuer, ok := strings.Cut(asset, ":")
	if !ok || len(code) == 0 || len(code) > 12 || !isValidGAccount(issuer) {
		return ParsedAsset{}, errors.New("Stellar asset must be XLM, CODE:ISSUER, or a C... contract ID")
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return ParsedAsset{}, errors.New("Stellar asset code must be alphanumeric")
		}
	}
	cid := ""
	if passphrase != "" {
		if ca, err := xdr.NewCreditAsset(code, issuer); err == nil {
			if rawID, err := ca.ContractID(passphrase); err == nil {
				cid, _ = strkey.Encode(strkey.VersionByteContract, rawID[:])
			}
		}
	}
	return ParsedAsset{Kind: AssetClassic, Code: code, Issuer: issuer, ContractID: cid}, nil
}

func isValidGAccount(s string) bool {
	if len(s) != 56 || !strings.HasPrefix(s, "G") {
		return false
	}
	_, err := keypair.ParseAddress(s)
	return err == nil
}

// ParseStroops converts a Stellar 7-decimal balance string (e.g. "12.3450000")
// into an exact integer stroops value (10^7 stroops = 1 unit).
func ParseStroops(dec string) (*big.Int, error) {
	dec = strings.TrimSpace(dec)
	if dec == "" || strings.HasPrefix(dec, "-") {
		return nil, errors.New("invalid Stellar amount")
	}
	intPart, fracPart, hasDot := strings.Cut(dec, ".")
	if hasDot && strings.Contains(fracPart, ".") {
		return nil, errors.New("invalid Stellar decimal")
	}
	if len(fracPart) > 7 {
		fracPart = fracPart[:7]
	}
	fracPart = fracPart + strings.Repeat("0", 7-len(fracPart))
	if intPart == "" {
		intPart = "0"
	}
	full := intPart + fracPart
	n, ok := new(big.Int).SetString(full, 10)
	if !ok || n.Sign() < 0 {
		return nil, errors.New("invalid Stellar numeric amount")
	}
	return n, nil
}

// TokenBalance returns the holder's exact balance in atomic units (stroops for
// native XLM and classic CODE:ISSUER trustlines; contract base units for C...).
func (s *Scheme) TokenBalance(ctx context.Context, address, asset string) (*big.Int, error) {
	if !isValidGAccount(address) {
		return nil, errors.New("invalid Stellar G... address")
	}
	pa, err := ParseAsset(asset, s.passphrase)
	if err != nil {
		return nil, err
	}
	if pa.Kind == AssetSorobanSAC {
		return s.sorobanBalance(ctx, address, pa.ContractID)
	}
	if s.Horizon.URL == "" {
		return nil, errors.New("Stellar Horizon URL is required for trustline balances")
	}
	hp, err := s.Horizon.Passphrase(ctx)
	if err != nil {
		return nil, err
	}
	if hp != s.passphrase {
		return nil, errors.New("Horizon network mismatch")
	}
	acct, err := s.Horizon.Account(ctx, address)
	if err != nil {
		return nil, err
	}
	for _, b := range acct.Balances {
		if pa.Kind == AssetNative && b.AssetType == "native" {
			return ParseStroops(b.Balance)
		}
		if pa.Kind == AssetClassic && b.AssetCode == pa.Code && b.AssetIssuer == pa.Issuer {
			if b.IsAuthorized != nil && !*b.IsAuthorized {
				return big.NewInt(0), nil
			}
			return ParseStroops(b.Balance)
		}
	}
	return big.NewInt(0), nil
}

func (s *Scheme) sorobanBalance(ctx context.Context, address, contractStr string) (*big.Int, error) {
	if s.RPC.URL == "" || s.Horizon.URL == "" {
		return nil, errors.New("Stellar RPC and Horizon URLs are required")
	}
	acct, err := s.Horizon.Account(ctx, address)
	if err != nil {
		return nil, err
	}
	rp, err := s.RPC.Passphrase(ctx)
	if err != nil {
		return nil, err
	}
	if rp != s.passphrase {
		return nil, errors.New("RPC network mismatch")
	}
	seq, err := atoi64(acct.Sequence)
	if err != nil {
		return nil, err
	}
	contract, err := contractAddress(contractStr)
	if err != nil {
		return nil, err
	}
	owner, err := scAddress(address)
	if err != nil {
		return nil, err
	}
	src, err := xdr.AddressToMuxedAccount(address)
	if err != nil {
		return nil, err
	}
	bounds := xdr.TimeBounds{MaxTime: xdr.TimePoint(time.Now().Add(30 * time.Second).Unix())}
	tx := xdr.Transaction{
		SourceAccount: src,
		Fee:           inclusionFeeStroops,
		SeqNum:        xdr.SequenceNumber(seq + 1),
		Cond:          xdr.Preconditions{Type: xdr.PreconditionTypePrecondTime, TimeBounds: &bounds},
		Operations: []xdr.Operation{{Body: xdr.OperationBody{
			Type: xdr.OperationTypeInvokeHostFunction,
			InvokeHostFunctionOp: &xdr.InvokeHostFunctionOp{
				HostFunction: xdr.HostFunction{
					Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
					InvokeContract: &xdr.InvokeContractArgs{
						ContractAddress: contract,
						FunctionName:    "balance",
						Args:            []xdr.ScVal{owner},
					},
				},
			},
		}}},
	}
	env, err := xdr.MarshalBase64(xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTx, V1: &xdr.TransactionV1Envelope{Tx: tx}})
	if err != nil {
		return nil, err
	}
	sim, err := s.RPC.Simulate(ctx, env)
	if err != nil || !sim.Success() || len(sim.Results) == 0 {
		return nil, errors.New("Soroban balance simulation failed")
	}
	var ret xdr.ScVal
	if err := xdr.SafeUnmarshalBase64(sim.Results[0].XDR, &ret); err != nil {
		return nil, err
	}
	n, ok := scNumber(ret)
	if !ok {
		return nil, errors.New("unexpected Soroban balance return type")
	}
	return n, nil
}

// MeetsMinBalance checks whether address holds at least minAtomic units of asset.
func (s *Scheme) MeetsMinBalance(ctx context.Context, address, asset, minAtomic string) (bool, string, error) {
	want, ok := new(big.Int).SetString(strings.TrimSpace(minAtomic), 10)
	if !ok || want.Sign() < 0 {
		return false, "", errors.New("invalid minimum balance")
	}
	bal, err := s.TokenBalance(ctx, address, asset)
	if err != nil {
		return false, "", err
	}
	return bal.Cmp(want) >= 0, bal.String(), nil
}

// SponsorBalance returns the configured sponsor account's XLM balance in stroops.
func (s *Scheme) SponsorBalance(ctx context.Context) (int64, error) {
	if s.Sponsor == nil {
		return 0, errors.New("no Stellar sponsor configured")
	}
	bal, err := s.TokenBalance(ctx, s.Sponsor.Address(), "XLM")
	if err != nil {
		return 0, err
	}
	return bal.Int64(), nil
}

// FindDirectPayment checks Horizon for a finalized payment to `to` from `from`
// (optional if empty) carrying exact text `memoText` and >= minStroops of asset.
func (s *Scheme) FindDirectPayment(ctx context.Context, from, to, asset, minStroops, memoText string, since time.Time) (txHash, payer string, err error) {
	if s.Horizon.URL == "" {
		return "", "", errors.New("Stellar Horizon URL is required for direct payment verification")
	}
	if !isValidGAccount(to) || (from != "" && !isValidGAccount(from)) {
		return "", "", errors.New("invalid Stellar G... address")
	}
	hp, err := s.Horizon.Passphrase(ctx)
	if err != nil {
		return "", "", err
	}
	if hp != s.passphrase {
		return "", "", errors.New("Horizon network mismatch")
	}
	pa, err := ParseAsset(asset, s.passphrase)
	if err != nil {
		return "", "", err
	}
	want, ok := new(big.Int).SetString(strings.TrimSpace(minStroops), 10)
	if !ok || want.Sign() <= 0 {
		return "", "", errors.New("invalid minimum Stellar amount")
	}
	payments, err := s.Horizon.Payments(ctx, to, 50)
	if err != nil {
		return "", "", err
	}
	for _, p := range payments {
		if !p.TransactionSuccessful || p.Type != "payment" || p.To != to {
			continue
		}
		if !since.IsZero() && p.CreatedAt.Before(since.Add(-30*time.Second)) {
			continue
		}
		if from != "" && p.From != from {
			continue
		}
		switch pa.Kind {
		case AssetNative:
			if p.AssetType != "native" {
				continue
			}
		case AssetClassic:
			if p.AssetCode != pa.Code || p.AssetIssuer != pa.Issuer {
				continue
			}
		default:
			continue
		}
		got, err := ParseStroops(p.Amount)
		if err != nil || got.Cmp(want) < 0 {
			continue
		}
		if memoText != "" {
			tx, err := s.Horizon.Transaction(ctx, p.TransactionHash)
			if err != nil || !tx.Successful || tx.MemoType != "text" || tx.Memo != memoText {
				continue
			}
		}
		return p.TransactionHash, p.From, nil
	}
	return "", "", errors.New("matching Stellar payment not found yet")
}
