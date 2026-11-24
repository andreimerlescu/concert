package solana

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/httpx"
	"github.com/andreimerlescu/concert/internal/x402"
)

const (
	ExactSchemeName        = "exact"
	maxComputeUnitLimit    = 400_000
	maxComputeUnitPriceMic = 5_000_000
	maxAutoScanNFTs        = 200
)

var (
	computeBudgetProgram   = mustKey("ComputeBudget111111111111111111111111111111")
	memoProgram            = mustKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
	memoProgramV1          = mustKey("Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo")
	token2022Program       = mustKey("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
	associatedTokenProgram = mustKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
)

// AssociatedTokenAddress derives the canonical SPL / Token-2022 ATA PDA.
func AssociatedTokenAddress(owner, mint, tokProg PublicKey) (PublicKey, error) {
	return FindProgramAddress([][]byte{owner[:], tokProg[:], mint[:]}, associatedTokenProgram)
}

type decodedIx struct {
	programIdx byte
	accounts   []byte
	data       []byte
}

// InspectPayment validates a signed legacy Solana payment transaction for either:
//   - native SOL ("concert-native-sol" / "exact" with asset "SOL"), tolerating
//     wallet-injected ComputeBudget priority-fee instructions and optional Memo; OR
//   - standard x402 SPL / Token-2022 ("exact" with asset == mint pubkey), allowing
//     ComputeBudget, optional CreateAssociatedTokenAccountIdempotent, optional Memo,
//     and exactly one Transfer or TransferChecked crediting payTo's ATA.
//
// It preserves strict single-signer, single-transfer, zero-drain guarantees.
func InspectPayment(encoded string, req x402.Requirements) (Transfer, error) {
	// Fast path: strict single-instruction native SOL transfers also pass tx.go's Inspect.
	var t Transfer
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) > maxTx || len(raw) < 100 || base64.StdEncoding.EncodeToString(raw) != encoded {
		return t, errors.New("invalid transaction encoding")
	}
	i := 0
	sigs, err := readLen(raw, &i)
	if err != nil || sigs != 1 {
		return t, errors.New("exactly one signature is required")
	}
	sig, err := take(raw, &i, 64)
	if err != nil {
		return t, err
	}
	msgStart := i
	header, err := take(raw, &i, 3)
	if err != nil {
		return t, err
	}
	if header[0]&0x80 != 0 {
		return t, errors.New("versioned transactions are not accepted")
	}
	required, readonlySigned, readonlyUnsigned := int(header[0]), int(header[1]), int(header[2])
	if required != 1 || readonlySigned != 0 {
		return t, errors.New("exactly one writable signer is required")
	}
	nkeys, err := readLen(raw, &i)
	if err != nil || nkeys < 3 || nkeys > 24 || readonlyUnsigned >= nkeys {
		return t, errors.New("invalid account list")
	}
	keys := make([]PublicKey, nkeys)
	seen := map[PublicKey]bool{}
	for k := range keys {
		b, err := take(raw, &i, 32)
		if err != nil {
			return t, err
		}
		copy(keys[k][:], b)
		if seen[keys[k]] {
			return t, errors.New("duplicate account key")
		}
		seen[keys[k]] = true
	}
	bh, err := take(raw, &i, 32)
	if err != nil {
		return t, err
	}
	copy(t.Blockhash[:], bh)
	nix, err := readLen(raw, &i)
	if err != nil || nix < 1 || nix > 6 {
		return t, errors.New("invalid instruction count")
	}
	ixs := make([]decodedIx, 0, nix)
	for n := 0; n < nix; n++ {
		pidx, err := take(raw, &i, 1)
		if err != nil {
			return t, err
		}
		if int(pidx[0]) >= nkeys {
			return t, errors.New("invalid instruction program index")
		}
		nacc, err := readLen(raw, &i)
		if err != nil || nacc > nkeys {
			return t, errors.New("invalid instruction account count")
		}
		acc, err := take(raw, &i, nacc)
		if err != nil {
			return t, err
		}
		for _, a := range acc {
			if int(a) >= nkeys {
				return t, errors.New("invalid instruction account index")
			}
		}
		ndata, err := readLen(raw, &i)
		if err != nil || ndata > 512 {
			return t, errors.New("invalid instruction data length")
		}
		data, err := take(raw, &i, ndata)
		if err != nil {
			return t, err
		}
		ixs = append(ixs, decodedIx{programIdx: pidx[0], accounts: acc, data: data})
	}
	if i != len(raw) {
		return t, errors.New("trailing transaction bytes")
	}

	writable := func(k int) bool {
		if k < required {
			return k < required-readonlySigned
		}
		return k-required < nkeys-required-readonlyUnsigned
	}

	payer := keys[0]
	payTo, err := ParsePublicKey(req.PayTo)
	if err != nil {
		return t, errors.New("invalid payTo")
	}
	if payer == payTo {
		return t, errors.New("self-payment is not accepted")
	}
	wantAmt, err := strconv.ParseUint(req.Amount, 10, 64)
	if err != nil || wantAmt == 0 {
		return t, errors.New("invalid payment amount")
	}
	isNative := req.Asset == "SOL"
	var wantMint, wantATALegacy, wantATA2022 PublicKey
	if !isNative {
		wantMint, err = ParsePublicKey(req.Asset)
		if err != nil {
			return t, errors.New("invalid SPL mint asset")
		}
		if wantATALegacy, err = AssociatedTokenAddress(payTo, wantMint, tokenProgram); err != nil {
			return t, err
		}
		if wantATA2022, err = AssociatedTokenAddress(payTo, wantMint, token2022Program); err != nil {
			return t, err
		}
	}

	transfers := 0
	var memos []string
	for _, ix := range ixs {
		prog := keys[ix.programIdx]
		switch prog {
		case computeBudgetProgram:
			if len(ix.accounts) != 0 || len(ix.data) == 0 {
				return t, errors.New("invalid ComputeBudget instruction")
			}
			switch ix.data[0] {
			case 2: // SetComputeUnitLimit(u32)
				if len(ix.data) != 5 || binary.LittleEndian.Uint32(ix.data[1:5]) > maxComputeUnitLimit {
					return t, errors.New("invalid ComputeUnitLimit")
				}
			case 3: // SetComputeUnitPrice(u64)
				if len(ix.data) != 9 || binary.LittleEndian.Uint64(ix.data[1:9]) > maxComputeUnitPriceMic {
					return t, errors.New("ComputeUnitPrice exceeds cap")
				}
			default:
				return t, errors.New("unsupported ComputeBudget instruction")
			}
		case memoProgram, memoProgramV1:
			if len(ix.data) > 256 {
				return t, errors.New("memo too large")
			}
			if len(ix.accounts) > 1 || (len(ix.accounts) == 1 && ix.accounts[0] != 0) {
				return t, errors.New("unexpected memo accounts")
			}
			memos = append(memos, string(ix.data))
		case associatedTokenProgram:
			if isNative {
				return t, errors.New("ATA instruction not allowed on native SOL payment")
			}
			// Create (empty or [0]) or CreateIdempotent ([1]) with 6 accounts:
			// [funding(payer), ata(merchantATA), wallet(payTo), mint(wantMint), system, tokenProgram]
			if len(ix.accounts) != 6 || len(ix.data) > 1 || (len(ix.data) == 1 && ix.data[0] != 0 && ix.data[0] != 1) {
				return t, errors.New("invalid ATA creation instruction")
			}
			ataKey := keys[ix.accounts[1]]
			if ix.accounts[0] != 0 || keys[ix.accounts[2]] != payTo || keys[ix.accounts[3]] != wantMint ||
				(ataKey != wantATALegacy && ataKey != wantATA2022) {
				return t, errors.New("ATA creation does not match recipient and mint")
			}
		case systemProgram:
			if !isNative {
				return t, errors.New("unexpected SystemProgram instruction in SPL payment")
			}
			if len(ix.accounts) != 2 || len(ix.data) != 12 || binary.LittleEndian.Uint32(ix.data[0:4]) != 2 {
				return t, errors.New("only a native SystemProgram transfer is accepted")
			}
			fromIdx, toIdx := int(ix.accounts[0]), int(ix.accounts[1])
			if fromIdx != 0 || toIdx == 0 || !writable(toIdx) || keys[toIdx] != payTo {
				return t, errors.New("invalid native transfer accounts")
			}
			gotAmt := binary.LittleEndian.Uint64(ix.data[4:12])
			if gotAmt != wantAmt {
				return t, errors.New("payment terms mismatch")
			}
			transfers++
		case tokenProgram, token2022Program:
			if isNative {
				return t, errors.New("unexpected SPL token instruction in native SOL payment")
			}
			expectedATA := wantATALegacy
			if prog == token2022Program {
				expectedATA = wantATA2022
			}
			if len(ix.data) == 10 && ix.data[0] == 12 && len(ix.accounts) == 4 {
				// TransferChecked: [source, mint, destination, authority]
				srcIdx, mintIdx, dstIdx, authIdx := int(ix.accounts[0]), int(ix.accounts[1]), int(ix.accounts[2]), int(ix.accounts[3])
				if authIdx != 0 || keys[mintIdx] != wantMint || keys[dstIdx] != expectedATA || srcIdx == dstIdx || !writable(dstIdx) {
					return t, errors.New("SPL TransferChecked accounts mismatch")
				}
				gotAmt := binary.LittleEndian.Uint64(ix.data[1:9])
				if gotAmt != wantAmt {
					return t, errors.New("payment terms mismatch")
				}
				transfers++
			} else if len(ix.data) == 9 && ix.data[0] == 3 && len(ix.accounts) == 3 {
				// Transfer: [source, destination, authority]
				srcIdx, dstIdx, authIdx := int(ix.accounts[0]), int(ix.accounts[1]), int(ix.accounts[2])
				if authIdx != 0 || keys[dstIdx] != expectedATA || srcIdx == dstIdx || !writable(dstIdx) {
					return t, errors.New("SPL Transfer accounts mismatch")
				}
				gotAmt := binary.LittleEndian.Uint64(ix.data[1:9])
				if gotAmt != wantAmt {
					return t, errors.New("payment terms mismatch")
				}
				transfers++
			} else {
				return t, errors.New("unsupported SPL token instruction")
			}
		default:
			return t, errors.New("unsupported Solana program in payment transaction")
		}
	}
	if transfers != 1 {
		return t, errors.New("exactly one payment transfer instruction is required")
	}
	if wantMemo, ok := req.Extra["memo"].(string); ok && wantMemo != "" {
		found := false
		for _, m := range memos {
			if m == wantMemo {
				found = true
				break
			}
		}
		if !found {
			return t, errors.New("required memo missing")
		}
	}
	t.Raw, t.Message, t.Signature = raw, raw[msgStart:], sig
	t.From, t.To, t.Lamports = payer, payTo, wantAmt
	if !ed25519.Verify(t.From[:], t.Message, t.Signature) {
		return t, errors.New("invalid payer signature")
	}
	// Canonical re-encoding check prevents malleable compact-u16 fingerprints.
	if !bytes.Equal(encodeLegacyTx(sig, header, keys, t.Blockhash, ixs), raw) {
		return t, errors.New("non-canonical transaction encoding")
	}
	return t, nil
}

func encodeLegacyTx(sig []byte, header []byte, keys []PublicKey, blockhash PublicKey, ixs []decodedIx) []byte {
	var b bytes.Buffer
	writeLen(&b, 1)
	b.Write(sig)
	b.Write(header)
	writeLen(&b, len(keys))
	for _, k := range keys {
		b.Write(k[:])
	}
	b.Write(blockhash[:])
	writeLen(&b, len(ixs))
	for _, ix := range ixs {
		b.WriteByte(ix.programIdx)
		writeLen(&b, len(ix.accounts))
		b.Write(ix.accounts)
		writeLen(&b, len(ix.data))
		b.Write(ix.data)
	}
	return b.Bytes()
}

// BuildSPLTransfer constructs an unsigned legacy SPL / Token-2022 TransferChecked
// transaction (optionally prepending CreateAssociatedTokenAccountIdempotent and Memo).
func BuildSPLTransfer(payer, payTo, mint, tokProg PublicKey, amount uint64, decimals byte, blockhash PublicKey, createMerchantATA bool, memo string) ([]byte, error) {
	srcATA, err := AssociatedTokenAddress(payer, mint, tokProg)
	if err != nil {
		return nil, err
	}
	dstATA, err := AssociatedTokenAddress(payTo, mint, tokProg)
	if err != nil {
		return nil, err
	}
	// Account order: [writable signers, readonly signers, writable unsigned, readonly unsigned]
	var keys []PublicKey
	idxOf := map[PublicKey]byte{}
	add := func(k PublicKey) byte {
		if idx, ok := idxOf[k]; ok {
			return idx
		}
		idx := byte(len(keys))
		idxOf[k] = idx
		keys = append(keys, k)
		return idx
	}
	// Writable signer: payer
	pIdx := add(payer)
	// Writable unsigned: srcATA, dstATA
	srcIdx := add(srcATA)
	dstIdx := add(dstATA)
	roStart := len(keys)
	// Readonly unsigned
	mintIdx := add(mint)
	tokIdx := add(tokProg)
	var ixs []decodedIx
	if createMerchantATA {
		toIdx := add(payTo)
		sysIdx := add(systemProgram)
		ataProgIdx := add(associatedTokenProgram)
		ixs = append(ixs, decodedIx{
			programIdx: ataProgIdx,
			accounts:   []byte{pIdx, dstIdx, toIdx, mintIdx, sysIdx, tokIdx},
			data:       []byte{1}, // CreateIdempotent
		})
	}
	var data [10]byte
	data[0] = 12 // TransferChecked
	binary.LittleEndian.PutUint64(data[1:9], amount)
	data[9] = decimals
	ixs = append(ixs, decodedIx{
		programIdx: tokIdx,
		accounts:   []byte{srcIdx, mintIdx, dstIdx, pIdx},
		data:       data[:],
	})
	if memo != "" {
		memoIdx := add(memoProgram)
		ixs = append(ixs, decodedIx{
			programIdx: memoIdx,
			accounts:   []byte{pIdx},
			data:       []byte(memo),
		})
	}
	roUnsigned := len(keys) - roStart
	header := []byte{1, 0, byte(roUnsigned)}
	return encodeLegacyTx(make([]byte, 64), header, keys, blockhash, ixs), nil
}

// BuildNativeTransferWithExtras constructs an unsigned native SOL transfer with
// optional ComputeBudget priority fee and optional SPL Memo instruction.
func BuildNativeTransferWithExtras(from, to PublicKey, lamports uint64, blockhash PublicKey, unitLimit uint32, unitPriceMicroLamports uint64, memo string) []byte {
	if unitLimit == 0 && unitPriceMicroLamports == 0 && memo == "" {
		return NewTransfer(from, to, lamports, blockhash)
	}
	keys := []PublicKey{from, to, systemProgram}
	idxOf := map[PublicKey]byte{from: 0, to: 1, systemProgram: 2}
	addRO := func(k PublicKey) byte {
		if idx, ok := idxOf[k]; ok {
			return idx
		}
		idx := byte(len(keys))
		idxOf[k] = idx
		keys = append(keys, k)
		return idx
	}
	var ixs []decodedIx
	if unitLimit > 0 {
		cbIdx := addRO(computeBudgetProgram)
		var d [5]byte
		d[0] = 2
		binary.LittleEndian.PutUint32(d[1:5], unitLimit)
		ixs = append(ixs, decodedIx{programIdx: cbIdx, data: d[:]})
	}
	if unitPriceMicroLamports > 0 {
		cbIdx := addRO(computeBudgetProgram)
		var d [9]byte
		d[0] = 3
		binary.LittleEndian.PutUint64(d[1:9], unitPriceMicroLamports)
		ixs = append(ixs, decodedIx{programIdx: cbIdx, data: d[:]})
	}
	var td [12]byte
	binary.LittleEndian.PutUint32(td[0:4], 2)
	binary.LittleEndian.PutUint64(td[4:12], lamports)
	ixs = append(ixs, decodedIx{programIdx: 2, accounts: []byte{0, 1}, data: td[:]})
	if memo != "" {
		mIdx := addRO(memoProgram)
		ixs = append(ixs, decodedIx{programIdx: mIdx, accounts: []byte{0}, data: []byte(memo)})
	}
	roUnsigned := len(keys) - 2
	return encodeLegacyTx(make([]byte, 64), []byte{1, 0, byte(roUnsigned)}, keys, blockhash, ixs)
}

// PreparePayment builds an unsigned transaction for native SOL or SPL/Token-2022.
func (s *Scheme) PreparePayment(ctx context.Context, address string, req x402.Requirements) ([]byte, error) {
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
	amt, err := strconv.ParseUint(req.Amount, 10, 64)
	if err != nil || amt == 0 {
		return nil, errors.New("invalid amount")
	}
	bh, err := s.RPC.LatestBlockhash(ctx)
	if err != nil {
		return nil, err
	}
	memo, _ := req.Extra["memo"].(string)
	if req.Asset == "SOL" {
		if memo == "" {
			return NewTransfer(from, to, amt, bh), nil
		}
		return BuildNativeTransferWithExtras(from, to, amt, bh, 0, 0, memo), nil
	}
	mint, err := ParsePublicKey(req.Asset)
	if err != nil {
		return nil, errors.New("invalid SPL mint")
	}
	info, err := s.RPC.Account(ctx, mint)
	if err != nil || info == nil || (info.Owner != tokenProgram && info.Owner != token2022Program) || len(info.Data) < 46 {
		return nil, errors.New("SPL mint account not found or invalid")
	}
	decimals := info.Data[44]
	merchantATA, err := AssociatedTokenAddress(to, mint, info.Owner)
	if err != nil {
		return nil, err
	}
	ataInfo, _ := s.RPC.Account(ctx, merchantATA)
	return BuildSPLTransfer(from, to, mint, info.Owner, amt, decimals, bh, ataInfo == nil, memo)
}

// TokenBalance returns finalized native SOL (lamports) or SPL/Token-2022 balance
// in atomic units held by owner.
func (s *Scheme) TokenBalance(ctx context.Context, owner, asset string) (*big.Int, error) {
	ownerKey, err := ParsePublicKey(owner)
	if err != nil {
		return nil, err
	}
	n, err := s.RPC.Network(ctx)
	if err != nil {
		return nil, err
	}
	if n != s.Network {
		return nil, errors.New("RPC network mismatch")
	}
	if asset == "SOL" {
		var out struct {
			Value uint64 `json:"value"`
		}
		if err := s.RPC.call(ctx, "getBalance", []any{ownerKey.String(), map[string]string{"commitment": "finalized"}}, &out); err != nil {
			return nil, err
		}
		return new(big.Int).SetUint64(out.Value), nil
	}
	mintKey, err := ParsePublicKey(asset)
	if err != nil {
		return nil, errors.New("invalid SPL mint")
	}
	var owned struct {
		Value []struct {
			Account struct {
				Owner string `json:"owner"`
				Data  struct {
					Parsed struct {
						Info struct {
							Owner       string `json:"owner"`
							TokenAmount struct {
								Amount string `json:"amount"`
							} `json:"tokenAmount"`
						} `json:"info"`
					} `json:"parsed"`
				} `json:"data"`
			} `json:"account"`
		} `json:"value"`
	}
	params := []any{ownerKey.String(), map[string]string{"mint": mintKey.String()}, map[string]string{"encoding": "jsonParsed", "commitment": "finalized"}}
	if err := s.RPC.call(ctx, "getTokenAccountsByOwner", params, &owned); err != nil {
		return nil, err
	}
	total := new(big.Int)
	for _, a := range owned.Value {
		if a.Account.Owner != tokenProgram.String() && a.Account.Owner != token2022Program.String() {
			continue
		}
		if a.Account.Data.Parsed.Info.Owner != ownerKey.String() {
			continue
		}
		if amt, ok := new(big.Int).SetString(a.Account.Data.Parsed.Info.TokenAmount.Amount, 10); ok && amt.Sign() > 0 {
			total.Add(total, amt)
		}
	}
	return total, nil
}

// MeetsMinBalance checks whether owner holds at least minAtomic units of asset.
func (s *Scheme) MeetsMinBalance(ctx context.Context, owner, asset, minAtomic string) (bool, string, error) {
	want, ok := new(big.Int).SetString(strings.TrimSpace(minAtomic), 10)
	if !ok || want.Sign() < 0 {
		return false, "", errors.New("invalid minimum balance")
	}
	bal, err := s.TokenBalance(ctx, owner, asset)
	if err != nil {
		return false, "", err
	}
	return bal.Cmp(want) >= 0, bal.String(), nil
}

// FindOwnedNFT proves collection ownership for owner. When optionalMint is empty,
// it automatically scans owner's SPL and Token-2022 1-supply 0-decimal accounts
// for a verified Metaplex collection match (plus optional DAS RPC fallback for
// Metaplex Core and compressed NFTs).
func (s *Scheme) FindOwnedNFT(ctx context.Context, owner, collection, optionalMint, dasRPC string) (string, error) {
	if optionalMint != "" {
		return s.OwnsNFT(ctx, owner, collection, optionalMint)
	}
	if _, err := ParsePublicKey(collection); err != nil {
		return "", errors.New("invalid Solana collection address")
	}
	ownerKey, err := ParsePublicKey(owner)
	if err != nil {
		return "", err
	}
	n, err := s.RPC.Network(ctx)
	if err != nil {
		return "", err
	}
	if n != s.Network {
		return "", errors.New("RPC network mismatch")
	}
	checked := 0
	for _, prog := range []PublicKey{tokenProgram, token2022Program} {
		var owned struct {
			Value []struct {
				Account struct {
					Owner string `json:"owner"`
					Data  struct {
						Parsed struct {
							Info struct {
								Mint        string `json:"mint"`
								Owner       string `json:"owner"`
								TokenAmount struct {
									Amount   string `json:"amount"`
									Decimals int    `json:"decimals"`
								} `json:"tokenAmount"`
							} `json:"info"`
						} `json:"parsed"`
					} `json:"data"`
				} `json:"account"`
			} `json:"value"`
		}
		params := []any{ownerKey.String(), map[string]string{"programId": prog.String()}, map[string]string{"encoding": "jsonParsed", "commitment": "finalized"}}
		if err := s.RPC.call(ctx, "getTokenAccountsByOwner", params, &owned); err != nil {
			continue
		}
		for _, a := range owned.Value {
			if checked >= maxAutoScanNFTs {
				break
			}
			info := a.Account.Data.Parsed.Info
			if info.Owner != ownerKey.String() || info.TokenAmount.Amount != "1" || info.TokenAmount.Decimals != 0 {
				continue
			}
			checked++
			mintKey, err := ParsePublicKey(info.Mint)
			if err != nil {
				continue
			}
			pda, err := FindProgramAddress([][]byte{[]byte("metadata"), metadataProgram[:], mintKey[:]}, metadataProgram)
			if err != nil {
				continue
			}
			meta, err := s.RPC.Account(ctx, pda)
			if err != nil || meta == nil || meta.Owner != metadataProgram {
				continue
			}
			c, err := ReadCollection(meta.Data, mintKey)
			if err == nil && c != nil && c.Verified && c.Key.String() == collection {
				return mintKey.String(), nil
			}
		}
	}
	if dasRPC != "" {
		if id, err := checkDASCollection(ctx, dasRPC, ownerKey.String(), collection); err == nil && id != "" {
			return id, nil
		}
	}
	return "", errors.New("no matching NFT in wallet")
}

func checkDASCollection(ctx context.Context, dasURL, owner, collection string) (string, error) {
	var out struct {
		Items []struct {
			ID       string `json:"id"`
			Burnt    bool   `json:"burnt"`
			Grouping []struct {
				GroupKey   string `json:"group_key"`
				GroupValue string `json:"group_value"`
			} `json:"grouping"`
		} `json:"items"`
	}
	params := map[string]any{"ownerAddress": owner, "page": 1, "limit": 100}
	if err := httpx.Call(ctx, dasURL, "getAssetsByOwner", params, &out); err != nil {
		return "", err
	}
	for _, item := range out.Items {
		if item.Burnt || item.ID == "" {
			continue
		}
		for _, g := range item.Grouping {
			if g.GroupKey == "collection" && g.GroupValue == collection {
				return item.ID, nil
			}
		}
	}
	return "", errors.New("no matching DAS NFT")
}

// FindDirectPayment scans recent finalized signatures on `to` (or `to`'s ATA
// for SPL tokens) for a payment from `from` (optional) carrying exact `memoText`
// and crediting `to` with >= minAtomic units of `asset` ("SOL" or mint pubkey).
func (s *Scheme) FindDirectPayment(ctx context.Context, from, to, asset, minAtomic, memoText string, since time.Time) (sig, payer string, err error) {
	toKey, err := ParsePublicKey(to)
	if err != nil {
		return "", "", errors.New("invalid Solana recipient")
	}
	if from != "" {
		if _, err := ParsePublicKey(from); err != nil {
			return "", "", errors.New("invalid Solana sender")
		}
	}
	want, ok := new(big.Int).SetString(strings.TrimSpace(minAtomic), 10)
	if !ok || want.Sign() <= 0 {
		return "", "", errors.New("invalid minimum Solana amount")
	}
	n, err := s.RPC.Network(ctx)
	if err != nil {
		return "", "", err
	}
	if n != s.Network {
		return "", "", errors.New("RPC network mismatch")
	}
	watchAddr := toKey.String()
	isNative := asset == "SOL"
	if !isNative {
		mintKey, err := ParsePublicKey(asset)
		if err != nil {
			return "", "", errors.New("invalid SPL mint")
		}
		tokProg := tokenProgram
		if info, err := s.RPC.Account(ctx, mintKey); err == nil && info != nil && info.Owner == token2022Program {
			tokProg = token2022Program
		}
		ata, err := AssociatedTokenAddress(toKey, mintKey, tokProg)
		if err != nil {
			return "", "", err
		}
		watchAddr = ata.String()
	}
	var sigs []struct {
		Signature string `json:"signature"`
		Err       any    `json:"err"`
		Memo      string `json:"memo"`
		BlockTime *int64 `json:"blockTime"`
	}
	if err := s.RPC.call(ctx, "getSignaturesForAddress", []any{watchAddr, map[string]any{"limit": 30, "commitment": "finalized"}}, &sigs); err != nil {
		return "", "", err
	}
	for _, entry := range sigs {
		if entry.Err != nil {
			continue
		}
		if !since.IsZero() && entry.BlockTime != nil && *entry.BlockTime < since.Add(-30*time.Second).Unix() {
			continue
		}
		if memoText != "" && entry.Memo != "" && !strings.Contains(entry.Memo, memoText) {
			continue
		}
		var tx struct {
			BlockTime *int64 `json:"blockTime"`
			Meta      *struct {
				Err              any     `json:"err"`
				PreBalances      []int64 `json:"preBalances"`
				PostBalances     []int64 `json:"postBalances"`
				PreTokenBalances []struct {
					Mint          string `json:"mint"`
					Owner         string `json:"owner"`
					UITokenAmount struct {
						Amount string `json:"amount"`
					} `json:"uiTokenAmount"`
				} `json:"preTokenBalances"`
				PostTokenBalances []struct {
					Mint          string `json:"mint"`
					Owner         string `json:"owner"`
					UITokenAmount struct {
						Amount string `json:"amount"`
					} `json:"uiTokenAmount"`
				} `json:"postTokenBalances"`
			} `json:"meta"`
			Transaction struct {
				Message struct {
					AccountKeys []struct {
						Pubkey string `json:"pubkey"`
						Signer bool   `json:"signer"`
					} `json:"accountKeys"`
					Instructions []struct {
						Program   string `json:"program"`
						ProgramID string `json:"programId"`
						Parsed    any    `json:"parsed"`
					} `json:"instructions"`
				} `json:"message"`
			} `json:"transaction"`
		}
		if err := s.RPC.call(ctx, "getTransaction", []any{entry.Signature, map[string]any{"encoding": "jsonParsed", "commitment": "finalized", "maxSupportedTransactionVersion": 0}}, &tx); err != nil || tx.Meta == nil || tx.Meta.Err != nil {
			continue
		}
		if len(tx.Transaction.Message.AccountKeys) == 0 {
			continue
		}
		txPayer := tx.Transaction.Message.AccountKeys[0].Pubkey
		if from != "" && txPayer != from {
			continue
		}
		if memoText != "" {
			memoOK := false
			for _, ix := range tx.Transaction.Message.Instructions {
				if ix.Program == "spl-memo" || ix.ProgramID == memoProgram.String() || ix.ProgramID == memoProgramV1.String() {
					if s, ok := ix.Parsed.(string); ok && s == memoText {
						memoOK = true
						break
					}
				}
			}
			if !memoOK {
				continue
			}
		}
		if isNative {
			toIdx := -1
			for idx, ak := range tx.Transaction.Message.AccountKeys {
				if ak.Pubkey == toKey.String() {
					toIdx = idx
					break
				}
			}
			if toIdx < 0 || toIdx >= len(tx.Meta.PreBalances) || toIdx >= len(tx.Meta.PostBalances) {
				continue
			}
			delta := tx.Meta.PostBalances[toIdx] - tx.Meta.PreBalances[toIdx]
			if delta <= 0 || big.NewInt(delta).Cmp(want) < 0 {
				continue
			}
		} else {
			preAmt := new(big.Int)
			postAmt := new(big.Int)
			for _, b := range tx.Meta.PreTokenBalances {
				if b.Mint == asset && b.Owner == toKey.String() {
					if v, ok := new(big.Int).SetString(b.UITokenAmount.Amount, 10); ok {
						preAmt.Add(preAmt, v)
					}
				}
			}
			for _, b := range tx.Meta.PostTokenBalances {
				if b.Mint == asset && b.Owner == toKey.String() {
					if v, ok := new(big.Int).SetString(b.UITokenAmount.Amount, 10); ok {
						postAmt.Add(postAmt, v)
					}
				}
			}
			delta := new(big.Int).Sub(postAmt, preAmt)
			if delta.Cmp(want) < 0 {
				continue
			}
		}
		return entry.Signature, txPayer, nil
	}
	return "", "", errors.New("matching Solana payment not found yet")
}
