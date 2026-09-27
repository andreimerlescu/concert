// Package solana implements the concert-native-sol payment scheme and
// Metaplex collection ownership checks against a Solana JSON-RPC endpoint.
package solana

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"

	"github.com/andreimerlescu/concert/internal/chain/base58"
	"github.com/andreimerlescu/concert/internal/x402"
)

const (
	SchemeName = "concert-native-sol"
	Mainnet    = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
	Devnet     = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	maxTx      = 1232 // packet data limit
)

type PublicKey [32]byte

func (k PublicKey) String() string { return base58.Bitcoin.Encode(k[:]) }

func ParsePublicKey(s string) (PublicKey, error) {
	var k PublicKey
	b, err := base58.Bitcoin.Decode(s)
	if err != nil || len(b) != 32 {
		return k, errors.New("invalid Solana public key")
	}
	copy(k[:], b)
	return k, nil
}

func mustKey(s string) PublicKey {
	k, err := ParsePublicKey(s)
	if err != nil {
		panic(err)
	}
	return k
}

var systemProgram PublicKey // 11111111111111111111111111111111

// Transfer is a decoded single native SOL transfer.
type Transfer struct {
	Raw       []byte
	Message   []byte
	From, To  PublicKey
	Lamports  uint64
	Blockhash PublicKey
	Signature []byte
}

func (t Transfer) SignatureString() string { return base58.Bitcoin.Encode(t.Signature) }

// compact-u16 as used by Solana's wire format.
func readLen(b []byte, i *int) (int, error) {
	v, shift := 0, 0
	for n := 0; n < 3; n++ {
		if *i >= len(b) {
			return 0, errors.New("truncated length")
		}
		c := b[*i]
		*i++
		v |= int(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, nil
		}
		shift += 7
	}
	return 0, errors.New("invalid length")
}

func writeLen(b *bytes.Buffer, n int) {
	for {
		c := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			b.WriteByte(c)
			return
		}
		b.WriteByte(c | 0x80)
	}
}

func take(b []byte, i *int, n int) ([]byte, error) {
	if n < 0 || *i+n > len(b) {
		return nil, errors.New("truncated transaction")
	}
	s := b[*i : *i+n]
	*i += n
	return s, nil
}

// Inspect accepts exactly one fully signed legacy transaction holding one
// System Program transfer from the fee payer to requirements.payTo for
// exactly requirements.amount lamports. Versioned transactions, extra
// instructions or signers, and non-canonical encodings are refused: one
// signature must have one byte sequence and therefore one fingerprint.
func Inspect(encoded string, req x402.Requirements) (Transfer, error) {
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
	nkeys, err := readLen(raw, &i)
	if err != nil || nkeys < 3 || nkeys > 16 {
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
	if required != 1 || readonlySigned != 0 || readonlyUnsigned >= nkeys {
		return t, errors.New("exactly one writable signer is required")
	}
	bh, err := take(raw, &i, 32)
	if err != nil {
		return t, err
	}
	copy(t.Blockhash[:], bh)
	nix, err := readLen(raw, &i)
	if err != nil || nix != 1 {
		return t, errors.New("exactly one instruction is required")
	}
	pidx, err := take(raw, &i, 1)
	if err != nil {
		return t, err
	}
	nacc, err := readLen(raw, &i)
	if err != nil || nacc != 2 {
		return t, errors.New("a transfer references exactly two accounts")
	}
	acc, err := take(raw, &i, 2)
	if err != nil {
		return t, err
	}
	ndata, err := readLen(raw, &i)
	if err != nil || ndata != 12 {
		return t, errors.New("only a native transfer is accepted")
	}
	data, err := take(raw, &i, 12)
	if err != nil {
		return t, err
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
	if int(pidx[0]) >= nkeys || keys[pidx[0]] != systemProgram || binary.LittleEndian.Uint32(data) != 2 {
		return t, errors.New("only a native SystemProgram transfer is accepted")
	}
	from, to := int(acc[0]), int(acc[1])
	if from != 0 || to >= nkeys || to == 0 || !writable(to) || to < required {
		return t, errors.New("invalid transfer authority")
	}
	t.Raw, t.Message, t.Signature = raw, raw[msgStart:], sig
	t.From, t.To, t.Lamports = keys[from], keys[to], binary.LittleEndian.Uint64(data[4:])
	if t.From.String() == req.PayTo || t.To.String() != req.PayTo || strconv.FormatUint(t.Lamports, 10) != req.Amount {
		return t, errors.New("payment terms mismatch")
	}
	if !ed25519.Verify(t.From[:], t.Message, t.Signature) {
		return t, errors.New("invalid payer signature")
	}
	// Re-encoding must reproduce the input exactly (no redundant length bytes).
	if !bytes.Equal(encodeTransfer(t.From, t.To, t.Lamports, t.Blockhash, t.Signature, keys, readonlyUnsigned), raw) {
		return t, errors.New("non-canonical transaction encoding")
	}
	return t, nil
}

func encodeTransfer(from, to PublicKey, lamports uint64, blockhash PublicKey, sig []byte, keys []PublicKey, readonlyUnsigned int) []byte {
	var b bytes.Buffer
	writeLen(&b, 1)
	b.Write(sig)
	b.Write([]byte{1, 0, byte(readonlyUnsigned)})
	writeLen(&b, len(keys))
	for _, k := range keys {
		b.Write(k[:])
	}
	b.Write(blockhash[:])
	writeLen(&b, 1)
	pidx := 0
	for i, k := range keys {
		if k == systemProgram {
			pidx = i
		}
	}
	toIdx := 0
	for i, k := range keys {
		if k == to {
			toIdx = i
		}
	}
	b.WriteByte(byte(pidx))
	writeLen(&b, 2)
	b.Write([]byte{0, byte(toIdx)})
	writeLen(&b, 12)
	var data [12]byte
	binary.LittleEndian.PutUint32(data[:], 2)
	binary.LittleEndian.PutUint64(data[4:], lamports)
	b.Write(data[:])
	return b.Bytes()
}

// NewTransfer builds the legacy transaction a wallet signs: fee payer and
// sender first, then the recipient, then the System Program, as Solana's
// own libraries order them. sig is 64 zero bytes when unsigned.
func NewTransfer(from, to PublicKey, lamports uint64, blockhash PublicKey) []byte {
	keys := []PublicKey{from, to, systemProgram}
	return encodeTransfer(from, to, lamports, blockhash, make([]byte, 64), keys, 1)
}

// Sign fills in the payer signature of a transaction built by NewTransfer.
func Sign(tx []byte, key ed25519.PrivateKey) []byte {
	out := append([]byte(nil), tx...)
	copy(out[1:65], ed25519.Sign(key, out[65:]))
	return out
}
