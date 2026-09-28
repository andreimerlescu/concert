// Package xrpl implements the x402 "exact" XRPL scheme for native XRP,
// ported rule for rule from @x402/xrpl, plus NFT ownership checks and the
// payer-side signing the reference client uses.
package xrpl

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// XRPL serialized type codes (ripple-binary-codec definitions).
const (
	tUInt16    = 1
	tUInt32    = 2
	tUInt64    = 3
	tHash128   = 4
	tHash256   = 5
	tAmount    = 6
	tBlob      = 7
	tAccountID = 8
	tNumber    = 9
	tInt32     = 10
	tInt64     = 11
	tSTObject  = 14
	tSTArray   = 15
	tUInt8     = 16
	tHash160   = 17
	tPathSet   = 18
	tVector256 = 19
	tUInt96    = 20
	tHash192   = 21
	tHash384   = 22
	tHash512   = 23
	tCurrency  = 26
)

type fieldID struct{ typ, nth int }

// Top-level Payment fields this implementation understands. Anything else
// is refused: a field we cannot interpret is not a field we can check.
var names = map[fieldID]string{
	{tUInt16, 2}: "TransactionType", {tUInt32, 1}: "NetworkID", {tUInt32, 2}: "Flags",
	{tUInt32, 3}: "SourceTag", {tUInt32, 4}: "Sequence", {tUInt32, 14}: "DestinationTag",
	{tUInt32, 27}: "LastLedgerSequence", {tUInt32, 41}: "TicketSequence", {tHash256, 17}: "InvoiceID",
	{tAmount, 1}: "Amount", {tAmount, 8}: "Fee", {tAmount, 9}: "SendMax", {tAmount, 10}: "DeliverMin",
	{tBlob, 3}: "SigningPubKey", {tBlob, 4}: "TxnSignature", {tAccountID, 1}: "Account",
	{tAccountID, 3}: "Destination", {tAccountID, 12}: "Delegate", {tSTArray, 3}: "Signers",
	{tSTArray, 9}: "Memos", {tPathSet, 1}: "Paths",
}

var ids = func() map[string]fieldID {
	m := map[string]fieldID{}
	for id, n := range names {
		m[n] = id
	}
	return m
}()

// Amount is a serialized amount. Only native XRP carries Drops.
type Amount struct {
	Native bool
	Drops  uint64
}

type field struct {
	id  fieldID
	raw []byte // header and value, exactly as serialized
	val []byte // value without header or length prefix
}

// Tx is a decoded transaction with the fields the scheme inspects.
type Tx struct {
	blob    []byte
	fields  []field
	Unknown []string

	TransactionType *uint16
	UInt32          map[string]uint32
	InvoiceID       []byte
	Amounts         map[string]Amount
	SigningPubKey   []byte
	TxnSignature    []byte
	Accounts        map[string][20]byte
	Present         map[string]bool
}

func (t *Tx) Has(name string) bool { return t.Present[name] }

func (t *Tx) U32(name string) (uint32, bool) {
	v, ok := t.UInt32[name]
	return v, ok
}

func readVL(b []byte, i *int) (int, error) {
	if *i >= len(b) {
		return 0, errors.New("truncated length")
	}
	b0 := int(b[*i])
	*i++
	switch {
	case b0 <= 192:
		return b0, nil
	case b0 <= 240:
		if *i >= len(b) {
			return 0, errors.New("truncated length")
		}
		n := 193 + (b0-193)*256 + int(b[*i])
		*i++
		if n <= 192 {
			return 0, errors.New("non-canonical length")
		}
		return n, nil
	case b0 <= 254:
		if *i+1 >= len(b) {
			return 0, errors.New("truncated length")
		}
		n := 12481 + (b0-241)*65536 + int(b[*i])*256 + int(b[*i+1])
		*i += 2
		if n <= 12480 {
			return 0, errors.New("non-canonical length")
		}
		return n, nil
	}
	return 0, errors.New("invalid length")
}

func writeVL(b *bytes.Buffer, n int) {
	switch {
	case n <= 192:
		b.WriteByte(byte(n))
	case n <= 12480:
		n -= 193
		b.Write([]byte{byte(193 + n/256), byte(n % 256)})
	default:
		n -= 12481
		b.Write([]byte{byte(241 + n/65536), byte(n / 256 % 256), byte(n % 256)})
	}
}

func readHeader(b []byte, i *int) (fieldID, error) {
	if *i >= len(b) {
		return fieldID{}, errors.New("truncated field")
	}
	b0 := b[*i]
	*i++
	t, n := int(b0>>4), int(b0&0x0f)
	if t == 0 {
		if *i >= len(b) {
			return fieldID{}, errors.New("truncated field")
		}
		t = int(b[*i])
		*i++
		if t < 16 {
			return fieldID{}, errors.New("non-canonical field header")
		}
	}
	if n == 0 {
		if *i >= len(b) {
			return fieldID{}, errors.New("truncated field")
		}
		n = int(b[*i])
		*i++
		if n < 16 {
			return fieldID{}, errors.New("non-canonical field header")
		}
	}
	return fieldID{t, n}, nil
}

func writeHeader(b *bytes.Buffer, id fieldID) {
	switch {
	case id.typ < 16 && id.nth < 16:
		b.WriteByte(byte(id.typ<<4 | id.nth))
	case id.typ >= 16 && id.nth < 16:
		b.Write([]byte{byte(id.nth), byte(id.typ)})
	case id.typ < 16:
		b.Write([]byte{byte(id.typ << 4), byte(id.nth)})
	default:
		b.Write([]byte{0, byte(id.typ), byte(id.nth)})
	}
}

var fixed = map[int]int{tUInt8: 1, tUInt16: 2, tUInt32: 4, tUInt64: 8, tHash128: 16, tHash160: 20, tHash192: 24,
	tHash256: 32, tHash384: 48, tHash512: 64, tUInt96: 12, tInt32: 4, tInt64: 8, tCurrency: 20, tNumber: 12}

func vlType(t int) bool { return t == tBlob || t == tAccountID || t == tVector256 }

// readValue returns the value bytes (without a length prefix) of a field.
func readValue(b []byte, i *int, id fieldID, depth int) ([]byte, error) {
	if depth > 4 {
		return nil, errors.New("nesting too deep")
	}
	take := func(n int) ([]byte, error) {
		if n < 0 || *i+n > len(b) {
			return nil, errors.New("truncated value")
		}
		v := b[*i : *i+n]
		*i += n
		return v, nil
	}
	if n, ok := fixed[id.typ]; ok {
		return take(n)
	}
	if vlType(id.typ) {
		n, err := readVL(b, i)
		if err != nil {
			return nil, err
		}
		return take(n)
	}
	start := *i
	switch id.typ {
	case tAmount:
		if *i >= len(b) {
			return nil, errors.New("truncated amount")
		}
		switch {
		case b[*i]&0x80 != 0:
			return take(48)
		case b[*i]&0x20 != 0:
			return take(33)
		default:
			return take(8)
		}
	case tPathSet:
		for {
			t, err := take(1)
			if err != nil {
				return nil, err
			}
			switch t[0] {
			case 0x00:
				return b[start:*i], nil
			case 0xff:
				continue
			}
			if t[0]&^0x31 != 0 {
				return nil, errors.New("invalid path step")
			}
			for _, bit := range []byte{0x01, 0x10, 0x20} {
				if t[0]&bit != 0 {
					if _, err := take(20); err != nil {
						return nil, err
					}
				}
			}
		}
	case tSTObject, tSTArray:
		end := byte(0xe1)
		if id.typ == tSTArray {
			end = 0xf1
		}
		for {
			if *i >= len(b) {
				return nil, errors.New("unterminated object")
			}
			if b[*i] == end {
				*i++
				return b[start : *i-1], nil
			}
			inner, err := readHeader(b, i)
			if err != nil {
				return nil, err
			}
			if _, err := readValue(b, i, inner, depth+1); err != nil {
				return nil, err
			}
		}
	}
	return nil, errors.New("unsupported field type " + strconv.Itoa(id.typ))
}

func less(a, b fieldID) bool { return a.typ < b.typ || (a.typ == b.typ && a.nth < b.nth) }

// Decode parses a signed transaction blob. Fields must appear in canonical
// order with minimal encodings, so the signing data and hash computed here
// are the ones the ledger computes.
func Decode(blobHex string) (*Tx, error) {
	for _, c := range blobHex {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return nil, errors.New("signedTxBlob must be hex")
		}
	}
	blob, err := hex.DecodeString(blobHex)
	if err != nil || len(blob) == 0 {
		return nil, errors.New("signedTxBlob must be hex")
	}
	t := &Tx{blob: blob, UInt32: map[string]uint32{}, Amounts: map[string]Amount{}, Accounts: map[string][20]byte{}, Present: map[string]bool{}}
	i := 0
	var prev *fieldID
	for i < len(blob) {
		start := i
		id, err := readHeader(blob, &i)
		if err != nil {
			return nil, err
		}
		if prev != nil && !less(*prev, id) {
			return nil, errors.New("fields are not in canonical order")
		}
		prev = &id
		val, err := readValue(blob, &i, id, 0)
		if err != nil {
			return nil, err
		}
		t.fields = append(t.fields, field{id: id, raw: blob[start:i], val: val})
		name, ok := names[id]
		if !ok {
			t.Unknown = append(t.Unknown, strconv.Itoa(id.typ)+"/"+strconv.Itoa(id.nth))
			continue
		}
		t.Present[name] = true
		switch id.typ {
		case tUInt16:
			v := binary.BigEndian.Uint16(val)
			t.TransactionType = &v
		case tUInt32:
			t.UInt32[name] = binary.BigEndian.Uint32(val)
		case tHash256:
			t.InvoiceID = val
		case tAmount:
			a := Amount{}
			if len(val) == 8 {
				v := binary.BigEndian.Uint64(val)
				if v&(1<<62) == 0 && v&^(1<<62) != 0 {
					return nil, errors.New("negative XRP amount")
				}
				a = Amount{Native: true, Drops: v &^ (1 << 62)}
			}
			t.Amounts[name] = a
		case tBlob:
			if name == "SigningPubKey" {
				t.SigningPubKey = val
			} else {
				t.TxnSignature = val
			}
		case tAccountID:
			if len(val) != 20 {
				return nil, errors.New("invalid account")
			}
			t.Accounts[name] = [20]byte(val)
		}
	}
	return t, nil
}

func sha512Half(parts ...[]byte) []byte {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)[:32]
}

var (
	prefixSign = []byte{0x53, 0x54, 0x58, 0x00} // STX\0
	prefixTxID = []byte{0x54, 0x58, 0x4e, 0x00} // TXN\0
)

// SigningData is what a single signer signs: every signing field, in
// canonical order, prefixed with STX\0. TxnSignature and Signers are not
// signing fields.
func (t *Tx) SigningData() []byte {
	var b bytes.Buffer
	b.Write(prefixSign)
	for _, f := range t.fields {
		if f.id == ids["TxnSignature"] || f.id == ids["Signers"] {
			continue
		}
		b.Write(f.raw)
	}
	return b.Bytes()
}

// Hash is the transaction ID: SHA-512Half of TXN\0 and the signed blob.
func (t *Tx) Hash() string {
	return strings.ToUpper(hex.EncodeToString(sha512Half(prefixTxID, t.blob)))
}

// HashBlob returns the transaction ID of a hex blob.
func HashBlob(blobHex string) (string, error) {
	t, err := Decode(blobHex)
	if err != nil {
		return "", err
	}
	return t.Hash(), nil
}

// JSON renders the understood fields as rippled tx_json, for simulate.
func (t *Tx) JSON(skip ...string) map[string]any {
	out := map[string]any{}
	omit := map[string]bool{}
	for _, s := range skip {
		omit[s] = true
	}
	for _, f := range t.fields {
		name, ok := names[f.id]
		if !ok || omit[name] {
			continue
		}
		switch f.id.typ {
		case tUInt16:
			out[name] = "Payment"
		case tUInt32:
			out[name] = t.UInt32[name]
		case tHash256:
			out[name] = strings.ToUpper(hex.EncodeToString(f.val))
		case tAmount:
			if a := t.Amounts[name]; a.Native {
				out[name] = strconv.FormatUint(a.Drops, 10)
			}
		case tBlob:
			out[name] = strings.ToUpper(hex.EncodeToString(f.val))
		case tAccountID:
			out[name] = EncodeAccountID(t.Accounts[name])
		}
	}
	return out
}

// Builder serializes a native XRP Payment in canonical field order.
type Builder struct{ fields map[fieldID][]byte }

func NewPayment() *Builder {
	b := &Builder{fields: map[fieldID][]byte{}}
	b.fields[ids["TransactionType"]] = []byte{0, 0}
	return b
}

func (b *Builder) U32(name string, v uint32) *Builder {
	b.fields[ids[name]] = binary.BigEndian.AppendUint32(nil, v)
	return b
}

func (b *Builder) Drops(name string, v uint64) *Builder {
	b.fields[ids[name]] = binary.BigEndian.AppendUint64(nil, v|1<<62)
	return b
}

func (b *Builder) Account(name string, id [20]byte) *Builder {
	b.fields[ids[name]] = id[:]
	return b
}

func (b *Builder) Blob(name string, v []byte) *Builder {
	b.fields[ids[name]] = v
	return b
}

func (b *Builder) Hash256(name string, v []byte) *Builder {
	b.fields[ids[name]] = v
	return b
}

func (b *Builder) Bytes() []byte {
	keys := make([]fieldID, 0, len(b.fields))
	for k := range b.fields {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return less(keys[i], keys[j]) })
	var out bytes.Buffer
	for _, k := range keys {
		writeHeader(&out, k)
		if vlType(k.typ) {
			writeVL(&out, len(b.fields[k]))
		}
		out.Write(b.fields[k])
	}
	return out.Bytes()
}
