package xrpl

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/andreimerlescu/concert/internal/chain/base58"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // XRPL account IDs are defined with RIPEMD-160.
)

func checksum(b []byte) []byte {
	h := sha256.Sum256(b)
	h = sha256.Sum256(h[:])
	return h[:4]
}

func encodeCheck(prefix, payload []byte) string {
	b := append(append([]byte{}, prefix...), payload...)
	return base58.Ripple.Encode(append(b, checksum(b)...))
}

func decodeCheck(s string, prefix []byte, size int) ([]byte, error) {
	b, err := base58.Ripple.Decode(s)
	if err != nil || len(b) != len(prefix)+size+4 || !bytes.HasPrefix(b, prefix) {
		return nil, errors.New("invalid XRPL encoding")
	}
	body, sum := b[:len(b)-4], b[len(b)-4:]
	if !bytes.Equal(checksum(body), sum) {
		return nil, errors.New("invalid XRPL checksum")
	}
	return body[len(prefix):], nil
}

// EncodeAccountID renders a 20-byte account ID as a classic r-address.
func EncodeAccountID(id [20]byte) string { return encodeCheck([]byte{0}, id[:]) }

// DecodeAddress parses a classic r-address.
func DecodeAddress(s string) ([20]byte, error) {
	b, err := decodeCheck(s, []byte{0}, 20)
	if err != nil {
		return [20]byte{}, err
	}
	return [20]byte(b), nil
}

func ValidAddress(s string) bool { _, err := DecodeAddress(s); return err == nil }

// AccountID is RIPEMD-160(SHA-256(public key)).
func AccountID(pub []byte) [20]byte {
	s := sha256.Sum256(pub)
	r := ripemd160.New()
	r.Write(s[:])
	return [20]byte(r.Sum(nil))
}

// AddressOf derives the classic address of a public key.
func AddressOf(pub []byte) string { return EncodeAccountID(AccountID(pub)) }

func canonicalPubKey(pub []byte) bool {
	return (len(pub) == 33 && (pub[0] == 2 || pub[0] == 3 || pub[0] == 0xed))
}

// Verify checks a signature by an XRPL key over data: Ed25519 over the raw
// bytes (key prefixed with 0xED), or secp256k1 over SHA-512Half(data) with a
// strict-DER, low-S ("fully canonical") signature.
func Verify(pub, data, sig []byte) bool {
	if !canonicalPubKey(pub) {
		return false
	}
	if pub[0] == 0xed {
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(pub[1:], data, sig)
	}
	key, err := secp256k1.ParsePubKey(pub)
	if err != nil {
		return false
	}
	s, err := ecdsa.ParseDERSignature(sig)
	if err != nil {
		return false
	}
	sv := s.S()
	if sv.IsOverHalfOrder() || !bytes.Equal(s.Serialize(), sig) {
		return false
	}
	return s.Verify(sha512Half(data), key)
}

// VerifyTx checks the single-signer signature embedded in a transaction.
func (t *Tx) VerifySignature() bool {
	return len(t.TxnSignature) > 0 && Verify(t.SigningPubKey, t.SigningData(), t.TxnSignature)
}

// Key is an XRPL signing key.
type Key struct {
	Public  []byte // 33 bytes; Ed25519 keys start with 0xED
	ed      ed25519.PrivateKey
	secp    *secp256k1.PrivateKey
	Address string
}

func (k *Key) Sign(data []byte) []byte {
	if k.ed != nil {
		return ed25519.Sign(k.ed, data)
	}
	return ecdsa.Sign(k.secp, sha512Half(data)).Serialize() // RFC 6979, low S
}

var (
	seedEd25519   = []byte{0x01, 0xe1, 0x4b}
	seedSecp256k1 = []byte{0x21}
	curveOrder    = secp256k1.S256().N
)

func deriveScalar(b []byte, discrim *uint32) *big.Int {
	for i := uint32(0); ; i++ {
		var buf bytes.Buffer
		buf.Write(b)
		if discrim != nil {
			_ = binary.Write(&buf, binary.BigEndian, *discrim)
		}
		_ = binary.Write(&buf, binary.BigEndian, i)
		k := new(big.Int).SetBytes(sha512Half(buf.Bytes()))
		if k.Sign() > 0 && k.Cmp(curveOrder) < 0 {
			return k
		}
	}
}

// KeyFromSeed derives the account key of a family seed ("s…" for
// secp256k1, "sEd…" for Ed25519) exactly as ripple-keypairs does.
func KeyFromSeed(seed string) (*Key, error) {
	if entropy, err := decodeCheck(seed, seedEd25519, 16); err == nil {
		priv := ed25519.NewKeyFromSeed(sha512Half(entropy))
		pub := append([]byte{0xed}, priv.Public().(ed25519.PublicKey)...)
		return &Key{Public: pub, ed: priv, Address: AddressOf(pub)}, nil
	}
	entropy, err := decodeCheck(seed, seedSecp256k1, 16)
	if err != nil {
		return nil, errors.New("invalid XRPL seed")
	}
	gen := deriveScalar(entropy, nil)
	var genScalar secp256k1.ModNScalar
	genScalar.SetByteSlice(gen.FillBytes(make([]byte, 32)))
	genPub := secp256k1.NewPrivateKey(&genScalar).PubKey().SerializeCompressed()
	zero := uint32(0)
	d := new(big.Int).Add(deriveScalar(genPub, &zero), gen)
	d.Mod(d, curveOrder)
	priv := secp256k1.PrivKeyFromBytes(d.FillBytes(make([]byte, 32)))
	pub := priv.PubKey().SerializeCompressed()
	return &Key{Public: pub, secp: priv, Address: AddressOf(pub)}, nil
}

// VerifyMessage checks an NFT challenge signature made with ripple-keypairs'
// sign(hex(message), key): the same algorithms as transaction signing,
// without the STX\0 prefix.
func VerifyMessage(publicKeyHex, message string, signature []byte) (string, bool) {
	pub, err := hex.DecodeString(publicKeyHex)
	if err != nil || !Verify(pub, []byte(message), signature) {
		return "", false
	}
	return AddressOf(pub), true
}

func upperHex(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }
