// Package base58 encodes and decodes base58 with a caller-chosen alphabet:
// Bitcoin's for Solana, Ripple's for XRPL.
package base58

import (
	"errors"
	"math/big"
)

type Alphabet struct {
	enc [58]byte
	dec [256]int16
}

func NewAlphabet(s string) *Alphabet {
	if len(s) != 58 {
		panic("base58: alphabet must have 58 characters")
	}
	a := &Alphabet{}
	for i := range a.dec {
		a.dec[i] = -1
	}
	for i := 0; i < 58; i++ {
		a.enc[i] = s[i]
		a.dec[s[i]] = int16(i)
	}
	return a
}

var (
	Bitcoin = NewAlphabet("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
	Ripple  = NewAlphabet("rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz")
)

var radix = big.NewInt(58)

func (a *Alphabet) Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	n := new(big.Int).SetBytes(b)
	var out []byte
	mod := new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, a.enc[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, a.enc[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func (a *Alphabet) Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("base58: empty string")
	}
	zeros := 0
	for zeros < len(s) && s[zeros] == a.enc[0] {
		zeros++
	}
	n := new(big.Int)
	for i := 0; i < len(s); i++ {
		d := a.dec[s[i]]
		if d < 0 {
			return nil, errors.New("base58: invalid character")
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(d)))
	}
	return append(make([]byte, zeros), n.Bytes()...), nil
}
