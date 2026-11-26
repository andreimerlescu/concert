package fastlane

import (
	"errors"
	"math/big"
	"strings"
)

// ParseDecimalToAtomic converts a positive human decimal string (e.g. "0.99")
// into an exact integer atomic-unit string for the given decimal scale (0..18).
// Binary floating point is never used.
func ParseDecimalToAtomic(human string, decimals int) (string, error) {
	if decimals < 0 || decimals > 18 {
		return "", errors.New("asset_decimals must be between 0 and 18")
	}
	s := strings.TrimSpace(human)
	if s == "" || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "+") {
		return "", errors.New("amount must be a positive decimal")
	}
	intPart, fracPart, hasDot := strings.Cut(s, ".")
	if hasDot && strings.Contains(fracPart, ".") {
		return "", errors.New("invalid decimal amount")
	}
	if intPart == "" {
		intPart = "0"
	}
	if len(fracPart) > decimals {
		extra := strings.TrimRight(fracPart[decimals:], "0")
		if extra != "" {
			return "", errors.New("amount has more fractional digits than asset_decimals")
		}
		fracPart = fracPart[:decimals]
	}
	fracPart = fracPart + strings.Repeat("0", decimals-len(fracPart))
	digits := intPart + fracPart
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return "", errors.New("amount contains non-digit characters")
		}
	}
	n, ok := new(big.Int).SetString(digits, 10)
	if !ok || n.Sign() <= 0 || !n.IsInt64() {
		return "", errors.New("amount must be a positive int64 atomic value")
	}
	return n.String(), nil
}

// NormalizePositiveDecimal validates and canonicalizes a positive decimal
// string (e.g. "0.990" -> "0.99", "1.0" -> "1") for XRPL IOUs.
func NormalizePositiveDecimal(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "+") {
		return "", errors.New("decimal amount must be positive")
	}
	intPart, fracPart, hasDot := strings.Cut(s, ".")
	if hasDot && strings.Contains(fracPart, ".") {
		return "", errors.New("invalid decimal amount")
	}
	if intPart == "" && fracPart == "" {
		return "", errors.New("empty decimal amount")
	}
	if intPart == "" {
		intPart = "0"
	}
	for i := 0; i < len(intPart); i++ {
		if intPart[i] < '0' || intPart[i] > '9' {
			return "", errors.New("invalid decimal digits")
		}
	}
	for i := 0; i < len(fracPart); i++ {
		if fracPart[i] < '0' || fracPart[i] > '9' {
			return "", errors.New("invalid decimal digits")
		}
	}
	intPart = strings.TrimLeft(intPart, "0")
	if intPart == "" {
		intPart = "0"
	}
	fracPart = strings.TrimRight(fracPart, "0")
	if intPart == "0" && fracPart == "" {
		return "", errors.New("decimal amount must be positive")
	}
	if len(intPart)+len(fracPart) > 16 {
		return "", errors.New("decimal amount exceeds 16 significant digits")
	}
	if fracPart == "" {
		return intPart, nil
	}
	return intPart + "." + fracPart, nil
}

// FormatAtomicToDecimal renders an atomic integer string at `decimals` places
// without binary floating point (e.g. "990000", 6 -> "0.99").
func FormatAtomicToDecimal(atomic string, decimals int) string {
	s := strings.TrimSpace(atomic)
	if decimals <= 0 || s == "" {
		return s
	}
	if len(s) <= decimals {
		s = strings.Repeat("0", decimals-len(s)+1) + s
	}
	intPart := s[:len(s)-decimals]
	fracPart := strings.TrimRight(s[len(s)-decimals:], "0")
	if fracPart == "" {
		return intPart
	}
	return intPart + "." + fracPart
}

// DefaultDecimalsForAsset returns the canonical decimal precision for known
// native assets when asset_decimals is unset.
func DefaultDecimalsForAsset(network, asset string) int {
	switch chain(network) {
	case "xrpl":
		if asset == "XRP" {
			return 6
		}
		return 0 // XRPL IOUs use native decimal strings directly
	case "stellar":
		return 7
	case "hedera":
		if asset == "0.0.0" {
			return 8
		}
		return 6
	case "solana":
		if asset == "SOL" {
			return 9
		}
		return 6
	}
	return 0
}

// DefaultSymbolForAsset infers a clean human-readable asset symbol when
// asset_symbol is not explicitly provided.
func DefaultSymbolForAsset(network, asset string) string {
	switch chain(network) {
	case "xrpl":
		if asset == "XRP" {
			return "XRP"
		}
		cur, _, ok := strings.Cut(asset, ":")
		if ok && cur != "" {
			if len(cur) == 40 {
				if ascii := decodePaddedHexTicker(cur); ascii != "" {
					return ascii
				}
			}
			return cur
		}
	case "stellar":
		if strings.EqualFold(asset, "XLM") || strings.HasPrefix(asset, "C") {
			if strings.EqualFold(asset, "XLM") || asset == "CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA" || asset == "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC" {
				return "XLM"
			}
			return "TOKEN"
		}
		code, _, ok := strings.Cut(asset, ":")
		if ok && code != "" {
			return code
		}
	case "hedera":
		if asset == "0.0.0" {
			return "HBAR"
		}
		return asset
	case "solana":
		if asset == "SOL" {
			return "SOL"
		}
		return "SPL"
	}
	return asset
}

func decodePaddedHexTicker(hex40 string) string {
	if len(hex40) != 40 {
		return ""
	}
	var out []byte
	for i := 0; i < 40; i += 2 {
		hi, ok1 := hexNib(hex40[i])
		lo, ok2 := hexNib(hex40[i+1])
		if !ok1 || !ok2 {
			return ""
		}
		b := hi<<4 | lo
		if b == 0 {
			continue
		}
		if b < 0x20 || b > 0x7e {
			return ""
		}
		out = append(out, b)
	}
	return strings.TrimSpace(string(out))
}

func hexNib(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
