package concert

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Wire constants matching github.com/andreimerlescu/room v1.8+ / Concert
// stateless Ed25519 verify-only split mode.
const (
	RM1Prefix           = "rm1"
	HeaderRoomPass      = "X-Room-Pass"
	HeaderRoomLease     = "X-Room-Lease"
	RM1MinTTL           = time.Second
	RM1DefaultMaxTTL    = 15 * time.Minute
	RM1MaxTTL           = time.Hour
	RM1DefaultClockSkew = 30 * time.Second
	RM1MaxClockSkew     = 5 * time.Minute
	RM1MaxTokenLen      = 2048
	RM1MaxScopeLen      = 256
	RM1MaxKeyIDLen      = 64
	RM1MaxKeyLen        = 256
)

// RM1TokenKind identifies the capability carried by a signed rm1 envelope.
// Kind is cryptographically bound: a pass cannot be replayed as a lease.
type RM1TokenKind string

const (
	// RM1KindPass grants front-of-line VIP pass admission.
	RM1KindPass RM1TokenKind = "pass"
	// RM1KindLease grants a slot in Concert's bounded signed-lease pool.
	RM1KindLease RM1TokenKind = "lease"
)

// Sentinel errors returned by SignRM1 and VerifyRM1. Match with errors.Is.
var (
	ErrRM1InvalidKey       = errors.New("concert: invalid ed25519 key or key id")
	ErrRM1InvalidClaims    = errors.New("concert: invalid rm1 claims")
	ErrRM1Malformed        = errors.New("concert: malformed rm1 token")
	ErrRM1UnknownKey       = errors.New("concert: unknown rm1 key id")
	ErrRM1InvalidSignature = errors.New("concert: invalid rm1 signature")
	ErrRM1WrongScope       = errors.New("concert: rm1 token scope mismatch")
	ErrRM1WrongKind        = errors.New("concert: rm1 token kind mismatch")
	ErrRM1KeyMismatch      = errors.New("concert: rm1 token key binding mismatch")
	ErrRM1FutureIssued     = errors.New("concert: rm1 token issued in the future")
	ErrRM1Expired          = errors.New("concert: rm1 token expired")
)

// RM1Claims is the authenticated JSON payload carried inside an rm1 token.
// Field names and types match room.TokenClaims byte-for-byte.
type RM1Claims struct {
	KeyID     string       `json:"kid"`
	Kind      RM1TokenKind `json:"kind"`
	Scope     string       `json:"scope"`
	Key       string       `json:"key,omitempty"`
	IssuedAt  int64        `json:"iat"`
	ExpiresAt int64        `json:"exp"`
}

// RM1VerifyOptions configures strict verification of an rm1 token.
type RM1VerifyOptions struct {
	// Scope is the required service/vhost scope (for example, "shop.example.com").
	// Must be non-empty; verification fails closed if empty.
	Scope string
	// Kind is the required capability kind (RM1KindPass or RM1KindLease).
	// Defaults to RM1KindPass when empty.
	Kind RM1TokenKind
	// Key is the expected client binding key. Required for RM1KindLease and
	// enforced for RM1KindPass whenever the token itself carries a non-empty key.
	Key string
	// Now overrides the current wall clock for deterministic verification tests.
	// Defaults to time.Now().UTC() when zero.
	Now time.Time
	// MaxClockSkew sets the allowed forward clock skew on iat.
	// Defaults to RM1DefaultClockSkew (30s) when <= 0, clamped to RM1MaxClockSkew.
	MaxClockSkew time.Duration
}

// SignRM1 validates claims and signs an rm1 Ed25519 envelope wire-compatible
// with Concert and github.com/andreimerlescu/room v1.8+.
//
// # Parameters
//
//   - priv: 64-byte Ed25519 private key. Never logged or retained after return.
//   - claims: Token claims. KeyID, Kind (pass or lease), Scope, IssuedAt (> 0),
//     and ExpiresAt (> IssuedAt) must be set. Lifetime (ExpiresAt - IssuedAt)
//     must lie within [1s, 1h]. RM1KindLease requires a non-empty Key.
//
// # Returns
//
// The compact "rm1.<base64url(json)>.<base64url(sig)>" token string and nil
// error, or "" and an error matching ErrRM1InvalidKey or ErrRM1InvalidClaims.
//
// # Example
//
//	_, priv, err := ed25519.GenerateKey(rand.Reader)
//	if err != nil {
//		return err
//	}
//	now := time.Now().UTC().Unix()
//	tok, err := concert.SignRM1(priv, concert.RM1Claims{
//		KeyID:     "k1",
//		Kind:      concert.RM1KindPass,
//		Scope:     "shop.example.com",
//		IssuedAt:  now,
//		ExpiresAt: now + 300,
//	})
//	if err != nil {
//		return err
//	}
//	_ = tok
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:278 (symbol reference)
//   - clients/go/src/concert_test.go:274 (direct call)
//   - clients/go/src/doc.go:278 (symbol reference)
//   - clients/go/src/priority.go:278 (symbol reference)
//   - clients/go/src/purge.go:278 (symbol reference)
//   - clients/go/src/rm1.go:278 (direct call)
//   - clients/go/src/signals.go:278 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func SignRM1(priv ed25519.PrivateKey, claims RM1Claims) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("%w: private key must be %d bytes, got %d", ErrRM1InvalidKey, ed25519.PrivateKeySize, len(priv))
	}
	if err := validateRM1ClaimsForSign(claims); err != nil {
		return "", err
	}

	rawJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("concert: marshal rm1 claims: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(rawJSON)
	signingInput := RM1Prefix + "." + payloadB64
	sig := ed25519.Sign(priv, []byte(signingInput))
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	if len(token) > RM1MaxTokenLen {
		return "", fmt.Errorf("%w: encoded token exceeds %d bytes", ErrRM1InvalidClaims, RM1MaxTokenLen)
	}
	return token, nil
}

// MintRM1Pass signs a short-lived rm1 VIP pass envelope using the current UTC
// clock and ttl.
//
// # Parameters
//
//   - priv: 64-byte Ed25519 private key.
//   - keyID: Non-empty key identifier (max 64 bytes) matching Concert's
//     -room-verify-keys configuration.
//   - scope: Non-empty target Concert scope (e.g. primary vhost hostname).
//   - key: Optional client key binding; empty mints an anonymous browser pass.
//   - ttl: Pass lifetime in [RM1MinTTL, RM1MaxTTL].
//
// # Returns
//
// The signed rm1 pass token and nil error, or "" and an error matching
// ErrRM1InvalidKey or ErrRM1InvalidClaims.
//
// # Example
//
//	pass, err := concert.MintRM1Pass(priv, "k1", "shop.example.com", "", 5*time.Minute)
//	if err != nil {
//		return err
//	}
//	_ = pass
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:294 (direct call)
//   - clients/go/src/concert_test.go:388 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func MintRM1Pass(priv ed25519.PrivateKey, keyID, scope, key string, ttl time.Duration) (string, error) {
	return mintRM1(priv, keyID, RM1KindPass, scope, key, time.Now().UTC(), ttl)
}

// MintRM1Lease signs a short-lived rm1 lease envelope bound to key using the
// current UTC clock and ttl.
//
// # Parameters
//
//   - priv: 64-byte Ed25519 private key.
//   - keyID: Non-empty key identifier (max 64 bytes).
//   - scope: Non-empty target Concert scope.
//   - key: Required non-empty client binding key (max 256 bytes).
//   - ttl: Lease lifetime in [RM1MinTTL, RM1MaxTTL].
//
// # Returns
//
// The signed rm1 lease token and nil error, or "" and an error matching
// ErrRM1InvalidKey or ErrRM1InvalidClaims.
//
// # Example
//
//	lease, err := concert.MintRM1Lease(priv, "k1", "shop.example.com", "agent-42", 5*time.Minute)
//	if err != nil {
//		return err
//	}
//	_ = lease
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:306 (direct call)
//   - clients/go/src/concert_test.go:391 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func MintRM1Lease(priv ed25519.PrivateKey, keyID, scope, key string, ttl time.Duration) (string, error) {
	return mintRM1(priv, keyID, RM1KindLease, scope, key, time.Now().UTC(), ttl)
}

// mintRM1 constructs RM1Claims from now and ttl and delegates to SignRM1.
//
// # Parameters
//
//   - priv: 64-byte Ed25519 private key.
//   - keyID: Signing key identifier.
//   - kind: RM1KindPass or RM1KindLease.
//   - scope: Target Concert scope.
//   - key: Optional (pass) or required (lease) client binding key.
//   - now: Current timestamp used to compute iat and exp.
//   - ttl: Token lifetime in [RM1MinTTL, RM1MaxTTL].
//
// # Returns
//
// Signed rm1 token string or a validation error.
//
// # Example
//
//	tok, err := mintRM1(priv, "k1", RM1KindPass, "shop.example.com", "", time.Now().UTC(), 5*time.Minute)
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:192 (symbol reference)
//   - clients/go/src/bidding.go:228 (symbol reference)
//   - clients/go/src/doc.go:192 (symbol reference)
//   - clients/go/src/doc.go:228 (symbol reference)
//   - clients/go/src/priority.go:192 (symbol reference)
//   - clients/go/src/priority.go:228 (symbol reference)
//   - clients/go/src/purge.go:192 (symbol reference)
//   - clients/go/src/purge.go:228 (symbol reference)
//   - clients/go/src/rm1.go:192 (direct call)
//   - clients/go/src/rm1.go:228 (direct call)
//   - clients/go/src/signals.go:192 (symbol reference)
//   - clients/go/src/signals.go:228 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func mintRM1(priv ed25519.PrivateKey, keyID string, kind RM1TokenKind, scope, key string, now time.Time, ttl time.Duration) (string, error) {
	if ttl < RM1MinTTL || ttl > RM1MaxTTL {
		return "", fmt.Errorf("%w: ttl %s must be between %s and %s", ErrRM1InvalidClaims, ttl, RM1MinTTL, RM1MaxTTL)
	}
	iat := now.Unix()
	exp := now.Add(ttl).Unix()
	if exp <= iat {
		exp = iat + 1
	}
	return SignRM1(priv, RM1Claims{
		KeyID:     keyID,
		Kind:      kind,
		Scope:     scope,
		Key:       key,
		IssuedAt:  iat,
		ExpiresAt: exp,
	})
}

// VerifyRM1 authenticates an rm1 token against keys and enforces scope, kind,
// key binding, clock skew, and expiry in strict security-first order.
//
// Verification checks run in the same order as room v1.8+:
//  1. Preconditions (non-empty scope, valid key map).
//  2. Length bound, framing ("rm1.<payload>.<sig>"), strict base64url, and
//     strict JSON decode (unknown fields and trailing tokens rejected).
//  3. Ed25519 signature verification FIRST, so forged tokens never masquerade
//     as expired tokens.
//  4. Scope, kind, and key binding checks.
//  5. Clock skew (iat) and expiry (exp) checks.
//
// # Parameters
//
//   - token: Compact rm1 token string (from X-Room-Pass, X-Room-Lease, or
//     room_pass cookie). Bounded to RM1MaxTokenLen bytes.
//   - keys: Map of keyID -> 32-byte Ed25519 public key (supports multi-key
//     zero-downtime rotation). Read-only; not mutated.
//   - opts: Verification options. opts.Scope must be non-empty.
//
// # Returns
//
// Verified RM1Claims and nil error on success, or zero RM1Claims and an error
// matching one of the ErrRM1* sentinels.
//
// # Example
//
//	claims, err := concert.VerifyRM1(tok, map[string]ed25519.PublicKey{"k1": pub}, concert.RM1VerifyOptions{
//		Scope: "shop.example.com",
//		Kind:  concert.RM1KindPass,
//	})
//	if err != nil {
//		return err
//	}
//	_ = claims
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:281 (direct call)
//   - clients/go/src/concert_test.go:298 (direct call)
//   - clients/go/src/concert_test.go:310 (direct call)
//   - clients/go/src/concert_test.go:328 (direct call)
//   - clients/go/src/concert_test.go:337 (direct call)
//   - clients/go/src/concert_test.go:345 (direct call)
//   - clients/go/src/concert_test.go:354 (direct call)
//   - clients/go/src/concert_test.go:362 (direct call)
//   - clients/go/src/concert_test.go:370 (direct call)
//   - clients/go/src/concert_test.go:379 (direct call)
//   - clients/go/src/concert_test.go:425 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func VerifyRM1(token string, keys map[string]ed25519.PublicKey, opts RM1VerifyOptions) (RM1Claims, error) {
	if opts.Scope == "" || len(opts.Scope) > RM1MaxScopeLen {
		return RM1Claims{}, fmt.Errorf("%w: verification scope must be 1..%d bytes", ErrRM1InvalidClaims, RM1MaxScopeLen)
	}
	if len(keys) == 0 {
		return RM1Claims{}, fmt.Errorf("%w: at least one ed25519 public key is required", ErrRM1InvalidKey)
	}
	expectedKind := opts.Kind
	if expectedKind == "" {
		expectedKind = RM1KindPass
	}
	if expectedKind != RM1KindPass && expectedKind != RM1KindLease {
		return RM1Claims{}, fmt.Errorf("%w: unsupported expected kind %q", ErrRM1InvalidClaims, expectedKind)
	}
	if token == "" || len(token) > RM1MaxTokenLen {
		return RM1Claims{}, ErrRM1Malformed
	}

	firstDot := strings.IndexByte(token, '.')
	if firstDot <= 0 || token[:firstDot] != RM1Prefix {
		return RM1Claims{}, ErrRM1Malformed
	}
	rest := token[firstDot+1:]
	secondDot := strings.IndexByte(rest, '.')
	if secondDot <= 0 || secondDot == len(rest)-1 {
		return RM1Claims{}, ErrRM1Malformed
	}
	payloadB64 := rest[:secondDot]
	sigB64 := rest[secondDot+1:]
	if strings.IndexByte(sigB64, '.') >= 0 {
		return RM1Claims{}, ErrRM1Malformed
	}

	payloadJSON, err := base64.RawURLEncoding.Strict().DecodeString(payloadB64)
	if err != nil {
		return RM1Claims{}, fmt.Errorf("%w: decode payload: %v", ErrRM1Malformed, err)
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return RM1Claims{}, ErrRM1Malformed
	}

	var claims RM1Claims
	dec := json.NewDecoder(bytes.NewReader(payloadJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&claims); err != nil {
		return RM1Claims{}, fmt.Errorf("%w: decode claims: %v", ErrRM1Malformed, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return RM1Claims{}, ErrRM1Malformed
	}
	if claims.KeyID == "" || len(claims.KeyID) > RM1MaxKeyIDLen ||
		claims.Scope == "" || len(claims.Scope) > RM1MaxScopeLen ||
		claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt {
		return RM1Claims{}, ErrRM1Malformed
	}
	if claims.Kind != RM1KindPass && claims.Kind != RM1KindLease {
		return RM1Claims{}, ErrRM1Malformed
	}

	// Verify signature before scope/kind/expiry so forged tokens are always
	// classified as cryptographic failures rather than benign expiration.
	pub, ok := keys[claims.KeyID]
	if !ok {
		return RM1Claims{}, fmt.Errorf("%w: %q", ErrRM1UnknownKey, claims.KeyID)
	}
	if len(pub) != ed25519.PublicKeySize {
		return RM1Claims{}, fmt.Errorf("%w: public key %q must be %d bytes", ErrRM1InvalidKey, claims.KeyID, ed25519.PublicKeySize)
	}
	signingInput := token[:firstDot+1+secondDot]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return RM1Claims{}, ErrRM1InvalidSignature
	}

	if claims.Scope != opts.Scope {
		return RM1Claims{}, fmt.Errorf("%w: got %q, want %q", ErrRM1WrongScope, claims.Scope, opts.Scope)
	}
	if claims.Kind != expectedKind {
		return RM1Claims{}, fmt.Errorf("%w: got %q, want %q", ErrRM1WrongKind, claims.Kind, expectedKind)
	}
	switch expectedKind {
	case RM1KindLease:
		if claims.Key == "" {
			return RM1Claims{}, ErrRM1Malformed
		}
		if claims.Key != opts.Key {
			return RM1Claims{}, ErrRM1KeyMismatch
		}
	case RM1KindPass:
		if claims.Key != "" && claims.Key != opts.Key {
			return RM1Claims{}, ErrRM1KeyMismatch
		}
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	skew := opts.MaxClockSkew
	if skew <= 0 {
		skew = RM1DefaultClockSkew
	} else if skew > RM1MaxClockSkew {
		skew = RM1MaxClockSkew
	}
	skewSecs := int64(skew / time.Second)
	if claims.IssuedAt > now.Unix()+skewSecs {
		return RM1Claims{}, ErrRM1FutureIssued
	}
	if now.Unix() >= claims.ExpiresAt {
		return RM1Claims{}, ErrRM1Expired
	}

	return claims, nil
}

// DecodeEd25519PublicKey decodes a 32-byte Ed25519 public key from raw
// base64url, padded base64url, standard base64, or hex (matching Concert's
// -room-verify-keys parser).
//
// # Parameters
//
//   - encoded: Encoded public key string; surrounding whitespace is trimmed.
//
// # Returns
//
// A freshly allocated 32-byte ed25519.PublicKey and nil error, or nil and an
// error matching ErrRM1InvalidKey.
//
// # Example
//
//	pub, err := concert.DecodeEd25519PublicKey(b64Pub)
//	if err != nil {
//		return err
//	}
//	_ = pub
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:401 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func DecodeEd25519PublicKey(encoded string) (ed25519.PublicKey, error) {
	s := strings.TrimSpace(encoded)
	if len(s) == hex.EncodedLen(ed25519.PublicKeySize) {
		if b, err := hex.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, fmt.Errorf("%w: must decode to %d-byte ed25519 public key", ErrRM1InvalidKey, ed25519.PublicKeySize)
}

// FormatVerifyKeysFlag formats a map of keyID -> Ed25519 public key into a
// deterministic comma-separated string suitable for Concert's -room-verify-keys
// flag or CONCERT_ROOM_VERIFY_KEYS environment variable during key rotation.
//
// # Parameters
//
//   - keys: Non-empty map of valid key IDs to 32-byte Ed25519 public keys.
//
// # Returns
//
// Deterministic "kid1=<base64url>,kid2=<base64url>" string sorted by key ID,
// or "" and an error matching ErrRM1InvalidKey.
//
// # Example
//
//	spec, err := concert.FormatVerifyKeysFlag(map[string]ed25519.PublicKey{"k1": pub1, "k2": pub2})
//	if err != nil {
//		return err
//	}
//	_ = spec
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:406 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func FormatVerifyKeysFlag(keys map[string]ed25519.PublicKey) (string, error) {
	if len(keys) == 0 {
		return "", fmt.Errorf("%w: at least one public key is required", ErrRM1InvalidKey)
	}
	ids := make([]string, 0, len(keys))
	for kid := range keys {
		ids = append(ids, kid)
	}
	sort.Strings(ids)

	parts := make([]string, 0, len(ids))
	for _, kid := range ids {
		if err := validateRM1KeyID(kid); err != nil {
			return "", err
		}
		if strings.ContainsAny(kid, ",=") {
			return "", fmt.Errorf("%w: key id %q must not contain ',' or '='", ErrRM1InvalidKey, kid)
		}
		pub := keys[kid]
		if len(pub) != ed25519.PublicKeySize {
			return "", fmt.Errorf("%w: public key %q must be %d bytes", ErrRM1InvalidKey, kid, ed25519.PublicKeySize)
		}
		parts = append(parts, kid+"="+base64.RawURLEncoding.EncodeToString(pub))
	}
	return strings.Join(parts, ","), nil
}

// validateRM1ClaimsForSign verifies all structural and security bounds on
// claims before marshaling and signing.
//
// # Parameters
//
//   - c: Candidate RM1Claims to sign.
//
// # Returns
//
// nil when valid, or an error matching ErrRM1InvalidKey or ErrRM1InvalidClaims.
//
// # Example
//
//	if err := validateRM1ClaimsForSign(claims); err != nil {
//		return "", err
//	}
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:140 (symbol reference)
//   - clients/go/src/doc.go:140 (symbol reference)
//   - clients/go/src/priority.go:140 (symbol reference)
//   - clients/go/src/purge.go:140 (symbol reference)
//   - clients/go/src/rm1.go:140 (direct call)
//   - clients/go/src/signals.go:140 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func validateRM1ClaimsForSign(c RM1Claims) error {
	if err := validateRM1KeyID(c.KeyID); err != nil {
		return err
	}
	if c.Kind != RM1KindPass && c.Kind != RM1KindLease {
		return fmt.Errorf("%w: kind must be %q or %q, got %q", ErrRM1InvalidClaims, RM1KindPass, RM1KindLease, c.Kind)
	}
	if c.Scope == "" || len(c.Scope) > RM1MaxScopeLen {
		return fmt.Errorf("%w: scope must be 1..%d bytes", ErrRM1InvalidClaims, RM1MaxScopeLen)
	}
	if c.Kind == RM1KindLease && c.Key == "" {
		return fmt.Errorf("%w: lease requires non-empty key", ErrRM1InvalidClaims)
	}
	if len(c.Key) > RM1MaxKeyLen {
		return fmt.Errorf("%w: key exceeds %d bytes", ErrRM1InvalidClaims, RM1MaxKeyLen)
	}
	if c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt {
		return fmt.Errorf("%w: require iat > 0 and exp > iat", ErrRM1InvalidClaims)
	}
	ttlSecs := c.ExpiresAt - c.IssuedAt
	if ttlSecs < int64(RM1MinTTL/time.Second) || ttlSecs > int64(RM1MaxTTL/time.Second) {
		return fmt.Errorf("%w: lifetime %ds must be within [%ds, %ds]",
			ErrRM1InvalidClaims, ttlSecs, int64(RM1MinTTL/time.Second), int64(RM1MaxTTL/time.Second))
	}
	return nil
}

// validateRM1KeyID enforces Concert/room key ID length constraints.
//
// # Parameters
//
//   - kid: Candidate key identifier string.
//
// # Returns
//
// nil when kid is 1..RM1MaxKeyIDLen bytes, or an error matching
// ErrRM1InvalidKey.
//
// # Example
//
//	if err := validateRM1KeyID("k1"); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:545 (symbol reference)
//   - clients/go/src/bidding.go:590 (symbol reference)
//   - clients/go/src/doc.go:545 (symbol reference)
//   - clients/go/src/doc.go:590 (symbol reference)
//   - clients/go/src/priority.go:545 (symbol reference)
//   - clients/go/src/priority.go:590 (symbol reference)
//   - clients/go/src/purge.go:545 (symbol reference)
//   - clients/go/src/purge.go:590 (symbol reference)
//   - clients/go/src/rm1.go:545 (direct call)
//   - clients/go/src/rm1.go:590 (direct call)
//   - clients/go/src/signals.go:545 (symbol reference)
//   - clients/go/src/signals.go:590 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func validateRM1KeyID(kid string) error {
	if kid == "" {
		return fmt.Errorf("%w: key id must not be empty", ErrRM1InvalidKey)
	}
	if len(kid) > RM1MaxKeyIDLen {
		return fmt.Errorf("%w: key id exceeds %d bytes", ErrRM1InvalidKey, RM1MaxKeyIDLen)
	}
	return nil
}
