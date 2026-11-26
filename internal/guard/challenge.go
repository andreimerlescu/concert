package guard

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// MinPoWDifficulty is the minimum supported SHA-256 leading-zero bit count.
	MinPoWDifficulty = 8

	// MaxPoWDifficulty is the maximum supported SHA-256 leading-zero bit count.
	MaxPoWDifficulty = 24

	// DefaultPoWDifficulty is the default SHA-256 leading-zero bit count when
	// ChallengeConfig.Difficulty is unset.
	DefaultPoWDifficulty = 16

	// DefaultPoWNonceTTL is the default validity window for a signed PoW challenge.
	DefaultPoWNonceTTL = 2 * time.Minute

	// DefaultClearanceTTL is the default lifetime of a minted clearance cookie.
	DefaultClearanceTTL = 15 * time.Minute

	// DefaultClearanceCookieName is the default HTTP cookie name carrying a
	// signed PoW clearance token.
	DefaultClearanceCookieName = "concert_pow"

	// DefaultPoWScriptPath is the default same-origin URL serving [PoWSolverJS]
	// under strict Content-Security-Policy (script-src 'self').
	DefaultPoWScriptPath = "/_concert/pow.js"

	// DefaultMaxUsedNonces caps the in-memory replay-protection cache (R3).
	DefaultMaxUsedNonces = 65536

	// DefaultTurnstileEndpoint is Cloudflare's Turnstile siteverify URL.
	DefaultTurnstileEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

	// DefaultTurnstileTimeout is the default end-to-end timeout for Turnstile
	// siteverify HTTPS requests.
	DefaultTurnstileTimeout = 5 * time.Second

	minSigningKeyBytes        = 16
	powRandomBytes            = 16
	maxNonceLen               = 256
	maxCounterLen             = 64
	maxTurnstileTokenBytes    = 2048
	maxTurnstileResponseBytes = 64 << 10
)

// ChallengeMode selects the pre-ticket bot-defense mechanism enforced by
// [ChallengeGate].
type ChallengeMode string

const (
	// ModeOff disables pre-ticket challenges.
	ModeOff ChallengeMode = "off"

	// ModePoW enforces built-in zero-dependency SHA-256 Proof-of-Work.
	ModePoW ChallengeMode = "pow"

	// ModeTurnstile enforces Cloudflare Turnstile siteverify verification.
	ModeTurnstile ChallengeMode = "turnstile"
)

var (
	// ErrInvalidChallengeConfig indicates invalid [ChallengeConfig] settings
	// (such as missing signing key/secret, out-of-range difficulty, or unsafe URL).
	ErrInvalidChallengeConfig = errors.New("guard: invalid challenge configuration")

	// ErrChallengeInvalid indicates a malformed, tampered, wrong-IP, or
	// insufficient-work challenge submission.
	ErrChallengeInvalid = errors.New("guard: invalid challenge")

	// ErrChallengeExpired indicates a challenge nonce has passed its expiry time.
	ErrChallengeExpired = errors.New("guard: challenge expired")

	// ErrChallengeReplayed indicates a valid challenge nonce was already consumed.
	ErrChallengeReplayed = errors.New("guard: challenge already used")

	// ErrChallengeModeMismatch indicates a PoW method was called in Turnstile
	// mode or vice versa.
	ErrChallengeModeMismatch = errors.New("guard: challenge mode mismatch")

	// ErrTurnstileUpstream indicates a network, HTTP status, size-limit, or
	// decode error communicating with the Turnstile verification endpoint.
	ErrTurnstileUpstream = errors.New("guard: turnstile verification request failed")
)

// ChallengeConfig configures a [ChallengeGate].
type ChallengeConfig struct {
	// Mode selects ModeOff, ModePoW, or ModeTurnstile. Defaults to ModeOff if empty.
	Mode ChallengeMode

	// SigningKey is the HMAC-SHA256 key used to sign PoW challenge nonces and
	// clearance cookies. Required (at least 16 bytes) when Mode == ModePoW;
	// there is intentionally no default key (S3, S7).
	SigningKey Secret

	// Difficulty is the required leading zero bits for SHA-256 PoW (8..24).
	// Defaults to DefaultPoWDifficulty (16) when 0.
	Difficulty int

	// NonceTTL is how long an issued PoW challenge nonce stays valid.
	// Defaults to DefaultPoWNonceTTL (2m) when <= 0.
	NonceTTL time.Duration

	// ClearanceTTL is how long a minted clearance cookie stays valid.
	// Defaults to DefaultClearanceTTL (15m) when <= 0.
	ClearanceTTL time.Duration

	// CookieName overrides the clearance cookie name. Defaults to "concert_pow".
	CookieName string

	// InsecureCookie disables the Secure cookie attribute when true (for local
	// HTTP development/testing only). Default false emits Secure=true.
	InsecureCookie bool

	// MaxUsedNonces bounds the in-memory replay cache for consumed PoW nonces.
	// Defaults to DefaultMaxUsedNonces (65536) when <= 0.
	MaxUsedNonces int

	// TurnstileSiteKey is the public Turnstile site key rendered on challenge pages.
	TurnstileSiteKey string

	// TurnstileSecret is the Cloudflare Turnstile secret key. Required when
	// Mode == ModeTurnstile; there is intentionally no default (S3, S7).
	TurnstileSecret Secret

	// TurnstileEndpoint overrides DefaultTurnstileEndpoint for unit tests.
	// Non-loopback endpoints must use https:// (S9).
	TurnstileEndpoint string

	// TurnstileTimeout sets the HTTP client timeout for Turnstile siteverify
	// calls. Defaults to DefaultTurnstileTimeout (5s) when <= 0.
	TurnstileTimeout time.Duration

	// HTTPClient optionally supplies the HTTP client used for Turnstile calls.
	// When nil, a dedicated client with strict dial/TLS/header/total timeouts
	// and disabled redirects is created.
	HTTPClient *http.Client
}

// PoWChallenge is an HMAC-signed Proof-of-Work challenge issued to a visitor.
type PoWChallenge struct {
	// Nonce is the opaque HMAC-signed challenge string that the solver hashes
	// as sha256(Nonce + ":" + counter).
	Nonce string

	// Difficulty is the required number of leading zero bits in the SHA-256 digest.
	Difficulty int

	// ExpiresAt is the UTC timestamp after which VerifyPoW rejects this challenge.
	ExpiresAt time.Time
}

// TurnstileResult contains the decoded Cloudflare Turnstile siteverify response.
type TurnstileResult struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
	Action      string   `json:"action"`
	CData       string   `json:"cdata"`
}

// usedNonceEntry tracks a consumed PoW nonce in an intrusive O(1) LRU list.
type usedNonceEntry struct {
	nonce string
	exp   time.Time
	prev  *usedNonceEntry
	next  *usedNonceEntry
}

// ChallengeGate enforces pre-ticket bot defense via built-in SHA-256
// Proof-of-Work ([ModePoW]) or Cloudflare Turnstile ([ModeTurnstile]).
//
// All exported methods are safe for concurrent use. Replay tracking state is
// guarded by mu and bounded to maxUsedNonces entries via O(1) LRU eviction.
type ChallengeGate struct {
	mode              ChallengeMode
	signingKey        Secret
	difficulty        int
	nonceTTL          time.Duration
	clearanceTTL      time.Duration
	cookieName        string
	insecureCookie    bool
	maxUsedNonces     int
	turnstileSiteKey  string
	turnstileSecret   Secret
	turnstileEndpoint string
	httpClient        *http.Client

	mu       sync.Mutex
	used     map[string]*usedNonceEntry // guarded by mu
	usedHead *usedNonceEntry            // MRU, guarded by mu
	usedTail *usedNonceEntry            // LRU, guarded by mu
}

// NewChallengeGate validates cfg and constructs a [ChallengeGate].
//
// Fails closed (S7) when ModePoW lacks a SigningKey of at least 16 bytes, when
// Difficulty is outside [8, 24], when ModeTurnstile lacks TurnstileSecret, or
// when TurnstileEndpoint uses a non-HTTPS scheme for a non-loopback host.
//
// # Parameters
//
//   - cfg: Challenge mode, cryptographic keys, difficulty, timeouts, and limits.
//
// # Returns
//
// A ready-to-use *ChallengeGate, or an error matching [ErrInvalidChallengeConfig].
//
// # Example
//
//	gate, err := guard.NewChallengeGate(guard.ChallengeConfig{
//	    Mode:       guard.ModePoW,
//	    SigningKey: guard.NewSecret(keyFromEnv),
//	    Difficulty: 16,
//	})
//	if err != nil {
//	    return err
//	}
//	_ = gate
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:99 (direct call)
//   - internal/guard/fuzz_test.go:736 (function value)
//   - internal/guard/fuzz_test.go:739 (function value)
//   - internal/guard/fuzz_test.go:748 (function value)
//   - internal/guard/fuzz_test.go:857 (function value)
//   - internal/guard/fuzz_test.go:899 (function value)
//   - internal/guard/guard_test.go:99 (function value)
//   - internal/guard/guard_test.go:736 (direct call)
//   - internal/guard/guard_test.go:739 (direct call)
//   - internal/guard/guard_test.go:748 (direct call)
//   - internal/guard/guard_test.go:857 (direct call)
//   - internal/guard/guard_test.go:899 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func NewChallengeGate(cfg ChallengeConfig) (*ChallengeGate, error) {
	mode := cfg.Mode
	if mode == "" {
		mode = ModeOff
	}
	switch mode {
	case ModeOff, ModePoW, ModeTurnstile:
	default:
		return nil, fmt.Errorf("%w: unknown mode %q", ErrInvalidChallengeConfig, mode)
	}

	diff := cfg.Difficulty
	if diff == 0 {
		diff = DefaultPoWDifficulty
	}
	if mode == ModePoW {
		if cfg.SigningKey.IsZero() || len(cfg.SigningKey.Reveal()) < minSigningKeyBytes {
			return nil, fmt.Errorf("%w: ModePoW requires SigningKey of at least %d bytes", ErrInvalidChallengeConfig, minSigningKeyBytes)
		}
		if looksLikePlaceholder(strings.TrimSpace(cfg.SigningKey.Reveal())) {
			return nil, fmt.Errorf("%w: SigningKey looks like a placeholder", ErrInvalidChallengeConfig)
		}
		if diff < MinPoWDifficulty || diff > MaxPoWDifficulty {
			return nil, fmt.Errorf("%w: difficulty %d out of range [%d..%d]", ErrInvalidChallengeConfig, diff, MinPoWDifficulty, MaxPoWDifficulty)
		}
	}

	nonceTTL := cfg.NonceTTL
	if nonceTTL <= 0 {
		nonceTTL = DefaultPoWNonceTTL
	}
	clearanceTTL := cfg.ClearanceTTL
	if clearanceTTL <= 0 {
		clearanceTTL = DefaultClearanceTTL
	}
	cookieName := strings.TrimSpace(cfg.CookieName)
	if cookieName == "" {
		cookieName = DefaultClearanceCookieName
	}
	maxUsed := cfg.MaxUsedNonces
	if maxUsed <= 0 {
		maxUsed = DefaultMaxUsedNonces
	}

	endpoint := strings.TrimSpace(cfg.TurnstileEndpoint)
	if endpoint == "" {
		endpoint = DefaultTurnstileEndpoint
	}
	timeout := cfg.TurnstileTimeout
	if timeout <= 0 {
		timeout = DefaultTurnstileTimeout
	}

	var client *http.Client
	if mode == ModeTurnstile {
		if cfg.TurnstileSecret.IsZero() || looksLikePlaceholder(strings.TrimSpace(cfg.TurnstileSecret.Reveal())) {
			return nil, fmt.Errorf("%w: ModeTurnstile requires non-empty TurnstileSecret", ErrInvalidChallengeConfig)
		}
		if err := validateTurnstileEndpoint(endpoint); err != nil {
			return nil, err
		}
		if cfg.HTTPClient != nil {
			client = cfg.HTTPClient
		} else {
			client = newTurnstileHTTPClient(timeout)
		}
	}

	return &ChallengeGate{
		mode:              mode,
		signingKey:        cfg.SigningKey,
		difficulty:        diff,
		nonceTTL:          nonceTTL,
		clearanceTTL:      clearanceTTL,
		cookieName:        cookieName,
		insecureCookie:    cfg.InsecureCookie,
		maxUsedNonces:     maxUsed,
		turnstileSiteKey:  cfg.TurnstileSiteKey,
		turnstileSecret:   cfg.TurnstileSecret,
		turnstileEndpoint: endpoint,
		httpClient:        client,
		used:              make(map[string]*usedNonceEntry),
	}, nil
}

// Mode returns the configured [ChallengeMode] of the gate.
//
// # Parameters
//
// None.
//
// # Returns
//
// ModeOff, ModePoW, or ModeTurnstile.
//
// # Example
//
//	m := gate.Mode()
//	_ = m
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (g *ChallengeGate) Mode() ChallengeMode {
	if g == nil {
		return ModeOff
	}
	return g.mode
}

// IssuePoW creates an HMAC-SHA256 signed Proof-of-Work challenge bound to ip's
// client bucket (IPv4 /32 or IPv6 /64) and expiring at now + NonceTTL.
//
// # Parameters
//
//   - ip: Client IP address; must be valid.
//   - now: Current timestamp; if zero, time.Now() is used.
//
// # Returns
//
// A [PoWChallenge] and nil error on success; ErrChallengeModeMismatch if the
// gate is not in ModePoW, or ErrChallengeInvalid if ip is invalid.
//
// # Example
//
//	ch, err := gate.IssuePoW(netip.MustParseAddr("198.51.100.7"), time.Now())
//	if err != nil {
//	    return err
//	}
//	_ = ch
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:110 (direct call)
//   - internal/guard/fuzz_test.go:765 (function value)
//   - internal/guard/guard_test.go:110 (function value)
//   - internal/guard/guard_test.go:765 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (g *ChallengeGate) IssuePoW(ip netip.Addr, now time.Time) (PoWChallenge, error) {
	if g == nil || g.mode != ModePoW {
		return PoWChallenge{}, ErrChallengeModeMismatch
	}
	bucket, ok := clientBucket(ip)
	if !ok {
		return PoWChallenge{}, fmt.Errorf("%w: invalid client ip", ErrChallengeInvalid)
	}
	if now.IsZero() {
		now = time.Now()
	}

	var raw [powRandomBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return PoWChallenge{}, fmt.Errorf("generate pow nonce: %w", err)
	}
	randHex := hex.EncodeToString(raw[:])
	expTime := now.UTC().Add(g.nonceTTL).Truncate(time.Second)
	expStr := strconv.FormatInt(expTime.Unix(), 10)
	diffStr := strconv.Itoa(g.difficulty)

	macHex := g.signPoW(bucket.String(), randHex, expStr, diffStr)
	nonce := randHex + "." + expStr + "." + diffStr + "." + macHex

	return PoWChallenge{
		Nonce:      nonce,
		Difficulty: g.difficulty,
		ExpiresAt:  expTime,
	}, nil
}

// VerifyPoW validates a Proof-of-Work submission (nonce, counter) for ip at
// time now.
//
// Verification checks (in order): mode, input length bounds, nonce syntax,
// difficulty bounds, expiration, constant-time HMAC-SHA256 bound to ip's
// bucket, SHA-256(nonce + ":" + counter) leading zero bits, and single-use
// replay protection. On success the nonce is recorded in the bounded replay
// cache so replaying the same solution returns (false, ErrChallengeReplayed).
//
// # Parameters
//
//   - ip: Client IP address submitting the solution.
//   - nonce: Signed challenge nonce from [ChallengeGate.IssuePoW].
//   - counter: Solver counter string (at most 64 bytes).
//   - now: Current timestamp; if zero, time.Now() is used.
//
// # Returns
//
// (true, nil) when valid and unspent; (false, err) matching one of
// ErrChallengeModeMismatch, ErrChallengeInvalid, ErrChallengeExpired, or
// ErrChallengeReplayed otherwise.
//
// # Example
//
//	ok, err := gate.VerifyPoW(ip, ch.Nonce, counter, time.Now())
//	_, _ = ok, err
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:121 (direct call)
//   - internal/guard/fuzz_test.go:775 (function value)
//   - internal/guard/fuzz_test.go:781 (function value)
//   - internal/guard/fuzz_test.go:786 (function value)
//   - internal/guard/fuzz_test.go:791 (function value)
//   - internal/guard/fuzz_test.go:796 (function value)
//   - internal/guard/guard_test.go:121 (function value)
//   - internal/guard/guard_test.go:775 (direct call)
//   - internal/guard/guard_test.go:781 (direct call)
//   - internal/guard/guard_test.go:786 (direct call)
//   - internal/guard/guard_test.go:791 (direct call)
//   - internal/guard/guard_test.go:796 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (g *ChallengeGate) VerifyPoW(ip netip.Addr, nonce, counter string, now time.Time) (bool, error) {
	if g == nil || g.mode != ModePoW {
		return false, ErrChallengeModeMismatch
	}
	bucket, ok := clientBucket(ip)
	if !ok {
		return false, fmt.Errorf("%w: invalid client ip", ErrChallengeInvalid)
	}
	if nonce == "" || len(nonce) > maxNonceLen || counter == "" || len(counter) > maxCounterLen {
		return false, fmt.Errorf("%w: missing or oversized nonce/counter", ErrChallengeInvalid)
	}
	if now.IsZero() {
		now = time.Now()
	}

	parts := strings.Split(nonce, ".")
	if len(parts) != 4 {
		return false, fmt.Errorf("%w: malformed nonce", ErrChallengeInvalid)
	}
	randHex, expStr, diffStr, macHex := parts[0], parts[1], parts[2], parts[3]
	if len(randHex) != powRandomBytes*2 {
		return false, fmt.Errorf("%w: invalid random length", ErrChallengeInvalid)
	}
	if _, err := hex.DecodeString(randHex); err != nil {
		return false, fmt.Errorf("%w: invalid random hex", ErrChallengeInvalid)
	}

	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || expUnix <= 0 {
		return false, fmt.Errorf("%w: invalid expiry", ErrChallengeInvalid)
	}
	diff, err := strconv.Atoi(diffStr)
	if err != nil || diff < MinPoWDifficulty || diff > MaxPoWDifficulty || diff < g.difficulty {
		return false, fmt.Errorf("%w: invalid difficulty", ErrChallengeInvalid)
	}

	gotMAC, err := hex.DecodeString(macHex)
	if err != nil || len(gotMAC) != sha256.Size {
		return false, fmt.Errorf("%w: invalid mac", ErrChallengeInvalid)
	}

	// Authenticate the nonce before doing expiry or replay bookkeeping so
	// unauthenticated attackers cannot probe or pollute replay state.
	wantMAC := g.computePoWMAC(bucket.String(), randHex, expStr, diffStr)
	if !hmac.Equal(gotMAC, wantMAC) {
		return false, fmt.Errorf("%w: signature mismatch", ErrChallengeInvalid)
	}

	expTime := time.Unix(expUnix, 0).UTC()
	if now.UTC().After(expTime) {
		return false, ErrChallengeExpired
	}

	sum := sha256.Sum256([]byte(nonce + ":" + counter))
	if !hasLeadingZeroBits(sum[:], diff) {
		return false, fmt.Errorf("%w: insufficient proof of work", ErrChallengeInvalid)
	}

	if !g.markNonceUsed(nonce, expTime, now.UTC()) {
		return false, ErrChallengeReplayed
	}
	return true, nil
}

// IssueClearanceCookie mints a short-lived HMAC-SHA256 signed HTTP clearance
// cookie (default name "concert_pow", HttpOnly, SameSite=Lax, Secure unless
// InsecureCookie is set) bound to ip's client bucket.
//
// # Parameters
//
//   - ip: Client IP address that passed the challenge.
//   - now: Current timestamp; if zero, time.Now() is used.
//
// # Returns
//
// A configured *http.Cookie and nil error, or an error when Mode != ModePoW or
// ip is invalid.
//
// # Example
//
//	cookie, err := gate.IssueClearanceCookie(ip, time.Now())
//	if err != nil {
//	    return err
//	}
//	http.SetCookie(w, cookie)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:801 (function value)
//   - internal/guard/guard_test.go:801 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (g *ChallengeGate) IssueClearanceCookie(ip netip.Addr, now time.Time) (*http.Cookie, error) {
	if g == nil || g.mode != ModePoW {
		return nil, ErrChallengeModeMismatch
	}
	bucket, ok := clientBucket(ip)
	if !ok {
		return nil, fmt.Errorf("%w: invalid client ip", ErrChallengeInvalid)
	}
	if now.IsZero() {
		now = time.Now()
	}

	var raw [powRandomBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("generate clearance token: %w", err)
	}
	randHex := hex.EncodeToString(raw[:])
	expTime := now.UTC().Add(g.clearanceTTL).Truncate(time.Second)
	expStr := strconv.FormatInt(expTime.Unix(), 10)
	macHex := hex.EncodeToString(g.computeClearanceMAC(bucket.String(), randHex, expStr))

	maxAge := max(int(g.clearanceTTL/time.Second), 1)
	return &http.Cookie{
		Name:     g.cookieName,
		Value:    randHex + "." + expStr + "." + macHex,
		Path:     "/",
		Expires:  expTime,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   !g.insecureCookie,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

// VerifyClearanceCookie extracts the configured clearance cookie from r and
// verifies it for ip at time now.
//
// # Parameters
//
//   - r: Incoming HTTP request; nil returns false.
//   - ip: Client IP address.
//   - now: Current timestamp; if zero, time.Now() is used.
//
// # Returns
//
// true if the request carries a valid, unexpired clearance cookie bound to ip.
//
// # Example
//
//	if gate.VerifyClearanceCookie(req, clientIP, time.Now()) {
//	    // allow into waiting room
//	}
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:810 (function value)
//   - internal/guard/fuzz_test.go:813 (function value)
//   - internal/guard/fuzz_test.go:816 (function value)
//   - internal/guard/guard_test.go:810 (direct call)
//   - internal/guard/guard_test.go:813 (direct call)
//   - internal/guard/guard_test.go:816 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (g *ChallengeGate) VerifyClearanceCookie(r *http.Request, ip netip.Addr, now time.Time) bool {
	if g == nil || r == nil || g.mode != ModePoW {
		return false
	}
	c, err := r.Cookie(g.cookieName)
	if err != nil {
		return false
	}
	return g.VerifyClearanceToken(ip, c.Value, now)
}

// VerifyClearanceToken verifies a raw clearance cookie value for ip at time now
// using constant-time HMAC comparison.
//
// # Parameters
//
//   - ip: Client IP address.
//   - token: Raw cookie value issued by [ChallengeGate.IssueClearanceCookie].
//   - now: Current timestamp; if zero, time.Now() is used.
//
// # Returns
//
// true when token is well-formed, validly signed for ip's bucket, and unexpired.
//
// # Example
//
//	valid := gate.VerifyClearanceToken(ip, cookie.Value, time.Now())
//	_ = valid
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:655 (direct call)
//   - internal/guard/fuzz_test.go:130 (direct call)
//   - internal/guard/geoasn.go:655 (function value)
//   - internal/guard/guard_test.go:130 (function value)
//   - internal/guard/queue_quota.go:655 (function value)
//   - internal/guard/ratelimit.go:655 (function value)
//   - internal/guard/secret.go:655 (function value)
//   - internal/guard/shedder.go:655 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (g *ChallengeGate) VerifyClearanceToken(ip netip.Addr, token string, now time.Time) bool {
	if g == nil || g.mode != ModePoW || token == "" || len(token) > maxNonceLen {
		return false
	}
	bucket, ok := clientBucket(ip)
	if !ok {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	randHex, expStr, macHex := parts[0], parts[1], parts[2]
	if len(randHex) != powRandomBytes*2 {
		return false
	}
	if _, err := hex.DecodeString(randHex); err != nil {
		return false
	}
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || expUnix <= 0 {
		return false
	}
	gotMAC, err := hex.DecodeString(macHex)
	if err != nil || len(gotMAC) != sha256.Size {
		return false
	}

	wantMAC := g.computeClearanceMAC(bucket.String(), randHex, expStr)
	if !hmac.Equal(gotMAC, wantMAC) {
		return false
	}
	return !now.UTC().After(time.Unix(expUnix, 0).UTC())
}

// SolvePoW searches sequentially for a decimal counter satisfying
// sha256(nonce + ":" + counter) having at least difficulty leading zero bits.
//
// # Parameters
//
//   - nonce: Non-empty challenge nonce.
//   - difficulty: Required leading zero bits in [MinPoWDifficulty, MaxPoWDifficulty].
//
// # Returns
//
// (counter, true) on success; ("", false) when nonce is empty or difficulty is
// out of range.
//
// # Example
//
//	counter, ok := guard.SolvePoW(ch.Nonce, ch.Difficulty)
//	_, _ = counter, ok
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:769 (function value)
//   - internal/guard/guard_test.go:769 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func SolvePoW(nonce string, difficulty int) (string, bool) {
	c, err := SolvePoWContext(context.Background(), nonce, difficulty)
	return c, err == nil
}

// SolvePoWContext searches for a Proof-of-Work counter while honoring ctx
// cancellation.
//
// # Parameters
//
//   - ctx: Cancellation context; checked periodically during search.
//   - nonce: Non-empty challenge nonce.
//   - difficulty: Required leading zero bits in [MinPoWDifficulty, MaxPoWDifficulty].
//
// # Returns
//
// Winning decimal counter string and nil error, or ErrChallengeInvalid / ctx.Err().
//
// # Example
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//	counter, err := guard.SolvePoWContext(ctx, ch.Nonce, ch.Difficulty)
//	_, _ = counter, err
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:758 (direct call)
//   - internal/guard/geoasn.go:758 (function value)
//   - internal/guard/queue_quota.go:758 (function value)
//   - internal/guard/ratelimit.go:758 (function value)
//   - internal/guard/secret.go:758 (function value)
//   - internal/guard/shedder.go:758 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func SolvePoWContext(ctx context.Context, nonce string, difficulty int) (string, error) {
	if nonce == "" || difficulty < MinPoWDifficulty || difficulty > MaxPoWDifficulty {
		return "", ErrChallengeInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}

	prefix := []byte(nonce + ":")
	buf := make([]byte, len(prefix), len(prefix)+20)
	copy(buf, prefix)

	for i := uint64(0); ; i++ {
		if i&0x3ff == 0 {
			if err := ctx.Err(); err != nil {
				return "", err
			}
		}
		candidate := strconv.AppendUint(buf[:len(prefix)], i, 10)
		sum := sha256.Sum256(candidate)
		if hasLeadingZeroBits(sum[:], difficulty) {
			return string(candidate[len(prefix):]), nil
		}
	}
}

// PoWChallengeHTML renders a minimal, zero-CDN HTML5 challenge page for ch
// that obeys strict Content-Security-Policy (`script-src 'self'`).
//
// The HTML contains zero inline scripts, zero inline event handlers, and zero
// external CDN references; it loads the self-hosted WebCrypto solver script
// returned by [PoWSolverJS] from scriptPath (defaulting to
// [DefaultPoWScriptPath]). All dynamic attributes are HTML-escaped (S9).
//
// # Parameters
//
//   - ch: Issued [PoWChallenge] whose Nonce and Difficulty are embedded as
//     form data attributes.
//   - submitAction: Form POST target path (defaults to "/" when empty).
//   - scriptPath: Same-origin URL path serving [PoWSolverJS] (defaults to
//     [DefaultPoWScriptPath] when empty).
//
// # Returns
//
// Complete HTML5 document string.
//
// # Example
//
//	page := guard.PoWChallengeHTML(ch, "/_concert/pow/verify", "/_concert/pow.js")
//	_ = page
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:821 (function value)
//   - internal/guard/guard_test.go:821 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func PoWChallengeHTML(ch PoWChallenge, submitAction, scriptPath string) string {
	if strings.TrimSpace(submitAction) == "" {
		submitAction = "/"
	}
	if strings.TrimSpace(scriptPath) == "" {
		scriptPath = DefaultPoWScriptPath
	}
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
	b.WriteString("<title>Verifying browser</title>\n")
	b.WriteString("</head>\n<body>\n")
	b.WriteString("<main>\n<h1>Checking your browser</h1>\n")
	b.WriteString("<p id=\"concert-pow-status\">Completing verification...</p>\n")
	b.WriteString("<form id=\"concert-pow-form\" method=\"POST\" action=\"")
	b.WriteString(html.EscapeString(submitAction))
	b.WriteString("\" data-nonce=\"")
	b.WriteString(html.EscapeString(ch.Nonce))
	b.WriteString("\" data-difficulty=\"")
	b.WriteString(strconv.Itoa(ch.Difficulty))
	b.WriteString("\">\n")
	b.WriteString("<input type=\"hidden\" name=\"nonce\" value=\"")
	b.WriteString(html.EscapeString(ch.Nonce))
	b.WriteString("\">\n")
	b.WriteString("<input type=\"hidden\" name=\"counter\" id=\"concert-pow-counter\" value=\"\">\n")
	b.WriteString("<noscript><p>JavaScript is required to continue.</p></noscript>\n")
	b.WriteString("</form>\n</main>\n")
	b.WriteString("<script src=\"")
	b.WriteString(html.EscapeString(scriptPath))
	b.WriteString("\" defer></script>\n")
	b.WriteString("</body>\n</html>\n")
	return b.String()
}

// PoWSolverJS returns the self-contained pure-JS WebCrypto SHA-256 solver
// script referenced by [PoWChallengeHTML]. Serve it from the same origin with
// `Content-Type: application/javascript; charset=utf-8` so strict CSP
// (`script-src 'self'`) is satisfied with zero external dependencies.
//
// # Parameters
//
// None.
//
// # Returns
//
// Pure JavaScript source string using window.crypto.subtle.digest("SHA-256").
//
// # Example
//
//	js := guard.PoWSolverJS()
//	_ = js
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:831 (function value)
//   - internal/guard/guard_test.go:831 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func PoWSolverJS() string {
	return powSolverScript
}

const powSolverScript = `(async function(){
"use strict";
var form=document.getElementById("concert-pow-form");
if(!form||!window.crypto||!window.crypto.subtle){return;}
var nonce=form.getAttribute("data-nonce")||"";
var diff=parseInt(form.getAttribute("data-difficulty")||"16",10);
var out=document.getElementById("concert-pow-counter");
var status=document.getElementById("concert-pow-status");
if(!nonce||!out||isNaN(diff)||diff<8||diff>24){return;}
var enc=new TextEncoder();
var full=Math.floor(diff/8),rem=diff%8,mask=rem?(0xff<<(8-rem))&0xff:0;
function ok(bytes){
  for(var i=0;i<full;i++){if(bytes[i]!==0){return false;}}
  return rem===0||(bytes[full]&mask)===0;
}
for(var c=0;;c++){
  var digest=new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(nonce+":"+c)));
  if(ok(digest)){
    out.value=String(c);
    if(status){status.textContent="Verified. Continuing...";}
    form.submit();
    return;
  }
}
})();
`

// VerifyTurnstile verifies a Cloudflare Turnstile response token via HTTPS
// POST to the configured siteverify endpoint with strict timeouts and bounded
// response reading (R3). The secret is revealed only while encoding the POST
// form body and is never included in returned errors (S5, S6).
//
// # Parameters
//
//   - ctx: Request context controlling cancellation and deadlines.
//   - token: Turnstile response token submitted by the client (non-empty, <= 2048 bytes).
//   - remoteIP: Optional client IP address forwarded as remoteip when valid.
//
// # Returns
//
// Decoded [TurnstileResult] and nil error when the upstream responds HTTP 200
// with valid JSON; zero result and an error matching ErrChallengeModeMismatch,
// ErrChallengeInvalid, or ErrTurnstileUpstream otherwise.
//
// # Example
//
//	res, err := gate.VerifyTurnstile(ctx, token, clientIP)
//	if err != nil {
//	    return err
//	}
//	if !res.Success {
//	    // reject visitor
//	}
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:912 (function value)
//   - internal/guard/fuzz_test.go:917 (function value)
//   - internal/guard/fuzz_test.go:924 (function value)
//   - internal/guard/fuzz_test.go:931 (function value)
//   - internal/guard/fuzz_test.go:939 (function value)
//   - internal/guard/fuzz_test.go:945 (function value)
//   - internal/guard/guard_test.go:912 (direct call)
//   - internal/guard/guard_test.go:917 (direct call)
//   - internal/guard/guard_test.go:924 (direct call)
//   - internal/guard/guard_test.go:931 (direct call)
//   - internal/guard/guard_test.go:939 (direct call)
//   - internal/guard/guard_test.go:945 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (g *ChallengeGate) VerifyTurnstile(ctx context.Context, token string, remoteIP netip.Addr) (TurnstileResult, error) {
	if g == nil || g.mode != ModeTurnstile {
		return TurnstileResult{}, ErrChallengeModeMismatch
	}
	if ctx == nil {
		ctx = context.Background()
	}
	token = strings.TrimSpace(token)
	if token == "" || len(token) > maxTurnstileTokenBytes {
		return TurnstileResult{}, fmt.Errorf("%w: missing or oversized turnstile token", ErrChallengeInvalid)
	}

	form := url.Values{}
	// Single point of secret reveal (S6): never logged or copied into errors.
	form.Set("secret", g.turnstileSecret.Reveal())
	form.Set("response", token)
	if ip := remoteIP.Unmap().WithZone(""); ip.IsValid() {
		form.Set("remoteip", ip.String())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.turnstileEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TurnstileResult{}, fmt.Errorf("%w: build request", ErrTurnstileUpstream)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		// Omit raw url.Error details that could carry unexpected URL context
		// while preserving context cancellation/deadline errors for callers.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return TurnstileResult{}, fmt.Errorf("%w: %w", ErrTurnstileUpstream, err)
		}
		return TurnstileResult{}, fmt.Errorf("%w: post failed", ErrTurnstileUpstream)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return TurnstileResult{}, fmt.Errorf("%w: unexpected HTTP status %d", ErrTurnstileUpstream, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTurnstileResponseBytes+1))
	if err != nil {
		return TurnstileResult{}, fmt.Errorf("%w: read response body", ErrTurnstileUpstream)
	}
	if len(body) > maxTurnstileResponseBytes {
		return TurnstileResult{}, fmt.Errorf("%w: response exceeds %d bytes", ErrTurnstileUpstream, maxTurnstileResponseBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	var res TurnstileResult
	if err := dec.Decode(&res); err != nil {
		return TurnstileResult{}, fmt.Errorf("%w: decode response JSON", ErrTurnstileUpstream)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return TurnstileResult{}, fmt.Errorf("%w: trailing data in response JSON", ErrTurnstileUpstream)
	}
	return res, nil
}

// signPoW returns the hex-encoded HMAC-SHA256 tag for a PoW challenge nonce.
//
// # Parameters
//
//   - bucket: Normalized client IP bucket string.
//   - randHex: Hex-encoded random bytes.
//   - expStr: Decimal Unix expiry timestamp.
//   - diffStr: Decimal difficulty bit count.
//
// # Returns
//
// Lowercase hex-encoded 32-byte HMAC-SHA256 digest.
//
// # Example
//
//	sig := g.signPoW("198.51.100.1", randHex, "1700000000", "16")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:430 (direct call)
//   - internal/guard/geoasn.go:430 (function value)
//   - internal/guard/queue_quota.go:430 (function value)
//   - internal/guard/ratelimit.go:430 (function value)
//   - internal/guard/secret.go:430 (function value)
//   - internal/guard/shedder.go:430 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (g *ChallengeGate) signPoW(bucket, randHex, expStr, diffStr string) string {
	return hex.EncodeToString(g.computePoWMAC(bucket, randHex, expStr, diffStr))
}

// computePoWMAC computes the raw HMAC-SHA256 tag binding bucket, random nonce,
// expiry, and difficulty under g.signingKey.
//
// # Parameters
//
//   - bucket: Normalized client IP bucket string.
//   - randHex: Hex-encoded random bytes.
//   - expStr: Decimal Unix expiry timestamp.
//   - diffStr: Decimal difficulty bit count.
//
// # Returns
//
// 32-byte HMAC-SHA256 digest.
//
// # Example
//
//	mac := g.computePoWMAC("198.51.100.1", randHex, "1700000000", "16")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:529 (direct call)
//   - internal/guard/challenge.go:1087 (direct call)
//   - internal/guard/geoasn.go:529 (function value)
//   - internal/guard/geoasn.go:1087 (function value)
//   - internal/guard/queue_quota.go:529 (function value)
//   - internal/guard/queue_quota.go:1087 (function value)
//   - internal/guard/ratelimit.go:529 (function value)
//   - internal/guard/ratelimit.go:1087 (function value)
//   - internal/guard/secret.go:529 (function value)
//   - internal/guard/secret.go:1087 (function value)
//   - internal/guard/shedder.go:529 (function value)
//   - internal/guard/shedder.go:1087 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (g *ChallengeGate) computePoWMAC(bucket, randHex, expStr, diffStr string) []byte {
	h := hmac.New(sha256.New, []byte(g.signingKey.Reveal()))
	_, _ = io.WriteString(h, "pow:v1|")
	_, _ = io.WriteString(h, bucket)
	_, _ = io.WriteString(h, "|")
	_, _ = io.WriteString(h, randHex)
	_, _ = io.WriteString(h, "|")
	_, _ = io.WriteString(h, expStr)
	_, _ = io.WriteString(h, "|")
	_, _ = io.WriteString(h, diffStr)
	return h.Sum(nil)
}

// computeClearanceMAC computes the raw HMAC-SHA256 tag for a clearance cookie
// using a distinct domain-separation prefix ("clear:v1|") so PoW nonces cannot
// be confused with clearance tokens.
//
// # Parameters
//
//   - bucket: Normalized client IP bucket string.
//   - randHex: Hex-encoded random bytes.
//   - expStr: Decimal Unix expiry timestamp.
//
// # Returns
//
// 32-byte HMAC-SHA256 digest.
//
// # Example
//
//	mac := g.computeClearanceMAC("198.51.100.1", randHex, "1700000000")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:600 (direct call)
//   - internal/guard/challenge.go:723 (direct call)
//   - internal/guard/geoasn.go:600 (function value)
//   - internal/guard/geoasn.go:723 (function value)
//   - internal/guard/queue_quota.go:600 (function value)
//   - internal/guard/queue_quota.go:723 (function value)
//   - internal/guard/ratelimit.go:600 (function value)
//   - internal/guard/ratelimit.go:723 (function value)
//   - internal/guard/secret.go:600 (function value)
//   - internal/guard/secret.go:723 (function value)
//   - internal/guard/shedder.go:600 (function value)
//   - internal/guard/shedder.go:723 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (g *ChallengeGate) computeClearanceMAC(bucket, randHex, expStr string) []byte {
	h := hmac.New(sha256.New, []byte(g.signingKey.Reveal()))
	_, _ = io.WriteString(h, "clear:v1|")
	_, _ = io.WriteString(h, bucket)
	_, _ = io.WriteString(h, "|")
	_, _ = io.WriteString(h, randHex)
	_, _ = io.WriteString(h, "|")
	_, _ = io.WriteString(h, expStr)
	return h.Sum(nil)
}

// hasLeadingZeroBits reports whether digest begins with at least bits zero bits.
//
// # Parameters
//
//   - digest: Hash byte slice (at least 32 bytes for SHA-256).
//   - bits: Number of required leading zero bits.
//
// # Returns
//
// true when the first bits bits of digest are all 0.
//
// # Example
//
//	ok := hasLeadingZeroBits(sum[:], 16)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:540 (direct call)
//   - internal/guard/challenge.go:815 (direct call)
//   - internal/guard/geoasn.go:540 (function value)
//   - internal/guard/geoasn.go:815 (function value)
//   - internal/guard/queue_quota.go:540 (function value)
//   - internal/guard/queue_quota.go:815 (function value)
//   - internal/guard/ratelimit.go:540 (function value)
//   - internal/guard/ratelimit.go:815 (function value)
//   - internal/guard/secret.go:540 (function value)
//   - internal/guard/secret.go:815 (function value)
//   - internal/guard/shedder.go:540 (function value)
//   - internal/guard/shedder.go:815 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func hasLeadingZeroBits(digest []byte, bits int) bool {
	if bits <= 0 {
		return true
	}
	if bits > len(digest)*8 {
		return false
	}
	fullBytes := bits / 8
	for i := 0; i < fullBytes; i++ {
		if digest[i] != 0 {
			return false
		}
	}
	rem := bits % 8
	if rem == 0 {
		return true
	}
	mask := byte(0xff << (8 - rem))
	return (digest[fullBytes] & mask) == 0
}

// markNonceUsed records nonce as consumed in the bounded O(1) LRU replay cache.
// Returns false if nonce is already recorded and unexpired.
//
// # Parameters
//
//   - nonce: Authenticated challenge nonce string.
//   - exp: Expiry timestamp of nonce.
//   - now: Current UTC timestamp.
//
// # Returns
//
// true if nonce was newly recorded; false if it was already consumed.
//
// # Example
//
//	fresh := g.markNonceUsed(nonce, exp, time.Now().UTC())
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:544 (direct call)
//   - internal/guard/geoasn.go:544 (function value)
//   - internal/guard/queue_quota.go:544 (function value)
//   - internal/guard/ratelimit.go:544 (function value)
//   - internal/guard/secret.go:544 (function value)
//   - internal/guard/shedder.go:544 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (g *ChallengeGate) markNonceUsed(nonce string, exp, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Evict any expired tail entries in O(1) amortized time before inserting.
	for g.usedTail != nil && now.After(g.usedTail.exp) {
		g.removeUsedLocked(g.usedTail)
	}

	if existing, ok := g.used[nonce]; ok {
		if !now.After(existing.exp) {
			return false
		}
		g.removeUsedLocked(existing)
	}

	for len(g.used) >= g.maxUsedNonces && g.usedTail != nil {
		g.removeUsedLocked(g.usedTail)
	}

	e := &usedNonceEntry{nonce: nonce, exp: exp}
	g.used[nonce] = e
	e.next = g.usedHead
	if g.usedHead != nil {
		g.usedHead.prev = e
	} else {
		g.usedTail = e
	}
	g.usedHead = e
	return true
}

// removeUsedLocked unlinks e from the replay LRU list and deletes it from g.used.
// Caller must hold g.mu.
//
// # Parameters
//
//   - e: Non-nil tracked usedNonceEntry.
//
// # Example
//
//	g.removeUsedLocked(g.usedTail)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:1279 (direct call)
//   - internal/guard/challenge.go:1286 (direct call)
//   - internal/guard/challenge.go:1290 (direct call)
//   - internal/guard/geoasn.go:1279 (function value)
//   - internal/guard/geoasn.go:1286 (function value)
//   - internal/guard/geoasn.go:1290 (function value)
//   - internal/guard/queue_quota.go:1279 (function value)
//   - internal/guard/queue_quota.go:1286 (function value)
//   - internal/guard/queue_quota.go:1290 (function value)
//   - internal/guard/ratelimit.go:1279 (function value)
//   - internal/guard/ratelimit.go:1286 (function value)
//   - internal/guard/ratelimit.go:1290 (function value)
//   - internal/guard/secret.go:1279 (function value)
//   - internal/guard/secret.go:1286 (function value)
//   - internal/guard/secret.go:1290 (function value)
//   - internal/guard/shedder.go:1279 (function value)
//   - internal/guard/shedder.go:1286 (function value)
//   - internal/guard/shedder.go:1290 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (g *ChallengeGate) removeUsedLocked(e *usedNonceEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		g.usedHead = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		g.usedTail = e.prev
	}
	e.prev = nil
	e.next = nil
	delete(g.used, e.nonce)
}

// validateTurnstileEndpoint enforces https:// for all remote endpoints while
// permitting http:// strictly for loopback addresses in local tests (S9).
//
// # Parameters
//
//   - rawURL: Candidate siteverify endpoint URL.
//
// # Returns
//
// nil if valid; an error matching [ErrInvalidChallengeConfig] otherwise.
//
// # Example
//
//	err := validateTurnstileEndpoint(guard.DefaultTurnstileEndpoint)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:320 (direct call)
//   - internal/guard/geoasn.go:320 (function value)
//   - internal/guard/queue_quota.go:320 (function value)
//   - internal/guard/ratelimit.go:320 (function value)
//   - internal/guard/secret.go:320 (function value)
//   - internal/guard/shedder.go:320 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func validateTurnstileEndpoint(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: invalid turnstile endpoint URL", ErrInvalidChallengeConfig)
	}
	if u.User != nil {
		return fmt.Errorf("%w: turnstile endpoint must not contain userinfo", ErrInvalidChallengeConfig)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if addr, err := netip.ParseAddr(host); err == nil && addr.IsLoopback() {
			return nil
		}
		return fmt.Errorf("%w: non-loopback turnstile endpoint must use https", ErrInvalidChallengeConfig)
	default:
		return fmt.Errorf("%w: unsupported turnstile endpoint scheme %q", ErrInvalidChallengeConfig, u.Scheme)
	}
}

// newTurnstileHTTPClient builds a dedicated HTTP client with strict dial, TLS,
// response-header, and total timeouts and redirects disabled so Turnstile
// secrets are never forwarded to another host (S9).
//
// # Parameters
//
//   - timeout: End-to-end request timeout.
//
// # Returns
//
// Configured *http.Client owned by the ChallengeGate.
//
// # Example
//
//	client := newTurnstileHTTPClient(5 * time.Second)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:326 (direct call)
//   - internal/guard/geoasn.go:326 (function value)
//   - internal/guard/queue_quota.go:326 (function value)
//   - internal/guard/ratelimit.go:326 (function value)
//   - internal/guard/secret.go:326 (function value)
//   - internal/guard/shedder.go:326 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func newTurnstileHTTPClient(timeout time.Duration) *http.Client {
	dialTimeout := min(timeout, 3*time.Second)
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   dialTimeout,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   8,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
