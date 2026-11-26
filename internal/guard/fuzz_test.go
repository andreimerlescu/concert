package guard_test

import (
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/guard"
)

// FuzzRateLimitRule fuzzes ParseRule, ParseRouteRule, NewRouteLimiter, and
// Allow against arbitrary rule specifications and paths, asserting invariants
// (valid parsed rules always construct a usable limiter; denials always return
// a positive Retry-After duration).
//
// # Parameters
//
//   - f: Go fuzz harness provided by `go test -fuzz`.
//
// # Example
//
//	go test -run '^$' -fuzz '^FuzzRateLimitRule$' -fuzztime 5s ./internal/guard
//
// # Used By
//
// Invoked by the `go test -fuzz` runner.
func FuzzRateLimitRule(f *testing.F) {
	seeds := []struct {
		prefix string
		spec   string
		path   string
	}{
		{"/", "5/1m", "/"},
		{"/api/login", "10/s:20", "/api/login/submit"},
		{"/api", "1/100ms", "/apiv2"},
		{"", "5/1m", "/"},
		{"/bad", "0/1m", "/bad"},
		{"/bad", "-5/1m", "/bad"},
		{"/bad", "5/0s", "/bad"},
		{"/bad", "999999999999999999999/1m", "/bad"},
		{"/bad", "5/1m:0", "/bad"},
		{"/bad", "5/1m:999999999999999", "/bad"},
	}
	for _, s := range seeds {
		f.Add(s.prefix, s.spec, s.path)
	}

	now := time.Date(2026, 11, 26, 15, 0, 0, 0, time.UTC)
	ip := netip.MustParseAddr("198.51.100.7")

	f.Fuzz(func(t *testing.T, prefix, spec, path string) {
		r, err := guard.ParseRule(spec)
		if err == nil {
			if r.Rate <= 0 || r.Window <= 0 || r.Burst <= 0 {
				t.Fatalf("ParseRule(%q) produced non-positive field: %+v", spec, r)
			}
		}

		rr, err := guard.ParseRouteRule(prefix, spec)
		if err != nil {
			return
		}
		lim, err := guard.NewRouteLimiter([]guard.Rule{rr}, 8)
		if err != nil {
			t.Fatalf("NewRouteLimiter rejected rule from ParseRouteRule(%q, %q): %v", prefix, spec, err)
		}
		ok, retry := lim.Allow(path, ip, now)
		if ok && retry != 0 {
			t.Fatalf("Allow(%q) returned allowed=true with retryAfter=%v", path, retry)
		}
		if !ok && retry <= 0 {
			t.Fatalf("Allow(%q) returned allowed=false with non-positive retryAfter=%v", path, retry)
		}
	})
}

// FuzzPoWVerify fuzzes VerifyPoW and VerifyClearanceToken with arbitrary
// untrusted nonce, counter, and cookie token inputs, verifying panic freedom
// and that arbitrary forged inputs cannot pass verification.
//
// # Parameters
//
//   - f: Go fuzz harness provided by `go test -fuzz`.
//
// # Example
//
//	go test -run '^$' -fuzz '^FuzzPoWVerify$' -fuzztime 5s ./internal/guard
//
// # Used By
//
// Invoked by the `go test -fuzz` runner.
func FuzzPoWVerify(f *testing.F) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		f.Fatalf("rand.Read: %v", err)
	}
	gate, err := guard.NewChallengeGate(guard.ChallengeConfig{
		Mode:       guard.ModePoW,
		SigningKey: guard.NewSecret("fuzz-" + hex.EncodeToString(raw[:])),
		Difficulty: 10,
	})
	if err != nil {
		f.Fatalf("NewChallengeGate: %v", err)
	}

	now := time.Date(2026, 11, 26, 15, 0, 0, 0, time.UTC)
	ip := netip.MustParseAddr("198.51.100.8")
	validCh, err := gate.IssuePoW(ip, now)
	if err != nil {
		f.Fatalf("IssuePoW: %v", err)
	}

	f.Add(validCh.Nonce, "0", "a.b.c")
	f.Add("", "", "")
	f.Add("deadbeef.9999999999.10.deadbeef", "42", "bad.token.sig")
	f.Add("a.b.c.d.e", "counter", "a.b.c.d")

	f.Fuzz(func(t *testing.T, nonce, counter, cookieToken string) {
		ok, vErr := gate.VerifyPoW(ip, nonce, counter, now)
		if ok && vErr != nil {
			t.Fatalf("VerifyPoW returned (true, %v)", vErr)
		}
		// Any nonce not equal to the legitimately issued nonce cannot be forged.
		if ok && nonce != validCh.Nonce {
			t.Fatalf("VerifyPoW accepted forged nonce %q", nonce)
		}
		// Arbitrary cookie token cannot forge clearance under a random 256-bit key.
		if gate.VerifyClearanceToken(ip, cookieToken, now) {
			t.Fatalf("VerifyClearanceToken accepted forged token %q", cookieToken)
		}
	})
}
