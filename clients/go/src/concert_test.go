package concert_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	concert "github.com/andreimerlescu/concert/clients/go/src"
)

// newTestEd25519 generates a fresh ephemeral Ed25519 key pair for unit tests
// so no static private key material exists in test sources (S1).
//
// # Parameters
//
//   - t: Active testing handle.
//
// # Returns
//
// Generated Ed25519 public and private keys.
//
// # Example
//
//	pub, priv := newTestEd25519(t)
//
// # Used By
//
// Invoked by rm1 test functions in clients/go/src/concert_test.go.
func newTestEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

// TestPriority_FormatAndSet verifies formatting, clamping, validation, and
// header emission for all Concert priority tiers.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestPriority_FormatAndSet$' ./...
//
// # Used By
//
// Invoked by the `go test` runner.
func TestPriority_FormatAndSet(t *testing.T) {
	t.Parallel()

	validTiers := []concert.PriorityTier{
		concert.PriorityGuest,
		concert.PriorityMember,
		concert.PriorityProspect,
		concert.PriorityCustomer,
		concert.PrioritySubscriber,
		concert.PriorityCheckout,
		concert.PriorityStaff,
	}
	for _, tier := range validTiers {
		if !tier.IsValid() {
			t.Errorf("PriorityTier(%q).IsValid() = false, want true", tier)
		}
		parsed, err := concert.ParsePriorityTier("  " + strings.ToUpper(string(tier)) + " ")
		if err != nil || parsed != tier {
			t.Errorf("ParsePriorityTier(%q) = (%q, %v), want (%q, nil)", tier, parsed, err, tier)
		}
	}

	if _, err := concert.ParsePriorityTier("vip-unknown"); !errors.Is(err, concert.ErrInvalidPriorityTier) {
		t.Errorf("ParsePriorityTier(invalid) err = %v, want ErrInvalidPriorityTier", err)
	}

	cases := []struct {
		name    string
		tier    concert.PriorityTier
		ttl     time.Duration
		want    string
		wantErr error
	}{
		{name: "staff default ttl", tier: concert.PriorityStaff, ttl: 0, want: "staff"},
		{name: "checkout 30m", tier: concert.PriorityCheckout, ttl: 30 * time.Minute, want: "checkout; ttl=30m"},
		{name: "subscriber 2h", tier: concert.PrioritySubscriber, ttl: 2 * time.Hour, want: "subscriber; ttl=2h"},
		{name: "customer 90s", tier: concert.PriorityCustomer, ttl: 90 * time.Second, want: "customer; ttl=90s"},
		{name: "clamp below 1m", tier: concert.PriorityProspect, ttl: 10 * time.Second, want: "prospect; ttl=1m"},
		{name: "clamp above 24h", tier: concert.PriorityMember, ttl: 48 * time.Hour, want: "member; ttl=24h"},
		{name: "guest omits ttl", tier: concert.PriorityGuest, ttl: 10 * time.Minute, want: "guest"},
		{name: "negative ttl rejected", tier: concert.PriorityCheckout, ttl: -time.Second, wantErr: concert.ErrInvalidPriorityTTL},
		{name: "unknown tier rejected", tier: concert.PriorityTier("platinum"), ttl: 5 * time.Minute, wantErr: concert.ErrInvalidPriorityTier},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := concert.FormatPriorityHeader(tc.tier, tc.ttl)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("FormatPriorityHeader(%q, %s) err = %v, want %v", tc.tier, tc.ttl, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("FormatPriorityHeader(%q, %s) = %q, want %q", tc.tier, tc.ttl, got, tc.want)
			}
		})
	}

	if err := concert.SetPriority(nil, concert.PriorityStaff, 0); !errors.Is(err, concert.ErrNilResponseWriter) {
		t.Errorf("SetPriority(nil) err = %v, want ErrNilResponseWriter", err)
	}

	rec := httptest.NewRecorder()
	if err := concert.SetPriority(rec, concert.PriorityCheckout, 30*time.Minute); err != nil {
		t.Fatalf("SetPriority: %v", err)
	}
	if got := rec.Header().Get(concert.PriorityHeader); got != "checkout; ttl=30m" {
		t.Errorf("header %s = %q, want %q", concert.PriorityHeader, got, "checkout; ttl=30m")
	}
}

// TestPriority_MiddlewareAndGinAdapter exercises PriorityMiddleware,
// PriorityHandlerFunc, and GinPriorityAdapter under concurrent load with
// httptest.Server.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestPriority_MiddlewareAndGinAdapter$' ./...
//
// # Used By
//
// Invoked by the `go test` runner.
func TestPriority_MiddlewareAndGinAdapter(t *testing.T) {
	t.Parallel()

	resolver := func(r *http.Request) (concert.PriorityTier, time.Duration, bool) {
		switch r.URL.Path {
		case "/checkout":
			return concert.PriorityCheckout, 30 * time.Minute, true
		case "/logout":
			return concert.PriorityGuest, 0, true
		case "/bad":
			return concert.PriorityTier("invalid"), time.Minute, true
		default:
			return "", 0, false
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})

	srv := httptest.NewServer(concert.PriorityMiddleware(resolver)(mux))
	t.Cleanup(srv.Close)

	const workers = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := range workers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			path := "/checkout"
			want := "checkout; ttl=30m"
			switch idx % 4 {
			case 1:
				path, want = "/logout", "guest"
			case 2:
				path, want = "/bad", ""
			case 3:
				path, want = "/public", ""
			}
			resp, err := srv.Client().Get(srv.URL + path)
			if err != nil {
				errCh <- fmt.Errorf("GET %s: %w", path, err)
				return
			}
			defer resp.Body.Close()
			if got := resp.Header.Get(concert.PriorityHeader); got != want {
				errCh <- fmt.Errorf("GET %s header = %q, want %q", path, got, want)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	// Verify GinPriorityAdapter invokes next after setting Concert-Priority.
	adapter := concert.GinPriorityAdapter(resolver)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/checkout", nil)
	nextCalled := false
	adapter(rec, req, func() {
		nextCalled = true
		if got := rec.Header().Get(concert.PriorityHeader); got != "checkout; ttl=30m" {
			t.Errorf("inside next: %s = %q, want checkout; ttl=30m", concert.PriorityHeader, got)
		}
	})
	if !nextCalled {
		t.Fatal("GinPriorityAdapter did not invoke next")
	}

	// Verify PriorityHandlerFunc sets header without writing a body.
	recHF := httptest.NewRecorder()
	concert.PriorityHandlerFunc(resolver)(recHF, req)
	if got := recHF.Header().Get(concert.PriorityHeader); got != "checkout; ttl=30m" {
		t.Errorf("PriorityHandlerFunc header = %q, want checkout; ttl=30m", got)
	}
	if recHF.Body.Len() != 0 {
		t.Errorf("PriorityHandlerFunc wrote unexpected body %q", recHF.Body.String())
	}
}

// TestRM1_SignVerifyAndKeyRotation proves end-to-end Ed25519 rm1 pass and
// lease signing, security-first verification, key rotation, and wire format
// compatibility with room v1.8+.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestRM1_SignVerifyAndKeyRotation$' ./...
//
// # Used By
//
// Invoked by the `go test` runner.
func TestRM1_SignVerifyAndKeyRotation(t *testing.T) {
	t.Parallel()

	pub1, priv1 := newTestEd25519(t)
	pub2, priv2 := newTestEd25519(t)
	now := time.Date(2026, 11, 26, 18, 0, 0, 0, time.UTC)

	keys := map[string]ed25519.PublicKey{
		"k1": pub1,
		"k2": pub2,
	}

	// 1. Valid pass signed with k1 and k2 (zero-downtime rotation).
	claimsK1 := concert.RM1Claims{
		KeyID:     "k1",
		Kind:      concert.RM1KindPass,
		Scope:     "shop.example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
	tokK1, err := concert.SignRM1(priv1, claimsK1)
	if err != nil {
		t.Fatalf("SignRM1 k1: %v", err)
	}
	if !strings.HasPrefix(tokK1, "rm1.") || strings.Count(tokK1, ".") != 2 {
		t.Fatalf("unexpected rm1 token framing: %q", tokK1)
	}
	verified, err := concert.VerifyRM1(tokK1, keys, concert.RM1VerifyOptions{
		Scope: "shop.example.com",
		Kind:  concert.RM1KindPass,
		Now:   now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("VerifyRM1 k1: %v", err)
	}
	if verified != claimsK1 {
		t.Fatalf("verified claims = %+v, want %+v", verified, claimsK1)
	}

	// MintRM1Pass and MintRM1Lease convenience helpers.
	livePass, err := concert.MintRM1Pass(priv2, "k2", "shop.example.com", "agent-1", 5*time.Minute)
	if err != nil {
		t.Fatalf("MintRM1Pass: %v", err)
	}
	if _, err := concert.VerifyRM1(livePass, keys, concert.RM1VerifyOptions{
		Scope: "shop.example.com",
		Kind:  concert.RM1KindPass,
		Key:   "agent-1",
	}); err != nil {
		t.Fatalf("VerifyRM1 livePass: %v", err)
	}

	liveLease, err := concert.MintRM1Lease(priv2, "k2", "shop.example.com", "agent-1", 5*time.Minute)
	if err != nil {
		t.Fatalf("MintRM1Lease: %v", err)
	}
	if _, err := concert.VerifyRM1(liveLease, keys, concert.RM1VerifyOptions{
		Scope: "shop.example.com",
		Kind:  concert.RM1KindLease,
		Key:   "agent-1",
	}); err != nil {
		t.Fatalf("VerifyRM1 liveLease: %v", err)
	}

	// 2. Security-first order: tampered signature on an expired token MUST
	// report ErrRM1InvalidSignature (never ErrRM1Expired). Flip a byte in the
	// decoded signature and re-encode canonically so Strict base64url accepts it.
	parts := strings.Split(tokK1, ".")
	sigBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig for tamper test: %v", err)
	}
	sigBytes[0] ^= 0x01
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sigBytes)
	if _, err := concert.VerifyRM1(tampered, keys, concert.RM1VerifyOptions{
		Scope: "shop.example.com",
		Kind:  concert.RM1KindPass,
		Now:   now.Add(2 * time.Hour),
	}); !errors.Is(err, concert.ErrRM1InvalidSignature) {
		t.Errorf("tampered expired token err = %v, want ErrRM1InvalidSignature", err)
	}

	// 3. Scope, kind, key binding, unknown key, future iat, expiry failures.
	if _, err := concert.VerifyRM1(tokK1, keys, concert.RM1VerifyOptions{
		Scope: "blog.example.com",
		Kind:  concert.RM1KindPass,
		Now:   now,
	}); !errors.Is(err, concert.ErrRM1WrongScope) {
		t.Errorf("wrong scope err = %v, want ErrRM1WrongScope", err)
	}

	if _, err := concert.VerifyRM1(tokK1, keys, concert.RM1VerifyOptions{
		Scope: "shop.example.com",
		Kind:  concert.RM1KindLease,
		Key:   "agent-1",
		Now:   now,
	}); !errors.Is(err, concert.ErrRM1WrongKind) {
		t.Errorf("wrong kind err = %v, want ErrRM1WrongKind", err)
	}

	if _, err := concert.VerifyRM1(liveLease, keys, concert.RM1VerifyOptions{
		Scope: "shop.example.com",
		Kind:  concert.RM1KindLease,
		Key:   "other-agent",
	}); !errors.Is(err, concert.ErrRM1KeyMismatch) {
		t.Errorf("lease key mismatch err = %v, want ErrRM1KeyMismatch", err)
	}

	if _, err := concert.VerifyRM1(tokK1, map[string]ed25519.PublicKey{"k2": pub2}, concert.RM1VerifyOptions{
		Scope: "shop.example.com",
		Kind:  concert.RM1KindPass,
		Now:   now,
	}); !errors.Is(err, concert.ErrRM1UnknownKey) {
		t.Errorf("unknown kid err = %v, want ErrRM1UnknownKey", err)
	}

	if _, err := concert.VerifyRM1(tokK1, keys, concert.RM1VerifyOptions{
		Scope:        "shop.example.com",
		Kind:         concert.RM1KindPass,
		Now:          now.Add(-2 * time.Minute),
		MaxClockSkew: 30 * time.Second,
	}); !errors.Is(err, concert.ErrRM1FutureIssued) {
		t.Errorf("future iat err = %v, want ErrRM1FutureIssued", err)
	}

	if _, err := concert.VerifyRM1(tokK1, keys, concert.RM1VerifyOptions{
		Scope: "shop.example.com",
		Kind:  concert.RM1KindPass,
		Now:   now.Add(5 * time.Minute),
	}); !errors.Is(err, concert.ErrRM1Expired) {
		t.Errorf("expired token err = %v, want ErrRM1Expired", err)
	}

	// 4. Reject TTL > 1h and missing lease key at signing time.
	if _, err := concert.MintRM1Pass(priv1, "k1", "shop.example.com", "", 2*time.Hour); !errors.Is(err, concert.ErrRM1InvalidClaims) {
		t.Errorf("TTL > 1h err = %v, want ErrRM1InvalidClaims", err)
	}
	if _, err := concert.MintRM1Lease(priv1, "k1", "shop.example.com", "", 5*time.Minute); !errors.Is(err, concert.ErrRM1InvalidClaims) {
		t.Errorf("lease without key err = %v, want ErrRM1InvalidClaims", err)
	}

	// 5. Public key decoding (base64url + hex) and verify-keys flag formatter.
	for _, enc := range []string{
		base64.RawURLEncoding.EncodeToString(pub1),
		base64.StdEncoding.EncodeToString(pub1),
		hex.EncodeToString(pub1),
	} {
		dec, err := concert.DecodeEd25519PublicKey(enc)
		if err != nil || !bytes.Equal(dec, pub1) {
			t.Errorf("DecodeEd25519PublicKey(%q) = (%x, %v)", enc, dec, err)
		}
	}
	flagSpec, err := concert.FormatVerifyKeysFlag(keys)
	if err != nil {
		t.Fatalf("FormatVerifyKeysFlag: %v", err)
	}
	wantFlag := "k1=" + base64.RawURLEncoding.EncodeToString(pub1) + ",k2=" + base64.RawURLEncoding.EncodeToString(pub2)
	if flagSpec != wantFlag {
		t.Errorf("FormatVerifyKeysFlag = %q, want %q", flagSpec, wantFlag)
	}

	// 6. Concurrent VerifyRM1 under -race.
	start := make(chan struct{})
	var wg sync.WaitGroup
	var failed atomic.Bool
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 25 {
				if _, err := concert.VerifyRM1(tokK1, keys, concert.RM1VerifyOptions{
					Scope: "shop.example.com",
					Kind:  concert.RM1KindPass,
					Now:   now,
				}); err != nil {
					failed.Store(true)
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	if failed.Load() {
		t.Fatal("concurrent VerifyRM1 failed unexpectedly")
	}
}

// TestSignals_ParseWaitingRoomSignal verifies strict waiting-room header
// parsing including default StatusURL, custom StatusURL, integer and HTTP-date
// Retry-After, and non-queued 429/503 guardrails.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestSignals_ParseWaitingRoomSignal$' ./...
//
// # Used By
//
// Invoked by the `go test` runner.
func TestSignals_ParseWaitingRoomSignal(t *testing.T) {
	t.Parallel()

	// Queued response with default status URL omitted.
	h := http.Header{}
	h.Set(concert.HeaderConcertQueue, "1")
	h.Set(concert.HeaderConcertPosition, "42")
	h.Set(concert.HeaderRetryAfter, "7")

	sig := concert.ParseWaitingRoomSignal(h)
	if !sig.Queued || !sig.HasPosition || sig.Position != 42 || !sig.HasRetryAfter || sig.RetryAfter != 7*time.Second || sig.StatusURL != concert.DefaultQueueStatusURL {
		t.Fatalf("ParseWaitingRoomSignal(default) = %+v", sig)
	}

	// Custom X-Concert-Status-Url overrides default.
	h.Set(concert.HeaderConcertStatusURL, "/custom/queue/status")
	sigCustom := concert.ParseWaitingRoomSignal(h)
	if sigCustom.StatusURL != "/custom/queue/status" {
		t.Errorf("custom StatusURL = %q, want /custom/queue/status", sigCustom.StatusURL)
	}

	// Non-queued 429/503 (e.g. abuse rate-limit or upstream error) WITHOUT
	// X-Concert-Queue: 1 must NEVER set Queued=true.
	nonQueued := http.Header{}
	nonQueued.Set(concert.HeaderRetryAfter, "15")
	sigNon := concert.ParseWaitingRoomSignal(nonQueued)
	if sigNon.Queued {
		t.Fatalf("non-queued headers reported Queued=true: %+v", sigNon)
	}
	if sigNon.StatusURL != "" {
		t.Errorf("non-queued StatusURL = %q, want empty", sigNon.StatusURL)
	}
	if !sigNon.HasRetryAfter || sigNon.RetryAfter != 15*time.Second {
		t.Errorf("non-queued RetryAfter = (%v, %v), want (15s, true)", sigNon.RetryAfter, sigNon.HasRetryAfter)
	}

	// HTTP-date Retry-After parses cleanly.
	futureDate := time.Now().UTC().Add(30 * time.Second).Truncate(time.Second)
	dateHeader := http.Header{}
	dateHeader.Set(concert.HeaderConcertQueue, "1")
	dateHeader.Set(concert.HeaderRetryAfter, futureDate.Format(http.TimeFormat))
	sigDate := concert.ParseWaitingRoomSignal(dateHeader)
	if !sigDate.HasRetryAfter || sigDate.RetryAfter <= 0 {
		t.Errorf("HTTP-date RetryAfter = (%v, %v), want positive duration", sigDate.RetryAfter, sigDate.HasRetryAfter)
	}

	// Invalid negative position is ignored safely.
	badPos := http.Header{}
	badPos.Set(concert.HeaderConcertQueue, "1")
	badPos.Set(concert.HeaderConcertPosition, "-5")
	sigBad := concert.ParseWaitingRoomSignal(badPos)
	if sigBad.HasPosition {
		t.Errorf("negative position unexpectedly parsed: %+v", sigBad)
	}

	// IsQueuedResponse helper.
	if concert.IsQueuedResponse(nil) {
		t.Error("IsQueuedResponse(nil) = true, want false")
	}
	if !concert.IsQueuedResponse(&http.Response{Header: h}) {
		t.Error("IsQueuedResponse(queued) = false, want true")
	}
	if concert.IsQueuedResponse(&http.Response{Header: nonQueued}) {
		t.Error("IsQueuedResponse(nonQueued) = true, want false")
	}
}

// TestSecret_RedactionAndValidation verifies S6 redaction across all fmt,
// json, text, and slog paths and S7 fail-closed placeholder rejection.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestSecret_RedactionAndValidation$' ./...
//
// # Used By
//
// Invoked by the `go test` runner.
func TestSecret_RedactionAndValidation(t *testing.T) {
	t.Parallel()

	// Dynamically constructed runtime test sentinel (never a real credential).
	sentinel := "ephemeral-" + fmt.Sprintf("%x", time.Now().UnixNano())
	sec, err := concert.NewValidatedSecret(sentinel)
	if err != nil {
		t.Fatalf("NewValidatedSecret: %v", err)
	}
	if sec.Reveal() != sentinel {
		t.Fatal("Reveal did not return original value")
	}

	cfg := concert.CachePurgeConfig{
		BaseURL: "https://edge.example.com",
		Token:   sec,
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	logger.Info("client config", "token", sec, "cfg", cfg)

	jsonBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal(cfg): %v", err)
	}
	textBytes, err := sec.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	outputs := []string{
		sec.String(),
		sec.GoString(),
		fmt.Sprintf("%v", sec),
		fmt.Sprintf("%+v", sec),
		fmt.Sprintf("%#v", sec),
		fmt.Sprintf("%s", sec),
		fmt.Sprintf("%q", sec),
		fmt.Sprintf("%+v", cfg),
		string(jsonBytes),
		string(textBytes),
		logBuf.String(),
	}
	for i, out := range outputs {
		if strings.Contains(out, sentinel) {
			t.Errorf("output[%d] leaked secret value: %q", i, out)
		}
		if !strings.Contains(out, concert.RedactedPlaceholder) {
			t.Errorf("output[%d] missing placeholder %q: %q", i, concert.RedactedPlaceholder, out)
		}
	}

	if _, err := concert.NewValidatedSecret("   "); !errors.Is(err, concert.ErrEmptySecret) {
		t.Errorf("empty secret err = %v, want ErrEmptySecret", err)
	}
	if _, err := concert.NewValidatedSecret("changeme"); !errors.Is(err, concert.ErrPlaceholderSecret) {
		t.Errorf("placeholder secret err = %v, want ErrPlaceholderSecret", err)
	}
}

// TestCachePurgeClient_AllModesAndGuards tests PurgeURL, PurgePrefix,
// PurgeTag, PurgeAll, auth enforcement, error handling, bounded body reads,
// context cancellation, and concurrent invocation under -race.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestCachePurgeClient_AllModesAndGuards$' ./...
//
// # Used By
//
// Invoked by the `go test` runner.
func TestCachePurgeClient_AllModesAndGuards(t *testing.T) {
	t.Parallel()

	runtimeToken := "op-runtime-" + fmt.Sprintf("%x", time.Now().UnixNano())
	var reqCount atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != concert.CachePurgePath {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+runtimeToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"unauthorized"}`)
			return
		}
		var body concert.PurgeRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"bad json"}`)
			return
		}
		if body.Target == "/oversized" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(bytes.Repeat([]byte("a"), 2048))
			return
		}
		if body.Target == "/forbidden" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":"viewer token cannot purge"}`)
			return
		}
		n := reqCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(concert.PurgeResult{Purged: n, Mode: string(body.Mode)})
	}))
	t.Cleanup(srv.Close)

	// Fail-closed constructor checks.
	if _, err := concert.NewCachePurgeClient(concert.CachePurgeConfig{
		BaseURL: "ftp://invalid.example",
		Token:   concert.NewSecret(runtimeToken),
	}); !errors.Is(err, concert.ErrInvalidBaseURL) {
		t.Fatalf("invalid scheme err = %v, want ErrInvalidBaseURL", err)
	}
	badUserInfoURL := (&url.URL{
		Scheme: "https",
		User:   url.UserPassword("test-actor", "not-a-credential"),
		Host:   "edge.example",
	}).String()
	if _, err := concert.NewCachePurgeClient(concert.CachePurgeConfig{
		BaseURL: badUserInfoURL,
		Token:   concert.NewSecret(runtimeToken),
	}); !errors.Is(err, concert.ErrInvalidBaseURL) {
		t.Fatalf("userinfo URL err = %v, want ErrInvalidBaseURL", err)
	}
	if _, err := concert.NewCachePurgeClient(concert.CachePurgeConfig{
		BaseURL: srv.URL,
		Token:   concert.NewSecret(""),
	}); !errors.Is(err, concert.ErrEmptySecret) {
		t.Fatalf("empty token err = %v, want ErrEmptySecret", err)
	}

	client, err := concert.NewCachePurgeClient(concert.CachePurgeConfig{
		BaseURL:          srv.URL,
		Token:            concert.NewSecret(runtimeToken),
		Timeout:          5 * time.Second,
		MaxResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewCachePurgeClient: %v", err)
	}

	ctx := context.Background()
	resURL, err := client.PurgeURL(ctx, "shop.example.com", "/products/1")
	if err != nil || resURL.Mode != "url" || resURL.Purged < 1 {
		t.Fatalf("PurgeURL = (%+v, %v)", resURL, err)
	}
	resPrefix, err := client.PurgePrefix(ctx, "shop.example.com", "/products/")
	if err != nil || resPrefix.Mode != "prefix" {
		t.Fatalf("PurgePrefix = (%+v, %v)", resPrefix, err)
	}
	resTag, err := client.PurgeTag(ctx, "shop.example.com", "sku-1")
	if err != nil || resTag.Mode != "tag" {
		t.Fatalf("PurgeTag = (%+v, %v)", resTag, err)
	}
	resAll, err := client.PurgeAll(ctx, "shop.example.com")
	if err != nil || resAll.Mode != "all" {
		t.Fatalf("PurgeAll = (%+v, %v)", resAll, err)
	}

	// Empty target for url mode fails before HTTP call.
	if _, err := client.PurgeURL(ctx, "shop.example.com", ""); !errors.Is(err, concert.ErrInvalidPurge) {
		t.Errorf("empty url target err = %v, want ErrInvalidPurge", err)
	}

	// Non-2xx returns *APIError without leaking Bearer token.
	_, err = client.PurgeURL(ctx, "shop.example.com", "/forbidden")
	var apiErr *concert.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("forbidden err = %v, want *APIError(403)", err)
	}
	if strings.Contains(err.Error(), runtimeToken) {
		t.Fatalf("APIError leaked token: %q", err.Error())
	}

	// Bounded response read (R3).
	if _, err := client.PurgeURL(ctx, "shop.example.com", "/oversized"); !errors.Is(err, concert.ErrResponseTooLarge) {
		t.Fatalf("oversized response err = %v, want ErrResponseTooLarge", err)
	}

	// Cancelled context fails promptly.
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := client.PurgeAll(cancelCtx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ctx err = %v, want context.Canceled", err)
	}

	// Concurrent purge calls under -race.
	start := make(chan struct{})
	var wg sync.WaitGroup
	errCh := make(chan error, 12)
	for i := range 12 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			_, err := client.PurgeTag(ctx, "shop.example.com", fmt.Sprintf("tag-%d", idx))
			if err != nil {
				errCh <- err
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent PurgeTag failed: %v", err)
	}
}

// TestAgentBidClient_CryptoOnlyFlow tests ParseAuctionOffer, SubmitBid across
// all 4 supported crypto chains (xrpl, stellar, hedera, solana), strict
// rejection of fiat/non-crypto chains, GetBidStatus, and concurrent bidding
// under -race.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestAgentBidClient_CryptoOnlyFlow$' ./...
//
// # Used By
//
// Invoked by the `go test` runner.
func TestAgentBidClient_CryptoOnlyFlow(t *testing.T) {
	t.Parallel()

	// 1. ParseAuctionOffer from a realistic Concert 429 queued JSON payload.
	queued429 := []byte(`{
		"queued": true,
		"position": 9,
		"queue_depth": 42,
		"status_url": "/queue/status",
		"retry_after_seconds": 5,
		"auction": {
			"mode": "auction",
			"auction_id": "auc-2026-01",
			"scope": "shop.example.com:/drop",
			"floor_micro_usd": 1000000,
			"closes_at": "2026-11-26T18:05:00Z",
			"slots": 2,
			"min_wait_seconds": 3,
			"bid_url": "/_concert/bids",
			"status_url": "/_concert/bids/status",
			"supported_chains": ["xrpl", "stellar", "hedera", "solana"]
		}
	}`)
	offer, err := concert.ParseAuctionOffer(queued429)
	if err != nil {
		t.Fatalf("ParseAuctionOffer: %v", err)
	}
	if offer.Mode != concert.OfferModeAuction || offer.FloorMicroUSD != 1_000_000 || len(offer.SupportedChains) != 4 {
		t.Fatalf("unexpected offer: %+v", offer)
	}

	// Non-crypto chain in offer is rejected fail-closed.
	badChain429 := []byte(`{"queued":true,"auction":{"mode":"instant","scope":"s","floor_micro_usd":1000000,"supported_chains":["stripe"]}}`)
	if _, err := concert.ParseAuctionOffer(badChain429); !errors.Is(err, concert.ErrUnsupportedChain) {
		t.Fatalf("non-crypto offer err = %v, want ErrUnsupportedChain", err)
	}

	// Queued 429 without auction block returns ErrNoAuctionOffer.
	noOffer429 := []byte(`{"queued":true,"status_url":"/queue/status","retry_after_seconds":5}`)
	if _, err := concert.ParseAuctionOffer(noOffer429); !errors.Is(err, concert.ErrNoAuctionOffer) {
		t.Fatalf("missing offer err = %v, want ErrNoAuctionOffer", err)
	}

	// 2. Live httptest.Server backing POST /_concert/bids and GET /_concert/bids/status.
	var mu sync.Mutex
	bids := make(map[string]concert.BidRecord)
	var seq atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == concert.BidSubmitPath:
			var sub concert.BidSubmission
			if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"invalid JSON body"}`)
				return
			}
			if sub.AmountAtomic == "1" {
				w.WriteHeader(http.StatusPaymentRequired)
				_, _ = io.WriteString(w, `{"error":"bidding: bid below floor micro-USD"}`)
				return
			}
			id := sub.BidID
			if id == "" {
				id = fmt.Sprintf("bid-%d", seq.Add(1))
			}
			status := concert.BidStatusPending
			httpStatus := http.StatusAccepted
			passIssued := false
			passToken := ""
			if sub.Chain == concert.ChainXRPL && sub.Scope == "instant" {
				status = concert.BidStatusSettled
				httpStatus = http.StatusOK
				passIssued = true
				passToken = "signed-priority-pass-token"
			}
			rec := concert.BidRecord{
				BidID:              id,
				Scope:              sub.Scope,
				Chain:              sub.Chain,
				Asset:              sub.Asset,
				AmountAtomic:       sub.AmountAtomic,
				NormalizedMicroUSD: 1_500_000,
				Status:             status,
			}
			mu.Lock()
			bids[id] = rec
			mu.Unlock()

			w.WriteHeader(httpStatus)
			_ = json.NewEncoder(w).Encode(concert.BidResponse{
				Bid:          rec,
				BidID:        id,
				Status:       status,
				StatusURL:    concert.BidStatusPath + "?bid_id=" + id,
				PassIssued:   passIssued,
				PriorityPass: passToken,
				PassToken:    passToken,
			})

		case r.Method == http.MethodGet && r.URL.Path == concert.BidStatusPath:
			id := r.URL.Query().Get("bid_id")
			mu.Lock()
			rec, ok := bids[id]
			if ok {
				rec.Status = concert.BidStatusSettled
				rec.Transaction = "tx-hash-" + id
				bids[id] = rec
			}
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"error":"bid_not_found"}`)
				return
			}
			_ = json.NewEncoder(w).Encode(concert.BidResponse{
				Bid:          rec,
				BidID:        id,
				Status:       concert.BidStatusSettled,
				PassIssued:   true,
				PriorityPass: "priority-pass-" + id,
				PassToken:    "priority-pass-" + id,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := concert.NewAgentBidClient(concert.AgentBidConfig{
		BaseURL:        srv.URL,
		ConcertSession: "agent-sess-01",
		Timeout:        5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewAgentBidClient: %v", err)
	}

	ctx := context.Background()
	samplePayload := json.RawMessage(`{"x402Version":2,"payload":{"auth":"signed-blob"}}`)

	// Reject fiat/non-crypto chains before any network call.
	for _, bad := range []string{"stripe", "usd", "card", "fiat", ""} {
		_, err := client.SubmitBid(ctx, concert.BidSubmission{
			Chain:          bad,
			Asset:          "USDC",
			AmountAtomic:   "1500000",
			PaymentPayload: samplePayload,
		})
		if !errors.Is(err, concert.ErrUnsupportedChain) {
			t.Errorf("SubmitBid(chain=%q) err = %v, want ErrUnsupportedChain", bad, err)
		}
	}

	// Reject invalid atomic amount (float/zero/negative).
	for _, badAmt := range []string{"0", "-100", "1.50", "not-a-number"} {
		_, err := client.SubmitBid(ctx, concert.BidSubmission{
			Chain:          concert.ChainSolana,
			Asset:          "USDC",
			AmountAtomic:   badAmt,
			PaymentPayload: samplePayload,
		})
		if !errors.Is(err, concert.ErrInvalidBid) {
			t.Errorf("SubmitBid(amount=%q) err = %v, want ErrInvalidBid", badAmt, err)
		}
	}

	// Instant-buy settlement (HTTP 200) on XRPL.
	instantResp, err := client.SubmitBid(ctx, concert.BidSubmission{
		Scope:          "instant",
		Chain:          concert.ChainXRPL,
		Asset:          "XRP",
		AmountAtomic:   "2000000",
		PaymentPayload: samplePayload,
	})
	if err != nil || instantResp.Status != concert.BidStatusSettled || !instantResp.PassIssued || instantResp.PassToken == "" {
		t.Fatalf("instant SubmitBid = (%+v, %v)", instantResp, err)
	}

	// Sealed-bid submission + status poll across all 4 crypto chains concurrently.
	chains := concert.SupportedChains()
	start := make(chan struct{})
	var wg sync.WaitGroup
	errCh := make(chan error, len(chains))
	for _, ch := range chains {
		wg.Add(1)
		go func(chain string) {
			defer wg.Done()
			<-start
			subResp, err := client.SubmitBid(ctx, concert.BidSubmission{
				Scope:          "shop.example.com:/drop",
				Chain:          chain,
				Asset:          "USDC",
				AmountAtomic:   "1500000",
				PaymentPayload: samplePayload,
			})
			if err != nil {
				errCh <- fmt.Errorf("SubmitBid(%s): %w", chain, err)
				return
			}
			if subResp.Status != concert.BidStatusPending {
				errCh <- fmt.Errorf("SubmitBid(%s) status = %q, want pending", chain, subResp.Status)
				return
			}
			statResp, err := client.GetBidStatus(ctx, subResp.BidID)
			if err != nil {
				errCh <- fmt.Errorf("GetBidStatus(%s): %w", chain, err)
				return
			}
			if !statResp.PassIssued || statResp.Status != concert.BidStatusSettled {
				errCh <- fmt.Errorf("GetBidStatus(%s) = %+v, want settled with pass", chain, statResp)
			}
		}(ch)
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	// Under-floor 402 surfaces as *APIError(402).
	_, err = client.SubmitBid(ctx, concert.BidSubmission{
		Chain:          concert.ChainHedera,
		Asset:          "HBAR",
		AmountAtomic:   "1",
		PaymentPayload: samplePayload,
	})
	var apiErr *concert.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("under-floor err = %v, want *APIError(402)", err)
	}

	// Empty bidID rejected locally.
	if _, err := client.GetBidStatus(ctx, " "); !errors.Is(err, concert.ErrInvalidBid) {
		t.Errorf("GetBidStatus(empty) err = %v, want ErrInvalidBid", err)
	}
}

// ExampleFormatPriorityHeader demonstrates formatting a Concert-Priority header
// for an authenticated checkout response.
func ExampleFormatPriorityHeader() {
	val, err := concert.FormatPriorityHeader(concert.PriorityCheckout, 30*time.Minute)
	if err != nil {
		panic(err)
	}
	fmt.Println(val)
	// Output:
	// checkout; ttl=30m
}

// ExampleParseWaitingRoomSignal demonstrates detecting a genuine Concert
// waiting-room response from HTTP headers.
func ExampleParseWaitingRoomSignal() {
	h := http.Header{}
	h.Set(concert.HeaderConcertQueue, "1")
	h.Set(concert.HeaderConcertPosition, "12")
	h.Set(concert.HeaderRetryAfter, "5")

	sig := concert.ParseWaitingRoomSignal(h)
	fmt.Printf("queued=%v pos=%d retry=%s status=%s\n", sig.Queued, sig.Position, sig.RetryAfter, sig.StatusURL)
	// Output:
	// queued=true pos=12 retry=5s status=/queue/status
}
