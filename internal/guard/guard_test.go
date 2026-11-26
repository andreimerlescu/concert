package guard_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/guard"
)

// ephemeralTestSecret generates a fresh random secret value at test runtime so
// no static secret-like literal ever appears in test source (S1).
//
// # Parameters
//
//   - t: Active test handle used to fail on random generation errors.
//
// # Returns
//
// A guard.Secret holding 32 random hex-encoded bytes (64 ASCII chars).
//
// # Example
//
//	sec := ephemeralTestSecret(t)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:646 (function value)
//   - internal/guard/fuzz_test.go:741 (function value)
//   - internal/guard/fuzz_test.go:747 (function value)
//   - internal/guard/fuzz_test.go:853 (function value)
//   - internal/guard/guard_test.go:646 (direct call)
//   - internal/guard/guard_test.go:741 (direct call)
//   - internal/guard/guard_test.go:747 (direct call)
//   - internal/guard/guard_test.go:853 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func ephemeralTestSecret(t *testing.T) guard.Secret {
	t.Helper()
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return guard.NewSecret("test-" + hex.EncodeToString(buf[:]))
}

// TestQueueQuota_Whitelisted500LemmingFlood simulates a 500-client flood from
// a single allowlisted IP and verifies that the flood is capped at
// AllowMaxPerIP while legitimate visitors from distinct IPs continue acquiring
// waiting-room slots freely and memory remains strictly bounded.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestQueueQuota_Whitelisted500LemmingFlood$' ./internal/guard
//
// # Used By
//
// Invoked by the `go test` runner.
func TestQueueQuota_Whitelisted500LemmingFlood(t *testing.T) {
	const (
		allowMax   = 32
		normalMax  = 8
		maxBuckets = 256
		lemmings   = 500
		realUsers  = 100
	)
	now := time.Date(2026, 11, 26, 15, 0, 0, 0, time.UTC)
	q := guard.NewQueueQuota(guard.QueueQuotaConfig{
		MaxPerIP:      normalMax,
		AllowMaxPerIP: allowMax,
		TicketTTL:     10 * time.Minute,
		MaxBuckets:    maxBuckets,
	})

	lemmingIP := netip.MustParseAddr("198.51.100.42")
	var admittedLemmings atomic.Int64
	var rejectedLemmings atomic.Int64

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range lemmings {
		wg.Go(func() {
			<-start
			ticket := fmt.Sprintf("lemming-%d", i)
			if q.TryAcquire(lemmingIP, ticket, true, now) {
				admittedLemmings.Add(1)
			} else {
				rejectedLemmings.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()

	if got := admittedLemmings.Load(); got != allowMax {
		t.Fatalf("admitted allowlisted lemmings = %d, want %d", got, allowMax)
	}
	if got := rejectedLemmings.Load(); got != lemmings-allowMax {
		t.Fatalf("rejected allowlisted lemmings = %d, want %d", got, lemmings-allowMax)
	}
	if got := q.Active(lemmingIP, now); got != allowMax {
		t.Fatalf("Active(lemmingIP) = %d, want %d", got, allowMax)
	}

	// Real visitors from distinct IPs must still acquire slots freely.
	for i := range realUsers {
		ip := netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)})
		if !q.TryAcquire(ip, fmt.Sprintf("real-%d", i), false, now) {
			t.Fatalf("legitimate visitor %s blocked during allowlisted flood", ip)
		}
	}

	if got := q.Buckets(); got > maxBuckets {
		t.Fatalf("Buckets() = %d, exceeds MaxBuckets %d", got, maxBuckets)
	}

	// Spray 10x MaxBuckets distinct IPs to prove strict O(1) LRU memory bound.
	for i := range maxBuckets * 10 {
		ip := netip.AddrFrom4([4]byte{10, byte((i >> 16) & 0xff), byte((i >> 8) & 0xff), byte(i & 0xff)})
		_ = q.TryAcquire(ip, "spray", false, now)
	}
	if got := q.Buckets(); got != maxBuckets {
		t.Fatalf("Buckets() after IP spray = %d, want %d", got, maxBuckets)
	}
}

// TestQueueQuota_IPv6BucketTTLReleaseSweep verifies IPv6 /64 bucketing,
// IPv4-in-IPv6 unmapping, idempotent ticket refresh, Release reclamation,
// TTL expiration, and Sweep cleanup.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -run '^TestQueueQuota_IPv6BucketTTLReleaseSweep$' ./internal/guard
//
// # Used By
//
// Invoked by the `go test` runner.
func TestQueueQuota_IPv6BucketTTLReleaseSweep(t *testing.T) {
	now := time.Date(2026, 11, 26, 15, 0, 0, 0, time.UTC)
	q := guard.NewQueueQuota(guard.QueueQuotaConfig{
		MaxPerIP:      2,
		AllowMaxPerIP: 4,
		TicketTTL:     time.Minute,
		MaxBuckets:    16,
	})

	// Invalid IP or empty ticket must fail closed.
	if q.TryAcquire(netip.Addr{}, "t1", false, now) {
		t.Fatal("TryAcquire accepted invalid IP")
	}
	v6a := netip.MustParseAddr("2001:db8:abcd:1234::1")
	v6b := netip.MustParseAddr("2001:db8:abcd:1234::dead:beef")
	if q.TryAcquire(v6a, "", false, now) {
		t.Fatal("TryAcquire accepted empty ticket")
	}

	// Two addresses in the same /64 share one bucket (cap 2).
	if !q.TryAcquire(v6a, "t1", false, now) {
		t.Fatal("first /64 acquire failed")
	}
	if !q.TryAcquire(v6b, "t2", false, now) {
		t.Fatal("second /64 acquire failed")
	}
	if q.TryAcquire(v6b, "t3", false, now) {
		t.Fatal("third /64 acquire exceeded MaxPerIP=2")
	}
	// Refreshing an existing ticket is idempotent and does not consume a new slot.
	if !q.TryAcquire(v6a, "t1", false, now.Add(30*time.Second)) {
		t.Fatal("idempotent refresh of held ticket failed")
	}

	// IPv4-mapped IPv6 maps to the same bucket as IPv4.
	v4 := netip.MustParseAddr("192.0.2.5")
	v4Mapped := netip.MustParseAddr("::ffff:192.0.2.5")
	if !q.TryAcquire(v4, "m1", false, now) || !q.TryAcquire(v4Mapped, "m2", false, now) {
		t.Fatal("v4 / v4-mapped acquire failed")
	}
	if q.TryAcquire(v4, "m3", false, now) {
		t.Fatal("v4-mapped did not share IPv4 /32 bucket")
	}

	// Release frees slots and removes empty buckets.
	q.Release(v4, "m1")
	q.Release(v4Mapped, "m2")
	if got := q.Active(v4, now); got != 0 {
		t.Fatalf("Active(v4) after release = %d, want 0", got)
	}

	// At now+61s, t2 expired (TTL 1m), while refreshed t1 (at +30s -> +90s) stays active.
	if got := q.Active(v6a, now.Add(61*time.Second)); got != 1 {
		t.Fatalf("Active(v6a) at +61s = %d, want 1", got)
	}

	// Sweep past all expiries reclaims every bucket.
	q.Sweep(now.Add(2 * time.Minute))
	if got := q.Buckets(); got != 0 {
		t.Fatalf("Buckets() after full Sweep = %d, want 0", got)
	}
}

// TestHostShedder_ThresholdsAndLifecycle verifies memory, FD, and connection
// shedding thresholds, priority order, HTTP 503 Retry-After output, and clean
// background goroutine startup/shutdown without time.Sleep.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestHostShedder_ThresholdsAndLifecycle$' ./internal/guard
//
// # Used By
//
// Invoked by the `go test` runner.
func TestHostShedder_ThresholdsAndLifecycle(t *testing.T) {
	var sampleMu sync.Mutex
	current := guard.HostSample{
		MemoryBytes: 100 << 20,
		OpenFDs:     100,
		ActiveConns: 10,
	}
	sampledCh := make(chan struct{}, 16)

	s := guard.NewHostShedder(guard.HostShedderConfig{
		MaxMemoryBytes: 500 << 20,
		MaxOpenFDs:     1000,
		MaxActiveConns: 200,
		PollInterval:   5 * time.Millisecond,
		RetryAfter:     7 * time.Second,
		Sampler: func() guard.HostSample {
			sampleMu.Lock()
			v := current
			sampleMu.Unlock()
			select {
			case sampledCh <- struct{}{}:
			default:
			}
			return v
		},
	})

	// Stop before Start must be a safe no-op.
	s.Stop()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s.Start(ctx)
	// Second Start while running must be a safe no-op.
	s.Start(ctx)

	// Synchronous initial sample ran inside Start.
	if shed, reason := s.ShouldShed(); shed || reason != guard.ShedNone {
		t.Fatalf("initial ShouldShed = (%v, %q), want (false, %q)", shed, reason, guard.ShedNone)
	}

	// Trigger connection shedding via deterministic sample.
	sampleMu.Lock()
	current.ActiveConns = 250
	sampleMu.Unlock()
	s.SampleNow()
	if shed, reason := s.ShouldShed(); !shed || reason != guard.ShedConnections {
		t.Fatalf("ShouldShed(conns) = (%v, %q), want (true, %q)", shed, reason, guard.ShedConnections)
	}

	// FD shedding overrides connections.
	sampleMu.Lock()
	current.OpenFDs = 1000
	sampleMu.Unlock()
	s.SampleNow()
	if shed, reason := s.ShouldShed(); !shed || reason != guard.ShedFDs {
		t.Fatalf("ShouldShed(fds) = (%v, %q), want (true, %q)", shed, reason, guard.ShedFDs)
	}

	// Memory shedding overrides both FDs and connections.
	sampleMu.Lock()
	current.MemoryBytes = 500 << 20
	sampleMu.Unlock()
	s.SampleNow()
	if shed, reason := s.ShouldShed(); !shed || reason != guard.ShedMemory {
		t.Fatalf("ShouldShed(memory) = (%v, %q), want (true, %q)", shed, reason, guard.ShedMemory)
	}

	// Verify 503 response formatting.
	rec := httptest.NewRecorder()
	s.WriteShedResponse(rec, guard.ShedMemory)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "7" {
		t.Fatalf("Retry-After = %q, want %q", got, "7")
	}
	if got := rec.Header().Get("X-Concert-Shed-Reason"); got != string(guard.ShedMemory) {
		t.Fatalf("X-Concert-Shed-Reason = %q, want %q", got, guard.ShedMemory)
	}

	// Wait for at least one background tick via channel (no time.Sleep).
	select {
	case <-sampledCh:
	case <-time.After(2 * time.Second):
		t.Fatal("background sampler did not tick")
	}

	// Recover headroom and verify ShouldShed clears.
	sampleMu.Lock()
	current = guard.HostSample{MemoryBytes: 50 << 20, OpenFDs: 50, ActiveConns: 5}
	sampleMu.Unlock()
	s.SampleNow()
	if shed, reason := s.ShouldShed(); shed || reason != guard.ShedNone {
		t.Fatalf("recovered ShouldShed = (%v, %q), want (false, %q)", shed, reason, guard.ShedNone)
	}

	// Clean Stop and idempotent second Stop.
	s.Stop()
	s.Stop()
}

// TestHostShedder_LiveConnectionsAndDefaultSampler verifies immediate shedding
// from the internal connection counter and real runtime default sampling.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -run '^TestHostShedder_LiveConnectionsAndDefaultSampler$' ./internal/guard
//
// # Used By
//
// Invoked by the `go test` runner.
func TestHostShedder_LiveConnectionsAndDefaultSampler(t *testing.T) {
	s := guard.NewHostShedder(guard.HostShedderConfig{
		MaxActiveConns: 2,
	})
	if s.IncActiveConns() != 1 || s.IncActiveConns() != 2 {
		t.Fatal("unexpected IncActiveConns counts")
	}
	if shed, reason := s.ShouldShed(); !shed || reason != guard.ShedConnections {
		t.Fatalf("ShouldShed at live limit = (%v, %q), want (true, %q)", shed, reason, guard.ShedConnections)
	}
	if s.DecActiveConns() != 1 {
		t.Fatal("unexpected DecActiveConns count")
	}
	if shed, _ := s.ShouldShed(); shed {
		t.Fatal("ShouldShed remained true after dropping below MaxActiveConns")
	}
	s.DecActiveConns()
	if got := s.DecActiveConns(); got != 0 {
		t.Fatalf("DecActiveConns below zero = %d, want 0", got)
	}
	sample := s.SampleNow()
	if sample.MemoryBytes == 0 || sample.SampledAt.IsZero() {
		t.Fatalf("default SampleNow returned incomplete sample: %+v", sample)
	}
	if last := s.LastSample(); last.SampledAt != sample.SampledAt {
		t.Fatalf("LastSample mismatch: got %+v, want %+v", last, sample)
	}
}

// TestRouteLimiter_RulesMatchingRefillLRUAndRace verifies rule parsing,
// longest-prefix segment matching, token refill and Retry-After accuracy, O(1)
// LRU eviction ordering, and concurrent race safety.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestRouteLimiter_RulesMatchingRefillLRUAndRace$' ./internal/guard
//
// # Used By
//
// Invoked by the `go test` runner.
func TestRouteLimiter_RulesMatchingRefillLRUAndRace(t *testing.T) {
	validSpecs := []struct {
		spec       string
		wantRate   int
		wantWindow time.Duration
		wantBurst  int
	}{
		{"5/1m", 5, time.Minute, 5},
		{"10/s", 10, time.Second, 10},
		{"3/30s:6", 3, 30 * time.Second, 6},
		{"120/h:150", 120, time.Hour, 150},
	}
	for _, tc := range validSpecs {
		got, err := guard.ParseRule(tc.spec)
		if err != nil {
			t.Fatalf("ParseRule(%q) unexpected error: %v", tc.spec, err)
		}
		if got.Rate != tc.wantRate || got.Window != tc.wantWindow || got.Burst != tc.wantBurst {
			t.Errorf("ParseRule(%q) = %+v, want rate=%d window=%v burst=%d", tc.spec, got, tc.wantRate, tc.wantWindow, tc.wantBurst)
		}
	}

	invalidSpecs := []string{"", "5", "0/1m", "-1/1m", "5/0s", "5/-1m", "5/bogus", "5/1m:0", "abc/1m"}
	for _, spec := range invalidSpecs {
		if _, err := guard.ParseRule(spec); !errors.Is(err, guard.ErrInvalidRule) {
			t.Errorf("ParseRule(%q) err = %v, want ErrInvalidRule", spec, err)
		}
	}

	rRoot, err := guard.ParseRouteRule("/", "100/1m")
	if err != nil {
		t.Fatalf("ParseRouteRule(/): %v", err)
	}
	rAPI, err := guard.ParseRouteRule("/api", "10/1m")
	if err != nil {
		t.Fatalf("ParseRouteRule(/api): %v", err)
	}
	rLogin, err := guard.ParseRouteRule("/api/login", "2/1m")
	if err != nil {
		t.Fatalf("ParseRouteRule(/api/login): %v", err)
	}

	// Duplicate prefixes must be rejected.
	if _, err := guard.NewRouteLimiter([]guard.Rule{rAPI, rAPI}, 10); !errors.Is(err, guard.ErrInvalidRule) {
		t.Fatalf("duplicate prefix err = %v, want ErrInvalidRule", err)
	}

	lim, err := guard.NewRouteLimiter([]guard.Rule{rRoot, rAPI, rLogin}, 3)
	if err != nil {
		t.Fatalf("NewRouteLimiter: %v", err)
	}

	now := time.Date(2026, 11, 26, 15, 0, 0, 0, time.UTC)
	ip1 := netip.MustParseAddr("198.51.100.1")

	// Longest prefix /api/login allows burst 2 then denies with Retry-After ~30s.
	for i := range 2 {
		if ok, retry := lim.Allow("/api/login/submit", ip1, now); !ok || retry != 0 {
			t.Fatalf("call %d on /api/login = (%v, %v), want (true, 0)", i, ok, retry)
		}
	}
	ok, retry := lim.Allow("/api/login/submit", ip1, now)
	if ok || retry <= 0 {
		t.Fatalf("3rd call on /api/login = (%v, %v), want (false, >0)", ok, retry)
	}
	// Advancing clock by retryAfter must allow the next request.
	if ok, _ := lim.Allow("/api/login/submit", ip1, now.Add(retry)); !ok {
		t.Fatalf("Allow after Retry-After (%v) failed", retry)
	}

	// Segment-boundary check: /apiv2 must match "/" (rate 100/1m), NOT "/api" (10/1m).
	for i := range 15 {
		if ok, _ := lim.Allow("/apiv2/ping", ip1, now); !ok {
			t.Fatalf("/apiv2/ping call %d wrongly matched /api instead of /", i)
		}
	}

	// O(1) LRU eviction check on /api/login (MaxEntries=3):
	// Currently holds ip1 (exhausted after 3 calls). Insert ip2, ip3; touch ip1
	// so ip2 becomes LRU; insert ip4 -> evicts ip2, keeping ip1 exhausted!
	ip2 := netip.MustParseAddr("198.51.100.2")
	ip3 := netip.MustParseAddr("198.51.100.3")
	ip4 := netip.MustParseAddr("198.51.100.4")
	t1 := now.Add(retry)
	_, _ = lim.Allow("/api/login", ip2, t1)
	_, _ = lim.Allow("/api/login", ip2, t1) // ip2 now has 0 tokens
	_, _ = lim.Allow("/api/login", ip3, t1)
	_, _ = lim.Allow("/api/login", ip1, t1) // touch ip1 -> MRU; order: ip1, ip3, ip2 (LRU)
	_, _ = lim.Allow("/api/login", ip4, t1) // evicts ip2

	if got := lim.EntryCount("/api/login"); got != 3 {
		t.Fatalf("EntryCount(/api/login) = %d, want 3", got)
	}
	// ip1 was kept warm so it must still be rate-limited at t1.
	if ok, _ := lim.Allow("/api/login", ip1, t1); ok {
		t.Fatal("warm MRU ip1 was evicted instead of LRU ip2")
	}
	// ip2 was evicted so it gets a fresh bucket at t1.
	if ok, _ := lim.Allow("/api/login", ip2, t1); !ok {
		t.Fatal("evicted LRU ip2 did not receive a fresh bucket")
	}

	// Concurrent stress under -race.
	start := make(chan struct{})
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Go(func() {
			<-start
			ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(g + 10)})
			for i := range 50 {
				lim.Allow("/api/login", ip, t1.Add(time.Duration(i)*time.Second))
				lim.Allow("/api/status", ip, t1.Add(time.Duration(i)*time.Second))
			}
		})
	}
	close(start)
	wg.Wait()
	if got := lim.EntryCount("/api/login"); got > 3 {
		t.Fatalf("EntryCount exceeded cap after concurrent stress: %d", got)
	}
}

// TestGeoASNPolicy_PrecedenceAndFailModes verifies strict deny-overrides-allow
// precedence, allowlist evaluation, fail-open vs fail-closed behavior, and
// config validation.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -run '^TestGeoASNPolicy_PrecedenceAndFailModes$' ./internal/guard
//
// # Used By
//
// Invoked by the `go test` runner.
func TestGeoASNPolicy_PrecedenceAndFailModes(t *testing.T) {
	if _, err := guard.NewGeoASNPolicy(guard.GeoASNConfig{DenyCountries: []string{"USA"}}, nil); !errors.Is(err, guard.ErrInvalidCountryCode) {
		t.Fatalf("invalid country code err = %v, want ErrInvalidCountryCode", err)
	}
	if _, err := guard.NewGeoASNPolicy(guard.GeoASNConfig{DenyASNs: []uint32{0}}, nil); !errors.Is(err, guard.ErrInvalidASN) {
		t.Fatalf("ASN 0 err = %v, want ErrInvalidASN", err)
	}

	ipUSGood := netip.MustParseAddr("198.51.100.1")
	ipUSBadASN := netip.MustParseAddr("198.51.100.2")
	ipBadCCGoodASN := netip.MustParseAddr("198.51.100.3")
	ipFR := netip.MustParseAddr("198.51.100.4")
	ipUnknown := netip.MustParseAddr("198.51.100.99")

	db := map[netip.Addr]struct {
		cc  string
		asn uint32
	}{
		ipUSGood:       {cc: "us", asn: 13335},
		ipUSBadASN:     {cc: "US", asn: 64512},
		ipBadCCGoodASN: {cc: "KP", asn: 13335},
		ipFR:           {cc: "FR", asn: 15169},
	}
	lookup := guard.IPLookupFunc(func(ip netip.Addr) (string, uint32, bool) {
		rec, ok := db[ip]
		return rec.cc, rec.asn, ok
	})

	polClosed, err := guard.NewGeoASNPolicy(guard.GeoASNConfig{
		AllowCountries: []string{"us"},
		AllowASNs:      []uint32{13335},
		DenyCountries:  []string{"kp"},
		DenyASNs:       []uint32{64512},
		FailOpen:       false,
	}, lookup)
	if err != nil {
		t.Fatalf("NewGeoASNPolicy(failClosed): %v", err)
	}

	cases := []struct {
		name       string
		ip         netip.Addr
		wantAllow  bool
		wantReason string
	}{
		{"allowed US + allowed ASN", ipUSGood, true, ""},
		{"deny ASN overrides allowed country", ipUSBadASN, false, "denied_asn"},
		{"deny country overrides allowed ASN", ipBadCCGoodASN, false, "denied_country"},
		{"not in allowlist", ipFR, false, "not_allowlisted"},
		{"unknown IP fail-closed", ipUnknown, false, "unknown_ip"},
		{"invalid IP fails closed", netip.Addr{}, false, "invalid_ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotAllow, gotReason := polClosed.Check(tc.ip)
			if gotAllow != tc.wantAllow || gotReason != tc.wantReason {
				t.Errorf("Check(%v) = (%v, %q), want (%v, %q)", tc.ip, gotAllow, gotReason, tc.wantAllow, tc.wantReason)
			}
			if polClosed.Allow(tc.ip) != tc.wantAllow {
				t.Errorf("Allow(%v) disagreed with Check", tc.ip)
			}
		})
	}

	// FailOpen allows unknown IPs and nil lookup while still enforcing deny rules.
	polOpen, err := guard.NewGeoASNPolicy(guard.GeoASNConfig{
		DenyASNs: []uint32{64512},
		FailOpen: true,
	}, lookup)
	if err != nil {
		t.Fatalf("NewGeoASNPolicy(failOpen): %v", err)
	}
	if !polOpen.Allow(ipUnknown) {
		t.Fatal("FailOpen policy denied unknown IP")
	}
	if polOpen.Allow(ipUSBadASN) {
		t.Fatal("FailOpen policy allowed denied ASN")
	}

	polNilLookup, err := guard.NewGeoASNPolicy(guard.GeoASNConfig{
		DenyCountries: []string{"KP"},
		FailOpen:      true,
	}, nil)
	if err != nil {
		t.Fatalf("NewGeoASNPolicy(nil lookup): %v", err)
	}
	if !polNilLookup.Allow(ipUSGood) {
		t.Fatal("FailOpen policy with nil lookup denied IP")
	}
}

// TestSecret_RedactionAndLoading verifies that Secret never leaks raw values
// through fmt, JSON, text, or slog, and that file/env loaders enforce
// permissions and placeholder checks (S5, S6, S7).
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -run '^TestSecret_RedactionAndLoading$' ./internal/guard
//
// # Used By
//
// Invoked by the `go test` runner.
func TestSecret_RedactionAndLoading(t *testing.T) {
	sec := ephemeralTestSecret(t)
	raw := sec.Reveal()

	outputs := []string{
		sec.String(),
		sec.GoString(),
		fmt.Sprintf("%v", sec),
		fmt.Sprintf("%+v", sec),
		fmt.Sprintf("%#v", sec),
		fmt.Sprintf("%s", sec),
		fmt.Sprintf("%q", sec),
		fmt.Sprintf("%x", sec),
	}
	jb, err := json.Marshal(struct{ K guard.Secret }{K: sec})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	outputs = append(outputs, string(jb))

	tb, err := sec.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	outputs = append(outputs, string(tb))

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	logger.Info("check", "secret", sec, "any", slog.Any("nested", sec))
	outputs = append(outputs, logBuf.String())

	for i, out := range outputs {
		if strings.Contains(out, raw) {
			t.Fatalf("output #%d leaked raw secret: %q", i, out)
		}
		if !strings.Contains(out, guard.RedactedPlaceholder) {
			t.Errorf("output #%d missing placeholder %q: %q", i, guard.RedactedPlaceholder, out)
		}
	}

	// SecretFromFile permission and validation checks.
	dir := t.TempDir()
	goodFile := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(goodFile, []byte(raw+"\n"), 0o600); err != nil {
		t.Fatalf("write good secret file: %v", err)
	}
	loaded, err := guard.SecretFromFile(goodFile)
	if err != nil || loaded.Reveal() != raw {
		t.Fatalf("SecretFromFile(0600) = (%v, %v), want exact match", loaded, err)
	}

	openFile := filepath.Join(dir, "world.txt")
	if err := os.WriteFile(openFile, []byte(raw), 0o644); err != nil {
		t.Fatalf("write open secret file: %v", err)
	}
	if _, err := guard.SecretFromFile(openFile); !errors.Is(err, guard.ErrSecretPermissions) {
		t.Fatalf("SecretFromFile(0644) err = %v, want ErrSecretPermissions", err)
	}

	placeholderFile := filepath.Join(dir, "placeholder.txt")
	if err := os.WriteFile(placeholderFile, []byte("changeme\n"), 0o600); err != nil {
		t.Fatalf("write placeholder file: %v", err)
	}
	if _, err := guard.SecretFromFile(placeholderFile); !errors.Is(err, guard.ErrSecretPlaceholder) {
		t.Fatalf("SecretFromFile(placeholder) err = %v, want ErrSecretPlaceholder", err)
	}

	t.Setenv("CONCERT_GUARD_TEST_SECRET", raw)
	envSec, err := guard.SecretFromEnv("CONCERT_GUARD_TEST_SECRET")
	if err != nil || envSec.Reveal() != raw {
		t.Fatalf("SecretFromEnv = (%v, %v), want match", envSec, err)
	}
}

// TestChallengeGate_PoWEndToEndSecurity verifies PoW issuance, solving,
// verification, expiry, forgery rejection, IP binding, replay protection,
// clearance cookies, and strict CSP-compliant HTML/JS output.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -race -run '^TestChallengeGate_PoWEndToEndSecurity$' ./internal/guard
//
// # Used By
//
// Invoked by the `go test` runner.
func TestChallengeGate_PoWEndToEndSecurity(t *testing.T) {
	// Fail-closed config checks.
	if _, err := guard.NewChallengeGate(guard.ChallengeConfig{Mode: guard.ModePoW}); !errors.Is(err, guard.ErrInvalidChallengeConfig) {
		t.Fatalf("missing signing key err = %v, want ErrInvalidChallengeConfig", err)
	}
	if _, err := guard.NewChallengeGate(guard.ChallengeConfig{
		Mode:       guard.ModePoW,
		SigningKey: ephemeralTestSecret(t),
		Difficulty: 4,
	}); !errors.Is(err, guard.ErrInvalidChallengeConfig) {
		t.Fatalf("low difficulty err = %v, want ErrInvalidChallengeConfig", err)
	}

	key := ephemeralTestSecret(t)
	gate, err := guard.NewChallengeGate(guard.ChallengeConfig{
		Mode:          guard.ModePoW,
		SigningKey:    key,
		Difficulty:    10,
		NonceTTL:      2 * time.Minute,
		ClearanceTTL:  10 * time.Minute,
		MaxUsedNonces: 64,
	})
	if err != nil {
		t.Fatalf("NewChallengeGate(ModePoW): %v", err)
	}

	now := time.Date(2026, 11, 26, 15, 0, 0, 0, time.UTC)
	ip := netip.MustParseAddr("2001:db8:cafe:1::10")
	sameSubnetIP := netip.MustParseAddr("2001:db8:cafe:1::99")
	otherIP := netip.MustParseAddr("2001:db8:cafe:2::10")

	ch, err := gate.IssuePoW(ip, now)
	if err != nil {
		t.Fatalf("IssuePoW: %v", err)
	}
	counter, ok := guard.SolvePoW(ch.Nonce, ch.Difficulty)
	if !ok {
		t.Fatal("SolvePoW failed")
	}

	// Wrong IP fails signature check before consuming replay entry.
	if ok, err := gate.VerifyPoW(otherIP, ch.Nonce, counter, now); ok || !errors.Is(err, guard.ErrChallengeInvalid) {
		t.Fatalf("VerifyPoW(otherIP) = (%v, %v), want (false, ErrChallengeInvalid)", ok, err)
	}

	// Tampered nonce fails signature check.
	tampered := "ff" + ch.Nonce[2:]
	if ok, err := gate.VerifyPoW(ip, tampered, counter, now); ok || !errors.Is(err, guard.ErrChallengeInvalid) {
		t.Fatalf("VerifyPoW(tampered) = (%v, %v), want (false, ErrChallengeInvalid)", ok, err)
	}

	// Expired nonce fails with ErrChallengeExpired.
	if ok, err := gate.VerifyPoW(ip, ch.Nonce, counter, now.Add(3*time.Minute)); ok || !errors.Is(err, guard.ErrChallengeExpired) {
		t.Fatalf("VerifyPoW(expired) = (%v, %v), want (false, ErrChallengeExpired)", ok, err)
	}

	// Valid verification from same /64 succeeds.
	if ok, err := gate.VerifyPoW(sameSubnetIP, ch.Nonce, counter, now.Add(time.Second)); !ok || err != nil {
		t.Fatalf("VerifyPoW(valid) = (%v, %v), want (true, nil)", ok, err)
	}

	// Replay of the exact same solved nonce fails with ErrChallengeReplayed.
	if ok, err := gate.VerifyPoW(ip, ch.Nonce, counter, now.Add(2*time.Second)); ok || !errors.Is(err, guard.ErrChallengeReplayed) {
		t.Fatalf("VerifyPoW(replay) = (%v, %v), want (false, ErrChallengeReplayed)", ok, err)
	}

	// Clearance cookie round-trip, attributes, IP binding, and expiry.
	cookie, err := gate.IssueClearanceCookie(ip, now)
	if err != nil {
		t.Fatalf("IssueClearanceCookie: %v", err)
	}
	if cookie.Name != guard.DefaultClearanceCookieName || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected cookie attributes: %+v", cookie)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	if !gate.VerifyClearanceCookie(req, sameSubnetIP, now.Add(time.Minute)) {
		t.Fatal("VerifyClearanceCookie rejected valid cookie")
	}
	if gate.VerifyClearanceCookie(req, otherIP, now.Add(time.Minute)) {
		t.Fatal("VerifyClearanceCookie accepted cookie for wrong IP")
	}
	if gate.VerifyClearanceCookie(req, ip, now.Add(11*time.Minute)) {
		t.Fatal("VerifyClearanceCookie accepted expired cookie")
	}

	// HTML/JS CSP & escaping verification.
	htmlDoc := guard.PoWChallengeHTML(ch, `/verify?next="><script>alert(1)</script>`, "/_concert/pow.js")
	if strings.Contains(htmlDoc, "<script>alert(1)</script>") {
		t.Fatal("PoWChallengeHTML failed to escape submitAction")
	}
	if strings.Contains(htmlDoc, "http://") || strings.Contains(htmlDoc, "https://") {
		t.Fatal("PoWChallengeHTML references external URL")
	}
	if !strings.Contains(htmlDoc, `<script src="/_concert/pow.js" defer></script>`) {
		t.Fatal("PoWChallengeHTML missing same-origin deferred script tag")
	}
	js := guard.PoWSolverJS()
	if !strings.Contains(js, `crypto.subtle.digest("SHA-256"`) {
		t.Fatal("PoWSolverJS missing WebCrypto SHA-256 digest call")
	}
}

// TestChallengeGate_TurnstileVerification verifies Cloudflare Turnstile POST
// contract, secret redaction in errors, bounded response reads, status errors,
// and endpoint scheme enforcement.
//
// # Parameters
//
//   - t: Standard testing handle invoked by `go test`.
//
// # Example
//
//	go test -run '^TestChallengeGate_TurnstileVerification$' ./internal/guard
//
// # Used By
//
// Invoked by the `go test` runner.
func TestChallengeGate_TurnstileVerification(t *testing.T) {
	sec := ephemeralTestSecret(t)
	rawSec := sec.Reveal()

	// Non-loopback HTTP endpoint must fail closed.
	if _, err := guard.NewChallengeGate(guard.ChallengeConfig{
		Mode:              guard.ModeTurnstile,
		TurnstileSecret:   sec,
		TurnstileEndpoint: "http://challenges.cloudflare.com/turnstile/v0/siteverify",
	}); !errors.Is(err, guard.ErrInvalidChallengeConfig) {
		t.Fatalf("non-loopback http endpoint err = %v, want ErrInvalidChallengeConfig", err)
	}

	var mode atomic.Int32 // 0=ok, 1=fail, 2=http500, 3=oversized, 4=trailing
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if got := r.FormValue("secret"); got != rawSec {
			t.Errorf("secret mismatch in POST body")
		}
		if got := r.FormValue("remoteip"); got != "203.0.113.9" {
			t.Errorf("remoteip = %q, want 203.0.113.9", got)
		}

		switch mode.Load() {
		case 0:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"hostname":"counthis.app","action":"queue"}`))
		case 1:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
		case 2:
			w.WriteHeader(http.StatusBadGateway)
		case 3:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bytes.Repeat([]byte("a"), 70<<10))
		case 4:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":true}{"extra":1}`))
		}
	}))
	defer srv.Close()

	gate, err := guard.NewChallengeGate(guard.ChallengeConfig{
		Mode:              guard.ModeTurnstile,
		TurnstileSecret:   sec,
		TurnstileEndpoint: srv.URL,
		TurnstileTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewChallengeGate(ModeTurnstile): %v", err)
	}

	ip := netip.MustParseAddr("203.0.113.9")

	// Empty token rejected before network call.
	if _, err := gate.VerifyTurnstile(t.Context(), "", ip); !errors.Is(err, guard.ErrChallengeInvalid) {
		t.Fatalf("empty token err = %v, want ErrChallengeInvalid", err)
	}

	// Success case.
	res, err := gate.VerifyTurnstile(t.Context(), "valid-token", ip)
	if err != nil || !res.Success || res.Hostname != "counthis.app" {
		t.Fatalf("VerifyTurnstile(ok) = (%+v, %v), want success", res, err)
	}

	// Rejected token case.
	mode.Store(1)
	res, err = gate.VerifyTurnstile(t.Context(), "bad-token", ip)
	if err != nil || res.Success || len(res.ErrorCodes) != 1 {
		t.Fatalf("VerifyTurnstile(fail) = (%+v, %v), want success=false with error-codes", res, err)
	}

	// HTTP 502 error.
	mode.Store(2)
	if _, err := gate.VerifyTurnstile(t.Context(), "tok", ip); !errors.Is(err, guard.ErrTurnstileUpstream) {
		t.Fatalf("VerifyTurnstile(502) err = %v, want ErrTurnstileUpstream", err)
	} else if strings.Contains(err.Error(), rawSec) {
		t.Fatal("Turnstile error leaked secret")
	}

	// Oversized response rejected (R3).
	mode.Store(3)
	if _, err := gate.VerifyTurnstile(t.Context(), "tok", ip); !errors.Is(err, guard.ErrTurnstileUpstream) {
		t.Fatalf("VerifyTurnstile(oversized) err = %v, want ErrTurnstileUpstream", err)
	}

	// Trailing JSON rejected.
	mode.Store(4)
	if _, err := gate.VerifyTurnstile(t.Context(), "tok", ip); !errors.Is(err, guard.ErrTurnstileUpstream) {
		t.Fatalf("VerifyTurnstile(trailing) err = %v, want ErrTurnstileUpstream", err)
	}
}

// ExampleQueueQuota demonstrates per-IP and allowlisted waiting-room slot caps.
//
// # Parameters
//
// None.
//
// # Example
//
//	go test -run '^ExampleQueueQuota$' ./internal/guard
//
// # Used By
//
// Invoked by the `go test` runner.
func ExampleQueueQuota() {
	now := time.Date(2026, 11, 26, 15, 0, 0, 0, time.UTC)
	q := guard.NewQueueQuota(guard.QueueQuotaConfig{MaxPerIP: 2, AllowMaxPerIP: 4})
	ip := netip.MustParseAddr("198.51.100.10")
	fmt.Println(q.TryAcquire(ip, "t1", false, now))
	fmt.Println(q.TryAcquire(ip, "t2", false, now))
	fmt.Println(q.TryAcquire(ip, "t3", false, now))
	// Output:
	// true
	// true
	// false
}

// ExampleRouteLimiter demonstrates parsing declarative route rules and
// applying longest-prefix rate limiting.
//
// # Parameters
//
// None.
//
// # Example
//
//	go test -run '^ExampleRouteLimiter$' ./internal/guard
//
// # Used By
//
// Invoked by the `go test` runner.
func ExampleRouteLimiter() {
	rule, err := guard.ParseRouteRule("/api/login", "2/1m")
	if err != nil {
		panic(err)
	}
	lim, err := guard.NewRouteLimiter([]guard.Rule{rule}, 1024)
	if err != nil {
		panic(err)
	}
	now := time.Date(2026, 11, 26, 15, 0, 0, 0, time.UTC)
	ip := netip.MustParseAddr("203.0.113.5")
	ok1, _ := lim.Allow("/api/login", ip, now)
	ok2, _ := lim.Allow("/api/login", ip, now)
	ok3, _ := lim.Allow("/api/login", ip, now)
	fmt.Println(ok1, ok2, ok3)
	// Output:
	// true true false
}
