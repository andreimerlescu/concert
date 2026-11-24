package hop

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerify_SingleUseReplayGuard(t *testing.T) {
	now := time.Unix(1795000000, 0)
	s, err := NewSigner(secretA, "edge-1")
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now }

	v, err := NewVerifier(30*time.Second, secretA)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return now }
	v.SetReplayGuard(true, true)

	h1 := s.Sign(sampleClaim(), "GET", "/checkout", "")
	if !strings.Contains(h1, ";n=") {
		t.Fatalf("expected nonce in signed header: %s", h1)
	}
	got, err := v.Verify(h1, "GET", "/checkout", "")
	if err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	if len(got.Nonce) != 16 {
		t.Fatalf("nonce length = %d, want 16 (%q)", len(got.Nonce), got.Nonce)
	}

	// Replaying the exact captured header within the skew window must fail.
	if _, err := v.Verify(h1, "GET", "/checkout", ""); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay err = %v, want ErrReplay", err)
	}

	// A freshly signed claim for the same method/URI gets a new nonce and succeeds.
	h2 := s.Sign(sampleClaim(), "GET", "/checkout", "")
	if h2 == h1 {
		t.Fatal("two consecutive Sign calls produced identical headers")
	}
	if _, err := v.Verify(h2, "GET", "/checkout", ""); err != nil {
		t.Fatalf("second distinct claim failed: %v", err)
	}

	// Forged signature carrying a real nonce must fail signature BEFORE polluting cache.
	// Mutate a byte before the final base64url character so real MAC bits (not unused
	// trailing padding bits) always flip.
	h3 := s.Sign(sampleClaim(), "GET", "/checkout", "")
	flipPos := len(h3) - 3
	replacement := byte('A')
	if h3[flipPos] == 'A' {
		replacement = 'B'
	}
	forged := h3[:flipPos] + string(replacement) + h3[flipPos+1:]
	if _, err := v.Verify(forged, "GET", "/checkout", ""); !errors.Is(err, ErrSignature) {
		t.Fatalf("forged err = %v, want ErrSignature", err)
	}
	if _, err := v.Verify(h3, "GET", "/checkout", ""); err != nil {
		t.Fatalf("legitimate claim after forged probe failed: %v", err)
	}
}

func TestVerify_LegacyNoncelessCompatibility(t *testing.T) {
	now := time.Unix(1795000000, 0)
	c := Claim{
		Edge:   "edge-v020",
		Issued: now,
		Client: netip.MustParseAddr("203.0.113.9"),
		Rank:   2,
		Class:  ClassPage,
		Proto:  "h2",
	}
	// Construct a legacy 8-field v0.2.0 header (without ;n=).
	fields := encodeFields(c)
	if strings.Contains(fields, ";n=") {
		t.Fatalf("unexpected nonce in legacy fields: %s", fields)
	}
	key := deriveKey(secretA)
	sig := mac(key, fields, "GET", "/", "")
	// Re-encode with RawURLEncoding via Verifier helper.
	s, _ := NewSigner(secretA, "edge-v020")
	_ = sig
	legacy := fields + ";s=" + encodeSigForTest(key, fields, "GET", "/", "")

	v, err := NewVerifier(30*time.Second, secretA)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return now }

	// Rolling-upgrade mode: replay guard on, requireNonce off -> legacy header accepted.
	v.SetReplayGuard(true, false)
	if _, err := v.Verify(legacy, "GET", "/", ""); err != nil {
		t.Fatalf("legacy claim rejected in rolling-upgrade mode: %v", err)
	}

	// Strict mode: requireNonce on -> legacy header refused.
	v.SetReplayGuard(true, true)
	if _, err := v.Verify(legacy, "GET", "/", ""); !errors.Is(err, ErrNonceRequired) {
		t.Fatalf("legacy claim in strict mode err = %v, want ErrNonceRequired", err)
	}
	_ = s
}

func encodeSigForTest(key []byte, fields, method, uri, bodyHash string) string {
	// Reuse package-internal mac and standard base64 URL raw encoding.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	sig := mac(key, fields, method, uri, bodyHash)
	var b strings.Builder
	for i := 0; i < len(sig); i += 3 {
		var n uint32
		rem := len(sig) - i
		n = uint32(sig[i]) << 16
		if rem > 1 {
			n |= uint32(sig[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(sig[i+2])
		}
		b.WriteByte(alphabet[(n>>18)&63])
		b.WriteByte(alphabet[(n>>12)&63])
		if rem > 1 {
			b.WriteByte(alphabet[(n>>6)&63])
		}
		if rem > 2 {
			b.WriteByte(alphabet[n&63])
		}
	}
	return b.String()
}

func TestVerify_ReplayRaceExactlyOneWins(t *testing.T) {
	now := time.Unix(1795000000, 0)
	s, _ := NewSigner(secretA, "edge-race")
	s.now = func() time.Time { return now }
	v, _ := NewVerifier(30*time.Second, secretA)
	v.now = func() time.Time { return now }
	v.SetReplayGuard(true, true)

	hdr := s.Sign(sampleClaim(), "POST", "/order", "")
	var wins, replays atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := v.Verify(hdr, "POST", "/order", "")
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrReplay):
				replays.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || replays.Load() != 31 {
		t.Fatalf("wins=%d replays=%d, want 1 and 31", wins.Load(), replays.Load())
	}
}

func TestReplayCache_O1RingEvictionAndEvictionCallback(t *testing.T) {
	now := time.Unix(1795000000, 0)
	s, err := NewSigner(secretA, "edge-ring")
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now }

	v, err := NewVerifier(30*time.Second, secretA)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return now }
	v.SetReplayGuard(true, true)

	var evictions atomic.Int64
	// Small capacity: 512 total across 256 shards (2 per shard).
	v.SetReplayOptions(512, false, func() {
		evictions.Add(1)
	})

	// Insert 1500 unexpired claims; well past 512 so evictions must occur, yet
	// every claim succeeds in fail-open (non-hardened) mode.
	for i := 0; i < 1500; i++ {
		h := s.Sign(sampleClaim(), "GET", "/items", "")
		if _, err := v.Verify(h, "GET", "/items", ""); err != nil {
			t.Fatalf("claim %d failed unexpectedly in non-hardened mode: %v", i, err)
		}
	}
	if evictions.Load() == 0 {
		t.Fatalf("evictions = 0 after 1500 unexpired claims into 512-cap cache; expected evictions > 0")
	}

	// Verify memory stayed strictly bounded per shard (<= 2 entries per shard).
	rc := v.replay.Load()
	totalStored := 0
	for i := range rc.shards {
		sh := &rc.shards[i]
		sh.mu.Lock()
		if len(sh.entries) > 2 || sh.count > 2 {
			t.Fatalf("shard %d exceeded cap 2: map=%d ring=%d", i, len(sh.entries), sh.count)
		}
		totalStored += len(sh.entries)
		sh.mu.Unlock()
	}
	if totalStored > 512 {
		t.Fatalf("totalStored = %d, want <= 512", totalStored)
	}

	// Advance clock past 2*MaxSkew: expired heads must pop cleanly in O(1)
	// WITHOUT triggering any further evictions! Send at most 1 fresh claim per
	// shard so random birthday collisions on 2-slot shards cannot cause genuine
	// fresh-vs-fresh evictions.
	now = now.Add(2*30*time.Second + time.Second)
	evBefore := evictions.Load()
	seenShard := map[byte]bool{}
	for len(seenShard) < 64 {
		h := s.Sign(sampleClaim(), "GET", "/fresh", "")
		c, _, _, perr := parse(h)
		if perr != nil {
			t.Fatal(perr)
		}
		shard := makeReplayKey(c.Edge, c.Nonce)[0]
		if seenShard[shard] {
			continue
		}
		seenShard[shard] = true
		if _, err := v.Verify(h, "GET", "/fresh", ""); err != nil {
			t.Fatalf("post-expiry claim failed: %v", err)
		}
	}
	if got := evictions.Load() - evBefore; got != 0 {
		t.Fatalf("post-expiry insertions triggered %d spurious evictions", got)
	}
}

func TestReplayCache_HardenedFailClosedSaturation(t *testing.T) {
	now := time.Unix(1795000000, 0)
	s, err := NewSigner(secretA, "edge-hardened")
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now }

	v, err := NewVerifier(30*time.Second, secretA)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return now }
	v.SetReplayGuard(true, true)

	var saturations atomic.Int64
	v.SetReplayOptions(512, true, func() {
		saturations.Add(1)
	})

	var accepted []string
	var saturated int
	for i := 0; i < 1500; i++ {
		h := s.Sign(sampleClaim(), "GET", "/checkout", "")
		_, err := v.Verify(h, "GET", "/checkout", "")
		switch {
		case err == nil:
			accepted = append(accepted, h)
		case errors.Is(err, ErrReplaySaturated):
			saturated++
		default:
			t.Fatalf("claim %d unexpected err: %v", i, err)
		}
	}
	if len(accepted) == 0 {
		t.Fatal("expected initial claims to be accepted before saturation")
	}
	if saturated == 0 {
		t.Fatalf("expected ErrReplaySaturated once 512-cap cache filled, got 0")
	}
	if saturations.Load() != int64(saturated) {
		t.Fatalf("onEvict count = %d, want %d", saturations.Load(), saturated)
	}

	// CRITICAL SECURITY INVARIANT: in hardened mode, ZERO unexpired accepted
	// nonces may be evicted — replaying every previously accepted claim MUST
	// still return ErrReplay!
	for i, h := range accepted {
		if _, err := v.Verify(h, "GET", "/checkout", ""); !errors.Is(err, ErrReplay) {
			t.Fatalf("accepted claim %d lost replay protection under saturation: err=%v, want ErrReplay", i, err)
		}
	}

	// Once the skew window elapses, expired entries pop and fresh claims succeed again.
	now = now.Add(2*30*time.Second + time.Second)
	fresh := s.Sign(sampleClaim(), "GET", "/checkout", "")
	if _, err := v.Verify(fresh, "GET", "/checkout", ""); err != nil {
		t.Fatalf("claim after expiry window failed: %v", err)
	}
}

func BenchmarkVerify_WithReplayGuard(b *testing.B) {
	s, _ := NewSigner(secretA, "edge-bench")
	v, _ := NewVerifier(30*time.Second, secretA)
	v.SetReplayGuard(true, true)
	c := sampleClaim()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := s.Sign(c, "GET", "/products/42?ref=home", "")
		if _, err := v.Verify(h, "GET", "/products/42?ref=home", ""); err != nil {
			b.Fatal(err)
		}
	}
}
