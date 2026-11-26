package cache_test

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/cache"
)

// FuzzFrameDecode exercises binary frame decoding and payload codecs against
// arbitrary untrusted inputs, asserting strict frame bounds and round-trip
// invariants without panics or unbounded allocations.
//
// # Parameters
//
//   - f: Go fuzz harness seeded with valid, truncated, and hostile wire frames.
//
// # Returns
//
// None. Failures are reported via t.Fatalf.
//
// # Example
//
//	// Run via the Go toolchain:
//	// go test -run '^$' -fuzz '^FuzzFrameDecode$' -fuzztime=5s ./internal/cache
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func FuzzFrameDecode(f *testing.F) {
	// Seed valid ping frame.
	var pingBuf bytes.Buffer
	_ = cache.WriteFrame(&pingBuf, cache.OpPing, 0, nil, cache.MaxFrameBytes)
	f.Add(pingBuf.Bytes())

	// Seed valid encoded entry frame.
	if rawEntry, err := cache.EncodeEntry(cache.Entry{
		Key:     "shop.example.com\x00/item\x00id=1\x00gz",
		Status:  http.StatusOK,
		Headers: http.Header{"Content-Type": {"text/html"}},
		Body:    []byte("<html>ok</html>"),
		Tags:    []string{"item:1", "catalog"},
		TTL:     15 * time.Second,
	}); err == nil {
		var entryBuf bytes.Buffer
		_ = cache.WriteFrame(&entryBuf, cache.OpPut, 0, rawEntry, cache.MaxFrameBytes)
		f.Add(entryBuf.Bytes())
	}

	// Seed valid purge pair, stats, and error frames.
	if pair, err := cache.EncodePurgePair("shop.example.com", "/product/"); err == nil {
		var b bytes.Buffer
		_ = cache.WriteFrame(&b, cache.OpPurgePrefix, 0, pair, cache.MaxFrameBytes)
		f.Add(b.Bytes())
	}
	var statsBuf bytes.Buffer
	_ = cache.WriteFrame(&statsBuf, cache.OpStats, 0, cache.EncodeStats(cache.Stats{Entries: 5, UsedBytes: 1024, Shards: 64}), cache.MaxFrameBytes)
	f.Add(statsBuf.Bytes())

	var errBuf bytes.Buffer
	_ = cache.WriteFrame(&errBuf, cache.RespErr, 0, cache.EncodeError(cache.ErrCodeUnauthorized, "unauthorized"), cache.MaxFrameBytes)
	f.Add(errBuf.Bytes())

	// Seed malformed / hostile headers.
	f.Add([]byte{cache.FrameMagic0, cache.FrameMagic1, cache.OpPut, 0, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x41})
	f.Add([]byte{})

	const fuzzMaxFrame = 64 << 10

	f.Fuzz(func(t *testing.T, data []byte) {
		fr, err := cache.ReadFrame(bytes.NewReader(data), fuzzMaxFrame)
		if err != nil {
			return
		}
		if len(fr.Payload) > fuzzMaxFrame {
			t.Fatalf("decoded payload length %d exceeded fuzzMaxFrame %d", len(fr.Payload), fuzzMaxFrame)
		}

		// Round-trip frame encoding must reproduce identical opcode, flags, and payload.
		var re bytes.Buffer
		if err := cache.WriteFrame(&re, fr.Op, fr.Flags, fr.Payload, fuzzMaxFrame); err != nil {
			t.Fatalf("WriteFrame after ReadFrame failed: %v", err)
		}
		fr2, err := cache.ReadFrame(&re, fuzzMaxFrame)
		if err != nil {
			t.Fatalf("second ReadFrame failed: %v", err)
		}
		if fr2.Op != fr.Op || fr2.Flags != fr.Flags || !bytes.Equal(fr2.Payload, fr.Payload) {
			t.Fatalf("frame round-trip mismatch: got (%x,%x,%d) want (%x,%x,%d)",
				fr2.Op, fr2.Flags, len(fr2.Payload), fr.Op, fr.Flags, len(fr.Payload))
		}

		// Exercise payload decoders on arbitrary frame payloads and verify round-trip invariants.
		if ent, err := cache.DecodeEntry(fr.Payload, fuzzMaxFrame); err == nil {
			enc, err := cache.EncodeEntry(ent)
			if err != nil {
				t.Fatalf("EncodeEntry after valid DecodeEntry failed: %v", err)
			}
			ent2, err := cache.DecodeEntry(enc, fuzzMaxFrame)
			if err != nil {
				t.Fatalf("DecodeEntry round-trip failed: %v", err)
			}
			if ent2.Key != ent.Key || ent2.Status != ent.Status || !bytes.Equal(ent2.Body, ent.Body) {
				t.Fatalf("entry round-trip mismatch: key=%q/%q status=%d/%d", ent2.Key, ent.Key, ent2.Status, ent.Status)
			}
		}

		if h, p, err := cache.DecodePurgePair(fr.Payload); err == nil {
			enc, err := cache.EncodePurgePair(h, p)
			if err != nil {
				t.Fatalf("EncodePurgePair after DecodePurgePair failed: %v", err)
			}
			h2, p2, err := cache.DecodePurgePair(enc)
			if err != nil || h2 != h || p2 != p {
				t.Fatalf("purge pair round-trip mismatch: (%q,%q,%v) want (%q,%q,nil)", h2, p2, err, h, p)
			}
		}

		if st, err := cache.DecodeStats(fr.Payload); err == nil {
			st2, err := cache.DecodeStats(cache.EncodeStats(st))
			if err != nil || st2 != st {
				t.Fatalf("stats round-trip mismatch: got %+v err=%v want %+v", st2, err, st)
			}
		}

		if v, err := cache.DecodeUint64(fr.Payload); err == nil {
			v2, err := cache.DecodeUint64(cache.EncodeUint64(v))
			if err != nil || v2 != v {
				t.Fatalf("uint64 round-trip mismatch: got %d err=%v want %d", v2, err, v)
			}
		}

		_ = cache.DecodeError(fr.Payload)
	})
}
