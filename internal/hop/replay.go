package hop

import (
	"crypto/sha256"
	"sync"
)

const (
	replayShards      = 64
	replayMaxPerShard = 4096 // 262,144 total tracked nonces across all shards
)

type replayKey [16]byte

type replayShard struct {
	mu      sync.Mutex
	entries map[replayKey]int64 // key -> expiry unix ms
	writes  uint32
}

// replayCache is a fixed-memory, lock-sharded replay guard keyed by
// (edge, nonce). Entries expire after 2*MaxSkew so a captured Concert-Hop
// header cannot be replayed even inside the clock-skew window.
type replayCache struct {
	shards [replayShards]replayShard
}

func newReplayCache() *replayCache {
	c := &replayCache{}
	for i := range c.shards {
		c.shards[i].entries = make(map[replayKey]int64, 64)
	}
	return c
}

func makeReplayKey(edge, nonce string) replayKey {
	h := sha256.New()
	_, _ = h.Write([]byte(edge))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(nonce))
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	var k replayKey
	copy(k[:], sum[:16])
	return k
}

// seenOrRecord returns true if (edge, nonce) was already accepted and has not
// expired yet. Otherwise it records (edge, nonce) until nowMs+ttlMs and
// returns false.
func (c *replayCache) seenOrRecord(edge, nonce string, nowMs, ttlMs int64) bool {
	if c == nil || nonce == "" {
		return false
	}
	if ttlMs < 1000 {
		ttlMs = 1000
	}
	k := makeReplayKey(edge, nonce)
	sh := &c.shards[k[0]&(replayShards-1)]

	sh.mu.Lock()
	defer sh.mu.Unlock()

	if exp, ok := sh.entries[k]; ok && exp > nowMs {
		return true
	}

	sh.writes++
	if len(sh.entries) >= replayMaxPerShard || sh.writes&0xff == 0 {
		for ek, exp := range sh.entries {
			if exp <= nowMs {
				delete(sh.entries, ek)
			}
		}
	}
	if len(sh.entries) >= replayMaxPerShard {
		// Under sustained flood beyond 262k requests per skew window, evict the
		// entry closest to expiration so memory remains strictly bounded.
		var oldestKey replayKey
		var oldestExp int64 = 1<<62 - 1
		for ek, exp := range sh.entries {
			if exp < oldestExp {
				oldestExp = exp
				oldestKey = ek
			}
		}
		delete(sh.entries, oldestKey)
	}
	sh.entries[k] = nowMs + ttlMs
	return false
}
