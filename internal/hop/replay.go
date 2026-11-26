package hop

import (
	"crypto/sha256"
	"sync"
)

const (
	replayShards = 256
)

type replayKey [16]byte

type replayEntry struct {
	key replayKey
	exp int64
}

type replayShard struct {
	mu      sync.Mutex
	entries map[replayKey]int64 // key -> expiry unix ms
	ring    []replayEntry       // circular FIFO buffer, lazily grown up to maxPerShard
	head    int
	count   int
}

func (sh *replayShard) isStaleHead(nowMs int64) bool {
	if sh.count == 0 {
		return false
	}
	old := sh.ring[sh.head]
	if old.exp <= nowMs {
		return true
	}
	curExp, ok := sh.entries[old.key]
	return !ok || curExp != old.exp
}

func (sh *replayShard) popHead() {
	old := sh.ring[sh.head]
	sh.ring[sh.head] = replayEntry{}
	sh.head++
	if sh.head == len(sh.ring) {
		sh.head = 0
	}
	sh.count--
	// Only delete from map if the map still holds this exact expiry, guarding
	// against the rare case where a key expired and was re-inserted while an
	// older ring slot remained ahead of it (e.g. across an NTP clock step).
	if curExp, ok := sh.entries[old.key]; ok && curExp == old.exp {
		delete(sh.entries, old.key)
	}
}

// replayCache is a fixed-memory, 256-shard O(1) FIFO replay guard keyed by
// (edge, nonce). Entries expire after 2*MaxSkew so a captured Concert-Hop
// header cannot be replayed even inside the clock-skew window.
type replayCache struct {
	shards      [replayShards]replayShard
	maxPerShard int
	failClosed  bool
	onEvict     func()
}

func newReplayCache(maxEntries int, failClosed bool, onEvict func()) *replayCache {
	if maxEntries <= 0 {
		maxEntries = DefaultReplayMax
	}
	perShard := maxEntries / replayShards
	if perShard < 1 {
		perShard = 1
	}
	return &replayCache{
		maxPerShard: perShard,
		failClosed:  failClosed,
		onEvict:     onEvict,
	}
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

// checkAndRecord checks whether (edge, nonce) is already tracked and unexpired
// (returning ErrReplay). Otherwise it records (edge, nonce) until nowMs+ttlMs
// in strict O(1) time.
//
// When the target shard is full of unexpired entries:
//   - if failClosed is true, it invokes onEvict and returns ErrReplaySaturated
//     without evicting any existing unexpired nonce;
//   - otherwise it evicts the oldest unexpired entry from the FIFO head in O(1),
//     records the new nonce, and invokes onEvict.
func (c *replayCache) checkAndRecord(edge, nonce string, nowMs, ttlMs int64) error {
	if c == nil || nonce == "" {
		return nil
	}
	if ttlMs < 1000 {
		ttlMs = 1000
	}
	k := makeReplayKey(edge, nonce)
	sh := &c.shards[k[0]]

	sh.mu.Lock()
	if sh.entries != nil {
		if exp, ok := sh.entries[k]; ok && exp > nowMs {
			sh.mu.Unlock()
			return ErrReplay
		}
	}

	// Reclaim a small bounded batch of expired/shadowed entries from the FIFO
	// head in strict O(1) time so lock hold time never scales with shard size.
	for popped := 0; popped < 4 && sh.count > 0 && sh.isStaleHead(nowMs); popped++ {
		sh.popHead()
	}

	evicted := false
	if sh.count >= c.maxPerShard {
		if sh.isStaleHead(nowMs) {
			sh.popHead()
		} else {
			evicted = true
			if c.failClosed {
				sh.mu.Unlock()
				if c.onEvict != nil {
					c.onEvict()
				}
				return ErrReplaySaturated
			}
			sh.popHead()
		}
	}

	// Lazily initialize or grow the per-shard ring up to maxPerShard so low-
	// traffic leaves consume minimal memory.
	if sh.entries == nil {
		initCap := 64
		if c.maxPerShard < initCap {
			initCap = c.maxPerShard
		}
		sh.entries = make(map[replayKey]int64, initCap)
		sh.ring = make([]replayEntry, initCap)
	} else if sh.count == len(sh.ring) {
		newCap := len(sh.ring) * 2
		if newCap > c.maxPerShard {
			newCap = c.maxPerShard
		}
		nr := make([]replayEntry, newCap)
		first := len(sh.ring) - sh.head
		if first > sh.count {
			first = sh.count
		}
		copy(nr, sh.ring[sh.head:sh.head+first])
		if sh.count > first {
			copy(nr[first:], sh.ring[:sh.count-first])
		}
		sh.ring = nr
		sh.head = 0
	}

	exp := nowMs + ttlMs
	tail := sh.head + sh.count
	if tail >= len(sh.ring) {
		tail -= len(sh.ring)
	}
	sh.ring[tail] = replayEntry{key: k, exp: exp}
	sh.count++
	sh.entries[k] = exp
	sh.mu.Unlock()

	if evicted && c.onEvict != nil {
		c.onEvict()
	}
	return nil
}
