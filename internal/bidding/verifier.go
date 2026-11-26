package bidding

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/andreimerlescu/concert/internal/x402"
)

// VerifyReceipt is the off-chain verification outcome returned by
// [PaymentSettler.Verify]. Verification never broadcasts transactions or takes
// custody of funds.
type VerifyReceipt struct {
	// Valid reports whether the crypto authorization passed off-chain
	// signature, amount, asset, and policy screening checks.
	Valid bool
	// Payer is the verified on-chain payer address for the authorization.
	Payer string
	// PolicyID is the optional policy screening identifier approving the bid.
	PolicyID string
	// InvalidReason is a machine-readable rejection code when Valid is false.
	InvalidReason string
}

// SettleReceipt is the on-chain settlement outcome returned by
// [PaymentSettler.Settle] for a winning or instant-buy bid.
type SettleReceipt struct {
	// Settled reports whether the winning authorization was settled on-chain.
	Settled bool
	// Transaction is the chain transaction hash or ledger identifier.
	Transaction string
	// Network is the CAIP-2 or canonical network identifier used for settlement.
	Network string
	// Payer is the settled on-chain payer address.
	Payer string
	// ErrorReason is a machine-readable failure code when Settled is false.
	ErrorReason string
}

// PaymentSettler is the narrow inward-facing port decoupling the bidding
// engine from chain gateways and x402 v2 settlement mechanisms.
//
// Implementations must be safe for concurrent use by multiple goroutines and
// must honor ctx cancellation and deadlines. Verify must be strictly off-chain
// (zero broadcast, zero custody); Settle is invoked only for winning bids (or
// instant-buy offers when slots are open).
type PaymentSettler interface {
	// Verify validates an x402 v2 crypto payment authorization and policy
	// screening strictly off-chain without broadcasting or taking custody.
	Verify(ctx context.Context, bid BidSubmission) (VerifyReceipt, error)

	// Settle broadcasts and settles a single winning or instant-buy bid on-chain.
	// Losing bids are never passed to Settle.
	Settle(ctx context.Context, bid BidSubmission) (SettleReceipt, error)
}

// ClusterSync is an optional outward port for replicating accepted bids to a
// shared cluster store such as concert-kv (via CQ.BID).
//
// Implementations must be safe for concurrent use and honor ctx cancellation.
type ClusterSync interface {
	// SyncBid propagates an accepted bid amount for a waiting ticket/bid in
	// scope to peer edges.
	SyncBid(ctx context.Context, scope, bidID string, normalizedMicroUSD int64) error
}

// ErrInvalidCapacity is returned when constructing a bounded cache with a
// non-positive capacity.
var ErrInvalidCapacity = errors.New("bidding: capacity must be positive")

// replayEntry is an intrusive doubly-linked list node stored inside
// ReplayCache so lookups, insertions, and LRU evictions run in O(1) time
// without interface boxing allocations.
type replayEntry struct {
	key  [32]byte
	prev *replayEntry
	next *replayEntry
}

// ReplayCache is a strictly bounded O(1) LRU set of SHA-256 payload digests
// used to prevent payment authorization replay attacks across bids and epochs.
//
// All methods are safe for concurrent use. Every access is guarded by mu.
type ReplayCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[[32]byte]*replayEntry // guarded by mu
	head     *replayEntry              // most recently used; guarded by mu
	tail     *replayEntry              // least recently used; guarded by mu
}

// NewReplayCache creates a bounded O(1) LRU replay cache holding at most
// capacity payload digests.
//
// # Parameters
//
//   - capacity: Maximum number of digests retained before the least-recently-used
//     digest is evicted. Must be at least 1.
//
// # Returns
//
// Returns a ready-to-use *ReplayCache, or ErrInvalidCapacity if capacity < 1.
//
// # Example
//
//	cache, err := NewReplayCache(1024)
//	if err != nil {
//		return err // inside a function returning error
//	}
//	digest := PayloadDigest(ChainXRPL, "XRP", "1000000", []byte(`{"nonce":"n1"}`))
//	_ = cache.AddIfAbsent(digest)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:557 (direct call)
//   - internal/bidding/auction.go:557 (function value)
//   - internal/bidding/bidding_test.go:1212 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func NewReplayCache(capacity int) (*ReplayCache, error) {
	if capacity < 1 {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidCapacity, capacity)
	}
	return &ReplayCache{
		capacity: capacity,
		entries:  make(map[[32]byte]*replayEntry, min(capacity, 256)),
	}, nil
}

// Contains reports whether digest is currently present in the cache without
// inserting it. If present, the entry is promoted to most-recently-used.
//
// # Parameters
//
//   - digest: 32-byte SHA-256 payload digest produced by [PayloadDigest].
//
// # Returns
//
// true if digest is in the cache, false otherwise. Safe for concurrent use.
//
// # Example
//
//	cache, err := NewReplayCache(64)
//	if err != nil {
//		return err // inside a function returning error
//	}
//	digest := PayloadDigest(ChainSolana, "SOL", "5000000", []byte(`{"nonce":"s1"}`))
//	_ = cache.Contains(digest)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:988 (direct call)
//   - internal/bidding/auction.go:988 (function value)
//   - internal/bidding/bidding_test.go:1223 (direct call)
//   - internal/bidding/bidding_test.go:1232 (direct call)
//   - internal/bidding/bidding_test.go:1235 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (c *ReplayCache) Contains(digest [32]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ent, ok := c.entries[digest]
	if !ok {
		return false
	}
	c.moveToFrontLocked(ent)
	return true
}

// AddIfAbsent atomically checks for digest and inserts it if absent. When the
// cache is at capacity, the least-recently-used digest is evicted in O(1) time.
//
// # Parameters
//
//   - digest: 32-byte SHA-256 payload digest produced by [PayloadDigest].
//
// # Returns
//
// true if digest was newly inserted, or false if digest was already present
// (indicating a replay). Safe for concurrent use.
//
// # Example
//
//	cache, err := NewReplayCache(64)
//	if err != nil {
//		return err // inside a function returning error
//	}
//	digest := PayloadDigest(ChainHedera, "0.0.0", "100000000", []byte(`{"nonce":"h1"}`))
//	first := cache.AddIfAbsent(digest)
//	second := cache.AddIfAbsent(digest)
//	_, _ = first, second
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:1202 (direct call)
//   - internal/bidding/auction.go:1202 (function value)
//   - internal/bidding/auction.go:1372 (direct call)
//   - internal/bidding/auction.go:1372 (function value)
//   - internal/bidding/bidding_test.go:1219 (direct call)
//   - internal/bidding/bidding_test.go:1226 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (c *ReplayCache) AddIfAbsent(digest [32]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ent, exists := c.entries[digest]; exists {
		c.moveToFrontLocked(ent)
		return false
	}
	ent := &replayEntry{key: digest}
	c.entries[digest] = ent
	c.pushFrontLocked(ent)
	if len(c.entries) > c.capacity {
		c.evictTailLocked()
	}
	return true
}

// Len returns the current number of digests stored in the cache.
//
// # Parameters
//
// None.
//
// # Returns
//
// Current entry count in [0, capacity]. Safe for concurrent use.
//
// # Example
//
//	cache, err := NewReplayCache(16)
//	if err != nil {
//		return err // inside a function returning error
//	}
//	_ = cache.Len()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:1229 (direct call)
//   - internal/bidding/bidding_test.go:1230 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// pushFrontLocked inserts ent at the head of the intrusive LRU list.
// Caller must hold c.mu.
//
// # Parameters
//
//   - ent: Newly allocated replayEntry not currently linked in the list.
//
// # Returns
//
// None. Mutates c.head and c.tail under c.mu.
//
// # Example
//
//	// Internal helper called under c.mu:
//	// c.pushFrontLocked(&replayEntry{key: digest})
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/verifier.go:225 (direct call)
//   - internal/bidding/verifier.go:225 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (c *ReplayCache) pushFrontLocked(ent *replayEntry) {
	ent.prev = nil
	ent.next = c.head
	if c.head != nil {
		c.head.prev = ent
	} else {
		c.tail = ent
	}
	c.head = ent
}

// moveToFrontLocked moves an already-linked entry to the head of the LRU list.
// Caller must hold c.mu.
//
// # Parameters
//
//   - ent: Non-nil replayEntry already present in c.entries.
//
// # Returns
//
// None. Mutates list pointers under c.mu.
//
// # Example
//
//	// Internal helper called under c.mu:
//	// c.moveToFrontLocked(ent)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/verifier.go:176 (direct call)
//   - internal/bidding/verifier.go:176 (function value)
//   - internal/bidding/verifier.go:220 (direct call)
//   - internal/bidding/verifier.go:220 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (c *ReplayCache) moveToFrontLocked(ent *replayEntry) {
	if ent == c.head {
		return
	}
	if ent.prev != nil {
		ent.prev.next = ent.next
	}
	if ent.next != nil {
		ent.next.prev = ent.prev
	} else {
		c.tail = ent.prev
	}
	ent.prev = nil
	ent.next = c.head
	if c.head != nil {
		c.head.prev = ent
	}
	c.head = ent
}

// evictTailLocked removes the least-recently-used entry from the tail of the
// list and deletes it from c.entries. Caller must hold c.mu.
//
// # Parameters
//
// None.
//
// # Returns
//
// None. Mutates c.entries, c.head, and c.tail under c.mu.
//
// # Example
//
//	// Internal helper called under c.mu when len(c.entries) > c.capacity:
//	// c.evictTailLocked()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/verifier.go:227 (direct call)
//   - internal/bidding/verifier.go:227 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (c *ReplayCache) evictTailLocked() {
	if c.tail == nil {
		return
	}
	victim := c.tail
	delete(c.entries, victim.key)
	if victim.prev != nil {
		victim.prev.next = nil
		c.tail = victim.prev
	} else {
		c.head = nil
		c.tail = nil
	}
	victim.prev = nil
	victim.next = nil
}

// PayloadDigest computes a deterministic SHA-256 fingerprint for a bid's
// crypto payment authorization. If payload is valid JSON (the standard x402 v2
// wire encoding), it is canonicalized first so key reordering or whitespace
// changes cannot bypass replay detection.
//
// # Parameters
//
//   - chain: Canonical chain identifier (e.g. "xrpl", "stellar", "hedera", "solana").
//   - asset: Asset identifier for the bid.
//   - amountAtomic: Atomic amount string for the bid.
//   - payload: Raw x402 payment authorization bytes. The slice is read-only and
//     not retained.
//
// # Returns
//
// A 32-byte SHA-256 digest uniquely identifying the payment authorization
// context. Never returns raw payload bytes.
//
// # Example
//
//	d1 := PayloadDigest(ChainXRPL, "XRP", "1000000", []byte(`{"b":2,"a":1}`))
//	d2 := PayloadDigest(ChainXRPL, "XRP", "1000000", []byte(`{"a":1,"b":2}`))
//	_ = d1 == d2 // true
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:987 (direct call)
//   - internal/bidding/auction.go:987 (function value)
//   - internal/bidding/bidding_test.go:1216 (direct call)
//   - internal/bidding/bidding_test.go:1217 (direct call)
//   - internal/bidding/bidding_test.go:1218 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func PayloadDigest(chain, asset, amountAtomic string, payload []byte) [32]byte {
	// Canonicalize valid JSON payloads so whitespace or key-order permutations
	// yield the same digest and cannot bypass replay detection.
	body := payload
	if canonical, err := x402.Canonical(payload); err == nil {
		body = canonical
	}
	h := sha256.New()
	// sha256.Hash.Write never returns a non-nil error.
	_, _ = h.Write([]byte(strings.ToLower(strings.TrimSpace(chain))))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.TrimSpace(asset)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.TrimSpace(amountAtomic)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(body)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// statusEntry is a node in the bounded bid-status lookup LRU kept by Engine so
// historical bid queries stay O(1) while memory stays strictly bounded (R3).
type statusEntry struct {
	bidID  string
	record BidRecord
	prev   *statusEntry
	next   *statusEntry
}

// statusHistory stores at most capacity BidRecord snapshots in O(1) LRU order.
// Not internally synchronized; owned and guarded by Engine.mu.
type statusHistory struct {
	capacity int
	entries  map[string]*statusEntry
	head     *statusEntry
	tail     *statusEntry
}

// newStatusHistory initializes a bounded statusHistory holding at most
// capacity records.
//
// # Parameters
//
//   - capacity: Maximum number of BidRecord snapshots to retain. Values below 1
//     are clamped to 1.
//
// # Returns
//
// Initialized *statusHistory ready for use under Engine.mu.
//
// # Example
//
//	h := newStatusHistory(128)
//	h.Put(BidRecord{BidID: "b1", Status: BidStatusPending})
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:581 (direct call)
//   - internal/bidding/auction.go:581 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func newStatusHistory(capacity int) *statusHistory {
	if capacity < 1 {
		capacity = 1
	}
	return &statusHistory{
		capacity: capacity,
		entries:  make(map[string]*statusEntry, min(capacity, 256)),
	}
}

// Put inserts or updates rec by rec.BidID and evicts the oldest entry if the
// capacity bound is exceeded. Caller must hold Engine.mu.
//
// # Parameters
//
//   - rec: Immutable BidRecord snapshot to store. Records with an empty BidID
//     are ignored.
//
// # Returns
//
// None. Mutates h in place.
//
// # Example
//
//	h := newStatusHistory(16)
//	h.Put(BidRecord{BidID: "bid-1", Status: BidStatusPending})
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:1259 (direct call)
//   - internal/bidding/auction.go:1259 (function value)
//   - internal/bidding/auction.go:1396 (direct call)
//   - internal/bidding/auction.go:1396 (function value)
//   - internal/bidding/auction.go:1440 (direct call)
//   - internal/bidding/auction.go:1440 (function value)
//   - internal/bidding/clear.go:395 (direct call)
//   - internal/bidding/clear.go:395 (function value)
//   - internal/bidding/clear.go:398 (direct call)
//   - internal/bidding/clear.go:398 (function value)
//   - internal/bidding/clear.go:401 (direct call)
//   - internal/bidding/clear.go:401 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (h *statusHistory) Put(rec BidRecord) {
	if rec.BidID == "" {
		return
	}
	if ent, ok := h.entries[rec.BidID]; ok {
		ent.record = rec
		h.moveToFront(ent)
		return
	}
	ent := &statusEntry{bidID: rec.BidID, record: rec}
	h.entries[rec.BidID] = ent
	ent.next = h.head
	if h.head != nil {
		h.head.prev = ent
	} else {
		h.tail = ent
	}
	h.head = ent
	if len(h.entries) > h.capacity {
		victim := h.tail
		delete(h.entries, victim.bidID)
		if victim.prev != nil {
			victim.prev.next = nil
			h.tail = victim.prev
		} else {
			h.head = nil
			h.tail = nil
		}
		victim.prev = nil
		victim.next = nil
	}
}

// Get retrieves the stored BidRecord for bidID without modifying its fields.
// Caller must hold Engine.mu.
//
// # Parameters
//
//   - bidID: Bid identifier to look up.
//
// # Returns
//
// The stored BidRecord snapshot and true if present, or the zero BidRecord and
// false if not found or evicted.
//
// # Example
//
//	h := newStatusHistory(16)
//	h.Put(BidRecord{BidID: "bid-1", Status: BidStatusSettled})
//	rec, ok := h.Get("bid-1")
//	_, _ = rec, ok
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:1494 (direct call)
//   - internal/bidding/auction.go:1494 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (h *statusHistory) Get(bidID string) (BidRecord, bool) {
	ent, ok := h.entries[bidID]
	if !ok {
		return BidRecord{}, false
	}
	h.moveToFront(ent)
	return ent.record, true
}

// moveToFront promotes an existing statusEntry to the head of the LRU list.
// Caller must hold Engine.mu.
//
// # Parameters
//
//   - ent: Non-nil statusEntry currently linked in h.
//
// # Returns
//
// None. Mutates list links in place.
//
// # Example
//
//	// Internal helper called by Put and Get under Engine.mu.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/verifier.go:543 (direct call)
//   - internal/bidding/verifier.go:543 (function value)
//   - internal/bidding/verifier.go:603 (direct call)
//   - internal/bidding/verifier.go:603 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (h *statusHistory) moveToFront(ent *statusEntry) {
	if ent == h.head {
		return
	}
	if ent.prev != nil {
		ent.prev.next = ent.next
	}
	if ent.next != nil {
		ent.next.prev = ent.prev
	} else {
		h.tail = ent.prev
	}
	ent.prev = nil
	ent.next = h.head
	if h.head != nil {
		h.head.prev = ent
	}
	h.head = ent
}
