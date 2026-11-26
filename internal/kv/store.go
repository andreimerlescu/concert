package kv

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	numShards = 64

	// Default store capacity bounds (R3).
	DefaultMaxMemoryBytes    int64 = 64 << 20 // 64 MiB
	DefaultPubSubBuffer      int   = 256
	DefaultSlowConsumerLimit int   = 16
	DefaultMaxSubscribers    int   = 10000
	DefaultMaxQueues         int   = 4096
	DefaultMaxQueueEntries   int   = 100000
	DefaultQueueTicketTTL          = 5 * time.Minute
	DefaultClaimRetentionTTL       = 30 * time.Second

	entryOverheadBytes int64 = 64
	queueEntryBytes    int64 = 128
)

// Sentinel errors returned by Store operations.
var (
	ErrMaxMemoryExceeded = errors.New("OOM command not allowed when used memory exceeds maxmemory")
	ErrWrongType         = errors.New("WRONGTYPE operation against a key holding the wrong kind of value")
	ErrNotInteger        = errors.New("ERR value is not an integer or out of range")
	ErrIntOverflow       = errors.New("ERR increment or decrement would overflow")
	ErrMaxSubscribers    = errors.New("ERR max pubsub subscribers reached")
	ErrMaxQueues         = errors.New("ERR max concert queues reached")
	ErrQueueFull         = errors.New("ERR concert queue entry limit reached")
	ErrTicketNotFound    = errors.New("ERR ticket not found in queue")
	ErrBidTooLow         = errors.New("ERR bid must exceed current ticket bid")
	ErrInvalidArg        = errors.New("ERR invalid argument")
)

// EvictionPolicy controls how Store reacts when a write would exceed
// MaxMemoryBytes.
type EvictionPolicy uint8

const (
	// EvictOldest deterministically evicts the least-recently-updated KV/hash
	// entries until the write fits under MaxMemoryBytes.
	EvictOldest EvictionPolicy = iota
	// EvictReject rejects writes with ErrMaxMemoryExceeded without evicting
	// existing keys.
	EvictReject
)

// StoreConfig configures capacity limits, eviction behavior, and an optional
// clock for deterministic tests. Zero fields use safe defaults.
type StoreConfig struct {
	// MaxMemoryBytes caps approximate tracked memory across all shards.
	// Negative disables the ceiling; zero uses DefaultMaxMemoryBytes.
	MaxMemoryBytes int64
	// EvictionPolicy selects EvictOldest (default) or EvictReject.
	EvictionPolicy EvictionPolicy
	// PubSubBuffer sets the per-subscriber buffered channel length.
	PubSubBuffer int
	// SlowConsumerLimit is the number of consecutive dropped publishes before
	// a slow subscriber is evicted and closed.
	SlowConsumerLimit int
	// MaxSubscribers caps active Pub/Sub subscriptions across the store.
	MaxSubscribers int
	// MaxQueues caps distinct Concert waiting-room queues.
	MaxQueues int
	// MaxQueueEntries caps entries in any single Concert queue.
	MaxQueueEntries int
	// Now overrides time.Now when non-nil (for deterministic TTL tests).
	Now func() time.Time
}

// SetOptions configures conditional and TTL behavior for Store.Set and
// Client.Set.
type SetOptions struct {
	// TTL sets a relative expiration duration (zero means no expiry unless
	// ExpiresAt is set).
	TTL time.Duration
	// ExpiresAt sets an explicit expiration instant; overrides TTL when non-zero.
	ExpiresAt time.Time
	// NX sets the key only if it does not already exist (or is expired).
	NX bool
	// XX sets the key only if it already exists and is not expired.
	XX bool
}

// StoreStats holds a point-in-time summary of store memory, key counts, and
// Pub/Sub counters surfaced by INFO and diagnostics.
type StoreStats struct {
	Keys              int64
	Hashes            int64
	Queues            int64
	UsedMemoryBytes   int64
	MaxMemoryBytes    int64
	Evictions         int64
	Mutations         uint64
	Commands          int64
	PubSubChannels    int64
	PubSubSubscribers int64
	PubSubPublished   int64
	PubSubDropped     int64
	PubSubEvicted     int64
}

// CQJoinResult summarizes the outcome of a CQ.JOIN command.
type CQJoinResult struct {
	Position int64
	Depth    int64
	Seq      uint64
	Degraded bool
}

// CQPollResult summarizes the status of a ticket queried via CQ.POLL.
type CQPollResult struct {
	Status      string // "waiting", "claimed", "missing", or "degraded"
	Position    int64
	Depth       int64
	Bid         int64
	RemainingMS int64
	Degraded    bool
}

// CQClaimEntry describes one ticket claimed from a Concert queue by an edge.
type CQClaimEntry struct {
	TicketID  string
	ClientKey string
	Bid       int64
	Seq       uint64
}

// CQBidResult summarizes an updated ticket bid from CQ.BID.
type CQBidResult struct {
	Position int64
	Depth    int64
	Bid      int64
	Degraded bool
}

// CQQueueStats holds point-in-time counters for a Concert waiting-room queue.
type CQQueueStats struct {
	Waiting      int64
	Claimed      int64
	TotalJoined  int64
	TotalClaimed int64
	TotalPurged  int64
	HighestBid   int64
	OldestWaitMS int64
	Degraded     bool
}

type kvEntry struct {
	val        []byte
	expiresAt  time.Time
	updatedSeq uint64
	bytes      int64
}

type hashEntry struct {
	fields     map[string][]byte
	expiresAt  time.Time
	updatedSeq uint64
	bytes      int64
}

type queueTicket struct {
	TicketID  string    `json:"ticket_id"`
	ClientKey string    `json:"client_key"`
	Seq       uint64    `json:"seq"`
	JoinedAt  time.Time `json:"joined_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Bid       int64     `json:"bid"`
	Claimed   bool      `json:"claimed"`
	ClaimedBy string    `json:"claimed_by,omitempty"`
	ClaimedAt time.Time `json:"claimed_at,omitempty"`
}

type concertQueue struct {
	tickets      map[string]*queueTicket
	nextSeq      uint64
	totalJoined  int64
	totalClaimed int64
	totalPurged  int64
	bytes        int64
}

type shard struct {
	// mu guards strings, hashes, and queues for this shard. Never hold mu
	// across I/O, callbacks, or while acquiring another shard's mu (except
	// ascending-order full-store Snapshot/LoadSnapshot).
	mu      sync.Mutex
	strings map[string]*kvEntry
	hashes  map[string]*hashEntry
	queues  map[string]*concertQueue
}

// PubSubMessage is an immutable value delivered over Subscription.Messages().
// Payload is copied before publication so subscribers never share mutable memory.
type PubSubMessage struct {
	Channel string
	Payload []byte
}

// Subscription represents one active Pub/Sub consumer with a bounded delivery
// channel. Callers must invoke Close when done.
type Subscription struct {
	id      uint64
	store   *Store
	ch      chan PubSubMessage
	evicted chan struct{}

	// mu guards closed, drops, and channels. Because Publish performs only a
	// non-blocking select under mu, holding mu during trySend cannot deadlock
	// and guarantees zero send-on-closed panics (C4, C5).
	mu       sync.Mutex
	closed   bool
	drops    int
	channels map[string]struct{}
}

// Messages returns the bounded receive-only channel for published messages.
// The channel closes when Close is called or when the subscriber is evicted
// as a slow consumer.
//
// # Parameters
//
// None.
//
// # Returns
//
// A receive-only channel yielding PubSubMessage values.
//
// # Example
//
//	for msg := range sub.Messages() {
//	    fmt.Println(msg.Channel, string(msg.Payload))
//	}
func (s *Subscription) Messages() <-chan PubSubMessage {
	return s.ch
}

// Evicted returns a channel that closes if the broker evicts this subscriber
// after exceeding SlowConsumerLimit consecutive dropped messages.
//
// # Parameters
//
// None.
//
// # Returns
//
// A signal channel closed upon slow-consumer eviction.
//
// # Example
//
//	select {
//	case <-sub.Evicted():
//	    // reconnect or shed load
//	case msg, ok := <-sub.Messages():
//	    _ = msg
//	    _ = ok
//	}
func (s *Subscription) Evicted() <-chan struct{} {
	return s.evicted
}

// Unsubscribe detaches this subscription from channels (or all subscribed
// channels when len(channels) == 0) and returns the remaining subscribed count.
//
// # Parameters
//
//   - channels: Channel names to remove; empty unsubscribes from all channels.
//
// # Returns
//
// Remaining number of channels attached to this subscription.
//
// # Example
//
//	rem := sub.Unsubscribe("concert:bans:events")
//	_ = rem
func (s *Subscription) Unsubscribe(channels ...string) int {
	return s.store.unsubscribe(s, channels...)
}

// Close detaches this subscription from all channels and closes Messages().
// Safe to call concurrently and multiple times.
//
// # Parameters
//
// None.
//
// # Returns
//
// None.
//
// # Example
//
//	sub, err := store.Subscribe("events")
//	if err != nil {
//	    return err
//	}
//	defer sub.Close()
func (s *Subscription) Close() {
	s.store.closeSubscription(s, false)
}

// trySend attempts a non-blocking send of msg to s.ch. Returns (delivered,
// shouldEvict). Safe for concurrent Publish calls.
//
// # Parameters
//
//   - msg: Immutable message value to enqueue.
//   - slowLimit: Consecutive drop threshold triggering eviction.
//
// # Returns
//
// delivered is true if enqueued; shouldEvict is true if consecutive drops
// reached slowLimit.
//
// # Example
//
//	delivered, evict := sub.trySend(msg, 16)
func (s *Subscription) trySend(msg PubSubMessage, slowLimit int) (delivered bool, shouldEvict bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, false
	}
	select {
	case s.ch <- msg:
		s.drops = 0
		return true, false
	default:
		s.drops++
		if slowLimit > 0 && s.drops >= slowLimit {
			return false, true
		}
		return false, false
	}
}

// closeChannels marks s closed and closes s.ch (and s.evicted when evicted is
// true). Safe to call more than once.
//
// # Parameters
//
//   - evicted: Whether closure was triggered by slow-consumer eviction.
//
// # Returns
//
// true if this call performed the transition from open to closed.
//
// # Example
//
//	if sub.closeChannels(true) {
//	    store.pubsubEvicted.Add(1)
//	}
func (s *Subscription) closeChannels(evicted bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.closed = true
	if evicted {
		close(s.evicted)
	}
	close(s.ch)
	return true
}

// Store is a 64-shard concurrent in-memory key-value, hash, bounded Pub/Sub,
// and Concert waiting-room queue engine. All exported methods are safe for
// concurrent use.
type Store struct {
	shards [numShards]shard
	cfg    StoreConfig
	nowFn  func() time.Time

	usedBytes   atomic.Int64
	evictions   atomic.Int64
	mutations   atomic.Uint64
	commands    atomic.Int64
	queueCount  atomic.Int64
	nextSubID   atomic.Uint64
	subCount    atomic.Int64
	pubSent     atomic.Int64
	pubDropped  atomic.Int64
	pubEvicted  atomic.Int64
	updateClock atomic.Uint64

	// pubMu guards pubSubs (channel -> subscriber map). Never held while
	// locking shard mutexes.
	pubMu   sync.RWMutex
	pubSubs map[string]map[uint64]*Subscription
}

// NewStore allocates and initializes a sharded Store with normalized capacity
// limits from cfg.
//
// # Parameters
//
//   - cfg: Store capacity, eviction, Pub/Sub, and clock settings; zero fields
//     use safe production defaults.
//
// # Returns
//
// A ready-to-use *Store safe for concurrent access.
//
// # Example
//
//	st := kv.NewStore(kv.StoreConfig{MaxMemoryBytes: 32 << 20})
//	_, _ = st.Set("k", []byte("v"), kv.SetOptions{})
func NewStore(cfg StoreConfig) *Store {
	if cfg.MaxMemoryBytes == 0 {
		cfg.MaxMemoryBytes = DefaultMaxMemoryBytes
	}
	if cfg.PubSubBuffer <= 0 {
		cfg.PubSubBuffer = DefaultPubSubBuffer
	}
	if cfg.SlowConsumerLimit <= 0 {
		cfg.SlowConsumerLimit = DefaultSlowConsumerLimit
	}
	if cfg.MaxSubscribers <= 0 {
		cfg.MaxSubscribers = DefaultMaxSubscribers
	}
	if cfg.MaxQueues <= 0 {
		cfg.MaxQueues = DefaultMaxQueues
	}
	if cfg.MaxQueueEntries <= 0 {
		cfg.MaxQueueEntries = DefaultMaxQueueEntries
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	s := &Store{
		cfg:     cfg,
		nowFn:   nowFn,
		pubSubs: make(map[string]map[uint64]*Subscription),
	}
	for i := range s.shards {
		s.shards[i].strings = make(map[string]*kvEntry)
		s.shards[i].hashes = make(map[string]*hashEntry)
		s.shards[i].queues = make(map[string]*concertQueue)
	}
	return s
}

// now returns the current store timestamp using the configured clock.
//
// # Parameters
//
// None.
//
// # Returns
//
// Current time.Time instant.
//
// # Example
//
//	t := s.now()
func (s *Store) now() time.Time {
	return s.nowFn()
}

// shardFor maps key deterministically to one of the 64 shards using FNV-1a.
//
// # Parameters
//
//   - key: Key or queue name to hash.
//
// # Returns
//
// Pointer to the owning shard and its index in [0, numShards).
//
// # Example
//
//	sh, idx := s.shardFor("session:123")
func (s *Store) shardFor(key string) (*shard, int) {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	idx := int(h.Sum32() & (numShards - 1))
	return &s.shards[idx], idx
}

// nextMutationSeq advances and returns the monotonic store mutation sequence.
//
// # Parameters
//
// None.
//
// # Returns
//
// Monotonically increasing sequence number >= 1.
//
// # Example
//
//	seq := s.nextMutationSeq()
func (s *Store) nextMutationSeq() uint64 {
	return s.mutations.Add(1)
}

// MutationSeq returns the latest committed mutation sequence number.
//
// # Parameters
//
// None.
//
// # Returns
//
// Current monotonic mutation sequence counter.
//
// # Example
//
//	seq := store.MutationSeq()
func (s *Store) MutationSeq() uint64 {
	return s.mutations.Load()
}

// ensureBudget makes room for delta additional bytes under MaxMemoryBytes.
// Caller must NOT hold any shard lock.
//
// # Parameters
//
//   - delta: Positive additional bytes required.
//   - startShard: Preferred shard index to inspect first for expirations/eviction.
//
// # Returns
//
// nil if budget is available (or unlimited); ErrMaxMemoryExceeded otherwise.
//
// # Example
//
//	if err := s.ensureBudget(1024, idx); err != nil {
//	    return err
//	}
func (s *Store) ensureBudget(delta int64, startShard int) error {
	limit := s.cfg.MaxMemoryBytes
	if limit < 0 || delta <= 0 {
		return nil
	}
	if delta > limit {
		return ErrMaxMemoryExceeded
	}
	if s.usedBytes.Load()+delta <= limit {
		return nil
	}
	now := s.now()
	// Pass 1: reap expired entries across shards, one shard lock at a time.
	for off := 0; off < numShards && s.usedBytes.Load()+delta > limit; off++ {
		sh := &s.shards[(startShard+off)&(numShards-1)]
		sh.mu.Lock()
		s.reapShardExpiredLocked(sh, now)
		sh.mu.Unlock()
	}
	if s.usedBytes.Load()+delta <= limit {
		return nil
	}
	if s.cfg.EvictionPolicy == EvictReject {
		return ErrMaxMemoryExceeded
	}
	// Pass 2: deterministic oldest-first eviction across shards until budget fits.
	for s.usedBytes.Load()+delta > limit {
		evictedAny := false
		for off := 0; off < numShards && s.usedBytes.Load()+delta > limit; off++ {
			sh := &s.shards[(startShard+off)&(numShards-1)]
			sh.mu.Lock()
			if s.evictOldestInShardLocked(sh) {
				evictedAny = true
			}
			sh.mu.Unlock()
		}
		if !evictedAny {
			return ErrMaxMemoryExceeded
		}
	}
	return nil
}

// reapShardExpiredLocked removes expired string and hash entries from sh.
// Caller must hold sh.mu.
//
// # Parameters
//
//   - sh: Locked shard to scan.
//   - now: Reference timestamp.
//
// # Returns
//
// None.
//
// # Example
//
//	sh.mu.Lock()
//	s.reapShardExpiredLocked(sh, now)
//	sh.mu.Unlock()
func (s *Store) reapShardExpiredLocked(sh *shard, now time.Time) {
	for k, e := range sh.strings {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			delete(sh.strings, k)
			s.usedBytes.Add(-e.bytes)
		}
	}
	for k, h := range sh.hashes {
		if !h.expiresAt.IsZero() && !now.Before(h.expiresAt) {
			delete(sh.hashes, k)
			s.usedBytes.Add(-h.bytes)
		}
	}
}

// evictOldestInShardLocked removes the single entry in sh with the lowest
// updatedSeq (preferring entries with shorter/existing keys deterministically).
// Caller must hold sh.mu.
//
// # Parameters
//
//   - sh: Locked shard from which to evict one entry.
//
// # Returns
//
// true if an entry was evicted; false if sh has no evictable string/hash keys.
//
// # Example
//
//	evicted := s.evictOldestInShardLocked(sh)
func (s *Store) evictOldestInShardLocked(sh *shard) bool {
	var (
		found     bool
		isHash    bool
		oldestKey string
		oldestSeq uint64 = math.MaxUint64
	)
	for k, e := range sh.strings {
		if !found || e.updatedSeq < oldestSeq || (e.updatedSeq == oldestSeq && k < oldestKey) {
			found = true
			isHash = false
			oldestKey = k
			oldestSeq = e.updatedSeq
		}
	}
	for k, h := range sh.hashes {
		if !found || h.updatedSeq < oldestSeq || (h.updatedSeq == oldestSeq && k < oldestKey) {
			found = true
			isHash = true
			oldestKey = k
			oldestSeq = h.updatedSeq
		}
	}
	if !found {
		return false
	}
	if isHash {
		h := sh.hashes[oldestKey]
		delete(sh.hashes, oldestKey)
		s.usedBytes.Add(-h.bytes)
	} else {
		e := sh.strings[oldestKey]
		delete(sh.strings, oldestKey)
		s.usedBytes.Add(-e.bytes)
	}
	s.evictions.Add(1)
	return true
}

// Get retrieves a copy of the string value stored at key. If key is missing,
// expired, or holds a hash, Get returns (nil, false). Safe for concurrent use.
//
// # Parameters
//
//   - key: Key name to look up.
//
// # Returns
//
// A freshly copied byte slice (caller owns it) and true if found; nil and
// false otherwise.
//
// # Example
//
//	val, ok := store.Get("greeting")
//	if ok {
//	    fmt.Println(string(val))
//	}
func (s *Store) Get(key string) ([]byte, bool) {
	sh, _ := s.shardFor(key)
	now := s.now()
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := sh.strings[key]
	if !ok {
		return nil, false
	}
	if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
		delete(sh.strings, key)
		s.usedBytes.Add(-e.bytes)
		return nil, false
	}
	return bytes.Clone(e.val), true
}

// Set stores a copy of val at key according to opts (EX/PX/PXAT, NX, XX).
// Safe for concurrent use.
//
// # Parameters
//
//   - key: Key name to set.
//   - val: Byte payload; copied before storing so caller may reuse it.
//   - opts: Optional TTL/ExpiresAt and NX/XX condition flags.
//
// # Returns
//
// (true, nil) if the key was written, (false, nil) if an NX/XX condition was
// not met, or (false, ErrMaxMemoryExceeded) / ErrInvalidArg on failure.
//
// # Example
//
//	ok, err := store.Set("lock:1", []byte("edge-a"), kv.SetOptions{
//	    TTL: 10 * time.Second,
//	    NX:  true,
//	})
//	if err != nil {
//	    return err
//	}
//	_ = ok
func (s *Store) Set(key string, val []byte, opts SetOptions) (bool, error) {
	if opts.NX && opts.XX {
		return false, fmt.Errorf("%w: NX and XX are mutually exclusive", ErrInvalidArg)
	}
	now := s.now()
	var exp time.Time
	switch {
	case !opts.ExpiresAt.IsZero():
		exp = opts.ExpiresAt
	case opts.TTL > 0:
		exp = now.Add(opts.TTL)
	case opts.TTL < 0:
		return false, fmt.Errorf("%w: TTL must be positive", ErrInvalidArg)
	}

	valCopy := bytes.Clone(val)
	if valCopy == nil {
		valCopy = []byte{}
	}
	newSize := entryOverheadBytes + int64(len(key)) + int64(len(valCopy))
	sh, idx := s.shardFor(key)

	if err := s.ensureBudget(newSize, idx); err != nil {
		return false, err
	}

	sh.mu.Lock()
	defer sh.mu.Unlock()

	// Check current existence (lazily expiring stale string or hash entries).
	var oldBytes int64
	exists := false
	if e, ok := sh.strings[key]; ok {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			delete(sh.strings, key)
			s.usedBytes.Add(-e.bytes)
		} else {
			exists = true
			oldBytes = e.bytes
		}
	}
	if !exists {
		if h, ok := sh.hashes[key]; ok {
			if !h.expiresAt.IsZero() && !now.Before(h.expiresAt) {
				delete(sh.hashes, key)
				s.usedBytes.Add(-h.bytes)
			} else {
				exists = true
				oldBytes = h.bytes
			}
		}
	}

	if opts.NX && exists {
		return false, nil
	}
	if opts.XX && !exists {
		return false, nil
	}

	// If expiry is already in the past (e.g. replayed expired PXAT), delete key.
	if !exp.IsZero() && !now.Before(exp) {
		if e, ok := sh.strings[key]; ok {
			delete(sh.strings, key)
			s.usedBytes.Add(-e.bytes)
		}
		if h, ok := sh.hashes[key]; ok {
			delete(sh.hashes, key)
			s.usedBytes.Add(-h.bytes)
		}
		s.nextMutationSeq()
		return true, nil
	}

	// Overwrite any hash at key (Redis SET replaces any existing key type).
	if h, ok := sh.hashes[key]; ok {
		delete(sh.hashes, key)
		s.usedBytes.Add(-h.bytes)
		oldBytes = 0
	}

	delta := newSize - oldBytes
	if s.cfg.MaxMemoryBytes > 0 && delta > 0 && s.usedBytes.Load()+delta > s.cfg.MaxMemoryBytes {
		if s.cfg.EvictionPolicy == EvictReject {
			return false, ErrMaxMemoryExceeded
		}
		for s.usedBytes.Load()+delta > s.cfg.MaxMemoryBytes {
			if !s.evictOldestInShardLocked(sh) {
				return false, ErrMaxMemoryExceeded
			}
		}
	}

	sh.strings[key] = &kvEntry{
		val:        valCopy,
		expiresAt:  exp,
		updatedSeq: s.updateClock.Add(1),
		bytes:      newSize,
	}
	s.usedBytes.Add(delta)
	s.nextMutationSeq()
	return true, nil
}

// Del removes one or more string or hash keys and returns the number of live
// keys removed. Safe for concurrent use.
//
// # Parameters
//
//   - keys: Key names to delete.
//
// # Returns
//
// Count of non-expired keys that were deleted.
//
// # Example
//
//	removed := store.Del("k1", "k2")
//	_ = removed
func (s *Store) Del(keys ...string) int64 {
	var deleted int64
	now := s.now()
	for _, key := range keys {
		sh, _ := s.shardFor(key)
		sh.mu.Lock()
		if e, ok := sh.strings[key]; ok {
			delete(sh.strings, key)
			s.usedBytes.Add(-e.bytes)
			if e.expiresAt.IsZero() || now.Before(e.expiresAt) {
				deleted++
			}
		}
		if h, ok := sh.hashes[key]; ok {
			delete(sh.hashes, key)
			s.usedBytes.Add(-h.bytes)
			if h.expiresAt.IsZero() || now.Before(h.expiresAt) {
				deleted++
			}
		}
		sh.mu.Unlock()
	}
	if deleted > 0 {
		s.nextMutationSeq()
	}
	return deleted
}

// Exists returns the number of supplied keys that currently exist and have not
// expired (counting duplicate key arguments each time, matching Redis).
//
// # Parameters
//
//   - keys: Key names to test.
//
// # Returns
//
// Count of existing non-expired keys.
//
// # Example
//
//	n := store.Exists("k1", "k2")
//	_ = n
func (s *Store) Exists(keys ...string) int64 {
	var count int64
	now := s.now()
	for _, key := range keys {
		sh, _ := s.shardFor(key)
		sh.mu.Lock()
		if e, ok := sh.strings[key]; ok {
			if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
				delete(sh.strings, key)
				s.usedBytes.Add(-e.bytes)
			} else {
				count++
			}
		} else if h, ok := sh.hashes[key]; ok {
			if !h.expiresAt.IsZero() && !now.Before(h.expiresAt) {
				delete(sh.hashes, key)
				s.usedBytes.Add(-h.bytes)
			} else {
				count++
			}
		}
		sh.mu.Unlock()
	}
	return count
}

// IncrBy atomically increments the integer stored at key by delta. Missing or
// expired keys start at 0. Preserves existing TTL when updating.
//
// # Parameters
//
//   - key: Key name to increment.
//   - delta: Signed 64-bit increment (may be negative).
//
// # Returns
//
// The new integer value, or an error matching ErrWrongType, ErrNotInteger,
// ErrIntOverflow, or ErrMaxMemoryExceeded.
//
// # Example
//
//	n, err := store.IncrBy("hits:home", 1)
//	if err != nil {
//	    return err
//	}
//	fmt.Println(n)
func (s *Store) IncrBy(key string, delta int64) (int64, error) {
	sh, idx := s.shardFor(key)
	estSize := entryOverheadBytes + int64(len(key)) + 24
	if err := s.ensureBudget(estSize, idx); err != nil {
		return 0, err
	}

	now := s.now()
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if h, ok := sh.hashes[key]; ok {
		if !h.expiresAt.IsZero() && !now.Before(h.expiresAt) {
			delete(sh.hashes, key)
			s.usedBytes.Add(-h.bytes)
		} else {
			return 0, ErrWrongType
		}
	}

	var cur int64
	var exp time.Time
	var oldBytes int64
	if e, ok := sh.strings[key]; ok {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			delete(sh.strings, key)
			s.usedBytes.Add(-e.bytes)
		} else {
			parsed, err := strconv.ParseInt(string(e.val), 10, 64)
			if err != nil {
				return 0, ErrNotInteger
			}
			cur = parsed
			exp = e.expiresAt
			oldBytes = e.bytes
		}
	}

	if (delta > 0 && cur > math.MaxInt64-delta) || (delta < 0 && cur < math.MinInt64-delta) {
		return 0, ErrIntOverflow
	}
	next := cur + delta
	encoded := strconv.AppendInt(nil, next, 10)
	newBytes := entryOverheadBytes + int64(len(key)) + int64(len(encoded))
	diff := newBytes - oldBytes
	if s.cfg.MaxMemoryBytes > 0 && diff > 0 && s.usedBytes.Load()+diff > s.cfg.MaxMemoryBytes {
		return 0, ErrMaxMemoryExceeded
	}
	sh.strings[key] = &kvEntry{
		val:        encoded,
		expiresAt:  exp,
		updatedSeq: s.updateClock.Add(1),
		bytes:      newBytes,
	}
	s.usedBytes.Add(diff)
	s.nextMutationSeq()
	return next, nil
}

// Expire sets a relative TTL on an existing string or hash key. A non-positive
// TTL immediately deletes the key (matching Redis EXPIRE semantics).
//
// # Parameters
//
//   - key: Key name to expire.
//   - ttl: Relative expiration duration.
//
// # Returns
//
// true if the key existed and was updated/deleted; false if the key did not
// exist.
//
// # Example
//
//	updated := store.Expire("session:1", 60*time.Second)
//	_ = updated
func (s *Store) Expire(key string, ttl time.Duration) bool {
	return s.ExpireAt(key, s.now().Add(ttl))
}

// ExpireAt sets an explicit expiration timestamp on an existing string or hash
// key. If at is at or before the current time, the key is deleted immediately.
//
// # Parameters
//
//   - key: Key name to update.
//   - at: Expiration instant.
//
// # Returns
//
// true if the key existed; false otherwise.
//
// # Example
//
//	ok := store.ExpireAt("k", time.Now().Add(time.Minute))
//	_ = ok
func (s *Store) ExpireAt(key string, at time.Time) bool {
	sh, _ := s.shardFor(key)
	now := s.now()
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if e, ok := sh.strings[key]; ok {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			delete(sh.strings, key)
			s.usedBytes.Add(-e.bytes)
			return false
		}
		if !now.Before(at) {
			delete(sh.strings, key)
			s.usedBytes.Add(-e.bytes)
		} else {
			e.expiresAt = at
		}
		s.nextMutationSeq()
		return true
	}
	if h, ok := sh.hashes[key]; ok {
		if !h.expiresAt.IsZero() && !now.Before(h.expiresAt) {
			delete(sh.hashes, key)
			s.usedBytes.Add(-h.bytes)
			return false
		}
		if !now.Before(at) {
			delete(sh.hashes, key)
			s.usedBytes.Add(-h.bytes)
		} else {
			h.expiresAt = at
		}
		s.nextMutationSeq()
		return true
	}
	return false
}

// TTL returns the remaining time-to-live of key in whole seconds, matching
// Redis semantics: -2 if key does not exist (or expired), -1 if key exists
// with no expiration, and >= 0 for remaining seconds.
//
// # Parameters
//
//   - key: Key name to inspect.
//
// # Returns
//
// Remaining seconds, -1 (no expiry), or -2 (missing).
//
// # Example
//
//	secs := store.TTL("session:1")
//	_ = secs
func (s *Store) TTL(key string) int64 {
	sh, _ := s.shardFor(key)
	now := s.now()
	sh.mu.Lock()
	defer sh.mu.Unlock()

	var exp time.Time
	if e, ok := sh.strings[key]; ok {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			delete(sh.strings, key)
			s.usedBytes.Add(-e.bytes)
			return -2
		}
		exp = e.expiresAt
	} else if h, ok := sh.hashes[key]; ok {
		if !h.expiresAt.IsZero() && !now.Before(h.expiresAt) {
			delete(sh.hashes, key)
			s.usedBytes.Add(-h.bytes)
			return -2
		}
		exp = h.expiresAt
	} else {
		return -2
	}

	if exp.IsZero() {
		return -1
	}
	rem := exp.Sub(now)
	if rem <= 0 {
		return 0
	}
	return int64(rem / time.Second)
}

// HSet sets one or more field/value pairs in the hash stored at key and returns
// the number of newly added fields (updated existing fields are not counted).
//
// # Parameters
//
//   - key: Hash key name.
//   - fields: Map of field name to value bytes; values are cloned on write.
//
// # Returns
//
// Count of newly inserted fields, or ErrWrongType / ErrMaxMemoryExceeded.
//
// # Example
//
//	added, err := store.HSet("concert:bans:state", map[string][]byte{
//	    "192.0.2.1": []byte(`{"action":"ban"}`),
//	})
//	if err != nil {
//	    return err
//	}
//	_ = added
func (s *Store) HSet(key string, fields map[string][]byte) (int64, error) {
	if len(fields) == 0 {
		return 0, nil
	}
	var estAdd int64 = entryOverheadBytes + int64(len(key))
	for f, v := range fields {
		estAdd += 32 + int64(len(f)) + int64(len(v))
	}
	sh, idx := s.shardFor(key)
	if err := s.ensureBudget(estAdd, idx); err != nil {
		return 0, err
	}

	now := s.now()
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if e, ok := sh.strings[key]; ok {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			delete(sh.strings, key)
			s.usedBytes.Add(-e.bytes)
		} else {
			return 0, ErrWrongType
		}
	}

	h, ok := sh.hashes[key]
	if ok && !h.expiresAt.IsZero() && !now.Before(h.expiresAt) {
		delete(sh.hashes, key)
		s.usedBytes.Add(-h.bytes)
		ok = false
	}

	var delta int64
	if !ok {
		delta += entryOverheadBytes + int64(len(key))
	}
	for f, v := range fields {
		if ok {
			if prev, exists := h.fields[f]; exists {
				delta += int64(len(v)) - int64(len(prev))
				continue
			}
		}
		delta += 32 + int64(len(f)) + int64(len(v))
	}

	if s.cfg.MaxMemoryBytes > 0 && delta > 0 && s.usedBytes.Load()+delta > s.cfg.MaxMemoryBytes {
		if s.cfg.EvictionPolicy == EvictReject {
			return 0, ErrMaxMemoryExceeded
		}
		for s.usedBytes.Load()+delta > s.cfg.MaxMemoryBytes {
			if !s.evictOldestInShardLocked(sh) {
				return 0, ErrMaxMemoryExceeded
			}
		}
	}

	if !ok {
		h = &hashEntry{
			fields: make(map[string][]byte, len(fields)),
			bytes:  entryOverheadBytes + int64(len(key)),
		}
		sh.hashes[key] = h
		s.usedBytes.Add(h.bytes)
	}

	var added int64
	for f, v := range fields {
		cp := bytes.Clone(v)
		if cp == nil {
			cp = []byte{}
		}
		if prev, exists := h.fields[f]; exists {
			diff := int64(len(cp)) - int64(len(prev))
			h.bytes += diff
			s.usedBytes.Add(diff)
		} else {
			inc := 32 + int64(len(f)) + int64(len(cp))
			h.bytes += inc
			s.usedBytes.Add(inc)
			added++
		}
		h.fields[f] = cp
	}
	h.updatedSeq = s.updateClock.Add(1)
	s.nextMutationSeq()
	return added, nil
}

// HGet returns a copy of field from the hash stored at key.
//
// # Parameters
//
//   - key: Hash key name.
//   - field: Field name within the hash.
//
// # Returns
//
// Cloned value bytes, found boolean, and ErrWrongType if key holds a string.
//
// # Example
//
//	val, ok, err := store.HGet("concert:bans:state", "192.0.2.1")
//	_, _, _ = val, ok, err
func (s *Store) HGet(key, field string) ([]byte, bool, error) {
	sh, _ := s.shardFor(key)
	now := s.now()
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if e, ok := sh.strings[key]; ok {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			delete(sh.strings, key)
			s.usedBytes.Add(-e.bytes)
		} else {
			return nil, false, ErrWrongType
		}
	}
	h, ok := sh.hashes[key]
	if !ok {
		return nil, false, nil
	}
	if !h.expiresAt.IsZero() && !now.Before(h.expiresAt) {
		delete(sh.hashes, key)
		s.usedBytes.Add(-h.bytes)
		return nil, false, nil
	}
	val, exists := h.fields[field]
	if !exists {
		return nil, false, nil
	}
	return bytes.Clone(val), true, nil
}

// HDel deletes fields from the hash at key, removing the hash key itself when
// it becomes empty.
//
// # Parameters
//
//   - key: Hash key name.
//   - fields: Field names to delete.
//
// # Returns
//
// Number of fields deleted, or ErrWrongType if key holds a string.
//
// # Example
//
//	n, err := store.HDel("concert:bans:state", "192.0.2.1")
//	_, _ = n, err
func (s *Store) HDel(key string, fields ...string) (int64, error) {
	if len(fields) == 0 {
		return 0, nil
	}
	sh, _ := s.shardFor(key)
	now := s.now()
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if e, ok := sh.strings[key]; ok {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			delete(sh.strings, key)
			s.usedBytes.Add(-e.bytes)
		} else {
			return 0, ErrWrongType
		}
	}
	h, ok := sh.hashes[key]
	if !ok {
		return 0, nil
	}
	if !h.expiresAt.IsZero() && !now.Before(h.expiresAt) {
		delete(sh.hashes, key)
		s.usedBytes.Add(-h.bytes)
		return 0, nil
	}
	var removed int64
	for _, f := range fields {
		if prev, exists := h.fields[f]; exists {
			delete(h.fields, f)
			dec := 32 + int64(len(f)) + int64(len(prev))
			h.bytes -= dec
			s.usedBytes.Add(-dec)
			removed++
		}
	}
	if len(h.fields) == 0 {
		delete(sh.hashes, key)
		s.usedBytes.Add(-h.bytes)
	}
	if removed > 0 {
		s.nextMutationSeq()
	}
	return removed, nil
}

// HGetAll returns a deep-copied map of all fields and values in the hash at
// key. Missing or expired keys return an empty non-nil map.
//
// # Parameters
//
//   - key: Hash key name.
//
// # Returns
//
// Caller-owned map of field -> value copies, or ErrWrongType if key holds a
// string.
//
// # Example
//
//	all, err := store.HGetAll("concert:bans:state")
//	_, _ = all, err
func (s *Store) HGetAll(key string) (map[string][]byte, error) {
	sh, _ := s.shardFor(key)
	now := s.now()
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if e, ok := sh.strings[key]; ok {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			delete(sh.strings, key)
			s.usedBytes.Add(-e.bytes)
		} else {
			return nil, ErrWrongType
		}
	}
	h, ok := sh.hashes[key]
	if !ok {
		return map[string][]byte{}, nil
	}
	if !h.expiresAt.IsZero() && !now.Before(h.expiresAt) {
		delete(sh.hashes, key)
		s.usedBytes.Add(-h.bytes)
		return map[string][]byte{}, nil
	}
	out := make(map[string][]byte, len(h.fields))
	for f, v := range h.fields {
		out[f] = bytes.Clone(v)
	}
	return out, nil
}

// Subscribe creates a bounded Subscription attached to channels. Callers must
// call sub.Close() to release resources.
//
// # Parameters
//
//   - channels: Initial channel names to subscribe to.
//
// # Returns
//
// A *Subscription with bounded Messages() channel, or ErrMaxSubscribers when
// MaxSubscribers is reached.
//
// # Example
//
//	sub, err := store.Subscribe("concert:bans:events")
//	if err != nil {
//	    return err
//	}
//	defer sub.Close()
func (s *Store) Subscribe(channels ...string) (*Subscription, error) {
	if s.subCount.Add(1) > int64(s.cfg.MaxSubscribers) {
		s.subCount.Add(-1)
		return nil, ErrMaxSubscribers
	}
	sub := &Subscription{
		id:       s.nextSubID.Add(1),
		store:    s,
		ch:       make(chan PubSubMessage, s.cfg.PubSubBuffer),
		evicted:  make(chan struct{}),
		channels: make(map[string]struct{}, len(channels)),
	}
	s.AddChannels(sub, channels...)
	return sub, nil
}

// AddChannels attaches an existing Subscription to additional channels and
// returns its updated total channel count.
//
// # Parameters
//
//   - sub: Existing open Subscription; must be non-nil.
//   - channels: Channel names to add.
//
// # Returns
//
// Current number of subscribed channels on sub.
//
// # Example
//
//	n := store.AddChannels(sub, "ch1", "ch2")
//	_ = n
func (s *Store) AddChannels(sub *Subscription, channels ...string) int {
	sub.mu.Lock()
	if sub.closed {
		sub.mu.Unlock()
		return 0
	}
	toAdd := make([]string, 0, len(channels))
	for _, ch := range channels {
		if _, exists := sub.channels[ch]; !exists {
			sub.channels[ch] = struct{}{}
			toAdd = append(toAdd, ch)
		}
	}
	count := len(sub.channels)
	sub.mu.Unlock()

	if len(toAdd) > 0 {
		s.pubMu.Lock()
		for _, ch := range toAdd {
			m := s.pubSubs[ch]
			if m == nil {
				m = make(map[uint64]*Subscription)
				s.pubSubs[ch] = m
			}
			m[sub.id] = sub
		}
		s.pubMu.Unlock()
	}
	return count
}

// unsubscribe detaches sub from channels (or all channels when empty) and
// returns the remaining subscribed channel count.
//
// # Parameters
//
//   - sub: Target Subscription.
//   - channels: Channel names to remove, or none to remove all.
//
// # Returns
//
// Remaining subscribed channel count.
//
// # Example
//
//	rem := s.unsubscribe(sub, "events")
func (s *Store) unsubscribe(sub *Subscription, channels ...string) int {
	sub.mu.Lock()
	var toRemove []string
	if len(channels) == 0 {
		toRemove = make([]string, 0, len(sub.channels))
		for ch := range sub.channels {
			toRemove = append(toRemove, ch)
			delete(sub.channels, ch)
		}
	} else {
		for _, ch := range channels {
			if _, ok := sub.channels[ch]; ok {
				delete(sub.channels, ch)
				toRemove = append(toRemove, ch)
			}
		}
	}
	rem := len(sub.channels)
	sub.mu.Unlock()

	if len(toRemove) > 0 {
		s.pubMu.Lock()
		for _, ch := range toRemove {
			if m := s.pubSubs[ch]; m != nil {
				delete(m, sub.id)
				if len(m) == 0 {
					delete(s.pubSubs, ch)
				}
			}
		}
		s.pubMu.Unlock()
	}
	return rem
}

// closeSubscription removes sub from every channel, closes its channels, and
// updates subscriber/eviction counters exactly once.
//
// # Parameters
//
//   - sub: Subscription to shut down.
//   - evicted: True when called because sub breached SlowConsumerLimit.
//
// # Returns
//
// None.
//
// # Example
//
//	s.closeSubscription(sub, true)
func (s *Store) closeSubscription(sub *Subscription, evicted bool) {
	s.unsubscribe(sub)
	if sub.closeChannels(evicted) {
		s.subCount.Add(-1)
		if evicted {
			s.pubEvicted.Add(1)
		}
	}
}

// Publish delivers a copy of payload to all subscribers of channel without
// blocking. Slow consumers whose bounded buffers are full increment the drop
// counter and are evicted once SlowConsumerLimit consecutive drops occur.
//
// # Parameters
//
//   - channel: Pub/Sub channel name.
//   - payload: Message bytes; cloned once before delivery.
//
// # Returns
//
// Number of subscribers that accepted the message into their buffer.
//
// # Example
//
//	delivered := store.Publish("concert:bans:events", []byte(`{"action":"ban"}`))
//	_ = delivered
func (s *Store) Publish(channel string, payload []byte) int64 {
	s.pubMu.RLock()
	m := s.pubSubs[channel]
	if len(m) == 0 {
		s.pubMu.RUnlock()
		return 0
	}
	targets := make([]*Subscription, 0, len(m))
	for _, sub := range m {
		targets = append(targets, sub)
	}
	s.pubMu.RUnlock()

	// Clone payload once; subscribers receive independent copies so no
	// subscriber can mutate bytes observed by another subscriber (C3).
	var delivered int64
	var toEvict []*Subscription
	for _, sub := range targets {
		msg := PubSubMessage{Channel: channel, Payload: bytes.Clone(payload)}
		ok, evict := sub.trySend(msg, s.cfg.SlowConsumerLimit)
		if ok {
			delivered++
		} else {
			s.pubDropped.Add(1)
			if evict {
				toEvict = append(toEvict, sub)
			}
		}
	}
	for _, sub := range toEvict {
		s.closeSubscription(sub, true)
	}
	s.pubSent.Add(delivered)
	return delivered
}

// ─── Native Atomic Concert Queue & Auction Commands (CQ.*) ──────────────────

// CQJoin atomically inserts or refreshes ticket in queue for clientKey with an
// optional TTL and auction bid. Re-joining an existing waiting ticket keeps
// its original FIFO sequence number, refreshes its expiration, and retains
// max(existingBid, bid).
//
// # Parameters
//
//   - queue: Waiting-room queue name (e.g. "shop-drop-1").
//   - ticket: Unique ticket/session identifier.
//   - clientKey: Client/IP/session owner key used for ban purges.
//   - ttl: Expiration duration; zero uses DefaultQueueTicketTTL.
//   - bid: Non-negative agent auction bid amount.
//
// # Returns
//
// CQJoinResult containing 1-based Position, active Depth, and assigned Seq,
// or an error on invalid arguments or capacity limits.
//
// # Example
//
//	res, err := store.CQJoin("drop-1", "tkt-42", "203.0.113.10", 2*time.Minute, 100)
//	if err != nil {
//	    return err
//	}
//	fmt.Println(res.Position, res.Depth)
func (s *Store) CQJoin(queue, ticket, clientKey string, ttl time.Duration, bid int64) (CQJoinResult, error) {
	if ttl < 0 {
		return CQJoinResult{}, fmt.Errorf("%w: TTL must be non-negative", ErrInvalidArg)
	}
	if ttl == 0 {
		ttl = DefaultQueueTicketTTL
	}
	return s.cqJoinAt(queue, ticket, clientKey, s.now().Add(ttl), bid)
}

// cqJoinAt executes CQ.JOIN with an explicit expiration timestamp so WAL
// replay and replication produce identical expiration instants.
//
// # Parameters
//
//   - queue: Queue identifier.
//   - ticket: Ticket identifier.
//   - clientKey: Client identifier.
//   - expiresAt: Explicit expiration time.
//   - bid: Non-negative bid value.
//
// # Returns
//
// CQJoinResult or validation/capacity error.
//
// # Example
//
//	res, err := s.cqJoinAt("q", "t1", "c1", time.Now().Add(time.Minute), 0)
func (s *Store) cqJoinAt(queue, ticket, clientKey string, expiresAt time.Time, bid int64) (CQJoinResult, error) {
	if queue == "" || ticket == "" || clientKey == "" {
		return CQJoinResult{}, fmt.Errorf("%w: queue, ticket, and clientKey must be non-empty", ErrInvalidArg)
	}
	if bid < 0 {
		return CQJoinResult{}, fmt.Errorf("%w: bid must be non-negative", ErrInvalidArg)
	}
	sh, idx := s.shardFor("cq:" + queue)
	if err := s.ensureBudget(queueEntryBytes, idx); err != nil {
		return CQJoinResult{}, err
	}

	now := s.now()
	sh.mu.Lock()
	defer sh.mu.Unlock()

	q, exists := sh.queues[queue]
	if !exists {
		if s.queueCount.Add(1) > int64(s.cfg.MaxQueues) {
			s.queueCount.Add(-1)
			return CQJoinResult{}, ErrMaxQueues
		}
		q = &concertQueue{tickets: make(map[string]*queueTicket)}
		sh.queues[queue] = q
	}
	s.reapQueueLocked(q, now)

	t, ok := q.tickets[ticket]
	if ok {
		t.ClientKey = clientKey
		t.ExpiresAt = expiresAt
		if bid > t.Bid {
			t.Bid = bid
		}
	} else {
		if len(q.tickets) >= s.cfg.MaxQueueEntries {
			return CQJoinResult{}, ErrQueueFull
		}
		q.nextSeq++
		t = &queueTicket{
			TicketID:  ticket,
			ClientKey: clientKey,
			Seq:       q.nextSeq,
			JoinedAt:  now,
			ExpiresAt: expiresAt,
			Bid:       bid,
		}
		q.tickets[ticket] = t
		q.totalJoined++
		q.bytes += queueEntryBytes
		s.usedBytes.Add(queueEntryBytes)
	}

	pos, depth := queuePositionLocked(q, t)
	s.nextMutationSeq()
	return CQJoinResult{
		Position: pos,
		Depth:    depth,
		Seq:      t.Seq,
	}, nil
}

// CQPoll checks the state of ticket in queue, optionally extending its TTL
// when extendTTL > 0.
//
// # Parameters
//
//   - queue: Queue name.
//   - ticket: Ticket identifier.
//   - extendTTL: If > 0, refreshes the ticket's expiration to now+extendTTL.
//
// # Returns
//
// CQPollResult with Status ("waiting", "claimed", or "missing"), 1-based
// Position (0 if not waiting), active waiting Depth, current Bid, and
// RemainingMS.
//
// # Example
//
//	res, err := store.CQPoll("drop-1", "tkt-42", 30*time.Second)
//	if err != nil {
//	    return err
//	}
//	fmt.Println(res.Status, res.Position)
func (s *Store) CQPoll(queue, ticket string, extendTTL time.Duration) (CQPollResult, error) {
	if extendTTL < 0 {
		return CQPollResult{}, fmt.Errorf("%w: TTL must be non-negative", ErrInvalidArg)
	}
	var extAt time.Time
	if extendTTL > 0 {
		extAt = s.now().Add(extendTTL)
	}
	return s.cqPollAt(queue, ticket, extAt)
}

// cqPollAt executes CQ.POLL with an optional explicit expiration refresh time.
//
// # Parameters
//
//   - queue: Queue name.
//   - ticket: Ticket identifier.
//   - extendAt: Zero to leave TTL unchanged; non-zero to set ExpiresAt.
//
// # Returns
//
// CQPollResult or validation error.
//
// # Example
//
//	res, err := s.cqPollAt("q", "t1", time.Time{})
func (s *Store) cqPollAt(queue, ticket string, extendAt time.Time) (CQPollResult, error) {
	if queue == "" || ticket == "" {
		return CQPollResult{}, fmt.Errorf("%w: queue and ticket must be non-empty", ErrInvalidArg)
	}
	sh, _ := s.shardFor("cq:" + queue)
	now := s.now()
	sh.mu.Lock()
	defer sh.mu.Unlock()

	q, ok := sh.queues[queue]
	if !ok {
		return CQPollResult{Status: "missing"}, nil
	}
	s.reapQueueLocked(q, now)

	t, exists := q.tickets[ticket]
	if !exists {
		return CQPollResult{Status: "missing", Depth: countWaitingLocked(q)}, nil
	}
	if !extendAt.IsZero() && !t.Claimed {
		t.ExpiresAt = extendAt
		s.nextMutationSeq()
	}
	rem := t.ExpiresAt.Sub(now).Milliseconds()
	if rem < 0 {
		rem = 0
	}
	if t.Claimed {
		return CQPollResult{
			Status:      "claimed",
			Depth:       countWaitingLocked(q),
			Bid:         t.Bid,
			RemainingMS: rem,
		}, nil
	}
	pos, depth := queuePositionLocked(q, t)
	return CQPollResult{
		Status:      "waiting",
		Position:    pos,
		Depth:       depth,
		Bid:         t.Bid,
		RemainingMS: rem,
	}, nil
}

// CQClaim atomically claims up to count highest-priority waiting tickets from
// queue for edgeID. Tickets are ordered by descending auction Bid, then
// ascending FIFO Seq. Claimed tickets remain pollable as "claimed" until
// DefaultClaimRetentionTTL expires.
//
// # Parameters
//
//   - queue: Queue name.
//   - edgeID: Identifier of the Concert edge claiming admission slots.
//   - count: Maximum tickets to claim (<= 0 defaults to 1; capped at 1024).
//
// # Returns
//
// Slice of claimed CQClaimEntry values in claim priority order, or an error.
//
// # Example
//
//	claimed, err := store.CQClaim("drop-1", "edge-us-east-1", 5)
//	if err != nil {
//	    return err
//	}
//	fmt.Println(len(claimed))
func (s *Store) CQClaim(queue, edgeID string, count int) ([]CQClaimEntry, error) {
	if queue == "" || edgeID == "" {
		return nil, fmt.Errorf("%w: queue and edgeID must be non-empty", ErrInvalidArg)
	}
	if count <= 0 {
		count = 1
	}
	if count > 1024 {
		count = 1024
	}
	sh, _ := s.shardFor("cq:" + queue)
	now := s.now()
	sh.mu.Lock()
	defer sh.mu.Unlock()

	q, ok := sh.queues[queue]
	if !ok {
		return []CQClaimEntry{}, nil
	}
	s.reapQueueLocked(q, now)

	waiting := sortedWaitingLocked(q)
	if len(waiting) == 0 {
		return []CQClaimEntry{}, nil
	}
	if count > len(waiting) {
		count = len(waiting)
	}

	claimed := make([]CQClaimEntry, 0, count)
	for i := 0; i < count; i++ {
		t := waiting[i]
		t.Claimed = true
		t.ClaimedBy = edgeID
		t.ClaimedAt = now
		claimExp := now.Add(DefaultClaimRetentionTTL)
		if t.ExpiresAt.After(claimExp) {
			t.ExpiresAt = claimExp
		}
		q.totalClaimed++
		claimed = append(claimed, CQClaimEntry{
			TicketID:  t.TicketID,
			ClientKey: t.ClientKey,
			Bid:       t.Bid,
			Seq:       t.Seq,
		})
	}
	s.nextMutationSeq()
	return claimed, nil
}

// CQBid atomically raises the auction bid for an active waiting ticket in
// queue. Rejects negative bids and bids that do not strictly exceed the
// ticket's current bid.
//
// # Parameters
//
//   - queue: Queue name.
//   - ticket: Waiting ticket identifier.
//   - amount: New bid amount; must be strictly greater than current bid.
//
// # Returns
//
// Updated CQBidResult with recomputed 1-based Position, Depth, and Bid, or an
// error matching ErrInvalidArg, ErrTicketNotFound, or ErrBidTooLow.
//
// # Example
//
//	res, err := store.CQBid("drop-1", "tkt-42", 250)
//	if err != nil {
//	    return err
//	}
//	fmt.Println(res.Position)
func (s *Store) CQBid(queue, ticket string, amount int64) (CQBidResult, error) {
	if queue == "" || ticket == "" || amount < 0 {
		return CQBidResult{}, fmt.Errorf("%w: invalid queue, ticket, or negative bid", ErrInvalidArg)
	}
	sh, _ := s.shardFor("cq:" + queue)
	now := s.now()
	sh.mu.Lock()
	defer sh.mu.Unlock()

	q, ok := sh.queues[queue]
	if !ok {
		return CQBidResult{}, ErrTicketNotFound
	}
	s.reapQueueLocked(q, now)

	t, exists := q.tickets[ticket]
	if !exists || t.Claimed {
		return CQBidResult{}, ErrTicketNotFound
	}
	if amount <= t.Bid {
		return CQBidResult{}, ErrBidTooLow
	}
	t.Bid = amount
	pos, depth := queuePositionLocked(q, t)
	s.nextMutationSeq()
	return CQBidResult{
		Position: pos,
		Depth:    depth,
		Bid:      t.Bid,
	}, nil
}

// CQPurge atomically removes tickets from queue according to mode ("stale" or
// "all") and optional clientKey filter (used when dropping banned clients).
//
// # Parameters
//
//   - queue: Queue name.
//   - mode: "stale" (default when empty) removes expired tickets; "all" removes
//     all tickets in queue. Ignored when clientKey is non-empty.
//   - clientKey: When non-empty, removes only tickets owned by clientKey.
//
// # Returns
//
// Count of purged tickets, or ErrInvalidArg if mode is unknown.
//
// # Example
//
//	purged, err := store.CQPurge("drop-1", "stale", "")
//	_, _ = purged, err
func (s *Store) CQPurge(queue, mode, clientKey string) (int64, error) {
	if queue == "" {
		return 0, fmt.Errorf("%w: queue must be non-empty", ErrInvalidArg)
	}
	if mode == "" {
		mode = "stale"
	}
	mode = strings.ToLower(mode)
	if clientKey == "" && mode != "stale" && mode != "all" {
		return 0, fmt.Errorf("%w: mode must be stale or all", ErrInvalidArg)
	}
	sh, _ := s.shardFor("cq:" + queue)
	now := s.now()
	sh.mu.Lock()
	defer sh.mu.Unlock()

	q, ok := sh.queues[queue]
	if !ok {
		return 0, nil
	}

	var purged int64
	if clientKey != "" {
		purged += s.reapQueueLocked(q, now)
		for id, t := range q.tickets {
			if t.ClientKey == clientKey {
				delete(q.tickets, id)
				q.bytes -= queueEntryBytes
				s.usedBytes.Add(-queueEntryBytes)
				purged++
			}
		}
	} else if mode == "all" {
		purged = int64(len(q.tickets))
		s.usedBytes.Add(-q.bytes)
		q.bytes = 0
		clear(q.tickets)
	} else {
		purged = s.reapQueueLocked(q, now)
	}

	if purged > 0 {
		q.totalPurged += purged
		s.nextMutationSeq()
	}
	return purged, nil
}

// CQStats returns current waiting/claimed counts, lifetime counters, highest
// active bid, and oldest wait duration for queue.
//
// # Parameters
//
//   - queue: Queue name.
//
// # Returns
//
// CQQueueStats snapshot (zeroed if queue does not exist).
//
// # Example
//
//	st := store.CQStats("drop-1")
//	fmt.Println(st.Waiting, st.HighestBid)
func (s *Store) CQStats(queue string) CQQueueStats {
	sh, _ := s.shardFor("cq:" + queue)
	now := s.now()
	sh.mu.Lock()
	defer sh.mu.Unlock()

	q, ok := sh.queues[queue]
	if !ok {
		return CQQueueStats{}
	}
	s.reapQueueLocked(q, now)

	var stats CQQueueStats
	stats.TotalJoined = q.totalJoined
	stats.TotalClaimed = q.totalClaimed
	stats.TotalPurged = q.totalPurged

	var oldest time.Time
	for _, t := range q.tickets {
		if t.Claimed {
			stats.Claimed++
			continue
		}
		stats.Waiting++
		if t.Bid > stats.HighestBid {
			stats.HighestBid = t.Bid
		}
		if oldest.IsZero() || t.JoinedAt.Before(oldest) {
			oldest = t.JoinedAt
		}
	}
	if !oldest.IsZero() {
		ms := now.Sub(oldest).Milliseconds()
		if ms > 0 {
			stats.OldestWaitMS = ms
		}
	}
	return stats
}

// reapQueueLocked deletes expired tickets in q and updates tracked memory.
// Caller must hold the owning shard's mu.
//
// # Parameters
//
//   - q: Queue to reap.
//   - now: Reference instant.
//
// # Returns
//
// Number of expired tickets removed.
//
// # Example
//
//	removed := s.reapQueueLocked(q, now)
func (s *Store) reapQueueLocked(q *concertQueue, now time.Time) int64 {
	var removed int64
	for id, t := range q.tickets {
		if !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt) {
			delete(q.tickets, id)
			q.bytes -= queueEntryBytes
			s.usedBytes.Add(-queueEntryBytes)
			removed++
		}
	}
	return removed
}

// countWaitingLocked counts active unclaimed tickets in q. Caller holds sh.mu.
//
// # Parameters
//
//   - q: Queue to count.
//
// # Returns
//
// Number of waiting (unclaimed) tickets.
//
// # Example
//
//	depth := countWaitingLocked(q)
func countWaitingLocked(q *concertQueue) int64 {
	var n int64
	for _, t := range q.tickets {
		if !t.Claimed {
			n++
		}
	}
	return n
}

// queuePositionLocked computes the 1-based position of target among waiting
// tickets in q (higher Bid ranks ahead; equal Bid breaks ties by lower Seq)
// along with total waiting depth. Caller holds sh.mu.
//
// # Parameters
//
//   - q: Queue containing target.
//   - target: Waiting ticket whose position is computed.
//
// # Returns
//
// (position, depth). If target is claimed, position is 0.
//
// # Example
//
//	pos, depth := queuePositionLocked(q, ticket)
func queuePositionLocked(q *concertQueue, target *queueTicket) (int64, int64) {
	var ahead, depth int64
	for _, t := range q.tickets {
		if t.Claimed {
			continue
		}
		depth++
		if t.TicketID == target.TicketID {
			continue
		}
		if t.Bid > target.Bid || (t.Bid == target.Bid && t.Seq < target.Seq) {
			ahead++
		}
	}
	if target.Claimed {
		return 0, depth
	}
	return ahead + 1, depth
}

// sortedWaitingLocked returns all unclaimed tickets in q ordered by descending
// Bid and ascending Seq. Caller holds sh.mu.
//
// # Parameters
//
//   - q: Queue to inspect.
//
// # Returns
//
// Sorted slice of waiting *queueTicket pointers.
//
// # Example
//
//	ordered := sortedWaitingLocked(q)
func sortedWaitingLocked(q *concertQueue) []*queueTicket {
	out := make([]*queueTicket, 0, len(q.tickets))
	for _, t := range q.tickets {
		if !t.Claimed {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bid != out[j].Bid {
			return out[i].Bid > out[j].Bid
		}
		return out[i].Seq < out[j].Seq
	})
	return out
}

// Stats returns a point-in-time StoreStats snapshot across all shards.
//
// # Parameters
//
// None.
//
// # Returns
//
// Aggregated StoreStats counters.
//
// # Example
//
//	st := store.Stats()
//	fmt.Println(st.Keys, st.UsedMemoryBytes)
func (s *Store) Stats() StoreStats {
	var keys, hashes, queues int64
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		keys += int64(len(sh.strings))
		hashes += int64(len(sh.hashes))
		queues += int64(len(sh.queues))
		sh.mu.Unlock()
	}
	s.pubMu.RLock()
	chCount := int64(len(s.pubSubs))
	s.pubMu.RUnlock()

	return StoreStats{
		Keys:              keys,
		Hashes:            hashes,
		Queues:            queues,
		UsedMemoryBytes:   s.usedBytes.Load(),
		MaxMemoryBytes:    s.cfg.MaxMemoryBytes,
		Evictions:         s.evictions.Load(),
		Mutations:         s.mutations.Load(),
		Commands:          s.commands.Load(),
		PubSubChannels:    chCount,
		PubSubSubscribers: s.subCount.Load(),
		PubSubPublished:   s.pubSent.Load(),
		PubSubDropped:     s.pubDropped.Load(),
		PubSubEvicted:     s.pubEvicted.Load(),
	}
}

// InfoText formats StoreStats in Redis-compatible INFO key:value lines.
//
// # Parameters
//
// None.
//
// # Returns
//
// Multi-line CRLF-delimited INFO string.
//
// # Example
//
//	fmt.Println(store.InfoText())
func (s *Store) InfoText() string {
	st := s.Stats()
	var b strings.Builder
	b.WriteString("# Server\r\n")
	b.WriteString("engine:concert-kv\r\n")
	b.WriteString("# Keyspace\r\n")
	fmt.Fprintf(&b, "keys:%d\r\n", st.Keys)
	fmt.Fprintf(&b, "hashes:%d\r\n", st.Hashes)
	fmt.Fprintf(&b, "queues:%d\r\n", st.Queues)
	b.WriteString("# Memory\r\n")
	fmt.Fprintf(&b, "used_memory:%d\r\n", st.UsedMemoryBytes)
	fmt.Fprintf(&b, "maxmemory:%d\r\n", st.MaxMemoryBytes)
	fmt.Fprintf(&b, "evicted_keys:%d\r\n", st.Evictions)
	b.WriteString("# Stats\r\n")
	fmt.Fprintf(&b, "total_commands_processed:%d\r\n", st.Commands)
	fmt.Fprintf(&b, "mutation_seq:%d\r\n", st.Mutations)
	b.WriteString("# Pubsub\r\n")
	fmt.Fprintf(&b, "pubsub_channels:%d\r\n", st.PubSubChannels)
	fmt.Fprintf(&b, "pubsub_subscribers:%d\r\n", st.PubSubSubscribers)
	fmt.Fprintf(&b, "pubsub_published:%d\r\n", st.PubSubPublished)
	fmt.Fprintf(&b, "pubsub_dropped:%d\r\n", st.PubSubDropped)
	fmt.Fprintf(&b, "pubsub_evicted:%d\r\n", st.PubSubEvicted)
	return b.String()
}

// ─── Command Dispatch (shared by Server, WAL Replay, and Replica Sync) ──────

// Execute dispatches one parsed RESP2 command against s. It returns the RESP2
// reply Value and, when the command mutated store state, canonical replication
// and WAL command arguments (walArgs) plus the committed mutation sequence.
// Connection-level commands (AUTH, SUBSCRIBE, UNSUBSCRIBE, SYNC, REPL, QUIT)
// are handled by Server before calling Execute.
//
// # Parameters
//
//   - args: Non-empty command tokens (case-insensitive command name at args[0]).
//
// # Returns
//
// (reply, walArgs, seq). Errors are returned as RESP2 KindError values inside
// reply so callers can write reply directly to the wire.
//
// # Example
//
//	reply, walArgs, seq := store.Execute([]string{"SET", "k", "v", "EX", "60"})
//	_, _, _ = reply, walArgs, seq
func (s *Store) Execute(args []string) (reply Value, walArgs []string, seq uint64) {
	s.commands.Add(1)
	if len(args) == 0 {
		return ErrorValue("ERR empty command"), nil, 0
	}
	cmd := strings.ToUpper(args[0])
	switch cmd {
	case "PING":
		if len(args) == 1 {
			return SimpleString("PONG"), nil, 0
		}
		if len(args) == 2 {
			return BulkFromString(args[1]), nil, 0
		}
		return ErrorValue("ERR wrong number of arguments for 'PING' command"), nil, 0

	case "INFO":
		return BulkFromString(s.InfoText()), nil, 0

	case "GET":
		if len(args) != 2 {
			return ErrorValue("ERR wrong number of arguments for 'GET' command"), nil, 0
		}
		val, ok := s.Get(args[1])
		if !ok {
			return NullBulk(), nil, 0
		}
		return BulkString(val), nil, 0

	case "SET":
		return s.execSet(args)

	case "DEL":
		if len(args) < 2 {
			return ErrorValue("ERR wrong number of arguments for 'DEL' command"), nil, 0
		}
		n := s.Del(args[1:]...)
		if n > 0 {
			return Integer(n), append([]string{"DEL"}, args[1:]...), s.MutationSeq()
		}
		return Integer(0), nil, 0

	case "EXISTS":
		if len(args) < 2 {
			return ErrorValue("ERR wrong number of arguments for 'EXISTS' command"), nil, 0
		}
		return Integer(s.Exists(args[1:]...)), nil, 0

	case "INCRBY":
		if len(args) != 3 {
			return ErrorValue("ERR wrong number of arguments for 'INCRBY' command"), nil, 0
		}
		delta, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil {
			return ErrorValue(ErrNotInteger.Error()), nil, 0
		}
		n, err := s.IncrBy(args[1], delta)
		if err != nil {
			return ErrorValue(err.Error()), nil, 0
		}
		return Integer(n), []string{"INCRBY", args[1], strconv.FormatInt(delta, 10)}, s.MutationSeq()

	case "EXPIRE":
		if len(args) != 3 {
			return ErrorValue("ERR wrong number of arguments for 'EXPIRE' command"), nil, 0
		}
		secs, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil {
			return ErrorValue(ErrNotInteger.Error()), nil, 0
		}
		at := s.now().Add(time.Duration(secs) * time.Second)
		if !s.ExpireAt(args[1], at) {
			return Integer(0), nil, 0
		}
		return Integer(1), []string{"PEXPIREAT", args[1], strconv.FormatInt(at.UnixMilli(), 10)}, s.MutationSeq()

	case "PEXPIREAT":
		if len(args) != 3 {
			return ErrorValue("ERR wrong number of arguments for 'PEXPIREAT' command"), nil, 0
		}
		ms, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil {
			return ErrorValue(ErrNotInteger.Error()), nil, 0
		}
		if !s.ExpireAt(args[1], time.UnixMilli(ms)) {
			return Integer(0), nil, 0
		}
		return Integer(1), []string{"PEXPIREAT", args[1], args[2]}, s.MutationSeq()

	case "TTL":
		if len(args) != 2 {
			return ErrorValue("ERR wrong number of arguments for 'TTL' command"), nil, 0
		}
		return Integer(s.TTL(args[1])), nil, 0

	case "HSET":
		if len(args) < 4 || (len(args)-2)%2 != 0 {
			return ErrorValue("ERR wrong number of arguments for 'HSET' command"), nil, 0
		}
		fields := make(map[string][]byte, (len(args)-2)/2)
		for i := 2; i < len(args); i += 2 {
			fields[args[i]] = []byte(args[i+1])
		}
		n, err := s.HSet(args[1], fields)
		if err != nil {
			return ErrorValue(err.Error()), nil, 0
		}
		wal := make([]string, len(args))
		wal[0] = "HSET"
		copy(wal[1:], args[1:])
		return Integer(n), wal, s.MutationSeq()

	case "HGET":
		if len(args) != 3 {
			return ErrorValue("ERR wrong number of arguments for 'HGET' command"), nil, 0
		}
		val, ok, err := s.HGet(args[1], args[2])
		if err != nil {
			return ErrorValue(err.Error()), nil, 0
		}
		if !ok {
			return NullBulk(), nil, 0
		}
		return BulkString(val), nil, 0

	case "HDEL":
		if len(args) < 3 {
			return ErrorValue("ERR wrong number of arguments for 'HDEL' command"), nil, 0
		}
		n, err := s.HDel(args[1], args[2:]...)
		if err != nil {
			return ErrorValue(err.Error()), nil, 0
		}
		if n > 0 {
			wal := make([]string, len(args))
			wal[0] = "HDEL"
			copy(wal[1:], args[1:])
			return Integer(n), wal, s.MutationSeq()
		}
		return Integer(0), nil, 0

	case "HGETALL":
		if len(args) != 2 {
			return ErrorValue("ERR wrong number of arguments for 'HGETALL' command"), nil, 0
		}
		all, err := s.HGetAll(args[1])
		if err != nil {
			return ErrorValue(err.Error()), nil, 0
		}
		keys := make([]string, 0, len(all))
		for k := range all {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		elems := make([]Value, 0, len(keys)*2)
		for _, k := range keys {
			elems = append(elems, BulkFromString(k), BulkString(all[k]))
		}
		return ArrayValue(elems...), nil, 0

	case "PUBLISH":
		if len(args) != 3 {
			return ErrorValue("ERR wrong number of arguments for 'PUBLISH' command"), nil, 0
		}
		n := s.Publish(args[1], []byte(args[2]))
		return Integer(n), nil, 0

	case "CQ.JOIN":
		return s.execCQJoin(args)
	case "CQ.POLL":
		return s.execCQPoll(args)
	case "CQ.CLAIM":
		return s.execCQClaim(args)
	case "CQ.BID":
		return s.execCQBid(args)
	case "CQ.PURGE":
		return s.execCQPurge(args)
	case "CQ.STATS":
		return s.execCQStats(args)

	default:
		return ErrorValue(fmt.Sprintf("ERR unknown command '%s'", args[0])), nil, 0
	}
}

// execSet parses and executes a SET command with EX, PX, PXAT, NX, and XX
// options.
//
// # Parameters
//
//   - args: Full command slice starting with "SET".
//
// # Returns
//
// RESP2 reply, canonical WAL args (converting EX/PX to PXAT for replay
// determinism), and committed mutation seq.
//
// # Example
//
//	reply, wal, seq := s.execSet([]string{"SET", "k", "v", "EX", "30", "NX"})
func (s *Store) execSet(args []string) (Value, []string, uint64) {
	if len(args) < 3 {
		return ErrorValue("ERR wrong number of arguments for 'SET' command"), nil, 0
	}
	var opts SetOptions
	hasExpiry := false
	for i := 3; i < len(args); i++ {
		opt := strings.ToUpper(args[i])
		switch opt {
		case "NX":
			opts.NX = true
		case "XX":
			opts.XX = true
		case "EX":
			if i+1 >= len(args) {
				return ErrorValue("ERR syntax error"), nil, 0
			}
			i++
			secs, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil || secs <= 0 {
				return ErrorValue("ERR invalid expire time in 'SET' command"), nil, 0
			}
			opts.ExpiresAt = s.now().Add(time.Duration(secs) * time.Second)
			hasExpiry = true
		case "PX":
			if i+1 >= len(args) {
				return ErrorValue("ERR syntax error"), nil, 0
			}
			i++
			ms, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil || ms <= 0 {
				return ErrorValue("ERR invalid expire time in 'SET' command"), nil, 0
			}
			opts.ExpiresAt = s.now().Add(time.Duration(ms) * time.Millisecond)
			hasExpiry = true
		case "PXAT":
			if i+1 >= len(args) {
				return ErrorValue("ERR syntax error"), nil, 0
			}
			i++
			ms, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil {
				return ErrorValue("ERR invalid expire time in 'SET' command"), nil, 0
			}
			opts.ExpiresAt = time.UnixMilli(ms)
			hasExpiry = true
		default:
			return ErrorValue("ERR syntax error"), nil, 0
		}
	}
	ok, err := s.Set(args[1], []byte(args[2]), opts)
	if err != nil {
		return ErrorValue(err.Error()), nil, 0
	}
	if !ok {
		return NullBulk(), nil, 0
	}
	wal := []string{"SET", args[1], args[2]}
	if hasExpiry {
		wal = append(wal, "PXAT", strconv.FormatInt(opts.ExpiresAt.UnixMilli(), 10))
	}
	return SimpleString("OK"), wal, s.MutationSeq()
}

// execCQJoin parses and executes CQ.JOIN <queue> <ticket> <clientKey>
// [TTL <ms> | EXPIRESAT <unixMs>] [BID <amount>].
//
// # Parameters
//
//   - args: Full command slice starting with "CQ.JOIN".
//
// # Returns
//
// RESP2 array [position, depth, seq], canonical WAL args, and mutation seq.
//
// # Example
//
//	reply, wal, seq := s.execCQJoin([]string{"CQ.JOIN", "q1", "t1", "c1", "TTL", "60000", "BID", "50"})
func (s *Store) execCQJoin(args []string) (Value, []string, uint64) {
	if len(args) < 4 {
		return ErrorValue("ERR wrong number of arguments for 'CQ.JOIN' command"), nil, 0
	}
	exp := s.now().Add(DefaultQueueTicketTTL)
	var bid int64
	for i := 4; i < len(args); i++ {
		opt := strings.ToUpper(args[i])
		if i+1 >= len(args) {
			return ErrorValue("ERR syntax error"), nil, 0
		}
		i++
		switch opt {
		case "TTL":
			ms, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil || ms <= 0 {
				return ErrorValue("ERR invalid TTL in 'CQ.JOIN'"), nil, 0
			}
			exp = s.now().Add(time.Duration(ms) * time.Millisecond)
		case "EXPIRESAT":
			ms, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil {
				return ErrorValue("ERR invalid EXPIRESAT in 'CQ.JOIN'"), nil, 0
			}
			exp = time.UnixMilli(ms)
		case "BID":
			v, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil || v < 0 {
				return ErrorValue("ERR invalid BID in 'CQ.JOIN'"), nil, 0
			}
			bid = v
		default:
			return ErrorValue("ERR syntax error"), nil, 0
		}
	}
	res, err := s.cqJoinAt(args[1], args[2], args[3], exp, bid)
	if err != nil {
		return ErrorValue(err.Error()), nil, 0
	}
	wal := []string{
		"CQ.JOIN", args[1], args[2], args[3],
		"EXPIRESAT", strconv.FormatInt(exp.UnixMilli(), 10),
		"BID", strconv.FormatInt(bid, 10),
	}
	return ArrayValue(
		Integer(res.Position),
		Integer(res.Depth),
		Integer(int64(res.Seq)),
	), wal, s.MutationSeq()
}

// execCQPoll parses and executes CQ.POLL <queue> <ticket> [TTL <ms> |
// EXPIRESAT <unixMs>].
//
// # Parameters
//
//   - args: Full command slice starting with "CQ.POLL".
//
// # Returns
//
// RESP2 array [status, position, depth, bid, remaining_ms], optional WAL args
// if TTL was extended, and mutation seq.
//
// # Example
//
//	reply, wal, seq := s.execCQPoll([]string{"CQ.POLL", "q1", "t1"})
func (s *Store) execCQPoll(args []string) (Value, []string, uint64) {
	if len(args) != 3 && len(args) != 5 {
		return ErrorValue("ERR wrong number of arguments for 'CQ.POLL' command"), nil, 0
	}
	var exp time.Time
	if len(args) == 5 {
		switch strings.ToUpper(args[3]) {
		case "TTL":
			ms, err := strconv.ParseInt(args[4], 10, 64)
			if err != nil || ms <= 0 {
				return ErrorValue("ERR invalid TTL in 'CQ.POLL'"), nil, 0
			}
			exp = s.now().Add(time.Duration(ms) * time.Millisecond)
		case "EXPIRESAT":
			ms, err := strconv.ParseInt(args[4], 10, 64)
			if err != nil {
				return ErrorValue("ERR invalid EXPIRESAT in 'CQ.POLL'"), nil, 0
			}
			exp = time.UnixMilli(ms)
		default:
			return ErrorValue("ERR syntax error"), nil, 0
		}
	}
	res, err := s.cqPollAt(args[1], args[2], exp)
	if err != nil {
		return ErrorValue(err.Error()), nil, 0
	}
	var wal []string
	var seq uint64
	if !exp.IsZero() && res.Status == "waiting" {
		wal = []string{"CQ.POLL", args[1], args[2], "EXPIRESAT", strconv.FormatInt(exp.UnixMilli(), 10)}
		seq = s.MutationSeq()
	}
	return ArrayValue(
		BulkFromString(res.Status),
		Integer(res.Position),
		Integer(res.Depth),
		Integer(res.Bid),
		Integer(res.RemainingMS),
	), wal, seq
}

// execCQClaim parses and executes CQ.CLAIM <queue> <edgeID> [COUNT <n>].
//
// # Parameters
//
//   - args: Full command slice starting with "CQ.CLAIM".
//
// # Returns
//
// RESP2 array of [ticketID, clientKey, bid, seq] arrays, canonical WAL args if
// any ticket was claimed, and mutation seq.
//
// # Example
//
//	reply, wal, seq := s.execCQClaim([]string{"CQ.CLAIM", "q1", "edge-1", "COUNT", "2"})
func (s *Store) execCQClaim(args []string) (Value, []string, uint64) {
	if len(args) != 3 && len(args) != 5 {
		return ErrorValue("ERR wrong number of arguments for 'CQ.CLAIM' command"), nil, 0
	}
	count := 1
	if len(args) == 5 {
		if strings.ToUpper(args[3]) != "COUNT" {
			return ErrorValue("ERR syntax error"), nil, 0
		}
		n, err := strconv.Atoi(args[4])
		if err != nil || n <= 0 {
			return ErrorValue("ERR invalid COUNT in 'CQ.CLAIM'"), nil, 0
		}
		count = n
	}
	claimed, err := s.CQClaim(args[1], args[2], count)
	if err != nil {
		return ErrorValue(err.Error()), nil, 0
	}
	elems := make([]Value, len(claimed))
	for i, c := range claimed {
		elems[i] = ArrayValue(
			BulkFromString(c.TicketID),
			BulkFromString(c.ClientKey),
			Integer(c.Bid),
			Integer(int64(c.Seq)),
		)
	}
	if len(claimed) == 0 {
		return ArrayValue(elems...), nil, 0
	}
	wal := []string{"CQ.CLAIM", args[1], args[2], "COUNT", strconv.Itoa(count)}
	return ArrayValue(elems...), wal, s.MutationSeq()
}

// execCQBid parses and executes CQ.BID <queue> <ticket> <amount>.
//
// # Parameters
//
//   - args: Full command slice starting with "CQ.BID".
//
// # Returns
//
// RESP2 array [position, depth, bid], canonical WAL args, and mutation seq.
//
// # Example
//
//	reply, wal, seq := s.execCQBid([]string{"CQ.BID", "q1", "t1", "500"})
func (s *Store) execCQBid(args []string) (Value, []string, uint64) {
	if len(args) != 4 {
		return ErrorValue("ERR wrong number of arguments for 'CQ.BID' command"), nil, 0
	}
	amount, err := strconv.ParseInt(args[3], 10, 64)
	if err != nil || amount < 0 {
		return ErrorValue("ERR invalid bid amount"), nil, 0
	}
	res, err := s.CQBid(args[1], args[2], amount)
	if err != nil {
		return ErrorValue(err.Error()), nil, 0
	}
	wal := []string{"CQ.BID", args[1], args[2], strconv.FormatInt(amount, 10)}
	return ArrayValue(
		Integer(res.Position),
		Integer(res.Depth),
		Integer(res.Bid),
	), wal, s.MutationSeq()
}

// execCQPurge parses and executes CQ.PURGE <queue> [MODE stale|all]
// [CLIENT <clientKey>].
//
// # Parameters
//
//   - args: Full command slice starting with "CQ.PURGE".
//
// # Returns
//
// RESP2 integer purged count, canonical WAL args if >0 purged, and seq.
//
// # Example
//
//	reply, wal, seq := s.execCQPurge([]string{"CQ.PURGE", "q1", "MODE", "stale"})
func (s *Store) execCQPurge(args []string) (Value, []string, uint64) {
	if len(args) < 2 {
		return ErrorValue("ERR wrong number of arguments for 'CQ.PURGE' command"), nil, 0
	}
	mode := "stale"
	var clientKey string
	for i := 2; i < len(args); i++ {
		if i+1 >= len(args) {
			return ErrorValue("ERR syntax error"), nil, 0
		}
		opt := strings.ToUpper(args[i])
		i++
		switch opt {
		case "MODE":
			mode = args[i]
		case "CLIENT":
			clientKey = args[i]
		default:
			return ErrorValue("ERR syntax error"), nil, 0
		}
	}
	n, err := s.CQPurge(args[1], mode, clientKey)
	if err != nil {
		return ErrorValue(err.Error()), nil, 0
	}
	if n == 0 {
		return Integer(0), nil, 0
	}
	wal := []string{"CQ.PURGE", args[1], "MODE", mode}
	if clientKey != "" {
		wal = append(wal, "CLIENT", clientKey)
	}
	return Integer(n), wal, s.MutationSeq()
}

// execCQStats parses and executes CQ.STATS <queue>.
//
// # Parameters
//
//   - args: Full command slice starting with "CQ.STATS".
//
// # Returns
//
// RESP2 flat key/value array of queue statistics.
//
// # Example
//
//	reply, _, _ := s.execCQStats([]string{"CQ.STATS", "q1"})
func (s *Store) execCQStats(args []string) (Value, []string, uint64) {
	if len(args) != 2 {
		return ErrorValue("ERR wrong number of arguments for 'CQ.STATS' command"), nil, 0
	}
	st := s.CQStats(args[1])
	return ArrayValue(
		BulkFromString("waiting"), Integer(st.Waiting),
		BulkFromString("claimed"), Integer(st.Claimed),
		BulkFromString("total_joined"), Integer(st.TotalJoined),
		BulkFromString("total_claimed"), Integer(st.TotalClaimed),
		BulkFromString("total_purged"), Integer(st.TotalPurged),
		BulkFromString("highest_bid"), Integer(st.HighestBid),
		BulkFromString("oldest_wait_ms"), Integer(st.OldestWaitMS),
	), nil, 0
}

// ─── Snapshot Export / Restore (WAL Compaction & Replica Catch-Up) ──────────

// SnapshotString serializes a single KV entry inside a store snapshot.
type SnapshotString struct {
	Value     []byte `json:"v"`
	ExpiresNS int64  `json:"exp,omitempty"`
}

// SnapshotHash serializes a single hash entry inside a store snapshot.
type SnapshotHash struct {
	Fields    map[string][]byte `json:"f"`
	ExpiresNS int64             `json:"exp,omitempty"`
}

// SnapshotQueue serializes a single Concert queue inside a store snapshot.
type SnapshotQueue struct {
	NextSeq      uint64        `json:"next_seq"`
	TotalJoined  int64         `json:"total_joined"`
	TotalClaimed int64         `json:"total_claimed"`
	TotalPurged  int64         `json:"total_purged"`
	Tickets      []queueTicket `json:"tickets"`
}

// SnapshotData represents a consistent point-in-time dump of Store state.
type SnapshotData struct {
	Version int                       `json:"version"`
	Seq     uint64                    `json:"seq"`
	Strings map[string]SnapshotString `json:"strings,omitempty"`
	Hashes  map[string]SnapshotHash   `json:"hashes,omitempty"`
	Queues  map[string]SnapshotQueue  `json:"queues,omitempty"`
}

// Snapshot exports a consistent point-in-time copy of all non-expired keys,
// hashes, and Concert queues. Locks shards in strictly ascending index order
// (0..63) to remain deadlock-free with single-shard callers (C4).
//
// # Parameters
//
// None.
//
// # Returns
//
// A self-contained SnapshotData safe to serialize without holding store locks.
//
// # Example
//
//	snap := store.Snapshot()
//	fmt.Println(snap.Seq, len(snap.Strings))
func (s *Store) Snapshot() SnapshotData {
	now := s.now()
	for i := range s.shards {
		s.shards[i].mu.Lock()
	}
	defer func() {
		for i := numShards - 1; i >= 0; i-- {
			s.shards[i].mu.Unlock()
		}
	}()

	snap := SnapshotData{
		Version: 1,
		Seq:     s.mutations.Load(),
		Strings: make(map[string]SnapshotString),
		Hashes:  make(map[string]SnapshotHash),
		Queues:  make(map[string]SnapshotQueue),
	}
	for i := range s.shards {
		sh := &s.shards[i]
		s.reapShardExpiredLocked(sh, now)
		for k, e := range sh.strings {
			var exp int64
			if !e.expiresAt.IsZero() {
				exp = e.expiresAt.UnixNano()
			}
			snap.Strings[k] = SnapshotString{
				Value:     bytes.Clone(e.val),
				ExpiresNS: exp,
			}
		}
		for k, h := range sh.hashes {
			var exp int64
			if !h.expiresAt.IsZero() {
				exp = h.expiresAt.UnixNano()
			}
			fields := make(map[string][]byte, len(h.fields))
			for fk, fv := range h.fields {
				fields[fk] = bytes.Clone(fv)
			}
			snap.Hashes[k] = SnapshotHash{
				Fields:    fields,
				ExpiresNS: exp,
			}
		}
		for qname, q := range sh.queues {
			s.reapQueueLocked(q, now)
			tickets := make([]queueTicket, 0, len(q.tickets))
			for _, t := range q.tickets {
				tickets = append(tickets, *t)
			}
			snap.Queues[qname] = SnapshotQueue{
				NextSeq:      q.nextSeq,
				TotalJoined:  q.totalJoined,
				TotalClaimed: q.totalClaimed,
				TotalPurged:  q.totalPurged,
				Tickets:      tickets,
			}
		}
	}
	return snap
}

// LoadSnapshot replaces all KV, hash, and queue state in s with snap, skipping
// entries already expired at the current store clock. Safe for concurrent use
// (locks shards in strictly ascending index order).
//
// # Parameters
//
//   - snap: Point-in-time SnapshotData obtained from Snapshot or WAL/replication.
//
// # Returns
//
// Error if snap.Version is unsupported.
//
// # Example
//
//	if err := replicaStore.LoadSnapshot(primaryStore.Snapshot()); err != nil {
//	    return err
//	}
func (s *Store) LoadSnapshot(snap SnapshotData) error {
	if snap.Version != 1 {
		return fmt.Errorf("unsupported snapshot version %d", snap.Version)
	}
	now := s.now()
	for i := range s.shards {
		s.shards[i].mu.Lock()
	}
	defer func() {
		for i := numShards - 1; i >= 0; i-- {
			s.shards[i].mu.Unlock()
		}
	}()

	for i := range s.shards {
		clear(s.shards[i].strings)
		clear(s.shards[i].hashes)
		clear(s.shards[i].queues)
	}
	var totalBytes int64
	var totalQueues int64

	for k, se := range snap.Strings {
		var exp time.Time
		if se.ExpiresNS > 0 {
			exp = time.Unix(0, se.ExpiresNS)
			if !now.Before(exp) {
				continue
			}
		}
		cp := bytes.Clone(se.Value)
		if cp == nil {
			cp = []byte{}
		}
		sz := entryOverheadBytes + int64(len(k)) + int64(len(cp))
		sh, _ := s.shardFor(k)
		sh.strings[k] = &kvEntry{
			val:        cp,
			expiresAt:  exp,
			updatedSeq: s.updateClock.Add(1),
			bytes:      sz,
		}
		totalBytes += sz
	}

	for k, shSnap := range snap.Hashes {
		var exp time.Time
		if shSnap.ExpiresNS > 0 {
			exp = time.Unix(0, shSnap.ExpiresNS)
			if !now.Before(exp) {
				continue
			}
		}
		fields := make(map[string][]byte, len(shSnap.Fields))
		sz := entryOverheadBytes + int64(len(k))
		for fk, fv := range shSnap.Fields {
			cp := bytes.Clone(fv)
			if cp == nil {
				cp = []byte{}
			}
			fields[fk] = cp
			sz += 32 + int64(len(fk)) + int64(len(cp))
		}
		if len(fields) == 0 {
			continue
		}
		sh, _ := s.shardFor(k)
		sh.hashes[k] = &hashEntry{
			fields:     fields,
			expiresAt:  exp,
			updatedSeq: s.updateClock.Add(1),
			bytes:      sz,
		}
		totalBytes += sz
	}

	for qname, sq := range snap.Queues {
		sh, _ := s.shardFor("cq:" + qname)
		q := &concertQueue{
			tickets:      make(map[string]*queueTicket, len(sq.Tickets)),
			nextSeq:      sq.NextSeq,
			totalJoined:  sq.TotalJoined,
			totalClaimed: sq.TotalClaimed,
			totalPurged:  sq.TotalPurged,
		}
		for _, t := range sq.Tickets {
			if !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt) {
				continue
			}
			tc := t
			q.tickets[tc.TicketID] = &tc
			q.bytes += queueEntryBytes
			totalBytes += queueEntryBytes
		}
		sh.queues[qname] = q
		totalQueues++
	}

	s.usedBytes.Store(totalBytes)
	s.queueCount.Store(totalQueues)
	s.mutations.Store(snap.Seq)
	return nil
}

// EncodeSnapshot marshals a Store snapshot into JSON bytes.
//
// # Parameters
//
//   - snap: SnapshotData to serialize.
//
// # Returns
//
// JSON byte slice or marshaling error.
//
// # Example
//
//	raw, err := kv.EncodeSnapshot(store.Snapshot())
//	_, _ = raw, err
func EncodeSnapshot(snap SnapshotData) ([]byte, error) {
	return json.Marshal(snap)
}

// DecodeSnapshot unmarshals JSON snapshot bytes into SnapshotData.
//
// # Parameters
//
//   - raw: JSON bytes produced by EncodeSnapshot.
//
// # Returns
//
// Decoded SnapshotData or unmarshaling error.
//
// # Example
//
//	snap, err := kv.DecodeSnapshot(raw)
//	_, _ = snap, err
func DecodeSnapshot(raw []byte) (SnapshotData, error) {
	var snap SnapshotData
	if err := json.Unmarshal(raw, &snap); err != nil {
		return SnapshotData{}, err
	}
	return snap, nil
}
