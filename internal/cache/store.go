package cache

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Capacity and protocol safety limits enforced across Store, Server, and Client.
const (
	DefaultMaxBytes      int64 = 256 << 20 // 256 MiB
	DefaultMaxEntryBytes int64 = 2 << 20   // 2 MiB
	DefaultShards        int   = 64
	MaxShards            int   = 1024
	DefaultTTL                 = 30 * time.Second

	MaxKeyBytes     int = 4 << 10  // 4 KiB
	MaxHostBytes    int = 512      // 512 B
	MaxPathBytes    int = 4 << 10  // 4 KiB
	MaxTagsPerEntry int = 64       // bounded surrogate-tag fanout per entry
	MaxTagBytes     int = 128      // max length of a single normalized tag
	MaxHeaderCount  int = 128      // max distinct header keys per cached entry
	MaxHeaderValues int = 32       // max values per header key
	MaxHeaderBytes  int = 32 << 10 // 32 KiB total serialized headers per entry
	MaxFrameBytes   int = 8 << 20  // 8 MiB hard wire-frame ceiling
)

// Sentinel errors returned by PageCache implementations and wire codecs.
var (
	ErrClosed        = errors.New("cache is closed")
	ErrInvalidKey    = errors.New("invalid cache key")
	ErrEntryTooLarge = errors.New("cache entry exceeds size limit")
	ErrTooManyTags   = errors.New("cache entry exceeds tag limit")
	ErrInvalidTag    = errors.New("invalid cache tag")
	ErrInvalidTTL    = errors.New("cache TTL must be positive")
	ErrUnauthorized  = errors.New("cache authentication failed")
	ErrFrameTooLarge = errors.New("cache wire frame exceeds maximum size")
	ErrProtocol      = errors.New("cache wire protocol error")
	ErrTooManyConns  = errors.New("cache server connection limit reached")
)

// Entry is an immutable-on-store snapshot of a cached HTTP page response.
// Callers own returned slices and headers; Store deep-copies on Put and Get so
// subsequent mutations never race with internal storage.
type Entry struct {
	Key       string
	Host      string
	Path      string
	Status    int
	Headers   http.Header
	Body      []byte
	Tags      []string
	StoredAt  time.Time
	ExpiresAt time.Time
	TTL       time.Duration
}

// Stats captures a point-in-time snapshot of cache utilization and activity.
type Stats struct {
	Entries   int64
	UsedBytes int64
	MaxBytes  int64
	Hits      int64
	Misses    int64
	Evictions int64
	Purges    int64
	Coalesced int64
	Tags      int64
	Shards    int
}

// PageCache is the port interface shared by in-process sharded stores, remote
// concert-cache clients, and microcache adapters. All implementations must be
// safe for concurrent use by multiple goroutines.
type PageCache interface {
	// Get retrieves a fresh entry by key, returning (entry, true, nil) on hit
	// or (Entry{}, false, nil) on miss.
	Get(ctx context.Context, key string) (Entry, bool, error)

	// Put stores entry with its TTL/ExpiresAt and optional surrogate tags.
	Put(ctx context.Context, entry Entry) error

	// PurgeURL removes all cached variants for the exact (host, path) pair and
	// returns the number of entries removed. An empty host matches any host.
	PurgeURL(ctx context.Context, host, path string) (int, error)

	// PurgePrefix removes all cached entries for host whose path begins with
	// prefix and returns the number of entries removed. An empty host matches
	// any host.
	PurgePrefix(ctx context.Context, host, prefix string) (int, error)

	// PurgeTag removes all cached entries indexed under tag and returns the
	// number of entries removed.
	PurgeTag(ctx context.Context, tag string) (int, error)

	// PurgeAll removes every entry from the cache and returns the number of
	// entries removed.
	PurgeAll(ctx context.Context) (int, error)

	// Stats returns a point-in-time snapshot of cache metrics.
	Stats(ctx context.Context) (Stats, error)

	// Close releases cache resources. Close is idempotent.
	Close() error
}

// StoreConfig configures an in-process sharded Store.
type StoreConfig struct {
	// MaxBytes is the global byte ceiling across all shards. Values <= 0
	// default to DefaultMaxBytes.
	MaxBytes int64
	// MaxEntryBytes caps a single stored entry's accounted size. Values <= 0
	// default to DefaultMaxEntryBytes and are clamped to MaxBytes.
	MaxEntryBytes int64
	// Shards sets the number of independent LRU shards. Values <= 0 default to
	// DefaultShards; values above MaxShards are clamped to MaxShards.
	Shards int
	// DefaultTTL is used on Put when both Entry.TTL and Entry.ExpiresAt are
	// unset. Values <= 0 default to DefaultTTL.
	DefaultTTL time.Duration
	// Clock optionally supplies the current time for deterministic tests.
	// Defaults to time.Now.
	Clock func() time.Time
}

type storedEntry struct {
	key       string
	host      string
	path      string
	status    int
	headers   http.Header
	body      []byte
	tags      []string
	storedAt  time.Time
	expiresAt time.Time
	sizeBytes int64
	listElem  *list.Element
}

type cacheShard struct {
	mu      sync.Mutex
	entries map[string]*storedEntry
	lru     *list.List // front = MRU, back = LRU
	tags    map[string]map[string]struct{}
}

type flightCall struct {
	done  chan struct{}
	entry Entry
	err   error
}

// Store is a concurrency-safe, sharded, byte-bounded LRU page cache with
// per-entry TTL, surrogate-tag indexing, URL/prefix/all purges, and in-process
// singleflight stampede coalescing.
//
// Lock ordering invariant: evictMu (level 1) may be acquired before any single
// shard.mu (level 2). Code must never acquire evictMu while holding shard.mu
// and must never hold two shard locks simultaneously.
type Store struct {
	maxBytes      int64
	maxEntryBytes int64
	defaultTTL    time.Duration
	clock         func() time.Time

	shards      []*cacheShard
	evictMu     sync.Mutex
	evicting    atomic.Int32
	evictCursor atomic.Uint64

	usedBytes atomic.Int64
	entries   atomic.Int64
	tagKeys   atomic.Int64
	hits      atomic.Int64
	misses    atomic.Int64
	evictions atomic.Int64
	purges    atomic.Int64
	coalesced atomic.Int64
	closed    atomic.Bool
	closeOnce sync.Once

	sfMu    sync.Mutex
	flights map[string]*flightCall
}

var _ PageCache = (*Store)(nil)

// NewStore creates a sharded byte-bounded Store using cfg. Zero or negative
// capacity fields fall back to package defaults; MaxEntryBytes is clamped to
// MaxBytes.
//
// # Parameters
//
//   - cfg: Store sizing, TTL, and optional clock settings.
//
// # Returns
//
// A ready-to-use *Store that must be closed with Close when no longer needed.
//
// # Example
//
//	s := cache.NewStore(cache.StoreConfig{MaxBytes: 64 << 20, Shards: 32})
//	defer s.Close()
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main.go:187 (function value)
//   - internal/cache/cache_test.go:183 (function value)
//   - internal/cache/cache_test.go:266 (function value)
//   - internal/cache/cache_test.go:308 (function value)
//   - internal/cache/cache_test.go:369 (function value)
//   - internal/cache/cache_test.go:463 (function value)
//   - internal/cache/cache_test.go:517 (function value)
//   - internal/cache/cache_test.go:659 (function value)
//   - internal/cache/cache_test.go:723 (function value)
//   - internal/cache/cache_test.go:882 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func NewStore(cfg StoreConfig) *Store {
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	maxEntry := cfg.MaxEntryBytes
	if maxEntry <= 0 {
		maxEntry = DefaultMaxEntryBytes
	}
	if maxEntry > maxBytes {
		maxEntry = maxBytes
	}
	nShards := cfg.Shards
	if nShards <= 0 {
		nShards = DefaultShards
	}
	if nShards > MaxShards {
		nShards = MaxShards
	}
	defTTL := cfg.DefaultTTL
	if defTTL <= 0 {
		defTTL = DefaultTTL
	}
	clk := cfg.Clock
	if clk == nil {
		clk = time.Now
	}

	shards := make([]*cacheShard, nShards)
	for i := range shards {
		shards[i] = &cacheShard{
			entries: make(map[string]*storedEntry),
			lru:     list.New(),
			tags:    make(map[string]map[string]struct{}),
		}
	}

	return &Store{
		maxBytes:      maxBytes,
		maxEntryBytes: maxEntry,
		defaultTTL:    defTTL,
		clock:         clk,
		shards:        shards,
		flights:       make(map[string]*flightCall),
	}
}

// Get retrieves the cached Entry for key if present and unexpired. Returned
// headers, body, and tags are deep copies owned by the caller.
//
// # Parameters
//
//   - ctx: Controls cancellation before shard lookup. Must be non-nil.
//   - key: Non-empty cache key (<= MaxKeyBytes).
//
// # Returns
//
// (entry, true, nil) on a fresh hit; (Entry{}, false, nil) on miss or expiry;
// or a non-nil error if ctx is cancelled, the store is closed, or key is invalid.
//
// # Example
//
//	ent, ok, err := store.Get(ctx, "example.com\x00/\x00\x00gz")
//	if err != nil {
//	    return err
//	}
//	_, _ = ent, ok
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:212 (function value)
//   - internal/cache/cache_test.go:228 (function value)
//   - internal/cache/cache_test.go:235 (function value)
//   - internal/cache/cache_test.go:258 (function value)
//   - internal/cache/cache_test.go:334 (function value)
//   - internal/cache/cache_test.go:483 (function value)
//   - internal/cache/cache_test.go:899 (function value)
//   - internal/cache/server.go:840 (function value)
//   - internal/cache/store.go:507 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) Get(ctx context.Context, key string) (Entry, bool, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, false, err
	}
	if s.closed.Load() {
		return Entry{}, false, ErrClosed
	}
	if key == "" || len(key) > MaxKeyBytes {
		return Entry{}, false, ErrInvalidKey
	}

	now := s.clock()
	sh := s.shardFor(key)
	sh.mu.Lock()
	if s.closed.Load() {
		sh.mu.Unlock()
		return Entry{}, false, ErrClosed
	}
	ent, ok := sh.entries[key]
	if !ok {
		sh.mu.Unlock()
		s.misses.Add(1)
		return Entry{}, false, nil
	}
	if !ent.expiresAt.After(now) {
		s.removeLocked(sh, ent, false)
		sh.mu.Unlock()
		s.misses.Add(1)
		return Entry{}, false, nil
	}
	sh.lru.MoveToFront(ent.listElem)
	out := entryFromStored(ent)
	sh.mu.Unlock()

	s.hits.Add(1)
	return out, true, nil
}

// Put validates, deep-copies, and inserts entry into the sharded LRU cache,
// evicting least-recently-used entries when needed to enforce MaxBytes strictly.
//
// # Parameters
//
//   - ctx: Controls cancellation before mutation. Must be non-nil.
//   - entry: Page entry to store. Key must be non-empty and <= MaxKeyBytes.
//     Host and Path default to parsed segments of canonical keys
//     ("host\x00path\x00query\x00enc") when omitted.
//
// # Returns
//
// nil on success, or an error matching ErrClosed, ErrInvalidKey,
// ErrEntryTooLarge, ErrTooManyTags, ErrInvalidTag, ErrInvalidTTL, or ctx.Err().
//
// # Example
//
//	err := store.Put(ctx, cache.Entry{
//	    Key:    "example.com\x00/\x00\x00raw",
//	    Status: http.StatusOK,
//	    Body:   []byte("<html>ok</html>"),
//	    Tags:   []string{"home", "post:1"},
//	    TTL:    30 * time.Second,
//	})
//	if err != nil {
//	    return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:196 (function value)
//   - internal/cache/cache_test.go:275 (function value)
//   - internal/cache/cache_test.go:285 (function value)
//   - internal/cache/cache_test.go:324 (function value)
//   - internal/cache/cache_test.go:345 (function value)
//   - internal/cache/cache_test.go:352 (function value)
//   - internal/cache/cache_test.go:482 (function value)
//   - internal/cache/cache_test.go:890 (function value)
//   - internal/cache/server.go:858 (function value)
//   - internal/cache/store.go:555 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) Put(ctx context.Context, entry Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed.Load() {
		return ErrClosed
	}
	se, err := s.prepareEntry(entry)
	if err != nil {
		return err
	}

	shIdx := s.shardIndex(se.key)
	sh := s.shards[shIdx]

	// Fast path: reserve bytes atomically without acquiring evictMu when no
	// slow-path eviction is active and global usage has headroom for se.sizeBytes.
	if s.evicting.Load() == 0 && s.tryReserveBytes(se.sizeBytes) {
		sh.mu.Lock()
		if s.closed.Load() {
			sh.mu.Unlock()
			s.usedBytes.Add(-se.sizeBytes)
			return ErrClosed
		}
		if old, exists := sh.entries[se.key]; exists {
			s.removeLocked(sh, old, false)
		}
		s.insertLocked(sh, se)
		sh.mu.Unlock()
		return nil
	}

	// Slow path: serialize cross-shard eviction under evictMu and ALWAYS acquire
	// budget through tryReserveBytes CAS so usedBytes can never overshoot
	// maxBytes even if an in-flight fast-path writer concurrently reserves
	// headroom freed by eviction.
	s.evictMu.Lock()
	s.evicting.Add(1)
	defer func() {
		s.evicting.Add(-1)
		s.evictMu.Unlock()
	}()

	if s.closed.Load() {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Free bytes held by any existing version of the same key first.
	sh.mu.Lock()
	if old, exists := sh.entries[se.key]; exists {
		s.removeLocked(sh, old, false)
	}
	sh.mu.Unlock()

	now := s.clock()
	for !s.tryReserveBytes(se.sizeBytes) {
		if s.closed.Load() {
			return ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !s.evictUntilRoomLocked(shIdx, se.sizeBytes, now) {
			if se.sizeBytes > s.maxBytes {
				return ErrEntryTooLarge
			}
			// An in-flight fast-path writer may hold reserved bytes not yet
			// linked into its shard's LRU; yield so it completes and becomes
			// visible to eviction or releases its budget.
			runtime.Gosched()
		}
	}

	sh.mu.Lock()
	if s.closed.Load() {
		sh.mu.Unlock()
		s.usedBytes.Add(-se.sizeBytes)
		return ErrClosed
	}
	if old, exists := sh.entries[se.key]; exists {
		s.removeLocked(sh, old, false)
	}
	s.insertLocked(sh, se)
	sh.mu.Unlock()
	return nil
}

// Do performs in-process singleflight stampede coalescing for key. It first
// checks the cache; on a miss, concurrent callers for the same key share a
// single invocation of fn. If fn succeeds, the resulting entry is stored in s
// and deep-copied to all waiters. Waiters honor ctx cancellation independently.
//
// # Parameters
//
//   - ctx: Controls caller wait cancellation and is passed to fn by the leader.
//   - key: Non-empty cache key (<= MaxKeyBytes).
//   - fn: Origin loader executed once by the singleflight leader on cache miss.
//     Must be non-nil.
//
// # Returns
//
// (entry, coalesced, err) where coalesced is true when the caller waited on an
// in-flight leader rather than executing fn or hitting the cache directly.
//
// # Example
//
//	ent, shared, err := store.Do(ctx, key, func(ctx context.Context) (cache.Entry, error) {
//	    return cache.Entry{Key: key, Status: 200, Body: []byte("ok"), TTL: 10 * time.Second}, nil
//	})
//	_, _, _ = ent, shared, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:394 (function value)
//   - internal/cache/cache_test.go:411 (function value)
//   - internal/cache/cache_test.go:426 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) Do(ctx context.Context, key string, fn func(context.Context) (Entry, error)) (Entry, bool, error) {
	if fn == nil {
		return Entry{}, false, errors.New("cache singleflight loader must not be nil")
	}
	if ent, ok, err := s.Get(ctx, key); err != nil || ok {
		return ent, false, err
	}

	s.sfMu.Lock()
	if s.closed.Load() {
		s.sfMu.Unlock()
		return Entry{}, false, ErrClosed
	}
	if call, waiting := s.flights[key]; waiting {
		s.sfMu.Unlock()
		select {
		case <-call.done:
			if call.err != nil {
				return Entry{}, true, call.err
			}
			s.coalesced.Add(1)
			return cloneEntry(call.entry), true, nil
		case <-ctx.Done():
			return Entry{}, false, ctx.Err()
		}
	}
	call := &flightCall{done: make(chan struct{})}
	s.flights[key] = call
	s.sfMu.Unlock()

	// Execute fn without holding sfMu and always release waiters on return or
	// panic so no waiting goroutine can block indefinitely.
	var (
		res    Entry
		resErr error
	)
	defer func() {
		s.sfMu.Lock()
		call.entry = res
		call.err = resErr
		delete(s.flights, key)
		close(call.done)
		s.sfMu.Unlock()
	}()

	res, resErr = fn(ctx)
	if resErr != nil {
		return Entry{}, false, resErr
	}
	if res.Key == "" {
		res.Key = key
	}
	if err := s.Put(ctx, res); err != nil {
		resErr = err
		return Entry{}, false, err
	}
	// Snapshot the normalized entry for waiters so leader mutations do not
	// alias waiter results.
	res = cloneEntry(res)
	return cloneEntry(res), false, nil
}

// PurgeURL removes every cached entry whose host and path match host and path
// (covering all query strings and encodings for that URL). An empty host
// matches entries from any host.
//
// # Parameters
//
//   - ctx: Controls cancellation across shard scans. Must be non-nil.
//   - host: Target host (case-insensitive, trimmed). Empty matches any host.
//   - path: Exact URL path to purge. Empty path removes 0 entries.
//
// # Returns
//
// Count of removed entries and any cancellation or closed-store error.
//
// # Example
//
//	removed, err := store.PurgeURL(ctx, "shop.example.com", "/product/tee/")
//	_, _ = removed, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:330 (function value)
//   - internal/cache/cache_test.go:488 (function value)
//   - internal/cache/server.go:868 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) PurgeURL(ctx context.Context, host, path string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.closed.Load() {
		return 0, ErrClosed
	}
	normHost := normalizeHost(host)
	if path == "" {
		return 0, nil
	}

	removed := 0
	for _, sh := range s.shards {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		sh.mu.Lock()
		for _, ent := range sh.entries {
			if (normHost == "" || ent.host == normHost) && ent.path == path {
				s.removeLocked(sh, ent, false)
				removed++
			}
		}
		sh.mu.Unlock()
	}
	if removed > 0 {
		s.purges.Add(int64(removed))
	}
	return removed, nil
}

// PurgePrefix removes every cached entry whose host matches host (or any host
// when host is empty) and whose path begins with prefix.
//
// # Parameters
//
//   - ctx: Controls cancellation across shard scans. Must be non-nil.
//   - host: Target host (case-insensitive, trimmed). Empty matches any host.
//   - prefix: Required path prefix. Empty prefix removes 0 entries.
//
// # Returns
//
// Count of removed entries and any cancellation or closed-store error.
//
// # Example
//
//	removed, err := store.PurgePrefix(ctx, "shop.example.com", "/product/")
//	_, _ = removed, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:346 (function value)
//   - internal/cache/cache_test.go:490 (function value)
//   - internal/cache/server.go:879 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) PurgePrefix(ctx context.Context, host, prefix string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.closed.Load() {
		return 0, ErrClosed
	}
	normHost := normalizeHost(host)
	if prefix == "" {
		return 0, nil
	}

	removed := 0
	for _, sh := range s.shards {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		sh.mu.Lock()
		for _, ent := range sh.entries {
			if (normHost == "" || ent.host == normHost) && strings.HasPrefix(ent.path, prefix) {
				s.removeLocked(sh, ent, false)
				removed++
			}
		}
		sh.mu.Unlock()
	}
	if removed > 0 {
		s.purges.Add(int64(removed))
	}
	return removed, nil
}

// PurgeTag removes every cached entry indexed under tag across all shards.
//
// # Parameters
//
//   - ctx: Controls cancellation across shard lookups. Must be non-nil.
//   - tag: Surrogate tag (trimmed, case-insensitive). Empty or invalid tag
//     removes 0 entries.
//
// # Returns
//
// Count of removed entries and any cancellation or closed-store error.
//
// # Example
//
//	removed, err := store.PurgeTag(ctx, "product:42")
//	_, _ = removed, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:339 (function value)
//   - internal/cache/cache_test.go:486 (function value)
//   - internal/cache/cache_test.go:903 (function value)
//   - internal/cache/server.go:889 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) PurgeTag(ctx context.Context, tag string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.closed.Load() {
		return 0, ErrClosed
	}
	normTag := normalizeTag(tag)
	if normTag == "" || len(normTag) > MaxTagBytes {
		return 0, nil
	}

	removed := 0
	for _, sh := range s.shards {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		sh.mu.Lock()
		keySet := sh.tags[normTag]
		if len(keySet) > 0 {
			keys := make([]string, 0, len(keySet))
			for k := range keySet {
				keys = append(keys, k)
			}
			for _, k := range keys {
				if ent, ok := sh.entries[k]; ok {
					s.removeLocked(sh, ent, false)
					removed++
				}
			}
		}
		sh.mu.Unlock()
	}
	if removed > 0 {
		s.purges.Add(int64(removed))
	}
	return removed, nil
}

// PurgeAll removes every entry and surrogate-tag index entry across all shards.
//
// # Parameters
//
//   - ctx: Controls cancellation across shards. Must be non-nil.
//
// # Returns
//
// Count of removed entries and any cancellation or closed-store error.
//
// # Example
//
//	removed, err := store.PurgeAll(ctx)
//	_, _ = removed, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:353 (function value)
//   - internal/cache/server.go:899 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) PurgeAll(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.closed.Load() {
		return 0, ErrClosed
	}

	removed := 0
	for _, sh := range s.shards {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		sh.mu.Lock()
		n, bytesFreed, tagBucketsFreed := clearShardLocked(sh)
		sh.mu.Unlock()
		if n > 0 {
			s.entries.Add(-int64(n))
			s.usedBytes.Add(-bytesFreed)
			s.tagKeys.Add(-int64(tagBucketsFreed))
			removed += n
		}
	}
	if removed > 0 {
		s.purges.Add(int64(removed))
	}
	return removed, nil
}

// Stats returns a consistent point-in-time snapshot of cache counters.
//
// # Parameters
//
//   - ctx: Controls cancellation. Must be non-nil.
//
// # Returns
//
// Stats snapshot and any cancellation error.
//
// # Example
//
//	st, err := store.Stats(ctx)
//	_, _ = st, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:240 (function value)
//   - internal/cache/cache_test.go:288 (function value)
//   - internal/cache/cache_test.go:297 (function value)
//   - internal/cache/cache_test.go:357 (function value)
//   - internal/cache/cache_test.go:492 (function value)
//   - internal/cache/cache_test.go:503 (function value)
//   - internal/cache/server.go:647 (function value)
//   - internal/cache/server.go:909 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	if err := ctx.Err(); err != nil {
		return Stats{}, err
	}
	return Stats{
		Entries:   max(0, s.entries.Load()),
		UsedBytes: max(0, s.usedBytes.Load()),
		MaxBytes:  s.maxBytes,
		Hits:      s.hits.Load(),
		Misses:    s.misses.Load(),
		Evictions: s.evictions.Load(),
		Purges:    s.purges.Load(),
		Coalesced: s.coalesced.Load(),
		Tags:      max(0, s.tagKeys.Load()),
		Shards:    len(s.shards),
	}, nil
}

// Close marks the store closed and releases all cached entries and tag indices.
// Subsequent Get/Put/Purge calls return ErrClosed. Close is idempotent.
//
// # Parameters
//
// None.
//
// # Returns
//
// Always nil.
//
// # Example
//
//	_ = store.Close()
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main.go:191 (function value)
//   - internal/cache/cache_test.go:189 (function value)
//   - internal/cache/cache_test.go:252 (function value)
//   - internal/cache/cache_test.go:255 (function value)
//   - internal/cache/cache_test.go:272 (function value)
//   - internal/cache/cache_test.go:313 (function value)
//   - internal/cache/cache_test.go:370 (function value)
//   - internal/cache/cache_test.go:469 (function value)
//   - internal/cache/cache_test.go:518 (function value)
//   - internal/cache/cache_test.go:660 (function value)
//   - internal/cache/cache_test.go:724 (function value)
//   - internal/cache/cache_test.go:887 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		for _, sh := range s.shards {
			sh.mu.Lock()
			n, bytesFreed, tagBucketsFreed := clearShardLocked(sh)
			sh.mu.Unlock()
			if n > 0 {
				s.entries.Add(-int64(n))
				s.usedBytes.Add(-bytesFreed)
				s.tagKeys.Add(-int64(tagBucketsFreed))
			}
		}
	})
	return nil
}

// prepareEntry validates bounds and deep-copies entry into a self-contained
// storedEntry.
//
// # Parameters
//
//   - entry: Caller-supplied Entry to validate and copy.
//
// # Returns
//
// An owned *storedEntry or a validation error.
//
// # Example
//
//	se, err := s.prepareEntry(entry)
//	_, _ = se, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/store.go:404 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) prepareEntry(entry Entry) (*storedEntry, error) {
	if entry.Key == "" || len(entry.Key) > MaxKeyBytes {
		return nil, ErrInvalidKey
	}

	host := normalizeHost(entry.Host)
	path := entry.Path
	if host == "" || path == "" {
		parsedHost, parsedPath := ParseCanonicalKey(entry.Key)
		if host == "" {
			host = parsedHost
		}
		if path == "" {
			path = parsedPath
		}
	}
	if len(host) > MaxHostBytes || len(path) > MaxPathBytes {
		return nil, ErrInvalidKey
	}

	now := s.clock()
	storedAt := entry.StoredAt
	if storedAt.IsZero() {
		storedAt = now
	}
	expiresAt := entry.ExpiresAt
	if expiresAt.IsZero() {
		ttl := entry.TTL
		if ttl == 0 {
			ttl = s.defaultTTL
		}
		if ttl < 0 {
			return nil, ErrInvalidTTL
		}
		expiresAt = now.Add(ttl)
	} else if !expiresAt.After(now) {
		return nil, ErrInvalidTTL
	}

	hdrCopy, hdrBytes, err := cloneAndMeasureHeaders(entry.Headers)
	if err != nil {
		return nil, err
	}

	tags, tagBytes, err := normalizeTags(entry.Tags)
	if err != nil {
		return nil, err
	}

	bodyCopy := append([]byte(nil), entry.Body...)
	sizeBytes := int64(len(entry.Key) + len(host) + len(path) + len(bodyCopy) + hdrBytes + tagBytes + 256)
	if sizeBytes > s.maxEntryBytes || sizeBytes > s.maxBytes {
		return nil, fmt.Errorf("%w: entry size %d exceeds limit %d", ErrEntryTooLarge, sizeBytes, s.maxEntryBytes)
	}

	status := entry.Status
	if status == 0 {
		status = http.StatusOK
	}

	return &storedEntry{
		key:       entry.Key,
		host:      host,
		path:      path,
		status:    status,
		headers:   hdrCopy,
		body:      bodyCopy,
		tags:      tags,
		storedAt:  storedAt,
		expiresAt: expiresAt,
		sizeBytes: sizeBytes,
	}, nil
}

// tryReserveBytes attempts an atomic compare-and-swap reservation of delta
// bytes without exceeding s.maxBytes.
//
// # Parameters
//
//   - delta: Positive byte count to reserve.
//
// # Returns
//
// true if the reservation succeeded within s.maxBytes; false if eviction is
// required.
//
// # Example
//
//	if s.tryReserveBytes(1024) {
//	    // room reserved
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/store.go:414 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) tryReserveBytes(delta int64) bool {
	for {
		cur := s.usedBytes.Load()
		if cur+delta > s.maxBytes {
			return false
		}
		if s.usedBytes.CompareAndSwap(cur, cur+delta) {
			return true
		}
	}
}

// evictUntilRoomLocked evicts expired or least-recently-used entries across
// shards until s.usedBytes + need <= s.maxBytes. Caller must hold s.evictMu
// and must not hold any shard lock.
//
// # Parameters
//
//   - preferredShard: Shard index tried first before round-robin sweeping.
//   - need: Required byte headroom.
//   - now: Current timestamp for expiry preference.
//
// # Returns
//
// true once enough room exists; false if the cache is empty and need still
// exceeds s.maxBytes.
//
// # Example
//
//	ok := s.evictUntilRoomLocked(0, 1024, time.Now())
//	_ = ok
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/store.go:449 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) evictUntilRoomLocked(preferredShard int, need int64, now time.Time) bool {
	n := len(s.shards)
	for s.usedBytes.Load()+need > s.maxBytes {
		evictedAny := false
		// Check preferred shard first to maintain local LRU locality, then sweep
		// remaining shards round-robin.
		start := int(s.evictCursor.Add(1)-1) % n
		for step := 0; step < n && s.usedBytes.Load()+need > s.maxBytes; step++ {
			idx := preferredShard
			if step > 0 {
				idx = (start + step - 1) % n
				if idx == preferredShard {
					idx = (idx + 1) % n
				}
			}
			sh := s.shards[idx]
			sh.mu.Lock()
			if back := sh.lru.Back(); back != nil {
				ent := back.Value.(*storedEntry)
				isEviction := ent.expiresAt.After(now)
				s.removeLocked(sh, ent, isEviction)
				evictedAny = true
			}
			sh.mu.Unlock()
		}
		if !evictedAny {
			return s.usedBytes.Load()+need <= s.maxBytes
		}
	}
	return true
}

// insertLocked inserts se at the MRU front of sh and updates tag indices.
// Caller must hold sh.mu and have already accounted for se.sizeBytes in
// s.usedBytes.
//
// # Parameters
//
//   - sh: Target shard whose mutex is held.
//   - se: Owned stored entry to insert.
//
// # Returns
//
// None.
//
// # Example
//
//	s.insertLocked(sh, se)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/store.go:424 (function value)
//   - internal/cache/store.go:463 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) insertLocked(sh *cacheShard, se *storedEntry) {
	se.listElem = sh.lru.PushFront(se)
	sh.entries[se.key] = se
	s.entries.Add(1)
	for _, tag := range se.tags {
		set := sh.tags[tag]
		if set == nil {
			set = make(map[string]struct{})
			sh.tags[tag] = set
			s.tagKeys.Add(1)
		}
		set[se.key] = struct{}{}
	}
}

// removeLocked unlinks ent from sh's LRU list, map, and surrogate-tag index,
// and releases its accounted byte count. Caller must hold sh.mu.
//
// # Parameters
//
//   - sh: Target shard whose mutex is held.
//   - ent: Entry currently present in sh.
//   - countEviction: When true, increments s.evictions.
//
// # Returns
//
// None.
//
// # Example
//
//	s.removeLocked(sh, ent, true)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/store.go:338 (function value)
//   - internal/cache/store.go:422 (function value)
//   - internal/cache/store.go:444 (function value)
//   - internal/cache/store.go:461 (function value)
//   - internal/cache/store.go:615 (function value)
//   - internal/cache/store.go:676 (function value)
//   - internal/cache/store.go:743 (function value)
//   - internal/cache/store.go:1098 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) removeLocked(sh *cacheShard, ent *storedEntry, countEviction bool) {
	if ent.listElem != nil {
		sh.lru.Remove(ent.listElem)
		ent.listElem = nil
	}
	delete(sh.entries, ent.key)
	for _, tag := range ent.tags {
		if set := sh.tags[tag]; set != nil {
			delete(set, ent.key)
			if len(set) == 0 {
				delete(sh.tags, tag)
				s.tagKeys.Add(-1)
			}
		}
	}
	s.entries.Add(-1)
	s.usedBytes.Add(-ent.sizeBytes)
	if countEviction {
		s.evictions.Add(1)
	}
}

// clearShardLocked empties sh and returns the removed entry count, freed byte
// total, and freed distinct tag bucket count. Caller must hold sh.mu.
//
// # Parameters
//
//   - sh: Target shard whose mutex is held.
//
// # Returns
//
// (removedEntries, freedBytes, freedTagBuckets).
//
// # Example
//
//	n, bytesFreed, tagsFreed := clearShardLocked(sh)
//	_, _, _ = n, bytesFreed, tagsFreed
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/store.go:795 (function value)
//   - internal/cache/store.go:899 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func clearShardLocked(sh *cacheShard) (int, int64, int) {
	n := len(sh.entries)
	if n == 0 {
		return 0, 0, 0
	}
	var bytesFreed int64
	for _, ent := range sh.entries {
		bytesFreed += ent.sizeBytes
		ent.listElem = nil
	}
	tagBuckets := len(sh.tags)
	sh.entries = make(map[string]*storedEntry)
	sh.lru.Init()
	sh.tags = make(map[string]map[string]struct{})
	return n, bytesFreed, tagBuckets
}

// shardFor returns the shard owning key.
//
// # Parameters
//
//   - key: Cache key to hash.
//
// # Returns
//
// Pointer to the owning *cacheShard.
//
// # Example
//
//	sh := s.shardFor("example.com\x00/\x00\x00raw")
//	_ = sh
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/store.go:325 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) shardFor(key string) *cacheShard {
	return s.shards[s.shardIndex(key)]
}

// shardIndex maps key to a shard index using 64-bit FNV-1a without allocating.
//
// # Parameters
//
//   - key: Cache key string.
//
// # Returns
//
// Index in [0, len(s.shards)).
//
// # Example
//
//	idx := s.shardIndex("example.com\x00/\x00\x00raw")
//	_ = idx
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/store.go:409 (function value)
//   - internal/cache/store.go:1275 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Store) shardIndex(key string) int {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	var h uint64 = offset64
	for i := 0; i < len(key); i++ {
		h ^= uint64(key[i])
		h *= prime64
	}
	return int(h % uint64(len(s.shards)))
}

// ParseCanonicalKey extracts normalized host and path from a canonical Concert
// cache key formatted as "host\x00path\x00query\x00enc". Keys not using that
// format return ("", "").
//
// # Parameters
//
//   - key: Cache key string.
//
// # Returns
//
// (normalizedHost, path).
//
// # Example
//
//	host, path := cache.ParseCanonicalKey("shop.example.com\x00/item\x00id=1\x00gz")
//	_, _ = host, path
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/protocol.go:245 (function value)
//   - internal/cache/store.go:944 (function value)
//   - internal/microcache/microcache.go:1341 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func ParseCanonicalKey(key string) (host, path string) {
	h, rest, ok := strings.Cut(key, "\x00")
	if !ok {
		return "", ""
	}
	p, _, ok := strings.Cut(rest, "\x00")
	if !ok {
		return normalizeHost(h), rest
	}
	return normalizeHost(h), p
}

// normalizeHost trims whitespace and lowercases host for consistent matching.
//
// # Parameters
//
//   - host: Raw host string.
//
// # Returns
//
// Normalized lowercase host string.
//
// # Example
//
//	h := normalizeHost(" Shop.Example.COM ") // "shop.example.com"
//	_ = h
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/protocol.go:242 (function value)
//   - internal/cache/protocol.go:485 (function value)
//   - internal/cache/store.go:602 (function value)
//   - internal/cache/store.go:663 (function value)
//   - internal/cache/store.go:941 (function value)
//   - internal/cache/store.go:1351 (function value)
//   - internal/cache/store.go:1353 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

// normalizeTag trims whitespace and lowercases tag.
//
// # Parameters
//
//   - tag: Raw surrogate tag string.
//
// # Returns
//
// Normalized tag string.
//
// # Example
//
//	t := normalizeTag(" Product:42 ") // "product:42"
//	_ = t
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/store.go:724 (function value)
//   - internal/cache/store.go:1457 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func normalizeTag(tag string) string {
	return strings.ToLower(strings.TrimSpace(tag))
}

// normalizeTags validates, deduplicates, and measures a slice of surrogate tags.
//
// # Parameters
//
//   - tags: Caller-provided tag slice.
//
// # Returns
//
// Deduplicated tag slice, total byte length, and any validation error
// (ErrTooManyTags or ErrInvalidTag).
//
// # Example
//
//	clean, n, err := normalizeTags([]string{"post:1", "POST:1", "home"})
//	_, _, _ = clean, n, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/protocol.go:266 (function value)
//   - internal/cache/protocol.go:454 (function value)
//   - internal/cache/store.go:980 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func normalizeTags(tags []string) ([]string, int, error) {
	if len(tags) == 0 {
		return nil, 0, nil
	}
	if len(tags) > MaxTagsPerEntry {
		return nil, 0, fmt.Errorf("%w: %d > %d", ErrTooManyTags, len(tags), MaxTagsPerEntry)
	}
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	totalBytes := 0
	for _, raw := range tags {
		t := normalizeTag(raw)
		if t == "" {
			continue
		}
		if len(t) > MaxTagBytes || strings.ContainsAny(t, "\r\n\x00") {
			return nil, 0, ErrInvalidTag
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
		totalBytes += len(t)
	}
	return out, totalBytes, nil
}

// cloneAndMeasureHeaders deep-copies src while enforcing MaxHeaderCount,
// MaxHeaderValues, and MaxHeaderBytes.
//
// # Parameters
//
//   - src: Caller-provided HTTP header map. May be nil.
//
// # Returns
//
// Deep-copied header map, approximate serialized byte size, and ErrEntryTooLarge
// if bounds are exceeded.
//
// # Example
//
//	hdr, n, err := cloneAndMeasureHeaders(http.Header{"Content-Type": {"text/html"}})
//	_, _, _ = hdr, n, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/protocol.go:262 (function value)
//   - internal/cache/store.go:975 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func cloneAndMeasureHeaders(src http.Header) (http.Header, int, error) {
	if len(src) == 0 {
		return nil, 0, nil
	}
	if len(src) > MaxHeaderCount {
		return nil, 0, fmt.Errorf("%w: header count %d exceeds %d", ErrEntryTooLarge, len(src), MaxHeaderCount)
	}
	dst := make(http.Header, len(src))
	total := 0
	for k, vals := range src {
		if len(vals) > MaxHeaderValues {
			return nil, 0, fmt.Errorf("%w: header %q value count %d exceeds %d", ErrEntryTooLarge, k, len(vals), MaxHeaderValues)
		}
		cp := make([]string, len(vals))
		for i, v := range vals {
			cp[i] = v
			total += len(k) + len(v) + 4
			if total > MaxHeaderBytes {
				return nil, 0, fmt.Errorf("%w: headers exceed %d bytes", ErrEntryTooLarge, MaxHeaderBytes)
			}
		}
		dst[k] = cp
	}
	return dst, total, nil
}

// entryFromStored produces a deep-copied Entry from an internal storedEntry.
//
// # Parameters
//
//   - se: Internal stored entry whose owning shard mutex is held.
//
// # Returns
//
// Caller-owned Entry snapshot.
//
// # Example
//
//	out := entryFromStored(se)
//	_ = out
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/store.go:344 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func entryFromStored(se *storedEntry) Entry {
	var hdr http.Header
	if len(se.headers) > 0 {
		hdr = make(http.Header, len(se.headers))
		for k, vals := range se.headers {
			hdr[k] = append([]string(nil), vals...)
		}
	}
	var tags []string
	if len(se.tags) > 0 {
		tags = append([]string(nil), se.tags...)
	}
	return Entry{
		Key:       se.key,
		Host:      se.host,
		Path:      se.path,
		Status:    se.status,
		Headers:   hdr,
		Body:      append([]byte(nil), se.body...),
		Tags:      tags,
		StoredAt:  se.storedAt,
		ExpiresAt: se.expiresAt,
		TTL:       se.expiresAt.Sub(se.storedAt),
	}
}

// cloneEntry deep-copies an Entry so callers cannot alias Body, Headers, or Tags.
//
// # Parameters
//
//   - e: Entry to deep-copy.
//
// # Returns
//
// Independent copy of e.
//
// # Example
//
//	cp := cloneEntry(orig)
//	_ = cp
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/store.go:524 (function value)
//   - internal/cache/store.go:561 (function value)
//   - internal/cache/store.go:562 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func cloneEntry(e Entry) Entry {
	var hdr http.Header
	if len(e.Headers) > 0 {
		hdr = make(http.Header, len(e.Headers))
		for k, vals := range e.Headers {
			hdr[k] = append([]string(nil), vals...)
		}
	}
	var tags []string
	if len(e.Tags) > 0 {
		tags = append([]string(nil), e.Tags...)
	}
	return Entry{
		Key:       e.Key,
		Host:      e.Host,
		Path:      e.Path,
		Status:    e.Status,
		Headers:   hdr,
		Body:      append([]byte(nil), e.Body...),
		Tags:      tags,
		StoredAt:  e.StoredAt,
		ExpiresAt: e.ExpiresAt,
		TTL:       e.TTL,
	}
}
