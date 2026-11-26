// Package microcache provides a pure-stdlib, byte-bounded in-memory anonymous
// GET/HEAD response micro-cache with singleflight stampede coalescing,
// surrogate-tag and URL/prefix active purging, and fail-safe
// WordPress/WooCommerce cookie/path/header bypass rules.
package microcache

import (
	"bytes"
	"container/list"
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/concert/internal/cache"
)

const (
	DefaultMaxBytes        int64 = 64 << 20 // 64 MiB
	DefaultMaxEntryBytes   int64 = 1 << 20  // 1 MiB
	DefaultMaxTagsPerEntry int   = 64       // bounded surrogate tags per entry
	DefaultMaxTagBytes     int   = 128      // max normalized tag byte length
)

// DefaultWordPressBypassPaths are paths that must never be served from or
// stored in the anonymous micro-cache.
var DefaultWordPressBypassPaths = []string{
	"/wp-admin",
	"/wp-admin/*",
	"/wp-login.php",
	"/wp-cron.php",
	"/xmlrpc.php",
	"/cart",
	"/cart/*",
	"/checkout",
	"/checkout/*",
	"/my-account",
	"/my-account/*",
	"/wc-api/*",
	"/wp-json/wc/*",
	"/_room/*",
	"/_concert/*",
	"/queue/status",
	"/queue/status/*",
}

// DefaultWordPressBypassCookiePrefixes are cookie name prefixes that indicate
// an authenticated, cart-holding, or personalized visitor who must bypass the
// anonymous micro-cache and enter the normal waiting room / priority flow.
var DefaultWordPressBypassCookiePrefixes = []string{
	"wordpress_logged_in_",
	"wordpress_sec_",
	"woocommerce_items_in_cart",
	"woocommerce_cart_hash",
	"wp_woocommerce_session_",
	"comment_author_",
	"wp-postpass_",
}

// DefaultWordPressBypassQueryKeys are query parameter names that force bypass.
var DefaultWordPressBypassQueryKeys = []string{
	"s",
	"add-to-cart",
	"remove_item",
	"undo_item",
	"preview",
	"nocache",
	"wc-ajax",
}

// Config configures a bounded anonymous micro-cache.
type Config struct {
	TTL                  time.Duration
	MaxBytes             int64
	MaxEntryBytes        int64
	MaxTagsPerEntry      int
	BypassPaths          []string
	BypassCookiePrefixes []string
	BypassQueryKeys      []string
	Clock                func() time.Time

	OnHit       func()
	OnMiss      func()
	OnBypass    func()
	OnCoalesced func()
}

// Entry is a caller-owned snapshot of a micro-cached HTTP response including
// optional surrogate tags.
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
}

type pathMatcher struct {
	exact  string
	prefix string
}

type cachedEntry struct {
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

type inflightCall struct {
	done  chan struct{}
	entry *cachedEntry // non-nil only when the leader captured a cacheable response
}

// Cache is a concurrency-safe, byte-bounded LRU micro-cache with stampede
// coalescing and active URL, prefix, surrogate-tag, and full purging. A nil
// *Cache is safe and always bypasses.
type Cache struct {
	ttl             time.Duration
	maxBytes        int64
	maxEntryBytes   int64
	maxTagsPerEntry int
	bypassPaths     []pathMatcher
	bypassCookies   []string
	bypassQuerySet  map[string]bool
	clock           func() time.Time

	onHit       func()
	onMiss      func()
	onBypass    func()
	onCoalesced func()

	mu        sync.Mutex
	entries   map[string]*cachedEntry
	lru       *list.List // front = MRU, back = LRU
	usedBytes int64
	tagIndex  map[string]map[string]struct{}
	inflight  map[string]*inflightCall

	hits      atomic.Int64
	misses    atomic.Int64
	evictions atomic.Int64
	purges    atomic.Int64
	coalesced atomic.Int64
}

// New constructs a Cache. Returns nil when cfg.TTL <= 0 (disabled).
//
// # Parameters
//
//   - cfg: Cache TTL, byte ceiling, tag bound, bypass lists, optional clock,
//     and observability hooks.
//
// # Returns
//
// An initialized *Cache, or nil when cfg.TTL <= 0.
//
// # Example
//
//	mc := microcache.New(microcache.Config{TTL: 10 * time.Second})
//	_ = mc
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/microcache/microcache_test.go:20 (function value)
//   - internal/microcache/microcache_test.go:119 (function value)
//   - internal/microcache/microcache_test.go:153 (function value)
//   - internal/microcache/microcache_test.go:194 (function value)
//   - internal/microcache/microcache_test.go:277 (function value)
//   - internal/microcache/microcache_test.go:319 (function value)
//   - internal/server/fcgi_bridge.go:100 (direct call)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func New(cfg Config) *Cache {
	if cfg.TTL <= 0 {
		return nil
	}
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
	maxTags := cfg.MaxTagsPerEntry
	if maxTags <= 0 {
		maxTags = DefaultMaxTagsPerEntry
	}
	clk := cfg.Clock
	if clk == nil {
		clk = time.Now
	}

	paths := cfg.BypassPaths
	if len(paths) == 0 {
		paths = DefaultWordPressBypassPaths
	}
	matchers := make([]pathMatcher, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, "/*") {
			matchers = append(matchers, pathMatcher{prefix: strings.TrimSuffix(p, "*")})
		} else {
			matchers = append(matchers, pathMatcher{exact: p})
		}
	}

	cookies := cfg.BypassCookiePrefixes
	if len(cookies) == 0 {
		cookies = DefaultWordPressBypassCookiePrefixes
	}
	normCookies := make([]string, 0, len(cookies))
	for _, ck := range cookies {
		if ck = strings.ToLower(strings.TrimSpace(ck)); ck != "" {
			normCookies = append(normCookies, ck)
		}
	}

	qkeys := cfg.BypassQueryKeys
	if len(qkeys) == 0 {
		qkeys = DefaultWordPressBypassQueryKeys
	}
	qset := make(map[string]bool, len(qkeys))
	for _, k := range qkeys {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			qset[k] = true
		}
	}

	return &Cache{
		ttl:             cfg.TTL,
		maxBytes:        maxBytes,
		maxEntryBytes:   maxEntry,
		maxTagsPerEntry: maxTags,
		bypassPaths:     matchers,
		bypassCookies:   normCookies,
		bypassQuerySet:  qset,
		clock:           clk,
		onHit:           cfg.OnHit,
		onMiss:          cfg.OnMiss,
		onBypass:        cfg.OnBypass,
		onCoalesced:     cfg.OnCoalesced,
		entries:         make(map[string]*cachedEntry),
		lru:             list.New(),
		tagIndex:        make(map[string]map[string]struct{}),
		inflight:        make(map[string]*inflightCall),
	}
}

// BytesUsed reports the current memory footprint of cached entries.
func (c *Cache) BytesUsed() int64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.usedBytes
}

// Entries reports the number of currently stored cache entries.
func (c *Cache) Entries() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Purge empties all cached entries immediately.
func (c *Cache) Purge() {
	_ = c.PurgeAll()
}

// PurgeAll empties all cached entries and surrogate-tag indices immediately
// and returns the number of entries removed. Safe on a nil receiver.
//
// # Parameters
//
// None. Receiver c may be nil (returns 0).
//
// # Returns
//
// Count of removed cache entries.
//
// # Example
//
//	removed := mc.PurgeAll()
//	_ = removed
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/microcache/microcache.go:297 (function value)
//   - internal/microcache/microcache.go:963 (function value)
//   - internal/microcache/microcache.go:1041 (function value)
//   - internal/microcache/microcache_test.go:204 (function value)
//   - internal/microcache/microcache_test.go:267 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Cache) PurgeAll() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	removed := len(c.entries)
	c.entries = make(map[string]*cachedEntry)
	c.lru.Init()
	c.tagIndex = make(map[string]map[string]struct{})
	c.usedBytes = 0
	c.mu.Unlock()
	if removed > 0 {
		c.purges.Add(int64(removed))
	}
	return removed
}

// PurgeURL removes all cached variants (across query strings and encodings)
// matching the exact (host, path) pair and returns the number of removed
// entries. An empty host matches entries across all hosts. Safe on nil.
//
// # Parameters
//
//   - host: Target host (case-insensitive, trimmed). Empty matches any host.
//   - path: Exact URL path to purge. Empty path removes 0 entries.
//
// # Returns
//
// Number of removed entries.
//
// # Example
//
//	removed := mc.PurgeURL("shop.example.com", "/product/tee/")
//	_ = removed
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/microcache/microcache.go:858 (function value)
//   - internal/microcache/microcache_test.go:203 (function value)
//   - internal/microcache/microcache_test.go:241 (function value)
//   - internal/microcache/microcache_test.go:351 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Cache) PurgeURL(host, path string) int {
	if c == nil || path == "" {
		return 0
	}
	normHost := strings.ToLower(strings.TrimSpace(host))

	c.mu.Lock()
	removed := 0
	for _, ent := range c.entries {
		if (normHost == "" || ent.host == normHost) && ent.path == path {
			c.removeLocked(ent)
			removed++
		}
	}
	c.mu.Unlock()
	if removed > 0 {
		c.purges.Add(int64(removed))
	}
	return removed
}

// PurgePrefix removes all cached entries whose host matches host (or any host
// when host is empty) and whose path begins with prefix. Safe on nil.
//
// # Parameters
//
//   - host: Target host (case-insensitive, trimmed). Empty matches any host.
//   - prefix: Path prefix to match. Empty prefix removes 0 entries.
//
// # Returns
//
// Number of removed entries.
//
// # Example
//
//	removed := mc.PurgePrefix("shop.example.com", "/product/")
//	_ = removed
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/microcache/microcache.go:894 (function value)
//   - internal/microcache/microcache_test.go:203 (function value)
//   - internal/microcache/microcache_test.go:257 (function value)
//   - internal/microcache/microcache_test.go:353 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Cache) PurgePrefix(host, prefix string) int {
	if c == nil || prefix == "" {
		return 0
	}
	normHost := strings.ToLower(strings.TrimSpace(host))

	c.mu.Lock()
	removed := 0
	for _, ent := range c.entries {
		if (normHost == "" || ent.host == normHost) && strings.HasPrefix(ent.path, prefix) {
			c.removeLocked(ent)
			removed++
		}
	}
	c.mu.Unlock()
	if removed > 0 {
		c.purges.Add(int64(removed))
	}
	return removed
}

// PurgeTag removes every cached entry indexed under surrogate tag and cleans up
// empty tag buckets. Safe on nil.
//
// # Parameters
//
//   - tag: Surrogate tag (trimmed, case-insensitive). Empty or oversized tag
//     removes 0 entries.
//
// # Returns
//
// Number of removed entries.
//
// # Example
//
//	removed := mc.PurgeTag("product:42")
//	_ = removed
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/microcache/microcache.go:929 (function value)
//   - internal/microcache/microcache_test.go:204 (function value)
//   - internal/microcache/microcache_test.go:249 (function value)
//   - internal/microcache/microcache_test.go:252 (function value)
//   - internal/microcache/microcache_test.go:349 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Cache) PurgeTag(tag string) int {
	if c == nil {
		return 0
	}
	normTag := strings.ToLower(strings.TrimSpace(tag))
	if normTag == "" || len(normTag) > DefaultMaxTagBytes {
		return 0
	}

	c.mu.Lock()
	removed := 0
	if keySet := c.tagIndex[normTag]; len(keySet) > 0 {
		keys := make([]string, 0, len(keySet))
		for k := range keySet {
			keys = append(keys, k)
		}
		for _, k := range keys {
			if ent, ok := c.entries[k]; ok {
				c.removeLocked(ent)
				removed++
			}
		}
	}
	c.mu.Unlock()
	if removed > 0 {
		c.purges.Add(int64(removed))
	}
	return removed
}

// Store inserts an entry into the micro-cache using the cache's default TTL
// when ttl <= 0. Any surrogate tags present in headers (Surrogate-Key,
// Cache-Tag, X-Cache-Tags) are indexed automatically.
//
// # Parameters
//
//   - key: Non-empty cache key (canonical "host\x00path\x00query\x00enc" enables
//     URL/prefix purging).
//   - status: HTTP status code; 0 defaults to http.StatusOK.
//   - headers: Response headers (cloned and stripped of hop-by-hop/cookie headers).
//   - body: Response body bytes (copied).
//   - ttl: Per-entry TTL; values <= 0 use the cache's configured TTL.
//
// # Returns
//
// true if stored; false if c is nil, key is empty, or the entry exceeds limits.
//
// # Example
//
//	ok := mc.Store(key, http.StatusOK, hdr, body, 15*time.Second)
//	_ = ok
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/microcache/microcache_test.go:229 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Cache) Store(key string, status int, headers http.Header, body []byte, ttl time.Duration) bool {
	return c.StoreWithTags(key, status, headers, body, ttl, nil)
}

// StoreWithTags inserts an entry into the micro-cache indexed under both
// explicit tags and any surrogate-tag headers present in headers, bounded by
// MaxTagsPerEntry.
//
// # Parameters
//
//   - key: Non-empty cache key.
//   - status: HTTP status code; 0 defaults to http.StatusOK.
//   - headers: Response headers (deep-copied).
//   - body: Response body bytes (deep-copied).
//   - ttl: Per-entry TTL; values <= 0 use the cache's configured TTL.
//   - tags: Optional explicit surrogate tags to associate with key.
//
// # Returns
//
// true if stored; false if c is nil, key is empty, or the entry exceeds size
// bounds.
//
// # Example
//
//	ok := mc.StoreWithTags(key, http.StatusOK, hdr, body, 30*time.Second, []string{"product:42", "catalog"})
//	_ = ok
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/microcache/microcache.go:539 (function value)
//   - internal/microcache/microcache_test.go:232 (function value)
//   - internal/microcache/microcache_test.go:235 (function value)
//   - internal/microcache/microcache_test.go:265 (function value)
//   - internal/microcache/microcache_test.go:266 (function value)
//   - internal/microcache/microcache_test.go:337 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Cache) StoreWithTags(key string, status int, headers http.Header, body []byte, ttl time.Duration, tags []string) bool {
	if c == nil || key == "" {
		return false
	}
	if status == 0 {
		status = http.StatusOK
	}
	if ttl <= 0 {
		ttl = c.ttl
	}
	if int64(len(body)) > c.maxEntryBytes {
		return false
	}
	ent := c.putWithOptions(key, "", "", status, headers, body, ttl, tags, c.clock())
	return ent != nil
}

// Lookup retrieves a deep-copied Entry for key if present and unexpired.
// Safe on a nil receiver.
//
// # Parameters
//
//   - key: Cache key to retrieve.
//
// # Returns
//
// (Entry, true) on a fresh hit, or (Entry{}, false) on miss or nil receiver.
//
// # Example
//
//	ent, ok := mc.Lookup(key)
//	_, _ = ent, ok
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/microcache/microcache.go:745 (function value)
//   - internal/microcache/microcache_test.go:207 (function value)
//   - internal/microcache/microcache_test.go:244 (function value)
//   - internal/microcache/microcache_test.go:338 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Cache) Lookup(key string) (Entry, bool) {
	if c == nil || key == "" {
		return Entry{}, false
	}
	now := c.clock()
	c.mu.Lock()
	ent := c.getLocked(key, now)
	if ent == nil {
		c.mu.Unlock()
		c.misses.Add(1)
		return Entry{}, false
	}
	out := snapshotEntry(ent)
	c.mu.Unlock()
	c.hits.Add(1)
	return out, true
}

// ExtractTags parses bounded, normalized, deduplicated surrogate tags from
// Surrogate-Key (space-delimited) and Cache-Tag / X-Cache-Tags (comma-delimited)
// headers.
//
// # Parameters
//
//   - hdr: HTTP header map to inspect. May be nil.
//
// # Returns
//
// Deduplicated slice of lowercase tags bounded by DefaultMaxTagsPerEntry and
// DefaultMaxTagBytes, or nil if no valid tags are found.
//
// # Example
//
//	tags := microcache.ExtractTags(http.Header{"Surrogate-Key": {"post-1 home"}})
//	_ = tags
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
func ExtractTags(hdr http.Header) []string {
	return extractTagsBounded(hdr, nil, DefaultMaxTagsPerEntry)
}

// AsPageCache wraps c in an adapter that satisfies cache.PageCache so
// microcache.Cache can be used interchangeably with cache.Store and
// cache.Client.
//
// # Parameters
//
// None. Receiver c may be nil (all operations act as an empty disabled cache).
//
// # Returns
//
// A cache.PageCache backed by c.
//
// # Example
//
//	var pc cache.PageCache = mc.AsPageCache()
//	defer pc.Close()
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/microcache/microcache_test.go:278 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Cache) AsPageCache() cache.PageCache {
	return &PageCacheAdapter{cache: c}
}

// PageCacheAdapter adapts *Cache to the cache.PageCache port interface.
type PageCacheAdapter struct {
	cache *Cache
}

var _ cache.PageCache = (*PageCacheAdapter)(nil)

// Get retrieves a fresh entry from the wrapped micro-cache.
//
// # Parameters
//
//   - ctx: Controls cancellation before lookup. Must be non-nil.
//   - key: Cache key.
//
// # Returns
//
// (entry, true, nil) on hit, (cache.Entry{}, false, nil) on miss, or ctx.Err().
//
// # Example
//
//	ent, ok, err := pc.Get(ctx, key)
//	_, _, _ = ent, ok, err
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
func (a *PageCacheAdapter) Get(ctx context.Context, key string) (cache.Entry, bool, error) {
	if err := ctx.Err(); err != nil {
		return cache.Entry{}, false, err
	}
	if a == nil || a.cache == nil {
		return cache.Entry{}, false, nil
	}
	if key == "" || len(key) > cache.MaxKeyBytes {
		return cache.Entry{}, false, cache.ErrInvalidKey
	}
	ent, ok := a.cache.Lookup(key)
	if !ok {
		return cache.Entry{}, false, nil
	}
	return cache.Entry{
		Key:       ent.Key,
		Host:      ent.Host,
		Path:      ent.Path,
		Status:    ent.Status,
		Headers:   ent.Headers,
		Body:      ent.Body,
		Tags:      ent.Tags,
		StoredAt:  ent.StoredAt,
		ExpiresAt: ent.ExpiresAt,
		TTL:       ent.ExpiresAt.Sub(ent.StoredAt),
	}, true, nil
}

// Put stores entry in the wrapped micro-cache, honoring explicit Host, Path,
// TTL/ExpiresAt, and Tags.
//
// # Parameters
//
//   - ctx: Controls cancellation before mutation. Must be non-nil.
//   - entry: Entry to store.
//
// # Returns
//
// nil on success, or an error matching ctx.Err(), cache.ErrInvalidKey,
// cache.ErrInvalidTTL, or cache.ErrEntryTooLarge.
//
// # Example
//
//	err := pc.Put(ctx, cache.Entry{Key: key, Status: 200, Body: []byte("ok"), TTL: 10 * time.Second})
//	_ = err
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
func (a *PageCacheAdapter) Put(ctx context.Context, entry cache.Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a == nil || a.cache == nil {
		return nil
	}
	if entry.Key == "" || len(entry.Key) > cache.MaxKeyBytes {
		return cache.ErrInvalidKey
	}
	now := a.cache.clock()
	ttl := entry.TTL
	if !entry.ExpiresAt.IsZero() {
		ttl = entry.ExpiresAt.Sub(now)
		if ttl <= 0 {
			return cache.ErrInvalidTTL
		}
	} else if ttl < 0 {
		return cache.ErrInvalidTTL
	} else if ttl == 0 {
		ttl = a.cache.ttl
	}
	if int64(len(entry.Body)) > a.cache.maxEntryBytes {
		return cache.ErrEntryTooLarge
	}
	status := entry.Status
	if status == 0 {
		status = http.StatusOK
	}
	if a.cache.putWithOptions(entry.Key, entry.Host, entry.Path, status, entry.Headers, entry.Body, ttl, entry.Tags, now) == nil {
		return cache.ErrEntryTooLarge
	}
	return nil
}

// PurgeURL delegates to Cache.PurgeURL.
//
// # Parameters
//
//   - ctx: Controls cancellation. Must be non-nil.
//   - host: Optional host filter.
//   - path: Exact path to purge.
//
// # Returns
//
// Removed entry count and any cancellation error.
//
// # Example
//
//	n, err := pc.PurgeURL(ctx, "example.com", "/p")
//	_, _ = n, err
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
func (a *PageCacheAdapter) PurgeURL(ctx context.Context, host, path string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if a == nil || a.cache == nil {
		return 0, nil
	}
	return a.cache.PurgeURL(host, path), nil
}

// PurgePrefix delegates to Cache.PurgePrefix.
//
// # Parameters
//
//   - ctx: Controls cancellation. Must be non-nil.
//   - host: Optional host filter.
//   - prefix: Path prefix to purge.
//
// # Returns
//
// Removed entry count and any cancellation error.
//
// # Example
//
//	n, err := pc.PurgePrefix(ctx, "example.com", "/blog/")
//	_, _ = n, err
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
func (a *PageCacheAdapter) PurgePrefix(ctx context.Context, host, prefix string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if a == nil || a.cache == nil {
		return 0, nil
	}
	return a.cache.PurgePrefix(host, prefix), nil
}

// PurgeTag delegates to Cache.PurgeTag.
//
// # Parameters
//
//   - ctx: Controls cancellation. Must be non-nil.
//   - tag: Surrogate tag to purge.
//
// # Returns
//
// Removed entry count and any cancellation error.
//
// # Example
//
//	n, err := pc.PurgeTag(ctx, "post:1")
//	_, _ = n, err
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
func (a *PageCacheAdapter) PurgeTag(ctx context.Context, tag string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if a == nil || a.cache == nil {
		return 0, nil
	}
	return a.cache.PurgeTag(tag), nil
}

// PurgeAll delegates to Cache.PurgeAll.
//
// # Parameters
//
//   - ctx: Controls cancellation. Must be non-nil.
//
// # Returns
//
// Removed entry count and any cancellation error.
//
// # Example
//
//	n, err := pc.PurgeAll(ctx)
//	_, _ = n, err
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
func (a *PageCacheAdapter) PurgeAll(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if a == nil || a.cache == nil {
		return 0, nil
	}
	return a.cache.PurgeAll(), nil
}

// Stats returns a cache.Stats snapshot for the wrapped micro-cache.
//
// # Parameters
//
//   - ctx: Controls cancellation. Must be non-nil.
//
// # Returns
//
// cache.Stats snapshot and any cancellation error.
//
// # Example
//
//	st, err := pc.Stats(ctx)
//	_, _ = st, err
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
func (a *PageCacheAdapter) Stats(ctx context.Context) (cache.Stats, error) {
	if err := ctx.Err(); err != nil {
		return cache.Stats{}, err
	}
	if a == nil || a.cache == nil {
		return cache.Stats{}, nil
	}
	a.cache.mu.Lock()
	entries := int64(len(a.cache.entries))
	used := a.cache.usedBytes
	tags := int64(len(a.cache.tagIndex))
	a.cache.mu.Unlock()
	return cache.Stats{
		Entries:   entries,
		UsedBytes: used,
		MaxBytes:  a.cache.maxBytes,
		Hits:      a.cache.hits.Load(),
		Misses:    a.cache.misses.Load(),
		Evictions: a.cache.evictions.Load(),
		Purges:    a.cache.purges.Load(),
		Coalesced: a.cache.coalesced.Load(),
		Tags:      tags,
		Shards:    1,
	}, nil
}

// Close clears all entries from the wrapped micro-cache. Idempotent.
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
//	_ = pc.Close()
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
func (a *PageCacheAdapter) Close() error {
	if a != nil && a.cache != nil {
		a.cache.PurgeAll()
	}
	return nil
}

// ShouldBypassRequest reports whether r must bypass the anonymous micro-cache.
func (c *Cache) ShouldBypassRequest(r *http.Request) bool {
	if c == nil || r == nil {
		return true
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return true
	}
	if r.Header.Get("Authorization") != "" || r.Header.Get("Range") != "" {
		return true
	}
	p := r.URL.Path
	for _, m := range c.bypassPaths {
		if m.prefix != "" {
			if strings.HasPrefix(p, m.prefix) {
				return true
			}
		} else if p == m.exact {
			return true
		}
	}
	if rq := r.URL.RawQuery; rq != "" {
		for _, part := range strings.Split(rq, "&") {
			k, _, _ := strings.Cut(part, "=")
			if c.bypassQuerySet[strings.ToLower(k)] {
				return true
			}
		}
	}
	for _, rawCookie := range r.Header.Values("Cookie") {
		for _, kv := range strings.Split(rawCookie, ";") {
			name, _, _ := strings.Cut(kv, "=")
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			for _, pref := range c.bypassCookies {
				if strings.HasPrefix(name, pref) {
					return true
				}
			}
		}
	}
	return false
}

// BuildKey returns the canonical cache key for r, partitioning by host, path,
// query string, and whether the client accepts gzip encoding.
func BuildKey(r *http.Request) string {
	enc := "raw"
	if acceptsGzip(r.Header.Get("Accept-Encoding")) {
		enc = "gz"
	}
	host := strings.ToLower(strings.TrimSpace(r.Host))
	return host + "\x00" + r.URL.Path + "\x00" + r.URL.RawQuery + "\x00" + enc
}

func acceptsGzip(ae string) bool {
	for _, part := range strings.Split(ae, ",") {
		part = strings.TrimSpace(part)
		enc, params, _ := strings.Cut(part, ";")
		if !strings.EqualFold(strings.TrimSpace(enc), "gzip") {
			continue
		}
		if strings.Contains(strings.ToLower(params), "q=0") && !strings.Contains(strings.ToLower(params), "q=0.") {
			return false
		}
		return true
	}
	return false
}

// ShouldCacheResponse checks whether an upstream response is strictly safe to
// share across anonymous visitors.
func ShouldCacheResponse(status int, hdr http.Header, bodyLen, maxEntryBytes int64) bool {
	if status != http.StatusOK {
		return false
	}
	if bodyLen <= 0 || bodyLen > maxEntryBytes {
		return false
	}
	if len(hdr.Values("Set-Cookie")) > 0 {
		return false
	}
	if hdr.Get("Concert-Priority") != "" {
		return false
	}
	if strings.Contains(strings.ToLower(hdr.Get("Pragma")), "no-cache") {
		return false
	}
	for _, cc := range hdr.Values("Cache-Control") {
		low := strings.ToLower(cc)
		if strings.Contains(low, "private") ||
			strings.Contains(low, "no-store") ||
			strings.Contains(low, "no-cache") ||
			strings.Contains(low, "max-age=0") {
			return false
		}
	}
	for _, v := range hdr.Values("Vary") {
		for _, tok := range strings.Split(v, ",") {
			t := strings.ToLower(strings.TrimSpace(tok))
			if t == "*" || t == "cookie" || t == "authorization" {
				return false
			}
		}
	}
	return true
}

// Serve handles r via the micro-cache when eligible. If r must bypass, it sets
// X-Concert-Cache: BYPASS and returns handled=false so the caller continues
// into the waiting room and origin proxy.
//
// When eligible:
//   - Fresh cache hit: writes cached response with X-Concert-Cache: HIT and returns handled=true.
//   - Cache miss: coalesces concurrent misses for the same key via singleflight;
//     leader executes fetch(w, r), caches if safe, and wakes waiters. Waiters
//     either get the cached entry directly (X-Concert-Cache: HIT) or fall back
//     to returning handled=false when the upstream response was non-cacheable.
func (c *Cache) Serve(w http.ResponseWriter, r *http.Request, fetch func(http.ResponseWriter, *http.Request)) (handled bool) {
	if c == nil {
		return false
	}
	if c.ShouldBypassRequest(r) {
		if c.onBypass != nil {
			c.onBypass()
		}
		w.Header().Set("X-Concert-Cache", "BYPASS")
		return false
	}

	key := BuildKey(r)
	now := c.clock()

	c.mu.Lock()
	if ent := c.getLocked(key, now); ent != nil {
		c.mu.Unlock()
		c.hits.Add(1)
		if c.onHit != nil {
			c.onHit()
		}
		writeCachedEntry(w, r, ent, now)
		return true
	}
	if call, waiting := c.inflight[key]; waiting {
		c.mu.Unlock()
		select {
		case <-call.done:
			if call.entry != nil {
				c.hits.Add(1)
				c.coalesced.Add(1)
				if c.onHit != nil {
					c.onHit()
				}
				if c.onCoalesced != nil {
					c.onCoalesced()
				}
				writeCachedEntry(w, r, call.entry, c.clock())
				return true
			}
			// Leader's response was non-cacheable (e.g. Set-Cookie or 5xx):
			// do NOT share private response; let caller proceed directly.
			if c.onBypass != nil {
				c.onBypass()
			}
			w.Header().Set("X-Concert-Cache", "BYPASS")
			return false
		case <-r.Context().Done():
			return true
		}
	}

	// Become the singleflight leader for key.
	call := &inflightCall{done: make(chan struct{})}
	c.inflight[key] = call
	c.mu.Unlock()

	c.misses.Add(1)
	if c.onMiss != nil {
		c.onMiss()
	}

	capW := newCaptureWriter(w, c.maxEntryBytes)
	defer func() {
		// Ensure waiters are always woken even if fetch panics.
		var stored *cachedEntry
		if !capW.streamed {
			status := capW.status
			if status == 0 {
				status = http.StatusOK
			}
			body := capW.buf.Bytes()
			if ShouldCacheResponse(status, capW.header, int64(len(body)), c.maxEntryBytes) {
				stored = c.put(key, status, capW.header, body, c.clock())
			}
			capW.flushToTarget(stored != nil)
		}
		c.mu.Lock()
		call.entry = stored
		delete(c.inflight, key)
		close(call.done)
		c.mu.Unlock()
	}()

	// If leader was a HEAD request, run fetch as GET internally? Keep method
	// untouched so we never surprise upstream; only GET bodies are non-empty so
	// HEAD naturally stays non-cached while still serving cached GET hits!
	fetch(capW, r)
	return true
}

func (c *Cache) getLocked(key string, now time.Time) *cachedEntry {
	ent, ok := c.entries[key]
	if !ok {
		return nil
	}
	if !ent.expiresAt.After(now) {
		c.removeLocked(ent)
		return nil
	}
	c.lru.MoveToFront(ent.listElem)
	return ent
}

func (c *Cache) removeLocked(ent *cachedEntry) {
	if ent.listElem != nil {
		c.lru.Remove(ent.listElem)
		ent.listElem = nil
	}
	delete(c.entries, ent.key)
	for _, tag := range ent.tags {
		if keySet := c.tagIndex[tag]; keySet != nil {
			delete(keySet, ent.key)
			if len(keySet) == 0 {
				delete(c.tagIndex, tag)
			}
		}
	}
	c.usedBytes -= ent.sizeBytes
	if c.usedBytes < 0 {
		c.usedBytes = 0
	}
}

func (c *Cache) put(key string, status int, srcHdr http.Header, body []byte, now time.Time) *cachedEntry {
	return c.putWithOptions(key, "", "", status, srcHdr, body, c.ttl, nil, now)
}

// putWithOptions validates, clones, indexes surrogate tags, and stores an entry
// under c's byte ceiling, evicting LRU entries as needed.
//
// # Parameters
//
//   - key: Cache key.
//   - host: Optional explicit host; defaults to host parsed from key.
//   - path: Optional explicit path; defaults to path parsed from key.
//   - status: HTTP status code.
//   - srcHdr: Response headers.
//   - body: Response body bytes.
//   - ttl: Entry lifetime.
//   - extraTags: Optional explicit surrogate tags merged with header tags.
//   - now: Current timestamp.
//
// # Returns
//
// Stored *cachedEntry pointer, or nil if the entry exceeds MaxBytes.
//
// # Example
//
//	ent := c.putWithOptions(key, "", "", 200, hdr, body, c.ttl, tags, time.Now())
//	_ = ent
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/microcache/microcache.go:592 (function value)
//   - internal/microcache/microcache.go:819 (function value)
//   - internal/microcache/microcache.go:1292 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Cache) putWithOptions(key, host, path string, status int, srcHdr http.Header, body []byte, ttl time.Duration, extraTags []string, now time.Time) *cachedEntry {
	cpBody := append([]byte(nil), body...)
	cpHdr := cloneCacheHeaders(srcHdr)
	tags := extractTagsBounded(srcHdr, extraTags, c.maxTagsPerEntry)
	tagBytes := 0
	for _, t := range tags {
		tagBytes += len(t)
	}

	normHost := strings.ToLower(strings.TrimSpace(host))
	if normHost == "" || path == "" {
		ph, pp := cache.ParseCanonicalKey(key)
		if normHost == "" {
			normHost = ph
		}
		if path == "" {
			path = pp
		}
	}

	size := int64(len(cpBody) + len(key) + len(normHost) + len(path) + tagBytes + 256)
	if size > c.maxBytes {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.entries[key]; ok {
		c.removeLocked(old)
	}
	for c.usedBytes+size > c.maxBytes && c.lru.Len() > 0 {
		back := c.lru.Back()
		if back == nil {
			break
		}
		victim := back.Value.(*cachedEntry)
		if victim.expiresAt.After(now) {
			c.evictions.Add(1)
		}
		c.removeLocked(victim)
	}
	if size > c.maxBytes {
		return nil
	}
	ent := &cachedEntry{
		key:       key,
		host:      normHost,
		path:      path,
		status:    status,
		headers:   cpHdr,
		body:      cpBody,
		tags:      tags,
		storedAt:  now,
		expiresAt: now.Add(ttl),
		sizeBytes: size,
	}
	ent.listElem = c.lru.PushFront(ent)
	c.entries[key] = ent
	for _, tag := range tags {
		keySet := c.tagIndex[tag]
		if keySet == nil {
			keySet = make(map[string]struct{})
			c.tagIndex[tag] = keySet
		}
		keySet[key] = struct{}{}
	}
	c.usedBytes += size
	return ent
}

// extractTagsBounded collects normalized, deduplicated surrogate tags from
// response headers and extraTags up to maxTags entries.
//
// # Parameters
//
//   - hdr: Optional response headers checked for Surrogate-Key, Cache-Tag, and X-Cache-Tags.
//   - extraTags: Optional explicit caller tags.
//   - maxTags: Hard cap on returned tag count.
//
// # Returns
//
// Bounded slice of normalized tags or nil when empty.
//
// # Example
//
//	tags := extractTagsBounded(hdr, []string{"product:1"}, 64)
//	_ = tags
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/microcache/microcache.go:670 (function value)
//   - internal/microcache/microcache.go:1333 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func extractTagsBounded(hdr http.Header, extraTags []string, maxTags int) []string {
	if maxTags <= 0 {
		maxTags = DefaultMaxTagsPerEntry
	}
	var (
		seen map[string]struct{}
		out  []string
	)
	addTag := func(raw string) {
		if len(out) >= maxTags {
			return
		}
		t := strings.ToLower(strings.TrimSpace(raw))
		if t == "" || len(t) > DefaultMaxTagBytes || strings.ContainsAny(t, "\r\n\x00") {
			return
		}
		if seen == nil {
			seen = make(map[string]struct{})
		}
		if _, dup := seen[t]; dup {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}

	for _, t := range extraTags {
		addTag(t)
	}
	if hdr != nil {
		for _, v := range hdr.Values("Surrogate-Key") {
			for _, tok := range strings.Fields(v) {
				addTag(tok)
			}
		}
		for _, headerName := range []string{"Cache-Tag", "X-Cache-Tags"} {
			for _, v := range hdr.Values(headerName) {
				for _, tok := range strings.Split(v, ",") {
					addTag(tok)
				}
			}
		}
	}
	return out
}

// snapshotEntry deep-copies an internal cachedEntry into a caller-owned Entry.
//
// # Parameters
//
//   - ent: Stored entry read under c.mu.
//
// # Returns
//
// Independent Entry copy.
//
// # Example
//
//	out := snapshotEntry(ent)
//	_ = out
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/microcache/microcache.go:636 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func snapshotEntry(ent *cachedEntry) Entry {
	var hdr http.Header
	if len(ent.headers) > 0 {
		hdr = make(http.Header, len(ent.headers))
		for k, vals := range ent.headers {
			hdr[k] = append([]string(nil), vals...)
		}
	}
	var tags []string
	if len(ent.tags) > 0 {
		tags = append([]string(nil), ent.tags...)
	}
	return Entry{
		Key:       ent.key,
		Host:      ent.host,
		Path:      ent.path,
		Status:    ent.status,
		Headers:   hdr,
		Body:      append([]byte(nil), ent.body...),
		Tags:      tags,
		StoredAt:  ent.storedAt,
		ExpiresAt: ent.expiresAt,
	}
}

func cloneCacheHeaders(src http.Header) http.Header {
	dst := make(http.Header, len(src))
	for k, vals := range src {
		lk := strings.ToLower(k)
		// Never cache hop-by-hop, cookie, or Concert internal headers.
		switch lk {
		case "set-cookie", "connection", "keep-alive", "transfer-encoding", "upgrade",
			"proxy-authenticate", "proxy-authorization", "te", "trailers",
			"x-concert-cache", "age", "concert-priority":
			continue
		}
		dst[k] = append([]string(nil), vals...)
	}
	return dst
}

func writeCachedEntry(w http.ResponseWriter, r *http.Request, ent *cachedEntry, now time.Time) {
	dst := w.Header()
	for k, vals := range ent.headers {
		dst[k] = append([]string(nil), vals...)
	}
	age := int(now.Sub(ent.storedAt) / time.Second)
	if age < 0 {
		age = 0
	}
	dst.Set("X-Concert-Cache", "HIT")
	dst.Set("Age", strconv.Itoa(age))
	dst.Set("Content-Length", strconv.Itoa(len(ent.body)))
	w.WriteHeader(ent.status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(ent.body)
	}
}

// ─── bounded response capture writer ─────────────────────────────────────────

type captureWriter struct {
	target   http.ResponseWriter
	maxBytes int64
	header   http.Header
	status   int
	buf      bytes.Buffer
	streamed bool
}

func newCaptureWriter(w http.ResponseWriter, maxBytes int64) *captureWriter {
	return &captureWriter{
		target:   w,
		maxBytes: maxBytes,
		header:   make(http.Header),
	}
}

func (w *captureWriter) Header() http.Header {
	if w.streamed {
		return w.target.Header()
	}
	return w.header
}

func (w *captureWriter) WriteHeader(code int) {
	if w.streamed {
		w.target.WriteHeader(code)
		return
	}
	if w.status != 0 {
		return
	}
	w.status = code
	// Fast-path stream directly if status or headers already preclude caching.
	if code != http.StatusOK || len(w.header.Values("Set-Cookie")) > 0 {
		w.switchToStream()
	}
}

func (w *captureWriter) Write(p []byte) (int, error) {
	if w.streamed {
		return w.target.Write(p)
	}
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
		if w.streamed {
			return w.target.Write(p)
		}
	}
	if int64(w.buf.Len()+len(p)) > w.maxBytes {
		w.switchToStream()
		return w.target.Write(p)
	}
	return w.buf.Write(p)
}

func (w *captureWriter) Flush() {
	if w.streamed {
		if fl, ok := w.target.(http.Flusher); ok {
			fl.Flush()
		}
	}
}

func (w *captureWriter) switchToStream() {
	if w.streamed {
		return
	}
	w.streamed = true
	dst := w.target.Header()
	for k, vals := range w.header {
		dst[k] = append([]string(nil), vals...)
	}
	dst.Set("X-Concert-Cache", "BYPASS")
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	w.target.WriteHeader(status)
	if w.buf.Len() > 0 {
		_, _ = w.target.Write(w.buf.Bytes())
		w.buf.Reset()
	}
}

func (w *captureWriter) flushToTarget(cached bool) {
	if w.streamed {
		return
	}
	dst := w.target.Header()
	for k, vals := range w.header {
		dst[k] = append([]string(nil), vals...)
	}
	if cached {
		dst.Set("X-Concert-Cache", "MISS")
	} else {
		dst.Set("X-Concert-Cache", "BYPASS")
	}
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	w.target.WriteHeader(status)
	if w.buf.Len() > 0 {
		_, _ = w.target.Write(w.buf.Bytes())
	}
}
