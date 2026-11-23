// Package microcache provides a pure-stdlib, byte-bounded in-memory anonymous
// GET/HEAD response micro-cache with singleflight stampede coalescing and
// fail-safe WordPress/WooCommerce cookie/path/header bypass rules.
package microcache

import (
	"bytes"
	"container/list"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultMaxBytes      int64 = 64 << 20 // 64 MiB
	DefaultMaxEntryBytes int64 = 1 << 20  // 1 MiB
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
	BypassPaths          []string
	BypassCookiePrefixes []string
	BypassQueryKeys      []string

	OnHit       func()
	OnMiss      func()
	OnBypass    func()
	OnCoalesced func()
}

type pathMatcher struct {
	exact  string
	prefix string
}

type cachedEntry struct {
	key       string
	status    int
	headers   http.Header
	body      []byte
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
// coalescing. A nil *Cache is safe and always bypasses.
type Cache struct {
	ttl            time.Duration
	maxBytes       int64
	maxEntryBytes  int64
	bypassPaths    []pathMatcher
	bypassCookies  []string
	bypassQuerySet map[string]bool

	onHit       func()
	onMiss      func()
	onBypass    func()
	onCoalesced func()

	mu        sync.Mutex
	entries   map[string]*cachedEntry
	lru       *list.List // front = MRU, back = LRU
	usedBytes int64
	inflight  map[string]*inflightCall
}

// New constructs a Cache. Returns nil when cfg.TTL <= 0 (disabled).
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
		ttl:            cfg.TTL,
		maxBytes:       maxBytes,
		maxEntryBytes:  maxEntry,
		bypassPaths:    matchers,
		bypassCookies:  normCookies,
		bypassQuerySet: qset,
		onHit:          cfg.OnHit,
		onMiss:         cfg.OnMiss,
		onBypass:       cfg.OnBypass,
		onCoalesced:    cfg.OnCoalesced,
		entries:        make(map[string]*cachedEntry),
		lru:            list.New(),
		inflight:       make(map[string]*inflightCall),
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
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cachedEntry)
	c.lru.Init()
	c.usedBytes = 0
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
	now := time.Now()

	c.mu.Lock()
	if ent := c.getLocked(key, now); ent != nil {
		c.mu.Unlock()
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
				if c.onHit != nil {
					c.onHit()
				}
				if c.onCoalesced != nil {
					c.onCoalesced()
				}
				writeCachedEntry(w, r, call.entry, time.Now())
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
				stored = c.put(key, status, capW.header, body, time.Now())
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
	if now.After(ent.expiresAt) {
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
	c.usedBytes -= ent.sizeBytes
	if c.usedBytes < 0 {
		c.usedBytes = 0
	}
}

func (c *Cache) put(key string, status int, srcHdr http.Header, body []byte, now time.Time) *cachedEntry {
	cpBody := append([]byte(nil), body...)
	cpHdr := cloneCacheHeaders(srcHdr)
	size := int64(len(cpBody) + len(key) + 256)

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
		c.removeLocked(back.Value.(*cachedEntry))
	}
	if size > c.maxBytes {
		return nil
	}
	ent := &cachedEntry{
		key:       key,
		status:    status,
		headers:   cpHdr,
		body:      cpBody,
		storedAt:  now,
		expiresAt: now.Add(c.ttl),
		sizeBytes: size,
	}
	ent.listElem = c.lru.PushFront(ent)
	c.entries[key] = ent
	c.usedBytes += size
	return ent
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
