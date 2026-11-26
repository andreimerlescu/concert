//go:build wordpress || enterprise

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/andreimerlescu/concert/internal/cache"
	"github.com/andreimerlescu/concert/internal/fcgi"
	"github.com/andreimerlescu/concert/internal/microcache"
	"github.com/andreimerlescu/concert/internal/wp"
	"github.com/gin-gonic/gin"
)

func hasWordPressEdition() bool { return true }

type fcgiTransport = fcgi.Transport

// pageMicroCache wraps either the in-process internal/microcache.Cache (for
// small/single hosts) or a pooled external internal/cache.Client (when
// -cache-addr is configured), exposing a uniform cache.PageCache purge port
// with fail-open degradation on external daemon outage.
type pageMicroCache struct {
	local      *microcache.Cache
	remote     *cache.Client
	port       cache.PageCache
	bypassGate *microcache.Cache
	ttl        time.Duration
	maxEntry   int64
	stats      *counters

	sfMu     sync.Mutex
	inflight map[string]*remoteInflight
}

type remoteInflight struct {
	done  chan struct{}
	entry *cache.Entry
}

func isFastCGITarget(u *url.URL) bool {
	return fcgi.IsFastCGI(u)
}

func validateFastCGITarget(u *url.URL) error {
	_, _, err := fcgi.ParseTarget(u)
	return err
}

func newFCGITransportWithStats(cfg config, stats *counters) (*fcgiTransport, error) {
	return fcgi.NewTransport(fcgi.Config{
		Root:            cfg.staticRoot,
		Index:           cfg.fcgiIndex,
		DenyPaths:       cfg.parsedFCGIDenyPaths,
		HeaderTimeout:   cfg.headerTimeout,
		BodyIdleTimeout: cfg.upstreamBodyIdleTimeout,
		OnStderr: func(msg string) {
			log.Printf("fcgi stderr: %s", clip(msg, 512))
		},
		OnRequest: func() {
			if stats != nil {
				stats.fcgiRequests.Add(1)
			}
		},
		OnDenied: func(string) {
			if stats != nil {
				stats.fcgiDenied.Add(1)
			}
		},
	})
}

func closeFCGITransport(tr *fcgiTransport) {
	if tr != nil {
		_ = tr.Close()
	}
}

func dialCheckFCGI(ctx context.Context, tr *fcgiTransport, target *url.URL) error {
	return tr.DialCheck(ctx, target)
}

func roundTripFCGI(tr *fcgiTransport, req *http.Request, target *url.URL) (*http.Response, error) {
	return tr.RoundTripTo(req, target)
}

func withFastCGIClientIP(req *http.Request, ip string) *http.Request {
	if ip == "" {
		return req
	}
	return req.WithContext(fcgi.WithClientIP(req.Context(), ip))
}

func withFastCGIBodyAbort(req *http.Request, fn func() bool) *http.Request {
	if fn == nil {
		return req
	}
	return req.WithContext(fcgi.WithBodyAbort(req.Context(), fn))
}

func withFastCGIStream(req *http.Request) *http.Request {
	if req == nil {
		return nil
	}
	return req.WithContext(fcgi.WithStream(req.Context()))
}

// buildMicroCache constructs the generation's page cache: an external pooled
// concert-cache client when -cache-addr is configured, or the bounded
// in-process microcache when -micro-cache-ttl > 0.
func buildMicroCache(cfg config, stats *counters) (*pageMicroCache, error) {
	if addr := strings.TrimSpace(cfg.cacheAddr); addr != "" {
		var tlsCfg *tls.Config
		if cfg.cacheTLS && !strings.HasPrefix(addr, "/") && !strings.HasPrefix(addr, "unix://") {
			host, _, _ := net.SplitHostPort(addr)
			tlsCfg = &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: host,
			}
		}
		ttl := cfg.microCacheTTL
		if ttl <= 0 {
			ttl = 15 * time.Second
		}
		cli, err := cache.NewClient(cache.ClientConfig{
			Address:    addr,
			Secret:     cfg.cacheSecret,
			TLSConfig:  tlsCfg,
			FailClosed: false,
		})
		if err != nil {
			return nil, err
		}
		return &pageMicroCache{
			remote:     cli,
			port:       cli,
			bypassGate: microcache.New(microcache.Config{TTL: ttl, MaxBytes: microcache.DefaultMaxEntryBytes}),
			ttl:        ttl,
			maxEntry:   microcache.DefaultMaxEntryBytes,
			stats:      stats,
			inflight:   make(map[string]*remoteInflight),
		}, nil
	}
	if cfg.microCacheTTL <= 0 {
		return nil, nil
	}
	maxBytes := int64(cfg.microCacheMaxMB) << 20
	if maxBytes <= 0 {
		maxBytes = microcache.DefaultMaxBytes
	}
	mc := microcache.New(microcache.Config{
		TTL:           cfg.microCacheTTL,
		MaxBytes:      maxBytes,
		MaxEntryBytes: microcache.DefaultMaxEntryBytes,
		OnHit: func() {
			if stats != nil {
				stats.microCacheHits.Add(1)
			}
		},
		OnMiss: func() {
			if stats != nil {
				stats.microCacheMisses.Add(1)
			}
		},
		OnBypass: func() {
			if stats != nil {
				stats.microCacheBypasses.Add(1)
			}
		},
		OnCoalesced: func() {
			if stats != nil {
				stats.microCacheCoalesced.Add(1)
			}
		},
	})
	return &pageMicroCache{
		local:    mc,
		port:     mc.AsPageCache(),
		ttl:      cfg.microCacheTTL,
		maxEntry: microcache.DefaultMaxEntryBytes,
		stats:    stats,
	}, nil
}

func sameMicroCache(a, b config) bool {
	secEq := (a.cacheSecret.IsZero() && b.cacheSecret.IsZero()) ||
		(!a.cacheSecret.IsZero() && !b.cacheSecret.IsZero() && a.cacheSecret.Equal([]byte(b.cacheSecret.Reveal())))
	return a.microCacheTTL == b.microCacheTTL &&
		a.microCacheMaxMB == b.microCacheMaxMB &&
		a.cacheAddr == b.cacheAddr &&
		a.cacheTLS == b.cacheTLS &&
		secEq
}

func (p *pageMicroCache) close() {
	if p == nil || p.port == nil {
		return
	}
	_ = p.port.Close()
}

func (p *pageMicroCache) bytesUsed() int64 {
	if p == nil {
		return 0
	}
	if p.local != nil {
		return p.local.BytesUsed()
	}
	if p.remote != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		st, err := p.remote.Stats(ctx)
		cancel()
		if err == nil {
			return st.UsedBytes
		}
	}
	return 0
}

// purge removes entries from the active page cache (built-in microcache or
// external concert-cache daemon) via the cache.PageCache port.
func (p *pageMicroCache) purge(ctx context.Context, mode, host, target string) (int, error) {
	if p == nil || p.port == nil {
		return 0, errors.New("page cache is not enabled")
	}
	switch mode {
	case "url":
		return p.port.PurgeURL(ctx, host, target)
	case "prefix":
		return p.port.PurgePrefix(ctx, host, target)
	case "tag":
		return p.port.PurgeTag(ctx, target)
	case "all":
		return p.port.PurgeAll(ctx)
	default:
		return 0, errors.New(`mode must be "url", "prefix", "tag", or "all"`)
	}
}

func (p *pageMicroCache) serve(w http.ResponseWriter, r *http.Request, fetch func(http.ResponseWriter, *http.Request)) bool {
	if p == nil {
		return false
	}
	if p.local != nil {
		return p.local.Serve(w, r, fetch)
	}
	return p.serveRemote(w, r, fetch)
}

// serveRemote serves anonymous cacheable GET/HEAD requests against an external
// concert-cache daemon with in-process singleflight stampede collapse and
// fail-open fallback when the cache daemon is unavailable.
func (p *pageMicroCache) serveRemote(w http.ResponseWriter, r *http.Request, fetch func(http.ResponseWriter, *http.Request)) bool {
	if p.remote == nil || p.bypassGate.ShouldBypassRequest(r) {
		if p.stats != nil {
			p.stats.microCacheBypasses.Add(1)
		}
		w.Header().Set("X-Concert-Cache", "BYPASS")
		return false
	}

	key := microcache.BuildKey(r)
	if ent, ok, err := p.remote.Get(r.Context(), key); err == nil && ok {
		if p.stats != nil {
			p.stats.microCacheHits.Add(1)
		}
		writeCachedPageEntry(w, r.Method, ent, "HIT")
		return true
	}

	p.sfMu.Lock()
	if existing, ok := p.inflight[key]; ok {
		p.sfMu.Unlock()
		select {
		case <-existing.done:
		case <-r.Context().Done():
			return false
		}
		if existing.entry != nil {
			if p.stats != nil {
				p.stats.microCacheCoalesced.Add(1)
				p.stats.microCacheHits.Add(1)
			}
			writeCachedPageEntry(w, r.Method, *existing.entry, "HIT")
			return true
		}
		return false
	}
	call := &remoteInflight{done: make(chan struct{})}
	p.inflight[key] = call
	p.sfMu.Unlock()

	var stored *cache.Entry
	defer func() {
		call.entry = stored
		p.sfMu.Lock()
		delete(p.inflight, key)
		p.sfMu.Unlock()
		close(call.done)
	}()

	capW := &remoteCaptureWriter{
		dst:      w,
		hdr:      make(http.Header),
		maxBytes: p.maxEntry,
	}
	fetch(capW, r)
	if capW.passthrough {
		// Response exceeded maxEntry or streamed directly; already written to dst.
		if p.stats != nil {
			p.stats.microCacheBypasses.Add(1)
		}
		return true
	}
	status := capW.status
	if status == 0 {
		status = http.StatusOK
	}
	body := capW.buf.Bytes()
	if microcache.ShouldCacheResponse(status, capW.hdr, int64(len(body)), p.maxEntry) {
		ent := cache.Entry{
			Key:     key,
			Status:  status,
			Headers: cloneCacheHeaders(capW.hdr),
			Body:    append([]byte(nil), body...),
			Tags:    microcache.ExtractTags(capW.hdr),
			TTL:     p.ttl,
		}
		_ = p.remote.Put(r.Context(), ent) // fail-open client absorbs transport errors
		stored = &ent
		if p.stats != nil {
			p.stats.microCacheMisses.Add(1)
		}
		writeCachedPageEntry(w, r.Method, ent, "MISS")
		return true
	}

	if p.stats != nil {
		p.stats.microCacheBypasses.Add(1)
	}
	dstH := w.Header()
	for k, vs := range capW.hdr {
		dstH[k] = append([]string(nil), vs...)
	}
	dstH.Set("X-Concert-Cache", "BYPASS")
	w.WriteHeader(status)
	if r.Method != http.MethodHead && len(body) > 0 {
		_, _ = w.Write(body)
	}
	return true
}

func cloneCacheHeaders(src http.Header) http.Header {
	dst := make(http.Header, len(src))
	for k, vs := range src {
		if strings.EqualFold(k, "Set-Cookie") {
			continue
		}
		dst[k] = append([]string(nil), vs...)
	}
	return dst
}

func writeCachedPageEntry(w http.ResponseWriter, method string, ent cache.Entry, cacheStatus string) {
	dst := w.Header()
	for k, vs := range ent.Headers {
		dst[k] = append([]string(nil), vs...)
	}
	dst.Set("X-Concert-Cache", cacheStatus)
	status := ent.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if method != http.MethodHead && len(ent.Body) > 0 {
		_, _ = w.Write(ent.Body)
	}
}

type remoteCaptureWriter struct {
	dst         http.ResponseWriter
	hdr         http.Header
	buf         bytes.Buffer
	status      int
	maxBytes    int64
	passthrough bool
}

func (w *remoteCaptureWriter) Header() http.Header {
	if w.passthrough {
		return w.dst.Header()
	}
	return w.hdr
}

func (w *remoteCaptureWriter) WriteHeader(code int) {
	if w.passthrough {
		w.dst.WriteHeader(code)
		return
	}
	if w.status == 0 {
		w.status = code
	}
}

func (w *remoteCaptureWriter) Write(p []byte) (int, error) {
	if w.passthrough {
		return w.dst.Write(p)
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if int64(w.buf.Len()+len(p)) > w.maxBytes {
		w.passthrough = true
		dstH := w.dst.Header()
		for k, vs := range w.hdr {
			dstH[k] = append([]string(nil), vs...)
		}
		dstH.Set("X-Concert-Cache", "BYPASS")
		w.dst.WriteHeader(w.status)
		if w.buf.Len() > 0 {
			if _, err := w.dst.Write(w.buf.Bytes()); err != nil {
				return 0, err
			}
			w.buf.Reset()
		}
		return w.dst.Write(p)
	}
	return w.buf.Write(p)
}

// admitOn200Writer issues or refreshes concert_admit on 200 OK micro-cache
// responses so anonymous visitors served from the micro-cache immediately
// hold a valid pass for pass-gated /wp-content/* static assets.
type admitOn200Writer struct {
	http.ResponseWriter
	req    *http.Request
	admit  *admitter
	wrote  bool
	forged bool
}

func (w *admitOn200Writer) ensureAdmit(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	if code == http.StatusOK && w.admit != nil {
		if _, status := w.admit.refresh(w.ResponseWriter, w.req, time.Now()); status == passForged {
			w.forged = true
		}
	}
}

func (w *admitOn200Writer) WriteHeader(code int) {
	w.ensureAdmit(code)
	w.ResponseWriter.WriteHeader(code)
}

func (w *admitOn200Writer) Write(p []byte) (int, error) {
	w.ensureAdmit(http.StatusOK)
	return w.ResponseWriter.Write(p)
}

func (w *admitOn200Writer) Flush() {
	if fl, ok := w.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func (w *admitOn200Writer) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// microCacheMiddleware serves eligible anonymous GET/HEAD page requests from
// the bounded in-memory micro-cache or external concert-cache daemon (with
// singleflight stampede coalescing) ahead of the waiting room. Logged-in, cart,
// checkout, POST, and private responses bypass cleanly into the waiting room
// and priority lane.
func (g *generation) microCacheMiddleware(c *gin.Context) {
	if g.microCache == nil {
		return
	}
	p := c.Request.URL.Path
	if strings.HasPrefix(p, "/_room") || strings.HasPrefix(p, "/_concert") || p == "/queue/status" || isTicketStatus(p) {
		return
	}
	aw := &admitOn200Writer{ResponseWriter: c.Writer, req: c.Request, admit: g.a.admit}
	handled := g.microCache.serve(aw, c.Request, func(w http.ResponseWriter, r *http.Request) {
		// Ensure Concert-Priority grants can still bind if the leader hits a
		// non-cacheable origin response carrying Concert-Priority.
		req := selectBackendForRequest(r, g.upstreams)
		req = g.edgeClaim(c, req)
		if hopIP, ok := hopInClientIP(req.Context()); ok {
			req = withFastCGIClientIP(req, hopIP.String())
		} else if ip := clientIPFrom(c); ip.IsValid() {
			req = withFastCGIClientIP(req, ip.String())
		}
		g.proxy.ServeHTTP(w, req)
	})
	if aw.forged {
		g.strike(c, strikeForgedPass)
	}
	if handled {
		c.Set(ctxAdmitted, true)
		c.Abort()
	}
}

func writeWordPressMetrics(b *strings.Builder, g *generation, stats *counters) {
	writePromMetric(b, "concert_microcache_hits_total", "counter", "Anonymous page responses served from the in-memory micro-cache.", stats.microCacheHits.Load())
	writePromMetric(b, "concert_microcache_misses_total", "counter", "Cacheable anonymous page requests fetched from upstream.", stats.microCacheMisses.Load())
	writePromMetric(b, "concert_microcache_bypasses_total", "counter", "Requests bypassing the micro-cache (logged-in, cart, POST, or uncacheable response).", stats.microCacheBypasses.Load())
	writePromMetric(b, "concert_microcache_coalesced_total", "counter", "Concurrent cold-URL requests collapsed via singleflight onto one upstream fetch.", stats.microCacheCoalesced.Load())
	var mcBytes int64
	if g != nil && g.microCache != nil {
		mcBytes = g.microCache.bytesUsed()
	}
	writePromMetric(b, "concert_microcache_bytes", "gauge", "Current byte footprint of the in-memory anonymous micro-cache.", mcBytes)
}

func wordpressSettingDefs() []settingDef {
	return []settingDef{
		{key: "fcgi_index", flag: "fcgi-index", env: "CONCERT_FCGI_INDEX", group: groupOrigin, label: "FastCGI index script",
			def: "index.php", usage: "entrypoint script for FastCGI try_files fallback and directory index",
			ptr: func(c *config) any { return &c.fcgiIndex }},
		{key: "fcgi_deny_paths", flag: "fcgi-deny-paths", env: "CONCERT_FCGI_DENY_PATHS", group: groupOrigin, label: "FastCGI denied paths", restart: true,
			def: "/wp-content/uploads/*,/wp-config.php", usage: "comma-separated paths blocked from FastCGI PHP execution with 403 (restart to change)",
			ptr: func(c *config) any { return &c.fcgiDenyPaths }, check: checkPathList},
		{key: "micro_cache_ttl", flag: "micro-cache-ttl", env: "CONCERT_MICRO_CACHE_TTL", group: groupOrigin, label: "Anonymous GET micro-cache TTL",
			def: time.Duration(0), usage: "in-memory anonymous GET/HEAD page micro-cache TTL with stampede collapse (0 disables; e.g. 15s)",
			ptr: func(c *config) any { return &c.microCacheTTL }, check: durationAtLeast(0)},
		{key: "micro_cache_max_mb", flag: "micro-cache-max-mb", env: "CONCERT_MICRO_CACHE_MAX_MB", group: groupOrigin, label: "Micro-cache max memory (MiB)",
			def: 64, usage: "maximum memory budget in MiB for the in-memory anonymous GET micro-cache (1-4096)",
			ptr: func(c *config) any { return &c.microCacheMaxMB }, check: intBetween(1, 4096)},
		{key: "cache_addr", flag: "cache-addr", env: "CONCERT_CACHE_ADDR", group: groupOrigin, label: "External concert-cache address", restart: true,
			def: "", usage: "TCP host:port or Unix socket path of external concert-cache daemon (empty uses built-in in-process micro-cache; requires CONCERT_CACHE_SECRET[_FILE])",
			ptr: func(c *config) any { return &c.cacheAddr }},
		{key: "cache_tls", flag: "cache-tls", env: "CONCERT_CACHE_TLS", group: groupOrigin, label: "External concert-cache TLS", restart: true,
			def: false, usage: "use TLS 1.2+ when connecting to external concert-cache over TCP",
			ptr: func(c *config) any { return &c.cacheTLS }},
		{key: "wp_preset", flag: "wp-preset", env: "CONCERT_WP_PRESET", group: groupOrigin, label: "WordPress security & asset preset", restart: true,
			def: false, usage: "apply opinionated WordPress/WooCommerce asset gating, /xmlrpc.php denial, and uploads PHP execution block",
			ptr: func(c *config) any { return &c.wpPreset }},
	}
}

func movedWordPressFlags() map[string]string { return nil }

func wordpressSubcommand(name string) func([]string, io.Writer) error {
	switch name {
	case "doctor":
		return wp.RunDoctorCLI
	case "init":
		return wp.RunInit
	}
	return nil
}

func applyWordPressPreset(cfg *config) error {
	if strings.TrimSpace(cfg.assets) == "" {
		cfg.assets = "/wp-content/*,/wp-includes/*"
	}
	if strings.TrimSpace(cfg.fcgiIndex) == "" {
		cfg.fcgiIndex = "index.php"
	}
	if strings.TrimSpace(cfg.fcgiDenyPaths) == "" {
		cfg.fcgiDenyPaths = "/wp-content/uploads/*,/wp-config.php,/xmlrpc.php"
	} else if !strings.Contains(cfg.fcgiDenyPaths, "/xmlrpc.php") {
		cfg.fcgiDenyPaths += ",/xmlrpc.php"
	}
	if strings.TrimSpace(cfg.banPaths) == "" && cfg.abuseEnabled {
		cfg.banPaths = "/xmlrpc.php"
	}
	// WordPress/WooCommerce checkouts routinely run 45s+ PHP scripts.
	if cfg.headerTimeout == 0 || cfg.headerTimeout == 60*time.Second || cfg.headerTimeout == 30*time.Second {
		cfg.headerTimeout = 90 * time.Second
	}
	return nil
}
