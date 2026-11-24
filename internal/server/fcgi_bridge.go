//go:build wordpress || enterprise

package server

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/fcgi"
	"github.com/andreimerlescu/concert/internal/microcache"
	"github.com/andreimerlescu/concert/internal/wp"
	"github.com/gin-gonic/gin"
)

func hasWordPressEdition() bool { return true }

type fcgiTransport = fcgi.Transport
type pageMicroCache = microcache.Cache

func isFastCGITarget(u *url.URL) bool {
	return fcgi.IsFastCGI(u)
}

func validateFastCGITarget(u *url.URL) error {
	_, _, err := fcgi.ParseTarget(u)
	return err
}

func newFCGITransportWithStats(cfg config, stats *counters) (*fcgiTransport, error) {
	return fcgi.NewTransport(fcgi.Config{
		Root:          cfg.staticRoot,
		Index:         cfg.fcgiIndex,
		DenyPaths:     cfg.parsedFCGIDenyPaths,
		HeaderTimeout: cfg.headerTimeout,
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

func buildMicroCache(cfg config, stats *counters) *pageMicroCache {
	if cfg.microCacheTTL <= 0 {
		return nil
	}
	maxBytes := int64(cfg.microCacheMaxMB) << 20
	if maxBytes <= 0 {
		maxBytes = microcache.DefaultMaxBytes
	}
	return microcache.New(microcache.Config{
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
}

func sameMicroCache(a, b config) bool {
	return a.microCacheTTL == b.microCacheTTL && a.microCacheMaxMB == b.microCacheMaxMB
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
// the bounded in-memory micro-cache (with singleflight stampede coalescing)
// ahead of the waiting room. Logged-in, cart, checkout, POST, and private
// responses bypass cleanly into the waiting room and priority lane.
func (g *generation) microCacheMiddleware(c *gin.Context) {
	if g.microCache == nil {
		return
	}
	p := c.Request.URL.Path
	if strings.HasPrefix(p, "/_room") || strings.HasPrefix(p, "/_concert") || p == "/queue/status" || isTicketStatus(p) {
		return
	}
	aw := &admitOn200Writer{ResponseWriter: c.Writer, req: c.Request, admit: g.a.admit}
	handled := g.microCache.Serve(aw, c.Request, func(w http.ResponseWriter, r *http.Request) {
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
		mcBytes = g.microCache.BytesUsed()
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
