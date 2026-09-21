package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/andreimerlescu/goenv/env"
	"github.com/andreimerlescu/room"
	"github.com/gin-gonic/gin"
)

// ctxAdmitted is set on the gin.Context the moment a request reaches the
// proxy handler. Anything written before that point was written by room.
const ctxAdmitted = "roomproxy.admitted"

// shutdownGrace bounds how long in-flight requests get to finish on SIGTERM.
const shutdownGrace = 30 * time.Second

// Cookies room owns. None of them are forwarded to the upstream.
//
//	room_ticket — HttpOnly queue session
//	room_pass   — HttpOnly VIP pass
//	room_probe  — non-HttpOnly cookie-support probe (added in 1.2.1)
var roomCookies = []string{"room_ticket", "room_pass", "room_probe"}

type config struct {
	listen        string
	upstream      string
	capacity      int
	maxQueue      int64
	reaper        time.Duration
	tokenTTL      time.Duration
	secureCookie  bool
	cookiePath    string
	cookieDomain  string
	preserveHost  bool
	bypass        string
	htmlFile      string
	skipURL       string
	rate          float64
	surge         float64
	passDuration  time.Duration
	headerTimeout time.Duration
	apiJSON       bool
	retryAfter    int
	adminToken    string

	// Derived / non-flag fields.
	target    *url.URL  // set by normalize
	accessLog io.Writer // gin access log destination; nil means os.Stdout
}

type counters struct {
	queued   atomic.Int64
	evicted  atomic.Int64
	timeouts atomic.Int64
	promoted atomic.Int64
}

// app is a fully wired proxy that has not yet been bound to a listener.
type app struct {
	cfg     config
	room    *room.WaitingRoom
	stats   *counters
	handler http.Handler
}

func main() {
	cfg, showVersion, err := parseConfig(flag.CommandLine, os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	if showVersion {
		fmt.Println(BinaryVersion())
		return
	}

	gin.SetMode(gin.ReleaseMode)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}

// ─── configuration ───────────────────────────────────────────────────────────

// parseConfig defines every flag on fs, with defaults drawn from the
// environment, and parses args. Environment variables are read at call time,
// so tests can drive them with t.Setenv. The returned bool reports -version;
// when it is true the config is not validated.
func parseConfig(fs *flag.FlagSet, args []string) (config, bool, error) {
	var cfg config
	fs.StringVar(&cfg.listen, "listen", env.String("CONCERT_LISTEN", ":8080"), "address to listen on")
	fs.StringVar(&cfg.upstream, "upstream", env.String("CONCERT_UPSTREAM", "http://127.0.0.1:3000"), "origin to proxy to")
	fs.IntVar(&cfg.capacity, "cap", env.Int("CONCERT_CAPACITY", 500), "max concurrent requests allowed through to the upstream")
	fs.Int64Var(&cfg.maxQueue, "max-queue", env.Int64("CONCERT_MAX_QUEUE", 10000), "reject with 503 beyond this queue depth (0 = unlimited)")
	fs.DurationVar(&cfg.reaper, "reaper", env.Duration("CONCERT_REAPER", 30*time.Second), "reaper interval for abandoned tickets")
	fs.DurationVar(&cfg.tokenTTL, "token-ttl", env.Duration("CONCERT_TOKEN_TTL", 0), "sliding TTL for queued tokens, 30s-24h (0 = room default, 5m)")
	fs.BoolVar(&cfg.secureCookie, "secure-cookie", env.Bool("CONCERT_SECURE_COOKIE", false), "set Secure on room cookies (only if browsers reach you over HTTPS)")
	fs.StringVar(&cfg.cookiePath, "cookie-path", env.String("CONCERT_COOKIE_PATH", "/"), "room cookie path")
	fs.StringVar(&cfg.cookieDomain, "cookie-domain", env.String("CONCERT_COOKIE_DOMAIN", ""), "room cookie domain")
	fs.BoolVar(&cfg.preserveHost, "preserve-host", env.Bool("CONCERT_PRESERVE_HOST", true), "forward the client's Host header to the upstream")
	fs.StringVar(&cfg.bypass, "bypass", env.String("CONCERT_BYPASS", "/favicon.ico"), "comma-separated paths that skip the queue; suffix /* for a prefix")
	fs.StringVar(&cfg.htmlFile, "html", env.String("CONCERT_HTML_FILE", ""), "custom waiting room HTML (must handle cookies_required and room_probe)")
	fs.StringVar(&cfg.skipURL, "skip-url", env.String("CONCERT_SKIP_URL", ""), "payment page URL; enables the skip-the-line card")
	fs.Float64Var(&cfg.rate, "rate", env.Float64("CONCERT_RATE", 0), "base cost per queue position (0 disables promotion)")
	fs.Float64Var(&cfg.surge, "surge", env.Float64("CONCERT_SURGE", 0), "extra cost per position for each client in the queue")
	fs.DurationVar(&cfg.passDuration, "pass", env.Duration("CONCERT_PASS_DURATION", 0), "VIP pass lifetime (0 disables passes)")
	fs.DurationVar(&cfg.headerTimeout, "upstream-timeout", env.Duration("CONCERT_UPSTREAM_TIMEOUT", 30*time.Second), "upstream response header timeout")
	fs.BoolVar(&cfg.apiJSON, "api-json", env.Bool("CONCERT_API_JSON", true), "answer queued non-HTML clients with JSON 429 instead of the HTML page")
	fs.IntVar(&cfg.retryAfter, "retry-after", env.Int("CONCERT_RETRY_AFTER", 5), "Retry-After seconds sent to queued API clients")
	showVersion := fs.Bool("version", false, "show version")

	if err := fs.Parse(args); err != nil {
		return config{}, false, err
	}
	cfg.adminToken = env.String("CONCERT_ADMIN_TOKEN", "")
	cfg.accessLog = os.Stdout

	if *showVersion {
		return cfg, true, nil
	}
	if err := cfg.normalize(); err != nil {
		return config{}, false, err
	}
	return cfg, false, nil
}

// normalize validates the config and fills derived fields. It is idempotent.
func (c *config) normalize() error {
	u, err := url.Parse(c.upstream)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid -upstream %q: must look like http://host:port", c.upstream)
	}
	c.target = u

	if c.capacity < 1 || c.capacity > math.MaxInt32 {
		return fmt.Errorf("invalid -cap %d: must be between 1 and %d", c.capacity, math.MaxInt32)
	}
	if c.retryAfter < 1 {
		c.retryAfter = 1
	}
	return nil
}

// ─── assembly ────────────────────────────────────────────────────────────────

// newApp builds the waiting room, proxy, and router without binding a port.
// Callers must Close the returned app.
func newApp(cfg config) (*app, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}

	wr := &room.WaitingRoom{}
	if err := wr.Init(int32(cfg.capacity)); err != nil {
		return nil, fmt.Errorf("room init: %w", err)
	}

	stats := &counters{}
	if err := configureRoom(wr, cfg, stats); err != nil {
		wr.Stop()
		return nil, fmt.Errorf("room config: %w", err)
	}

	proxy := newProxy(cfg.target, cfg.preserveHost, cfg.headerTimeout)
	engine := newRouter(cfg, wr, stats, forwardTo(proxy))

	return &app{cfg: cfg, room: wr, stats: stats, handler: engine}, nil
}

// Close stops the waiting room's background workers.
func (a *app) Close() {
	a.room.Stop()
}

// run builds the app, binds cfg.listen, and serves until ctx is cancelled.
func run(ctx context.Context, cfg config) error {
	a, err := newApp(cfg)
	if err != nil {
		return err
	}
	defer a.Close()

	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.listen, err)
	}

	log.Printf("room proxy %s -> %s (cap=%d, max-queue=%d, token-ttl=%s)",
		ln.Addr(), a.cfg.target, cfg.capacity, cfg.maxQueue, a.room.TokenTTL())

	return serve(ctx, ln, a.handler, shutdownGrace)
}

// serve runs h on ln until ctx is cancelled, then drains for up to grace.
// It returns nil on a clean shutdown.
func serve(ctx context.Context, ln net.Listener, h http.Handler, grace time.Duration) error {
	srv := newServer(h)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case err := <-errCh:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	log.Println("draining...")
	sctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	log.Println("stopped")
	return nil
}

func newServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout: it would cut off streamed and upgraded responses.
	}
}

// newRouter wires routes in the order that determines what is gated:
// ops and bypass routes first (ungated), then the API interceptor, then
// room's middleware, then the proxy catch-all (gated).
func newRouter(cfg config, wr *room.WaitingRoom, stats *counters, forward gin.HandlerFunc) *gin.Engine {
	r := gin.New()

	// A proxy must forward paths exactly as received. Gin's defaults would
	// answer "/foo/" with a 301 to "/foo" instead of passing it upstream.
	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false
	r.HandleMethodNotAllowed = false
	_ = r.SetTrustedProxies(nil)

	logOut := cfg.accessLog
	if logOut == nil {
		logOut = os.Stdout
	}
	r.Use(gin.Recovery())
	r.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		Output:    logOut,
		SkipPaths: []string{"/queue/status", "/_room/healthz"},
	}))

	// ---- Registered BEFORE the room middleware: never queued. ----
	registerOps(r, wr, cfg, stats)
	registerBypass(r, cfg.bypass, forward)

	// ---- Runs ahead of room's middleware on gated requests only. ----
	if cfg.apiJSON {
		r.Use(apiQueueResponses(cfg.retryAfter))
	}

	// ---- Attaches room's middleware and GET /queue/status. ----
	wr.RegisterRoutes(r)

	// ---- Everything else: gated, then proxied. ----
	// Gin rebuilds the NoRoute chain on every Use(), so this catch-all
	// inherits Recovery, Logger, the API interceptor, and room's middleware.
	r.NoRoute(forward)

	return r
}

// forwardTo marks the request as admitted and hands it to the proxy.
func forwardTo(proxy http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(ctxAdmitted, true)
		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

// ─── room configuration ──────────────────────────────────────────────────────

func configureRoom(wr *room.WaitingRoom, cfg config, stats *counters) error {
	wr.SetSecureCookie(cfg.secureCookie)
	wr.SetCookiePath(cfg.cookiePath)
	if cfg.cookieDomain != "" {
		wr.SetCookieDomain(cfg.cookieDomain)
	}
	if err := wr.SetMaxQueueDepth(cfg.maxQueue); err != nil {
		return err
	}
	if err := wr.SetReaperInterval(cfg.reaper); err != nil {
		return err
	}
	if cfg.tokenTTL > 0 {
		if err := wr.SetTokenTTL(cfg.tokenTTL); err != nil {
			return err
		}
	}
	if cfg.htmlFile != "" {
		html, err := os.ReadFile(cfg.htmlFile)
		if err != nil {
			return err
		}
		wr.SetHTML(html)
		log.Printf("custom waiting room loaded from %s — it must treat cookies_required as terminal "+
			"and check document.cookie for room_probe before its first poll", cfg.htmlFile)
	}
	if cfg.rate > 0 {
		base, surge := cfg.rate, cfg.surge
		wr.SetRateFunc(func(depth int64) float64 {
			return base + float64(depth)*surge
		})
		if cfg.skipURL != "" {
			wr.SetSkipURL(cfg.skipURL)
		}
	}
	if cfg.passDuration > 0 {
		if err := wr.SetPassDuration(cfg.passDuration); err != nil {
			return err
		}
	}

	// Edge-triggered: these fire once per transition, safe to log.
	wr.On(room.EventFull, func(s room.Snapshot) {
		log.Printf("upstream saturated: %d/%d slots, %d queued (%d live)",
			s.Occupancy, s.Capacity, s.QueueDepth, wr.LiveQueueDepth())
	})
	wr.On(room.EventDrain, func(s room.Snapshot) {
		log.Printf("draining: %d/%d slots, %d queued (%d live)",
			s.Occupancy, s.Capacity, s.QueueDepth, wr.LiveQueueDepth())
	})

	// Per-request events: count, don't log. Evictions in particular can be
	// frequent when scripts without cookie jars retry against a full room.
	wr.On(room.EventQueue, func(room.Snapshot) { stats.queued.Add(1) })
	wr.On(room.EventEvict, func(room.Snapshot) { stats.evicted.Add(1) })
	wr.On(room.EventTimeout, func(room.Snapshot) { stats.timeouts.Add(1) })
	wr.On(room.EventPromote, func(room.Snapshot) { stats.promoted.Add(1) })
	return nil
}

// ─── ungated routes ──────────────────────────────────────────────────────────

func registerOps(r *gin.Engine, wr *room.WaitingRoom, cfg config, stats *counters) {
	r.GET("/_room/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	r.GET("/_room/stats", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"upstream":         cfg.upstream,
			"cap":              wr.Cap(),
			"occupancy":        wr.Len(),
			"queue_depth":      wr.QueueDepth(),
			"live_queue_depth": wr.LiveQueueDepth(),
			"max_queue_depth":  wr.MaxQueueDepth(),
			"utilization":      wr.UtilizationSmoothed(),
			"token_ttl":        wr.TokenTTL().String(),
			"queued_total":     stats.queued.Load(),
			"evicted_total":    stats.evicted.Load(),
			"timeouts_total":   stats.timeouts.Load(),
			"promoted_total":   stats.promoted.Load(),
		})
	})

	r.POST("/_room/cap", func(c *gin.Context) {
		if cfg.adminToken == "" {
			c.Status(http.StatusNotFound)
			return
		}
		got := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(cfg.adminToken)) != 1 {
			c.Status(http.StatusUnauthorized)
			return
		}
		var body struct {
			Cap int32 `json:"cap"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := wr.SetCap(body.Cap); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"cap": wr.Cap(), "occupancy": wr.Len()})
	})
}

// registerBypass wires paths that should never be queued straight to the
// proxy. "/static/*" means the whole prefix; "/favicon.ico" means that exact
// path. Bypassed paths have NO protection — keep them cheap for the origin.
func registerBypass(r *gin.Engine, spec string, forward gin.HandlerFunc) {
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" || !strings.HasPrefix(entry, "/") {
			continue
		}
		if strings.HasSuffix(entry, "/*") {
			r.Any(strings.TrimSuffix(entry, "/*")+"/*filepath", forward)
		} else {
			r.Any(entry, forward)
		}
		log.Printf("bypass: %s", entry)
	}
}

// ─── API client interceptor ──────────────────────────────────────────────────

// apiQueueResponses rewrites room's own responses (waiting-room HTML, breaker
// 503) into JSON for clients that did not ask for HTML. It applies only to
// gated catch-all requests: registered routes (/queue/status, /_room/*,
// bypass paths) have a non-empty FullPath and are left alone.
func apiQueueResponses(retryAfter int) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.FullPath() != "" || wantsHTML(c.Request) {
			c.Next()
			return
		}
		c.Writer = &apiQueueWriter{
			ResponseWriter: c.Writer,
			c:              c,
			retryAfter:     retryAfter,
		}
		c.Next()
	}
}

func wantsHTML(r *http.Request) bool {
	return strings.Contains(strings.Join(r.Header.Values("Accept"), ","), "text/html")
}

// apiQueueWriter decides once, at the first header or body write, whether
// the response came from room (proxy not reached) or from the upstream
// (proxy reached). Upstream responses pass through untouched, including
// streaming, flushing, and connection hijacking for upgrades.
type apiQueueWriter struct {
	gin.ResponseWriter
	c          *gin.Context
	retryAfter int
	decided    bool
	swallow    bool
}

func (w *apiQueueWriter) WriteHeader(code int) {
	if w.decided {
		if !w.swallow {
			w.ResponseWriter.WriteHeader(code)
		}
		return
	}
	w.decided = true

	if w.c.GetBool(ctxAdmitted) {
		w.ResponseWriter.WriteHeader(code)
		return
	}

	// room is answering this request itself. Keep its Set-Cookie headers so
	// clients with a cookie jar hold their place, replace everything else.
	w.swallow = true
	status, body := w.translate(code)

	h := w.ResponseWriter.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
		h.Set("Retry-After", strconv.Itoa(w.retryAfter))
	}

	w.ResponseWriter.WriteHeader(status)
	w.ResponseWriter.WriteHeaderNow()
	_, _ = w.ResponseWriter.Write(body)
}

func (w *apiQueueWriter) WriteHeaderNow() {
	if !w.decided {
		w.WriteHeader(w.ResponseWriter.Status())
	}
	if !w.swallow {
		w.ResponseWriter.WriteHeaderNow()
	}
}

func (w *apiQueueWriter) Write(b []byte) (int, error) {
	if !w.decided {
		w.WriteHeader(w.ResponseWriter.Status())
	}
	if w.swallow {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func (w *apiQueueWriter) WriteString(s string) (int, error) {
	if !w.decided {
		w.WriteHeader(w.ResponseWriter.Status())
	}
	if w.swallow {
		return len(s), nil
	}
	return w.ResponseWriter.WriteString(s)
}

func (w *apiQueueWriter) Flush() {
	if !w.decided {
		w.WriteHeader(w.ResponseWriter.Status())
	}
	w.ResponseWriter.Flush()
}

func (w *apiQueueWriter) translate(code int) (int, []byte) {
	switch code {
	case http.StatusOK:
		// The waiting-room page. The client is queued.
		return http.StatusTooManyRequests, mustJSON(gin.H{
			"queued":              true,
			"status_url":          "/queue/status",
			"retry_after_seconds": w.retryAfter,
			"hint":                "keep the room_ticket cookie and retry to hold your position",
		})
	case http.StatusServiceUnavailable:
		// Breaker tripped or admission timed out.
		return http.StatusServiceUnavailable, mustJSON(gin.H{
			"queued":              false,
			"error":               "waiting room is full",
			"retry_after_seconds": w.retryAfter,
		})
	default:
		return code, mustJSON(gin.H{"error": http.StatusText(code)})
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"error":"internal"}`)
	}
	return b
}

// ─── reverse proxy ───────────────────────────────────────────────────────────

func newProxy(target *url.URL, preserveHost bool, headerTimeout time.Duration) *httputil.ReverseProxy {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: headerTimeout,
	}

	return &httputil.ReverseProxy{
		Transport: transport,
		// -1 flushes immediately, which keeps SSE and chunked responses live.
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			if preserveHost {
				pr.Out.Host = pr.In.Host
				pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			}
			stripCookies(pr.Out, roomCookies...)
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return // client hung up; nothing to report
			}
			log.Printf("upstream error %s %s: %v", req.Method, req.URL.Path, err)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("upstream unavailable\n"))
		},
	}
}

func stripCookies(req *http.Request, names ...string) {
	cookies := req.Cookies()
	if len(cookies) == 0 {
		return
	}
	drop := make(map[string]struct{}, len(names))
	for _, n := range names {
		drop[n] = struct{}{}
	}
	req.Header.Del("Cookie")
	for _, c := range cookies {
		if _, skip := drop[c.Name]; skip {
			continue
		}
		req.AddCookie(c)
	}
}
