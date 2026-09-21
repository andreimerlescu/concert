package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/andreimerlescu/goenv/env"
	"github.com/andreimerlescu/room"
	"github.com/andreimerlescu/sema"
	"github.com/gin-gonic/gin"
)

// ctxAdmitted is set on the gin.Context the moment a request reaches the
// proxy handler. Anything written before that point was written by room.
const ctxAdmitted = "concert.admitted"

// shutdownGrace bounds how long in-flight requests get to finish on SIGTERM.
const shutdownGrace = 30 * time.Second

// Admission pass layout: id(16) | expiry unix seconds(8) | truncated HMAC-SHA256(16),
// base64url encoded without padding.
const (
	admitCookie  = "concert_admit"
	passIDLen    = 16
	passExpLen   = 8
	passMACLen   = 16
	passBodyLen  = passIDLen + passExpLen
	passRawLen   = passBodyLen + passMACLen
	minSecretLen = 32
)

// userShards must be a power of two. Pass IDs are random, so the first byte
// distributes users evenly across shards.
const userShards = 64

// Cookies owned by concert and room. None of them are forwarded upstream.
//
//	room_ticket   — HttpOnly queue session
//	room_pass     — HttpOnly VIP pass
//	room_probe    — non-HttpOnly cookie-support probe
//	concert_admit — HttpOnly signed admission pass for the asset tier
var proxyCookies = []string{"room_ticket", "room_pass", "room_probe", admitCookie}

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

	assets            string
	assetPublic       string
	assetCap          int
	assetWait         time.Duration
	assetUserCapH1    int
	assetUserCapH2    int
	assetUserWait     time.Duration
	admitTTL          time.Duration
	clientProtoHeader string
	accessLogEnabled  bool

	// Derived / non-flag fields.
	admitSecret          []byte    // CONCERT_ADMIT_SECRET, or random when unset
	admitSecretGenerated bool      // true when admitSecret was generated
	target               *url.URL  // set by normalize
	accessLog            io.Writer // access log destination; nil means os.Stdout
}

type counters struct {
	queued   atomic.Int64
	evicted  atomic.Int64
	timeouts atomic.Int64
	promoted atomic.Int64

	assetServed          atomic.Int64
	assetDenied          atomic.Int64
	assetUserThrottled   atomic.Int64
	assetGlobalThrottled atomic.Int64
}

// app is a fully wired proxy that has not yet been bound to a listener.
type app struct {
	cfg      config
	room     *room.WaitingRoom
	stats    *counters
	admit    *admitter
	assets   *assetGuard
	forward  gin.HandlerFunc
	handler  http.Handler
	stop     chan struct{}
	stopOnce sync.Once
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
	fs.IntVar(&cfg.capacity, "cap", env.Int("CONCERT_CAPACITY", 500), "max concurrent page requests allowed through to the upstream")
	fs.Int64Var(&cfg.maxQueue, "max-queue", env.Int64("CONCERT_MAX_QUEUE", 10000), "reject with 503 beyond this queue depth (0 = unlimited)")
	fs.DurationVar(&cfg.reaper, "reaper", env.Duration("CONCERT_REAPER", 30*time.Second), "reaper interval for abandoned tickets")
	fs.DurationVar(&cfg.tokenTTL, "token-ttl", env.Duration("CONCERT_TOKEN_TTL", 0), "sliding TTL for queued tokens, 30s-24h (0 = room default, 5m)")
	fs.BoolVar(&cfg.secureCookie, "secure-cookie", env.Bool("CONCERT_SECURE_COOKIE", false), "set Secure on cookies (only if browsers reach you over HTTPS)")
	fs.StringVar(&cfg.cookiePath, "cookie-path", env.String("CONCERT_COOKIE_PATH", "/"), "cookie path")
	fs.StringVar(&cfg.cookieDomain, "cookie-domain", env.String("CONCERT_COOKIE_DOMAIN", ""), "cookie domain")
	fs.BoolVar(&cfg.preserveHost, "preserve-host", env.Bool("CONCERT_PRESERVE_HOST", true), "forward the client's Host header to the upstream")
	fs.StringVar(&cfg.bypass, "bypass", env.String("CONCERT_BYPASS", "/favicon.ico"), "comma-separated paths that skip every guard; suffix /* for a prefix")
	fs.StringVar(&cfg.htmlFile, "html", env.String("CONCERT_HTML_FILE", ""), "custom waiting room HTML (must handle cookies_required and room_probe)")
	fs.StringVar(&cfg.skipURL, "skip-url", env.String("CONCERT_SKIP_URL", ""), "payment page URL; enables the skip-the-line card")
	fs.Float64Var(&cfg.rate, "rate", env.Float64("CONCERT_RATE", 0), "base cost per queue position (0 disables promotion)")
	fs.Float64Var(&cfg.surge, "surge", env.Float64("CONCERT_SURGE", 0), "extra cost per position for each client in the queue")
	fs.DurationVar(&cfg.passDuration, "pass", env.Duration("CONCERT_PASS_DURATION", 0), "VIP pass lifetime (0 disables passes)")
	fs.DurationVar(&cfg.headerTimeout, "upstream-timeout", env.Duration("CONCERT_UPSTREAM_TIMEOUT", 30*time.Second), "upstream response header timeout")
	fs.BoolVar(&cfg.apiJSON, "api-json", env.Bool("CONCERT_API_JSON", true), "answer queued non-HTML clients with JSON 429 instead of the HTML page")
	fs.IntVar(&cfg.retryAfter, "retry-after", env.Int("CONCERT_RETRY_AFTER", 5), "Retry-After seconds sent to queued API clients")
	fs.StringVar(&cfg.assets, "assets", env.String("CONCERT_ASSETS", ""), "comma-separated asset paths that require an admission pass; suffix /* for a prefix")
	fs.StringVar(&cfg.assetPublic, "asset-public", env.String("CONCERT_ASSET_PUBLIC", ""), "comma-separated asset paths served without a pass, still under the global asset cap")
	fs.IntVar(&cfg.assetCap, "asset-cap", env.Int("CONCERT_ASSET_CAP", 0), "global concurrent asset requests (0 = cap × asset-user-cap-h2)")
	fs.DurationVar(&cfg.assetWait, "asset-wait", env.Duration("CONCERT_ASSET_WAIT", 2*time.Second), "max wait for a global asset slot before 503")
	fs.IntVar(&cfg.assetUserCapH1, "asset-user-cap-h1", env.Int("CONCERT_ASSET_USER_CAP_H1", 8), "concurrent asset requests per pass over HTTP/1.x")
	fs.IntVar(&cfg.assetUserCapH2, "asset-user-cap-h2", env.Int("CONCERT_ASSET_USER_CAP_H2", 128), "concurrent asset requests per pass over HTTP/2 and HTTP/3")
	fs.DurationVar(&cfg.assetUserWait, "asset-user-wait", env.Duration("CONCERT_ASSET_USER_WAIT", 2*time.Second), "max wait for a per-pass asset slot before 429")
	fs.DurationVar(&cfg.admitTTL, "admit-ttl", env.Duration("CONCERT_ADMIT_TTL", 10*time.Minute), "sliding lifetime of the admission pass (min 30s)")
	fs.StringVar(&cfg.clientProtoHeader, "client-proto-header", env.String("CONCERT_CLIENT_PROTO_HEADER", ""), "header set by a trusted TLS terminator carrying the client's HTTP protocol")
	fs.BoolVar(&cfg.accessLogEnabled, "access-log", env.Bool("CONCERT_ACCESS_LOG", true), "write an access log line per non-asset request")
	showVersion := fs.Bool("version", false, "show version")

	if err := fs.Parse(args); err != nil {
		return config{}, false, err
	}
	cfg.adminToken = env.String("CONCERT_ADMIN_TOKEN", "")
	cfg.admitSecret = []byte(env.String("CONCERT_ADMIT_SECRET", ""))
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
	if c.assetCap < 0 || c.assetCap > math.MaxInt32 {
		return fmt.Errorf("invalid -asset-cap %d: must be 0 (derived) or between 1 and %d", c.assetCap, math.MaxInt32)
	}
	if c.assetUserCapH1 < 1 {
		return fmt.Errorf("invalid -asset-user-cap-h1 %d: must be at least 1", c.assetUserCapH1)
	}
	if c.assetUserCapH2 < 1 {
		return fmt.Errorf("invalid -asset-user-cap-h2 %d: must be at least 1", c.assetUserCapH2)
	}
	if c.assetWait < 0 || c.assetUserWait < 0 {
		return errors.New("-asset-wait and -asset-user-wait must not be negative")
	}
	if c.admitTTL < 30*time.Second {
		return fmt.Errorf("invalid -admit-ttl %s: must be at least 30s", c.admitTTL)
	}

	if len(c.admitSecret) == 0 {
		secret := make([]byte, minSecretLen)
		if _, err := rand.Read(secret); err != nil {
			return fmt.Errorf("generate admit secret: %w", err)
		}
		c.admitSecret = secret
		c.admitSecretGenerated = true
	} else if len(c.admitSecret) < minSecretLen {
		return fmt.Errorf("CONCERT_ADMIT_SECRET must be at least %d bytes", minSecretLen)
	}

	return validateRoutes(c)
}

// effectiveAssetCap is -asset-cap when set, otherwise cap × asset-user-cap-h2,
// clamped to MaxInt32.
func (c config) effectiveAssetCap() int {
	if c.assetCap > 0 {
		return c.assetCap
	}
	n := int64(c.capacity) * int64(c.assetUserCapH2)
	if n > math.MaxInt32 {
		n = math.MaxInt32
	}
	return int(n)
}

// ─── path rules ──────────────────────────────────────────────────────────────

type pathRule struct {
	path   string
	prefix bool
}

// parsePaths reads "/static/*,/robots.txt" style lists. Entries not starting
// with "/" are ignored.
func parsePaths(spec string) []pathRule {
	var rules []pathRule
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" || !strings.HasPrefix(entry, "/") {
			continue
		}
		if strings.HasSuffix(entry, "/*") {
			rules = append(rules, pathRule{path: strings.TrimSuffix(entry, "/*"), prefix: true})
			continue
		}
		rules = append(rules, pathRule{path: entry})
	}
	return rules
}

func (p pathRule) pattern() string {
	if p.prefix {
		return p.path + "/*filepath"
	}
	return p.path
}

func (p pathRule) matches(path string) bool {
	if p.prefix {
		return strings.HasPrefix(path, p.path+"/")
	}
	return path == p.path
}

// validateRoutes catches the mistakes that are cheap to detect up front.
// Structural conflicts gin detects itself are converted to errors in buildRouter.
func validateRoutes(c *config) error {
	seen := map[string]string{}
	groups := []struct{ flag, spec string }{
		{"-bypass", c.bypass},
		{"-assets", c.assets},
		{"-asset-public", c.assetPublic},
	}
	for _, g := range groups {
		for _, r := range parsePaths(g.spec) {
			if r.prefix && r.path == "" {
				return fmt.Errorf("%s: \"/*\" would capture every path", g.flag)
			}
			if r.path == "/queue/status" || r.path == "/_room" || strings.HasPrefix(r.path, "/_room/") {
				return fmt.Errorf("%s: %s is reserved by concert", g.flag, r.path)
			}
			if prev, dup := seen[r.pattern()]; dup {
				return fmt.Errorf("%s: %s is already listed in %s", g.flag, r.path, prev)
			}
			seen[r.pattern()] = g.flag
		}
	}
	return nil
}

// ─── assembly ────────────────────────────────────────────────────────────────

// newApp builds the waiting room, asset tier, proxy, and router without
// binding a port. Callers must Close the returned app.
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

	global, err := sema.New(cfg.effectiveAssetCap())
	if err != nil {
		wr.Stop()
		return nil, fmt.Errorf("asset semaphore: %w", err)
	}

	admit := &admitter{
		secret: cfg.admitSecret,
		ttl:    cfg.admitTTL,
		path:   cfg.cookiePath,
		domain: cfg.cookieDomain,
		secure: cfg.secureCookie,
	}

	a := &app{
		cfg:   cfg,
		room:  wr,
		stats: stats,
		admit: admit,
		assets: &assetGuard{
			admit:       admit,
			users:       newUserStore(cfg.assetUserCapH1, cfg.assetUserCapH2),
			global:      global,
			userWait:    cfg.assetUserWait,
			globalWait:  cfg.assetWait,
			protoHeader: cfg.clientProtoHeader,
			stats:       stats,
		},
		forward: forwardTo(newProxy(cfg.target, cfg.preserveHost, cfg.headerTimeout)),
		stop:    make(chan struct{}),
	}

	handler, err := buildRouter(a)
	if err != nil {
		wr.Stop()
		return nil, err
	}
	a.handler = handler

	go a.assets.users.janitor(janitorInterval(cfg.admitTTL), cfg.admitTTL, a.stop)
	return a, nil
}

// Close stops the janitor and the waiting room's background workers.
func (a *app) Close() {
	a.stopOnce.Do(func() {
		close(a.stop)
		a.room.Stop()
	})
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

	derived := ""
	if a.cfg.assetCap == 0 {
		derived = " (derived)"
	}
	log.Printf("concert %s -> %s (cap=%d, max-queue=%d, token-ttl=%s, asset-cap=%d%s, asset-user-cap=%d h1 / %d h2)",
		ln.Addr(), a.cfg.target, a.cfg.capacity, a.cfg.maxQueue, a.room.TokenTTL(),
		a.assets.global.Cap(), derived, a.cfg.assetUserCapH1, a.cfg.assetUserCapH2)
	if a.cfg.admitSecretGenerated {
		log.Printf("CONCERT_ADMIT_SECRET not set: using a random secret; admission passes reset on restart and are not shared across instances")
	}

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

// buildRouter wires routes in the order that determines what is guarded:
// ops, bypass, and asset routes first (outside the room), then the API
// interceptor, then room's middleware, then the gated proxy catch-all.
// Route conflicts make gin panic; they are returned as errors instead.
func buildRouter(a *app) (engine *gin.Engine, err error) {
	defer func() {
		if p := recover(); p != nil {
			engine = nil
			err = fmt.Errorf("route registration: %v", p)
		}
	}()

	cfg := a.cfg
	r := gin.New()

	// A proxy must forward paths exactly as received. Gin's defaults would
	// answer "/foo/" with a 301 to "/foo" instead of passing it upstream.
	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false
	r.HandleMethodNotAllowed = false
	_ = r.SetTrustedProxies(nil)

	r.Use(gin.Recovery())
	if cfg.accessLogEnabled {
		out := cfg.accessLog
		if out == nil {
			out = os.Stdout
		}
		r.Use(gin.LoggerWithConfig(gin.LoggerConfig{
			Output: out,
			Skip:   accessLogSkipper(cfg),
		}))
	}

	// ---- Outside the room. ----
	registerOps(r, a)
	registerPaths(r, parsePaths(cfg.bypass), a.forward)
	registerPaths(r, parsePaths(cfg.assets), a.assets.private, a.forward)
	registerPaths(r, parsePaths(cfg.assetPublic), a.assets.public, a.forward)

	// ---- Runs ahead of room's middleware on gated requests only. ----
	if cfg.apiJSON {
		r.Use(apiQueueResponses(cfg.retryAfter))
	}

	// ---- Attaches room's middleware and GET /queue/status. ----
	a.room.RegisterRoutes(r)

	// ---- Everything else: gated, then proxied. ----
	// Gin rebuilds the NoRoute chain on every Use(), so this catch-all
	// inherits Recovery, Logger, the API interceptor, and room's middleware.
	r.NoRoute(a.gated)

	return r, nil
}

func registerPaths(r *gin.Engine, rules []pathRule, handlers ...gin.HandlerFunc) {
	for _, rule := range rules {
		r.Any(rule.pattern(), handlers...)
	}
}

// accessLogSkipper keeps asset traffic and pollers out of the access log.
// Assets are the bulk of requests; a log line each would dominate I/O.
func accessLogSkipper(cfg config) func(*gin.Context) bool {
	quiet := append(parsePaths(cfg.assets), parsePaths(cfg.assetPublic)...)
	quiet = append(quiet, pathRule{path: "/queue/status"}, pathRule{path: "/_room/healthz"})
	return func(c *gin.Context) bool {
		p := c.Request.URL.Path
		for _, rule := range quiet {
			if rule.matches(p) {
				return true
			}
		}
		return false
	}
}

// gated handles requests room has admitted: issue or refresh the admission
// pass, then proxy.
func (a *app) gated(c *gin.Context) {
	a.admit.refresh(c.Writer, c.Request, time.Now())
	a.forward(c)
}

// forwardTo marks the request as admitted and hands it to the proxy.
func forwardTo(proxy http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(ctxAdmitted, true)
		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

func janitorInterval(ttl time.Duration) time.Duration {
	if iv := ttl / 2; iv > 10*time.Second {
		return iv
	}
	return 10 * time.Second
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

	// Per-request events: count, don't log.
	wr.On(room.EventQueue, func(room.Snapshot) { stats.queued.Add(1) })
	wr.On(room.EventEvict, func(room.Snapshot) { stats.evicted.Add(1) })
	wr.On(room.EventTimeout, func(room.Snapshot) { stats.timeouts.Add(1) })
	wr.On(room.EventPromote, func(room.Snapshot) { stats.promoted.Add(1) })
	return nil
}

// ─── ops routes ──────────────────────────────────────────────────────────────

func registerOps(r *gin.Engine, a *app) {
	cfg, wr, stats, assets := a.cfg, a.room, a.stats, a.assets

	r.GET("/_room/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	r.GET("/_room/stats", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"upstream":                     cfg.upstream,
			"cap":                          wr.Cap(),
			"occupancy":                    wr.Len(),
			"queue_depth":                  wr.QueueDepth(),
			"live_queue_depth":             wr.LiveQueueDepth(),
			"max_queue_depth":              wr.MaxQueueDepth(),
			"utilization":                  wr.UtilizationSmoothed(),
			"token_ttl":                    wr.TokenTTL().String(),
			"queued_total":                 stats.queued.Load(),
			"evicted_total":                stats.evicted.Load(),
			"timeouts_total":               stats.timeouts.Load(),
			"promoted_total":               stats.promoted.Load(),
			"asset_cap":                    assets.global.Cap(),
			"asset_in_flight":              assets.global.Len(),
			"asset_users":                  assets.users.count.Load(),
			"asset_user_cap_h1":            cfg.assetUserCapH1,
			"asset_user_cap_h2":            cfg.assetUserCapH2,
			"asset_served_total":           stats.assetServed.Load(),
			"asset_denied_total":           stats.assetDenied.Load(),
			"asset_user_throttled_total":   stats.assetUserThrottled.Load(),
			"asset_global_throttled_total": stats.assetGlobalThrottled.Load(),
		})
	})

	// Changes the page cap only. The asset cap is fixed at startup: sema's
	// SetCap drains every slot when shrinking, which would break in-flight
	// asset releases.
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

// ─── admission pass ──────────────────────────────────────────────────────────

type passID [passIDLen]byte

func newPassID() (passID, error) {
	var id passID
	_, err := rand.Read(id[:])
	return id, err
}

// admitter issues and verifies the signed concert_admit cookie. Verification
// is stateless, so any instance sharing CONCERT_ADMIT_SECRET accepts a pass.
type admitter struct {
	secret []byte
	ttl    time.Duration
	path   string
	domain string
	secure bool
}

func (a *admitter) mint(id passID, now time.Time) string {
	var buf [passRawLen]byte
	copy(buf[:passIDLen], id[:])
	binary.BigEndian.PutUint64(buf[passIDLen:passBodyLen], uint64(now.Add(a.ttl).Unix()))
	mac := hmac.New(sha256.New, a.secret)
	mac.Write(buf[:passBodyLen])
	copy(buf[passBodyLen:], mac.Sum(nil)[:passMACLen])
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

// verify returns the pass ID and expiry when the value is authentic and unexpired.
func (a *admitter) verify(value string, now time.Time) (passID, time.Time, bool) {
	var id passID
	if base64.RawURLEncoding.DecodedLen(len(value)) != passRawLen {
		return id, time.Time{}, false
	}
	var buf [passRawLen]byte
	n, err := base64.RawURLEncoding.Decode(buf[:], []byte(value))
	if err != nil || n != passRawLen {
		return id, time.Time{}, false
	}
	mac := hmac.New(sha256.New, a.secret)
	mac.Write(buf[:passBodyLen])
	if !hmac.Equal(buf[passBodyLen:], mac.Sum(nil)[:passMACLen]) {
		return id, time.Time{}, false
	}
	exp := time.Unix(int64(binary.BigEndian.Uint64(buf[passIDLen:passBodyLen])), 0)
	if !now.Before(exp) {
		return id, time.Time{}, false
	}
	copy(id[:], buf[:passIDLen])
	return id, exp, true
}

func (a *admitter) set(w http.ResponseWriter, id passID, now time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     admitCookie,
		Value:    a.mint(id, now),
		Path:     a.path,
		Domain:   a.domain,
		MaxAge:   int(a.ttl / time.Second),
		Secure:   a.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// refresh runs on every admitted page request. A valid pass is re-signed only
// past half its lifetime, so most responses carry no Set-Cookie and stay
// cacheable. A missing or invalid pass is replaced with a new one.
func (a *admitter) refresh(w http.ResponseWriter, r *http.Request, now time.Time) {
	if ck, err := r.Cookie(admitCookie); err == nil {
		if id, exp, ok := a.verify(ck.Value, now); ok {
			if exp.Sub(now) <= a.ttl/2 {
				a.set(w, id, now)
			}
			return
		}
	}
	id, err := newPassID()
	if err != nil {
		return // no entropy: serve the page without a pass
	}
	a.set(w, id, now)
}

// check runs on every private asset request. It also slides the pass past
// half-life, so pages that lazy-load assets without navigating stay admitted.
func (a *admitter) check(w http.ResponseWriter, r *http.Request, now time.Time) (passID, bool) {
	ck, err := r.Cookie(admitCookie)
	if err != nil {
		return passID{}, false
	}
	id, exp, ok := a.verify(ck.Value, now)
	if !ok {
		return passID{}, false
	}
	if exp.Sub(now) <= a.ttl/2 {
		a.set(w, id, now)
	}
	return id, true
}

// ─── asset tier ──────────────────────────────────────────────────────────────

// userStore holds one pair of semaphores per admission pass. Entries exist
// only for authentic passes, so the map is bounded by admitted users within
// the pass lifetime.
type userStore struct {
	shards [userShards]userShard
	h1Cap  int
	h2Cap  int
	count  atomic.Int64
}

type userShard struct {
	mu sync.Mutex
	m  map[passID]*userSlots
}

// userSlots keeps separate pools per protocol family. sema.SetCap drains when
// shrinking, so a single semaphore can't be resized when a user's protocol
// changes; two lazily created ones avoid that.
type userSlots struct {
	lastSeen int64 // unix nanos, guarded by the shard mutex
	h1       sema.Semaphore
	h2       sema.Semaphore
}

func newUserStore(h1Cap, h2Cap int) *userStore {
	s := &userStore{h1Cap: h1Cap, h2Cap: h2Cap}
	for i := range s.shards {
		s.shards[i].m = make(map[passID]*userSlots)
	}
	return s
}

// slot returns the user's semaphore for the protocol family, creating the
// entry and semaphore on first use. lastSeen is updated under the lock so the
// janitor can never evict an entry between lookup and acquire.
func (s *userStore) slot(id passID, multiplexed bool, now int64) sema.Semaphore {
	sh := &s.shards[id[0]&(userShards-1)]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	u, ok := sh.m[id]
	if !ok {
		u = &userSlots{}
		sh.m[id] = u
		s.count.Add(1)
	}
	u.lastSeen = now

	if multiplexed {
		if u.h2 == nil {
			u.h2 = sema.Must(s.h2Cap)
		}
		return u.h2
	}
	if u.h1 == nil {
		u.h1 = sema.Must(s.h1Cap)
	}
	return u.h1
}

// sweep evicts entries idle since before cutoff with nothing in flight.
func (s *userStore) sweep(cutoff int64) int {
	evicted := 0
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for id, u := range sh.m {
			if u.lastSeen < cutoff && semIdle(u.h1) && semIdle(u.h2) {
				delete(sh.m, id)
				evicted++
			}
		}
		sh.mu.Unlock()
	}
	s.count.Add(int64(-evicted))
	return evicted
}

func (s *userStore) janitor(every, idle time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			s.sweep(now.Add(-idle).UnixNano())
		}
	}
}

func semIdle(s sema.Semaphore) bool {
	return s == nil || s.Len() == 0
}

// assetGuard admits asset requests through two semaphores: the caller's
// per-pass pool first, so an abusive pass is rejected before it can take a
// global slot, then the global pool that protects the host.
//
// This is the hot path: no logging, counters only.
type assetGuard struct {
	admit       *admitter
	users       *userStore
	global      sema.Semaphore
	userWait    time.Duration
	globalWait  time.Duration
	protoHeader string
	stats       *counters
}

// private requires a valid admission pass.
func (g *assetGuard) private(c *gin.Context) {
	now := time.Now()
	id, ok := g.admit.check(c.Writer, c.Request, now)
	if !ok {
		g.stats.assetDenied.Add(1)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	userSem := g.users.slot(id, isMultiplexed(c.Request, g.protoHeader), now.UnixNano())
	if !acquire(c.Request.Context(), userSem, g.userWait) {
		g.stats.assetUserThrottled.Add(1)
		c.Header("Retry-After", "1")
		c.AbortWithStatus(http.StatusTooManyRequests)
		return
	}
	defer func() { _ = userSem.Release() }()

	g.serve(c)
}

// public skips the pass check but still counts against the global cap.
func (g *assetGuard) public(c *gin.Context) {
	g.serve(c)
}

func (g *assetGuard) serve(c *gin.Context) {
	if !acquire(c.Request.Context(), g.global, g.globalWait) {
		g.stats.assetGlobalThrottled.Add(1)
		c.Header("Retry-After", "1")
		c.AbortWithStatus(http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = g.global.Release() }()

	g.stats.assetServed.Add(1)
	c.Next() // run the proxy while both slots are held
}

// acquire tries the zero-allocation fast path first and only builds a timeout
// context when it has to wait. The request context is honoured so a client
// that disconnects stops waiting.
func acquire(ctx context.Context, s sema.Semaphore, wait time.Duration) bool {
	if s.TryAcquire() {
		return true
	}
	if wait <= 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	return s.AcquireWith(ctx) == nil
}

// isMultiplexed reports whether the client speaks HTTP/2 or HTTP/3. Behind a
// TLS terminator the connection to concert is always HTTP/1.1, so a trusted
// header naming the client's protocol takes precedence when configured.
func isMultiplexed(r *http.Request, header string) bool {
	if header != "" {
		v := r.Header.Get(header)
		switch {
		case strings.HasPrefix(v, "HTTP/1"):
			return false
		case strings.HasPrefix(v, "HTTP/2"), strings.HasPrefix(v, "HTTP/3"):
			return true
		}
	}
	return r.ProtoMajor >= 2
}

// ─── API client interceptor ──────────────────────────────────────────────────

// apiQueueResponses rewrites room's own responses (waiting-room HTML, breaker
// 503) into JSON for clients that did not ask for HTML. It applies only to
// gated catch-all requests: registered routes (/queue/status, /_room/*,
// bypass and asset paths) have a non-empty FullPath and are left alone.
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
			stripCookies(pr.Out, proxyCookies...)
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
