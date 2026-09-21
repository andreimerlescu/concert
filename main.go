package main

import (
	"bytes"
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
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"sort"
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

// Context keys.
const (
	// ctxAdmitted is set the moment a request reaches the proxy handler.
	// Anything written before that point was written by room.
	ctxAdmitted = "concert.admitted"
	// ctxClientIP holds the resolved client netip.Addr for the request.
	ctxClientIP = "concert.client_ip"
)

// shutdownGrace bounds how long in-flight requests get to finish on SIGTERM.
const shutdownGrace = 30 * time.Second

// Admission pass layout:
//
//	id(16) | expiry unix seconds(8) | key id(4) | truncated HMAC-SHA256(16)
//
// base64url encoded without padding. The key id lets a pass signed by a
// different secret be recognised as stale rather than forged.
const (
	admitCookie  = "concert_admit"
	passIDLen    = 16
	passExpLen   = 8
	passKIDLen   = 4
	passMACLen   = 16
	passExpOff   = passIDLen
	passKIDOff   = passExpOff + passExpLen
	passBodyLen  = passKIDOff + passKIDLen
	passRawLen   = passBodyLen + passMACLen
	minSecretLen = 32
)

// Shard counts must be powers of two.
const (
	userShards  = 64
	abuseShards = 64
)

// Strike weights. A client is banned when its strikes within -abuse-window
// reach -abuse-strikes. Ban paths bypass weights and ban immediately.
const (
	strikeForgedPass   = 5 // admission pass with a bad signature under the current key
	strikeAdminAuth    = 5 // wrong admin token
	strikeUserThrottle = 1 // per-pass asset pool exhausted
	strikeTicketChurn  = 1 // queued arrival without a room_ticket cookie
)

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

	trustedProxies   string
	abuseEnabled     bool
	abuseStrikes     int
	abuseWindow      time.Duration
	abuseCooldown    time.Duration
	abuseMaxCooldown time.Duration
	abuseMaxEntries  int
	abuseAllow       string
	banPaths         string

	// Derived / non-flag fields.
	admitSecret          []byte         // CONCERT_ADMIT_SECRET, or random when unset
	admitSecretGenerated bool           // true when admitSecret was generated
	target               *url.URL       // set by normalize
	trusted              []netip.Prefix // parsed -trusted-proxies
	allow                []netip.Prefix // parsed -abuse-allow
	accessLog            io.Writer      // access log destination; nil means os.Stdout
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

	abuseStrikes  atomic.Int64
	abuseBans     atomic.Int64
	abuseRejected atomic.Int64
	abuseDropped  atomic.Int64
}

// app is a fully wired proxy that has not yet been bound to a listener.
type app struct {
	cfg      config
	room     *room.WaitingRoom
	stats    *counters
	admit    *admitter
	assets   *assetGuard
	abuse    *abuseRegistry // nil when -abuse=false
	banRules []pathRule
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
	fs.StringVar(&cfg.trustedProxies, "trusted-proxies", env.String("CONCERT_TRUSTED_PROXIES", "127.0.0.1/32,::1/128"), "comma-separated CIDRs whose X-Forwarded-For and X-Forwarded-Proto are trusted")
	fs.BoolVar(&cfg.abuseEnabled, "abuse", env.Bool("CONCERT_ABUSE", true), "enable the abuse registry")
	fs.IntVar(&cfg.abuseStrikes, "abuse-strikes", env.Int("CONCERT_ABUSE_STRIKES", 20), "strike total within -abuse-window that triggers a ban")
	fs.DurationVar(&cfg.abuseWindow, "abuse-window", env.Duration("CONCERT_ABUSE_WINDOW", time.Minute), "window over which strikes accumulate")
	fs.DurationVar(&cfg.abuseCooldown, "abuse-cooldown", env.Duration("CONCERT_ABUSE_COOLDOWN", 5*time.Minute), "first ban length; doubles with each repeat ban")
	fs.DurationVar(&cfg.abuseMaxCooldown, "abuse-max-cooldown", env.Duration("CONCERT_ABUSE_MAX_COOLDOWN", 24*time.Hour), "longest ban; also how long ban history is remembered")
	fs.IntVar(&cfg.abuseMaxEntries, "abuse-max-entries", env.Int("CONCERT_ABUSE_MAX_ENTRIES", 100000), "max clients tracked at once")
	fs.StringVar(&cfg.abuseAllow, "abuse-allow", env.String("CONCERT_ABUSE_ALLOW", ""), "comma-separated CIDRs that are never struck or banned")
	fs.StringVar(&cfg.banPaths, "ban-paths", env.String("CONCERT_BAN_PATHS", ""), "comma-separated paths that ban the client on first hit; suffix /* for a prefix")
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

	if c.trusted, err = parsePrefixes(c.trustedProxies); err != nil {
		return fmt.Errorf("invalid -trusted-proxies: %w", err)
	}
	if c.allow, err = parsePrefixes(c.abuseAllow); err != nil {
		return fmt.Errorf("invalid -abuse-allow: %w", err)
	}

	if c.abuseEnabled {
		if c.abuseStrikes < 1 {
			return fmt.Errorf("invalid -abuse-strikes %d: must be at least 1", c.abuseStrikes)
		}
		if c.abuseWindow <= 0 {
			return fmt.Errorf("invalid -abuse-window %s: must be positive", c.abuseWindow)
		}
		if c.abuseCooldown <= 0 {
			return fmt.Errorf("invalid -abuse-cooldown %s: must be positive", c.abuseCooldown)
		}
		if c.abuseMaxCooldown < c.abuseCooldown {
			return fmt.Errorf("invalid -abuse-max-cooldown %s: must be at least -abuse-cooldown %s", c.abuseMaxCooldown, c.abuseCooldown)
		}
		if c.abuseMaxEntries < 1 {
			return fmt.Errorf("invalid -abuse-max-entries %d: must be at least 1", c.abuseMaxEntries)
		}
	} else if len(parsePaths(c.banPaths)) > 0 {
		return errors.New("-ban-paths requires -abuse")
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

// parsePrefixes reads "10.0.0.0/8, 192.0.2.1, ::1" style lists. Bare
// addresses become single-address prefixes.
func parsePrefixes(spec string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, err
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, err
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func containsAddr(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
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
		{"-ban-paths", c.banPaths},
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

// newApp builds the waiting room, asset tier, abuse registry, proxy, and
// router without binding a port. Callers must Close the returned app.
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

	admit := newAdmitter(cfg.admitSecret, cfg.admitTTL, cfg.cookiePath, cfg.cookieDomain, cfg.secureCookie)

	a := &app{
		cfg:      cfg,
		room:     wr,
		stats:    stats,
		admit:    admit,
		banRules: parsePaths(cfg.banPaths),
		forward:  forwardTo(newProxy(cfg.target, cfg.preserveHost, cfg.headerTimeout, cfg.trusted)),
		stop:     make(chan struct{}),
	}
	if cfg.abuseEnabled {
		a.abuse = newAbuseRegistry(cfg, stats)
	}
	a.assets = &assetGuard{
		admit:       admit,
		users:       newUserStore(cfg.assetUserCapH1, cfg.assetUserCapH2),
		global:      global,
		userWait:    cfg.assetUserWait,
		globalWait:  cfg.assetWait,
		protoHeader: cfg.clientProtoHeader,
		stats:       stats,
		strike:      a.strike,
	}

	handler, err := buildRouter(a)
	if err != nil {
		wr.Stop()
		return nil, err
	}
	a.handler = handler

	go a.assets.users.janitor(janitorInterval(cfg.admitTTL), cfg.admitTTL, a.stop)
	if a.abuse != nil {
		go a.abuse.janitor(janitorInterval(cfg.abuseWindow), a.stop)
	}
	return a, nil
}

// Close stops the janitors and the waiting room's background workers.
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
	if a.abuse != nil {
		log.Printf("abuse registry: %d strikes per %s, cooldown %s doubling to %s, %d ban paths",
			a.cfg.abuseStrikes, a.cfg.abuseWindow, a.cfg.abuseCooldown, a.cfg.abuseMaxCooldown, len(a.banRules))
	}
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
// client identification and ban enforcement first, then ops, bypass, and
// asset routes (outside the room), then churn detection and the API
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
	_ = r.SetTrustedProxies(nil) // concert resolves client IPs itself

	r.Use(gin.Recovery())
	r.Use(a.identify) // before the logger: banned requests are never logged
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

	// ---- Run ahead of room's middleware on gated requests only. ----
	if a.abuse != nil {
		r.Use(a.watchChurn)
	}
	if cfg.apiJSON {
		r.Use(apiQueueResponses(cfg.retryAfter))
	}

	// ---- Attaches room's middleware and GET /queue/status. ----
	a.room.RegisterRoutes(r)

	// ---- Everything else: gated, then proxied. ----
	// Gin rebuilds the NoRoute chain on every Use(), so this catch-all
	// inherits every middleware above plus room's.
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
	if a.admit.refresh(c.Writer, c.Request, time.Now()) == passForged {
		a.strike(c, strikeForgedPass)
	}
	a.forward(c)
}

// forwardTo marks the request as admitted and hands it to the proxy.
func forwardTo(proxy http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(ctxAdmitted, true)
		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

func janitorInterval(d time.Duration) time.Duration {
	if iv := d / 2; iv > 10*time.Second {
		return iv
	}
	return 10 * time.Second
}

// ─── client identity and abuse enforcement ───────────────────────────────────

// identify resolves the client IP, rejects banned clients, and bans clients
// that touch a ban path. Hot path: one map lookup, no logging.
func (a *app) identify(c *gin.Context) {
	ip := clientIP(c.Request, a.cfg.trusted)
	c.Set(ctxClientIP, ip)
	if a.abuse == nil {
		return
	}

	now := time.Now()
	if left, banned := a.abuse.banned(ip, now); banned {
		a.stats.abuseRejected.Add(1)
		rejectBanned(c, left)
		return
	}

	if len(a.banRules) == 0 {
		return
	}
	p := c.Request.URL.Path
	for _, rule := range a.banRules {
		if rule.matches(p) {
			if left, banned := a.abuse.banNow(ip, now); banned {
				rejectBanned(c, left)
			}
			return
		}
	}
}

// watchChurn strikes clients that arrive without a room_ticket and are
// issued a new one: a script discarding cookies to take fresh places in line.
func (a *app) watchChurn(c *gin.Context) {
	if c.FullPath() != "" {
		c.Next()
		return
	}
	_, err := c.Request.Cookie("room_ticket")
	hadTicket := err == nil

	c.Next()

	if hadTicket || c.GetBool(ctxAdmitted) {
		return
	}
	for _, v := range c.Writer.Header().Values("Set-Cookie") {
		if strings.HasPrefix(v, "room_ticket=") {
			a.strike(c, strikeTicketChurn)
			return
		}
	}
}

// strike records weighted abuse against the request's client.
func (a *app) strike(c *gin.Context, weight int) {
	if a.abuse == nil {
		return
	}
	a.abuse.strike(clientIPFrom(c), weight, time.Now())
}

func clientIPFrom(c *gin.Context) netip.Addr {
	if v, ok := c.Get(ctxClientIP); ok {
		if ip, ok := v.(netip.Addr); ok {
			return ip
		}
	}
	return netip.Addr{}
}

func rejectBanned(c *gin.Context, left time.Duration) {
	secs := int((left + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	s := strconv.Itoa(secs)
	c.Header("Retry-After", s)
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusTooManyRequests, "application/json; charset=utf-8",
		[]byte(`{"error":"temporarily blocked","retry_after_seconds":`+s+`}`))
	c.Abort()
}

func remoteAddr(r *http.Request) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(r.RemoteAddr); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

// clientIP returns the connection address, or, when the connection comes
// from a trusted proxy, the right-most X-Forwarded-For entry that is not
// itself a trusted proxy. Entries left of that point are client-controlled
// and ignored. Scans right to left without allocating.
func clientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	remote, ok := remoteAddr(r)
	if !ok {
		return netip.Addr{}
	}
	if !containsAddr(trusted, remote) {
		return remote
	}

	hop := remote
	vals := r.Header.Values("X-Forwarded-For")
	for i := len(vals) - 1; i >= 0; i-- {
		s := vals[i]
		for s != "" {
			var part string
			if j := strings.LastIndexByte(s, ','); j >= 0 {
				part, s = s[j+1:], s[:j]
			} else {
				part, s = s, ""
			}
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			a, err := netip.ParseAddr(part)
			if err != nil {
				return remote // malformed chain: trust nothing in it
			}
			a = a.Unmap()
			if !containsAddr(trusted, a) {
				return a
			}
			hop = a
		}
	}
	return hop // every hop was trusted: internal traffic
}

// abuseKey maps a client to its registry key: the address itself for IPv4,
// the /64 prefix for IPv6, where one host can rotate through the whole /64.
func abuseKey(ip netip.Addr) (netip.Addr, bool) {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return netip.Addr{}, false
	}
	if ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().Addr(), true
	}
	return ip, true
}

func displayKey(k netip.Addr) string {
	if k.Is6() {
		return netip.PrefixFrom(k, 64).String()
	}
	return k.String()
}

// ─── abuse registry ──────────────────────────────────────────────────────────

// abuseRegistry tracks weighted strikes per client and bans clients whose
// strikes within a fixed window reach the threshold. Each ban doubles the
// previous cooldown up to max. History is forgotten after max of good behaviour.
type abuseRegistry struct {
	shards     [abuseShards]abuseShard
	threshold  int
	window     int64 // nanoseconds
	base       time.Duration
	max        time.Duration
	maxEntries int64
	exempt     []netip.Prefix // -abuse-allow plus -trusted-proxies
	count      atomic.Int64
	stats      *counters
}

type abuseShard struct {
	mu sync.Mutex
	m  map[netip.Addr]*abuseEntry
}

type abuseEntry struct {
	strikes     int
	windowStart int64 // unix nanos
	bannedUntil int64 // unix nanos; 0 when never banned
	offenses    int
}

type banView struct {
	Client           string    `json:"client"`
	Until            time.Time `json:"until"`
	RemainingSeconds int       `json:"remaining_seconds"`
	Offenses         int       `json:"offenses"`
}

func newAbuseRegistry(cfg config, stats *counters) *abuseRegistry {
	exempt := make([]netip.Prefix, 0, len(cfg.allow)+len(cfg.trusted))
	exempt = append(exempt, cfg.allow...)
	exempt = append(exempt, cfg.trusted...)

	r := &abuseRegistry{
		threshold:  cfg.abuseStrikes,
		window:     int64(cfg.abuseWindow),
		base:       cfg.abuseCooldown,
		max:        cfg.abuseMaxCooldown,
		maxEntries: int64(cfg.abuseMaxEntries),
		exempt:     exempt,
		stats:      stats,
	}
	for i := range r.shards {
		r.shards[i].m = make(map[netip.Addr]*abuseEntry)
	}
	return r
}

func (r *abuseRegistry) shard(k netip.Addr) *abuseShard {
	b := k.As16()
	return &r.shards[(b[4]^b[5]^b[6]^b[7]^b[12]^b[13]^b[14]^b[15])&(abuseShards-1)]
}

// trackable returns the key for ip, or false when ip is invalid or exempt.
func (r *abuseRegistry) trackable(ip netip.Addr) (netip.Addr, bool) {
	ip = ip.Unmap()
	if !ip.IsValid() || containsAddr(r.exempt, ip) {
		return netip.Addr{}, false
	}
	return abuseKey(ip)
}

// entryLocked returns the entry for k, creating it when there is room. When
// the table is full it evicts one unbanned entry from the same shard, or
// drops tracking for k. Caller holds sh.mu.
func (r *abuseRegistry) entryLocked(sh *abuseShard, k netip.Addr, now int64) *abuseEntry {
	if e := sh.m[k]; e != nil {
		return e
	}
	if r.count.Load() >= r.maxEntries {
		evicted := false
		for victim, e := range sh.m {
			if e.bannedUntil <= now {
				delete(sh.m, victim)
				r.count.Add(-1)
				evicted = true
				break
			}
		}
		if !evicted {
			r.stats.abuseDropped.Add(1)
			return nil
		}
	}
	e := &abuseEntry{windowStart: now}
	sh.m[k] = e
	r.count.Add(1)
	return e
}

func (r *abuseRegistry) cooldown(offenses int) time.Duration {
	d := r.base
	for i := 1; i < offenses; i++ {
		d *= 2
		if d >= r.max {
			return r.max
		}
	}
	if d > r.max {
		return r.max
	}
	return d
}

// banLocked bans e starting at now. Caller holds the shard lock.
func (r *abuseRegistry) banLocked(e *abuseEntry, now int64) time.Duration {
	e.offenses++
	d := r.cooldown(e.offenses)
	e.bannedUntil = now + int64(d)
	e.strikes = 0
	e.windowStart = now
	r.stats.abuseBans.Add(1)
	return d
}

// banned reports whether ip is banned and for how much longer.
func (r *abuseRegistry) banned(ip netip.Addr, now time.Time) (time.Duration, bool) {
	if r == nil {
		return 0, false
	}
	k, ok := abuseKey(ip)
	if !ok {
		return 0, false
	}
	sh := r.shard(k)
	sh.mu.Lock()
	var until int64
	if e := sh.m[k]; e != nil {
		until = e.bannedUntil
	}
	sh.mu.Unlock()

	if left := until - now.UnixNano(); left > 0 {
		return time.Duration(left), true
	}
	return 0, false
}

// strike adds weight to ip's strikes and reports whether ip is now banned.
func (r *abuseRegistry) strike(ip netip.Addr, weight int, now time.Time) bool {
	if r == nil || weight <= 0 {
		return false
	}
	k, ok := r.trackable(ip)
	if !ok {
		return false
	}
	r.stats.abuseStrikes.Add(1)

	n := now.UnixNano()
	sh := r.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	e := r.entryLocked(sh, k, n)
	if e == nil {
		return false
	}
	if e.bannedUntil > n {
		return true
	}
	if n-e.windowStart > r.window {
		e.windowStart = n
		e.strikes = 0
	}
	e.strikes += weight
	if e.strikes < r.threshold {
		return false
	}
	r.banLocked(e, n)
	return true
}

// banNow bans ip immediately, escalating like any other ban. It returns the
// remaining ban and false when ip is exempt or cannot be tracked.
func (r *abuseRegistry) banNow(ip netip.Addr, now time.Time) (time.Duration, bool) {
	if r == nil {
		return 0, false
	}
	k, ok := r.trackable(ip)
	if !ok {
		return 0, false
	}

	n := now.UnixNano()
	sh := r.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	e := r.entryLocked(sh, k, n)
	if e == nil {
		return 0, false
	}
	if e.bannedUntil > n {
		return time.Duration(e.bannedUntil - n), true
	}
	return r.banLocked(e, n), true
}

// unban forgets ip entirely, including its offense history.
func (r *abuseRegistry) unban(ip netip.Addr) bool {
	if r == nil {
		return false
	}
	k, ok := abuseKey(ip)
	if !ok {
		return false
	}
	sh := r.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, ok := sh.m[k]; !ok {
		return false
	}
	delete(sh.m, k)
	r.count.Add(-1)
	return true
}

// bans lists currently banned clients, longest remaining first.
func (r *abuseRegistry) bans(now time.Time) []banView {
	out := []banView{}
	if r == nil {
		return out
	}
	n := now.UnixNano()
	for i := range r.shards {
		sh := &r.shards[i]
		sh.mu.Lock()
		for k, e := range sh.m {
			if e.bannedUntil > n {
				out = append(out, banView{
					Client:           displayKey(k),
					Until:            time.Unix(0, e.bannedUntil).UTC(),
					RemainingSeconds: int((time.Duration(e.bannedUntil-n) + time.Second - 1) / time.Second),
					Offenses:         e.offenses,
				})
			}
		}
		sh.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Until.After(out[j].Until) })
	return out
}

func (r *abuseRegistry) tracked() int64 {
	if r == nil {
		return 0
	}
	return r.count.Load()
}

// sweep removes entries that are unbanned, outside their strike window, and
// either never banned or clean for longer than max.
func (r *abuseRegistry) sweep(now time.Time) int {
	n := now.UnixNano()
	maxNS := int64(r.max)
	evicted := 0
	for i := range r.shards {
		sh := &r.shards[i]
		sh.mu.Lock()
		for k, e := range sh.m {
			if e.bannedUntil > n || n-e.windowStart <= r.window {
				continue
			}
			if e.offenses == 0 || n-e.bannedUntil > maxNS {
				delete(sh.m, k)
				evicted++
			}
		}
		sh.mu.Unlock()
	}
	r.count.Add(int64(-evicted))
	return evicted
}

func (r *abuseRegistry) janitor(every time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			r.sweep(now)
		}
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

	// Per-request events: count, don't log.
	wr.On(room.EventQueue, func(room.Snapshot) { stats.queued.Add(1) })
	wr.On(room.EventEvict, func(room.Snapshot) { stats.evicted.Add(1) })
	wr.On(room.EventTimeout, func(room.Snapshot) { stats.timeouts.Add(1) })
	wr.On(room.EventPromote, func(room.Snapshot) { stats.promoted.Add(1) })
	return nil
}

// ─── ops routes ──────────────────────────────────────────────────────────────

// requireAdmin checks the bearer token. Wrong tokens earn strikes.
func (a *app) requireAdmin(c *gin.Context) bool {
	if a.cfg.adminToken == "" {
		c.AbortWithStatus(http.StatusNotFound)
		return false
	}
	got := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(a.cfg.adminToken)) != 1 {
		a.strike(c, strikeAdminAuth)
		c.AbortWithStatus(http.StatusUnauthorized)
		return false
	}
	return true
}

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
			"abuse_enabled":                a.abuse != nil,
			"abuse_tracked":                a.abuse.tracked(),
			"abuse_strikes_total":          stats.abuseStrikes.Load(),
			"abuse_bans_total":             stats.abuseBans.Load(),
			"abuse_rejected_total":         stats.abuseRejected.Load(),
			"abuse_dropped_total":          stats.abuseDropped.Load(),
		})
	})

	// Changes the page cap only. The asset cap is fixed at startup: sema's
	// SetCap drains every slot when shrinking, which would break in-flight
	// asset releases.
	r.POST("/_room/cap", func(c *gin.Context) {
		if !a.requireAdmin(c) {
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

	r.GET("/_room/abuse", func(c *gin.Context) {
		if !a.requireAdmin(c) {
			return
		}
		if a.abuse == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "abuse registry disabled"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"tracked": a.abuse.tracked(),
			"bans":    a.abuse.bans(time.Now()),
		})
	})

	// DELETE /_room/abuse?client=203.0.113.9 or ?client=2001:db8::/64
	r.DELETE("/_room/abuse", func(c *gin.Context) {
		if !a.requireAdmin(c) {
			return
		}
		if a.abuse == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "abuse registry disabled"})
			return
		}
		ip, err := parseClient(c.Query("client"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "client must be an IP address or IPv6 /64 prefix"})
			return
		}
		key, _ := abuseKey(ip)
		if !a.abuse.unban(ip) {
			c.JSON(http.StatusNotFound, gin.H{"error": "client not tracked", "client": displayKey(key)})
			return
		}
		c.JSON(http.StatusOK, gin.H{"unbanned": displayKey(key)})
	})
}

func parseClient(s string) (netip.Addr, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Addr{}, err
		}
		return p.Addr(), nil
	}
	return netip.ParseAddr(s)
}

// ─── admission pass ──────────────────────────────────────────────────────────

type passID [passIDLen]byte

type passStatus int

const (
	passMissing passStatus = iota // no cookie, or an empty one
	passValid                     // authentic and unexpired
	passExpired                   // authentic but past its expiry
	passStale                     // signed under a different key (restart, rotation)
	passForged                    // malformed, or bad signature under the current key
)

func newPassID() (passID, error) {
	var id passID
	_, err := rand.Read(id[:])
	return id, err
}

// admitter issues and verifies the signed concert_admit cookie. Verification
// is stateless, so any instance sharing CONCERT_ADMIT_SECRET accepts a pass.
type admitter struct {
	secret []byte
	kid    [passKIDLen]byte
	ttl    time.Duration
	path   string
	domain string
	secure bool
}

func newAdmitter(secret []byte, ttl time.Duration, path, domain string, secure bool) *admitter {
	a := &admitter{secret: secret, ttl: ttl, path: path, domain: domain, secure: secure}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("concert/admit/key-id"))
	copy(a.kid[:], m.Sum(nil))
	return a
}

func (a *admitter) mint(id passID, now time.Time) string {
	var buf [passRawLen]byte
	copy(buf[:passIDLen], id[:])
	binary.BigEndian.PutUint64(buf[passExpOff:passKIDOff], uint64(now.Add(a.ttl).Unix()))
	copy(buf[passKIDOff:passBodyLen], a.kid[:])
	mac := hmac.New(sha256.New, a.secret)
	mac.Write(buf[:passBodyLen])
	copy(buf[passBodyLen:], mac.Sum(nil)[:passMACLen])
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

func (a *admitter) verify(value string, now time.Time) (passID, time.Time, passStatus) {
	var id passID
	if value == "" {
		return id, time.Time{}, passMissing
	}
	if base64.RawURLEncoding.DecodedLen(len(value)) != passRawLen {
		return id, time.Time{}, passForged
	}
	var buf [passRawLen]byte
	n, err := base64.RawURLEncoding.Decode(buf[:], []byte(value))
	if err != nil || n != passRawLen {
		return id, time.Time{}, passForged
	}
	if !bytes.Equal(buf[passKIDOff:passBodyLen], a.kid[:]) {
		return id, time.Time{}, passStale
	}
	mac := hmac.New(sha256.New, a.secret)
	mac.Write(buf[:passBodyLen])
	if !hmac.Equal(buf[passBodyLen:], mac.Sum(nil)[:passMACLen]) {
		return id, time.Time{}, passForged
	}
	exp := time.Unix(int64(binary.BigEndian.Uint64(buf[passExpOff:passKIDOff])), 0)
	if !now.Before(exp) {
		return id, time.Time{}, passExpired
	}
	copy(id[:], buf[:passIDLen])
	return id, exp, passValid
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
// cacheable. Anything else is replaced with a new pass. The incoming status
// is returned so the caller can strike forgeries.
func (a *admitter) refresh(w http.ResponseWriter, r *http.Request, now time.Time) passStatus {
	status := passMissing
	if ck, err := r.Cookie(admitCookie); err == nil {
		var id passID
		var exp time.Time
		id, exp, status = a.verify(ck.Value, now)
		if status == passValid {
			if exp.Sub(now) <= a.ttl/2 {
				a.set(w, id, now)
			}
			return status
		}
	}
	if id, err := newPassID(); err == nil {
		a.set(w, id, now)
	}
	return status
}

// check runs on every private asset request. It also slides the pass past
// half-life, so pages that lazy-load assets without navigating stay admitted.
func (a *admitter) check(w http.ResponseWriter, r *http.Request, now time.Time) (passID, passStatus) {
	ck, err := r.Cookie(admitCookie)
	if err != nil {
		return passID{}, passMissing
	}
	id, exp, status := a.verify(ck.Value, now)
	if status == passValid && exp.Sub(now) <= a.ttl/2 {
		a.set(w, id, now)
	}
	return id, status
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
	strike      func(*gin.Context, int)
}

// private requires a valid admission pass.
func (g *assetGuard) private(c *gin.Context) {
	now := time.Now()
	id, status := g.admit.check(c.Writer, c.Request, now)
	if status != passValid {
		if status == passForged {
			g.strike(c, strikeForgedPass)
		}
		g.stats.assetDenied.Add(1)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	userSem := g.users.slot(id, isMultiplexed(c.Request, g.protoHeader), now.UnixNano())
	if !acquire(c.Request.Context(), userSem, g.userWait) {
		g.stats.assetUserThrottled.Add(1)
		g.strike(c, strikeUserThrottle)
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

func newProxy(target *url.URL, preserveHost bool, headerTimeout time.Duration, trusted []netip.Prefix) *httputil.ReverseProxy {
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

			// Rewrite strips inbound X-Forwarded-* before this runs. Restore
			// the chain from trusted proxies so SetXForwarded appends to it;
			// from anyone else it is client-controlled and discarded.
			ra, ok := remoteAddr(pr.In)
			fromTrusted := ok && containsAddr(trusted, ra)
			if fromTrusted {
				if v := pr.In.Header.Values("X-Forwarded-For"); len(v) > 0 {
					pr.Out.Header["X-Forwarded-For"] = append([]string(nil), v...)
				}
			}
			pr.SetXForwarded()
			if fromTrusted {
				if p := pr.In.Header.Get("X-Forwarded-Proto"); p != "" {
					pr.Out.Header.Set("X-Forwarded-Proto", p)
				}
			}

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
