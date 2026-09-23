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

// shutdownGrace bounds how long in-flight requests get to finish on SIGTERM,
// and on the old listener when a listen address changes.
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

// First-poll grace limits. room accepts 10s-24h (0 turns it off). concert
// also keeps it at least twice -retry-after, so an API client that retries
// on schedule instead of polling /queue/status is not reclaimed.
const (
	minFirstPollGrace = 10 * time.Second
	maxFirstPollGrace = 24 * time.Hour
)

// Permanent bans. A client or range whose ban ends at banForever stays
// banned until an administrator lifts it; banned() reports banForeverLeft.
const (
	banForever     = int64(math.MaxInt64)
	banForeverLeft = time.Duration(math.MaxInt64)
)

// Cookies owned by concert and room. None of them are forwarded upstream.
//
//	room_ticket   — HttpOnly queue session
//	room_pass     — HttpOnly VIP pass
//	room_probe    — non-HttpOnly cookie-support probe
//	concert_admit — HttpOnly signed admission pass for the asset and stream tiers
var proxyCookies = []string{"room_ticket", "room_pass", "room_probe", admitCookie}

type config struct {
	listen         string
	upstream       string
	capacity       int
	maxQueue       int64
	reaper         time.Duration
	tokenTTL       time.Duration
	firstPollGrace time.Duration
	secureCookie   bool
	cookiePath     string
	cookieDomain   string
	preserveHost   bool
	bypass         string
	htmlFile       string
	skipURL        string
	rate           float64
	surge          float64
	passDuration   time.Duration
	headerTimeout  time.Duration
	apiJSON        bool
	retryAfter     int
	adminToken     string

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

	// Long-lived WebSocket and SSE paths; see stream.go. They skip the
	// waiting room but need an admission pass and a slot under streamCap.
	streamPaths string
	streamCap   int

	// Let's Encrypt; see tls.go. TLS on -listen is enabled when tlsDomains
	// names at least one host.
	tlsDomains  string
	tlsEmail    string
	tlsCacheDir string
	tlsStaging  bool

	trustedProxies   string
	abuseEnabled     bool
	abuseStrikes     int
	abuseWindow      time.Duration
	abuseCooldown    time.Duration
	abuseMaxCooldown time.Duration
	abuseMaxEntries  int
	abuseAllow       string
	banPaths         string

	// portal holds the admin portal settings; see portal.go. Its flags are
	// declared with every other flag, from settingDefs in settings.go.
	portal portalConfig

	// dataDir holds settings.json, bans.json and the saved queue; see
	// settings.go, persist.go and queue.go. Empty disables persistence.
	dataDir string

	// Filled by parseConfig; see loadSettingsLayer. Nil for configs built
	// directly, such as in tests.
	settingBase        map[string]any    // values from flags, environment and defaults
	settingBaseSources map[string]string // where each settingBase value came from
	settingFile        map[string]any    // values from settings.json, which win

	// Derived / non-flag fields.
	admitSecret          []byte         // CONCERT_ADMIT_SECRET, or random when unset
	admitSecretGenerated bool           // true when admitSecret was generated
	target               *url.URL       // set by normalize
	trusted              []netip.Prefix // parsed -trusted-proxies
	allow                []netip.Prefix // parsed -abuse-allow
	tlsHosts             []string       // parsed -tls-domains; empty means plain HTTP
	accessLog            io.Writer      // access log destination; nil means os.Stdout
}

type counters struct {
	queued   atomic.Int64
	evicted  atomic.Int64
	timeouts atomic.Int64
	promoted atomic.Int64
	removed  atomic.Int64 // room EventRemove: bans, kicks and removals by concert

	assetServed          atomic.Int64
	assetDenied          atomic.Int64
	assetUserThrottled   atomic.Int64
	assetGlobalThrottled atomic.Int64

	streamServed    atomic.Int64
	streamDenied    atomic.Int64
	streamThrottled atomic.Int64

	abuseStrikes  atomic.Int64
	abuseBans     atomic.Int64
	abuseRejected atomic.Int64
	abuseDropped  atomic.Int64
}

// app is concert's long-lived state plus the generation currently serving
// requests; see reload.go. The waiting room, the abuse registry, the
// admission pass signer and the counters live as long as the process.
// Everything built from settings lives in the generation and is replaced
// when a setting changes.
type app struct {
	cfg       config // as concert started; the running configuration is current().cfg
	room      *room.WaitingRoom
	stats     *counters
	admit     *admitter
	abuse     *abuseRegistry // always present; current().abuse is nil while -abuse=false
	handler   http.Handler   // serves every request with the current generation
	settings  *settingsManager
	drops     *dropper      // bans waiting to be removed from the line; see queue.go
	bansPath  string        // bans.json, or "" when bans are not persisted
	queuePath string        // saved queue, or "" when the queue is not persisted
	rateBits  atomic.Uint64 // skip-the-line base price, float64 bits
	surgeBits atomic.Uint64 // skip-the-line surge, float64 bits
	gen       atomic.Pointer[generation]

	// Listeners, set by run once serving starts; guarded by settings.mu.
	mainEP, portalEP *endpoint

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup // background writers and the drop loop, awaited on Close
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

// parseConfig defines every flag on fs and parses args. Each value resolves
// as settings.json > flag > CONCERT_* environment variable > built-in
// default. The settings themselves are declared once, in settingDefs
// (settings.go). Environment variables are read at call time, so tests can
// drive them with t.Setenv. The returned bool reports -version; when it is
// true neither settings.json nor validation is applied.
func parseConfig(fs *flag.FlagSet, args []string) (config, bool, error) {
	var cfg config

	registerSettingFlags(fs, &cfg)

	// -data-dir says where settings.json is, so it cannot itself live there.
	fs.StringVar(&cfg.dataDir, "data-dir", env.String("CONCERT_DATA_DIR", defaultDataDir),
		"directory for settings.json, bans.json and the saved queue (empty disables persistence)")

	showVersion := fs.Bool("version", false, "show version")

	if err := fs.Parse(args); err != nil {
		return config{}, false, err
	}

	// Secrets are environment-only: command-line arguments are visible in
	// ps output and shell history, and they are never written to settings.json.
	cfg.adminToken = env.String("CONCERT_ADMIN_TOKEN", "")
	cfg.admitSecret = []byte(env.String("CONCERT_ADMIT_SECRET", ""))
	cfg.portal.pass = env.String("CONCERT_PORTAL_PASS", "")
	cfg.accessLog = os.Stdout

	if *showVersion {
		return cfg, true, nil
	}
	if err := loadSettingsLayer(&cfg, fs); err != nil {
		return config{}, false, err
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
	if g := c.firstPollGrace; g != 0 {
		if g < minFirstPollGrace || g > maxFirstPollGrace {
			return fmt.Errorf("invalid -first-poll-grace %s: must be 0 (off) or between %s and %s",
				g, minFirstPollGrace, maxFirstPollGrace)
		}
		if min := 2 * time.Duration(c.retryAfter) * time.Second; g < min {
			return fmt.Errorf("invalid -first-poll-grace %s: must be at least twice -retry-after (%s), "+
				"so API clients that retry instead of polling keep their place", g, min)
		}
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
	if c.streamCap < 1 || c.streamCap > math.MaxInt32 {
		return fmt.Errorf("invalid -stream-cap %d: must be between 1 and %d", c.streamCap, math.MaxInt32)
	}

	if c.tlsHosts, err = parseTLSDomains(c.tlsDomains); err != nil {
		return fmt.Errorf("invalid -tls-domains: %w", err)
	}
	if len(c.tlsHosts) > 0 {
		if strings.TrimSpace(c.tlsCacheDir) == "" {
			return errors.New("-tls-cache is required with -tls-domains")
		}
		if c.tlsEmail != "" && !strings.Contains(c.tlsEmail, "@") {
			return fmt.Errorf("invalid -tls-email %q", c.tlsEmail)
		}
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

	if err := c.portal.normalize(); err != nil {
		return err
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
		{"-stream-paths", c.streamPaths},
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

// newApp builds the waiting room, abuse registry, admission signer and the
// first generation without binding a port. With -data-dir set it also
// restores bans.json and the saved queue, and starts the ban writer.
// Callers must Close the returned app.
//
// Order matters for the queue: room's settings (including the ticket TTL
// and first-poll grace, which judge what is stale) are applied by commit
// before the saved queue is imported, and nothing is served until newApp
// returns.
func newApp(cfg config) (*app, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}

	stats := &counters{}
	a := &app{
		cfg:   cfg,
		stats: stats,
		admit: newAdmitter(cfg.admitSecret, cfg.admitTTL, cfg.cookiePath, cfg.cookieDomain, cfg.secureCookie),
		abuse: newAbuseRegistry(cfg, stats),
		drops: newDropper(),
		stop:  make(chan struct{}),
	}
	a.settings = newSettingsManager(cfg)

	wr := &room.WaitingRoom{}
	if err := wr.Init(int32(cfg.capacity)); err != nil {
		return nil, fmt.Errorf("room init: %w", err)
	}
	a.room = wr

	// room keys each queued visitor by the address concert resolved in
	// identify. gin's own ClientIP would name the TLS terminator: concert
	// turns gin's proxy trust off and applies -trusted-proxies itself.
	wr.SetClientKeyFunc(func(c *gin.Context) string {
		if ip := clientIPFrom(c); ip.IsValid() {
			return ip.String()
		}
		return ""
	})
	registerRoomEvents(wr, a)

	g, err := a.buildGeneration(cfg, nil)
	if err != nil {
		wr.Stop()
		return nil, err
	}
	if err := a.commit(g, nil); err != nil {
		g.assets.users.close()
		wr.Stop()
		return nil, fmt.Errorf("room config: %w", err)
	}
	a.handler = http.HandlerFunc(a.serveHTTP)

	if cfg.dataDir != "" {
		a.bansPath = bansFilePath(cfg.dataDir)
		n, err := a.abuse.loadBans(a.bansPath, time.Now())
		if err != nil {
			g.assets.users.close()
			wr.Stop()
			return nil, err
		}
		if n > 0 {
			log.Printf("bans: restored %d ban record(s) from %s", n, a.bansPath)
		}

		a.queuePath = queueFilePath(cfg.dataDir)
		if err := a.restoreQueue(); err != nil {
			g.assets.users.close()
			wr.Stop()
			return nil, err
		}
	}

	// Every new ban drops that network's waiting visitors from room's line.
	a.abuse.setOnBan(a.queueDrop)

	go a.abuse.janitor(a.stop)
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.dropLoop()
	}()
	if a.bansPath != "" {
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			a.abuse.persistLoop(a.bansPath, bansSaveEvery, a.stop)
		}()
	}
	return a, nil
}

// serveHTTP hands the request to the current generation's engine. A request
// keeps that engine even if a setting changes while it runs.
func (a *app) serveHTTP(w http.ResponseWriter, r *http.Request) {
	a.current().engine.ServeHTTP(w, r)
}

// Close stops the janitors and the drop loop, flushes unsaved bans, saves
// the queue, and stops the waiting room's background workers. run calls it
// after the listeners have drained, so no new tickets arrive while the
// queue is being saved.
func (a *app) Close() {
	a.stopOnce.Do(func() {
		close(a.stop)
		a.wg.Wait()
		if a.queuePath != "" {
			a.saveQueue()
		}
		if g := a.current(); g != nil {
			g.assets.users.close()
		}
		a.room.Stop()
	})
}

// saveBansNow writes bans.json immediately when anything changed. Used after
// administrator actions so a ban is on disk before the API answers.
func (a *app) saveBansNow() {
	if a.bansPath != "" {
		a.abuse.flush(a.bansPath)
	}
}

// registerRoomEvents counts room's per-request events, logs its
// edge-triggered ones, and strikes ticket churn. Registered once; room keeps
// them across changes. Callbacks run in their own goroutines, so none of
// them may block. Snapshot.Token is a bearer credential and is never logged.
func registerRoomEvents(wr *room.WaitingRoom, a *app) {
	stats := a.stats
	wr.On(room.EventFull, func(s room.Snapshot) {
		log.Printf("upstream saturated: %d/%d slots, %d queued (%d live)",
			s.Occupancy, s.Capacity, s.QueueDepth, wr.LiveQueueDepth())
	})
	wr.On(room.EventDrain, func(s room.Snapshot) {
		log.Printf("draining: %d/%d slots, %d queued (%d live)",
			s.Occupancy, s.Capacity, s.QueueDepth, wr.LiveQueueDepth())
	})
	wr.On(room.EventQueue, func(s room.Snapshot) {
		stats.queued.Add(1)
		// A visitor who arrived with no room_ticket at all took a fresh
		// place in line: a script discarding cookies does this on every
		// retry. An unrecognised ticket (StaleTicket) is a browser whose old
		// ticket expired or was removed, and is not struck.
		if !s.StaleTicket {
			a.churnStrike(s.ClientKey)
		}
	})
	wr.On(room.EventEvict, func(room.Snapshot) { stats.evicted.Add(1) })
	wr.On(room.EventTimeout, func(room.Snapshot) { stats.timeouts.Add(1) })
	wr.On(room.EventPromote, func(room.Snapshot) { stats.promoted.Add(1) })
	wr.On(room.EventRemove, func(room.Snapshot) { stats.removed.Add(1) })
}

// churnStrike records a ticket-churn strike against the client room keyed
// the arrival by. The key is the address concert resolved in identify.
func (a *app) churnStrike(key string) {
	reg := a.current().abuse
	if reg == nil || key == "" {
		return
	}
	ip, err := netip.ParseAddr(key)
	if err != nil {
		return
	}
	reg.strike(ip, strikeTicketChurn, time.Now())
}

// run builds the app, starts the admin portal when configured, binds the
// main listener, and serves until ctx is cancelled. Both listeners are
// endpoints (see server.go); the deferred Close saves the queue after they
// have drained.
func run(ctx context.Context, cfg config) error {
	a, err := newApp(cfg)
	if err != nil {
		return err
	}
	defer a.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // stops the portal if the main listener fails

	p, err := newPortal(a)
	if err != nil {
		return err
	}
	handler := p.wrap(a.handler)

	g := a.current()
	c := g.cfg

	// Built before binding, so a bad certificate cache fails fast.
	tlsCfg, err := newACMETLSConfig(c)
	if err != nil {
		p.closeListener()
		return err
	}

	ln, err := listen(c.listen)
	if err != nil {
		p.closeListener()
		return fmt.Errorf("listen %s: %w", c.listen, err)
	}

	mainEP := newEndpoint("main", handler, shutdownGrace, newServer)
	mainEP.setTLS(tlsCfg)
	portalEP := p.start(ctx)
	a.attachEndpoints(mainEP, portalEP)

	derived := ""
	if c.assetCap == 0 {
		derived = " (derived)"
	}
	log.Printf("concert %s -> %s (cap=%d, max-queue=%d, token-ttl=%s, first-poll-grace=%s, asset-cap=%d%s, asset-user-cap=%d h1 / %d h2)",
		ln.Addr(), c.target, c.capacity, c.maxQueue, a.room.TokenTTL(), a.room.FirstPollGrace(),
		g.assets.global.Cap(), derived, c.assetUserCapH1, c.assetUserCapH2)
	if rules := parsePaths(c.streamPaths); len(rules) > 0 {
		log.Printf("streams: %d path(s) outside the waiting room, admission pass required, at most %d at once",
			len(rules), c.streamCap)
	}
	if tlsCfg != nil {
		directory := "production"
		if c.tlsStaging {
			directory = "staging (untrusted certificates)"
		}
		log.Printf("tls: Let's Encrypt %s for %s, cache %s",
			directory, strings.Join(c.tlsHosts, ","), c.tlsCacheDir)
		if !c.secureCookie {
			log.Printf("tls: browsers now reach concert over HTTPS; set CONCERT_SECURE_COOKIE=true")
		}
	}
	if c.abuseEnabled {
		log.Printf("abuse registry: %d strikes per %s, cooldown %s doubling to %s, %d ban paths",
			c.abuseStrikes, c.abuseWindow, c.abuseCooldown, c.abuseMaxCooldown, len(g.banRules))
	}
	if c.dataDir != "" {
		if err := ensureWritableDir(c.dataDir); err != nil {
			log.Printf("data dir: %v; settings, bans and the queue changed now will not be saved", err)
		} else {
			log.Printf("data dir: %s (settings.json overrides flags and environment; bans and the queue survive restarts)", c.dataDir)
		}
	}
	if c.admitSecretGenerated {
		log.Printf("CONCERT_ADMIT_SECRET not set: using a random secret; admission passes reset on restart and are not shared across instances")
	}

	mainEP.serveOn(ln, c.listen)
	return awaitShutdown(ctx, mainEP, portalEP)
}

// buildRouter wires routes in the order that determines what is guarded:
// client identification and ban enforcement first, then ops, bypass, asset
// and stream routes (outside the room), then the API interceptor, then
// room's middleware, then the gated proxy catch-all.
// Route conflicts make gin panic; they are returned as errors instead.
func buildRouter(g *generation) (engine *gin.Engine, err error) {
	defer func() {
		if p := recover(); p != nil {
			engine = nil
			err = fmt.Errorf("route registration: %v", p)
		}
	}()

	cfg := g.cfg
	r := gin.New()

	// A proxy must forward paths exactly as received. Gin's defaults would
	// answer "/foo/" with a 301 to "/foo" instead of passing it upstream.
	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false
	r.HandleMethodNotAllowed = false
	_ = r.SetTrustedProxies(nil) // concert resolves client IPs itself

	r.Use(gin.Recovery())
	r.Use(g.identify) // before the logger: banned requests are never logged
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
	registerOps(r, g)
	registerPaths(r, parsePaths(cfg.bypass), g.forward)
	registerPaths(r, parsePaths(cfg.assets), g.assets.private, g.forward)
	registerPaths(r, parsePaths(cfg.assetPublic), g.assets.public, g.forward)
	registerPaths(r, parsePaths(cfg.streamPaths), g.streams.handle, g.forward)

	// ---- Run ahead of room's middleware on gated requests only. ----
	if cfg.apiJSON {
		r.Use(apiQueueResponses(cfg.retryAfter))
	}

	// ---- Attaches room's middleware and GET /queue/status. ----
	g.a.room.RegisterRoutes(r)

	// ---- Everything else: gated, then proxied. ----
	// Gin rebuilds the NoRoute chain on every Use(), so this catch-all
	// inherits every middleware above plus room's.
	r.NoRoute(g.gated)

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
func (g *generation) gated(c *gin.Context) {
	if g.a.admit.refresh(c.Writer, c.Request, time.Now()) == passForged {
		g.strike(c, strikeForgedPass)
	}
	g.forward(c)
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

// ─── pricing ─────────────────────────────────────────────────────────────────

// setPricing stores the skip-the-line price. It changes at runtime, so it
// is kept as atomic float64 bits.
func (a *app) setPricing(rate, surge float64) {
	a.rateBits.Store(math.Float64bits(rate))
	a.surgeBits.Store(math.Float64bits(surge))
}

func (a *app) pricing() (rate, surge float64) {
	return math.Float64frombits(a.rateBits.Load()), math.Float64frombits(a.surgeBits.Load())
}

// price is room's RateFunc while paid skip-the-line is configured (-rate or
// -surge above 0): base + depth × surge per position. See applyRoom.
func (a *app) price(depth int64) float64 {
	rate, surge := a.pricing()
	return rate + float64(depth)*surge
}

// ─── client identity and abuse enforcement ───────────────────────────────────

// identify resolves the client IP, rejects banned clients, and bans clients
// that touch a ban path. Hot path: one map lookup, no logging. The address
// it stores is also room's client key (see newApp).
func (g *generation) identify(c *gin.Context) {
	ip := clientIP(c.Request, g.cfg.trusted)
	c.Set(ctxClientIP, ip)
	if g.abuse == nil {
		return
	}

	now := time.Now()
	if left, banned := g.abuse.banned(ip, now); banned {
		g.a.stats.abuseRejected.Add(1)
		g.rejectBanned(c, left)
		return
	}

	if len(g.banRules) == 0 {
		return
	}
	p := c.Request.URL.Path
	for _, rule := range g.banRules {
		if rule.matches(p) {
			if left, banned := g.abuse.banNow(ip, now); banned {
				g.rejectBanned(c, left)
			}
			return
		}
	}
}

// strike records weighted abuse against the request's client.
func (g *generation) strike(c *gin.Context, weight int) {
	if g.abuse == nil {
		return
	}
	g.abuse.strike(clientIPFrom(c), weight, time.Now())
}

func clientIPFrom(c *gin.Context) netip.Addr {
	if v, ok := c.Get(ctxClientIP); ok {
		if ip, ok := v.(netip.Addr); ok {
			return ip
		}
	}
	return netip.Addr{}
}

const blockedPage = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Access blocked</title></head>
<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem;text-align:center">
<h1>Access blocked</h1>
<p>%s</p></body></html>`

// rejectBanned answers a banned client.
//
// A waiting-room page polling /queue/status is told it is ready, so it
// reloads at once and the reload shows the block notice. The ban itself
// also removes the client's ticket from room's line (see queue.go). The
// room_ticket cookie is cleared, so a client whose ban ends rejoins at the
// back of the line.
//
// Temporary bans answer 429 with Retry-After; permanent bans answer 403.
// Browsers get a short HTML page, everything else JSON.
func (g *generation) rejectBanned(c *gin.Context, left time.Duration) {
	c.Header("Cache-Control", "no-store")
	if c.Request.URL.Path == "/queue/status" {
		c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(`{"ready":true}`))
		c.Abort()
		return
	}
	if _, err := c.Request.Cookie("room_ticket"); err == nil {
		http.SetCookie(c.Writer, &http.Cookie{
			Name: "room_ticket", Value: "", Path: g.cfg.cookiePath, Domain: g.cfg.cookieDomain,
			MaxAge: -1, Secure: g.cfg.secureCookie, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	}

	if left == banForeverLeft {
		if wantsHTML(c.Request) {
			c.Data(http.StatusForbidden, "text/html; charset=utf-8",
				[]byte(fmt.Sprintf(blockedPage, "Requests from your network are blocked.")))
		} else {
			c.Data(http.StatusForbidden, "application/json; charset=utf-8",
				[]byte(`{"error":"blocked","permanent":true}`))
		}
		c.Abort()
		return
	}

	secs := int((left + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	s := strconv.Itoa(secs)
	c.Header("Retry-After", s)
	if wantsHTML(c.Request) {
		wait := (time.Duration(secs) * time.Second).String()
		c.Data(http.StatusTooManyRequests, "text/html; charset=utf-8",
			[]byte(fmt.Sprintf(blockedPage, "Requests from your network are temporarily blocked. Try again in "+wait+".")))
	} else {
		c.Data(http.StatusTooManyRequests, "application/json; charset=utf-8",
			[]byte(`{"error":"temporarily blocked","retry_after_seconds":`+s+`}`))
	}
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

// keyPrefix is every address a registry key covers: an IPv4 /32 or an IPv6 /64.
func keyPrefix(k netip.Addr) netip.Prefix {
	if k.Is6() {
		return netip.PrefixFrom(k, 64)
	}
	return netip.PrefixFrom(k, 32)
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
// Administrators can also ban a client for a set time or permanently.
// Administrator-set CIDR range bans live alongside in ranges (see ranges.go).
// With -data-dir set, bans survive restarts (see persist.go).
//
// The tuning (thresholds, cooldowns, exemptions) lives in params and is
// replaced whole when a setting changes; the tracked clients and bans stay.
type abuseRegistry struct {
	shards [abuseShards]abuseShard
	params atomic.Pointer[abuseParams]
	count  atomic.Int64
	stats  *counters
	ranges rangeSet // CIDR range bans; see ranges.go

	// onBan is called, outside every registry lock, with the addresses a new
	// or changed ban covers. The app uses it to drop waiting visitors.
	onBan atomic.Pointer[func(netip.Prefix)]

	// Persistence; see persist.go.
	dirty       atomic.Bool // bans changed since the last save
	saveMu      sync.Mutex  // serialises saves
	saveFailing atomic.Bool // the last save failed; logs once per outage
}

// abuseParams is the registry's tuning, from settings.
type abuseParams struct {
	threshold  int
	window     int64 // nanoseconds
	base       time.Duration
	max        time.Duration
	maxEntries int64
	exempt     []netip.Prefix // -abuse-allow plus -trusted-proxies
}

func abuseParamsFrom(cfg config) *abuseParams {
	exempt := make([]netip.Prefix, 0, len(cfg.allow)+len(cfg.trusted))
	exempt = append(exempt, cfg.allow...)
	exempt = append(exempt, cfg.trusted...)
	return &abuseParams{
		threshold:  cfg.abuseStrikes,
		window:     int64(cfg.abuseWindow),
		base:       cfg.abuseCooldown,
		max:        cfg.abuseMaxCooldown,
		maxEntries: int64(cfg.abuseMaxEntries),
		exempt:     exempt,
	}
}

type abuseShard struct {
	mu sync.Mutex
	m  map[netip.Addr]*abuseEntry
}

type abuseEntry struct {
	strikes     int
	windowStart int64 // unix nanos
	bannedUntil int64 // unix nanos; 0 when never banned; banForever when permanent
	offenses    int
}

// banView is one ban as the admin API and portal list it. Permanent bans
// have a zero Until and RemainingSeconds.
type banView struct {
	Client           string    `json:"client"`
	Until            time.Time `json:"until"`
	RemainingSeconds int       `json:"remaining_seconds"`
	Offenses         int       `json:"offenses"`
	Range            bool      `json:"range"`
	Permanent        bool      `json:"permanent"`
}

func newAbuseRegistry(cfg config, stats *counters) *abuseRegistry {
	r := &abuseRegistry{stats: stats}
	r.params.Store(abuseParamsFrom(cfg))
	for i := range r.shards {
		r.shards[i].m = make(map[netip.Addr]*abuseEntry)
	}
	r.ranges.m = make(map[netip.Prefix]*rangeBan)
	return r
}

// p is the registry's current tuning.
func (r *abuseRegistry) p() *abuseParams {
	return r.params.Load()
}

// setParams replaces the tuning. Safe on a nil registry.
func (r *abuseRegistry) setParams(p *abuseParams) {
	if r != nil {
		r.params.Store(p)
	}
}

// setOnBan installs the ban callback. Safe on a nil registry.
func (r *abuseRegistry) setOnBan(f func(netip.Prefix)) {
	if r != nil {
		r.onBan.Store(&f)
	}
}

// notifyBan marks the bans dirty and runs the callback. Callers must not
// hold any registry lock.
func (r *abuseRegistry) notifyBan(p netip.Prefix) {
	r.dirty.Store(true)
	if f := r.onBan.Load(); f != nil {
		(*f)(p)
	}
}

// isExempt reports whether ip is in -abuse-allow or -trusted-proxies.
func (r *abuseRegistry) isExempt(ip netip.Addr) bool {
	return r != nil && containsAddr(r.p().exempt, ip.Unmap())
}

func (r *abuseRegistry) shard(k netip.Addr) *abuseShard {
	b := k.As16()
	return &r.shards[(b[4]^b[5]^b[6]^b[7]^b[12]^b[13]^b[14]^b[15])&(abuseShards-1)]
}

// trackable returns the key for ip, or false when ip is invalid or exempt.
func (r *abuseRegistry) trackable(ip netip.Addr) (netip.Addr, bool) {
	ip = ip.Unmap()
	if !ip.IsValid() || containsAddr(r.p().exempt, ip) {
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
	if r.count.Load() >= r.p().maxEntries {
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
	pr := r.p()
	d := pr.base
	for i := 1; i < offenses; i++ {
		d *= 2
		if d >= pr.max {
			return pr.max
		}
	}
	if d > pr.max {
		return pr.max
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

// banned reports whether ip is banned, individually or by a range, and for
// how much longer. Permanent bans report banForeverLeft.
func (r *abuseRegistry) banned(ip netip.Addr, now time.Time) (time.Duration, bool) {
	if r == nil {
		return 0, false
	}
	k, ok := abuseKey(ip)
	if !ok {
		return 0, false
	}
	n := now.UnixNano()

	sh := r.shard(k)
	sh.mu.Lock()
	var until int64
	if e := sh.m[k]; e != nil {
		until = e.bannedUntil
	}
	sh.mu.Unlock()

	if until == banForever {
		return banForeverLeft, true
	}
	if left := until - n; left > 0 {
		return time.Duration(left), true
	}
	return r.rangeBanned(ip, n)
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

	banned, fresh := r.strikeKey(k, weight, now.UnixNano())
	if fresh {
		r.notifyBan(keyPrefix(k))
	}
	return banned
}

// strikeKey applies a strike under the shard lock. fresh reports a new ban.
func (r *abuseRegistry) strikeKey(k netip.Addr, weight int, n int64) (banned, fresh bool) {
	pr := r.p()
	sh := r.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	e := r.entryLocked(sh, k, n)
	if e == nil {
		return false, false
	}
	if e.bannedUntil > n {
		return true, false
	}
	if n-e.windowStart > pr.window {
		e.windowStart = n
		e.strikes = 0
	}
	e.strikes += weight
	if e.strikes < pr.threshold {
		return false, false
	}
	r.banLocked(e, n)
	return true, true
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
	left, banned, fresh := r.banNowKey(k, now.UnixNano())
	if fresh {
		r.notifyBan(keyPrefix(k))
	}
	return left, banned
}

func (r *abuseRegistry) banNowKey(k netip.Addr, n int64) (left time.Duration, banned, fresh bool) {
	sh := r.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	e := r.entryLocked(sh, k, n)
	if e == nil {
		return 0, false, false
	}
	if e.bannedUntil == banForever {
		return banForeverLeft, true, false
	}
	if e.bannedUntil > n {
		return time.Duration(e.bannedUntil - n), true, false
	}
	return r.banLocked(e, n), true, true
}

// banFor sets ip's ban to end d from now; d <= 0 makes it permanent. A new
// ban counts as an offense for future escalation; changing an active ban
// does not. Waiting visitors from ip are dropped (see onBan).
func (r *abuseRegistry) banFor(ip netip.Addr, d time.Duration, now time.Time) (netip.Addr, error) {
	if r == nil {
		return netip.Addr{}, errAbuseDisabled
	}
	if !ip.IsValid() {
		return netip.Addr{}, errors.New("invalid address")
	}
	k, ok := r.trackable(ip)
	if !ok {
		return netip.Addr{}, errClientExempt
	}
	if err := r.setBanKey(k, d, now.UnixNano()); err != nil {
		return netip.Addr{}, err
	}
	r.notifyBan(keyPrefix(k))
	return k, nil
}

func (r *abuseRegistry) setBanKey(k netip.Addr, d time.Duration, n int64) error {
	sh := r.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	e := r.entryLocked(sh, k, n)
	if e == nil {
		return errRegistryFull
	}
	if e.bannedUntil <= n {
		e.offenses++
		r.stats.abuseBans.Add(1)
	}
	if d <= 0 {
		e.bannedUntil = banForever
	} else {
		e.bannedUntil = n + int64(d)
	}
	e.strikes = 0
	e.windowStart = n
	return nil
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
	r.dirty.Store(true)
	return true
}

// bans lists currently banned clients and ranges: permanent bans first,
// then longest remaining first.
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
			if e.bannedUntil <= n {
				continue
			}
			v := banView{Client: displayKey(k), Offenses: e.offenses}
			if e.bannedUntil == banForever {
				v.Permanent = true
			} else {
				v.Until = time.Unix(0, e.bannedUntil).UTC()
				v.RemainingSeconds = int((time.Duration(e.bannedUntil-n) + time.Second - 1) / time.Second)
			}
			out = append(out, v)
		}
		sh.mu.Unlock()
	}
	out = append(out, r.rangeViews(n)...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Permanent != out[j].Permanent {
			return out[i].Permanent
		}
		return out[i].Until.After(out[j].Until)
	})
	return out
}

func (r *abuseRegistry) tracked() int64 {
	if r == nil {
		return 0
	}
	return r.count.Load()
}

// sweep removes entries that are unbanned, outside their strike window, and
// either never banned or clean for longer than max. Permanent bans stay.
func (r *abuseRegistry) sweep(now time.Time) int {
	pr := r.p()
	n := now.UnixNano()
	maxNS := int64(pr.max)
	evicted := 0
	for i := range r.shards {
		sh := &r.shards[i]
		sh.mu.Lock()
		for k, e := range sh.m {
			if e.bannedUntil > n || n-e.windowStart <= pr.window {
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

// janitor sweeps expired entries and range bans. Its interval follows the
// strike window, which can change at runtime, so it is recomputed each time.
func (r *abuseRegistry) janitor(stop <-chan struct{}) {
	t := time.NewTimer(janitorInterval(time.Duration(r.p().window)))
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			r.sweep(now)
			r.sweepRanges(now)
			t.Reset(janitorInterval(time.Duration(r.p().window)))
		}
	}
}

// ─── ops routes ──────────────────────────────────────────────────────────────

// requireAdmin checks the bearer token. Wrong tokens earn strikes.
func (g *generation) requireAdmin(c *gin.Context) bool {
	if g.cfg.adminToken == "" {
		c.AbortWithStatus(http.StatusNotFound)
		return false
	}
	got := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(g.cfg.adminToken)) != 1 {
		g.strike(c, strikeAdminAuth)
		c.AbortWithStatus(http.StatusUnauthorized)
		return false
	}
	return true
}

func registerOps(r *gin.Engine, g *generation) {
	a, cfg := g.a, g.cfg
	wr, stats, assets, streams := a.room, a.stats, g.assets, g.streams

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
			"first_poll_grace":             wr.FirstPollGrace().String(),
			"queued_total":                 stats.queued.Load(),
			"evicted_total":                stats.evicted.Load(),
			"timeouts_total":               stats.timeouts.Load(),
			"promoted_total":               stats.promoted.Load(),
			"removed_total":                stats.removed.Load(),
			"asset_cap":                    assets.global.Cap(),
			"asset_in_flight":              assets.global.Len(),
			"asset_users":                  assets.users.count.Load(),
			"asset_user_cap_h1":            cfg.assetUserCapH1,
			"asset_user_cap_h2":            cfg.assetUserCapH2,
			"asset_served_total":           stats.assetServed.Load(),
			"asset_denied_total":           stats.assetDenied.Load(),
			"asset_user_throttled_total":   stats.assetUserThrottled.Load(),
			"asset_global_throttled_total": stats.assetGlobalThrottled.Load(),
			"stream_cap":                   streams.sem.Cap(),
			"stream_active":                streams.sem.Len(),
			"stream_served_total":          stats.streamServed.Load(),
			"stream_denied_total":          stats.streamDenied.Load(),
			"stream_throttled_total":       stats.streamThrottled.Load(),
			"abuse_enabled":                g.abuse != nil,
			"abuse_tracked":                g.abuse.tracked(),
			"abuse_range_bans":             g.abuse.rangeCount(),
			"abuse_strikes_total":          stats.abuseStrikes.Load(),
			"abuse_bans_total":             stats.abuseBans.Load(),
			"abuse_rejected_total":         stats.abuseRejected.Load(),
			"abuse_dropped_total":          stats.abuseDropped.Load(),
		})
	})

	// Changes the page cap and saves it to settings.json, like a change made
	// in the portal.
	r.POST("/_room/cap", func(c *gin.Context) {
		if !g.requireAdmin(c) {
			return
		}
		var body struct {
			Cap int32 `json:"cap"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		raw, _ := json.Marshal(body.Cap)
		if err := a.changeSettings(map[string]json.RawMessage{"cap": raw}, nil, netip.Addr{}); err != nil {
			c.JSON(settingsStatus(err), gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"cap": wr.Cap(), "occupancy": wr.Len()})
	})

	r.GET("/_room/abuse", func(c *gin.Context) {
		if !g.requireAdmin(c) {
			return
		}
		if g.abuse == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "abuse registry disabled"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"tracked": g.abuse.tracked(),
			"ranges":  g.abuse.rangeCount(),
			"bans":    g.abuse.bans(time.Now()),
		})
	})

	// DELETE /_room/abuse?client=203.0.113.9, ?client=2001:db8::/64,
	// or a range such as ?client=203.0.0.0/16
	r.DELETE("/_room/abuse", func(c *gin.Context) {
		if !g.requireAdmin(c) {
			return
		}
		if g.abuse == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "abuse registry disabled"})
			return
		}
		t, err := parseBanTarget(c.Query("client"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if !g.abuse.unbanTarget(t) {
			c.JSON(http.StatusNotFound, gin.H{"error": "client not tracked", "client": t.String()})
			return
		}
		a.saveBansNow()
		c.JSON(http.StatusOK, gin.H{"unbanned": t.String()})
	})
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
// The key never changes while concert runs; the lifetime and cookie
// attributes can, through configure, and passes already issued stay valid
// because each carries its own expiry.
type admitter struct {
	secret []byte
	kid    [passKIDLen]byte
	opts   atomic.Pointer[admitOpts]
}

type admitOpts struct {
	ttl    time.Duration
	path   string
	domain string
	secure bool
}

func newAdmitter(secret []byte, ttl time.Duration, path, domain string, secure bool) *admitter {
	a := &admitter{secret: secret}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("concert/admit/key-id"))
	copy(a.kid[:], m.Sum(nil))
	a.configure(ttl, path, domain, secure)
	return a
}

// configure sets the lifetime and cookie attributes of passes issued from now on.
func (a *admitter) configure(ttl time.Duration, path, domain string, secure bool) {
	a.opts.Store(&admitOpts{ttl: ttl, path: path, domain: domain, secure: secure})
}

func (a *admitter) mint(id passID, now time.Time) string {
	o := a.opts.Load()
	var buf [passRawLen]byte
	copy(buf[:passIDLen], id[:])
	binary.BigEndian.PutUint64(buf[passExpOff:passKIDOff], uint64(now.Add(o.ttl).Unix()))
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
	o := a.opts.Load()
	http.SetCookie(w, &http.Cookie{
		Name:     admitCookie,
		Value:    a.mint(id, now),
		Path:     o.path,
		Domain:   o.domain,
		MaxAge:   int(o.ttl / time.Second),
		Secure:   o.secure,
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
			if exp.Sub(now) <= a.opts.Load().ttl/2 {
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

// check runs on every private asset and stream request. It also slides the
// pass past half-life, so pages that lazy-load assets without navigating
// stay admitted.
func (a *admitter) check(w http.ResponseWriter, r *http.Request, now time.Time) (passID, passStatus) {
	ck, err := r.Cookie(admitCookie)
	if err != nil {
		return passID{}, passMissing
	}
	id, exp, status := a.verify(ck.Value, now)
	if status == passValid && exp.Sub(now) <= a.opts.Load().ttl/2 {
		a.set(w, id, now)
	}
	return id, status
}

// ─── asset tier ──────────────────────────────────────────────────────────────

// userStore holds one pair of semaphores per admission pass. Entries exist
// only for authentic passes, so the map is bounded by admitted users within
// the pass lifetime. A store is replaced when the per-user caps or the pass
// lifetime change; its janitor stops when it is closed.
type userStore struct {
	shards   [userShards]userShard
	h1Cap    int
	h2Cap    int
	count    atomic.Int64
	stop     chan struct{}
	stopOnce sync.Once
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
	s := &userStore{h1Cap: h1Cap, h2Cap: h2Cap, stop: make(chan struct{})}
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

// startJanitor sweeps idle entries every interval until close.
func (s *userStore) startJanitor(every, idle time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case now := <-t.C:
				s.sweep(now.Add(-idle).UnixNano())
			}
		}
	}()
}

// close stops the janitor. Requests still holding one of the store's
// semaphores release it normally.
func (s *userStore) close() {
	s.stopOnce.Do(func() { close(s.stop) })
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
// header naming the client's protocol takes precedence when configured. When
// concert terminates TLS itself (-tls-domains), the connection's protocol is
// the client's protocol and no header is needed.
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
// bypass, asset and stream paths) have a non-empty FullPath and are left alone.
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
			// SetXForwarded also sets X-Forwarded-Proto from the inbound
			// connection, so an origin behind concert's own TLS sees https.
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
