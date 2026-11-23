package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/static"
	"github.com/andreimerlescu/goenv/env"
	"github.com/andreimerlescu/room"
)

// Cookies owned by concert and room. None of them are forwarded upstream.
//
//	room_ticket      — HttpOnly queue session
//	room_pass        — HttpOnly VIP pass
//	room_probe       — non-HttpOnly cookie-support probe
//	concert_admit    — HttpOnly signed admission pass for the asset and stream tiers
//	concert_priority — HttpOnly signed rank granted by the origin; see priority.go
var proxyCookies = []string{"room_ticket", "room_pass", "room_probe", admitCookie, priorityCookie, "concert_fastlane"}

type config struct {
	fastlaneFile string // immutable startup configuration; see docs/FASTLANE.md
	networksFile string // chain endpoints for the fast lane's gateway
	configFile   string // declarative Concertfile or .json path; see vhost.go

	// Multi-vhost / declarative config metadata populated by vhost.go.
	configManaged   bool
	siteHost        string
	preset          string
	wpPreset        bool
	microCacheTTL   time.Duration
	microCacheMaxMB int
	http3           bool

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

	// room v1.8.0 verify-only Ed25519 split mode for multi-replica VIP passes & signed leases.
	roomVerifyKeys       string
	roomScope            string
	roomSignedMaxTTL     time.Duration
	roomLeaseFraction    float64
	parsedRoomVerifyKeys map[string]ed25519.PublicKey

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

	// Static file offload, compression, and FastCGI (php-fpm); see internal/static and internal/fcgi.
	staticRoot         string
	staticMounts       string
	staticAllowExt     string
	staticCacheControl string
	staticFallback     bool
	compress           bool
	fcgiIndex          string
	fcgiDenyPaths      string

	// Parsed static & FastCGI config populated by normalize().
	parsedStaticMounts   []static.Mount
	parsedStaticAllowExt []string
	parsedFCGIDenyPaths  []string
	hasFastCGI           bool

	// Long-lived WebSocket and SSE paths; see stream.go. They skip the
	// waiting room but need an admission pass and a slot under streamCap.
	streamPaths string
	streamCap   int

	// Ranked visitors and the priority lane; see priority.go.
	priorityCap      int
	priorityWait     time.Duration
	priorityLaneRank int
	priorityForms    bool
	// priorityOrderLine places ranked visitors who wait ahead of lower
	// ranks in room's line; false keeps strict arrival order.
	priorityOrderLine bool

	// Keyed places for Concert-Session clients; see agent.go. agentPlaces
	// 0, as in configs built directly, means defaultAgentPlaces.
	agentQueue  bool
	agentPlaces int

	// Let's Encrypt & Enterprise TLS; see tls.go. TLS on -listen is enabled
	// when tlsDomains names at least one host OR tlsCert+tlsKey are set.
	tlsDomains           string
	tlsEmail             string
	tlsCacheDir          string
	tlsStaging           bool
	tlsCert              string
	tlsKey               string
	tlsClientCA          string
	tlsRequireClientCert bool
	tlsMinVersion        string
	hstsMaxAge           int
	tlsHTTPListen        string

	// Upstream resilience & mTLS; see upstream.go.
	upstreamHealthPath     string
	upstreamHealthInterval time.Duration
	upstreamCBFailures     int
	upstreamCBCooldown     time.Duration
	upstreamCA             string
	upstreamClientCert     string
	upstreamClientKey      string

	// Enterprise security, logging, privacy, and multi-node sync.
	statsAuth          bool
	readOnlySettings   bool
	hardened           bool
	auditLog           string
	logFormat          string
	logLevel           string
	privacyScrubQuery  bool
	privacyStripQuery  bool
	privacyAnonymizeIP bool
	historyRetention   time.Duration

	redisAddr     string
	redisTLS      bool
	redisPrefix   string
	redisPassword string // env/file only: CONCERT_REDIS_PASSWORD

	// Edge and leaf tiers; see topology.go and docs/TOPOLOGY.md.
	role             string        // standalone, edge or leaf
	nodeID           string        // this node's ID in hop claims; empty derives one
	hopPeers         string        // leaf: CIDRs allowed to present hop claims
	hopMaxSkew       time.Duration // clock skew a hop claim may carry
	hopWait          time.Duration // leaf: how long a hop page request waits for a host slot
	hopReplayGuard   bool          // leaf: reject replayed Concert-Hop nonces within 2*maxSkew
	hopRequireNonce  bool          // leaf: reject legacy v0.2.0 Concert-Hop claims without a nonce
	hopRequireMTLS   bool          // leaf: require verified TLS client cert on hop claims and control plane
	hopLeaves        string        // edge: leaf control URLs; empty means the upstreams
	hopPoll          time.Duration // edge: how often leaves are polled
	hopAutoCap       bool          // edge: size the room from what the leaves report
	hostCap          int           // leaf: host ceiling; 0 means capacity.json, then -cap
	upstreamRetries  int           // retries on another upstream for refused, bodyless requests
	benchOnStart     bool          // leaf: benchmark the upstream before serving when capacity.json is missing
	benchP95         time.Duration // p95 limit the startup benchmark holds the application to
	benchMaxLemmings int           // most concurrent lemmings the startup benchmark tries
	hopSecret        []byte        // CONCERT_HOP_SECRET
	hopSecretPrev    []byte        // CONCERT_HOP_SECRET_PREV, accepted during rotation
	hopPeerPrefixes  []netip.Prefix
	hopLeafURLs      []*url.URL

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

	// email holds administrator email delivery, cadence, and compliance
	// settings; see mailer.go and internal/mailer.
	email emailConfig

	// historyLog is where the portal's request history is written and
	// restored from; see history_log.go. Empty means history.jsonl in
	// dataDir; "off" keeps the history in memory only.
	historyLog string

	// dataDir holds settings.json, bans.json, the saved queue and the
	// history log; see settings.go, persist.go, queue.go and history_log.go.
	// Empty disables persistence.
	dataDir string

	// Filled by parseConfig; see loadSettingsLayer. Nil for configs built
	// directly, such as in tests.
	settingBase        map[string]any    // values from flags, environment and defaults
	settingBaseSources map[string]string // where each settingBase value came from
	settingFile        map[string]any    // values from settings.json, which win

	// Derived / non-flag fields.
	admitSecret          []byte         // CONCERT_ADMIT_SECRET, or random when unset
	admitSecretPrev      []byte         // CONCERT_ADMIT_SECRET_PREV for zero-downtime key rotation
	admitSecretGenerated bool           // true when admitSecret was generated
	adminTokensSpec      string         // CONCERT_ADMIN_TOKENS
	apiTokens            *apiTokenStore // parsed CONCERT_ADMIN_TOKEN + CONCERT_ADMIN_TOKENS
	target               *url.URL       // primary upstream; set by normalize
	targets              []*url.URL     // all parsed upstreams; set by normalize
	trusted              []netip.Prefix // parsed -trusted-proxies
	allow                []netip.Prefix // parsed -abuse-allow
	tlsHosts             []string       // parsed -tls-domains; empty means no ACME
	accessLog            io.Writer      // access log destination; nil means os.Stdout
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
		"directory for settings.json, bans.json, the saved queue and the history log (empty disables persistence)")
	fs.StringVar(&cfg.configFile, "config", env.String("CONCERT_CONFIG", ""),
		"declarative multi-vhost config file (Concertfile or .json); source of truth reloaded on SIGHUP")

	showVersion := fs.Bool("version", false, "show version")

	if err := checkMovedFlags(args); err != nil {
		return config{}, false, err
	}
	if err := fs.Parse(args); err != nil {
		return config{}, false, err
	}

	// Secrets are environment-only (or *_FILE for Kubernetes/Docker/Vault
	// mounted secrets): command-line arguments are visible in ps output and
	// shell history, and secrets are never written to settings.json.
	cfg.adminToken = envOrFile("CONCERT_ADMIN_TOKEN", "")
	cfg.adminTokensSpec = envOrFile("CONCERT_ADMIN_TOKENS", "")
	cfg.admitSecret = []byte(envOrFile("CONCERT_ADMIT_SECRET", ""))
	cfg.admitSecretPrev = []byte(envOrFile("CONCERT_ADMIT_SECRET_PREV", ""))
	cfg.portal.pass = envOrFile("CONCERT_PORTAL_PASS", "")
	cfg.portal.usersSpec = envOrFile("CONCERT_PORTAL_USERS", "")
	cfg.redisPassword = envOrFile("CONCERT_REDIS_PASSWORD", "")
	cfg.hopSecret = []byte(envOrFile("CONCERT_HOP_SECRET", ""))
	cfg.hopSecretPrev = []byte(envOrFile("CONCERT_HOP_SECRET_PREV", ""))
	cfg.email.smtpPass = envOrFile("CONCERT_SMTP_PASS", "")
	cfg.email.resendAPIKey = envOrFile("CONCERT_RESEND_API_KEY", "")
	cfg.email.sendPandaAPIKey = envOrFile("CONCERT_SENDPANDA_API_KEY", "")
	if strings.TrimSpace(cfg.roomVerifyKeys) == "" {
		cfg.roomVerifyKeys = envOrFile("CONCERT_ROOM_VERIFY_KEYS", "")
	}
	cfg.accessLog = os.Stdout

	if *showVersion {
		return cfg, true, nil
	}
	if strings.TrimSpace(cfg.configFile) != "" {
		// Declarative -config mode: the Concertfile/.json is the source of
		// truth; per-site normalization happens inside newVhostManager.
		return cfg, false, nil
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
	if c.wpPreset {
		if err := applyWordPressPreset(c); err != nil {
			return err
		}
	}
	if c.microCacheTTL < 0 {
		return fmt.Errorf("invalid -micro-cache-ttl %s: must not be negative", c.microCacheTTL)
	}
	if c.microCacheMaxMB < 0 {
		return fmt.Errorf("invalid -micro-cache-max-mb %d: must not be negative", c.microCacheMaxMB)
	}
	targets, err := parseUpstreams(c.upstream)
	if err != nil {
		return err
	}
	c.targets = targets
	c.target = targets[0]
	c.hasFastCGI = false
	for _, u := range targets {
		if isFastCGITarget(u) {
			c.hasFastCGI = true
		}
	}

	if strings.TrimSpace(c.staticRoot) != "" {
		info, serr := os.Stat(strings.TrimSpace(c.staticRoot))
		if serr != nil || !info.IsDir() {
			return fmt.Errorf("invalid -static-root %q: must be an existing directory", c.staticRoot)
		}
	} else if c.hasFastCGI {
		return errors.New("-static-root is required when -upstream uses fcgi:// or fcgi+unix://")
	}
	if c.parsedStaticMounts, err = static.ParseMounts(c.staticMounts); err != nil {
		return err
	}
	if c.parsedStaticAllowExt, err = static.ParseAllowExt(c.staticAllowExt); err != nil {
		return err
	}
	c.parsedFCGIDenyPaths = nil
	for _, part := range strings.Split(c.fcgiDenyPaths, ",") {
		p := strings.TrimSpace(part)
		if p != "" {
			if !strings.HasPrefix(p, "/") {
				return fmt.Errorf("invalid -fcgi-deny-paths entry %q: must start with /", p)
			}
			c.parsedFCGIDenyPaths = append(c.parsedFCGIDenyPaths, p)
		}
	}
	if strings.TrimSpace(c.fcgiIndex) == "" {
		c.fcgiIndex = "index.php"
	}
	if strings.Contains(c.fcgiIndex, "..") || strings.ContainsAny(c.fcgiIndex, "\\\x00\r\n") {
		return fmt.Errorf("invalid -fcgi-index %q", c.fcgiIndex)
	}

	if c.upstreamCBFailures < 0 {
		return fmt.Errorf("invalid -upstream-cb-failures %d: must be >= 0", c.upstreamCBFailures)
	}
	if c.upstreamCBCooldown < 0 {
		return fmt.Errorf("invalid -upstream-cb-cooldown %s: must not be negative", c.upstreamCBCooldown)
	}
	if c.upstreamCBCooldown == 0 {
		c.upstreamCBCooldown = 15 * time.Second
	}
	if c.upstreamHealthPath != "" && !strings.HasPrefix(c.upstreamHealthPath, "/") {
		return fmt.Errorf("invalid -upstream-health-path %q: must start with /", c.upstreamHealthPath)
	}
	if c.upstreamHealthInterval == 0 {
		c.upstreamHealthInterval = 10 * time.Second
	}
	if c.upstreamHealthInterval < time.Second {
		return fmt.Errorf("invalid -upstream-health-interval %s: must be at least 1s", c.upstreamHealthInterval)
	}
	if (c.upstreamClientCert == "") != (c.upstreamClientKey == "") {
		return errors.New("-upstream-client-cert and -upstream-client-key must both be set")
	}

	if c.capacity < 1 || c.capacity > math.MaxInt32 {
		return fmt.Errorf("invalid -cap %d: must be between 1 and %d", c.capacity, math.MaxInt32)
	}
	if c.retryAfter < 1 {
		c.retryAfter = 1
	}
	if strings.TrimSpace(c.roomVerifyKeys) != "" {
		keys, err := parseEd25519VerifyKeys(c.roomVerifyKeys)
		if err != nil {
			return fmt.Errorf("invalid -room-verify-keys: %w", err)
		}
		c.parsedRoomVerifyKeys = keys
		if strings.TrimSpace(c.roomScope) == "" {
			return errors.New("-room-scope is required when -room-verify-keys is set")
		}
	} else {
		c.parsedRoomVerifyKeys = nil
	}
	c.roomScope = strings.TrimSpace(c.roomScope)
	if c.roomSignedMaxTTL != 0 && (c.roomSignedMaxTTL < time.Second || c.roomSignedMaxTTL > room.MaxSignedTokenTTL) {
		return fmt.Errorf("invalid -room-signed-max-ttl %s: must be 0 (default 15m) or between 1s and %s", c.roomSignedMaxTTL, room.MaxSignedTokenTTL)
	}
	if math.IsNaN(c.roomLeaseFraction) || math.IsInf(c.roomLeaseFraction, 0) || c.roomLeaseFraction < 0 || c.roomLeaseFraction > 1 {
		return fmt.Errorf("invalid -room-lease-fraction %g: must be between 0 and 1", c.roomLeaseFraction)
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
	if err := c.normalizePriority(); err != nil {
		return err
	}
	if c.agentPlaces == 0 {
		c.agentPlaces = defaultAgentPlaces
	}
	if c.agentPlaces < 1 || c.agentPlaces > maxAgentPlaces {
		return fmt.Errorf("invalid -agent-places %d: must be between 1 and %d", c.agentPlaces, maxAgentPlaces)
	}

	if c.tlsHosts, err = parseTLSDomains(c.tlsDomains); err != nil {
		return fmt.Errorf("invalid -tls-domains: %w", err)
	}
	if _, err := parseTLSMinVersion(c.tlsMinVersion); err != nil {
		return err
	}
	if (c.tlsCert == "") != (c.tlsKey == "") {
		return errors.New("-tls-cert and -tls-key must both be set")
	}
	if len(c.tlsHosts) > 0 && c.tlsCert != "" {
		return errors.New("-tls-cert/-tls-key cannot be combined with -tls-domains")
	}
	hasTLS := len(c.tlsHosts) > 0 || c.tlsCert != ""
	if c.tlsRequireClientCert && strings.TrimSpace(c.tlsClientCA) == "" {
		return errors.New("-tls-require-client-cert requires -tls-client-ca")
	}
	if strings.TrimSpace(c.tlsClientCA) != "" && !hasTLS {
		return errors.New("-tls-client-ca requires TLS (-tls-cert/-tls-key or -tls-domains)")
	}
	if c.hopRequireMTLS && c.role == roleLeaf && (!hasTLS || strings.TrimSpace(c.tlsClientCA) == "") {
		return errors.New("-hop-require-mtls requires TLS and -tls-client-ca on leaf nodes")
	}
	if len(c.tlsHosts) > 0 {
		if strings.TrimSpace(c.tlsCacheDir) == "" {
			return errors.New("-tls-cache is required with -tls-domains")
		}
		if c.tlsEmail != "" && !strings.Contains(c.tlsEmail, "@") {
			return fmt.Errorf("invalid -tls-email %q", c.tlsEmail)
		}
	}
	if c.hstsMaxAge < 0 {
		return fmt.Errorf("invalid -hsts-max-age %d: must not be negative", c.hstsMaxAge)
	}
	if hl := strings.TrimSpace(c.tlsHTTPListen); hl != "" {
		if !hasTLS {
			return errors.New("-tls-http-listen requires TLS (-tls-domains or -tls-cert/-tls-key)")
		}
		if _, _, serr := net.SplitHostPort(hl); serr != nil {
			return fmt.Errorf("invalid -tls-http-listen %q: must look like :80 or 127.0.0.1:8080", hl)
		}
		if samePort(hl, c.listen) {
			return fmt.Errorf("-tls-http-listen %q cannot share the same port as -listen %q", hl, c.listen)
		}
	}
	if c.http3 && !hasTLS && !c.configManaged {
		return errors.New("-http3 requires TLS (-tls-domains or -tls-cert/-tls-key)")
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
	if len(c.admitSecretPrev) > 0 && len(c.admitSecretPrev) < minSecretLen {
		return fmt.Errorf("CONCERT_ADMIT_SECRET_PREV must be at least %d bytes", minSecretLen)
	}
	if c.apiTokens, err = loadAPITokens(c.adminToken, c.adminTokensSpec); err != nil {
		return err
	}
	if c.historyRetention == 0 {
		c.historyRetention = historyRetention
	}
	if c.historyRetention < time.Hour || c.historyRetention > 30*24*time.Hour {
		return fmt.Errorf("invalid -history-retention %s: must be between 1h and 720h", c.historyRetention)
	}
	if lf := strings.ToLower(strings.TrimSpace(c.logFormat)); lf != "" && lf != "text" && lf != "json" {
		return fmt.Errorf("invalid -log-format %q: must be text or json", c.logFormat)
	}
	if ll := strings.ToLower(strings.TrimSpace(c.logLevel)); ll != "" && ll != "debug" && ll != "info" && ll != "warn" && ll != "warning" && ll != "error" {
		return fmt.Errorf("invalid -log-level %q: must be debug, info, warn, or error", c.logLevel)
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
	if err := c.normalizeEnterprise(); err != nil {
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
			// room registers GET /queue/status/:ticket as well as
			// /queue/status; a path under it would make gin panic.
			if r.path == "/queue/status" || strings.HasPrefix(r.path, "/queue/status/") ||
				r.path == "/_room" || strings.HasPrefix(r.path, "/_room/") ||
				r.path == "/_concert" || strings.HasPrefix(r.path, "/_concert/") {
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

// parseEd25519VerifyKeys parses comma-separated "kid=<pubkey>" entries for
// room v1.8.0 verify-only split mode. Each public key may be encoded as 64-char
// hex or standard/URL base64 (with or without padding) decoding to exactly 32
// Ed25519 public key bytes.
func parseEd25519VerifyKeys(spec string) (map[string]ed25519.PublicKey, error) {
	out := make(map[string]ed25519.PublicKey)
	for _, raw := range strings.Split(spec, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		kid, val, ok := strings.Cut(entry, "=")
		kid = strings.TrimSpace(kid)
		val = strings.TrimSpace(val)
		if !ok || kid == "" || val == "" {
			return nil, fmt.Errorf("malformed entry %q (expected kid=<ed25519-pubkey>)", entry)
		}
		if _, dup := out[kid]; dup {
			return nil, fmt.Errorf("duplicate key ID %q", kid)
		}
		pub, err := decodeEd25519PubKey(val)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", kid, err)
		}
		out[kid] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("at least one kid=<ed25519-pubkey> entry is required")
	}
	return out, nil
}

func decodeEd25519PubKey(s string) (ed25519.PublicKey, error) {
	if len(s) == hex.EncodedLen(ed25519.PublicKeySize) {
		if b, err := hex.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, fmt.Errorf("must decode to %d-byte Ed25519 public key (base64url, base64, or hex)", ed25519.PublicKeySize)
}
