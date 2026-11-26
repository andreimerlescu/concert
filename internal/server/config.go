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
	"strconv"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/acme"
	"github.com/andreimerlescu/concert/internal/bidding"
	"github.com/andreimerlescu/concert/internal/cache"
	"github.com/andreimerlescu/concert/internal/configfile"
	"github.com/andreimerlescu/concert/internal/guard"
	"github.com/andreimerlescu/concert/internal/kv"
	"github.com/andreimerlescu/concert/internal/notify"
	"github.com/andreimerlescu/concert/internal/static"
	"github.com/andreimerlescu/concert/internal/telemetry"
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
//	concert_pow      — HttpOnly signed Proof-of-Work / Turnstile clearance pass
var proxyCookies = []string{"room_ticket", "room_pass", "room_probe", admitCookie, priorityCookie, guard.DefaultClearanceCookieName, dropTicketCookie, "concert_fastlane", "concert_fastlane_pass"}

type config struct {
	fastlaneFile             string // fast-lane configuration JSON path; see docs/FASTLANE.md
	networksFile             string // chain endpoints for the fast lane's gateway
	fastlaneLockDestinations bool   // lock payTo wallet destinations read-only in Admin Portal
	skipFastlaneInit         bool   // internal: vhost reload transfers existing fastlane/gateway handles
	configFile               string // declarative Concertfile or .json path; see vhost.go

	// Multi-vhost / declarative config metadata populated by vhost.go.
	configManaged   bool
	siteHost        string
	preset          string
	wpPreset        bool
	microCacheTTL   time.Duration
	microCacheMaxMB int
	cacheAddr       string       // external concert-cache address (TCP or Unix); empty uses in-process microcache
	cacheTLS        bool         // enable TLS when dialing external concert-cache over TCP
	cacheSecret     cache.Secret // CONCERT_CACHE_SECRET[_FILE]; env/file only, never logged (S6)
	http3           bool

	listen                  string
	upstream                string
	capacity                int
	maxQueue                int64
	reaper                  time.Duration
	tokenTTL                time.Duration
	firstPollGrace          time.Duration
	readyGrace              time.Duration
	idlePollTTL             time.Duration
	secureCookie            bool
	cookiePath              string
	cookieDomain            string
	preserveHost            bool
	bypass                  string
	htmlFile                string
	busyHTMLFile            string
	clearQueueOnStart       bool
	skipURL                 string
	rate                    float64
	surge                   float64
	passDuration            time.Duration
	headerTimeout           time.Duration
	upstreamBodyIdleTimeout time.Duration
	bodyReadIdleTimeout     time.Duration
	maxUploadTime           time.Duration
	apiJSON                 bool
	retryAfter              int
	adminToken              string

	// room v1.8.0 verify-only Ed25519 split mode for multi-replica VIP passes & signed leases.
	roomVerifyKeys       string
	roomScope            string
	roomSignedMaxTTL     time.Duration
	roomLeaseFraction    float64
	parsedRoomVerifyKeys map[string]ed25519.PublicKey

	assets                 string
	assetPublic            string
	assetCap               int
	assetWait              time.Duration
	assetUserCapH1         int
	assetUserCapH2         int
	assetUserWait          time.Duration
	admitTTL               time.Duration
	admitSessionContinuity bool
	clientProtoHeader      string
	accessLogEnabled       bool

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

	// Non-custodial hybrid AI agent pass bidding; see bidding_wiring.go.
	agentBidding              bool
	agentBiddingFloorMicroUSD int64
	agentBiddingEpoch         time.Duration
	agentBiddingSlots         int
	agentBiddingMinWait       time.Duration
	biddingSettler            bidding.PaymentSettler // optional test injection; nil uses gateway/fail-closed

	// Declarative path-based routes, response headers, redirects, and scheduled drop; see routes_wiring.go & drop_wiring.go.
	siteRoutes    []configfile.RouteConfig
	siteHeaders   []configfile.HeaderRule
	siteRedirects []configfile.RedirectRule
	dropEventID   string
	dropLobbyAt   string
	dropOpenAt    string

	// ChatOps alerting & pure-stdlib OTLP/HTTP JSON tracing; see observability_wiring.go.
	notifySlackURL                 notify.Secret // CONCERT_NOTIFY_SLACK_URL[_FILE] / -notify-slack-url (S6)
	notifyDiscordURL               notify.Secret // CONCERT_NOTIFY_DISCORD_URL[_FILE] / -notify-discord-url (S6)
	notifyTeamsURL                 notify.Secret // CONCERT_NOTIFY_TEAMS_URL[_FILE] / -notify-teams-url (S6)
	notifyWebhookURL               notify.Secret // CONCERT_NOTIFY_WEBHOOK_URL[_FILE] / -notify-webhook-url (S6)
	notifyWebhookSecret            notify.Secret // CONCERT_NOTIFY_WEBHOOK_SECRET[_FILE] (S6)
	notifyPagerDutyKey             notify.Secret // CONCERT_NOTIFY_PAGERDUTY_KEY[_FILE] / -notify-pagerduty-key (S6)
	notifyPagerDutyURL             string        // CONCERT_NOTIFY_PAGERDUTY_URL (defaults to PagerDuty Events API v2)
	notifyDisableCoalesce          bool          // internal test toggle
	otlpEndpoint                   string        // -otlp-endpoint / CONCERT_OTLP_ENDPOINT
	otlpSampleRate                 float64       // -otlp-sample-rate / CONCERT_OTLP_SAMPLE_RATE
	otlpAuthHeaderName             string        // CONCERT_OTLP_AUTH_HEADER_NAME (default "Authorization")
	otlpAuthHeader                 telemetry.Secret
	observabilityAllowLoopbackHTTP bool // internal test toggle; production always enforces HTTPS + SSRF checks

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
	tlsDNSProvider       string      // ACME DNS-01 provider: "" (disabled), "cloudflare", or "webhook"
	tlsDNSWebhookURL     string      // HTTPS endpoint for -tls-dns-provider webhook
	dnsAPIToken          acme.Secret // CONCERT_DNS_API_TOKEN[_FILE]; env/file only (S6)
	dnsWebhookToken      acme.Secret // CONCERT_DNS_WEBHOOK_TOKEN[_FILE]; env/file only (S6)

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

	kvAddr        string
	kvTLS         bool
	kvPrefix      string
	kvSharedQueue bool
	kvPassword    kv.Secret // env/file only: CONCERT_KV_PASSWORD[_FILE] (S6)

	redisAddr     string
	redisTLS      bool
	redisPrefix   string
	redisPassword string // env/file only: CONCERT_REDIS_PASSWORD[_FILE] (legacy alias)

	// Host-protection guardrails; see internal/guard and guard_wiring.go.
	maxQueuePerIP             int
	allowMaxQueuePerIP        int
	hostMaxMemMB              int
	hostMaxFDs                int
	hostMaxConns              int64
	rateLimits                string   // comma-separated /path=rate/window[:burst]
	concertfileRateLimits     []string // declarative Concertfile rate_limit directives
	blockASN                  string
	allowCountries            string
	blockCountries            string
	challengeMode             string // off | pow | turnstile
	challengePowBits          int
	challengeTurnstileSiteKey string
	turnstileSecret           guard.Secret // env/file only: CONCERT_TURNSTILE_SECRET[_FILE] (S6)
	turnstileEndpoint         string       // optional override for tests; defaults to Cloudflare endpoint
	parsedRateLimits          []guard.Rule
	parsedBlockASNs           []uint32
	parsedAllowCountries      []string
	parsedBlockCountries      []string

	// Edge and leaf tiers; see topology.go and docs/TOPOLOGY.md.
	role             string        // standalone, edge or leaf
	nodeID           string        // this node's ID in hop claims; empty derives one
	hopPeers         string        // leaf: CIDRs allowed to present hop claims
	hopMaxSkew       time.Duration // clock skew a hop claim may carry
	hopWait          time.Duration // leaf: how long a hop page request waits for a host slot
	hopReplayGuard   bool          // leaf: reject replayed Concert-Hop nonces within 2*maxSkew
	hopRequireNonce  bool          // leaf: reject legacy v0.2.0 Concert-Hop claims without a nonce
	hopRequireMTLS   bool          // leaf: require verified TLS client cert on hop claims and control plane
	hopReplayMax     int           // leaf: max tracked single-use Concert-Hop nonces across 256 shards
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

	if v := strings.TrimSpace(envOrFile("CONCERT_NOTIFY_WEBHOOK_SECRET", "")); v != "" {
		cfg.notifyWebhookSecret = notify.NewSecret(v)
	}
	cfg.notifyPagerDutyURL = strings.TrimSpace(os.Getenv("CONCERT_NOTIFY_PAGERDUTY_URL"))
	cfg.otlpAuthHeaderName = strings.TrimSpace(os.Getenv("CONCERT_OTLP_AUTH_HEADER_NAME"))
	if v := strings.TrimSpace(envOrFile("CONCERT_OTLP_AUTH_HEADER", "")); v != "" {
		cfg.otlpAuthHeader = telemetry.NewSecret(v)
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
	if kvPass := envOrFile("CONCERT_KV_PASSWORD", ""); kvPass != "" {
		cfg.kvPassword = kv.NewSecret(kvPass)
	}
	if cacheSec := envOrFile("CONCERT_CACHE_SECRET", ""); cacheSec != "" {
		cfg.cacheSecret = cache.NewSecret(cacheSec)
	}
	if tsSec := envOrFile("CONCERT_TURNSTILE_SECRET", ""); tsSec != "" {
		cfg.turnstileSecret = guard.NewSecret(tsSec)
	}
	if dnsTok := envOrFile("CONCERT_DNS_API_TOKEN", ""); dnsTok != "" {
		cfg.dnsAPIToken = acme.NewSecret(dnsTok)
	}
	if whTok := envOrFile("CONCERT_DNS_WEBHOOK_TOKEN", ""); whTok != "" {
		cfg.dnsWebhookToken = acme.NewSecret(whTok)
	}
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
	if strings.TrimSpace(c.cacheAddr) != "" {
		if c.cacheSecret.IsZero() {
			return errors.New("CONCERT_CACHE_SECRET or CONCERT_CACHE_SECRET_FILE is required when -cache-addr is set")
		}
		if c.microCacheTTL == 0 {
			c.microCacheTTL = 15 * time.Second
		}
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
	if c.upstreamBodyIdleTimeout != 0 && (c.upstreamBodyIdleTimeout < minUpstreamBodyIdleTimeout || c.upstreamBodyIdleTimeout > maxUpstreamBodyIdleTimeout) {
		return fmt.Errorf("invalid -upstream-body-idle-timeout %s: must be 0 (off) or between %s and %s",
			c.upstreamBodyIdleTimeout, minUpstreamBodyIdleTimeout, maxUpstreamBodyIdleTimeout)
	}
	if c.bodyReadIdleTimeout < 0 {
		return fmt.Errorf("invalid -body-read-idle-timeout %s: must not be negative", c.bodyReadIdleTimeout)
	}
	if c.maxUploadTime < 0 {
		return fmt.Errorf("invalid -max-upload-time %s: must not be negative", c.maxUploadTime)
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
	minRetryGrace := 2 * time.Duration(c.retryAfter) * time.Second
	effTokenTTL := c.effectiveTokenTTL()
	if g := c.firstPollGrace; g != 0 {
		if g < minFirstPollGrace || g > maxFirstPollGrace {
			return fmt.Errorf("invalid -first-poll-grace %s: must be 0 (off) or between %s and %s",
				g, minFirstPollGrace, maxFirstPollGrace)
		}
		if g < minRetryGrace {
			return fmt.Errorf("invalid -first-poll-grace %s: must be at least twice -retry-after (%s), "+
				"so API clients that retry instead of polling keep their place", g, minRetryGrace)
		}
	}
	if g := c.readyGrace; g != 0 {
		if g < minReadyGrace || g > maxReadyGrace {
			return fmt.Errorf("invalid -ready-grace %s: must be 0 (off) or between %s and %s",
				g, minReadyGrace, maxReadyGrace)
		}
		if g < minRetryGrace {
			return fmt.Errorf("invalid -ready-grace %s: must be at least twice -retry-after (%s), "+
				"so API clients that retry on schedule can claim their slot", g, minRetryGrace)
		}
		if g > effTokenTTL {
			return fmt.Errorf("invalid -ready-grace %s: must not exceed effective -token-ttl (%s)", g, effTokenTTL)
		}
	}
	if g := c.idlePollTTL; g != 0 {
		if g < minIdlePollTTL || g > maxIdlePollTTL {
			return fmt.Errorf("invalid -idle-poll-ttl %s: must be 0 (off) or between %s and %s",
				g, minIdlePollTTL, maxIdlePollTTL)
		}
		if g < minRetryGrace {
			return fmt.Errorf("invalid -idle-poll-ttl %s: must be at least twice -retry-after (%s), "+
				"so API clients that retry on schedule keep their place", g, minRetryGrace)
		}
		if g > effTokenTTL {
			return fmt.Errorf("invalid -idle-poll-ttl %s: must not exceed effective -token-ttl (%s)", g, effTokenTTL)
		}
	}
	if p := strings.TrimSpace(c.busyHTMLFile); p != "" {
		info, serr := os.Stat(p)
		if serr != nil {
			return fmt.Errorf("cannot read -busy-html %s: %w", c.busyHTMLFile, serr)
		}
		if info.IsDir() {
			return fmt.Errorf("cannot read -busy-html %s: is a directory", c.busyHTMLFile)
		}
		f, ferr := os.Open(p)
		if ferr != nil {
			return fmt.Errorf("cannot read -busy-html %s: %w", c.busyHTMLFile, ferr)
		}
		_ = f.Close()
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

	dnsProv := strings.ToLower(strings.TrimSpace(c.tlsDNSProvider))
	switch dnsProv {
	case "", "cloudflare", "webhook":
		c.tlsDNSProvider = dnsProv
	default:
		return fmt.Errorf("invalid -tls-dns-provider %q: must be empty, cloudflare, or webhook", c.tlsDNSProvider)
	}
	allowWildcard := c.tlsDNSProvider != ""
	if c.tlsHosts, err = parseTLSDomainsMode(c.tlsDomains, allowWildcard); err != nil {
		return fmt.Errorf("invalid -tls-domains: %w", err)
	}
	if c.tlsDNSProvider == "cloudflare" && c.dnsAPIToken.IsZero() {
		return errors.New("CONCERT_DNS_API_TOKEN or CONCERT_DNS_API_TOKEN_FILE is required when -tls-dns-provider=cloudflare")
	}
	if c.tlsDNSProvider == "webhook" && strings.TrimSpace(c.tlsDNSWebhookURL) == "" {
		return errors.New("-tls-dns-webhook-url is required when -tls-dns-provider=webhook")
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

	if err := c.normalizeGuard(); err != nil {
		return err
	}
	if err := c.normalizeObservability(); err != nil {
		return err
	}
	if err := c.portal.normalize(); err != nil {
		return err
	}
	if err := c.normalizeEnterprise(); err != nil {
		return err
	}

	return validateRoutes(c)
}

// effectiveKVAddr returns the configured concert-kv / Redis address, preferring
// -kv-addr over the legacy -redis-addr alias.
func (c config) effectiveKVAddr() string {
	if s := strings.TrimSpace(c.kvAddr); s != "" {
		return s
	}
	return strings.TrimSpace(c.redisAddr)
}

// effectiveKVTLS reports whether TLS is enabled for the KV/cluster connection.
func (c config) effectiveKVTLS() bool {
	return c.kvTLS || c.redisTLS
}

// effectiveKVPrefix returns the key/channel prefix for KV/cluster sync,
// preserving backward compatibility with -redis-prefix.
func (c config) effectiveKVPrefix() string {
	if p := strings.TrimSpace(c.kvPrefix); p != "" && p != "concert" {
		return p
	}
	if p := strings.TrimSpace(c.redisPrefix); p != "" && p != "concert" {
		return p
	}
	if p := strings.TrimSpace(c.kvPrefix); p != "" {
		return p
	}
	if p := strings.TrimSpace(c.redisPrefix); p != "" {
		return p
	}
	return "concert"
}

// effectiveKVPassword returns the redacting KV AUTH password, preferring
// CONCERT_KV_PASSWORD[_FILE] and falling back to CONCERT_REDIS_PASSWORD[_FILE].
func (c config) effectiveKVPassword() kv.Secret {
	if !c.kvPassword.IsZero() {
		return c.kvPassword
	}
	if c.redisPassword != "" {
		return kv.NewSecret(c.redisPassword)
	}
	return kv.Secret{}
}

// normalizeGuard validates all host-protection guardrail settings (queue
// quotas, host shedder ceilings, per-route rate limits, Geo/ASN policies, and
// PoW/Turnstile challenge settings) and populates their parsed fields.
func (c *config) normalizeGuard() error {
	if c.maxQueuePerIP < 0 {
		return fmt.Errorf("invalid -max-queue-per-ip %d: must be >= 0", c.maxQueuePerIP)
	}
	if c.allowMaxQueuePerIP < 0 {
		return fmt.Errorf("invalid -allow-max-queue-per-ip %d: must be >= 0", c.allowMaxQueuePerIP)
	}
	if c.hostMaxMemMB < 0 {
		return fmt.Errorf("invalid -host-max-mem-mb %d: must be >= 0", c.hostMaxMemMB)
	}
	if c.hostMaxFDs < 0 {
		return fmt.Errorf("invalid -host-max-fds %d: must be >= 0", c.hostMaxFDs)
	}
	if c.hostMaxConns < 0 {
		return fmt.Errorf("invalid -host-max-conns %d: must be >= 0", c.hostMaxConns)
	}

	rules, err := parseRateLimitSpecs(c.rateLimits, c.concertfileRateLimits)
	if err != nil {
		return err
	}
	c.parsedRateLimits = rules

	asns, err := parseASNList(c.blockASN)
	if err != nil {
		return fmt.Errorf("invalid -block-asn: %w", err)
	}
	c.parsedBlockASNs = asns
	c.parsedAllowCountries = parseCountryCodeList(c.allowCountries)
	c.parsedBlockCountries = parseCountryCodeList(c.blockCountries)
	if len(c.parsedBlockASNs) > 0 || len(c.parsedAllowCountries) > 0 || len(c.parsedBlockCountries) > 0 {
		if _, err := guard.NewGeoASNPolicy(guard.GeoASNConfig{
			AllowCountries: c.parsedAllowCountries,
			DenyCountries:  c.parsedBlockCountries,
			DenyASNs:       c.parsedBlockASNs,
			FailOpen:       true,
		}, nil); err != nil {
			return fmt.Errorf("invalid geo/asn policy: %w", err)
		}
	}

	mode := strings.ToLower(strings.TrimSpace(c.challengeMode))
	if mode == "" {
		mode = string(guard.ModeOff)
	}
	switch guard.ChallengeMode(mode) {
	case guard.ModeOff:
		c.challengeMode = string(guard.ModeOff)
	case guard.ModePoW:
		c.challengeMode = string(guard.ModePoW)
		if c.challengePowBits == 0 {
			c.challengePowBits = guard.DefaultPoWDifficulty
		}
		if c.challengePowBits < guard.MinPoWDifficulty || c.challengePowBits > guard.MaxPoWDifficulty {
			return fmt.Errorf("invalid -challenge-pow-bits %d: must be between %d and %d",
				c.challengePowBits, guard.MinPoWDifficulty, guard.MaxPoWDifficulty)
		}
	case guard.ModeTurnstile:
		c.challengeMode = string(guard.ModeTurnstile)
		if c.turnstileSecret.IsZero() {
			return errors.New("CONCERT_TURNSTILE_SECRET or CONCERT_TURNSTILE_SECRET_FILE is required when -challenge-mode=turnstile")
		}
	default:
		return fmt.Errorf("invalid -challenge-mode %q: must be off, pow, or turnstile", c.challengeMode)
	}
	return nil
}

// parseRateLimitSpecs parses comma-separated CLI/env route rate-limit entries
// ("/path=rate/window[:burst]" or "/path rate/window[:burst]") and declarative
// Concertfile directives into validated guard.Rule slices.
func parseRateLimitSpecs(flagSpec string, fileSpecs []string) ([]guard.Rule, error) {
	var rawEntries []string
	for _, part := range strings.Split(flagSpec, ",") {
		if p := strings.TrimSpace(part); p != "" {
			rawEntries = append(rawEntries, p)
		}
	}
	for _, part := range fileSpecs {
		if p := strings.TrimSpace(part); p != "" {
			rawEntries = append(rawEntries, p)
		}
	}
	if len(rawEntries) == 0 {
		return nil, nil
	}
	rules := make([]guard.Rule, 0, len(rawEntries))
	for _, entry := range rawEntries {
		var prefix, spec string
		if p, s, ok := strings.Cut(entry, "="); ok {
			prefix, spec = strings.TrimSpace(p), strings.TrimSpace(s)
		} else {
			fields := strings.Fields(entry)
			if len(fields) != 2 {
				return nil, fmt.Errorf("invalid rate limit %q: expected <path>=<rate>/<window> or <path> <rate>/<window>", entry)
			}
			prefix, spec = fields[0], fields[1]
		}
		r, err := guard.ParseRouteRule(prefix, spec)
		if err != nil {
			return nil, fmt.Errorf("invalid rate limit %q: %w", entry, err)
		}
		rules = append(rules, r)
	}
	if _, err := guard.NewRouteLimiter(rules, 0); err != nil {
		return nil, fmt.Errorf("invalid rate limits: %w", err)
	}
	return rules, nil
}

// parseASNList parses comma-separated autonomous system numbers ("13335,AS15169").
func parseASNList(spec string) ([]uint32, error) {
	var out []uint32
	for _, part := range strings.Split(spec, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if len(p) >= 2 && strings.EqualFold(p[:2], "AS") {
			p = p[2:]
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("invalid ASN %q", strings.TrimSpace(part))
		}
		out = append(out, uint32(n))
	}
	return out, nil
}

// parseCountryCodeList splits a comma-separated list of ISO-3166-1 alpha-2 codes.
func parseCountryCodeList(spec string) []string {
	var out []string
	for _, part := range strings.Split(spec, ",") {
		if p := strings.ToUpper(strings.TrimSpace(part)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// effectiveTokenTTL returns the active sliding token TTL: room.DefaultTokenTTL
// when -token-ttl is 0, otherwise c.tokenTTL.
func (c *config) effectiveTokenTTL() time.Duration {
	if c.tokenTTL == 0 {
		return room.DefaultTokenTTL
	}
	return c.tokenTTL
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
