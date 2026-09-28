package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/andreimerlescu/goenv/env"
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

	// Ranked visitors and the priority lane; see priority.go.
	priorityCap      int
	priorityWait     time.Duration
	priorityLaneRank int
	priorityForms    bool

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
	admitSecretGenerated bool           // true when admitSecret was generated
	target               *url.URL       // set by normalize
	trusted              []netip.Prefix // parsed -trusted-proxies
	allow                []netip.Prefix // parsed -abuse-allow
	tlsHosts             []string       // parsed -tls-domains; empty means plain HTTP
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
	if err := c.normalizePriority(); err != nil {
		return err
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
			if r.path == "/queue/status" || r.path == "/_room" || strings.HasPrefix(r.path, "/_room/") ||
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
