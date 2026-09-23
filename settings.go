package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/andreimerlescu/goenv/env"
)

// Persistent settings.
//
// Every setting can come from four places. From lowest to highest priority:
//
//	built-in default < CONCERT_* environment variable < command-line flag < settings.json
//
// settings.json lives in -data-dir (default /var/lib/concert/data). It holds
// only the values an operator changed through the admin portal or the admin
// API; every other setting keeps following flags and the environment.
// Resetting a setting in the portal removes it from the file again.
//
// Every change applies immediately, without restarting concert: see
// reload.go. Secrets (CONCERT_ADMIN_TOKEN, CONCERT_ADMIT_SECRET,
// CONCERT_PORTAL_PASS) and -data-dir itself are never stored in the file and
// are the only settings that need a restart.

const (
	settingsFileName    = "settings.json"
	settingsFileVersion = 1
)

// defaultDataDir is where settings.json and bans.json live unless -data-dir
// or CONCERT_DATA_DIR says otherwise. Tests point it somewhere empty.
var defaultDataDir = "/var/lib/concert/data"

// Where a setting's current value came from.
const (
	sourceDefault = "default"
	sourceEnv     = "env"
	sourceFlag    = "flag"
	sourceFile    = "file"
)

// Value kinds, as shown to the portal.
const (
	kindString   = "string"
	kindInt      = "int"
	kindFloat    = "float"
	kindBool     = "bool"
	kindDuration = "duration"
)

// Portal sections, in display order.
const (
	groupRoom    = "Waiting room"
	groupSkip    = "Skip the line"
	groupOrigin  = "Origin and listener"
	groupCookies = "Cookies"
	groupPaths   = "Paths"
	groupAssets  = "Asset tier"
	groupAbuse   = "Abuse registry"
	groupTLS     = "Let's Encrypt"
	groupPortal  = "Admin portal"
)

// settingDef describes one setting: its flag, environment variable, default,
// where it lives in config, and how the portal presents it.
type settingDef struct {
	key     string            // settings.json and portal API key
	flag    string            // command-line flag, without the dash
	env     string            // environment variable
	group   string            // portal section
	label   string            // portal label
	usage   string            // flag usage and portal help text
	def     any               // built-in default, of the field's type
	ptr     func(*config) any // pointer to the config field
	check   func(any) error   // extra validation for values from the file or portal
	restart bool              // set only by flag or environment; takes effect on restart
	kind    string            // derived from ptr in init
}

// settingDefs is every setting concert has. parseConfig declares one flag per
// entry, so this table is the single place a setting is defined.
var settingDefs = []settingDef{
	// ---- Waiting room ----
	{key: "cap", flag: "cap", env: "CONCERT_CAPACITY", group: groupRoom, label: "Page slots",
		def: 434, usage: "max concurrent page requests allowed through to the upstream",
		ptr: func(c *config) any { return &c.capacity }, check: intAtLeast(1)},
	{key: "max_queue", flag: "max-queue", env: "CONCERT_MAX_QUEUE", group: groupRoom, label: "Max queue depth",
		def: int64(369), usage: "reject with 503 beyond this queue depth (0 = unlimited)",
		ptr: func(c *config) any { return &c.maxQueue }, check: int64AtLeast(0)},
	{key: "token_ttl", flag: "token-ttl", env: "CONCERT_TOKEN_TTL", group: groupRoom, label: "Ticket TTL",
		def: time.Duration(0), usage: "sliding TTL for queued tokens, 30s-24h (0 = room default, 5m)",
		ptr: func(c *config) any { return &c.tokenTTL }, check: durationZeroOrBetween(30*time.Second, 24*time.Hour)},
	{key: "reaper", flag: "reaper", env: "CONCERT_REAPER", group: groupRoom, label: "Reaper interval",
		def: 36 * time.Second, usage: "reaper interval for abandoned tickets, 5s-24h",
		ptr: func(c *config) any { return &c.reaper }, check: durationBetween(5*time.Second, 24*time.Hour)},
	{key: "retry_after", flag: "retry-after", env: "CONCERT_RETRY_AFTER", group: groupRoom, label: "Retry-After for API clients",
		def: 5, usage: "Retry-After seconds sent to queued API clients",
		ptr: func(c *config) any { return &c.retryAfter }, check: intAtLeast(1)},
	{key: "api_json", flag: "api-json", env: "CONCERT_API_JSON", group: groupRoom, label: "JSON for API clients",
		def: true, usage: "answer queued non-HTML clients with JSON 429 instead of the HTML page",
		ptr: func(c *config) any { return &c.apiJSON }},
	{key: "html", flag: "html", env: "CONCERT_HTML_FILE", group: groupRoom, label: "Custom waiting room HTML",
		def: "", usage: "custom waiting room HTML file, empty for room's page (must handle cookies_required and room_probe)",
		ptr: func(c *config) any { return &c.htmlFile }},

	// ---- Skip the line ----
	{key: "rate", flag: "rate", env: "CONCERT_RATE", group: groupSkip, label: "Price per position",
		def: 0.0, usage: "base cost per queue position",
		ptr: func(c *config) any { return &c.rate }, check: floatBetween(0, 1e6)},
	{key: "surge", flag: "surge", env: "CONCERT_SURGE", group: groupSkip, label: "Surge per queued visitor",
		def: 0.0, usage: "extra cost per position for each client in the queue",
		ptr: func(c *config) any { return &c.surge }, check: floatBetween(0, 1e6)},
	{key: "skip_url", flag: "skip-url", env: "CONCERT_SKIP_URL", group: groupSkip, label: "Payment page URL",
		def: "", usage: "payment page URL; enables the skip-the-line card",
		ptr: func(c *config) any { return &c.skipURL }, check: checkSkipURL},
	{key: "pass_duration", flag: "pass", env: "CONCERT_PASS_DURATION", group: groupSkip, label: "VIP pass lifetime",
		def: time.Duration(0), usage: "VIP pass lifetime (0 disables passes)",
		ptr: func(c *config) any { return &c.passDuration }, check: durationZeroOrBetween(time.Minute, 24*time.Hour)},

	// ---- Origin and listener ----
	{key: "listen", flag: "listen", env: "CONCERT_LISTEN", group: groupOrigin, label: "Listen address", restart: true,
		def: ":8080", usage: "address to listen on (flag or CONCERT_LISTEN only; takes a restart)",
		ptr: func(c *config) any { return &c.listen }},
	{key: "upstream", flag: "upstream", env: "CONCERT_UPSTREAM", group: groupOrigin, label: "Upstream origin",
		def: "http://127.0.0.1:3000", usage: "origin to proxy to",
		ptr: func(c *config) any { return &c.upstream }},
	{key: "upstream_timeout", flag: "upstream-timeout", env: "CONCERT_UPSTREAM_TIMEOUT", group: groupOrigin, label: "Upstream header timeout",
		def: 30 * time.Second, usage: "upstream response header timeout",
		ptr: func(c *config) any { return &c.headerTimeout }, check: durationAtLeast(0)},
	{key: "preserve_host", flag: "preserve-host", env: "CONCERT_PRESERVE_HOST", group: groupOrigin, label: "Preserve Host header",
		def: true, usage: "forward the client's Host header to the upstream",
		ptr: func(c *config) any { return &c.preserveHost }},
	{key: "trusted_proxies", flag: "trusted-proxies", env: "CONCERT_TRUSTED_PROXIES", group: groupOrigin, label: "Trusted proxies",
		def: "127.0.0.1/32,::1/128", usage: "comma-separated CIDRs whose X-Forwarded-For and X-Forwarded-Proto are trusted",
		ptr: func(c *config) any { return &c.trustedProxies }},
	{key: "access_log", flag: "access-log", env: "CONCERT_ACCESS_LOG", group: groupOrigin, label: "Access log",
		def: true, usage: "write an access log line per non-asset request",
		ptr: func(c *config) any { return &c.accessLogEnabled }},

	// ---- Cookies ----
	{key: "secure_cookie", flag: "secure-cookie", env: "CONCERT_SECURE_COOKIE", group: groupCookies, label: "Secure cookies",
		def: false, usage: "set Secure on cookies (only if browsers reach you over HTTPS)",
		ptr: func(c *config) any { return &c.secureCookie }},
	{key: "cookie_path", flag: "cookie-path", env: "CONCERT_COOKIE_PATH", group: groupCookies, label: "Cookie path",
		def: "/", usage: "cookie path",
		ptr: func(c *config) any { return &c.cookiePath }},
	{key: "cookie_domain", flag: "cookie-domain", env: "CONCERT_COOKIE_DOMAIN", group: groupCookies, label: "Cookie domain",
		def: "", usage: "cookie domain",
		ptr: func(c *config) any { return &c.cookieDomain }},

	// ---- Paths ----
	{key: "bypass", flag: "bypass", env: "CONCERT_BYPASS", group: groupPaths, label: "Bypass paths",
		def: "/favicon.ico", usage: "comma-separated paths that skip every guard; suffix /* for a prefix",
		ptr: func(c *config) any { return &c.bypass }},
	{key: "assets", flag: "assets", env: "CONCERT_ASSETS", group: groupPaths, label: "Asset paths",
		def: "", usage: "comma-separated asset paths that require an admission pass; suffix /* for a prefix",
		ptr: func(c *config) any { return &c.assets }},
	{key: "asset_public", flag: "asset-public", env: "CONCERT_ASSET_PUBLIC", group: groupPaths, label: "Public asset paths",
		def: "", usage: "comma-separated asset paths served without a pass, still under the global asset cap",
		ptr: func(c *config) any { return &c.assetPublic }},
	{key: "ban_paths", flag: "ban-paths", env: "CONCERT_BAN_PATHS", group: groupPaths, label: "Ban paths",
		def: "", usage: "comma-separated paths that ban the client on first hit; suffix /* for a prefix",
		ptr: func(c *config) any { return &c.banPaths }},

	// ---- Asset tier ----
	{key: "asset_cap", flag: "asset-cap", env: "CONCERT_ASSET_CAP", group: groupAssets, label: "Global asset cap",
		def: 0, usage: "global concurrent asset requests (0 = cap × asset-user-cap-h2)",
		ptr: func(c *config) any { return &c.assetCap }},
	{key: "asset_wait", flag: "asset-wait", env: "CONCERT_ASSET_WAIT", group: groupAssets, label: "Global asset wait",
		def: 2 * time.Second, usage: "max wait for a global asset slot before 503",
		ptr: func(c *config) any { return &c.assetWait }},
	{key: "asset_user_cap_h1", flag: "asset-user-cap-h1", env: "CONCERT_ASSET_USER_CAP_H1", group: groupAssets, label: "Per-user assets, HTTP/1.x",
		def: 8, usage: "concurrent asset requests per pass over HTTP/1.x",
		ptr: func(c *config) any { return &c.assetUserCapH1 }},
	{key: "asset_user_cap_h2", flag: "asset-user-cap-h2", env: "CONCERT_ASSET_USER_CAP_H2", group: groupAssets, label: "Per-user assets, HTTP/2+",
		def: 128, usage: "concurrent asset requests per pass over HTTP/2 and HTTP/3",
		ptr: func(c *config) any { return &c.assetUserCapH2 }},
	{key: "asset_user_wait", flag: "asset-user-wait", env: "CONCERT_ASSET_USER_WAIT", group: groupAssets, label: "Per-user asset wait",
		def: 2 * time.Second, usage: "max wait for a per-pass asset slot before 429",
		ptr: func(c *config) any { return &c.assetUserWait }},
	{key: "admit_ttl", flag: "admit-ttl", env: "CONCERT_ADMIT_TTL", group: groupAssets, label: "Admission pass TTL",
		def: 10 * time.Minute, usage: "sliding lifetime of the admission pass (min 30s)",
		ptr: func(c *config) any { return &c.admitTTL }},
	{key: "client_proto_header", flag: "client-proto-header", env: "CONCERT_CLIENT_PROTO_HEADER", group: groupAssets, label: "Client protocol header",
		def: "", usage: "header set by a trusted TLS terminator carrying the client's HTTP protocol",
		ptr: func(c *config) any { return &c.clientProtoHeader }},

	// ---- Abuse registry ----
	{key: "abuse", flag: "abuse", env: "CONCERT_ABUSE", group: groupAbuse, label: "Abuse registry enabled",
		def: true, usage: "enable the abuse registry; bans are kept while it is off",
		ptr: func(c *config) any { return &c.abuseEnabled }},
	{key: "abuse_strikes", flag: "abuse-strikes", env: "CONCERT_ABUSE_STRIKES", group: groupAbuse, label: "Strikes before a ban",
		def: 20, usage: "strike total within -abuse-window that triggers a ban",
		ptr: func(c *config) any { return &c.abuseStrikes }},
	{key: "abuse_window", flag: "abuse-window", env: "CONCERT_ABUSE_WINDOW", group: groupAbuse, label: "Strike window",
		def: time.Minute, usage: "window over which strikes accumulate",
		ptr: func(c *config) any { return &c.abuseWindow }},
	{key: "abuse_cooldown", flag: "abuse-cooldown", env: "CONCERT_ABUSE_COOLDOWN", group: groupAbuse, label: "First ban length",
		def: 5 * time.Minute, usage: "first ban length; doubles with each repeat ban",
		ptr: func(c *config) any { return &c.abuseCooldown }},
	{key: "abuse_max_cooldown", flag: "abuse-max-cooldown", env: "CONCERT_ABUSE_MAX_COOLDOWN", group: groupAbuse, label: "Longest ban",
		def: 24 * time.Hour, usage: "longest ban; also how long ban history is remembered",
		ptr: func(c *config) any { return &c.abuseMaxCooldown }},
	{key: "abuse_max_entries", flag: "abuse-max-entries", env: "CONCERT_ABUSE_MAX_ENTRIES", group: groupAbuse, label: "Max clients tracked",
		def: 100000, usage: "max clients tracked at once",
		ptr: func(c *config) any { return &c.abuseMaxEntries }},
	{key: "abuse_allow", flag: "abuse-allow", env: "CONCERT_ABUSE_ALLOW", group: groupAbuse, label: "Abuse allowlist",
		def: "", usage: "comma-separated CIDRs that are never struck or banned",
		ptr: func(c *config) any { return &c.abuseAllow }},

	// ---- Let's Encrypt; see tls.go ----
	{key: "tls_domains", flag: "tls-domains", env: "CONCERT_TLS_DOMAINS", group: groupTLS, label: "Certificate hostnames",
		def: "", usage: "comma-separated hostnames to get Let's Encrypt certificates for; enables TLS on -listen",
		ptr: func(c *config) any { return &c.tlsDomains }},
	{key: "tls_email", flag: "tls-email", env: "CONCERT_TLS_EMAIL", group: groupTLS, label: "ACME contact email",
		def: "", usage: "contact email for the ACME account (expiry notices)",
		ptr: func(c *config) any { return &c.tlsEmail }},
	{key: "tls_cache", flag: "tls-cache", env: "CONCERT_TLS_CACHE", group: groupTLS, label: "Certificate cache",
		def: "/var/lib/concert/acme", usage: "directory for the ACME account key and certificates",
		ptr: func(c *config) any { return &c.tlsCacheDir }},
	{key: "tls_staging", flag: "tls-staging", env: "CONCERT_TLS_STAGING", group: groupTLS, label: "Use staging directory",
		def: false, usage: "use the Let's Encrypt staging directory (untrusted certificates, generous rate limits)",
		ptr: func(c *config) any { return &c.tlsStaging }},

	// ---- Admin portal; see portal.go. It only runs when CONCERT_PORTAL_PASS is set. ----
	{key: "portal_listen", flag: "portal-listen", env: "CONCERT_PORTAL_LISTEN", group: groupPortal, label: "Portal address", restart: true,
		def: "127.0.0.1:8081", usage: "admin portal address, empty turns the portal off (flag or CONCERT_PORTAL_LISTEN only; takes a restart); the portal needs CONCERT_PORTAL_PASS",
		ptr: func(c *config) any { return &c.portal.listen }},
	{key: "portal_allow", flag: "portal-allow", env: "CONCERT_PORTAL_ALLOW", group: groupPortal, label: "Portal allowlist",
		def: "127.0.0.1/32,::1/128", usage: "comma-separated CIDRs allowed to reach the admin portal",
		ptr: func(c *config) any { return &c.portal.allowSpec }},
	{key: "portal_session_ttl", flag: "portal-session-ttl", env: "CONCERT_PORTAL_SESSION_TTL", group: groupPortal, label: "Portal session length",
		def: 8 * time.Hour, usage: "admin portal sign-in lifetime",
		ptr: func(c *config) any { return &c.portal.sessionTTL }, check: durationAtLeast(5 * time.Minute)},
	{key: "portal_secure_cookie", flag: "portal-secure-cookie", env: "CONCERT_PORTAL_SECURE_COOKIE", group: groupPortal, label: "Secure portal cookie",
		def: false, usage: "mark the portal session cookie Secure (portal served over HTTPS)",
		ptr: func(c *config) any { return &c.portal.secureCookie }},
}

// settingByKey indexes settingDefs by key.
var settingByKey = map[string]*settingDef{}

func init() {
	for i := range settingDefs {
		d := &settingDefs[i]
		d.kind = kindOf(d.ptr(&config{}))
		if d.kind == "" {
			panic("settings: unsupported field type for " + d.key)
		}
		if _, dup := settingByKey[d.key]; dup {
			panic("settings: duplicate key " + d.key)
		}
		settingByKey[d.key] = d
	}
}

func kindOf(ptr any) string {
	switch ptr.(type) {
	case *string:
		return kindString
	case *int, *int64:
		return kindInt
	case *float64:
		return kindFloat
	case *bool:
		return kindBool
	case *time.Duration:
		return kindDuration
	}
	return ""
}

// get returns the setting's current value in c.
func (d *settingDef) get(c *config) any {
	switch p := d.ptr(c).(type) {
	case *string:
		return *p
	case *int:
		return *p
	case *int64:
		return *p
	case *float64:
		return *p
	case *bool:
		return *p
	case *time.Duration:
		return *p
	}
	return nil
}

// set stores v, which must have the field's type, in c.
func (d *settingDef) set(c *config, v any) {
	switch p := d.ptr(c).(type) {
	case *string:
		*p = v.(string)
	case *int:
		*p = v.(int)
	case *int64:
		*p = v.(int64)
	case *float64:
		*p = v.(float64)
	case *bool:
		*p = v.(bool)
	case *time.Duration:
		*p = v.(time.Duration)
	}
}

// decode reads a JSON value into the field's type. Durations are strings
// such as "30s" or "24h".
func (d *settingDef) decode(raw json.RawMessage) (any, error) {
	switch d.ptr(&config{}).(type) {
	case *string:
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, errors.New("must be a string")
		}
		return strings.TrimSpace(s), nil
	case *int:
		n, err := decodeInt(raw)
		if err != nil {
			return nil, err
		}
		if n < math.MinInt32 || n > math.MaxInt32 {
			return nil, errors.New("is out of range")
		}
		return int(n), nil
	case *int64:
		return decodeInt(raw)
	case *float64:
		var f float64
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, errors.New("must be a number")
		}
		return f, nil
	case *bool:
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, errors.New("must be true or false")
		}
		return b, nil
	case *time.Duration:
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, errors.New("must be a duration such as 30s, 5m or 24h")
		}
		dur, err := time.ParseDuration(strings.TrimSpace(s))
		if err != nil {
			return nil, errors.New("must be a duration such as 30s, 5m or 24h")
		}
		return dur, nil
	}
	return nil, errors.New("unsupported setting type")
}

func decodeInt(raw json.RawMessage) (int64, error) {
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, errors.New("must be a whole number")
	}
	v, err := n.Int64()
	if err != nil {
		return 0, errors.New("must be a whole number")
	}
	return v, nil
}

// encodeSetting converts a value to its JSON form: durations become strings.
func encodeSetting(v any) any {
	if d, ok := v.(time.Duration); ok {
		return d.String()
	}
	return v
}

// ─── validators ──────────────────────────────────────────────────────────────

func intAtLeast(min int) func(any) error {
	return func(v any) error {
		if v.(int) < min {
			return fmt.Errorf("must be at least %d", min)
		}
		return nil
	}
}

func int64AtLeast(min int64) func(any) error {
	return func(v any) error {
		if v.(int64) < min {
			return fmt.Errorf("must be at least %d", min)
		}
		return nil
	}
}

func floatBetween(lo, hi float64) func(any) error {
	return func(v any) error {
		f := v.(float64)
		if math.IsNaN(f) || math.IsInf(f, 0) || f < lo || f > hi {
			return fmt.Errorf("must be between %g and %g", lo, hi)
		}
		return nil
	}
}

func durationAtLeast(min time.Duration) func(any) error {
	return func(v any) error {
		if v.(time.Duration) < min {
			return fmt.Errorf("must be at least %s", min)
		}
		return nil
	}
}

func durationBetween(lo, hi time.Duration) func(any) error {
	return func(v any) error {
		if d := v.(time.Duration); d < lo || d > hi {
			return fmt.Errorf("must be between %s and %s", lo, hi)
		}
		return nil
	}
}

func durationZeroOrBetween(lo, hi time.Duration) func(any) error {
	return func(v any) error {
		d := v.(time.Duration)
		if d != 0 && (d < lo || d > hi) {
			return fmt.Errorf("must be 0s or between %s and %s", lo, hi)
		}
		return nil
	}
}

func checkSkipURL(v any) error {
	s := v.(string)
	valid := s == "" || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
	if !valid || len(s) > 2048 || strings.ContainsAny(s, " \t\r\n\"<>") {
		return errors.New("must be empty, a path starting with /, or an http(s) URL")
	}
	return nil
}

// ─── loading ─────────────────────────────────────────────────────────────────

// registerSettingFlags declares one flag per setting, each defaulting to its
// environment variable and then its built-in default.
func registerSettingFlags(fs *flag.FlagSet, cfg *config) {
	for i := range settingDefs {
		d := &settingDefs[i]
		switch p := d.ptr(cfg).(type) {
		case *string:
			fs.StringVar(p, d.flag, env.String(d.env, d.def.(string)), d.usage)
		case *int:
			fs.IntVar(p, d.flag, env.Int(d.env, d.def.(int)), d.usage)
		case *int64:
			fs.Int64Var(p, d.flag, env.Int64(d.env, d.def.(int64)), d.usage)
		case *float64:
			fs.Float64Var(p, d.flag, env.Float64(d.env, d.def.(float64)), d.usage)
		case *bool:
			fs.BoolVar(p, d.flag, env.Bool(d.env, d.def.(bool)), d.usage)
		case *time.Duration:
			fs.DurationVar(p, d.flag, env.Duration(d.env, d.def.(time.Duration)), d.usage)
		}
	}
}

func envIsSet(name string) bool {
	v, ok := os.LookupEnv(name)
	return ok && strings.TrimSpace(v) != ""
}

// loadSettingsLayer records where each flag-parsed value came from, then
// applies settings.json on top: the file beats flags, flags beat the
// environment, and the environment beats the defaults.
func loadSettingsLayer(cfg *config, fs *flag.FlagSet) error {
	onCLI := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { onCLI[f.Name] = true })

	cfg.settingBase = make(map[string]any, len(settingDefs))
	cfg.settingBaseSources = make(map[string]string, len(settingDefs))
	for i := range settingDefs {
		d := &settingDefs[i]
		cfg.settingBase[d.key] = d.get(cfg)
		switch {
		case onCLI[d.flag]:
			cfg.settingBaseSources[d.key] = sourceFlag
		case envIsSet(d.env):
			cfg.settingBaseSources[d.key] = sourceEnv
		default:
			cfg.settingBaseSources[d.key] = sourceDefault
		}
	}

	cfg.settingFile = map[string]any{}
	if cfg.dataDir == "" {
		return nil
	}
	path := settingsPath(cfg.dataDir)
	values, err := readSettingsFile(path)
	if err != nil {
		return fmt.Errorf("settings file %s: %w (fix it, or remove it to fall back to flags and environment)", path, err)
	}
	for key, v := range values {
		settingByKey[key].set(cfg, v)
		cfg.settingFile[key] = v
	}
	if len(values) > 0 {
		log.Printf("settings: %d value(s) from %s override flags and environment", len(values), path)
	}
	return nil
}

func settingsPath(dir string) string {
	return filepath.Join(dir, settingsFileName)
}

type settingsDoc struct {
	Version  int                        `json:"version"`
	Updated  time.Time                  `json:"updated"`
	Settings map[string]json.RawMessage `json:"settings"`
}

// readSettingsFile returns the typed values in path. A missing file is empty.
// Unknown keys are logged and skipped, so a file written by a newer concert
// still loads.
func readSettingsFile(path string) (map[string]any, error) {
	out := map[string]any{}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	var doc settingsDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if doc.Version > settingsFileVersion {
		return nil, fmt.Errorf("written by a newer concert (version %d)", doc.Version)
	}
	for key, raw := range doc.Settings {
		d, ok := settingByKey[key]
		if !ok {
			log.Printf("settings: ignoring unknown setting %q in %s", key, path)
			continue
		}
		if d.restart {
			log.Printf("settings: ignoring %q in %s: it can only be set by flag or environment", key, path)
			continue
		}
		v, err := d.decode(raw)
		if err == nil && d.check != nil {
			err = d.check(v)
		}
		if err != nil {
			return nil, fmt.Errorf("%s %w", key, err)
		}
		out[key] = v
	}
	return out, nil
}

func writeSettingsFile(path string, values map[string]any, now time.Time) error {
	encoded := make(map[string]any, len(values))
	for k, v := range values {
		encoded[k] = encodeSetting(v)
	}
	doc := struct {
		Version  int            `json:"version"`
		Updated  time.Time      `json:"updated"`
		Settings map[string]any `json:"settings"`
	}{settingsFileVersion, now.UTC(), encoded}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'))
}

// ─── runtime changes ─────────────────────────────────────────────────────────

// settingsManager owns settings.json while concert runs, and serializes
// changes. mu also guards the app's listener endpoints (see attachEndpoints).
type settingsManager struct {
	mu          sync.Mutex
	path        string            // "" when -data-dir is empty
	file        map[string]any    // values stored in settings.json
	base        map[string]any    // values from flags, environment and defaults
	baseSources map[string]string // where each base value came from
}

func newSettingsManager(cfg config) *settingsManager {
	m := &settingsManager{
		file:        map[string]any{},
		base:        make(map[string]any, len(settingDefs)),
		baseSources: make(map[string]string, len(settingDefs)),
	}
	if cfg.dataDir != "" {
		m.path = settingsPath(cfg.dataDir)
	}
	for k, v := range cfg.settingFile {
		m.file[k] = v
	}
	for i := range settingDefs {
		d := &settingDefs[i]
		if v, ok := cfg.settingBase[d.key]; ok {
			m.base[d.key] = v
		} else {
			m.base[d.key] = d.get(&cfg)
		}
		if s, ok := cfg.settingBaseSources[d.key]; ok {
			m.baseSources[d.key] = s
		} else {
			m.baseSources[d.key] = sourceDefault
		}
	}
	return m
}

// source reports where key's value comes from. Caller holds m.mu or owns m
// exclusively.
func (m *settingsManager) source(key string) string {
	if _, ok := m.file[key]; ok {
		return sourceFile
	}
	return m.baseSources[key]
}

// settingsError carries the HTTP status a failed change should answer with.
type settingsError struct {
	status int
	msg    string
}

func (e *settingsError) Error() string { return e.msg }

func settingsStatus(err error) int {
	var se *settingsError
	if errors.As(err, &se) {
		return se.status
	}
	return http.StatusInternalServerError
}

// changeSettings applies set and reset to the running concert. reset
// removes keys from settings.json, restoring their flag, environment or
// default value. actor is the portal operator's address, or the zero Addr
// for the admin API.
//
// Every value is decoded and checked, the whole configuration is validated,
// a new generation is built, and new listen addresses are bound, all before
// anything is saved. Only then is settings.json written and the change
// swapped in, so a rejected change leaves the file and the running concert
// exactly as they were.
func (a *app) changeSettings(set map[string]json.RawMessage, reset []string, actor netip.Addr) error {
	if len(set)+len(reset) == 0 {
		return &settingsError{http.StatusBadRequest, "no settings to change"}
	}
	m := a.settings
	m.mu.Lock()
	defer m.mu.Unlock()

	prev := a.current()
	cand := prev.cfg
	file := make(map[string]any, len(m.file)+len(set))
	for k, v := range m.file {
		file[k] = v
	}

	var problems []string
	for _, key := range sortedKeys(set) {
		d, ok := settingByKey[key]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: unknown setting", key))
			continue
		}
		if d.restart {
			problems = append(problems, fmt.Sprintf("%s (%s) can only be changed with %s in concert.env and a restart", d.label, d.key, d.env))
			continue
		}
		v, err := d.decode(set[key])
		if err == nil && d.check != nil {
			err = d.check(v)
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s (%s) %v", d.label, d.key, err))
			continue
		}
		d.set(&cand, v)
		file[key] = v
	}
	for _, key := range reset {
		d, ok := settingByKey[key]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: unknown setting", key))
			continue
		}
		if d.restart {
			problems = append(problems, fmt.Sprintf("%s (%s) can only be changed with %s in concert.env and a restart", d.label, d.key, d.env))
			continue
		}
		d.set(&cand, m.base[key])
		delete(file, key)
	}
	if len(problems) > 0 {
		return &settingsError{http.StatusBadRequest, strings.Join(problems, "; ")}
	}

	if err := cand.normalize(); err != nil {
		return &settingsError{http.StatusBadRequest, err.Error()}
	}
	if actor.IsValid() && cand.portal.enabled() && !containsAddr(cand.portal.allow, actor) {
		return &settingsError{http.StatusBadRequest, fmt.Sprintf(
			"portal_allow must still include your address %s, or you would lock yourself out of the portal", actor)}
	}

	g, err := a.buildGeneration(cand, prev)
	if err != nil {
		return &settingsError{http.StatusBadRequest, "concert cannot use these settings: " + err.Error()}
	}
	lp, err := a.prepareListeners(cand)
	if err != nil {
		return &settingsError{http.StatusBadRequest, err.Error()}
	}

	if m.path != "" {
		if err := writeSettingsFile(m.path, file, time.Now()); err != nil {
			lp.abort()
			return &settingsError{http.StatusInternalServerError, "could not save settings: " + err.Error()}
		}
	}
	m.file = file

	if err := a.commit(g, lp); err != nil {
		return &settingsError{http.StatusInternalServerError,
			"settings were saved and applied, but the waiting room rejected part of them: " + err.Error()}
	}
	return nil
}

// settingView is one setting as the portal shows it.
type settingView struct {
	Key     string `json:"key"`
	Group   string `json:"group"`
	Label   string `json:"label"`
	Help    string `json:"help"`
	Kind    string `json:"kind"`
	Flag    string `json:"flag"`
	Env     string `json:"env"`
	Value   any    `json:"value"`
	Source  string `json:"source"`
	Restart bool   `json:"restart"`
}

// settingsViews lists every setting in table order with its running value,
// and returns the path of settings.json ("" when settings are not saved).
func (a *app) settingsViews() ([]settingView, string) {
	m := a.settings
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := a.current().cfg
	out := make([]settingView, 0, len(settingDefs))
	for i := range settingDefs {
		d := &settingDefs[i]
		out = append(out, settingView{
			Key: d.key, Group: d.group, Label: d.label, Help: d.usage, Kind: d.kind,
			Flag: d.flag, Env: d.env, Value: encodeSetting(d.get(&cfg)), Source: m.source(d.key),
			Restart: d.restart,
		})
	}
	return out, m.path
}

// fixedSettings describes what the portal cannot change — secrets and the
// data directory, which are environment- or command-line-only — plus where
// concert is listening right now.
func (a *app) fixedSettings() map[string]string {
	a.settings.mu.Lock()
	mainEP, portalEP := a.mainEP, a.portalEP
	a.settings.mu.Unlock()

	cfg := a.current().cfg
	dataDir := cfg.dataDir
	if dataDir == "" {
		dataDir = "none: changes last until concert restarts"
	}
	secret := "set (CONCERT_ADMIT_SECRET)"
	if cfg.admitSecretGenerated {
		secret = "random at startup (CONCERT_ADMIT_SECRET unset)"
	}
	token := "not set: admin API disabled"
	if cfg.adminToken != "" {
		token = "set (CONCERT_ADMIN_TOKEN)"
	}
	return map[string]string{
		"Data directory":   dataDir,
		"Admission secret": secret,
		"Admin token":      token,
		"Portal pass":      "set (CONCERT_PORTAL_PASS)",
		"Main listener":    mainEP.describe(),
		"Portal listener":  portalEP.describe(),
		"Version":          BinaryVersion(),
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
