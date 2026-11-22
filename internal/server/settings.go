package server

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

	"github.com/andreimerlescu/concert/internal/hop"
	"github.com/andreimerlescu/concert/internal/mailer"
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
// reload.go. The listen addresses and the history log are the exception:
// they are set by flag or environment and take a restart. Secrets
// (CONCERT_ADMIN_TOKEN, CONCERT_ADMIT_SECRET, CONCERT_PORTAL_PASS), -data-dir
// itself and the IP database (NADDR_DATA, NADDR_ADDR) are never stored in
// the file.

const (
	settingsFileName    = "settings.json"
	settingsFileVersion = 1
)

// defaultDataDir is where settings.json, bans.json, the saved queue and the
// history log live unless -data-dir or CONCERT_DATA_DIR says otherwise.
// Tests point it somewhere empty.
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

// List kinds. A setting with a list kind is still a single comma-separated
// string everywhere concert stores or reads it (flags, environment,
// settings.json, the API); the portal shows it as one input per entry and
// checks each entry before joining them with ",".
const (
	listPaths = "path" // entries start with "/"; suffix /* for a prefix
	listCIDRs = "cidr" // entries are IP addresses or CIDR ranges
	listHosts = "host" // entries are bare, fully qualified hostnames
)

// Portal sections, in display order.
const (
	groupRoom       = "Waiting room"
	groupSkip       = "Skip the line"
	groupPriority   = "Priority"
	groupOrigin     = "Origin and listener"
	groupCookies    = "Cookies"
	groupPaths      = "Paths"
	groupAssets     = "Asset tier"
	groupStreams    = "Streams"
	groupAbuse      = "Abuse registry"
	groupTLS        = "TLS"
	groupPortal     = "Admin portal"
	groupEnterprise = "Enterprise security & observability"
	groupPrivacy    = "Privacy & retention"
	groupCluster    = "Cluster sync"
	groupTopology   = "Edge and leaf tiers"
	groupEmail      = "Email delivery"
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
	list    string            // list kind (listPaths, listCIDRs, listHosts): the portal edits it one entry per input
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
	{key: "first_poll_grace", flag: "first-poll-grace", env: "CONCERT_FIRST_POLL_GRACE", group: groupRoom, label: "First-poll grace",
		def: 30 * time.Second, usage: "reclaim a new ticket whose visitor has not polled within this time, 10s-24h and at least twice -retry-after (0 = off)",
		ptr: func(c *config) any { return &c.firstPollGrace }, check: durationZeroOrBetween(minFirstPollGrace, maxFirstPollGrace)},
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
		def: "", usage: "custom waiting room HTML file, empty for Concert's built-in page (must handle cookies_required and room_probe)",
		ptr: func(c *config) any { return &c.htmlFile }},

	// ---- Fast lane ----
	{key: "fastlane_config", flag: "fastlane-config", env: "CONCERT_FASTLANE_CONFIG", group: groupSkip, label: "x402 / NFT configuration file", restart: true,
		def: "", usage: "fast lane JSON (x402 offers and NFT rules; see docs/FASTLANE.md), empty turns wallet access off (flag or CONCERT_FASTLANE_CONFIG only; takes a restart)", ptr: func(c *config) any { return &c.fastlaneFile }},
	{key: "networks_config", flag: "networks-config", env: "CONCERT_NETWORKS_CONFIG", group: groupSkip, label: "Chain endpoints file", restart: true,
		def: "", usage: "chain endpoints JSON for the fast lane's payment networks (see docs/FASTLANE.md); sponsor keys come from CONCERT_STELLAR_FEE_SECRET and CONCERT_HEDERA_FEE_SECRET (flag or CONCERT_NETWORKS_CONFIG only; takes a restart)", ptr: func(c *config) any { return &c.networksFile }},
	{key: "agent_queue", flag: "agent-queue", env: "CONCERT_AGENT_QUEUE", group: groupSkip, label: "AI agents wait in line",
		def: false, usage: "with wallet access on, requests carrying a valid Concert-Session header keep one place in line per session, with no cookies (off by default: agents are also what scalpers use)",
		ptr: func(c *config) any { return &c.agentQueue }},
	{key: "agent_places", flag: "agent-places", env: "CONCERT_AGENT_PLACES", group: groupSkip, label: "Agent places per address",
		def: defaultAgentPlaces, usage: "keyed places one client address (IPv6: its /64) may hold in line; past it, 429 and a strike",
		ptr: func(c *config) any { return &c.agentPlaces }, check: intBetween(1, maxAgentPlaces)},
	// ---- Skip the line ----
	{key: "rate", flag: "rate", env: "CONCERT_RATE", group: groupSkip, label: "Price per position",
		def: 0.0, usage: "base cost per queue position (0 with -surge 0 turns paid skip-the-line off)",
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

	// ---- Priority; see priority.go ----
	{key: "priority_cap", flag: "priority-cap", env: "CONCERT_PRIORITY_CAP", group: groupPriority, label: "Priority lane slots",
		def: 0, usage: "page requests the priority lane allows at once, on top of -cap (0 = a quarter of -cap, at least 1)",
		ptr: func(c *config) any { return &c.priorityCap }, check: intAtLeast(0)},
	{key: "priority_lane_rank", flag: "priority-lane-rank", env: "CONCERT_PRIORITY_LANE_RANK", group: groupPriority, label: "Lowest rank in the lane",
		def: 3, usage: "lowest Concert-Priority rank that skips the line through the priority lane: 1 member, 2 prospect, 3 customer, 4 subscriber, 5 checkout, 6 staff, 7 nobody",
		ptr: func(c *config) any { return &c.priorityLaneRank }, check: intBetween(1, 7)},
	{key: "priority_wait", flag: "priority-wait", env: "CONCERT_PRIORITY_WAIT", group: groupPriority, label: "Priority lane wait",
		def: 5 * time.Second, usage: "longest a priority request waits for a lane slot before joining the line, 0s-1m",
		ptr: func(c *config) any { return &c.priorityWait }, check: durationBetween(0, time.Minute)},
	{key: "priority_forms", flag: "priority-forms", env: "CONCERT_PRIORITY_FORMS", group: groupPriority, label: "Forms skip the line",
		def: true, usage: "form submissions from admitted visitors use the priority lane instead of the waiting room, and get 503 rather than queuing when it is full",
		ptr: func(c *config) any { return &c.priorityForms }},
	{key: "priority_order_line", flag: "priority-order-line", env: "CONCERT_PRIORITY_ORDER_LINE", group: groupPriority, label: "Order the line by rank",
		def: true, usage: "ranked visitors who wait are placed ahead of lower ranks, in arrival order within a rank; false keeps the line in strict arrival order",
		ptr: func(c *config) any { return &c.priorityOrderLine }},

	// ---- Origin and listener ----
	{key: "listen", flag: "listen", env: "CONCERT_LISTEN", group: groupOrigin, label: "Listen address", restart: true,
		def: ":8080", usage: "address to listen on (flag or CONCERT_LISTEN only; takes a restart)",
		ptr: func(c *config) any { return &c.listen }},
	{key: "upstream", flag: "upstream", env: "CONCERT_UPSTREAM", group: groupOrigin, label: "Upstream origin",
		def: "http://127.0.0.1:3000", usage: "origin to proxy to (http://, https://, fcgi://host:port, or fcgi+unix:///path/to/php-fpm.sock)",
		ptr: func(c *config) any { return &c.upstream }},
	{key: "fcgi_index", flag: "fcgi-index", env: "CONCERT_FCGI_INDEX", group: groupOrigin, label: "FastCGI index script",
		def: "index.php", usage: "entrypoint script for FastCGI try_files fallback and directory index",
		ptr: func(c *config) any { return &c.fcgiIndex }},
	{key: "fcgi_deny_paths", flag: "fcgi-deny-paths", env: "CONCERT_FCGI_DENY_PATHS", group: groupOrigin, label: "FastCGI denied paths", restart: true,
		def: "/wp-content/uploads/*,/wp-config.php", usage: "comma-separated paths forbidden from FastCGI PHP execution (403); suffix /* for a prefix",
		ptr: func(c *config) any { return &c.fcgiDenyPaths }, check: checkPathList},
	{key: "upstream_timeout", flag: "upstream-timeout", env: "CONCERT_UPSTREAM_TIMEOUT", group: groupOrigin, label: "Upstream header timeout",
		def: 30 * time.Second, usage: "upstream response header timeout",
		ptr: func(c *config) any { return &c.headerTimeout }, check: durationAtLeast(0)},
	{key: "preserve_host", flag: "preserve-host", env: "CONCERT_PRESERVE_HOST", group: groupOrigin, label: "Preserve Host header",
		def: true, usage: "forward the client's Host header to the upstream",
		ptr: func(c *config) any { return &c.preserveHost }},
	{key: "trusted_proxies", flag: "trusted-proxies", env: "CONCERT_TRUSTED_PROXIES", group: groupOrigin, label: "Trusted proxies",
		def: "127.0.0.1/32,::1/128", usage: "comma-separated CIDRs whose X-Forwarded-For and X-Forwarded-Proto are trusted",
		ptr: func(c *config) any { return &c.trustedProxies }, check: checkCIDRList, list: listCIDRs},
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
		ptr: func(c *config) any { return &c.bypass }, check: checkPathList, list: listPaths},
	{key: "assets", flag: "assets", env: "CONCERT_ASSETS", group: groupPaths, label: "Asset paths",
		def: "", usage: "comma-separated asset paths that require an admission pass; suffix /* for a prefix",
		ptr: func(c *config) any { return &c.assets }, check: checkPathList, list: listPaths},
	{key: "asset_public", flag: "asset-public", env: "CONCERT_ASSET_PUBLIC", group: groupPaths, label: "Public asset paths",
		def: "", usage: "comma-separated asset paths served without a pass, still under the global asset cap",
		ptr: func(c *config) any { return &c.assetPublic }, check: checkPathList, list: listPaths},
	{key: "ban_paths", flag: "ban-paths", env: "CONCERT_BAN_PATHS", group: groupPaths, label: "Ban paths",
		def: "", usage: "comma-separated paths that ban the client on first hit; suffix /* for a prefix",
		ptr: func(c *config) any { return &c.banPaths }, check: checkPathList, list: listPaths},

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
	{key: "static_root", flag: "static-root", env: "CONCERT_STATIC_ROOT", group: groupAssets, label: "Static document root", restart: true,
		def: "", usage: "host directory served directly off disk via os.Root (also DOCUMENT_ROOT for FastCGI; flag or CONCERT_STATIC_ROOT only)",
		ptr: func(c *config) any { return &c.staticRoot }},
	{key: "static_mounts", flag: "static-mounts", env: "CONCERT_STATIC_MOUNTS", group: groupAssets, label: "Static prefix mounts", restart: true,
		def: "", usage: "comma-separated /prefix=/dir static asset mounts confined by os.Root (flag or CONCERT_STATIC_MOUNTS only)",
		ptr: func(c *config) any { return &c.staticMounts }},
	{key: "static_allow_ext", flag: "static-allow-ext", env: "CONCERT_STATIC_ALLOW_EXT", group: groupAssets, label: "Extra static extensions",
		def: "", usage: "comma-separated extra safe file extensions added to the static allowlist (scripts and secrets remain hard-blocked)",
		ptr: func(c *config) any { return &c.staticAllowExt }},
	{key: "static_cache_control", flag: "static-cache-control", env: "CONCERT_STATIC_CACHE_CONTROL", group: groupAssets, label: "Static Cache-Control",
		def: "public, max-age=3600", usage: "Cache-Control header applied to static assets served directly from disk",
		ptr: func(c *config) any { return &c.staticCacheControl }},
	{key: "static_fallback", flag: "static-fallback", env: "CONCERT_STATIC_FALLBACK", group: groupAssets, label: "Fallback on missing static files",
		def: false, usage: "forward missing mounted or asset-tier static files upstream instead of answering fast 404",
		ptr: func(c *config) any { return &c.staticFallback }},
	{key: "compress", flag: "compress", env: "CONCERT_COMPRESS", group: groupAssets, label: "Gzip compression",
		def: true, usage: "enable on-the-fly stdlib gzip (>=1 KiB) for locally served static files and FastCGI responses",
		ptr: func(c *config) any { return &c.compress }},

	// ---- Streams; see stream.go ----
	{key: "stream_paths", flag: "stream-paths", env: "CONCERT_STREAM_PATHS", group: groupStreams, label: "Stream paths",
		def: "", usage: "comma-separated WebSocket and server-sent event paths: outside the waiting room, admission pass required; suffix /* for a prefix",
		ptr: func(c *config) any { return &c.streamPaths }, check: checkPathList, list: listPaths},
	{key: "stream_cap", flag: "stream-cap", env: "CONCERT_STREAM_CAP", group: groupStreams, label: "Concurrent streams",
		def: 1000, usage: "most stream connections open at once; more get 503",
		ptr: func(c *config) any { return &c.streamCap }, check: intAtLeast(1)},

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
		ptr: func(c *config) any { return &c.abuseAllow }, check: checkCIDRList, list: listCIDRs},

	// ---- TLS; see tls.go ----
	{key: "tls_domains", flag: "tls-domains", env: "CONCERT_TLS_DOMAINS", group: groupTLS, label: "Certificate hostnames",
		def: "", usage: "comma-separated hostnames to get Let's Encrypt certificates for; enables TLS on -listen",
		ptr: func(c *config) any { return &c.tlsDomains }, check: checkHostList, list: listHosts},
	{key: "tls_email", flag: "tls-email", env: "CONCERT_TLS_EMAIL", group: groupTLS, label: "ACME contact email",
		def: "", usage: "contact email for the ACME account (expiry notices)",
		ptr: func(c *config) any { return &c.tlsEmail }},
	{key: "tls_cache", flag: "tls-cache", env: "CONCERT_TLS_CACHE", group: groupTLS, label: "Certificate cache",
		def: "/var/lib/concert/acme", usage: "directory for the ACME account key and certificates",
		ptr: func(c *config) any { return &c.tlsCacheDir }},
	{key: "tls_staging", flag: "tls-staging", env: "CONCERT_TLS_STAGING", group: groupTLS, label: "Use staging directory",
		def: false, usage: "use the Let's Encrypt staging directory (untrusted certificates, generous rate limits)",
		ptr: func(c *config) any { return &c.tlsStaging }},
	{key: "tls_cert", flag: "tls-cert", env: "CONCERT_TLS_CERT", group: groupTLS, label: "TLS certificate file (PEM)",
		def: "", usage: "PEM certificate chain file for enterprise PKI TLS (hot-reloaded on change)",
		ptr: func(c *config) any { return &c.tlsCert }},
	{key: "tls_key", flag: "tls-key", env: "CONCERT_TLS_KEY", group: groupTLS, label: "TLS private key file (PEM)",
		def: "", usage: "PEM private key file for enterprise PKI TLS (hot-reloaded on change)",
		ptr: func(c *config) any { return &c.tlsKey }},
	{key: "tls_client_ca", flag: "tls-client-ca", env: "CONCERT_TLS_CLIENT_CA", group: groupTLS, label: "Client CA bundle (mTLS)", restart: true,
		def: "", usage: "PEM CA bundle used to verify client certificates on the main HTTPS listener (VerifyClientCertIfGiven by default so public browsers keep working)",
		ptr: func(c *config) any { return &c.tlsClientCA }},
	{key: "tls_require_client_cert", flag: "tls-require-client-cert", env: "CONCERT_TLS_REQUIRE_CLIENT_CERT", group: groupTLS, label: "Require client cert for all TLS", restart: true,
		def: false, usage: "require a verified client certificate for every connection on the main TLS listener (internal-only leaves)",
		ptr: func(c *config) any { return &c.tlsRequireClientCert }},
	{key: "tls_min_version", flag: "tls-min-version", env: "CONCERT_TLS_MIN_VERSION", group: groupTLS, label: "Minimum TLS version",
		def: "1.2", usage: "minimum TLS version on listeners (1.2 or 1.3)",
		ptr: func(c *config) any { return &c.tlsMinVersion }},
	{key: "hsts_max_age", flag: "hsts-max-age", env: "CONCERT_HSTS_MAX_AGE", group: groupTLS, label: "HSTS max-age (seconds)",
		def: 0, usage: "Strict-Transport-Security max-age in seconds on HTTPS responses (0 disables)",
		ptr: func(c *config) any { return &c.hstsMaxAge }, check: intAtLeast(0)},
	{key: "tls_http_listen", flag: "tls-http-listen", env: "CONCERT_TLS_HTTP_LISTEN", group: groupTLS, label: "HTTP redirect / ACME HTTP-01 address", restart: true,
		def: "", usage: "companion plain-HTTP listener (e.g. :80) serving ACME HTTP-01 challenges and redirecting HTTP to HTTPS (flag or CONCERT_TLS_HTTP_LISTEN only)",
		ptr: func(c *config) any { return &c.tlsHTTPListen }},

	// ---- Upstream resilience & mTLS; see upstream.go ----
	{key: "upstream_health_path", flag: "upstream-health-path", env: "CONCERT_UPSTREAM_HEALTH_PATH", group: groupOrigin, label: "Upstream health path",
		def: "", usage: "active health-check path on each upstream backend (e.g. /healthz; empty disables active probing)",
		ptr: func(c *config) any { return &c.upstreamHealthPath }},
	{key: "upstream_health_interval", flag: "upstream-health-interval", env: "CONCERT_UPSTREAM_HEALTH_INTERVAL", group: groupOrigin, label: "Upstream health interval",
		def: 10 * time.Second, usage: "how often active upstream health probes run",
		ptr: func(c *config) any { return &c.upstreamHealthInterval }, check: durationAtLeast(time.Second)},
	{key: "upstream_cb_failures", flag: "upstream-cb-failures", env: "CONCERT_UPSTREAM_CB_FAILURES", group: groupOrigin, label: "Circuit breaker failures",
		def: 0, usage: "consecutive upstream 502/503/504 or transport failures to open circuit breaker (0 disables)",
		ptr: func(c *config) any { return &c.upstreamCBFailures }, check: intAtLeast(0)},
	{key: "upstream_cb_cooldown", flag: "upstream-cb-cooldown", env: "CONCERT_UPSTREAM_CB_COOLDOWN", group: groupOrigin, label: "Circuit breaker cooldown",
		def: 15 * time.Second, usage: "how long an open upstream circuit stays open before retrying",
		ptr: func(c *config) any { return &c.upstreamCBCooldown }, check: durationAtLeast(time.Second)},
	{key: "upstream_retries", flag: "upstream-retries", env: "CONCERT_UPSTREAM_RETRIES", group: groupOrigin, label: "Upstream retries",
		def: 1, usage: "with several upstreams, retry a bodyless request on another one after a connection failure or a leaf's backpressure 503, 0-5",
		ptr: func(c *config) any { return &c.upstreamRetries }, check: intBetween(0, 5)},
	{key: "upstream_ca", flag: "upstream-ca", env: "CONCERT_UPSTREAM_CA", group: groupOrigin, label: "Upstream CA bundle", restart: true,
		def: "", usage: "PEM CA certificate bundle for verifying internal HTTPS origins",
		ptr: func(c *config) any { return &c.upstreamCA }},
	{key: "upstream_client_cert", flag: "upstream-client-cert", env: "CONCERT_UPSTREAM_CLIENT_CERT", group: groupOrigin, label: "Upstream mTLS client cert", restart: true,
		def: "", usage: "PEM client certificate for mutual TLS (mTLS) to HTTPS origins",
		ptr: func(c *config) any { return &c.upstreamClientCert }},
	{key: "upstream_client_key", flag: "upstream-client-key", env: "CONCERT_UPSTREAM_CLIENT_KEY", group: groupOrigin, label: "Upstream mTLS client key", restart: true,
		def: "", usage: "PEM client private key for mutual TLS (mTLS) to HTTPS origins",
		ptr: func(c *config) any { return &c.upstreamClientKey }},

	// ---- Admin portal; see portal.go. ----
	{key: "portal_listen", flag: "portal-listen", env: "CONCERT_PORTAL_LISTEN", group: groupPortal, label: "Portal address", restart: true,
		def: "127.0.0.1:8081", usage: "admin portal address, empty turns the portal off (flag or CONCERT_PORTAL_LISTEN only; takes a restart); requires CONCERT_PORTAL_PASS, CONCERT_PORTAL_USERS, or SSO",
		ptr: func(c *config) any { return &c.portal.listen }},
	{key: "portal_allow", flag: "portal-allow", env: "CONCERT_PORTAL_ALLOW", group: groupPortal, label: "Portal allowlist",
		def: "127.0.0.1/32,::1/128", usage: "comma-separated CIDRs allowed to reach the admin portal",
		ptr: func(c *config) any { return &c.portal.allowSpec }, check: checkCIDRList, list: listCIDRs},
	{key: "portal_session_ttl", flag: "portal-session-ttl", env: "CONCERT_PORTAL_SESSION_TTL", group: groupPortal, label: "Portal session length",
		def: 8 * time.Hour, usage: "admin portal sign-in lifetime",
		ptr: func(c *config) any { return &c.portal.sessionTTL }, check: durationAtLeast(5 * time.Minute)},
	{key: "portal_secure_cookie", flag: "portal-secure-cookie", env: "CONCERT_PORTAL_SECURE_COOKIE", group: groupPortal, label: "Secure portal cookie",
		def: false, usage: "mark the portal session cookie Secure (portal served over HTTPS)",
		ptr: func(c *config) any { return &c.portal.secureCookie }},
	{key: "portal_tls_cert", flag: "portal-tls-cert", env: "CONCERT_PORTAL_TLS_CERT", group: groupPortal, label: "Portal TLS certificate", restart: true,
		def: "", usage: "PEM certificate file to serve the admin portal natively over HTTPS",
		ptr: func(c *config) any { return &c.portal.tlsCert }},
	{key: "portal_tls_key", flag: "portal-tls-key", env: "CONCERT_PORTAL_TLS_KEY", group: groupPortal, label: "Portal TLS key", restart: true,
		def: "", usage: "PEM private key file to serve the admin portal natively over HTTPS",
		ptr: func(c *config) any { return &c.portal.tlsKey }},
	{key: "portal_sso_header", flag: "portal-sso-header", env: "CONCERT_PORTAL_SSO_HEADER", group: groupPortal, label: "SSO identity header", restart: true,
		def: "", usage: "header set by a trusted SSO proxy (e.g. X-Forwarded-Email) identifying the signed-in user",
		ptr: func(c *config) any { return &c.portal.ssoHeader }},
	{key: "portal_sso_role_header", flag: "portal-sso-role-header", env: "CONCERT_PORTAL_SSO_ROLE_HEADER", group: groupPortal, label: "SSO role/group header", restart: true,
		def: "", usage: "header set by a trusted SSO proxy carrying RBAC roles/groups (viewer, operator, admin)",
		ptr: func(c *config) any { return &c.portal.ssoRoleHeader }},
	{key: "portal_sso_default_role", flag: "portal-sso-default-role", env: "CONCERT_PORTAL_SSO_DEFAULT_ROLE", group: groupPortal, label: "SSO default role", restart: true,
		def: "viewer", usage: "default RBAC role for SSO users when no role header matches (viewer, operator, admin)",
		ptr: func(c *config) any { return &c.portal.ssoDefaultRole }},
	{key: "portal_trusted_proxies", flag: "portal-trusted-proxies", env: "CONCERT_PORTAL_TRUSTED_PROXIES", group: groupPortal, label: "Portal trusted SSO proxies", restart: true,
		def: "", usage: "comma-separated CIDRs of identity proxies trusted to set SSO headers",
		ptr: func(c *config) any { return &c.portal.trustedProxiesSpec }, check: checkCIDRList},
	{key: "history_log", flag: "history-log", env: "CONCERT_HISTORY_LOG", group: groupPortal, label: "History log file", restart: true,
		def: "", usage: "JSON-lines file the portal's request history is written to and restored from; empty means history.jsonl in -data-dir, off keeps it in memory only (flag or CONCERT_HISTORY_LOG only; takes a restart)",
		ptr: func(c *config) any { return &c.historyLog }},

	// ---- Enterprise security & observability ----
	{key: "stats_auth", flag: "stats-auth", env: "CONCERT_STATS_AUTH", group: groupEnterprise, label: "Require auth on stats/metrics",
		def: false, usage: "require bearer token authentication on /_room/stats and /_room/metrics",
		ptr: func(c *config) any { return &c.statsAuth }},
	{key: "read_only_settings", flag: "read-only-settings", env: "CONCERT_READ_ONLY_SETTINGS", group: groupEnterprise, label: "Read-only settings (GitOps)", restart: true,
		def: false, usage: "forbid live mutations to settings.json via portal or API for immutable/GitOps deployments",
		ptr: func(c *config) any { return &c.readOnlySettings }},
	{key: "hardened", flag: "enterprise-hardened", env: "CONCERT_HARDENED", group: groupEnterprise, label: "Enterprise hardened preset", restart: true,
		def: false, usage: "enforce baseline enterprise security requirements at startup (explicit secrets, secure cookies, stats auth, audit log)",
		ptr: func(c *config) any { return &c.hardened }},
	{key: "audit_log", flag: "audit-log", env: "CONCERT_AUDIT_LOG", group: groupEnterprise, label: "Tamper-evident audit log", restart: true,
		def: "", usage: "hash-chained JSONL audit log path; empty means audit.jsonl in -data-dir, off disables persistence",
		ptr: func(c *config) any { return &c.auditLog }},
	{key: "log_format", flag: "log-format", env: "CONCERT_LOG_FORMAT", group: groupEnterprise, label: "Log format", restart: true,
		def: "text", usage: "access and structured log format: text or json",
		ptr: func(c *config) any { return &c.logFormat }},
	{key: "log_level", flag: "log-level", env: "CONCERT_LOG_LEVEL", group: groupEnterprise, label: "Log level", restart: true,
		def: "info", usage: "structured log level: debug, info, warn, error",
		ptr: func(c *config) any { return &c.logLevel }},

	// ---- Privacy & retention; see privacy.go ----
	{key: "privacy_scrub_query", flag: "privacy-scrub-query", env: "CONCERT_PRIVACY_SCRUB_QUERY", group: groupPrivacy, label: "Scrub sensitive query params",
		def: true, usage: "redact sensitive query parameters (tokens, secrets, keys, PII) in logs and history",
		ptr: func(c *config) any { return &c.privacyScrubQuery }},
	{key: "privacy_strip_query", flag: "privacy-strip-query", env: "CONCERT_PRIVACY_STRIP_QUERY", group: groupPrivacy, label: "Strip all query strings",
		def: false, usage: "omit all query strings from logs and history (recommended for PCI/HIPAA)",
		ptr: func(c *config) any { return &c.privacyStripQuery }},
	{key: "privacy_anonymize_ip", flag: "privacy-anonymize-ip", env: "CONCERT_PRIVACY_ANONYMIZE_IP", group: groupPrivacy, label: "Anonymize IPs in logs/history",
		def: false, usage: "mask client IPs to /24 (IPv4) and /48 (IPv6) in access logs and request history",
		ptr: func(c *config) any { return &c.privacyAnonymizeIP }},
	{key: "history_retention", flag: "history-retention", env: "CONCERT_HISTORY_RETENTION", group: groupPrivacy, label: "History retention",
		def: 72 * time.Hour, usage: "how long client history and ended bans are kept (1h-720h)",
		ptr: func(c *config) any { return &c.historyRetention }, check: durationBetween(time.Hour, 30*24*time.Hour)},

	// ---- Cluster sync; see cluster.go ----
	{key: "redis_addr", flag: "redis-addr", env: "CONCERT_REDIS_ADDR", group: groupCluster, label: "Redis/Valkey address", restart: true,
		def: "", usage: "host:port of Redis/Valkey for multi-node HA ban synchronization (empty disables)",
		ptr: func(c *config) any { return &c.redisAddr }},
	{key: "redis_tls", flag: "redis-tls", env: "CONCERT_REDIS_TLS", group: groupCluster, label: "Redis TLS", restart: true,
		def: false, usage: "use TLS 1.2+ when connecting to Redis/Valkey",
		ptr: func(c *config) any { return &c.redisTLS }},
	{key: "redis_prefix", flag: "redis-prefix", env: "CONCERT_REDIS_PREFIX", group: groupCluster, label: "Redis key prefix", restart: true,
		def: "concert", usage: "key and pubsub channel prefix for cluster state in Redis/Valkey",
		ptr: func(c *config) any { return &c.redisPrefix }},

	// ---- Edge and leaf tiers; see topology.go and docs/TOPOLOGY.md ----
	{key: "role", flag: "role", env: "CONCERT_ROLE", group: groupTopology, label: "Node role", restart: true,
		def: roleStandalone, usage: "standalone (one tier), edge (waiting room in front of leaf Concerts) or leaf (protects one host behind an edge)",
		ptr: func(c *config) any { return &c.role }, check: checkRole},
	{key: "node_id", flag: "node-id", env: "CONCERT_NODE_ID", group: groupTopology, label: "Node ID", restart: true,
		def: "", usage: "this node's ID in trust-chain claims and leaf reports, 1-32 of [A-Za-z0-9._-] (empty derives one from the hostname)",
		ptr: func(c *config) any { return &c.nodeID }, check: checkNodeID},
	{key: "hop_peers", flag: "hop-peers", env: "CONCERT_HOP_PEERS", group: groupTopology, label: "Hop peers (leaf)",
		def: "", usage: "leaf: CIDRs whose connections may present Concert-Hop claims: the edges, or the load balancer between tiers; required with -role leaf",
		ptr: func(c *config) any { return &c.hopPeers }, check: checkCIDRList, list: listCIDRs},
	{key: "hop_max_skew", flag: "hop-max-skew", env: "CONCERT_HOP_MAX_SKEW", group: groupTopology, label: "Hop clock skew", restart: true,
		def: hop.DefaultMaxSkew, usage: "leaf: how far a claim's timestamp may be from this clock, 1s-5m",
		ptr: func(c *config) any { return &c.hopMaxSkew }, check: durationBetween(time.Second, 5*time.Minute)},
	{key: "hop_wait", flag: "hop-wait", env: "CONCERT_HOP_WAIT", group: groupTopology, label: "Hop host-slot wait (leaf)",
		def: 2 * time.Second, usage: "leaf: how long an edge's page request waits for a host slot before 503 backpressure, 0s-30s",
		ptr: func(c *config) any { return &c.hopWait }, check: durationBetween(0, 30*time.Second)},
	{key: "hop_replay_guard", flag: "hop-replay-guard", env: "CONCERT_HOP_REPLAY_GUARD", group: groupTopology, label: "Hop nonce replay guard (leaf)",
		def: true, usage: "leaf: reject replayed single-use Concert-Hop nonces within 2x -hop-max-skew",
		ptr: func(c *config) any { return &c.hopReplayGuard }},
	{key: "hop_require_nonce", flag: "hop-require-nonce", env: "CONCERT_HOP_REQUIRE_NONCE", group: groupTopology, label: "Require hop nonces (leaf)",
		def: false, usage: "leaf: reject legacy Concert-Hop claims without a single-use nonce (required in -enterprise-hardened mode)",
		ptr: func(c *config) any { return &c.hopRequireNonce }},
	{key: "hop_require_mtls", flag: "hop-require-mtls", env: "CONCERT_HOP_REQUIRE_MTLS", group: groupTopology, label: "Require mTLS for hop claims (leaf)",
		def: false, usage: "leaf: require a verified TLS client certificate (-tls-client-ca) on Concert-Hop claims and /_room/hop/* while still allowing direct public browsers on HTTPS",
		ptr: func(c *config) any { return &c.hopRequireMTLS }},
	{key: "host_cap", flag: "host-cap", env: "CONCERT_HOST_CAP", group: groupTopology, label: "Host capacity (leaf)",
		def: 0, usage: "leaf: page requests this host serves at once from every source; 0 uses capacity.json from the benchmark, then -cap",
		ptr: func(c *config) any { return &c.hostCap }, check: intAtLeast(0)},
	{key: "hop_leaves", flag: "hop-leaves", env: "CONCERT_HOP_LEAVES", group: groupTopology, label: "Leaf control URLs (edge)",
		def: "", usage: "edge: comma-separated base URLs of the leaf Concerts to poll and sync bans to; empty means the -upstream targets (no load balancer between tiers)",
		ptr: func(c *config) any { return &c.hopLeaves }, check: checkURLList},
	{key: "hop_poll", flag: "hop-poll", env: "CONCERT_HOP_POLL", group: groupTopology, label: "Leaf poll interval (edge)",
		def: 2 * time.Second, usage: "edge: how often each leaf's capacity is read and bans are synced, 500ms-1m",
		ptr: func(c *config) any { return &c.hopPoll }, check: durationBetween(500*time.Millisecond, time.Minute)},
	{key: "hop_auto_cap", flag: "hop-auto-cap", env: "CONCERT_HOP_AUTO_CAP", group: groupTopology, label: "Size room from leaves (edge)",
		def: true, usage: "edge: set the room's capacity to what healthy leaves report, never above -cap",
		ptr: func(c *config) any { return &c.hopAutoCap }},
	{key: "bench_on_start", flag: "bench-on-start", env: "CONCERT_BENCH_ON_START", group: groupTopology, label: "Benchmark on first start (leaf)", restart: true,
		def: false, usage: "leaf: before serving, crawl the upstream with the capacity benchmark when capacity.json is missing, and use its result as the host capacity",
		ptr: func(c *config) any { return &c.benchOnStart }},
	{key: "bench_p95", flag: "bench-p95", env: "CONCERT_BENCH_P95", group: groupTopology, label: "Benchmark p95 limit", restart: true,
		def: 2 * time.Second, usage: "the p95 latency the startup benchmark holds the application to, 100ms-1m",
		ptr: func(c *config) any { return &c.benchP95 }, check: durationBetween(100*time.Millisecond, time.Minute)},
	{key: "bench_max_lemmings", flag: "bench-max-lemmings", env: "CONCERT_BENCH_MAX_LEMMINGS", group: groupTopology, label: "Benchmark lemming ceiling", restart: true,
		def: 1024, usage: "the most concurrent lemmings the startup benchmark tries, 1-100000",
		ptr: func(c *config) any { return &c.benchMaxLemmings }, check: intBetween(1, 100000)},

	// ---- Email delivery; see mailer.go and internal/mailer ----
	{key: "email_provider", flag: "email-provider", env: "CONCERT_EMAIL_PROVIDER", group: groupEmail, label: "Delivery provider",
		def: "", usage: "administrator alert delivery provider: empty (disabled), smtp, resend, or sendpanda",
		ptr: func(c *config) any { return &c.email.provider }, check: checkEmailProvider},
	{key: "email_smtp_host", flag: "email-smtp-host", env: "CONCERT_EMAIL_SMTP_HOST", group: groupEmail, label: "SMTP host",
		def: "", usage: "SMTP relay hostname (for -email-provider smtp)",
		ptr: func(c *config) any { return &c.email.smtpHost }},
	{key: "email_smtp_port", flag: "email-smtp-port", env: "CONCERT_EMAIL_SMTP_PORT", group: groupEmail, label: "SMTP port",
		def: 587, usage: "SMTP port (587 for STARTTLS, 465 for implicit TLS)",
		ptr: func(c *config) any { return &c.email.smtpPort }, check: intBetween(0, 65535)},
	{key: "email_smtp_tls", flag: "email-smtp-tls", env: "CONCERT_EMAIL_SMTP_TLS", group: groupEmail, label: "SMTP TLS mode",
		def: mailer.TLSStartTLS, usage: "SMTP transport security: starttls, tls (implicit SMTPS), or none (local relay only)",
		ptr: func(c *config) any { return &c.email.smtpTLS }, check: checkSMTPTLS},
	{key: "email_smtp_user", flag: "email-smtp-user", env: "CONCERT_EMAIL_SMTP_USER", group: groupEmail, label: "SMTP username",
		def: "", usage: "SMTP authentication username (password comes from CONCERT_SMTP_PASS or encrypted email-secrets.json)",
		ptr: func(c *config) any { return &c.email.smtpUser }},
	{key: "email_resend_url", flag: "email-resend-url", env: "CONCERT_EMAIL_RESEND_URL", group: groupEmail, label: "Resend API base URL",
		def: "", usage: "Resend REST API base URL (empty uses https://api.resend.com)",
		ptr: func(c *config) any { return &c.email.resendURL }, check: checkOptionalHTTPURL},
	{key: "email_sendpanda_url", flag: "email-sendpanda-url", env: "CONCERT_EMAIL_SENDPANDA_URL", group: groupEmail, label: "SendPanda API base URL",
		def: "", usage: "SendPanda REST API base URL (empty uses https://api.sendpanda.email/v1)",
		ptr: func(c *config) any { return &c.email.sendPandaURL }, check: checkOptionalHTTPURL},
	{key: "email_from_name", flag: "email-from-name", env: "CONCERT_EMAIL_FROM_NAME", group: groupEmail, label: "Sender display name",
		def: "Concert", usage: "display name on outgoing administrator digest emails",
		ptr: func(c *config) any { return &c.email.fromName }},
	{key: "email_from_addr", flag: "email-from-addr", env: "CONCERT_EMAIL_FROM_ADDR", group: groupEmail, label: "Sender email address",
		def: "", usage: "From email address on outgoing digests (e.g. alerts@example.com)",
		ptr: func(c *config) any { return &c.email.fromAddr }, check: checkOptionalEmail},
	{key: "email_to", flag: "email-to", env: "CONCERT_EMAIL_TO", group: groupEmail, label: "Administrator recipients",
		def: "", usage: "comma-separated administrator email addresses to receive scheduled digests",
		ptr: func(c *config) any { return &c.email.toAddrs }, check: checkEmailList},
	{key: "email_dkim_selector", flag: "email-dkim-selector", env: "CONCERT_EMAIL_DKIM_SELECTOR", group: groupEmail, label: "DKIM selector",
		def: "", usage: "optional DKIM DNS selector verified under <selector>._domainkey.<from-domain>",
		ptr: func(c *config) any { return &c.email.dkimSelector }},
	{key: "email_cadence_max", flag: "email-cadence-max", env: "CONCERT_EMAIL_CADENCE_MAX", group: groupEmail, label: "Max emails per window",
		def: 1, usage: "maximum digest emails delivered per cadence window (1-1000, paced evenly at window / max)",
		ptr: func(c *config) any { return &c.email.cadenceMax }, check: intBetween(1, mailer.MaxCadenceEmails)},
	{key: "email_cadence_window", flag: "email-cadence-window", env: "CONCERT_EMAIL_CADENCE_WINDOW", group: groupEmail, label: "Cadence window value",
		def: 15, usage: "numeric length of the digest cadence window (combined with -email-cadence-unit, 15m to 30d)",
		ptr: func(c *config) any { return &c.email.cadenceWindowValue }, check: intAtLeast(1)},
	{key: "email_cadence_unit", flag: "email-cadence-unit", env: "CONCERT_EMAIL_CADENCE_UNIT", group: groupEmail, label: "Cadence window unit",
		def: mailer.UnitMinutes, usage: "unit for the digest cadence window: minutes, hours, or days",
		ptr: func(c *config) any { return &c.email.cadenceWindowUnit }, check: checkCadenceUnit},
	{key: "email_events", flag: "email-events", env: "CONCERT_EMAIL_EVENTS", group: groupEmail, label: "Subscribed event categories",
		def: "", usage: "comma-separated event categories to queue (empty = all; none = disabled; silence,capacity,bans,fastlane,queue,security)",
		ptr: func(c *config) any { return &c.email.events }, check: checkEmailEvents},
	{key: "email_org_name", flag: "email-org-name", env: "CONCERT_EMAIL_ORG_NAME", group: groupEmail, label: "Organization name",
		def: "", usage: "sender organization name displayed in compliance email headers and footers",
		ptr: func(c *config) any { return &c.email.orgName }},
	{key: "email_postal_address", flag: "email-postal-address", env: "CONCERT_EMAIL_POSTAL_ADDRESS", group: groupEmail, label: "Physical postal address",
		def: "", usage: "organization physical mailing address included in compliance email footers (CAN-SPAM)",
		ptr: func(c *config) any { return &c.email.postalAddress }},
	{key: "email_privacy_url", flag: "email-privacy-url", env: "CONCERT_EMAIL_PRIVACY_URL", group: groupEmail, label: "Privacy policy URL",
		def: "", usage: "link to your privacy policy included in compliance email footers",
		ptr: func(c *config) any { return &c.email.privacyURL }, check: checkOptionalHTTPURL},
	{key: "email_terms_url", flag: "email-terms-url", env: "CONCERT_EMAIL_TERMS_URL", group: groupEmail, label: "Terms URL",
		def: "", usage: "link to your terms or operational notice included in compliance email footers",
		ptr: func(c *config) any { return &c.email.termsURL }, check: checkOptionalHTTPURL},
	{key: "email_portal_url", flag: "email-portal-url", env: "CONCERT_EMAIL_PORTAL_URL", group: groupEmail, label: "Admin portal link URL",
		def: "", usage: "URL linked in digest emails so administrators can jump directly to this Concert portal",
		ptr: func(c *config) any { return &c.email.portalURL }, check: checkOptionalHTTPURL},
	{key: "email_public_base_url", flag: "email-public-base-url", env: "CONCERT_EMAIL_PUBLIC_BASE_URL", group: groupEmail, label: "Public base URL (unsubscribe)",
		def: "", usage: "public origin URL used to build signed RFC 8058 one-click /_concert/email/unsubscribe links",
		ptr: func(c *config) any { return &c.email.publicBaseURL }, check: checkOptionalHTTPURL},
	{key: "email_cluster_dedupe", flag: "email-cluster-dedupe", env: "CONCERT_EMAIL_CLUSTER_DEDUPE", group: groupEmail, label: "Cluster alert deduplication",
		def: true, usage: "when -redis-addr is set, deduplicate shared cluster alert fingerprints across peers via fail-open Redis leases",
		ptr: func(c *config) any { return &c.email.clusterDedupe }},
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
		if d.list != "" && d.kind != kindString {
			panic("settings: list kind on a non-string setting " + d.key)
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

// checkPathList validates a comma-separated path list from the file or the
// portal: every entry must start with "/", contain no whitespace, and appear
// only once. Empty entries (a stray or trailing comma) are ignored, as
// parsePaths ignores them. Conflicts between lists and reserved paths are
// caught later by validateRoutes.
func checkPathList(v any) error {
	seen := map[string]bool{}
	for _, entry := range strings.Split(v.(string), ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.HasPrefix(entry, "/") {
			return fmt.Errorf("entry %q must start with /", entry)
		}
		if strings.ContainsAny(entry, " \t\r\n") {
			return fmt.Errorf("entry %q must not contain spaces", entry)
		}
		if seen[entry] {
			return fmt.Errorf("lists %q more than once", entry)
		}
		seen[entry] = true
	}
	return nil
}

// checkCIDRList validates a comma-separated address list from the file or
// the portal: every entry must be an IP address or a CIDR range, as
// parsePrefixes reads them, and appear only once. Empty entries are
// ignored, as parsePrefixes ignores them.
func checkCIDRList(v any) error {
	seen := map[string]bool{}
	for _, entry := range strings.Split(v.(string), ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, err := parsePrefixes(entry); err != nil {
			return fmt.Errorf("entry %q is not an IP address or CIDR range", entry)
		}
		if seen[entry] {
			return fmt.Errorf("lists %q more than once", entry)
		}
		seen[entry] = true
	}
	return nil
}

// checkHostList validates a comma-separated hostname list from the file or
// the portal: every entry must be a bare, fully qualified hostname, as
// parseTLSDomains reads them, and appear only once, ignoring case and a
// trailing dot. Empty entries are ignored.
func checkHostList(v any) error {
	seen := map[string]bool{}
	for _, entry := range strings.Split(v.(string), ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, err := parseTLSDomains(entry); err != nil {
			return err
		}
		h := strings.TrimSuffix(strings.ToLower(entry), ".")
		if h == "" {
			continue
		}
		if seen[h] {
			return fmt.Errorf("lists %q more than once", entry)
		}
		seen[h] = true
	}
	return nil
}

func checkEmailProvider(v any) error {
	switch strings.ToLower(strings.TrimSpace(v.(string))) {
	case mailer.ProviderOff, mailer.ProviderSMTP, mailer.ProviderResend, mailer.ProviderSendPanda:
		return nil
	default:
		return errors.New("must be empty (disabled), smtp, resend, or sendpanda")
	}
}

func checkSMTPTLS(v any) error {
	switch strings.ToLower(strings.TrimSpace(v.(string))) {
	case "", mailer.TLSStartTLS, mailer.TLSImplicit, mailer.TLSNone:
		return nil
	default:
		return errors.New("must be starttls, tls, or none")
	}
}

func checkCadenceUnit(v any) error {
	switch strings.ToLower(strings.TrimSpace(v.(string))) {
	case mailer.UnitMinutes, mailer.UnitHours, mailer.UnitDays:
		return nil
	default:
		return errors.New("must be minutes, hours, or days")
	}
}

func checkOptionalEmail(v any) error {
	s := strings.TrimSpace(v.(string))
	if s == "" {
		return nil
	}
	_, err := mailer.ValidateAddress(s)
	return err
}

func checkEmailList(v any) error {
	_, err := mailer.ParseAddressList(v.(string))
	return err
}

func checkEmailEvents(v any) error {
	_, err := mailer.ParseCategoryList(v.(string))
	return err
}

func checkOptionalHTTPURL(v any) error {
	s := strings.TrimSpace(v.(string))
	if s == "" {
		return nil
	}
	return mailer.ValidateHTTPURL(s, false)
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
	if prev.cfg.readOnlySettings {
		return &settingsError{http.StatusForbidden, "settings are read-only (-read-only-settings / GitOps mode)"}
	}
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
	if cand.upstream != prev.cfg.upstream {
		for _, u := range cand.targets {
			if u.Scheme == "fcgi+unix" {
				return &settingsError{http.StatusBadRequest, "fcgi+unix:// upstreams can only be changed with CONCERT_UPSTREAM in concert.env and a restart"}
			}
		}
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

// settingView is one setting as the portal shows it. List is the list kind
// (listPaths, listCIDRs or listHosts) for comma-separated settings the
// portal edits one entry per input; the value is still the comma-joined
// string.
type settingView struct {
	Key     string `json:"key"`
	Group   string `json:"group"`
	Label   string `json:"label"`
	Help    string `json:"help"`
	Kind    string `json:"kind"`
	List    string `json:"list,omitempty"`
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
			Key: d.key, Group: d.group, Label: d.label, Help: d.usage, Kind: d.kind, List: d.list,
			Flag: d.flag, Env: d.env, Value: encodeSetting(d.get(&cfg)), Source: m.source(d.key),
			Restart: d.restart,
		})
	}
	return out, m.path
}

// fixedSettings describes what the portal cannot change — secrets, the data
// directory and the IP database, which are environment- or command-line-only —
// plus where concert is listening right now and where its history goes.
func (a *app) fixedSettings() map[string]string {
	a.settings.mu.Lock()
	mainEP, portalEP := a.mainEP, a.portalEP
	a.settings.mu.Unlock()

	cfg := a.current().cfg
	dataDir := cfg.dataDir
	if dataDir == "" {
		dataDir = "none: changes and the queue last until concert restarts"
	}
	secret := "set (CONCERT_ADMIT_SECRET)"
	if cfg.admitSecretGenerated {
		secret = "random at startup (CONCERT_ADMIT_SECRET unset)"
	} else if len(cfg.admitSecretPrev) > 0 {
		secret = "set with dual-key rotation (CONCERT_ADMIT_SECRET + CONCERT_ADMIT_SECRET_PREV)"
	}
	token := "not set: admin API disabled"
	if cfg.apiTokens.enabled() {
		token = fmt.Sprintf("enabled (%d token(s))", len(cfg.apiTokens.tokens))
	}
	portalAuth := "legacy password (CONCERT_PORTAL_PASS)"
	if cfg.portal.users != nil && cfg.portal.users.count() > 0 {
		portalAuth = fmt.Sprintf("RBAC users (%d account(s))", cfg.portal.users.count())
		if cfg.portal.ssoHeader != "" {
			portalAuth += " + SSO (" + cfg.portal.ssoHeader + ")"
		}
	} else if cfg.portal.ssoHeader != "" {
		portalAuth = "SSO proxy (" + cfg.portal.ssoHeader + ")"
	}
	clusterDesc := "standalone (in-memory)"
	if cfg.redisAddr != "" {
		clusterDesc = "Redis sync (" + cfg.redisAddr + ")"
	}
	emailSecretsDesc := "none configured"
	if a.mailer != nil && a.mailer.Secrets() != nil {
		st := a.mailer.Secrets().Status()
		emailSecretsDesc = fmt.Sprintf("SMTP=%s, Resend=%s, SendPanda=%s", st.SMTPPass, st.ResendAPIKey, st.SendPandaAPIKey)
	}
	return map[string]string{
		"Data directory":   dataDir,
		"Admission secret": secret,
		"Admin tokens":     token,
		"Portal auth":      portalAuth,
		"Email secrets":    emailSecretsDesc,
		"Audit log":        a.audit.describe(),
		"Cluster sync":     clusterDesc,
		"IP details":       a.ipinfo.describe(),
		"History log":      a.history.describeLog(),
		"Main listener":    mainEP.describe(),
		"Portal listener":  portalEP.describe(),
		"Version":          BinaryVersion() + " (" + fipsModeLabel() + ")",
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
