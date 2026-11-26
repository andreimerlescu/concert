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

	"github.com/andreimerlescu/concert/internal/guard"
	"github.com/andreimerlescu/concert/internal/notify"
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
	{key: "ready_grace", flag: "ready-grace", env: "CONCERT_READY_GRACE", group: groupRoom, label: "Ready-claim grace",
		def: 30 * time.Second, usage: "reclaim a ticket inside the serving window that is not claimed within this time, 5s-10m, at least twice -retry-after, and at most -token-ttl (0 = off)",
		ptr: func(c *config) any { return &c.readyGrace }, check: durationZeroOrBetween(minReadyGrace, maxReadyGrace)},
	{key: "idle_poll_ttl", flag: "idle-poll-ttl", env: "CONCERT_IDLE_POLL_TTL", group: groupRoom, label: "Idle-poll TTL",
		def: 45 * time.Second, usage: "evict a queued ticket with no client contact for longer than this time, 10s-24h, at least twice -retry-after, and at most -token-ttl (0 = off)",
		ptr: func(c *config) any { return &c.idlePollTTL }, check: durationZeroOrBetween(minIdlePollTTL, maxIdlePollTTL)},
	{key: "reaper", flag: "reaper", env: "CONCERT_REAPER", group: groupRoom, label: "Reaper interval",
		def: 10 * time.Second, usage: "reaper interval for abandoned tickets, 5s-24h",
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
	{key: "busy_html", flag: "busy-html", env: "CONCERT_BUSY_HTML", group: groupRoom, label: "Custom busy 503 HTML",
		def: "", usage: "custom HTML file served when the waiting room is full (503), empty for Concert's built-in busy page",
		ptr: func(c *config) any { return &c.busyHTMLFile }},
	{key: "clear_queue_on_start", flag: "clear-queue-on-start", env: "CONCERT_CLEAR_QUEUE_ON_START", group: groupRoom, label: "Clear saved queue on startup", restart: true,
		def: false, usage: "discard any persisted queue.snapshot on startup instead of restoring it (flag or CONCERT_CLEAR_QUEUE_ON_START only; takes a restart)",
		ptr: func(c *config) any { return &c.clearQueueOnStart }},
	{key: "room_verify_keys", flag: "room-verify-keys", env: "CONCERT_ROOM_VERIFY_KEYS", group: groupRoom, label: "Ed25519 verify keys (split mode)", restart: true,
		def: "", usage: "comma-separated kid=<ed25519-pubkey> entries for stateless room v1.8.0 verify-only VIP passes and signed leases (also supports CONCERT_ROOM_VERIFY_KEYS_FILE)",
		ptr: func(c *config) any { return &c.roomVerifyKeys }},
	{key: "room_scope", flag: "room-scope", env: "CONCERT_ROOM_SCOPE", group: groupRoom, label: "Signed token scope", restart: true,
		def: "", usage: "service scope bound into signed room v1.8.0 passes and leases (required with -room-verify-keys; auto-defaults to site hostname in -config mode)",
		ptr: func(c *config) any { return &c.roomScope }},
	{key: "room_signed_max_ttl", flag: "room-signed-max-ttl", env: "CONCERT_ROOM_SIGNED_MAX_TTL", group: groupRoom, label: "Signed token max TTL",
		def: time.Duration(0), usage: "maximum TTL accepted for signed room v1.8.0 passes and leases, 1s-1h (0 = room default, 15m)",
		ptr: func(c *config) any { return &c.roomSignedMaxTTL }, check: durationZeroOrBetween(time.Second, time.Hour)},
	{key: "room_lease_fraction", flag: "room-lease-fraction", env: "CONCERT_ROOM_LEASE_FRACTION", group: groupRoom, label: "Signed lease pool fraction",
		def: 0.0, usage: "fraction of -cap reserved for the work-conserving lease pool, 0-1 (0 = room default: 0.25 in signed mode, 1.0 otherwise)",
		ptr: func(c *config) any { return &c.roomLeaseFraction }, check: floatBetween(0, 1)},

	// ---- Agent queue ----
	{key: "agent_queue", flag: "agent-queue", env: "CONCERT_AGENT_QUEUE", group: groupSkip, label: "AI agents wait in line",
		def: false, usage: "with wallet access on, requests carrying a valid Concert-Session header keep one place in line per session, with no cookies (off by default: agents are also what scalpers use)",
		ptr: func(c *config) any { return &c.agentQueue }},
	{key: "agent_places", flag: "agent-places", env: "CONCERT_AGENT_PLACES", group: groupSkip, label: "Agent places per address",
		def: defaultAgentPlaces, usage: "keyed places one client address (IPv6: its /64) may hold in line; past it, 429 and a strike",
		ptr: func(c *config) any { return &c.agentPlaces }, check: intBetween(1, maxAgentPlaces)},
	{key: "agent_bidding", flag: "agent-bidding", env: "CONCERT_AGENT_BIDDING", group: groupSkip, label: "AI agent pass bidding", restart: true,
		def: false, usage: "enable non-custodial crypto-only (XRPL, Stellar, Hedera, Solana) hybrid instant-buy and sealed-bid auction offers for queued AI agents",
		ptr: func(c *config) any { return &c.agentBidding }},
	{key: "agent_bidding_floor", flag: "agent-bidding-floor", env: "CONCERT_AGENT_BIDDING_FLOOR", group: groupSkip, label: "Agent bid floor (micro-USD)", restart: true,
		def: defaultBiddingFloor, usage: "minimum accepted crypto bid and instant-buy floor price in micro-USD (1000000 = $1.00)",
		ptr: func(c *config) any { return &c.agentBiddingFloorMicroUSD }, check: int64AtLeast(1)},
	{key: "agent_bidding_epoch", flag: "agent-bidding-epoch", env: "CONCERT_AGENT_BIDDING_EPOCH", group: groupSkip, label: "Agent auction epoch duration", restart: true,
		def: 10 * time.Second, usage: "sealed-bid auction clearing epoch window when saturated (e.g. 10s)",
		ptr: func(c *config) any { return &c.agentBiddingEpoch }, check: durationBetween(time.Second, 10*time.Minute)},
	{key: "agent_bidding_slots", flag: "agent-bidding-slots", env: "CONCERT_AGENT_BIDDING_SLOTS", group: groupSkip, label: "Agent auction slots per epoch", restart: true,
		def: 1, usage: "maximum winning agent bids settled per clearing epoch",
		ptr: func(c *config) any { return &c.agentBiddingSlots }, check: intBetween(1, 1000)},
	{key: "agent_bidding_min_wait", flag: "agent-bidding-min-wait", env: "CONCERT_AGENT_BIDDING_MIN_WAIT", group: groupSkip, label: "Agent minimum wait before bidding", restart: true,
		def: time.Duration(0), usage: "minimum queue wait duration required before an agent may submit a bid (0 disables)",
		ptr: func(c *config) any { return &c.agentBiddingMinWait }, check: durationAtLeast(0)},
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
		def: "http://127.0.0.1:3000", usage: "origin to proxy to (http:// or https://; fcgi:// and fcgi+unix:// in wpconcert/econcert)",
		ptr: func(c *config) any { return &c.upstream }},
	{key: "upstream_timeout", flag: "upstream-timeout", env: "CONCERT_UPSTREAM_TIMEOUT", group: groupOrigin, label: "Upstream header timeout",
		def: 60 * time.Second, usage: "upstream response header timeout (starts after request body upload finishes; default 60s, 90s in WordPress preset)",
		ptr: func(c *config) any { return &c.headerTimeout }, check: durationAtLeast(0)},
	{key: "upstream_body_idle_timeout", flag: "upstream-body-idle-timeout", env: "CONCERT_UPSTREAM_BODY_IDLE_TIMEOUT", group: groupOrigin, label: "Upstream body idle timeout",
		def: 30 * time.Second, usage: "maximum idle pause between upstream response body chunks on non-stream requests, 1s-24h (0 disables; distinct from inbound upload -body-read-idle-timeout)",
		ptr: func(c *config) any { return &c.upstreamBodyIdleTimeout }, check: durationZeroOrBetween(minUpstreamBodyIdleTimeout, maxUpstreamBodyIdleTimeout)},
	{key: "body_read_idle_timeout", flag: "body-read-idle-timeout", env: "CONCERT_BODY_READ_IDLE_TIMEOUT", group: groupOrigin, label: "Body read idle timeout",
		def: 30 * time.Second, usage: "maximum idle pause between request body chunks on non-stream requests (0 disables)",
		ptr: func(c *config) any { return &c.bodyReadIdleTimeout }, check: durationAtLeast(0)},
	{key: "max_upload_time", flag: "max-upload-time", env: "CONCERT_MAX_UPLOAD_TIME", group: groupOrigin, label: "Max upload duration",
		def: 10 * time.Minute, usage: "total wall-clock cap for reading a non-stream request body so tricklers cannot pin page slots (0 disables)",
		ptr: func(c *config) any { return &c.maxUploadTime }, check: durationAtLeast(0)},
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
	{key: "admit_session_continuity", flag: "admit-session-continuity", env: "CONCERT_ADMIT_SESSION_CONTINUITY", group: groupAssets, label: "Admitted session continuity",
		def: true, usage: "allow visitors with a valid, unexpired concert_admit cookie to bypass queue re-entry during active browsing (bounded per pass)",
		ptr: func(c *config) any { return &c.admitSessionContinuity }},
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

	// ---- Host-protection guardrails; see internal/guard and guard_wiring.go ----
	{key: "max_queue_per_ip", flag: "max-queue-per-ip", env: "CONCERT_MAX_QUEUE_PER_IP", group: groupAbuse, label: "Max queued tickets per IP",
		def: guard.DefaultMaxPerIP, usage: "maximum concurrent waiting-room tickets per IPv4 /32 or IPv6 /64 (0 disables)",
		ptr: func(c *config) any { return &c.maxQueuePerIP }, check: intAtLeast(0)},
	{key: "allow_max_queue_per_ip", flag: "allow-max-queue-per-ip", env: "CONCERT_ALLOW_MAX_QUEUE_PER_IP", group: groupAbuse, label: "Max queued tickets per allowlisted IP",
		def: guard.DefaultAllowMaxPerIP, usage: "maximum concurrent waiting-room tickets per allowlisted IP (-abuse-allow); disabled only when explicitly 0",
		ptr: func(c *config) any { return &c.allowMaxQueuePerIP }, check: intAtLeast(0)},
	{key: "host_max_mem_mb", flag: "host-max-mem-mb", env: "CONCERT_HOST_MAX_MEM_MB", group: groupAbuse, label: "Host memory shed ceiling (MiB)",
		def: 0, usage: "shed non-admitted arrivals with 503 when process RSS/heap reaches this MiB ceiling (0 disables)",
		ptr: func(c *config) any { return &c.hostMaxMemMB }, check: intAtLeast(0)},
	{key: "host_max_fds", flag: "host-max-fds", env: "CONCERT_HOST_MAX_FDS", group: groupAbuse, label: "Host open FD shed ceiling",
		def: 0, usage: "shed non-admitted arrivals with 503 when open file descriptors reach this ceiling (0 disables)",
		ptr: func(c *config) any { return &c.hostMaxFDs }, check: intAtLeast(0)},
	{key: "host_max_conns", flag: "host-max-conns", env: "CONCERT_HOST_MAX_CONNS", group: groupAbuse, label: "Host active connections shed ceiling",
		def: int64(0), usage: "shed non-admitted arrivals with 503 when active connections reach this ceiling (0 disables)",
		ptr: func(c *config) any { return &c.hostMaxConns }, check: int64AtLeast(0)},
	{key: "rate_limits", flag: "rate-limit", env: "CONCERT_RATE_LIMIT", group: groupAbuse, label: "Per-route rate limits",
		def: "", usage: "comma-separated per-route token-bucket rules: /path=rate/window[:burst] (e.g. /wp-login.php=5/1m,/api/=60/1m)",
		ptr: func(c *config) any { return &c.rateLimits }},
	{key: "block_asn", flag: "block-asn", env: "CONCERT_BLOCK_ASN", group: groupAbuse, label: "Blocked ASNs",
		def: "", usage: "comma-separated autonomous system numbers to block with 403 (e.g. 13335,AS15169; requires IP database)",
		ptr: func(c *config) any { return &c.blockASN }},
	{key: "allow_countries", flag: "allow-countries", env: "CONCERT_ALLOW_COUNTRIES", group: groupAbuse, label: "Allowed countries",
		def: "", usage: "comma-separated ISO-3166-1 alpha-2 country codes allowed to access (e.g. US,CA; empty allows all)",
		ptr: func(c *config) any { return &c.allowCountries }},
	{key: "block_countries", flag: "block-countries", env: "CONCERT_BLOCK_COUNTRIES", group: groupAbuse, label: "Blocked countries",
		def: "", usage: "comma-separated ISO-3166-1 alpha-2 country codes blocked with 403 (deny overrides allow)",
		ptr: func(c *config) any { return &c.blockCountries }},
	{key: "challenge_mode", flag: "challenge-mode", env: "CONCERT_CHALLENGE_MODE", group: groupAbuse, label: "Pre-ticket bot challenge",
		def: string(guard.ModeOff), usage: "pre-ticket bot challenge mode: off, pow (zero-dep SHA-256 Proof-of-Work), or turnstile (requires CONCERT_TURNSTILE_SECRET[_FILE])",
		ptr: func(c *config) any { return &c.challengeMode }},
	{key: "challenge_pow_bits", flag: "challenge-pow-bits", env: "CONCERT_CHALLENGE_POW_BITS", group: groupAbuse, label: "PoW challenge difficulty (bits)",
		def: guard.DefaultPoWDifficulty, usage: "leading zero bits required for SHA-256 Proof-of-Work challenges (8-24)",
		ptr: func(c *config) any { return &c.challengePowBits }, check: intBetween(guard.MinPoWDifficulty, guard.MaxPoWDifficulty)},
	{key: "challenge_turnstile_site_key", flag: "challenge-turnstile-site-key", env: "CONCERT_TURNSTILE_SITE_KEY", group: groupAbuse, label: "Turnstile site key",
		def: "", usage: "public Cloudflare Turnstile site key rendered on challenge pages when -challenge-mode=turnstile",
		ptr: func(c *config) any { return &c.challengeTurnstileSiteKey }},

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
	{key: "tls_min_version", flag: "tls-min-version", env: "CONCERT_TLS_MIN_VERSION", group: groupTLS, label: "Minimum TLS version",
		def: "1.2", usage: "minimum TLS version on listeners (1.2 or 1.3)",
		ptr: func(c *config) any { return &c.tlsMinVersion }},
	{key: "hsts_max_age", flag: "hsts-max-age", env: "CONCERT_HSTS_MAX_AGE", group: groupTLS, label: "HSTS max-age (seconds)",
		def: 0, usage: "Strict-Transport-Security max-age in seconds on HTTPS responses (0 disables)",
		ptr: func(c *config) any { return &c.hstsMaxAge }, check: intAtLeast(0)},
	{key: "tls_http_listen", flag: "tls-http-listen", env: "CONCERT_TLS_HTTP_LISTEN", group: groupTLS, label: "HTTP redirect / ACME HTTP-01 address", restart: true,
		def: "", usage: "companion plain-HTTP listener (e.g. :80) serving ACME HTTP-01 challenges and redirecting HTTP to HTTPS (flag or CONCERT_TLS_HTTP_LISTEN only)",
		ptr: func(c *config) any { return &c.tlsHTTPListen }},
	{key: "http3", flag: "http3", env: "CONCERT_HTTP3", group: groupTLS, label: "Enable HTTP/3 (QUIC)", restart: true,
		def: false, usage: "serve HTTP/3 over QUIC on UDP -listen alongside TCP HTTPS and advertise Alt-Svc (requires TLS; restart to change)",
		ptr: func(c *config) any { return &c.http3 }},
	{key: "tls_dns_provider", flag: "tls-dns-provider", env: "CONCERT_TLS_DNS_PROVIDER", group: groupTLS, label: "ACME DNS-01 provider", restart: true,
		def: "", usage: "ACME DNS-01 provider for wildcard certificates: empty (off), cloudflare (CONCERT_DNS_API_TOKEN[_FILE]), or webhook (-tls-dns-webhook-url)",
		ptr: func(c *config) any { return &c.tlsDNSProvider }},
	{key: "tls_dns_webhook_url", flag: "tls-dns-webhook-url", env: "CONCERT_TLS_DNS_WEBHOOK_URL", group: groupTLS, label: "ACME DNS-01 webhook URL", restart: true,
		def: "", usage: "HTTPS endpoint for -tls-dns-provider webhook (optional bearer token via CONCERT_DNS_WEBHOOK_TOKEN[_FILE])",
		ptr: func(c *config) any { return &c.tlsDNSWebhookURL }},

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
	{key: "history_log", flag: "history-log", env: "CONCERT_HISTORY_LOG", group: groupPortal, label: "History log file", restart: true,
		def: "", usage: "JSON-lines file the portal's request history is written to and restored from; empty means history.jsonl in -data-dir, off keeps it in memory only (flag or CONCERT_HISTORY_LOG only; takes a restart)",
		ptr: func(c *config) any { return &c.historyLog }},

	// ---- Security & observability ----
	{key: "stats_auth", flag: "stats-auth", env: "CONCERT_STATS_AUTH", group: groupEnterprise, label: "Require auth on stats/metrics",
		def: false, usage: "require bearer token authentication on /_room/stats and /_room/metrics",
		ptr: func(c *config) any { return &c.statsAuth }},
	{key: "read_only_settings", flag: "read-only-settings", env: "CONCERT_READ_ONLY_SETTINGS", group: groupEnterprise, label: "Read-only settings (GitOps)", restart: true,
		def: false, usage: "forbid live mutations to settings.json via portal or API for immutable/GitOps deployments",
		ptr: func(c *config) any { return &c.readOnlySettings }},
	{key: "log_format", flag: "log-format", env: "CONCERT_LOG_FORMAT", group: groupEnterprise, label: "Log format", restart: true,
		def: "text", usage: "access and structured log format: text or json",
		ptr: func(c *config) any { return &c.logFormat }},
	{key: "log_level", flag: "log-level", env: "CONCERT_LOG_LEVEL", group: groupEnterprise, label: "Log level", restart: true,
		def: "info", usage: "structured log level: debug, info, warn, error",
		ptr: func(c *config) any { return &c.logLevel }},
	{key: "otlp_endpoint", flag: "otlp-endpoint", env: "CONCERT_OTLP_ENDPOINT", group: groupEnterprise, label: "OTLP/HTTP trace endpoint", restart: true,
		def: "", usage: "pure-stdlib OTLP/HTTP JSON collector HTTPS URL (e.g. https://otel.example.com/v1/traces; auth header via CONCERT_OTLP_AUTH_HEADER[_FILE])",
		ptr: func(c *config) any { return &c.otlpEndpoint }},
	{key: "otlp_sample_rate", flag: "otlp-sample-rate", env: "CONCERT_OTLP_SAMPLE_RATE", group: groupEnterprise, label: "OTLP trace sample rate", restart: true,
		def: 0.1, usage: "root span sampling probability in [0.0, 1.0]",
		ptr: func(c *config) any { return &c.otlpSampleRate }, check: floatBetween(0, 1)},
	{key: "notify_slack_url", flag: "notify-slack-url", env: "CONCERT_NOTIFY_SLACK_URL", group: groupEnterprise, label: "Slack webhook URL", restart: true,
		def: "", usage: "Slack incoming webhook HTTPS URL (prefer CONCERT_NOTIFY_SLACK_URL or CONCERT_NOTIFY_SLACK_URL_FILE; redacted in API/logs)",
		ptr: func(c *config) any { return &c.notifySlackURL }},
	{key: "notify_discord_url", flag: "notify-discord-url", env: "CONCERT_NOTIFY_DISCORD_URL", group: groupEnterprise, label: "Discord webhook URL", restart: true,
		def: "", usage: "Discord webhook HTTPS URL (prefer CONCERT_NOTIFY_DISCORD_URL or CONCERT_NOTIFY_DISCORD_URL_FILE; redacted in API/logs)",
		ptr: func(c *config) any { return &c.notifyDiscordURL }},
	{key: "notify_teams_url", flag: "notify-teams-url", env: "CONCERT_NOTIFY_TEAMS_URL", group: groupEnterprise, label: "Teams webhook URL", restart: true,
		def: "", usage: "Microsoft Teams webhook HTTPS URL (prefer CONCERT_NOTIFY_TEAMS_URL or CONCERT_NOTIFY_TEAMS_URL_FILE; redacted in API/logs)",
		ptr: func(c *config) any { return &c.notifyTeamsURL }},
	{key: "notify_webhook_url", flag: "notify-webhook-url", env: "CONCERT_NOTIFY_WEBHOOK_URL", group: groupEnterprise, label: "Generic webhook URL", restart: true,
		def: "", usage: "generic signed webhook HTTPS URL (prefer CONCERT_NOTIFY_WEBHOOK_URL or CONCERT_NOTIFY_WEBHOOK_URL_FILE; redacted in API/logs)",
		ptr: func(c *config) any { return &c.notifyWebhookURL }},
	{key: "notify_pagerduty_key", flag: "notify-pagerduty-key", env: "CONCERT_NOTIFY_PAGERDUTY_KEY", group: groupEnterprise, label: "PagerDuty routing key", restart: true,
		def: "", usage: "PagerDuty Events API v2 routing key (prefer CONCERT_NOTIFY_PAGERDUTY_KEY or CONCERT_NOTIFY_PAGERDUTY_KEY_FILE; redacted in API/logs)",
		ptr: func(c *config) any { return &c.notifyPagerDutyKey }},

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
}

// settingByKey indexes settingDefs by key.
var settingByKey = map[string]*settingDef{}

func init() {
	settingDefs = append(settingDefs, wordpressSettingDefs()...)
	settingDefs = append(settingDefs, enterpriseSettingDefs()...)
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
	case *string, *notify.Secret:
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

// get returns the setting's current value in c. Redacting secrets return ""
// when unset and "[REDACTED]" when set so raw credentials never leave config.
func (d *settingDef) get(c *config) any {
	switch p := d.ptr(c).(type) {
	case *string:
		return *p
	case *notify.Secret:
		if p.IsZero() {
			return ""
		}
		return p.String()
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
	case *notify.Secret:
		s := strings.TrimSpace(v.(string))
		if s == "" {
			*p = notify.Secret{}
		} else {
			*p = notify.NewSecret(s)
		}
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

// Email setting validators live in enterprise_hooks.go.

// ─── loading ─────────────────────────────────────────────────────────────────

// notifySecretFlagValue binds a CLI flag to a redacting notify.Secret without
// ever exposing the secret value in FlagSet help/defaults output (S5/S6).
type notifySecretFlagValue struct {
	dst *notify.Secret
}

func (f *notifySecretFlagValue) String() string {
	if f == nil || f.dst == nil || f.dst.IsZero() {
		return ""
	}
	return f.dst.String()
}

func (f *notifySecretFlagValue) Set(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		*f.dst = notify.Secret{}
		return nil
	}
	*f.dst = notify.NewSecret(trimmed)
	return nil
}

// registerSettingFlags declares one flag per setting, each defaulting to its
// environment variable and then its built-in default.
func registerSettingFlags(fs *flag.FlagSet, cfg *config) {
	for i := range settingDefs {
		d := &settingDefs[i]
		switch p := d.ptr(cfg).(type) {
		case *string:
			fs.StringVar(p, d.flag, env.String(d.env, d.def.(string)), d.usage)
		case *notify.Secret:
			if v := strings.TrimSpace(envOrFile(d.env, "")); v != "" {
				*p = notify.NewSecret(v)
			}
			fs.Var(&notifySecretFlagValue{dst: p}, d.flag, d.usage)
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
	if v, ok := os.LookupEnv(name + "_FILE"); ok && strings.TrimSpace(v) != "" {
		return true
	}
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
		d := settingByKey[key]
		baseSrc := cfg.settingBaseSources[key]
		if (baseSrc == sourceFlag || baseSrc == sourceEnv) && encodeSetting(cfg.settingBase[key]) != encodeSetting(v) {
			log.Printf("settings: WARNING %s overrides %s for %s (%v -> %v); reset in portal to follow %s again",
				path, baseSrc, key, encodeSetting(cfg.settingBase[key]), encodeSetting(v), baseSrc)
		}
		d.set(cfg, v)
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
	if prev.cfg.configManaged {
		// Declarative -config mode: the config file is the source of truth.
		// Only temporary live emergency cap overrides are permitted here;
		// they are never persisted to settings.json and reset on reload.
		if len(reset) > 0 || len(set) != 1 {
			return &settingsError{http.StatusBadRequest, "this instance is managed by -config; edit the Concertfile and send SIGHUP (or click Reload config) to persist changes — only temporary live cap overrides are permitted here"}
		}
		rawCap, ok := set["cap"]
		if !ok {
			return &settingsError{http.StatusBadRequest, "this instance is managed by -config; only temporary live cap overrides are permitted via the portal/API (edit the Concertfile and reload for all other changes)"}
		}
		d := settingByKey["cap"]
		v, err := d.decode(rawCap)
		if err == nil && d.check != nil {
			err = d.check(v)
		}
		if err != nil {
			return &settingsError{http.StatusBadRequest, fmt.Sprintf("cap %v", err)}
		}
		cand := prev.cfg
		d.set(&cand, v)
		if err := cand.normalize(); err != nil {
			return &settingsError{http.StatusBadRequest, err.Error()}
		}
		g, err := a.buildGeneration(cand, prev)
		if err != nil {
			return &settingsError{http.StatusBadRequest, "concert cannot apply cap override: " + err.Error()}
		}
		if err := a.commit(g, nil); err != nil {
			return &settingsError{http.StatusInternalServerError, "waiting room rejected cap override: " + err.Error()}
		}
		a.runtimeCapOverride.Store(true)
		return nil
	}

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
	out := map[string]string{
		"Data directory":   dataDir,
		"Admission secret": secret,
		"Admin tokens":     token,
		"Portal auth":      portalAuth,
		"IP details":       a.ipinfo.describe(),
		"History log":      a.history.describeLog(),
		"Main listener":    mainEP.describe(),
		"Portal listener":  portalEP.describe(),
		"Version":          BinaryVersion() + " (" + fipsModeLabel() + ")",
	}
	a.describeEnterpriseSecrets(cfg, out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
