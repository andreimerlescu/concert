// Package configfile parses Concert's declarative multi-vhost configuration
// files: zero-dependency Caddyfile-inspired Concertfile syntax and strict JSON
// (.json) fallback.
package configfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/opt"
)

// File is the complete parsed declarative configuration.
type File struct {
	Global GlobalConfig `json:"global"`
	Sites  []SiteConfig `json:"sites"`
}

// GlobalConfig holds process-level listener, TLS, HTTP/3, Portal, and logging
// directives shared across all virtual hosts.
//
// Optional scalar directives (such as PortalSecureCookie, StatsAuth,
// RoomLeaseFraction, ClearQueueOnStart, UpstreamCBFailures, and
// FastlaneLockDestinations) use value-type [opt.Option] fields tagged with
// `omitzero`: an absent or JSON `null` directive leaves the zero value (None)
// so runtime defaults apply, whereas explicit false/0/0.0 values decode as
// Some(v) and marshal back to JSON. Value semantics guarantee that copying a
// GlobalConfig never aliases optional scalar fields across copies.
type GlobalConfig struct {
	Listen                   string              `json:"listen,omitempty"`
	HTTPListen               string              `json:"http_listen,omitempty"`
	TLSEmail                 string              `json:"tls_email,omitempty"`
	TLSCache                 string              `json:"tls_cache,omitempty"`
	TLSStaging               bool                `json:"tls_staging,omitempty"`
	TLSCert                  string              `json:"tls_cert,omitempty"`
	TLSKey                   string              `json:"tls_key,omitempty"`
	TLSMinVersion            string              `json:"tls_min_version,omitempty"`
	TLSDNSProvider           string              `json:"tls_dns_provider,omitempty"`
	TLSDNSWebhookURL         string              `json:"tls_dns_webhook_url,omitempty"`
	HSTSMaxAge               int                 `json:"hsts_max_age,omitempty"`
	HTTP3                    bool                `json:"http3,omitempty"`
	PortalListen             string              `json:"portal_listen,omitempty"`
	PortalAllow              string              `json:"portal_allow,omitempty"`
	PortalTLSCert            string              `json:"portal_tls_cert,omitempty"`
	PortalTLSKey             string              `json:"portal_tls_key,omitempty"`
	PortalSecureCookie       opt.Option[bool]    `json:"portal_secure_cookie,omitzero"`
	DataDir                  string              `json:"data_dir,omitempty"`
	TrustedProxies           string              `json:"trusted_proxies,omitempty"`
	LogFormat                string              `json:"log_format,omitempty"`
	LogLevel                 string              `json:"log_level,omitempty"`
	StatsAuth                opt.Option[bool]    `json:"stats_auth,omitzero"`
	RoomVerifyKeys           string              `json:"room_verify_keys,omitempty"`
	RoomSignedMaxTTL         string              `json:"room_signed_max_ttl,omitempty"`
	RoomLeaseFraction        opt.Option[float64] `json:"room_lease_fraction,omitzero"`
	TokenTTL                 string              `json:"token_ttl,omitempty"`
	FirstPollGrace           string              `json:"first_poll_grace,omitempty"`
	ReadyGrace               string              `json:"ready_grace,omitempty"`
	IdlePollTTL              string              `json:"idle_poll_ttl,omitempty"`
	Reaper                   string              `json:"reaper,omitempty"`
	RetryAfter               int                 `json:"retry_after,omitempty"`
	BusyHTML                 string              `json:"busy_html,omitempty"`
	ClearQueueOnStart        opt.Option[bool]    `json:"clear_queue_on_start,omitzero"`
	BodyReadIdleTimeout      string              `json:"body_read_idle_timeout,omitempty"`
	MaxUploadTime            string              `json:"max_upload_time,omitempty"`
	UpstreamTimeout          string              `json:"upstream_timeout,omitempty"`
	UpstreamBodyIdleTimeout  string              `json:"upstream_body_idle_timeout,omitempty"`
	UpstreamCBFailures       opt.Option[int]     `json:"upstream_cb_failures,omitzero"`
	UpstreamCBCooldown       string              `json:"upstream_cb_cooldown,omitempty"`
	UpstreamHealthPath       string              `json:"upstream_health_path,omitempty"`
	UpstreamHealthInterval   string              `json:"upstream_health_interval,omitempty"`
	FastlaneConfig           string              `json:"fastlane_config,omitempty"`
	NetworksConfig           string              `json:"networks_config,omitempty"`
	FastlaneLockDestinations opt.Option[bool]    `json:"fastlane_lock_destinations,omitzero"`
	Extra                    map[string]string   `json:"extra,omitempty"`
}

// SiteConfig holds one virtual host block (one or more hostnames sharing a
// waiting room, upstream pool, static root, and optional micro-cache).
//
// Optional per-site overrides (StaticFallback, Compress, MaxQueue,
// SecureCookie, PreserveHost, Abuse, RoomLeaseFraction, ClearQueueOnStart,
// UpstreamCBFailures, and FastlaneLockDestinations) use value-type
// [opt.Option] fields tagged with `omitzero`: None inherits the global or
// preset default and is omitted when marshaling JSON, while Some(v) records an
// explicit override (including false, 0, or 0.0) without pointer allocation or
// cross-copy aliasing.
type SiteConfig struct {
	Hosts                    []string            `json:"hosts"`
	Preset                   string              `json:"preset,omitempty"`
	Upstream                 string              `json:"upstream,omitempty"`
	Root                     string              `json:"root,omitempty"`
	Mounts                   []string            `json:"mounts,omitempty"`
	StaticAllowExt           string              `json:"static_allow_ext,omitempty"`
	StaticCacheControl       string              `json:"static_cache_control,omitempty"`
	StaticFallback           opt.Option[bool]    `json:"static_fallback,omitzero"`
	Compress                 opt.Option[bool]    `json:"compress,omitzero"`
	Assets                   string              `json:"assets,omitempty"`
	AssetPublic              string              `json:"asset_public,omitempty"`
	Bypass                   string              `json:"bypass,omitempty"`
	StreamPaths              string              `json:"stream_paths,omitempty"`
	Cap                      int                 `json:"cap,omitempty"`
	MaxQueue                 opt.Option[int64]   `json:"max_queue,omitzero"`
	PriorityCap              int                 `json:"priority_cap,omitempty"`
	PriorityLaneRank         int                 `json:"priority_lane_rank,omitempty"`
	SecureCookie             opt.Option[bool]    `json:"secure_cookie,omitzero"`
	PreserveHost             opt.Option[bool]    `json:"preserve_host,omitzero"`
	FCGIIndex                string              `json:"fcgi_index,omitempty"`
	FCGIDenyPaths            string              `json:"fcgi_deny_paths,omitempty"`
	MicroCache               string              `json:"micro_cache,omitempty"`
	MicroCacheMaxMB          int                 `json:"micro_cache_max_mb,omitempty"`
	Abuse                    opt.Option[bool]    `json:"abuse,omitzero"`
	AbuseStrikes             int                 `json:"abuse_strikes,omitempty"`
	BanPaths                 string              `json:"ban_paths,omitempty"`
	RateLimits               []string            `json:"rate_limits,omitempty"`
	RoomVerifyKeys           string              `json:"room_verify_keys,omitempty"`
	RoomScope                string              `json:"room_scope,omitempty"`
	RoomSignedMaxTTL         string              `json:"room_signed_max_ttl,omitempty"`
	RoomLeaseFraction        opt.Option[float64] `json:"room_lease_fraction,omitzero"`
	TokenTTL                 string              `json:"token_ttl,omitempty"`
	FirstPollGrace           string              `json:"first_poll_grace,omitempty"`
	ReadyGrace               string              `json:"ready_grace,omitempty"`
	IdlePollTTL              string              `json:"idle_poll_ttl,omitempty"`
	Reaper                   string              `json:"reaper,omitempty"`
	RetryAfter               int                 `json:"retry_after,omitempty"`
	BusyHTML                 string              `json:"busy_html,omitempty"`
	ClearQueueOnStart        opt.Option[bool]    `json:"clear_queue_on_start,omitzero"`
	BodyReadIdleTimeout      string              `json:"body_read_idle_timeout,omitempty"`
	MaxUploadTime            string              `json:"max_upload_time,omitempty"`
	UpstreamTimeout          string              `json:"upstream_timeout,omitempty"`
	UpstreamBodyIdleTimeout  string              `json:"upstream_body_idle_timeout,omitempty"`
	UpstreamCBFailures       opt.Option[int]     `json:"upstream_cb_failures,omitzero"`
	UpstreamCBCooldown       string              `json:"upstream_cb_cooldown,omitempty"`
	UpstreamHealthPath       string              `json:"upstream_health_path,omitempty"`
	UpstreamHealthInterval   string              `json:"upstream_health_interval,omitempty"`
	FastlaneConfig           string              `json:"fastlane_config,omitempty"`
	NetworksConfig           string              `json:"networks_config,omitempty"`
	FastlaneLockDestinations opt.Option[bool]    `json:"fastlane_lock_destinations,omitzero"`
	TLSCert                  string              `json:"tls_cert,omitempty"`
	TLSKey                   string              `json:"tls_key,omitempty"`
	Routes                   []RouteConfig       `json:"routes,omitempty"`
	Headers                  []HeaderRule        `json:"headers,omitempty"`
	Redirects                []RedirectRule      `json:"redirects,omitempty"`
	DropEventID              string              `json:"drop_event_id,omitempty"`
	DropLobbyAt              string              `json:"drop_lobby_at,omitempty"`
	DropOpenAt               string              `json:"drop_open_at,omitempty"`
	Extra                    map[string]string   `json:"extra,omitempty"`
}

// Load reads and parses a Concertfile (or JSON file when path ends in .json).
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if strings.EqualFold(filepath.Ext(path), ".json") {
		return ParseJSON(data)
	}
	return ParseConcertfile(data)
}

// ParseJSON decodes a strict JSON Concert configuration file.
func ParseJSON(data []byte) (*File, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse JSON config: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err == nil {
		return nil, errors.New("parse JSON config: unexpected trailing data")
	}
	if err := f.NormalizeAndValidate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// NormalizeAndValidate canonicalizes hostnames and checks structural invariants.
func (f *File) NormalizeAndValidate() error {
	if f == nil {
		return errors.New("config is nil")
	}
	if len(f.Sites) == 0 {
		return errors.New("config must declare at least one site block")
	}
	seenHosts := map[string]int{}
	for i := range f.Sites {
		s := &f.Sites[i]
		if len(s.Hosts) == 0 {
			return fmt.Errorf("site #%d has no hostnames", i+1)
		}
		norm := make([]string, 0, len(s.Hosts))
		for _, raw := range s.Hosts {
			h, err := NormalizeHost(raw)
			if err != nil {
				return fmt.Errorf("site #%d host %q: %w", i+1, raw, err)
			}
			if prev, dup := seenHosts[h]; dup {
				return fmt.Errorf("duplicate host %q (site #%d and site #%d)", h, prev, i+1)
			}
			seenHosts[h] = i + 1
			norm = append(norm, h)
		}
		s.Hosts = norm
		if s.Preset != "" {
			p := strings.ToLower(strings.TrimSpace(s.Preset))
			if p != "wordpress" {
				return fmt.Errorf("site %s: unknown preset %q (supported: wordpress)", s.Hosts[0], s.Preset)
			}
			s.Preset = p
		}
		if s.Cap < 0 {
			return fmt.Errorf("site %s: cap must not be negative", s.Hosts[0])
		}
		if s.PriorityCap < 0 {
			return fmt.Errorf("site %s: priority_cap must not be negative", s.Hosts[0])
		}
		if s.MicroCache != "" && !strings.EqualFold(s.MicroCache, "off") && s.MicroCache != "0" {
			d, err := time.ParseDuration(s.MicroCache)
			if err != nil || d < 0 {
				return fmt.Errorf("site %s: invalid micro_cache duration %q", s.Hosts[0], s.MicroCache)
			}
		}
		if s.MicroCacheMaxMB < 0 {
			return fmt.Errorf("site %s: micro_cache_max_mb must not be negative", s.Hosts[0])
		}
		if s.RoomSignedMaxTTL != "" {
			d, err := time.ParseDuration(s.RoomSignedMaxTTL)
			if err != nil || d < time.Second || d > time.Hour {
				return fmt.Errorf("site %s: invalid room_signed_max_ttl %q (must be 1s-1h)", s.Hosts[0], s.RoomSignedMaxTTL)
			}
		}
		if v, ok := s.RoomLeaseFraction.Get(); ok && (v < 0 || v > 1) {
			return fmt.Errorf("site %s: invalid room_lease_fraction %g (must be 0-1)", s.Hosts[0], v)
		}
		if s.BodyReadIdleTimeout != "" && !strings.EqualFold(s.BodyReadIdleTimeout, "off") && s.BodyReadIdleTimeout != "0" {
			d, err := time.ParseDuration(s.BodyReadIdleTimeout)
			if err != nil || d < 0 {
				return fmt.Errorf("site %s: invalid body_read_idle_timeout %q", s.Hosts[0], s.BodyReadIdleTimeout)
			}
		}
		if s.MaxUploadTime != "" && !strings.EqualFold(s.MaxUploadTime, "off") && s.MaxUploadTime != "0" {
			d, err := time.ParseDuration(s.MaxUploadTime)
			if err != nil || d < 0 {
				return fmt.Errorf("site %s: invalid max_upload_time %q", s.Hosts[0], s.MaxUploadTime)
			}
		}
		if err := validateCommonTimers("site "+s.Hosts[0],
			s.TokenTTL, s.FirstPollGrace, s.ReadyGrace, s.IdlePollTTL, s.Reaper, s.RetryAfter,
			s.UpstreamTimeout, s.UpstreamBodyIdleTimeout, s.UpstreamCBFailures, s.UpstreamCBCooldown,
			s.UpstreamHealthPath, s.UpstreamHealthInterval); err != nil {
			return err
		}
		if (s.TLSCert == "") != (s.TLSKey == "") {
			return fmt.Errorf("site %s: tls_cert and tls_key must both be set", s.Hosts[0])
		}
		for _, rl := range s.RateLimits {
			if err := validateRateLimitDirective(rl); err != nil {
				return fmt.Errorf("site %s: %w", s.Hosts[0], err)
			}
		}
		if err := validateSiteExtensions(s); err != nil {
			return err
		}
	}
	if dp := strings.ToLower(strings.TrimSpace(f.Global.TLSDNSProvider)); dp != "" && dp != "cloudflare" && dp != "webhook" {
		return fmt.Errorf("global: invalid tls_dns_provider %q (supported: cloudflare, webhook)", f.Global.TLSDNSProvider)
	} else {
		f.Global.TLSDNSProvider = dp
	}
	if f.Global.RoomSignedMaxTTL != "" {
		d, err := time.ParseDuration(f.Global.RoomSignedMaxTTL)
		if err != nil || d < time.Second || d > time.Hour {
			return fmt.Errorf("global: invalid room_signed_max_ttl %q (must be 1s-1h)", f.Global.RoomSignedMaxTTL)
		}
	}
	if v, ok := f.Global.RoomLeaseFraction.Get(); ok && (v < 0 || v > 1) {
		return fmt.Errorf("global: invalid room_lease_fraction %g (must be 0-1)", v)
	}
	if f.Global.BodyReadIdleTimeout != "" && !strings.EqualFold(f.Global.BodyReadIdleTimeout, "off") && f.Global.BodyReadIdleTimeout != "0" {
		d, err := time.ParseDuration(f.Global.BodyReadIdleTimeout)
		if err != nil || d < 0 {
			return fmt.Errorf("global: invalid body_read_idle_timeout %q", f.Global.BodyReadIdleTimeout)
		}
	}
	if f.Global.MaxUploadTime != "" && !strings.EqualFold(f.Global.MaxUploadTime, "off") && f.Global.MaxUploadTime != "0" {
		d, err := time.ParseDuration(f.Global.MaxUploadTime)
		if err != nil || d < 0 {
			return fmt.Errorf("global: invalid max_upload_time %q", f.Global.MaxUploadTime)
		}
	}
	if err := validateCommonTimers("global",
		f.Global.TokenTTL, f.Global.FirstPollGrace, f.Global.ReadyGrace, f.Global.IdlePollTTL, f.Global.Reaper, f.Global.RetryAfter,
		f.Global.UpstreamTimeout, f.Global.UpstreamBodyIdleTimeout, f.Global.UpstreamCBFailures, f.Global.UpstreamCBCooldown,
		f.Global.UpstreamHealthPath, f.Global.UpstreamHealthInterval); err != nil {
		return err
	}
	if (f.Global.TLSCert == "") != (f.Global.TLSKey == "") {
		return errors.New("global: tls_cert and tls_key must both be set")
	}
	if f.Global.HSTSMaxAge < 0 {
		return errors.New("global: hsts_max_age must not be negative")
	}
	return nil
}

func validateDurationField(scope, name, raw string, allowOff bool, minD, maxD time.Duration) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	if allowOff && (s == "0" || strings.EqualFold(s, "off")) {
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("%s: invalid %s %q", scope, name, raw)
	}
	if allowOff && d == 0 {
		return nil
	}
	if d < 0 || (minD > 0 && d < minD) || (maxD > 0 && d > maxD) {
		return fmt.Errorf("%s: invalid %s %q", scope, name, raw)
	}
	return nil
}

// validateCommonTimers checks queue timer, retry, and upstream health/circuit-
// breaker directives shared by [GlobalConfig] and [SiteConfig].
//
// # Parameters
//
//   - scope: Diagnostic label ("global" or "site <host>") prefixed to errors.
//   - tokenTTL, firstPollGrace, readyGrace, idlePollTTL, reaper: Duration
//     strings validated against their respective bounds; empty leaves defaults.
//   - retryAfter: Non-negative Retry-After header interval in seconds.
//   - upstreamTimeout, upstreamBodyIdleTimeout: Optional upstream durations
//     ("off" or "0" disables).
//   - upstreamCBFailures: Optional consecutive-failure threshold; None leaves
//     the default, Some(0) disables the circuit breaker, and negative values
//     are rejected.
//   - upstreamCBCooldown, upstreamHealthPath, upstreamHealthInterval: Upstream
//     circuit-breaker cooldown and active health-probe settings.
//
// # Returns
//
// nil when every supplied directive is within its permitted range, or an error
// identifying scope and the first invalid directive.
//
// # Example
//
//	if err := validateCommonTimers("global", "2m", "20s", "15s", "30s", "10s", 3,
//		"45s", "20s", opt.Some(5), "15s", "/healthz", "5s"); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/configfile.go:257 (direct call)
//   - internal/configfile/configfile.go:301 (direct call)
//
// Scope: current module (github.com/andreimerlescu/concert), including tests;
// build configuration: darwin/arm64, default tags.
// Interface, reflection, callback, and external callers are not exhaustive.
func validateCommonTimers(
	scope string,
	tokenTTL, firstPollGrace, readyGrace, idlePollTTL, reaper string,
	retryAfter int,
	upstreamTimeout, upstreamBodyIdleTimeout string,
	upstreamCBFailures opt.Option[int],
	upstreamCBCooldown, upstreamHealthPath, upstreamHealthInterval string,
) error {
	if err := validateDurationField(scope, "token_ttl", tokenTTL, true, 30*time.Second, 24*time.Hour); err != nil {
		return err
	}
	if err := validateDurationField(scope, "first_poll_grace", firstPollGrace, true, 10*time.Second, 24*time.Hour); err != nil {
		return err
	}
	if err := validateDurationField(scope, "ready_grace", readyGrace, true, 5*time.Second, 10*time.Minute); err != nil {
		return err
	}
	if err := validateDurationField(scope, "idle_poll_ttl", idlePollTTL, true, 10*time.Second, 24*time.Hour); err != nil {
		return err
	}
	if err := validateDurationField(scope, "reaper", reaper, false, 5*time.Second, 24*time.Hour); err != nil {
		return err
	}
	if retryAfter < 0 {
		return fmt.Errorf("%s: retry_after must not be negative", scope)
	}
	if err := validateDurationField(scope, "upstream_timeout", upstreamTimeout, true, 0, 0); err != nil {
		return err
	}
	if err := validateDurationField(scope, "upstream_body_idle_timeout", upstreamBodyIdleTimeout, true, time.Second, 24*time.Hour); err != nil {
		return err
	}
	if v, ok := upstreamCBFailures.Get(); ok && v < 0 {
		return fmt.Errorf("%s: upstream_cb_failures must not be negative", scope)
	}
	if err := validateDurationField(scope, "upstream_cb_cooldown", upstreamCBCooldown, false, time.Second, 0); err != nil {
		return err
	}
	if hp := strings.TrimSpace(upstreamHealthPath); hp != "" && !strings.EqualFold(hp, "off") && !strings.HasPrefix(hp, "/") {
		return fmt.Errorf("%s: invalid upstream_health_path %q (must start with / or be off)", scope, upstreamHealthPath)
	}
	if err := validateDurationField(scope, "upstream_health_interval", upstreamHealthInterval, false, time.Second, 0); err != nil {
		return err
	}
	return nil
}

// NormalizeHost canonicalizes a virtual host label: "*" (catch-all), a single-
// label wildcard ("*.example.com"), a bare IP literal, "localhost", or a bare
// DNS hostname (lowercased, trailing dot removed, no scheme/port/path/whitespace).
func NormalizeHost(raw string) (string, error) {
	h := strings.TrimSpace(strings.ToLower(raw))
	if h == "" {
		return "", errors.New("empty hostname")
	}
	if h == "*" || h == "default" {
		return "*", nil
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", errors.New("empty hostname")
	}
	wildcard := false
	if strings.HasPrefix(h, "*.") {
		wildcard = true
		h = strings.TrimPrefix(h, "*.")
		if h == "" || !strings.Contains(h, ".") {
			return "", errors.New("wildcard hostname must look like *.example.com")
		}
	}
	if strings.ContainsAny(h, "/:@ \t\r\n\\?*") {
		return "", errors.New("must be a bare hostname (no scheme, port, or path), *.example.com, or *")
	}
	if h == "localhost" {
		if wildcard {
			return "", errors.New("wildcard hostname must look like *.example.com")
		}
		return h, nil
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		if wildcard {
			return "", errors.New("wildcard hostname cannot be an IP address")
		}
		return addr.Unmap().String(), nil
	}
	for _, r := range h {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.') {
			return "", fmt.Errorf("invalid character %q in hostname", r)
		}
	}
	if strings.HasPrefix(h, ".") || strings.HasPrefix(h, "-") || strings.HasSuffix(h, "-") || strings.Contains(h, "..") {
		return "", errors.New("malformed DNS hostname")
	}
	if wildcard {
		return "*." + h, nil
	}
	return h, nil
}

func validateRateLimitDirective(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return errors.New("rate_limit directive must not be empty")
	}
	var prefix, spec string
	if p, sp, ok := strings.Cut(s, "="); ok {
		prefix, spec = strings.TrimSpace(p), strings.TrimSpace(sp)
	} else {
		fields := strings.Fields(s)
		if len(fields) != 2 {
			return fmt.Errorf("invalid rate_limit %q: expected <path> <rate>/<window>", raw)
		}
		prefix, spec = fields[0], fields[1]
	}
	if !strings.HasPrefix(prefix, "/") {
		return fmt.Errorf("invalid rate_limit %q: path must start with /", raw)
	}
	rateStr, winSpec, ok := strings.Cut(spec, "/")
	if !ok || rateStr == "" || winSpec == "" {
		return fmt.Errorf("invalid rate_limit %q: expected <rate>/<window>", raw)
	}
	rate, err := strconv.Atoi(strings.TrimSpace(rateStr))
	if err != nil || rate <= 0 {
		return fmt.Errorf("invalid rate_limit %q: invalid rate %q", raw, rateStr)
	}
	winPart, burstPart, hasBurst := strings.Cut(winSpec, ":")
	if hasBurst {
		b, berr := strconv.Atoi(strings.TrimSpace(burstPart))
		if berr != nil || b <= 0 {
			return fmt.Errorf("invalid rate_limit %q: invalid burst %q", raw, burstPart)
		}
	}
	winPart = strings.TrimSpace(winPart)
	switch winPart {
	case "s", "m", "h":
		winPart = "1" + winPart
	}
	if d, derr := time.ParseDuration(winPart); derr != nil || d <= 0 {
		return fmt.Errorf("invalid rate_limit %q: invalid window %q", raw, winPart)
	}
	return nil
}

// ─── Concertfile lexer & recursive-descent parser ────────────────────────────

type tokKind uint8

const (
	tokEOF tokKind = iota
	tokWord
	tokLBrace
	tokRBrace
	tokComma
	tokNewline
	tokSemi
)

type token struct {
	kind tokKind
	val  string
	line int
	col  int
}

func tokenize(src []byte) ([]token, error) {
	var out []token
	line, col := 1, 1
	i := 0
	n := len(src)
	for i < n {
		c := src[i]
		switch c {
		case ' ', '\t', '\r':
			i++
			col++
		case '\n':
			out = append(out, token{kind: tokNewline, line: line, col: col})
			i++
			line++
			col = 1
		case '#':
			for i < n && src[i] != '\n' {
				i++
				col++
			}
		case '{':
			out = append(out, token{kind: tokLBrace, val: "{", line: line, col: col})
			i++
			col++
		case '}':
			out = append(out, token{kind: tokRBrace, val: "}", line: line, col: col})
			i++
			col++
		case ',':
			out = append(out, token{kind: tokComma, val: ",", line: line, col: col})
			i++
			col++
		case ';':
			out = append(out, token{kind: tokSemi, val: ";", line: line, col: col})
			i++
			col++
		case '"':
			startLine, startCol := line, col
			i++
			col++
			var sb strings.Builder
			closed := false
			for i < n {
				ch := src[i]
				if ch == '\\' {
					if i+1 >= n {
						return nil, fmt.Errorf("Concertfile:%d:%d: unterminated escape sequence", line, col)
					}
					next := src[i+1]
					switch next {
					case '"', '\\':
						sb.WriteByte(next)
					case 'n':
						sb.WriteByte('\n')
					case 't':
						sb.WriteByte('\t')
					default:
						sb.WriteByte(next)
					}
					i += 2
					col += 2
					continue
				}
				if ch == '"' {
					i++
					col++
					closed = true
					break
				}
				if ch == '\n' {
					return nil, fmt.Errorf("Concertfile:%d:%d: unterminated quoted string", startLine, startCol)
				}
				sb.WriteByte(ch)
				i++
				col++
			}
			if !closed {
				return nil, fmt.Errorf("Concertfile:%d:%d: unterminated quoted string", startLine, startCol)
			}
			out = append(out, token{kind: tokWord, val: sb.String(), line: startLine, col: startCol})
		default:
			startLine, startCol := line, col
			start := i
			for i < n {
				ch := src[i]
				if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '{' || ch == '}' || ch == ',' || ch == ';' || ch == '#' || ch == '"' {
					break
				}
				i++
				col++
			}
			out = append(out, token{kind: tokWord, val: string(src[start:i]), line: startLine, col: startCol})
		}
	}
	out = append(out, token{kind: tokEOF, line: line, col: col})
	return out, nil
}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token {
	if p.pos >= len(p.toks) {
		return token{kind: tokEOF}
	}
	return p.toks[p.pos]
}

func (p *parser) next() token {
	t := p.peek()
	if p.pos < len(p.toks) {
		p.pos++
	}
	return t
}

func (p *parser) skipSeparators() {
	for {
		k := p.peek().kind
		if k == tokNewline || k == tokSemi {
			p.next()
			continue
		}
		return
	}
}

// ParseConcertfile parses Concertfile block syntax into a validated File.
func ParseConcertfile(src []byte) (*File, error) {
	toks, err := tokenize(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	f := &File{}
	seenGlobal := false

	for {
		p.skipSeparators()
		t := p.peek()
		if t.kind == tokEOF {
			break
		}
		if t.kind == tokLBrace {
			if seenGlobal {
				return nil, fmt.Errorf("Concertfile:%d:%d: global options block { ... } may only appear once", t.line, t.col)
			}
			seenGlobal = true
			p.next() // consume '{'
			if err := p.parseGlobalBlock(&f.Global); err != nil {
				return nil, err
			}
			continue
		}
		if t.kind != tokWord {
			return nil, fmt.Errorf("Concertfile:%d:%d: expected hostname or '{', got %q", t.line, t.col, t.val)
		}
		site, err := p.parseSiteBlock()
		if err != nil {
			return nil, err
		}
		f.Sites = append(f.Sites, site)
	}
	if err := f.NormalizeAndValidate(); err != nil {
		return nil, err
	}
	return f, nil
}

func (p *parser) parseDirectiveArgs() ([]string, error) {
	var args []string
	for {
		t := p.peek()
		switch t.kind {
		case tokEOF, tokNewline, tokSemi, tokRBrace:
			return args, nil
		case tokComma:
			p.next()
		case tokWord:
			args = append(args, p.next().val)
		default:
			return nil, fmt.Errorf("Concertfile:%d:%d: unexpected token %q in directive", t.line, t.col, t.val)
		}
	}
}

func parseBoolArg(t token, args []string) (bool, error) {
	if len(args) == 0 {
		return true, nil
	}
	if len(args) != 1 {
		return false, fmt.Errorf("Concertfile:%d:%d: directive %q expects 1 boolean argument", t.line, t.col, t.val)
	}
	switch strings.ToLower(args[0]) {
	case "true", "on", "yes", "1":
		return true, nil
	case "false", "off", "no", "0":
		return false, nil
	default:
		return false, fmt.Errorf("Concertfile:%d:%d: directive %q invalid boolean %q", t.line, t.col, t.val, args[0])
	}
}

func requireOneArg(t token, args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("Concertfile:%d:%d: directive %q expects 1 argument, got %d", t.line, t.col, t.val, len(args))
	}
	return args[0], nil
}

func parseIntArg(t token, args []string) (int, error) {
	s, err := requireOneArg(t, args)
	if err != nil {
		return 0, err
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("Concertfile:%d:%d: directive %q invalid integer %q", t.line, t.col, t.val, s)
	}
	return v, nil
}

func parseInt64Arg(t token, args []string) (int64, error) {
	s, err := requireOneArg(t, args)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("Concertfile:%d:%d: directive %q invalid integer %q", t.line, t.col, t.val, s)
	}
	return v, nil
}

func (p *parser) parseGlobalBlock(g *GlobalConfig) error {
	for {
		p.skipSeparators()
		t := p.peek()
		if t.kind == tokEOF {
			return fmt.Errorf("Concertfile:%d:%d: unclosed global block (missing '}')", t.line, t.col)
		}
		if t.kind == tokRBrace {
			p.next()
			return nil
		}
		if t.kind != tokWord {
			return fmt.Errorf("Concertfile:%d:%d: expected directive name, got %q", t.line, t.col, t.val)
		}
		dir := p.next()
		args, err := p.parseDirectiveArgs()
		if err != nil {
			return err
		}
		key := strings.ToLower(strings.ReplaceAll(dir.val, "-", "_"))
		switch key {
		case "listen":
			if g.Listen, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "http_listen", "tls_http_listen":
			if g.HTTPListen, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "tls_email":
			if g.TLSEmail, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "tls_cache", "tls_cache_dir":
			if g.TLSCache, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "tls_staging":
			if g.TLSStaging, err = parseBoolArg(dir, args); err != nil {
				return err
			}
		case "tls_cert":
			if g.TLSCert, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "tls_key":
			if g.TLSKey, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "tls_min_version":
			if g.TLSMinVersion, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "tls_dns_provider":
			if g.TLSDNSProvider, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "tls_dns_webhook_url":
			if g.TLSDNSWebhookURL, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "hsts_max_age":
			if g.HSTSMaxAge, err = parseIntArg(dir, args); err != nil {
				return err
			}
		case "http3":
			if g.HTTP3, err = parseBoolArg(dir, args); err != nil {
				return err
			}
		case "portal_listen":
			if g.PortalListen, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "portal_allow":
			g.PortalAllow = strings.Join(args, ",")
		case "portal_tls_cert":
			if g.PortalTLSCert, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "portal_tls_key":
			if g.PortalTLSKey, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "portal_secure_cookie":
			b, err := parseBoolArg(dir, args)
			if err != nil {
				return err
			}
			g.PortalSecureCookie = opt.Some(b)
		case "data_dir":
			if g.DataDir, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "trusted_proxies":
			g.TrustedProxies = strings.Join(args, ",")
		case "log_format":
			if g.LogFormat, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "log_level":
			if g.LogLevel, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "stats_auth":
			b, err := parseBoolArg(dir, args)
			if err != nil {
				return err
			}
			g.StatsAuth = opt.Some(b)
		case "room_verify_keys":
			if len(args) == 0 {
				return fmt.Errorf("Concertfile:%d:%d: room_verify_keys requires kid=key entries", dir.line, dir.col)
			}
			g.RoomVerifyKeys = strings.Join(args, ",")
		case "room_signed_max_ttl":
			if g.RoomSignedMaxTTL, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "room_lease_fraction":
			s, err := requireOneArg(dir, args)
			if err != nil {
				return err
			}
			v, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return fmt.Errorf("Concertfile:%d:%d: directive %q invalid number %q", dir.line, dir.col, dir.val, s)
			}
			g.RoomLeaseFraction = opt.Some(v)
		case "token_ttl":
			if g.TokenTTL, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "first_poll_grace":
			if g.FirstPollGrace, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "ready_grace":
			if g.ReadyGrace, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "idle_poll_ttl":
			if g.IdlePollTTL, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "reaper":
			if g.Reaper, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "retry_after":
			v, err := parseIntArg(dir, args)
			if err != nil {
				return err
			}
			if v < 1 {
				return fmt.Errorf("Concertfile:%d:%d: directive %q must be at least 1", dir.line, dir.col, dir.val)
			}
			g.RetryAfter = v
		case "busy_html":
			if g.BusyHTML, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "clear_queue_on_start":
			b, err := parseBoolArg(dir, args)
			if err != nil {
				return err
			}
			g.ClearQueueOnStart = opt.Some(b)
		case "body_read_idle_timeout":
			if g.BodyReadIdleTimeout, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "max_upload_time":
			if g.MaxUploadTime, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "upstream_timeout":
			if g.UpstreamTimeout, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "upstream_body_idle_timeout":
			if g.UpstreamBodyIdleTimeout, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "upstream_cb_failures":
			v, err := parseIntArg(dir, args)
			if err != nil {
				return err
			}
			g.UpstreamCBFailures = opt.Some(v)
		case "upstream_cb_cooldown":
			if g.UpstreamCBCooldown, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "upstream_health_path":
			if g.UpstreamHealthPath, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "upstream_health_interval":
			if g.UpstreamHealthInterval, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "fastlane_config":
			if g.FastlaneConfig, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "networks_config":
			if g.NetworksConfig, err = requireOneArg(dir, args); err != nil {
				return err
			}
		case "fastlane_lock_destinations":
			b, err := parseBoolArg(dir, args)
			if err != nil {
				return err
			}
			g.FastlaneLockDestinations = opt.Some(b)
		default:
			return fmt.Errorf("Concertfile:%d:%d: unknown global directive %q", dir.line, dir.col, dir.val)
		}
	}
}

func (p *parser) parseSiteBlock() (SiteConfig, error) {
	var s SiteConfig
	for {
		t := p.peek()
		switch t.kind {
		case tokWord:
			s.Hosts = append(s.Hosts, p.next().val)
		case tokComma:
			p.next()
		case tokLBrace:
			p.next()
			goto body
		default:
			return s, fmt.Errorf("Concertfile:%d:%d: expected hostname or '{' to open site block, got %q", t.line, t.col, t.val)
		}
	}
body:
	for {
		p.skipSeparators()
		t := p.peek()
		if t.kind == tokEOF {
			return s, fmt.Errorf("Concertfile:%d:%d: unclosed site block for %v (missing '}')", t.line, t.col, s.Hosts)
		}
		if t.kind == tokRBrace {
			p.next()
			return s, nil
		}
		if t.kind != tokWord {
			return s, fmt.Errorf("Concertfile:%d:%d: expected directive name, got %q", t.line, t.col, t.val)
		}
		dir := p.next()
		key := strings.ToLower(strings.ReplaceAll(dir.val, "-", "_"))
		if key == "route" {
			r, err := p.parseRouteBlock(dir)
			if err != nil {
				return s, err
			}
			s.Routes = append(s.Routes, r)
			continue
		}
		args, err := p.parseDirectiveArgs()
		if err != nil {
			return s, err
		}
		switch key {
		case "preset":
			if s.Preset, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "upstream":
			if len(args) == 0 {
				return s, fmt.Errorf("Concertfile:%d:%d: upstream requires at least one URL", dir.line, dir.col)
			}
			s.Upstream = strings.Join(args, ",")
		case "root", "static_root":
			if s.Root, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "mount", "static_mounts":
			if len(args) == 0 {
				return s, fmt.Errorf("Concertfile:%d:%d: %s requires /prefix=/dir", dir.line, dir.col, dir.val)
			}
			for _, a := range args {
				for _, part := range strings.Split(a, ",") {
					if part = strings.TrimSpace(part); part != "" {
						s.Mounts = append(s.Mounts, part)
					}
				}
			}
		case "static_allow_ext":
			s.StaticAllowExt = strings.Join(args, ",")
		case "static_cache_control":
			if s.StaticCacheControl, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "static_fallback":
			b, err := parseBoolArg(dir, args)
			if err != nil {
				return s, err
			}
			s.StaticFallback = opt.Some(b)
		case "compress":
			b, err := parseBoolArg(dir, args)
			if err != nil {
				return s, err
			}
			s.Compress = opt.Some(b)
		case "assets":
			s.Assets = strings.Join(args, ",")
		case "asset_public":
			s.AssetPublic = strings.Join(args, ",")
		case "bypass":
			s.Bypass = strings.Join(args, ",")
		case "stream_paths":
			s.StreamPaths = strings.Join(args, ",")
		case "cap":
			if s.Cap, err = parseIntArg(dir, args); err != nil {
				return s, err
			}
		case "max_queue":
			v, err := parseInt64Arg(dir, args)
			if err != nil {
				return s, err
			}
			s.MaxQueue = opt.Some(v)
		case "priority_cap":
			if s.PriorityCap, err = parseIntArg(dir, args); err != nil {
				return s, err
			}
		case "priority_lane_rank":
			if s.PriorityLaneRank, err = parseIntArg(dir, args); err != nil {
				return s, err
			}
		case "secure_cookie":
			b, err := parseBoolArg(dir, args)
			if err != nil {
				return s, err
			}
			s.SecureCookie = opt.Some(b)
		case "preserve_host":
			b, err := parseBoolArg(dir, args)
			if err != nil {
				return s, err
			}
			s.PreserveHost = opt.Some(b)
		case "fcgi_index":
			if s.FCGIIndex, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "fcgi_deny_paths":
			s.FCGIDenyPaths = strings.Join(args, ",")
		case "micro_cache":
			if s.MicroCache, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "micro_cache_max_mb":
			if s.MicroCacheMaxMB, err = parseIntArg(dir, args); err != nil {
				return s, err
			}
		case "abuse":
			b, err := parseBoolArg(dir, args)
			if err != nil {
				return s, err
			}
			s.Abuse = opt.Some(b)
		case "abuse_strikes":
			if s.AbuseStrikes, err = parseIntArg(dir, args); err != nil {
				return s, err
			}
		case "ban_paths":
			s.BanPaths = strings.Join(args, ",")
		case "rate_limit":
			if len(args) == 2 {
				s.RateLimits = append(s.RateLimits, args[0]+" "+args[1])
			} else if len(args) == 1 && strings.Contains(args[0], "=") {
				s.RateLimits = append(s.RateLimits, args[0])
			} else {
				return s, fmt.Errorf("Concertfile:%d:%d: rate_limit expects <path> <rate>/<window>", dir.line, dir.col)
			}
		case "room_verify_keys":
			if len(args) == 0 {
				return s, fmt.Errorf("Concertfile:%d:%d: room_verify_keys requires kid=key entries", dir.line, dir.col)
			}
			s.RoomVerifyKeys = strings.Join(args, ",")
		case "room_scope":
			if s.RoomScope, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "room_signed_max_ttl":
			if s.RoomSignedMaxTTL, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "room_lease_fraction":
			arg, err := requireOneArg(dir, args)
			if err != nil {
				return s, err
			}
			v, err := strconv.ParseFloat(arg, 64)
			if err != nil {
				return s, fmt.Errorf("Concertfile:%d:%d: directive %q invalid number %q", dir.line, dir.col, dir.val, arg)
			}
			s.RoomLeaseFraction = opt.Some(v)
		case "token_ttl":
			if s.TokenTTL, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "first_poll_grace":
			if s.FirstPollGrace, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "ready_grace":
			if s.ReadyGrace, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "idle_poll_ttl":
			if s.IdlePollTTL, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "reaper":
			if s.Reaper, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "retry_after":
			v, err := parseIntArg(dir, args)
			if err != nil {
				return s, err
			}
			if v < 1 {
				return s, fmt.Errorf("Concertfile:%d:%d: directive %q must be at least 1", dir.line, dir.col, dir.val)
			}
			s.RetryAfter = v
		case "busy_html":
			if s.BusyHTML, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "clear_queue_on_start":
			b, err := parseBoolArg(dir, args)
			if err != nil {
				return s, err
			}
			s.ClearQueueOnStart = opt.Some(b)
		case "body_read_idle_timeout":
			if s.BodyReadIdleTimeout, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "max_upload_time":
			if s.MaxUploadTime, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "upstream_timeout":
			if s.UpstreamTimeout, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "upstream_body_idle_timeout":
			if s.UpstreamBodyIdleTimeout, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "upstream_cb_failures":
			v, err := parseIntArg(dir, args)
			if err != nil {
				return s, err
			}
			s.UpstreamCBFailures = opt.Some(v)
		case "upstream_cb_cooldown":
			if s.UpstreamCBCooldown, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "upstream_health_path":
			if s.UpstreamHealthPath, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "upstream_health_interval":
			if s.UpstreamHealthInterval, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "fastlane_config":
			if s.FastlaneConfig, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "networks_config":
			if s.NetworksConfig, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "fastlane_lock_destinations":
			b, err := parseBoolArg(dir, args)
			if err != nil {
				return s, err
			}
			s.FastlaneLockDestinations = opt.Some(b)
		case "tls_cert":
			if s.TLSCert, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "tls_key":
			if s.TLSKey, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "header":
			hr, err := parseHeaderDirective(dir, args)
			if err != nil {
				return s, err
			}
			s.Headers = append(s.Headers, hr)
		case "redirect":
			rr, err := parseRedirectDirective(dir, args)
			if err != nil {
				return s, err
			}
			s.Redirects = append(s.Redirects, rr)
		case "drop_event_id":
			if s.DropEventID, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "drop_lobby_at":
			if s.DropLobbyAt, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		case "drop_open_at":
			if s.DropOpenAt, err = requireOneArg(dir, args); err != nil {
				return s, err
			}
		default:
			return s, fmt.Errorf("Concertfile:%d:%d: unknown site directive %q", dir.line, dir.col, dir.val)
		}
	}
}

// FormatConcertfile renders f in canonical human-readable Concertfile syntax.
func FormatConcertfile(f *File) string {
	var b strings.Builder
	quote := func(s string) string {
		if s == "" || strings.ContainsAny(s, " \t\n\"#{};,") {
			return strconv.Quote(s)
		}
		return s
	}

	g := f.Global
	hasGlobal := g.Listen != "" || g.HTTPListen != "" || g.TLSEmail != "" || g.TLSCache != "" ||
		g.TLSStaging || g.TLSCert != "" || g.TLSDNSProvider != "" || g.TLSDNSWebhookURL != "" || g.HTTP3 || g.PortalListen != "" || g.DataDir != "" ||
		g.TrustedProxies != "" || g.LogFormat != "" || g.LogLevel != "" || g.HSTSMaxAge > 0 ||
		g.RoomVerifyKeys != "" || g.RoomSignedMaxTTL != "" || g.RoomLeaseFraction.IsSome() ||
		g.TokenTTL != "" || g.FirstPollGrace != "" || g.ReadyGrace != "" || g.IdlePollTTL != "" ||
		g.Reaper != "" || g.RetryAfter > 0 || g.BusyHTML != "" || g.ClearQueueOnStart.IsSome() ||
		g.BodyReadIdleTimeout != "" || g.MaxUploadTime != "" || g.UpstreamTimeout != "" ||
		g.UpstreamBodyIdleTimeout != "" || g.UpstreamCBFailures.IsSome() || g.UpstreamCBCooldown != "" ||
		g.UpstreamHealthPath != "" || g.UpstreamHealthInterval != ""
	if hasGlobal {
		b.WriteString("{\n")
		if g.Listen != "" {
			fmt.Fprintf(&b, "    listen %s\n", quote(g.Listen))
		}
		if g.HTTPListen != "" {
			fmt.Fprintf(&b, "    http_listen %s\n", quote(g.HTTPListen))
		}
		if g.TLSEmail != "" {
			fmt.Fprintf(&b, "    tls_email %s\n", quote(g.TLSEmail))
		}
		if g.TLSCache != "" {
			fmt.Fprintf(&b, "    tls_cache %s\n", quote(g.TLSCache))
		}
		if g.TLSStaging {
			b.WriteString("    tls_staging on\n")
		}
		if g.TLSCert != "" {
			fmt.Fprintf(&b, "    tls_cert %s\n", quote(g.TLSCert))
			fmt.Fprintf(&b, "    tls_key %s\n", quote(g.TLSKey))
		}
		if g.TLSDNSProvider != "" {
			fmt.Fprintf(&b, "    tls_dns_provider %s\n", quote(g.TLSDNSProvider))
		}
		if g.TLSDNSWebhookURL != "" {
			fmt.Fprintf(&b, "    tls_dns_webhook_url %s\n", quote(g.TLSDNSWebhookURL))
		}
		if g.HSTSMaxAge > 0 {
			fmt.Fprintf(&b, "    hsts_max_age %d\n", g.HSTSMaxAge)
		}
		if g.HTTP3 {
			b.WriteString("    http3 on\n")
		}
		if g.DataDir != "" {
			fmt.Fprintf(&b, "    data_dir %s\n", quote(g.DataDir))
		}
		if g.PortalListen != "" {
			fmt.Fprintf(&b, "    portal_listen %s\n", quote(g.PortalListen))
		}
		if g.RoomVerifyKeys != "" {
			fmt.Fprintf(&b, "    room_verify_keys %s\n", quote(g.RoomVerifyKeys))
		}
		if g.RoomSignedMaxTTL != "" {
			fmt.Fprintf(&b, "    room_signed_max_ttl %s\n", quote(g.RoomSignedMaxTTL))
		}
		if v, ok := g.RoomLeaseFraction.Get(); ok {
			fmt.Fprintf(&b, "    room_lease_fraction %g\n", v)
		}
		if g.TokenTTL != "" {
			fmt.Fprintf(&b, "    token_ttl %s\n", quote(g.TokenTTL))
		}
		if g.FirstPollGrace != "" {
			fmt.Fprintf(&b, "    first_poll_grace %s\n", quote(g.FirstPollGrace))
		}
		if g.ReadyGrace != "" {
			fmt.Fprintf(&b, "    ready_grace %s\n", quote(g.ReadyGrace))
		}
		if g.IdlePollTTL != "" {
			fmt.Fprintf(&b, "    idle_poll_ttl %s\n", quote(g.IdlePollTTL))
		}
		if g.Reaper != "" {
			fmt.Fprintf(&b, "    reaper %s\n", quote(g.Reaper))
		}
		if g.RetryAfter > 0 {
			fmt.Fprintf(&b, "    retry_after %d\n", g.RetryAfter)
		}
		if g.BusyHTML != "" {
			fmt.Fprintf(&b, "    busy_html %s\n", quote(g.BusyHTML))
		}
		if v, ok := g.ClearQueueOnStart.Get(); ok {
			fmt.Fprintf(&b, "    clear_queue_on_start %v\n", v)
		}
		if g.BodyReadIdleTimeout != "" {
			fmt.Fprintf(&b, "    body_read_idle_timeout %s\n", quote(g.BodyReadIdleTimeout))
		}
		if g.MaxUploadTime != "" {
			fmt.Fprintf(&b, "    max_upload_time %s\n", quote(g.MaxUploadTime))
		}
		if g.UpstreamTimeout != "" {
			fmt.Fprintf(&b, "    upstream_timeout %s\n", quote(g.UpstreamTimeout))
		}
		if g.UpstreamBodyIdleTimeout != "" {
			fmt.Fprintf(&b, "    upstream_body_idle_timeout %s\n", quote(g.UpstreamBodyIdleTimeout))
		}
		if v, ok := g.UpstreamCBFailures.Get(); ok {
			fmt.Fprintf(&b, "    upstream_cb_failures %d\n", v)
		}
		if g.UpstreamCBCooldown != "" {
			fmt.Fprintf(&b, "    upstream_cb_cooldown %s\n", quote(g.UpstreamCBCooldown))
		}
		if g.UpstreamHealthPath != "" {
			fmt.Fprintf(&b, "    upstream_health_path %s\n", quote(g.UpstreamHealthPath))
		}
		if g.UpstreamHealthInterval != "" {
			fmt.Fprintf(&b, "    upstream_health_interval %s\n", quote(g.UpstreamHealthInterval))
		}
		b.WriteString("}\n\n")
	}

	for i, s := range f.Sites {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(strings.Join(s.Hosts, ", "))
		b.WriteString(" {\n")
		if s.Preset != "" {
			fmt.Fprintf(&b, "    preset %s\n", quote(s.Preset))
		}
		if s.Root != "" {
			fmt.Fprintf(&b, "    root %s\n", quote(s.Root))
		}
		if s.Upstream != "" {
			fmt.Fprintf(&b, "    upstream %s\n", quote(s.Upstream))
		}
		for _, m := range s.Mounts {
			fmt.Fprintf(&b, "    mount %s\n", quote(m))
		}
		if s.Cap > 0 {
			fmt.Fprintf(&b, "    cap %d\n", s.Cap)
		}
		if s.PriorityCap > 0 {
			fmt.Fprintf(&b, "    priority_cap %d\n", s.PriorityCap)
		}
		if s.Assets != "" {
			fmt.Fprintf(&b, "    assets %s\n", quote(s.Assets))
		}
		if s.MicroCache != "" {
			fmt.Fprintf(&b, "    micro_cache %s\n", quote(s.MicroCache))
		}
		if s.MicroCacheMaxMB > 0 {
			fmt.Fprintf(&b, "    micro_cache_max_mb %d\n", s.MicroCacheMaxMB)
		}
		if s.FCGIIndex != "" {
			fmt.Fprintf(&b, "    fcgi_index %s\n", quote(s.FCGIIndex))
		}
		if s.FCGIDenyPaths != "" {
			fmt.Fprintf(&b, "    fcgi_deny_paths %s\n", quote(s.FCGIDenyPaths))
		}
		if v, ok := s.SecureCookie.Get(); ok {
			fmt.Fprintf(&b, "    secure_cookie %v\n", v)
		}
		if s.RoomVerifyKeys != "" {
			fmt.Fprintf(&b, "    room_verify_keys %s\n", quote(s.RoomVerifyKeys))
		}
		if s.RoomScope != "" {
			fmt.Fprintf(&b, "    room_scope %s\n", quote(s.RoomScope))
		}
		if s.RoomSignedMaxTTL != "" {
			fmt.Fprintf(&b, "    room_signed_max_ttl %s\n", quote(s.RoomSignedMaxTTL))
		}
		if v, ok := s.RoomLeaseFraction.Get(); ok {
			fmt.Fprintf(&b, "    room_lease_fraction %g\n", v)
		}
		if s.TokenTTL != "" {
			fmt.Fprintf(&b, "    token_ttl %s\n", quote(s.TokenTTL))
		}
		if s.FirstPollGrace != "" {
			fmt.Fprintf(&b, "    first_poll_grace %s\n", quote(s.FirstPollGrace))
		}
		if s.ReadyGrace != "" {
			fmt.Fprintf(&b, "    ready_grace %s\n", quote(s.ReadyGrace))
		}
		if s.IdlePollTTL != "" {
			fmt.Fprintf(&b, "    idle_poll_ttl %s\n", quote(s.IdlePollTTL))
		}
		if s.Reaper != "" {
			fmt.Fprintf(&b, "    reaper %s\n", quote(s.Reaper))
		}
		if s.RetryAfter > 0 {
			fmt.Fprintf(&b, "    retry_after %d\n", s.RetryAfter)
		}
		if s.BusyHTML != "" {
			fmt.Fprintf(&b, "    busy_html %s\n", quote(s.BusyHTML))
		}
		if v, ok := s.ClearQueueOnStart.Get(); ok {
			fmt.Fprintf(&b, "    clear_queue_on_start %v\n", v)
		}
		if s.BodyReadIdleTimeout != "" {
			fmt.Fprintf(&b, "    body_read_idle_timeout %s\n", quote(s.BodyReadIdleTimeout))
		}
		if s.MaxUploadTime != "" {
			fmt.Fprintf(&b, "    max_upload_time %s\n", quote(s.MaxUploadTime))
		}
		if s.UpstreamTimeout != "" {
			fmt.Fprintf(&b, "    upstream_timeout %s\n", quote(s.UpstreamTimeout))
		}
		if s.UpstreamBodyIdleTimeout != "" {
			fmt.Fprintf(&b, "    upstream_body_idle_timeout %s\n", quote(s.UpstreamBodyIdleTimeout))
		}
		if v, ok := s.UpstreamCBFailures.Get(); ok {
			fmt.Fprintf(&b, "    upstream_cb_failures %d\n", v)
		}
		if s.UpstreamCBCooldown != "" {
			fmt.Fprintf(&b, "    upstream_cb_cooldown %s\n", quote(s.UpstreamCBCooldown))
		}
		if s.UpstreamHealthPath != "" {
			fmt.Fprintf(&b, "    upstream_health_path %s\n", quote(s.UpstreamHealthPath))
		}
		if s.UpstreamHealthInterval != "" {
			fmt.Fprintf(&b, "    upstream_health_interval %s\n", quote(s.UpstreamHealthInterval))
		}
		if s.TLSCert != "" {
			fmt.Fprintf(&b, "    tls_cert %s\n", quote(s.TLSCert))
			fmt.Fprintf(&b, "    tls_key %s\n", quote(s.TLSKey))
		}
		for _, rl := range s.RateLimits {
			if p, sp, ok := strings.Cut(rl, "="); ok {
				fmt.Fprintf(&b, "    rate_limit %s %s\n", quote(strings.TrimSpace(p)), quote(strings.TrimSpace(sp)))
			} else if fields := strings.Fields(rl); len(fields) == 2 {
				fmt.Fprintf(&b, "    rate_limit %s %s\n", quote(fields[0]), quote(fields[1]))
			}
		}
		formatSiteExtensions(&b, s, quote)
		b.WriteString("}\n")
	}
	return b.String()
}
