package configfile

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// Validation bounds for routes, headers, redirects, and drop schedules (R3, S9).
const (
	maxRoutePathLen   = 1024
	maxHeaderNameLen  = 256
	maxHeaderValueLen = 8192
	maxRedirectURLLen = 2048
	maxDropEventIDLen = 128
)

// HeaderAction names the response header mutation performed by a [HeaderRule].
type HeaderAction string

const (
	// HeaderSet replaces any existing response header values with Value.
	HeaderSet HeaderAction = "set"
	// HeaderAdd appends Value to the response header without replacing existing values.
	HeaderAdd HeaderAction = "add"
	// HeaderRemove deletes the named response header before sending the response.
	HeaderRemove HeaderAction = "remove"
)

// RouteConfig defines a path-based upstream routing override inside a [SiteConfig].
type RouteConfig struct {
	// Path is the normalized URL path prefix (starting with "/") matched by this route.
	Path string `json:"path"`
	// Upstream optionally overrides the site upstream target(s) for matching requests.
	// Uses the same http://, https://, fcgi://, or fcgi+unix:// syntax as SiteConfig.Upstream.
	Upstream string `json:"upstream,omitempty"`
	// StripPrefix removes Path from the forwarded request URI when true.
	StripPrefix bool `json:"strip_prefix,omitempty"`
	// RateLimit optionally sets a per-route rate limit in "<count>/<duration>"
	// (or "<count>/<duration>:<burst>") format.
	RateLimit string `json:"rate_limit,omitempty"`
	// Bypass skips the waiting room for matching requests when true.
	Bypass bool `json:"bypass,omitempty"`
	// Cap optionally overrides the concurrency cap for matching requests (must be >= 0).
	Cap int32 `json:"cap,omitempty"`
	// AgentBidding enables AI agent pass bidding for matching requests when true.
	AgentBidding bool `json:"agent_bidding,omitempty"`
}

// HeaderRule defines a single response header mutation applied to a [SiteConfig].
type HeaderRule struct {
	// Action is one of HeaderSet ("set"), HeaderAdd ("add"), or HeaderRemove ("remove").
	Action HeaderAction `json:"action"`
	// Name is an RFC 7230 header field-name token. Forbidden hop-by-hop and
	// security-override headers (such as Host, Transfer-Encoding, Content-Length,
	// and Set-Cookie) are rejected.
	Name string `json:"name"`
	// Value is the header field-value for set/add rules (empty for remove).
	// Must not contain CR, LF, NUL, or other ASCII control characters except HTAB.
	Value string `json:"value,omitempty"`
}

// RedirectRule defines an HTTP redirect rule on a [SiteConfig].
type RedirectRule struct {
	// From is the normalized request path (starting with "/") that triggers the redirect.
	From string `json:"from"`
	// To is the redirect target: either a single-slash relative path ("/...")
	// or an absolute http:// or https:// URL.
	To string `json:"to"`
	// Status is the HTTP redirect status code (301, 302, 307, or 308; defaults to 302).
	Status int `json:"status,omitempty"`
}

// forbiddenHeaders lists lowercased hop-by-hop and security-override header
// names that HeaderRule must never mutate (S9).
var forbiddenHeaders = map[string]struct{}{
	"host":                {},
	"transfer-encoding":   {},
	"content-length":      {},
	"set-cookie":          {},
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"upgrade":             {},
}

// parseRouteBlock parses a nested `route [<path>] { ... }` block inside a site block.
//
// # Parameters
//
//   - dir: The `route` directive token already consumed by parseSiteBlock.
//
// # Returns
//
// A populated RouteConfig (validated subsequently by NormalizeAndValidate), or
// an error with Concertfile line and column coordinates on syntax failure.
//
// # Example
//
//	r, err := p.parseRouteBlock(dir)
//	if err != nil {
//		return s, err
//	}
//	s.Routes = append(s.Routes, r)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/configfile.go:974 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (p *parser) parseRouteBlock(dir token) (RouteConfig, error) {
	var r RouteConfig

	// Accept `route /prefix { ... }` or `route { path /prefix ... }`.
	t := p.peek()
	if t.kind == tokWord {
		r.Path = p.next().val
		t = p.peek()
	}
	if t.kind != tokLBrace {
		return r, fmt.Errorf("Concertfile:%d:%d: route directive expects '{' after path, got %q",
			t.line, t.col, t.val)
	}
	p.next() // consume '{'

	for {
		p.skipSeparators()
		cur := p.peek()
		if cur.kind == tokEOF {
			return r, fmt.Errorf("Concertfile:%d:%d: unclosed route block for %q (missing '}')",
				cur.line, cur.col, r.Path)
		}
		if cur.kind == tokRBrace {
			p.next()
			return r, nil
		}
		if cur.kind != tokWord {
			return r, fmt.Errorf("Concertfile:%d:%d: expected route directive name, got %q",
				cur.line, cur.col, cur.val)
		}
		sub := p.next()
		args, err := p.parseDirectiveArgs()
		if err != nil {
			return r, err
		}
		subKey := strings.ToLower(strings.ReplaceAll(sub.val, "-", "_"))
		switch subKey {
		case "path":
			v, err := requireOneArg(sub, args)
			if err != nil {
				return r, err
			}
			if r.Path != "" && r.Path != v {
				return r, fmt.Errorf("Concertfile:%d:%d: route path already set to %q", sub.line, sub.col, r.Path)
			}
			r.Path = v
		case "upstream":
			if len(args) == 0 {
				return r, fmt.Errorf("Concertfile:%d:%d: route upstream requires at least one URL", sub.line, sub.col)
			}
			r.Upstream = strings.Join(args, ",")
		case "strip_prefix":
			b, err := parseBoolArg(sub, args)
			if err != nil {
				return r, err
			}
			r.StripPrefix = b
		case "rate_limit":
			v, err := requireOneArg(sub, args)
			if err != nil {
				return r, err
			}
			r.RateLimit = v
		case "bypass":
			b, err := parseBoolArg(sub, args)
			if err != nil {
				return r, err
			}
			r.Bypass = b
		case "cap":
			v, err := parseInt32Arg(sub, args)
			if err != nil {
				return r, err
			}
			r.Cap = v
		case "agent_bidding":
			b, err := parseBoolArg(sub, args)
			if err != nil {
				return r, err
			}
			r.AgentBidding = b
		default:
			return r, fmt.Errorf("Concertfile:%d:%d: unknown route directive %q", sub.line, sub.col, sub.val)
		}
	}
}

// parseInt32Arg parses a single base-10 signed 32-bit integer directive argument.
//
// # Parameters
//
//   - t: Directive token for error reporting.
//   - args: Raw argument tokens collected for the directive.
//
// # Returns
//
// The parsed int32 value, or an error if argument count != 1 or parsing overflows int32.
//
// # Example
//
//	capVal, err := parseInt32Arg(sub, args)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/routes.go:191 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func parseInt32Arg(t token, args []string) (int32, error) {
	s, err := requireOneArg(t, args)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil || v < math.MinInt32 || v > math.MaxInt32 {
		return 0, fmt.Errorf("Concertfile:%d:%d: directive %q invalid int32 %q", t.line, t.col, t.val, s)
	}
	return int32(v), nil
}

// parseHeaderDirective parses a site `header` directive into a [HeaderRule].
//
// Supported forms:
//   - `header set <Name> <Value>`
//   - `header add <Name> <Value>`
//   - `header remove <Name>`
//   - `header +<Name> <Value>` (shorthand for add)
//   - `header -<Name>` (shorthand for remove)
//
// # Parameters
//
//   - dir: The `header` directive token for error reporting.
//   - args: Argument tokens following `header`.
//
// # Returns
//
// A HeaderRule ready for semantic validation in NormalizeAndValidate, or a syntax error.
//
// # Example
//
//	hr, err := parseHeaderDirective(dir, args)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/configfile.go:1219 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func parseHeaderDirective(dir token, args []string) (HeaderRule, error) {
	if len(args) == 0 {
		return HeaderRule{}, fmt.Errorf("Concertfile:%d:%d: header expects set/add/remove (or +Name/-Name)", dir.line, dir.col)
	}

	first := args[0]
	if strings.HasPrefix(first, "+") && len(first) > 1 {
		if len(args) != 2 {
			return HeaderRule{}, fmt.Errorf("Concertfile:%d:%d: header +%s expects 1 value argument", dir.line, dir.col, first[1:])
		}
		return HeaderRule{Action: HeaderAdd, Name: first[1:], Value: args[1]}, nil
	}
	if strings.HasPrefix(first, "-") && len(first) > 1 {
		if len(args) != 1 {
			return HeaderRule{}, fmt.Errorf("Concertfile:%d:%d: header -%s takes no value argument", dir.line, dir.col, first[1:])
		}
		return HeaderRule{Action: HeaderRemove, Name: first[1:]}, nil
	}

	action := HeaderAction(strings.ToLower(first))
	switch action {
	case HeaderSet, HeaderAdd:
		if len(args) != 3 {
			return HeaderRule{}, fmt.Errorf("Concertfile:%d:%d: header %s expects <Name> <Value>", dir.line, dir.col, action)
		}
		return HeaderRule{Action: action, Name: args[1], Value: args[2]}, nil
	case HeaderRemove:
		if len(args) != 2 {
			return HeaderRule{}, fmt.Errorf("Concertfile:%d:%d: header remove expects <Name>", dir.line, dir.col)
		}
		return HeaderRule{Action: HeaderRemove, Name: args[1]}, nil
	default:
		return HeaderRule{}, fmt.Errorf("Concertfile:%d:%d: invalid header action %q (expected set, add, remove, +Name, or -Name)",
			dir.line, dir.col, first)
	}
}

// parseRedirectDirective parses a site `redirect <from> <to> [301|302|307|308]` directive.
//
// # Parameters
//
//   - dir: The `redirect` directive token for error reporting.
//   - args: Argument tokens following `redirect` (2 or 3 arguments).
//
// # Returns
//
// A RedirectRule (with Status defaulted to 302 when omitted), or a syntax error.
//
// # Example
//
//	rr, err := parseRedirectDirective(dir, args)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/configfile.go:1225 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func parseRedirectDirective(dir token, args []string) (RedirectRule, error) {
	if len(args) < 2 || len(args) > 3 {
		return RedirectRule{}, fmt.Errorf("Concertfile:%d:%d: redirect expects <from> <to> [301|302|307|308]", dir.line, dir.col)
	}
	status := 302
	if len(args) == 3 {
		code, err := strconv.Atoi(args[2])
		if err != nil {
			return RedirectRule{}, fmt.Errorf("Concertfile:%d:%d: redirect invalid status %q", dir.line, dir.col, args[2])
		}
		status = code
	}
	return RedirectRule{
		From:   args[0],
		To:     args[1],
		Status: status,
	}, nil
}

// validateSiteExtensions normalizes and validates Routes, Headers, Redirects,
// and Drop schedule directives on a single SiteConfig.
//
// # Parameters
//
//   - s: SiteConfig to normalize and validate in place; must have at least one host.
//
// # Returns
//
// nil when every extension passes validation; otherwise a site-scoped error.
//
// # Example
//
//	if err := validateSiteExtensions(s); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/configfile.go:253 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func validateSiteExtensions(s *SiteConfig) error {
	host := s.Hosts[0]

	seenRoutes := make(map[string]struct{}, len(s.Routes))
	for i := range s.Routes {
		if err := normalizeAndValidateRoute(&s.Routes[i], seenRoutes); err != nil {
			return fmt.Errorf("site %s: route #%d: %w", host, i+1, err)
		}
	}

	for i := range s.Headers {
		if err := normalizeAndValidateHeader(&s.Headers[i]); err != nil {
			return fmt.Errorf("site %s: header #%d: %w", host, i+1, err)
		}
	}

	seenRedirects := make(map[string]struct{}, len(s.Redirects))
	for i := range s.Redirects {
		if err := normalizeAndValidateRedirect(&s.Redirects[i], seenRedirects); err != nil {
			return fmt.Errorf("site %s: redirect #%d: %w", host, i+1, err)
		}
	}

	if err := validateDropSchedule(s); err != nil {
		return fmt.Errorf("site %s: %w", host, err)
	}
	return nil
}

// normalizeAndValidateRoute canonicalizes and validates a single RouteConfig
// and checks for duplicate normalized route paths within a site.
//
// # Parameters
//
//   - r: RouteConfig to normalize and validate in place.
//   - seen: Set of already-seen normalized route paths for the enclosing site.
//
// # Returns
//
// nil on success, or a descriptive validation error.
//
// # Example
//
//	if err := normalizeAndValidateRoute(&route, seen); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/routes.go:378 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func normalizeAndValidateRoute(r *RouteConfig, seen map[string]struct{}) error {
	normPath, err := normalizeHTTPPath(r.Path)
	if err != nil {
		return fmt.Errorf("invalid path %q: %w", r.Path, err)
	}
	if _, dup := seen[normPath]; dup {
		return fmt.Errorf("duplicate route path %q", normPath)
	}
	seen[normPath] = struct{}{}
	r.Path = normPath

	if r.Upstream != "" {
		normUp, err := validateUpstreamSpec(r.Upstream)
		if err != nil {
			return fmt.Errorf("path %q: %w", normPath, err)
		}
		r.Upstream = normUp
	}

	if r.RateLimit != "" {
		spec := strings.TrimSpace(r.RateLimit)
		if err := validateRateLimitSpec(spec); err != nil {
			return fmt.Errorf("path %q: invalid rate_limit %q: %w", normPath, r.RateLimit, err)
		}
		r.RateLimit = spec
	}

	if r.Cap < 0 {
		return fmt.Errorf("path %q: cap must not be negative", normPath)
	}
	return nil
}

// normalizeHTTPPath validates and canonicalizes a URL path prefix starting with "/".
//
// # Parameters
//
//   - raw: Raw path string from a route or redirect rule.
//
// # Returns
//
// A cleaned absolute path starting with "/" (with trailing slashes removed
// except for "/"), or an error when empty, overly long, containing control or
// whitespace bytes, or not starting with "/".
//
// # Example
//
//	p, err := normalizeHTTPPath("/api/v1/")
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/routes.go:428 (direct call)
//   - internal/configfile/routes.go:787 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func normalizeHTTPPath(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("path must not be empty")
	}
	if len(raw) > maxRoutePathLen {
		return "", fmt.Errorf("path length %d exceeds max %d", len(raw), maxRoutePathLen)
	}
	if hasControlOrSpace(raw) {
		return "", errors.New("path must not contain whitespace or control characters")
	}
	if !strings.HasPrefix(raw, "/") {
		return "", errors.New("path must start with /")
	}
	if strings.ContainsAny(raw, "?#\\") {
		return "", errors.New("path must not contain query, fragment, or backslash")
	}
	cleaned := path.Clean(raw)
	if !strings.HasPrefix(cleaned, "/") {
		return "", errors.New("path must start with /")
	}
	return cleaned, nil
}

// validateUpstreamSpec validates a comma-separated list of Concert upstream
// targets matching Concert's site upstream rules: http://, https://, fcgi://,
// and fcgi+unix:///absolute/socket.sock.
//
// # Parameters
//
//   - spec: Raw comma-separated upstream target specification.
//
// # Returns
//
// The trimmed, normalized comma-separated upstream list, or a validation error.
//
// # Example
//
//	up, err := validateUpstreamSpec("http://127.0.0.1:4000,http://127.0.0.1:4001")
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/routes.go:439 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func validateUpstreamSpec(spec string) (string, error) {
	parts := strings.Split(spec, ",")
	out := make([]string, 0, len(parts))
	for _, raw := range parts {
		part := strings.TrimSpace(raw)
		if part == "" {
			continue
		}
		if hasControlOrSpace(part) {
			return "", fmt.Errorf("invalid upstream %q: must not contain whitespace or control characters", part)
		}
		u, err := url.Parse(part)
		if err != nil {
			return "", fmt.Errorf("invalid upstream %q: %w", part, err)
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https":
			if u.Host == "" {
				return "", fmt.Errorf("invalid upstream %q: must include host (e.g. http://127.0.0.1:3000)", part)
			}
		case "fcgi":
			if u.Host == "" {
				return "", fmt.Errorf("invalid upstream %q: fcgi:// requires host:port", part)
			}
		case "fcgi+unix":
			if u.Host != "" || !strings.HasPrefix(u.Path, "/") || len(u.Path) < 2 {
				return "", fmt.Errorf("invalid upstream %q: expected fcgi+unix:///absolute/socket.sock", part)
			}
		default:
			return "", fmt.Errorf("invalid upstream %q: must use http://, https://, fcgi://, or fcgi+unix://", part)
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return "", fmt.Errorf("invalid upstream %q: must not be empty", spec)
	}
	return strings.Join(out, ","), nil
}

// validateRateLimitSpec validates a `<count>/<duration>` (or `<count>/<duration>:<burst>`)
// rate limit specification without a leading path.
//
// # Parameters
//
//   - spec: Rate specification such as "100/1m", "20/s", or "60/1m:15".
//
// # Returns
//
// nil when spec is valid; otherwise a validation error.
//
// # Example
//
//	if err := validateRateLimitSpec("100/1m"); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/routes.go:448 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func validateRateLimitSpec(spec string) error {
	rateStr, winSpec, ok := strings.Cut(spec, "/")
	if !ok || rateStr == "" || winSpec == "" {
		return errors.New("expected <count>/<duration>")
	}
	rate, err := strconv.Atoi(strings.TrimSpace(rateStr))
	if err != nil || rate <= 0 {
		return fmt.Errorf("invalid count %q", rateStr)
	}
	winPart, burstPart, hasBurst := strings.Cut(winSpec, ":")
	if hasBurst {
		b, berr := strconv.Atoi(strings.TrimSpace(burstPart))
		if berr != nil || b <= 0 {
			return fmt.Errorf("invalid burst %q", burstPart)
		}
	}
	winPart = strings.TrimSpace(winPart)
	switch winPart {
	case "s", "m", "h":
		winPart = "1" + winPart
	}
	if d, derr := time.ParseDuration(winPart); derr != nil || d <= 0 {
		return fmt.Errorf("invalid duration %q", winPart)
	}
	return nil
}

// normalizeAndValidateHeader enforces RFC 7230 field-name token characters,
// CR/LF header-injection protection, value bounds, and the forbidden
// hop-by-hop/security-override denylist on a [HeaderRule] (S9).
//
// # Parameters
//
//   - h: HeaderRule to normalize and validate in place.
//
// # Returns
//
// nil when valid; otherwise a descriptive security or syntax validation error.
//
// # Example
//
//	if err := normalizeAndValidateHeader(&rule); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/routes.go:384 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func normalizeAndValidateHeader(h *HeaderRule) error {
	h.Action = HeaderAction(strings.ToLower(strings.TrimSpace(string(h.Action))))
	switch h.Action {
	case HeaderSet, HeaderAdd, HeaderRemove:
	default:
		return fmt.Errorf("invalid header action %q (expected set, add, or remove)", h.Action)
	}

	if h.Name == "" {
		return errors.New("header name must not be empty")
	}
	if len(h.Name) > maxHeaderNameLen {
		return fmt.Errorf("header name %q exceeds max length %d", h.Name, maxHeaderNameLen)
	}
	if !isRFC7230Token(h.Name) {
		return fmt.Errorf("header name %q contains invalid RFC 7230 token characters", h.Name)
	}
	if _, forbidden := forbiddenHeaders[strings.ToLower(h.Name)]; forbidden {
		return fmt.Errorf("header %q is forbidden (hop-by-hop or security-override header)", h.Name)
	}

	if h.Action == HeaderRemove {
		if h.Value != "" {
			return fmt.Errorf("header remove %q must not specify a value", h.Name)
		}
		return nil
	}

	if len(h.Value) > maxHeaderValueLen {
		return fmt.Errorf("header %q value exceeds max length %d", h.Name, maxHeaderValueLen)
	}
	if err := validateHeaderValue(h.Value); err != nil {
		return fmt.Errorf("header %q invalid value: %w", h.Name, err)
	}
	return nil
}

// isRFC7230Token reports whether s consists exclusively of RFC 7230 Section 3.2.6
// tchar bytes (`!#$%&'*+-.^_`|~`, digits, and ASCII letters).
//
// # Parameters
//
//   - s: Candidate HTTP header field-name.
//
// # Returns
//
// true when s is non-empty and every byte is a valid RFC 7230 tchar.
//
// # Example
//
//	ok := isRFC7230Token("X-Frame-Options")
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/routes.go:659 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func isRFC7230Token(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

// validateHeaderValue rejects CR, LF, NUL, and non-HTAB ASCII control characters
// in an HTTP response header value to prevent response-splitting injection (S9).
//
// # Parameters
//
//   - val: Candidate header value string.
//
// # Returns
//
// nil when val is safe; otherwise an error identifying the forbidden control byte.
//
// # Example
//
//	if err := validateHeaderValue("DENY"); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/routes.go:676 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func validateHeaderValue(val string) error {
	for i := range len(val) {
		b := val[i]
		if b == '\r' || b == '\n' {
			return errors.New("must not contain CR or LF characters")
		}
		if (b < 0x20 && b != '\t') || b == 0x7f {
			return fmt.Errorf("contains forbidden control byte 0x%02x", b)
		}
	}
	return nil
}

// normalizeAndValidateRedirect validates a [RedirectRule], defaulting Status to
// 302 when zero and rejecting unsafe schemes (javascript:, data:, protocol-relative
// //), CR/LF injection, unsupported status codes, and duplicate From paths (S9).
//
// # Parameters
//
//   - r: RedirectRule to normalize and validate in place.
//   - seen: Set of already-seen normalized From paths for the enclosing site.
//
// # Returns
//
// nil when valid; otherwise a descriptive validation error.
//
// # Example
//
//	if err := normalizeAndValidateRedirect(&rule, seen); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/routes.go:391 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func normalizeAndValidateRedirect(r *RedirectRule, seen map[string]struct{}) error {
	normFrom, err := normalizeHTTPPath(r.From)
	if err != nil {
		return fmt.Errorf("invalid from path %q: %w", r.From, err)
	}
	if _, dup := seen[normFrom]; dup {
		return fmt.Errorf("duplicate redirect from path %q", normFrom)
	}
	seen[normFrom] = struct{}{}
	r.From = normFrom

	if err := validateRedirectTarget(r.To); err != nil {
		return fmt.Errorf("from %q: invalid target %q: %w", normFrom, r.To, err)
	}

	if r.Status == 0 {
		r.Status = 302
	}
	switch r.Status {
	case 301, 302, 307, 308:
	default:
		return fmt.Errorf("from %q: unsupported redirect status %d (supported: 301, 302, 307, 308)", normFrom, r.Status)
	}
	return nil
}

// validateRedirectTarget enforces that a redirect destination is either a safe
// single-slash relative path ("/...") or an absolute http:// or https:// URL,
// rejecting javascript:/data: schemes, protocol-relative "//", and CR/LF (S9).
//
// # Parameters
//
//   - to: Candidate redirect target string.
//
// # Returns
//
// nil when valid; otherwise a validation error.
//
// # Example
//
//	if err := validateRedirectTarget("https://shop.example.com/sale"); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/routes.go:797 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func validateRedirectTarget(to string) error {
	if to == "" {
		return errors.New("target must not be empty")
	}
	if len(to) > maxRedirectURLLen {
		return fmt.Errorf("target length %d exceeds max %d", len(to), maxRedirectURLLen)
	}
	for i := range len(to) {
		b := to[i]
		if b == '\r' || b == '\n' {
			return errors.New("target must not contain CR or LF characters")
		}
		if b < 0x20 || b == 0x7f {
			return fmt.Errorf("target contains forbidden control byte 0x%02x", b)
		}
	}

	if strings.HasPrefix(to, "/") {
		// Reject protocol-relative open redirects ("//evil.com") and backslash variants ("/\evil.com").
		if strings.HasPrefix(to, "//") || strings.HasPrefix(to, `/\`) {
			return errors.New("relative target must not start with // or /\\")
		}
		return nil
	}

	u, err := url.Parse(to)
	if err != nil {
		return fmt.Errorf("malformed URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported scheme %q (must be relative /, http://, or https://)", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("absolute redirect URL must include host")
	}
	return nil
}

// validateDropSchedule validates optional drop_event_id, drop_lobby_at, and
// drop_open_at directives on a [SiteConfig], ensuring RFC 3339 timestamps and
// drop_open_at > drop_lobby_at whenever both timestamps are present.
//
// # Parameters
//
//   - s: SiteConfig whose drop schedule fields are validated.
//
// # Returns
//
// nil when valid; otherwise a validation error.
//
// # Example
//
//	if err := validateDropSchedule(site); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/routes.go:396 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func validateDropSchedule(s *SiteConfig) error {
	if s.DropEventID != "" {
		if strings.TrimSpace(s.DropEventID) == "" {
			return errors.New("drop_event_id must not be whitespace")
		}
		if len(s.DropEventID) > maxDropEventIDLen {
			return fmt.Errorf("drop_event_id length %d exceeds max %d", len(s.DropEventID), maxDropEventIDLen)
		}
		if hasControlChar(s.DropEventID) {
			return errors.New("drop_event_id must not contain control characters")
		}
	}

	var (
		lobbyAt  time.Time
		openAt   time.Time
		hasLobby bool
		hasOpen  bool
		err      error
	)
	if s.DropLobbyAt != "" {
		lobbyAt, err = time.Parse(time.RFC3339, s.DropLobbyAt)
		if err != nil {
			return fmt.Errorf("invalid drop_lobby_at %q (expected RFC3339): %w", s.DropLobbyAt, err)
		}
		hasLobby = true
	}
	if s.DropOpenAt != "" {
		openAt, err = time.Parse(time.RFC3339, s.DropOpenAt)
		if err != nil {
			return fmt.Errorf("invalid drop_open_at %q (expected RFC3339): %w", s.DropOpenAt, err)
		}
		hasOpen = true
	}
	if hasLobby && hasOpen && !openAt.After(lobbyAt) {
		return fmt.Errorf("drop_open_at (%s) must be strictly after drop_lobby_at (%s)", s.DropOpenAt, s.DropLobbyAt)
	}
	return nil
}

// hasControlOrSpace reports whether s contains any ASCII whitespace or control byte.
//
// # Parameters
//
//   - s: String to inspect byte-by-byte.
//
// # Returns
//
// true if any byte is <= 0x20 or == 0x7f.
//
// # Example
//
//	if hasControlOrSpace(rawPath) {
//		return errors.New("invalid path")
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/routes.go:491 (direct call)
//   - internal/configfile/routes.go:538 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func hasControlOrSpace(s string) bool {
	for i := range len(s) {
		b := s[i]
		if b <= 0x20 || b == 0x7f {
			return true
		}
	}
	return false
}

// hasControlChar reports whether s contains any ASCII control byte (< 0x20 or 0x7f).
//
// # Parameters
//
//   - s: String to inspect byte-by-byte.
//
// # Returns
//
// true if any byte is < 0x20 or == 0x7f.
//
// # Example
//
//	if hasControlChar(eventID) {
//		return errors.New("invalid event ID")
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/routes.go:909 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func hasControlChar(s string) bool {
	for i := range len(s) {
		b := s[i]
		if b < 0x20 || b == 0x7f {
			return true
		}
	}
	return false
}

// formatSiteExtensions emits Routes, Headers, Redirects, and drop schedule
// directives into b in canonical Concertfile syntax for round-trip formatting.
//
// # Parameters
//
//   - b: Destination string builder for the enclosing site block.
//   - s: SiteConfig whose extensions are formatted.
//   - quote: Quoting helper from FormatConcertfile.
//
// # Returns
//
// None. Writes formatted lines directly into b.
//
// # Example
//
//	formatSiteExtensions(&b, s, quote)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/configfile/configfile.go:1480 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func formatSiteExtensions(b *strings.Builder, s SiteConfig, quote func(string) string) {
	if s.DropEventID != "" {
		fmt.Fprintf(b, "    drop_event_id %s\n", quote(s.DropEventID))
	}
	if s.DropLobbyAt != "" {
		fmt.Fprintf(b, "    drop_lobby_at %s\n", quote(s.DropLobbyAt))
	}
	if s.DropOpenAt != "" {
		fmt.Fprintf(b, "    drop_open_at %s\n", quote(s.DropOpenAt))
	}
	for _, h := range s.Headers {
		if h.Action == HeaderRemove {
			fmt.Fprintf(b, "    header remove %s\n", quote(h.Name))
		} else {
			fmt.Fprintf(b, "    header %s %s %s\n", h.Action, quote(h.Name), quote(h.Value))
		}
	}
	for _, red := range s.Redirects {
		status := red.Status
		if status == 0 {
			status = 302
		}
		fmt.Fprintf(b, "    redirect %s %s %d\n", quote(red.From), quote(red.To), status)
	}
	for _, r := range s.Routes {
		fmt.Fprintf(b, "    route %s {\n", quote(r.Path))
		if r.Upstream != "" {
			fmt.Fprintf(b, "        upstream %s\n", quote(r.Upstream))
		}
		if r.StripPrefix {
			b.WriteString("        strip_prefix on\n")
		}
		if r.RateLimit != "" {
			fmt.Fprintf(b, "        rate_limit %s\n", quote(r.RateLimit))
		}
		if r.Bypass {
			b.WriteString("        bypass on\n")
		}
		if r.Cap > 0 {
			fmt.Fprintf(b, "        cap %d\n", r.Cap)
		}
		if r.AgentBidding {
			b.WriteString("        agent_bidding on\n")
		}
		b.WriteString("    }\n")
	}
}
