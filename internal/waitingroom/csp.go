package waitingroom

import (
	"net/url"
	"sort"
	"strings"
)

const youtubeNoCookieOrigin = "https://www.youtube-nocookie.com"

// ContentSecurityPolicy builds the strict Content-Security-Policy header value
// for the waiting room given cfg.
//
// All layouts enforce frame-src 'none' EXCEPT LayoutYouTube when
// cfg.YouTubeVideoID is a valid 11-character video ID, in which case frame-src
// narrowly permits https://www.youtube-nocookie.com only. Scripts remain
// strictly 'self' (no 'unsafe-inline'), plugins/objects are disabled, framing
// by third-party origins is blocked (frame-ancestors 'none'), and base URL
// hijacking is disabled (base-uri 'none').
//
// # Parameters
//
//   - cfg: Active waiting-room configuration. Invalid or unvalidated fields fail
//     closed (never widening frame-src or img-src).
//
// # Returns
//
// A deterministic Content-Security-Policy header string safe to emit on HTTP
// responses.
//
// # Concurrency
//
// Pure function; safe for unrestricted concurrent use.
//
// # Example
//
//	cfg := waitingroom.DefaultConfig()
//	csp := waitingroom.ContentSecurityPolicy(cfg)
//	fmt.Println(strings.Contains(csp, "frame-src 'none'")) // true
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/waitingroom_test.go:361 (direct call)
//   - internal/waitingroom/waitingroom_test.go:394 (direct call)
//   - internal/waitingroom/waitingroom_test.go:401 (direct call)
//   - internal/waitingroom/waitingroom_test.go:667 (direct call)
//   - internal/waitingroom/waitingroom_test.go:672 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func ContentSecurityPolicy(cfg Config) string {
	frameSrc := "'none'"
	if cfg.Layout == LayoutYouTube && IsValidYouTubeID(cfg.YouTubeVideoID) {
		frameSrc = youtubeNoCookieOrigin
	}

	imgOrigins := collectHTTPSOrigins(cfg.LogoURL, cfg.HeroImageURL)
	imgSrc := "'self' data:"
	if len(imgOrigins) > 0 {
		imgSrc += " " + strings.Join(imgOrigins, " ")
	}

	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self'",
		"connect-src 'self'",
		"img-src " + imgSrc,
		"frame-src " + frameSrc,
		"object-src 'none'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"form-action 'self'",
	}, "; ")
}

// collectHTTPSOrigins extracts unique, sorted "https://<host>" origins from
// validated HTTPS URLs while ignoring relative paths and invalid URLs.
//
// # Parameters
//
//   - rawURLs: Zero or more candidate URL strings.
//
// # Returns
//
// Deterministically sorted slice of "https://<host>" CSP source expressions.
//
// # Example
//
//	origins := collectHTTPSOrigins("https://cdn.example.com/logo.png", "/local.png")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/csp.go:58 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func collectHTTPSOrigins(rawURLs ...string) []string {
	seen := make(map[string]struct{}, len(rawURLs))
	for _, raw := range rawURLs {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "/") {
			continue
		}
		if err := ValidateSafeURL(raw); err != nil {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
			continue
		}
		origin := "https://" + strings.ToLower(u.Host)
		seen[origin] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for origin := range seen {
		out = append(out, origin)
	}
	sort.Strings(out)
	return out
}
