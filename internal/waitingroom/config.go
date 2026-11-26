// Package waitingroom implements Concert's Waiting Room Studio configuration
// store, strict input validation, YouTube video ID parsing, EWMA queue ETA
// estimation, dynamic Content-Security-Policy generation, and safe HTML
// rendering with zero external dependencies.
package waitingroom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/andreimerlescu/concert/internal/i18n"
)

const (
	// LayoutDefault renders Concert's two-column editorial waiting room with scene.
	LayoutDefault = "default"
	// LayoutYouTube renders the widescreen YouTube Cinema stage alongside queue status.
	LayoutYouTube = "youtube"
	// LayoutDropCountdown renders a centered high-energy launch/drop waiting room.
	LayoutDropCountdown = "drop-countdown"
	// LayoutMinimalBrand renders a minimal single-column branded queue card.
	LayoutMinimalBrand = "minimal-brand"
	// LayoutSplitStage renders a balanced 50/50 brand stage and queue split layout.
	LayoutSplitStage = "split-stage"

	// ThemeSystem follows the visitor's prefers-color-scheme preference.
	ThemeSystem = "system"
	// ThemePaper matches Concert Portal's warm light Paper WCAG palette.
	ThemePaper = "paper"
	// ThemeSynthwave84 matches Concert Portal's SynthWave '84 dark palette.
	ThemeSynthwave84 = "synthwave84"
	// ThemeSolarizedLight matches Concert Portal's Solarized Light palette.
	ThemeSolarizedLight = "solarized-light"
	// ThemeSolarizedDark matches Concert Portal's Solarized Dark palette.
	ThemeSolarizedDark = "solarized-dark"
	// ThemeNord matches Concert Portal's Nord palette.
	ThemeNord = "nord"
	// ThemeDracula matches Concert Portal's Dracula palette.
	ThemeDracula = "dracula"
	// ThemeGruvboxDark matches Concert Portal's Gruvbox Dark palette.
	ThemeGruvboxDark = "gruvbox-dark"
	// ThemeGitHubLight matches Concert Portal's GitHub Light palette.
	ThemeGitHubLight = "github-light"
	// ThemeGitHubDark matches Concert Portal's GitHub Dark palette.
	ThemeGitHubDark = "github-dark"
	// ThemeHighContrast matches Concert Portal's WCAG AAA High Contrast palette.
	ThemeHighContrast = "high-contrast"

	// MaxBroadcastRunes bounds operator broadcast message length.
	MaxBroadcastRunes = 280
	// MaxBrandNameRunes bounds operator brand name length.
	MaxBrandNameRunes = 120
	// MaxHeadlineRunes bounds operator headline length.
	MaxHeadlineRunes = 200
	// MaxSubheadlineRunes bounds operator subheadline length.
	MaxSubheadlineRunes = 500
	// maxURLBytes bounds LogoURL and HeroImageURL lengths (R3).
	maxURLBytes = 2048
	// maxConfigFileBytes bounds waitingroom.json reads on startup (R3).
	maxConfigFileBytes = 1 << 20
)

var (
	// ErrInvalidLayout indicates an unsupported waiting-room layout identifier.
	ErrInvalidLayout = errors.New("waitingroom: invalid layout")
	// ErrInvalidTheme indicates an unsupported waiting-room theme identifier.
	ErrInvalidTheme = errors.New("waitingroom: invalid theme")
	// ErrInvalidURL indicates a malformed or disallowed LogoURL or HeroImageURL.
	ErrInvalidURL = errors.New("waitingroom: invalid url")
	// ErrInvalidAccentColor indicates an accent color that does not match #RRGGBB.
	ErrInvalidAccentColor = errors.New("waitingroom: invalid accent color")
	// ErrInvalidYouTubeID indicates an invalid YouTube URL or 11-character video ID.
	ErrInvalidYouTubeID = errors.New("waitingroom: invalid youtube video id")
	// ErrInvalidLocale indicates a DefaultLocale unsupported by package i18n.
	ErrInvalidLocale = errors.New("waitingroom: invalid default locale")
	// ErrBroadcastTooLong indicates a broadcast message exceeding MaxBroadcastRunes.
	ErrBroadcastTooLong = errors.New("waitingroom: broadcast message too long")
	// ErrFieldTooLong indicates a text field exceeding its configured rune budget.
	ErrFieldTooLong = errors.New("waitingroom: text field too long")
	// ErrConfigTooLarge indicates a persisted waitingroom.json file exceeding 1 MiB.
	ErrConfigTooLarge = errors.New("waitingroom: config file exceeds maximum size")
	// ErrEmptyStorePath indicates NewStore was called with an empty filesystem path.
	ErrEmptyStorePath = errors.New("waitingroom: store path must not be empty")
)

var (
	accentColorPattern = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)
	youtubeIDPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{11}$`)

	validLayouts = []string{
		LayoutDefault,
		LayoutYouTube,
		LayoutDropCountdown,
		LayoutMinimalBrand,
		LayoutSplitStage,
	}

	validThemes = []string{
		ThemeSystem,
		ThemePaper,
		ThemeSynthwave84,
		ThemeSolarizedLight,
		ThemeSolarizedDark,
		ThemeNord,
		ThemeDracula,
		ThemeGruvboxDark,
		ThemeGitHubLight,
		ThemeGitHubDark,
		ThemeHighContrast,
	}

	validLayoutSet = map[string]struct{}{
		LayoutDefault:       {},
		LayoutYouTube:       {},
		LayoutDropCountdown: {},
		LayoutMinimalBrand:  {},
		LayoutSplitStage:    {},
	}

	validThemeSet = map[string]struct{}{
		ThemeSystem:         {},
		ThemePaper:          {},
		ThemeSynthwave84:    {},
		ThemeSolarizedLight: {},
		ThemeSolarizedDark:  {},
		ThemeNord:           {},
		ThemeDracula:        {},
		ThemeGruvboxDark:    {},
		ThemeGitHubLight:    {},
		ThemeGitHubDark:     {},
		ThemeHighContrast:   {},
	}
)

// Broadcast holds an operator's live waiting-room announcement message and the
// UTC timestamp of its last update.
type Broadcast struct {
	// Message is the plain-text operator announcement (at most 280 runes).
	Message string `json:"message"`
	// UpdatedAt records when Message was last updated in UTC.
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// Config holds the full operator-configurable Waiting Room Studio settings.
// All fields are pure value types so Config values may be copied safely across
// goroutines without aliasing mutable state.
type Config struct {
	// Layout selects the waiting-room visual layout (one of ValidLayouts).
	Layout string `json:"layout"`
	// Theme selects the WCAG palette ("system" or one of the 10 Portal themes).
	Theme string `json:"theme"`
	// BrandName is the operator's site or event display name.
	BrandName string `json:"brand_name"`
	// LogoURL is an optional validated relative ("/") or HTTPS URL for the brand mark.
	LogoURL string `json:"logo_url"`
	// AccentColor is an optional "#RRGGBB" hex accent override.
	AccentColor string `json:"accent_color"`
	// Headline is an optional custom waiting-room heading overriding the localized default.
	Headline string `json:"headline"`
	// Subheadline is an optional custom lead paragraph overriding the localized default.
	Subheadline string `json:"subheadline"`
	// HeroImageURL is an optional validated relative ("/") or HTTPS URL for hero artwork.
	HeroImageURL string `json:"hero_image_url"`
	// YouTubeVideoID is an optional strict 11-character YouTube video ID used by LayoutYouTube.
	YouTubeVideoID string `json:"youtube_video_id"`
	// DefaultLocale is the fallback locale validated against package i18n.
	DefaultLocale string `json:"default_locale"`
	// Broadcast carries an optional live operator announcement shown on the waiting room page.
	Broadcast Broadcast `json:"broadcast"`
}

// Store persists and serves a validated waiting-room Config backed by an atomic
// 0600 JSON file on disk. All exported methods on Store are safe for concurrent
// use by multiple goroutines.
type Store struct {
	path string

	// mu guards cfg and serializes atomic on-disk replacements so concurrent
	// Save and UpdateBroadcast calls cannot reorder or lose updates.
	mu  sync.RWMutex
	cfg Config
}

// ValidLayouts returns a fresh slice containing all 5 supported waiting-room
// layout identifiers in canonical order.
//
// # Parameters
//
// None.
//
// # Returns
//
// A newly allocated []string that the caller may modify freely.
//
// # Example
//
//	layouts := waitingroom.ValidLayouts()
//	fmt.Println(len(layouts)) // 5
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/waitingroom_test.go:160 (direct call)
//   - internal/waitingroom/waitingroom_test.go:290 (direct call)
//   - internal/waitingroom/waitingroom_test.go:357 (direct call)
//   - internal/waitingroom/waitingroom_test.go:608 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func ValidLayouts() []string {
	out := make([]string, len(validLayouts))
	copy(out, validLayouts)
	return out
}

// ValidThemes returns a fresh slice containing "system" plus all 10 exact
// Concert Portal WCAG theme identifiers in canonical order.
//
// # Parameters
//
// None.
//
// # Returns
//
// A newly allocated []string that the caller may modify freely.
//
// # Example
//
//	themes := waitingroom.ValidThemes()
//	fmt.Println(len(themes)) // 11
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/waitingroom_test.go:161 (direct call)
//   - internal/waitingroom/waitingroom_test.go:291 (direct call)
//   - internal/waitingroom/waitingroom_test.go:609 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func ValidThemes() []string {
	out := make([]string, len(validThemes))
	copy(out, validThemes)
	return out
}

// DefaultConfig returns a valid baseline waiting-room configuration using the
// default layout, system theme, "Concert" brand name, and English default locale.
//
// # Parameters
//
// None.
//
// # Returns
//
// A valid Config value safe to pass directly to Store.Save or RenderHTML.
//
// # Example
//
//	cfg := waitingroom.DefaultConfig()
//	fmt.Println(cfg.Layout, cfg.Theme, cfg.DefaultLocale)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/config.go:688 (direct call)
//   - internal/waitingroom/waitingroom_test.go:43 (direct call)
//   - internal/waitingroom/waitingroom_test.go:44 (direct call)
//   - internal/waitingroom/waitingroom_test.go:169 (direct call)
//   - internal/waitingroom/waitingroom_test.go:300 (direct call)
//   - internal/waitingroom/waitingroom_test.go:329 (direct call)
//   - internal/waitingroom/waitingroom_test.go:358 (direct call)
//   - internal/waitingroom/waitingroom_test.go:392 (direct call)
//   - internal/waitingroom/waitingroom_test.go:399 (direct call)
//   - internal/waitingroom/waitingroom_test.go:580 (direct call)
//   - internal/waitingroom/waitingroom_test.go:594 (direct call)
//   - internal/waitingroom/waitingroom_test.go:610 (direct call)
//   - internal/waitingroom/waitingroom_test.go:666 (direct call)
//   - internal/waitingroom/waitingroom_test.go:669 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func DefaultConfig() Config {
	return Config{
		Layout:        LayoutDefault,
		Theme:         ThemeSystem,
		BrandName:     "Concert",
		DefaultLocale: i18n.DefaultLocale,
	}
}

// IsValidYouTubeID reports whether id strictly matches the 11-character YouTube
// video identifier grammar ^[A-Za-z0-9_-]{11}$.
//
// # Parameters
//
//   - id: Candidate YouTube video ID string.
//
// # Returns
//
// true if and only if id is an exact 11-character ASCII YouTube video ID.
//
// # Example
//
//	fmt.Println(waitingroom.IsValidYouTubeID("dQw4w9WgXcQ")) // true
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/csp.go:54 (direct call)
//   - internal/waitingroom/render.go:560 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func IsValidYouTubeID(id string) bool {
	return youtubeIDPattern.MatchString(id)
}

// ParseYouTubeID extracts and strictly validates an 11-character YouTube video
// ID from a bare ID or a supported YouTube URL shape:
//   - https://youtube.com/watch?v=<id> (also www., m., music.)
//   - https://youtu.be/<id>
//   - https://youtube.com/live/<id>
//   - https://youtube.com/embed/<id>
//   - https://youtube.com/shorts/<id>
//   - https://youtube-nocookie.com/embed/<id> (also www.)
//   - bare 11-character ID matching ^[A-Za-z0-9_-]{11}$
//
// Disallowed schemes, non-YouTube hosts, URL userinfo, control characters, and
// malformed IDs are rejected with ErrInvalidYouTubeID.
//
// # Parameters
//
//   - input: Operator-supplied YouTube URL or bare 11-character video ID.
//
// # Returns
//
// The validated 11-character video ID and nil error on success, or ("", err)
// wrapping ErrInvalidYouTubeID on failure.
//
// # Example
//
//	id, err := waitingroom.ParseYouTubeID("https://youtu.be/dQw4w9WgXcQ")
//	if err != nil {
//		return err
//	}
//	fmt.Println(id) // dQw4w9WgXcQ
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/config.go:553 (direct call)
//   - internal/waitingroom/waitingroom_test.go:237 (direct call)
//   - internal/waitingroom/waitingroom_test.go:264 (direct call)
//   - internal/waitingroom/waitingroom_test.go:642 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func ParseYouTubeID(input string) (string, error) {
	if hasControlChars(input) {
		return "", ErrInvalidYouTubeID
	}
	raw := strings.TrimSpace(input)
	if raw == "" || len(raw) > maxURLBytes {
		return "", ErrInvalidYouTubeID
	}

	if youtubeIDPattern.MatchString(raw) {
		return raw, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", ErrInvalidYouTubeID
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", ErrInvalidYouTubeID
	}
	if u.User != nil || u.Host == "" {
		return "", ErrInvalidYouTubeID
	}

	host := strings.ToLower(u.Hostname())
	var candidate string
	switch host {
	case "youtu.be", "www.youtu.be":
		segs := splitPathSegments(u.Path)
		if len(segs) == 1 {
			candidate = segs[0]
		}
	case "youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com":
		segs := splitPathSegments(u.Path)
		switch {
		case len(segs) == 1 && segs[0] == "watch":
			candidate = u.Query().Get("v")
		case len(segs) == 2 && (segs[0] == "live" || segs[0] == "embed" || segs[0] == "shorts"):
			candidate = segs[1]
		}
	case "youtube-nocookie.com", "www.youtube-nocookie.com":
		segs := splitPathSegments(u.Path)
		if len(segs) == 2 && segs[0] == "embed" {
			candidate = segs[1]
		}
	default:
		return "", ErrInvalidYouTubeID
	}

	if !youtubeIDPattern.MatchString(candidate) {
		return "", ErrInvalidYouTubeID
	}
	return candidate, nil
}

// ValidateSafeURL validates that raw is either empty, a root-relative path
// beginning with a single "/" (rejecting protocol-relative "//" URLs), or an
// HTTPS URL without userinfo, backslashes, whitespace, or control characters.
// Schemes such as javascript:, data:, vbscript:, file:, and http: are rejected.
//
// # Parameters
//
//   - raw: Optional URL string (for example LogoURL or HeroImageURL).
//
// # Returns
//
// nil when raw is empty or satisfies the strict allowlist; otherwise an error
// matching ErrInvalidURL via errors.Is.
//
// # Example
//
//	if err := waitingroom.ValidateSafeURL("https://cdn.example.com/logo.png"); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/config.go:611 (direct call)
//   - internal/waitingroom/config.go:614 (direct call)
//   - internal/waitingroom/csp.go:107 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func ValidateSafeURL(raw string) error {
	if raw == "" {
		return nil
	}
	if len(raw) > maxURLBytes || hasControlChars(raw) || strings.ContainsAny(raw, " \t\\") {
		return fmt.Errorf("%w: disallowed characters or length", ErrInvalidURL)
	}
	if strings.HasPrefix(raw, "/") {
		// Reject protocol-relative URLs such as "//evil.example/a.png".
		if strings.HasPrefix(raw, "//") {
			return fmt.Errorf("%w: protocol-relative url rejected", ErrInvalidURL)
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
			return fmt.Errorf("%w: malformed relative path", ErrInvalidURL)
		}
		return nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%w: scheme must be https or relative /", ErrInvalidURL)
	}
	if u.User != nil {
		return fmt.Errorf("%w: url userinfo rejected", ErrInvalidURL)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("%w: missing host", ErrInvalidURL)
	}
	return nil
}

// Normalized trims fields, fills empty Layout, Theme, and DefaultLocale with
// defaults, extracts a canonical 11-character YouTubeVideoID when a full YouTube
// URL is provided, normalizes Broadcast.UpdatedAt to UTC, and validates the
// resulting Config.
//
// # Parameters
//
//   - c (receiver): Candidate Config value. The receiver is passed by value and
//     not mutated in place.
//
// # Returns
//
// The normalized, validated Config and nil error on success, or the zero Config
// and a descriptive error wrapping one of the package sentinel errors on failure.
//
// # Example
//
//	cfg, err := (waitingroom.Config{
//		Layout:         waitingroom.LayoutYouTube,
//		YouTubeVideoID: "https://youtu.be/dQw4w9WgXcQ",
//	}).Normalized()
//	if err != nil {
//		return err
//	}
//	fmt.Println(cfg.YouTubeVideoID) // dQw4w9WgXcQ
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/config.go:718 (direct call)
//   - internal/waitingroom/config.go:801 (direct call)
//   - internal/waitingroom/config.go:870 (direct call)
//   - internal/waitingroom/render.go:107 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func (c Config) Normalized() (Config, error) {
	out := c
	out.Layout = strings.TrimSpace(out.Layout)
	if out.Layout == "" {
		out.Layout = LayoutDefault
	}
	out.Theme = strings.TrimSpace(out.Theme)
	if out.Theme == "" {
		out.Theme = ThemeSystem
	}
	out.DefaultLocale = strings.TrimSpace(out.DefaultLocale)
	if out.DefaultLocale == "" {
		out.DefaultLocale = i18n.DefaultLocale
	} else if i18n.IsSupported(out.DefaultLocale) {
		out.DefaultLocale = i18n.Negotiate(out.DefaultLocale, "", "", i18n.DefaultLocale)
	}

	out.BrandName = strings.TrimSpace(out.BrandName)
	out.LogoURL = strings.TrimSpace(out.LogoURL)
	out.AccentColor = strings.TrimSpace(out.AccentColor)
	out.Headline = strings.TrimSpace(out.Headline)
	out.Subheadline = strings.TrimSpace(out.Subheadline)
	out.HeroImageURL = strings.TrimSpace(out.HeroImageURL)
	out.YouTubeVideoID = strings.TrimSpace(out.YouTubeVideoID)
	out.Broadcast.Message = strings.TrimSpace(out.Broadcast.Message)

	if out.YouTubeVideoID != "" {
		id, err := ParseYouTubeID(out.YouTubeVideoID)
		if err != nil {
			return Config{}, err
		}
		out.YouTubeVideoID = id
	}

	if !out.Broadcast.UpdatedAt.IsZero() {
		out.Broadcast.UpdatedAt = out.Broadcast.UpdatedAt.UTC()
	}

	if err := out.Validate(); err != nil {
		return Config{}, err
	}
	return out, nil
}

// Validate checks every field of c against strict allowlists and rune bounds
// without mutating c.
//
// # Parameters
//
//   - c (receiver): Config value to validate.
//
// # Returns
//
// nil when every field is valid; otherwise an error wrapping the corresponding
// package sentinel error (for example ErrInvalidLayout, ErrInvalidTheme,
// ErrInvalidURL, ErrInvalidAccentColor, ErrInvalidYouTubeID, ErrInvalidLocale,
// ErrBroadcastTooLong, or ErrFieldTooLong).
//
// # Example
//
//	if err := waitingroom.DefaultConfig().Validate(); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/config.go:564 (direct call)
//   - internal/waitingroom/waitingroom_test.go:184 (direct call)
//   - internal/waitingroom/waitingroom_test.go:198 (direct call)
//   - internal/waitingroom/waitingroom_test.go:303 (direct call)
//   - internal/waitingroom/waitingroom_test.go:331 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func (c Config) Validate() error {
	if _, ok := validLayoutSet[c.Layout]; !ok {
		return fmt.Errorf("%w: %q", ErrInvalidLayout, c.Layout)
	}
	if _, ok := validThemeSet[c.Theme]; !ok {
		return fmt.Errorf("%w: %q", ErrInvalidTheme, c.Theme)
	}
	if !i18n.IsSupported(c.DefaultLocale) {
		return fmt.Errorf("%w: %q", ErrInvalidLocale, c.DefaultLocale)
	}
	if err := ValidateSafeURL(c.LogoURL); err != nil {
		return fmt.Errorf("logo_url: %w", err)
	}
	if err := ValidateSafeURL(c.HeroImageURL); err != nil {
		return fmt.Errorf("hero_image_url: %w", err)
	}
	if c.AccentColor != "" && !accentColorPattern.MatchString(c.AccentColor) {
		return fmt.Errorf("%w: %q", ErrInvalidAccentColor, c.AccentColor)
	}
	if c.YouTubeVideoID != "" && !youtubeIDPattern.MatchString(c.YouTubeVideoID) {
		return fmt.Errorf("%w: %q", ErrInvalidYouTubeID, c.YouTubeVideoID)
	}
	if utf8.RuneCountInString(c.BrandName) > MaxBrandNameRunes {
		return fmt.Errorf("%w: brand_name exceeds %d characters", ErrFieldTooLong, MaxBrandNameRunes)
	}
	if utf8.RuneCountInString(c.Headline) > MaxHeadlineRunes {
		return fmt.Errorf("%w: headline exceeds %d characters", ErrFieldTooLong, MaxHeadlineRunes)
	}
	if utf8.RuneCountInString(c.Subheadline) > MaxSubheadlineRunes {
		return fmt.Errorf("%w: subheadline exceeds %d characters", ErrFieldTooLong, MaxSubheadlineRunes)
	}
	if utf8.RuneCountInString(c.Broadcast.Message) > MaxBroadcastRunes {
		return fmt.Errorf("%w: %d > %d", ErrBroadcastTooLong, utf8.RuneCountInString(c.Broadcast.Message), MaxBroadcastRunes)
	}
	if hasControlChars(c.BrandName) || hasControlChars(c.Headline) || hasControlChars(c.Subheadline) || hasControlChars(c.Broadcast.Message) {
		return fmt.Errorf("%w: control characters not allowed", ErrFieldTooLong)
	}
	return nil
}

// NewStore opens or initializes a waiting-room configuration store at path.
// If path does not exist, Store initializes in memory with DefaultConfig without
// writing to disk until Save or UpdateBroadcast is called. If path exists, its
// contents (bounded to 1 MiB) are decoded, normalized, and validated.
//
// # Parameters
//
//   - path: Filesystem path to waitingroom.json; must be non-empty.
//
// # Returns
//
// A ready *Store and nil error on success, or (nil, err) when path is empty,
// unreadable, exceeds 1 MiB, contains malformed JSON, or fails validation.
//
// # Concurrency
//
// The returned *Store is safe for concurrent use by multiple goroutines.
//
// # Example
//
//	store, err := waitingroom.NewStore(filepath.Join(dir, "waitingroom.json"))
//	if err != nil {
//		return err
//	}
//	cfg := store.Get()
//	fmt.Println(cfg.Layout)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/waitingroom_test.go:39 (direct call)
//   - internal/waitingroom/waitingroom_test.go:85 (direct call)
//   - internal/waitingroom/waitingroom_test.go:125 (direct call)
//   - internal/waitingroom/waitingroom_test.go:132 (direct call)
//   - internal/waitingroom/waitingroom_test.go:155 (direct call)
//   - internal/waitingroom/waitingroom_test.go:194 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func NewStore(path string) (*Store, error) {
	cleaned := strings.TrimSpace(path)
	if cleaned == "" {
		return nil, ErrEmptyStorePath
	}

	s := &Store{
		path: cleaned,
		cfg:  DefaultConfig(),
	}

	f, err := os.Open(cleaned)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, fmt.Errorf("open waitingroom config %q: %w", cleaned, err)
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, maxConfigFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read waitingroom config %q: %w", cleaned, err)
	}
	if len(raw) > maxConfigFileBytes {
		return nil, ErrConfigTooLarge
	}

	var decoded Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decode waitingroom config %q: %w", cleaned, err)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode waitingroom config %q: trailing data", cleaned)
	}

	norm, err := decoded.Normalized()
	if err != nil {
		return nil, fmt.Errorf("validate waitingroom config %q: %w", cleaned, err)
	}
	s.cfg = norm
	return s, nil
}

// Get returns an independent snapshot copy of the current waiting-room Config.
//
// # Parameters
//
//   - s (receiver): Non-nil *Store constructed by NewStore.
//
// # Returns
//
// A copy of the active Config value.
//
// # Concurrency
//
// Safe for concurrent use by multiple goroutines.
//
// # Example
//
//	cfg := store.Get()
//	fmt.Println(cfg.Theme)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/config.go:407 (direct call)
//   - internal/waitingroom/waitingroom_test.go:43 (direct call)
//   - internal/waitingroom/waitingroom_test.go:89 (direct call)
//   - internal/waitingroom/waitingroom_test.go:103 (direct call)
//   - internal/waitingroom/waitingroom_test.go:104 (direct call)
//   - internal/waitingroom/waitingroom_test.go:183 (direct call)
//   - internal/waitingroom/waitingroom_test.go:198 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Save normalizes, validates, and atomically persists cfg to disk with 0600
// permissions (CreateTemp + Chmod(0600) + Write + Sync + Close + Rename).
// If validation or any I/O step fails, the previously persisted file and
// in-memory configuration remain unchanged.
//
// # Parameters
//
//   - s (receiver): Non-nil *Store constructed by NewStore.
//   - cfg: Candidate waiting-room configuration to persist.
//
// # Returns
//
// nil on success, or an error describing the validation or persistence failure.
//
// # Concurrency
//
// Safe for concurrent use by multiple goroutines; writers are serialized under s.mu.
//
// # Example
//
//	cfg := waitingroom.DefaultConfig()
//	cfg.Layout = waitingroom.LayoutYouTube
//	cfg.YouTubeVideoID = "dQw4w9WgXcQ"
//	if err := store.Save(cfg); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/waitingroom_test.go:64 (direct call)
//   - internal/waitingroom/waitingroom_test.go:100 (direct call)
//   - internal/waitingroom/waitingroom_test.go:173 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func (s *Store) Save(cfg Config) error {
	norm, err := cfg.Normalized()
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := writeAtomicJSON(s.path, norm); err != nil {
		return err
	}
	s.cfg = norm
	return nil
}

// UpdateBroadcast atomically updates the live broadcast message and timestamp,
// persists the updated configuration to disk with 0600 permissions, and returns
// the resulting Config snapshot. Passing an empty message clears the broadcast
// and zeroes UpdatedAt.
//
// # Parameters
//
//   - s (receiver): Non-nil *Store constructed by NewStore.
//   - message: Plain-text broadcast message (at most 280 runes), or "" to clear.
//   - now: Update timestamp; when zero and message is non-empty, time.Now().UTC() is used.
//
// # Returns
//
// The persisted Config snapshot and nil error on success, or the zero Config and
// an error if validation or atomic persistence fails.
//
// # Concurrency
//
// Safe for concurrent use by multiple goroutines.
//
// # Example
//
//	cfg, err := store.UpdateBroadcast("Doors open in 2 minutes!", time.Now().UTC())
//	if err != nil {
//		return err
//	}
//	fmt.Println(cfg.Broadcast.Message)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/waitingroom_test.go:109 (direct call)
//   - internal/waitingroom/waitingroom_test.go:116 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func (s *Store) UpdateBroadcast(message string, now time.Time) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cfg
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		next.Broadcast = Broadcast{}
	} else {
		if now.IsZero() {
			now = time.Now().UTC()
		}
		next.Broadcast = Broadcast{
			Message:   trimmed,
			UpdatedAt: now.UTC(),
		}
	}

	norm, err := next.Normalized()
	if err != nil {
		return Config{}, err
	}
	if err := writeAtomicJSON(s.path, norm); err != nil {
		return Config{}, err
	}
	s.cfg = norm
	return norm, nil
}

// writeAtomicJSON marshals cfg to formatted JSON and replaces target atomically
// via a sibling temp file created with 0600 permissions, synced, closed, and
// renamed into place.
//
// # Parameters
//
//   - target: Destination file path.
//   - cfg: Validated Config to serialize.
//
// # Returns
//
// nil on durable replacement; otherwise the I/O error with any partial temp file
// removed on failure.
//
// # Example
//
//	if err := writeAtomicJSON(path, cfg); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/config.go:809 (direct call)
//   - internal/waitingroom/config.go:874 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func writeAtomicJSON(target string, cfg Config) error {
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal waitingroom config: %w", err)
	}
	payload = append(payload, '\n')

	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir %q: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".waitingroom-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp waitingroom config: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	// Enforce 0600 explicitly before writing payload so permissions never depend
	// solely on the process umask.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp waitingroom config: %w", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp waitingroom config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp waitingroom config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp waitingroom config: %w", err)
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return fmt.Errorf("rename waitingroom config: %w", err)
	}
	cleanup = false
	return nil
}

// splitPathSegments trims leading and trailing slashes from p and splits it
// into non-empty slash-delimited segments.
//
// # Parameters
//
//   - p: URL path component.
//
// # Returns
//
// Slice of path segments, or nil when p contains no non-empty segments.
//
// # Example
//
//	segs := splitPathSegments("/embed/dQw4w9WgXcQ/") // []string{"embed", "dQw4w9WgXcQ"}
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/config.go:399 (direct call)
//   - internal/waitingroom/config.go:404 (direct call)
//   - internal/waitingroom/config.go:412 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func splitPathSegments(p string) []string {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// hasControlChars reports whether s contains any ASCII control byte (< 0x20 or 0x7f).
//
// # Parameters
//
//   - s: Input string to inspect.
//
// # Returns
//
// true when any ASCII control byte is present; false otherwise.
//
// # Example
//
//	fmt.Println(hasControlChars("hello\r\n")) // true
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/config.go:371 (direct call)
//   - internal/waitingroom/config.go:459 (direct call)
//   - internal/waitingroom/config.go:635 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func hasControlChars(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
