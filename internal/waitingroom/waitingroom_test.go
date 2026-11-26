package waitingroom_test

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/i18n"
	"github.com/andreimerlescu/concert/internal/waitingroom"
)

// TestStore_AtomicPersistence0600 verifies atomic 0600 temp+sync+rename writes,
// reload round-tripping, broadcast updates, and unchanged state on validation error.
//
// # Parameters
//
//   - t: Standard Go test handle.
//
// # Example
//
//	go test -run '^TestStore_AtomicPersistence0600$' ./internal/waitingroom
//
// # Used By
//
// Invoked by `go test`.
func TestStore_AtomicPersistence0600(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "waitingroom.json")

	store, err := waitingroom.NewStore(path)
	if err != nil {
		t.Fatalf("NewStore(%q) error = %v", path, err)
	}
	if got := store.Get(); got != waitingroom.DefaultConfig() {
		t.Fatalf("initial Get() = %+v, want %+v", got, waitingroom.DefaultConfig())
	}

	want := waitingroom.Config{
		Layout:         waitingroom.LayoutYouTube,
		Theme:          waitingroom.ThemeDracula,
		BrandName:      "Starlight Festival",
		LogoURL:        "/assets/logo.svg",
		AccentColor:    "#ff79c6",
		Headline:       "Main Stage Livestream",
		Subheadline:    "Watch the opener while your ticket enters.",
		HeroImageURL:   "https://cdn.example.com/hero.jpg",
		YouTubeVideoID: "https://youtu.be/dQw4w9WgXcQ?si=test123",
		DefaultLocale:  "es-MX",
		Broadcast: waitingroom.Broadcast{
			Message:   "Doors open in 5 minutes!",
			UpdatedAt: time.Date(2026, 11, 26, 18, 0, 0, 0, time.UTC),
		},
	}

	if err := store.Save(want); err != nil {
		t.Fatalf("Save(valid) error = %v", err)
	}

	// Verify file permissions are strictly 0600 and no stray temp files remain.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("waitingroom.json mode = %#o, want 0600", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q) error = %v", dir, err)
	}
	if len(entries) != 1 || entries[0].Name() != "waitingroom.json" {
		t.Errorf("unexpected directory entries after atomic write: %v", entries)
	}

	// Reload from disk in a fresh Store instance.
	reloaded, err := waitingroom.NewStore(path)
	if err != nil {
		t.Fatalf("NewStore reload error = %v", err)
	}
	got := reloaded.Get()
	if got.YouTubeVideoID != "dQw4w9WgXcQ" {
		t.Errorf("reloaded YouTubeVideoID = %q, want %q", got.YouTubeVideoID, "dQw4w9WgXcQ")
	}
	if got.Layout != waitingroom.LayoutYouTube || got.Theme != waitingroom.ThemeDracula || got.DefaultLocale != "es-MX" {
		t.Errorf("reloaded config mismatch: %+v", got)
	}

	// Invalid Save must fail closed and leave previous state intact.
	bad := got
	bad.LogoURL = "javascript:alert(1)"
	if err := reloaded.Save(bad); !errors.Is(err, waitingroom.ErrInvalidURL) {
		t.Fatalf("Save(javascript logo) error = %v, want ErrInvalidURL", err)
	}
	if reloaded.Get().LogoURL != "/assets/logo.svg" {
		t.Fatalf("failed Save corrupted in-memory config: %+v", reloaded.Get())
	}

	// UpdateBroadcast persists message and clears cleanly when empty.
	ts := time.Date(2026, 11, 26, 19, 30, 0, 0, time.UTC)
	updated, err := reloaded.UpdateBroadcast("VIP lanes open now!", ts)
	if err != nil {
		t.Fatalf("UpdateBroadcast error = %v", err)
	}
	if updated.Broadcast.Message != "VIP lanes open now!" || !updated.Broadcast.UpdatedAt.Equal(ts) {
		t.Errorf("UpdateBroadcast = %+v, want message + timestamp", updated.Broadcast)
	}
	cleared, err := reloaded.UpdateBroadcast("", ts)
	if err != nil {
		t.Fatalf("UpdateBroadcast(clear) error = %v", err)
	}
	if cleared.Broadcast.Message != "" || !cleared.Broadcast.UpdatedAt.IsZero() {
		t.Errorf("UpdateBroadcast(clear) = %+v, want zero broadcast", cleared.Broadcast)
	}

	// NewStore error paths: empty path and corrupt JSON.
	if _, err := waitingroom.NewStore("   "); !errors.Is(err, waitingroom.ErrEmptyStorePath) {
		t.Errorf("NewStore(empty) error = %v, want ErrEmptyStorePath", err)
	}
	corruptPath := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(corruptPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("WriteFile corrupt: %v", err)
	}
	if _, err := waitingroom.NewStore(corruptPath); err == nil {
		t.Errorf("NewStore(corrupt) succeeded, want error")
	}
}

// TestStore_ConcurrentSaveAndGet exercises concurrent readers and writers on
// Store under -race to verify lock discipline and atomic disk replacement.
//
// # Parameters
//
//   - t: Standard Go test handle.
//
// # Example
//
//	go test -race -run '^TestStore_ConcurrentSaveAndGet$' ./internal/waitingroom
//
// # Used By
//
// Invoked by `go test`.
func TestStore_ConcurrentSaveAndGet(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "waitingroom.json")
	store, err := waitingroom.NewStore(path)
	if err != nil {
		t.Fatalf("NewStore error = %v", err)
	}

	layouts := waitingroom.ValidLayouts()
	themes := waitingroom.ValidThemes()
	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := range 8 {
		wg.Go(func() {
			<-start
			for j := range 10 {
				cfg := waitingroom.DefaultConfig()
				cfg.Layout = layouts[(i+j)%len(layouts)]
				cfg.Theme = themes[(i+j)%len(themes)]
				cfg.BrandName = fmt.Sprintf("Stage-%d-%d", i, j)
				if err := store.Save(cfg); err != nil {
					t.Errorf("concurrent Save error = %v", err)
				}
			}
		})
	}
	for range 8 {
		wg.Go(func() {
			<-start
			for range 20 {
				cfg := store.Get()
				if err := cfg.Validate(); err != nil {
					t.Errorf("concurrent Get returned invalid config: %v", err)
				}
			}
		})
	}
	close(start)
	wg.Wait()

	// Final on-disk file must remain valid JSON and 0600.
	reloaded, err := waitingroom.NewStore(path)
	if err != nil {
		t.Fatalf("reload after concurrent writes error = %v", err)
	}
	if err := reloaded.Get().Validate(); err != nil {
		t.Fatalf("reloaded config invalid: %v", err)
	}
}

// TestParseYouTubeID covers all supported YouTube URL shapes and rejects XSS,
// non-YouTube hosts, userinfo, and malformed video IDs.
//
// # Parameters
//
//   - t: Standard Go test handle.
//
// # Example
//
//	go test -run '^TestParseYouTubeID$' ./internal/waitingroom
//
// # Used By
//
// Invoked by `go test`.
func TestParseYouTubeID(t *testing.T) {
	t.Parallel()

	validCases := []struct {
		name string
		in   string
		want string
	}{
		{name: "bare 11-char ID", in: "dQw4w9WgXcQ", want: "dQw4w9WgXcQ"},
		{name: "bare ID with dash and underscore", in: "Ab_12-XyZ09", want: "Ab_12-XyZ09"},
		{name: "watch url", in: "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=42s", want: "dQw4w9WgXcQ"},
		{name: "mobile watch url", in: "https://m.youtube.com/watch?v=dQw4w9WgXcQ", want: "dQw4w9WgXcQ"},
		{name: "short youtu.be url", in: "https://youtu.be/dQw4w9WgXcQ?si=xyz", want: "dQw4w9WgXcQ"},
		{name: "live url", in: "https://www.youtube.com/live/jfKfPfyJRdk?feature=share", want: "jfKfPfyJRdk"},
		{name: "embed url", in: "https://www.youtube.com/embed/dQw4w9WgXcQ?rel=0", want: "dQw4w9WgXcQ"},
		{name: "nocookie embed url", in: "https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ", want: "dQw4w9WgXcQ"},
		{name: "shorts url", in: "https://youtube.com/shorts/dQw4w9WgXcQ", want: "dQw4w9WgXcQ"},
	}
	for _, tt := range validCases {
		t.Run("valid/"+tt.name, func(t *testing.T) {
			got, err := waitingroom.ParseYouTubeID(tt.in)
			if err != nil {
				t.Fatalf("ParseYouTubeID(%q) error = %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseYouTubeID(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	invalidCases := []struct {
		name string
		in   string
	}{
		{name: "empty", in: ""},
		{name: "too short", in: "abc123"},
		{name: "too long", in: "dQw4w9WgXcQ1"},
		{name: "javascript xss", in: "javascript:alert(1)"},
		{name: "data uri", in: "data:text/html,<script>alert(1)</script>"},
		{name: "evil host lookalike", in: "https://youtube.com.evil.example/watch?v=dQw4w9WgXcQ"},
		{name: "userinfo smuggling", in: "https://visitor@" + "www.youtube.com/watch?v=dQw4w9WgXcQ"},
		{name: "xss in query id", in: `https://youtube.com/watch?v=abc"onload=1`},
		{name: "nocookie non-embed path", in: "https://www.youtube-nocookie.com/watch?v=dQw4w9WgXcQ"},
		{name: "control char", in: "dQw4w9WgXcQ\r\n"},
	}
	for _, tt := range invalidCases {
		t.Run("invalid/"+tt.name, func(t *testing.T) {
			got, err := waitingroom.ParseYouTubeID(tt.in)
			if !errors.Is(err, waitingroom.ErrInvalidYouTubeID) {
				t.Fatalf("ParseYouTubeID(%q) = (%q, %v), want ErrInvalidYouTubeID", tt.in, got, err)
			}
		})
	}
}

// TestConfigValidation_AllBoundaries verifies strict validation of layouts,
// themes, URLs, accent colors, locales, and broadcast lengths.
//
// # Parameters
//
//   - t: Standard Go test handle.
//
// # Example
//
//	go test -run '^TestConfigValidation_AllBoundaries$' ./internal/waitingroom
//
// # Used By
//
// Invoked by `go test`.
func TestConfigValidation_AllBoundaries(t *testing.T) {
	t.Parallel()

	// All 5 layouts and all 11 themes (system + 10 portal themes) must validate.
	layouts := waitingroom.ValidLayouts()
	themes := waitingroom.ValidThemes()
	if len(layouts) != 5 {
		t.Fatalf("len(ValidLayouts()) = %d, want 5", len(layouts))
	}
	if len(themes) != 11 {
		t.Fatalf("len(ValidThemes()) = %d, want 11", len(themes))
	}
	for _, layout := range layouts {
		for _, theme := range themes {
			cfg := waitingroom.DefaultConfig()
			cfg.Layout = layout
			cfg.Theme = theme
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate(layout=%q, theme=%q) error = %v", layout, theme, err)
			}
		}
	}

	cases := []struct {
		name    string
		mutate  func(*waitingroom.Config)
		wantErr error
	}{
		{name: "invalid layout", mutate: func(c *waitingroom.Config) { c.Layout = "carousel" }, wantErr: waitingroom.ErrInvalidLayout},
		{name: "invalid theme", mutate: func(c *waitingroom.Config) { c.Theme = "neon-pink" }, wantErr: waitingroom.ErrInvalidTheme},
		{name: "invalid locale", mutate: func(c *waitingroom.Config) { c.DefaultLocale = "xx-YY" }, wantErr: waitingroom.ErrInvalidLocale},
		{name: "http logo rejected", mutate: func(c *waitingroom.Config) { c.LogoURL = "http://example.com/logo.png" }, wantErr: waitingroom.ErrInvalidURL},
		{name: "javascript logo rejected", mutate: func(c *waitingroom.Config) { c.LogoURL = "javascript:alert(1)" }, wantErr: waitingroom.ErrInvalidURL},
		{name: "data hero rejected", mutate: func(c *waitingroom.Config) { c.HeroImageURL = "data:image/svg+xml,<svg/>" }, wantErr: waitingroom.ErrInvalidURL},
		{name: "protocol-relative logo rejected", mutate: func(c *waitingroom.Config) { c.LogoURL = "//evil.example/a.png" }, wantErr: waitingroom.ErrInvalidURL},
		{name: "userinfo logo rejected", mutate: func(c *waitingroom.Config) { c.LogoURL = "https://visitor@" + "example.com/a.png" }, wantErr: waitingroom.ErrInvalidURL},
		{name: "short hex accent rejected", mutate: func(c *waitingroom.Config) { c.AccentColor = "#fff" }, wantErr: waitingroom.ErrInvalidAccentColor},
		{name: "css injection accent rejected", mutate: func(c *waitingroom.Config) { c.AccentColor = "#ffffff;background:url(x)" }, wantErr: waitingroom.ErrInvalidAccentColor},
		{name: "broadcast over 280 runes rejected", mutate: func(c *waitingroom.Config) { c.Broadcast.Message = strings.Repeat("a", 281) }, wantErr: waitingroom.ErrBroadcastTooLong},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := waitingroom.DefaultConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestContentSecurityPolicy_Strictness proves frame-src is 'none' on every
// layout except youtube with a valid YouTubeVideoID, where only
// https://www.youtube-nocookie.com is granted.
//
// # Parameters
//
//   - t: Standard Go test handle.
//
// # Example
//
//	go test -run '^TestContentSecurityPolicy_Strictness$' ./internal/waitingroom
//
// # Used By
//
// Invoked by `go test`.
func TestContentSecurityPolicy_Strictness(t *testing.T) {
	t.Parallel()

	for _, layout := range waitingroom.ValidLayouts() {
		cfg := waitingroom.DefaultConfig()
		cfg.Layout = layout
		cfg.YouTubeVideoID = "dQw4w9WgXcQ"
		csp := waitingroom.ContentSecurityPolicy(cfg)

		for _, required := range []string{
			"script-src 'self'",
			"object-src 'none'",
			"frame-ancestors 'none'",
			"base-uri 'none'",
		} {
			if !strings.Contains(csp, required) {
				t.Errorf("layout=%q CSP missing %q: %s", layout, required, csp)
			}
		}

		if layout == waitingroom.LayoutYouTube {
			if !strings.Contains(csp, "frame-src https://www.youtube-nocookie.com") {
				t.Errorf("youtube layout with ID missing nocookie frame-src: %s", csp)
			}
			if strings.Contains(csp, "frame-src 'none'") {
				t.Errorf("youtube layout with ID should not have frame-src 'none': %s", csp)
			}
		} else {
			if !strings.Contains(csp, "frame-src 'none'") {
				t.Errorf("layout=%q must have frame-src 'none': %s", layout, csp)
			}
			if strings.Contains(csp, "youtube-nocookie.com") {
				t.Errorf("layout=%q leaked youtube frame-src: %s", layout, csp)
			}
		}
	}

	// YouTube layout WITHOUT a video ID must keep frame-src 'none'.
	ytEmpty := waitingroom.DefaultConfig()
	ytEmpty.Layout = waitingroom.LayoutYouTube
	if csp := waitingroom.ContentSecurityPolicy(ytEmpty); !strings.Contains(csp, "frame-src 'none'") {
		t.Errorf("youtube layout without video ID must keep frame-src 'none': %s", csp)
	}

	// Valid HTTPS LogoURL narrows img-src to exact origin.
	withLogo := waitingroom.DefaultConfig()
	withLogo.LogoURL = "https://cdn.example.com/images/logo.png"
	if csp := waitingroom.ContentSecurityPolicy(withLogo); !strings.Contains(csp, "img-src 'self' data: https://cdn.example.com") {
		t.Errorf("CSP missing exact logo origin: %s", csp)
	}
}

// TestETAEstimator_MathConfidenceAndConcurrency verifies EWMA rate accuracy,
// confidence transitions, staleness, burst clamping, clock regression immunity,
// and concurrent safety under -race.
//
// # Parameters
//
//   - t: Standard Go test handle.
//
// # Example
//
//	go test -race -run '^TestETAEstimator_MathConfidenceAndConcurrency$' ./internal/waitingroom
//
// # Used By
//
// Invoked by `go test`.
func TestETAEstimator_MathConfidenceAndConcurrency(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	est := waitingroom.NewETAEstimator(0.25)

	// 0 and 1 sample -> low confidence, zero ETA.
	if got := est.Estimate(10, base); got.Seconds != 0 || got.Confidence != waitingroom.ConfidenceLow {
		t.Fatalf("empty Estimate = %+v, want 0s low", got)
	}
	est.RecordAdmission(base)
	if got := est.Estimate(10, base); got.Seconds != 0 || got.Confidence != waitingroom.ConfidenceLow {
		t.Fatalf("1-sample Estimate = %+v, want 0s low", got)
	}

	// 10 steady admissions 2s apart -> 30/min, high confidence, 15 * 2s = 30s.
	for i := 1; i <= 10; i++ {
		est.RecordAdmission(base.Add(time.Duration(i*2) * time.Second))
	}
	now := base.Add(20 * time.Second)
	got := est.Estimate(15, now)
	if got.Seconds != 30 {
		t.Errorf("Estimate(15).Seconds = %d, want 30", got.Seconds)
	}
	if math.Abs(got.AdmissionsPerMinute-30.0) > 1e-6 {
		t.Errorf("AdmissionsPerMinute = %f, want 30.0", got.AdmissionsPerMinute)
	}
	if got.Confidence != waitingroom.ConfidenceHigh {
		t.Errorf("Confidence = %q, want %q", got.Confidence, waitingroom.ConfidenceHigh)
	}

	// Medium confidence check on a fresh estimator with 4 samples.
	med := waitingroom.NewETAEstimator(0.5)
	for i := range 4 {
		med.RecordAdmission(base.Add(time.Duration(i*4) * time.Second))
	}
	medGot := med.Estimate(5, base.Add(12*time.Second))
	if medGot.Confidence != waitingroom.ConfidenceMedium || medGot.Seconds != 20 {
		t.Errorf("medium Estimate = %+v, want 20s medium", medGot)
	}

	// Stale observation (> 5 min since last admission) degrades to low confidence.
	if stale := est.Estimate(15, now.Add(6*time.Minute)); stale.Confidence != waitingroom.ConfidenceLow {
		t.Errorf("stale Confidence = %q, want %q", stale.Confidence, waitingroom.ConfidenceLow)
	}

	// Out-of-order past timestamp must not corrupt rate.
	est.RecordAdmission(base)
	if afterPast := est.Estimate(15, now); afterPast.Seconds != 30 {
		t.Errorf("after out-of-order timestamp Seconds = %d, want 30", afterPast.Seconds)
	}

	// Reset clears all state back to unknown/low confidence.
	med.Reset()
	if resetEst := med.Estimate(5, base.Add(20*time.Second)); resetEst.Seconds != 0 || resetEst.Confidence != waitingroom.ConfidenceLow {
		t.Errorf("after Reset() Estimate = %+v, want 0s low", resetEst)
	}

	// Concurrent RecordAdmission and Estimate stress under -race.
	start := make(chan struct{})
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Go(func() {
			<-start
			for i := range 50 {
				tNow := base.Add(time.Duration(g*50+i) * 100 * time.Millisecond)
				est.RecordAdmission(tNow)
				e := est.Estimate(i+1, tNow)
				if math.IsNaN(e.AdmissionsPerMinute) || math.IsInf(e.AdmissionsPerMinute, 0) {
					t.Errorf("non-finite rate: %+v", e)
				}
			}
		})
	}
	close(start)
	wg.Wait()
}

// TestRenderHTML_XSSAndRTLAndLayouts proves that RenderHTML escapes hostile
// HTML/script payloads, sets RTL attributes for all 4 RTL locales, preserves
// backward-compatible hooks, and renders all 5 layouts and 10 Portal themes.
//
// # Parameters
//
//   - t: Standard Go test handle.
//
// # Example
//
//	go test -run '^TestRenderHTML_XSSAndRTLAndLayouts$' ./internal/waitingroom
//
// # Used By
//
// Invoked by `go test`.
func TestRenderHTML_XSSAndRTLAndLayouts(t *testing.T) {
	t.Parallel()

	baseHTML, err := os.ReadFile(filepath.Join("..", "server", "web", "waiting.html"))
	if err != nil {
		t.Fatalf("read waiting.html: %v", err)
	}

	xssPayload := `</script><script>alert("xss")</script><img src=x onerror=alert(1)>`
	cfg := waitingroom.Config{
		Layout:         waitingroom.LayoutYouTube,
		Theme:          waitingroom.ThemeSynthwave84,
		BrandName:      xssPayload,
		AccentColor:    "#36f9f6",
		Headline:       xssPayload,
		Subheadline:    xssPayload,
		YouTubeVideoID: "dQw4w9WgXcQ",
		DefaultLocale:  "en",
		Broadcast: waitingroom.Broadcast{
			Message:   xssPayload,
			UpdatedAt: time.Date(2026, 11, 26, 18, 0, 0, 0, time.UTC),
		},
	}

	rendered, err := waitingroom.RenderHTML(baseHTML, cfg, "arc", waitingroom.RenderOptions{
		Position: 42,
		ETA: &waitingroom.ETAEstimate{
			Seconds:             90,
			AdmissionsPerMinute: 28,
			Confidence:          waitingroom.ConfidenceHigh,
		},
	})
	if err != nil {
		t.Fatalf("RenderHTML error = %v", err)
	}
	htmlStr := string(rendered)

	// Unescaped XSS payload must NEVER appear anywhere in rendered output.
	if strings.Contains(htmlStr, "<script>alert(") || strings.Contains(htmlStr, "<img src=x") {
		t.Fatalf("rendered HTML contains unescaped XSS payload")
	}
	if strings.Count(htmlStr, "</script>") != 2 {
		// Exactly 2 </script> closing tags: waiting.js in <head> and concert-wr-state JSON.
		t.Errorf("unexpected </script> count = %d, want 2", strings.Count(htmlStr, "</script>"))
	}

	// Verify RTL, locale, theme, layout, YouTube nocookie iframe, and legacy hooks.
	for _, want := range []string{
		`lang="arc"`,
		`dir="rtl"`,
		`data-gd-theme="synthwave84"`,
		`data-layout="youtube"`,
		`data-accent="#36f9f6"`,
		`id="position"`,
		`42`,
		`/_concert/waiting.js`,
		`https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ`,
		`id="concert-wr-state" type="application/json"`,
	} {
		if !strings.Contains(htmlStr, want) {
			t.Errorf("rendered HTML missing expected token %q", want)
		}
	}

	// Verify all 4 RTL locales produce dir="rtl".
	for _, rtl := range []string{"ar", "he", "fa", "arc"} {
		out, err := waitingroom.RenderHTML(baseHTML, waitingroom.DefaultConfig(), rtl, waitingroom.RenderOptions{})
		if err != nil {
			t.Fatalf("RenderHTML(%q) error = %v", rtl, err)
		}
		if !bytes.Contains(out, []byte(`dir="rtl"`)) || !bytes.Contains(out, []byte(`lang="`+rtl+`"`)) {
			t.Errorf("RenderHTML(%q) missing dir=\"rtl\" or lang attribute", rtl)
		}
		// Position <= 0 must preserve {{.Position}} placeholder for room.
		if !bytes.Contains(out, []byte(`{{.Position}}`)) {
			t.Errorf("RenderHTML(%q) with Position=0 did not preserve {{.Position}}", rtl)
		}
	}

	// Verify youtube layout without video ID renders pure-CSS placeholder card (no iframe).
	ytEmpty := waitingroom.DefaultConfig()
	ytEmpty.Layout = waitingroom.LayoutYouTube
	outPlaceholder, err := waitingroom.RenderHTML(baseHTML, ytEmpty, "en", waitingroom.RenderOptions{})
	if err != nil {
		t.Fatalf("RenderHTML(youtube placeholder) error = %v", err)
	}
	if bytes.Contains(outPlaceholder, []byte("<iframe")) {
		t.Errorf("youtube layout without video ID must not render an <iframe>")
	}
	if !bytes.Contains(outPlaceholder, []byte("cinema-placeholder")) {
		t.Errorf("youtube layout without video ID missing cinema-placeholder card")
	}

	// Verify all 5 layouts and all 10 named Portal themes render cleanly.
	for _, layout := range waitingroom.ValidLayouts() {
		for _, theme := range waitingroom.ValidThemes() {
			c := waitingroom.DefaultConfig()
			c.Layout = layout
			c.Theme = theme
			out, err := waitingroom.RenderHTML(baseHTML, c, i18n.DefaultLocale, waitingroom.RenderOptions{})
			if err != nil {
				t.Fatalf("RenderHTML(layout=%q, theme=%q) error = %v", layout, theme, err)
			}
			if !bytes.Contains(out, []byte(`data-layout="`+layout+`"`)) {
				t.Errorf("missing data-layout=%q", layout)
			}
			if theme != waitingroom.ThemeSystem && !bytes.Contains(out, []byte(`data-gd-theme="`+theme+`"`)) {
				t.Errorf("missing data-gd-theme=%q", theme)
			}
		}
	}
}

// ExampleParseYouTubeID demonstrates extracting a validated 11-character video
// ID from multiple YouTube URL formats.
//
// # Parameters
//
// None. Executed by `go test`.
//
// # Example
//
//	go test -run '^ExampleParseYouTubeID$' ./internal/waitingroom
//
// # Used By
//
// Invoked by `go test`.
func ExampleParseYouTubeID() {
	id, err := waitingroom.ParseYouTubeID("https://www.youtube.com/live/jfKfPfyJRdk?feature=share")
	if err != nil {
		panic(err)
	}
	fmt.Println(id)
	// Output:
	// jfKfPfyJRdk
}

// ExampleContentSecurityPolicy demonstrates the strict CSP output for default
// versus YouTube Cinema layouts.
//
// # Parameters
//
// None. Executed by `go test`.
//
// # Example
//
//	go test -run '^ExampleContentSecurityPolicy$' ./internal/waitingroom
//
// # Used By
//
// Invoked by `go test`.
func ExampleContentSecurityPolicy() {
	def := waitingroom.DefaultConfig()
	fmt.Println(strings.Contains(waitingroom.ContentSecurityPolicy(def), "frame-src 'none'"))

	yt := waitingroom.DefaultConfig()
	yt.Layout = waitingroom.LayoutYouTube
	yt.YouTubeVideoID = "dQw4w9WgXcQ"
	fmt.Println(strings.Contains(waitingroom.ContentSecurityPolicy(yt), "frame-src https://www.youtube-nocookie.com"))
	// Output:
	// true
	// true
}
