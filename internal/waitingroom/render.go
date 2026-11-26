package waitingroom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"strconv"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/i18n"
)

const (
	markerTitle          = "<!--CONCERT_WR_TITLE-->"
	markerBrandStart     = "<!--CONCERT_WR_BRAND_START-->"
	markerBrandEnd       = "<!--CONCERT_WR_BRAND_END-->"
	markerBroadcastStart = "<!--CONCERT_WR_BROADCAST_START-->"
	markerBroadcastEnd   = "<!--CONCERT_WR_BROADCAST_END-->"
	markerHeroStart      = "<!--CONCERT_WR_HERO_START-->"
	markerHeroEnd        = "<!--CONCERT_WR_HERO_END-->"
	markerStageStart     = "<!--CONCERT_WR_STAGE_START-->"
	markerStageEnd       = "<!--CONCERT_WR_STAGE_END-->"
	markerLangStart      = "<!--CONCERT_WR_LANG_OPTIONS_START-->"
	markerLangEnd        = "<!--CONCERT_WR_LANG_OPTIONS_END-->"
	markerState          = "<!--CONCERT_WR_STATE-->"
)

// RenderOptions provides optional per-request context when rendering a waiting
// room HTML document via RenderHTML.
type RenderOptions struct {
	// Position is the visitor's 1-based queue position. When > 0, occurrences of
	// "{{.Position}}" in baseHTML are replaced with the formatted integer; when <= 0,
	// "{{.Position}}" is preserved for downstream template rendering.
	Position int
	// ETA optionally provides an initial server-computed wait estimate hydrated
	// into the inert JSON state payload.
	ETA *ETAEstimate
}

// clientState is the inert JSON payload serialized into
// <script id="concert-wr-state" type="application/json"> for waiting.js.
type clientState struct {
	Layout      string            `json:"layout"`
	Theme       string            `json:"theme"`
	Locale      string            `json:"locale"`
	Dir         string            `json:"dir"`
	BrandName   string            `json:"brand_name"`
	AccentColor string            `json:"accent_color,omitempty"`
	Broadcast   Broadcast         `json:"broadcast"`
	ETA         *ETAEstimate      `json:"eta,omitempty"`
	Locales     []i18n.LocaleInfo `json:"locales"`
	I18n        map[string]string `json:"i18n"`
}

// RenderHTML safely injects validated Waiting Room Studio settings, resolved
// locale and writing direction, HTML-escaped brand/headline/broadcast/stage
// markup, and an inert JSON hydration block into baseHTML without inline
// executable scripts.
//
// Every operator-controlled field is first validated via cfg.Normalized and then
// escaped with html.EscapeString before insertion into HTML text or attributes.
// The JSON state block uses type="application/json" (inert under script-src 'self')
// with Go's standard HTML-safe JSON escaping (\u003c, \u003e, \u0026) so no value
// can break out of the script element.
//
// # Parameters
//
//   - baseHTML: Base waiting-room HTML template bytes (never mutated in place).
//   - cfg: Operator Waiting Room Studio configuration; validated before rendering.
//   - locale: Preferred BCP-47 locale tag (negotiated against package i18n with
//     fallback to cfg.DefaultLocale and "en").
//   - opts: Optional per-request queue position and initial ETA estimate.
//
// # Returns
//
// Newly allocated rendered HTML bytes and nil error on success, or (nil, err)
// when cfg fails validation or state serialization fails.
//
// # Concurrency
//
// Pure function; safe for concurrent use across goroutines provided baseHTML is
// not mutated concurrently by the caller.
//
// # Example
//
//	cfg := waitingroom.DefaultConfig()
//	cfg.Theme = waitingroom.ThemeNord
//	out, err := waitingroom.RenderHTML(baseHTML, cfg, "arc", waitingroom.RenderOptions{Position: 7})
//	if err != nil {
//		return err
//	}
//	fmt.Println(bytes.Contains(out, []byte(`dir="rtl"`))) // true
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/waitingroom_test.go:538 (direct call)
//   - internal/waitingroom/waitingroom_test.go:580 (direct call)
//   - internal/waitingroom/waitingroom_test.go:596 (direct call)
//   - internal/waitingroom/waitingroom_test.go:613 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func RenderHTML(baseHTML []byte, cfg Config, locale string, opts RenderOptions) ([]byte, error) {
	norm, err := cfg.Normalized()
	if err != nil {
		return nil, err
	}

	resolvedLocale := i18n.Negotiate(locale, "", "", norm.DefaultLocale)
	dir := i18n.Dir(resolvedLocale)
	catalog := i18n.Catalog(resolvedLocale)
	locales := i18n.SupportedLocales()

	brandDisplay := norm.BrandName
	if brandDisplay == "" {
		brandDisplay = "Concert"
	}

	state := clientState{
		Layout:      norm.Layout,
		Theme:       norm.Theme,
		Locale:      resolvedLocale,
		Dir:         dir,
		BrandName:   brandDisplay,
		AccentColor: norm.AccentColor,
		Broadcast:   norm.Broadcast,
		ETA:         opts.ETA,
		Locales:     locales,
		I18n:        catalog,
	}
	stateJSON, err := marshalSafeScriptJSON(state)
	if err != nil {
		return nil, fmt.Errorf("marshal waitingroom state: %w", err)
	}
	stateTag := `<script id="concert-wr-state" type="application/json">` + stateJSON + `</script>`

	doc := string(baseHTML)
	doc = rewriteHTMLTag(doc, resolvedLocale, dir, norm.Theme, norm.Layout)
	doc = rewriteBodyAccent(doc, norm.AccentColor)

	if opts.Position > 0 {
		doc = strings.ReplaceAll(doc, "{{.Position}}", strconv.Itoa(opts.Position))
	}

	titleText := html.EscapeString(catalog["page.title"] + " · " + brandDisplay)
	if strings.Contains(doc, markerTitle) {
		doc = strings.ReplaceAll(doc, markerTitle, titleText)
	} else {
		doc = replaceTitleTag(doc, titleText)
	}

	brandHTML := renderBrandHTML(norm, brandDisplay)
	broadcastHTML := renderBroadcastHTML(norm.Broadcast, catalog["broadcast.label"])
	heroHTML := renderHeroHTML(norm, catalog)
	stageHTML := renderStageHTML(norm, catalog, brandDisplay)
	langOptionsHTML := renderLangOptionsHTML(locales, resolvedLocale)

	hasMarkers := strings.Contains(doc, markerState) || strings.Contains(doc, markerStageStart) || strings.Contains(doc, markerBroadcastStart)
	doc = replaceSection(doc, markerBrandStart, markerBrandEnd, brandHTML)
	doc = replaceSection(doc, markerBroadcastStart, markerBroadcastEnd, broadcastHTML)
	doc = replaceSection(doc, markerHeroStart, markerHeroEnd, heroHTML)
	doc = replaceSection(doc, markerStageStart, markerStageEnd, stageHTML)
	doc = replaceSection(doc, markerLangStart, markerLangEnd, langOptionsHTML)
	if strings.Contains(doc, markerState) {
		doc = strings.ReplaceAll(doc, markerState, stateTag)
	}

	// Fallback for minimal or custom operator templates lacking CONCERT_WR markers:
	// inject broadcast, YouTube cinema embed (if configured), and inert JSON state
	// right before </body> so every security and rendering invariant still holds.
	if !hasMarkers {
		var extra strings.Builder
		if norm.Broadcast.Message != "" {
			extra.WriteString(broadcastHTML)
		}
		if norm.Layout == LayoutYouTube {
			extra.WriteString(stageHTML)
		}
		extra.WriteString(stateTag)
		doc = injectBeforeClosingBody(doc, extra.String())
	}

	return []byte(doc), nil
}

// replaceSection replaces the substring delimited by startMarker and endMarker
// (inclusive) in doc with replacement when both markers appear in order.
//
// # Parameters
//
//   - doc: Source HTML document text.
//   - startMarker: Opening HTML comment marker.
//   - endMarker: Closing HTML comment marker.
//   - replacement: Pre-escaped HTML fragment to substitute.
//
// # Returns
//
// Updated document text, or doc unchanged if markers are absent or misordered.
//
// # Example
//
//	out := replaceSection("<!--S-->old<!--E-->", "<!--S-->", "<!--E-->", "new")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/render.go:162 (direct call)
//   - internal/waitingroom/render.go:163 (direct call)
//   - internal/waitingroom/render.go:164 (direct call)
//   - internal/waitingroom/render.go:165 (direct call)
//   - internal/waitingroom/render.go:166 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func replaceSection(doc, startMarker, endMarker, replacement string) string {
	s := strings.Index(doc, startMarker)
	if s < 0 {
		return doc
	}
	e := strings.Index(doc[s+len(startMarker):], endMarker)
	if e < 0 {
		return doc
	}
	endIdx := s + len(startMarker) + e + len(endMarker)
	return doc[:s] + replacement + doc[endIdx:]
}

// marshalSafeScriptJSON serializes v to JSON with Go's HTML-safe escaping
// enabled (<, >, &, U+2028, U+2029 escaped) so the result cannot terminate an
// enclosing <script type="application/json"> element.
//
// # Parameters
//
//   - v: Value to serialize as JSON.
//
// # Returns
//
// Compact JSON string safe for direct embedding inside a JSON script element.
//
// # Example
//
//	encoded, err := marshalSafeScriptJSON(map[string]string{"msg": "</script>"})
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/render.go:134 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func marshalSafeScriptJSON(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// rewriteHTMLTag updates the opening <html> element in doc with escaped lang,
// dir, data-layout, and theme attributes (emitting data-gd-theme when a named
// Portal theme is selected, or data-wr-theme="system" for system preference).
//
// # Parameters
//
//   - doc: HTML document text.
//   - locale: Validated BCP-47 locale tag.
//   - dir: Writing direction ("ltr" or "rtl").
//   - theme: Validated theme identifier.
//   - layout: Validated layout identifier.
//
// # Returns
//
// Document text with its opening <html> tag updated.
//
// # Example
//
//	out := rewriteHTMLTag(`<html lang="en">`, "ar", "rtl", "nord", "youtube")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/render.go:141 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func rewriteHTMLTag(doc, locale, dir, theme, layout string) string {
	lower := strings.ToLower(doc)
	start := strings.Index(lower, "<html")
	if start < 0 {
		return doc
	}
	end := strings.IndexByte(doc[start:], '>')
	if end < 0 {
		return doc
	}
	end += start

	var attrs strings.Builder
	attrs.WriteString(`<html lang="`)
	attrs.WriteString(html.EscapeString(locale))
	attrs.WriteString(`" dir="`)
	attrs.WriteString(html.EscapeString(dir))
	attrs.WriteString(`" data-layout="`)
	attrs.WriteString(html.EscapeString(layout))
	attrs.WriteString(`" data-wr-theme="`)
	attrs.WriteString(html.EscapeString(theme))
	attrs.WriteByte('"')
	if theme != ThemeSystem {
		attrs.WriteString(` data-gd-theme="`)
		attrs.WriteString(html.EscapeString(theme))
		attrs.WriteByte('"')
	}
	attrs.WriteByte('>')

	return doc[:start] + attrs.String() + doc[end+1:]
}

// rewriteBodyAccent attaches a validated data-accent="#RRGGBB" attribute to the
// opening <body> tag without using inline style attributes blocked by style-src 'self'.
//
// # Parameters
//
//   - doc: HTML document text.
//   - accentColor: Empty or validated "#RRGGBB" color value.
//
// # Returns
//
// Updated HTML document text.
//
// # Example
//
//	out := rewriteBodyAccent(`<body class="queue-page">`, "#36f9f6")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/render.go:142 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func rewriteBodyAccent(doc, accentColor string) string {
	if accentColor == "" {
		return doc
	}
	lower := strings.ToLower(doc)
	start := strings.Index(lower, "<body")
	if start < 0 {
		return doc
	}
	end := strings.IndexByte(doc[start:], '>')
	if end < 0 {
		return doc
	}
	end += start
	tag := doc[start:end]
	if strings.Contains(strings.ToLower(tag), "data-accent=") {
		return doc
	}
	return doc[:end] + ` data-accent="` + html.EscapeString(accentColor) + `"` + doc[end:]
}

// replaceTitleTag replaces the text inside the first <title>...</title> element
// with escapedTitle when present.
//
// # Parameters
//
//   - doc: HTML document text.
//   - escapedTitle: Pre-escaped HTML title text.
//
// # Returns
//
// Updated HTML document text.
//
// # Example
//
//	out := replaceTitleTag(`<title>Old</title>`, "New Title")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/render.go:152 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func replaceTitleTag(doc, escapedTitle string) string {
	lower := strings.ToLower(doc)
	openIdx := strings.Index(lower, "<title>")
	if openIdx < 0 {
		return doc
	}
	closeIdx := strings.Index(lower[openIdx:], "</title>")
	if closeIdx < 0 {
		return doc
	}
	closeIdx += openIdx
	return doc[:openIdx+len("<title>")] + escapedTitle + doc[closeIdx:]
}

// renderBrandHTML builds the HTML-escaped masthead brand lockup with an optional
// validated logo image or Concert's equalizer bars.
//
// # Parameters
//
//   - cfg: Validated Config.
//   - brandDisplay: Non-empty brand name to display.
//
// # Returns
//
// Escaped HTML markup for the masthead wordmark contents.
//
// # Example
//
//	markup := renderBrandHTML(cfg, "Concert")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/render.go:155 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func renderBrandHTML(cfg Config, brandDisplay string) string {
	escapedBrand := html.EscapeString(brandDisplay)
	if cfg.LogoURL != "" {
		return `<img class="brand-logo" src="` + html.EscapeString(cfg.LogoURL) + `" alt="` + escapedBrand + `"><span class="brand-name">` + escapedBrand + `</span>`
	}
	if strings.EqualFold(brandDisplay, "concert") {
		return `<span class="brand-bars" aria-hidden="true"><i></i><i></i><i></i><i></i></span>concert<span class="brand-dot">.</span>`
	}
	return `<span class="brand-bars" aria-hidden="true"><i></i><i></i><i></i><i></i></span><span class="brand-name">` + escapedBrand + `</span>`
}

// renderBroadcastHTML builds the operator live broadcast banner markup. When
// b.Message is empty, the element is rendered hidden so waiting.js can reveal it
// dynamically if a live broadcast arrives later.
//
// # Parameters
//
//   - b: Broadcast message and timestamp.
//   - label: Localized short badge label (for example "LIVE UPDATE").
//
// # Returns
//
// Escaped HTML markup for the broadcast banner element.
//
// # Example
//
//	markup := renderBroadcastHTML(cfg.Broadcast, "LIVE UPDATE")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/render.go:156 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func renderBroadcastHTML(b Broadcast, label string) string {
	hiddenAttr := ""
	if b.Message == "" {
		hiddenAttr = " hidden"
	}
	timeText := ""
	if !b.UpdatedAt.IsZero() {
		timeText = b.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return `<section class="broadcast-banner" id="broadcast-banner" role="status" aria-live="polite"` + hiddenAttr + `>` +
		`<span class="broadcast-badge" data-i18n="broadcast.label">` + html.EscapeString(label) + `</span>` +
		`<p class="broadcast-text" id="broadcast-message">` + html.EscapeString(b.Message) + `</p>` +
		`<time class="broadcast-time" id="broadcast-time" datetime="` + html.EscapeString(timeText) + `">` + html.EscapeString(timeText) + `</time>` +
		`</section>`
}

// renderHeroHTML builds the escaped headline and lead copy block using operator
// overrides when configured or the active locale catalog defaults otherwise.
//
// # Parameters
//
//   - cfg: Validated Config.
//   - cat: Localized translation map for the active locale.
//
// # Returns
//
// Escaped HTML markup for the intro heading and lead paragraph.
//
// # Example
//
//	markup := renderHeroHTML(cfg, i18n.Catalog("en"))
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/render.go:157 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func renderHeroHTML(cfg Config, cat map[string]string) string {
	var b strings.Builder
	b.WriteString(`<p class="eyebrow" data-i18n="eyebrow.space">`)
	b.WriteString(html.EscapeString(cat["eyebrow.space"]))
	b.WriteString(`</p>`)

	if cfg.Headline != "" {
		b.WriteString(`<h1 id="hero-headline">`)
		b.WriteString(html.EscapeString(cfg.Headline))
		b.WriteString(`</h1>`)
	} else {
		b.WriteString(`<h1 id="hero-headline"><span class="headline-lead" data-i18n="hero.headline">`)
		b.WriteString(html.EscapeString(cat["hero.headline"]))
		b.WriteString(`</span><br><span class="headline-accent" data-i18n="hero.headline_accent">`)
		b.WriteString(html.EscapeString(cat["hero.headline_accent"]))
		b.WriteString(`</span></h1>`)
	}

	lede := cfg.Subheadline
	ledeAttr := ""
	if lede == "" {
		lede = cat["hero.lede"]
		ledeAttr = ` data-i18n="hero.lede"`
	}
	b.WriteString(`<p class="lede" id="hero-subheadline"` + ledeAttr + `>`)
	b.WriteString(html.EscapeString(lede))
	b.WriteString(`</p>`)
	return b.String()
}

// renderStageHTML builds the layout-specific visual stage:
//   - LayoutYouTube with valid YouTubeVideoID: privacy-enhanced youtube-nocookie.com iframe
//   - LayoutYouTube without YouTubeVideoID: pure-CSS animated Concert stage placeholder card
//   - Other layouts with HeroImageURL: responsive escaped hero image card
//   - Default fallback: Concert's pure-CSS retro horizon scene
//
// # Parameters
//
//   - cfg: Validated Config.
//   - cat: Active locale translation map.
//   - brandDisplay: Non-empty brand name used for accessible iframe/image labels.
//
// # Returns
//
// Escaped HTML markup for the visual stage slot.
//
// # Example
//
//	markup := renderStageHTML(cfg, i18n.Catalog("en"), "Concert")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/render.go:158 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func renderStageHTML(cfg Config, cat map[string]string, brandDisplay string) string {
	if cfg.Layout == LayoutYouTube {
		if IsValidYouTubeID(cfg.YouTubeVideoID) {
			embedURL := youtubeNoCookieOrigin + "/embed/" + cfg.YouTubeVideoID + "?rel=0&amp;modestbranding=1"
			iframeTitle := html.EscapeString(brandDisplay + " · " + cat["cinema.stage_badge"])
			return `<div class="cinema-stage" id="stage-container"><div class="cinema-frame"><iframe class="youtube-embed" src="` + embedURL + `" title="` + iframeTitle + `" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe></div></div>`
		}
		return `<div class="cinema-stage" id="stage-container"><div class="cinema-placeholder" role="region" aria-label="` + html.EscapeString(cat["cinema.stage_title"]) + `">` +
			`<div class="stage-beams" aria-hidden="true"><i></i><i></i><i></i></div>` +
			`<div class="stage-eq" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div>` +
			`<span class="cinema-badge" data-i18n="cinema.stage_badge">` + html.EscapeString(cat["cinema.stage_badge"]) + `</span>` +
			`<h2 class="cinema-placeholder-title" data-i18n="cinema.stage_title">` + html.EscapeString(cat["cinema.stage_title"]) + `</h2>` +
			`<p class="cinema-placeholder-desc" data-i18n="cinema.stage_desc">` + html.EscapeString(cat["cinema.stage_desc"]) + `</p>` +
			`</div></div>`
	}

	if cfg.HeroImageURL != "" {
		return `<div class="hero-media" id="stage-container"><img class="hero-image" src="` + html.EscapeString(cfg.HeroImageURL) + `" alt="` + html.EscapeString(brandDisplay) + `"></div>`
	}

	return `<div class="scene" id="stage-container" aria-hidden="true"><div class="sun"></div><div class="horizon"></div><div class="grid-floor"></div><div class="scene-label" data-i18n="scene.label">` + html.EscapeString(cat["scene.label"]) + `</div></div>`
}

// renderLangOptionsHTML renders HTML <option> elements for all 19 supported
// locales with the active locale selected.
//
// # Parameters
//
//   - locales: Ordered list of supported LocaleInfo descriptors.
//   - activeLocale: Canonical code of the currently selected locale.
//
// # Returns
//
// Escaped <option> markup for the language picker <select>.
//
// # Example
//
//	opts := renderLangOptionsHTML(i18n.SupportedLocales(), "en")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/render.go:159 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func renderLangOptionsHTML(locales []i18n.LocaleInfo, activeLocale string) string {
	var b strings.Builder
	for _, loc := range locales {
		b.WriteString(`<option value="`)
		b.WriteString(html.EscapeString(loc.Code))
		b.WriteByte('"')
		if loc.Code == activeLocale {
			b.WriteString(` selected`)
		}
		b.WriteByte('>')
		b.WriteString(html.EscapeString(loc.NativeName))
		b.WriteString(`</option>`)
	}
	return b.String()
}

// injectBeforeClosingBody inserts fragment right before </body> (case-insensitive)
// or appends it to doc when no closing body tag is present.
//
// # Parameters
//
//   - doc: HTML document text.
//   - fragment: Safe pre-escaped HTML fragment to inject.
//
// # Returns
//
// Updated HTML document text.
//
// # Example
//
//	out := injectBeforeClosingBody("<html><body></body></html>", "<div>hi</div>")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/render.go:183 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func injectBeforeClosingBody(doc, fragment string) string {
	lower := strings.ToLower(doc)
	idx := strings.LastIndex(lower, "</body>")
	if idx < 0 {
		return doc + fragment
	}
	return doc[:idx] + fragment + doc[idx:]
}
