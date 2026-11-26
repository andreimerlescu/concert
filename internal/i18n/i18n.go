// Package i18n provides embedded 19-locale waiting-room translation catalogs,
// BCP-47 language negotiation, and text-direction metadata with zero external
// dependencies.
//
// All translation tables and locale descriptors are immutable after package
// initialization. Every exported function returns either an immutable scalar
// string or a fresh defensive copy of any slice or map, making the entire
// package safe for unrestricted concurrent reads without locks.
package i18n

import (
	"maps"
	"sort"
	"strconv"
	"strings"
)

const (
	// DirLTR indicates left-to-right writing direction.
	DirLTR = "ltr"
	// DirRTL indicates right-to-left writing direction.
	DirRTL = "rtl"
	// DefaultLocale is the guaranteed fallback locale when no requested tag matches.
	DefaultLocale = "en"

	// maxAcceptLanguageBytes bounds untrusted Accept-Language headers (R3).
	maxAcceptLanguageBytes = 1024
	// maxAcceptLanguageTags bounds the number of weighted tags parsed from a header (R3).
	maxAcceptLanguageTags = 32
)

// LocaleInfo describes a supported waiting-room locale and its writing direction.
type LocaleInfo struct {
	// Code is the canonical BCP-47 language tag (for example "en", "es-MX", or "arc").
	Code string `json:"code"`
	// Name is the English display name for operator configuration interfaces.
	Name string `json:"name"`
	// NativeName is the localized endonym shown to visitors in the language picker.
	NativeName string `json:"native_name"`
	// Dir is the HTML writing direction: "ltr" or "rtl".
	Dir string `json:"dir"`
}

// acceptEntry represents a single parsed tag and quality weight from Accept-Language.
type acceptEntry struct {
	tag   string
	q     float64
	order int
}

// supportedLocales defines the canonical ordering and metadata of all 19 locales.
// It is read-only after package initialization.
var supportedLocales = []LocaleInfo{
	{Code: "en", Name: "English", NativeName: "English", Dir: DirLTR},
	{Code: "es", Name: "Spanish", NativeName: "Español", Dir: DirLTR},
	{Code: "es-MX", Name: "Spanish (Mexico)", NativeName: "Español (México)", Dir: DirLTR},
	{Code: "fr", Name: "French", NativeName: "Français", Dir: DirLTR},
	{Code: "fr-CA", Name: "French (Canada)", NativeName: "Français (Canada)", Dir: DirLTR},
	{Code: "ro", Name: "Romanian", NativeName: "Română", Dir: DirLTR},
	{Code: "ru", Name: "Russian", NativeName: "Русский", Dir: DirLTR},
	{Code: "tr", Name: "Turkish", NativeName: "Türkçe", Dir: DirLTR},
	{Code: "de", Name: "German", NativeName: "Deutsch", Dir: DirLTR},
	{Code: "it", Name: "Italian", NativeName: "Italiano", Dir: DirLTR},
	{Code: "ja", Name: "Japanese", NativeName: "日本語", Dir: DirLTR},
	{Code: "zh-CN", Name: "Chinese (Simplified)", NativeName: "简体中文", Dir: DirLTR},
	{Code: "hi", Name: "Hindi", NativeName: "हिन्दी", Dir: DirLTR},
	{Code: "pl", Name: "Polish", NativeName: "Polski", Dir: DirLTR},
	{Code: "sr", Name: "Serbian", NativeName: "Српски", Dir: DirLTR},
	{Code: "ar", Name: "Arabic", NativeName: "العربية", Dir: DirRTL},
	{Code: "he", Name: "Hebrew", NativeName: "עברית", Dir: DirRTL},
	{Code: "fa", Name: "Persian", NativeName: "فارسی", Dir: DirRTL},
	{Code: "arc", Name: "Aramaic (Syriac)", NativeName: "ܣܘܪܝܝܐ", Dir: DirRTL},
}

// localeByLower maps lower-cased canonical tags to their LocaleInfo.
// It is read-only after package initialization.
var localeByLower map[string]LocaleInfo

// tagAliases maps common BCP-47 script, legacy ISO 639-1, and regional variants
// to a canonical supported locale code. It is read-only after package initialization.
var tagAliases = map[string]string{
	"zh":      "zh-CN",
	"zh-hans": "zh-CN",
	"zh-hant": "zh-CN",
	"zh-sg":   "zh-CN",
	"zh-tw":   "zh-CN",
	"zh-hk":   "zh-CN",
	"zh-mo":   "zh-CN",
	"iw":      "he",
	"syr":     "arc",
	"syc":     "arc",
	"aii":     "arc",
	"cld":     "arc",
}

// init builds the read-only lowercase lookup index from supportedLocales.
//
// # Parameters
//
// None. Invoked once by the Go runtime during package initialization.
//
// # Side Effects
//
// Populates localeByLower before any package function can execute.
//
// # Example
//
//	// Executed automatically by the Go runtime when package i18n is imported.
//
// # Used By
//
// Invoked by the Go runtime during package initialization; no direct callers.
func init() {
	localeByLower = make(map[string]LocaleInfo, len(supportedLocales))
	for _, info := range supportedLocales {
		localeByLower[strings.ToLower(info.Code)] = info
	}
}

// SupportedLocales returns a fresh slice listing all 19 supported locales in
// canonical order.
//
// # Parameters
//
// None.
//
// # Returns
//
// A newly allocated []LocaleInfo containing all 19 supported locales. Callers
// may modify the returned slice without affecting internal package state.
//
// # Concurrency
//
// Safe for concurrent use by multiple goroutines.
//
// # Example
//
//	locales := i18n.SupportedLocales()
//	fmt.Println(len(locales)) // 19
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/i18n/i18n_test.go:35 (direct call)
//   - internal/i18n/i18n_test.go:87 (direct call)
//   - internal/i18n/i18n_test.go:114 (direct call)
//   - internal/i18n/i18n_test.go:416 (direct call)
//   - internal/waitingroom/render.go:115 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func SupportedLocales() []LocaleInfo {
	out := make([]LocaleInfo, len(supportedLocales))
	copy(out, supportedLocales)
	return out
}

// IsSupported reports whether locale matches one of the 19 supported canonical
// locale codes (case-insensitively, accepting "-" or "_" separators).
//
// # Parameters
//
//   - locale: Candidate BCP-47 locale code to check.
//
// # Returns
//
// true when locale resolves directly to one of the 19 supported locales without
// region-stripping fallback; false otherwise.
//
// # Concurrency
//
// Safe for concurrent use by multiple goroutines.
//
// # Example
//
//	fmt.Println(i18n.IsSupported("es-MX")) // true
//	fmt.Println(i18n.IsSupported("es-AR")) // false
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/i18n/i18n_test.go:63 (direct call)
//   - internal/i18n/i18n_test.go:80 (direct call)
//   - internal/waitingroom/config.go:539 (direct call)
//   - internal/waitingroom/config.go:608 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func IsSupported(locale string) bool {
	norm := normalizeTag(locale)
	if norm == "" {
		return false
	}
	_, ok := localeByLower[norm]
	return ok
}

// Negotiate selects the best supported canonical locale using the priority order:
// queryLang, cookieLang, acceptLanguage (RFC 9110 weighted list), defaultLocale,
// and finally "en".
//
// BCP-47 region and script fallbacks are applied automatically (for example
// "es-AR" -> "es", "fr-BE" -> "fr", "zh-Hans" -> "zh-CN", "arc-Syrc" -> "arc").
//
// # Parameters
//
//   - queryLang: Explicit query-string language override (for example from "?lang=").
//   - cookieLang: Persisted visitor cookie value (for example "concert_lang").
//   - acceptLanguage: Raw HTTP Accept-Language header; bounded internally to prevent
//     excessive work on hostile headers.
//   - defaultLocale: Operator-configured default locale fallback.
//
// # Returns
//
// A canonical locale code guaranteed to exist in SupportedLocales.
//
// # Concurrency
//
// Safe for concurrent use by multiple goroutines.
//
// # Example
//
//	loc := i18n.Negotiate("", "", "es-AR,fr-CA;q=0.8,en;q=0.5", "en")
//	fmt.Println(loc) // es
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/i18n/i18n_test.go:316 (direct call)
//   - internal/i18n/i18n_test.go:420 (direct call)
//   - internal/i18n/i18n_test.go:453 (direct call)
//   - internal/i18n/i18n_test.go:454 (direct call)
//   - internal/waitingroom/config.go:540 (direct call)
//   - internal/waitingroom/render.go:112 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func Negotiate(queryLang, cookieLang, acceptLanguage, defaultLocale string) string {
	if matched, ok := matchTag(queryLang); ok {
		return matched
	}
	if matched, ok := matchTag(cookieLang); ok {
		return matched
	}
	if matched, ok := matchAcceptLanguage(acceptLanguage); ok {
		return matched
	}
	if matched, ok := matchTag(defaultLocale); ok {
		return matched
	}
	return DefaultLocale
}

// Dir returns the HTML writing direction ("rtl" or "ltr") for locale.
// Right-to-left locales ("ar", "he", "fa", "arc", and their regional variants)
// return "rtl"; all other inputs return "ltr".
//
// # Parameters
//
//   - locale: Canonical or variant BCP-47 locale tag.
//
// # Returns
//
// DirRTL ("rtl") for Arabic, Hebrew, Persian, and Aramaic; DirLTR ("ltr") otherwise.
//
// # Concurrency
//
// Safe for concurrent use by multiple goroutines.
//
// # Example
//
//	fmt.Println(i18n.Dir("arc")) // rtl
//	fmt.Println(i18n.Dir("en"))  // ltr
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/i18n/i18n_test.go:60 (direct call)
//   - internal/i18n/i18n_test.go:77 (direct call)
//   - internal/i18n/i18n_test.go:360 (direct call)
//   - internal/i18n/i18n_test.go:424 (direct call)
//   - internal/i18n/i18n_test.go:455 (direct call)
//   - internal/waitingroom/render.go:113 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func Dir(locale string) string {
	if matched, ok := matchTag(locale); ok {
		if info, exists := localeByLower[strings.ToLower(matched)]; exists {
			return info.Dir
		}
	}
	return DirLTR
}

// Catalog returns a fresh copy of the full translation map for locale.
// Unknown or variant tags fall back through BCP-47 resolution to DefaultLocale ("en").
//
// # Parameters
//
//   - locale: Canonical or variant BCP-47 locale tag.
//
// # Returns
//
// A newly allocated map[string]string owned by the caller. Mutating the returned
// map does not affect internal package tables or other callers.
//
// # Concurrency
//
// Safe for concurrent use by multiple goroutines.
//
// # Example
//
//	cat := i18n.Catalog("fr-CA")
//	fmt.Println(cat["status.saved"])
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/i18n/i18n_test.go:109 (direct call)
//   - internal/i18n/i18n_test.go:115 (direct call)
//   - internal/i18n/i18n_test.go:427 (direct call)
//   - internal/waitingroom/render.go:114 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func Catalog(locale string) map[string]string {
	resolved := DefaultLocale
	if matched, ok := matchTag(locale); ok {
		resolved = matched
	}
	src, ok := catalogs[resolved]
	if !ok {
		src = catalogs[DefaultLocale]
	}
	return maps.Clone(src)
}

// T looks up a single translated string for key in locale.
// If locale is unknown, it falls back through BCP-47 resolution to "en".
// If key is absent in the resolved catalog, it checks "en", and if still absent
// returns key unchanged so callers never receive an empty UI label unexpectedly.
//
// # Parameters
//
//   - locale: Canonical or variant BCP-47 locale tag.
//   - key: Translation message key (for example "status.saved").
//
// # Returns
//
// The localized string for key, the English fallback if missing in locale, or
// key itself if unknown.
//
// # Concurrency
//
// Safe for concurrent use by multiple goroutines.
//
// # Example
//
//	label := i18n.T("ja", "status.saved")
//	fmt.Println(label)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/i18n/i18n_test.go:128 (direct call)
//   - internal/i18n/i18n_test.go:141 (direct call)
//   - internal/i18n/i18n_test.go:146 (direct call)
//   - internal/i18n/i18n_test.go:382 (direct call)
//   - internal/i18n/i18n_test.go:385 (direct call)
//   - internal/i18n/i18n_test.go:429 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func T(locale, key string) string {
	resolved := DefaultLocale
	if matched, ok := matchTag(locale); ok {
		resolved = matched
	}
	if cat, ok := catalogs[resolved]; ok {
		if val, exists := cat[key]; exists && val != "" {
			return val
		}
	}
	if val, exists := catalogs[DefaultLocale][key]; exists && val != "" {
		return val
	}
	return key
}

// normalizeTag trims whitespace, replaces "_" with "-", and lowercases raw for
// canonical BCP-47 matching. Tags containing control characters or exceeding 35
// bytes (RFC 5646 practical bound) are rejected as empty.
//
// # Parameters
//
//   - raw: Unvalidated BCP-47 tag candidate.
//
// # Returns
//
// Normalized lowercase hyphen-separated tag, or "" when raw is empty or invalid.
//
// # Example
//
//	norm := normalizeTag(" es_MX ") // "es-mx"
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/i18n/i18n.go:190 (direct call)
//   - internal/i18n/i18n.go:474 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func normalizeTag(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 35 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		if c == '_' {
			c = '-'
		}
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + ('a' - 'A'))
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-':
			b.WriteByte(c)
		default:
			return ""
		}
	}
	out := b.String()
	if strings.HasPrefix(out, "-") || strings.HasSuffix(out, "-") || strings.Contains(out, "--") {
		return ""
	}
	return out
}

// matchTag resolves a single BCP-47 language tag to one of the 19 canonical
// supported locale codes using exact match, script/region alias lookup, and
// progressively shorter subtag prefix fallback.
//
// # Parameters
//
//   - raw: Single BCP-47 tag candidate (for example "es-AR" or "zh-Hans-SG").
//
// # Returns
//
// The matched canonical locale code and true on success, or ("", false) if raw
// does not resolve to any supported locale.
//
// # Example
//
//	code, ok := matchTag("fr-BE") // "fr", true
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/i18n/i18n.go:239 (direct call)
//   - internal/i18n/i18n.go:242 (direct call)
//   - internal/i18n/i18n.go:248 (direct call)
//   - internal/i18n/i18n.go:288 (direct call)
//   - internal/i18n/i18n.go:329 (direct call)
//   - internal/i18n/i18n.go:377 (direct call)
//   - internal/i18n/i18n.go:577 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func matchTag(raw string) (string, bool) {
	norm := normalizeTag(raw)
	if norm == "" || norm == "*" {
		return "", false
	}

	// 1. Exact canonical match (preserves es-MX vs es, fr-CA vs fr, zh-CN).
	if info, ok := localeByLower[norm]; ok {
		return info.Code, true
	}

	// 2. Direct alias match (e.g. "zh-hans" -> "zh-CN", "syr" -> "arc").
	if target, ok := tagAliases[norm]; ok {
		return target, true
	}

	// 3. Progressive subtag stripping: e.g. "zh-hans-sg" -> "zh-hans" -> "zh",
	//    "es-ar" -> "es", "fr-be" -> "fr", "arc-syrc" -> "arc".
	cur := norm
	for {
		idx := strings.LastIndexByte(cur, '-')
		if idx <= 0 {
			break
		}
		cur = cur[:idx]
		if info, ok := localeByLower[cur]; ok {
			return info.Code, true
		}
		if target, ok := tagAliases[cur]; ok {
			return target, true
		}
	}
	return "", false
}

// matchAcceptLanguage parses a bounded RFC 9110 Accept-Language header, sorts
// valid non-zero quality entries stably in descending preference order, and
// returns the first tag that resolves to a supported locale.
//
// # Parameters
//
//   - header: Raw Accept-Language header value.
//
// # Returns
//
// The highest-priority matched canonical locale code and true, or ("", false)
// when no tag in header matches a supported locale.
//
// # Example
//
//	code, ok := matchAcceptLanguage("de-AT;q=0.9, en-US;q=0.8") // "de", true
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/i18n/i18n.go:245 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func matchAcceptLanguage(header string) (string, bool) {
	if header == "" {
		return "", false
	}
	if len(header) > maxAcceptLanguageBytes {
		header = header[:maxAcceptLanguageBytes]
	}

	entries := make([]acceptEntry, 0, 8)
	order := 0
	for part := range strings.SplitSeq(header, ",") {
		if len(entries) >= maxAcceptLanguageTags {
			break
		}
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tagPart, params, hasParams := strings.Cut(part, ";")
		tagPart = strings.TrimSpace(tagPart)
		if tagPart == "" || tagPart == "*" {
			continue
		}
		q := 1.0
		valid := true
		if hasParams {
			q, valid = parseQuality(params)
		}
		if !valid || q <= 0 {
			continue
		}
		entries = append(entries, acceptEntry{
			tag:   tagPart,
			q:     q,
			order: order,
		})
		order++
	}

	// Preserve original header order for equal quality weights.
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].q > entries[j].q
	})

	for _, e := range entries {
		if matched, ok := matchTag(e.tag); ok {
			return matched, true
		}
	}
	return "", false
}

// parseQuality extracts an RFC 9110 q-value parameter (for example "q=0.8")
// from the semicolon-delimited parameter suffix of an Accept-Language entry.
//
// # Parameters
//
//   - params: Parameter portion following the first ';' in an Accept-Language item.
//
// # Returns
//
// The parsed quality value in [0.0, 1.0] and true when valid; (0, false) if any
// q-parameter is malformed or out of range. If no q parameter appears, returns
// (1.0, true).
//
// # Example
//
//	q, ok := parseQuality("q=0.75") // 0.75, true
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/i18n/i18n.go:558 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func parseQuality(params string) (float64, bool) {
	q := 1.0
	for param := range strings.SplitSeq(params, ";") {
		param = strings.TrimSpace(param)
		if param == "" {
			continue
		}
		k, v, ok := strings.Cut(param, "=")
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(k), "q") {
			continue
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || parsed < 0 || parsed > 1 {
			return 0, false
		}
		q = parsed
	}
	return q, true
}
