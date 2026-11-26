package i18n_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/andreimerlescu/concert/internal/i18n"
)

// TestSupportedLocales_All19Present verifies that all 19 required locales are
// registered with exact LTR/RTL directions and non-empty metadata.
//
// # Parameters
//
//   - t: Standard Go test handle.
//
// # Example
//
//	go test -run '^TestSupportedLocales_All19Present$' ./internal/i18n
//
// # Used By
//
// Invoked by `go test`.
func TestSupportedLocales_All19Present(t *testing.T) {
	t.Parallel()

	wantLTR := []string{
		"en", "es", "es-MX", "fr", "fr-CA", "ro", "ru", "tr",
		"de", "it", "ja", "zh-CN", "hi", "pl", "sr",
	}
	wantRTL := []string{"ar", "he", "fa", "arc"}

	locales := i18n.SupportedLocales()
	if got, want := len(locales), len(wantLTR)+len(wantRTL); got != want {
		t.Fatalf("len(SupportedLocales()) = %d, want %d", got, want)
	}

	seen := make(map[string]i18n.LocaleInfo, len(locales))
	for _, info := range locales {
		if info.Code == "" || info.Name == "" || info.NativeName == "" {
			t.Errorf("locale %+v has empty metadata field", info)
		}
		if _, dup := seen[info.Code]; dup {
			t.Errorf("duplicate locale code %q", info.Code)
		}
		seen[info.Code] = info
	}

	for _, code := range wantLTR {
		info, ok := seen[code]
		if !ok {
			t.Errorf("missing LTR locale %q", code)
			continue
		}
		if info.Dir != i18n.DirLTR {
			t.Errorf("LocaleInfo[%q].Dir = %q, want %q", code, info.Dir, i18n.DirLTR)
		}
		if got := i18n.Dir(code); got != i18n.DirLTR {
			t.Errorf("Dir(%q) = %q, want %q", code, got, i18n.DirLTR)
		}
		if !i18n.IsSupported(code) {
			t.Errorf("IsSupported(%q) = false, want true", code)
		}
	}

	for _, code := range wantRTL {
		info, ok := seen[code]
		if !ok {
			t.Errorf("missing RTL locale %q", code)
			continue
		}
		if info.Dir != i18n.DirRTL {
			t.Errorf("LocaleInfo[%q].Dir = %q, want %q", code, info.Dir, i18n.DirRTL)
		}
		if got := i18n.Dir(code); got != i18n.DirRTL {
			t.Errorf("Dir(%q) = %q, want %q", code, got, i18n.DirRTL)
		}
		if !i18n.IsSupported(code) {
			t.Errorf("IsSupported(%q) = false, want true", code)
		}
	}

	// Verify SupportedLocales returns a defensive copy.
	locales[0].Code = "mutated"
	if got := i18n.SupportedLocales()[0].Code; got != "en" {
		t.Fatalf("SupportedLocales()[0].Code mutated to %q, want %q", got, "en")
	}
}

// TestCatalogs_IdenticalKeysAndNonEmpty proves every one of the 19 locales has
// the exact same key set as English and zero empty or whitespace-only values.
//
// # Parameters
//
//   - t: Standard Go test handle.
//
// # Example
//
//	go test -run '^TestCatalogs_IdenticalKeysAndNonEmpty$' ./internal/i18n
//
// # Used By
//
// Invoked by `go test`.
func TestCatalogs_IdenticalKeysAndNonEmpty(t *testing.T) {
	t.Parallel()

	en := i18n.Catalog("en")
	if len(en) == 0 {
		t.Fatal("Catalog(\"en\") is empty")
	}

	for _, info := range i18n.SupportedLocales() {
		cat := i18n.Catalog(info.Code)
		if len(cat) != len(en) {
			t.Errorf("Catalog(%q) has %d keys, want %d", info.Code, len(cat), len(en))
		}
		for k := range en {
			v, ok := cat[k]
			if !ok {
				t.Errorf("Catalog(%q) missing key %q", info.Code, k)
				continue
			}
			if strings.TrimSpace(v) == "" {
				t.Errorf("Catalog(%q)[%q] is empty", info.Code, k)
			}
			if got := i18n.T(info.Code, k); got != v {
				t.Errorf("T(%q, %q) = %q, want %q", info.Code, k, got, v)
			}
		}
		for k := range cat {
			if _, ok := en[k]; !ok {
				t.Errorf("Catalog(%q) has extra key %q absent from en", info.Code, k)
			}
		}
	}

	// Verify Catalog returns an independent defensive copy.
	en["page.title"] = "mutated"
	if got := i18n.T("en", "page.title"); got == "mutated" {
		t.Fatal("mutating returned Catalog map corrupted internal package state")
	}

	// Verify Syriac script characters are present in Aramaic ("arc").
	arcTitle := i18n.T("arc", "page.title")
	hasSyriac := false
	for _, r := range arcTitle {
		if r >= 0x0700 && r <= 0x074F {
			hasSyriac = true
			break
		}
	}
	if !hasSyriac {
		t.Errorf("T(\"arc\", \"page.title\") = %q, expected Syriac script code points", arcTitle)
	}
}

// TestNegotiate_BCP47AndFallbacks exercises priority ordering, region/script
// fallbacks, quality weights, malformed headers, and hostile oversized input.
//
// # Parameters
//
//   - t: Standard Go test handle.
//
// # Example
//
//	go test -run '^TestNegotiate_BCP47AndFallbacks$' ./internal/i18n
//
// # Used By
//
// Invoked by `go test`.
func TestNegotiate_BCP47AndFallbacks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		queryLang      string
		cookieLang     string
		acceptLanguage string
		defaultLocale  string
		want           string
	}{
		{
			name:           "query overrides cookie and accept-language",
			queryLang:      "ja",
			cookieLang:     "de",
			acceptLanguage: "fr-CA,fr;q=0.9",
			defaultLocale:  "en",
			want:           "ja",
		},
		{
			name:           "cookie overrides accept-language",
			cookieLang:     "es-MX",
			acceptLanguage: "de-DE,de;q=0.9",
			defaultLocale:  "en",
			want:           "es-MX",
		},
		{
			name:           "region fallback es-AR to es",
			acceptLanguage: "es-AR,en;q=0.5",
			defaultLocale:  "en",
			want:           "es",
		},
		{
			name:           "exact es-MX preserved over generic es",
			acceptLanguage: "es-MX,es;q=0.9",
			defaultLocale:  "en",
			want:           "es-MX",
		},
		{
			name:           "region fallback fr-BE to fr",
			acceptLanguage: "fr-BE,en;q=0.5",
			defaultLocale:  "en",
			want:           "fr",
		},
		{
			name:           "exact fr-CA preserved",
			acceptLanguage: "fr-CA,fr;q=0.9",
			defaultLocale:  "en",
			want:           "fr-CA",
		},
		{
			name:           "script fallback zh-Hans to zh-CN",
			acceptLanguage: "zh-Hans,en;q=0.5",
			defaultLocale:  "en",
			want:           "zh-CN",
		},
		{
			name:           "script and region zh-Hans-SG to zh-CN",
			acceptLanguage: "zh-Hans-SG",
			defaultLocale:  "en",
			want:           "zh-CN",
		},
		{
			name:           "aramaic syriac subtag arc-Syrc to arc",
			acceptLanguage: "arc-Syrc",
			defaultLocale:  "en",
			want:           "arc",
		},
		{
			name:           "syriac ISO 639-2 alias syr to arc",
			acceptLanguage: "syr-IQ",
			defaultLocale:  "en",
			want:           "arc",
		},
		{
			name:           "legacy hebrew iw-IL to he",
			acceptLanguage: "iw-IL",
			defaultLocale:  "en",
			want:           "he",
		},
		{
			name:           "serbian script tag sr-Latn-RS to sr",
			acceptLanguage: "sr-Latn-RS",
			defaultLocale:  "en",
			want:           "sr",
		},
		{
			name:           "quality weights sort highest first",
			acceptLanguage: "de;q=0.4, pl-PL;q=0.9, ro;q=0.7",
			defaultLocale:  "en",
			want:           "pl",
		},
		{
			name:           "q=0 excluded",
			acceptLanguage: "fr;q=0, it;q=0.5",
			defaultLocale:  "en",
			want:           "it",
		},
		{
			name:           "invalid q ignored",
			acceptLanguage: "fr;q=9.9, tr;q=0.6",
			defaultLocale:  "en",
			want:           "tr",
		},
		{
			name:           "unknown falls back to defaultLocale",
			queryLang:      "xx-ZZ",
			cookieLang:     "yy",
			acceptLanguage: "zz-AA;q=1.0",
			defaultLocale:  "ro",
			want:           "ro",
		},
		{
			name:           "unknown defaultLocale falls back to en",
			queryLang:      "xx",
			cookieLang:     "",
			acceptLanguage: "zz",
			defaultLocale:  "invalid-locale",
			want:           "en",
		},
		{
			name:          "underscore separator normalized",
			queryLang:     "fr_ca",
			defaultLocale: "en",
			want:          "fr-CA",
		},
		{
			name:           "injection characters rejected cleanly",
			queryLang:      "en\"><script>alert(1)</script>",
			acceptLanguage: "ar-SA",
			defaultLocale:  "en",
			want:           "ar",
		},
		{
			name:           "oversized accept-language bounded safely",
			acceptLanguage: strings.Repeat("xx-YY,", 400) + "he",
			defaultLocale:  "de",
			want:           "de",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := i18n.Negotiate(tt.queryLang, tt.cookieLang, tt.acceptLanguage, tt.defaultLocale)
			if got != tt.want {
				t.Errorf("Negotiate(%q, %q, %q, %q) = %q, want %q",
					tt.queryLang, tt.cookieLang, tt.acceptLanguage, tt.defaultLocale, got, tt.want)
			}
		})
	}
}

// TestDir_VariantsAndUnknown verifies RTL/LTR direction resolution across
// regional variants and unknown tags.
//
// # Parameters
//
//   - t: Standard Go test handle.
//
// # Example
//
//	go test -run '^TestDir_VariantsAndUnknown$' ./internal/i18n
//
// # Used By
//
// Invoked by `go test`.
func TestDir_VariantsAndUnknown(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"ar":       i18n.DirRTL,
		"ar-SA":    i18n.DirRTL,
		"he":       i18n.DirRTL,
		"he-IL":    i18n.DirRTL,
		"iw":       i18n.DirRTL,
		"fa":       i18n.DirRTL,
		"fa-IR":    i18n.DirRTL,
		"arc":      i18n.DirRTL,
		"arc-Syrc": i18n.DirRTL,
		"syr":      i18n.DirRTL,
		"en":       i18n.DirLTR,
		"es-MX":    i18n.DirLTR,
		"zh-Hans":  i18n.DirLTR,
		"unknown":  i18n.DirLTR,
		"":         i18n.DirLTR,
	}
	for loc, want := range cases {
		if got := i18n.Dir(loc); got != want {
			t.Errorf("Dir(%q) = %q, want %q", loc, got, want)
		}
	}
}

// TestT_Fallbacks verifies missing-key and unknown-locale fallback behavior.
//
// # Parameters
//
//   - t: Standard Go test handle.
//
// # Example
//
//	go test -run '^TestT_Fallbacks$' ./internal/i18n
//
// # Used By
//
// Invoked by `go test`.
func TestT_Fallbacks(t *testing.T) {
	t.Parallel()

	if got, want := i18n.T("unknown-locale", "page.title"), i18n.T("en", "page.title"); got != want {
		t.Errorf("T(unknown, page.title) = %q, want %q", got, want)
	}
	if got, want := i18n.T("en", "nonexistent.key"), "nonexistent.key"; got != want {
		t.Errorf("T(en, nonexistent.key) = %q, want %q", got, want)
	}
}

// TestConcurrency_RaceFree exercises all package functions concurrently across
// 32 goroutines under -race while callers mutate their returned copies.
//
// # Parameters
//
//   - t: Standard Go test handle.
//
// # Example
//
//	go test -race -run '^TestConcurrency_RaceFree$' ./internal/i18n
//
// # Used By
//
// Invoked by `go test`.
func TestConcurrency_RaceFree(t *testing.T) {
	t.Parallel()

	const workers = 32
	const iters = 100
	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := range workers {
		wg.Go(func() {
			<-start
			for j := range iters {
				locales := i18n.SupportedLocales()
				loc := locales[(i+j)%len(locales)]
				locales[0].Code = "scratch"

				got := i18n.Negotiate("", "", "es-AR,fr-CA;q=0.8,arc;q=0.7", loc.Code)
				if got != "es" {
					t.Errorf("unexpected Negotiate result: %q", got)
				}
				if dir := i18n.Dir(loc.Code); dir != loc.Dir {
					t.Errorf("Dir(%q) = %q, want %q", loc.Code, dir, loc.Dir)
				}
				cat := i18n.Catalog(loc.Code)
				cat["page.title"] = "scratch"
				if i18n.T(loc.Code, "page.title") == "" {
					t.Errorf("empty T(%q, page.title)", loc.Code)
				}
			}
		})
	}
	close(start)
	wg.Wait()
}

// ExampleNegotiate demonstrates BCP-47 locale negotiation with region fallback.
//
// # Parameters
//
// None. Executed by `go test`.
//
// # Example
//
//	go test -run '^ExampleNegotiate$' ./internal/i18n
//
// # Used By
//
// Invoked by `go test`.
func ExampleNegotiate() {
	fmt.Println(i18n.Negotiate("", "", "es-AR,fr-CA;q=0.9,en;q=0.5", "en"))
	fmt.Println(i18n.Negotiate("", "", "zh-Hans", "en"))
	fmt.Println(i18n.Dir("arc"))
	// Output:
	// es
	// zh-CN
	// rtl
}
