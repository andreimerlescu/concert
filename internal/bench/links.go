package bench

import (
	"bytes"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// Kind is what a URL found on a page is to the crawler.
type Kind int

const (
	KindPage  Kind = iota // a link a visitor follows: crawled
	KindAsset             // something a page loads: fetched, not crawled
)

// found is one URL extracted from a page.
type found struct {
	url  string
	kind Kind
}

// assetAttrs are the attributes that make a browser load something, per
// element. Everything else with an href is a link.
var assetAttrs = map[string][]string{
	"img":    {"src", "srcset", "data-src"},
	"script": {"src"},
	"source": {"src", "srcset"},
	"video":  {"src", "poster"},
	"audio":  {"src"},
	"track":  {"src"},
	"embed":  {"src"},
	"object": {"data"},
	"input":  {"src"},
	"iframe": {"src"},
}

// linkRels are <link rel> values that make a browser fetch the target.
var linkRels = map[string]bool{
	"stylesheet": true, "icon": true, "shortcut": true, "apple-touch-icon": true,
	"preload": true, "modulepreload": true, "prefetch": true, "manifest": true,
}

var cssURL = regexp.MustCompile(`url\(\s*['"]?([^'")\s]+)['"]?\s*\)`)
var cssImport = regexp.MustCompile(`@import\s+['"]([^'"]+)['"]`)

// extractHTML returns the same-host pages and assets an HTML document
// references, resolved against base (and any <base href>). It reads at most
// limit bytes of r.
func extractHTML(r io.Reader, base *url.URL, limit int64) []found {
	z := html.NewTokenizer(io.LimitReader(r, limit))
	var out []found
	seen := map[string]bool{}
	add := func(raw string, k Kind) {
		u, ok := resolve(base, raw)
		if !ok || seen[u] {
			return
		}
		seen[u] = true
		if k == KindPage && looksLikeAsset(u) {
			k = KindAsset
		}
		out = append(out, found{u, k})
	}
	inStyle := false
	for {
		switch z.Next() {
		case html.ErrorToken:
			return out
		case html.TextToken:
			if inStyle {
				for _, m := range extractCSSRefs(z.Text()) {
					add(m, KindAsset)
				}
			}
		case html.EndTagToken:
			if name, _ := z.TagName(); string(name) == "style" {
				inStyle = false
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			if tag == "style" {
				inStyle = true
			}
			attrs := map[string]string{}
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				attrs[string(k)] = string(v)
			}
			if style := attrs["style"]; style != "" {
				for _, m := range extractCSSRefs([]byte(style)) {
					add(m, KindAsset)
				}
			}
			switch tag {
			case "base":
				if h := attrs["href"]; h != "" {
					if u, err := base.Parse(h); err == nil {
						base = u
					}
				}
			case "a", "area":
				if h := attrs["href"]; h != "" {
					add(h, KindPage)
				}
			case "link":
				if h := attrs["href"]; h != "" {
					fetch := false
					for _, rel := range strings.Fields(strings.ToLower(attrs["rel"])) {
						if linkRels[rel] {
							fetch = true
						}
					}
					if fetch {
						add(h, KindAsset)
					}
				}
			default:
				for _, a := range assetAttrs[tag] {
					v := attrs[a]
					if v == "" {
						continue
					}
					if strings.HasSuffix(a, "srcset") {
						for _, cand := range strings.Split(v, ",") {
							if f := strings.Fields(cand); len(f) > 0 {
								add(f[0], KindAsset)
							}
						}
						continue
					}
					add(v, KindAsset)
				}
			}
		}
	}
}

// extractCSSRefs returns url(...) and @import targets in a stylesheet.
func extractCSSRefs(b []byte) []string {
	var out []string
	for _, m := range cssURL.FindAllSubmatch(b, -1) {
		out = append(out, string(m[1]))
	}
	for _, m := range cssImport.FindAllSubmatch(b, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

// extractCSS returns the same-host assets a stylesheet references.
func extractCSS(b []byte, base *url.URL) []found {
	var out []found
	seen := map[string]bool{}
	for _, raw := range extractCSSRefs(b) {
		if u, ok := resolve(base, raw); ok && !seen[u] {
			seen[u] = true
			out = append(out, found{u, KindAsset})
		}
	}
	return out
}

// resolve makes raw absolute against base and keeps it only if it is an
// http(s) URL on base's host. Fragments are dropped.
func resolve(base *url.URL, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "data:") {
		return "", false
	}
	lower := strings.ToLower(raw)
	for _, p := range []string{"mailto:", "tel:", "javascript:", "sms:", "blob:"} {
		if strings.HasPrefix(lower, p) {
			return "", false
		}
	}
	u, err := base.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Host, base.Host) {
		return "", false
	}
	u.Fragment, u.RawFragment = "", ""
	return u.String(), true
}

// looksLikeAsset reports a link whose extension says it is a file, not a
// page: a product's PDF, a download, an image link.
func looksLikeAsset(u string) bool {
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	return extClass(path.Ext(p.Path)) != ""
}

// isHTML reports whether a Content-Type is an HTML document.
func isHTML(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/html") || strings.HasPrefix(ct, "application/xhtml")
}

func isCSS(ct string) bool {
	return strings.HasPrefix(strings.ToLower(ct), "text/css")
}

// sniffHTML reports whether a body without a Content-Type looks like HTML.
func sniffHTML(b []byte) bool {
	b = bytes.TrimSpace(b)
	if len(b) > 512 {
		b = b[:512]
	}
	l := bytes.ToLower(b)
	return bytes.HasPrefix(l, []byte("<!doctype html")) || bytes.HasPrefix(l, []byte("<html"))
}
