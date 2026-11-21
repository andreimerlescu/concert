// Package testsite is a deterministic fake shop for tests: product pages
// linked several layers deep, and every kind of file an electronic-commerce
// site serves (stylesheets with fonts and background images, scripts,
// images in every common format, audio, video, archives, documents, text
// and data). Files are served with http.ServeContent, so byte ranges, ETags,
// If-None-Match, If-Modified-Since and HEAD behave as on a real server.
//
// It can also behave like an overloaded application: PageLimit refuses
// pages beyond a fixed concurrency with 503, and PageDelay slows every page.
package testsite

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// File is one static file of the site.
type File struct {
	Path        string
	ContentType string
	Class       string // the bench package's class name for it
	Body        []byte
	SHA256      [32]byte
	// Gzip, when set, is served instead of Body to clients that accept
	// gzip, with Content-Encoding: gzip, as a CDN-style precompressed file.
	Gzip []byte
}

// Options shape the site.
type Options struct {
	Pages     int           // product pages besides the home page (default 30)
	Fanout    int           // links per page (default 4)
	MediaSize int           // bytes of each audio file; video is 4× (default 256 KiB)
	PageLimit int           // pages served at once before 503 (0: unlimited)
	PageDelay time.Duration // added to every page
	Seed      uint64
}

// Site is the fake shop.
type Site struct {
	Options
	Files map[string]*File
	mod   time.Time

	inFlight atomic.Int64
	peak     atomic.Int64
	refused  atomic.Int64
	served   atomic.Int64

	mu       sync.Mutex
	pageHits map[string]int
}

// New builds a site.
func New(o Options) *Site {
	if o.Pages == 0 {
		o.Pages = 30
	}
	if o.Fanout == 0 {
		o.Fanout = 4
	}
	if o.MediaSize == 0 {
		o.MediaSize = 256 << 10
	}
	if o.Seed == 0 {
		o.Seed = 42
	}
	s := &Site{Options: o, Files: map[string]*File{}, mod: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), pageHits: map[string]int{}}
	rng := rand.New(rand.NewPCG(o.Seed, 7))
	blob := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(rng.Uint32())
		}
		return b
	}
	add := func(path, ct, class string, body []byte) *File {
		f := &File{Path: path, ContentType: ct, Class: class, Body: body, SHA256: sha256.Sum256(body)}
		s.Files[path] = f
		return f
	}
	add("/static/css/site.css", "text/css; charset=utf-8", "style",
		[]byte("@import \"/static/css/print.css\";\n@font-face{font-family:Shop;src:url(/static/fonts/shop.woff2) format(\"woff2\"),url('/static/fonts/shop.woff') format(\"woff\"),url(/static/fonts/shop.ttf)}\nbody{background:url(\"/static/img/bg.webp\")}\n"))
	add("/static/css/print.css", "text/css; charset=utf-8", "style", []byte("@media print{nav{display:none}}\n"))
	app := add("/static/js/app.js", "text/javascript; charset=utf-8", "script",
		[]byte(strings.Repeat("window.shop=window.shop||{};shop.cart=[];\n", 400)))
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(app.Body)
	_ = zw.Close()
	app.Gzip = gz.Bytes()
	add("/static/js/vendor.mjs", "text/javascript; charset=utf-8", "script", []byte("export const v=1;\n"))
	add("/static/fonts/shop.woff2", "font/woff2", "font", blob(24<<10))
	add("/static/fonts/shop.woff", "font/woff", "font", blob(28<<10))
	add("/static/fonts/shop.ttf", "font/ttf", "font", blob(40<<10))
	add("/static/img/bg.webp", "image/webp", "image", blob(12<<10))
	add("/static/img/logo.svg", "image/svg+xml", "image", []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10"/></svg>`))
	add("/static/img/favicon.ico", "image/x-icon", "image", blob(1<<10))
	add("/static/img/hero.avif", "image/avif", "image", blob(30<<10))
	add("/static/img/spinner.gif", "image/gif", "image", blob(3<<10))
	add("/media/audio/jingle.mp3", "audio/mpeg", "audio", blob(o.MediaSize))
	add("/media/audio/jingle.ogg", "audio/ogg", "audio", blob(o.MediaSize))
	add("/media/video/demo.mp4", "video/mp4", "video", blob(4*o.MediaSize))
	add("/media/video/demo.webm", "video/webm", "video", blob(4*o.MediaSize))
	add("/media/video/demo.vtt", "text/vtt; charset=utf-8", "text", []byte("WEBVTT\n\n00:00.000 --> 00:01.000\nHello\n"))
	add("/downloads/catalog.zip", "application/zip", "archive", blob(64<<10))
	add("/downloads/assets.tar.gz", "application/gzip", "archive", blob(48<<10))
	add("/downloads/manual.pdf", "application/pdf", "document", blob(80<<10))
	add("/downloads/prices.csv", "text/csv; charset=utf-8", "text", []byte("sku,price\nA,1\nB,2\n"))
	add("/files/readme.txt", "text/plain; charset=utf-8", "text", []byte("Thanks for shopping.\n"))
	add("/api/products.json", "application/json", "data", []byte(`{"products":[1,2,3]}`))
	add("/feed.xml", "application/xml", "data", []byte(`<?xml version="1.0"?><rss/>`))
	add("/manifest.webmanifest", "application/manifest+json", "data", []byte(`{"name":"Shop"}`))
	for i := 0; i < o.Pages; i++ {
		ext := []string{".jpg", ".png", ".webp", ".gif"}[i%4]
		ct := map[string]string{".jpg": "image/jpeg", ".png": "image/png", ".webp": "image/webp", ".gif": "image/gif"}[ext]
		add(fmt.Sprintf("/static/img/product-%d%s", i, ext), ct, "image", blob(6<<10+i*97))
	}
	return s
}

// PagePaths are the site's pages: / and /p/0 … /p/N-1.
func (s *Site) PagePaths() []string {
	out := []string{"/"}
	for i := 0; i < s.Pages; i++ {
		out = append(out, "/p/"+strconv.Itoa(i))
	}
	return out
}

// FilePaths are the site's files, sorted.
func (s *Site) FilePaths() []string {
	out := make([]string, 0, len(s.Files))
	for p := range s.Files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Peak is the most pages served at once; Refused how many were refused.
func (s *Site) Peak() int64    { return s.peak.Load() }
func (s *Site) Refused() int64 { return s.refused.Load() }
func (s *Site) Served() int64  { return s.served.Load() }

// PageHits is how often each page was served.
func (s *Site) PageHits() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.pageHits))
	for k, v := range s.pageHits {
		out[k] = v
	}
	return out
}

// page renders a page: links to the next Fanout pages (a tree deeper than
// the crawl depth), one broken link, the shared assets and its product
// image, audio and video.
func (s *Site) page(i int) []byte {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>Shop</title>`)
	b.WriteString(`<link rel="stylesheet" href="/static/css/site.css"><link rel="icon" href="/static/img/favicon.ico">`)
	b.WriteString(`<link rel="manifest" href="/manifest.webmanifest"><script type="module" src="/static/js/vendor.mjs"></script>`)
	b.WriteString(`<script src="/static/js/app.js" defer></script></head><body><nav><a href="/">Home</a> <a href="#top">Top</a> `)
	b.WriteString(`<a href="mailto:shop@example.com">Mail</a> <a href="https://elsewhere.example/">Away</a> <a href="/gone">Old sale</a></nav>`)
	b.WriteString(`<img src="/static/img/logo.svg" alt=""><picture><source srcset="/static/img/hero.avif 1x"><img src="/static/img/spinner.gif" alt=""></picture>`)
	for k := 1; k <= s.Fanout; k++ {
		n := (i*s.Fanout + k) % s.Pages
		fmt.Fprintf(&b, `<a href="/p/%d">Product %d</a> `, n, n)
	}
	if i >= 0 {
		ext := []string{".jpg", ".png", ".webp", ".gif"}[i%4]
		fmt.Fprintf(&b, `<img src="/static/img/product-%d%s" alt="">`, i, ext)
	}
	b.WriteString(`<audio src="/media/audio/jingle.mp3"></audio><audio><source src="/media/audio/jingle.ogg"></audio>`)
	b.WriteString(`<video poster="/static/img/bg.webp"><source src="/media/video/demo.mp4"><source src="/media/video/demo.webm"><track src="/media/video/demo.vtt"></video>`)
	b.WriteString(`<a href="/downloads/catalog.zip">Catalog</a> <a href="/downloads/manual.pdf">Manual</a> <a href="/downloads/assets.tar.gz">Press kit</a>`)
	b.WriteString(`<a href="/downloads/prices.csv">Prices</a> <a href="/files/readme.txt">Readme</a>`)
	b.WriteString(`<div style="background:url(/static/img/bg.webp)"></div></body></html>`)
	return []byte(b.String())
}

// ServeHTTP serves the site.
func (s *Site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f, ok := s.Files[r.URL.Path]; ok {
		s.served.Add(1)
		w.Header().Set("Content-Type", f.ContentType)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("ETag", fmt.Sprintf(`"%x"`, f.SHA256[:8]))
		body := f.Body
		if f.Gzip != nil {
			w.Header().Add("Vary", "Accept-Encoding")
			if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && r.Header.Get("Range") == "" {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("ETag", fmt.Sprintf(`"%x-gz"`, f.SHA256[:8]))
				body = f.Gzip
			}
		}
		http.ServeContent(w, r, f.Path, s.mod, bytes.NewReader(body))
		return
	}
	idx := -1
	switch {
	case r.URL.Path == "/":
		idx = 0
	case strings.HasPrefix(r.URL.Path, "/p/"):
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/p/"))
		if err != nil || n < 0 || n >= s.Pages {
			http.NotFound(w, r)
			return
		}
		idx = n
	default:
		http.NotFound(w, r)
		return
	}
	n := s.inFlight.Add(1)
	defer s.inFlight.Add(-1)
	for {
		p := s.peak.Load()
		if n <= p || s.peak.CompareAndSwap(p, n) {
			break
		}
	}
	if s.PageLimit > 0 && n > int64(s.PageLimit) {
		s.refused.Add(1)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	if s.PageDelay > 0 {
		time.Sleep(s.PageDelay)
	}
	s.mu.Lock()
	s.pageHits[r.URL.Path]++
	s.mu.Unlock()
	s.served.Add(1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(s.page(idx))
}
