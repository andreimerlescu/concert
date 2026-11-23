package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func writeDiskFile(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestStaticOffload_PassGatedAssetsZeroOriginLoad(t *testing.T) {
	var originHits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>dynamic page</body></html>"))
	}))
	defer origin.Close()

	root := t.TempDir()
	css := bytes.Repeat([]byte("body{margin:0;padding:0;}\n"), 80) // > 1 KiB
	writeDiskFile(t, filepath.Join(root, "wp-content", "themes", "site.css"), css)
	writeDiskFile(t, filepath.Join(root, "wp-content", "media", "clip.mp4"), []byte("0123456789abcdefghij"))
	writeDiskFile(t, filepath.Join(root, "robots.txt"), []byte("User-agent: *\nDisallow:\n"))
	writeDiskFile(t, filepath.Join(root, ".env"), []byte("DB_PASS=secret"))
	writeDiskFile(t, filepath.Join(root, "wp-config.php"), []byte("<?php define('SECRET','top');"))

	cfg := testConfig(origin.URL)
	cfg.staticRoot = root
	cfg.assets = "/wp-content/*"
	cfg.staticCacheControl = "public, max-age=3600"
	cfg.compress = true
	a, front := newTestApp(t, cfg, nil)

	// 1. Private asset without pass -> 403, zero origin hits.
	rawCli := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	resp, err := rawCli.Get(front.URL + "/wp-content/themes/site.css")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("asset without pass: status=%d, want 403", resp.StatusCode)
	}

	// 2. Visit dynamic page -> hits origin once and receives concert_admit pass.
	resp, err = rawCli.Get(front.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page status=%d", resp.StatusCode)
	}
	var admitCk *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == admitCookie {
			admitCk = c
		}
	}
	if admitCk == nil {
		t.Fatal("dynamic page did not issue concert_admit pass")
	}
	if originHits.Load() != 1 {
		t.Fatalf("originHits = %d, want 1", originHits.Load())
	}

	// 3. Private asset WITH pass -> served straight from disk (gzipped), zero extra origin hits.
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/wp-content/themes/site.css", nil)
	req.AddCookie(admitCk)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err = rawCli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	gzBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("static css: status=%d enc=%q", resp.StatusCode, resp.Header.Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(bytes.NewReader(gzBody))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(zr)
	_ = zr.Close()
	if !bytes.Equal(plain, css) {
		t.Fatal("static css decompressed mismatch")
	}

	// 4. Range 206 on media file -> served from disk, zero origin hits.
	reqR, _ := http.NewRequest(http.MethodGet, front.URL+"/wp-content/media/clip.mp4", nil)
	reqR.AddCookie(admitCk)
	reqR.Header.Set("Range", "bytes=5-14")
	resp, err = rawCli.Do(reqR)
	if err != nil {
		t.Fatal(err)
	}
	rBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent || string(rBody) != "56789abcde" {
		t.Fatalf("range: status=%d body=%q", resp.StatusCode, string(rBody))
	}

	// 5. Missing file under -assets -> fast 404, zero origin hits.
	req404, _ := http.NewRequest(http.MethodGet, front.URL+"/wp-content/themes/missing.css", nil)
	req404.AddCookie(admitCk)
	resp, err = rawCli.Do(req404)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing static asset: status=%d, want 404", resp.StatusCode)
	}

	// 6. Root static file outside -assets (/robots.txt) -> served from disk off waiting room, zero origin hits.
	resp, err = rawCli.Get(front.URL + "/robots.txt")
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(rb), "User-agent") {
		t.Fatalf("robots.txt: status=%d body=%q", resp.StatusCode, string(rb))
	}

	// 7. Dotfile /.env -> 404 without touching origin.
	resp, err = rawCli.Get(front.URL + "/.env")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/.env: status=%d, want 404", resp.StatusCode)
	}

	if originHits.Load() != 1 {
		t.Fatalf("static offload leaked requests to origin: originHits=%d, want 1", originHits.Load())
	}
	if a.stats.staticServed.Load() != 3 || a.stats.staticNotFound.Load() != 1 {
		t.Fatalf("stats staticServed=%d staticNotFound=%d, want 3, 1", a.stats.staticServed.Load(), a.stats.staticNotFound.Load())
	}
}

func TestTLSHttpRedirect_HostValidationAndACME(t *testing.T) {
	cfg := config{
		listen:   ":443",
		tlsHosts: []string{"shop.example.com"},
	}
	h := httpsRedirectHandler(cfg, nil)

	// 1. Valid GET redirects 301 -> https://shop.example.com/cart?x=1
	req := httptest.NewRequest(http.MethodGet, "http://shop.example.com/cart?x=1", nil)
	req.Host = "shop.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "https://shop.example.com/cart?x=1" {
		t.Fatalf("GET redirect: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	// 2. Valid POST redirects 308 (preserving method/body).
	req = httptest.NewRequest(http.MethodPost, "http://shop.example.com/webhook", nil)
	req.Host = "shop.example.com:80"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusPermanentRedirect || rec.Header().Get("Location") != "https://shop.example.com/webhook" {
		t.Fatalf("POST redirect: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	// 3. Spoofed Host rejected (421 Misdirected Request) to prevent open redirects.
	req = httptest.NewRequest(http.MethodGet, "http://evil.example/phish", nil)
	req.Host = "evil.example"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("spoofed Host: %d, want 421", rec.Code)
	}

	// 4. Malformed Host rejected (400).
	req = httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.Host = "bad host/evil"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed Host: %d, want 400", rec.Code)
	}
}

func TestPortal_StaticRootAndFcgiUnixLocked(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.staticRoot = t.TempDir()
	cfg.portal.listen = "127.0.0.1:0"
	cfg.portal.allowSpec = "127.0.0.1/32,::1/128"
	cfg.portal.sessionTTL = time.Hour
	cfg.portal.pass = testPortalPass
	_, p, _ := newTestPortal(t, cfg, up)
	ck, csrf := portalLogin(t, p)

	locked := []string{
		`{"static_root":"/etc"}`,
		`{"static_mounts":"/etc=/etc"}`,
		`{"tls_http_listen":":80"}`,
		`{"upstream":"fcgi+unix:///run/php-fpm/www.sock"}`,
	}
	if hasWordPressEdition() {
		locked = append(locked, `{"fcgi_deny_paths":""}`)
	}
	for _, body := range locked {
		rec := portalDo(p, http.MethodPost, "/api/settings", body, ck, csrf, false)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("portal accepted locked setting %s: status=%d body=%s", body, rec.Code, rec.Body.String())
		}
	}
}
