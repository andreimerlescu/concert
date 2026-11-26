package static

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func mustWriteFile(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestStatic_SecurityInvariants(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	mustWriteFile(t, filepath.Join(outside, "secret.txt"), []byte("HOST-SECRET"))
	mustWriteFile(t, filepath.Join(root, "wp-config.php"), []byte("<?php define('DB_PASSWORD','hunter2');"))
	mustWriteFile(t, filepath.Join(root, "wp-config.php.bak"), []byte("backup-secret"))
	mustWriteFile(t, filepath.Join(root, ".env"), []byte("API_KEY=12345"))
	mustWriteFile(t, filepath.Join(root, ".git", "config"), []byte("[core]"))
	mustWriteFile(t, filepath.Join(root, "wp-content", "debug.log"), []byte("stack trace"))
	mustWriteFile(t, filepath.Join(root, "dump.sql"), []byte("CREATE TABLE users"))
	mustWriteFile(t, filepath.Join(root, "wp-content", "themes", "style.css"), []byte("body{color:#111}"))
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "escape.txt")); err != nil {
		t.Fatal(err)
	}

	s, err := New(Config{Root: root, CacheControl: "public, max-age=3600", Compress: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	cases := []struct {
		name string
		path string
		auth bool
		want Result
	}{
		{"php source never served", "/wp-config.php", false, ResultPassThrough},
		{"php under assets passes through", "/wp-config.php", true, ResultPassThrough},
		{"dotfile .env blocked", "/.env", false, ResultForbidden},
		{"dotdir .git/config blocked", "/.git/config", false, ResultForbidden},
		{"traversal blocked", "/../secret.txt", false, ResultForbidden},
		{"backslash blocked", `/wp-content\style.css`, false, ResultForbidden},
		{"backup extension blocked", "/wp-config.php.bak", false, ResultForbidden},
		{"log extension blocked", "/wp-content/debug.log", true, ResultForbidden},
		{"sql dump blocked", "/dump.sql", false, ResultForbidden},
		{"symlink escaping os.Root refused", "/escape.txt", true, ResultNotFound},
		{"well-known passes through", "/.well-known/acme-challenge/tok", false, ResultPassThrough},
		{"directory listing refused", "/wp-content/", false, ResultPassThrough},
		{"valid css served", "/wp-content/themes/style.css", true, ResultServed},
		{"missing asset fast 404", "/wp-content/themes/missing.css", true, ResultNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
			req.URL.Path = tc.path
			rec := httptest.NewRecorder()
			got := s.Serve(rec, req, tc.auth)
			if got != tc.want {
				t.Fatalf("Serve(%q) = %v, want %v (body=%q)", tc.path, got, tc.want, rec.Body.String())
			}
			if got != ResultServed && rec.Body.Len() != 0 {
				t.Fatalf("non-served result wrote body: %q", rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "HOST-SECRET") || strings.Contains(rec.Body.String(), "hunter2") {
				t.Fatalf("secret leaked in response body")
			}
		})
	}
}

func TestStatic_ParseAllowExtBlocksForbidden(t *testing.T) {
	for _, bad := range []string{".php", "phtml", ".env", ".sql", ".bak", ".log", ".key"} {
		if _, err := ParseAllowExt(bad); err == nil {
			t.Errorf("ParseAllowExt(%q) succeeded, want error", bad)
		}
	}
	exts, err := ParseAllowExt("epub, .dmg")
	if err != nil || len(exts) != 2 || exts[0] != ".epub" || exts[1] != ".dmg" {
		t.Fatalf("ParseAllowExt valid: %v %v", exts, err)
	}
}

func TestStatic_PrecompressedSidecarGzipETagRange(t *testing.T) {
	root := t.TempDir()
	bigCSS := bytes.Repeat([]byte("body { background: #000; color: #fff; }\n"), 100) // ~4000 bytes
	mustWriteFile(t, filepath.Join(root, "app.css"), bigCSS)

	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write([]byte("precompressed-gz-payload"))
	_ = gw.Close()
	mustWriteFile(t, filepath.Join(root, "bundle.js"), []byte("console.log('plain');"))
	mustWriteFile(t, filepath.Join(root, "bundle.js.gz"), gzBuf.Bytes())
	mustWriteFile(t, filepath.Join(root, "bundle.js.br"), []byte("fake-brotli-bytes"))

	video := bytes.Repeat([]byte("0123456789"), 200) // 2000 bytes
	mustWriteFile(t, filepath.Join(root, "clip.mp4"), video)

	s, err := New(Config{Root: root, CacheControl: "public, max-age=3600", Compress: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// 1. Brotli sidecar preferred when both br and gzip are accepted.
	req := httptest.NewRequest(http.MethodGet, "http://example.test/bundle.js", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	rec := httptest.NewRecorder()
	if got := s.Serve(rec, req, true); got != ResultServed {
		t.Fatalf("br sidecar: got %v", got)
	}
	if rec.Header().Get("Content-Encoding") != "br" || rec.Body.String() != "fake-brotli-bytes" {
		t.Fatalf("br sidecar mismatch: enc=%q body=%q", rec.Header().Get("Content-Encoding"), rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("br sidecar wrong content-type: %q", rec.Header().Get("Content-Type"))
	}

	// 2. Gzip sidecar served when only gzip accepted.
	req = httptest.NewRequest(http.MethodGet, "http://example.test/bundle.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec = httptest.NewRecorder()
	if got := s.Serve(rec, req, true); got != ResultServed || rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("gz sidecar failed: got=%v enc=%q", got, rec.Header().Get("Content-Encoding"))
	}

	// 3. On-the-fly gzip for >= 1 KiB CSS with no sidecar, plus ETag 304.
	req = httptest.NewRequest(http.MethodGet, "http://example.test/app.css", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec = httptest.NewRecorder()
	if got := s.Serve(rec, req, true); got != ResultServed {
		t.Fatalf("on-the-fly gzip: got %v", got)
	}
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected Content-Encoding: gzip, got %q", rec.Header().Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("gzip decode: %v", err)
	}
	plain, _ := io.ReadAll(zr)
	_ = zr.Close()
	if !bytes.Equal(plain, bigCSS) {
		t.Fatal("decompressed body mismatch")
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}
	req304 := httptest.NewRequest(http.MethodGet, "http://example.test/app.css", nil)
	req304.Header.Set("Accept-Encoding", "gzip")
	req304.Header.Set("If-None-Match", etag)
	rec304 := httptest.NewRecorder()
	if got := s.Serve(rec304, req304, true); got != ResultServed || rec304.Code != http.StatusNotModified {
		t.Fatalf("304 check: got=%v code=%d", got, rec304.Code)
	}

	// 4. HTTP Range request returns 206 Partial Content without compression.
	reqR := httptest.NewRequest(http.MethodGet, "http://example.test/clip.mp4", nil)
	reqR.Header.Set("Range", "bytes=10-19")
	reqR.Header.Set("Accept-Encoding", "gzip")
	recR := httptest.NewRecorder()
	if got := s.Serve(recR, reqR, true); got != ResultServed || recR.Code != http.StatusPartialContent {
		t.Fatalf("range: got=%v code=%d", got, recR.Code)
	}
	if recR.Body.String() != "0123456789" {
		t.Fatalf("range body = %q, want 0123456789", recR.Body.String())
	}
}

func TestStatic_MountsLongestPrefixAndFallbackAndConcurrency(t *testing.T) {
	d1 := t.TempDir()
	d2 := t.TempDir()
	mustWriteFile(t, filepath.Join(d1, "a.css"), []byte("from-d1"))
	mustWriteFile(t, filepath.Join(d2, "a.css"), []byte("from-d2"))

	mounts, err := ParseMounts("/static=" + d1 + ",/static/v2=" + d2)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Mounts: mounts, Compress: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "http://example.test/static/v2/a.css", nil)
			rec := httptest.NewRecorder()
			if got := s.Serve(rec, req, false); got != ResultServed || rec.Body.String() != "from-d2" {
				t.Errorf("longest prefix mount: got=%v body=%q", got, rec.Body.String())
			}
			reqMiss := httptest.NewRequest(http.MethodGet, "http://example.test/static/missing.css", nil)
			recMiss := httptest.NewRecorder()
			if got := s.Serve(recMiss, reqMiss, false); got != ResultNotFound {
				t.Errorf("mount miss: got=%v want ResultNotFound", got)
			}
		}()
	}
	wg.Wait()

	// With Fallback=true, missing files pass through.
	s2, err := New(Config{Mounts: mounts, Fallback: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	reqMiss := httptest.NewRequest(http.MethodGet, "http://example.test/static/missing.css", nil)
	if got := s2.Serve(httptest.NewRecorder(), reqMiss, false); got != ResultPassThrough {
		t.Fatalf("fallback miss: got=%v want ResultPassThrough", got)
	}
}

func FuzzResolvePath(f *testing.F) {
	f.Add("/")
	f.Add("/wp-content/themes/style.css")
	f.Add("/../etc/passwd")
	f.Add("/.env")
	f.Add("/.well-known/acme-challenge/abc")
	f.Add("/.well-known/../.env")
	f.Add("/a//b/c\x00.png")
	f.Fuzz(func(t *testing.T, in string) {
		rel, _, kind := resolvePath(in)
		if kind == pathOK {
			if strings.HasPrefix(rel, "/") || strings.ContainsAny(rel, "\x00\\") {
				t.Fatalf("unsafe rel %q from %q", rel, in)
			}
			for _, seg := range strings.Split(rel, "/") {
				if seg == "." || seg == ".." || (seg != "" && seg[0] == '.') {
					t.Fatalf("dot segment %q leaked in %q from %q", seg, rel, in)
				}
			}
		}
	})
}
