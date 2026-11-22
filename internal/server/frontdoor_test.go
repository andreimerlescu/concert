package server

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// startTestFPM starts a minimal Unix-socket FastCGI responder for server integration tests.
func startTestFPM(t *testing.T, fn func(params map[string]string, stdin []byte) []byte) (sockPath string, calls *atomic.Int64) {
	t.Helper()
	sockDir, err := os.MkdirTemp("/tmp", "cfpm-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath = filepath.Join(sockDir, "php-fpm.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	calls = &atomic.Int64{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				defer conn.Close()
				serveTestFCGI(conn, calls, fn)
			}(c)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return sockPath, calls
}

func serveTestFCGI(conn net.Conn, calls *atomic.Int64, fn func(map[string]string, []byte) []byte) {
	readRec := func() (uint8, uint16, []byte, error) {
		var h [8]byte
		if _, err := io.ReadFull(conn, h[:]); err != nil {
			return 0, 0, nil, err
		}
		reqID := binary.BigEndian.Uint16(h[2:4])
		cl := binary.BigEndian.Uint16(h[4:6])
		pl := h[6]
		var body []byte
		if cl > 0 {
			body = make([]byte, cl)
			if _, err := io.ReadFull(conn, body); err != nil {
				return 0, 0, nil, err
			}
		}
		if pl > 0 {
			var pad [256]byte
			_, _ = io.ReadFull(conn, pad[:pl])
		}
		return h[1], reqID, body, nil
	}
	writeRec := func(rt uint8, reqID uint16, body []byte) {
		var h [8]byte
		h[0] = 1
		h[1] = rt
		binary.BigEndian.PutUint16(h[2:4], reqID)
		binary.BigEndian.PutUint16(h[4:6], uint16(len(body)))
		_, _ = conn.Write(h[:])
		if len(body) > 0 {
			_, _ = conn.Write(body)
		}
	}
	decode := func(b []byte) map[string]string {
		out := map[string]string{}
		rdLen := func() (int, bool) {
			if len(b) == 0 {
				return 0, false
			}
			if b[0]&0x80 == 0 {
				n := int(b[0])
				b = b[1:]
				return n, true
			}
			if len(b) < 4 {
				return 0, false
			}
			n := int(binary.BigEndian.Uint32(b[:4]) & 0x7fffffff)
			b = b[4:]
			return n, true
		}
		for len(b) > 0 {
			kl, ok := rdLen()
			if !ok {
				break
			}
			vl, ok := rdLen()
			if !ok || len(b) < kl+vl {
				break
			}
			out[string(b[:kl])] = string(b[kl : kl+vl])
			b = b[kl+vl:]
		}
		return out
	}

	var pbuf, ibuf bytes.Buffer
	var reqID uint16
	for {
		rt, id, payload, err := readRec()
		if err != nil {
			return
		}
		if reqID == 0 {
			reqID = id
		}
		switch rt {
		case 4: // PARAMS
			pbuf.Write(payload)
		case 5: // STDIN
			if len(payload) == 0 {
				calls.Add(1)
				out := fn(decode(pbuf.Bytes()), ibuf.Bytes())
				if len(out) > 0 {
					writeRec(6, reqID, out)
				}
				writeRec(6, reqID, nil)
				var end [8]byte
				writeRec(3, reqID, end[:])
				return
			}
			ibuf.Write(payload)
		}
	}
}

func TestFastCGI_WordPressEndToEnd(t *testing.T) {
	root := t.TempDir()
	writeDiskFile(t, filepath.Join(root, "index.php"), []byte("<?php"))
	writeDiskFile(t, filepath.Join(root, "wp-config.php"), []byte("<?php secret"))
	writeDiskFile(t, filepath.Join(root, "wp-admin", "index.php"), []byte("<?php admin"))
	writeDiskFile(t, filepath.Join(root, "wp-content", "uploads", "evil.php"), []byte("<?php evil"))
	writeDiskFile(t, filepath.Join(root, "wp-content", "themes", "app.css"), []byte("body{color:red}"))
	var gzCSS bytes.Buffer
	gw := gzip.NewWriter(&gzCSS)
	_, _ = gw.Write([]byte("body{color:red}"))
	_ = gw.Close()
	writeDiskFile(t, filepath.Join(root, "wp-content", "themes", "app.css.gz"), gzCSS.Bytes())

	bigHTML := "<html><body>" + strings.Repeat("WordPress product catalog entry. ", 60) + "</body></html>"
	sockPath, fpmCalls := startTestFPM(t, func(params map[string]string, _ []byte) []byte {
		var out bytes.Buffer
		out.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		if strings.HasPrefix(params["REQUEST_URI"], "/checkout") {
			out.WriteString("Concert-Priority: checkout\r\n")
		}
		out.WriteString("\r\n")
		fmt.Fprintf(&out, "SCRIPT=%s URI=%s %s", params["SCRIPT_NAME"], params["REQUEST_URI"], bigHTML)
		return out.Bytes()
	})

	cfg := testConfig("fcgi+unix://" + sockPath)
	cfg.staticRoot = root
	cfg.assets = "/wp-content/*"
	cfg.fcgiIndex = "index.php"
	cfg.fcgiDenyPaths = "/wp-content/uploads/*,/wp-config.php"
	cfg.compress = true
	a, front := newTestApp(t, cfg, nil)

	rawCli := &http.Client{
		Transport: &http.Transport{DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1. WordPress pretty permalink -> index.php + Concert-Priority grant + on-the-fly gzip!
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/checkout/?item=1", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := rawCli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rawBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("checkout status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected FastCGI HTML response to be gzipped, got %q", resp.Header.Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(bytes.NewReader(rawBody))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(zr)
	_ = zr.Close()
	if !strings.Contains(string(plain), "SCRIPT=/index.php URI=/checkout/?item=1") {
		t.Fatalf("unexpected FastCGI HTML: %q", string(plain[:min(120, len(plain))]))
	}
	var admitCk, prioCk *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == admitCookie {
			admitCk = c
		}
		if c.Name == priorityCookie {
			prioCk = c
		}
	}
	if admitCk == nil || prioCk == nil {
		t.Fatalf("missing cookies after checkout: admit=%v prio=%v", admitCk != nil, prioCk != nil)
	}

	// 2. Precompressed static asset with admit cookie -> 200 gzip from disk, ZERO FastCGI calls.
	before := fpmCalls.Load()
	reqA, _ := http.NewRequest(http.MethodGet, front.URL+"/wp-content/themes/app.css", nil)
	reqA.AddCookie(admitCk)
	reqA.Header.Set("Accept-Encoding", "gzip")
	resp, err = rawCli.Do(reqA)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("static asset gz: status=%d enc=%q", resp.StatusCode, resp.Header.Get("Content-Encoding"))
	}

	// 3. Blocked PHP paths -> 403, missing .php -> 404, /wp-admin -> 301: ALL with ZERO FastCGI calls!
	for _, tc := range []struct {
		path string
		want int
		ck   *http.Cookie
	}{
		{"/wp-content/uploads/evil.php", http.StatusForbidden, admitCk},
		{"/wp-config.php", http.StatusForbidden, nil},
		{"/scanner-probe.php", http.StatusNotFound, nil},
		{"/wp-admin", http.StatusMovedPermanently, nil},
	} {
		r, _ := http.NewRequest(http.MethodGet, front.URL+tc.path, nil)
		if tc.ck != nil {
			r.AddCookie(tc.ck)
		}
		resp, err := rawCli.Do(r)
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s: status=%d, want %d", tc.path, resp.StatusCode, tc.want)
		}
	}
	if fpmCalls.Load() != before {
		t.Fatalf("static/blocked/missing requests reached php-fpm: delta=%d", fpmCalls.Load()-before)
	}

	// 4. Verify Prometheus metrics include static & fcgi counters.
	metrics := a.renderPrometheusMetrics()
	for _, want := range []string{
		"concert_static_served_total 1",
		"concert_fcgi_requests_total 1",
		"concert_fcgi_denied_total 2",
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("metrics missing %q", want)
		}
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

func TestLeafHop_StaticOffload(t *testing.T) {
	var originHits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("page-from-origin"))
	}))
	defer origin.Close()

	root := t.TempDir()
	writeDiskFile(t, filepath.Join(root, "static", "app.js"), []byte("console.log('leaf-disk');"))
	secret := []byte("concert-leaf-static-offload-secret-0123456789")

	leafCfg := testConfig(origin.URL)
	leafCfg.role = roleLeaf
	leafCfg.nodeID = "leaf-static"
	leafCfg.hostCap = 10
	leafCfg.hopSecret = secret
	leafCfg.hopPeers = "127.0.0.1/32,::1/128"
	leafCfg.staticRoot = root
	leafCfg.assets = "/static/*"
	_, leafSrv := newTestApp(t, leafCfg, nil)

	edgeCfg := testConfig(leafSrv.URL)
	edgeCfg.role = roleEdge
	edgeCfg.nodeID = "edge-static"
	edgeCfg.hopSecret = secret
	edgeCfg.hopPoll = 500 * time.Millisecond
	edgeCfg.assets = "/static/*"
	_, edgeSrv := newTestApp(t, edgeCfg, nil)

	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := testClient.Get(edgeSrv.URL + "/_room/readyz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("edge never became ready")
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Hit a page through edge -> hits origin once and gets concert_admit cookie.
	resp, err := testClient.Get(edgeSrv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var admitCk *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == admitCookie {
			admitCk = c
		}
	}
	if admitCk == nil {
		t.Fatal("edge did not issue admit cookie")
	}

	// Hit asset through edge -> leaf serves straight off disk with ZERO origin hits!
	req, _ := http.NewRequest(http.MethodGet, edgeSrv.URL+"/static/app.js", nil)
	req.AddCookie(admitCk)
	resp, err = testClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "console.log('leaf-disk');" {
		t.Fatalf("leaf static asset: status=%d body=%q", resp.StatusCode, string(body))
	}
	if originHits.Load() != 1 {
		t.Fatalf("leaf static offload leaked to origin: hits=%d, want 1", originHits.Load())
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

	for _, body := range []string{
		`{"static_root":"/etc"}`,
		`{"static_mounts":"/etc=/etc"}`,
		`{"tls_http_listen":":80"}`,
		`{"fcgi_deny_paths":""}`,
		`{"upstream":"fcgi+unix:///run/php-fpm/www.sock"}`,
	} {
		rec := portalDo(p, http.MethodPost, "/api/settings", body, ck, csrf, false)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("portal accepted locked setting %s: status=%d body=%s", body, rec.Code, rec.Body.String())
		}
	}
}
