//go:build wordpress || enterprise

package server

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

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
