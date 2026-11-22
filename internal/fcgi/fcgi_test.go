package fcgi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// mockFPM is a minimal in-process FastCGI 1.0 responder for tests.
type mockFPM struct {
	ln      net.Listener
	calls   atomic.Int64
	handler func(params map[string]string, stdin []byte) (stdout, stderr []byte)
	wg      sync.WaitGroup
}

func startMockFPM(t *testing.T, network, addr string, fn func(map[string]string, []byte) ([]byte, []byte)) *mockFPM {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockFPM{ln: ln, handler: fn}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			m.wg.Add(1)
			go func(conn net.Conn) {
				defer m.wg.Done()
				defer conn.Close()
				m.serveConn(conn)
			}(c)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		m.wg.Wait()
	})
	return m
}

func decodeParams(b []byte) map[string]string {
	out := map[string]string{}
	readLen := func() (int, bool) {
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
		kl, ok := readLen()
		if !ok {
			break
		}
		vl, ok := readLen()
		if !ok || len(b) < kl+vl {
			break
		}
		k := string(b[:kl])
		v := string(b[kl : kl+vl])
		b = b[kl+vl:]
		out[k] = v
	}
	return out
}

func (m *mockFPM) serveConn(conn net.Conn) {
	var paramBuf, stdinBuf bytes.Buffer
	var reqID uint16
	for {
		hdr, payload, err := readRecord(conn)
		if err != nil {
			return
		}
		if reqID == 0 {
			reqID = hdr.RequestID
		}
		switch hdr.Type {
		case typeParams:
			paramBuf.Write(payload)
		case typeStdin:
			if len(payload) == 0 {
				m.calls.Add(1)
				stdout, stderr := m.handler(decodeParams(paramBuf.Bytes()), stdinBuf.Bytes())
				if len(stderr) > 0 {
					_ = writeRecord(conn, typeStderr, reqID, stderr)
					_ = writeRecord(conn, typeStderr, reqID, nil)
				}
				if len(stdout) > 0 {
					_ = writeRecord(conn, typeStdout, reqID, stdout)
				}
				_ = writeRecord(conn, typeStdout, reqID, nil)
				var endBody [8]byte
				_ = writeRecord(conn, typeEndRequest, reqID, endBody[:])
				return
			}
			stdinBuf.Write(payload)
		}
	}
}

func setupWPRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range []string{
		"index.php",
		"wp-login.php",
		"wp-config.php",
		"wp-admin/index.php",
		"wp-admin/post.php",
		"wp-content/uploads/shell.php",
	} {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("<?php echo 'ok';"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestFastCGI_WordPressRoutingUnixAndTCP(t *testing.T) {
	root := setupWPRoot(t)
	var stderrMu sync.Mutex
	var stderrMsgs []string

	handler := func(params map[string]string, stdin []byte) ([]byte, []byte) {
		var out bytes.Buffer
		if params["SCRIPT_NAME"] == "/wp-login.php" {
			out.WriteString("Status: 302 Found\r\n")
			out.WriteString("Location: /wp-admin/\r\n")
			out.WriteString("Set-Cookie: wp_a=1; Path=/\r\n")
			out.WriteString("Set-Cookie: wp_b=2; Path=/\r\n")
			out.WriteString("Concert-Priority: checkout\r\n")
			out.WriteString("\r\nredirecting")
			return out.Bytes(), []byte("PHP Notice: login notice\n")
		}
		out.WriteString("Content-Type: text/plain\r\n\r\n")
		fmt.Fprintf(&out, "script=%s uri=%s qs=%s pathinfo=%s proxy=%s https=%s body=%d",
			params["SCRIPT_NAME"], params["REQUEST_URI"], params["QUERY_STRING"],
			params["PATH_INFO"], params["HTTP_PROXY"], params["HTTPS"], len(stdin))
		return out.Bytes(), nil
	}

	// Start both a Unix-socket responder (short path in /tmp to stay under macOS 104-byte sun_path limit) and a TCP responder.
	sockDir, err := os.MkdirTemp("/tmp", "fcgi-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "fpm.sock")
	fpmUnix := startMockFPM(t, "unix", sockPath, handler)
	fpmTCP := startMockFPM(t, "tcp", "127.0.0.1:0", handler)

	tr, err := NewTransport(Config{
		Root:      root,
		Index:     "index.php",
		DenyPaths: []string{"/wp-content/uploads/*", "/wp-config.php"},
		OnStderr: func(msg string) {
			stderrMu.Lock()
			stderrMsgs = append(stderrMsgs, msg)
			stderrMu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	unixTarget, _ := url.Parse("fcgi+unix://" + sockPath)
	tcpTarget, _ := url.Parse("fcgi://" + fpmTCP.ln.Addr().String())

	// 1. WordPress pretty permalink via Unix socket (try_files -> index.php) + httpoxy Proxy stripped.
	req := httptest.NewRequest(http.MethodGet, "https://shop.example/product/hoodie/?color=black", nil)
	req.Header.Set("Proxy", "http://evil.proxy:8080")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := tr.RoundTripTo(req, unixTarget)
	if err != nil {
		t.Fatalf("permalink RoundTripTo: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("permalink status = %d", resp.StatusCode)
	}
	want := "script=/index.php uri=/product/hoodie/?color=black qs=color=black pathinfo= proxy= https=on body=0"
	if string(body) != want {
		t.Fatalf("permalink body = %q, want %q", string(body), want)
	}

	// 2. Direct PHP script with Status: 302, multi Set-Cookie, Concert-Priority, and FCGI_STDERR.
	req = httptest.NewRequest(http.MethodGet, "https://shop.example/wp-login.php", nil)
	resp, err = tr.RoundTripTo(req, tcpTarget)
	if err != nil {
		t.Fatalf("wp-login RoundTripTo: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/wp-admin/" || resp.Header.Get("Concert-Priority") != "checkout" {
		t.Fatalf("wp-login headers = %d %v", resp.StatusCode, resp.Header)
	}
	if cookies := resp.Header.Values("Set-Cookie"); len(cookies) != 2 {
		t.Fatalf("Set-Cookie count = %d, want 2 (%v)", len(cookies), cookies)
	}
	stderrMu.Lock()
	if len(stderrMsgs) != 1 || !strings.Contains(stderrMsgs[0], "login notice") {
		t.Fatalf("stderr capture = %v", stderrMsgs)
	}
	stderrMu.Unlock()

	// 3. PATH_INFO splitting + large multi-record POST upload (>128 KiB).
	payload := bytes.Repeat([]byte("A"), 140<<10)
	req = httptest.NewRequest(http.MethodPost, "http://shop.example/wp-admin/post.php/edit/42", bytes.NewReader(payload))
	resp, err = tr.RoundTripTo(req, unixTarget)
	if err != nil {
		t.Fatalf("upload RoundTripTo: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "script=/wp-admin/post.php") || !strings.Contains(string(body), "pathinfo=/edit/42") || !strings.Contains(string(body), "body=143360") {
		t.Fatalf("upload/pathinfo body = %q", string(body))
	}

	// 4. Directory /wp-admin redirects 301 -> /wp-admin/, and /wp-admin/ executes wp-admin/index.php.
	req = httptest.NewRequest(http.MethodGet, "https://shop.example/wp-admin?foo=1", nil)
	resp, err = tr.RoundTripTo(req, unixTarget)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "/wp-admin/?foo=1" {
		t.Fatalf("wp-admin redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// 5. Security guards: blocked uploads PHP (403), wp-config.php (403), nonexistent .php probe (404) — ZERO FPM dials!
	callsBefore := fpmUnix.calls.Load()
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/wp-content/uploads/shell.php", http.StatusForbidden},
		{"/wp-config.php", http.StatusForbidden},
		{"/.env", http.StatusForbidden},
		{"/nonexistent-probe.php", http.StatusNotFound},
	} {
		r := httptest.NewRequest(http.MethodGet, "https://shop.example"+tc.path, nil)
		resp, err := tr.RoundTripTo(r, unixTarget)
		if err != nil {
			t.Fatalf("%s error: %v", tc.path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.path, resp.StatusCode, tc.want)
		}
	}
	if fpmUnix.calls.Load() != callsBefore {
		t.Fatalf("blocked/missing PHP probes reached php-fpm: delta=%d", fpmUnix.calls.Load()-callsBefore)
	}

	// 6. DialCheck works against Unix and TCP targets.
	if err := tr.DialCheck(context.Background(), unixTarget); err != nil {
		t.Fatalf("DialCheck unix: %v", err)
	}
	if err := tr.DialCheck(context.Background(), tcpTarget); err != nil {
		t.Fatalf("DialCheck tcp: %v", err)
	}
}

func FuzzReadRecord(f *testing.F) {
	var valid bytes.Buffer
	_ = writeRecord(&valid, typeStdout, 1, []byte("Content-Type: text/plain\r\n\r\nhi"))
	f.Add(valid.Bytes())
	f.Add([]byte{1, 6, 0, 1, 0, 0, 0, 0})
	f.Add([]byte{9, 9, 9})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = readRecord(bytes.NewReader(data))
	})
}

func FuzzParseCGIHeaders(f *testing.F) {
	f.Add([]byte("Status: 200 OK\r\nContent-Type: text/html\r\n\r\n<body>"))
	f.Add([]byte("Location: /next\r\nSet-Cookie: a=1\r\n\r\n"))
	f.Add([]byte("BadHeaderWithoutColon\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		code, _, hdr, err := parseCGIHeaders(bufio.NewReader(bytes.NewReader(data)))
		if err == nil {
			if code < 100 || code > 599 {
				t.Fatalf("out-of-range status %d", code)
			}
			for k, vals := range hdr {
				if !validHeaderName(k) {
					t.Fatalf("invalid header name %q", k)
				}
				for _, v := range vals {
					if strings.ContainsAny(v, "\r\n\x00") {
						t.Fatalf("injected header value %q", v)
					}
				}
			}
		}
	})
}
