//go:build wordpress || enterprise

package server

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFastCGI_RemoteAddrIgnoresSpoofedLeftmostXFFBehindTrustedProxy(t *testing.T) {
	root := t.TempDir()
	for _, f := range []string{"index.php", "wp-login.php"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("<?php\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var (
		mu         sync.Mutex
		lastParams map[string]string
	)
	sock, _ := startTestFPM(t, func(params map[string]string, _ []byte) []byte {
		mu.Lock()
		lastParams = params
		mu.Unlock()
		return []byte(fmt.Sprintf("Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nremote=%s", params["REMOTE_ADDR"]))
	})

	// Trusted proxy mode (nginx/Cloudflare -> wpconcert -> php-fpm): 127.0.0.1 is trusted.
	cfg := testConfig("fcgi+unix://" + sock)
	cfg.staticRoot = root
	cfg.trustedProxies = "127.0.0.1/32,::1/128"
	_, front := newTestApp(t, cfg, nil)

	// Attacker behind nginx injects a spoofed leftmost 127.0.0.1 before the real client IP 203.0.113.55.
	resp, body := get(t, front.URL+"/wp-login.php", map[string]string{
		"X-Forwarded-For": "127.0.0.1, 203.0.113.55",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	mu.Lock()
	gotRemote := lastParams["REMOTE_ADDR"]
	gotHost := lastParams["REMOTE_HOST"]
	mu.Unlock()
	if gotRemote != "203.0.113.55" || gotHost != "203.0.113.55" {
		t.Fatalf("trusted proxy spoof test: PHP saw REMOTE_ADDR=%q REMOTE_HOST=%q (body=%q), want 203.0.113.55",
			gotRemote, gotHost, string(body))
	}

	// Untrusted direct client mode: attacker sends X-Forwarded-For: 198.51.100.77, PHP must see 127.0.0.1.
	cfgDirect := testConfig("fcgi+unix://" + sock)
	cfgDirect.staticRoot = root
	cfgDirect.trustedProxies = ""
	_, frontDirect := newTestApp(t, cfgDirect, nil)

	resp2, _ := get(t, frontDirect.URL+"/", map[string]string{
		"X-Forwarded-For": "198.51.100.77",
	})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("direct status = %d, want 200", resp2.StatusCode)
	}
	mu.Lock()
	gotDirect := lastParams["REMOTE_ADDR"]
	mu.Unlock()
	if gotDirect != "127.0.0.1" {
		t.Fatalf("direct spoof test: PHP saw REMOTE_ADDR=%q, want 127.0.0.1", gotDirect)
	}
}

func TestFastCGI_DropsUnderscoreHeaders(t *testing.T) {
	root := t.TempDir()
	for _, f := range []string{"index.php", "wp-login.php"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("<?php\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var (
		mu         sync.Mutex
		lastParams map[string]string
	)
	sock, _ := startTestFPM(t, func(params map[string]string, _ []byte) []byte {
		mu.Lock()
		lastParams = params
		mu.Unlock()
		return []byte("Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nok")
	})

	cfg := testConfig("fcgi+unix://" + sock)
	cfg.staticRoot = root
	_, front := newTestApp(t, cfg, nil)

	req, err := http.NewRequest(http.MethodGet, front.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Bypass Go's canonical header normalization by inserting underscore names directly.
	req.Header["X_Forwarded_Proto"] = []string{"https"}
	req.Header["X_Forwarded_For"] = []string{"127.0.0.9"}
	req.Header["X_Room_Pass"] = []string{"smuggled-pass"}
	req.Header["X_Custom_Bad"] = []string{"evil"}
	req.Header.Set("X-Custom-Ok", "good-value")

	resp, err := testClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	mu.Lock()
	params := lastParams
	mu.Unlock()

	if v := params["HTTP_X_FORWARDED_PROTO"]; strings.EqualFold(v, "https") {
		t.Fatalf("underscore smuggling succeeded: HTTP_X_FORWARDED_PROTO=%q on plain HTTP request", v)
	}
	if v := params["HTTP_X_FORWARDED_FOR"]; strings.Contains(v, "127.0.0.9") {
		t.Fatalf("underscore smuggling succeeded: HTTP_X_FORWARDED_FOR=%q", v)
	}
	if v := params["HTTP_X_ROOM_PASS"]; v != "" {
		t.Fatalf("underscore smuggling leaked HTTP_X_ROOM_PASS=%q", v)
	}
	if v := params["HTTP_X_CUSTOM_BAD"]; v != "" {
		t.Fatalf("underscore header leaked HTTP_X_CUSTOM_BAD=%q", v)
	}
	if v := params["HTTP_X_CUSTOM_OK"]; v != "good-value" {
		t.Fatalf("normal dashed header dropped: HTTP_X_CUSTOM_OK=%q, want good-value", v)
	}
}

func TestFastCGI_SteadyUploadLongerThanHeaderTimeoutSucceeds(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sock, _ := startTestFPM(t, func(_ map[string]string, stdin []byte) []byte {
		return []byte(fmt.Sprintf("Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nreceived=%d:%s", len(stdin), string(stdin)))
	})

	cfg := testConfig("fcgi+unix://" + sock)
	cfg.staticRoot = root
	cfg.headerTimeout = 150 * time.Millisecond
	cfg.bodyReadIdleTimeout = 500 * time.Millisecond
	cfg.maxUploadTime = 3 * time.Second
	_, front := newTestApp(t, cfg, nil)

	pr, pw := io.Pipe()
	var want strings.Builder
	go func() {
		defer pw.Close()
		for i := 0; i < 6; i++ {
			chunk := fmt.Sprintf("chunk-%d\n", i)
			_, _ = pw.Write([]byte(chunk))
			time.Sleep(60 * time.Millisecond) // total ~360ms > 2x headerTimeout (150ms)
		}
	}()
	for i := 0; i < 6; i++ {
		want.WriteString(fmt.Sprintf("chunk-%d\n", i))
	}

	req, err := http.NewRequest(http.MethodPost, front.URL+"/upload", pr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := testClient.Do(req)
	if err != nil {
		t.Fatalf("steady upload request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	expected := fmt.Sprintf("received=%d:%s", want.Len(), want.String())
	if resp.StatusCode != http.StatusOK || string(body) != expected {
		t.Fatalf("steady upload: got %d %q, want 200 %q", resp.StatusCode, string(body), expected)
	}
}

func TestFastCGI_IdleClientBodyCutOffAndSlotReleased(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sock, _ := startTestFPM(t, func(_ map[string]string, stdin []byte) []byte {
		return []byte(fmt.Sprintf("Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nlen=%d", len(stdin)))
	})

	cfg := testConfig("fcgi+unix://" + sock)
	cfg.staticRoot = root
	cfg.capacity = 1
	cfg.headerTimeout = 2 * time.Second
	cfg.bodyReadIdleTimeout = 150 * time.Millisecond
	cfg.maxUploadTime = 5 * time.Second
	a, front := newTestApp(t, cfg, nil)

	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send partial body and stall without closing the socket.
	_, err = io.WriteString(conn, "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 10000\r\n\r\nhello")
	if err != nil {
		t.Fatal(err)
	}

	// Wait until the request enters the waiting room, then confirm idle timeout releases the slot.
	deadline := time.Now().Add(1500 * time.Millisecond)
	entered := false
	for time.Now().Before(deadline) {
		if a.room.Len() > 0 {
			entered = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = entered

	// After bodyReadIdleTimeout (150ms), the stalled body must be aborted and the slot freed.
	releaseDeadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(releaseDeadline) {
		if a.room.Len() == 0 {
			// Verify a subsequent healthy request succeeds immediately on the freed slot.
			resp, _ := get(t, front.URL+"/health-check-page", nil)
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("stalled client body held waiting-room slot past idle timeout (room.Len()=%d)", a.room.Len())
}

func TestFastCGI_TricklerBodyCutOffByMaxUploadTime(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sock, _ := startTestFPM(t, func(_ map[string]string, stdin []byte) []byte {
		return []byte(fmt.Sprintf("Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nlen=%d", len(stdin)))
	})

	cfg := testConfig("fcgi+unix://" + sock)
	cfg.staticRoot = root
	cfg.capacity = 1
	cfg.headerTimeout = 2 * time.Second
	cfg.bodyReadIdleTimeout = 250 * time.Millisecond
	cfg.maxUploadTime = 300 * time.Millisecond
	a, front := newTestApp(t, cfg, nil)

	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, err = io.WriteString(conn, "POST /trickle HTTP/1.1\r\nHost: example.test\r\nContent-Length: 10000\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}

	stopTrickle := make(chan struct{})
	defer close(stopTrickle)
	go func() {
		ticker := time.NewTicker(60 * time.Millisecond) // faster than bodyReadIdleTimeout (250ms)
		defer ticker.Stop()
		for {
			select {
			case <-stopTrickle:
				return
			case <-ticker.C:
				if _, werr := conn.Write([]byte("x")); werr != nil {
					return
				}
			}
		}
	}()

	// Wait past maxUploadTime (300ms) and assert the trickler was cut off and the room slot released.
	time.Sleep(400 * time.Millisecond)
	releaseDeadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(releaseDeadline) {
		if a.room.Len() == 0 {
			resp, _ := get(t, front.URL+"/after-trickle", nil)
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("1-byte trickler held waiting-room slot past maxUploadTime (room.Len()=%d)", a.room.Len())
}

func TestFastCGI_EarlyBackendAbortUnblocksSlowStdinAndReleasesSlot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Custom FastCGI responder that answers 413 immediately after PARAMS EOF,
	// without reading STDIN EOF.
	sockDir, err := os.MkdirTemp("/tmp", "cfpm-early-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "php-fpm.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				defer conn.Close()
				for {
					var h [8]byte
					if _, rerr := io.ReadFull(conn, h[:]); rerr != nil {
						return
					}
					rt := h[1]
					reqID := binary.BigEndian.Uint16(h[2:4])
					cl := binary.BigEndian.Uint16(h[4:6])
					pl := h[6]
					if cl > 0 {
						_, _ = io.CopyN(io.Discard, conn, int64(cl))
					}
					if pl > 0 {
						_, _ = io.CopyN(io.Discard, conn, int64(pl))
					}
					if rt == 4 && cl == 0 { // FCGI_PARAMS EOF -> respond 413 immediately with a >16KB body!
						largeBody := strings.Repeat("too-large!", 4800) // 48 KB > 16 KB bufio.Reader
						out := []byte("Status: 413 Payload Too Large\r\nContent-Type: text/plain\r\n\r\n" + largeBody)
						writeRec := func(typ uint8, body []byte) {
							for len(body) > 0 {
								chunk := body
								if len(chunk) > 32768 {
									chunk = chunk[:32768]
								}
								body = body[len(chunk):]
								var rh [8]byte
								rh[0] = 1
								rh[1] = typ
								binary.BigEndian.PutUint16(rh[2:4], reqID)
								binary.BigEndian.PutUint16(rh[4:6], uint16(len(chunk)))
								_, _ = conn.Write(rh[:])
								_, _ = conn.Write(chunk)
							}
						}
						writeEmpty := func(typ uint8, body []byte) {
							var rh [8]byte
							rh[0] = 1
							rh[1] = typ
							binary.BigEndian.PutUint16(rh[2:4], reqID)
							binary.BigEndian.PutUint16(rh[4:6], uint16(len(body)))
							_, _ = conn.Write(rh[:])
							if len(body) > 0 {
								_, _ = conn.Write(body)
							}
						}
						writeRec(6, out)
						writeEmpty(6, nil)
						writeEmpty(3, make([]byte, 8))
						return
					}
				}
			}(c)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})

	cfg := testConfig("fcgi+unix://" + sock)
	cfg.staticRoot = root
	cfg.capacity = 1
	// Intentionally generous idle/upload timeouts so ONLY early backend abort can unblock quickly!
	cfg.headerTimeout = 2 * time.Second
	cfg.bodyReadIdleTimeout = 30 * time.Second
	cfg.maxUploadTime = 30 * time.Second
	a, front := newTestApp(t, cfg, nil)

	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send headers + 3 bytes of a 100KB body and never finish sending.
	_, err = io.WriteString(conn, "POST /big HTTP/1.1\r\nHost: example.test\r\nContent-Length: 100000\r\n\r\nabc")
	if err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("did not receive early 413 response promptly: %v", err)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("reading early 413 response body: %v", err)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	wantBody := strings.Repeat("too-large!", 4800)
	if string(bodyBytes) != wantBody {
		t.Fatalf("body len = %d, want %d", len(bodyBytes), len(wantBody))
	}

	// Waiting-room slot MUST be released promptly even while the client keeps the TCP conn open!
	releaseDeadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(releaseDeadline) {
		if a.room.Len() == 0 {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("early php-fpm abort still held waiting-room slot (<-stdinDone hung; room.Len()=%d)", a.room.Len())
}
