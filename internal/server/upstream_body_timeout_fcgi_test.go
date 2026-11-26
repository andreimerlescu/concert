//go:build wordpress || enterprise

package server

import (
	"bytes"
	"encoding/binary"
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

// startStreamingTestFPM starts a Unix-socket FastCGI responder whose handler
// can stream multiple FCGI_STDOUT chunks and intentionally stall mid-body.
func startStreamingTestFPM(t *testing.T, fn func(params map[string]string, writeStdout func([]byte) error, waitClosed func())) string {
	t.Helper()
	sockDir, err := os.MkdirTemp("/tmp", "cfpm-stall-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "php-fpm.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}

	stopAll := make(chan struct{})
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
				writeRec := func(rt uint8, reqID uint16, body []byte) error {
					var h [8]byte
					h[0] = 1
					h[1] = rt
					binary.BigEndian.PutUint16(h[2:4], reqID)
					binary.BigEndian.PutUint16(h[4:6], uint16(len(body)))
					if _, err := conn.Write(h[:]); err != nil {
						return err
					}
					if len(body) > 0 {
						_, err := conn.Write(body)
						return err
					}
					return nil
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

				var pbuf bytes.Buffer
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
							writeStdout := func(b []byte) error {
								return writeRec(6, reqID, b)
							}
							waitClosed := func() {
								done := make(chan struct{})
								go func() {
									defer close(done)
									var buf [1]byte
									_, _ = conn.Read(buf[:])
								}()
								select {
								case <-done:
								case <-stopAll:
									_ = conn.Close()
									<-done
								}
							}
							fn(decode(pbuf.Bytes()), writeStdout, waitClosed)
							_ = writeRec(6, reqID, nil)
							var end [8]byte
							_ = writeRec(3, reqID, end[:])
							return
						}
					}
				}
			}(c)
		}
	}()

	t.Cleanup(func() {
		close(stopAll)
		_ = ln.Close()
		wg.Wait()
	})
	return sockPath
}

func TestUpstream_FastCGIBodyIdleTimeoutWithGzipDoesNotDeadlock(t *testing.T) {
	root := t.TempDir()
	writeDiskFile(t, filepath.Join(root, "index.php"), []byte("<?php\n"))

	sock := startStreamingTestFPM(t, func(params map[string]string, writeStdout func([]byte) error, waitClosed func()) {
		switch params["REQUEST_URI"] {
		case "/admit":
			_ = writeStdout([]byte("Content-Type: text/plain\r\n\r\nok"))
		case "/stall-after-sniff":
			// Exceeds minFCGIGzipBytes (1024) so maybeGzipFastCGI spawns its
			// background io.Copy -> io.Pipe goroutine before stalling.
			chunk := "Content-Type: text/html; charset=utf-8\r\n\r\n" + strings.Repeat("<html>wordpress-chunk</html>", 80)
			_ = writeStdout([]byte(chunk))
			waitClosed()
		case "/stall-during-sniff":
			// Smaller than minFCGIGzipBytes so the stall occurs synchronously
			// inside maybeGzipFastCGI's io.ReadFull 1 KiB sniff.
			_ = writeStdout([]byte("Content-Type: text/html; charset=utf-8\r\n\r\n<html>partial"))
			waitClosed()
		case "/sse":
			_ = writeStdout([]byte("Content-Type: text/event-stream; charset=utf-8\r\n\r\ndata: fcgi-1\n\n"))
			time.Sleep(1350 * time.Millisecond)
			_ = writeStdout([]byte("data: fcgi-2\n\n"))
		case "/stream/feed":
			_ = writeStdout([]byte("Content-Type: text/plain; charset=utf-8\r\n\r\npart-1\n"))
			time.Sleep(1350 * time.Millisecond)
			_ = writeStdout([]byte("part-2\n"))
		default:
			_ = writeStdout([]byte("Content-Type: text/plain\r\n\r\nok"))
		}
	})

	// 1. Stalled FastCGI bodies with gzip enabled must abort cleanly (no deadlock
	// in pipeCloser.Close, no hang in 1 KiB sniff), release the room slot, count
	// metrics, and trip the circuit breaker.
	cfg := testConfig("fcgi+unix://" + sock)
	cfg.staticRoot = root
	cfg.compress = true
	cfg.capacity = 1
	cfg.upstreamBodyIdleTimeout = time.Second
	cfg.upstreamCBFailures = 2
	cfg.upstreamCBCooldown = 30 * time.Second
	a, front := newTestApp(t, cfg, nil)

	rawCli := &http.Client{
		Transport: &http.Transport{DisableCompression: true},
		Timeout:   5 * time.Second,
	}

	// (a) Stall AFTER 1 KiB sniff (inside gzip goroutine / pipeCloser).
	req1, _ := http.NewRequest(http.MethodGet, front.URL+"/stall-after-sniff", nil)
	req1.Header.Set("Accept-Encoding", "gzip")
	resp1, err := rawCli.Do(req1)
	if err != nil {
		t.Fatalf("GET /stall-after-sniff: %v", err)
	}
	if resp1.StatusCode != http.StatusOK || resp1.Header.Get("Content-Encoding") != "gzip" {
		_ = resp1.Body.Close()
		t.Fatalf("/stall-after-sniff headers: status=%d enc=%q, want 200 gzip", resp1.StatusCode, resp1.Header.Get("Content-Encoding"))
	}
	_, readErr1 := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	if readErr1 == nil {
		t.Fatal("expected wire abort read error on stalled gzipped FastCGI body, got clean EOF")
	}
	waitRoomOccupancyZero(t, a, 2*time.Second)
	if got := a.stats.upstreamBodyIdleTimeouts.Load(); got != 1 {
		t.Fatalf("after /stall-after-sniff: upstreamBodyIdleTimeouts = %d, want 1", got)
	}

	// (b) Stall DURING 1 KiB sniff (synchronous io.ReadFull in maybeGzipFastCGI).
	req2, _ := http.NewRequest(http.MethodGet, front.URL+"/stall-during-sniff", nil)
	req2.Header.Set("Accept-Encoding", "gzip")
	resp2, err := rawCli.Do(req2)
	if err != nil {
		t.Fatalf("GET /stall-during-sniff: %v", err)
	}
	_, readErr2 := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if readErr2 == nil {
		t.Fatal("expected wire abort read error on FastCGI body stalled during 1 KiB gzip sniff, got clean EOF")
	}
	waitRoomOccupancyZero(t, a, 2*time.Second)
	if got := a.stats.upstreamBodyIdleTimeouts.Load(); got != 2 {
		t.Fatalf("after /stall-during-sniff: upstreamBodyIdleTimeouts = %d, want 2", got)
	}

	// (c) Verify both stalls counted toward CB (threshold 2 -> circuit open 503).
	resp3, err := rawCli.Get(front.URL + "/after-fcgi-stalls")
	if err != nil {
		t.Fatalf("GET /after-fcgi-stalls: %v", err)
	}
	b3, _ := io.ReadAll(resp3.Body)
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(b3), "upstream circuit open") {
		t.Fatalf("expected 503 upstream circuit open after 2 FastCGI stalls, got %d %q", resp3.StatusCode, string(b3))
	}

	// 2. FastCGI SSE and -stream-paths responses are exempt from both native
	// conn.SetReadDeadline and respBodyIdleReader.
	cfg2 := testConfig("fcgi+unix://" + sock)
	cfg2.staticRoot = root
	cfg2.compress = true
	cfg2.upstreamBodyIdleTimeout = time.Second
	cfg2.streamPaths = "/stream/*"
	a2, front2 := newTestApp(t, cfg2, nil)

	admitResp, err := rawCli.Get(front2.URL + "/admit")
	if err != nil {
		t.Fatalf("GET /admit: %v", err)
	}
	_, _ = io.ReadAll(admitResp.Body)
	_ = admitResp.Body.Close()
	var admitCk *http.Cookie
	for _, ck := range admitResp.Cookies() {
		if ck.Name == admitCookie {
			admitCk = ck
		}
	}
	if admitCk == nil {
		t.Fatal("missing concert_admit cookie")
	}

	respSSE, err := rawCli.Get(front2.URL + "/sse")
	if err != nil {
		t.Fatalf("GET /sse: %v", err)
	}
	sseBody, err := io.ReadAll(respSSE.Body)
	_ = respSSE.Body.Close()
	if err != nil || string(sseBody) != "data: fcgi-1\n\ndata: fcgi-2\n\n" {
		t.Fatalf("FastCGI SSE failed: err=%v body=%q", err, string(sseBody))
	}

	reqSt, _ := http.NewRequest(http.MethodGet, front2.URL+"/stream/feed", nil)
	reqSt.AddCookie(admitCk)
	respSt, err := rawCli.Do(reqSt)
	if err != nil {
		t.Fatalf("GET /stream/feed: %v", err)
	}
	stBody, err := io.ReadAll(respSt.Body)
	_ = respSt.Body.Close()
	if err != nil || string(stBody) != "part-1\npart-2\n" {
		t.Fatalf("FastCGI -stream-paths failed: err=%v body=%q", err, string(stBody))
	}
	if got := a2.stats.upstreamBodyIdleTimeouts.Load(); got != 0 {
		t.Fatalf("exempt FastCGI streams triggered upstreamBodyIdleTimeouts = %d, want 0", got)
	}
}
