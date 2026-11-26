package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/quic-go/quic-go/http3"
)

func waitRoomOccupancyZero(t *testing.T, a *app, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if a.room.Len() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("waiting-room occupancy did not return to 0 within %s (room.Len()=%d)", within, a.room.Len())
}

func writeCertPEMFile(t *testing.T, dir, name string, cert *x509.Certificate) string {
	t.Helper()
	p := filepath.Join(dir, name)
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUpstream_BodyIdleTimeoutReleasesRoomSlot(t *testing.T) {
	t.Run("HTTP1_ChunkedStallAbortsAndReleasesSlot", func(t *testing.T) {
		t.Parallel()

		releaseOrigin := make(chan struct{})
		originCanceled := make(chan struct{}, 1)
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("chunk-1\n"))
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			select {
			case <-r.Context().Done():
				select {
				case originCanceled <- struct{}{}:
				default:
				}
			case <-releaseOrigin:
			}
		}))
		t.Cleanup(origin.Close)
		t.Cleanup(func() { close(releaseOrigin) })

		cfg := testConfig(origin.URL)
		cfg.capacity = 1
		cfg.upstreamBodyIdleTimeout = time.Second
		cfg.upstreamCBFailures = 1
		cfg.upstreamCBCooldown = 30 * time.Second
		a, front := newTestApp(t, cfg, nil)

		cli := &http.Client{Timeout: 5 * time.Second}
		start := time.Now()
		resp, err := cli.Get(front.URL + "/stall")
		if err != nil {
			t.Fatalf("GET /stall: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			t.Fatalf("status = %d, want 200 before mid-body abort", resp.StatusCode)
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		elapsed := time.Since(start)
		if readErr == nil {
			t.Fatalf("expected wire abort read error on stalled HTTP/1.1 chunked body, got clean EOF with body=%q", string(body))
		}
		if elapsed > 3500*time.Millisecond {
			t.Fatalf("stalled body took %s to abort, want ~1s", elapsed)
		}

		waitRoomOccupancyZero(t, a, 2*time.Second)

		if got := a.stats.upstreamBodyIdleTimeouts.Load(); got != 1 {
			t.Fatalf("upstreamBodyIdleTimeouts = %d, want 1", got)
		}
		if metrics := a.renderPrometheusMetrics(); !strings.Contains(metrics, "concert_upstream_body_idle_timeouts_total 1") {
			t.Fatalf("prometheus metrics missing concert_upstream_body_idle_timeouts_total 1")
		}

		select {
		case <-originCanceled:
		case <-time.After(time.Second):
			t.Fatal("expected upstream request context to cancel on body idle timeout")
		}

		// Circuit breaker should now be open after 1 failure.
		resp2, err := cli.Get(front.URL + "/after-stall")
		if err != nil {
			t.Fatalf("GET /after-stall: %v", err)
		}
		b2, _ := io.ReadAll(resp2.Body)
		_ = resp2.Body.Close()
		if resp2.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(b2), "upstream circuit open") {
			t.Fatalf("expected 503 upstream circuit open after stall CB trip, got %d %q", resp2.StatusCode, string(b2))
		}
	})

	t.Run("HTTP2_MidBodyStallResetsStreamAndReleasesSlot", func(t *testing.T) {
		t.Parallel()

		releaseOrigin := make(chan struct{})
		origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("h2-chunk-1\n"))
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			select {
			case <-r.Context().Done():
			case <-releaseOrigin:
			}
		}))
		origin.EnableHTTP2 = true
		origin.StartTLS()
		t.Cleanup(origin.Close)
		t.Cleanup(func() { close(releaseOrigin) })

		caPath := writeCertPEMFile(t, t.TempDir(), "origin-ca.pem", origin.Certificate())
		cfg := testConfig(origin.URL)
		cfg.capacity = 1
		cfg.upstreamCA = caPath
		cfg.upstreamBodyIdleTimeout = time.Second
		a, err := newApp(cfg)
		if err != nil {
			t.Fatalf("newApp: %v", err)
		}
		t.Cleanup(a.Close)

		front := httptest.NewUnstartedServer(a.handler)
		front.EnableHTTP2 = true
		front.StartTLS()
		t.Cleanup(front.Close)

		frontPool := x509.NewCertPool()
		frontPool.AddCert(front.Certificate())
		h2Tr := &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   &tls.Config{RootCAs: frontPool},
		}
		t.Cleanup(h2Tr.CloseIdleConnections)
		h2Cli := &http.Client{Transport: h2Tr, Timeout: 5 * time.Second}

		resp, err := h2Cli.Get(front.URL + "/stall-h2")
		if err != nil {
			t.Fatalf("HTTP/2 GET /stall-h2: %v", err)
		}
		if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			t.Fatalf("HTTP/2 response: proto=%s status=%d, want HTTP/2 200", resp.Proto, resp.StatusCode)
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr == nil {
			t.Fatalf("expected HTTP/2 RST_STREAM read error on stalled body, got clean EOF with body=%q", string(body))
		}

		waitRoomOccupancyZero(t, a, 2*time.Second)

		if got := a.stats.upstreamBodyIdleTimeouts.Load(); got != 1 {
			t.Fatalf("upstreamBodyIdleTimeouts = %d, want 1", got)
		}
	})

	t.Run("HTTP3_MidBodyStallResetsQUICStreamAndReleasesSlot", func(t *testing.T) {
		t.Parallel()

		releaseOrigin := make(chan struct{})
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("h3-chunk-1\n"))
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			select {
			case <-r.Context().Done():
			case <-releaseOrigin:
			}
		}))
		t.Cleanup(origin.Close)
		t.Cleanup(func() { close(releaseOrigin) })

		dir := t.TempDir()
		certPath, keyPath, pool := generateTestSelfSignedCert(t, dir, "h3-stall.example.test")

		cfg := testConfig(origin.URL)
		cfg.capacity = 1
		cfg.tlsCert = certPath
		cfg.tlsKey = keyPath
		cfg.http3 = true
		cfg.upstreamBodyIdleTimeout = time.Second
		a, err := newApp(cfg)
		if err != nil {
			t.Fatalf("newApp: %v", err)
		}
		t.Cleanup(a.Close)

		tlsCfg, _, err := newACMETLSConfigWithManager(a.current().cfg)
		if err != nil {
			t.Fatalf("newACMETLSConfigWithManager: %v", err)
		}
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		addr := pc.LocalAddr().String()
		stopH3, err := startHTTP3OnPacketConn(pc, tlsCfg, a.handler)
		if err != nil {
			_ = pc.Close()
			t.Fatalf("startHTTP3OnPacketConn: %v", err)
		}
		t.Cleanup(func() {
			if cerr := stopH3(); cerr != nil {
				t.Errorf("stopH3: %v", cerr)
			}
		})

		h3Tr := &http3.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: "h3-stall.example.test",
			},
		}
		t.Cleanup(func() { _ = h3Tr.Close() })
		h3Cli := &http.Client{Transport: h3Tr, Timeout: 5 * time.Second}

		resp, err := h3Cli.Get("https://" + addr + "/stall-h3")
		if err != nil {
			t.Fatalf("HTTP/3 GET /stall-h3: %v", err)
		}
		if resp.ProtoMajor != 3 || resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			t.Fatalf("HTTP/3 response: proto=%s status=%d, want HTTP/3 200", resp.Proto, resp.StatusCode)
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr == nil {
			t.Fatalf("expected QUIC stream reset error on stalled HTTP/3 body, got clean EOF with body=%q", string(body))
		}

		waitRoomOccupancyZero(t, a, 2*time.Second)

		if got := a.stats.upstreamBodyIdleTimeouts.Load(); got != 1 {
			t.Fatalf("upstreamBodyIdleTimeouts = %d, want 1", got)
		}
	})

	t.Run("HealthySlowTricklingDownloadSucceeds", func(t *testing.T) {
		t.Parallel()

		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fl, _ := w.(http.Flusher)
			for i := 0; i < 5; i++ {
				_, _ = fmt.Fprintf(w, "chunk-%d\n", i)
				if fl != nil {
					fl.Flush()
				}
				if i < 4 {
					select {
					case <-time.After(350 * time.Millisecond): // total ~1.4s > 1s idle timeout, per-chunk < 1s
					case <-r.Context().Done():
						return
					}
				}
			}
		}))
		t.Cleanup(origin.Close)

		cfg := testConfig(origin.URL)
		cfg.upstreamBodyIdleTimeout = time.Second
		a, front := newTestApp(t, cfg, nil)

		cli := &http.Client{Timeout: 5 * time.Second}
		resp, err := cli.Get(front.URL + "/trickle-ok")
		if err != nil {
			t.Fatalf("GET /trickle-ok: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("trickling download failed unexpectedly: %v", err)
		}
		want := "chunk-0\nchunk-1\nchunk-2\nchunk-3\nchunk-4\n"
		if resp.StatusCode != http.StatusOK || string(body) != want {
			t.Fatalf("trickling download: status=%d body=%q, want 200 %q", resp.StatusCode, string(body), want)
		}
		if got := a.stats.upstreamBodyIdleTimeouts.Load(); got != 0 {
			t.Fatalf("upstreamBodyIdleTimeouts = %d, want 0", got)
		}
	})

	t.Run("StreamPathsSSEAndUpgrade101_ExemptPastIdleTimeout", func(t *testing.T) {
		t.Parallel()

		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fl, _ := w.(http.Flusher)
			switch r.URL.Path {
			case "/admit":
				_, _ = w.Write([]byte("ok"))
			case "/live/feed":
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = w.Write([]byte("stream-1\n"))
				if fl != nil {
					fl.Flush()
				}
				select {
				case <-time.After(1350 * time.Millisecond):
				case <-r.Context().Done():
					return
				}
				_, _ = w.Write([]byte("stream-2\n"))
			case "/events":
				// Non-stream-path SSE response must auto-exempt and NOT cancel attemptCtx early.
				w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
				_, _ = w.Write([]byte("data: first\n\n"))
				if fl != nil {
					fl.Flush()
				}
				select {
				case <-time.After(1350 * time.Millisecond):
				case <-r.Context().Done():
					return
				}
				_, _ = w.Write([]byte("data: second\n\n"))
			case "/ws":
				hj, ok := w.(http.Hijacker)
				if !ok {
					http.Error(w, "no hijack", http.StatusInternalServerError)
					return
				}
				conn, rw, err := hj.Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
				_ = rw.Flush()
				_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
				line, err := rw.ReadString('\n')
				if err != nil {
					return
				}
				time.Sleep(1350 * time.Millisecond)
				_, _ = rw.WriteString("echo:" + line)
				_ = rw.Flush()
			default:
				_, _ = w.Write([]byte("ok"))
			}
		}))
		t.Cleanup(origin.Close)

		cfg := testConfig(origin.URL)
		cfg.upstreamBodyIdleTimeout = time.Second
		cfg.streamPaths = "/live/*"
		a, front := newTestApp(t, cfg, nil)

		cli := &http.Client{Timeout: 6 * time.Second}

		// Obtain admission pass cookie required by -stream-paths.
		admitResp, err := cli.Get(front.URL + "/admit")
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

		// 1. -stream-paths route survives pause > idle timeout.
		reqStream, _ := http.NewRequest(http.MethodGet, front.URL+"/live/feed", nil)
		reqStream.AddCookie(admitCk)
		respStream, err := cli.Do(reqStream)
		if err != nil {
			t.Fatalf("GET /live/feed: %v", err)
		}
		bodyStream, err := io.ReadAll(respStream.Body)
		_ = respStream.Body.Close()
		if err != nil || string(bodyStream) != "stream-1\nstream-2\n" {
			t.Fatalf("-stream-paths route failed: err=%v body=%q", err, string(bodyStream))
		}

		// 2. Non-stream-path SSE (text/event-stream) survives pause > idle timeout.
		respSSE, err := cli.Get(front.URL + "/events")
		if err != nil {
			t.Fatalf("GET /events: %v", err)
		}
		bodySSE, err := io.ReadAll(respSSE.Body)
		_ = respSSE.Body.Close()
		if err != nil || string(bodySSE) != "data: first\n\ndata: second\n\n" {
			t.Fatalf("non-stream-path SSE failed: err=%v body=%q", err, string(bodySSE))
		}

		// 3. Non-stream-path HTTP 101 Switching Protocols upgrade survives pause > idle timeout
		// and preserves io.ReadWriteCloser bidirectional traffic.
		conn, err := net.DialTimeout("tcp", front.Listener.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial /ws: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		if err != nil {
			t.Fatalf("write upgrade request: %v", err)
		}
		br := bufio.NewReader(conn)
		statusLine, err := br.ReadString('\n')
		if err != nil || !strings.Contains(statusLine, "101") {
			t.Fatalf("upgrade status line = %q err=%v, want 101", statusLine, err)
		}
		for {
			hdrLine, herr := br.ReadString('\n')
			if herr != nil {
				t.Fatalf("reading upgrade headers: %v", herr)
			}
			if hdrLine == "\r\n" {
				break
			}
		}
		if _, err := io.WriteString(conn, "ping\n"); err != nil {
			t.Fatalf("write upgraded frame: %v", err)
		}
		reply, err := br.ReadString('\n')
		if err != nil || reply != "echo:ping\n" {
			t.Fatalf("upgraded reply = %q err=%v, want %q", reply, err, "echo:ping\n")
		}

		if got := a.stats.upstreamBodyIdleTimeouts.Load(); got != 0 {
			t.Fatalf("exempt streams triggered upstreamBodyIdleTimeouts = %d, want 0", got)
		}
	})

	t.Run("SingleBackendActiveHealthFailFastWithCBDisabled", func(t *testing.T) {
		t.Parallel()

		var healthy atomic.Bool
		healthy.Store(true)
		var pageHits atomic.Int64

		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				if healthy.Load() {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("ok"))
				} else {
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte("sick"))
				}
				return
			}
			pageHits.Add(1)
			_, _ = w.Write([]byte("page-ok"))
		}))
		t.Cleanup(origin.Close)

		cfg := testConfig(origin.URL)
		cfg.upstreamHealthPath = "/healthz"
		cfg.upstreamHealthInterval = time.Second
		cfg.upstreamCBFailures = 0 // CB disabled; active health probe must still fail fast
		_, front := newTestApp(t, cfg, nil)

		cli := &http.Client{Timeout: 3 * time.Second}

		// Wait until initial probe confirms healthy.
		waitReadyStatus := func(want int) {
			t.Helper()
			deadline := time.Now().Add(4 * time.Second)
			var last int
			for time.Now().Before(deadline) {
				resp, err := cli.Get(front.URL + "/_room/readyz")
				if err == nil {
					_, _ = io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					last = resp.StatusCode
					if last == want {
						return
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
			t.Fatalf("/_room/readyz = %d, want %d within 4s", last, want)
		}

		waitReadyStatus(http.StatusOK)

		resp, err := cli.Get(front.URL + "/home")
		if err != nil {
			t.Fatalf("GET /home healthy: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || pageHits.Load() != 1 {
			t.Fatalf("healthy GET /home: status=%d hits=%d", resp.StatusCode, pageHits.Load())
		}

		// Mark origin unhealthy; active health probe must cause live traffic to fail fast with 503.
		healthy.Store(false)
		waitReadyStatus(http.StatusServiceUnavailable)

		resp, err = cli.Get(front.URL + "/home")
		if err != nil {
			t.Fatalf("GET /home unhealthy: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("unhealthy single-backend GET /home: status=%d body=%q, want 503", resp.StatusCode, string(body))
		}
		if pageHits.Load() != 1 {
			t.Fatalf("unhealthy single backend still received live traffic: pageHits=%d, want 1", pageHits.Load())
		}

		// Recover origin; active health probe restores live traffic automatically.
		healthy.Store(true)
		waitReadyStatus(http.StatusOK)

		resp, err = cli.Get(front.URL + "/home")
		if err != nil {
			t.Fatalf("GET /home recovered: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || pageHits.Load() != 2 {
			t.Fatalf("recovered GET /home: status=%d hits=%d, want 200 & 2", resp.StatusCode, pageHits.Load())
		}
	})

	t.Run("ConcertRecoveryRePanicsErrAbortHandlerAndReturns500OnPanic", func(t *testing.T) {
		t.Parallel()

		r := gin.New()
		r.Use(concertRecovery())
		r.GET("/boom", func(c *gin.Context) {
			panic("unexpected bug")
		})
		r.GET("/abort", func(c *gin.Context) {
			panic(http.ErrAbortHandler)
		})

		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("/boom status = %d, want 500", rec.Code)
		}

		var gotPanic any
		func() {
			defer func() { gotPanic = recover() }()
			r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/abort", nil))
		}()
		if gotPanic != http.ErrAbortHandler {
			t.Fatalf("/abort panic = %v, want http.ErrAbortHandler", gotPanic)
		}
	})

	t.Run("RespBodyIdleReader_CancelLifecycleAndParentCancel", func(t *testing.T) {
		t.Parallel()

		// 1. Exempt 101 ReadWriteCloser preserves io.ReadWriteCloser and only cancels on Close().
		parentCtx := context.Background()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/ws", nil)
		attemptReq, cancel := prepareRespBodyIdleTimeout(req, 50*time.Millisecond)
		if cancel == nil {
			t.Fatal("expected non-nil cancel for non-stream request")
		}
		buf := &testRWC{Reader: bytes.NewBufferString("abc")}
		resp := &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			Header:     make(http.Header),
			Body:       buf,
		}
		wrapRespBodyIdleTimeout(parentCtx, attemptReq, resp, 50*time.Millisecond, cancel, nil)
		rwc, ok := resp.Body.(io.ReadWriteCloser)
		if !ok {
			t.Fatalf("101 Switching Protocols body lost io.ReadWriteCloser interface")
		}
		if attemptReq.Context().Err() != nil {
			t.Fatal("attempt context was canceled prematurely for 101 upgrade")
		}
		if _, err := rwc.Write([]byte("hi")); err != nil {
			t.Fatalf("Write on 101 body: %v", err)
		}
		_ = rwc.Close()
		if attemptReq.Context().Err() == nil {
			t.Fatal("attempt context was not canceled after Close()")
		}

		// 2. Parent/client cancellation during blocked Read must NOT invoke onStall.
		pCtx, pCancel := context.WithCancel(context.Background())
		req2 := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil).WithContext(pCtx)
		aReq2, cancel2 := prepareRespBodyIdleTimeout(req2, 500*time.Millisecond)
		pr, pw := io.Pipe()
		t.Cleanup(func() { _ = pw.Close() })
		var stalls atomic.Int64
		resp2 := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/plain"}},
			Body:       pr,
		}
		wrapRespBodyIdleTimeout(pCtx, aReq2, resp2, 500*time.Millisecond, cancel2, func() {
			stalls.Add(1)
		})
		go func() {
			time.Sleep(40 * time.Millisecond)
			pCancel()
			_ = pw.CloseWithError(context.Canceled)
		}()
		_, err := io.ReadAll(resp2.Body)
		_ = resp2.Body.Close()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("parent cancel Read err = %v, want context.Canceled", err)
		}
		if stalls.Load() != 0 {
			t.Fatalf("parent cancel incremented stalls = %d, want 0", stalls.Load())
		}
	})
}

type testRWC struct {
	io.Reader
	written bytes.Buffer
	closed  bool
}

func (t *testRWC) Write(p []byte) (int, error) { return t.written.Write(p) }
func (t *testRWC) Close() error {
	t.closed = true
	return nil
}
