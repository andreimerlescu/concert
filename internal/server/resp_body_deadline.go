package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// errUpstreamBodyIdleTimeout is returned from respBodyIdleReader.Read when an
// upstream stops sending response body bytes for longer than
// -upstream-body-idle-timeout.
var errUpstreamBodyIdleTimeout = errors.New("upstream response body idle timeout")

type ctxReqIsStreamKey struct{}

// withReqIsStream marks req as belonging to a -stream-paths route so both
// trackedTransport and the FastCGI transport exempt its response body from the
// non-stream response-body idle timeout.
func withReqIsStream(req *http.Request) *http.Request {
	if req == nil {
		return nil
	}
	req = req.WithContext(context.WithValue(req.Context(), ctxReqIsStreamKey{}, true))
	return withFastCGIStream(req)
}

func isReqStream(req *http.Request) bool {
	if req == nil {
		return false
	}
	v, _ := req.Context().Value(ctxReqIsStreamKey{}).(bool)
	return v
}

// prepareRespBodyIdleTimeout derives a cancellable child context on req when
// idle > 0 and req is not already marked as a stream route. When cancel is
// non-nil, the caller must either hand it to wrapRespBodyIdleTimeout on
// RoundTrip success or invoke cancel() on RoundTrip error.
func prepareRespBodyIdleTimeout(req *http.Request, idle time.Duration) (*http.Request, context.CancelFunc) {
	if idle <= 0 || isReqStream(req) {
		return req, nil
	}
	ctx, cancel := context.WithCancel(req.Context())
	return req.WithContext(ctx), cancel
}

func isEventStreamContentType(ct string) bool {
	if semi := strings.IndexByte(ct, ';'); semi >= 0 {
		ct = ct[:semi]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "text/event-stream")
}

func isExemptRespBodyIdle(resp *http.Response) bool {
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return true
	}
	return isEventStreamContentType(resp.Header.Get("Content-Type"))
}

// wrapRespBodyIdleTimeout wraps resp.Body with a per-read idle timer unless
// disabled or exempted (-stream-paths, HTTP 101 upgrades, text/event-stream,
// or empty/NoBody). Ownership of cancel transfers to resp.Body (or is called
// immediately when no body remains) so exempt long-lived streams are never
// canceled prematurely and no context leaks.
func wrapRespBodyIdleTimeout(
	parentCtx context.Context,
	req *http.Request,
	resp *http.Response,
	idle time.Duration,
	cancel context.CancelFunc,
	onStall func(),
) {
	if resp == nil {
		if cancel != nil {
			cancel()
		}
		return
	}
	if resp.Body == nil || resp.Body == http.NoBody {
		if cancel != nil {
			cancel()
		}
		return
	}
	if idle <= 0 || isReqStream(req) || isExemptRespBodyIdle(resp) {
		if cancel != nil {
			resp.Body = wrapCancelOnClose(resp.Body, cancel)
		}
		return
	}
	resp.Body = &respBodyIdleReader{
		orig:      resp.Body,
		idle:      idle,
		parentCtx: parentCtx,
		cancel:    cancel,
		onStall:   onStall,
	}
}

func wrapCancelOnClose(body io.ReadCloser, cancel context.CancelFunc) io.ReadCloser {
	if rwc, ok := body.(io.ReadWriteCloser); ok {
		return &cancelOnCloseReadWriteCloser{ReadWriteCloser: rwc, cancel: cancel}
	}
	return &cancelOnCloseReadCloser{ReadCloser: body, cancel: cancel}
}

type cancelOnCloseReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
	once   sync.Once
}

func (c *cancelOnCloseReadCloser) Close() error {
	err := c.ReadCloser.Close()
	c.once.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
	})
	return err
}

// cancelOnCloseReadWriteCloser preserves io.ReadWriteCloser for HTTP 101
// Switching Protocols upgraded connections handled by httputil.ReverseProxy.
type cancelOnCloseReadWriteCloser struct {
	io.ReadWriteCloser
	cancel context.CancelFunc
	once   sync.Once
}

func (c *cancelOnCloseReadWriteCloser) Close() error {
	err := c.ReadWriteCloser.Close()
	c.once.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
	})
	return err
}

// respBodyIdleReader wraps an upstream response body with a per-read idle
// timeout. Active slow downloads that keep delivering chunks within idle
// succeed regardless of total transfer time; stalled origins have their
// attempt context canceled and body closed immediately.
type respBodyIdleReader struct {
	orig      io.ReadCloser
	idle      time.Duration
	parentCtx context.Context
	cancel    context.CancelFunc
	onStall   func()

	mu       sync.Mutex
	timer    *time.Timer
	armed    bool
	deadline time.Time
	closed   bool
	timedOut atomic.Bool

	stallOnce sync.Once
	closeOnce sync.Once
	closeErr  error
}

func (r *respBodyIdleReader) armTimer() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.timedOut.Load() {
		return false
	}
	r.armed = true
	r.deadline = time.Now().Add(r.idle)
	if r.timer == nil {
		r.timer = time.AfterFunc(r.idle, r.onTimer)
	} else {
		r.timer.Reset(r.idle)
	}
	return true
}

func (r *respBodyIdleReader) disarmTimer() {
	r.mu.Lock()
	r.armed = false
	if r.timer != nil {
		if !r.timer.Stop() {
			// Timer already fired; discard so a future Reset cannot race with
			// its callback goroutine.
			r.timer = nil
		}
	}
	r.mu.Unlock()
}

func (r *respBodyIdleReader) onTimer() {
	r.mu.Lock()
	if r.closed || !r.armed || time.Now().Before(r.deadline) {
		r.mu.Unlock()
		return
	}
	r.armed = false
	r.timer = nil
	if r.parentCtx != nil && r.parentCtx.Err() != nil {
		// Parent/client request already canceled; do not attribute as upstream stall.
		r.mu.Unlock()
		if r.cancel != nil {
			r.cancel()
		}
		return
	}
	r.timedOut.Store(true)
	r.mu.Unlock()

	r.abortOnStall()
}

func (r *respBodyIdleReader) markNativeTimeout() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.armed = false
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	r.timedOut.Store(true)
	r.mu.Unlock()

	r.abortOnStall()
}

func (r *respBodyIdleReader) abortOnStall() {
	r.stallOnce.Do(func() {
		if r.onStall != nil {
			r.onStall()
		}
	})
	// Cancel the per-attempt upstream request context BEFORE closing orig so
	// http.Transport (H1/H2) and fcgi.Transport abort the upstream socket/stream
	// and unblock any in-flight orig.Read without blocking on orig's mutex.
	if r.cancel != nil {
		r.cancel()
	}
	_ = r.closeOrig()
}

func (r *respBodyIdleReader) closeOrig() error {
	r.closeOnce.Do(func() {
		r.closeErr = r.orig.Close()
	})
	return r.closeErr
}

func (r *respBodyIdleReader) Read(p []byte) (int, error) {
	if r.timedOut.Load() {
		return 0, errUpstreamBodyIdleTimeout
	}
	if !r.armTimer() {
		if r.timedOut.Load() {
			return 0, errUpstreamBodyIdleTimeout
		}
		return r.orig.Read(p)
	}
	n, err := r.orig.Read(p)
	r.disarmTimer()
	if r.timedOut.Load() {
		return n, errUpstreamBodyIdleTimeout
	}
	// If an underlying transport's native per-read socket deadline (such as
	// fcgi.Transport's conn.SetReadDeadline) tripped slightly before our timer,
	// still record the stall metric, log, and circuit-breaker failure once.
	if err != nil && isTimeoutError(err) && (r.parentCtx == nil || r.parentCtx.Err() == nil) {
		r.markNativeTimeout()
		return n, errUpstreamBodyIdleTimeout
	}
	return n, err
}

func (r *respBodyIdleReader) Close() error {
	r.mu.Lock()
	r.closed = true
	r.armed = false
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	timedOut := r.timedOut.Load()
	r.mu.Unlock()

	if timedOut {
		if r.cancel != nil {
			r.cancel()
		}
		return r.closeOrig()
	}
	// On normal completion, close orig before canceling the attempt context so
	// http.Transport can return healthy keep-alive connections to the idle pool.
	err := r.closeOrig()
	if r.cancel != nil {
		r.cancel()
	}
	return err
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
