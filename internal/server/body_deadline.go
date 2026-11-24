package server

import (
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var (
	errUploadTimeExceeded = errors.New("request body upload exceeded max upload time")
	errBodyReadAborted    = errors.New("request body read aborted")
)

// deadlineBody wraps an inbound HTTP request body with both a per-chunk idle
// read-progress deadline and a total wall-clock upload deadline using Go's
// http.ResponseController.SetReadDeadline.
//
// Legitimate large uploads that make steady progress succeed up to maxTotal,
// while stalled clients fail after idle and 1-byte tricklers fail at maxTotal.
// Calling Abort expires the read deadline immediately so any goroutine blocked
// in Read (such as FastCGI STDIN streaming) unblocks without hanging or
// leaking, and post-handler keep-alive body draining does not block.
type deadlineBody struct {
	inner        io.ReadCloser
	rc           *http.ResponseController
	idle         time.Duration
	hardDeadline time.Time

	eof     atomic.Bool
	dlMu    sync.Mutex
	aborted bool
	abortOK bool
}

func newDeadlineBody(w http.ResponseWriter, body io.ReadCloser, idle, maxTotal time.Duration) *deadlineBody {
	db := &deadlineBody{
		inner: body,
		rc:    http.NewResponseController(w),
		idle:  idle,
	}
	if maxTotal > 0 {
		db.hardDeadline = time.Now().Add(maxTotal)
	}
	return db
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	now := time.Now()
	if !b.hardDeadline.IsZero() && !now.Before(b.hardDeadline) {
		b.Abort()
		return 0, errUploadTimeExceeded
	}
	var dl time.Time
	if b.idle > 0 {
		dl = now.Add(b.idle)
	}
	if !b.hardDeadline.IsZero() && (dl.IsZero() || b.hardDeadline.Before(dl)) {
		dl = b.hardDeadline
	}
	b.dlMu.Lock()
	if b.aborted {
		b.dlMu.Unlock()
		return 0, errBodyReadAborted
	}
	if !dl.IsZero() {
		_ = b.rc.SetReadDeadline(dl)
	}
	b.dlMu.Unlock()

	n, err := b.inner.Read(p)
	if errors.Is(err, io.EOF) {
		b.eof.Store(true)
		b.dlMu.Lock()
		if !b.aborted {
			_ = b.rc.SetReadDeadline(time.Time{})
		}
		b.dlMu.Unlock()
	} else if err != nil {
		// On read timeout or connection error, mark aborted so post-handler
		// body draining does not re-block on the stalled peer.
		b.Abort()
	}
	return n, err
}

// Abort forces any blocked Read on the underlying client connection to return
// immediately with a read deadline error. Returns true if the underlying
// ResponseWriter supported SetReadDeadline. Safe to call concurrently.
func (b *deadlineBody) Abort() bool {
	b.dlMu.Lock()
	if !b.aborted {
		b.aborted = true
		b.abortOK = b.rc.SetReadDeadline(time.Now()) == nil
	}
	ok := b.abortOK
	b.dlMu.Unlock()
	return ok
}

func (b *deadlineBody) Close() error {
	if b.eof.Load() {
		b.dlMu.Lock()
		if !b.aborted {
			_ = b.rc.SetReadDeadline(time.Time{})
		}
		b.dlMu.Unlock()
	}
	return b.inner.Close()
}

// Finish restores the connection's read deadline if the request body reached
// EOF cleanly, or keeps it expired (forcing clean connection teardown) if the
// handler returned early while unread body bytes remained.
func (b *deadlineBody) Finish() {
	if b.eof.Load() {
		b.dlMu.Lock()
		if !b.aborted {
			_ = b.rc.SetReadDeadline(time.Time{})
			b.dlMu.Unlock()
			return
		}
		b.dlMu.Unlock()
	}
	b.Abort()
}
