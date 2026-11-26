package concert

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Waiting-room response header names emitted by Concert.
const (
	HeaderConcertQueue     = "X-Concert-Queue"
	HeaderConcertPosition  = "X-Concert-Position"
	HeaderRetryAfter       = "Retry-After"
	HeaderConcertStatusURL = "X-Concert-Status-Url"
	DefaultQueueStatusURL  = "/queue/status"
)

// WaitingRoomSignal holds parsed waiting-room metadata extracted from HTTP
// response headers.
//
// Concert guarantees that X-Concert-Queue: 1 is emitted ONLY on genuine
// waiting-room responses, never on abuse bans, capacity-breaker 503s, or
// upstream 429/503 responses.
type WaitingRoomSignal struct {
	// Queued is true strictly when X-Concert-Queue equals "1".
	Queued bool
	// Position is the visitor's non-negative queue position when HasPosition is true.
	Position int
	// HasPosition reports whether X-Concert-Position contained a valid non-negative integer.
	HasPosition bool
	// RetryAfter is the suggested polling interval parsed from Retry-After when
	// HasRetryAfter is true.
	RetryAfter time.Duration
	// HasRetryAfter reports whether Retry-After was present and parseable.
	HasRetryAfter bool
	// StatusURL is the status endpoint from X-Concert-Status-Url, or
	// DefaultQueueStatusURL ("/queue/status") when Queued is true and the header
	// was omitted (Concert omits the header for the default path).
	StatusURL string
}

// ParseWaitingRoomSignal parses Concert waiting-room headers from h using the
// current wall clock for HTTP-date Retry-After headers.
//
// # Parameters
//
//   - h: HTTP response headers (may be nil). The map is read-only and never
//     mutated.
//
// # Returns
//
// A WaitingRoomSignal value. Queued is true only when X-Concert-Queue is "1".
// Invalid or negative numeric values leave their corresponding Has* flag false
// instead of failing.
//
// # Example
//
//	sig := concert.ParseWaitingRoomSignal(resp.Header)
//	if sig.Queued {
//		fmt.Printf("queued at position %d, poll %s after %s\n", sig.Position, sig.StatusURL, sig.RetryAfter)
//	}
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:117 (symbol reference)
//   - clients/go/src/concert_test.go:466 (direct call)
//   - clients/go/src/concert_test.go:473 (direct call)
//   - clients/go/src/concert_test.go:482 (direct call)
//   - clients/go/src/concert_test.go:498 (direct call)
//   - clients/go/src/concert_test.go:507 (direct call)
//   - clients/go/src/concert_test.go:1031 (direct call)
//   - clients/go/src/doc.go:117 (symbol reference)
//   - clients/go/src/priority.go:117 (symbol reference)
//   - clients/go/src/purge.go:117 (symbol reference)
//   - clients/go/src/rm1.go:117 (symbol reference)
//   - clients/go/src/signals.go:117 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func ParseWaitingRoomSignal(h http.Header) WaitingRoomSignal {
	return parseWaitingRoomSignalAt(h, time.Now().UTC())
}

// IsQueuedResponse reports whether resp is a genuine Concert waiting-room
// response (non-nil response carrying X-Concert-Queue: 1).
//
// # Parameters
//
//   - resp: HTTP response to inspect; nil returns false.
//
// # Returns
//
// true iff resp is non-nil and resp.Header contains X-Concert-Queue: 1.
//
// # Example
//
//	if concert.IsQueuedResponse(resp) {
//		sig := concert.ParseWaitingRoomSignal(resp.Header)
//		_ = sig
//	}
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:513 (direct call)
//   - clients/go/src/concert_test.go:516 (direct call)
//   - clients/go/src/concert_test.go:519 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func IsQueuedResponse(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	return ParseWaitingRoomSignal(resp.Header).Queued
}

// parseWaitingRoomSignalAt parses Concert waiting-room headers relative to now
// so HTTP-date Retry-After headers can be tested deterministically.
//
// # Parameters
//
//   - h: HTTP response headers (may be nil).
//   - now: Reference timestamp for HTTP-date Retry-After parsing.
//
// # Returns
//
// Parsed WaitingRoomSignal.
//
// # Example
//
//	sig := parseWaitingRoomSignalAt(resp.Header, time.Now().UTC())
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:83 (symbol reference)
//   - clients/go/src/doc.go:83 (symbol reference)
//   - clients/go/src/priority.go:83 (symbol reference)
//   - clients/go/src/purge.go:83 (symbol reference)
//   - clients/go/src/rm1.go:83 (symbol reference)
//   - clients/go/src/signals.go:83 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func parseWaitingRoomSignalAt(h http.Header, now time.Time) WaitingRoomSignal {
	if h == nil {
		return WaitingRoomSignal{}
	}
	var sig WaitingRoomSignal
	if strings.TrimSpace(h.Get(HeaderConcertQueue)) == "1" {
		sig.Queued = true
	}
	if rawPos := strings.TrimSpace(h.Get(HeaderConcertPosition)); rawPos != "" {
		if pos, err := strconv.Atoi(rawPos); err == nil && pos >= 0 {
			sig.Position = pos
			sig.HasPosition = true
		}
	}
	if d, ok := parseRetryAfter(h.Get(HeaderRetryAfter), now); ok {
		sig.RetryAfter = d
		sig.HasRetryAfter = true
	}
	if statusURL := strings.TrimSpace(h.Get(HeaderConcertStatusURL)); statusURL != "" {
		sig.StatusURL = statusURL
	} else if sig.Queued {
		// Concert intentionally omits X-Concert-Status-Url when using the
		// default /queue/status endpoint; populate the default for callers.
		sig.StatusURL = DefaultQueueStatusURL
	}
	return sig
}

// parseRetryAfter parses an RFC 9110 Retry-After header value as either
// non-negative delay-seconds or an HTTP-date relative to now.
//
// # Parameters
//
//   - raw: Raw Retry-After header string.
//   - now: Reference UTC instant for HTTP-date subtraction.
//
// # Returns
//
// Parsed duration (>= 0) and true when parseable, or (0, false) otherwise.
//
// # Example
//
//	d, ok := parseRetryAfter("5", time.Now().UTC())
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:162 (symbol reference)
//   - clients/go/src/doc.go:162 (symbol reference)
//   - clients/go/src/priority.go:162 (symbol reference)
//   - clients/go/src/purge.go:162 (symbol reference)
//   - clients/go/src/rm1.go:162 (symbol reference)
//   - clients/go/src/signals.go:162 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func parseRetryAfter(raw string, now time.Time) (time.Duration, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false
	}
	if secs, err := strconv.ParseInt(s, 10, 64); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if ts, err := http.ParseTime(s); err == nil {
		d := ts.Sub(now)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}
