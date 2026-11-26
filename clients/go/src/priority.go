package concert

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// PriorityHeader is the HTTP response header emitted by an origin server to
// grant or clear a visitor's Concert priority rank. Concert strips this header
// before forwarding the response to the browser and binds the grant to the
// visitor's signed concert_admit cookie.
const PriorityHeader = "Concert-Priority"

// PriorityMinTTL and PriorityMaxTTL match Concert's accepted TTL bounds for
// non-guest Concert-Priority grants (1 minute to 24 hours).
const (
	PriorityMinTTL = time.Minute
	PriorityMaxTTL = 24 * time.Hour
)

// PriorityTier identifies one of Concert's origin-assigned visitor ranks.
// Ranks are ordered from lowest (PriorityGuest) to highest (PriorityStaff).
type PriorityTier string

const (
	// PriorityGuest clears any active priority grant (for example, on logout).
	PriorityGuest PriorityTier = "guest"
	// PriorityMember places a signed-in visitor ahead of anonymous guests.
	PriorityMember PriorityTier = "member"
	// PriorityProspect places a visitor with buying intent ahead of members.
	PriorityProspect PriorityTier = "prospect"
	// PriorityCustomer grants priority-lane eligibility to returning buyers.
	PriorityCustomer PriorityTier = "customer"
	// PrioritySubscriber grants priority-lane eligibility to active subscribers.
	PrioritySubscriber PriorityTier = "subscriber"
	// PriorityCheckout grants high-priority lane access during payment flows.
	PriorityCheckout PriorityTier = "checkout"
	// PriorityStaff grants the highest priority rank to operators and support.
	PriorityStaff PriorityTier = "staff"
)

// Sentinel errors returned by priority helpers. Callers should match with
// errors.Is.
var (
	ErrInvalidPriorityTier = errors.New("concert: invalid priority tier")
	ErrInvalidPriorityTTL  = errors.New("concert: invalid priority ttl")
	ErrNilResponseWriter   = errors.New("concert: nil http.ResponseWriter")
)

// PriorityResolver inspects an incoming HTTP request and chooses the
// Concert-Priority tier and optional TTL to emit on the response.
//
// Returning ok == false leaves the response without a Concert-Priority header.
// Returning ttl == 0 omits the ttl directive so Concert applies its per-tier
// default TTL.
type PriorityResolver func(r *http.Request) (tier PriorityTier, ttl time.Duration, ok bool)

// IsValid reports whether t is one of Concert's recognized priority tiers.
//
// # Parameters
//
//   - t (receiver): PriorityTier value to validate. Matching is exact and
//     case-sensitive against Concert's canonical lowercase tier identifiers.
//
// # Returns
//
// true when t is guest, member, prospect, customer, subscriber, checkout, or
// staff; false otherwise.
//
// # Example
//
//	if concert.PriorityCheckout.IsValid() {
//		_ = concert.SetPriority(w, concert.PriorityCheckout, 30*time.Minute)
//	}
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:138 (symbol reference)
//   - clients/go/src/concert_test.go:81 (direct call)
//   - clients/go/src/doc.go:138 (symbol reference)
//   - clients/go/src/priority.go:138 (direct call)
//   - clients/go/src/purge.go:138 (symbol reference)
//   - clients/go/src/rm1.go:138 (symbol reference)
//   - clients/go/src/signals.go:138 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (t PriorityTier) IsValid() bool {
	switch t {
	case PriorityGuest, PriorityMember, PriorityProspect, PriorityCustomer,
		PrioritySubscriber, PriorityCheckout, PriorityStaff:
		return true
	default:
		return false
	}
}

// ParsePriorityTier normalizes and validates a string priority tier name.
//
// # Parameters
//
//   - raw: Candidate tier name; surrounding whitespace and ASCII letter case
//     are normalized before lookup.
//
// # Returns
//
// The canonical PriorityTier and nil error on success, or an empty
// PriorityTier and ErrInvalidPriorityTier when raw does not match a known tier.
//
// # Example
//
//	tier, err := concert.ParsePriorityTier("Checkout")
//	if err != nil {
//		return err
//	}
//	_ = tier
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:185 (symbol reference)
//   - clients/go/src/concert_test.go:84 (direct call)
//   - clients/go/src/concert_test.go:90 (direct call)
//   - clients/go/src/doc.go:185 (symbol reference)
//   - clients/go/src/priority.go:185 (direct call)
//   - clients/go/src/purge.go:185 (symbol reference)
//   - clients/go/src/rm1.go:185 (symbol reference)
//   - clients/go/src/signals.go:185 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func ParsePriorityTier(raw string) (PriorityTier, error) {
	norm := PriorityTier(strings.ToLower(strings.TrimSpace(raw)))
	if !norm.IsValid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidPriorityTier, strings.TrimSpace(raw))
	}
	return norm, nil
}

// FormatPriorityHeader validates tier and ttl and renders a Concert-Priority
// header value (such as "checkout; ttl=30m" or "staff").
//
// # Parameters
//
//   - tier: Canonical PriorityTier (or mixed-case equivalent accepted after
//     normalization). Must be valid.
//   - ttl: Optional grant lifetime. Zero omits the ttl directive so Concert
//     applies its rank default. Negative values return ErrInvalidPriorityTTL.
//     For non-guest tiers, positive durations are clamped to
//     [PriorityMinTTL, PriorityMaxTTL] and formatted in whole seconds or Go
//     duration syntax accepted by Concert. For PriorityGuest, ttl is omitted.
//
// # Returns
//
// The formatted header value and nil error, or "" and an error matching
// ErrInvalidPriorityTier or ErrInvalidPriorityTTL.
//
// # Example
//
//	val, err := concert.FormatPriorityHeader(concert.PriorityCheckout, 30*time.Minute)
//	if err != nil {
//		return err
//	}
//	_ = val // "checkout; ttl=30m"
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:285 (symbol reference)
//   - clients/go/src/concert_test.go:114 (direct call)
//   - clients/go/src/concert_test.go:1014 (direct call)
//   - clients/go/src/doc.go:285 (symbol reference)
//   - clients/go/src/priority.go:285 (direct call)
//   - clients/go/src/purge.go:285 (symbol reference)
//   - clients/go/src/rm1.go:285 (symbol reference)
//   - clients/go/src/signals.go:285 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func FormatPriorityHeader(tier PriorityTier, ttl time.Duration) (string, error) {
	norm, err := ParsePriorityTier(string(tier))
	if err != nil {
		return "", err
	}
	if ttl < 0 {
		return "", fmt.Errorf("%w: must be non-negative, got %s", ErrInvalidPriorityTTL, ttl)
	}
	if norm == PriorityGuest || ttl == 0 {
		return string(norm), nil
	}
	// Clamp positive TTLs to Concert's server-side bounds [1m, 24h] and emit
	// clean duration strings (e.g. "30m", "2h", "90s") accepted by
	// parsePriorityHeader on the Concert proxy.
	if ttl < PriorityMinTTL {
		ttl = PriorityMinTTL
	} else if ttl > PriorityMaxTTL {
		ttl = PriorityMaxTTL
	}
	secs := int64(ttl / time.Second)
	return string(norm) + "; ttl=" + formatPriorityDuration(secs), nil
}

// formatPriorityDuration formats a positive whole-second duration cleanly as
// hours ("2h"), minutes ("30m"), or seconds ("90s").
//
// # Parameters
//
//   - secs: Positive duration in seconds.
//
// # Returns
//
// A compact duration token accepted by Go's time.ParseDuration and Concert's
// Concert-Priority header parser.
//
// # Example
//
//	s := formatPriorityDuration(1800) // "30m"
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:204 (symbol reference)
//   - clients/go/src/doc.go:204 (symbol reference)
//   - clients/go/src/priority.go:204 (direct call)
//   - clients/go/src/purge.go:204 (symbol reference)
//   - clients/go/src/rm1.go:204 (symbol reference)
//   - clients/go/src/signals.go:204 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func formatPriorityDuration(secs int64) string {
	switch {
	case secs%3600 == 0:
		return fmt.Sprintf("%dh", secs/3600)
	case secs%60 == 0:
		return fmt.Sprintf("%dm", secs/60)
	default:
		return fmt.Sprintf("%ds", secs)
	}
}

// SetPriority writes the Concert-Priority response header onto w.
//
// # Parameters
//
//   - w: Target http.ResponseWriter; must be non-nil. Call before WriteHeader
//     or writing the response body so the header is included on the wire.
//   - tier: Visitor priority tier to grant (or PriorityGuest to clear).
//   - ttl: Optional grant duration; zero uses Concert's per-tier default.
//
// # Returns
//
// nil on success, ErrNilResponseWriter if w is nil, or an error matching
// ErrInvalidPriorityTier / ErrInvalidPriorityTTL if tier or ttl is invalid.
//
// # Example
//
//	if err := concert.SetPriority(w, concert.PrioritySubscriber, 2*time.Hour); err != nil {
//		http.Error(w, "internal error", http.StatusInternalServerError)
//		return
//	}
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:469 (symbol reference)
//   - clients/go/src/concert_test.go:124 (direct call)
//   - clients/go/src/concert_test.go:129 (direct call)
//   - clients/go/src/doc.go:469 (symbol reference)
//   - clients/go/src/priority.go:469 (direct call)
//   - clients/go/src/purge.go:469 (symbol reference)
//   - clients/go/src/rm1.go:469 (symbol reference)
//   - clients/go/src/signals.go:469 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func SetPriority(w http.ResponseWriter, tier PriorityTier, ttl time.Duration) error {
	if w == nil {
		return ErrNilResponseWriter
	}
	val, err := FormatPriorityHeader(tier, ttl)
	if err != nil {
		return err
	}
	w.Header().Set(PriorityHeader, val)
	return nil
}

// PriorityMiddleware returns a standard net/http middleware that evaluates
// resolve for every incoming request and sets the Concert-Priority response
// header before invoking next.
//
// # Parameters
//
//   - resolve: Callback invoked synchronously once per request before next.
//     If resolve is nil, the middleware passes requests through unchanged.
//     If resolve returns ok == false or an invalid tier/ttl, the header is not
//     set and the request proceeds without failing the handler.
//
// # Returns
//
// A middleware function safe for concurrent use across goroutines provided
// resolve itself is concurrency-safe.
//
// # Example
//
//	mw := concert.PriorityMiddleware(func(r *http.Request) (concert.PriorityTier, time.Duration, bool) {
//		if r.URL.Path == "/checkout" {
//			return concert.PriorityCheckout, 30 * time.Minute, true
//		}
//		return "", 0, false
//	})
//	handler := mw(mux)
//	_ = handler
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:173 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func PriorityMiddleware(resolve PriorityResolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if next == nil {
			next = http.NotFoundHandler()
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			applyResolvedPriority(w, r, resolve)
			next.ServeHTTP(w, r)
		})
	}
}

// PriorityHandlerFunc returns a standard http.HandlerFunc that resolves and
// sets the Concert-Priority header on w without writing a body. It can be
// plugged directly into Gin via gin.WrapF(concert.PriorityHandlerFunc(resolve))
// or composed in any net/http handler chain.
//
// # Parameters
//
//   - resolve: Callback invoked synchronously for each request. When nil or
//     when it returns ok == false, the header is left untouched.
//
// # Returns
//
// An http.HandlerFunc safe for concurrent use when resolve is concurrency-safe.
//
// # Example
//
//	// With Gin (zero Gin dependency in this client package):
//	// router.Use(gin.WrapF(concert.PriorityHandlerFunc(resolve)))
//	hf := concert.PriorityHandlerFunc(func(r *http.Request) (concert.PriorityTier, time.Duration, bool) {
//		return concert.PriorityMember, 0, true
//	})
//	_ = hf
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:230 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func PriorityHandlerFunc(resolve PriorityResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		applyResolvedPriority(w, r, resolve)
	}
}

// GinPriorityAdapter returns a framework-agnostic adapter function with
// signature func(w http.ResponseWriter, r *http.Request, next func()) for
// wrapping inside a Gin HandlerFunc without importing github.com/gin-gonic/gin.
//
// # Parameters
//
//   - resolve: Callback invoked synchronously before next. When nil or when it
//     returns ok == false, the header is not set.
//
// # Returns
//
// An adapter function that sets Concert-Priority on w and then invokes next
// (if non-nil). Safe for concurrent use when resolve is concurrency-safe.
//
// # Example
//
//	adapter := concert.GinPriorityAdapter(func(r *http.Request) (concert.PriorityTier, time.Duration, bool) {
//		if r.Header.Get("X-Staff") == "1" {
//			return concert.PriorityStaff, 8 * time.Hour, true
//		}
//		return "", 0, false
//	})
//	// In a Gin application:
//	// r.Use(func(c *gin.Context) { adapter(c.Writer, c.Request, c.Next) })
//	_ = adapter
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:214 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func GinPriorityAdapter(resolve PriorityResolver) func(w http.ResponseWriter, r *http.Request, next func()) {
	return func(w http.ResponseWriter, r *http.Request, next func()) {
		applyResolvedPriority(w, r, resolve)
		if next != nil {
			next()
		}
	}
}

// applyResolvedPriority invokes resolve (if non-nil) and writes a valid
// Concert-Priority header to w, silently ignoring invalid resolver outputs so
// origin responses are never aborted by bad priority metadata.
//
// # Parameters
//
//   - w: Destination http.ResponseWriter.
//   - r: Incoming *http.Request passed to resolve.
//   - resolve: PriorityResolver callback; no-op if nil.
//
// # Returns
//
// None.
//
// # Example
//
//	applyResolvedPriority(w, r, resolve)
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:333 (symbol reference)
//   - clients/go/src/bidding.go:371 (symbol reference)
//   - clients/go/src/bidding.go:410 (symbol reference)
//   - clients/go/src/doc.go:333 (symbol reference)
//   - clients/go/src/doc.go:371 (symbol reference)
//   - clients/go/src/doc.go:410 (symbol reference)
//   - clients/go/src/priority.go:333 (direct call)
//   - clients/go/src/priority.go:371 (direct call)
//   - clients/go/src/priority.go:410 (direct call)
//   - clients/go/src/purge.go:333 (symbol reference)
//   - clients/go/src/purge.go:371 (symbol reference)
//   - clients/go/src/purge.go:410 (symbol reference)
//   - clients/go/src/rm1.go:333 (symbol reference)
//   - clients/go/src/rm1.go:371 (symbol reference)
//   - clients/go/src/rm1.go:410 (symbol reference)
//   - clients/go/src/signals.go:333 (symbol reference)
//   - clients/go/src/signals.go:371 (symbol reference)
//   - clients/go/src/signals.go:410 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func applyResolvedPriority(w http.ResponseWriter, r *http.Request, resolve PriorityResolver) {
	if resolve == nil || w == nil || r == nil {
		return
	}
	tier, ttl, ok := resolve(r)
	if !ok {
		return
	}
	// Best-effort header emission: invalid tier/TTL is dropped rather than
	// breaking an application response.
	_ = SetPriority(w, tier, ttl)
}
