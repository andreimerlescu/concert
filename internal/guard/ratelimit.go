package guard

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultRouteMaxEntries is the default per-route client bucket ceiling
	// before O(1) LRU eviction kicks in.
	DefaultRouteMaxEntries = 65536

	maxRuleRate = 1_000_000_000
	maxRuleSpec = 128
)

// ErrInvalidRule is returned when a declarative rate-limit rule specification
// or [Rule] struct is malformed or has out-of-range parameters.
var ErrInvalidRule = errors.New("guard: invalid rate-limit rule")

// Rule defines a token-bucket rate limit attached to a URL path prefix.
type Rule struct {
	// Prefix is the URL path prefix matched by this rule (for example "/api/login"
	// or "/"). Must start with "/" when passed to NewRouteLimiter.
	Prefix string

	// Rate is the number of tokens replenished per Window. Must be > 0.
	Rate int

	// Window is the replenishment interval for Rate tokens. Must be > 0.
	Window time.Duration

	// Burst is the maximum bucket capacity (initial tokens). When <= 0,
	// NewRouteLimiter defaults Burst to Rate.
	Burst int
}

// ParseRule parses a compact declarative rate specification of the form
// "<rate>/<window>" or "<rate>/<window>:<burst>", such as "5/1m", "20/s", or
// "10/1m:25".
//
// Single-letter window shorthands "s", "m", and "h" are accepted as "1s", "1m",
// and "1h"; otherwise the window uses [time.ParseDuration]. The returned Rule
// has an empty Prefix, which the caller may populate before calling
// [NewRouteLimiter], or use [ParseRouteRule] directly.
//
// # Parameters
//
//   - spec: Non-empty rate specification string, at most 128 bytes.
//
// # Returns
//
// A validated [Rule] (with Burst set to Rate when omitted) and nil error on
// success; the zero Rule and an error matching [ErrInvalidRule] otherwise.
//
// # Example
//
//	rule, err := guard.ParseRule("5/1m")
//	if err != nil {
//	    return err
//	}
//	rule.Prefix = "/login"
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:173 (function value)
//   - internal/guard/fuzz_test.go:54 (direct call)
//   - internal/guard/fuzz_test.go:415 (function value)
//   - internal/guard/fuzz_test.go:426 (function value)
//   - internal/guard/geoasn.go:173 (function value)
//   - internal/guard/guard_test.go:54 (function value)
//   - internal/guard/guard_test.go:415 (direct call)
//   - internal/guard/guard_test.go:426 (direct call)
//   - internal/guard/queue_quota.go:173 (function value)
//   - internal/guard/ratelimit.go:173 (direct call)
//   - internal/guard/secret.go:173 (function value)
//   - internal/guard/shedder.go:173 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func ParseRule(spec string) (Rule, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" || len(trimmed) > maxRuleSpec {
		return Rule{}, fmt.Errorf("%w: empty or oversized spec", ErrInvalidRule)
	}
	rateStr, rest, ok := strings.Cut(trimmed, "/")
	if !ok || rateStr == "" || rest == "" {
		return Rule{}, fmt.Errorf("%w: expected <rate>/<window>[:<burst>]", ErrInvalidRule)
	}

	rate, err := strconv.Atoi(strings.TrimSpace(rateStr))
	if err != nil || rate <= 0 || rate > maxRuleRate {
		return Rule{}, fmt.Errorf("%w: invalid rate %q", ErrInvalidRule, rateStr)
	}

	winPart := rest
	burst := rate
	if w, b, hasBurst := strings.Cut(rest, ":"); hasBurst {
		winPart = w
		bv, bErr := strconv.Atoi(strings.TrimSpace(b))
		if bErr != nil || bv <= 0 || bv > maxRuleRate {
			return Rule{}, fmt.Errorf("%w: invalid burst %q", ErrInvalidRule, b)
		}
		burst = bv
	}

	winStr := strings.TrimSpace(winPart)
	switch winStr {
	case "s", "m", "h":
		winStr = "1" + winStr
	}
	window, err := time.ParseDuration(winStr)
	if err != nil || window <= 0 {
		return Rule{}, fmt.Errorf("%w: invalid window %q", ErrInvalidRule, winPart)
	}

	return Rule{
		Rate:   rate,
		Window: window,
		Burst:  burst,
	}, nil
}

// ParseRouteRule parses spec via [ParseRule] and binds it to prefix.
//
// # Parameters
//
//   - prefix: URL path prefix starting with "/".
//   - spec: Rate specification accepted by [ParseRule].
//
// # Returns
//
// A validated [Rule] bound to prefix, or an error matching [ErrInvalidRule].
//
// # Example
//
//	rule, err := guard.ParseRouteRule("/api/ticket", "5/1m:10")
//	if err != nil {
//	    return err
//	}
//	_ = rule
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:61 (direct call)
//   - internal/guard/fuzz_test.go:431 (function value)
//   - internal/guard/fuzz_test.go:435 (function value)
//   - internal/guard/fuzz_test.go:439 (function value)
//   - internal/guard/fuzz_test.go:991 (function value)
//   - internal/guard/guard_test.go:61 (function value)
//   - internal/guard/guard_test.go:431 (direct call)
//   - internal/guard/guard_test.go:435 (direct call)
//   - internal/guard/guard_test.go:439 (direct call)
//   - internal/guard/guard_test.go:991 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func ParseRouteRule(prefix, spec string) (Rule, error) {
	if !validRoutePrefix(prefix) {
		return Rule{}, fmt.Errorf("%w: prefix must start with '/'", ErrInvalidRule)
	}
	r, err := ParseRule(spec)
	if err != nil {
		return Rule{}, err
	}
	r.Prefix = prefix
	return r, nil
}

// validRoutePrefix reports whether prefix is a non-empty URL path prefix
// starting with '/' and containing no whitespace or control characters.
//
// # Parameters
//
//   - prefix: Candidate path prefix.
//
// # Returns
//
// true when prefix is valid for route matching.
//
// # Example
//
//	ok := validRoutePrefix("/api/v1")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:170 (function value)
//   - internal/guard/challenge.go:308 (function value)
//   - internal/guard/geoasn.go:170 (function value)
//   - internal/guard/geoasn.go:308 (function value)
//   - internal/guard/queue_quota.go:170 (function value)
//   - internal/guard/queue_quota.go:308 (function value)
//   - internal/guard/ratelimit.go:170 (direct call)
//   - internal/guard/ratelimit.go:308 (direct call)
//   - internal/guard/secret.go:170 (function value)
//   - internal/guard/secret.go:308 (function value)
//   - internal/guard/shedder.go:170 (function value)
//   - internal/guard/shedder.go:308 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func validRoutePrefix(prefix string) bool {
	if prefix == "" || prefix[0] != '/' {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if prefix[i] <= 0x20 || prefix[i] == 0x7f {
			return false
		}
	}
	return true
}

// tokenEntry holds token-bucket state for a single client bucket on one route
// and participates in the route's intrusive doubly-linked LRU list.
type tokenEntry struct {
	key    netip.Addr
	tokens float64
	last   time.Time
	prev   *tokenEntry
	next   *tokenEntry
}

// routeLimiterState holds one route's immutable rule and its mutex-guarded
// O(1) LRU map of per-client token buckets.
type routeLimiterState struct {
	rule         Rule
	tokensPerSec float64
	maxEntries   int

	mu      sync.Mutex
	entries map[netip.Addr]*tokenEntry // guarded by mu
	head    *tokenEntry                // MRU, guarded by mu
	tail    *tokenEntry                // LRU, guarded by mu
}

// RouteLimiter enforces declarative per-route token-bucket rate limits using
// longest-prefix matching and O(1) doubly-linked-list LRU bounded maps per
// route (R3).
//
// The route slice is immutable after construction; each route owns an
// independent mutex so traffic on different routes does not contend. All
// exported methods are safe for concurrent use.
type RouteLimiter struct {
	routes []*routeLimiterState
}

// NewRouteLimiter validates rules and constructs a [RouteLimiter] sorted by
// descending prefix length for longest-prefix matching.
//
// # Parameters
//
//   - rules: Slice of per-route [Rule] definitions. Duplicate prefixes or
//     invalid rules (empty prefix, missing leading '/', non-positive Rate or
//     Window) return an error matching [ErrInvalidRule].
//   - maxEntries: Maximum client buckets retained per route before O(1) LRU
//     eviction. Defaults to [DefaultRouteMaxEntries] (65536) when <= 0.
//
// # Returns
//
// A concurrency-safe *RouteLimiter, or an error matching [ErrInvalidRule].
//
// # Example
//
//	r1, _ := guard.ParseRouteRule("/", "60/1m")
//	r2, _ := guard.ParseRouteRule("/api/login", "5/1m")
//	lim, err := guard.NewRouteLimiter([]guard.Rule{r1, r2}, 10000)
//	if err != nil {
//	    return err
//	}
//	_ = lim
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:65 (direct call)
//   - internal/guard/fuzz_test.go:445 (function value)
//   - internal/guard/fuzz_test.go:449 (function value)
//   - internal/guard/fuzz_test.go:995 (function value)
//   - internal/guard/guard_test.go:65 (function value)
//   - internal/guard/guard_test.go:445 (direct call)
//   - internal/guard/guard_test.go:449 (direct call)
//   - internal/guard/guard_test.go:995 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func NewRouteLimiter(rules []Rule, maxEntries int) (*RouteLimiter, error) {
	if maxEntries <= 0 {
		maxEntries = DefaultRouteMaxEntries
	}
	seen := make(map[string]struct{}, len(rules))
	routes := make([]*routeLimiterState, 0, len(rules))
	for _, r := range rules {
		if !validRoutePrefix(r.Prefix) {
			return nil, fmt.Errorf("%w: invalid prefix %q", ErrInvalidRule, r.Prefix)
		}
		if r.Rate <= 0 || r.Rate > maxRuleRate {
			return nil, fmt.Errorf("%w: invalid rate %d for %q", ErrInvalidRule, r.Rate, r.Prefix)
		}
		if r.Window <= 0 {
			return nil, fmt.Errorf("%w: invalid window %v for %q", ErrInvalidRule, r.Window, r.Prefix)
		}
		if r.Burst <= 0 {
			r.Burst = r.Rate
		}
		if r.Burst > maxRuleRate {
			return nil, fmt.Errorf("%w: invalid burst %d for %q", ErrInvalidRule, r.Burst, r.Prefix)
		}
		if _, dup := seen[r.Prefix]; dup {
			return nil, fmt.Errorf("%w: duplicate prefix %q", ErrInvalidRule, r.Prefix)
		}
		seen[r.Prefix] = struct{}{}

		tps := float64(r.Rate) / r.Window.Seconds()
		routes = append(routes, &routeLimiterState{
			rule:         r,
			tokensPerSec: tps,
			maxEntries:   maxEntries,
			entries:      make(map[netip.Addr]*tokenEntry),
		})
	}

	// Longest prefix wins; ties are broken lexicographically for determinism.
	sort.Slice(routes, func(i, j int) bool {
		if len(routes[i].rule.Prefix) != len(routes[j].rule.Prefix) {
			return len(routes[i].rule.Prefix) > len(routes[j].rule.Prefix)
		}
		return routes[i].rule.Prefix < routes[j].rule.Prefix
	})

	return &RouteLimiter{routes: routes}, nil
}

// Allow checks and consumes one token for client ip on the longest matching
// route prefix for path at time now.
//
// Prefix matching uses path-segment boundaries: a rule prefix "/api" matches
// "/api", "/api/", and "/api/login", but does not match "/apiv2". A rule prefix
// ending in "/" (including "/") matches any path with that exact string prefix.
// If no rule matches path, Allow returns (true, 0). Invalid IP addresses fail
// closed and return (false, 0) when a rule matches.
//
// # Parameters
//
//   - path: Request URL path (e.g. "/api/login").
//   - ip: Client IP address, bucketed by IPv4 /32 or IPv6 /64.
//   - now: Current timestamp; if zero, time.Now() is used.
//
// # Returns
//
// (true, 0) when the request is permitted; (false, retryAfter) when rate
// limited, where retryAfter is the duration until one full token is available.
//
// # Example
//
//	rule, _ := guard.ParseRouteRule("/login", "5/1m")
//	lim, _ := guard.NewRouteLimiter([]guard.Rule{rule}, 1024)
//	allowed, retryAfter := lim.Allow("/login", netip.MustParseAddr("203.0.113.5"), time.Now())
//	_, _ = allowed, retryAfter
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:69 (direct call)
//   - internal/guard/fuzz_test.go:459 (function value)
//   - internal/guard/fuzz_test.go:463 (function value)
//   - internal/guard/fuzz_test.go:468 (function value)
//   - internal/guard/fuzz_test.go:474 (function value)
//   - internal/guard/fuzz_test.go:486 (function value)
//   - internal/guard/fuzz_test.go:487 (function value)
//   - internal/guard/fuzz_test.go:488 (function value)
//   - internal/guard/fuzz_test.go:489 (function value)
//   - internal/guard/fuzz_test.go:490 (function value)
//   - internal/guard/fuzz_test.go:496 (function value)
//   - internal/guard/fuzz_test.go:500 (function value)
//   - internal/guard/fuzz_test.go:512 (function value)
//   - internal/guard/fuzz_test.go:513 (function value)
//   - internal/guard/fuzz_test.go:1001 (function value)
//   - internal/guard/fuzz_test.go:1002 (function value)
//   - internal/guard/fuzz_test.go:1003 (function value)
//   - internal/guard/guard_test.go:69 (function value)
//   - internal/guard/guard_test.go:459 (direct call)
//   - internal/guard/guard_test.go:463 (direct call)
//   - internal/guard/guard_test.go:468 (direct call)
//   - internal/guard/guard_test.go:474 (direct call)
//   - internal/guard/guard_test.go:486 (direct call)
//   - internal/guard/guard_test.go:487 (direct call)
//   - internal/guard/guard_test.go:488 (direct call)
//   - internal/guard/guard_test.go:489 (direct call)
//   - internal/guard/guard_test.go:490 (direct call)
//   - internal/guard/guard_test.go:496 (direct call)
//   - internal/guard/guard_test.go:500 (direct call)
//   - internal/guard/guard_test.go:512 (direct call)
//   - internal/guard/guard_test.go:513 (direct call)
//   - internal/guard/guard_test.go:1001 (direct call)
//   - internal/guard/guard_test.go:1002 (direct call)
//   - internal/guard/guard_test.go:1003 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (l *RouteLimiter) Allow(path string, ip netip.Addr, now time.Time) (allowed bool, retryAfter time.Duration) {
	if l == nil || len(l.routes) == 0 {
		return true, 0
	}
	rt := l.matchRoute(path)
	if rt == nil {
		return true, 0
	}
	key, ok := clientBucket(ip)
	if !ok {
		return false, 0
	}
	if now.IsZero() {
		now = time.Now()
	}
	return rt.allow(key, now)
}

// EntryCount returns the current number of client buckets stored for the exact
// rule prefix, or 0 if prefix is not configured.
//
// # Parameters
//
//   - prefix: Exact rule prefix passed to [NewRouteLimiter].
//
// # Returns
//
// Current tracked client bucket count for that route (always <= maxEntries).
//
// # Example
//
//	n := lim.EntryCount("/login")
//	_ = n
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:492 (function value)
//   - internal/guard/fuzz_test.go:519 (function value)
//   - internal/guard/guard_test.go:492 (direct call)
//   - internal/guard/guard_test.go:519 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (l *RouteLimiter) EntryCount(prefix string) int {
	if l == nil {
		return 0
	}
	for _, rt := range l.routes {
		if rt.rule.Prefix == prefix {
			rt.mu.Lock()
			n := len(rt.entries)
			rt.mu.Unlock()
			return n
		}
	}
	return 0
}

// matchRoute returns the longest-prefix route matching path, or nil if none match.
//
// # Parameters
//
//   - path: Request URL path.
//
// # Returns
//
// Matching *routeLimiterState or nil.
//
// # Example
//
//	rt := l.matchRoute("/api/v1/items")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:420 (function value)
//   - internal/guard/geoasn.go:420 (function value)
//   - internal/guard/queue_quota.go:420 (function value)
//   - internal/guard/ratelimit.go:420 (direct call)
//   - internal/guard/secret.go:420 (function value)
//   - internal/guard/shedder.go:420 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (l *RouteLimiter) matchRoute(path string) *routeLimiterState {
	for _, rt := range l.routes {
		if matchRoutePrefix(path, rt.rule.Prefix) {
			return rt
		}
	}
	return nil
}

// matchRoutePrefix checks whether path falls under prefix on a path-segment
// boundary (or exact string prefix when prefix ends in '/').
//
// # Parameters
//
//   - path: Request URL path.
//   - prefix: Rule prefix starting with '/'.
//
// # Returns
//
// true when path matches prefix.
//
// # Example
//
//	ok := matchRoutePrefix("/api/login", "/api")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:505 (function value)
//   - internal/guard/geoasn.go:505 (function value)
//   - internal/guard/queue_quota.go:505 (function value)
//   - internal/guard/ratelimit.go:505 (direct call)
//   - internal/guard/secret.go:505 (function value)
//   - internal/guard/shedder.go:505 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func matchRoutePrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	if strings.HasSuffix(prefix, "/") {
		return true
	}
	return len(path) == len(prefix) || path[len(prefix)] == '/'
}

// allow evaluates and updates the token bucket for key on a single route while
// maintaining O(1) LRU ordering and bounded entry count.
//
// # Parameters
//
//   - key: Normalized client bucket address (IPv4 /32 or IPv6 /64).
//   - now: Current timestamp.
//
// # Returns
//
// (true, 0) if a token was consumed; (false, retryAfter) otherwise.
//
// # Example
//
//	ok, retry := rt.allow(key, time.Now())
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:431 (function value)
//   - internal/guard/geoasn.go:431 (function value)
//   - internal/guard/queue_quota.go:431 (function value)
//   - internal/guard/ratelimit.go:431 (direct call)
//   - internal/guard/secret.go:431 (function value)
//   - internal/guard/shedder.go:431 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (rt *routeLimiterState) allow(key netip.Addr, now time.Time) (bool, time.Duration) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	e, exists := rt.entries[key]
	if !exists {
		for len(rt.entries) >= rt.maxEntries && rt.tail != nil {
			rt.removeEntryLocked(rt.tail)
		}
		e = &tokenEntry{
			key:    key,
			tokens: float64(rt.rule.Burst),
			last:   now,
		}
		rt.entries[key] = e
		rt.pushFrontLocked(e)
	} else {
		rt.moveToFrontLocked(e)
		if elapsed := now.Sub(e.last); elapsed > 0 {
			e.tokens += elapsed.Seconds() * rt.tokensPerSec
			if maxTokens := float64(rt.rule.Burst); e.tokens > maxTokens {
				e.tokens = maxTokens
			}
			e.last = now
		}
	}

	if e.tokens >= 1.0 {
		e.tokens -= 1.0
		return true, 0
	}

	deficit := 1.0 - e.tokens
	waitSec := deficit / rt.tokensPerSec
	retryAfter := time.Duration(math.Ceil(waitSec * float64(time.Second)))
	if retryAfter < time.Millisecond {
		retryAfter = time.Millisecond
	}
	return false, retryAfter
}

// pushFrontLocked inserts a detached entry at the MRU head of the route's LRU list.
// Caller must hold rt.mu.
//
// # Parameters
//
//   - e: Non-nil detached tokenEntry.
//
// # Example
//
//	rt.pushFrontLocked(e)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:595 (function value)
//   - internal/guard/challenge.go:736 (function value)
//   - internal/guard/geoasn.go:595 (function value)
//   - internal/guard/geoasn.go:736 (function value)
//   - internal/guard/queue_quota.go:595 (function value)
//   - internal/guard/queue_quota.go:736 (function value)
//   - internal/guard/ratelimit.go:595 (direct call)
//   - internal/guard/ratelimit.go:736 (direct call)
//   - internal/guard/secret.go:595 (function value)
//   - internal/guard/secret.go:736 (function value)
//   - internal/guard/shedder.go:595 (function value)
//   - internal/guard/shedder.go:736 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (rt *routeLimiterState) pushFrontLocked(e *tokenEntry) {
	e.prev = nil
	e.next = rt.head
	if rt.head != nil {
		rt.head.prev = e
	} else {
		rt.tail = e
	}
	rt.head = e
}

// unlinkLocked detaches e from the route's LRU list without removing it from
// rt.entries. Caller must hold rt.mu.
//
// # Parameters
//
//   - e: Non-nil linked tokenEntry.
//
// # Example
//
//	rt.unlinkLocked(e)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:735 (function value)
//   - internal/guard/challenge.go:764 (function value)
//   - internal/guard/geoasn.go:735 (function value)
//   - internal/guard/geoasn.go:764 (function value)
//   - internal/guard/queue_quota.go:735 (function value)
//   - internal/guard/queue_quota.go:764 (function value)
//   - internal/guard/ratelimit.go:735 (direct call)
//   - internal/guard/ratelimit.go:764 (direct call)
//   - internal/guard/secret.go:735 (function value)
//   - internal/guard/secret.go:764 (function value)
//   - internal/guard/shedder.go:735 (function value)
//   - internal/guard/shedder.go:764 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (rt *routeLimiterState) unlinkLocked(e *tokenEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		rt.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		rt.tail = e.prev
	}
	e.prev = nil
	e.next = nil
}

// moveToFrontLocked promotes an already-linked entry to the MRU head in O(1).
// Caller must hold rt.mu.
//
// # Parameters
//
//   - e: Non-nil linked tokenEntry.
//
// # Example
//
//	rt.moveToFrontLocked(e)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:597 (function value)
//   - internal/guard/geoasn.go:597 (function value)
//   - internal/guard/queue_quota.go:597 (function value)
//   - internal/guard/ratelimit.go:597 (direct call)
//   - internal/guard/secret.go:597 (function value)
//   - internal/guard/shedder.go:597 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (rt *routeLimiterState) moveToFrontLocked(e *tokenEntry) {
	if rt.head == e {
		return
	}
	rt.unlinkLocked(e)
	rt.pushFrontLocked(e)
}

// removeEntryLocked unlinks e from the LRU list and deletes it from rt.entries.
// Caller must hold rt.mu.
//
// # Parameters
//
//   - e: Non-nil tracked tokenEntry.
//
// # Example
//
//	rt.removeEntryLocked(rt.tail)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:587 (function value)
//   - internal/guard/geoasn.go:587 (function value)
//   - internal/guard/queue_quota.go:587 (function value)
//   - internal/guard/ratelimit.go:587 (direct call)
//   - internal/guard/secret.go:587 (function value)
//   - internal/guard/shedder.go:587 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (rt *routeLimiterState) removeEntryLocked(e *tokenEntry) {
	rt.unlinkLocked(e)
	delete(rt.entries, e.key)
}
