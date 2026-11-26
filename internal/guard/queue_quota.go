// Package guard provides pure-stdlib host protection, per-client waiting-room
// queue quotas, declarative per-route token-bucket rate limiting, Geo/ASN
// access policies, and pre-ticket bot defense (SHA-256 Proof-of-Work and
// optional Cloudflare Turnstile) for Concert.
package guard

import (
	"net/netip"
	"sync"
	"time"
)

const (
	// DefaultMaxPerIP is the default maximum number of concurrent waiting-room
	// tickets a standard client bucket (IPv4 /32 or IPv6 /64) may hold.
	DefaultMaxPerIP = 8

	// DefaultAllowMaxPerIP is the default maximum number of concurrent
	// waiting-room tickets an allowlisted client bucket may hold. Even
	// allowlisted clients are capped so a misbehaving or automated allowlisted
	// host cannot exhaust the global waiting-room capacity.
	DefaultAllowMaxPerIP = 32

	// DefaultTicketTTL is the default time-to-live for an acquired waiting-room
	// ticket before it expires automatically if not released.
	DefaultTicketTTL = 15 * time.Minute

	// DefaultMaxBuckets is the default maximum number of tracked client buckets
	// kept in memory before least-recently-used eviction triggers.
	DefaultMaxBuckets = 65536
)

// clientBucket normalizes ip to its rate-limit / quota aggregation bucket:
// an IPv4 /32 address (with IPv4-mapped IPv6 addresses unmapped) or the /64
// network prefix address for IPv6, stripping any zone identifier.
//
// # Parameters
//
//   - ip: Candidate client IP address; may be invalid or IPv4-mapped IPv6.
//
// # Returns
//
// The normalized bucket address and true when ip is valid; the zero netip.Addr
// and false otherwise.
//
// # Example
//
//	bucket, ok := clientBucket(netip.MustParseAddr("2001:db8:1:2::dead:beef"))
//	// ok == true, bucket == 2001:db8:1:2::
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:288 (function value)
//   - internal/guard/challenge.go:369 (function value)
//   - internal/guard/challenge.go:413 (direct call)
//   - internal/guard/challenge.go:422 (function value)
//   - internal/guard/challenge.go:424 (function value)
//   - internal/guard/challenge.go:490 (direct call)
//   - internal/guard/challenge.go:585 (direct call)
//   - internal/guard/challenge.go:695 (direct call)
//   - internal/guard/geoasn.go:288 (function value)
//   - internal/guard/geoasn.go:369 (function value)
//   - internal/guard/geoasn.go:413 (function value)
//   - internal/guard/geoasn.go:422 (function value)
//   - internal/guard/geoasn.go:424 (function value)
//   - internal/guard/geoasn.go:490 (function value)
//   - internal/guard/geoasn.go:585 (function value)
//   - internal/guard/geoasn.go:695 (function value)
//   - internal/guard/queue_quota.go:288 (direct call)
//   - internal/guard/queue_quota.go:369 (direct call)
//   - internal/guard/queue_quota.go:413 (function value)
//   - internal/guard/queue_quota.go:422 (direct call)
//   - internal/guard/queue_quota.go:424 (function value)
//   - internal/guard/queue_quota.go:490 (function value)
//   - internal/guard/queue_quota.go:585 (function value)
//   - internal/guard/queue_quota.go:695 (function value)
//   - internal/guard/ratelimit.go:288 (function value)
//   - internal/guard/ratelimit.go:369 (function value)
//   - internal/guard/ratelimit.go:413 (function value)
//   - internal/guard/ratelimit.go:422 (function value)
//   - internal/guard/ratelimit.go:424 (direct call)
//   - internal/guard/ratelimit.go:490 (function value)
//   - internal/guard/ratelimit.go:585 (function value)
//   - internal/guard/ratelimit.go:695 (function value)
//   - internal/guard/secret.go:288 (function value)
//   - internal/guard/secret.go:369 (function value)
//   - internal/guard/secret.go:413 (function value)
//   - internal/guard/secret.go:422 (function value)
//   - internal/guard/secret.go:424 (function value)
//   - internal/guard/secret.go:490 (function value)
//   - internal/guard/secret.go:585 (function value)
//   - internal/guard/secret.go:695 (function value)
//   - internal/guard/shedder.go:288 (function value)
//   - internal/guard/shedder.go:369 (function value)
//   - internal/guard/shedder.go:413 (function value)
//   - internal/guard/shedder.go:422 (function value)
//   - internal/guard/shedder.go:424 (function value)
//   - internal/guard/shedder.go:490 (function value)
//   - internal/guard/shedder.go:585 (function value)
//   - internal/guard/shedder.go:695 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func clientBucket(ip netip.Addr) (netip.Addr, bool) {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() {
		return netip.Addr{}, false
	}
	if ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().Addr(), true
	}
	return ip, true
}

// QueueQuotaConfig configures a [QueueQuota] tracker. Zero or negative values
// fall back to the corresponding Default* constants.
type QueueQuotaConfig struct {
	// MaxPerIP is the maximum active tickets allowed per standard client bucket.
	// Defaults to DefaultMaxPerIP (8) when <= 0.
	MaxPerIP int

	// AllowMaxPerIP is the maximum active tickets allowed per allowlisted
	// client bucket. Applied even to allowlisted clients so an allowlisted
	// flood cannot exhaust the global queue. Defaults to DefaultAllowMaxPerIP (32)
	// when <= 0.
	AllowMaxPerIP int

	// TicketTTL is how long an active ticket remains counted if Release is not
	// called. Defaults to DefaultTicketTTL (15m) when <= 0.
	TicketTTL time.Duration

	// MaxBuckets caps the total number of client buckets retained in memory.
	// When exceeded, the least-recently-used bucket is evicted in O(1) time.
	// Defaults to DefaultMaxBuckets (65536) when <= 0.
	MaxBuckets int
}

// quotaBucket tracks active waiting-room tickets for a single client bucket
// and participates in an intrusive doubly-linked LRU list owned by QueueQuota.
type quotaBucket struct {
	key     netip.Addr
	tickets map[string]time.Time
	prev    *quotaBucket
	next    *quotaBucket
}

// QueueQuota enforces bounded per-client-bucket (IPv4 /32, IPv6 /64) active
// waiting-room ticket quotas with TTL expiration and O(1) LRU bucket eviction.
//
// All exported methods are safe for concurrent use by multiple goroutines.
// Mutable state (buckets map and LRU list pointers) is guarded by mu.
type QueueQuota struct {
	maxPerIP      int
	allowMaxPerIP int
	ticketTTL     time.Duration
	maxBuckets    int

	mu      sync.Mutex
	buckets map[netip.Addr]*quotaBucket // guarded by mu
	head    *quotaBucket                // MRU, guarded by mu
	tail    *quotaBucket                // LRU, guarded by mu
}

// NewQueueQuota constructs a [QueueQuota] applying defaults for any zero or
// negative fields in cfg.
//
// # Parameters
//
//   - cfg: Quota limits, ticket TTL, and maximum tracked bucket count.
//
// # Returns
//
// A ready-to-use, concurrency-safe *QueueQuota with bounded memory.
//
// # Example
//
//	q := guard.NewQueueQuota(guard.QueueQuotaConfig{
//	    MaxPerIP:      8,
//	    AllowMaxPerIP: 32,
//	    TicketTTL:     10 * time.Minute,
//	    MaxBuckets:    10000,
//	})
//	_ = q
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:90 (function value)
//   - internal/guard/fuzz_test.go:166 (function value)
//   - internal/guard/fuzz_test.go:965 (function value)
//   - internal/guard/guard_test.go:90 (direct call)
//   - internal/guard/guard_test.go:166 (direct call)
//   - internal/guard/guard_test.go:965 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func NewQueueQuota(cfg QueueQuotaConfig) *QueueQuota {
	if cfg.MaxPerIP <= 0 {
		cfg.MaxPerIP = DefaultMaxPerIP
	}
	if cfg.AllowMaxPerIP <= 0 {
		cfg.AllowMaxPerIP = DefaultAllowMaxPerIP
	}
	if cfg.TicketTTL <= 0 {
		cfg.TicketTTL = DefaultTicketTTL
	}
	if cfg.MaxBuckets <= 0 {
		cfg.MaxBuckets = DefaultMaxBuckets
	}
	return &QueueQuota{
		maxPerIP:      cfg.MaxPerIP,
		allowMaxPerIP: cfg.AllowMaxPerIP,
		ticketTTL:     cfg.TicketTTL,
		maxBuckets:    cfg.MaxBuckets,
		buckets:       make(map[netip.Addr]*quotaBucket),
	}
}

// TryAcquire attempts to reserve a waiting-room ticket slot for ip at time now.
//
// When allowlisted is true, the bucket is still bounded by AllowMaxPerIP rather
// than being unlimited, preventing an allowlisted flood from starving other
// visitors. Re-acquiring an already active ticket ID refreshes its TTL and
// succeeds without consuming an additional slot.
//
// # Parameters
//
//   - ip: Client IP address; normalized to IPv4 /32 or IPv6 /64. Invalid IPs
//     return false.
//   - ticket: Non-empty opaque ticket identifier; empty strings return false.
//   - allowlisted: True when ip matches the server's abuse allowlist.
//   - now: Current timestamp used for TTL expiration; if zero, time.Now() is used.
//
// # Returns
//
// true if the ticket slot was acquired or refreshed within quota; false if ip
// is invalid, ticket is empty, or the client bucket is already at its cap.
//
// # Example
//
//	q := guard.NewQueueQuota(guard.QueueQuotaConfig{MaxPerIP: 2, AllowMaxPerIP: 4})
//	ip := netip.MustParseAddr("198.51.100.10")
//	ok := q.TryAcquire(ip, "tkt-1", false, time.Now())
//	_ = ok
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:107 (function value)
//   - internal/guard/fuzz_test.go:130 (function value)
//   - internal/guard/fuzz_test.go:142 (function value)
//   - internal/guard/fuzz_test.go:174 (function value)
//   - internal/guard/fuzz_test.go:179 (function value)
//   - internal/guard/fuzz_test.go:184 (function value)
//   - internal/guard/fuzz_test.go:187 (function value)
//   - internal/guard/fuzz_test.go:190 (function value)
//   - internal/guard/fuzz_test.go:194 (function value)
//   - internal/guard/fuzz_test.go:201 (function value)
//   - internal/guard/fuzz_test.go:204 (function value)
//   - internal/guard/fuzz_test.go:967 (function value)
//   - internal/guard/fuzz_test.go:968 (function value)
//   - internal/guard/fuzz_test.go:969 (function value)
//   - internal/guard/guard_test.go:107 (direct call)
//   - internal/guard/guard_test.go:130 (direct call)
//   - internal/guard/guard_test.go:142 (direct call)
//   - internal/guard/guard_test.go:174 (direct call)
//   - internal/guard/guard_test.go:179 (direct call)
//   - internal/guard/guard_test.go:184 (direct call)
//   - internal/guard/guard_test.go:187 (direct call)
//   - internal/guard/guard_test.go:190 (direct call)
//   - internal/guard/guard_test.go:194 (direct call)
//   - internal/guard/guard_test.go:201 (direct call)
//   - internal/guard/guard_test.go:204 (direct call)
//   - internal/guard/guard_test.go:967 (direct call)
//   - internal/guard/guard_test.go:968 (direct call)
//   - internal/guard/guard_test.go:969 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (q *QueueQuota) TryAcquire(ip netip.Addr, ticket string, allowlisted bool, now time.Time) bool {
	if q == nil || ticket == "" {
		return false
	}
	key, ok := clientBucket(ip)
	if !ok {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}

	limit := q.maxPerIP
	if allowlisted {
		limit = q.allowMaxPerIP
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	b, exists := q.buckets[key]
	if exists {
		pruneExpiredTickets(b, now)
		if _, held := b.tickets[ticket]; held {
			// Idempotent refresh for an already-held ticket does not consume
			// another slot and promotes the bucket to MRU.
			b.tickets[ticket] = now.Add(q.ticketTTL)
			q.moveToFrontLocked(b)
			return true
		}
		if len(b.tickets) >= limit {
			q.moveToFrontLocked(b)
			return false
		}
		b.tickets[ticket] = now.Add(q.ticketTTL)
		q.moveToFrontLocked(b)
		return true
	}

	// Evict least-recently-used bucket in O(1) before admitting a new bucket
	// so memory stays strictly bounded under IP-spray attacks (R3).
	for len(q.buckets) >= q.maxBuckets && q.tail != nil {
		q.removeBucketLocked(q.tail)
	}

	b = &quotaBucket{
		key:     key,
		tickets: make(map[string]time.Time, 1),
	}
	b.tickets[ticket] = now.Add(q.ticketTTL)
	q.buckets[key] = b
	q.pushFrontLocked(b)
	return true
}

// Release removes ticket from ip's active quota bucket. If the bucket becomes
// empty, the bucket entry is immediately reclaimed from memory.
//
// # Parameters
//
//   - ip: Client IP address; invalid or untracked addresses are ignored.
//   - ticket: Ticket identifier to release; empty or unknown tickets are ignored.
//
// # Example
//
//	q := guard.NewQueueQuota(guard.QueueQuotaConfig{})
//	ip := netip.MustParseAddr("198.51.100.10")
//	q.TryAcquire(ip, "tkt-1", false, time.Now())
//	q.Release(ip, "tkt-1")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:209 (function value)
//   - internal/guard/fuzz_test.go:210 (function value)
//   - internal/guard/guard_test.go:209 (direct call)
//   - internal/guard/guard_test.go:210 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (q *QueueQuota) Release(ip netip.Addr, ticket string) {
	if q == nil || ticket == "" {
		return
	}
	key, ok := clientBucket(ip)
	if !ok {
		return
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	b, exists := q.buckets[key]
	if !exists {
		return
	}
	delete(b.tickets, ticket)
	if len(b.tickets) == 0 {
		q.removeBucketLocked(b)
	}
}

// Active returns the number of non-expired tickets currently held by ip's
// client bucket at time now, pruning any expired tickets in that bucket.
//
// # Parameters
//
//   - ip: Client IP address; invalid or untracked addresses return 0.
//   - now: Current timestamp for expiry evaluation; if zero, time.Now() is used.
//
// # Returns
//
// Count of active, non-expired tickets in ip's bucket (always >= 0).
//
// # Example
//
//	q := guard.NewQueueQuota(guard.QueueQuotaConfig{})
//	n := q.Active(netip.MustParseAddr("198.51.100.10"), time.Now())
//	_ = n
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:123 (function value)
//   - internal/guard/fuzz_test.go:211 (function value)
//   - internal/guard/fuzz_test.go:216 (function value)
//   - internal/guard/guard_test.go:123 (direct call)
//   - internal/guard/guard_test.go:211 (direct call)
//   - internal/guard/guard_test.go:216 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (q *QueueQuota) Active(ip netip.Addr, now time.Time) int {
	if q == nil {
		return 0
	}
	key, ok := clientBucket(ip)
	if !ok {
		return 0
	}
	if now.IsZero() {
		now = time.Now()
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	b, exists := q.buckets[key]
	if !exists {
		return 0
	}
	pruneExpiredTickets(b, now)
	if len(b.tickets) == 0 {
		q.removeBucketLocked(b)
		return 0
	}
	return len(b.tickets)
}

// Sweep prunes expired tickets across all tracked buckets and reclaims any
// buckets that become empty.
//
// # Parameters
//
//   - now: Current timestamp for expiry evaluation; if zero, time.Now() is used.
//
// # Example
//
//	q := guard.NewQueueQuota(guard.QueueQuotaConfig{})
//	q.Sweep(time.Now())
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:221 (function value)
//   - internal/guard/guard_test.go:221 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (q *QueueQuota) Sweep(now time.Time) {
	if q == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	// Walk via the intrusive linked list so unlinking empty buckets during
	// traversal does not rely on map iteration semantics.
	for b := q.tail; b != nil; {
		prev := b.prev
		pruneExpiredTickets(b, now)
		if len(b.tickets) == 0 {
			q.removeBucketLocked(b)
		}
		b = prev
	}
}

// Buckets returns the number of client buckets currently retained in memory.
// The returned count never exceeds the configured MaxBuckets limit.
//
// # Parameters
//
// None.
//
// # Returns
//
// Number of tracked buckets currently in memory.
//
// # Example
//
//	q := guard.NewQueueQuota(guard.QueueQuotaConfig{MaxBuckets: 100})
//	count := q.Buckets()
//	_ = count
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:135 (function value)
//   - internal/guard/fuzz_test.go:144 (function value)
//   - internal/guard/fuzz_test.go:222 (function value)
//   - internal/guard/guard_test.go:135 (direct call)
//   - internal/guard/guard_test.go:144 (direct call)
//   - internal/guard/guard_test.go:222 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (q *QueueQuota) Buckets() int {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.buckets)
}

// pruneExpiredTickets deletes every ticket in b whose expiry is at or before now.
// Caller must hold q.mu.
//
// # Parameters
//
//   - b: Non-nil bucket to prune.
//   - now: Current timestamp.
//
// # Example
//
//	pruneExpiredTickets(bucket, time.Now())
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:306 (function value)
//   - internal/guard/challenge.go:437 (function value)
//   - internal/guard/challenge.go:481 (function value)
//   - internal/guard/geoasn.go:306 (function value)
//   - internal/guard/geoasn.go:437 (function value)
//   - internal/guard/geoasn.go:481 (function value)
//   - internal/guard/queue_quota.go:306 (direct call)
//   - internal/guard/queue_quota.go:437 (direct call)
//   - internal/guard/queue_quota.go:481 (direct call)
//   - internal/guard/ratelimit.go:306 (function value)
//   - internal/guard/ratelimit.go:437 (function value)
//   - internal/guard/ratelimit.go:481 (function value)
//   - internal/guard/secret.go:306 (function value)
//   - internal/guard/secret.go:437 (function value)
//   - internal/guard/secret.go:481 (function value)
//   - internal/guard/shedder.go:306 (function value)
//   - internal/guard/shedder.go:437 (function value)
//   - internal/guard/shedder.go:481 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func pruneExpiredTickets(b *quotaBucket, now time.Time) {
	for id, exp := range b.tickets {
		if !now.Before(exp) {
			delete(b.tickets, id)
		}
	}
}

// pushFrontLocked inserts a detached bucket at the head (MRU) of the LRU list.
// Caller must hold q.mu.
//
// # Parameters
//
//   - b: Non-nil detached bucket.
//
// # Example
//
//	q.pushFrontLocked(b)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:335 (function value)
//   - internal/guard/challenge.go:700 (function value)
//   - internal/guard/geoasn.go:335 (function value)
//   - internal/guard/geoasn.go:700 (function value)
//   - internal/guard/queue_quota.go:335 (direct call)
//   - internal/guard/queue_quota.go:700 (direct call)
//   - internal/guard/ratelimit.go:335 (function value)
//   - internal/guard/ratelimit.go:700 (function value)
//   - internal/guard/secret.go:335 (function value)
//   - internal/guard/secret.go:700 (function value)
//   - internal/guard/shedder.go:335 (function value)
//   - internal/guard/shedder.go:700 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (q *QueueQuota) pushFrontLocked(b *quotaBucket) {
	b.prev = nil
	b.next = q.head
	if q.head != nil {
		q.head.prev = b
	} else {
		q.tail = b
	}
	q.head = b
}

// unlinkLocked detaches b from the intrusive LRU list without deleting it from
// q.buckets. Caller must hold q.mu.
//
// # Parameters
//
//   - b: Non-nil bucket currently linked in the LRU list.
//
// # Example
//
//	q.unlinkLocked(b)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:699 (function value)
//   - internal/guard/challenge.go:746 (function value)
//   - internal/guard/geoasn.go:699 (function value)
//   - internal/guard/geoasn.go:746 (function value)
//   - internal/guard/queue_quota.go:699 (direct call)
//   - internal/guard/queue_quota.go:746 (direct call)
//   - internal/guard/ratelimit.go:699 (function value)
//   - internal/guard/ratelimit.go:746 (function value)
//   - internal/guard/secret.go:699 (function value)
//   - internal/guard/secret.go:746 (function value)
//   - internal/guard/shedder.go:699 (function value)
//   - internal/guard/shedder.go:746 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (q *QueueQuota) unlinkLocked(b *quotaBucket) {
	if b.prev != nil {
		b.prev.next = b.next
	} else {
		q.head = b.next
	}
	if b.next != nil {
		b.next.prev = b.prev
	} else {
		q.tail = b.prev
	}
	b.prev = nil
	b.next = nil
}

// moveToFrontLocked promotes an already-linked bucket to the head (MRU) of the
// LRU list in O(1) time. Caller must hold q.mu.
//
// # Parameters
//
//   - b: Non-nil bucket currently linked in the LRU list.
//
// # Example
//
//	q.moveToFrontLocked(b)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:311 (function value)
//   - internal/guard/challenge.go:315 (function value)
//   - internal/guard/challenge.go:319 (function value)
//   - internal/guard/geoasn.go:311 (function value)
//   - internal/guard/geoasn.go:315 (function value)
//   - internal/guard/geoasn.go:319 (function value)
//   - internal/guard/queue_quota.go:311 (direct call)
//   - internal/guard/queue_quota.go:315 (direct call)
//   - internal/guard/queue_quota.go:319 (direct call)
//   - internal/guard/ratelimit.go:311 (function value)
//   - internal/guard/ratelimit.go:315 (function value)
//   - internal/guard/ratelimit.go:319 (function value)
//   - internal/guard/secret.go:311 (function value)
//   - internal/guard/secret.go:315 (function value)
//   - internal/guard/secret.go:319 (function value)
//   - internal/guard/shedder.go:311 (function value)
//   - internal/guard/shedder.go:315 (function value)
//   - internal/guard/shedder.go:319 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (q *QueueQuota) moveToFrontLocked(b *quotaBucket) {
	if q.head == b {
		return
	}
	q.unlinkLocked(b)
	q.pushFrontLocked(b)
}

// removeBucketLocked unlinks b from the LRU list and deletes it from q.buckets.
// Caller must hold q.mu.
//
// # Parameters
//
//   - b: Non-nil bucket currently tracked in q.
//
// # Example
//
//	q.removeBucketLocked(q.tail)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:326 (function value)
//   - internal/guard/challenge.go:383 (function value)
//   - internal/guard/challenge.go:439 (function value)
//   - internal/guard/challenge.go:483 (function value)
//   - internal/guard/geoasn.go:326 (function value)
//   - internal/guard/geoasn.go:383 (function value)
//   - internal/guard/geoasn.go:439 (function value)
//   - internal/guard/geoasn.go:483 (function value)
//   - internal/guard/queue_quota.go:326 (direct call)
//   - internal/guard/queue_quota.go:383 (direct call)
//   - internal/guard/queue_quota.go:439 (direct call)
//   - internal/guard/queue_quota.go:483 (direct call)
//   - internal/guard/ratelimit.go:326 (function value)
//   - internal/guard/ratelimit.go:383 (function value)
//   - internal/guard/ratelimit.go:439 (function value)
//   - internal/guard/ratelimit.go:483 (function value)
//   - internal/guard/secret.go:326 (function value)
//   - internal/guard/secret.go:383 (function value)
//   - internal/guard/secret.go:439 (function value)
//   - internal/guard/secret.go:483 (function value)
//   - internal/guard/shedder.go:326 (function value)
//   - internal/guard/shedder.go:383 (function value)
//   - internal/guard/shedder.go:439 (function value)
//   - internal/guard/shedder.go:483 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (q *QueueQuota) removeBucketLocked(b *quotaBucket) {
	q.unlinkLocked(b)
	delete(q.buckets, b.key)
}
