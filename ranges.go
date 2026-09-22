package main

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Range bans block a whole CIDR block, such as 10.1.0.0/16. They are
// created only by an administrator (portal or admin API), never by strikes.
// A single client — an IPv4 /32 or an IPv6 /64 or narrower — is still
// tracked in the per-client table in main.go, with strikes and escalation.
//
// Addresses in -abuse-allow and -trusted-proxies stay reachable even inside
// a banned range.

const (
	minRangeBitsV4 = 8  // broadest IPv4 range that may be banned
	minRangeBitsV6 = 16 // broadest IPv6 range that may be banned
	maxRangeBans   = 4096
)

var (
	errBadBanTarget  = errors.New("client must be an IP address or a CIDR range such as 203.0.113.0/24")
	errRangeTooBroad = fmt.Errorf("range is too broad: use /%d or narrower for IPv4 and /%d or narrower for IPv6", minRangeBitsV4, minRangeBitsV6)
	errRangeLimit    = fmt.Errorf("too many range bans (limit %d)", maxRangeBans)
)

// banTarget is a parsed, normalised ban request.
type banTarget struct {
	prefix netip.Prefix // masked; IPv4-mapped input converted to IPv4
	single bool         // true: one client (IPv4 /32, IPv6 /64 or narrower)
}

// parseBanTarget accepts an address or a CIDR range. Host bits are masked,
// so 10.1.2.3/16 becomes 10.1.0.0/16.
func parseBanTarget(s string) (banTarget, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return banTarget{}, errBadBanTarget
	}

	var p netip.Prefix
	if strings.Contains(s, "/") {
		pp, err := netip.ParsePrefix(s)
		if err != nil {
			return banTarget{}, errBadBanTarget
		}
		p = pp
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return banTarget{}, errBadBanTarget
		}
		a = a.WithZone("")
		p = netip.PrefixFrom(a, a.BitLen())
	}

	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	p = p.Masked()
	if !p.IsValid() {
		return banTarget{}, errBadBanTarget
	}

	var single bool
	if p.Addr().Is4() {
		single = p.Bits() == 32
		if !single && p.Bits() < minRangeBitsV4 {
			return banTarget{}, errRangeTooBroad
		}
	} else {
		single = p.Bits() >= 64
		if !single && p.Bits() < minRangeBitsV6 {
			return banTarget{}, errRangeTooBroad
		}
	}
	return banTarget{prefix: p, single: single}, nil
}

// String is the form shown to operators: the client key for single clients
// (IPv6 as its /64), the CIDR block for ranges.
func (t banTarget) String() string {
	if t.single {
		k, _ := abuseKey(t.prefix.Addr())
		return displayKey(k)
	}
	return t.prefix.String()
}

type rangeBan struct {
	until    int64 // unix nanos
	offenses int
}

// rangeSet is embedded in abuseRegistry. n mirrors len(m) so the hot path
// can skip the lock entirely when no range bans exist.
type rangeSet struct {
	mu sync.RWMutex
	m  map[netip.Prefix]*rangeBan
	n  atomic.Int64
}

// rangeBanned reports whether ip falls inside an active range ban and for
// how long. Exempt addresses are never banned by a range.
func (r *abuseRegistry) rangeBanned(ip netip.Addr, now int64) (time.Duration, bool) {
	if r == nil || r.ranges.n.Load() == 0 || !ip.IsValid() {
		return 0, false
	}
	ip = ip.Unmap()

	var until int64
	r.ranges.mu.RLock()
	for p, b := range r.ranges.m {
		if b.until > now && b.until > until && p.Contains(ip) {
			until = b.until
		}
	}
	r.ranges.mu.RUnlock()

	if until == 0 || containsAddr(r.exempt, ip) {
		return 0, false
	}
	return time.Duration(until - now), true
}

// banRange sets the range's ban to end d from now. A new ban counts as an
// offense; changing an active ban does not.
func (r *abuseRegistry) banRange(p netip.Prefix, d time.Duration, now time.Time) error {
	if r == nil {
		return errAbuseDisabled
	}
	n := now.UnixNano()

	r.ranges.mu.Lock()
	defer r.ranges.mu.Unlock()
	if r.ranges.m == nil {
		r.ranges.m = make(map[netip.Prefix]*rangeBan)
	}
	b := r.ranges.m[p]
	if b == nil {
		if len(r.ranges.m) >= maxRangeBans {
			return errRangeLimit
		}
		b = &rangeBan{}
		r.ranges.m[p] = b
		r.ranges.n.Add(1)
	}
	if b.until <= n {
		b.offenses++
		r.stats.abuseBans.Add(1)
	}
	b.until = n + int64(d)
	return nil
}

func (r *abuseRegistry) unbanRange(p netip.Prefix) bool {
	if r == nil {
		return false
	}
	r.ranges.mu.Lock()
	defer r.ranges.mu.Unlock()
	if _, ok := r.ranges.m[p]; !ok {
		return false
	}
	delete(r.ranges.m, p)
	r.ranges.n.Add(-1)
	return true
}

// unbanTarget lifts a ban on a single client or a range.
func (r *abuseRegistry) unbanTarget(t banTarget) bool {
	if r == nil {
		return false
	}
	if t.single {
		return r.unban(t.prefix.Addr())
	}
	return r.unbanRange(t.prefix)
}

// rangeViews lists active range bans for bans().
func (r *abuseRegistry) rangeViews(now int64) []banView {
	if r == nil || r.ranges.n.Load() == 0 {
		return nil
	}
	r.ranges.mu.RLock()
	defer r.ranges.mu.RUnlock()
	out := make([]banView, 0, len(r.ranges.m))
	for p, b := range r.ranges.m {
		if b.until > now {
			out = append(out, banView{
				Client:           p.String(),
				Until:            time.Unix(0, b.until).UTC(),
				RemainingSeconds: int((time.Duration(b.until-now) + time.Second - 1) / time.Second),
				Offenses:         b.offenses,
				Range:            true,
			})
		}
	}
	return out
}

// sweepRanges removes expired range bans.
func (r *abuseRegistry) sweepRanges(now time.Time) int {
	if r == nil || r.ranges.n.Load() == 0 {
		return 0
	}
	n := now.UnixNano()
	r.ranges.mu.Lock()
	defer r.ranges.mu.Unlock()
	evicted := 0
	for p, b := range r.ranges.m {
		if b.until <= n {
			delete(r.ranges.m, p)
			evicted++
		}
	}
	r.ranges.n.Add(int64(-evicted))
	return evicted
}

func (r *abuseRegistry) rangeCount() int64 {
	if r == nil {
		return 0
	}
	return r.ranges.n.Load()
}

// exemptWithin lists the exempt prefixes that overlap p. Those addresses
// stay reachable even while p is banned.
func (r *abuseRegistry) exemptWithin(p netip.Prefix) []string {
	out := []string{}
	if r == nil {
		return out
	}
	for _, e := range r.exempt {
		if p.Overlaps(e) {
			out = append(out, e.String())
		}
	}
	return out
}
