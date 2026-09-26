package main

import (
	"errors"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// abuseKey maps a client to its registry key: the address itself for IPv4,
// the /64 prefix for IPv6, where one host can rotate through the whole /64.
func abuseKey(ip netip.Addr) (netip.Addr, bool) {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return netip.Addr{}, false
	}
	if ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().Addr(), true
	}
	return ip, true
}

// keyPrefix is every address a registry key covers: an IPv4 /32 or an IPv6 /64.
func keyPrefix(k netip.Addr) netip.Prefix {
	if k.Is6() {
		return netip.PrefixFrom(k, 64)
	}
	return netip.PrefixFrom(k, 32)
}

func displayKey(k netip.Addr) string {
	if k.Is6() {
		return netip.PrefixFrom(k, 64).String()
	}
	return k.String()
}

// ─── abuse registry ──────────────────────────────────────────────────────────

// abuseRegistry tracks weighted strikes per client and bans clients whose
// strikes within a fixed window reach the threshold. Each ban doubles the
// previous cooldown up to max. History is forgotten after max of good behaviour.
// Administrators can also ban a client for a set time or permanently.
// Administrator-set CIDR range bans live alongside in ranges (see ranges.go).
// With -data-dir set, bans survive restarts (see persist.go).
//
// The tuning (thresholds, cooldowns, exemptions) lives in params and is
// replaced whole when a setting changes; the tracked clients and bans stay.
type abuseRegistry struct {
	shards [abuseShards]abuseShard
	params atomic.Pointer[abuseParams]
	count  atomic.Int64
	stats  *counters
	ranges rangeSet // CIDR range bans; see ranges.go

	// onBan is called, outside every registry lock, with the addresses a new
	// or changed ban covers. The app uses it to drop waiting visitors.
	onBan atomic.Pointer[func(netip.Prefix)]

	// Persistence; see persist.go.
	dirty       atomic.Bool // bans changed since the last save
	saveMu      sync.Mutex  // serialises saves
	saveFailing atomic.Bool // the last save failed; logs once per outage
}

// abuseParams is the registry's tuning, from settings.
type abuseParams struct {
	threshold  int
	window     int64 // nanoseconds
	base       time.Duration
	max        time.Duration
	maxEntries int64
	exempt     []netip.Prefix // -abuse-allow plus -trusted-proxies
}

func abuseParamsFrom(cfg config) *abuseParams {
	exempt := make([]netip.Prefix, 0, len(cfg.allow)+len(cfg.trusted))
	exempt = append(exempt, cfg.allow...)
	exempt = append(exempt, cfg.trusted...)
	return &abuseParams{
		threshold:  cfg.abuseStrikes,
		window:     int64(cfg.abuseWindow),
		base:       cfg.abuseCooldown,
		max:        cfg.abuseMaxCooldown,
		maxEntries: int64(cfg.abuseMaxEntries),
		exempt:     exempt,
	}
}

type abuseShard struct {
	mu sync.Mutex
	m  map[netip.Addr]*abuseEntry
}

type abuseEntry struct {
	strikes     int
	windowStart int64 // unix nanos
	bannedUntil int64 // unix nanos; 0 when never banned; banForever when permanent
	offenses    int
}

// banView is one ban as the admin API and portal list it. Permanent bans
// have a zero Until and RemainingSeconds.
type banView struct {
	Client           string    `json:"client"`
	Until            time.Time `json:"until"`
	RemainingSeconds int       `json:"remaining_seconds"`
	Offenses         int       `json:"offenses"`
	Range            bool      `json:"range"`
	Permanent        bool      `json:"permanent"`
}

func newAbuseRegistry(cfg config, stats *counters) *abuseRegistry {
	r := &abuseRegistry{stats: stats}
	r.params.Store(abuseParamsFrom(cfg))
	for i := range r.shards {
		r.shards[i].m = make(map[netip.Addr]*abuseEntry)
	}
	r.ranges.m = make(map[netip.Prefix]*rangeBan)
	return r
}

// p is the registry's current tuning.
func (r *abuseRegistry) p() *abuseParams {
	return r.params.Load()
}

// setParams replaces the tuning. Safe on a nil registry.
func (r *abuseRegistry) setParams(p *abuseParams) {
	if r != nil {
		r.params.Store(p)
	}
}

// setOnBan installs the ban callback. Safe on a nil registry.
func (r *abuseRegistry) setOnBan(f func(netip.Prefix)) {
	if r != nil {
		r.onBan.Store(&f)
	}
}

// notifyBan marks the bans dirty and runs the callback. Callers must not
// hold any registry lock.
func (r *abuseRegistry) notifyBan(p netip.Prefix) {
	r.dirty.Store(true)
	if f := r.onBan.Load(); f != nil {
		(*f)(p)
	}
}

// isExempt reports whether ip is in -abuse-allow or -trusted-proxies.
func (r *abuseRegistry) isExempt(ip netip.Addr) bool {
	return r != nil && containsAddr(r.p().exempt, ip.Unmap())
}

func (r *abuseRegistry) shard(k netip.Addr) *abuseShard {
	b := k.As16()
	return &r.shards[(b[4]^b[5]^b[6]^b[7]^b[12]^b[13]^b[14]^b[15])&(abuseShards-1)]
}

// trackable returns the key for ip, or false when ip is invalid or exempt.
func (r *abuseRegistry) trackable(ip netip.Addr) (netip.Addr, bool) {
	ip = ip.Unmap()
	if !ip.IsValid() || containsAddr(r.p().exempt, ip) {
		return netip.Addr{}, false
	}
	return abuseKey(ip)
}

// entryLocked returns the entry for k, creating it when there is room. When
// the table is full it evicts one unbanned entry from the same shard, or
// drops tracking for k. Caller holds sh.mu.
func (r *abuseRegistry) entryLocked(sh *abuseShard, k netip.Addr, now int64) *abuseEntry {
	if e := sh.m[k]; e != nil {
		return e
	}
	if r.count.Load() >= r.p().maxEntries {
		evicted := false
		for victim, e := range sh.m {
			if e.bannedUntil <= now {
				delete(sh.m, victim)
				r.count.Add(-1)
				evicted = true
				break
			}
		}
		if !evicted {
			r.stats.abuseDropped.Add(1)
			return nil
		}
	}
	e := &abuseEntry{windowStart: now}
	sh.m[k] = e
	r.count.Add(1)
	return e
}

func (r *abuseRegistry) cooldown(offenses int) time.Duration {
	pr := r.p()
	d := pr.base
	for i := 1; i < offenses; i++ {
		d *= 2
		if d >= pr.max {
			return pr.max
		}
	}
	if d > pr.max {
		return pr.max
	}
	return d
}

// banLocked bans e starting at now. Caller holds the shard lock.
func (r *abuseRegistry) banLocked(e *abuseEntry, now int64) time.Duration {
	e.offenses++
	d := r.cooldown(e.offenses)
	e.bannedUntil = now + int64(d)
	e.strikes = 0
	e.windowStart = now
	r.stats.abuseBans.Add(1)
	return d
}

// banned reports whether ip is banned, individually or by a range, and for
// how much longer. Permanent bans report banForeverLeft.
func (r *abuseRegistry) banned(ip netip.Addr, now time.Time) (time.Duration, bool) {
	if r == nil {
		return 0, false
	}
	k, ok := abuseKey(ip)
	if !ok {
		return 0, false
	}
	n := now.UnixNano()

	sh := r.shard(k)
	sh.mu.Lock()
	var until int64
	if e := sh.m[k]; e != nil {
		until = e.bannedUntil
	}
	sh.mu.Unlock()

	if until == banForever {
		return banForeverLeft, true
	}
	if left := until - n; left > 0 {
		return time.Duration(left), true
	}
	return r.rangeBanned(ip, n)
}

// strike adds weight to ip's strikes and reports whether ip is now banned.
func (r *abuseRegistry) strike(ip netip.Addr, weight int, now time.Time) bool {
	if r == nil || weight <= 0 {
		return false
	}
	k, ok := r.trackable(ip)
	if !ok {
		return false
	}
	r.stats.abuseStrikes.Add(1)

	banned, fresh := r.strikeKey(k, weight, now.UnixNano())
	if fresh {
		r.notifyBan(keyPrefix(k))
	}
	return banned
}

// strikeKey applies a strike under the shard lock. fresh reports a new ban.
func (r *abuseRegistry) strikeKey(k netip.Addr, weight int, n int64) (banned, fresh bool) {
	pr := r.p()
	sh := r.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	e := r.entryLocked(sh, k, n)
	if e == nil {
		return false, false
	}
	if e.bannedUntil > n {
		return true, false
	}
	if n-e.windowStart > pr.window {
		e.windowStart = n
		e.strikes = 0
	}
	e.strikes += weight
	if e.strikes < pr.threshold {
		return false, false
	}
	r.banLocked(e, n)
	return true, true
}

// banNow bans ip immediately, escalating like any other ban. It returns the
// remaining ban and false when ip is exempt or cannot be tracked.
func (r *abuseRegistry) banNow(ip netip.Addr, now time.Time) (time.Duration, bool) {
	if r == nil {
		return 0, false
	}
	k, ok := r.trackable(ip)
	if !ok {
		return 0, false
	}
	left, banned, fresh := r.banNowKey(k, now.UnixNano())
	if fresh {
		r.notifyBan(keyPrefix(k))
	}
	return left, banned
}

func (r *abuseRegistry) banNowKey(k netip.Addr, n int64) (left time.Duration, banned, fresh bool) {
	sh := r.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	e := r.entryLocked(sh, k, n)
	if e == nil {
		return 0, false, false
	}
	if e.bannedUntil == banForever {
		return banForeverLeft, true, false
	}
	if e.bannedUntil > n {
		return time.Duration(e.bannedUntil - n), true, false
	}
	return r.banLocked(e, n), true, true
}

// banFor sets ip's ban to end d from now; d <= 0 makes it permanent. A new
// ban counts as an offense for future escalation; changing an active ban
// does not. Waiting visitors from ip are dropped (see onBan).
func (r *abuseRegistry) banFor(ip netip.Addr, d time.Duration, now time.Time) (netip.Addr, error) {
	if r == nil {
		return netip.Addr{}, errAbuseDisabled
	}
	if !ip.IsValid() {
		return netip.Addr{}, errors.New("invalid address")
	}
	k, ok := r.trackable(ip)
	if !ok {
		return netip.Addr{}, errClientExempt
	}
	if err := r.setBanKey(k, d, now.UnixNano()); err != nil {
		return netip.Addr{}, err
	}
	r.notifyBan(keyPrefix(k))
	return k, nil
}

func (r *abuseRegistry) setBanKey(k netip.Addr, d time.Duration, n int64) error {
	sh := r.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	e := r.entryLocked(sh, k, n)
	if e == nil {
		return errRegistryFull
	}
	if e.bannedUntil <= n {
		e.offenses++
		r.stats.abuseBans.Add(1)
	}
	if d <= 0 {
		e.bannedUntil = banForever
	} else {
		e.bannedUntil = n + int64(d)
	}
	e.strikes = 0
	e.windowStart = n
	return nil
}

// unban forgets ip entirely, including its offense history.
func (r *abuseRegistry) unban(ip netip.Addr) bool {
	if r == nil {
		return false
	}
	k, ok := abuseKey(ip)
	if !ok {
		return false
	}
	sh := r.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, ok := sh.m[k]; !ok {
		return false
	}
	delete(sh.m, k)
	r.count.Add(-1)
	r.dirty.Store(true)
	return true
}

// bans lists currently banned clients and ranges: permanent bans first,
// then longest remaining first. Ties (every permanent ban, and bans ending
// at the same moment) are broken by single clients before ranges, then by
// client, so the order is the same on every call.
func (r *abuseRegistry) bans(now time.Time) []banView {
	out := []banView{}
	if r == nil {
		return out
	}
	n := now.UnixNano()
	for i := range r.shards {
		sh := &r.shards[i]
		sh.mu.Lock()
		for k, e := range sh.m {
			if e.bannedUntil <= n {
				continue
			}
			v := banView{Client: displayKey(k), Offenses: e.offenses}
			if e.bannedUntil == banForever {
				v.Permanent = true
			} else {
				v.Until = time.Unix(0, e.bannedUntil).UTC()
				v.RemainingSeconds = int((time.Duration(e.bannedUntil-n) + time.Second - 1) / time.Second)
			}
			out = append(out, v)
		}
		sh.mu.Unlock()
	}
	out = append(out, r.rangeViews(n)...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Permanent != b.Permanent {
			return a.Permanent
		}
		if !a.Until.Equal(b.Until) {
			return a.Until.After(b.Until)
		}
		if a.Range != b.Range {
			return !a.Range
		}
		return a.Client < b.Client
	})
	return out
}

func (r *abuseRegistry) tracked() int64 {
	if r == nil {
		return 0
	}
	return r.count.Load()
}

// sweep removes entries that are unbanned, outside their strike window, and
// either never banned or clean for longer than max. Permanent bans stay.
func (r *abuseRegistry) sweep(now time.Time) int {
	pr := r.p()
	n := now.UnixNano()
	maxNS := int64(pr.max)
	evicted := 0
	for i := range r.shards {
		sh := &r.shards[i]
		sh.mu.Lock()
		for k, e := range sh.m {
			if e.bannedUntil > n || n-e.windowStart <= pr.window {
				continue
			}
			if e.offenses == 0 || n-e.bannedUntil > maxNS {
				delete(sh.m, k)
				evicted++
			}
		}
		sh.mu.Unlock()
	}
	r.count.Add(int64(-evicted))
	return evicted
}

// janitor sweeps expired entries and range bans. Its interval follows the
// strike window, which can change at runtime, so it is recomputed each time.
func (r *abuseRegistry) janitor(stop <-chan struct{}) {
	t := time.NewTimer(janitorInterval(time.Duration(r.p().window)))
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			r.sweep(now)
			r.sweepRanges(now)
			t.Reset(janitorInterval(time.Duration(r.p().window)))
		}
	}
}
