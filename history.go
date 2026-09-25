package main

import (
	"bufio"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// Request history for the admin portal's History tab.
//
// The access log goes to stdout and scrolls away, and it never sees banned
// clients at all: bans are enforced before the logger runs. A ban that fired
// while nobody was watching left no trace of what the client was probing
// for. The history keeps, in memory, the recent requests of every client the
// main listener has seen, grouped by client address, plus a log of every
// ban: when it began, when it ends or ended, which request started it, and
// every request the banned network made while it was blocked.
//
// What is recorded: everything the access log records, and also requests
// from banned clients, the request that started a ban, and any request
// answered with 4xx or 5xx, including on asset and status paths (a forged
// admission pass shows up here). Successful asset, /queue/status and
// /_room/healthz requests are left out, as they are from the access log:
// they are most of the traffic and say nothing about abuse.
//
// Recording happens in portal.wrap once the response status is known (the
// first header or body write), so a WebSocket or event stream appears the
// moment it opens rather than when it closes.
//
// Bounds: at most historyMaxClients addresses with historyPerClient requests
// each. When the table is full, the quietest client that was never banned
// makes room. A ban window keeps up to historyWindowPaths distinct paths and
// historyWindowClients addresses and counts the rest. Clients idle for
// historyRetention, and bans that ended that long ago, are forgotten. The
// history lives in memory only; bans still in force at startup (restored
// from bans.json) are listed with an unknown start.

const (
	historyShards        = 16
	historyMaxClients    = 4096
	historyPerClient     = 100
	historyMaxUAs        = 4
	historyMaxWindows    = 5000
	historyWindowPaths   = 100
	historyWindowClients = 100
	historyRetention     = 72 * time.Hour
	historyPathLen       = 256
	historyUALen         = 200
	historyListLimit     = 500 // clients the History tab lists
	historyBanLimit      = 200 // bans the ban log lists
	historySummaryPaths  = 3   // top paths shown per ban in the ban log
	historyTriggerDelay  = 500 * time.Millisecond
	historyTriggerWindow = 5 * time.Second
	historyUAOther       = uint8(255)
)

// ─── recording ───────────────────────────────────────────────────────────────

// historyRequest is what is captured from a request before it is served, so
// nothing downstream can change it.
type historyRequest struct {
	method string
	path   string
	query  string
	ua     string
	rank   priorityRank
}

// historyEntry is one recorded request.
type historyEntry struct {
	at        time.Time
	method    string
	path      string // with the query string
	status    int
	latency   time.Duration // time to the response status
	ua        uint8         // index into historyClient.uas
	blocked   bool          // arrived while the client was banned
	triggered bool          // this request started a ban
	window    uint64        // ban window id, 0 for none
	rank      priorityRank  // Concert-Priority rank the request carried
}

// historyClient is one client address and its recent requests.
type historyClient struct {
	first     time.Time
	last      time.Time
	requests  int64
	blocked   int64
	errors    int64 // 4xx and 5xx that were not ban blocks
	triggered int
	uas       []string
	entries   []historyEntry // ring buffer
	next      int            // where the next entry is written
}

func (c *historyClient) push(e historyEntry) {
	if len(c.entries) < historyPerClient {
		c.entries = append(c.entries, e)
	} else {
		c.entries[c.next] = e
	}
	c.next = (c.next + 1) % historyPerClient
}

// at returns the i-th newest entry (0 is the newest).
func (c *historyClient) at(i int) *historyEntry {
	n := len(c.entries)
	return &c.entries[((c.next-1-i)%n+n)%n]
}

func (c *historyClient) latest() *historyEntry {
	if len(c.entries) == 0 {
		return nil
	}
	return c.at(0)
}

func (c *historyClient) uaIndex(ua string) uint8 {
	for i, u := range c.uas {
		if u == ua {
			return uint8(i)
		}
	}
	if len(c.uas) < historyMaxUAs {
		c.uas = append(c.uas, ua)
		return uint8(len(c.uas) - 1)
	}
	return historyUAOther
}

func (c *historyClient) uaString(i uint8) string {
	if int(i) < len(c.uas) {
		return c.uas[i]
	}
	return "(another browser)"
}

func (c *historyClient) flagged() bool {
	return c.blocked > 0 || c.triggered > 0
}

func (c *historyClient) matches(ip netip.Addr, q string) bool {
	if strings.Contains(ip.String(), q) {
		return true
	}
	for i := range c.entries {
		if strings.Contains(strings.ToLower(c.entries[i].path), q) {
			return true
		}
	}
	return false
}

// banTrigger is the request that started a ban.
type banTrigger struct {
	client netip.Addr
	method string
	path   string
	status int
	at     time.Time
}

// banWindow is one ban from start to end, with what the banned network
// requested while it was blocked.
type banWindow struct {
	id        uint64
	target    string       // as operators see it: an address, an IPv6 /64, or a range
	scope     netip.Prefix // every address the ban covers; immutable
	rangeBan  bool
	begin     time.Time // zero: already in force when the history started
	until     time.Time // zero when permanent
	permanent bool
	liftedAt  time.Time
	liftedBy  string
	source    string
	changes   int
	trigger   *banTrigger

	requests     int64
	firstHit     time.Time
	lastHit      time.Time
	paths        map[string]int64
	otherPaths   int64
	clients      map[netip.Addr]int64
	otherClients int64
}

func (w *banWindow) active(now time.Time) bool {
	return w.liftedAt.IsZero() && (w.permanent || w.until.After(now))
}

// ended is when the ban ended and why, or zero while it is in force.
func (w *banWindow) ended(now time.Time) (time.Time, string) {
	if !w.liftedAt.IsZero() {
		return w.liftedAt, "lifted"
	}
	if !w.permanent && !w.until.After(now) {
		return w.until, "expired"
	}
	return time.Time{}, ""
}

func (w *banWindow) setUntil(until int64) {
	if until == banForever {
		w.permanent, w.until = true, time.Time{}
		return
	}
	w.permanent, w.until = false, time.Unix(0, until)
}

func (w *banWindow) untilIs(until int64) bool {
	if until == banForever {
		return w.permanent
	}
	return !w.permanent && w.until.UnixNano() == until
}

// history is the portal's record of requests and bans.
type history struct {
	reg     *abuseRegistry  // always the app's registry, even while -abuse=false
	grants  *priorityGrants // reads each request's rank; see priority.go
	shards  [historyShards]historyShard
	count   atomic.Int64
	evicted atomic.Int64

	mu      sync.Mutex
	windows []*banWindow // oldest first
	nextID  uint64

	quietCache atomic.Pointer[quietRules]
}

type historyShard struct {
	mu sync.Mutex
	m  map[netip.Addr]*historyClient
}

// quietRules are the paths left out of the history when they succeed. They
// follow the running generation's settings.
type quietRules struct {
	g     *generation
	rules []pathRule
}

// newHistory builds an empty history and lists every ban already in force,
// such as those restored from bans.json, with an unknown start.
func newHistory(reg *abuseRegistry, grants *priorityGrants, now time.Time) *history {
	h := &history{reg: reg, grants: grants}
	for i := range h.shards {
		h.shards[i].m = make(map[netip.Addr]*historyClient)
	}
	for _, b := range reg.bans(now) {
		t, err := parseBanTarget(b.Client)
		if err != nil {
			continue
		}
		w := h.newWindowLocked(t.scope(), time.Time{})
		if b.Permanent {
			w.permanent = true
		} else {
			w.until = b.Until
		}
		w.source = "in force when concert started (restored from bans.json)"
	}
	return h
}

// attach adds the history to the registry's ban callback, keeping the
// callback already installed (dropping banned visitors from the line).
func (h *history) attach(reg *abuseRegistry) {
	prev := reg.onBan.Load()
	reg.setOnBan(func(p netip.Prefix) {
		if prev != nil {
			(*prev)(p)
		}
		h.banStarted(p)
	})
}

func (h *history) shard(ip netip.Addr) *historyShard {
	b := ip.As16()
	return &h.shards[(b[7]^b[13]^b[14]^b[15])&(historyShards-1)]
}

func (h *history) quiet(g *generation) []pathRule {
	if q := h.quietCache.Load(); q != nil && q.g == g {
		return q.rules
	}
	rules := append(parsePaths(g.cfg.assets), parsePaths(g.cfg.assetPublic)...)
	rules = append(rules, pathRule{path: "/queue/status"}, pathRule{path: "/_room/healthz"})
	h.quietCache.Store(&quietRules{g: g, rules: rules})
	return rules
}

func matchesAny(rules []pathRule, p string) bool {
	for _, r := range rules {
		if r.matches(p) {
			return true
		}
	}
	return false
}

// begin starts recording one request on the main listener. The returned
// writer records the request when its status is known; call finish when the
// handler returns.
func (h *history) begin(w http.ResponseWriter, r *http.Request, g *generation) *historyWriter {
	start := time.Now()
	ip := clientIP(r, g.cfg.trusted)
	_, blocked := g.abuse.banned(ip, start)
	req := historyRequest{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, ua: r.UserAgent(), rank: h.grants.rankOf(r, start)}
	return &historyWriter{
		ResponseWriter: w,
		record:         func(status int) { h.record(g, ip, req, status, start, blocked) },
	}
}

// record stores one request. blocked says whether the client was banned
// when the request arrived; a client banned by the time the status is known
// was banned by this request.
func (h *history) record(g *generation, ip netip.Addr, req historyRequest, status int, start time.Time, blocked bool) {
	if !ip.IsValid() {
		return
	}
	now := time.Now()
	bannedNow := false
	if !blocked {
		_, bannedNow = g.abuse.banned(ip, now)
	}
	if !blocked && !bannedNow && status < http.StatusBadRequest && matchesAny(h.quiet(g), req.path) {
		return
	}
	target := req.path
	if req.query != "" {
		target += "?" + req.query
	}
	e := historyEntry{
		at:      now,
		method:  clip(req.method, 16),
		path:    clip(target, historyPathLen),
		status:  status,
		latency: now.Sub(start),
		blocked: blocked,
		rank:    req.rank,
	}
	if blocked || bannedNow {
		e.window, e.triggered = h.hitWindow(ip, e, start, !blocked)
	}
	h.add(ip, e, clip(req.ua, historyUALen))
}

// hitWindow attributes a request to the ban covering ip. A blocked request
// is counted against the ban. A request after which ip became banned starts
// the ban when the ban covers only this client and began while the request
// was being answered.
func (h *history) hitWindow(ip netip.Addr, e historyEntry, start time.Time, triggering bool) (uint64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	w := h.activeForLocked(ip, e.at)
	if w == nil {
		return 0, false
	}
	if triggering {
		if w.trigger == nil && !w.rangeBan && !w.begin.Before(start) {
			w.trigger = &banTrigger{client: ip, method: e.method, path: e.path, status: e.status, at: e.at}
			return w.id, true
		}
		return w.id, false
	}
	w.requests++
	if w.firstHit.IsZero() {
		w.firstHit = e.at
	}
	w.lastHit = e.at
	countBounded(w.paths, e.path, historyWindowPaths, &w.otherPaths)
	countBounded(w.clients, ip, historyWindowClients, &w.otherClients)
	return w.id, false
}

// activeForLocked is the narrowest ban in force covering ip. Caller holds h.mu.
func (h *history) activeForLocked(ip netip.Addr, now time.Time) *banWindow {
	var best *banWindow
	for _, w := range h.windows {
		if w.active(now) && w.scope.Contains(ip) && (best == nil || w.scope.Bits() > best.scope.Bits()) {
			best = w
		}
	}
	return best
}

func countBounded[K comparable](m map[K]int64, k K, max int, other *int64) {
	if _, ok := m[k]; ok || len(m) < max {
		m[k]++
		return
	}
	*other++
}

// add appends e to ip's history, making room when the table is full.
func (h *history) add(ip netip.Addr, e historyEntry, ua string) {
	sh := h.shard(ip)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	c := sh.m[ip]
	if c == nil {
		if len(sh.m) >= historyMaxClients/historyShards {
			h.evictLocked(sh)
		}
		c = &historyClient{first: e.at}
		sh.m[ip] = c
		h.count.Add(1)
	}
	c.last = e.at
	c.requests++
	switch {
	case e.blocked:
		c.blocked++
	case e.status >= http.StatusBadRequest:
		c.errors++
	}
	if e.triggered {
		c.triggered++
	}
	e.ua = c.uaIndex(ua)
	c.push(e)
}

// evictLocked removes the client least worth keeping: one never banned or
// blocked before one that was, then the one idle longest. Caller holds sh.mu.
func (h *history) evictLocked(sh *historyShard) {
	var victim netip.Addr
	var vc *historyClient
	for ip, c := range sh.m {
		if vc == nil {
			victim, vc = ip, c
			continue
		}
		if fc, fv := c.flagged(), vc.flagged(); fc != fv {
			if !fc {
				victim, vc = ip, c
			}
			continue
		}
		if c.last.Before(vc.last) {
			victim, vc = ip, c
		}
	}
	if vc != nil {
		delete(sh.m, victim)
		h.count.Add(-1)
		h.evicted.Add(1)
	}
}

// ─── ban windows ─────────────────────────────────────────────────────────────

func isSingleScope(p netip.Prefix) bool {
	return (p.Addr().Is4() && p.Bits() == 32) || (p.Addr().Is6() && p.Bits() == 64)
}

// newWindowLocked appends a window for scope. Caller holds h.mu.
func (h *history) newWindowLocked(scope netip.Prefix, begin time.Time) *banWindow {
	h.nextID++
	single := isSingleScope(scope)
	w := &banWindow{
		id:       h.nextID,
		scope:    scope,
		rangeBan: !single,
		begin:    begin,
		paths:    make(map[string]int64),
		clients:  make(map[netip.Addr]int64),
	}
	if single {
		w.target = displayKey(scope.Addr())
	} else {
		w.target = scope.String()
	}
	h.windows = append(h.windows, w)
	return w
}

func (h *history) windowLocked(id uint64) *banWindow {
	for i := len(h.windows) - 1; i >= 0; i-- {
		if h.windows[i].id == id {
			return h.windows[i]
		}
	}
	return nil
}

// trimLocked keeps at most historyMaxWindows, dropping the oldest ended bans
// first. Caller holds h.mu.
func (h *history) trimLocked(now time.Time) {
	for len(h.windows) > historyMaxWindows {
		i := 0
		for j, w := range h.windows {
			if !w.active(now) {
				i = j
				break
			}
		}
		copy(h.windows[i:], h.windows[i+1:])
		h.windows[len(h.windows)-1] = nil
		h.windows = h.windows[:len(h.windows)-1]
	}
}

// banUntil reads when the ban on scope ends: unix nanos, banForever for a
// permanent ban, or false when the registry holds no ban for it.
func (r *abuseRegistry) banUntil(scope netip.Prefix) (int64, bool) {
	if r == nil {
		return 0, false
	}
	if isSingleScope(scope) {
		k := scope.Addr()
		sh := r.shard(k)
		sh.mu.Lock()
		defer sh.mu.Unlock()
		if e := sh.m[k]; e != nil && e.bannedUntil != 0 {
			return e.bannedUntil, true
		}
		return 0, false
	}
	r.ranges.mu.RLock()
	defer r.ranges.mu.RUnlock()
	if b := r.ranges.m[scope]; b != nil {
		return b.until, true
	}
	return 0, false
}

// banStarted is called by the registry for every new or changed ban. It runs
// outside every registry lock and must not block.
func (h *history) banStarted(p netip.Prefix) {
	now := time.Now()
	until, ok := h.reg.banUntil(p)
	if !ok || (until != banForever && until <= now.UnixNano()) {
		return
	}
	h.mu.Lock()
	var w *banWindow
	for i := len(h.windows) - 1; i >= 0; i-- {
		if x := h.windows[i]; x.scope == p && x.active(now) {
			w = x
			break
		}
	}
	fresh := w == nil
	if fresh {
		w = h.newWindowLocked(p, now)
	} else if !w.untilIs(until) {
		w.changes++
	}
	w.setUntil(until)
	id := w.id
	h.trimLocked(now)
	h.mu.Unlock()

	// Strikes from room's queue events land a moment after the request that
	// earned them. If no request claimed the ban by then, credit the
	// client's last request just before it began.
	if fresh && isSingleScope(p) {
		time.AfterFunc(historyTriggerDelay, func() { h.attributeTrigger(id, p) })
	}
}

func (h *history) attributeTrigger(id uint64, scope netip.Prefix) {
	h.mu.Lock()
	w := h.windowLocked(id)
	if w == nil || w.trigger != nil {
		h.mu.Unlock()
		return
	}
	begin := w.begin
	h.mu.Unlock()

	var best *banTrigger
	look := func(sh *historyShard) {
		sh.mu.Lock()
		defer sh.mu.Unlock()
		for ip, c := range sh.m {
			if !scope.Contains(ip) {
				continue
			}
			for i := 0; i < len(c.entries); i++ {
				e := c.at(i)
				if e.at.After(begin) {
					continue
				}
				if !e.blocked && !e.triggered && begin.Sub(e.at) <= historyTriggerWindow &&
					(best == nil || e.at.After(best.at)) {
					best = &banTrigger{client: ip, method: e.method, path: e.path, status: e.status, at: e.at}
				}
				break
			}
		}
	}
	if scope.Bits() == scope.Addr().BitLen() {
		look(h.shard(scope.Addr()))
	} else {
		for i := range h.shards {
			look(&h.shards[i])
		}
	}
	if best == nil {
		return
	}

	sh := h.shard(best.client)
	sh.mu.Lock()
	if c := sh.m[best.client]; c != nil {
		for i := 0; i < len(c.entries); i++ {
			if e := c.at(i); e.at.Equal(best.at) && e.path == best.path && !e.triggered {
				e.triggered, e.window = true, id
				c.triggered++
				break
			}
		}
	}
	sh.mu.Unlock()

	h.mu.Lock()
	if w := h.windowLocked(id); w != nil && w.trigger == nil {
		w.trigger = best
	}
	h.mu.Unlock()
}

// noteSource records who issued the ban in force on p.
func (h *history) noteSource(p netip.Prefix, source string) {
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.windows) - 1; i >= 0; i-- {
		if w := h.windows[i]; w.scope == p && w.active(now) {
			w.source = source
			return
		}
	}
}

// lifted ends the ban in force on p early.
func (h *history) lifted(p netip.Prefix, now time.Time, by string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.windows) - 1; i >= 0; i-- {
		if w := h.windows[i]; w.scope == p && w.active(now) {
			w.liftedAt, w.liftedBy = now, by
			return
		}
	}
}

// sweep notices bans lifted or changed outside the portal, and forgets
// clients and bans older than historyRetention. Run by the portal janitor.
func (h *history) sweep(now time.Time) {
	h.mu.Lock()
	var open []*banWindow
	for _, w := range h.windows {
		if w.active(now) {
			open = append(open, w)
		}
	}
	h.mu.Unlock()

	type state struct {
		until int64
		ok    bool
	}
	states := make(map[uint64]state, len(open))
	for _, w := range open { // id and scope never change
		until, ok := h.reg.banUntil(w.scope)
		states[w.id] = state{until, ok}
	}

	n := now.UnixNano()
	cutoff := now.Add(-historyRetention)
	h.mu.Lock()
	kept := h.windows[:0]
	for _, w := range h.windows {
		if s, checked := states[w.id]; checked && w.active(now) {
			if s.ok && (s.until == banForever || s.until > n) {
				if !w.untilIs(s.until) {
					w.setUntil(s.until)
					w.changes++
				}
			} else {
				w.liftedAt, w.liftedBy = now, "the admin API or another tool outside the portal"
			}
		}
		if ended, _ := w.ended(now); !ended.IsZero() && ended.Before(cutoff) {
			continue
		}
		kept = append(kept, w)
	}
	clear(h.windows[len(kept):])
	h.windows = kept
	h.mu.Unlock()

	for i := range h.shards {
		sh := &h.shards[i]
		sh.mu.Lock()
		for ip, c := range sh.m {
			if c.last.Before(cutoff) {
				delete(sh.m, ip)
				h.count.Add(-1)
			}
		}
		sh.mu.Unlock()
	}
}

// ─── views ───────────────────────────────────────────────────────────────────

type historyClientView struct {
	Client        string    `json:"client"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Requests      int64     `json:"requests"`
	Blocked       int64     `json:"blocked"`
	Errors        int64     `json:"errors"`
	BansTriggered int       `json:"bans_triggered"`
	LastMethod    string    `json:"last_method"`
	LastPath      string    `json:"last_path"`
	LastStatus    int       `json:"last_status"`
	BannedNow     bool      `json:"banned_now"`
	BanPermanent  bool      `json:"ban_permanent"`
	BanRemaining  int       `json:"ban_remaining_seconds"`
	Rank          string    `json:"rank"`

	addr netip.Addr
}

func (c *historyClient) summary(ip netip.Addr) historyClientView {
	v := historyClientView{
		Client: ip.String(), FirstSeen: c.first.UTC(), LastSeen: c.last.UTC(),
		Requests: c.requests, Blocked: c.blocked, Errors: c.errors, BansTriggered: c.triggered,
		addr: ip,
	}
	if e := c.latest(); e != nil {
		v.LastMethod, v.LastPath, v.LastStatus = e.method, e.path, e.status
		v.Rank = rankLabel(e.rank)
	}
	return v
}

// setBan fills in whether the client is banned now. reg is nil while the
// registry is off, when nothing is enforced.
func (v *historyClientView) setBan(reg *abuseRegistry, now time.Time) {
	left, banned := reg.banned(v.addr, now)
	if !banned {
		return
	}
	v.BannedNow = true
	if left == banForeverLeft {
		v.BanPermanent = true
		return
	}
	v.BanRemaining = int((left + time.Second - 1) / time.Second)
}

type historyEntryView struct {
	At        time.Time `json:"at"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
	LatencyMS float64   `json:"latency_ms"`
	UserAgent string    `json:"user_agent"`
	Blocked   bool      `json:"blocked"`
	Triggered bool      `json:"triggered_ban"`
	BanID     uint64    `json:"ban_id,omitempty"`
	Rank      string    `json:"rank"`
}

type namedCount struct {
	Name string `json:"name"`
	Hits int64  `json:"hits"`
}

type banTriggerView struct {
	Client string    `json:"client"`
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Status int       `json:"status"`
	At     time.Time `json:"at"`
}

type banWindowView struct {
	ID               uint64          `json:"id"`
	Target           string          `json:"target"`
	Range            bool            `json:"range"`
	Permanent        bool            `json:"permanent"`
	Active           bool            `json:"active"`
	Began            *time.Time      `json:"began"`
	Until            *time.Time      `json:"until"`
	Ended            *time.Time      `json:"ended"`
	EndReason        string          `json:"end_reason"`
	LiftedBy         string          `json:"lifted_by,omitempty"`
	RemainingSeconds int             `json:"remaining_seconds"`
	Changes          int             `json:"changes"`
	Source           string          `json:"source,omitempty"`
	Trigger          *banTriggerView `json:"trigger"`
	Requests         int64           `json:"requests"`
	FirstHit         *time.Time      `json:"first_hit"`
	LastHit          *time.Time      `json:"last_hit"`
	Paths            []namedCount    `json:"paths"`
	DistinctPaths    int             `json:"distinct_paths"`
	OtherPaths       int64           `json:"other_paths"`
	Clients          []namedCount    `json:"clients"`
	DistinctClients  int             `json:"distinct_clients"`
	OtherClients     int64           `json:"other_clients"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func topCounts[K comparable](m map[K]int64, limit int, name func(K) string) []namedCount {
	out := make([]namedCount, 0, len(m))
	for k, n := range m {
		out = append(out, namedCount{Name: name(k), Hits: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].Name < out[j].Name
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// view renders w. limit caps the paths and addresses listed; 0 lists all.
// Caller holds h.mu.
func (w *banWindow) view(now time.Time, limit int) banWindowView {
	v := banWindowView{
		ID: w.id, Target: w.target, Range: w.rangeBan, Permanent: w.permanent,
		Active: w.active(now), Began: timePtr(w.begin), Changes: w.changes,
		Source: w.source, LiftedBy: w.liftedBy, Requests: w.requests,
		FirstHit: timePtr(w.firstHit), LastHit: timePtr(w.lastHit),
		DistinctPaths: len(w.paths), OtherPaths: w.otherPaths,
		DistinctClients: len(w.clients), OtherClients: w.otherClients,
	}
	if !w.permanent {
		v.Until = timePtr(w.until)
	}
	if ended, reason := w.ended(now); !ended.IsZero() {
		v.Ended, v.EndReason = timePtr(ended), reason
	} else if !w.permanent {
		v.RemainingSeconds = int((w.until.Sub(now) + time.Second - 1) / time.Second)
	}
	if t := w.trigger; t != nil {
		v.Trigger = &banTriggerView{Client: t.client.String(), Method: t.method, Path: t.path, Status: t.status, At: t.at.UTC()}
	}
	v.Paths = topCounts(w.paths, limit, func(s string) string { return s })
	v.Clients = topCounts(w.clients, limit, func(a netip.Addr) string { return a.String() })
	return v
}

func (w *banWindow) matches(q string) bool {
	if strings.Contains(strings.ToLower(w.target), q) {
		return true
	}
	if t := w.trigger; t != nil && (strings.Contains(strings.ToLower(t.path), q) || strings.Contains(t.client.String(), q)) {
		return true
	}
	for p := range w.paths {
		if strings.Contains(strings.ToLower(p), q) {
			return true
		}
	}
	for a := range w.clients {
		if strings.Contains(a.String(), q) {
			return true
		}
	}
	return false
}

// clientViews lists clients matching q (an address fragment or a path
// fragment, lowercased), banned clients first, then clients that were
// banned, then the most recent. It also returns how many matched.
func (h *history) clientViews(q string, flagged bool, reg *abuseRegistry, now time.Time) ([]historyClientView, int) {
	out := []historyClientView{}
	for i := range h.shards {
		sh := &h.shards[i]
		sh.mu.Lock()
		for ip, c := range sh.m {
			if q != "" && !c.matches(ip, q) {
				continue
			}
			out = append(out, c.summary(ip))
		}
		sh.mu.Unlock()
	}
	kept := out[:0]
	for _, v := range out {
		v.setBan(reg, now)
		if flagged && !v.BannedNow && v.Blocked == 0 && v.BansTriggered == 0 {
			continue
		}
		kept = append(kept, v)
	}
	sort.Slice(kept, func(i, j int) bool {
		a, b := kept[i], kept[j]
		if a.BannedNow != b.BannedNow {
			return a.BannedNow
		}
		fa, fb := a.Blocked > 0 || a.BansTriggered > 0, b.Blocked > 0 || b.BansTriggered > 0
		if fa != fb {
			return fa
		}
		return a.LastSeen.After(b.LastSeen)
	})
	matched := len(kept)
	if len(kept) > historyListLimit {
		kept = kept[:historyListLimit]
	}
	return kept, matched
}

// clientDetail returns one client's summary, requests newest first, and the
// browsers it used.
func (h *history) clientDetail(ip netip.Addr) (historyClientView, []historyEntryView, []string, bool) {
	sh := h.shard(ip)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	c := sh.m[ip]
	if c == nil {
		return historyClientView{}, nil, nil, false
	}
	entries := make([]historyEntryView, 0, len(c.entries))
	for i := 0; i < len(c.entries); i++ {
		e := c.at(i)
		entries = append(entries, historyEntryView{
			At: e.at.UTC(), Method: e.method, Path: e.path, Status: e.status,
			LatencyMS: float64(e.latency.Microseconds()) / 1000,
			Rank:      rankLabel(e.rank),
			UserAgent: c.uaString(e.ua), Blocked: e.blocked, Triggered: e.triggered, BanID: e.window,
		})
	}
	return c.summary(ip), entries, append([]string{}, c.uas...), true
}

// windowViews lists the ban log, newest first, with each ban's top paths.
func (h *history) windowViews(q string, now time.Time) []banWindowView {
	out := []banWindowView{}
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.windows) - 1; i >= 0 && len(out) < historyBanLimit; i-- {
		w := h.windows[i]
		if q != "" && !w.matches(q) {
			continue
		}
		out = append(out, w.view(now, historySummaryPaths))
	}
	return out
}

// windowsFor lists every ban that covered ip, newest first, in full.
func (h *history) windowsFor(ip netip.Addr, now time.Time) []banWindowView {
	out := []banWindowView{}
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.windows) - 1; i >= 0; i-- {
		if w := h.windows[i]; w.scope.Contains(ip) {
			out = append(out, w.view(now, 0))
		}
	}
	return out
}

func (h *history) windowByID(id uint64, now time.Time) (banWindowView, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if w := h.windowLocked(id); w != nil {
		return w.view(now, 0), true
	}
	return banWindowView{}, false
}

// ─── portal API ──────────────────────────────────────────────────────────────

// apiHistory lists clients and the ban log. ?q= filters both by address or
// path fragment; ?flagged=1 lists only clients that are or were banned.
func (p *portal) apiHistory(c *gin.Context) {
	now := time.Now()
	g := p.a.current()
	q := strings.ToLower(strings.TrimSpace(c.Query("q")))
	clients, matched := p.history.clientViews(q, c.Query("flagged") == "1", g.abuse, now)
	c.JSON(http.StatusOK, gin.H{
		"clients":       clients,
		"listed":        len(clients),
		"matched":       matched,
		"tracked":       p.history.count.Load(),
		"evicted":       p.history.evicted.Load(),
		"bans":          p.history.windowViews(q, now),
		"abuse_enabled": g.abuse != nil,
		"limits": gin.H{
			"max_clients":     historyMaxClients,
			"per_client":      historyPerClient,
			"retention_hours": int(historyRetention / time.Hour),
			"listed":          historyListLimit,
			"bans_listed":     historyBanLimit,
		},
	})
}

// apiHistoryClient returns one client's requests and every ban covering it.
func (p *portal) apiHistoryClient(c *gin.Context) {
	ip, err := netip.ParseAddr(strings.TrimSpace(c.Query("client")))
	if err != nil {
		jsonError(c, http.StatusBadRequest, "client must be an IP address")
		return
	}
	ip = ip.Unmap().WithZone("")
	now := time.Now()
	v, entries, uas, ok := p.history.clientDetail(ip)
	if !ok {
		jsonError(c, http.StatusNotFound, "no requests recorded from that address")
		return
	}
	v.setBan(p.a.current().abuse, now)
	c.JSON(http.StatusOK, gin.H{
		"client":      v,
		"entries":     entries,
		"user_agents": uas,
		"bans":        p.history.windowsFor(ip, now),
	})
}

// apiHistoryBan returns one ban with every path and address it blocked.
func (p *portal) apiHistoryBan(c *gin.Context) {
	id, err := strconv.ParseUint(c.Query("id"), 10, 64)
	if err != nil {
		jsonError(c, http.StatusBadRequest, "id is required")
		return
	}
	v, ok := p.history.windowByID(id, time.Now())
	if !ok {
		jsonError(c, http.StatusNotFound, "that ban is no longer in the history")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ban": v})
}

// ─── response writer ─────────────────────────────────────────────────────────

// historyWriter records its request once the response status is known. It
// forwards Flush and Hijack like ticketWriter, so streaming and upgrades
// keep working.
type historyWriter struct {
	http.ResponseWriter
	recorded bool
	record   func(status int)
}

func (w *historyWriter) mark(status int) {
	if w.recorded {
		return
	}
	w.recorded = true
	w.record(status)
}

func (w *historyWriter) WriteHeader(code int) {
	// Informational responses such as 103 Early Hints precede the real status.
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.mark(code)
	w.ResponseWriter.WriteHeader(code)
}

func (w *historyWriter) Write(b []byte) (int, error) {
	w.mark(http.StatusOK)
	return w.ResponseWriter.Write(b)
}

func (w *historyWriter) Flush() {
	w.mark(http.StatusOK)
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *historyWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.mark(http.StatusSwitchingProtocols)
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (w *historyWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// finish records a request whose handler wrote nothing (an implicit 200).
func (w *historyWriter) finish() { w.mark(http.StatusOK) }
