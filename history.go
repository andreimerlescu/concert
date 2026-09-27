package main

import (
	"bufio"
	"fmt"
	"log"
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

// Request history for the admin portal's Visitors and Ban log tabs.
//
// The access log goes to stdout and scrolls away, and it never sees banned
// clients at all: bans are enforced before the logger runs. The history
// keeps, in memory, the recent requests of every client the main listener
// has seen, grouped by client address, plus a log of every ban: when it
// began, when it ends or ended, which request started it, and every request
// the banned network made while it was blocked. With a history log (see
// history_log.go) all of it survives restarts.
//
// What is recorded: everything the access log records, and also requests
// from banned clients, the request that started a ban, and any request
// answered with 4xx or 5xx, including on asset and status paths (a forged
// admission pass shows up here). Successful asset, /queue/status and
// /_room/healthz requests are left out, as they are from the access log.
//
// Recording happens in portal.wrap once the response status is known (the
// first header or body write), so a WebSocket or event stream appears the
// moment it opens rather than when it closes.
//
// Bounds: at most historyMaxClients addresses with historyPerClient requests
// each; the portal pages through them. When the table is full, the quietest
// client that was never banned makes room. A ban window keeps up to
// historyWindowPaths distinct paths and historyWindowClients addresses and
// counts the rest. Clients idle for historyRetention, and bans that ended
// that long ago, are forgotten.

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
	historyListLimit     = 500 // clients the JSON API lists
	historyBanLimit      = 200 // bans the JSON API lists
	historySummaryPaths  = 3   // top paths shown per ban in the ban log
	historyTriggerDelay  = 500 * time.Millisecond
	historyTriggerWindow = 5 * time.Second
	historyUAOther       = uint8(255)
	historyRawPerBan     = 100 // blocked requests per client per ban written to the log one by one
	historyAggEvery      = time.Second
	historyAggMax        = 50000 // clients aggregated per second before counts are dropped
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

func (t *banTrigger) logTrigger() *logTrigger {
	return &logTrigger{Client: t.client.String(), Method: t.method, Path: t.path, Status: t.status, At: t.at.UTC()}
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

	logged map[netip.Addr]int // blocked requests written to the log, per client
}

func newBanWindow(id uint64, scope netip.Prefix, begin time.Time) *banWindow {
	single := isSingleScope(scope)
	w := &banWindow{
		id:       id,
		scope:    scope,
		rangeBan: !single,
		begin:    begin,
		paths:    make(map[string]int64),
		clients:  make(map[netip.Addr]int64),
		logged:   make(map[netip.Addr]int),
	}
	if single {
		w.target = displayKey(scope.Addr())
	} else {
		w.target = scope.String()
	}
	return w
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

// count adds n blocked requests from ip for path.
func (w *banWindow) count(ip netip.Addr, path string, at time.Time, n int64) {
	w.requests += n
	if w.firstHit.IsZero() || at.Before(w.firstHit) {
		w.firstHit = at
	}
	if at.After(w.lastHit) {
		w.lastHit = at
	}
	countBounded(w.paths, path, historyWindowPaths, &w.otherPaths, n)
	countBounded(w.clients, ip, historyWindowClients, &w.otherClients, n)
}

// event is the window's full state as a log line. Caller holds h.mu.
func (w *banWindow) event() *historyEvent {
	ev := &historyEvent{
		T: evBan, At: time.Now().UTC(), Ban: w.id, Target: w.target, Scope: w.scope.String(),
		Range: w.rangeBan, Begin: timePtr(w.begin), Permanent: w.permanent, Changes: w.changes, Source: w.source,
	}
	if !w.permanent {
		ev.Until = timePtr(w.until)
	}
	return ev
}

func (w *banWindow) liftEvent() *historyEvent {
	return &historyEvent{T: evLift, At: w.liftedAt.UTC(), Ban: w.id, By: w.liftedBy}
}

type aggKey struct {
	id uint64
	ip netip.Addr
}

type aggVal struct {
	n     int64
	first time.Time
	last  time.Time
	paths map[string]int64
	other int64
}

// history is the portal's record of requests and bans.
type history struct {
	reg     *abuseRegistry  // always the app's registry, even while -abuse=false
	grants  *priorityGrants // reads each request's rank; see priority.go
	info    *ipLookup       // ess details written to the log with each request
	log     *historyLog     // nil: memory only
	logErr  string          // why the log is off, when one was asked for
	shards  [historyShards]historyShard
	count   atomic.Int64
	evicted atomic.Int64

	mu      sync.RWMutex
	windows []*banWindow          // oldest first
	byID    map[uint64]*banWindow // every window in windows
	active  map[uint64]*banWindow // windows that may still be in force
	nextID  uint64

	aggMu      sync.Mutex
	agg        map[aggKey]*aggVal
	aggDropped atomic.Int64

	quietCache atomic.Pointer[quietRules]

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
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

// newHistory builds the history, replays the history log at logPath when
// one is given, and lists every ban in force that the log did not know
// about, such as bans restored from bans.json, with an unknown start.
func newHistory(reg *abuseRegistry, grants *priorityGrants, info *ipLookup, logPath string, now time.Time) *history {
	h := &history{
		reg: reg, grants: grants, info: info,
		byID:   map[uint64]*banWindow{},
		active: map[uint64]*banWindow{},
		agg:    map[aggKey]*aggVal{},
		stop:   make(chan struct{}),
	}
	for i := range h.shards {
		h.shards[i].m = make(map[netip.Addr]*historyClient)
	}

	if logPath != "" {
		start := time.Now()
		st, err := replayHistoryLog(logPath, historyLogKeep, now.Add(-historyRetention), h.apply)
		if err != nil {
			log.Printf("history: could not replay %s: %v; continuing with what was read", logPath, err)
		}
		if st.events > 0 || st.bad > 0 {
			log.Printf("history: restored %d event(s) from %s in %s (%d unreadable, %d older than %s)",
				st.events, logPath, time.Since(start).Round(time.Millisecond), st.bad, st.old, historyRetention)
		}
		h.mu.Lock()
		h.dropEndedLocked(now.Add(-historyRetention), now)
		h.trimLocked(now)
		h.mu.Unlock()

		l, err := openHistoryLog(logPath, historyLogMaxBytes, historyLogKeep)
		if err != nil {
			h.logErr = err.Error()
			log.Printf("history: %v; the history is kept in memory only", err)
		} else {
			h.log = l
		}
	}

	h.reconcile(now)
	if h.log != nil {
		h.wg.Add(1)
		go h.aggLoop()
	}
	return h
}

// reconcile matches the windows the log restored with the bans actually in
// force: a window whose ban is gone is ended, a ban with no window gets one.
func (h *history) reconcile(now time.Time) {
	inForce := map[netip.Prefix]int64{}
	for _, b := range h.reg.bans(now) {
		t, err := parseBanTarget(b.Client)
		if err != nil {
			continue
		}
		until := banForever
		if !b.Permanent {
			until = b.Until.UnixNano()
		}
		inForce[t.scope()] = until
	}

	var events []*historyEvent
	h.mu.Lock()
	for id, w := range h.active {
		if !w.active(now) {
			delete(h.active, id)
			continue
		}
		until, ok := inForce[w.scope]
		if !ok {
			w.liftedAt, w.liftedBy = now, "concert restarted without it (not in bans.json)"
			delete(h.active, id)
			events = append(events, w.liftEvent())
			continue
		}
		delete(inForce, w.scope)
		if !w.untilIs(until) {
			w.setUntil(until)
			w.changes++
			events = append(events, w.event())
		}
	}
	for scope, until := range inForce {
		w := h.newWindowLocked(scope, time.Time{})
		w.setUntil(until)
		w.source = "in force when concert started (restored from bans.json)"
		events = append(events, w.event())
	}
	h.mu.Unlock()
	for _, ev := range events {
		h.log.emit(ev)
	}
}

// close flushes the aggregates and the log. Safe on a nil history.
func (h *history) close() {
	if h == nil {
		return
	}
	h.stopOnce.Do(func() {
		close(h.stop)
		h.wg.Wait()
		if h.log != nil {
			h.flushAgg()
			h.log.close()
		}
	})
}

// describeLog is the history log's state for operators.
func (h *history) describeLog() string {
	if h == nil {
		return "off: the admin portal is off, so no history is kept"
	}
	if h.log == nil {
		if h.logErr != "" {
			return "off: " + h.logErr
		}
		return "off: memory only (-history-log off, or -data-dir empty)"
	}
	return fmt.Sprintf("%s · %d event(s) written · %d dropped", h.log.path,
		h.log.written.Load(), h.log.dropped.Load()+h.aggDropped.Load())
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
	logRaw := true
	if blocked || bannedNow {
		e.window, e.triggered, logRaw = h.hitWindow(ip, e, start, !blocked)
	}
	ua := clip(req.ua, historyUALen)
	h.add(ip, e, ua)
	if h.log == nil {
		return
	}
	if logRaw {
		h.log.emit(h.requestEvent(ip, e, ua))
	} else {
		h.aggAdd(e.window, ip, e.path, e.at)
	}
}

func (h *history) requestEvent(ip netip.Addr, e historyEntry, ua string) *historyEvent {
	return &historyEvent{
		T: evRequest, At: e.at.UTC(), IP: ip.String(), Method: e.method, Path: e.path, Status: e.status,
		LatencyUS: e.latency.Microseconds(), UA: ua, Blocked: e.blocked, Triggered: e.triggered,
		Ban: e.window, Rank: rankLabel(e.rank), Info: h.info.logInfo(ip),
	}
}

// hitWindow attributes a request to the ban covering ip. A blocked request
// is counted against the ban. A request after which ip became banned starts
// the ban when the ban covers only this client and began while the request
// was being answered. logRaw is false once a client has had
// historyRawPerBan blocked requests written to the log for this ban.
func (h *history) hitWindow(ip netip.Addr, e historyEntry, start time.Time, triggering bool) (id uint64, triggered, logRaw bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	w := h.activeForLocked(ip, e.at)
	if w == nil {
		return 0, false, true
	}
	if triggering {
		if w.trigger == nil && !w.rangeBan && !w.begin.Before(start) {
			w.trigger = &banTrigger{client: ip, method: e.method, path: e.path, status: e.status, at: e.at}
			return w.id, true, true
		}
		return w.id, false, true
	}
	w.count(ip, e.path, e.at, 1)
	n, seen := w.logged[ip]
	if !seen && len(w.logged) >= historyWindowClients*10 {
		return w.id, false, false
	}
	w.logged[ip] = n + 1
	return w.id, false, n < historyRawPerBan
}

// activeForLocked is the narrowest ban in force covering ip. Caller holds h.mu.
func (h *history) activeForLocked(ip netip.Addr, now time.Time) *banWindow {
	var best *banWindow
	for _, w := range h.active {
		if !w.active(now) || !w.scope.Contains(ip) {
			continue
		}
		if best == nil || w.scope.Bits() > best.scope.Bits() ||
			(w.scope.Bits() == best.scope.Bits() && w.id > best.id) {
			best = w
		}
	}
	return best
}

// activeScopeLocked is the newest ban in force on exactly p. Caller holds h.mu.
func (h *history) activeScopeLocked(p netip.Prefix, now time.Time) *banWindow {
	var best *banWindow
	for _, w := range h.active {
		if w.scope == p && w.active(now) && (best == nil || w.id > best.id) {
			best = w
		}
	}
	return best
}

func countBounded[K comparable](m map[K]int64, k K, max int, other *int64, n int64) {
	if _, ok := m[k]; ok || len(m) < max {
		m[k] += n
		return
	}
	*other += n
}

// clientLocked returns ip's client, making room when the table is full.
// Caller holds sh.mu.
func (h *history) clientLocked(sh *historyShard, ip netip.Addr, at time.Time) *historyClient {
	c := sh.m[ip]
	if c == nil {
		if len(sh.m) >= historyMaxClients/historyShards {
			h.evictLocked(sh)
		}
		c = &historyClient{first: at, last: at}
		sh.m[ip] = c
		h.count.Add(1)
	}
	return c
}

// add appends e to ip's history.
func (h *history) add(ip netip.Addr, e historyEntry, ua string) {
	sh := h.shard(ip)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	c := h.clientLocked(sh, ip, e.at)
	if e.at.After(c.last) {
		c.last = e.at
	}
	if e.at.Before(c.first) {
		c.first = e.at
	}
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

// addCount counts n blocked requests that were aggregated in the log.
func (h *history) addCount(ip netip.Addr, at time.Time, n int64) {
	if n <= 0 {
		return
	}
	sh := h.shard(ip)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	c := h.clientLocked(sh, ip, at)
	if at.After(c.last) {
		c.last = at
	}
	c.requests += n
	c.blocked += n
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

// markTriggered flags the request that started ban id.
func (h *history) markTriggered(ip netip.Addr, at time.Time, path string, id uint64) {
	sh := h.shard(ip)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	c := sh.m[ip]
	if c == nil {
		return
	}
	for i := 0; i < len(c.entries); i++ {
		if e := c.at(i); e.at.Equal(at) && e.path == path && !e.triggered {
			e.triggered, e.window = true, id
			c.triggered++
			return
		}
	}
}

// ─── aggregation of floods ───────────────────────────────────────────────────

func (h *history) aggAdd(id uint64, ip netip.Addr, path string, at time.Time) {
	h.aggMu.Lock()
	defer h.aggMu.Unlock()
	k := aggKey{id: id, ip: ip}
	v := h.agg[k]
	if v == nil {
		if len(h.agg) >= historyAggMax {
			h.aggDropped.Add(1)
			return
		}
		v = &aggVal{first: at, paths: map[string]int64{}}
		h.agg[k] = v
	}
	v.n++
	v.last = at
	countBounded(v.paths, path, historyWindowPaths, &v.other, 1)
}

func (h *history) aggLoop() {
	defer h.wg.Done()
	t := time.NewTicker(historyAggEvery)
	defer t.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-t.C:
			h.flushAgg()
		}
	}
}

func (h *history) flushAgg() {
	h.aggMu.Lock()
	batch := h.agg
	h.agg = map[aggKey]*aggVal{}
	h.aggMu.Unlock()
	for k, v := range batch {
		h.log.emit(&historyEvent{
			T: evAgg, At: v.last.UTC(), First: timePtr(v.first), Ban: k.id, IP: k.ip.String(),
			Count: v.n, Paths: v.paths, OtherPaths: v.other,
		})
	}
}

// ─── ban windows ─────────────────────────────────────────────────────────────

func isSingleScope(p netip.Prefix) bool {
	return (p.Addr().Is4() && p.Bits() == 32) || (p.Addr().Is6() && p.Bits() == 64)
}

// newWindowLocked appends a window for scope. Caller holds h.mu.
func (h *history) newWindowLocked(scope netip.Prefix, begin time.Time) *banWindow {
	w := newBanWindow(h.nextID+1, scope, begin)
	h.addWindowLocked(w)
	return w
}

func (h *history) addWindowLocked(w *banWindow) {
	h.windows = append(h.windows, w)
	h.byID[w.id] = w
	h.active[w.id] = w
	if w.id > h.nextID {
		h.nextID = w.id
	}
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
		w := h.windows[i]
		delete(h.byID, w.id)
		delete(h.active, w.id)
		copy(h.windows[i:], h.windows[i+1:])
		h.windows[len(h.windows)-1] = nil
		h.windows = h.windows[:len(h.windows)-1]
	}
}

// dropEndedLocked forgets bans that ended before cutoff. Caller holds h.mu.
func (h *history) dropEndedLocked(cutoff, now time.Time) {
	kept := h.windows[:0]
	for _, w := range h.windows {
		if ended, _ := w.ended(now); !ended.IsZero() && ended.Before(cutoff) {
			delete(h.byID, w.id)
			delete(h.active, w.id)
			continue
		}
		kept = append(kept, w)
	}
	clear(h.windows[len(kept):])
	h.windows = kept
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
	w := h.activeScopeLocked(p, now)
	fresh := w == nil
	changed := fresh
	if fresh {
		w = h.newWindowLocked(p, now)
	} else if !w.untilIs(until) {
		w.changes++
		changed = true
	}
	w.setUntil(until)
	id := w.id
	var ev *historyEvent
	if changed {
		ev = w.event()
	}
	h.trimLocked(now)
	h.mu.Unlock()
	h.log.emit(ev)

	// Strikes from room's queue events land a moment after the request that
	// earned them. If no request claimed the ban by then, credit the
	// client's last request just before it began.
	if fresh && isSingleScope(p) {
		time.AfterFunc(historyTriggerDelay, func() { h.attributeTrigger(id, p) })
	}
}

func (h *history) attributeTrigger(id uint64, scope netip.Prefix) {
	h.mu.RLock()
	w := h.byID[id]
	if w == nil || w.trigger != nil {
		h.mu.RUnlock()
		return
	}
	begin := w.begin
	h.mu.RUnlock()

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
	h.markTriggered(best.client, best.at, best.path, id)

	var ev *historyEvent
	h.mu.Lock()
	if w := h.byID[id]; w != nil && w.trigger == nil {
		w.trigger = best
		ev = &historyEvent{T: evTrigger, At: time.Now().UTC(), Ban: id, Trigger: best.logTrigger()}
	}
	h.mu.Unlock()
	h.log.emit(ev)
}

// noteSource records who issued the ban in force on p.
func (h *history) noteSource(p netip.Prefix, source string) {
	now := time.Now()
	var ev *historyEvent
	h.mu.Lock()
	if w := h.activeScopeLocked(p, now); w != nil {
		w.source = source
		ev = w.event()
	}
	h.mu.Unlock()
	h.log.emit(ev)
}

// lifted ends the ban in force on p early.
func (h *history) lifted(p netip.Prefix, now time.Time, by string) {
	var ev *historyEvent
	h.mu.Lock()
	if w := h.activeScopeLocked(p, now); w != nil {
		w.liftedAt, w.liftedBy = now, by
		delete(h.active, w.id)
		ev = w.liftEvent()
	}
	h.mu.Unlock()
	h.log.emit(ev)
}

// sweep notices bans lifted or changed outside the portal, and forgets
// clients and bans older than historyRetention. Run by the portal janitor.
func (h *history) sweep(now time.Time) {
	h.mu.RLock()
	open := make([]*banWindow, 0, len(h.active))
	for _, w := range h.active {
		if w.active(now) {
			open = append(open, w)
		}
	}
	h.mu.RUnlock()

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
	var events []*historyEvent
	h.mu.Lock()
	for id, w := range h.active {
		if !w.active(now) {
			delete(h.active, id)
			continue
		}
		s, checked := states[id]
		if !checked {
			continue
		}
		if s.ok && (s.until == banForever || s.until > n) {
			if !w.untilIs(s.until) {
				w.setUntil(s.until)
				w.changes++
				events = append(events, w.event())
			}
			continue
		}
		w.liftedAt, w.liftedBy = now, "the admin API or another tool outside the portal"
		delete(h.active, id)
		events = append(events, w.liftEvent())
	}
	h.dropEndedLocked(now.Add(-historyRetention), now)
	h.mu.Unlock()
	for _, ev := range events {
		h.log.emit(ev)
	}

	cutoff := now.Add(-historyRetention)
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

// ─── replay ──────────────────────────────────────────────────────────────────

// apply rebuilds state from one log event. Used only while replaying, before
// the log is open, so nothing is written back.
func (h *history) apply(ev *historyEvent) {
	switch ev.T {
	case evRequest:
		h.applyRequest(ev)
	case evAgg:
		h.applyAgg(ev)
	case evBan:
		h.applyBan(ev)
	case evLift:
		h.applyLift(ev)
	case evTrigger:
		h.applyTrigger(ev)
	}
}

func (h *history) applyRequest(ev *historyEvent) {
	ip, err := netip.ParseAddr(ev.IP)
	if err != nil {
		return
	}
	rank, _ := parseRank(ev.Rank)
	e := historyEntry{
		at: ev.At, method: ev.Method, path: ev.Path, status: ev.Status,
		latency: time.Duration(ev.LatencyUS) * time.Microsecond,
		blocked: ev.Blocked, triggered: ev.Triggered, window: ev.Ban, rank: rank,
	}
	if ev.Ban != 0 {
		h.mu.Lock()
		if w := h.byID[ev.Ban]; w != nil {
			if ev.Blocked {
				w.count(ip, e.path, e.at, 1)
			}
			if ev.Triggered && w.trigger == nil {
				w.trigger = &banTrigger{client: ip, method: e.method, path: e.path, status: e.status, at: e.at}
			}
		}
		h.mu.Unlock()
	}
	h.add(ip, e, ev.UA)
}

func (h *history) applyAgg(ev *historyEvent) {
	ip, err := netip.ParseAddr(ev.IP)
	if err != nil || ev.Count <= 0 {
		return
	}
	h.mu.Lock()
	if w := h.byID[ev.Ban]; w != nil {
		var itemised int64
		for p, n := range ev.Paths {
			w.count(ip, p, ev.At, n)
			itemised += n
		}
		if rest := ev.Count - itemised; rest > 0 {
			w.requests += rest
			w.otherPaths += rest
			countBounded(w.clients, ip, historyWindowClients, &w.otherClients, rest)
		}
		if ev.First != nil && (w.firstHit.IsZero() || ev.First.Before(w.firstHit)) {
			w.firstHit = *ev.First
		}
	}
	h.mu.Unlock()
	h.addCount(ip, ev.At, ev.Count)
}

func (h *history) applyBan(ev *historyEvent) {
	scope, err := netip.ParsePrefix(ev.Scope)
	if err != nil || ev.Ban == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	w := h.byID[ev.Ban]
	if w == nil {
		var begin time.Time
		if ev.Begin != nil {
			begin = *ev.Begin
		}
		w = newBanWindow(ev.Ban, scope, begin)
		h.addWindowLocked(w)
	}
	if ev.Target != "" {
		w.target = ev.Target
	}
	w.rangeBan = ev.Range
	if ev.Permanent {
		w.permanent, w.until = true, time.Time{}
	} else if ev.Until != nil {
		w.permanent, w.until = false, *ev.Until
	}
	w.changes = ev.Changes
	w.source = ev.Source
}

func (h *history) applyLift(ev *historyEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if w := h.byID[ev.Ban]; w != nil {
		w.liftedAt, w.liftedBy = ev.At, ev.By
		delete(h.active, w.id)
	}
}

func (h *history) applyTrigger(ev *historyEvent) {
	if ev.Trigger == nil {
		return
	}
	ip, err := netip.ParseAddr(ev.Trigger.Client)
	if err != nil {
		return
	}
	t := &banTrigger{client: ip, method: ev.Trigger.Method, path: ev.Trigger.Path, status: ev.Trigger.Status, at: ev.Trigger.At}
	h.mu.Lock()
	if w := h.byID[ev.Ban]; w != nil && w.trigger == nil {
		w.trigger = t
	}
	h.mu.Unlock()
	h.markTriggered(ip, t.at, t.path, ev.Ban)
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
	BanUntilMS    int64     `json:"ban_until_ms,omitempty"`
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
	v.BanUntilMS = now.Add(left).UnixMilli()
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
// Caller holds h.mu (read or write).
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

// sortedClients lists every client matching q (an address fragment or a path
// fragment, lowercased): permanently banned clients first, then temporarily
// banned ones, then clients that were banned, then the most recent. Ties
// break by address, so the order is stable between pages.
func (h *history) sortedClients(q string, flagged bool, reg *abuseRegistry, now time.Time) []historyClientView {
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
		if a.BannedNow && a.BanPermanent != b.BanPermanent {
			return a.BanPermanent
		}
		fa, fb := a.Blocked > 0 || a.BansTriggered > 0, b.Blocked > 0 || b.BansTriggered > 0
		if fa != fb {
			return fa
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.Client < b.Client
	})
	return kept
}

// clientViews is sortedClients capped for the JSON API, with how many matched.
func (h *history) clientViews(q string, flagged bool, reg *abuseRegistry, now time.Time) ([]historyClientView, int) {
	kept := h.sortedClients(q, flagged, reg, now)
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

// windowViews lists the ban log for the JSON API, newest first, with each
// ban's top paths.
func (h *history) windowViews(q string, now time.Time) []banWindowView {
	out := []banWindowView{}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for i := len(h.windows) - 1; i >= 0 && len(out) < historyBanLimit; i-- {
		w := h.windows[i]
		if q != "" && !w.matches(q) {
			continue
		}
		out = append(out, w.view(now, historySummaryPaths))
	}
	return out
}

// windowPage is one page of the ban log, newest first. Only the page's bans
// are rendered. where maps each key in keysParam to the page it is on now.
func (h *history) windowPage(q string, now time.Time, page, size int, keysParam string) (views []banWindowView, total, p, pages int, where map[string]int) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	matched := make([]*banWindow, 0, len(h.windows))
	for i := len(h.windows) - 1; i >= 0; i-- {
		if w := h.windows[i]; q == "" || w.matches(q) {
			matched = append(matched, w)
		}
	}
	total = len(matched)
	var start, end int
	start, end, p, pages = paginate(total, page, size)
	views = make([]banWindowView, 0, end-start)
	for _, w := range matched[start:end] {
		views = append(views, w.view(now, historySummaryPaths))
	}
	where = wherePages(keysParam, size, total, func(i int) string { return strconv.FormatUint(matched[i].id, 10) })
	return views, total, p, pages, where
}

// windowsFor lists every ban that covered ip, newest first, in full.
func (h *history) windowsFor(ip netip.Addr, now time.Time) []banWindowView {
	out := []banWindowView{}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for i := len(h.windows) - 1; i >= 0; i-- {
		if w := h.windows[i]; w.scope.Contains(ip) {
			out = append(out, w.view(now, 0))
		}
	}
	return out
}

func (h *history) windowByID(id uint64, now time.Time) (banWindowView, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if w := h.byID[id]; w != nil {
		return w.view(now, 0), true
	}
	return banWindowView{}, false
}

// ─── portal JSON API ─────────────────────────────────────────────────────────

// apiHistory lists clients and the ban log. ?q= filters both by address or
// path fragment; ?flagged=1 lists only clients that are or were banned. The
// portal itself uses the paginated fragments in fragments.go.
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
		"persisted":     p.history.log != nil,
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
