package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/room"
	"github.com/gin-gonic/gin"
)

// Priority: visitors ranked by the origin.
//
// The origin ranks its own visitors by adding a Concert-Priority header to
// any page response:
//
//	Concert-Priority: checkout; ttl=30m
//
// concert removes the header before the response leaves, and stores the
// grant in concert_priority: a cookie signed with a key derived from
// CONCERT_ADMIT_SECRET and bound to the visitor's admission pass. Only the
// origin can grant a rank. Browsers cannot set response headers, and cannot
// forge a grant or move one to another pass. The latest header wins, so the
// origin can raise, lower (checkout, then customer after payment) or clear
// (guest, on logout) a grant, and every header renews the grant's lifetime.
// Only page responses grant: asset, bypass and stream responses are ignored.
//
// Ranks, lowest to highest, and what they get while the room is busy:
//
//	0 guest       anonymous; no header needed        first come, first served
//	1 member      signed in, nothing bought          waits, ahead of guests
//	2 prospect    buying page, items in cart         waits, ahead of members
//	3 customer    has bought before                  priority lane
//	4 subscriber  active subscription                priority lane
//	5 checkout    payment in progress                priority lane
//	6 staff       operators and support              priority lane, first
//
// Ranked visitors below -priority-lane-rank still wait, but room's line is
// kept ordered by rank, first come first served within a rank. Visitors at
// or above it take the priority lane: a separate pool of -priority-cap
// slots, so the origin never sees more than -cap + -priority-cap page
// requests at once. A lane request waits up to -priority-wait for a slot,
// highest rank first, and otherwise joins the line at the front of its rank.
//
// With -priority-forms, a form submission (any method but GET and HEAD) from
// a visitor holding a valid admission pass also uses the lane, at its own
// rank. If the lane stays full the submission is refused with 503 instead
// of queued: the waiting room would swallow the form.
//
// The lane and the ranked line are used only while the room is busy (every
// page slot taken, or visitors waiting). Otherwise every request goes
// through the room as before. Bans apply at every rank: identify runs first.

const (
	priorityHeader    = "Concert-Priority"
	priorityCookie    = "concert_priority"
	priorityMinTTL    = time.Minute
	priorityMaxTTL    = 24 * time.Hour
	maxPriorityWait   = time.Minute
	rankedLineMax     = 100000 // ranked tickets tracked in room's line
	priorityLogValues = 50     // distinct bad header values logged

	// Grant cookie: pass id(16) | rank(1) | expiry unix seconds(8) | HMAC(16)
	grantRankOff = passIDLen
	grantExpOff  = grantRankOff + 1
	grantBodyLen = grantExpOff + 8
	grantMACLen  = 16
	grantRawLen  = grantBodyLen + grantMACLen
)

// ─── ranks ───────────────────────────────────────────────────────────────────

type priorityRank uint8

const (
	rankGuest priorityRank = iota
	rankMember
	rankProspect
	rankCustomer
	rankSubscriber
	rankCheckout
	rankStaff
	rankCount
)

var rankNames = [rankCount]string{"guest", "member", "prospect", "customer", "subscriber", "checkout", "staff"}

// rankDefaultTTL applies when the header carries no ttl.
var rankDefaultTTL = [rankCount]time.Duration{
	0, 8 * time.Hour, 30 * time.Minute, 8 * time.Hour, 8 * time.Hour, 30 * time.Minute, 8 * time.Hour,
}

func (r priorityRank) String() string {
	if r < rankCount {
		return rankNames[r]
	}
	return "none"
}

// rankLabel is the rank as views show it: empty for guests.
func rankLabel(r priorityRank) string {
	if r == rankGuest || r >= rankCount {
		return ""
	}
	return r.String()
}

func parseRank(s string) (priorityRank, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	for i, n := range rankNames {
		if n == s {
			return priorityRank(i), true
		}
	}
	return rankGuest, false
}

// parsePriorityHeader reads "checkout", "customer; ttl=600" or
// "staff; ttl=2h". ttl is seconds or a duration, clamped to 1m-24h.
func parsePriorityHeader(v string) (priorityRank, time.Duration, error) {
	parts := strings.Split(v, ";")
	rank, ok := parseRank(parts[0])
	if !ok {
		return rankGuest, 0, fmt.Errorf("unknown rank %q", strings.TrimSpace(parts[0]))
	}
	ttl := rankDefaultTTL[rank]
	for _, p := range parts[1:] {
		k, val, found := strings.Cut(strings.TrimSpace(p), "=")
		if !found || !strings.EqualFold(strings.TrimSpace(k), "ttl") {
			continue
		}
		val = strings.TrimSpace(val)
		if n, err := strconv.Atoi(val); err == nil {
			ttl = time.Duration(n) * time.Second
		} else if d, err := time.ParseDuration(val); err == nil {
			ttl = d
		} else {
			return rankGuest, 0, fmt.Errorf("bad ttl %q", val)
		}
	}
	if rank != rankGuest {
		ttl = min(max(ttl, priorityMinTTL), priorityMaxTTL)
	}
	return rank, ttl, nil
}

// ─── configuration ───────────────────────────────────────────────────────────

// normalizePriority validates the priority settings. A zero lane rank, as
// in configs built directly, means the default: customer.
func (c *config) normalizePriority() error {
	if c.priorityCap < 0 || c.priorityCap > math.MaxInt32 {
		return fmt.Errorf("invalid -priority-cap %d: must be 0 (derived) or between 1 and %d", c.priorityCap, math.MaxInt32)
	}
	if c.priorityWait < 0 || c.priorityWait > maxPriorityWait {
		return fmt.Errorf("invalid -priority-wait %s: must be between 0s and %s", c.priorityWait, maxPriorityWait)
	}
	if c.priorityLaneRank == 0 {
		c.priorityLaneRank = int(rankCustomer)
	}
	if c.priorityLaneRank < 1 || c.priorityLaneRank > int(rankCount) {
		return fmt.Errorf("invalid -priority-lane-rank %d: must be between 1 and %d (%d means no rank uses the lane)",
			c.priorityLaneRank, rankCount, rankCount)
	}
	return nil
}

// effectivePriorityCap is -priority-cap when set, otherwise a quarter of
// -cap, at least 1.
func (c config) effectivePriorityCap() int {
	if c.priorityCap > 0 {
		return c.priorityCap
	}
	return max(1, c.capacity/4)
}

func intBetween(lo, hi int) func(any) error {
	return func(v any) error {
		if n := v.(int); n < lo || n > hi {
			return fmt.Errorf("must be between %d and %d", lo, hi)
		}
		return nil
	}
}

// ─── grants ──────────────────────────────────────────────────────────────────

// priorityGrants signs, verifies and issues concert_priority cookies.
type priorityGrants struct {
	key      []byte
	admit    *admitter
	issued   atomic.Int64
	cleared  atomic.Int64
	rejected atomic.Int64
	logged   sync.Map
	nlogged  atomic.Int64
}

func newPriorityGrants(secret []byte, admit *admitter) *priorityGrants {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("concert/priority/grant-key"))
	return &priorityGrants{key: m.Sum(nil), admit: admit}
}

func (g *priorityGrants) mac(body []byte) []byte {
	m := hmac.New(sha256.New, g.key)
	m.Write(body)
	return m.Sum(nil)[:grantMACLen]
}

func (g *priorityGrants) mint(id passID, rank priorityRank, exp time.Time) string {
	var buf [grantRawLen]byte
	copy(buf[:passIDLen], id[:])
	buf[grantRankOff] = byte(rank)
	binary.BigEndian.PutUint64(buf[grantExpOff:grantBodyLen], uint64(exp.Unix()))
	copy(buf[grantBodyLen:], g.mac(buf[:grantBodyLen]))
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

// verify returns the rank in value when it is authentic, unexpired and bound
// to the admission pass id.
func (g *priorityGrants) verify(value string, id passID, now time.Time) (priorityRank, bool) {
	if base64.RawURLEncoding.DecodedLen(len(value)) != grantRawLen {
		return rankGuest, false
	}
	var buf [grantRawLen]byte
	if n, err := base64.RawURLEncoding.Decode(buf[:], []byte(value)); err != nil || n != grantRawLen {
		return rankGuest, false
	}
	if !hmac.Equal(buf[grantBodyLen:], g.mac(buf[:grantBodyLen])) {
		return rankGuest, false
	}
	var bound passID
	copy(bound[:], buf[:passIDLen])
	if bound != id {
		return rankGuest, false
	}
	rank := priorityRank(buf[grantRankOff])
	if rank >= rankCount || now.Unix() >= int64(binary.BigEndian.Uint64(buf[grantExpOff:grantBodyLen])) {
		return rankGuest, false
	}
	return rank, true
}

// rankOf is the rank r carries: a valid grant bound to a valid admission
// pass, or guest.
func (g *priorityGrants) rankOf(r *http.Request, now time.Time) priorityRank {
	ck, err := r.Cookie(priorityCookie)
	if err != nil || ck.Value == "" {
		return rankGuest
	}
	ac, err := r.Cookie(admitCookie)
	if err != nil {
		return rankGuest
	}
	id, _, status := g.admit.verify(ac.Value, now)
	if status != passValid {
		return rankGuest
	}
	rank, _ := g.verify(ck.Value, id, now)
	return rank
}

// valid reports whether r carries a valid admission pass.
func (a *admitter) valid(r *http.Request, now time.Time) bool {
	ck, err := r.Cookie(admitCookie)
	if err != nil {
		return false
	}
	_, _, status := a.verify(ck.Value, now)
	return status == passValid
}

type passIDKey struct{}

// withPassID records the admission pass a page response leaves the visitor
// holding, so the origin's grant can be bound to it. Set by gated.
func withPassID(ctx context.Context, id passID) context.Context {
	return context.WithValue(ctx, passIDKey{}, id)
}

func passIDFromContext(ctx context.Context) (passID, bool) {
	id, ok := ctx.Value(passIDKey{}).(passID)
	return id, ok
}

// modifyResponse is the proxy's ModifyResponse. It removes Concert-Priority
// from every response, and turns it into a grant on page responses.
func (g *priorityGrants) modifyResponse(resp *http.Response) error {
	vals := resp.Header.Values(priorityHeader)
	if len(vals) == 0 {
		return nil
	}
	resp.Header.Del(priorityHeader)
	if resp.Request == nil {
		return nil
	}
	id, ok := passIDFromContext(resp.Request.Context())
	if !ok {
		return nil // not a page response
	}
	v := vals[len(vals)-1]
	rank, ttl, err := parsePriorityHeader(v)
	if err != nil {
		g.rejected.Add(1)
		if g.nlogged.Load() < priorityLogValues {
			if _, seen := g.logged.LoadOrStore(v, true); !seen {
				g.nlogged.Add(1)
				log.Printf("priority: ignoring %s %q from the origin: %v", priorityHeader, v, err)
			}
		}
		return nil
	}

	o := g.admit.opts.Load()
	ck := &http.Cookie{
		Name: priorityCookie, Path: o.path, Domain: o.domain,
		Secure: o.secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
	if rank == rankGuest {
		ck.MaxAge = -1
		g.cleared.Add(1)
	} else {
		ck.Value = g.mint(id, rank, time.Now().Add(ttl))
		ck.MaxAge = int(ttl / time.Second)
		g.issued.Add(1)
	}
	resp.Header.Add("Set-Cookie", ck.String())
	return nil
}

// ─── the ranked line ─────────────────────────────────────────────────────────

// rankedLine remembers the rank of ranked visitors waiting in room's line,
// and keeps them ahead of lower ranks.
type rankedLine struct {
	mu sync.Mutex
	m  map[string]priorityRank // room ticket -> rank
}

func (l *rankedLine) rankOf(token string) priorityRank {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.m[token]
}

// place moves token up room's line behind every waiting visitor of equal or
// higher rank. It reports whether the ticket moved.
func (l *rankedLine) place(wr *room.WaitingRoom, token string, rank priorityRank) bool {
	l.mu.Lock()
	if _, ok := l.m[token]; !ok && len(l.m) >= rankedLineMax {
		l.mu.Unlock()
		return false
	}
	l.m[token] = rank
	ahead := make([]string, 0, len(l.m))
	for t, r := range l.m {
		if t != token && r >= rank {
			ahead = append(ahead, t)
		}
	}
	l.mu.Unlock()

	me, ok := wr.Ticket(token)
	if !ok || me.Position <= 0 {
		return false
	}
	var target int64 = 1
	for _, t := range ahead {
		if ti, ok := wr.Ticket(t); ok && ti.Position > 0 {
			target++
		}
	}
	if target >= me.Position {
		return false
	}
	return promoteAt(wr.AdminPromote, token, target) == nil
}

// prune forgets tickets that are no longer waiting.
func (l *rankedLine) prune(wr *room.WaitingRoom) {
	l.mu.Lock()
	tokens := make([]string, 0, len(l.m))
	for t := range l.m {
		tokens = append(tokens, t)
	}
	l.mu.Unlock()

	var gone []string
	for _, t := range tokens {
		if ti, ok := wr.Ticket(t); !ok || ti.Position <= 0 {
			gone = append(gone, t)
		}
	}
	l.mu.Lock()
	for _, t := range gone {
		delete(l.m, t)
	}
	l.mu.Unlock()
}

// promoteAt calls room's AdminPromote with pos as the target position,
// whatever integer type room declares for it.
func promoteAt[P ~int | ~int32 | ~int64](promote func(string, P) error, token string, pos int64) error {
	return promote(token, P(pos))
}

// ─── the priority lane ───────────────────────────────────────────────────────

// rankedSem is a semaphore whose waiters are served highest rank first,
// first come first served within a rank. A freed slot passes straight to
// the next waiter.
type rankedSem struct {
	mu      sync.Mutex
	cap     int
	used    int
	seq     uint64
	waiters []*semWaiter
}

type semWaiter struct {
	rank    priorityRank
	seq     uint64
	ready   chan struct{}
	granted bool
}

func newRankedSem(n int) *rankedSem { return &rankedSem{cap: n} }

func (s *rankedSem) Cap() int { return s.cap }

func (s *rankedSem) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.used
}

func (s *rankedSem) Waiting() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.waiters)
}

// acquire takes a slot, waiting up to wait. A true result must be released.
func (s *rankedSem) acquire(ctx context.Context, rank priorityRank, wait time.Duration) bool {
	s.mu.Lock()
	if s.used < s.cap && len(s.waiters) == 0 {
		s.used++
		s.mu.Unlock()
		return true
	}
	if wait <= 0 {
		s.mu.Unlock()
		return false
	}
	w := &semWaiter{rank: rank, seq: s.seq, ready: make(chan struct{})}
	s.seq++
	s.waiters = append(s.waiters, w)
	s.mu.Unlock()

	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-w.ready:
		return true
	case <-t.C:
	case <-ctx.Done():
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if w.granted {
		return true
	}
	for i, x := range s.waiters {
		if x == w {
			s.waiters = append(s.waiters[:i], s.waiters[i+1:]...)
			break
		}
	}
	return false
}

func (s *rankedSem) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.waiters) > 0 {
		best := 0
		for i := 1; i < len(s.waiters); i++ {
			w, b := s.waiters[i], s.waiters[best]
			if w.rank > b.rank || (w.rank == b.rank && w.seq < b.seq) {
				best = i
			}
		}
		w := s.waiters[best]
		s.waiters = append(s.waiters[:best], s.waiters[best+1:]...)
		w.granted = true
		close(w.ready)
		return
	}
	if s.used > 0 {
		s.used--
	}
}

// ─── state and the gate ──────────────────────────────────────────────────────

// priorityState is priority's long-lived state; the lane itself belongs to
// the generation (see reload.go) because its size is a setting.
type priorityState struct {
	grants       *priorityGrants
	line         *rankedLine
	requests     [rankCount]atomic.Int64 // gated page requests, by rank
	laneServed   atomic.Int64
	laneFull     atomic.Int64 // waited for the lane in vain
	placed       atomic.Int64 // tickets moved up the line by rank
	forms        atomic.Int64 // form submissions that used the lane
	formsRefused atomic.Int64
}

func newPriorityState(secret []byte, admit *admitter) *priorityState {
	return &priorityState{
		grants: newPriorityGrants(secret, admit),
		line:   &rankedLine{m: map[string]priorityRank{}},
	}
}

// janitor forgets ranked tickets that are no longer waiting.
func (ps *priorityState) janitor(wr *room.WaitingRoom, stop <-chan struct{}) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			ps.line.prune(wr)
		}
	}
}

// roomBusy reports whether a new page request would have to wait: every
// slot is taken, or visitors are already waiting.
func roomBusy(wr *room.WaitingRoom) bool {
	return int64(wr.Len()) >= int64(wr.Cap()) || wr.LiveQueueDepth() > 0
}

// priorityGate runs ahead of room's middleware on gated requests. It sends
// lane-ranked visitors and admitted form submissions through the priority
// lane while the room is busy, and moves ranked visitors who end up
// waiting ahead of lower ranks.
func (g *generation) priorityGate(c *gin.Context) {
	if c.FullPath() != "" {
		return // registered routes: status, ops, bypass, assets, streams
	}
	ps, cfg, r := g.a.prio, g.cfg, c.Request
	now := time.Now()
	rank := ps.grants.rankOf(r, now)
	ps.requests[rank].Add(1)

	laneRank := priorityRank(cfg.priorityLaneRank)
	if roomBusy(g.a.room) {
		form := cfg.priorityForms && r.Method != http.MethodGet && r.Method != http.MethodHead &&
			g.a.admit.valid(r, now)
		if rank >= laneRank || form {
			if g.lane.acquire(r.Context(), rank, cfg.priorityWait) {
				defer g.lane.release()
				ps.laneServed.Add(1)
				if form && rank < laneRank {
					ps.forms.Add(1)
				}
				g.gated(c)
				c.Abort()
				return
			}
			ps.laneFull.Add(1)
			if form && rank < laneRank {
				ps.formsRefused.Add(1)
				g.refuseForm(c)
				return
			}
		}
	}

	var token string
	if ck, err := r.Cookie("room_ticket"); err == nil {
		token = ck.Value
	}
	c.Next()
	if rank == rankGuest || c.GetBool(ctxAdmitted) {
		return
	}
	if t := issuedTicket(c.Writer.Header()); t != "" {
		token = t
	}
	if token != "" && ps.line.place(g.a.room, token, rank) {
		ps.placed.Add(1)
	}
}

// issuedTicket is the room_ticket a response sets, if any.
func issuedTicket(h http.Header) string {
	for _, v := range h.Values("Set-Cookie") {
		if !strings.HasPrefix(v, "room_ticket=") {
			continue
		}
		val := strings.TrimPrefix(v, "room_ticket=")
		if i := strings.IndexByte(val, ';'); i >= 0 {
			val = val[:i]
		}
		if val != "" {
			return val
		}
	}
	return ""
}

const formBusyPage = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Not sent: the site is busy</title></head>
<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem;text-align:center">
<h1>Your form was not sent</h1>
<p>The site is very busy right now. It was not processed, so it is safe to go back and submit it again in a few seconds.</p>
</body></html>`

// refuseForm answers a form submission the lane could not take. Queuing it
// would lose the form, so the visitor is told to resubmit instead.
func (g *generation) refuseForm(c *gin.Context) {
	secs := strconv.Itoa(g.cfg.retryAfter)
	c.Header("Cache-Control", "no-store")
	c.Header("Retry-After", secs)
	if wantsHTML(c.Request) {
		c.Data(http.StatusServiceUnavailable, "text/html; charset=utf-8", []byte(formBusyPage))
	} else {
		c.Data(http.StatusServiceUnavailable, "application/json; charset=utf-8",
			[]byte(`{"error":"busy","submitted":false,"retry_after_seconds":`+secs+`}`))
	}
	c.Abort()
}

// priorityView is the portal overview's priority section.
func (g *generation) priorityView() gin.H {
	ps := g.a.prio
	lane := "off"
	if lr := priorityRank(g.cfg.priorityLaneRank); lr < rankCount {
		lane = lr.String() + " and above"
	}
	h := gin.H{
		"priority_lane_cap":              g.lane.Cap(),
		"priority_lane_in_flight":        g.lane.Len(),
		"priority_lane_waiting":          g.lane.Waiting(),
		"priority_lane_ranks":            lane,
		"priority_lane_served_total":     ps.laneServed.Load(),
		"priority_lane_full_total":       ps.laneFull.Load(),
		"priority_placed_total":          ps.placed.Load(),
		"priority_forms_total":           ps.forms.Load(),
		"priority_forms_refused_total":   ps.formsRefused.Load(),
		"priority_grants_total":          ps.grants.issued.Load(),
		"priority_grants_cleared_total":  ps.grants.cleared.Load(),
		"priority_grants_rejected_total": ps.grants.rejected.Load(),
	}
	for r := rankGuest; r < rankCount; r++ {
		h["priority_requests_"+r.String()] = ps.requests[r].Load()
	}
	return h
}
