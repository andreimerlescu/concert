package server

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/room"
	"github.com/gin-gonic/gin"
)

// Agent places: keyed tickets for software that waits in line.
//
// x402 exists so that software can pay, and software waiting for a drop
// calls with a Concert-Session header and keeps no cookie jar. On the cookie
// flow every retry would take a new ticket at the back of the line and a
// churn strike. With -agent-queue (and wallet access configured), a request
// carrying a valid Concert-Session header is identified to room by its
// session instead: room keys the ticket by "s:" + the session ID, sets no
// cookies, and the same session finds the same place on every retry. The
// session ID is stable across renewals, so renewing keeps the place.
//
// Nothing here gives an agent an advantage over a person. Agents queue
// first come, first served with everyone else; bans drop their places like
// anyone's, because room records the address concert resolved on keyed
// tickets too; and sessions are free to create, so -agent-places caps the
// keyed tickets one client address (IPv6: its /64) may hold. A paid session
// still goes through the priority lane, ahead of all of this, exactly as a
// paid browser does. Browsers carry the concert_fastlane cookie, not the
// header, and stay on the cookie flow.
//
// A queued agent is answered with Concert's API contract (429 and
// Retry-After: -retry-after), not room's keyed default (503 and
// Retry-After: 3). The body names its place, an absolute status_url the
// agent can hand to a person, and, when payment offers are configured, the
// fast-lane offer in a form software can act on. Paying stays an explicit
// act of the payer, subject to the policy screening every payment gets.
//
// The line is per process, like the rest of the queue.

const (
	// agentKeyPrefix marks a room key that names a fast-lane session.
	agentKeyPrefix = "s:"
	// agentTrackMax bounds the key → address table. room's store is
	// bounded by -max-queue; this bounds Concert's side when it is 0.
	agentTrackMax = 100000
	// agentPruneEvery limits full reconciliation passes over room's line
	// when the table is full.
	agentPruneEvery = time.Second
	// agentWaitBodyMax bounds how much of room's own wait response is kept
	// as a fallback (room's body is under 200 bytes).
	agentWaitBodyMax = 4 << 10
	agentWaitHint    = "send the same Concert-Session header and retry to hold your position"

	defaultAgentPlaces = 4
	maxAgentPlaces     = 1000
)

// agentPlaces records which client address took each keyed place, so the
// per-address cap can be enforced before room issues a ticket.
//
// room never reports which key a reaped ticket had (EventEvict carries no
// key), so the table may hold keys whose tickets are gone. They are
// reconciled lazily against room's line (TicketByKey) when an address
// reaches its cap, and all at once (Queue) when the table is full. Keys are
// forgotten eagerly when their ticket is admitted, removed in the portal or
// dropped by a ban. Stale entries are reconciled before they can refuse
// anyone, so the cap counts only places room still holds.
//
// mu guards every field. It is never held while calling into room.
type agentPlaces struct {
	mu        sync.Mutex
	byKey     map[string]netip.Addr // room key → abuse key of the address
	byAddr    map[netip.Addr]map[string]struct{}
	lastPrune time.Time
	refused   atomic.Int64 // arrivals refused by the per-address cap
}

func newAgentPlaces() *agentPlaces {
	return &agentPlaces{byKey: map[string]netip.Addr{}, byAddr: map[netip.Addr]map[string]struct{}{}}
}

// addLocked records key for addr. Caller holds p.mu.
func (p *agentPlaces) addLocked(key string, addr netip.Addr) {
	p.byKey[key] = addr
	set := p.byAddr[addr]
	if set == nil {
		set = map[string]struct{}{}
		p.byAddr[addr] = set
	}
	set[key] = struct{}{}
}

// forgetLocked drops key. Caller holds p.mu.
func (p *agentPlaces) forgetLocked(key string) {
	addr, ok := p.byKey[key]
	if !ok {
		return
	}
	delete(p.byKey, key)
	if set := p.byAddr[addr]; set != nil {
		delete(set, key)
		if len(set) == 0 {
			delete(p.byAddr, addr)
		}
	}
}

// forget drops key, whose ticket left the line.
func (p *agentPlaces) forget(key string) {
	p.mu.Lock()
	p.forgetLocked(key)
	p.mu.Unlock()
}

// count is how many places addr holds, as far as the table knows.
func (p *agentPlaces) count(addr netip.Addr) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byAddr[addr])
}

// held is how many keyed places the table tracks.
func (p *agentPlaces) held() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byKey)
}

// reserve records that addr is taking key's place, before room issues the
// ticket, so concurrent arrivals from one address cannot exceed limit.
// A key already in the table is always allowed: it is the same place.
// fresh reports that this call added key; ok is false when addr already
// holds limit places (after reconciling them with room's line).
func (p *agentPlaces) reserve(wr *room.WaitingRoom, key string, addr netip.Addr, limit int, now time.Time) (fresh, ok bool) {
	p.mu.Lock()
	if _, known := p.byKey[key]; known {
		p.mu.Unlock()
		return false, true
	}
	if len(p.byAddr[addr]) < limit && len(p.byKey) < agentTrackMax {
		p.addLocked(key, addr)
		p.mu.Unlock()
		return true, true
	}
	mine := make([]string, 0, len(p.byAddr[addr]))
	for k := range p.byAddr[addr] {
		mine = append(mine, k)
	}
	pruneAll := len(p.byKey) >= agentTrackMax && now.Sub(p.lastPrune) >= agentPruneEvery
	if pruneAll {
		p.lastPrune = now
	}
	p.mu.Unlock()

	// Outside the lock: room v1.7.0 executes TicketByKey in O(log N) under RLock,
	// and keeping lookups outside p.mu avoids lock nesting. A key that already
	// has a place (its entry lost to a concurrent admission of the same session)
	// is never refused for it.
	_, self := wr.TicketByKey(key)
	var gone []string
	for _, k := range mine {
		if _, live := wr.TicketByKey(k); !live {
			gone = append(gone, k)
		}
	}
	var live map[string]struct{}
	if pruneAll {
		live = liveKeys(wr)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	for _, k := range gone {
		p.forgetLocked(k)
	}
	if live != nil {
		for k := range p.byKey {
			if _, ok := live[k]; !ok {
				p.forgetLocked(k)
			}
		}
	}
	if _, known := p.byKey[key]; known {
		return false, true
	}
	if self && len(p.byKey) < agentTrackMax {
		p.addLocked(key, addr)
		return false, true
	}
	if len(p.byAddr[addr]) >= limit || len(p.byKey) >= agentTrackMax {
		return false, false
	}
	p.addLocked(key, addr)
	return true, true
}

// liveKeys is the set of agent keys with a ticket in room's line.
func liveKeys(wr *room.WaitingRoom) map[string]struct{} {
	live := map[string]struct{}{}
	for _, t := range wr.Queue(math.MaxInt32) {
		if strings.HasPrefix(t.Key, agentKeyPrefix) {
			live[t.Key] = struct{}{}
		}
	}
	return live
}

// seed records the keyed places in room's line, after a restored queue.
func (p *agentPlaces) seed(wr *room.WaitingRoom) int {
	line := wr.Queue(math.MaxInt32)
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, t := range line {
		if !strings.HasPrefix(t.Key, agentKeyPrefix) || len(p.byKey) >= agentTrackMax {
			continue
		}
		ip, err := netip.ParseAddr(t.ClientKey)
		if err != nil {
			continue
		}
		if addr, ok := abuseKey(ip); ok {
			p.addLocked(t.Key, addr)
			n++
		}
	}
	return n
}

// agentKeyFromContext is room's TicketKeyFunc. agentGate has already read
// the Concert-Session header and checked its HMAC, once, and left the key
// in the context only when -agent-queue is on; every other request,
// browsers included, uses the cookie flow.
func agentKeyFromContext(c *gin.Context) (string, bool) {
	key := c.GetString(ctxAgentKey)
	return key, key != ""
}

// agentSessionLabel is what the portal shows for a keyed ticket: the first
// 8 characters of its session ID. It names the session without revealing
// its token.
func agentSessionLabel(key string) string {
	id, ok := strings.CutPrefix(key, agentKeyPrefix)
	if !ok {
		return ""
	}
	return id[:min(8, len(id))]
}

// agentGate runs after the priority gate, and before room, on gated
// requests. A request with a valid Concert-Session header takes, or finds,
// its keyed place; an address over -agent-places is refused with 429
// before room issues anything.
func (g *generation) agentGate(c *gin.Context) {
	if c.FullPath() != "" || !g.cfg.agentQueue || !g.a.fastlaneEnabled() {
		return
	}
	sid, ok := g.a.fastlaneSessionID(c.Request)
	if !ok {
		return
	}
	addr, ok := abuseKey(clientIPFrom(c))
	if !ok {
		return
	}
	key := agentKeyPrefix + sid
	places := g.a.agents
	fresh, ok := places.reserve(g.a.room, key, addr, g.cfg.agentPlaces, time.Now())
	if !ok {
		places.refused.Add(1)
		g.strike(c, strikeAgentPlaces)
		g.refuseAgentPlace(c)
		return
	}

	c.Set(ctxAgentKey, key)
	w := &agentWaitWriter{ResponseWriter: c.Writer, c: c, retryAfter: g.cfg.retryAfter}
	c.Writer = w
	c.Next()
	c.Writer = w.ResponseWriter
	if w.mode == agentHeld {
		g.writeAgentWait(c, key, w.roomBody.Bytes())
	}
	switch {
	case c.GetBool(ctxAdmitted):
		// room claimed the ticket (or there was none to take).
		places.forget(key)
	case w.mode == agentHeld:
		// The place exists.
	case fresh:
		// Refused by the breaker, or an error: no place was taken.
		places.forget(key)
	}
}

// isKeyedWait reports whether room answered a keyed request with its JSON
// wait response: 503 with a JSON body. room's queue-depth breaker also
// answers 503, but with no body and no Content-Type.
func isKeyedWait(status int, h http.Header) bool {
	return status == http.StatusServiceUnavailable &&
		strings.HasPrefix(h.Get("Content-Type"), "application/json")
}

// agentWaitWriter sits between room and the client on a keyed request. It
// decides once, at the first header or body write, whose response this is:
//
//   - the proxy's (the request was admitted): passed through untouched,
//     including streaming, flushing and hijacking;
//   - room's keyed wait response (503 with a JSON body): held back, and
//     replaced by writeAgentWait once room returns;
//   - room's queue-depth breaker (503, no body, no Content-Type): replaced
//     at once by the JSON body cookie API clients get;
//   - anything else room says: passed through.
//
// It is owned by one request's goroutine.
type agentWaitWriter struct {
	gin.ResponseWriter
	c          *gin.Context
	retryAfter int
	decided    bool
	mode       agentWriteMode
	roomBody   bytes.Buffer // room's held wait body, kept as a fallback
}

type agentWriteMode uint8

const (
	agentPassThrough agentWriteMode = iota
	agentHeld                       // room's wait response; see writeAgentWait
	agentReplaced                   // already answered; room's body is dropped
)

func (w *agentWaitWriter) decide(code int) {
	if w.decided {
		return
	}
	w.decided = true
	if w.c.GetBool(ctxAdmitted) {
		return
	}
	h := w.ResponseWriter.Header()
	switch {
	case isKeyedWait(code, h):
		w.mode = agentHeld
	case code == http.StatusServiceUnavailable:
		w.mode = agentReplaced
		h.Del("Content-Length")
		h.Set("Content-Type", "application/json; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		h.Set("Retry-After", strconv.Itoa(w.retryAfter))
		w.ResponseWriter.WriteHeader(code)
		w.ResponseWriter.WriteHeaderNow()
		_, _ = w.ResponseWriter.Write(mustJSON(gin.H{ // a failed write means the client went away
			"queued":              false,
			"error":               "waiting room is full",
			"retry_after_seconds": w.retryAfter,
		}))
	}
}

func (w *agentWaitWriter) WriteHeader(code int) {
	w.decide(code)
	if w.mode == agentPassThrough {
		w.ResponseWriter.WriteHeader(code)
	}
}

func (w *agentWaitWriter) WriteHeaderNow() {
	w.decide(w.ResponseWriter.Status())
	if w.mode == agentPassThrough {
		w.ResponseWriter.WriteHeaderNow()
	}
}

func (w *agentWaitWriter) Write(b []byte) (int, error) {
	w.decide(w.ResponseWriter.Status())
	switch w.mode {
	case agentHeld:
		if left := agentWaitBodyMax - w.roomBody.Len(); left > 0 {
			w.roomBody.Write(b[:min(len(b), left)])
		}
		return len(b), nil
	case agentReplaced:
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func (w *agentWaitWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func (w *agentWaitWriter) Flush() {
	w.decide(w.ResponseWriter.Status())
	if w.mode == agentPassThrough {
		w.ResponseWriter.Flush()
	}
}

// writeAgentWait answers a queued agent: Concert's 429 contract, its place
// from room (TicketInfo.Place, the place GET status_url shows), and the
// fast-lane offer when there is one. If the ticket left the line in the
// moment since room answered, room's own body supplies the place.
func (g *generation) writeAgentWait(c *gin.Context, key string, roomBody []byte) {
	wr := g.a.room
	var position int64
	var statusURL string
	if ti, ok := wr.TicketByKey(key); ok {
		position, statusURL = ti.Place, wr.StatusBaseURL()+ti.ID
	} else {
		var fallback struct {
			Position  int64  `json:"position"`
			StatusURL string `json:"status_url"`
		}
		_ = json.Unmarshal(roomBody, &fallback) // zero values if room's body is unreadable
		position, statusURL = fallback.Position, fallback.StatusURL
	}
	secs := g.cfg.retryAfter
	body := gin.H{
		"queued":              true,
		"position":            position,
		"queue_depth":         wr.LiveQueueDepth(),
		"status_url":          statusURL,
		"retry_after_seconds": secs,
		"hint":                agentWaitHint,
	}
	h := c.Writer.Header()
	if offer := g.a.agentOffer; offer != nil {
		body["fast_lane"] = offer.body
		h.Set("Link", "<"+offer.paymentURL+`>; rel="payment"`)
	}
	h.Del("Content-Length")
	h.Set("Retry-After", strconv.Itoa(secs))
	h.Set("Cache-Control", "no-store")
	c.Data(http.StatusTooManyRequests, "application/json; charset=utf-8", mustJSON(body))
}

// agentOffer is the fast-lane offer in a queued agent's response, built
// once from the fast lane's public configuration (see enterprise_hooks.go).
type agentOffer struct {
	paymentURL string
	body       gin.H
}

// refuseAgentPlace answers an arrival whose address already holds
// -agent-places keyed places.
func (g *generation) refuseAgentPlace(c *gin.Context) {
	secs := g.cfg.retryAfter
	c.Header("Retry-After", strconv.Itoa(secs))
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusTooManyRequests, gin.H{
		"queued":              false,
		"error":               "agent_places_exceeded",
		"agent_places":        g.cfg.agentPlaces,
		"retry_after_seconds": secs,
		"hint":                "this address already holds its places in line; retry with a Concert-Session that is already waiting",
	})
	c.Abort()
}

// agentView is the portal overview's agent section.
func (g *generation) agentView() gin.H {
	return gin.H{
		"agent_queue":                g.cfg.agentQueue && g.a.fastlaneEnabled(),
		"agent_places_per_address":   g.cfg.agentPlaces,
		"agent_places_held":          g.a.agents.held(),
		"agent_places_refused_total": g.a.agents.refused.Load(),
	}
}
