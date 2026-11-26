package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/sema"
	"github.com/gin-gonic/gin"
)

type passID [passIDLen]byte

type passStatus int

const (
	passMissing passStatus = iota // no cookie, or an empty one
	passValid                     // authentic and unexpired
	passExpired                   // authentic but past its expiry
	passStale                     // signed under a different key (restart, rotation)
	passForged                    // malformed, or bad signature under the current key
)

func newPassID() (passID, error) {
	var id passID
	_, err := rand.Read(id[:])
	return id, err
}

// admitter issues and verifies the signed concert_admit cookie. Verification
// is stateless, so any instance sharing CONCERT_ADMIT_SECRET accepts a pass.
// Setting CONCERT_ADMIT_SECRET_PREV enables zero-downtime key rotation: passes
// signed with the previous secret remain valid and are seamlessly re-signed
// with the current secret on the visitor's next request.
type admitter struct {
	secret     []byte
	kid        [passKIDLen]byte
	prevSecret []byte
	prevKID    [passKIDLen]byte
	hasPrev    bool
	opts       atomic.Pointer[admitOpts]
}

type admitOpts struct {
	ttl    time.Duration
	path   string
	domain string
	secure bool
}

func derivePassKID(secret []byte) [passKIDLen]byte {
	var kid [passKIDLen]byte
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("concert/admit/key-id"))
	copy(kid[:], m.Sum(nil))
	return kid
}

func newAdmitter(secret []byte, ttl time.Duration, path, domain string, secure bool) *admitter {
	a := &admitter{
		secret: secret,
		kid:    derivePassKID(secret),
	}
	a.configure(ttl, path, domain, secure)
	return a
}

// setPrevSecret configures a previous signing secret for zero-downtime key rotation.
func (a *admitter) setPrevSecret(prev []byte) {
	if len(prev) == 0 {
		return
	}
	a.prevSecret = append([]byte(nil), prev...)
	a.prevKID = derivePassKID(prev)
	a.hasPrev = true
}

// configure sets the lifetime and cookie attributes of passes issued from now on.
func (a *admitter) configure(ttl time.Duration, path, domain string, secure bool) {
	a.opts.Store(&admitOpts{ttl: ttl, path: path, domain: domain, secure: secure})
}

func (a *admitter) mint(id passID, now time.Time) string {
	o := a.opts.Load()
	var buf [passRawLen]byte
	copy(buf[:passIDLen], id[:])
	binary.BigEndian.PutUint64(buf[passExpOff:passKIDOff], uint64(now.Add(o.ttl).Unix()))
	copy(buf[passKIDOff:passBodyLen], a.kid[:])
	mac := hmac.New(sha256.New, a.secret)
	mac.Write(buf[:passBodyLen])
	copy(buf[passBodyLen:], mac.Sum(nil)[:passMACLen])
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

func (a *admitter) verifyWithRotation(value string, now time.Time) (passID, time.Time, passStatus, bool) {
	var id passID
	if value == "" {
		return id, time.Time{}, passMissing, false
	}
	if base64.RawURLEncoding.DecodedLen(len(value)) != passRawLen {
		return id, time.Time{}, passForged, false
	}
	var buf [passRawLen]byte
	n, err := base64.RawURLEncoding.Decode(buf[:], []byte(value))
	if err != nil || n != passRawLen {
		return id, time.Time{}, passForged, false
	}

	var key []byte
	rotated := false
	switch {
	case bytes.Equal(buf[passKIDOff:passBodyLen], a.kid[:]):
		key = a.secret
	case a.hasPrev && bytes.Equal(buf[passKIDOff:passBodyLen], a.prevKID[:]):
		key = a.prevSecret
		rotated = true
	default:
		return id, time.Time{}, passStale, false
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(buf[:passBodyLen])
	if !hmac.Equal(buf[passBodyLen:], mac.Sum(nil)[:passMACLen]) {
		return id, time.Time{}, passForged, false
	}
	exp := time.Unix(int64(binary.BigEndian.Uint64(buf[passExpOff:passKIDOff])), 0)
	if !now.Before(exp) {
		return id, time.Time{}, passExpired, false
	}
	copy(id[:], buf[:passIDLen])
	return id, exp, passValid, rotated
}

func (a *admitter) verify(value string, now time.Time) (passID, time.Time, passStatus) {
	id, exp, st, _ := a.verifyWithRotation(value, now)
	return id, exp, st
}

// set mints a signed concert_admit cookie for id at time now with Max-Age
// aligned to the current server-side admitTTL.
//
// # Parameters
//
//   - w: Destination HTTP response writer; must be non-nil.
//   - id: Admission pass identifier to encode.
//   - now: Current timestamp used to compute the token expiry.
//
// # Example
//
//	a.set(w, id, time.Now())
//
// # Used By
//
// Called by admitter.refresh and admitter.check in internal/server/pass.go.
func (a *admitter) set(w http.ResponseWriter, id passID, now time.Time) {
	o := a.opts.Load()
	maxAge := max(int(o.ttl/time.Second), 1)
	http.SetCookie(w, &http.Cookie{
		Name:     admitCookie,
		Value:    a.mint(id, now),
		Path:     o.path,
		Domain:   o.domain,
		MaxAge:   maxAge,
		Secure:   o.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// clear emits an expiring Set-Cookie header (`concert_admit=; Max-Age=0`) so
// clients receiving a waiting-room response discard any expired, stale, forged,
// or re-queued concert_admit cookie alongside room_ticket.
//
// # Parameters
//
//   - w: Destination HTTP response writer; nil is ignored.
//
// # Example
//
//	a.clear(w)
//
// # Used By
//
// Called by applyWaitingRoomHeaders in internal/server/api.go and
// writeAgentWait in internal/server/agent.go.
func (a *admitter) clear(w http.ResponseWriter) {
	if a == nil || w == nil {
		return
	}
	o := a.opts.Load()
	// Go's http.Cookie.String serializes MaxAge < 0 as "Max-Age=0" (whereas
	// MaxAge == 0 omits the Max-Age attribute completely).
	http.SetCookie(w, &http.Cookie{
		Name:     admitCookie,
		Value:    "",
		Path:     o.path,
		Domain:   o.domain,
		MaxAge:   -1,
		Secure:   o.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// refresh runs on every admitted page request. A valid pass is re-signed only
// past half its lifetime, so most responses carry no Set-Cookie and stay
// cacheable. Anything else is replaced with a new pass. It returns the ID of
// the pass the visitor holds after this response (zero if a new one could
// not be made) and the incoming status, so the caller can strike forgeries.
func (a *admitter) refresh(w http.ResponseWriter, r *http.Request, now time.Time) (passID, passStatus) {
	status := passMissing
	if ck, err := r.Cookie(admitCookie); err == nil {
		var id passID
		var exp time.Time
		var rotated bool
		id, exp, status, rotated = a.verifyWithRotation(ck.Value, now)
		if status == passValid {
			if rotated || exp.Sub(now) <= a.opts.Load().ttl/2 {
				a.set(w, id, now)
			}
			return id, status
		}
	}
	id, err := newPassID()
	if err != nil {
		return passID{}, status
	}
	a.set(w, id, now)
	return id, status
}

// check runs on every private asset and stream request. It also slides the
// pass past half-life (or re-signs immediately after secret rotation), so
// pages that lazy-load assets without navigating stay admitted.
func (a *admitter) check(w http.ResponseWriter, r *http.Request, now time.Time) (passID, passStatus) {
	ck, err := r.Cookie(admitCookie)
	if err != nil {
		return passID{}, passMissing
	}
	id, exp, status, rotated := a.verifyWithRotation(ck.Value, now)
	if status == passValid && (rotated || exp.Sub(now) <= a.opts.Load().ttl/2) {
		a.set(w, id, now)
	}
	return id, status
}

// ─── asset tier ──────────────────────────────────────────────────────────────

// userStore holds one pair of semaphores per admission pass. Entries exist
// only for authentic passes, so the map is bounded by admitted users within
// the pass lifetime. A store is replaced when the per-user caps or the pass
// lifetime change; its janitor stops when it is closed.
type userStore struct {
	shards   [userShards]userShard
	h1Cap    int
	h2Cap    int
	count    atomic.Int64
	stop     chan struct{}
	stopOnce sync.Once
}

type userShard struct {
	mu sync.Mutex
	m  map[passID]*userSlots
}

// userSlots keeps separate pools per protocol family (h1/h2 assets) plus a
// bounded per-pass concurrent page pool for active-session continuity.
type userSlots struct {
	lastSeen int64 // unix nanos, guarded by the shard mutex
	h1       sema.Semaphore
	h2       sema.Semaphore
	page     sema.Semaphore
}

func newUserStore(h1Cap, h2Cap int) *userStore {
	s := &userStore{h1Cap: h1Cap, h2Cap: h2Cap, stop: make(chan struct{})}
	for i := range s.shards {
		s.shards[i].m = make(map[passID]*userSlots)
	}
	return s
}

// slot returns the user's semaphore for the protocol family, creating the
// entry and semaphore on first use. lastSeen is updated under the lock so the
// janitor can never evict an entry between lookup and acquire.
func (s *userStore) slot(id passID, multiplexed bool, now int64) sema.Semaphore {
	sh := &s.shards[id[0]&(userShards-1)]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	u, ok := sh.m[id]
	if !ok {
		u = &userSlots{}
		sh.m[id] = u
		s.count.Add(1)
	}
	u.lastSeen = now

	if multiplexed {
		if u.h2 == nil {
			u.h2 = sema.Must(s.h2Cap)
		}
		return u.h2
	}
	if u.h1 == nil {
		u.h1 = sema.Must(s.h1Cap)
	}
	return u.h1
}

// pageSlot returns the bounded concurrent page semaphore (cap
// defaultAdmitPageCap) for admission pass id, creating the shard entry on
// first use and updating lastSeen under the shard mutex so the janitor cannot
// evict the entry between lookup and acquire.
//
// # Parameters
//
//   - id: Verified admission pass identifier.
//   - now: Current Unix timestamp in nanoseconds.
//
// # Returns
//
// A concurrency-safe sema.Semaphore bounded to defaultAdmitPageCap slots.
//
// # Example
//
//	sem := g.assets.users.pageSlot(id, time.Now().UnixNano())
//
// # Used By
//
// Called by generation.priorityGate in internal/server/priority.go.
func (s *userStore) pageSlot(id passID, now int64) sema.Semaphore {
	sh := &s.shards[id[0]&(userShards-1)]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	u, ok := sh.m[id]
	if !ok {
		u = &userSlots{}
		sh.m[id] = u
		s.count.Add(1)
	}
	u.lastSeen = now

	if u.page == nil {
		u.page = sema.Must(defaultAdmitPageCap)
	}
	return u.page
}

// sweep evicts entries idle since before cutoff with nothing in flight.
func (s *userStore) sweep(cutoff int64) int {
	evicted := 0
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for id, u := range sh.m {
			if u.lastSeen < cutoff && semIdle(u.h1) && semIdle(u.h2) && semIdle(u.page) {
				delete(sh.m, id)
				evicted++
			}
		}
		sh.mu.Unlock()
	}
	s.count.Add(int64(-evicted))
	return evicted
}

// startJanitor sweeps idle entries every interval until close.
func (s *userStore) startJanitor(every, idle time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case now := <-t.C:
				s.sweep(now.Add(-idle).UnixNano())
			}
		}
	}()
}

// close stops the janitor. Requests still holding one of the store's
// semaphores release it normally.
func (s *userStore) close() {
	s.stopOnce.Do(func() { close(s.stop) })
}

func semIdle(s sema.Semaphore) bool {
	return s == nil || s.Len() == 0
}

// assetGuard admits asset requests through two semaphores: the caller's
// per-pass pool first, so an abusive pass is rejected before it can take a
// global slot, then the global PrioritySemaphore (sema v1.3.0) that protects
// the host while giving admitted and priority-ranked visitors O(1) priority
// ahead of unauthenticated public assets under contention.
//
// This is the hot path: no logging, counters only.
type assetGuard struct {
	admit       *admitter
	prio        *priorityGrants
	laneRank    priorityRank
	users       *userStore
	global      sema.PrioritySemaphore
	userWait    time.Duration
	globalWait  time.Duration
	protoHeader string
	stats       *counters
	strike      func(*gin.Context, int)
}

// priorityForPass maps an already-verified admission pass and optional
// concert_priority cookie onto sema v1.3.0's O(1) priority tiers. When no
// concert_priority cookie is present (the common case), it returns
// PriorityNormal immediately with zero HMAC work.
func (g *assetGuard) priorityForPass(r *http.Request, id passID, now time.Time) sema.Priority {
	if g.prio == nil {
		return sema.PriorityNormal
	}
	ck, err := r.Cookie(priorityCookie)
	if err != nil || ck.Value == "" {
		return sema.PriorityNormal
	}
	rank, ok := g.prio.verify(ck.Value, id, now)
	if !ok {
		return sema.PriorityNormal
	}
	if rank >= rankCheckout {
		return sema.PriorityCritical
	}
	if g.laneRank > 0 && rank >= g.laneRank {
		return sema.PriorityHigh
	}
	return sema.PriorityNormal
}

// priorityForRequest classifies an arbitrary request (used by staticOffload):
// unauthenticated requests take PriorityLow, while visitors holding a valid
// admission pass take PriorityNormal or higher based on any priority grant.
func (g *assetGuard) priorityForRequest(r *http.Request, now time.Time) sema.Priority {
	if g.admit == nil {
		return sema.PriorityLow
	}
	ck, err := r.Cookie(admitCookie)
	if err != nil || ck.Value == "" {
		return sema.PriorityLow
	}
	id, _, status := g.admit.verify(ck.Value, now)
	if status != passValid {
		return sema.PriorityLow
	}
	return g.priorityForPass(r, id, now)
}

// private requires a valid admission pass.
func (g *assetGuard) private(c *gin.Context) {
	now := time.Now()
	id, status := g.admit.check(c.Writer, c.Request, now)
	if status != passValid {
		if status == passForged {
			g.strike(c, strikeForgedPass)
		}
		g.stats.assetDenied.Add(1)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	userSem := g.users.slot(id, isMultiplexed(c.Request, g.protoHeader), now.UnixNano())
	if !acquire(c.Request.Context(), userSem, g.userWait) {
		g.stats.assetUserThrottled.Add(1)
		g.strike(c, strikeUserThrottle)
		c.Header("Retry-After", "1")
		c.AbortWithStatus(http.StatusTooManyRequests)
		return
	}
	defer func() { _ = userSem.Release() }()

	g.serve(c, g.priorityForPass(c.Request, id, now))
}

// public skips the pass check and runs at PriorityLow on the global asset cap
// so unauthenticated asset floods never starve admitted visitors.
func (g *assetGuard) public(c *gin.Context) {
	g.serve(c, sema.PriorityLow)
}

func (g *assetGuard) serve(c *gin.Context, p sema.Priority) {
	if !acquirePriority(c.Request.Context(), g.global, p, g.globalWait) {
		g.stats.assetGlobalThrottled.Add(1)
		c.Header("Retry-After", "1")
		c.AbortWithStatus(http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = g.global.Release() }()

	g.stats.assetServed.Add(1)
	c.Next() // run the proxy while both slots are held
}

// acquire tries the zero-allocation fast path first and only builds a timeout
// context when it has to wait. The request context is honoured so a client
// that disconnects stops waiting.
func acquire(ctx context.Context, s sema.Semaphore, wait time.Duration) bool {
	if s.TryAcquire() {
		return true
	}
	if wait <= 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	return s.AcquireWith(ctx) == nil
}

// acquirePriority acquires a slot on s at priority p, taking the non-barging
// O(1) fast path before allocating a timeout context.
func acquirePriority(ctx context.Context, s sema.PrioritySemaphore, p sema.Priority, wait time.Duration) bool {
	if s.TryAcquireWithPriority(ctx, p) == nil {
		return true
	}
	if wait <= 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	return s.AcquireWithPriority(ctx, p) == nil
}

// isMultiplexed reports whether the client speaks HTTP/2 or HTTP/3. Behind a
// TLS terminator the connection to concert is always HTTP/1.1, so a trusted
// header naming the client's protocol takes precedence when configured. When
// concert terminates TLS itself (-tls-domains), the connection's protocol is
// the client's protocol and no header is needed.
func isMultiplexed(r *http.Request, header string) bool {
	if header != "" {
		v := r.Header.Get(header)
		switch {
		case strings.HasPrefix(v, "HTTP/1"):
			return false
		case strings.HasPrefix(v, "HTTP/2"), strings.HasPrefix(v, "HTTP/3"):
			return true
		}
	}
	return r.ProtoMajor >= 2
}
