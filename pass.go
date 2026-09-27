package main

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
// The key never changes while concert runs; the lifetime and cookie
// attributes can, through configure, and passes already issued stay valid
// because each carries its own expiry.
type admitter struct {
	secret []byte
	kid    [passKIDLen]byte
	opts   atomic.Pointer[admitOpts]
}

type admitOpts struct {
	ttl    time.Duration
	path   string
	domain string
	secure bool
}

func newAdmitter(secret []byte, ttl time.Duration, path, domain string, secure bool) *admitter {
	a := &admitter{secret: secret}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("concert/admit/key-id"))
	copy(a.kid[:], m.Sum(nil))
	a.configure(ttl, path, domain, secure)
	return a
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

func (a *admitter) verify(value string, now time.Time) (passID, time.Time, passStatus) {
	var id passID
	if value == "" {
		return id, time.Time{}, passMissing
	}
	if base64.RawURLEncoding.DecodedLen(len(value)) != passRawLen {
		return id, time.Time{}, passForged
	}
	var buf [passRawLen]byte
	n, err := base64.RawURLEncoding.Decode(buf[:], []byte(value))
	if err != nil || n != passRawLen {
		return id, time.Time{}, passForged
	}
	if !bytes.Equal(buf[passKIDOff:passBodyLen], a.kid[:]) {
		return id, time.Time{}, passStale
	}
	mac := hmac.New(sha256.New, a.secret)
	mac.Write(buf[:passBodyLen])
	if !hmac.Equal(buf[passBodyLen:], mac.Sum(nil)[:passMACLen]) {
		return id, time.Time{}, passForged
	}
	exp := time.Unix(int64(binary.BigEndian.Uint64(buf[passExpOff:passKIDOff])), 0)
	if !now.Before(exp) {
		return id, time.Time{}, passExpired
	}
	copy(id[:], buf[:passIDLen])
	return id, exp, passValid
}

func (a *admitter) set(w http.ResponseWriter, id passID, now time.Time) {
	o := a.opts.Load()
	http.SetCookie(w, &http.Cookie{
		Name:     admitCookie,
		Value:    a.mint(id, now),
		Path:     o.path,
		Domain:   o.domain,
		MaxAge:   int(o.ttl / time.Second),
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
		id, exp, status = a.verify(ck.Value, now)
		if status == passValid {
			if exp.Sub(now) <= a.opts.Load().ttl/2 {
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
// pass past half-life, so pages that lazy-load assets without navigating
// stay admitted.
func (a *admitter) check(w http.ResponseWriter, r *http.Request, now time.Time) (passID, passStatus) {
	ck, err := r.Cookie(admitCookie)
	if err != nil {
		return passID{}, passMissing
	}
	id, exp, status := a.verify(ck.Value, now)
	if status == passValid && exp.Sub(now) <= a.opts.Load().ttl/2 {
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

// userSlots keeps separate pools per protocol family. sema.SetCap drains when
// shrinking, so a single semaphore can't be resized when a user's protocol
// changes; two lazily created ones avoid that.
type userSlots struct {
	lastSeen int64 // unix nanos, guarded by the shard mutex
	h1       sema.Semaphore
	h2       sema.Semaphore
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

// sweep evicts entries idle since before cutoff with nothing in flight.
func (s *userStore) sweep(cutoff int64) int {
	evicted := 0
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for id, u := range sh.m {
			if u.lastSeen < cutoff && semIdle(u.h1) && semIdle(u.h2) {
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
// global slot, then the global pool that protects the host.
//
// This is the hot path: no logging, counters only.
type assetGuard struct {
	admit       *admitter
	users       *userStore
	global      sema.Semaphore
	userWait    time.Duration
	globalWait  time.Duration
	protoHeader string
	stats       *counters
	strike      func(*gin.Context, int)
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

	g.serve(c)
}

// public skips the pass check but still counts against the global cap.
func (g *assetGuard) public(c *gin.Context) {
	g.serve(c)
}

func (g *assetGuard) serve(c *gin.Context) {
	if !acquire(c.Request.Context(), g.global, g.globalWait) {
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
