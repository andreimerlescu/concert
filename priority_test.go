package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// grantFor mints the grant the origin's header would give pass.
func grantFor(t *testing.T, a *app, pass string, rank priorityRank) string {
	t.Helper()
	id, _, status := a.admit.verify(pass, time.Now())
	if status != passValid {
		t.Fatal("admission pass does not verify")
	}
	return a.prio.grants.mint(id, rank, time.Now().Add(time.Hour))
}

func withGrant(pass, grant string) map[string]string {
	return map[string]string{"Cookie": admitCookie + "=" + pass + "; " + priorityCookie + "=" + grant}
}

func TestPriorityHeader_Parse(t *testing.T) {
	cases := []struct {
		in   string
		rank priorityRank
		ttl  time.Duration
		bad  bool
	}{
		{"checkout", rankCheckout, 30 * time.Minute, false},
		{" Customer ; ttl=600", rankCustomer, 10 * time.Minute, false},
		{"staff; ttl=2h", rankStaff, 2 * time.Hour, false},
		{"member; ttl=5", rankMember, time.Minute, false},              // clamped up
		{"subscriber; ttl=72h", rankSubscriber, 24 * time.Hour, false}, // clamped down
		{"guest", rankGuest, 0, false},
		{"emperor", 0, 0, true},
		{"member; ttl=soon", 0, 0, true},
	}
	for _, c := range cases {
		rank, ttl, err := parsePriorityHeader(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("%q: expected an error", c.in)
			}
			continue
		}
		if err != nil || rank != c.rank || ttl != c.ttl {
			t.Errorf("%q: got %s %s %v, want %s %s", c.in, rank, ttl, err, c.rank, c.ttl)
		}
	}
}

func TestPriority_GrantFromOriginHeader(t *testing.T) {
	var leaked atomic.Bool
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie(priorityCookie); err == nil {
			leaked.Store(true)
		}
		switch r.URL.Path {
		case "/checkout":
			w.Header().Set(priorityHeader, "checkout; ttl=10m")
		case "/logout":
			w.Header().Set(priorityHeader, "guest")
		case "/junk":
			w.Header().Set(priorityHeader, "emperor")
		}
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(origin.Close)
	a, front := newTestApp(t, testConfig(origin.URL), nil)
	now := time.Now()

	resp, _ := get(t, front.URL+"/checkout", map[string]string{"Accept": "text/html"})
	if resp.Header.Get(priorityHeader) != "" {
		t.Error("the Concert-Priority header must not reach the browser")
	}
	pass, _ := cookieValue(resp, admitCookie)
	grant, ok := cookieValue(resp, priorityCookie)
	if !ok {
		t.Fatal("no grant issued")
	}
	id, _, _ := a.admit.verify(pass, now)
	if rank, ok := a.prio.grants.verify(grant, id, now); !ok || rank != rankCheckout {
		t.Errorf("grant: rank=%s ok=%v, want checkout", rank, ok)
	}
	if _, ok := a.prio.grants.verify(grant, passID{9}, now); ok {
		t.Error("a grant must only be valid with the pass it was issued to")
	}

	resp, _ = get(t, front.URL+"/logout", withGrant(pass, grant))
	cleared := false
	for _, c := range resp.Cookies() {
		if c.Name == priorityCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("guest should clear the grant")
	}
	if leaked.Load() {
		t.Error("concert_priority must not be forwarded to the origin")
	}

	resp, _ = get(t, front.URL+"/junk", map[string]string{"Cookie": admitCookie + "=" + pass})
	if _, ok := cookieValue(resp, priorityCookie); ok || resp.Header.Get(priorityHeader) != "" {
		t.Error("an unknown rank must be ignored and stripped")
	}
	if a.prio.grants.rejected.Load() != 1 {
		t.Errorf("rejected: %d, want 1", a.prio.grants.rejected.Load())
	}
}

func TestPriority_LaneSkipsFullRoom(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	a, front := newTestApp(t, cfg, up)
	pass := admitPass(t, front)
	other := admitPass(t, front)
	fillSlot(t, front, up)

	if resp, _ := get(t, front.URL+"/hello", withPass(pass, nil)); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("guest with a pass: got %d, want queued 429", resp.StatusCode)
	}
	if resp, _ := get(t, front.URL+"/hello", withGrant(pass, grantFor(t, a, pass, rankProspect))); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("prospect is below the lane rank: got %d, want queued 429", resp.StatusCode)
	}
	resp, body := get(t, front.URL+"/hello", withGrant(pass, grantFor(t, a, pass, rankCustomer)))
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Errorf("customer while the room is full: got %d %q, want 200 through the lane", resp.StatusCode, body)
	}
	if resp, _ := get(t, front.URL+"/hello", withGrant(other, grantFor(t, a, pass, rankStaff))); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("a grant presented with another pass: got %d, want queued 429", resp.StatusCode)
	}
	if a.prio.laneServed.Load() != 1 {
		t.Errorf("lane served: %d, want 1", a.prio.laneServed.Load())
	}
}

func TestRankedSem_HighestRankFirst(t *testing.T) {
	s := newRankedSem(1)
	ctx := context.Background()
	if !s.acquire(ctx, rankGuest, 0) {
		t.Fatal("first acquire failed")
	}
	if s.acquire(ctx, rankStaff, 20*time.Millisecond) || s.Waiting() != 0 {
		t.Fatal("a full semaphore must time out and forget the waiter")
	}

	got := make(chan priorityRank, 2)
	go func() {
		if s.acquire(ctx, rankCustomer, 5*time.Second) {
			got <- rankCustomer
		}
	}()
	eventually(t, 2*time.Second, func() bool { return s.Waiting() == 1 }, "customer never waited")
	go func() {
		if s.acquire(ctx, rankStaff, 5*time.Second) {
			got <- rankStaff
		}
	}()
	eventually(t, 2*time.Second, func() bool { return s.Waiting() == 2 }, "staff never waited")

	s.release()
	if first := <-got; first != rankStaff {
		t.Errorf("first served: %s, want staff", first)
	}
	s.release()
	if second := <-got; second != rankCustomer {
		t.Errorf("second served: %s, want customer", second)
	}
	s.release()
	if s.Len() != 0 {
		t.Errorf("in use: %d, want 0", s.Len())
	}
}

// rankedLineTest is a full room (cap 1, one parked request) and a way to
// join its line with a fresh cookie jar, optionally holding a rank grant,
// from a given address.
type rankedLineTest struct {
	a     *app
	p     *portal
	front *httptest.Server
	pass  string
}

func newRankedLineTest(t *testing.T, orderLine bool) *rankedLineTest {
	t.Helper()
	up := newFakeUpstream(t)
	cfg := portalTestConfig(up.URL())
	cfg.capacity = 1
	cfg.trustedProxies = "127.0.0.1/32"
	cfg.priorityOrderLine = orderLine
	a, p, front := newTestPortal(t, cfg, up)
	pass := admitPass(t, front)
	fillSlot(t, front, up)
	return &rankedLineTest{a: a, p: p, front: front, pass: pass}
}

// join queues a new visitor from ip at rank (rankGuest: no grant) and
// returns its room ticket.
func (l *rankedLineTest) join(t *testing.T, ip string, rank priorityRank) string {
	t.Helper()
	hdr := withXFF(ip)
	if rank != rankGuest {
		for k, v := range withGrant(l.pass, grantFor(t, l.a, l.pass, rank)) {
			hdr[k] = v
		}
	}
	c := jarClient()
	resp, _ := doReq(t, c, http.MethodGet, l.front.URL+"/api/wait", hdr, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected to be queued, got %d", resp.StatusCode)
	}
	return ticketOf(t, c, l.front)
}

func (l *rankedLineTest) line(t *testing.T, want ...string) {
	t.Helper()
	line := l.a.room.Queue(10)
	got := make([]string, len(line))
	for i, ti := range line {
		got[i] = ti.Token
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("line order:\n got %v\nwant %v", got, want)
	}
}

// With -priority-order-line (the default), ranked visitors below the lane
// rank wait ahead of lower ranks, in arrival order within a rank, and the
// portal shows the rank room recorded.
func TestPriority_LineOrderedByRank(t *testing.T) {
	l := newRankedLineTest(t, true)
	g1 := l.join(t, "203.0.113.1", rankGuest)
	g2 := l.join(t, "203.0.113.2", rankGuest)
	g3 := l.join(t, "203.0.113.3", rankGuest)
	m1 := l.join(t, "203.0.113.4", rankMember)
	l.line(t, m1, g1, g2, g3) // a member who arrived after three guests is ahead of them

	p1 := l.join(t, "203.0.113.5", rankProspect)
	l.line(t, p1, m1, g1, g2, g3) // a prospect is ahead of a member

	m2 := l.join(t, "203.0.113.6", rankMember)
	l.line(t, p1, m1, m2, g1, g2, g3) // equal ranks keep arrival order

	if n := l.a.prio.placed.Load(); n != 3 {
		t.Errorf("priority_placed_total: %d, want 3 (every ranked arrival passed someone)", n)
	}
	views := l.p.queueViews(time.Now())
	if views[0].Rank != "prospect" || views[1].Rank != "member" || views[3].Rank != "" {
		t.Errorf("queue view ranks: %q %q %q", views[0].Rank, views[1].Rank, views[3].Rank)
	}
}

// -priority-order-line=false keeps strict arrival order for ranked visitors.
func TestPriority_RankedVisitorsWaitInArrivalOrderWhenOff(t *testing.T) {
	l := newRankedLineTest(t, false)
	guest := l.join(t, "203.0.113.1", rankGuest)
	prospect := l.join(t, "203.0.113.2", rankProspect)
	member := l.join(t, "203.0.113.3", rankMember)
	l.line(t, guest, prospect, member)
	if n := l.a.prio.placed.Load(); n != 0 {
		t.Errorf("nobody should be moved with -priority-order-line=false: %d", n)
	}
}

// A ban drops a ranked visitor from the line like any other.
func TestPriority_BanDropsRankedVisitor(t *testing.T) {
	l := newRankedLineTest(t, true)
	guest := l.join(t, "203.0.113.1", rankGuest)
	l.join(t, "198.51.100.9", rankProspect)
	if _, err := l.a.abuse.banFor(netip.MustParseAddr("198.51.100.9"), time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	eventually(t, 2*time.Second, func() bool { return l.a.room.LiveQueueDepth() == 1 },
		"the ban never removed the ranked visitor")
	l.line(t, guest)
}

func TestPriority_FormsSkipLineForAdmittedVisitors(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.priorityForms = true
	a, front := newTestApp(t, cfg, up)
	pass := admitPass(t, front)
	fillSlot(t, front, up)

	resp, body := doReq(t, testClient, http.MethodPost, front.URL+"/submit", withPass(pass, nil), strings.NewReader("a=1"))
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Errorf("admitted form while full: got %d %q, want 200", resp.StatusCode, body)
	}
	resp, _ = doReq(t, testClient, http.MethodPost, front.URL+"/submit", nil, strings.NewReader("a=1"))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("form without a pass: got %d, want queued 429", resp.StatusCode)
	}

	park(t, front, up, "/slow", withGrant(pass, grantFor(t, a, pass, rankCustomer))) // lane now full
	resp, body = doReq(t, testClient, http.MethodPost, front.URL+"/submit", withPass(pass, nil), strings.NewReader("a=1"))
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" ||
		!strings.Contains(string(body), `"submitted":false`) {
		t.Errorf("form with the lane full: got %d %s, want 503 without queuing", resp.StatusCode, body)
	}
	if a.prio.forms.Load() != 1 || a.prio.formsRefused.Load() != 1 {
		t.Errorf("forms=%d refused=%d, want 1 and 1", a.prio.forms.Load(), a.prio.formsRefused.Load())
	}
}

func TestPriority_BansApplyAtEveryRank(t *testing.T) {
	up := newFakeUpstream(t)
	a, front := newTestApp(t, testConfig(up.URL()), up)
	pass := admitPass(t, front)
	grant := grantFor(t, a, pass, rankStaff)
	if _, err := a.abuse.banFor(netip.MustParseAddr("127.0.0.1"), time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	if resp, body := get(t, front.URL+"/hello", withGrant(pass, grant)); !isBlocked(resp, body) {
		t.Errorf("banned staff: got %d, want blocked", resp.StatusCode)
	}
}

// Ordering the line by rank is what priority.go was written to do, so it is
// on unless an operator turns it off.
func TestPriority_OrderLineDefaultsOn(t *testing.T) {
	clearConcertEnv(t)
	cfg, _, err := parseConfig(newFlagSet(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.priorityOrderLine {
		t.Error("-priority-order-line should default to true")
	}
	t.Setenv("CONCERT_PRIORITY_ORDER_LINE", "false")
	if cfg, _, err = parseConfig(newFlagSet(), nil); err != nil || cfg.priorityOrderLine {
		t.Errorf("CONCERT_PRIORITY_ORDER_LINE=false: got %v %v", cfg.priorityOrderLine, err)
	}
}
