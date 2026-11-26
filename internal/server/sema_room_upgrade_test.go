package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andreimerlescu/sema"
)

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for condition")
}

func TestAssetPriority_CheckoutBeatsAdmittedBeatsPublic(t *testing.T) {
	var (
		mu       sync.Mutex
		order    []string
		started  = make(chan string, 8)
		releases = map[string]chan struct{}{
			"blocker":  make(chan struct{}),
			"checkout": make(chan struct{}),
			"admitted": make(chan struct{}),
			"public":   make(chan struct{}),
		}
	)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tag := r.URL.Query().Get("tag")
		if tag != "" {
			mu.Lock()
			order = append(order, tag)
			mu.Unlock()
			started <- tag
			if ch, ok := releases[tag]; ok {
				<-ch
			}
		}
		_, _ = fmt.Fprint(w, "ok:"+tag)
	}))
	t.Cleanup(origin.Close)

	cfg := testConfig(origin.URL)
	cfg.assets = "/static/*"
	cfg.assetPublic = "/public/*"
	cfg.assetCap = 1
	cfg.assetWait = 3 * time.Second
	cfg.assetUserWait = 3 * time.Second
	a, front := newTestApp(t, cfg, nil)

	admittedPass := admitPass(t, front)
	checkoutPass := admitPass(t, front)
	checkoutGrant := grantFor(t, a, checkoutPass, rankCheckout)

	// 1. Occupy the single global asset slot with a blocker.
	blockerDone := make(chan int, 1)
	go func() {
		resp, _ := get(t, front.URL+"/public/block.png?tag=blocker", nil)
		blockerDone <- resp.StatusCode
	}()
	if got := <-started; got != "blocker" {
		t.Fatalf("expected blocker to start first, got %q", got)
	}

	// 2. Enqueue public (PriorityLow), then admitted (PriorityNormal), then checkout (PriorityCritical).
	pubDone := make(chan int, 1)
	go func() {
		resp, _ := get(t, front.URL+"/public/logo.png?tag=public", nil)
		pubDone <- resp.StatusCode
	}()
	waitUntil(t, func() bool {
		p, ok := a.current().assets.global.HighestWaitingPriority()
		return ok && p == sema.PriorityLow
	})

	admDone := make(chan int, 1)
	go func() {
		resp, _ := get(t, front.URL+"/static/app.js?tag=admitted", withPass(admittedPass, nil))
		admDone <- resp.StatusCode
	}()
	waitUntil(t, func() bool {
		p, ok := a.current().assets.global.HighestWaitingPriority()
		return ok && p == sema.PriorityNormal
	})

	chkDone := make(chan int, 1)
	go func() {
		resp, _ := get(t, front.URL+"/static/checkout.js?tag=checkout", withGrant(checkoutPass, checkoutGrant))
		chkDone <- resp.StatusCode
	}()
	waitUntil(t, func() bool {
		p, ok := a.current().assets.global.HighestWaitingPriority()
		return ok && p == sema.PriorityCritical
	})

	// Lock-free HighestWaitingPriority must surface in Prometheus metrics.
	metricsText := a.renderPrometheusMetrics()
	if !strings.Contains(metricsText, "concert_assets_waiting_priority 4\n") {
		t.Fatalf("expected concert_assets_waiting_priority 4 in metrics, got:\n%s", metricsText)
	}

	// 3. Release one slot at a time and verify strict O(1) priority ordering.
	close(releases["blocker"])
	if st := <-blockerDone; st != http.StatusOK {
		t.Fatalf("blocker status = %d, want 200", st)
	}

	if got := <-started; got != "checkout" {
		t.Fatalf("1st woken waiter = %q, want checkout (PriorityCritical)", got)
	}
	close(releases["checkout"])
	if st := <-chkDone; st != http.StatusOK {
		t.Fatalf("checkout status = %d, want 200", st)
	}

	if got := <-started; got != "admitted" {
		t.Fatalf("2nd woken waiter = %q, want admitted (PriorityNormal)", got)
	}
	close(releases["admitted"])
	if st := <-admDone; st != http.StatusOK {
		t.Fatalf("admitted status = %d, want 200", st)
	}

	if got := <-started; got != "public" {
		t.Fatalf("3rd woken waiter = %q, want public (PriorityLow)", got)
	}
	close(releases["public"])
	if st := <-pubDone; st != http.StatusOK {
		t.Fatalf("public status = %d, want 200", st)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"blocker", "checkout", "admitted", "public"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
}

func TestReloadPoolShrink_ZeroOverAdmission(t *testing.T) {
	started := make(chan struct{}, 16)
	releaseOne := make(chan struct{}, 16)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("hold") == "1" {
			started <- struct{}{}
			<-releaseOne
		}
		_, _ = fmt.Fprint(w, "ok")
	}))
	t.Cleanup(origin.Close)

	cfg := testConfig(origin.URL)
	cfg.assetPublic = "/public/*"
	cfg.streamPaths = "/ws/*"
	cfg.assetCap = 3
	cfg.assetWait = 0
	cfg.streamCap = 3
	cfg.priorityCap = 3
	a, front := newTestApp(t, cfg, nil)

	pass := admitPass(t, front)

	// Hold 3 global asset slots and 3 stream slots simultaneously.
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			resp, _ := get(t, front.URL+"/public/a.css?hold=1", nil)
			if resp.StatusCode != http.StatusOK {
				t.Errorf("in-flight asset got %d, want 200", resp.StatusCode)
			}
		}()
		go func() {
			defer wg.Done()
			resp, _ := get(t, front.URL+"/ws/feed?hold=1", withPass(pass, nil))
			if resp.StatusCode != http.StatusOK {
				t.Errorf("in-flight stream got %d, want 200", resp.StatusCode)
			}
		}()
	}
	for i := 0; i < 6; i++ {
		<-started
	}

	// Shrink asset_cap, stream_cap, and priority_cap live via generation commit.
	prev := a.current()
	next := prev.cfg
	next.assetCap = 1
	next.streamCap = 1
	next.priorityCap = 1
	g, err := a.buildGeneration(next, prev)
	if err != nil {
		t.Fatalf("buildGeneration: %v", err)
	}
	// Before commit, live caps must remain untouched.
	if prev.assets.global.Cap() != 3 || prev.streams.sem.Cap() != 3 || prev.lane.Cap() != 3 {
		t.Fatalf("buildGeneration mutated live caps before commit: asset=%d stream=%d lane=%d",
			prev.assets.global.Cap(), prev.streams.sem.Cap(), prev.lane.Cap())
	}
	if err := a.commit(g, nil); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Pools must be resized in place (same underlying semaphores, Cap=1, Len=3).
	if g.assets.global != prev.assets.global || g.streams.sem != prev.streams.sem || g.lane != prev.lane {
		t.Fatal("expected in-place pool reuse across reload")
	}
	if g.assets.global.Cap() != 1 || g.assets.global.Len() != 3 {
		t.Fatalf("asset pool after shrink: cap=%d len=%d, want cap=1 len=3", g.assets.global.Cap(), g.assets.global.Len())
	}
	if g.streams.sem.Cap() != 1 || g.streams.sem.Len() != 3 {
		t.Fatalf("stream pool after shrink: cap=%d len=%d, want cap=1 len=3", g.streams.sem.Cap(), g.streams.sem.Len())
	}
	if g.lane.Cap() != 1 {
		t.Fatalf("lane cap after shrink: %d, want 1", g.lane.Cap())
	}

	// Draining gauges must report 1 while Len > Cap.
	m := a.renderPrometheusMetrics()
	if !strings.Contains(m, "concert_assets_cap_draining 1\n") {
		t.Fatalf("expected concert_assets_cap_draining 1, got:\n%s", m)
	}
	if !strings.Contains(m, "concert_streams_cap_draining 1\n") {
		t.Fatalf("expected concert_streams_cap_draining 1, got:\n%s", m)
	}

	// Zero over-admission: both a 4th asset and a 4th stream must be rejected with 503.
	if resp, _ := get(t, front.URL+"/public/extra.css", nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("extra asset during shrink drain = %d, want 503", resp.StatusCode)
	}
	if resp, _ := get(t, front.URL+"/ws/extra", withPass(pass, nil)); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("extra stream during shrink drain = %d, want 503", resp.StatusCode)
	}

	// Release all 6 in-flight holders; new requests must succeed again under cap=1.
	for i := 0; i < 6; i++ {
		releaseOne <- struct{}{}
	}
	wg.Wait()

	if resp, _ := get(t, front.URL+"/public/after.css", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("asset after drain = %d, want 200", resp.StatusCode)
	}
	if resp, _ := get(t, front.URL+"/ws/after", withPass(pass, nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("stream after drain = %d, want 200", resp.StatusCode)
	}
}

func TestRankedSem_All7RanksAndNonDrainingSetCap(t *testing.T) {
	sem := newRankedSem(2)
	ctx := context.Background()

	// Take both slots.
	if !sem.acquire(ctx, rankGuest, 0) || !sem.acquire(ctx, rankGuest, 0) {
		t.Fatal("failed to take initial 2 slots")
	}

	// Shrink from 2 -> 1 while 2 are held (non-draining).
	sem.SetCap(1)
	if sem.Cap() != 1 || sem.Len() != 2 {
		t.Fatalf("after shrink: cap=%d len=%d, want 1, 2", sem.Cap(), sem.Len())
	}

	// Release 1 holder: Len drops 2 -> 1, still at cap=1 so no new acquire may enter.
	sem.release()
	if sem.acquire(ctx, rankStaff, 0) {
		t.Fatal("over-admitted while at shrunk cap=1")
	}

	// Queue one waiter at every single Concert rank (guest..staff) in reverse order.
	ranks := []priorityRank{rankGuest, rankMember, rankProspect, rankCustomer, rankSubscriber, rankCheckout, rankStaff}
	orderCh := make(chan priorityRank, len(ranks))
	var wg sync.WaitGroup
	for _, r := range ranks {
		wg.Add(1)
		go func(rk priorityRank) {
			defer wg.Done()
			if !sem.acquire(ctx, rk, 2*time.Second) {
				t.Errorf("rank %s timed out", rk)
				return
			}
			orderCh <- rk
			// Hold briefly, then release sequentially via test control below?
			// Simpler: release immediately after recording to observe strict dispatch.
			sem.release()
		}(r)
	}
	waitUntil(t, func() bool { return sem.Waiting() == len(ranks) })

	// Release the last holder; since each woken waiter releases after recording,
	// we can test deterministic step-by-step dispatch with a separate gate for strict order.
	// Wait: with concurrent goroutines, recording before release guarantees the
	// semaphore wakes strictly in rankStaff -> rankGuest order, though scheduler
	// interleaving could reorder channel sends if we release immediately.
	// Let's release here just to drain cleanly, then test deterministic order with a barrier below.
	sem.release()
	wg.Wait()
	close(orderCh)
	if len(orderCh) != len(ranks) {
		t.Fatalf("woken count = %d, want %d", len(orderCh), len(ranks))
	}

	// Deterministic strict 7-rank order check + grow SetCap waking multiple waiters.
	s2 := newRankedSem(1)
	if !s2.acquire(ctx, rankGuest, 0) {
		t.Fatal("failed to acquire initial slot")
	}
	woken := make(chan priorityRank, len(ranks))
	gate := make(chan struct{})
	var wg2 sync.WaitGroup
	for _, r := range ranks {
		wg2.Add(1)
		go func(rk priorityRank) {
			defer wg2.Done()
			if !s2.acquire(ctx, rk, 2*time.Second) {
				t.Errorf("rank %s timed out", rk)
				return
			}
			woken <- rk
			<-gate
			s2.release()
		}(r)
	}
	waitUntil(t, func() bool { return s2.Waiting() == len(ranks) })

	// Step through one release at a time to verify exact 7-rank strict ordering.
	s2.release()
	wantOrder := []priorityRank{rankStaff, rankCheckout, rankSubscriber, rankCustomer, rankProspect, rankMember, rankGuest}
	for i, want := range wantOrder {
		got := <-woken
		if got != want {
			t.Fatalf("step %d: got rank %s, want %s", i, got, want)
		}
		if i < len(wantOrder)-1 {
			gate <- struct{}{}
		}
	}
	close(gate)
	wg2.Wait()
}

func TestRoomV17_ParallelStatusPollingAndRankedOrder(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.priorityCap = 1
	cfg.priorityOrderLine = true
	cfg.priorityLaneRank = int(rankCount) // keep everyone in the ranked waiting line
	cfg.abuseEnabled = false
	a, front := newTestApp(t, cfg, up)

	// Mint passes before filling the single page slot.
	passes := make([]string, 10)
	for i := range passes {
		passes[i] = admitPass(t, front)
	}

	// Fill the single page slot so all subsequent visitors queue.
	fillSlot(t, front, up)

	// Enqueue 30 visitors (20 guests + 10 prospects ranked ahead).
	var tickets []string
	for i := 0; i < 20; i++ {
		resp, _ := get(t, front.URL+"/drop", map[string]string{"Accept": "text/html"})
		if tok, ok := cookieValue(resp, "room_ticket"); ok {
			tickets = append(tickets, tok)
		}
	}
	for _, pass := range passes {
		grant := grantFor(t, a, pass, rankProspect)
		resp, _ := get(t, front.URL+"/drop", map[string]string{
			"Accept": "text/html",
			"Cookie": admitCookie + "=" + pass + "; " + priorityCookie + "=" + grant,
		})
		if tok, ok := cookieValue(resp, "room_ticket"); ok {
			tickets = append(tickets, tok)
		}
	}
	if len(tickets) < 25 {
		t.Fatalf("expected >=25 queued tickets, got %d", len(tickets))
	}

	// Verify room v1.7.0 treap ordering: first 10 queued tickets are prospects (rank 2).
	line := a.room.Queue(10)
	if len(line) != 10 {
		t.Fatalf("Queue(10) len = %d, want 10", len(line))
	}
	for i, ti := range line {
		if ti.Rank != int(rankProspect) {
			t.Fatalf("line[%d].Rank = %d, want %d (prospect)", i, ti.Rank, rankProspect)
		}
	}

	// Fire parallel /queue/status polls (RLock path in room v1.7.0) concurrently with Queue() reads.
	var okCount atomic.Int64
	var wg sync.WaitGroup
	for _, tok := range tickets {
		wg.Add(1)
		go func(tk string) {
			defer wg.Done()
			resp, _ := get(t, front.URL+"/queue/status", map[string]string{"Cookie": "room_ticket=" + tk})
			if resp.StatusCode == http.StatusOK {
				okCount.Add(1)
			}
		}(tok)
	}
	wg.Wait()
	if okCount.Load() != int64(len(tickets)) {
		t.Fatalf("parallel status polls: %d/%d returned 200", okCount.Load(), len(tickets))
	}
}
