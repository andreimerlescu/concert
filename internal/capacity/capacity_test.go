package capacity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGateBasic(t *testing.T) {
	g := NewGate(2)
	if !g.TryAcquire(Hop) || !g.TryAcquire(Direct) {
		t.Fatal("free slots refused")
	}
	if g.TryAcquire(Hop) || g.TryAcquire(Direct) {
		t.Fatal("over cap granted")
	}
	if g.Acquire(context.Background(), Direct, 0) {
		t.Fatal("zero wait granted when full")
	}
	g.Release(Hop)
	if g.InUse(Hop) != 0 || g.InUse(Direct) != 1 {
		t.Fatalf("in use hop %d direct %d", g.InUse(Hop), g.InUse(Direct))
	}
	if NewGate(0).Cap() != 1 {
		t.Fatal("cap below 1 not raised to 1")
	}
}

// waitFor polls cond for up to a second.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// A freed slot goes to a waiting hop request even if a direct request has
// waited longer: the edge's admitted visitors come first.
func TestGateHopBeforeDirect(t *testing.T) {
	g := NewGate(1)
	g.TryAcquire(Direct)
	order := make(chan Class, 2)
	go func() {
		if g.Acquire(context.Background(), Direct, time.Second) {
			order <- Direct
			g.Release(Direct)
		}
	}()
	waitFor(t, "direct waiter", func() bool { return g.Waiting(Direct) == 1 })
	go func() {
		if g.Acquire(context.Background(), Hop, time.Second) {
			order <- Hop
			time.Sleep(10 * time.Millisecond)
			g.Release(Hop)
		}
	}()
	waitFor(t, "hop waiter", func() bool { return g.Waiting(Hop) == 1 })
	g.Release(Direct)
	if first := <-order; first != Hop {
		t.Fatalf("first granted %v, want Hop", first)
	}
	if second := <-order; second != Direct {
		t.Fatalf("second granted %v, want Direct", second)
	}
}

// Paid or high-rank hop traffic is served before other hop traffic.
func TestGatePriorityBeforeHop(t *testing.T) {
	g := NewGate(1)
	g.TryAcquire(Direct)
	order := make(chan Class, 2)
	for _, c := range []Class{Hop, HopPriority} {
		c := c
		n := g.Waiting(Hop) + g.Waiting(HopPriority)
		go func() {
			if g.Acquire(context.Background(), c, time.Second) {
				order <- c
				time.Sleep(5 * time.Millisecond)
				g.Release(c)
			}
		}()
		waitFor(t, "waiter", func() bool { return g.Waiting(Hop)+g.Waiting(HopPriority) == n+1 })
	}
	g.Release(Direct)
	if first := <-order; first != HopPriority {
		t.Fatalf("first granted %v, want HopPriority", first)
	}
	<-order
}

// A direct arrival may not take a free slot ahead of a waiting hop request.
func TestGateNoBargingPastWaiters(t *testing.T) {
	g := NewGate(1)
	g.TryAcquire(Hop)
	done := make(chan bool)
	go func() { done <- g.Acquire(context.Background(), Hop, time.Second) }()
	waitFor(t, "hop waiter", func() bool { return g.Waiting(Hop) == 1 })
	g.Release(Hop) // granted straight to the waiter
	if g.TryAcquire(Direct) {
		t.Fatal("direct barged past the hop waiter")
	}
	if !<-done {
		t.Fatal("hop waiter not granted")
	}
}

func TestGateFIFOWithinClass(t *testing.T) {
	g := NewGate(1)
	g.TryAcquire(Direct)
	got := make(chan int, 3)
	for i := 0; i < 3; i++ {
		i := i
		waitFor(t, "previous waiter", func() bool { return g.Waiting(Direct) == i })
		go func() {
			if g.Acquire(context.Background(), Direct, 2*time.Second) {
				got <- i
				g.Release(Direct)
			}
		}()
	}
	waitFor(t, "three waiters", func() bool { return g.Waiting(Direct) == 3 })
	g.Release(Direct)
	for want := 0; want < 3; want++ {
		if i := <-got; i != want {
			t.Fatalf("granted %d, want %d", i, want)
		}
	}
}

func TestGateTimeoutAndCancel(t *testing.T) {
	g := NewGate(1)
	g.TryAcquire(Hop)
	start := time.Now()
	if g.Acquire(context.Background(), Hop, 30*time.Millisecond) {
		t.Fatal("granted while full")
	}
	if time.Since(start) < 25*time.Millisecond {
		t.Fatal("returned before the wait")
	}
	ctx, cancel := context.WithCancel(context.Background())
	res := make(chan bool)
	go func() { res <- g.Acquire(ctx, Direct, time.Minute) }()
	waitFor(t, "waiter", func() bool { return g.Waiting(Direct) == 1 })
	cancel()
	if <-res {
		t.Fatal("granted after cancel")
	}
	if g.Waiting(Direct) != 0 {
		t.Fatal("cancelled waiter still queued")
	}
	// A waiter that left must not have consumed a slot.
	g.Release(Hop)
	if !g.TryAcquire(Direct) {
		t.Fatal("slot lost")
	}
}

// A waiter that timed out must not block a lower class behind it.
func TestGateTimedOutWaiterUnblocksOthers(t *testing.T) {
	g := NewGate(2)
	g.TryAcquire(Hop)
	g.TryAcquire(Hop)
	go g.Acquire(context.Background(), Hop, 20*time.Millisecond)
	waitFor(t, "hop waiter", func() bool { return g.Waiting(Hop) == 1 })
	g.SetCap(3) // grants the hop waiter
	waitFor(t, "grant", func() bool { return g.InUse(Hop) == 3 })
	g.Release(Hop)
	if !g.TryAcquire(Direct) {
		t.Fatal("direct refused a free slot")
	}
}

func TestGateShrinkRevokesNothingGrowWakes(t *testing.T) {
	g := NewGate(3)
	for i := 0; i < 3; i++ {
		g.TryAcquire(Direct)
	}
	g.SetCap(1)
	g.Release(Direct)
	if g.TryAcquire(Direct) {
		t.Fatal("granted while above the new cap")
	}
	g.Release(Direct)
	g.Release(Direct)
	if !g.TryAcquire(Direct) || g.TryAcquire(Direct) {
		t.Fatal("cap 1 not enforced after drain")
	}
	res := make(chan bool)
	go func() { res <- g.Acquire(context.Background(), Hop, time.Second) }()
	waitFor(t, "waiter", func() bool { return g.Waiting(Hop) == 1 })
	g.SetCap(2)
	if !<-res {
		t.Fatal("growing did not wake the waiter")
	}
}

// Under contention from both classes the ceiling is never exceeded and every
// slot is returned.
func TestGateStress(t *testing.T) {
	const capN = 7
	g := NewGate(capN)
	var cur, peak atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		c := Class(i % int(numClasses))
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if !g.Acquire(context.Background(), c, 50*time.Millisecond) {
					continue
				}
				n := cur.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				cur.Add(-1)
				g.Release(c)
			}
		}()
	}
	wg.Wait()
	if p := peak.Load(); p > capN {
		t.Fatalf("peak %d exceeded cap %d", p, capN)
	}
	if g.InUse(HopPriority)+g.InUse(Hop)+g.InUse(Direct) != 0 || g.Waiting(HopPriority)+g.Waiting(Hop)+g.Waiting(Direct) != 0 {
		t.Fatal("slots or waiters leaked")
	}
}

func TestPlannerWeights(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	p := &Planner{Stale: 10 * time.Second, Expire: 30 * time.Second}
	reports := []Report{
		{Leaf: "fresh", Share: 100, Usable: true, At: now.Add(-time.Second)},
		{Leaf: "fading", Share: 100, Usable: true, At: now.Add(-20 * time.Second)}, // half weight
		{Leaf: "gone", Share: 100, Usable: true, At: now.Add(-time.Minute)},
		{Leaf: "unhealthy", Share: 100, Usable: false, At: now},
		{Leaf: "never", Share: 100, Usable: true},
	}
	got := p.Plan(reports, now)
	if got.Total != 150 || got.Leaves != 2 || got.Cap != 150 {
		t.Fatalf("plan %+v, want total 150 over 2 leaves", got)
	}
}

func TestPlannerLaneMaxAndFloor(t *testing.T) {
	now := time.Now()
	fresh := func(share int) []Report {
		return []Report{{Leaf: "a", Share: share, Usable: true, At: now}}
	}
	p := &Planner{Lane: 20, Max: 50, Stale: time.Minute, Expire: 2 * time.Minute}
	if got := p.Plan(fresh(100), now); got.Desired != 50 || got.Total != 100 {
		t.Fatalf("max clamp: %+v", got)
	}
	p = &Planner{Lane: 20, Stale: time.Minute, Expire: 2 * time.Minute}
	if got := p.Plan(fresh(100), now); got.Desired != 80 {
		t.Fatalf("lane subtraction: %+v", got)
	}
	p = &Planner{Lane: 20, Stale: time.Minute, Expire: 2 * time.Minute}
	if got := p.Plan(fresh(10), now); got.Desired != 1 || got.Cap != 1 {
		t.Fatalf("floor: %+v", got)
	}
	p = &Planner{Stale: time.Minute, Expire: 2 * time.Minute}
	if got := p.Plan(nil, now); got.Cap != 1 || got.Total != 0 {
		t.Fatalf("no leaves: %+v", got)
	}
}

// Drops apply at once; raises wait for RaiseAfter agreeing plans and then
// take the smallest proposal of the streak.
func TestPlannerHysteresis(t *testing.T) {
	now := time.Now()
	p := &Planner{Stale: time.Minute, Expire: 2 * time.Minute, RaiseAfter: 3}
	plan := func(share int) int {
		return p.Plan([]Report{{Leaf: "a", Share: share, Usable: true, At: now}}, now).Cap
	}
	if c := plan(100); c != 100 {
		t.Fatalf("first plan %d", c)
	}
	if c := plan(40); c != 40 {
		t.Fatalf("drop not immediate: %d", c)
	}
	if c := plan(100); c != 40 {
		t.Fatalf("raise after 1: %d", c)
	}
	if c := plan(90); c != 40 {
		t.Fatalf("raise after 2: %d", c)
	}
	if c := plan(100); c != 90 {
		t.Fatalf("raise after 3 = %d, want the streak minimum 90", c)
	}
	// A plan equal to current breaks a streak.
	plan(120)
	plan(90)
	if c := plan(120); c != 90 {
		t.Fatalf("broken streak raised to %d", c)
	}
}

func TestSafeShrink(t *testing.T) {
	cases := []struct{ target, occ, want int }{
		{50, 10, 50},
		{50, 80, 80},
		{0, 0, 1},
		{-3, 0, 1},
	}
	for _, tc := range cases {
		if got := SafeShrink(tc.target, tc.occ); got != tc.want {
			t.Errorf("SafeShrink(%d, %d) = %d, want %d", tc.target, tc.occ, got, tc.want)
		}
	}
}

func TestFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := Path(filepath.Join(dir, "data"))
	in := File{At: time.Now().UTC().Truncate(time.Second), Target: "http://127.0.0.1:3000/", HostCap: 37, Lemmings: 41, P95Ms: 1800, LimitMs: 2000, Pages: 120, Safety: 0.9}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", st.Mode().Perm())
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	in.Version = fileVersion
	if out != in {
		t.Fatalf("loaded %+v, want %+v", out, in)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestFileRejects(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	if err := Save(filepath.Join(dir, "c.json"), File{At: time.Now()}); err == nil {
		t.Fatal("saved host_cap 0")
	}
	for name, body := range map[string]string{
		"bad.json":     "{",
		"version.json": `{"version":9,"at":"2026-01-01T00:00:00Z","host_cap":3}`,
		"cap.json":     `{"version":1,"at":"2026-01-01T00:00:00Z","host_cap":0}`,
		"at.json":      `{"version":1,"host_cap":3}`,
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("%s loaded", name)
		}
	}
}
