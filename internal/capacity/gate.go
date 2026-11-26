// Package capacity decides how much traffic a Concert node lets through to
// what is behind it.
//
// A leaf protects its host with a Gate: one ceiling shared by trust-chain
// (hop) traffic from an edge and direct traffic from the public, where hop
// traffic is served first (paid and high-rank hop traffic before the rest)
// and direct traffic gets whatever remains. An edge
// sizes its waiting room with a Planner from what its leaves report. The
// ceiling itself comes from a capacity File written by the benchmark.
package capacity

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// Class is a Gate's traffic class. Lower values are served first.
type Class int

const (
	HopPriority Class = iota // hop traffic the edge ranked into its lane, or paid
	Hop                      // other hop traffic admitted by an edge
	Direct                   // the leaf's own traffic: its room, lane and forms
	numClasses
)

// Gate is a resizable counting semaphore with strictly ordered classes: a
// freed slot goes to the longest-waiting HopPriority request, then Hop, then
// Direct. Within a class, waiters are served first come, first served.
//
// Shrinking never revokes a slot: holders finish, and no new slot is granted
// until usage is under the new ceiling. Safe for concurrent use.
type Gate struct {
	mu      sync.Mutex
	cap     int
	inUse   [numClasses]int
	waiters [numClasses]*list.List // of *waiter
}

type waiter struct {
	ch      chan struct{}
	granted bool
}

// NewGate returns a gate admitting at most n requests at once (n < 1 is
// treated as 1).
func NewGate(n int) *Gate {
	if n < 1 {
		n = 1
	}
	g := &Gate{cap: n}
	for i := range g.waiters {
		g.waiters[i] = list.New()
	}
	return g
}

func (g *Gate) usedLocked() int {
	n := 0
	for _, v := range g.inUse {
		n += v
	}
	return n
}

// mayTakeLocked reports whether class c can take a free slot now without
// jumping a waiter that outranks it or arrived first in its own class.
func (g *Gate) mayTakeLocked(c Class) bool {
	if g.usedLocked() >= g.cap {
		return false
	}
	for k := Class(0); k <= c; k++ {
		if g.waiters[k].Len() > 0 {
			return false
		}
	}
	return true
}

// TryAcquire takes a slot for class c if one is free right now.
func (g *Gate) TryAcquire(c Class) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.mayTakeLocked(c) {
		g.inUse[c]++
		return true
	}
	return false
}

// Acquire takes a slot for class c, waiting at most wait (0 means do not
// wait) or until ctx is done. It reports whether a slot was taken; every
// true must be paired with one Release(c).
func (g *Gate) Acquire(ctx context.Context, c Class, wait time.Duration) bool {
	g.mu.Lock()
	if g.mayTakeLocked(c) {
		g.inUse[c]++
		g.mu.Unlock()
		return true
	}
	if wait <= 0 {
		g.mu.Unlock()
		return false
	}
	w := &waiter{ch: make(chan struct{})}
	el := g.waiters[c].PushBack(w)
	g.mu.Unlock()

	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-w.ch:
		return true
	case <-t.C:
	case <-ctx.Done():
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if w.granted {
		// Granted while we were timing out: the slot is ours already.
		return true
	}
	g.waiters[c].Remove(el)
	// Our leaving may let someone behind us take a slot that was free
	// but reserved for us by order.
	g.grantLocked()
	return false
}

// Release returns a slot taken for class c.
func (g *Gate) Release(c Class) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inUse[c] > 0 {
		g.inUse[c]--
	}
	g.grantLocked()
}

// grantLocked hands free slots to waiters in class order.
func (g *Gate) grantLocked() {
	for g.usedLocked() < g.cap {
		var w *waiter
		var c Class
		for k := Class(0); k < numClasses; k++ {
			if front := g.waiters[k].Front(); front != nil {
				w = g.waiters[k].Remove(front).(*waiter)
				c = k
				break
			}
		}
		if w == nil {
			return
		}
		w.granted = true
		g.inUse[c]++
		close(w.ch)
	}
}

// SetCap changes the ceiling (n < 1 is treated as 1). Growing wakes
// waiters; shrinking revokes nothing.
func (g *Gate) SetCap(n int) {
	if n < 1 {
		n = 1
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cap = n
	g.grantLocked()
}

// Cap is the current ceiling.
func (g *Gate) Cap() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cap
}

// InUse is the number of slots class c holds.
func (g *Gate) InUse(c Class) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inUse[c]
}

// Waiting is the number of class c requests waiting for a slot.
func (g *Gate) Waiting(c Class) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.waiters[c].Len()
}
