# PR Specification: `github.com/andreimerlescu/sema` v1.2.0 — Non-Draining `SetCap` Shrink & Zero-Leak Waiter Queue

> **Execution guide:** Open a session in the `github.com/andreimerlescu/sema` repository (at `v1.1.0`) and execute this specification from top to bottom. Every change preserves **100% API and binary/source backward compatibility** for `github.com/andreimerlescu/room`, `concert`, and all downstream applications.

---

## 1. Problem Statement

In `sema v1.1.0`, occupancy is stored inside a buffered `chan struct{}` whose buffer length equals capacity (`len(ch) <= cap(ch)`). Because a Go channel cannot hold more elements than its capacity, `SetCap(c)` executes `s.drainLocked()` whenever `c < len(oldCh)` (`sema.go:702–708`):

1. **In-flight over-admission:** Shrinking `SetCap(4)` while `8` goroutines hold slots resets `Len()` to `0` and opens `4` brand-new slots immediately — allowing **`8 + 4 = 12` concurrent holders** (exceeding both the old and new ceilings).
2. **Spurious release errors:** All `8` in-flight holders receive `ErrReleaseExceedsCount` when they subsequently call `Release()`.
3. **Missed-wakeup & goroutine-per-waiter hazard in `AcquireWith` (`sema.go:76–103`):** Blocking acquires spawn a helper goroutine that calls `s.mu.Lock(); s.cond.Wait()` *after* the caller releases `s.mu`. A `Release()`/`Broadcast()` that runs between the caller's `Unlock()` and the helper's `Lock()` misses the wakeup.
4. **Partial-slot hold in `AcquireNWith` (`sema.go:304–330`):** Multi-slot acquires claim slots one by one while waiting for the rest, allowing two concurrent `AcquireN` callers to deadlock each other even when total capacity exceeds each individual request.

---

## 2. Backward-Compatibility Contract (Non-Negotiable)

Multiple production services depend on `sema` directly and transitively via `github.com/andreimerlescu/room`. The following invariants **MUST NOT** change:

- **Go toolchain floor:** Keep `go 1.21` in `go.mod` (zero new dependencies; stdlib only).
- **Exported `Semaphore` interface:** **Zero** added, removed, or altered methods on `type Semaphore interface` (so external mocks and wrappers continue compiling untouched).
- **Exported constructors & observer:** `New`, `NewWithObserver`, `Must`, and `Observer` signatures remain identical.
- **Exported error types & `errors.Is` / `errors.Unwrap`:** Keep all 8 types (`ErrInvalidCap`, `ErrInvalidN`, `ErrReleaseExceedsCount`, `ErrNoSlot`, `ErrAcquireCancelled`, `ErrDrain`, `ErrRecovered`, `ErrNExceedsCap`) unchanged.
- **Metric bounds:**
  - `Utilization()` and `UtilizationSmoothed()` **MUST remain clamped to `[0.0, 1.0]`** even while oversubscribed (`Len() > Cap()` during shrink drain). Downstream tests (including `room`'s `TestUtilization_BetweenZeroAndOne`) and Prometheus/autoscaler loops assume `0 <= u <= 1`.
  - `IsFull()` returns `Len() >= Cap()` (accurate while `Len() > Cap()` during shrink drain: any new acquire will block or fail).
  - `IsEmpty()` returns `Len() == 0`.
  - `ErrNoSlot.Available` clamps at `>= 0` (`max(0, cap - held)`), never negative.
- **Explicit `Drain()` & `Reset()`:** Retain exact existing forcible-clear semantics (`held = 0`, EWMA reset to `0`, wake `Wait()` callers first, then unblock waiting acquires).
- **`AcquireN(n)`:** Retain the `10*time.Minute` fallback timeout and `ErrNExceedsCap` check on entry (`n > cap`).
- **`Observer` locking contract:** Continue firing `OnAcquire(count, cap)` once per acquire call (including bulk `AcquireN`), `OnRelease(count, cap)` once per release call (including bulk `ReleaseN`), and `OnWaitStart()`/`OnWaitEnd(err)` around `Wait`, with zero observer calls on failed/cancelled acquires.
- **Zero heap allocations on the uncontended fast path:** `Acquire`/`Release`/`TryAcquire`/`Len`/`Cap`/`IsEmpty`/`IsFull`/`Utilization`/`UtilizationSmoothed` stay `0 B/op, 0 allocs/op`.

---

## 3. Core Design

Replace the backing `chan struct{}` + `sync.Cond` with:

1. **Mutex-guarded integer counters** (`held int`, `cap int`) + **atomic mirrors** (`heldAtom atomic.Int64`, `capAtom atomic.Int64`) for lock-free reads (`Len`, `Cap`, `IsEmpty`, `IsFull`, `Utilization`).
2. **Intrusive FIFO waiter list (`waiter` nodes)** under `s.mu`:
   ```go
   type waiter struct {
       n       int
       ready   chan struct{}
       granted bool
       prev    *waiter
       next    *waiter
   }
   ```
   - **Zero goroutines spawned** in `Acquire`, `AcquireWith`, `AcquireN`, `AcquireNWith`, or `Wait`.
   - **Zero missed wakeups:** Registration in `s.waiters` happens atomically under `s.mu` before unlocking; `Release`/`ReleaseN`/`SetCap`/`Drain`/`Reset` grants slots and closes `w.ready` under `s.mu`.
   - **Atomic multi-slot acquisition:** A waiter requesting `n` slots waits until `s.held + n <= s.cap`, then claims all `n` slots atomically — eliminating partial-acquisition deadlocks and rollback races.
   - **Safe shrink below waiting `AcquireN`:** When scanning `s.waiters` in `dispatchLocked()`:
     - If a waiter's `w.n > s.cap` (temporarily unsatisfiable after a shrink), skip over it rather than blocking smaller satisfiable waiters behind it; if `s.cap` later grows back to `>= w.n`, it wakes cleanly.
     - For satisfiable waiters (`w.n <= s.cap`), preserve strict FIFO order: stop at the first satisfiable waiter that cannot yet fit (`s.held + w.n > s.cap`) so large multi-slot requests cannot be starved by continuous 1-slot arrivals.
   - **Race-safe context cancellation:** If `ctx.Done()` is selected in `select { case <-w.ready: case <-ctx.Done(): }`, re-acquire `s.mu`:
     - If `w.granted` is already `true` (a concurrent `Release`/`SetCap` handed slots to `w` right as `ctx` fired), immediately return those `w.n` slots (`s.held -= w.n`), sync `heldAtom`, run `dispatchLocked()` + `notifyEmptyLocked()`, and return `ErrAcquireCancelled{Cause: ctx.Err()}` without firing `OnAcquire`.
     - If `w.granted` is `false`, unlink `w` from `s.waiters` and run `dispatchLocked()` (removing a blocked head waiter may unblock waiters behind it).
   - **Zero-goroutine `Wait(ctx)`:** Maintain a lazily allocated `emptyCh chan struct{}` under `s.mu`. Whenever `s.held == 0`, `notifyEmptyLocked()` closes and nils `s.emptyCh`. `Wait(ctx)` checks `s.held == 0` under `s.mu`, otherwise creates/grabs `ch := s.emptyCh`, unlocks, and selects on `<-ch` vs `<-ctx.Done()`.

### State Transitions on `SetCap(c)`

| Condition | Behavior in `v1.1.0` | Behavior in `v1.2.0` |
| --- | --- | --- |
| `c == -1` | Uses `defaultCap` (`10`) | Unchanged (`defaultCap = 10`) |
| `c < 1` (not `-1`) | Returns `ErrInvalidCap{Value: c}` | Unchanged |
| `c > held` (expand) | Copies `held` tokens into new channel, wakes waiters | Updates `cap = c`, updates EWMA, dispatches FIFO waiters up to `c` |
| `c == held` | Copies `held` tokens into new channel | Updates `cap = c`, updates EWMA; `IsFull() == true` |
| `c < held` (**shrink**) | **Drained `held` to `0`**, opened `c` extra slots, broke `Release()` | **Preserves `held` unchanged** (`Len() == held`, `Cap() == c`, `IsFull() == true`, `Utilization() == 1.0`). Blocks all new acquires until `held < c`. Existing holders' `Release()` succeeds cleanly. |

---

## 4. File-by-File Changes

### 4.1 `types.go`

1. Update doc comments on `Semaphore` and `Semaphore.SetCap` to document non-draining shrink semantics:
   - Shrinking `SetCap` below current occupancy preserves all held slots; no new slots are granted until occupancy drops below the new capacity, and existing holders release normally without `ErrReleaseExceedsCount`.
   - `Utilization` and `UtilizationSmoothed` remain clamped to `[0.0, 1.0]`.
   - `IsFull` reports `Len() >= Cap()`.
2. Update the unexported `semaphore` struct (keep all exported error types and the `Semaphore` interface **byte-for-byte identical in signature**):

```go
type waiter struct {
	n       int
	ready   chan struct{}
	granted bool
	prev    *waiter
	next    *waiter
}

type semaphore struct {
	mu       sync.Mutex
	held     int
	cap      int
	head     *waiter
	tail     *waiter
	emptyCh  chan struct{}
	heldAtom atomic.Int64
	capAtom  atomic.Int64
	ewma     atomic.Uint64
	observer Observer
}
```

### 4.2 `new.go`

Update `New(c int)` to initialize the counter fields instead of `sync.Cond` and `newChannel`:

```go
func New(c int) (Semaphore, error) {
	if c == -1 {
		c = defaultCap
	}
	if c < 1 {
		return nil, ErrInvalidCap{Value: c}
	}
	s := &semaphore{
		cap: c,
	}
	s.capAtom.Store(int64(c))
	return s, nil
}
```

### 4.3 `internal.go`

Remove the unused `newChannel` helper (keep `validateN` unchanged).

### 4.4 `private.go`

Replace channel helpers with counter, waiter-list, EWMA, and empty-notification helpers (all `*Locked` methods require `s.mu` held):

```go
package sema

import "math"

func (s *semaphore) notify(fn func(Observer)) {
	if s.observer != nil {
		fn(s.observer)
	}
}

func (s *semaphore) syncAtomicsLocked() {
	s.heldAtom.Store(int64(s.held))
	s.capAtom.Store(int64(s.cap))
}

func clampUtilization(held, capacity int) float64 {
	if capacity <= 0 || held <= 0 {
		return 0
	}
	u := float64(held) / float64(capacity)
	if u > 1.0 {
		return 1.0
	}
	return u
}

func (s *semaphore) updateEWMALocked() {
	current := clampUtilization(s.held, s.cap)
	for {
		old := math.Float64frombits(s.ewma.Load())
		next := ewmaAlpha*current + (1-ewmaAlpha)*old
		if s.ewma.CompareAndSwap(
			math.Float64bits(old),
			math.Float64bits(next),
		) {
			return
		}
	}
}

func (s *semaphore) resetEWMA() {
	s.ewma.Store(0)
}

func (s *semaphore) enqueueWaiterLocked(n int) *waiter {
	w := &waiter{
		n:     n,
		ready: make(chan struct{}),
	}
	if s.tail == nil {
		s.head = w
		s.tail = w
	} else {
		w.prev = s.tail
		s.tail.next = w
		s.tail = w
	}
	return w
}

func (s *semaphore) removeWaiterLocked(w *waiter) {
	if w.prev != nil {
		w.prev.next = w.next
	} else if s.head == w {
		s.head = w.next
	}
	if w.next != nil {
		w.next.prev = w.prev
	} else if s.tail == w {
		s.tail = w.prev
	}
	w.prev = nil
	w.next = nil
}

// hasSatisfiableWaiterLocked reports whether any queued waiter can fit within
// the current capacity (ignoring waiters temporarily larger than s.cap).
func (s *semaphore) hasSatisfiableWaiterLocked() bool {
	for w := s.head; w != nil; w = w.next {
		if w.n <= s.cap {
			return true
		}
	}
	return false
}

// dispatchLocked wakes queued waiters in FIFO order whose slot demands fit.
// Waiters whose request exceeds s.cap (after a shrink) are skipped so they
// cannot deadlock smaller waiters; the first satisfiable waiter that does not
// yet have enough free slots stops dispatch to preserve FIFO fairness.
func (s *semaphore) dispatchLocked() {
	for w := s.head; w != nil; {
		next := w.next
		if w.n > s.cap {
			w = next
			continue
		}
		if s.held+w.n > s.cap {
			return
		}
		s.removeWaiterLocked(w)
		s.held += w.n
		w.granted = true
		s.syncAtomicsLocked()
		close(w.ready)
		w = next
	}
}

func (s *semaphore) notifyEmptyLocked() {
	if s.held == 0 && s.emptyCh != nil {
		close(s.emptyCh)
		s.emptyCh = nil
	}
}

func (s *semaphore) availableLocked() int {
	if avail := s.cap - s.held; avail > 0 {
		return avail
	}
	return 0
}
```

### 4.5 `sema.go`

Implement all `Semaphore` methods cleanly on top of the counter + FIFO waiter list:

```go
func (s *semaphore) Acquire() {
	s.mu.Lock()
	if !s.hasSatisfiableWaiterLocked() && s.held+1 <= s.cap {
		s.held++
		s.syncAtomicsLocked()
		s.notify(func(o Observer) { o.OnAcquire(s.held, s.cap) })
		s.mu.Unlock()
		return
	}
	w := s.enqueueWaiterLocked(1)
	s.mu.Unlock()

	<-w.ready

	if s.observer != nil {
		s.mu.Lock()
		s.notify(func(o Observer) { o.OnAcquire(s.held, s.cap) })
		s.mu.Unlock()
	}
}

func (s *semaphore) AcquireWith(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ErrAcquireCancelled{Cause: ctx.Err()}
	default:
	}

	s.mu.Lock()
	if !s.hasSatisfiableWaiterLocked() && s.held+1 <= s.cap {
		s.held++
		s.syncAtomicsLocked()
		s.notify(func(o Observer) { o.OnAcquire(s.held, s.cap) })
		s.mu.Unlock()
		return nil
	}
	w := s.enqueueWaiterLocked(1)
	s.mu.Unlock()

	return s.awaitWaiter(ctx, w)
}

func (s *semaphore) awaitWaiter(ctx context.Context, w *waiter) error {
	select {
	case <-w.ready:
		if s.observer != nil {
			s.mu.Lock()
			s.notify(func(o Observer) { o.OnAcquire(s.held, s.cap) })
			s.mu.Unlock()
		}
		return nil
	case <-ctx.Done():
		s.mu.Lock()
		if w.granted {
			// Slots were handed to w right as ctx fired; return them cleanly.
			s.held -= w.n
			if s.held < 0 {
				s.held = 0
			}
			s.syncAtomicsLocked()
			s.notifyEmptyLocked()
			s.dispatchLocked()
			s.mu.Unlock()
			return ErrAcquireCancelled{Cause: ctx.Err()}
		}
		s.removeWaiterLocked(w)
		s.dispatchLocked()
		s.mu.Unlock()
		return ErrAcquireCancelled{Cause: ctx.Err()}
	}
}

func (s *semaphore) TryAcquire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hasSatisfiableWaiterLocked() || s.held+1 > s.cap {
		return false
	}
	s.held++
	s.syncAtomicsLocked()
	s.notify(func(o Observer) { o.OnAcquire(s.held, s.cap) })
	return true
}

func (s *semaphore) TryAcquireWith(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ErrAcquireCancelled{Cause: ctx.Err()}
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hasSatisfiableWaiterLocked() || s.held+1 > s.cap {
		return ErrNoSlot{Requested: 1, Available: s.availableLocked()}
	}
	s.held++
	s.syncAtomicsLocked()
	s.notify(func(o Observer) { o.OnAcquire(s.held, s.cap) })
	return nil
}

func (s *semaphore) Release() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.held < 1 {
		return ErrReleaseExceedsCount{Attempted: 1, Current: s.held}
	}
	s.held--
	s.syncAtomicsLocked()
	s.notify(func(o Observer) { o.OnRelease(s.held, s.cap) })
	s.updateEWMALocked()
	s.notifyEmptyLocked()
	s.dispatchLocked()
	return nil
}

func (s *semaphore) AcquireN(n int) error {
	if err := validateN(n); err != nil {
		return err
	}
	s.mu.Lock()
	if n > s.cap {
		c := s.cap
		s.mu.Unlock()
		return ErrNExceedsCap{Requested: n, Cap: c}
	}
	if !s.hasSatisfiableWaiterLocked() && s.held+n <= s.cap {
		s.held += n
		s.syncAtomicsLocked()
		s.notify(func(o Observer) { o.OnAcquire(s.held, s.cap) })
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return s.AcquireNWith(ctx, n)
}

func (s *semaphore) AcquireNWith(ctx context.Context, n int) error {
	if err := validateN(n); err != nil {
		return err
	}
	s.mu.Lock()
	if n > s.cap {
		c := s.cap
		s.mu.Unlock()
		return ErrNExceedsCap{Requested: n, Cap: c}
	}
	select {
	case <-ctx.Done():
		s.mu.Unlock()
		return ErrAcquireCancelled{Cause: ctx.Err()}
	default:
	}
	if !s.hasSatisfiableWaiterLocked() && s.held+n <= s.cap {
		s.held += n
		s.syncAtomicsLocked()
		s.notify(func(o Observer) { o.OnAcquire(s.held, s.cap) })
		s.mu.Unlock()
		return nil
	}
	w := s.enqueueWaiterLocked(n)
	s.mu.Unlock()

	return s.awaitWaiter(ctx, w)
}

// AcquireTimeout and AcquireNTimeout remain unchanged wrappers around
// AcquireWith and AcquireNWith.

func (s *semaphore) TryAcquireN(n int) bool {
	if err := validateN(n); err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > s.cap || s.hasSatisfiableWaiterLocked() || s.held+n > s.cap {
		return false
	}
	s.held += n
	s.syncAtomicsLocked()
	s.notify(func(o Observer) { o.OnAcquire(s.held, s.cap) })
	return true
}

func (s *semaphore) TryAcquireNWith(ctx context.Context, n int) error {
	if err := validateN(n); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ErrAcquireCancelled{Cause: ctx.Err()}
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > s.cap {
		return ErrNExceedsCap{Requested: n, Cap: s.cap}
	}
	if s.hasSatisfiableWaiterLocked() || s.held+n > s.cap {
		return ErrNoSlot{Requested: n, Available: s.availableLocked()}
	}
	s.held += n
	s.syncAtomicsLocked()
	s.notify(func(o Observer) { o.OnAcquire(s.held, s.cap) })
	return nil
}

func (s *semaphore) ReleaseN(n int) error {
	if err := validateN(n); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > s.held {
		return ErrReleaseExceedsCount{Attempted: n, Current: s.held}
	}
	s.held -= n
	s.syncAtomicsLocked()
	s.notify(func(o Observer) { o.OnRelease(s.held, s.cap) })
	s.updateEWMALocked()
	s.notifyEmptyLocked()
	s.dispatchLocked()
	return nil
}

func (s *semaphore) Wait(ctx context.Context) error {
	s.notify(func(o Observer) { o.OnWaitStart() })

	s.mu.Lock()
	if s.held == 0 {
		s.mu.Unlock()
		s.notify(func(o Observer) { o.OnWaitEnd(nil) })
		return nil
	}
	if s.emptyCh == nil {
		s.emptyCh = make(chan struct{})
	}
	ch := s.emptyCh
	s.mu.Unlock()

	select {
	case <-ch:
		s.notify(func(o Observer) { o.OnWaitEnd(nil) })
		return nil
	case <-ctx.Done():
		err := ErrAcquireCancelled{Cause: ctx.Err()}
		s.notify(func(o Observer) { o.OnWaitEnd(err) })
		return err
	}
}

func (s *semaphore) Drain() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.held = 0
	s.syncAtomicsLocked()
	s.resetEWMA()
	s.notifyEmptyLocked()
	s.dispatchLocked()
	return nil
}

func (s *semaphore) Reset() error {
	return s.Drain()
}

func (s *semaphore) Len() int {
	return int(s.heldAtom.Load())
}

func (s *semaphore) Cap() int {
	return int(s.capAtom.Load())
}

func (s *semaphore) Utilization() float64 {
	return clampUtilization(s.Len(), s.Cap())
}

func (s *semaphore) UtilizationSmoothed() float64 {
	return math.Float64frombits(s.ewma.Load())
}

func (s *semaphore) IsEmpty() bool {
	return s.Len() == 0
}

func (s *semaphore) IsFull() bool {
	return s.Len() >= s.Cap()
}

func (s *semaphore) SetCap(c int) error {
	if c == -1 {
		c = defaultCap
	}
	if c < 1 {
		return ErrInvalidCap{Value: c}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cap = c
	s.syncAtomicsLocked()
	s.updateEWMALocked()
	s.dispatchLocked()
	return nil
}
```

> **Subtle edge case check for `Drain()` + blocked waiters + `Wait()`:**
> Notice in `Drain()` we call `s.notifyEmptyLocked()` **before** `s.dispatchLocked()`, so any goroutine blocked in `Wait(ctx)` wakes cleanly as soon as `Drain()` empties the semaphore, while blocked `Acquire` waiters are then granted slots under the fresh occupancy.
>
> **Subtle edge case check for `AcquireNWith` when `TryAcquireNWith` fails with `ErrNExceedsCap` vs `ErrNoSlot`:**
> In `AcquireNWith`: `n > s.cap` is checked once at entry (matching `v1.1.0`). Check `TestTryAcquireNWith_CancelledContext` (`ctx.Done()` checked before `n > cap`, matching `v1.1.0:401–411`).

### 4.6 `sema_test.go`

1. **Update the two legacy drain-on-shrink tests** (`sema_test.go:1837–1901`):
   - Replace `TestSetCap_Shrink_LenIsZero` and `TestSetCap_Shrink_BelowCurrentLen` with tests asserting the **new non-draining guarantee**:
     - `AcquireN(8)` on `cap=10`, call `SetCap(4)`.
     - Assert `Cap() == 4`, `Len() == 8`, `IsEmpty() == false`, `IsFull() == true`.
     - Assert `Utilization() == 1.0` (strictly `<= 1.0`) and `UtilizationSmoothed() <= 1.0`.
     - Assert `TryAcquire() == false`, `TryAcquireWith(ctx)` returns `ErrNoSlot{Requested: 1, Available: 0}` (not negative!).
     - Release 4 slots (`8 → 4`): assert `Len() == 4`, `IsFull() == true`, `TryAcquire() == false`, zero `ErrReleaseExceedsCount` errors!
     - Release 1 more slot (`4 → 3`): assert `Len() == 3`, `IsFull() == false`, `TryAcquire() == true` (`Len() == 4`)!
     - Release remaining 4 slots: assert `Len() == 0`, `IsEmpty() == true`.
2. **Add new concurrency & invariant stress tests:**
   - `TestSetCap_ShrinkUnderLoad_StrictCeiling`: Start `cap=20`, hold 20 active workers, shrink `SetCap(4)`, spawn 50 additional contending goroutines calling `AcquireWith`/`TryAcquire` while gradually releasing the initial 20. Track `atomic.Int64` active worker count and assert:
     - **Peak concurrency never exceeds `20`** while initial holders drain;
     - **Zero new acquisitions succeed** while `active >= 4`;
     - Once initial 20 exit, **peak concurrency never exceeds `4`**;
     - Final `Len() == 0` and zero `Release()` errors.
   - `TestSetCap_ShrinkThenExpand_UnblocksWaiters`: Fill 8/10, shrink to 3, queue blocked `AcquireWith` + `AcquireNWith(4)` waiters, expand back to 12, verify both waiters unblock and acquire cleanly.
   - `TestSetCap_ShrinkBelowWaitingAcquireN_DoesNotBlockSmallerWaiters`: Fill 5/5, queue `AcquireNWith(4)` then `AcquireWith()`, shrink to 2, release 4 slots (`5 → 1`), verify the 1-slot waiter proceeds without deadlocking behind the 4-slot waiter.
   - `TestAcquireWith_CancelDuringHandOff_NoSlotLeak`: Hammer concurrent `AcquireWith(shortTimeout)` + `Release()` across 32 goroutines for 200ms and assert final `Len() == 0`.
   - `TestWait_ZeroGoroutineLeak`: Verify `runtime.NumGoroutine()` does not grow during 500 concurrent `Wait(ctx)` calls (zero helper goroutines spawned).
   - `FuzzConcurrentSetCapShrink`: Fuzz random mixes of `AcquireWith`, `TryAcquire`, `AcquireNWith`, `Release`, and `SetCap(shrink/expand)`, asserting `Utilization() in [0,1]`, `Release()` never errors on held slots, and final `Len() == 0`.

### 4.7 Documentation & Version

- `VERSION`: bump `v1.1.0` → `v1.2.0` (no trailing newline, matching existing file format).
- `README.md` & `TESTS.md`: update `SetCap` section and architecture notes to reflect non-draining shrink, FIFO waiter queue, zero-goroutine `Wait`/`AcquireWith`, and clamped `[0.0, 1.0]` utilization.

---

## 5. Verification Commands (Must All Pass Before Tagging `v1.2.0`)

```sh
gofmt -l .                                                  # expect empty
go vet ./...
go test -race -count=1 -v ./...
go test -race -count=20 -run 'TestSetCap_|TestAcquireWith_|TestWait_' ./...
make test-bench                                             # verify 0 allocs/op on AcquireRelease & TryAcquire
FUZZTIME=15s make test-fuzz                                 # all fuzz targets including new FuzzConcurrentSetCapShrink
```

### Release Checklist

1. Confirm `git diff` touches zero exported signatures on `Semaphore`, `Observer`, `New`, `NewWithObserver`, `Must`, or error types.
2. Confirm `go.mod` still declares `go 1.21` and has zero external dependencies.
3. Commit cleanly, tag `v1.2.0`, and push (`git tag v1.2.0 && git push origin main v1.2.0`).
4. Proceed to [ROOM-PR.md](ROOM-PR.md) in `github.com/andreimerlescu/room`.
