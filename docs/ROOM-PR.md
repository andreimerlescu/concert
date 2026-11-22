# PR Specification: `github.com/andreimerlescu/room` v1.6.0 — Non-Draining `SetCap` Shrink via `sema v1.2.0`

> **Execution guide:** Execute **after** `github.com/andreimerlescu/sema v1.2.0` (see [SEMA-PR.md](SEMA-PR.md)) is tagged and published (or via temporary local `replace` during pre-tag verification). Open a session in the `github.com/andreimerlescu/room` repository (at `v1.5.0`) and execute this specification from top to bottom.
>
> **Critical compatibility requirement:** Multiple production applications depend directly on `github.com/andreimerlescu/room`. This release maintains **100% API, cookie, HTTP endpoint, callback, and behavioral backward compatibility**.

---

## 1. Problem Statement

In `room v1.5.0` (which depends on `sema v1.1.0`):

1. **`SetCap(smaller)` over-admission & occupancy desync (`room.go:504–517`):**
   - `wr.SetCap(cap)` delegates to `wr.sem.SetCap(int(cap))`. On `sema v1.1.0`, shrinking below current in-flight requests drained the semaphore to `0`, allowing new arrivals/waiters to acquire up to `newCap` extra slots *on top of* the already in-flight requests (`oldUse + newCap` concurrent upstream requests!).
   - Simultaneously, `wr.Len()` (which returns `wr.sem.Len()`) dropped to `0` while `wr.occupancy` and `wr.Held()` stayed at `oldUse`, causing dashboards, autoscalers, and `wr.release()` (`wr.sem.Release()` silently returning `ErrReleaseExceedsCount`) to fall out of sync.
2. **Snapshot restore into smaller capacity (`persist.go:444–461`):**
   - When `restoreLeases` restores `L` persisted leases into a room initialized with `cap < L`, `for range leases { wr.sem.TryAcquire(); wr.occupancy.Add(1) }` only acquired `cap` semaphore slots while adding `L` to `wr.occupancy` and `wr.leases`, leaving `wr.sem.Len() != wr.occupancy` until `L - cap` leases expired/released.

---

## 2. Why `room`'s Serving Window Aligns 1:1 with `sema v1.2.0`

Auditing `room v1.5.0` proves that `room`'s ticket arithmetic and lifecycle events already match non-draining `sema.SetCap` mathematically:

- **Serving window (`room.go:402–404`):** `ticketReady(ticket)` checks `ticket <= nowServing + cap`.
  - Suppose `cap = 10`, `10` requests are in flight (`nowServing = 0`, `nextTicket = 10`, `sem.Len() = 10`), and ticket `11` is queued.
  - Operator calls `wr.SetCap(4)`: `wr.sem.SetCap(4)` keeps `sem.Len() = 10, sem.Cap() = 4`; `wr.cap.Store(4)` sets `windowEdge = 0 + 4 = 4`.
  - As the first `6` in-flight requests complete: `nowServing` advances `0 → 6`, `windowEdge = 6 + 4 = 10` (`ticket 11` still not ready), `sem.Len()` steps `10 → 4` (still full).
  - When the `7th` in-flight request completes: `nowServing = 7`, `windowEdge = 7 + 4 = 11` (`ticket 11` becomes ready), `sem.Len()` drops `4 → 3 < 4` (slot #4 opens at the **exact same instant**!).
- **Edge-triggered `EventDrain` (`room.go:312–315`):**
  - `wr.exit()` checks `wr.occupancy.Add(-1) == capacity - 1`.
  - During the drain from `10 → 4`, `occupancy` steps `9, 8, 7, 6, 5, 4` (`!= 3`).
  - On the transition `4 → 3`, `wr.occupancy.Add(-1) == 3 == 4 - 1` fires `EventDrain` **once**, at the exact moment a real slot opens under the new cap!
- **Utilization range (`room.go:560–570`, `status.go:162`):**
  - Because `sema v1.2.0` clamps `Utilization()` and `UtilizationSmoothed()` to `[0.0, 1.0]`, `wr.Utilization()`, `wr.UtilizationSmoothed()`, and `/queue/status` JSON responses stay strictly in `[0.0, 1.0]` even while `wr.Len() > int(wr.Cap())`.

---

## 3. Backward-Compatibility Contract (Non-Negotiable)

- **Zero exported API changes:** Every method signature on `WaitingRoom`, every struct (`Snapshot`, `TicketInfo`, `StatusResponse`, `QueueSnapshot`), every callback event (`EventEnter`, `EventExit`, `EventFull`, `EventDrain`, `EventQueue`, `EventPromote`, `EventTimeout`, `EventLease`, `EventRelease`, `EventLeaseExpire`), every error type, and every cookie/route stays **100% identical**.
- **Existing tests pass untouched:** Every single test in `room_test.go`, `callback_test.go`, `cookie_test.go`, `grace_test.go`, `keyed_test.go`, `ledger_test.go`, `persist_test.go`, `promote_test.go`, `queue_test.go`, `rank_test.go`, `reaper_test.go`, `remove_test.go`, and `status_test.go` MUST pass without loosening any assertion.
- **No Go version bump beyond what's already required:** Keep `go.mod` compatible (update only `github.com/andreimerlescu/sema v1.2.0`, running `go mod tidy` and verifying minimal diff).

---

## 4. File-by-File Changes

### 4.1 `go.mod` & `go.sum`

Upgrade `sema`:

```sh
go get github.com/andreimerlescu/sema@v1.2.0
go mod tidy
```

Confirm `git diff go.mod` changes **only** the `github.com/andreimerlescu/sema` version line from `v1.1.0` to `v1.2.0`.

### 4.2 `persist.go` (`restoreLeases`, lines 440–461)

Ensure restoring `L > cap` persisted leases records all `L` slots in `wr.sem` via non-draining `SetCap` so `wr.Len()`, `wr.occupancy`, and `wr.Held()` stay 100% synchronized across restarts into a smaller capacity:

```go
// restoreLeases installs leases as tickets 1..L, already admitted. Their
// times move forward by the downtime, so it is not charged against a
// lease TTL. When L exceeds the room's configured capacity, the semaphore
// temporarily expands to absorb all L slots and immediately shrinks back
// to cap (sema v1.2.0 preserves held slots on shrink), keeping wr.Len(),
// wr.Held(), and wr.occupancy identical.
func (wr *WaitingRoom) restoreLeases(leases []persistedLease, shift time.Duration) {
	if len(leases) == 0 {
		return
	}
	wr.leaseMu.Lock()
	for i, l := range leases {
		wr.leases[l.Key] = leaseEntry{
			ticket:     int64(i + 1),
			acquiredAt: l.AcquiredAt.Add(shift),
			renewedAt:  l.RenewedAt.Add(shift),
		}
	}
	wr.leaseMu.Unlock()

	curCap := int(wr.cap.Load())
	if len(leases) > curCap {
		_ = wr.sem.SetCap(len(leases))
		for range leases {
			wr.sem.TryAcquire()
			wr.occupancy.Add(1)
		}
		_ = wr.sem.SetCap(curCap)
		return
	}
	for range leases {
		wr.sem.TryAcquire()
		wr.occupancy.Add(1)
	}
}
```

### 4.3 `room.go` & `lease.go` (Doc Comments Only)

1. `room.go:495–500` (`SetCap` doc comment):
   Replace `"Shrinking drains in-flight work via the underlying sema implementation."` with:
   `"Shrinking preserves all in-flight requests and leases; no new slot is granted until occupancy drops below the new capacity, so the room never over-admits during a shrink."`
2. `lease.go:23–30` (`# Capacity changes` comment):
   Update to reflect that both the serving window **and** the underlying semaphore (`sema v1.2.0`) now preserve held slots when shrunk below `Held()`, keeping `Len()` and `Held()` aligned at every step.

### 4.4 New Regression & Stress Tests

Add to `room_test.go` (and `keyed_test.go` / `persist_test.go`):

1. **`TestSetCap_ShrinkPreservesInFlightCeiling` (`room_test.go`):**
   - Initialize `WaitingRoom` with `cap = 10`.
   - Hold 10 concurrent HTTP requests inside the origin handler (using a barrier + release channel) and verify `wr.Len() == 10`.
   - Call `wr.SetCap(3)`.
   - Assert immediately: `wr.Cap() == 3`, `wr.Len() == 10`, `wr.Utilization() == 1.0`, `wr.UtilizationSmoothed() <= 1.0`.
   - Send 20 concurrent new requests (both fast-path arrivals and queued clients polling `/queue/status` and reloading once `ready == true`).
   - Release the initial 10 holders one by one while tracking `active` and `peak` inside the origin handler with `atomic.Int32`:
     - Assert **zero** new requests enter the origin while `active >= 3` (first 7 releases bring `active` from `10 → 3`).
     - Assert **overall peak never exceeds `10`** during drain.
     - Once initial 10 have finished, assert **peak among the 20 new requests never exceeds `3`**.
     - Assert final `wr.Len() == 0` and `wr.occupancy.Load() == 0`.
2. **`TestSetCap_ShrinkEventDrainFiresOnce` (`room_test.go`):**
   - Fill `cap = 6`, register `EventDrain` collector, shrink `wr.SetCap(2)`.
   - Release 4 holders (`6 → 2`): assert `EventDrain` count is still `0`.
   - Release 5th holder (`2 → 1`): assert `EventDrain` fires **exactly once**.
   - Release 6th holder (`1 → 0`): assert `EventDrain` count remains `1`.
3. **Extend `TestSetCap_BelowHeld` (`keyed_test.go:681–712`):**
   - After `wr.SetCap(2)` with 5 leases held, also assert `wr.Len() == 5` (previously `0` on `sema v1.1.0`!).
   - After each release of `h0, h1, h2`, assert `wr.Len() == int(wr.Held())` (`4, 3, 2`).
   - After releasing `h3` and granting `"w"`, assert `wr.Len() == 2 && wr.Held() == 2`.
4. **`TestRestoreLeases_SmallerCapPreservesSemLen` (`persist_test.go`):**
   - Acquire 5 leases on `cap = 5`, export snapshot, import into a fresh `WaitingRoom` initialized with `cap = 2`.
   - Assert `wr.Held() == 5`, `wr.Len() == 5`, `wr.Cap() == 2`, `wr.Utilization() == 1.0`.
   - Verify no new request or lease is admitted until 4 leases are released (`5 → 1`).

### 4.5 Documentation & Version

- `VERSION`: bump `1.5.0` → `1.6.0` (note: `room/VERSION` uses `1.5.0` without leading `v`).
- `README.md`: update `SetCap` documentation to highlight zero-over-admission graceful shrinking as a first-class feature.

---

## 5. Verification Commands (Must All Pass Before Tagging `v1.6.0`)

```sh
gofmt -l .                                                  # expect empty
go vet ./...
go test -count=1 -v ./...
go test -race -count=1 ./...
go test -race -count=10 -run 'TestSetCap_|TestConcurrent_SetCap|TestRestoreLeases_' ./...
make test-fuzz                                              # 30s FuzzWaitingRoom
make bench
```

### Downstream Compatibility Smoke Test (Before Tagging)

Verify `concert` (and any other local app depending on `room`) compiles and passes `-race` against the new `room` + `sema` using a temporary `go.work` (do **not** commit `go.work`):

```sh
# From a temp workspace directory or concert with temporary replace:
go test -race -count=1 ./...
```

### Release Checklist

1. Confirm zero breaking changes to any exported `room` type, method, event, cookie, or HTTP response.
2. Commit cleanly, tag `v1.6.0`, and push (`git tag v1.6.0 && git push origin main v1.6.0`).
3. Return to `concert`:
   - `go get github.com/andreimerlescu/sema@v1.2.0 github.com/andreimerlescu/room@v1.6.0 && go mod tidy`
   - Drop the `SafeShrink` step-down workaround (or retain `capacity.SafeShrink` only if needed for compatibility), add `TestSetCap_ShrinkUnderLoad` in `concert`, and resume Concert `v0.3.0` Phases 2–6!
