# Reserved checkout slots

**Status: Proposal.** Nothing here is implemented. It needs operator decisions on pricing, refunds, compliance and idle capacity before any code is written.

## The product

A fast-lane pass today buys *eligibility*: a paid request shares the bounded priority lane, and [FASTLANE.md](FASTLANE.md) says plainly that eligibility does not reserve capacity. When the lane is full, a paid form gets `fast_lane_busy` and a paid page request joins the line.

A **reserved checkout slot** would be a scarcer, higher-priced product: for the pass's duration, one origin slot belongs to the buyer. Their requests never wait and are never refused for capacity. Only a fixed number of these slots exists, sold first come, first served.

room v1.5.0's leases are the mechanism. `Acquire(key)` takes a slot that stays held until `Release(key)`, not until a handler returns. It is first come, first served through the same serving window as requests, safe when capacity shrinks (a smaller cap revokes nothing; it only stops new grants until enough leases are released), and kept across `Export`/`Import`.

## A separate pool

The reserved pool must be **its own `room.WaitingRoom`**, with its own cap (`-reserved-cap`), not leases taken from the main room:

- Leases in the main room come out of `-cap`. Every slot sold would be a slot taken from the free line, so selling reservations would make the free line slower. That is the opposite of how Concert treats people who don't pay.
- A separate room gives the origin a ceiling that can be stated and tested: **`cap + priority-cap + reserved`** page requests at once. An operator sizing PHP-FPM workers needs that number.
- A separate room keeps the main line's export at version 1. Only the reserved room's export becomes version 2.

Buying a reservation would call `reserved.Acquire("s:" + sessionID)`. If no slot is free, the sale does not happen. The buyer is not charged and is told the reserved slots are sold out. They can still buy an ordinary pass. Whether a sold-out reservation can be waited for in its own line is an operator decision. The default should be no.

## What a lease holder's requests bypass

A request from a session holding a reserved lease skips the main room's middleware and the priority lane. It is counted against the reserved room instead, with `SetTicketKeyFunc` on the reserved room so it takes no second slot.

It does not skip anything else. `identify` and bans still run first, and a ban releases the lease. The abuse registry, asset and stream tiers and the admission pass work as today. A lease is a reserved slot. It is never an unbounded bypass.

## Per-holder concurrency

A lease is one slot, but a checkout page makes several requests at once. Each holder's in-flight page requests need a cap (`-reserved-per-holder`, default 2). A small per-session semaphore enforces it. The cap is held by the session, and the origin ceiling above counts slots, so the true bound is `reserved × reserved-per-holder`. The documentation must say so, and the origin must be sized for it.

## Restart

`Close` already stops the room before it saves the queue. The reserved room would be exported beside `queue.snapshot`, as `reserved.snapshot`, in version 2 because leases are held. room older than v1.5.0 refuses a version 2 file rather than drop the leases and admit over capacity, so a rollback must delete that file deliberately. The lease TTL and pass expiry decide what is stale at import. A lease whose pass expired while Concert was down is released at once.

## How a lease ends

- **Pass expiry.** A receipt carries `expires`. room's `SetLeaseTTL` is one value for the whole room, measured from the grant or the last `Acquire`, with a minimum of one minute. Passes can be as short as 30 seconds. So Concert would `Release` each lease at its pass's expiry with a timer the app owns, and set `SetLeaseTTL` to the longest pass plus a margin as a backstop. A Concert bug then cannot hold a slot forever.
- **Ban** or **portal removal**: `Release`.
- **Refund**: `Release` before the refund is issued.
- Renewing a pass would call `Acquire` again, which renews the lease in place.

## Questions an operator must answer first

1. **Price and refunds.** A reserved slot is a promise of capacity. Is the buyer refunded, fully or pro rata, when the origin is down or slow during their reservation? Who decides that the origin was down, and from which signal?
2. **Idle capacity.** Unused reserved slots sit idle while the free line waits. Is that acceptable, or should idle reserved slots be lent to the line, and taken back when the holder returns?
3. **Outage behaviour.** If Concert restarts, holders keep their slots through the export. If the origin fails, reservations keep running down. Does the pass clock stop?
4. **Compliance.** [US_COMPLIANCE.md](US_COMPLIANCE.md) covers selling eligibility. Selling guaranteed capacity may change consumer-protection and refund obligations, and the terms page must describe it. `policy_url` screening applies to every reservation sale as to every pass.
5. **Scalping.** Reservations are scarce, so bots will try to buy them all. What limits apply: one per session, one per address, a per-payer limit from screening?

## Tests it would need

- The origin never sees more than `cap + priority-cap + reserved` page requests at once, with all three pools saturated.
- A sale with no free reserved slot charges nothing.
- A lease holder's requests skip the main line but are still banned, and a ban releases the lease.
- `-reserved-per-holder` bounds a holder's concurrent requests.
- A lease ends at pass expiry with no request in flight, and through the `SetLeaseTTL` backstop if the timer is disabled.
- Shrinking `-reserved-cap` below the held count revokes nothing and grants nothing until releases bring it under.
- `Export` writes version 2 with leases, `Import` restores them, and an expired pass's lease is released at import.
- The free line's order and speed are unchanged by reservations being sold.
