package bidding

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// EpochResult captures the deterministic outcome of clearing one sealed-bid
// epoch for a scope.
type EpochResult struct {
	AuctionID          string      `json:"auction_id"`
	Scope              string      `json:"scope"`
	StartedAt          time.Time   `json:"started_at"`
	ClearedAt          time.Time   `json:"cleared_at"`
	Slots              int         `json:"slots"`
	TotalBids          int         `json:"total_bids"`
	Winners            []BidRecord `json:"winners"`
	SettlementFailures []BidRecord `json:"settlement_failures,omitempty"`
	Losers             []BidRecord `json:"losers,omitempty"`
}

// JournalEntry is one secret-free JSON line appended to the durable 0600
// bidding journal after an epoch clears or an instant-buy completes.
// Raw PaymentPayload bytes are never persisted in the journal.
type JournalEntry struct {
	Type               string      `json:"type"`
	Timestamp          time.Time   `json:"timestamp"`
	Scope              string      `json:"scope"`
	AuctionID          string      `json:"auction_id,omitempty"`
	Slots              int         `json:"slots,omitempty"`
	TotalBids          int         `json:"total_bids,omitempty"`
	Winners            []BidRecord `json:"winners,omitempty"`
	SettlementFailures []BidRecord `json:"settlement_failures,omitempty"`
	LoserCount         int         `json:"loser_count"`
}

// Journal appends fsync'd JSON-lines epoch and settlement records to a 0600
// file on disk.
//
// All methods are safe for concurrent use; file writes and closes are guarded
// by mu.
type Journal struct {
	mu     sync.Mutex
	path   string
	file   *os.File
	closed bool
}

// OpenJournal creates parent directories (mode 0700) and opens or creates a
// durable append-only JSONL journal file with strict 0600 permissions.
//
// # Parameters
//
//   - path: Non-empty filesystem path to the JSONL journal file.
//
// # Returns
//
// An open *Journal, or an error if path is empty or the file cannot be opened
// or secured. Callers must call [Journal.Close] to flush and release the file
// descriptor.
//
// # Example
//
//	j, err := OpenJournal(filepath.Join(dir, "bidding.jsonl"))
//	if err != nil {
//		return err // inside a function returning error
//	}
//	defer j.Close()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:564 (direct call)
//   - internal/bidding/auction.go:564 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func OpenJournal(path string) (*Journal, error) {
	cleaned := strings.TrimSpace(path)
	if cleaned == "" {
		return nil, fmt.Errorf("%w: journal path is empty", ErrInvalidConfig)
	}
	dir := filepath.Dir(cleaned)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create journal directory %q: %w", dir, err)
	}
	f, err := os.OpenFile(cleaned, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open journal %q: %w", cleaned, err)
	}
	// Explicitly enforce 0600 even when the file already existed with wider bits.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("chmod journal %q: %w", cleaned, err)
	}
	return &Journal{
		path: cleaned,
		file: f,
	}, nil
}

// Append marshals entry as a single JSON line, appends it atomically under
// j.mu, and calls Sync to persist it to disk.
//
// # Parameters
//
//   - entry: Secret-free [JournalEntry] to persist. Timestamp defaults to
//     current UTC time if zero.
//
// # Returns
//
// nil on durable persistence, or an error if the journal is closed or the
// write/sync fails. Safe for concurrent use.
//
// # Example
//
//	err := journal.Append(JournalEntry{
//		Type:      "epoch_cleared",
//		Timestamp: time.Now().UTC(),
//		Scope:     "site:drop",
//	})
//	if err != nil {
//		return err // inside a function returning error
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:1273 (direct call)
//   - internal/bidding/auction.go:1273 (function value)
//   - internal/bidding/clear.go:423 (direct call)
//   - internal/bidding/clear.go:423 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (j *Journal) Append(entry JournalEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	} else {
		entry.Timestamp = entry.Timestamp.UTC()
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal journal entry: %w", err)
	}
	line = append(line, '\n')

	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.file == nil {
		return ErrEngineClosed
	}
	n, err := j.file.Write(line)
	if err != nil {
		return fmt.Errorf("write journal %q: %w", j.path, err)
	}
	if n != len(line) {
		return fmt.Errorf("short write to journal %q: wrote %d of %d bytes", j.path, n, len(line))
	}
	if err := j.file.Sync(); err != nil {
		return fmt.Errorf("sync journal %q: %w", j.path, err)
	}
	return nil
}

// Close syncs and closes the underlying journal file. Repeated calls are safe
// and return nil after the first close.
//
// # Parameters
//
// None.
//
// # Returns
//
// Any error from syncing or closing the file descriptor. Safe for concurrent
// use.
//
// # Example
//
//	if err := journal.Close(); err != nil {
//		return err // inside a function returning error
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/clear.go:859 (direct call)
//   - internal/bidding/clear.go:859 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	if j.file == nil {
		return nil
	}
	f := j.file
	j.file = nil
	syncErr := f.Sync()
	closeErr := f.Close()
	return errors.Join(syncErr, closeErr)
}

// ClearEpoch deterministically clears the active sealed-bid epoch for scope.
//
// Pending verified bids are sorted by:
//  1. NormalizedMicroUSD DESC
//  2. WaitDuration DESC (longest-waiting agent wins ties)
//  3. ReceivedAt ASC
//  4. BidID ASC
//
// The engine attempts on-chain settlement via [PaymentSettler.Settle] ONLY on
// the top K = SlotsPerEpoch candidates, using a bounded per-winner timeout. If
// a selected winner fails settlement, the next ranked runner-up is promoted
// until K winners settle or candidates are exhausted. All remaining losing bids
// are dropped unsettled (losers pay $0, zero custody, zero refunds).
//
// # Parameters
//
//   - ctx: Controls cancellation and deadlines for winner settlement. Must be
//     non-nil.
//   - scope: Scope identifier whose active epoch should be cleared.
//   - now: Clearing timestamp (defaults to engine clock if zero).
//
// # Returns
//
// The deterministic [EpochResult] and any journal persistence error. If scope
// has no active epoch or no pending bids, returns an empty EpochResult and nil.
// Safe for concurrent use; holds e.mu only to detach the epoch and publish
// final bid statuses, never during settlement or journal I/O (C4).
//
// # Example
//
//	res, err := engine.ClearEpoch(ctx, "site:drop", time.Now().UTC())
//	if err != nil {
//		return err // inside a function returning error
//	}
//	_ = len(res.Winners)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:786 (direct call)
//   - internal/bidding/bidding_test.go:925 (direct call)
//   - internal/bidding/bidding_test.go:1048 (direct call)
//   - internal/bidding/bidding_test.go:1200 (direct call)
//   - internal/bidding/bidding_test.go:1378 (direct call)
//   - internal/bidding/bidding_test.go:1499 (direct call)
//   - internal/bidding/bidding_test.go:1718 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) ClearEpoch(ctx context.Context, scope string, now time.Time) (EpochResult, error) {
	if ctx == nil {
		return EpochResult{}, fmt.Errorf("%w: context must not be nil", ErrInvalidBid)
	}
	s := strings.TrimSpace(scope)
	if s == "" {
		return EpochResult{}, fmt.Errorf("%w: scope is required", ErrInvalidBid)
	}
	if now.IsZero() {
		now = e.now().UTC()
	} else {
		now = now.UTC()
	}

	// Atomically detach the active epoch under e.mu so new bids open a fresh
	// epoch while settlement runs unlocked (C4).
	e.mu.Lock()
	ep, ok := e.epochs[s]
	if ok {
		delete(e.epochs, s)
	}
	e.mu.Unlock()

	if !ok {
		return EpochResult{
			Scope:     s,
			ClearedAt: now,
			Slots:     e.cfg.SlotsPerEpoch,
		}, nil
	}
	return e.clearDetachedEpoch(ctx, ep, now)
}

// clearDetachedEpoch ranks, settles winners (with runner-up promotion), drops
// losers unsettled, updates status history, and appends to the journal for a
// single epoch already removed from e.epochs.
//
// # Parameters
//
//   - ctx: Parent context for winner settlements.
//   - ep: Detached *scopeEpoch owned exclusively by this call.
//   - now: Clearing timestamp in UTC.
//
// # Returns
//
// Completed EpochResult and any journal append error.
//
// # Example
//
//	// Internal helper called by ClearEpoch and background epoch draining.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/clear.go:302 (direct call)
//   - internal/bidding/clear.go:302 (function value)
//   - internal/bidding/clear.go:660 (direct call)
//   - internal/bidding/clear.go:660 (function value)
//   - internal/bidding/clear.go:854 (direct call)
//   - internal/bidding/clear.go:854 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) clearDetachedEpoch(ctx context.Context, ep *scopeEpoch, now time.Time) (EpochResult, error) {
	res := EpochResult{
		AuctionID: ep.auctionID,
		Scope:     ep.scope,
		StartedAt: ep.startedAt,
		ClearedAt: now,
		Slots:     e.cfg.SlotsPerEpoch,
		TotalBids: len(ep.byAgent),
	}
	if len(ep.byAgent) == 0 {
		e.epochsCleared.Add(1)
		return res, nil
	}

	candidates := make([]*pendingBid, 0, len(ep.byAgent))
	for _, b := range ep.byAgent {
		candidates = append(candidates, b)
	}
	// Deterministic ranking:
	// (NormalizedMicroUSD DESC, WaitDuration DESC, ReceivedAt ASC, BidID ASC).
	slices.SortFunc(candidates, comparePendingBids)

	winners := make([]BidRecord, 0, min(e.cfg.SlotsPerEpoch, len(candidates)))
	var failures []BidRecord
	losers := make([]BidRecord, 0, max(0, len(candidates)-e.cfg.SlotsPerEpoch))

	for _, cand := range candidates {
		if len(winners) < e.cfg.SlotsPerEpoch {
			if ctx.Err() != nil {
				// Context cancelled before settling this candidate: drop unsettled
				// so no partial/unwanted settlement is attempted after cancellation.
				losers = append(losers, makeBidRecord(ep.auctionID, cand, BidStatusLost, "", "", "epoch_cancelled", now))
				continue
			}
			sReceipt, err := e.settleWinner(ctx, cand.submission)
			if err == nil && sReceipt.Settled {
				rec := makeBidRecord(ep.auctionID, cand, BidStatusSettled, firstNonEmpty(sReceipt.Payer, cand.payer), sReceipt.Transaction, "", now)
				winners = append(winners, rec)
				continue
			}
			reason := firstNonEmpty(sReceipt.ErrorReason, "settlement_failed")
			if err != nil && sReceipt.ErrorReason == "" {
				reason = err.Error()
			}
			// Winner failed settlement: record failure and continue loop so the
			// next ranked runner-up is promoted into the open slot.
			failures = append(failures, makeBidRecord(ep.auctionID, cand, BidStatusSettlementFailed, firstNonEmpty(sReceipt.Payer, cand.payer), sReceipt.Transaction, reason, now))
			continue
		}
		// Losing bids are NEVER passed to PaymentSettler.Settle (losers pay $0).
		losers = append(losers, makeBidRecord(ep.auctionID, cand, BidStatusLost, cand.payer, "", "outbid", now))
	}

	res.Winners = winners
	res.SettlementFailures = failures
	res.Losers = losers

	e.mu.Lock()
	for _, r := range winners {
		e.history.Put(r)
	}
	for _, r := range failures {
		e.history.Put(r)
	}
	for _, r := range losers {
		e.history.Put(r)
	}
	e.mu.Unlock()

	e.epochsCleared.Add(1)
	e.winnersSettled.Add(int64(len(winners)))
	e.settlementFailures.Add(int64(len(failures)))
	e.losersDropped.Add(int64(len(losers)))

	var jerr error
	if e.journal != nil {
		entry := JournalEntry{
			Type:               "epoch_cleared",
			Timestamp:          now,
			Scope:              ep.scope,
			AuctionID:          ep.auctionID,
			Slots:              e.cfg.SlotsPerEpoch,
			TotalBids:          res.TotalBids,
			Winners:            winners,
			SettlementFailures: failures,
			LoserCount:         len(losers),
		}
		if err := e.journal.Append(entry); err != nil {
			jerr = fmt.Errorf("append epoch journal %q: %w", ep.auctionID, err)
		}
	}
	return res, jerr
}

// comparePendingBids defines the total deterministic ordering for sealed-bid
// epoch clearing:
// (NormalizedMicroUSD DESC, WaitDuration DESC, ReceivedAt ASC, BidID ASC).
//
// # Parameters
//
//   - a: First pending bid candidate.
//   - b: Second pending bid candidate.
//
// # Returns
//
// Negative if a ranks ahead of b, positive if b ranks ahead of a, zero if equal.
//
// # Example
//
//	// Used with slices.SortFunc(candidates, comparePendingBids).
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/clear.go:356 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func comparePendingBids(a, b *pendingBid) int {
	if c := cmp.Compare(b.submission.NormalizedMicroUSD, a.submission.NormalizedMicroUSD); c != 0 {
		return c
	}
	if c := cmp.Compare(b.wait, a.wait); c != 0 {
		return c
	}
	if a.submission.ReceivedAt.Before(b.submission.ReceivedAt) {
		return -1
	}
	if b.submission.ReceivedAt.Before(a.submission.ReceivedAt) {
		return 1
	}
	return cmp.Compare(a.submission.BidID, b.submission.BidID)
}

// settleWinner executes PaymentSettler.Settle for a single selected winner
// under a bounded per-winner timeout context so deferred cancellation runs on
// every loop iteration (E2).
//
// # Parameters
//
//   - ctx: Parent clearing or instant-buy context.
//   - bid: Winning BidSubmission whose PaymentPayload is cloned before handoff.
//
// # Returns
//
// The SettleReceipt and any settlement error.
//
// # Example
//
//	// Internal helper called only for winning or instant-buy bids.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:1223 (direct call)
//   - internal/bidding/auction.go:1223 (function value)
//   - internal/bidding/clear.go:370 (direct call)
//   - internal/bidding/clear.go:370 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) settleWinner(ctx context.Context, bid BidSubmission) (SettleReceipt, error) {
	sctx, cancel := context.WithTimeout(ctx, e.cfg.SettleTimeout)
	defer cancel()
	bid.PaymentPayload = bytes.Clone(bid.PaymentPayload)
	return e.settler.Settle(sctx, bid)
}

// makeBidRecord constructs an immutable, secret-free BidRecord from a pending
// bid and its clearing outcome.
//
// # Parameters
//
//   - auctionID: Epoch identifier.
//   - cand: Source pendingBid.
//   - status: Terminal BidStatus.
//   - payer: Resolved payer address.
//   - tx: Settled transaction hash (empty unless settled).
//   - reason: Optional machine-readable status reason.
//   - updatedAt: Timestamp of the status transition.
//
// # Returns
//
// Populated BidRecord value.
//
// # Example
//
//	// Internal helper called during clearDetachedEpoch.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/clear.go:367 (direct call)
//   - internal/bidding/clear.go:367 (function value)
//   - internal/bidding/clear.go:372 (direct call)
//   - internal/bidding/clear.go:372 (function value)
//   - internal/bidding/clear.go:382 (direct call)
//   - internal/bidding/clear.go:382 (function value)
//   - internal/bidding/clear.go:386 (direct call)
//   - internal/bidding/clear.go:386 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func makeBidRecord(auctionID string, cand *pendingBid, status BidStatus, payer, tx, reason string, updatedAt time.Time) BidRecord {
	return BidRecord{
		BidID:              cand.submission.BidID,
		AuctionID:          auctionID,
		AgentKey:           cand.submission.AgentKey,
		Scope:              cand.submission.Scope,
		Chain:              cand.submission.Chain,
		Asset:              cand.submission.Asset,
		AmountAtomic:       cand.submission.AmountAtomic,
		NormalizedMicroUSD: cand.submission.NormalizedMicroUSD,
		Status:             status,
		Payer:              payer,
		Transaction:        tx,
		PolicyID:           cand.policyID,
		Reason:             reason,
		WaitDuration:       cand.wait,
		QueuedAt:           cand.submission.QueuedAt,
		ReceivedAt:         cand.submission.ReceivedAt,
		UpdatedAt:          updatedAt,
	}
}

// Start launches the single background epoch clearing goroutine owned by e.
//
// Ownership and lifecycle (C1/R2): Start spawns at most one goroutine that
// sleeps until the earliest active epoch's ClosesAt timestamp, clears expired
// epochs, and exits when ctx is cancelled or [Engine.Close] is called. Calling
// [Engine.Close] joins this goroutine and drains any remaining active epochs
// before returning.
//
// # Parameters
//
//   - ctx: Parent context controlling background execution. Must be non-nil.
//
// # Returns
//
// nil on successful start, [ErrAlreadyStarted] if already started,
// [ErrEngineClosed] if closed, or [ErrInvalidBid] if ctx is nil. Safe for
// concurrent use.
//
// # Example
//
//	if err := engine.Start(ctx); err != nil {
//		return err // inside a function returning error
//	}
//	defer engine.Close()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:1566 (direct call)
//   - internal/bidding/bidding_test.go:1569 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) Start(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context must not be nil", ErrInvalidBid)
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return ErrEngineClosed
	}
	if e.started {
		e.mu.Unlock()
		return ErrAlreadyStarted
	}
	e.started = true
	e.mu.Unlock()

	e.wg.Go(func() {
		e.tickerLoop(ctx)
	})
	return nil
}

// tickerLoop drives automatic clearing of expired sealed-bid epochs without
// busy polling. It wakes on the earliest epoch deadline, on new epoch creation
// (wakeCh), on ctx.Done(), or on Close (stopCh).
//
// # Parameters
//
//   - ctx: Parent lifecycle context passed to Start.
//
// # Returns
//
// None. Exits cleanly when ctx is cancelled or stopCh is closed.
//
// # Example
//
//	// Internal goroutine body started and joined by Engine.Start / Engine.Close.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/clear.go:615 (direct call)
//   - internal/bidding/clear.go:615 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) tickerLoop(ctx context.Context) {
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		if ctx.Err() != nil {
			return
		}
		now := e.now().UTC()
		ep, nextDeadline := e.detachNextExpiredScope(now)
		if ep != nil {
			if _, err := e.clearDetachedEpoch(ctx, ep, e.now().UTC()); err != nil {
				e.journalErrors.Add(1)
			}
			continue
		}

		var timerCh <-chan time.Time
		if !nextDeadline.IsZero() {
			wait := nextDeadline.Sub(e.now().UTC())
			if wait <= 0 {
				continue
			}
			if timer == nil {
				timer = time.NewTimer(wait)
			} else {
				timer.Stop()
				timer.Reset(wait)
			}
			timerCh = timer.C
		} else if timer != nil {
			timer.Stop()
		}

		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case <-e.wakeCh:
		case <-timerCh:
		}
	}
}

// detachNextExpiredScope atomically detaches the lexicographically first
// active epoch whose ClosesAt is at or before now, or returns the earliest
// remaining ClosesAt deadline when no epoch is due yet.
//
// # Parameters
//
//   - now: Current UTC instant.
//
// # Returns
//
// The next expired detached *scopeEpoch (or nil if none are expired) and the
// earliest ClosesAt among remaining non-expired epochs (zero if none remain).
//
// # Example
//
//	// Internal helper called by tickerLoop.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/clear.go:658 (direct call)
//   - internal/bidding/clear.go:658 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) detachNextExpiredScope(now time.Time) (*scopeEpoch, time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var expiredScope string
	var earliest time.Time
	for scope, ep := range e.epochs {
		if !ep.closesAt.After(now) {
			if expiredScope == "" || scope < expiredScope {
				expiredScope = scope
			}
			continue
		}
		if earliest.IsZero() || ep.closesAt.Before(earliest) {
			earliest = ep.closesAt
		}
	}
	if expiredScope != "" {
		ep := e.epochs[expiredScope]
		delete(e.epochs, expiredScope)
		return ep, earliest
	}
	return nil, earliest
}

// Close gracefully shuts down the engine: stops accepting new bids, stops and
// joins the background ticker goroutine (if started), drains and clears all
// remaining active epochs with a bounded shutdown timeout, and closes the
// optional 0600 journal. Repeated calls to Close are idempotent and return nil.
//
// # Parameters
//
// None.
//
// # Returns
//
// Joined error from epoch drain journaling or journal close, or nil on clean
// shutdown. Safe for concurrent use.
//
// # Example
//
//	if err := engine.Close(); err != nil {
//		return err // inside a function returning error
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:526 (direct call)
//   - internal/bidding/bidding_test.go:644 (direct call)
//   - internal/bidding/bidding_test.go:832 (direct call)
//   - internal/bidding/bidding_test.go:1019 (direct call)
//   - internal/bidding/bidding_test.go:1104 (direct call)
//   - internal/bidding/bidding_test.go:1273 (direct call)
//   - internal/bidding/bidding_test.go:1381 (direct call)
//   - internal/bidding/bidding_test.go:1508 (direct call)
//   - internal/bidding/bidding_test.go:1630 (direct call)
//   - internal/bidding/bidding_test.go:1634 (direct call)
//   - internal/bidding/bidding_test.go:1694 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) Close() error {
	drainTimeout := max(e.cfg.SettleTimeout*time.Duration(max(1, e.cfg.SlotsPerEpoch)), 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	return e.CloseContext(ctx)
}

// CloseContext gracefully shuts down the engine using ctx to bound final
// active-epoch settlement draining before closing the journal.
//
// # Parameters
//
//   - ctx: Controls deadline and cancellation for draining active epochs.
//     Must be non-nil.
//
// # Returns
//
// Joined error from draining active epochs or closing the journal, or nil on
// clean shutdown. Repeated calls return nil. Safe for concurrent use.
//
// # Example
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//	if err := engine.CloseContext(ctx); err != nil {
//		return err // inside a function returning error
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/clear.go:787 (direct call)
//   - internal/bidding/clear.go:787 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context must not be nil", ErrInvalidBid)
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.mu.Unlock()

	// Stop and join the background ticker goroutine BEFORE draining epochs or
	// closing the journal so no concurrent tick races with teardown (R2).
	e.stopOnce.Do(func() {
		close(e.stopCh)
	})
	e.wg.Wait()

	// Detach every remaining active epoch deterministically by scope name.
	e.mu.Lock()
	remaining := make([]*scopeEpoch, 0, len(e.epochs))
	for scope, ep := range e.epochs {
		remaining = append(remaining, ep)
		delete(e.epochs, scope)
	}
	e.mu.Unlock()
	slices.SortFunc(remaining, func(a, b *scopeEpoch) int {
		return cmp.Compare(a.scope, b.scope)
	})

	var errs []error
	drainNow := e.now().UTC()
	for _, ep := range remaining {
		if _, err := e.clearDetachedEpoch(ctx, ep, drainNow); err != nil {
			errs = append(errs, err)
		}
	}
	if e.journal != nil {
		if err := e.journal.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close journal: %w", err))
		}
	}
	return errors.Join(errs...)
}
