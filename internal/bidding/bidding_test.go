package bidding_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/andreimerlescu/concert/internal/bidding"
)

// fakeSettler models PaymentSettler contracts for unit and concurrency tests,
// recording every Verify and Settle call so tests can strictly prove that
// losing bids are never passed to Settle.
type fakeSettler struct {
	mu           sync.Mutex
	verifyCalls  []bidding.BidSubmission
	settleCalls  []bidding.BidSubmission
	verifyFn     func(ctx context.Context, bid bidding.BidSubmission) (bidding.VerifyReceipt, error)
	settleFn     func(ctx context.Context, bid bidding.BidSubmission) (bidding.SettleReceipt, error)
	settleNotify chan string
}

// newFakeSettler returns a fakeSettler that approves all off-chain verifications
// and settles every passed winner with a deterministic transaction identifier.
//
// # Parameters
//
// None.
//
// # Returns
//
// Ready *fakeSettler safe for concurrent use in tests.
//
// # Example
//
//	settler := newFakeSettler()
//	_ = settler
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:506 (direct call)
//   - internal/bidding/bidding_test.go:623 (direct call)
//   - internal/bidding/bidding_test.go:821 (direct call)
//   - internal/bidding/bidding_test.go:993 (direct call)
//   - internal/bidding/bidding_test.go:1091 (direct call)
//   - internal/bidding/bidding_test.go:1261 (direct call)
//   - internal/bidding/bidding_test.go:1322 (direct call)
//   - internal/bidding/bidding_test.go:1445 (direct call)
//   - internal/bidding/bidding_test.go:1551 (direct call)
//   - internal/bidding/bidding_test.go:1684 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func newFakeSettler() *fakeSettler {
	return &fakeSettler{}
}

// Verify records the off-chain verification call and delegates to verifyFn if
// configured, otherwise returns a valid VerifyReceipt.
//
// # Parameters
//
//   - ctx: Context honoring deadlines/cancellation.
//   - bid: BidSubmission being verified off-chain.
//
// # Returns
//
// VerifyReceipt and optional error. Safe for concurrent use.
//
// # Example
//
//	// Invoked via bidding.PaymentSettler interface by bidding.Engine.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (f *fakeSettler) Verify(ctx context.Context, bid bidding.BidSubmission) (bidding.VerifyReceipt, error) {
	if err := ctx.Err(); err != nil {
		return bidding.VerifyReceipt{}, err
	}
	f.mu.Lock()
	f.verifyCalls = append(f.verifyCalls, bid)
	fn := f.verifyFn
	f.mu.Unlock()

	if fn != nil {
		return fn(ctx, bid)
	}
	return bidding.VerifyReceipt{
		Valid:    true,
		Payer:    "payer-" + bid.AgentKey,
		PolicyID: "policy-ok",
	}, nil
}

// Settle records the on-chain settlement call and delegates to settleFn if
// configured, otherwise returns a settled SettleReceipt.
//
// # Parameters
//
//   - ctx: Context honoring deadlines/cancellation.
//   - bid: Winning or instant-buy BidSubmission to settle.
//
// # Returns
//
// SettleReceipt and optional error. Safe for concurrent use.
//
// # Example
//
//	// Invoked via bidding.PaymentSettler interface by bidding.Engine.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (f *fakeSettler) Settle(ctx context.Context, bid bidding.BidSubmission) (bidding.SettleReceipt, error) {
	if err := ctx.Err(); err != nil {
		return bidding.SettleReceipt{}, err
	}
	f.mu.Lock()
	f.settleCalls = append(f.settleCalls, bid)
	fn := f.settleFn
	notify := f.settleNotify
	f.mu.Unlock()

	var res bidding.SettleReceipt
	var err error
	if fn != nil {
		res, err = fn(ctx, bid)
	} else {
		res = bidding.SettleReceipt{
			Settled:     true,
			Transaction: "tx-" + bid.BidID,
			Network:     bid.Chain,
			Payer:       "payer-" + bid.AgentKey,
		}
	}
	if notify != nil {
		select {
		case notify <- bid.BidID:
		default:
		}
	}
	return res, err
}

// settledBidIDs returns a snapshot of every BidID passed to Settle in call order.
//
// # Parameters
//
// None.
//
// # Returns
//
// Cloned slice of BidIDs passed to Settle. Safe for concurrent use.
//
// # Example
//
//	ids := settler.settledBidIDs()
//	_ = ids
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:569 (direct call)
//   - internal/bidding/bidding_test.go:793 (direct call)
//   - internal/bidding/bidding_test.go:921 (direct call)
//   - internal/bidding/bidding_test.go:943 (direct call)
//   - internal/bidding/bidding_test.go:1061 (direct call)
//   - internal/bidding/bidding_test.go:1207 (direct call)
//   - internal/bidding/bidding_test.go:1522 (direct call)
//   - internal/bidding/bidding_test.go:1523 (direct call)
//   - internal/bidding/bidding_test.go:1638 (direct call)
//   - internal/bidding/bidding_test.go:1722 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (f *fakeSettler) settledBidIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.settleCalls))
	for i, b := range f.settleCalls {
		out[i] = b.BidID
	}
	return out
}

// verifyCount returns the total number of Verify calls observed.
//
// # Parameters
//
// None.
//
// # Returns
//
// Count of Verify invocations. Safe for concurrent use.
//
// # Example
//
//	_ = settler.verifyCount()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:1122 (direct call)
//   - internal/bidding/bidding_test.go:1135 (direct call)
//   - internal/bidding/bidding_test.go:1136 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (f *fakeSettler) verifyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.verifyCalls)
}

// fakeClock provides a deterministic, concurrency-safe wall clock for tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// newFakeClock creates a fakeClock initialized to start.
//
// # Parameters
//
//   - start: Initial UTC timestamp.
//
// # Returns
//
// Initialized *fakeClock.
//
// # Example
//
//	clk := newFakeClock(time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC))
//	_ = clk.Now()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:505 (direct call)
//   - internal/bidding/bidding_test.go:622 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start.UTC()}
}

// Now returns the clock's current timestamp.
//
// # Parameters
//
// None.
//
// # Returns
//
// Current UTC time.Time. Safe for concurrent use.
//
// # Example
//
//	_ = clk.Now()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:520 (function value)
//   - internal/bidding/bidding_test.go:558 (direct call)
//   - internal/bidding/bidding_test.go:588 (direct call)
//   - internal/bidding/bidding_test.go:639 (function value)
//   - internal/bidding/bidding_test.go:669 (direct call)
//   - internal/bidding/bidding_test.go:683 (direct call)
//   - internal/bidding/bidding_test.go:697 (direct call)
//   - internal/bidding/bidding_test.go:711 (direct call)
//   - internal/bidding/bidding_test.go:725 (direct call)
//   - internal/bidding/bidding_test.go:739 (direct call)
//   - internal/bidding/bidding_test.go:753 (direct call)
//   - internal/bidding/bidding_test.go:767 (direct call)
//   - internal/bidding/bidding_test.go:786 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
//
// # Parameters
//
//   - d: Duration to add to the current clock instant.
//
// # Returns
//
// Updated UTC time.Time. Safe for concurrent use.
//
// # Example
//
//	_ = clk.Advance(10 * time.Second)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (c *fakeClock) Advance(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	return c.now
}

// fakeClusterSync records CQ.BID replication calls and supports injected errors.
type fakeClusterSync struct {
	mu      sync.Mutex
	calls   []string
	failErr error
}

// SyncBid records a cluster bid sync event and returns failErr if configured.
//
// # Parameters
//
//   - ctx: Request context.
//   - scope: Scope identifier.
//   - bidID: Accepted bid identifier.
//   - normalizedMicroUSD: Normalized micro-USD bid value.
//
// # Returns
//
// Configured failErr or nil. Safe for concurrent use.
//
// # Example
//
//	// Invoked via bidding.ClusterSync interface by bidding.Engine.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (s *fakeClusterSync) SyncBid(ctx context.Context, scope, bidID string, normalizedMicroUSD int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, fmt.Sprintf("%s:%s:%d", scope, bidID, normalizedMicroUSD))
	return s.failErr
}

// testRates returns deterministic 1-to-1 micro-USD rates across all four
// crypto chains so test amounts are easy to audit.
//
// # Parameters
//
// None.
//
// # Returns
//
// Slice of bidding.AssetRate for xrpl, stellar, hedera, and solana.
//
// # Example
//
//	rates := testRates()
//	_ = rates
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:516 (direct call)
//   - internal/bidding/bidding_test.go:638 (direct call)
//   - internal/bidding/bidding_test.go:826 (direct call)
//   - internal/bidding/bidding_test.go:1013 (direct call)
//   - internal/bidding/bidding_test.go:1098 (direct call)
//   - internal/bidding/bidding_test.go:1266 (direct call)
//   - internal/bidding/bidding_test.go:1327 (direct call)
//   - internal/bidding/bidding_test.go:1450 (direct call)
//   - internal/bidding/bidding_test.go:1558 (direct call)
//   - internal/bidding/bidding_test.go:1688 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func testRates() []bidding.AssetRate {
	return []bidding.AssetRate{
		{Chain: bidding.ChainXRPL, Asset: "XRP", Decimals: 6, MicroUSDPerUnit: 2_000_000},     // 1 drop = 2 micro-USD
		{Chain: bidding.ChainStellar, Asset: "XLM", Decimals: 7, MicroUSDPerUnit: 1_000_000},  // 10 stroops = 1 micro-USD
		{Chain: bidding.ChainHedera, Asset: "0.0.0", Decimals: 8, MicroUSDPerUnit: 1_000_000}, // 100 tinybars = 1 micro-USD
		{Chain: bidding.ChainSolana, Asset: "SOL", Decimals: 9, MicroUSDPerUnit: 100_000_000}, // 10 lamports = 1 micro-USD
	}
}

// testPayload builds a synthetic, clearly fake x402 v2 JSON payload for tests.
//
// # Parameters
//
//   - nonce: Unique test nonce string.
//
// # Returns
//
// JSON payload bytes.
//
// # Example
//
//	p := testPayload("n-1")
//	_ = p
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:557 (direct call)
//   - internal/bidding/bidding_test.go:668 (direct call)
//   - internal/bidding/bidding_test.go:682 (direct call)
//   - internal/bidding/bidding_test.go:696 (direct call)
//   - internal/bidding/bidding_test.go:710 (direct call)
//   - internal/bidding/bidding_test.go:724 (direct call)
//   - internal/bidding/bidding_test.go:738 (direct call)
//   - internal/bidding/bidding_test.go:752 (direct call)
//   - internal/bidding/bidding_test.go:849 (direct call)
//   - internal/bidding/bidding_test.go:860 (direct call)
//   - internal/bidding/bidding_test.go:871 (direct call)
//   - internal/bidding/bidding_test.go:882 (direct call)
//   - internal/bidding/bidding_test.go:893 (direct call)
//   - internal/bidding/bidding_test.go:904 (direct call)
//   - internal/bidding/bidding_test.go:1041 (direct call)
//   - internal/bidding/bidding_test.go:1147 (direct call)
//   - internal/bidding/bidding_test.go:1161 (direct call)
//   - internal/bidding/bidding_test.go:1175 (direct call)
//   - internal/bidding/bidding_test.go:1190 (direct call)
//   - internal/bidding/bidding_test.go:1282 (direct call)
//   - internal/bidding/bidding_test.go:1346 (direct call)
//   - internal/bidding/bidding_test.go:1361 (direct call)
//   - internal/bidding/bidding_test.go:1373 (direct call)
//   - internal/bidding/bidding_test.go:1470 (direct call)
//   - internal/bidding/bidding_test.go:1582 (direct call)
//   - internal/bidding/bidding_test.go:1594 (direct call)
//   - internal/bidding/bidding_test.go:1624 (direct call)
//   - internal/bidding/bidding_test.go:1656 (direct call)
//   - internal/bidding/bidding_test.go:1704 (direct call)
//   - internal/bidding/bidding_test.go:1714 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func testPayload(nonce string) []byte {
	return []byte(fmt.Sprintf(`{"x402Version":2,"nonce":%q,"signature":"fake-test-sig-%s"}`, nonce, nonce))
}

// TestEngine_InstantBuyVsAuctionOfferSwitching verifies mode switching between
// instant-buy (when priority slots are open) and sealed-bid auction epochs
// (when saturated), including immediate instant-buy settlement and replay guard.
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -run '^TestEngine_InstantBuyVsAuctionOfferSwitching$' ./internal/bidding`.
//
// # Returns
//
// None. Fails t if offer modes or instant-buy settlement invariants break.
//
// # Example
//
//	// Run with: go test -run '^TestEngine_InstantBuyVsAuctionOfferSwitching$' ./internal/bidding
//
// # Used By
//
// Invoked by the Go test runner (`go test ./internal/bidding`).
func TestEngine_InstantBuyVsAuctionOfferSwitching(t *testing.T) {
	t.Parallel()
	clk := newFakeClock(time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC))
	settler := newFakeSettler()

	var probeOpen atomic.Bool
	probeOpen.Store(true)

	eng, err := bidding.NewEngine(bidding.Config{
		EpochDuration:   10 * time.Second,
		SlotsPerEpoch:   2,
		MinWaitDuration: 15 * time.Second,
		FloorMicroUSD:   1_000_000, // $1.00
		AssetRates:      testRates(),
		SlotProbe: func(scope string) bool {
			return probeOpen.Load()
		},
		Now: clk.Now,
	}, settler)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	t.Cleanup(func() {
		if cerr := eng.Close(); cerr != nil {
			t.Errorf("Close() error = %v", cerr)
		}
	})

	// Open slots -> instant-buy mode.
	if !eng.HasOpenSlots("site:shop") {
		t.Fatalf("HasOpenSlots() = false, want true")
	}
	offer, err := eng.Offer("site:shop")
	if err != nil {
		t.Fatalf("Offer() error = %v", err)
	}
	if offer.Mode != bidding.ModeInstant {
		t.Fatalf("Offer.Mode = %q, want %q", offer.Mode, bidding.ModeInstant)
	}
	if offer.FloorMicroUSD != 1_000_000 {
		t.Errorf("Offer.FloorMicroUSD = %d, want 1000000", offer.FloorMicroUSD)
	}
	if offer.AuctionID != "" || !offer.ClosesAt.IsZero() {
		t.Errorf("instant offer should have empty AuctionID and zero ClosesAt; got %q, %v", offer.AuctionID, offer.ClosesAt)
	}

	// Instant-buy submission settles immediately even with 0 wait duration.
	rec, err := eng.SubmitBid(t.Context(), bidding.BidSubmission{
		BidID:          "instant-1",
		AgentKey:       "agent-fast",
		Scope:          "site:shop",
		Chain:          bidding.ChainXRPL,
		Asset:          "XRP",
		AmountAtomic:   "500000", // 0.5 XRP * $2 = $1.00 == FloorMicroUSD
		PaymentPayload: testPayload("instant-nonce-1"),
		QueuedAt:       clk.Now(),
	})
	if err != nil {
		t.Fatalf("SubmitBid(instant) error = %v", err)
	}
	if rec.Status != bidding.BidStatusSettled {
		t.Errorf("rec.Status = %q, want %q", rec.Status, bidding.BidStatusSettled)
	}
	if rec.Transaction != "tx-instant-1" {
		t.Errorf("rec.Transaction = %q, want tx-instant-1", rec.Transaction)
	}
	if got := settler.settledBidIDs(); !slices.Equal(got, []string{"instant-1"}) {
		t.Errorf("settledBidIDs = %v, want [instant-1]", got)
	}

	// Switch to saturated -> sealed-bid auction mode.
	probeOpen.Store(false)
	if eng.HasOpenSlots("site:shop") {
		t.Fatalf("HasOpenSlots() = true, want false")
	}
	auctionOffer, err := eng.Offer("site:shop")
	if err != nil {
		t.Fatalf("Offer(saturated) error = %v", err)
	}
	if auctionOffer.Mode != bidding.ModeAuction {
		t.Fatalf("Offer.Mode = %q, want %q", auctionOffer.Mode, bidding.ModeAuction)
	}
	if auctionOffer.AuctionID == "" {
		t.Errorf("auction offer AuctionID is empty")
	}
	wantCloses := clk.Now().Add(10 * time.Second)
	if !auctionOffer.ClosesAt.Equal(wantCloses) {
		t.Errorf("auction ClosesAt = %v, want %v", auctionOffer.ClosesAt, wantCloses)
	}
	if auctionOffer.MinWaitSeconds != 15 {
		t.Errorf("auction MinWaitSeconds = %d, want 15", auctionOffer.MinWaitSeconds)
	}
	if auctionOffer.Slots != 2 {
		t.Errorf("auction Slots = %d, want 2", auctionOffer.Slots)
	}
}

// TestEngine_RejectionsNeverStoredNeverSettled proves that under-floor,
// unsupported-chain (including any non-crypto identifier), ineligible-wait,
// oversized-payload, and invalid-signature bids are rejected immediately,
// never stored in the epoch, and never passed to PaymentSettler.Settle.
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -run '^TestEngine_RejectionsNeverStoredNeverSettled$' ./internal/bidding`.
//
// # Returns
//
// None. Fails t if any invalid bid is stored or settled.
//
// # Example
//
//	// Run with: go test -run '^TestEngine_RejectionsNeverStoredNeverSettled$' ./internal/bidding
//
// # Used By
//
// Invoked by the Go test runner (`go test ./internal/bidding`).
func TestEngine_RejectionsNeverStoredNeverSettled(t *testing.T) {
	t.Parallel()
	clk := newFakeClock(time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC))
	settler := newFakeSettler()
	settler.verifyFn = func(ctx context.Context, bid bidding.BidSubmission) (bidding.VerifyReceipt, error) {
		if bid.BidID == "bad-sig" {
			return bidding.VerifyReceipt{Valid: false, InvalidReason: "invalid_signature"}, nil
		}
		if bid.BidID == "verify-err" {
			return bidding.VerifyReceipt{}, errors.New("policy webhook denied")
		}
		return bidding.VerifyReceipt{Valid: true, Payer: "payer-ok"}, nil
	}

	eng, err := bidding.NewEngine(bidding.Config{
		FloorMicroUSD:   1_000_000,
		MinWaitDuration: 30 * time.Second,
		MaxPayloadBytes: 256,
		AssetRates:      testRates(),
		Now:             clk.Now,
	}, settler)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })

	// Also prove NewEngine rejects non-crypto chains in configuration.
	if _, err := bidding.NewEngine(bidding.Config{
		FloorMicroUSD:   1_000_000,
		SupportedChains: []string{"stripe"},
	}, settler); !errors.Is(err, bidding.ErrInvalidConfig) {
		t.Fatalf("NewEngine(non-crypto chain) error = %v, want ErrInvalidConfig", err)
	}

	tests := []struct {
		name    string
		bid     bidding.BidSubmission
		wantErr error
	}{
		{
			name: "under floor",
			bid: bidding.BidSubmission{
				BidID:          "under-floor",
				AgentKey:       "a1",
				Scope:          "site:drop",
				Chain:          bidding.ChainXRPL,
				Asset:          "XRP",
				AmountAtomic:   "499999", // 999,998 micro-USD < 1,000,000
				PaymentPayload: testPayload("uf-1"),
				QueuedAt:       clk.Now().Add(-60 * time.Second),
			},
			wantErr: bidding.ErrUnderFloor,
		},
		{
			name: "unsupported chain ethereum",
			bid: bidding.BidSubmission{
				BidID:          "bad-chain-eth",
				AgentKey:       "a2",
				Scope:          "site:drop",
				Chain:          "ethereum",
				Asset:          "ETH",
				AmountAtomic:   "1000000",
				PaymentPayload: testPayload("bc-1"),
				QueuedAt:       clk.Now().Add(-60 * time.Second),
			},
			wantErr: bidding.ErrUnsupportedChain,
		},
		{
			name: "unsupported chain fiat",
			bid: bidding.BidSubmission{
				BidID:          "bad-chain-fiat",
				AgentKey:       "a3",
				Scope:          "site:drop",
				Chain:          "usd",
				Asset:          "USD",
				AmountAtomic:   "1000000",
				PaymentPayload: testPayload("bc-2"),
				QueuedAt:       clk.Now().Add(-60 * time.Second),
			},
			wantErr: bidding.ErrUnsupportedChain,
		},
		{
			name: "unsupported asset on valid chain",
			bid: bidding.BidSubmission{
				BidID:          "bad-asset",
				AgentKey:       "a4",
				Scope:          "site:drop",
				Chain:          bidding.ChainSolana,
				Asset:          "UNKNOWN",
				AmountAtomic:   "100000000",
				PaymentPayload: testPayload("ba-1"),
				QueuedAt:       clk.Now().Add(-60 * time.Second),
			},
			wantErr: bidding.ErrUnsupportedAsset,
		},
		{
			name: "ineligible wait duration",
			bid: bidding.BidSubmission{
				BidID:          "short-wait",
				AgentKey:       "a5",
				Scope:          "site:drop",
				Chain:          bidding.ChainStellar,
				Asset:          "XLM",
				AmountAtomic:   "20000000", // 2 XLM = $2.00
				PaymentPayload: testPayload("sw-1"),
				QueuedAt:       clk.Now().Add(-10 * time.Second), // < 30s
			},
			wantErr: bidding.ErrIneligibleWait,
		},
		{
			name: "invalid signature rejected off-chain",
			bid: bidding.BidSubmission{
				BidID:          "bad-sig",
				AgentKey:       "a6",
				Scope:          "site:drop",
				Chain:          bidding.ChainHedera,
				Asset:          "0.0.0",
				AmountAtomic:   "200000000", // 2 HBAR = $2.00
				PaymentPayload: testPayload("bs-1"),
				QueuedAt:       clk.Now().Add(-60 * time.Second),
			},
			wantErr: bidding.ErrVerificationFailed,
		},
		{
			name: "verifier returned error",
			bid: bidding.BidSubmission{
				BidID:          "verify-err",
				AgentKey:       "a7",
				Scope:          "site:drop",
				Chain:          bidding.ChainXRPL,
				Asset:          "XRP",
				AmountAtomic:   "1000000",
				PaymentPayload: testPayload("ve-1"),
				QueuedAt:       clk.Now().Add(-60 * time.Second),
			},
			wantErr: bidding.ErrVerificationFailed,
		},
		{
			name: "oversized payload",
			bid: bidding.BidSubmission{
				BidID:          "big-payload",
				AgentKey:       "a8",
				Scope:          "site:drop",
				Chain:          bidding.ChainXRPL,
				Asset:          "XRP",
				AmountAtomic:   "1000000",
				PaymentPayload: []byte(strings.Repeat("x", 257)),
				QueuedAt:       clk.Now().Add(-60 * time.Second),
			},
			wantErr: bidding.ErrInvalidBid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := eng.SubmitBid(t.Context(), tc.bid)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("SubmitBid(%s) error = %v, want %v", tc.bid.BidID, err, tc.wantErr)
			}
			if rec.Status != bidding.BidStatusRejected {
				t.Errorf("rec.Status = %q, want %q", rec.Status, bidding.BidStatusRejected)
			}
		})
	}

	// Clearing the epoch must find zero stored bids and invoke zero settlements.
	res, err := eng.ClearEpoch(t.Context(), "site:drop", clk.Now())
	if err != nil {
		t.Fatalf("ClearEpoch() error = %v", err)
	}
	if res.TotalBids != 0 || len(res.Winners) != 0 {
		t.Fatalf("ClearEpoch() = total:%d winners:%d, want 0/0", res.TotalBids, len(res.Winners))
	}
	if got := settler.settledBidIDs(); len(got) != 0 {
		t.Fatalf("Settle called on rejected bids: %v", got)
	}
}

// TestEngine_DeterministicTieBreakingAndLosersNeverSettled verifies exact
// ranking order (NormalizedMicroUSD DESC, WaitDuration DESC, ReceivedAt ASC,
// BidID ASC) across all 4 crypto chains and strictly asserts that losing bids
// are NEVER passed to PaymentSettler.Settle.
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -run '^TestEngine_DeterministicTieBreakingAndLosersNeverSettled$' ./internal/bidding`.
//
// # Returns
//
// None. Fails t if tie-breaking order is wrong or any loser is passed to Settle.
//
// # Example
//
//	// Run with: go test -run '^TestEngine_DeterministicTieBreakingAndLosersNeverSettled$' ./internal/bidding
//
// # Used By
//
// Invoked by the Go test runner (`go test ./internal/bidding`).
func TestEngine_DeterministicTieBreakingAndLosersNeverSettled(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	settler := newFakeSettler()

	eng, err := bidding.NewEngine(bidding.Config{
		FloorMicroUSD: 1_000_000,
		SlotsPerEpoch: 3,
		AssetRates:    testRates(),
		Now:           func() time.Time { return base },
	}, settler)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })

	// Submit 6 bids across XRPL, Stellar, Hedera, and Solana:
	// 1. bid-top:       $5.00 (Solana)               -> Winner #1
	// 2. bid-tie-wait:  $2.00, waited 120s (XRPL)    -> Winner #2 (longest wait)
	// 3. bid-tie-early: $2.00, waited 60s, t+1s (XLM)-> Winner #3 (earlier ReceivedAt)
	// 4. bid-tie-late:  $2.00, waited 60s, t+2s (HBAR)-> Loser (later ReceivedAt)
	// 5. bid-tie-id-b:  $2.00, waited 60s, t+2s (XRPL)-> Loser (tie on ReceivedAt, BidID)
	// 6. bid-low:       $1.00, waited 300s (Solana)  -> Loser (lower USD despite long wait)
	submissions := []bidding.BidSubmission{
		{
			BidID:          "bid-low",
			AgentKey:       "agent-low",
			Scope:          "route:/drop",
			Chain:          "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", // CAIP-2 form
			Asset:          "SOL",
			AmountAtomic:   "10000000", // 0.01 SOL * $100 = $1.00
			PaymentPayload: testPayload("tb-low"),
			QueuedAt:       base.Add(-300 * time.Second),
			ReceivedAt:     base,
		},
		{
			BidID:          "bid-tie-late",
			AgentKey:       "agent-late",
			Scope:          "route:/drop",
			Chain:          "hedera:mainnet",
			Asset:          "0.0.0",
			AmountAtomic:   "200000000", // 2 HBAR * $1 = $2.00
			PaymentPayload: testPayload("tb-late"),
			QueuedAt:       base.Add(2 * time.Second).Add(-60 * time.Second),
			ReceivedAt:     base.Add(2 * time.Second),
		},
		{
			BidID:          "bid-tie-early",
			AgentKey:       "agent-early",
			Scope:          "route:/drop",
			Chain:          "stellar:pubnet",
			Asset:          "XLM",
			AmountAtomic:   "20000000", // 2 XLM * $1 = $2.00
			PaymentPayload: testPayload("tb-early"),
			QueuedAt:       base.Add(1 * time.Second).Add(-60 * time.Second),
			ReceivedAt:     base.Add(1 * time.Second),
		},
		{
			BidID:          "bid-tie-wait",
			AgentKey:       "agent-wait",
			Scope:          "route:/drop",
			Chain:          "xrpl:0",
			Asset:          "XRP",
			AmountAtomic:   "1000000", // 1 XRP * $2 = $2.00
			PaymentPayload: testPayload("tb-wait"),
			QueuedAt:       base.Add(5 * time.Second).Add(-120 * time.Second),
			ReceivedAt:     base.Add(5 * time.Second),
		},
		{
			BidID:          "bid-top",
			AgentKey:       "agent-top",
			Scope:          "route:/drop",
			Chain:          bidding.ChainSolana,
			Asset:          "SOL",
			AmountAtomic:   "50000000", // 0.05 SOL * $100 = $5.00
			PaymentPayload: testPayload("tb-top"),
			QueuedAt:       base.Add(-5 * time.Second),
			ReceivedAt:     base,
		},
		{
			BidID:          "bid-tie-id-b",
			AgentKey:       "agent-id-b",
			Scope:          "route:/drop",
			Chain:          bidding.ChainXRPL,
			Asset:          "XRP",
			AmountAtomic:   "1000000", // $2.00
			PaymentPayload: testPayload("tb-idb"),
			QueuedAt:       base.Add(2 * time.Second).Add(-60 * time.Second),
			ReceivedAt:     base.Add(2 * time.Second),
		},
	}

	for _, sub := range submissions {
		rec, err := eng.SubmitBid(t.Context(), sub)
		if err != nil {
			t.Fatalf("SubmitBid(%s) error = %v", sub.BidID, err)
		}
		if rec.Status != bidding.BidStatusPending {
			t.Errorf("SubmitBid(%s) status = %q, want pending", sub.BidID, rec.Status)
		}
	}

	// Before ClearEpoch, ZERO settlements must have occurred (off-chain verify only!).
	if got := settler.settledBidIDs(); len(got) != 0 {
		t.Fatalf("Settle called before ClearEpoch: %v", got)
	}

	res, err := eng.ClearEpoch(t.Context(), "route:/drop", base.Add(10*time.Second))
	if err != nil {
		t.Fatalf("ClearEpoch() error = %v", err)
	}

	wantWinners := []string{"bid-top", "bid-tie-wait", "bid-tie-early"}
	gotWinners := make([]string, len(res.Winners))
	for i, w := range res.Winners {
		gotWinners[i] = w.BidID
		if w.Status != bidding.BidStatusSettled {
			t.Errorf("winner %s status = %q, want settled", w.BidID, w.Status)
		}
	}
	if !slices.Equal(gotWinners, wantWinners) {
		t.Fatalf("winners = %v, want %v", gotWinners, wantWinners)
	}

	// Strict invariant: Settle was invoked ONLY on the exact winning bids.
	settledCalls := settler.settledBidIDs()
	if len(settledCalls) != len(res.Winners) {
		t.Fatalf("settledCount = %d, want %d (winners only)", len(settledCalls), len(res.Winners))
	}
	if !slices.Equal(settledCalls, wantWinners) {
		t.Fatalf("settledCalls = %v, want %v", settledCalls, wantWinners)
	}

	// Verify losers were dropped unsettled and recorded as BidStatusLost.
	wantLosers := []string{"bid-tie-id-b", "bid-tie-late", "bid-low"}
	gotLosers := make([]string, len(res.Losers))
	for i, l := range res.Losers {
		gotLosers[i] = l.BidID
		if l.Status != bidding.BidStatusLost {
			t.Errorf("loser %s status = %q, want lost", l.BidID, l.Status)
		}
		if l.Transaction != "" {
			t.Errorf("loser %s has non-empty Transaction %q", l.BidID, l.Transaction)
		}
		if st, ok := eng.GetBidStatus(l.BidID); !ok || st.Status != bidding.BidStatusLost {
			t.Errorf("GetBidStatus(%s) = (%v, %v), want lost", l.BidID, st.Status, ok)
		}
	}
	if !slices.Equal(gotLosers, wantLosers) {
		t.Fatalf("losers = %v, want %v", gotLosers, wantLosers)
	}
}

// TestEngine_RunnerUpPromotionOnSettlementFailure proves that when a selected
// winner fails on-chain settlement (either via error or Settled=false), the
// next ranked runner-up is promoted, while unpromoted losers are never settled.
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -run '^TestEngine_RunnerUpPromotionOnSettlementFailure$' ./internal/bidding`.
//
// # Returns
//
// None. Fails t if runner-up promotion or loser protection breaks.
//
// # Example
//
//	// Run with: go test -run '^TestEngine_RunnerUpPromotionOnSettlementFailure$' ./internal/bidding
//
// # Used By
//
// Invoked by the Go test runner (`go test ./internal/bidding`).
func TestEngine_RunnerUpPromotionOnSettlementFailure(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	settler := newFakeSettler()
	settler.settleFn = func(ctx context.Context, bid bidding.BidSubmission) (bidding.SettleReceipt, error) {
		switch bid.BidID {
		case "bid-1":
			return bidding.SettleReceipt{}, errors.New("rpc timeout")
		case "bid-2":
			return bidding.SettleReceipt{Settled: false, ErrorReason: "insufficient_balance"}, nil
		default:
			return bidding.SettleReceipt{
				Settled:     true,
				Transaction: "tx-" + bid.BidID,
				Network:     bid.Chain,
				Payer:       "payer-" + bid.AgentKey,
			}, nil
		}
	}

	eng, err := bidding.NewEngine(bidding.Config{
		FloorMicroUSD: 1_000_000,
		SlotsPerEpoch: 1,
		AssetRates:    testRates(),
		Now:           func() time.Time { return base },
	}, settler)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })

	// 4 bids ranked bid-1 ($5) > bid-2 ($4) > bid-3 ($3) > bid-4 ($2).
	// bid-1 fails (error), bid-2 fails (Settled=false) -> bid-3 promoted & settled!
	// bid-4 MUST NEVER be passed to Settle.
	bids := []struct {
		id     string
		atomic string // XRP drops (1 drop = 2 micro-USD)
	}{
		{"bid-1", "2500000"}, // $5
		{"bid-2", "2000000"}, // $4
		{"bid-3", "1500000"}, // $3
		{"bid-4", "1000000"}, // $2
	}
	for _, b := range bids {
		if _, err := eng.SubmitBid(t.Context(), bidding.BidSubmission{
			BidID:          b.id,
			AgentKey:       "agent-" + b.id,
			Scope:          "site:promo",
			Chain:          bidding.ChainXRPL,
			Asset:          "XRP",
			AmountAtomic:   b.atomic,
			PaymentPayload: testPayload("promo-" + b.id),
			QueuedAt:       base.Add(-10 * time.Second),
		}); err != nil {
			t.Fatalf("SubmitBid(%s) error = %v", b.id, err)
		}
	}

	res, err := eng.ClearEpoch(t.Context(), "site:promo", base.Add(10*time.Second))
	if err != nil {
		t.Fatalf("ClearEpoch() error = %v", err)
	}
	if len(res.Winners) != 1 || res.Winners[0].BidID != "bid-3" {
		t.Fatalf("Winners = %+v, want [bid-3]", res.Winners)
	}
	if len(res.SettlementFailures) != 2 || res.SettlementFailures[0].BidID != "bid-1" || res.SettlementFailures[1].BidID != "bid-2" {
		t.Fatalf("SettlementFailures = %+v, want [bid-1, bid-2]", res.SettlementFailures)
	}
	if len(res.Losers) != 1 || res.Losers[0].BidID != "bid-4" {
		t.Fatalf("Losers = %+v, want [bid-4]", res.Losers)
	}
	if got, want := settler.settledBidIDs(), []string{"bid-1", "bid-2", "bid-3"}; !slices.Equal(got, want) {
		t.Fatalf("Settle calls = %v, want %v (bid-4 must never be settled)", got, want)
	}
	if st, ok := eng.GetBidStatus("bid-1"); !ok || st.Status != bidding.BidStatusSettlementFailed {
		t.Errorf("GetBidStatus(bid-1) = (%v, %v), want settlement_failed", st.Status, ok)
	}
}

// TestEngine_ReplayAndDoubleBidAndMaxBidsBound verifies canonical JSON replay
// protection, bounded LRU replay eviction, single-active-bid per (AgentKey,
// EpochID) with higher re-bid replacement, and MaxBidsPerEpoch cap (R3).
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -run '^TestEngine_ReplayAndDoubleBidAndMaxBidsBound$' ./internal/bidding`.
//
// # Returns
//
// None. Fails t if replay, re-bid, or capacity bounds fail.
//
// # Example
//
//	// Run with: go test -run '^TestEngine_ReplayAndDoubleBidAndMaxBidsBound$' ./internal/bidding
//
// # Used By
//
// Invoked by the Go test runner (`go test ./internal/bidding`).
func TestEngine_ReplayAndDoubleBidAndMaxBidsBound(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	settler := newFakeSettler()

	eng, err := bidding.NewEngine(bidding.Config{
		FloorMicroUSD:   1_000_000,
		SlotsPerEpoch:   1,
		MaxBidsPerEpoch: 2,
		ReplayCacheSize: 4,
		AssetRates:      testRates(),
		Now:             func() time.Time { return base },
	}, settler)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })

	// 1. Submit initial bid for agent-A ($2).
	if _, err := eng.SubmitBid(t.Context(), bidding.BidSubmission{
		BidID:          "a-low",
		AgentKey:       "agent-A",
		Scope:          "site:cap",
		Chain:          bidding.ChainXRPL,
		Asset:          "XRP",
		AmountAtomic:   "1000000",
		PaymentPayload: []byte(`{"x402Version":2,"nonce":"dup-1"}`),
		QueuedAt:       base.Add(-20 * time.Second),
	}); err != nil {
		t.Fatalf("SubmitBid(a-low) error = %v", err)
	}

	// 2. Replay attack with reordered JSON keys and whitespace MUST be blocked
	// BEFORE calling Verify again.
	verifyBefore := settler.verifyCount()
	if _, err := eng.SubmitBid(t.Context(), bidding.BidSubmission{
		BidID:          "a-replay",
		AgentKey:       "agent-B",
		Scope:          "site:cap",
		Chain:          bidding.ChainXRPL,
		Asset:          "XRP",
		AmountAtomic:   "1000000",
		PaymentPayload: []byte(`{ "nonce" : "dup-1" , "x402Version" : 2 }`),
		QueuedAt:       base.Add(-20 * time.Second),
	}); !errors.Is(err, bidding.ErrReplayDetected) {
		t.Fatalf("replayed payload error = %v, want ErrReplayDetected", err)
	}
	if settler.verifyCount() != verifyBefore {
		t.Errorf("replay fast-path called Verify (%d -> %d), want no call", verifyBefore, settler.verifyCount())
	}

	// 3. Same agent equal/lower re-bid MUST be rejected with ErrRebidNotHigher.
	if _, err := eng.SubmitBid(t.Context(), bidding.BidSubmission{
		BidID:          "a-eq",
		AgentKey:       "agent-A",
		Scope:          "site:cap",
		Chain:          bidding.ChainXRPL,
		Asset:          "XRP",
		AmountAtomic:   "1000000",
		PaymentPayload: testPayload("a-eq-nonce"),
		QueuedAt:       base.Add(-20 * time.Second),
	}); !errors.Is(err, bidding.ErrRebidNotHigher) {
		t.Fatalf("equal re-bid error = %v, want ErrRebidNotHigher", err)
	}

	// 4. Fill epoch to MaxBidsPerEpoch=2 with agent-B ($3).
	if _, err := eng.SubmitBid(t.Context(), bidding.BidSubmission{
		BidID:          "b-bid",
		AgentKey:       "agent-B",
		Scope:          "site:cap",
		Chain:          bidding.ChainXRPL,
		Asset:          "XRP",
		AmountAtomic:   "1500000", // $3
		PaymentPayload: testPayload("b-nonce"),
		QueuedAt:       base.Add(-20 * time.Second),
	}); err != nil {
		t.Fatalf("SubmitBid(b-bid) error = %v", err)
	}

	// 5. Third distinct agent MUST be rejected with ErrEpochFull (R3).
	if _, err := eng.SubmitBid(t.Context(), bidding.BidSubmission{
		BidID:          "c-bid",
		AgentKey:       "agent-C",
		Scope:          "site:cap",
		Chain:          bidding.ChainXRPL,
		Asset:          "XRP",
		AmountAtomic:   "5000000",
		PaymentPayload: testPayload("c-nonce"),
		QueuedAt:       base.Add(-20 * time.Second),
	}); !errors.Is(err, bidding.ErrEpochFull) {
		t.Fatalf("over-capacity bid error = %v, want ErrEpochFull", err)
	}

	// 6. Existing agent-A CAN still submit a strictly higher re-bid ($4) at cap,
	// cleanly replacing a-low.
	if _, err := eng.SubmitBid(t.Context(), bidding.BidSubmission{
		BidID:          "a-high",
		AgentKey:       "agent-A",
		Scope:          "site:cap",
		Chain:          bidding.ChainXRPL,
		Asset:          "XRP",
		AmountAtomic:   "2000000", // $4
		PaymentPayload: testPayload("a-high-nonce"),
		QueuedAt:       base.Add(-20 * time.Second),
	}); err != nil {
		t.Fatalf("SubmitBid(a-high replacement) error = %v", err)
	}
	if prev, ok := eng.GetBidStatus("a-low"); !ok || prev.Status != bidding.BidStatusLost || prev.Reason != "replaced_by_higher_bid" {
		t.Errorf("replaced bid status = (%+v, %v), want lost/replaced_by_higher_bid", prev, ok)
	}

	// Clearing settles ONLY a-high; neither a-low nor b-bid is settled.
	res, err := eng.ClearEpoch(t.Context(), "site:cap", base.Add(10*time.Second))
	if err != nil {
		t.Fatalf("ClearEpoch() error = %v", err)
	}
	if res.TotalBids != 2 {
		t.Errorf("res.TotalBids = %d, want 2", res.TotalBids)
	}
	if got := settler.settledBidIDs(); !slices.Equal(got, []string{"a-high"}) {
		t.Fatalf("settledBidIDs = %v, want [a-high]", got)
	}

	// Direct ReplayCache O(1) LRU capacity bound check (R3).
	cache, err := bidding.NewReplayCache(2)
	if err != nil {
		t.Fatalf("NewReplayCache(2) error = %v", err)
	}
	d1 := bidding.PayloadDigest(bidding.ChainXRPL, "XRP", "1", []byte("1"))
	d2 := bidding.PayloadDigest(bidding.ChainXRPL, "XRP", "2", []byte("2"))
	d3 := bidding.PayloadDigest(bidding.ChainXRPL, "XRP", "3", []byte("3"))
	if !cache.AddIfAbsent(d1) || !cache.AddIfAbsent(d2) {
		t.Fatalf("expected d1 and d2 to insert cleanly")
	}
	// Touch d1 so d2 becomes LRU.
	if !cache.Contains(d1) {
		t.Fatalf("Contains(d1) = false, want true")
	}
	if !cache.AddIfAbsent(d3) {
		t.Fatalf("AddIfAbsent(d3) = false, want true")
	}
	if cache.Len() != 2 {
		t.Errorf("cache.Len() = %d, want 2", cache.Len())
	}
	if cache.Contains(d2) {
		t.Errorf("expected LRU entry d2 to be evicted")
	}
	if !cache.Contains(d1) || !cache.Contains(d3) {
		t.Errorf("expected d1 and d3 to remain in cache")
	}
}

// TestEngine_ClusterSyncIntegration verifies that accepted sealed bids invoke
// the optional ClusterSync port (concert-kv CQ.BID) and fail open on sync error.
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -run '^TestEngine_ClusterSyncIntegration$' ./internal/bidding`.
//
// # Returns
//
// None. Fails t if ClusterSync is not called or fails closed.
//
// # Example
//
//	// Run with: go test -run '^TestEngine_ClusterSyncIntegration$' ./internal/bidding
//
// # Used By
//
// Invoked by the Go test runner (`go test ./internal/bidding`).
func TestEngine_ClusterSyncIntegration(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	settler := newFakeSettler()
	syncer := &fakeClusterSync{failErr: errors.New("kv unreachable")}

	eng, err := bidding.NewEngine(bidding.Config{
		FloorMicroUSD: 1_000_000,
		AssetRates:    testRates(),
		ClusterSync:   syncer,
		Now:           func() time.Time { return base },
	}, settler)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })

	if _, err := eng.SubmitBid(t.Context(), bidding.BidSubmission{
		BidID:          "sync-1",
		AgentKey:       "agent-sync",
		Scope:          "site:kv",
		Chain:          bidding.ChainXRPL,
		Asset:          "XRP",
		AmountAtomic:   "1000000",
		PaymentPayload: testPayload("sync-n1"),
		QueuedAt:       base.Add(-5 * time.Second),
	}); err != nil {
		t.Fatalf("SubmitBid() should fail open on ClusterSync error; got %v", err)
	}
	if st := eng.Stats(); st.ClusterSyncErrors != 1 {
		t.Errorf("Stats().ClusterSyncErrors = %d, want 1", st.ClusterSyncErrors)
	}
	syncer.mu.Lock()
	gotCalls := slices.Clone(syncer.calls)
	syncer.mu.Unlock()
	if !slices.Equal(gotCalls, []string{"site:kv:sync-1:2000000"}) {
		t.Errorf("ClusterSync calls = %v, want [site:kv:sync-1:2000000]", gotCalls)
	}
}

// TestEngine_Journal0600DurabilityAndSecretFree verifies that the optional
// JSONL journal is created with strict 0600 permissions, persists durable
// epoch and instant-buy entries, and never writes raw PaymentPayload bytes.
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -run '^TestEngine_Journal0600DurabilityAndSecretFree$' ./internal/bidding`.
//
// # Returns
//
// None. Fails t if permissions, JSONL records, or secret redaction checks fail.
//
// # Example
//
//	// Run with: go test -run '^TestEngine_Journal0600DurabilityAndSecretFree$' ./internal/bidding
//
// # Used By
//
// Invoked by the Go test runner (`go test ./internal/bidding`).
func TestEngine_Journal0600DurabilityAndSecretFree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "nested", "bidding.jsonl")
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	settler := newFakeSettler()

	eng, err := bidding.NewEngine(bidding.Config{
		FloorMicroUSD: 1_000_000,
		SlotsPerEpoch: 1,
		AssetRates:    testRates(),
		JournalPath:   journalPath,
		Now:           func() time.Time { return base },
	}, settler)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	const sentinelPayloadToken = "never-persist-this-raw-payload-marker"

	// 1. Instant-buy journal entry.
	eng.SetOpenSlots("site:j", true)
	if _, err := eng.SubmitBid(t.Context(), bidding.BidSubmission{
		BidID:          "j-instant",
		AgentKey:       "agent-j1",
		Scope:          "site:j",
		Chain:          bidding.ChainXRPL,
		Asset:          "XRP",
		AmountAtomic:   "1000000",
		PaymentPayload: testPayload(sentinelPayloadToken + "-1"),
		QueuedAt:       base,
	}); err != nil {
		t.Fatalf("SubmitBid(instant) error = %v", err)
	}

	// 2. Sealed-bid epoch journal entry.
	eng.SetOpenSlots("site:j", false)
	if _, err := eng.SubmitBid(t.Context(), bidding.BidSubmission{
		BidID:          "j-win",
		AgentKey:       "agent-j2",
		Scope:          "site:j",
		Chain:          bidding.ChainSolana,
		Asset:          "SOL",
		AmountAtomic:   "30000000", // $3
		PaymentPayload: testPayload(sentinelPayloadToken + "-2"),
		QueuedAt:       base.Add(-10 * time.Second),
	}); err != nil {
		t.Fatalf("SubmitBid(j-win) error = %v", err)
	}
	if _, err := eng.SubmitBid(t.Context(), bidding.BidSubmission{
		BidID:          "j-lose",
		AgentKey:       "agent-j3",
		Scope:          "site:j",
		Chain:          bidding.ChainStellar,
		Asset:          "XLM",
		AmountAtomic:   "10000000", // $1
		PaymentPayload: testPayload(sentinelPayloadToken + "-3"),
		QueuedAt:       base.Add(-10 * time.Second),
	}); err != nil {
		t.Fatalf("SubmitBid(j-lose) error = %v", err)
	}
	if _, err := eng.ClearEpoch(t.Context(), "site:j", base.Add(10*time.Second)); err != nil {
		t.Fatalf("ClearEpoch() error = %v", err)
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	fi, err := os.Stat(journalPath)
	if err != nil {
		t.Fatalf("os.Stat(%q) error = %v", journalPath, err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("journal permissions = %04o, want 0600", perm)
	}

	raw, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) error = %v", journalPath, err)
	}
	if strings.Contains(string(raw), sentinelPayloadToken) {
		t.Fatalf("journal leaked raw PaymentPayload contents")
	}

	var entries []bidding.JournalEntry
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		var ent bidding.JournalEntry
		if err := json.Unmarshal(sc.Bytes(), &ent); err != nil {
			t.Fatalf("unmarshal journal line: %v", err)
		}
		entries = append(entries, ent)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan journal: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("journal entry count = %d, want 2", len(entries))
	}
	if entries[0].Type != "instant_buy" || len(entries[0].Winners) != 1 || entries[0].Winners[0].BidID != "j-instant" {
		t.Errorf("entries[0] = %+v, want instant_buy winner j-instant", entries[0])
	}
	if entries[1].Type != "epoch_cleared" || len(entries[1].Winners) != 1 || entries[1].Winners[0].BidID != "j-win" || entries[1].LoserCount != 1 {
		t.Errorf("entries[1] = %+v, want epoch_cleared winner j-win with 1 loser", entries[1])
	}
}

// TestEngine_ConcurrentSubmitAndClearRace exercises concurrent bid submission,
// status queries, offer reads, and epoch clearing behind a synchronized start
// barrier to verify race freedom under `-race` and strict winner-only settlement.
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -race -run '^TestEngine_ConcurrentSubmitAndClearRace$' ./internal/bidding`.
//
// # Returns
//
// None. Fails t on any race, error, or loser settlement violation.
//
// # Example
//
//	// Run with: go test -race -run '^TestEngine_ConcurrentSubmitAndClearRace$' ./internal/bidding
//
// # Used By
//
// Invoked by the Go test runner (`go test ./internal/bidding`).
func TestEngine_ConcurrentSubmitAndClearRace(t *testing.T) {
	t.Parallel()
	settler := newFakeSettler()
	eng, err := bidding.NewEngine(bidding.Config{
		FloorMicroUSD:   1_000_000,
		SlotsPerEpoch:   2,
		MaxBidsPerEpoch: 256,
		AssetRates:      testRates(),
	}, settler)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	const workers = 16
	const bidsPerWorker = 10
	scopes := []string{"site:alpha", "site:beta"}

	start := make(chan struct{})
	var wg sync.WaitGroup
	var submitErrs atomic.Int64

	for w := range workers {
		wg.Go(func() {
			<-start
			for i := range bidsPerWorker {
				scope := scopes[(w+i)%len(scopes)]
				_, _ = eng.Offer(scope)
				payload := testPayload(fmt.Sprintf("conc-%d-%d", w, i))
				rec, err := eng.SubmitBid(t.Context(), bidding.BidSubmission{
					BidID:          fmt.Sprintf("b-%d-%d", w, i),
					AgentKey:       fmt.Sprintf("agent-%d-%d", w, i),
					Scope:          scope,
					Chain:          bidding.ChainXRPL,
					Asset:          "XRP",
					AmountAtomic:   fmt.Sprintf("%d", 500000+int64(i)*100000),
					PaymentPayload: payload,
					QueuedAt:       time.Now().Add(-time.Duration(i+1) * time.Second),
				})
				// Mutate original slice after SubmitBid to verify defensive copy (C2).
				if len(payload) > 0 {
					payload[0] = '!'
				}
				if err != nil {
					submitErrs.Add(1)
					continue
				}
				_, _ = eng.GetBidStatus(rec.BidID)
			}
		})
	}

	// Concurrent clearer goroutine racing with submitters.
	wg.Go(func() {
		<-start
		for range 8 {
			for _, scope := range scopes {
				_, _ = eng.ClearEpoch(t.Context(), scope, time.Now().UTC())
			}
		}
	})

	close(start)
	wg.Wait()

	// Graceful Close drains any remaining active epochs.
	if err := eng.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if submitErrs.Load() != 0 {
		t.Fatalf("unexpected submission errors: %d", submitErrs.Load())
	}

	st := eng.Stats()
	if st.Submitted != workers*bidsPerWorker {
		t.Fatalf("Stats().Submitted = %d, want %d", st.Submitted, workers*bidsPerWorker)
	}
	if st.WinnersSettled+st.LosersDropped != st.Submitted {
		t.Fatalf("winners(%d) + losers(%d) != submitted(%d)", st.WinnersSettled, st.LosersDropped, st.Submitted)
	}
	if int64(len(settler.settledBidIDs())) != st.WinnersSettled {
		t.Fatalf("Settle call count (%d) != WinnersSettled (%d); losers must never settle", len(settler.settledBidIDs()), st.WinnersSettled)
	}
}

// TestEngine_BackgroundTickerAndGracefulCloseDrain uses testing/synctest
// fake time (zero time.Sleep synchronization, T2/T4) to prove:
//  1. Background ticker automatically clears expired epochs after EpochDuration.
//  2. Close() cleanly stops/joins the background goroutine and drains any
//     active in-flight epoch before returning.
//  3. Double Close() is idempotent and post-Close calls return ErrEngineClosed.
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -race -run '^TestEngine_BackgroundTickerAndGracefulCloseDrain$' ./internal/bidding`.
//
// # Returns
//
// None. Fails t if ticker clearing, drain-on-close, or idempotency breaks.
//
// # Example
//
//	// Run with: go test -race -run '^TestEngine_BackgroundTickerAndGracefulCloseDrain$' ./internal/bidding
//
// # Used By
//
// Invoked by the Go test runner (`go test ./internal/bidding`).
func TestEngine_BackgroundTickerAndGracefulCloseDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		settler := newFakeSettler()
		settler.settleNotify = make(chan string, 8)

		eng, err := bidding.NewEngine(bidding.Config{
			EpochDuration: 10 * time.Second,
			SlotsPerEpoch: 1,
			FloorMicroUSD: 1_000_000,
			AssetRates:    testRates(),
		}, settler)
		if err != nil {
			t.Fatalf("NewEngine() error = %v", err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		if err := eng.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		if err := eng.Start(ctx); !errors.Is(err, bidding.ErrAlreadyStarted) {
			t.Fatalf("second Start() error = %v, want ErrAlreadyStarted", err)
		}

		// Submit two bids into epoch 1; wait for synctest bubble to advance
		// 10s so the background ticker clears the epoch automatically.
		if _, err := eng.SubmitBid(ctx, bidding.BidSubmission{
			BidID:          "tick-win",
			AgentKey:       "agent-tw",
			Scope:          "site:auto",
			Chain:          bidding.ChainXRPL,
			Asset:          "XRP",
			AmountAtomic:   "2000000", // $4
			PaymentPayload: testPayload("tick-1"),
			QueuedAt:       time.Now().Add(-30 * time.Second),
		}); err != nil {
			t.Fatalf("SubmitBid(tick-win) error = %v", err)
		}
		if _, err := eng.SubmitBid(ctx, bidding.BidSubmission{
			BidID:          "tick-lose",
			AgentKey:       "agent-tl",
			Scope:          "site:auto",
			Chain:          bidding.ChainXRPL,
			Asset:          "XRP",
			AmountAtomic:   "1000000", // $2
			PaymentPayload: testPayload("tick-2"),
			QueuedAt:       time.Now().Add(-30 * time.Second),
		}); err != nil {
			t.Fatalf("SubmitBid(tick-lose) error = %v", err)
		}

		// Advance fake time inside the synctest bubble until epoch closes.
		synctest.Sleep(10 * time.Second)

		select {
		case settledID := <-settler.settleNotify:
			if settledID != "tick-win" {
				t.Fatalf("auto-cleared winner = %q, want tick-win", settledID)
			}
		default:
			t.Fatalf("expected background ticker to settle tick-win after EpochDuration")
		}
		if st, ok := eng.GetBidStatus("tick-lose"); !ok || st.Status != bidding.BidStatusLost {
			t.Errorf("tick-lose status = (%v, %v), want lost", st.Status, ok)
		}

		// Submit a new bid into epoch 2 (not yet expired) and call Close().
		// Close MUST drain and settle this active epoch before returning (R2).
		if _, err := eng.SubmitBid(ctx, bidding.BidSubmission{
			BidID:          "drain-win",
			AgentKey:       "agent-dw",
			Scope:          "site:drain",
			Chain:          bidding.ChainSolana,
			Asset:          "SOL",
			AmountAtomic:   "30000000", // $3
			PaymentPayload: testPayload("drain-1"),
			QueuedAt:       time.Now().Add(-10 * time.Second),
		}); err != nil {
			t.Fatalf("SubmitBid(drain-win) error = %v", err)
		}

		if err := eng.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		// Second Close must be idempotent.
		if err := eng.Close(); err != nil {
			t.Fatalf("second Close() error = %v", err)
		}

		if got, want := settler.settledBidIDs(), []string{"tick-win", "drain-win"}; !slices.Equal(got, want) {
			t.Fatalf("settledBidIDs = %v, want %v", got, want)
		}
		if st, ok := eng.GetBidStatus("drain-win"); !ok || st.Status != bidding.BidStatusSettled {
			t.Errorf("drain-win status after Close = (%v, %v), want settled", st.Status, ok)
		}

		// Post-Close calls fail closed with ErrEngineClosed.
		if _, err := eng.Offer("site:auto"); !errors.Is(err, bidding.ErrEngineClosed) {
			t.Errorf("Offer after Close error = %v, want ErrEngineClosed", err)
		}
		if _, err := eng.SubmitBid(ctx, bidding.BidSubmission{
			BidID:          "after-close",
			AgentKey:       "agent-ac",
			Scope:          "site:auto",
			Chain:          bidding.ChainXRPL,
			Asset:          "XRP",
			AmountAtomic:   "1000000",
			PaymentPayload: testPayload("ac-1"),
			QueuedAt:       time.Now(),
		}); !errors.Is(err, bidding.ErrEngineClosed) {
			t.Errorf("SubmitBid after Close error = %v, want ErrEngineClosed", err)
		}
	})
}

// ExampleEngine_ClearEpoch demonstrates deterministic sealed-bid clearing with
// equal-bid tie-breaking by longest wait duration and winner-only settlement.
//
// # Parameters
//
// None. Executed by `go test ./internal/bidding`.
//
// # Returns
//
// None. Verified via GoDoc Output comment.
//
// # Example
//
//	// Run with: go test -run '^ExampleEngine_ClearEpoch$' ./internal/bidding
//
// # Used By
//
// Executed by the Go test runner (`go test ./internal/bidding`).
func ExampleEngine_ClearEpoch() {
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	settler := newFakeSettler()
	eng, err := bidding.NewEngine(bidding.Config{
		FloorMicroUSD: 1_000_000,
		SlotsPerEpoch: 1,
		AssetRates:    testRates(),
		Now:           func() time.Time { return base },
	}, settler)
	if err != nil {
		panic(err)
	}
	defer eng.Close()

	ctx := context.Background()
	_, _ = eng.SubmitBid(ctx, bidding.BidSubmission{
		BidID:          "shorter-wait",
		AgentKey:       "agent-1",
		Scope:          "site:example",
		Chain:          bidding.ChainXRPL,
		Asset:          "XRP",
		AmountAtomic:   "1000000", // $2.00
		PaymentPayload: testPayload("ex-1"),
		QueuedAt:       base.Add(-10 * time.Second),
	})
	_, _ = eng.SubmitBid(ctx, bidding.BidSubmission{
		BidID:          "longer-wait",
		AgentKey:       "agent-2",
		Scope:          "site:example",
		Chain:          bidding.ChainStellar,
		Asset:          "XLM",
		AmountAtomic:   "20000000", // $2.00
		PaymentPayload: testPayload("ex-2"),
		QueuedAt:       base.Add(-60 * time.Second),
	})

	res, err := eng.ClearEpoch(ctx, "site:example", base.Add(10*time.Second))
	if err != nil {
		panic(err)
	}
	fmt.Printf("winner=%s settled=%d losers=%d\n", res.Winners[0].BidID, len(settler.settledBidIDs()), len(res.Losers))
	// Output:
	// winner=longer-wait settled=1 losers=1
}
