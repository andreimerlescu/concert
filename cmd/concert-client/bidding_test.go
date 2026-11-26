package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/bidding"
)

// fakeBidServer models Concert's waiting room + /_concert/bids +
// /_concert/bids/status endpoints in-process for deterministic unit and -race
// tests without real network or time.Sleep synchronization.
type fakeBidServer struct {
	mu                 sync.Mutex
	offer              auctionOffer
	submitStatus       string
	submitCookie       *http.Cookie
	submitPassToken    string
	pollStatuses       []string
	pollPassCookie     string
	pollPassToken      string
	admitAfterQueued   int
	queuedHits         int
	submittedBids      []bidSubmitRequest
	statusPolls        int
	admittedCookies    []string
	admittedPassTokens []string
}

// ServeHTTP handles target path GETs, POST /_concert/bids, and
// GET /_concert/bids/status for bidding CLI tests.
//
// # Parameters
//
//   - w: HTTP response writer.
//   - r: Incoming HTTP request.
//
// # Returns
//
// None. Writes deterministic JSON or admitted response bodies.
//
// # Example
//
//	// Registered with httptest.NewServer(srv).
//
// # Used By
//
// Invoked by net/http/httptest server handlers.
func (s *fakeBidServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch r.URL.Path {
	case "/drop":
		// Admit immediately if the client attached a settled pass cookie or token.
		if ck, err := r.Cookie("concert_fastlane"); err == nil && ck.Value != "" {
			s.admittedCookies = append(s.admittedCookies, ck.Value)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("admitted-via-pass-cookie"))
			return
		}
		if tok := r.Header.Get("X-Concert-Pass"); tok != "" {
			s.admittedPassTokens = append(s.admittedPassTokens, tok)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("admitted-via-pass-token"))
			return
		}
		s.queuedHits++
		if s.admitAfterQueued > 0 && s.queuedHits > s.admitAfterQueued {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("admitted-via-queue"))
			return
		}
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"queued":              true,
			"position":            s.queuedHits,
			"queue_depth":         10,
			"status_url":          "https://shop.example/queue/status/q1",
			"retry_after_seconds": 1,
			"auction":             s.offer,
		})
	case "/_concert/bids":
		var req bidSubmitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "bad json"})
			return
		}
		s.submittedBids = append(s.submittedBids, req)
		if s.submitCookie != nil {
			http.SetCookie(w, s.submitCookie)
		}
		status := s.submitStatus
		if status == "" {
			status = string(bidding.BidStatusPending)
		}
		resp := map[string]any{
			"bid_id": "bid-srv-1",
			"status": status,
		}
		if status == string(bidding.BidStatusSettled) {
			resp["transaction"] = "tx-instant-1"
		}
		if s.submitPassToken != "" {
			resp["pass_token"] = s.submitPassToken
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	case "/_concert/bids/status":
		s.statusPolls++
		idx := s.statusPolls - 1
		st := string(bidding.BidStatusPending)
		if idx < len(s.pollStatuses) {
			st = s.pollStatuses[idx]
		} else if len(s.pollStatuses) > 0 {
			st = s.pollStatuses[len(s.pollStatuses)-1]
		}
		resp := map[string]any{
			"bid_id": r.URL.Query().Get("bid_id"),
			"status": st,
		}
		if st == string(bidding.BidStatusSettled) || st == string(bidding.BidStatusWon) {
			resp["transaction"] = "tx-epoch-win"
			if s.pollPassCookie != "" {
				resp["pass_cookie"] = s.pollPassCookie
			}
			if s.pollPassToken != "" {
				resp["pass_token"] = s.pollPassToken
			}
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// testBidSigner returns a deterministic pluggable bidSigner for unit tests
// that records the bid amount and produces a clearly fake x402 payload.
//
// # Parameters
//
//   - sentinel: Marker string placed inside the fake payload to verify no
//     payload bytes are ever printed to output logs (S5).
//
// # Returns
//
// A bidSigner function safe for concurrent use.
//
// # Example
//
//	signer := testBidSigner("test-only-payload")
//	_ = signer
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/bidding_test.go:327 (direct call)
//   - cmd/concert-client/bidding_test.go:327 (function value)
//   - cmd/concert-client/bidding_test.go:409 (direct call)
//   - cmd/concert-client/bidding_test.go:409 (function value)
//   - cmd/concert-client/bidding_test.go:482 (direct call)
//   - cmd/concert-client/bidding_test.go:482 (function value)
//   - cmd/concert-client/bidding_test.go:622 (direct call)
//   - cmd/concert-client/bidding_test.go:622 (function value)
//   - cmd/concert-client/bidding_test.go:638 (direct call)
//   - cmd/concert-client/bidding_test.go:638 (function value)
//   - cmd/concert-client/bidding_test.go:664 (direct call)
//   - cmd/concert-client/bidding_test.go:664 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func testBidSigner(sentinel string) bidSigner {
	return func(ctx context.Context, offer auctionOffer, chain, asset string, bidMicroUSD int64) (bidPaymentPayload, error) {
		if err := ctx.Err(); err != nil {
			return bidPaymentPayload{}, err
		}
		if asset == "" {
			asset = defaultAssetForChain(chain)
		}
		raw, _ := json.Marshal(map[string]any{
			"x402Version": 2,
			"chain":       chain,
			"asset":       asset,
			"micro_usd":   bidMicroUSD,
			"fake_sig":    sentinel,
		})
		return bidPaymentPayload{
			Chain:          chain,
			Asset:          asset,
			AmountAtomic:   fmt.Sprintf("%d", bidMicroUSD),
			PaymentPayload: raw,
		}, nil
	}
}

// TestParseCLIArgsAndUSD verifies strict parsing of -bid, -max-bid,
// -bid-chain (100% crypto-only), -bid-asset, and -bid-poll-interval flags.
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -run '^TestParseCLIArgsAndUSD$' ./cmd/concert-client`.
//
// # Returns
//
// None. Fails t if flag or USD decimal parsing breaks.
//
// # Example
//
//	// Run with: go test -run '^TestParseCLIArgsAndUSD$' ./cmd/concert-client
//
// # Used By
//
// Invoked by the Go test runner (`go test ./cmd/concert-client`).
func TestParseCLIArgsAndUSD(t *testing.T) {
	t.Parallel()

	opts, err := parseCLIArgs([]string{
		"--wait", "/drop",
		"-bid",
		"-max-bid", "2.50",
		"-bid-chain", "xrpl",
		"-bid-asset", "XRP",
		"-bid-poll-interval", "250ms",
	})
	if err != nil {
		t.Fatalf("parseCLIArgs() error = %v", err)
	}
	if !opts.bidEnabled || opts.waitPath != "/drop" || opts.maxBidMicroUSD != 2_500_000 || opts.bidChain != bidding.ChainXRPL || opts.bidAsset != "XRP" || opts.bidPollInterval != 250*time.Millisecond {
		t.Fatalf("unexpected parsed opts: %+v", opts)
	}

	// Reject non-crypto chain in -bid-chain.
	if _, err := parseCLIArgs([]string{"--wait", "/drop", "-bid", "-max-bid", "1.00", "-bid-chain", "stripe"}); !errors.Is(err, ErrInvalidBidChain) {
		t.Fatalf("non-crypto -bid-chain error = %v, want ErrInvalidBidChain", err)
	}
	// Reject missing -max-bid when -bid is enabled.
	if _, err := parseCLIArgs([]string{"--wait", "/drop", "-bid"}); !errors.Is(err, ErrInvalidMaxBid) {
		t.Fatalf("missing -max-bid error = %v, want ErrInvalidMaxBid", err)
	}
	// Reject invalid/negative -max-bid.
	for _, bad := range []string{"0", "-1.00", "1.1234567", "abc"} {
		if _, err := parseUSDToMicroUSD(bad); !errors.Is(err, ErrInvalidMaxBid) {
			t.Errorf("parseUSDToMicroUSD(%q) error = %v, want ErrInvalidMaxBid", bad, err)
		}
	}
	// Reject invalid poll interval.
	if _, err := parseCLIArgs([]string{"--wait", "/drop", "-bid", "-max-bid", "1", "-bid-poll-interval", "-5s"}); !errors.Is(err, ErrInvalidBidPoll) {
		t.Fatalf("negative poll interval error = %v, want ErrInvalidBidPoll", err)
	}
	// Clamp tiny poll interval to minBidPollInterval.
	optsClamped, err := parseCLIArgs([]string{"--wait", "/drop", "-bid", "-max-bid=0.25", "-bid-poll-interval=1ms"})
	if err != nil {
		t.Fatalf("parseCLIArgs(clamped) error = %v", err)
	}
	if optsClamped.maxBidMicroUSD != 250_000 || optsClamped.bidPollInterval != minBidPollInterval {
		t.Errorf("clamped opts = (%d, %v), want (250000, %v)", optsClamped.maxBidMicroUSD, optsClamped.bidPollInterval, minBidPollInterval)
	}
}

// TestWaitWithBidding_InstantBuySettlesAndRetriesTarget verifies that an
// instant-buy auction offer bids exactly FloorMicroUSD (never overpaying up to
// -max-bid), attaches the returned pass cookie, and retries the target URL
// immediately to receive the admitted 200 OK body.
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -run '^TestWaitWithBidding_InstantBuySettlesAndRetriesTarget$' ./cmd/concert-client`.
//
// # Returns
//
// None. Fails t if instant-buy bid amount, cookie attachment, or admission fails.
//
// # Example
//
//	// Run with: go test -run '^TestWaitWithBidding_InstantBuySettlesAndRetriesTarget$' ./cmd/concert-client
//
// # Used By
//
// Invoked by the Go test runner (`go test ./cmd/concert-client`).
func TestWaitWithBidding_InstantBuySettlesAndRetriesTarget(t *testing.T) {
	t.Parallel()
	const payloadMarker = "fake-payload-marker-never-log"

	srv := &fakeBidServer{
		offer: auctionOffer{
			Mode:            bidding.ModeInstant,
			Scope:           "site:drop",
			FloorMicroUSD:   1_000_000, // $1.00
			Slots:           2,
			BidURL:          "/_concert/bids",
			StatusURL:       "/_concert/bids/status",
			SupportedChains: []string{"xrpl", "solana"},
		},
		submitStatus: string(bidding.BidStatusSettled),
		submitCookie: &http.Cookie{Name: "concert_fastlane", Value: "pass-cookie-instant-1"},
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	c := newClient(ts.URL)
	c.pause = func(context.Context, time.Duration) error {
		t.Error("instant-buy settled immediately; pause should not be called")
		return nil
	}

	var out bytes.Buffer
	err := c.waitWithBidding(t.Context(), "/drop", "sess.1.mac", bidConfig{
		Enabled:        true,
		MaxBidMicroUSD: 5_000_000, // $5.00 ceiling; instant-buy must only bid $1.00 floor
		Chain:          bidding.ChainXRPL,
		Asset:          "XRP",
		PollInterval:   100 * time.Millisecond,
		Signer:         testBidSigner(payloadMarker),
	}, &out)
	if err != nil {
		t.Fatalf("waitWithBidding(instant) error = %v", err)
	}

	srv.mu.Lock()
	submitted := slices.Clone(srv.submittedBids)
	cookies := slices.Clone(srv.admittedCookies)
	polls := srv.statusPolls
	srv.mu.Unlock()

	if len(submitted) != 1 || submitted[0].BidMicroUSD != 1_000_000 {
		t.Fatalf("submitted bids = %+v, want 1 instant bid at 1000000 micro-USD", submitted)
	}
	if polls != 0 {
		t.Errorf("status polls = %d, want 0 for synchronous instant settlement", polls)
	}
	if !slices.Equal(cookies, []string{"pass-cookie-instant-1"}) {
		t.Errorf("admitted cookies = %v, want [pass-cookie-instant-1]", cookies)
	}
	gotOut := out.String()
	if !strings.Contains(gotOut, "admitted-via-pass-cookie") {
		t.Errorf("output missing admitted body:\n%s", gotOut)
	}
	if strings.Contains(gotOut, payloadMarker) {
		t.Errorf("output leaked raw payment payload marker")
	}
}

// TestWaitWithBidding_SealedBidWinPollsAndAttachesPass proves that a sealed-bid
// auction submits up to -max-bid, polls /_concert/bids/status until settled,
// attaches the returned pass token, and retries the target URL automatically.
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -run '^TestWaitWithBidding_SealedBidWinPollsAndAttachesPass$' ./cmd/concert-client`.
//
// # Returns
//
// None. Fails t if sealed-bid polling or pass retry breaks.
//
// # Example
//
//	// Run with: go test -run '^TestWaitWithBidding_SealedBidWinPollsAndAttachesPass$' ./cmd/concert-client
//
// # Used By
//
// Invoked by the Go test runner (`go test ./cmd/concert-client`).
func TestWaitWithBidding_SealedBidWinPollsAndAttachesPass(t *testing.T) {
	t.Parallel()
	srv := &fakeBidServer{
		offer: auctionOffer{
			AuctionID:       "ep-win-1",
			Mode:            bidding.ModeAuction,
			Scope:           "site:drop",
			FloorMicroUSD:   1_000_000,
			Slots:           1,
			BidURL:          "/_concert/bids",
			StatusURL:       "/_concert/bids/status",
			SupportedChains: []string{"stellar", "solana"},
		},
		submitStatus:  string(bidding.BidStatusPending),
		pollStatuses:  []string{string(bidding.BidStatusPending), string(bidding.BidStatusSettled)},
		pollPassToken: "pass-tok-win-1",
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	c := newClient(ts.URL)
	var pauses int
	c.pause = func(ctx context.Context, _ time.Duration) error {
		pauses++
		return ctx.Err()
	}

	var out bytes.Buffer
	err := c.waitWithBidding(t.Context(), "/drop", "sess.2.mac", bidConfig{
		Enabled:        true,
		MaxBidMicroUSD: 3_000_000, // $3.00
		Chain:          bidding.ChainSolana,
		PollInterval:   200 * time.Millisecond,
		Signer:         testBidSigner("sealed-win-sig"),
	}, &out)
	if err != nil {
		t.Fatalf("waitWithBidding(sealed win) error = %v", err)
	}

	srv.mu.Lock()
	submitted := slices.Clone(srv.submittedBids)
	tokens := slices.Clone(srv.admittedPassTokens)
	polls := srv.statusPolls
	srv.mu.Unlock()

	if len(submitted) != 1 || submitted[0].BidMicroUSD != 3_000_000 || submitted[0].Chain != bidding.ChainSolana || submitted[0].Asset != "SOL" {
		t.Fatalf("submitted = %+v, want 1 Solana/SOL bid at 3000000", submitted)
	}
	if polls != 2 || pauses != 2 {
		t.Errorf("polls=%d pauses=%d, want 2/2", polls, pauses)
	}
	if !slices.Equal(tokens, []string{"pass-tok-win-1"}) {
		t.Errorf("admitted pass tokens = %v, want [pass-tok-win-1]", tokens)
	}
	if !strings.Contains(out.String(), "admitted-via-pass-token") {
		t.Errorf("output missing admitted body:\n%s", out.String())
	}
}

// TestWaitWithBidding_SealedBidLossPaysZeroAndContinuesWaiting proves that a
// losing bid logs that $0 was charged, never re-bids the same epoch, and
// seamlessly continues waiting-room polling until admitted via the queue.
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -run '^TestWaitWithBidding_SealedBidLossPaysZeroAndContinuesWaiting$' ./cmd/concert-client`.
//
// # Returns
//
// None. Fails t if loss handling or continued queue polling breaks.
//
// # Example
//
//	// Run with: go test -run '^TestWaitWithBidding_SealedBidLossPaysZeroAndContinuesWaiting$' ./cmd/concert-client
//
// # Used By
//
// Invoked by the Go test runner (`go test ./cmd/concert-client`).
func TestWaitWithBidding_SealedBidLossPaysZeroAndContinuesWaiting(t *testing.T) {
	t.Parallel()
	srv := &fakeBidServer{
		offer: auctionOffer{
			AuctionID:       "ep-loss-1",
			Mode:            bidding.ModeAuction,
			FloorMicroUSD:   1_000_000,
			Slots:           1,
			BidURL:          "/_concert/bids",
			StatusURL:       "/_concert/bids/status",
			SupportedChains: []string{"hedera"},
		},
		submitStatus:     string(bidding.BidStatusPending),
		pollStatuses:     []string{string(bidding.BidStatusLost)},
		admitAfterQueued: 2, // queued twice, admitted on 3rd GET
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	c := newClient(ts.URL)
	c.pause = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }

	var out bytes.Buffer
	err := c.waitWithBidding(t.Context(), "/drop", "sess.3.mac", bidConfig{
		Enabled:        true,
		MaxBidMicroUSD: 2_000_000,
		Chain:          bidding.ChainHedera,
		PollInterval:   100 * time.Millisecond,
		Signer:         testBidSigner("sealed-loss-sig"),
	}, &out)
	if err != nil {
		t.Fatalf("waitWithBidding(sealed loss) error = %v", err)
	}

	srv.mu.Lock()
	submittedCount := len(srv.submittedBids)
	queuedHits := srv.queuedHits
	srv.mu.Unlock()

	if submittedCount != 1 {
		t.Fatalf("submitted bids = %d, want 1 (must not re-bid same epoch)", submittedCount)
	}
	if queuedHits != 3 {
		t.Errorf("queuedHits = %d, want 3 (2 queued + 1 admitted)", queuedHits)
	}
	gotOut := out.String()
	if !strings.Contains(gotOut, "$0 charged") || !strings.Contains(gotOut, "admitted-via-queue") {
		t.Errorf("expected $0 charged log and normal queue admission:\n%s", gotOut)
	}
}

// TestWaitWithBidding_OverMaxBidSkipsAndWaits proves that when an auction's
// floor_micro_usd exceeds -max-bid, the client NEVER signs or submits a bid
// and falls back seamlessly to waiting-room polling.
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -run '^TestWaitWithBidding_OverMaxBidSkipsAndWaits$' ./cmd/concert-client`.
//
// # Returns
//
// None. Fails t if a bid is signed or submitted above -max-bid.
//
// # Example
//
//	// Run with: go test -run '^TestWaitWithBidding_OverMaxBidSkipsAndWaits$' ./cmd/concert-client
//
// # Used By
//
// Invoked by the Go test runner (`go test ./cmd/concert-client`).
func TestWaitWithBidding_OverMaxBidSkipsAndWaits(t *testing.T) {
	t.Parallel()
	srv := &fakeBidServer{
		offer: auctionOffer{
			AuctionID:       "ep-expensive",
			Mode:            bidding.ModeAuction,
			FloorMicroUSD:   5_000_000, // $5.00 floor > $2.00 max-bid
			Slots:           1,
			BidURL:          "/_concert/bids",
			StatusURL:       "/_concert/bids/status",
			SupportedChains: []string{"xrpl"},
		},
		admitAfterQueued: 1,
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	c := newClient(ts.URL)
	c.pause = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }

	signerCalled := false
	var out bytes.Buffer
	err := c.waitWithBidding(t.Context(), "/drop", "sess.4.mac", bidConfig{
		Enabled:        true,
		MaxBidMicroUSD: 2_000_000, // $2.00 ceiling
		Chain:          bidding.ChainXRPL,
		PollInterval:   100 * time.Millisecond,
		Signer: func(context.Context, auctionOffer, string, string, int64) (bidPaymentPayload, error) {
			signerCalled = true
			return bidPaymentPayload{}, errors.New("must never sign over max-bid")
		},
	}, &out)
	if err != nil {
		t.Fatalf("waitWithBidding(over max-bid) error = %v", err)
	}
	if signerCalled {
		t.Fatalf("signer was invoked despite floor > max-bid")
	}
	srv.mu.Lock()
	submittedCount := len(srv.submittedBids)
	srv.mu.Unlock()
	if submittedCount != 0 {
		t.Fatalf("submitted bids = %d, want 0", submittedCount)
	}
	gotOut := out.String()
	if !strings.Contains(gotOut, "exceeds -max-bid") || !strings.Contains(gotOut, "admitted-via-queue") {
		t.Errorf("expected skip message and queue admission:\n%s", gotOut)
	}
}

// TestWaitWithBidding_TimeoutAndCrossOriginGuard proves bounded status polling
// timeout handling (ErrBidTimeout) and same-origin URL enforcement (S9) with
// zero time.Sleep synchronization.
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -run '^TestWaitWithBidding_TimeoutAndCrossOriginGuard$' ./cmd/concert-client`.
//
// # Returns
//
// None. Fails t if timeout or cross-origin rejection fails.
//
// # Example
//
//	// Run with: go test -run '^TestWaitWithBidding_TimeoutAndCrossOriginGuard$' ./cmd/concert-client
//
// # Used By
//
// Invoked by the Go test runner (`go test ./cmd/concert-client`).
func TestWaitWithBidding_TimeoutAndCrossOriginGuard(t *testing.T) {
	t.Parallel()

	// 1. Bounded max poll attempts triggers ErrBidTimeout cleanly without hanging.
	srv := &fakeBidServer{
		offer: auctionOffer{
			AuctionID:       "ep-timeout",
			Mode:            bidding.ModeAuction,
			FloorMicroUSD:   1_000_000,
			Slots:           1,
			BidURL:          "/_concert/bids",
			StatusURL:       "/_concert/bids/status",
			SupportedChains: []string{"xrpl"},
		},
		submitStatus: string(bidding.BidStatusPending),
		pollStatuses: []string{string(bidding.BidStatusPending)},
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	c := newClient(ts.URL)
	c.pause = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }

	err := c.waitWithBidding(t.Context(), "/drop", "sess.5.mac", bidConfig{
		Enabled:         true,
		MaxBidMicroUSD:  2_000_000,
		Chain:           bidding.ChainXRPL,
		PollInterval:    100 * time.Millisecond,
		MaxPollAttempts: 3,
		Signer:          testBidSigner("timeout-sig"),
	}, &bytes.Buffer{})
	if !errors.Is(err, ErrBidTimeout) {
		t.Fatalf("waitWithBidding(max polls) error = %v, want ErrBidTimeout", err)
	}

	// 2. Context deadline exceeded during poll pause also surfaces ErrBidTimeout.
	c2 := newClient(ts.URL)
	c2.pause = func(ctx context.Context, _ time.Duration) error {
		return context.DeadlineExceeded
	}
	err = c2.waitWithBidding(t.Context(), "/drop", "sess.6.mac", bidConfig{
		Enabled:        true,
		MaxBidMicroUSD: 2_000_000,
		Chain:          bidding.ChainXRPL,
		PollInterval:   100 * time.Millisecond,
		Signer:         testBidSigner("deadline-sig"),
	}, &bytes.Buffer{})
	if !errors.Is(err, ErrBidTimeout) {
		t.Fatalf("waitWithBidding(deadline) error = %v, want ErrBidTimeout", err)
	}

	// 3. Cross-origin bid_url in auction offer is rejected before signing/posting (S9).
	evilSrv := &fakeBidServer{
		offer: auctionOffer{
			AuctionID:       "ep-evil",
			Mode:            bidding.ModeAuction,
			FloorMicroUSD:   1_000_000,
			Slots:           1,
			BidURL:          "https://attacker.invalid/_concert/bids",
			StatusURL:       "/_concert/bids/status",
			SupportedChains: []string{"xrpl"},
		},
	}
	evilTS := httptest.NewServer(evilSrv)
	t.Cleanup(evilTS.Close)

	c3 := newClient(evilTS.URL)
	err = c3.waitWithBidding(t.Context(), "/drop", "sess.7.mac", bidConfig{
		Enabled:        true,
		MaxBidMicroUSD: 2_000_000,
		Chain:          bidding.ChainXRPL,
		Signer:         testBidSigner("evil-sig"),
	}, &bytes.Buffer{})
	if !errors.Is(err, ErrCrossOriginURL) {
		t.Fatalf("cross-origin bid_url error = %v, want ErrCrossOriginURL", err)
	}
}

// TestRunWaitWithBidding_EndToEndWalletSigner exercises the full CLI run()
// path with --wait /drop -bid -max-bid 2.00 -bid-chain solana using the real
// local Solana wallet signer and an in-process httptest server.
//
// # Parameters
//
//   - t: Go testing harness; invoked via `go test -run '^TestRunWaitWithBidding_EndToEndWalletSigner$' ./cmd/concert-client`.
//
// # Returns
//
// None. Fails t if CLI wiring, local wallet signing, or pass admission fails.
//
// # Example
//
//	// Run with: go test -run '^TestRunWaitWithBidding_EndToEndWalletSigner$' ./cmd/concert-client
//
// # Used By
//
// Invoked by the Go test runner (`go test ./cmd/concert-client`).
func TestRunWaitWithBidding_EndToEndWalletSigner(t *testing.T) {
	s := newSetup(t)
	bidSrv := &fakeBidServer{
		offer: auctionOffer{
			AuctionID:       "ep-e2e-1",
			Mode:            bidding.ModeInstant,
			FloorMicroUSD:   1_500_000, // $1.50 <= $2.00
			Slots:           1,
			BidURL:          "/_concert/bids",
			StatusURL:       "/_concert/bids/status",
			SupportedChains: []string{"solana"},
		},
		submitStatus: string(bidding.BidStatusSettled),
		submitCookie: &http.Cookie{Name: "concert_fastlane", Value: "e2e-pass-cookie"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/_concert/session", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"session": "e2e.1.mac"})
	})
	mux.Handle("/", bidSrv)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	origin := strings.Replace(ts.URL, "127.0.0.1", "localhost", 1)
	t.Setenv("CONCERT_ORIGIN", origin)
	s.origin = origin

	if err := s.run("--wait", "/drop", "-bid", "-max-bid", "2.00", "-bid-chain", "solana", "-bid-poll-interval", "100ms"); err != nil {
		t.Fatalf("run(--wait -bid) error = %v", err)
	}

	bidSrv.mu.Lock()
	submitted := slices.Clone(bidSrv.submittedBids)
	cookies := slices.Clone(bidSrv.admittedCookies)
	bidSrv.mu.Unlock()

	if len(submitted) != 1 || submitted[0].Chain != bidding.ChainSolana || submitted[0].BidMicroUSD != 1_500_000 {
		t.Fatalf("e2e submitted = %+v, want 1 solana bid at 1500000", submitted)
	}
	if !slices.Equal(cookies, []string{"e2e-pass-cookie"}) {
		t.Fatalf("e2e admitted cookies = %v, want [e2e-pass-cookie]", cookies)
	}
}
