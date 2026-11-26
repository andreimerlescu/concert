// Package bidding implements Concert's non-custodial hybrid AI agent pass
// bidding bounded context.
//
// Concert is 100% crypto-only, supporting XRPL, Stellar, Hedera, and Solana
// payment authorizations via x402 v2. When priority slots are available for a
// scope, the engine offers instant-buy admission at FloorMicroUSD; when
// saturated, it runs timed sealed-bid clearing epochs that verify bids
// off-chain, settle ONLY winning bids on-chain, promote runners-up on
// settlement failure, and drop losing bids unsettled (losers pay $0 with zero
// custody and zero refunds).
package bidding

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Canonical supported crypto chain identifiers. Concert is 100% crypto-only.
const (
	ChainXRPL    = "xrpl"
	ChainStellar = "stellar"
	ChainHedera  = "hedera"
	ChainSolana  = "solana"
)

// Offer mode identifiers returned in [Offer.Mode].
const (
	ModeInstant = "instant"
	ModeAuction = "auction"
)

// Operational defaults and safety bounds (R3).
const (
	DefaultEpochDuration   = 10 * time.Second
	DefaultSlotsPerEpoch   = 1
	DefaultMaxBidsPerEpoch = 1024
	DefaultMaxPayloadBytes = 64 << 10 // 64 KiB, aligned with fastlane.MaxBody
	DefaultReplayCacheSize = 4096
	DefaultMaxScopes       = 256
	DefaultMaxHistory      = 4096
	DefaultVerifyTimeout   = 5 * time.Second
	DefaultSettleTimeout   = 10 * time.Second
	DefaultBidURL          = "/_concert/bid"
	DefaultStatusURL       = "/_concert/bid/status"
)

// BidStatus enumerates the lifecycle states of a submitted bid.
type BidStatus string

const (
	BidStatusPending          BidStatus = "pending"
	BidStatusWon              BidStatus = "won"
	BidStatusLost             BidStatus = "lost"
	BidStatusRejected         BidStatus = "rejected"
	BidStatusSettled          BidStatus = "settled"
	BidStatusSettlementFailed BidStatus = "settlement_failed"
)

// Sentinel errors returned by [Engine] operations. Callers should match with
// [errors.Is].
var (
	ErrInvalidConfig      = errors.New("bidding: invalid configuration")
	ErrEngineClosed       = errors.New("bidding: engine is closed")
	ErrAlreadyStarted     = errors.New("bidding: engine ticker already started")
	ErrUnsupportedChain   = errors.New("bidding: unsupported crypto chain")
	ErrUnsupportedAsset   = errors.New("bidding: unsupported asset for chain")
	ErrInvalidBid         = errors.New("bidding: invalid bid submission")
	ErrUnderFloor         = errors.New("bidding: bid below floor micro-USD")
	ErrIneligibleWait     = errors.New("bidding: agent wait duration below minimum")
	ErrReplayDetected     = errors.New("bidding: payment payload replay detected")
	ErrEpochFull          = errors.New("bidding: epoch bid capacity reached")
	ErrScopeLimitReached  = errors.New("bidding: maximum active scopes reached")
	ErrRebidNotHigher     = errors.New("bidding: re-bid must exceed agent's active pending bid")
	ErrVerificationFailed = errors.New("bidding: off-chain payment verification failed")
	ErrSettlementFailed   = errors.New("bidding: on-chain settlement failed")
)

// AssetRate configures exact integer USD normalization for one crypto
// (Chain, Asset) pair without binary floating point.
//
// NormalizedMicroUSD is computed as:
//
//	floor(AmountAtomic * MicroUSDPerUnit / 10^Decimals)
//
// where 1_000_000 micro-USD equals $1.00 USD.
type AssetRate struct {
	Chain           string
	Asset           string
	Decimals        int
	MicroUSDPerUnit int64
}

// Config configures a hybrid bidding [Engine].
type Config struct {
	// EpochDuration sets how long each sealed-bid clearing epoch stays open.
	// Defaults to DefaultEpochDuration (10s).
	EpochDuration time.Duration
	// SlotsPerEpoch is the maximum number of winning bids settled per epoch.
	// Defaults to DefaultSlotsPerEpoch (1).
	SlotsPerEpoch int
	// MinWaitDuration is the minimum queue wait required before an agent may
	// submit a bid. Zero disables the wait-time floor.
	MinWaitDuration time.Duration
	// FloorMicroUSD is the minimum accepted bid and instant-buy price in
	// micro-USD (1_000_000 == $1.00). Must be positive.
	FloorMicroUSD int64
	// MaxBidsPerEpoch bounds the number of unique active pending bids in one
	// scope epoch (R3). Defaults to DefaultMaxBidsPerEpoch (1024).
	MaxBidsPerEpoch int
	// MaxPayloadBytes bounds the byte length of BidSubmission.PaymentPayload (R3).
	// Defaults to DefaultMaxPayloadBytes (64 KiB).
	MaxPayloadBytes int
	// ReplayCacheSize bounds the O(1) LRU replay digest cache (R3).
	// Defaults to DefaultReplayCacheSize (4096).
	ReplayCacheSize int
	// MaxScopes bounds the number of distinct scopes tracked concurrently (R3).
	// Defaults to DefaultMaxScopes (256).
	MaxScopes int
	// MaxStatusHistory bounds the number of BidRecord snapshots retained for
	// status queries (R3). Defaults to DefaultMaxHistory (4096).
	MaxStatusHistory int
	// VerifyTimeout bounds each off-chain PaymentSettler.Verify call.
	// Defaults to DefaultVerifyTimeout (5s).
	VerifyTimeout time.Duration
	// SettleTimeout bounds each on-chain PaymentSettler.Settle call per winner.
	// Defaults to DefaultSettleTimeout (10s).
	SettleTimeout time.Duration
	// SupportedChains restricts accepted chains to a subset of
	// {xrpl, stellar, hedera, solana}. Defaults to all four crypto chains.
	SupportedChains []string
	// AssetRates defines per-chain/asset USD normalization rates. When empty,
	// DefaultAssetRates() is applied for the configured SupportedChains.
	AssetRates []AssetRate
	// BidURL is the HTTP endpoint advertised in Offer.BidURL. Defaults to
	// DefaultBidURL ("/_concert/bid").
	BidURL string
	// StatusURL is the HTTP endpoint advertised in Offer.StatusURL. Defaults to
	// DefaultStatusURL ("/_concert/bid/status").
	StatusURL string
	// JournalPath optionally enables a durable 0600 JSONL epoch/settlement
	// journal at the given filesystem path.
	JournalPath string
	// SlotProbe optionally reports whether priority slots are currently open
	// for scope. When nil, Engine uses its internal per-scope open-slot flags
	// controlled via SetOpenSlots (defaulting to false / auction mode).
	SlotProbe func(scope string) bool
	// ClusterSync optionally propagates accepted bids to concert-kv (CQ.BID).
	ClusterSync ClusterSync
	// Now optionally supplies the wall clock for deterministic testing.
	// Defaults to time.Now.
	Now func() time.Time
}

// BidSubmission is the value object submitted by an AI agent for either
// instant-buy admission or a sealed-bid auction epoch.
//
// PaymentPayload may contain signed x402 v2 payment authorization bytes and is
// treated as sensitive material: Engine never logs it, never writes it to the
// JSONL journal, and copies it defensively on entry.
type BidSubmission struct {
	BidID              string    `json:"bid_id"`
	AgentKey           string    `json:"agent_key"`
	Scope              string    `json:"scope"`
	Chain              string    `json:"chain"`
	Asset              string    `json:"asset"`
	AmountAtomic       string    `json:"amount_atomic"`
	NormalizedMicroUSD int64     `json:"normalized_micro_usd"`
	PaymentPayload     []byte    `json:"-"`
	QueuedAt           time.Time `json:"queued_at"`
	ReceivedAt         time.Time `json:"received_at"`
}

// Offer describes the active admission terms for a scope: either instant-buy
// at FloorMicroUSD when slots are open, or a timed sealed-bid auction when
// saturated.
type Offer struct {
	Mode            string    `json:"mode"`
	AuctionID       string    `json:"auction_id,omitempty"`
	Scope           string    `json:"scope"`
	FloorMicroUSD   int64     `json:"floor_micro_usd"`
	ClosesAt        time.Time `json:"closes_at,omitempty"`
	Slots           int       `json:"slots"`
	MinWaitSeconds  int64     `json:"min_wait_seconds"`
	BidURL          string    `json:"bid_url"`
	StatusURL       string    `json:"status_url"`
	SupportedChains []string  `json:"supported_chains"`
}

// BidRecord is an immutable, secret-free snapshot of a bid's lifecycle state
// returned by [Engine.SubmitBid], [Engine.GetBidStatus], and [Engine.ClearEpoch].
type BidRecord struct {
	BidID              string        `json:"bid_id"`
	AuctionID          string        `json:"auction_id,omitempty"`
	AgentKey           string        `json:"agent_key"`
	Scope              string        `json:"scope"`
	Chain              string        `json:"chain"`
	Asset              string        `json:"asset"`
	AmountAtomic       string        `json:"amount_atomic"`
	NormalizedMicroUSD int64         `json:"normalized_micro_usd"`
	Status             BidStatus     `json:"status"`
	Payer              string        `json:"payer,omitempty"`
	Transaction        string        `json:"transaction,omitempty"`
	PolicyID           string        `json:"policy_id,omitempty"`
	Reason             string        `json:"reason,omitempty"`
	WaitDuration       time.Duration `json:"wait_duration"`
	QueuedAt           time.Time     `json:"queued_at"`
	ReceivedAt         time.Time     `json:"received_at"`
	UpdatedAt          time.Time     `json:"updated_at"`
}

// EngineStats captures point-in-time counters for observability and testing.
type EngineStats struct {
	Submitted          int64
	Rejected           int64
	InstantSettled     int64
	EpochsCleared      int64
	WinnersSettled     int64
	SettlementFailures int64
	LosersDropped      int64
	ReplaysBlocked     int64
	ClusterSyncErrors  int64
	JournalErrors      int64
}

// pendingBid holds an off-chain-verified bid awaiting epoch clearing.
type pendingBid struct {
	submission BidSubmission
	payer      string
	policyID   string
	wait       time.Duration
}

// scopeEpoch holds the open sealed-bid epoch state for one scope.
// All fields are owned and guarded by Engine.mu.
type scopeEpoch struct {
	auctionID string
	scope     string
	startedAt time.Time
	closesAt  time.Time
	// byAgent enforces at most one active pending bid per (AgentKey, EpochID).
	byAgent map[string]*pendingBid
}

// Engine is the bounded-context aggregate managing per-scope hybrid AI agent
// pass bidding, off-chain verification, replay defense, deterministic sealed-bid
// epoch clearing, winner-only settlement, and durable 0600 journaling.
//
// All exported methods are safe for concurrent use by multiple goroutines.
// Mutable state (epochs, openSlots, history, lifecycle flags) is guarded by mu;
// mu is never held across PaymentSettler, ClusterSync, or Journal I/O (C4).
type Engine struct {
	cfg             Config
	settler         PaymentSettler
	supportedChains []string
	chainSet        map[string]struct{}
	rates           map[string]AssetRate
	replay          *ReplayCache
	journal         *Journal
	now             func() time.Time

	mu        sync.Mutex
	closed    bool
	started   bool
	epochs    map[string]*scopeEpoch // guarded by mu
	openSlots map[string]bool        // guarded by mu
	history   *statusHistory         // guarded by mu
	epochSeq  uint64                 // guarded by mu

	// Background ticker ownership (C1/R2): Start spawns at most one tickerLoop
	// goroutine; Close signals stopCh/cancel and joins wg before draining.
	wakeCh   chan struct{}
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	// Independent operational counters updated atomically.
	submitted          atomic.Int64
	rejected           atomic.Int64
	instantSettled     atomic.Int64
	epochsCleared      atomic.Int64
	winnersSettled     atomic.Int64
	settlementFailures atomic.Int64
	losersDropped      atomic.Int64
	replaysBlocked     atomic.Int64
	clusterSyncErrors  atomic.Int64
	journalErrors      atomic.Int64
}

// DefaultAssetRates returns baseline micro-USD normalization rates for the
// four supported crypto chains (XRPL, Stellar, Hedera, Solana) using their
// canonical native decimals. Operators should supply live rates via
// [Config.AssetRates] in production.
//
// # Parameters
//
// None.
//
// # Returns
//
// A freshly allocated slice of AssetRate entries covering XRPL (XRP), Stellar
// (XLM), Hedera (0.0.0 / HBAR), and Solana (SOL).
//
// # Example
//
//	rates := DefaultAssetRates()
//	_ = len(rates)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:530 (direct call)
//   - internal/bidding/auction.go:530 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func DefaultAssetRates() []AssetRate {
	return []AssetRate{
		{Chain: ChainXRPL, Asset: "XRP", Decimals: 6, MicroUSDPerUnit: 2_000_000},
		{Chain: ChainStellar, Asset: "XLM", Decimals: 7, MicroUSDPerUnit: 250_000},
		{Chain: ChainHedera, Asset: "0.0.0", Decimals: 8, MicroUSDPerUnit: 200_000},
		{Chain: ChainSolana, Asset: "SOL", Decimals: 9, MicroUSDPerUnit: 150_000_000},
	}
}

// NormalizeChain validates and maps a chain or CAIP-2 network identifier to
// its canonical lowercase Concert chain name (xrpl, stellar, hedera, or
// solana). Any non-crypto or unknown identifier is rejected.
//
// # Parameters
//
//   - raw: Bare chain name (e.g. "xrpl") or CAIP-2 network string (e.g.
//     "xrpl:0", "stellar:pubnet", "hedera:mainnet",
//     "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp").
//
// # Returns
//
// The canonical lowercase chain identifier and true if supported, or ("", false)
// otherwise.
//
// # Example
//
//	chain, ok := NormalizeChain("xrpl:0")
//	_, _ = chain, ok // "xrpl", true
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:514 (direct call)
//   - internal/bidding/auction.go:514 (function value)
//   - internal/bidding/auction.go:538 (direct call)
//   - internal/bidding/auction.go:538 (function value)
//   - internal/bidding/auction.go:827 (direct call)
//   - internal/bidding/auction.go:827 (function value)
//   - internal/bidding/auction.go:1110 (direct call)
//   - internal/bidding/auction.go:1110 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func NormalizeChain(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return "", false
	}
	family, _, _ := strings.Cut(s, ":")
	switch family {
	case ChainXRPL, ChainStellar, ChainHedera, ChainSolana:
		return family, true
	default:
		return "", false
	}
}

// NewEngine validates cfg, opens any configured 0600 journal, initializes the
// bounded replay cache and rate table, and returns a ready [Engine].
//
// # Parameters
//
//   - cfg: Engine configuration. FloorMicroUSD must be > 0; all optional bounds
//     default to safe non-zero limits. SupportedChains may contain only crypto
//     chains from {xrpl, stellar, hedera, solana}.
//   - settler: Non-nil [PaymentSettler] performing off-chain verification and
//     winner-only on-chain settlement.
//
// # Returns
//
// An initialized *Engine, or an error wrapping [ErrInvalidConfig] or journal
// open errors. The caller must call [Engine.Close] to release resources and
// drain active epochs.
//
// # Example
//
//	engine, err := NewEngine(Config{
//		FloorMicroUSD: 1_000_000,
//		SlotsPerEpoch: 2,
//	}, settler)
//	if err != nil {
//		return err // inside a function returning error
//	}
//	defer engine.Close()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:511 (direct call)
//   - internal/bidding/bidding_test.go:634 (direct call)
//   - internal/bidding/bidding_test.go:647 (direct call)
//   - internal/bidding/bidding_test.go:823 (direct call)
//   - internal/bidding/bidding_test.go:1010 (direct call)
//   - internal/bidding/bidding_test.go:1093 (direct call)
//   - internal/bidding/bidding_test.go:1264 (direct call)
//   - internal/bidding/bidding_test.go:1324 (direct call)
//   - internal/bidding/bidding_test.go:1446 (direct call)
//   - internal/bidding/bidding_test.go:1554 (direct call)
//   - internal/bidding/bidding_test.go:1685 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func NewEngine(cfg Config, settler PaymentSettler) (*Engine, error) {
	if settler == nil {
		return nil, fmt.Errorf("%w: payment settler must not be nil", ErrInvalidConfig)
	}
	if cfg.FloorMicroUSD <= 0 {
		return nil, fmt.Errorf("%w: floor_micro_usd must be positive", ErrInvalidConfig)
	}
	if cfg.EpochDuration < 0 {
		return nil, fmt.Errorf("%w: epoch_duration must be non-negative", ErrInvalidConfig)
	}
	if cfg.EpochDuration == 0 {
		cfg.EpochDuration = DefaultEpochDuration
	}
	if cfg.SlotsPerEpoch < 0 {
		return nil, fmt.Errorf("%w: slots_per_epoch must be positive", ErrInvalidConfig)
	}
	if cfg.SlotsPerEpoch == 0 {
		cfg.SlotsPerEpoch = DefaultSlotsPerEpoch
	}
	if cfg.MinWaitDuration < 0 {
		return nil, fmt.Errorf("%w: min_wait_duration must be non-negative", ErrInvalidConfig)
	}
	if cfg.MaxBidsPerEpoch < 0 {
		return nil, fmt.Errorf("%w: max_bids_per_epoch must be positive", ErrInvalidConfig)
	}
	if cfg.MaxBidsPerEpoch == 0 {
		cfg.MaxBidsPerEpoch = DefaultMaxBidsPerEpoch
	}
	if cfg.MaxPayloadBytes < 0 {
		return nil, fmt.Errorf("%w: max_payload_bytes must be positive", ErrInvalidConfig)
	}
	if cfg.MaxPayloadBytes == 0 {
		cfg.MaxPayloadBytes = DefaultMaxPayloadBytes
	}
	if cfg.ReplayCacheSize < 0 {
		return nil, fmt.Errorf("%w: replay_cache_size must be positive", ErrInvalidConfig)
	}
	if cfg.ReplayCacheSize == 0 {
		cfg.ReplayCacheSize = DefaultReplayCacheSize
	}
	if cfg.MaxScopes < 0 {
		return nil, fmt.Errorf("%w: max_scopes must be positive", ErrInvalidConfig)
	}
	if cfg.MaxScopes == 0 {
		cfg.MaxScopes = DefaultMaxScopes
	}
	if cfg.MaxStatusHistory < 0 {
		return nil, fmt.Errorf("%w: max_status_history must be positive", ErrInvalidConfig)
	}
	if cfg.MaxStatusHistory == 0 {
		cfg.MaxStatusHistory = DefaultMaxHistory
	}
	if cfg.VerifyTimeout < 0 {
		return nil, fmt.Errorf("%w: verify_timeout must be non-negative", ErrInvalidConfig)
	}
	if cfg.VerifyTimeout == 0 {
		cfg.VerifyTimeout = DefaultVerifyTimeout
	}
	if cfg.SettleTimeout < 0 {
		return nil, fmt.Errorf("%w: settle_timeout must be non-negative", ErrInvalidConfig)
	}
	if cfg.SettleTimeout == 0 {
		cfg.SettleTimeout = DefaultSettleTimeout
	}
	if strings.TrimSpace(cfg.BidURL) == "" {
		cfg.BidURL = DefaultBidURL
	}
	if strings.TrimSpace(cfg.StatusURL) == "" {
		cfg.StatusURL = DefaultStatusURL
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	rawChains := cfg.SupportedChains
	if len(rawChains) == 0 {
		rawChains = []string{ChainXRPL, ChainStellar, ChainHedera, ChainSolana}
	}
	chainSet := make(map[string]struct{}, len(rawChains))
	supported := make([]string, 0, len(rawChains))
	for _, rc := range rawChains {
		norm, ok := NormalizeChain(rc)
		if !ok {
			return nil, fmt.Errorf("%w: unsupported chain %q", ErrInvalidConfig, rc)
		}
		if _, dup := chainSet[norm]; dup {
			continue
		}
		chainSet[norm] = struct{}{}
		supported = append(supported, norm)
	}
	if len(supported) == 0 {
		return nil, fmt.Errorf("%w: at least one supported crypto chain is required", ErrInvalidConfig)
	}

	rawRates := cfg.AssetRates
	if len(rawRates) == 0 {
		for _, def := range DefaultAssetRates() {
			if _, ok := chainSet[def.Chain]; ok {
				rawRates = append(rawRates, def)
			}
		}
	}
	rates := make(map[string]AssetRate, len(rawRates))
	for _, r := range rawRates {
		normChain, ok := NormalizeChain(r.Chain)
		if !ok {
			return nil, fmt.Errorf("%w: asset rate uses unsupported chain %q", ErrInvalidConfig, r.Chain)
		}
		asset := strings.TrimSpace(r.Asset)
		if asset == "" {
			return nil, fmt.Errorf("%w: asset rate for %q has empty asset", ErrInvalidConfig, normChain)
		}
		if r.Decimals < 0 || r.Decimals > 18 {
			return nil, fmt.Errorf("%w: asset %s/%s decimals %d out of range [0,18]", ErrInvalidConfig, normChain, asset, r.Decimals)
		}
		if r.MicroUSDPerUnit <= 0 {
			return nil, fmt.Errorf("%w: asset %s/%s micro_usd_per_unit must be positive", ErrInvalidConfig, normChain, asset)
		}
		r.Chain = normChain
		r.Asset = asset
		rates[rateKey(normChain, asset)] = r
	}

	replay, err := NewReplayCache(cfg.ReplayCacheSize)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	var journal *Journal
	if strings.TrimSpace(cfg.JournalPath) != "" {
		journal, err = OpenJournal(cfg.JournalPath)
		if err != nil {
			return nil, fmt.Errorf("open bidding journal: %w", err)
		}
	}

	return &Engine{
		cfg:             cfg,
		settler:         settler,
		supportedChains: supported,
		chainSet:        chainSet,
		rates:           rates,
		replay:          replay,
		journal:         journal,
		now:             nowFn,
		epochs:          make(map[string]*scopeEpoch),
		openSlots:       make(map[string]bool),
		history:         newStatusHistory(cfg.MaxStatusHistory),
		wakeCh:          make(chan struct{}, 1),
		stopCh:          make(chan struct{}),
	}, nil
}

// rateKey builds the canonical lookup key for an asset rate table entry.
//
// # Parameters
//
//   - chain: Canonical lowercase chain identifier.
//   - asset: Trimmed asset identifier.
//
// # Returns
//
// Composite lookup key string.
//
// # Example
//
//	k := rateKey(ChainXRPL, "XRP")
//	_ = k
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:554 (direct call)
//   - internal/bidding/auction.go:554 (function value)
//   - internal/bidding/auction.go:835 (direct call)
//   - internal/bidding/auction.go:835 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func rateKey(chain, asset string) string {
	return chain + "/" + asset
}

// HasOpenSlots reports whether priority slots are currently available for
// scope. When true, the engine operates in instant-buy mode at FloorMicroUSD;
// when false, the engine operates in sealed-bid auction mode.
//
// If [Config.SlotProbe] is set, HasOpenSlots delegates to it without holding
// internal locks. Otherwise it reads the per-scope flag configured by
// [Engine.SetOpenSlots], defaulting to false (auction mode).
//
// # Parameters
//
//   - scope: Site or route scope identifier. Whitespace is trimmed.
//
// # Returns
//
// true if instant-buy slots are open for scope, false if saturated. Safe for
// concurrent use.
//
// # Example
//
//	engine.SetOpenSlots("site:shop", true)
//	_ = engine.HasOpenSlots("site:shop") // true
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:747 (direct call)
//   - internal/bidding/auction.go:747 (function value)
//   - internal/bidding/auction.go:966 (direct call)
//   - internal/bidding/auction.go:966 (function value)
//   - internal/bidding/bidding_test.go:532 (direct call)
//   - internal/bidding/bidding_test.go:575 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) HasOpenSlots(scope string) bool {
	s := strings.TrimSpace(scope)
	if e.cfg.SlotProbe != nil {
		return e.cfg.SlotProbe(s)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.openSlots[s]
}

// SetOpenSlots updates the local open-slot indicator for scope when no
// [Config.SlotProbe] callback is installed.
//
// # Parameters
//
//   - scope: Site or route scope identifier. Empty scopes are ignored.
//   - open: true to switch scope into instant-buy mode, false for sealed-bid
//     auction mode.
//
// # Returns
//
// None. Safe for concurrent use.
//
// # Example
//
//	engine.SetOpenSlots("route:/checkout", false)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:1338 (direct call)
//   - internal/bidding/bidding_test.go:1353 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) SetOpenSlots(scope string, open bool) {
	s := strings.TrimSpace(scope)
	if s == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !open {
		delete(e.openSlots, s)
		return
	}
	if _, exists := e.openSlots[s]; !exists && len(e.openSlots) >= e.cfg.MaxScopes {
		return
	}
	e.openSlots[s] = true
}

// Offer returns the current hybrid admission [Offer] for scope.
//
// When [Engine.HasOpenSlots] returns true, Offer returns an instant-buy offer
// (`Mode: "instant"`) priced at FloorMicroUSD with no auction wait. When
// saturated, Offer ensures an active sealed-bid clearing epoch exists for scope
// and returns its terms (`Mode: "auction"`).
//
// # Parameters
//
//   - scope: Non-empty site or route scope identifier.
//
// # Returns
//
// An [Offer] snapshot with a cloned SupportedChains slice, or an error matching
// [ErrInvalidBid], [ErrEngineClosed], or [ErrScopeLimitReached]. Safe for
// concurrent use.
//
// # Example
//
//	offer, err := engine.Offer("site:drop")
//	if err != nil {
//		return err // inside a function returning error
//	}
//	_ = offer.Mode
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:535 (direct call)
//   - internal/bidding/bidding_test.go:578 (direct call)
//   - internal/bidding/bidding_test.go:1469 (direct call)
//   - internal/bidding/bidding_test.go:1646 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) Offer(scope string) (Offer, error) {
	s := strings.TrimSpace(scope)
	if s == "" {
		return Offer{}, fmt.Errorf("%w: scope is required", ErrInvalidBid)
	}
	open := e.HasOpenSlots(s)
	now := e.now().UTC()

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return Offer{}, ErrEngineClosed
	}
	if open {
		e.mu.Unlock()
		return Offer{
			Mode:            ModeInstant,
			Scope:           s,
			FloorMicroUSD:   e.cfg.FloorMicroUSD,
			Slots:           e.cfg.SlotsPerEpoch,
			MinWaitSeconds:  0,
			BidURL:          e.cfg.BidURL,
			StatusURL:       e.cfg.StatusURL,
			SupportedChains: slices.Clone(e.supportedChains),
		}, nil
	}
	ep, created, err := e.ensureEpochLocked(s, now)
	if err != nil {
		e.mu.Unlock()
		return Offer{}, err
	}
	offer := Offer{
		Mode:            ModeAuction,
		AuctionID:       ep.auctionID,
		Scope:           s,
		FloorMicroUSD:   e.cfg.FloorMicroUSD,
		ClosesAt:        ep.closesAt,
		Slots:           e.cfg.SlotsPerEpoch,
		MinWaitSeconds:  int64(e.cfg.MinWaitDuration / time.Second),
		BidURL:          e.cfg.BidURL,
		StatusURL:       e.cfg.StatusURL,
		SupportedChains: slices.Clone(e.supportedChains),
	}
	e.mu.Unlock()

	if created {
		e.signalWake()
	}
	return offer, nil
}

// NormalizeMicroUSD converts an exact positive integer atomic amount string
// for (chain, asset) into micro-USD using integer big.Int arithmetic (zero
// binary floating point).
//
// # Parameters
//
//   - chain: Chain or CAIP-2 network identifier; must be in SupportedChains.
//   - asset: Asset identifier matching a configured [AssetRate].
//   - amountAtomic: Base-10 positive integer string in the asset's smallest unit.
//
// # Returns
//
// Normalized amount in micro-USD (1_000_000 == $1.00), or an error matching
// [ErrUnsupportedChain], [ErrUnsupportedAsset], or [ErrInvalidBid]. Safe for
// concurrent use.
//
// # Example
//
//	microUSD, err := engine.NormalizeMicroUSD(ChainXRPL, "XRP", "1000000")
//	if err != nil {
//		return err // inside a function returning error
//	}
//	_ = microUSD
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:1119 (direct call)
//   - internal/bidding/auction.go:1119 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) NormalizeMicroUSD(chain, asset, amountAtomic string) (int64, error) {
	normChain, ok := NormalizeChain(chain)
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrUnsupportedChain, chain)
	}
	if _, enabled := e.chainSet[normChain]; !enabled {
		return 0, fmt.Errorf("%w: %q is not enabled", ErrUnsupportedChain, normChain)
	}
	trimmedAsset := strings.TrimSpace(asset)
	rate, ok := e.rates[rateKey(normChain, trimmedAsset)]
	if !ok {
		return 0, fmt.Errorf("%w: %s/%s", ErrUnsupportedAsset, normChain, trimmedAsset)
	}
	amtStr := strings.TrimSpace(amountAtomic)
	if amtStr == "" || len(amtStr) > 36 {
		return 0, fmt.Errorf("%w: invalid atomic amount", ErrInvalidBid)
	}
	for i := 0; i < len(amtStr); i++ {
		if amtStr[i] < '0' || amtStr[i] > '9' {
			return 0, fmt.Errorf("%w: atomic amount must contain digits only", ErrInvalidBid)
		}
	}
	amt, ok := new(big.Int).SetString(amtStr, 10)
	if !ok || amt.Sign() <= 0 {
		return 0, fmt.Errorf("%w: atomic amount must be positive", ErrInvalidBid)
	}
	// Compute floor(amt * MicroUSDPerUnit / 10^Decimals) in exact integer math.
	num := new(big.Int).Mul(amt, big.NewInt(rate.MicroUSDPerUnit))
	denom := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(rate.Decimals)), nil)
	quot := new(big.Int).Quo(num, denom)
	if !quot.IsInt64() || quot.Int64() > math.MaxInt64 {
		return 0, fmt.Errorf("%w: normalized micro-USD overflows int64", ErrInvalidBid)
	}
	return quot.Int64(), nil
}

// SubmitBid validates, off-chain verifies, and admits a bid into either
// instant-buy settlement (when [Engine.HasOpenSlots] is true) or the active
// sealed-bid epoch for bid.Scope (when saturated).
//
// Invalid, under-floor, unsupported-chain, ineligible-wait, replayed, or
// off-chain verification-rejected bids are NEVER stored in the epoch and NEVER
// passed to [PaymentSettler.Settle].
//
// If the same AgentKey already holds a pending bid in the active epoch, a
// strictly higher NormalizedMicroUSD re-bid cleanly replaces the prior pending
// bid (marking the prior bid as lost); an equal or lower re-bid is rejected
// with [ErrRebidNotHigher].
//
// # Parameters
//
//   - ctx: Controls cancellation and deadlines for off-chain verification,
//     optional cluster sync, and (in instant-buy mode) settlement. Must be
//     non-nil.
//   - bid: Agent bid submission. PaymentPayload is defensively copied so caller
//     mutation after return cannot race. NormalizedMicroUSD is authoritatively
//     computed from AmountAtomic and the engine's configured AssetRates.
//
// # Returns
//
// The resulting [BidRecord] snapshot and nil on acceptance (status "pending"
// in auction mode, or "settled" in instant-buy mode). On error, returns any
// diagnostic BidRecord (status "rejected" or "settlement_failed") and an error
// matching one of the package sentinel errors. Safe for concurrent use.
//
// # Example
//
//	rec, err := engine.SubmitBid(ctx, BidSubmission{
//		AgentKey:       "agent-1",
//		Scope:          "site:drop",
//		Chain:          ChainXRPL,
//		Asset:          "XRP",
//		AmountAtomic:   "1000000",
//		PaymentPayload: []byte(`{"x402Version":2,"nonce":"abc"}`),
//		QueuedAt:       time.Now().Add(-30 * time.Second),
//	})
//	if err != nil {
//		return err // inside a function returning error
//	}
//	_ = rec.Status
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:550 (direct call)
//   - internal/bidding/bidding_test.go:775 (direct call)
//   - internal/bidding/bidding_test.go:911 (direct call)
//   - internal/bidding/bidding_test.go:1034 (direct call)
//   - internal/bidding/bidding_test.go:1107 (direct call)
//   - internal/bidding/bidding_test.go:1123 (direct call)
//   - internal/bidding/bidding_test.go:1140 (direct call)
//   - internal/bidding/bidding_test.go:1154 (direct call)
//   - internal/bidding/bidding_test.go:1168 (direct call)
//   - internal/bidding/bidding_test.go:1183 (direct call)
//   - internal/bidding/bidding_test.go:1275 (direct call)
//   - internal/bidding/bidding_test.go:1339 (direct call)
//   - internal/bidding/bidding_test.go:1354 (direct call)
//   - internal/bidding/bidding_test.go:1366 (direct call)
//   - internal/bidding/bidding_test.go:1471 (direct call)
//   - internal/bidding/bidding_test.go:1575 (direct call)
//   - internal/bidding/bidding_test.go:1587 (direct call)
//   - internal/bidding/bidding_test.go:1617 (direct call)
//   - internal/bidding/bidding_test.go:1649 (direct call)
//   - internal/bidding/bidding_test.go:1697 (direct call)
//   - internal/bidding/bidding_test.go:1707 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) SubmitBid(ctx context.Context, bid BidSubmission) (BidRecord, error) {
	if ctx == nil {
		return BidRecord{}, fmt.Errorf("%w: context must not be nil", ErrInvalidBid)
	}
	if err := ctx.Err(); err != nil {
		return BidRecord{}, err
	}

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return BidRecord{}, ErrEngineClosed
	}
	e.mu.Unlock()

	normalized, wait, err := e.validateSubmission(bid)
	if err != nil {
		e.rejected.Add(1)
		return BidRecord{
			BidID:      normalized.BidID,
			AgentKey:   normalized.AgentKey,
			Scope:      normalized.Scope,
			Chain:      normalized.Chain,
			Asset:      normalized.Asset,
			Status:     BidStatusRejected,
			Reason:     err.Error(),
			ReceivedAt: normalized.ReceivedAt,
			UpdatedAt:  normalized.ReceivedAt,
		}, err
	}

	openSlots := e.HasOpenSlots(normalized.Scope)
	if !openSlots && e.cfg.MinWaitDuration > 0 && wait < e.cfg.MinWaitDuration {
		e.rejected.Add(1)
		return BidRecord{
			BidID:              normalized.BidID,
			AgentKey:           normalized.AgentKey,
			Scope:              normalized.Scope,
			Chain:              normalized.Chain,
			Asset:              normalized.Asset,
			AmountAtomic:       normalized.AmountAtomic,
			NormalizedMicroUSD: normalized.NormalizedMicroUSD,
			Status:             BidStatusRejected,
			Reason:             "wait_below_minimum",
			WaitDuration:       wait,
			QueuedAt:           normalized.QueuedAt,
			ReceivedAt:         normalized.ReceivedAt,
			UpdatedAt:          normalized.ReceivedAt,
		}, fmt.Errorf("%w: waited %s, need at least %s", ErrIneligibleWait, wait, e.cfg.MinWaitDuration)
	}

	// Fast-path replay check before invoking off-chain verification.
	digest := PayloadDigest(normalized.Chain, normalized.Asset, normalized.AmountAtomic, normalized.PaymentPayload)
	if e.replay.Contains(digest) {
		e.rejected.Add(1)
		e.replaysBlocked.Add(1)
		return BidRecord{
			BidID:              normalized.BidID,
			AgentKey:           normalized.AgentKey,
			Scope:              normalized.Scope,
			Chain:              normalized.Chain,
			Asset:              normalized.Asset,
			AmountAtomic:       normalized.AmountAtomic,
			NormalizedMicroUSD: normalized.NormalizedMicroUSD,
			Status:             BidStatusRejected,
			Reason:             "replay_detected",
			WaitDuration:       wait,
			QueuedAt:           normalized.QueuedAt,
			ReceivedAt:         normalized.ReceivedAt,
			UpdatedAt:          normalized.ReceivedAt,
		}, ErrReplayDetected
	}

	// Off-chain verification MUST run outside e.mu (C4) and never broadcasts.
	receipt, err := e.verifyOffChain(ctx, normalized)
	if err != nil || !receipt.Valid {
		e.rejected.Add(1)
		reason := receipt.InvalidReason
		if reason == "" && err != nil {
			reason = "verification_error"
		}
		if reason == "" {
			reason = "invalid_authorization"
		}
		retErr := fmt.Errorf("%w: %s", ErrVerificationFailed, reason)
		if err != nil {
			retErr = fmt.Errorf("%w: %w", ErrVerificationFailed, err)
		}
		return BidRecord{
			BidID:              normalized.BidID,
			AgentKey:           normalized.AgentKey,
			Scope:              normalized.Scope,
			Chain:              normalized.Chain,
			Asset:              normalized.Asset,
			AmountAtomic:       normalized.AmountAtomic,
			NormalizedMicroUSD: normalized.NormalizedMicroUSD,
			Status:             BidStatusRejected,
			Payer:              receipt.Payer,
			PolicyID:           receipt.PolicyID,
			Reason:             reason,
			WaitDuration:       wait,
			QueuedAt:           normalized.QueuedAt,
			ReceivedAt:         normalized.ReceivedAt,
			UpdatedAt:          e.now().UTC(),
		}, retErr
	}

	if openSlots {
		return e.submitInstantBuy(ctx, normalized, digest, receipt, wait)
	}
	return e.submitSealedBid(ctx, normalized, digest, receipt, wait)
}

// validateSubmission validates and defensively normalizes an incoming
// BidSubmission without acquiring locks or performing I/O.
//
// # Parameters
//
//   - bid: Caller-supplied BidSubmission.
//
// # Returns
//
// A defensively copied and normalized BidSubmission, its computed non-negative
// WaitDuration, and any validation error.
//
// # Example
//
//	// Internal helper called by Engine.SubmitBid.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:950 (direct call)
//   - internal/bidding/auction.go:950 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) validateSubmission(bid BidSubmission) (BidSubmission, time.Duration, error) {
	now := e.now().UTC()
	out := BidSubmission{
		BidID:        strings.TrimSpace(bid.BidID),
		AgentKey:     strings.TrimSpace(bid.AgentKey),
		Scope:        strings.TrimSpace(bid.Scope),
		Chain:        strings.TrimSpace(bid.Chain),
		Asset:        strings.TrimSpace(bid.Asset),
		AmountAtomic: strings.TrimSpace(bid.AmountAtomic),
		QueuedAt:     bid.QueuedAt.UTC(),
		ReceivedAt:   bid.ReceivedAt.UTC(),
	}
	if out.ReceivedAt.IsZero() {
		out.ReceivedAt = now
	}
	if out.BidID == "" {
		id, err := newRandomID("bid")
		if err != nil {
			return out, 0, fmt.Errorf("%w: generate bid id: %w", ErrInvalidBid, err)
		}
		out.BidID = id
	}
	if out.Scope == "" {
		return out, 0, fmt.Errorf("%w: scope is required", ErrInvalidBid)
	}
	if out.AgentKey == "" {
		return out, 0, fmt.Errorf("%w: agent_key is required", ErrInvalidBid)
	}
	if len(bid.PaymentPayload) == 0 {
		return out, 0, fmt.Errorf("%w: payment_payload is required", ErrInvalidBid)
	}
	if len(bid.PaymentPayload) > e.cfg.MaxPayloadBytes {
		return out, 0, fmt.Errorf("%w: payment_payload exceeds %d bytes", ErrInvalidBid, e.cfg.MaxPayloadBytes)
	}
	// Defensive copy isolates Engine state from post-call caller mutations (C2).
	out.PaymentPayload = bytes.Clone(bid.PaymentPayload)

	normChain, ok := NormalizeChain(out.Chain)
	if !ok {
		return out, 0, fmt.Errorf("%w: %q", ErrUnsupportedChain, out.Chain)
	}
	if _, enabled := e.chainSet[normChain]; !enabled {
		return out, 0, fmt.Errorf("%w: %q", ErrUnsupportedChain, normChain)
	}
	out.Chain = normChain

	microUSD, err := e.NormalizeMicroUSD(out.Chain, out.Asset, out.AmountAtomic)
	if err != nil {
		return out, 0, err
	}
	out.NormalizedMicroUSD = microUSD
	if out.NormalizedMicroUSD < e.cfg.FloorMicroUSD {
		return out, 0, fmt.Errorf("%w: got %d micro-USD, floor is %d", ErrUnderFloor, out.NormalizedMicroUSD, e.cfg.FloorMicroUSD)
	}

	var wait time.Duration
	if !out.QueuedAt.IsZero() && out.ReceivedAt.After(out.QueuedAt) {
		wait = out.ReceivedAt.Sub(out.QueuedAt)
	}
	return out, wait, nil
}

// verifyOffChain invokes PaymentSettler.Verify with a bounded timeout context.
//
// # Parameters
//
//   - ctx: Parent request context.
//   - bid: Validated BidSubmission whose PaymentPayload is cloned before handoff.
//
// # Returns
//
// The off-chain VerifyReceipt and any error returned by the settler.
//
// # Example
//
//	// Internal helper called by Engine.SubmitBid with e.mu unlocked.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:1009 (direct call)
//   - internal/bidding/auction.go:1009 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) verifyOffChain(ctx context.Context, bid BidSubmission) (VerifyReceipt, error) {
	vctx, cancel := context.WithTimeout(ctx, e.cfg.VerifyTimeout)
	defer cancel()
	bid.PaymentPayload = bytes.Clone(bid.PaymentPayload)
	return e.settler.Verify(vctx, bid)
}

// submitInstantBuy settles an off-chain-verified bid immediately when open
// priority slots are available for the scope, bypassing auction wait.
//
// # Parameters
//
//   - ctx: Parent request context.
//   - bid: Validated BidSubmission.
//   - digest: SHA-256 payload digest for replay protection.
//   - verified: Successful off-chain VerifyReceipt.
//   - wait: Computed queue wait duration.
//
// # Returns
//
// Settled or settlement_failed BidRecord and any error.
//
// # Example
//
//	// Internal helper called by Engine.SubmitBid in instant-buy mode.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:1043 (direct call)
//   - internal/bidding/auction.go:1043 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) submitInstantBuy(ctx context.Context, bid BidSubmission, digest [32]byte, verified VerifyReceipt, wait time.Duration) (BidRecord, error) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return BidRecord{}, ErrEngineClosed
	}
	e.mu.Unlock()

	if !e.replay.AddIfAbsent(digest) {
		e.rejected.Add(1)
		e.replaysBlocked.Add(1)
		return BidRecord{
			BidID:              bid.BidID,
			AgentKey:           bid.AgentKey,
			Scope:              bid.Scope,
			Chain:              bid.Chain,
			Asset:              bid.Asset,
			AmountAtomic:       bid.AmountAtomic,
			NormalizedMicroUSD: bid.NormalizedMicroUSD,
			Status:             BidStatusRejected,
			Reason:             "replay_detected",
			WaitDuration:       wait,
			QueuedAt:           bid.QueuedAt,
			ReceivedAt:         bid.ReceivedAt,
			UpdatedAt:          e.now().UTC(),
		}, ErrReplayDetected
	}

	e.submitted.Add(1)
	sReceipt, err := e.settleWinner(ctx, bid)
	now := e.now().UTC()
	rec := BidRecord{
		BidID:              bid.BidID,
		AgentKey:           bid.AgentKey,
		Scope:              bid.Scope,
		Chain:              bid.Chain,
		Asset:              bid.Asset,
		AmountAtomic:       bid.AmountAtomic,
		NormalizedMicroUSD: bid.NormalizedMicroUSD,
		Payer:              firstNonEmpty(sReceipt.Payer, verified.Payer),
		Transaction:        sReceipt.Transaction,
		PolicyID:           verified.PolicyID,
		WaitDuration:       wait,
		QueuedAt:           bid.QueuedAt,
		ReceivedAt:         bid.ReceivedAt,
		UpdatedAt:          now,
	}

	var retErr error
	if err != nil || !sReceipt.Settled {
		rec.Status = BidStatusSettlementFailed
		rec.Reason = firstNonEmpty(sReceipt.ErrorReason, "settlement_failed")
		e.settlementFailures.Add(1)
		if err != nil {
			retErr = fmt.Errorf("%w: %w", ErrSettlementFailed, err)
		} else {
			retErr = fmt.Errorf("%w: %s", ErrSettlementFailed, rec.Reason)
		}
	} else {
		rec.Status = BidStatusSettled
		e.instantSettled.Add(1)
		e.winnersSettled.Add(1)
	}

	e.mu.Lock()
	e.history.Put(rec)
	e.mu.Unlock()

	if e.journal != nil {
		entry := JournalEntry{
			Type:      "instant_buy",
			Timestamp: now,
			Scope:     bid.Scope,
		}
		if rec.Status == BidStatusSettled {
			entry.Winners = []BidRecord{rec}
		} else {
			entry.SettlementFailures = []BidRecord{rec}
		}
		if jerr := e.journal.Append(entry); jerr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("append instant-buy journal: %w", jerr))
		}
	}

	return rec, retErr
}

// submitSealedBid admits an off-chain-verified bid into the scope's active
// sealed-bid epoch, enforcing replay protection, MaxBidsPerEpoch, and
// one-active-bid-per-(AgentKey, EpochID) replacement semantics.
//
// # Parameters
//
//   - ctx: Parent request context used for optional ClusterSync propagation.
//   - bid: Validated BidSubmission.
//   - digest: SHA-256 payload digest for replay protection.
//   - verified: Successful off-chain VerifyReceipt.
//   - wait: Computed queue wait duration.
//
// # Returns
//
// Pending BidRecord snapshot and nil on admission, or an error on rejection.
//
// # Example
//
//	// Internal helper called by Engine.SubmitBid in sealed-bid mode.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:1045 (direct call)
//   - internal/bidding/auction.go:1045 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) submitSealedBid(ctx context.Context, bid BidSubmission, digest [32]byte, verified VerifyReceipt, wait time.Duration) (BidRecord, error) {
	now := e.now().UTC()
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return BidRecord{}, ErrEngineClosed
	}
	ep, created, err := e.ensureEpochLocked(bid.Scope, now)
	if err != nil {
		e.mu.Unlock()
		e.rejected.Add(1)
		return BidRecord{}, err
	}

	// Enforce one active pending bid per (AgentKey, EpochID): only a strictly
	// higher re-bid may replace the agent's existing pending bid.
	prev, hasPrev := ep.byAgent[bid.AgentKey]
	if hasPrev {
		if bid.NormalizedMicroUSD <= prev.submission.NormalizedMicroUSD {
			e.mu.Unlock()
			e.rejected.Add(1)
			return BidRecord{
				BidID:              bid.BidID,
				AuctionID:          ep.auctionID,
				AgentKey:           bid.AgentKey,
				Scope:              bid.Scope,
				Chain:              bid.Chain,
				Asset:              bid.Asset,
				AmountAtomic:       bid.AmountAtomic,
				NormalizedMicroUSD: bid.NormalizedMicroUSD,
				Status:             BidStatusRejected,
				Reason:             "rebid_not_higher",
				WaitDuration:       wait,
				QueuedAt:           bid.QueuedAt,
				ReceivedAt:         bid.ReceivedAt,
				UpdatedAt:          now,
			}, fmt.Errorf("%w: new %d <= active %d", ErrRebidNotHigher, bid.NormalizedMicroUSD, prev.submission.NormalizedMicroUSD)
		}
	} else if len(ep.byAgent) >= e.cfg.MaxBidsPerEpoch {
		e.mu.Unlock()
		e.rejected.Add(1)
		return BidRecord{
			BidID:              bid.BidID,
			AuctionID:          ep.auctionID,
			AgentKey:           bid.AgentKey,
			Scope:              bid.Scope,
			Chain:              bid.Chain,
			Asset:              bid.Asset,
			AmountAtomic:       bid.AmountAtomic,
			NormalizedMicroUSD: bid.NormalizedMicroUSD,
			Status:             BidStatusRejected,
			Reason:             "epoch_full",
			WaitDuration:       wait,
			QueuedAt:           bid.QueuedAt,
			ReceivedAt:         bid.ReceivedAt,
			UpdatedAt:          now,
		}, ErrEpochFull
	}

	// Claim the payload digest atomically only once all admission checks pass so
	// rejected bids cannot pollute the replay cache, while concurrent duplicate
	// submissions cannot both slip through.
	if !e.replay.AddIfAbsent(digest) {
		e.mu.Unlock()
		e.rejected.Add(1)
		e.replaysBlocked.Add(1)
		return BidRecord{
			BidID:              bid.BidID,
			AuctionID:          ep.auctionID,
			AgentKey:           bid.AgentKey,
			Scope:              bid.Scope,
			Chain:              bid.Chain,
			Asset:              bid.Asset,
			AmountAtomic:       bid.AmountAtomic,
			NormalizedMicroUSD: bid.NormalizedMicroUSD,
			Status:             BidStatusRejected,
			Reason:             "replay_detected",
			WaitDuration:       wait,
			QueuedAt:           bid.QueuedAt,
			ReceivedAt:         bid.ReceivedAt,
			UpdatedAt:          now,
		}, ErrReplayDetected
	}

	if hasPrev {
		// Supersede prior pending bid cleanly without settling it (pays $0).
		e.history.Put(BidRecord{
			BidID:              prev.submission.BidID,
			AuctionID:          ep.auctionID,
			AgentKey:           prev.submission.AgentKey,
			Scope:              prev.submission.Scope,
			Chain:              prev.submission.Chain,
			Asset:              prev.submission.Asset,
			AmountAtomic:       prev.submission.AmountAtomic,
			NormalizedMicroUSD: prev.submission.NormalizedMicroUSD,
			Status:             BidStatusLost,
			Payer:              prev.payer,
			PolicyID:           prev.policyID,
			Reason:             "replaced_by_higher_bid",
			WaitDuration:       prev.wait,
			QueuedAt:           prev.submission.QueuedAt,
			ReceivedAt:         prev.submission.ReceivedAt,
			UpdatedAt:          now,
		})
		e.losersDropped.Add(1)
	}

	ep.byAgent[bid.AgentKey] = &pendingBid{
		submission: bid,
		payer:      verified.Payer,
		policyID:   verified.PolicyID,
		wait:       wait,
	}
	rec := BidRecord{
		BidID:              bid.BidID,
		AuctionID:          ep.auctionID,
		AgentKey:           bid.AgentKey,
		Scope:              bid.Scope,
		Chain:              bid.Chain,
		Asset:              bid.Asset,
		AmountAtomic:       bid.AmountAtomic,
		NormalizedMicroUSD: bid.NormalizedMicroUSD,
		Status:             BidStatusPending,
		Payer:              verified.Payer,
		PolicyID:           verified.PolicyID,
		WaitDuration:       wait,
		QueuedAt:           bid.QueuedAt,
		ReceivedAt:         bid.ReceivedAt,
		UpdatedAt:          now,
	}
	e.history.Put(rec)
	e.mu.Unlock()

	e.submitted.Add(1)
	if created {
		e.signalWake()
	}

	// Best-effort cluster replication (e.g. concert-kv CQ.BID) runs outside
	// e.mu with a bounded timeout so remote store blips never stall bidding.
	if e.cfg.ClusterSync != nil {
		sctx, cancel := context.WithTimeout(ctx, e.cfg.VerifyTimeout)
		err := e.cfg.ClusterSync.SyncBid(sctx, rec.Scope, rec.BidID, rec.NormalizedMicroUSD)
		cancel()
		if err != nil {
			e.clusterSyncErrors.Add(1)
		}
	}

	return rec, nil
}

// GetBidStatus returns the latest immutable [BidRecord] snapshot for bidID.
//
// # Parameters
//
//   - bidID: Bid identifier to look up.
//
// # Returns
//
// The BidRecord and true if retained in the bounded status history, or the
// zero BidRecord and false if unknown or evicted. Safe for concurrent use.
//
// # Example
//
//	rec, ok := engine.GetBidStatus("bid-123")
//	_, _ = rec, ok
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:962 (direct call)
//   - internal/bidding/bidding_test.go:1064 (direct call)
//   - internal/bidding/bidding_test.go:1195 (direct call)
//   - internal/bidding/bidding_test.go:1489 (direct call)
//   - internal/bidding/bidding_test.go:1611 (direct call)
//   - internal/bidding/bidding_test.go:1641 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) GetBidStatus(bidID string) (BidRecord, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.history.Get(bidID)
}

// Stats returns a point-in-time snapshot of engine counters.
//
// # Parameters
//
// None.
//
// # Returns
//
// [EngineStats] read atomically. Safe for concurrent use.
//
// # Example
//
//	st := engine.Stats()
//	_ = st.WinnersSettled
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/bidding_test.go:1287 (direct call)
//   - internal/bidding/bidding_test.go:1515 (direct call)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) Stats() EngineStats {
	return EngineStats{
		Submitted:          e.submitted.Load(),
		Rejected:           e.rejected.Load(),
		InstantSettled:     e.instantSettled.Load(),
		EpochsCleared:      e.epochsCleared.Load(),
		WinnersSettled:     e.winnersSettled.Load(),
		SettlementFailures: e.settlementFailures.Load(),
		LosersDropped:      e.losersDropped.Load(),
		ReplaysBlocked:     e.replaysBlocked.Load(),
		ClusterSyncErrors:  e.clusterSyncErrors.Load(),
		JournalErrors:      e.journalErrors.Load(),
	}
}

// ensureEpochLocked returns the active epoch for scope, creating one if absent.
// Caller must hold e.mu.
//
// # Parameters
//
//   - scope: Trimmed non-empty scope name.
//   - now: Current UTC timestamp used for StartedAt and ClosesAt.
//
// # Returns
//
// The active *scopeEpoch, a bool indicating whether a new epoch was created,
// and ErrScopeLimitReached if creating a new scope would exceed MaxScopes.
//
// # Example
//
//	// Internal helper called under e.mu by Offer and submitSealedBid.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:768 (direct call)
//   - internal/bidding/auction.go:768 (function value)
//   - internal/bidding/auction.go:1317 (direct call)
//   - internal/bidding/auction.go:1317 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) ensureEpochLocked(scope string, now time.Time) (*scopeEpoch, bool, error) {
	if ep, ok := e.epochs[scope]; ok {
		return ep, false, nil
	}
	if len(e.epochs) >= e.cfg.MaxScopes {
		return nil, false, ErrScopeLimitReached
	}
	e.epochSeq++
	ep := &scopeEpoch{
		auctionID: fmt.Sprintf("ep-%d-%d", now.UnixNano(), e.epochSeq),
		scope:     scope,
		startedAt: now,
		closesAt:  now.Add(e.cfg.EpochDuration),
		byAgent:   make(map[string]*pendingBid),
	}
	e.epochs[scope] = ep
	return ep, true, nil
}

// signalWake nudges the background epoch ticker goroutine without blocking.
//
// # Parameters
//
// None.
//
// # Returns
//
// None. Safe for concurrent use.
//
// # Example
//
//	// Internal helper called when a new epoch is created.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:788 (direct call)
//   - internal/bidding/auction.go:788 (function value)
//   - internal/bidding/auction.go:1445 (direct call)
//   - internal/bidding/auction.go:1445 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (e *Engine) signalWake() {
	select {
	case e.wakeCh <- struct{}{}:
	default:
	}
}

// newRandomID generates an unguessable prefixed identifier using crypto/rand.
//
// # Parameters
//
//   - prefix: Short human-readable prefix (e.g. "bid").
//
// # Returns
//
// Identifier formatted as "<prefix>-<24 hex chars>", or a CSPRNG read error.
//
// # Example
//
//	id, err := newRandomID("bid")
//	_, _ = id, err
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:1089 (direct call)
//   - internal/bidding/auction.go:1089 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func newRandomID(prefix string) (string, error) {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(buf[:]), nil
}

// firstNonEmpty returns the first trimmed non-empty string in values.
//
// # Parameters
//
//   - values: Candidate strings inspected in order.
//
// # Returns
//
// The first non-empty value, or "" if all candidates are empty.
//
// # Example
//
//	_ = firstNonEmpty("", "fallback")
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/bidding/auction.go:1233 (direct call)
//   - internal/bidding/auction.go:1233 (function value)
//   - internal/bidding/auction.go:1245 (direct call)
//   - internal/bidding/auction.go:1245 (function value)
//   - internal/bidding/clear.go:372 (direct call)
//   - internal/bidding/clear.go:372 (function value)
//   - internal/bidding/clear.go:376 (direct call)
//   - internal/bidding/clear.go:376 (function value)
//   - internal/bidding/clear.go:382 (direct call)
//   - internal/bidding/clear.go:382 (function value)
//
// Scope: internal/bidding package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}
