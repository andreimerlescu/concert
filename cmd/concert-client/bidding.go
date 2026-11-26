package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/bidding"
	"github.com/andreimerlescu/concert/internal/gateway"
	"github.com/andreimerlescu/concert/internal/x402"
)

// Bidding CLI defaults and safety bounds (R3).
const (
	defaultBidPollInterval = time.Second
	minBidPollInterval     = 100 * time.Millisecond
	maxBidPollInterval     = 30 * time.Second
	defaultBidPollTimeout  = 60 * time.Second
	maxBidPollTimeout      = 5 * time.Minute
	maxBidPollAttempts     = 300
	maxBidResponseBytes    = 1 << 20 // 1 MiB
	maxAttemptedAuctions   = 1024
	defaultBidPath         = "/_concert/bids"
	defaultBidStatusPath   = "/_concert/bids/status"
)

// Sentinel errors for agent bidding CLI validation and flow control.
var (
	ErrInvalidMaxBid    = errors.New("invalid -max-bid USD amount")
	ErrInvalidBidChain  = errors.New("unsupported -bid-chain (must be xrpl, stellar, hedera, or solana)")
	ErrInvalidBidPoll   = errors.New("invalid -bid-poll-interval duration")
	ErrBidTimeout       = errors.New("timed out waiting for bid status resolution")
	ErrCrossOriginURL   = errors.New("auction URL does not match Concert origin")
	ErrMissingBidSigner = errors.New("no crypto wallet signer available for bidding")
)

// cliOptions holds parsed command-line options for concert-client.
type cliOptions struct {
	nft             bool
	direct          bool
	waitPath        string
	bidEnabled      bool
	maxBidMicroUSD  int64
	bidChain        string
	bidAsset        string
	bidPollInterval time.Duration
}

// auctionOffer is the optional auction block included inside a queued 429
// response when Concert is accepting instant-buy or sealed-bid pass bids.
type auctionOffer struct {
	AuctionID       string             `json:"auction_id"`
	Mode            string             `json:"mode"`
	Scope           string             `json:"scope,omitempty"`
	FloorMicroUSD   int64              `json:"floor_micro_usd"`
	ClosesAt        string             `json:"closes_at,omitempty"`
	Slots           int                `json:"slots"`
	MinWaitSeconds  int64              `json:"min_wait_seconds,omitempty"`
	BidURL          string             `json:"bid_url"`
	StatusURL       string             `json:"status_url"`
	SupportedChains []string           `json:"supported_chains"`
	Requirements    *x402.Requirements `json:"requirements,omitempty"`
}

// bidPaymentPayload is the signed crypto authorization produced by a bidSigner.
// PaymentPayload is sensitive signed material and must never be logged (S5).
type bidPaymentPayload struct {
	Chain          string
	Asset          string
	AmountAtomic   string
	PaymentPayload []byte
}

// bidSigner constructs a signed crypto payment authorization for an auction
// offer without broadcasting on-chain.
type bidSigner func(ctx context.Context, offer auctionOffer, chain, asset string, bidMicroUSD int64) (bidPaymentPayload, error)

// bidConfig controls automated AI agent pass bidding during wait loops.
type bidConfig struct {
	Enabled         bool
	MaxBidMicroUSD  int64
	Chain           string
	Asset           string
	PollInterval    time.Duration
	PollTimeout     time.Duration
	MaxPollAttempts int
	Signer          bidSigner
}

// bidSubmitRequest is the JSON request posted to /_concert/bids.
type bidSubmitRequest struct {
	AuctionID      string          `json:"auction_id,omitempty"`
	Scope          string          `json:"scope,omitempty"`
	Chain          string          `json:"chain"`
	Asset          string          `json:"asset"`
	AmountAtomic   string          `json:"amount_atomic"`
	BidMicroUSD    int64           `json:"bid_micro_usd"`
	PaymentPayload json.RawMessage `json:"payment_payload"`
}

// bidStatusResponse models the JSON reply from both POST /_concert/bids and
// GET /_concert/bids/status?bid_id=...
type bidStatusResponse struct {
	failure
	BidID       string `json:"bid_id"`
	Status      string `json:"status"`
	Transaction string `json:"transaction,omitempty"`
	PassCookie  string `json:"pass_cookie,omitempty"`
	PassToken   string `json:"pass_token,omitempty"`
	Session     string `json:"session,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// passCredentials holds fast-lane pass credentials returned after a winning or
// instant-buy bid settles, attached automatically on the next target retry.
type passCredentials struct {
	cookies   []*http.Cookie
	rawCookie string
	passToken string
	session   string
}

// bidOutcome summarizes the result of attempting one auction offer.
type bidOutcome struct {
	settled bool
	creds   passCredentials
}

// parseUSDToMicroUSD converts a positive decimal USD string (up to 6 decimal
// places, e.g. "2.50" or "0.05") into exact integer micro-USD without binary
// floating point.
//
// # Parameters
//
//   - raw: Trimmed decimal USD amount string. Must be strictly positive, have
//     at most 6 fractional digits, and fit in int64 micro-USD.
//
// # Returns
//
// Exact positive micro-USD integer (1_000_000 == $1.00), or an error wrapping
// [ErrInvalidMaxBid].
//
// # Example
//
//	micro, err := parseUSDToMicroUSD("1.25")
//	_, _ = micro, err // 1250000, nil
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/bidding.go:405 (direct call)
//   - cmd/concert-client/bidding.go:405 (function value)
//   - cmd/concert-client/bidding_test.go:256 (direct call)
//   - cmd/concert-client/bidding_test.go:256 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func parseUSDToMicroUSD(raw string) (int64, error) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "+") {
		return 0, fmt.Errorf("%w: must be a positive USD decimal", ErrInvalidMaxBid)
	}
	intPart, fracPart, hasDot := strings.Cut(s, ".")
	if hasDot && strings.Contains(fracPart, ".") {
		return 0, fmt.Errorf("%w: multiple decimal points", ErrInvalidMaxBid)
	}
	if intPart == "" && fracPart == "" {
		return 0, fmt.Errorf("%w: empty amount", ErrInvalidMaxBid)
	}
	if intPart == "" {
		intPart = "0"
	}
	if len(fracPart) > 6 {
		extra := strings.TrimRight(fracPart[6:], "0")
		if extra != "" {
			return 0, fmt.Errorf("%w: at most 6 fractional digits supported", ErrInvalidMaxBid)
		}
		fracPart = fracPart[:6]
	}
	fracPart += strings.Repeat("0", 6-len(fracPart))
	digits := intPart + fracPart
	if len(digits) > 19 {
		return 0, fmt.Errorf("%w: amount overflows int64 micro-USD", ErrInvalidMaxBid)
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, fmt.Errorf("%w: non-digit character in amount", ErrInvalidMaxBid)
		}
	}
	v, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || v == 0 || v > math.MaxInt64 {
		return 0, fmt.Errorf("%w: must be positive and within int64 bounds", ErrInvalidMaxBid)
	}
	return int64(v), nil
}

// formatMicroUSD renders an integer micro-USD value as a human-readable USD
// string without binary floating point (e.g. 1500000 -> "$1.50").
//
// # Parameters
//
//   - microUSD: Non-negative micro-USD integer.
//
// # Returns
//
// Formatted USD display string prefixed with "$".
//
// # Example
//
//	_ = formatMicroUSD(1_250_000) // "$1.25"
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/bidding.go:698 (direct call)
//   - cmd/concert-client/bidding.go:698 (function value)
//   - cmd/concert-client/bidding.go:751 (direct call)
//   - cmd/concert-client/bidding.go:751 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func formatMicroUSD(microUSD int64) string {
	if microUSD <= 0 {
		return "$0.00"
	}
	dollars := microUSD / 1_000_000
	frac := fmt.Sprintf("%06d", microUSD%1_000_000)
	trimmed := strings.TrimRight(frac, "0")
	if len(trimmed) < 2 {
		trimmed = frac[:2]
	}
	return fmt.Sprintf("$%d.%s", dollars, trimmed)
}

// clampBidPollInterval bounds a configured bid status poll interval to
// [minBidPollInterval, maxBidPollInterval], defaulting zero to
// defaultBidPollInterval.
//
// # Parameters
//
//   - d: Requested poll interval duration.
//
// # Returns
//
// Bounded poll interval duration.
//
// # Example
//
//	_ = clampBidPollInterval(500 * time.Millisecond)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/bidding.go:416 (direct call)
//   - cmd/concert-client/bidding.go:416 (function value)
//   - cmd/concert-client/bidding.go:786 (direct call)
//   - cmd/concert-client/bidding.go:786 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func clampBidPollInterval(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultBidPollInterval
	}
	return min(max(d, minBidPollInterval), maxBidPollInterval)
}

// parseCLIArgs parses command-line arguments for concert-client, preserving
// strict mutual exclusion for --nft / --direct / --wait and validating the
// AI agent pass bidding flags (-bid, -max-bid, -bid-chain, -bid-asset,
// -bid-poll-interval).
//
// # Parameters
//
//   - args: Raw argument slice (os.Args[1:]).
//
// # Returns
//
// Parsed cliOptions on success, or an error (matching usage on structural
// syntax errors, or sentinel bidding errors on invalid flag values).
//
// # Example
//
//	opts, err := parseCLIArgs([]string{"--wait", "/drop", "-bid", "-max-bid", "2.50", "-bid-chain", "xrpl"})
//	_, _ = opts, err
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/bidding_test.go:231 (direct call)
//   - cmd/concert-client/bidding_test.go:231 (function value)
//   - cmd/concert-client/bidding_test.go:247 (direct call)
//   - cmd/concert-client/bidding_test.go:247 (function value)
//   - cmd/concert-client/bidding_test.go:251 (direct call)
//   - cmd/concert-client/bidding_test.go:251 (function value)
//   - cmd/concert-client/bidding_test.go:261 (direct call)
//   - cmd/concert-client/bidding_test.go:261 (function value)
//   - cmd/concert-client/bidding_test.go:265 (direct call)
//   - cmd/concert-client/bidding_test.go:265 (function value)
//   - cmd/concert-client/main.go:448 (direct call)
//   - cmd/concert-client/main.go:448 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func parseCLIArgs(args []string) (cliOptions, error) {
	opts := cliOptions{
		bidPollInterval: defaultBidPollInterval,
	}
	var maxBidRaw string
	var pollRaw string

	nextValue := func(flagName string, i *int) (string, error) {
		if *i+1 >= len(args) {
			return "", errors.New(usage)
		}
		*i++
		return args[*i], nil
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, eqVal, hasEq := strings.Cut(arg, "=")
		switch {
		case arg == "--nft" && !opts.nft && !opts.direct && opts.waitPath == "":
			opts.nft = true
		case arg == "--direct" && !opts.nft && !opts.direct && opts.waitPath == "":
			opts.direct = true
		case (arg == "--wait" || arg == "-wait") && !opts.nft && !opts.direct && opts.waitPath == "" && i+1 < len(args) && strings.HasPrefix(args[i+1], "/"):
			opts.waitPath = args[i+1]
			i++
		case name == "-bid" || name == "--bid":
			if hasEq {
				b, err := strconv.ParseBool(eqVal)
				if err != nil {
					return cliOptions{}, errors.New(usage)
				}
				opts.bidEnabled = b
			} else {
				opts.bidEnabled = true
			}
		case name == "-max-bid" || name == "--max-bid":
			v := eqVal
			if !hasEq {
				var err error
				v, err = nextValue(name, &i)
				if err != nil {
					return cliOptions{}, err
				}
			}
			maxBidRaw = v
		case name == "-bid-chain" || name == "--bid-chain":
			v := eqVal
			if !hasEq {
				var err error
				v, err = nextValue(name, &i)
				if err != nil {
					return cliOptions{}, err
				}
			}
			norm, ok := bidding.NormalizeChain(v)
			if !ok {
				return cliOptions{}, fmt.Errorf("%w: %q", ErrInvalidBidChain, v)
			}
			opts.bidChain = norm
		case name == "-bid-asset" || name == "--bid-asset":
			v := eqVal
			if !hasEq {
				var err error
				v, err = nextValue(name, &i)
				if err != nil {
					return cliOptions{}, err
				}
			}
			opts.bidAsset = strings.TrimSpace(v)
		case name == "-bid-poll-interval" || name == "--bid-poll-interval":
			v := eqVal
			if !hasEq {
				var err error
				v, err = nextValue(name, &i)
				if err != nil {
					return cliOptions{}, err
				}
			}
			pollRaw = v
		default:
			return cliOptions{}, errors.New(usage)
		}
	}

	if maxBidRaw != "" {
		micro, err := parseUSDToMicroUSD(maxBidRaw)
		if err != nil {
			return cliOptions{}, err
		}
		opts.maxBidMicroUSD = micro
	}
	if pollRaw != "" {
		d, err := time.ParseDuration(pollRaw)
		if err != nil || d <= 0 {
			return cliOptions{}, fmt.Errorf("%w: %q", ErrInvalidBidPoll, pollRaw)
		}
		opts.bidPollInterval = clampBidPollInterval(d)
	}
	if opts.bidEnabled {
		if opts.waitPath == "" {
			return cliOptions{}, errors.New("-bid requires --wait PATH")
		}
		if opts.maxBidMicroUSD <= 0 {
			return cliOptions{}, fmt.Errorf("%w: -max-bid is required when -bid is enabled", ErrInvalidMaxBid)
		}
	}
	return opts, nil
}

// resolveSameOriginURL resolves raw against origin and verifies that the
// resulting URL stays strictly on the same scheme and host as origin so a
// malicious auction offer cannot redirect signed payloads or sessions (S9).
//
// # Parameters
//
//   - origin: Validated Concert origin URL (e.g. "https://shop.example").
//   - raw: Relative path or absolute URL returned in an auction offer.
//   - fallbackPath: Default path used when raw is empty.
//
// # Returns
//
// Resolved absolute same-origin URL string, or [ErrCrossOriginURL].
//
// # Example
//
//	u, err := resolveSameOriginURL("https://shop.example", "/_concert/bids", defaultBidPath)
//	_, _ = u, err
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/bidding.go:714 (direct call)
//   - cmd/concert-client/bidding.go:714 (function value)
//   - cmd/concert-client/bidding.go:718 (direct call)
//   - cmd/concert-client/bidding.go:718 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func resolveSameOriginURL(origin, raw, fallbackPath string) (string, error) {
	base, err := url.Parse(origin)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("%w: invalid origin", ErrCrossOriginURL)
	}
	targetRaw := strings.TrimSpace(raw)
	if targetRaw == "" {
		targetRaw = fallbackPath
	}
	ref, err := url.Parse(targetRaw)
	if err != nil || ref.User != nil {
		return "", fmt.Errorf("%w: malformed auction URL", ErrCrossOriginURL)
	}
	resolved := base.ResolveReference(ref)
	if !strings.EqualFold(resolved.Scheme, base.Scheme) || !strings.EqualFold(resolved.Host, base.Host) {
		return "", fmt.Errorf("%w: %q does not match origin host %q", ErrCrossOriginURL, resolved.Host, base.Host)
	}
	return resolved.String(), nil
}

// defaultAssetForChain returns the canonical native asset identifier for one
// of Concert's four supported crypto chains when -bid-asset is not set.
//
// # Parameters
//
//   - chain: Canonical lowercase chain identifier (xrpl, stellar, hedera, solana).
//
// # Returns
//
// Canonical native asset identifier string.
//
// # Example
//
//	_ = defaultAssetForChain(bidding.ChainHedera) // "0.0.0"
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/bidding.go:556 (direct call)
//   - cmd/concert-client/bidding.go:556 (function value)
//   - cmd/concert-client/bidding_test.go:192 (direct call)
//   - cmd/concert-client/bidding_test.go:192 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func defaultAssetForChain(chain string) string {
	switch chain {
	case bidding.ChainXRPL:
		return "XRP"
	case bidding.ChainStellar:
		return "XLM"
	case bidding.ChainHedera:
		return "0.0.0"
	case bidding.ChainSolana:
		return "SOL"
	default:
		return ""
	}
}

// walletBidSigner adapts the client's existing local crypto wallet to sign
// non-custodial pass bid payment authorizations without broadcasting on-chain.
//
// When offer.Requirements is provided by the server, it invokes w.pay to build
// a full x402 v2 payload; otherwise it signs a canonical bid commitment with
// w.sign so the gateway/verifier can verify wallet ownership off-chain.
//
// # Parameters
//
//   - network: Configured CAIP-2 network string (e.g. "xrpl:0", "solana:...").
//   - w: Non-nil local crypto wallet whose private key stays in-process.
//
// # Returns
//
// A [bidSigner] closure suitable for [bidConfig.Signer].
//
// # Example
//
//	signer := walletBidSigner("xrpl:0", w)
//	_ = signer
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/bidding.go:1122 (direct call)
//   - cmd/concert-client/bidding.go:1122 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func walletBidSigner(network string, w *wallet) bidSigner {
	return func(ctx context.Context, offer auctionOffer, chain, asset string, bidMicroUSD int64) (bidPaymentPayload, error) {
		if w == nil {
			return bidPaymentPayload{}, ErrMissingBidSigner
		}
		if asset == "" {
			asset = defaultAssetForChain(chain)
		}
		if offer.Requirements != nil && w.pay != nil {
			req := *offer.Requirements
			if asset != "" && req.Asset == "" {
				req.Asset = asset
			}
			proof, err := w.pay(ctx, req)
			if err != nil {
				return bidPaymentPayload{}, err
			}
			encoded, err := json.Marshal(x402.Payload{
				Version:  2,
				Accepted: req,
				Payload:  proof,
			})
			if err != nil {
				return bidPaymentPayload{}, err
			}
			return bidPaymentPayload{
				Chain:          chain,
				Asset:          req.Asset,
				AmountAtomic:   req.Amount,
				PaymentPayload: encoded,
			}, nil
		}
		if w.sign == nil {
			return bidPaymentPayload{}, ErrMissingBidSigner
		}
		// Sign a deterministic commitment bound to auction, chain, asset, and
		// micro-USD bid amount so replay across epochs is cryptographically
		// prevented while keeping private keys strictly local.
		commitment := fmt.Sprintf("concert-bid-v1|%s|%s|%s|%s|%d", offer.AuctionID, network, chain, asset, bidMicroUSD)
		sig, pub := w.sign(commitment)
		raw, err := json.Marshal(map[string]any{
			"x402Version": 2,
			"scheme":      "exact",
			"network":     network,
			"payer":       w.address,
			"auction_id":  offer.AuctionID,
			"commitment":  commitment,
			"signature":   base64.StdEncoding.EncodeToString(sig),
			"public_key":  pub,
		})
		if err != nil {
			return bidPaymentPayload{}, err
		}
		return bidPaymentPayload{
			Chain:          chain,
			Asset:          asset,
			AmountAtomic:   strconv.FormatInt(bidMicroUSD, 10),
			PaymentPayload: raw,
		}, nil
	}
}

// chainAllowedByOffer reports whether targetChain is permitted by the auction
// offer's SupportedChains list. When SupportedChains is empty, any of Concert's
// four supported crypto chains is permitted.
//
// # Parameters
//
//   - targetChain: Canonical lowercase chain identifier.
//   - supported: Chains advertised in auctionOffer.SupportedChains.
//
// # Returns
//
// true if targetChain is allowed, false otherwise.
//
// # Example
//
//	ok := chainAllowedByOffer(bidding.ChainXRPL, []string{"xrpl", "solana"})
//	_ = ok
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/bidding.go:705 (direct call)
//   - cmd/concert-client/bidding.go:705 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func chainAllowedByOffer(targetChain string, supported []string) bool {
	if _, ok := bidding.NormalizeChain(targetChain); !ok {
		return false
	}
	if len(supported) == 0 {
		return true
	}
	for _, s := range supported {
		if norm, ok := bidding.NormalizeChain(s); ok && norm == targetChain {
			return true
		}
	}
	return false
}

// attemptAuctionBid evaluates an auction offer against cfg.MaxBidMicroUSD,
// signs and submits POST <bid_url>, and polls <status_url>?bid_id=... until
// terminal status or timeout.
//
// Enforcement guarantees:
//   - Never submits a bid if offer.FloorMicroUSD > cfg.MaxBidMicroUSD.
//   - Never sends raw PaymentPayload bytes to out or error strings (S5).
//   - Enforces same-origin URLs, bounded response reads, and bounded polling (R3/S9).
//
// # Parameters
//
//   - ctx: Parent wait-loop context.
//   - session: Active Concert-Session header token.
//   - offer: Auction offer parsed from a queued 429 response.
//   - cfg: Validated bidding configuration including MaxBidMicroUSD and Signer.
//   - out: Progress output writer.
//
// # Returns
//
// A bidOutcome containing passCredentials if the bid settled, or an error on
// transport/timeout/signing failures. Non-fatal skips (floor over ceiling,
// unsupported chain, lost/rejected bid) return (bidOutcome{settled: false}, nil)
// so the caller seamlessly continues waiting-room polling.
//
// # Example
//
//	// Internal method invoked by (*client).waitWithBidding on 429 auction offers.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/main.go:774 (direct call)
//   - cmd/concert-client/main.go:774 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (c *client) attemptAuctionBid(ctx context.Context, session string, offer auctionOffer, cfg bidConfig, out io.Writer) (bidOutcome, error) {
	if offer.FloorMicroUSD <= 0 {
		fmt.Fprintln(out, "Skipping auction offer: invalid floor price; continuing to wait in line.")
		return bidOutcome{}, nil
	}
	if offer.FloorMicroUSD > cfg.MaxBidMicroUSD {
		fmt.Fprintf(out, "Skipping auction %s: floor %s exceeds -max-bid %s; continuing to wait in line.\n",
			or(offer.AuctionID, "(instant)"), formatMicroUSD(offer.FloorMicroUSD), formatMicroUSD(cfg.MaxBidMicroUSD))
		return bidOutcome{}, nil
	}
	targetChain, ok := bidding.NormalizeChain(cfg.Chain)
	if !ok {
		return bidOutcome{}, fmt.Errorf("%w: %q", ErrInvalidBidChain, cfg.Chain)
	}
	if !chainAllowedByOffer(targetChain, offer.SupportedChains) {
		fmt.Fprintf(out, "Skipping auction %s: chain %s not in supported chains %v; continuing to wait in line.\n",
			or(offer.AuctionID, "(instant)"), targetChain, offer.SupportedChains)
		return bidOutcome{}, nil
	}
	if cfg.Signer == nil {
		return bidOutcome{}, ErrMissingBidSigner
	}

	bidURL, err := resolveSameOriginURL(c.origin, offer.BidURL, defaultBidPath)
	if err != nil {
		return bidOutcome{}, err
	}
	statusURL, err := resolveSameOriginURL(c.origin, offer.StatusURL, defaultBidStatusPath)
	if err != nil {
		return bidOutcome{}, err
	}

	// Instant-buy bids exactly FloorMicroUSD; sealed-bid bids up to MaxBidMicroUSD
	// (strictly guaranteed >= FloorMicroUSD and <= MaxBidMicroUSD).
	bidMicroUSD := cfg.MaxBidMicroUSD
	if strings.EqualFold(strings.TrimSpace(offer.Mode), bidding.ModeInstant) {
		bidMicroUSD = offer.FloorMicroUSD
	}
	if bidMicroUSD > cfg.MaxBidMicroUSD {
		bidMicroUSD = cfg.MaxBidMicroUSD
	}

	signed, err := cfg.Signer(ctx, offer, targetChain, cfg.Asset, bidMicroUSD)
	if err != nil {
		return bidOutcome{}, fmt.Errorf("sign crypto bid: %w", err)
	}
	if len(signed.PaymentPayload) == 0 {
		return bidOutcome{}, errors.New("bid signer returned empty payment payload")
	}

	reqBody := bidSubmitRequest{
		AuctionID:      offer.AuctionID,
		Scope:          offer.Scope,
		Chain:          signed.Chain,
		Asset:          signed.Asset,
		AmountAtomic:   signed.AmountAtomic,
		BidMicroUSD:    bidMicroUSD,
		PaymentPayload: json.RawMessage(signed.PaymentPayload),
	}
	fmt.Fprintf(out, "Submitting %s bid of %s on %s (%s) for auction %s…\n",
		or(offer.Mode, bidding.ModeAuction), formatMicroUSD(bidMicroUSD), signed.Chain, signed.Asset, or(offer.AuctionID, "instant"))

	resp, creds, statusCode, err := c.postBid(ctx, bidURL, session, reqBody)
	if err != nil {
		return bidOutcome{}, err
	}
	if statusCode >= http.StatusBadRequest {
		fmt.Fprintf(out, "Bid rejected (%d: %s; $0 charged); continuing to wait in line.\n",
			statusCode, or(resp.Reason, or(resp.Error, "rejected")))
		return bidOutcome{}, nil
	}

	// Instant-buy or synchronous settlement may return terminal status immediately.
	if done, outcome := evaluateBidStatus(resp, creds, offer.AuctionID, out); done {
		return outcome, nil
	}
	if strings.TrimSpace(resp.BidID) == "" {
		return bidOutcome{}, errors.New("bid submission response missing bid_id")
	}

	pollTimeout := cfg.PollTimeout
	if pollTimeout <= 0 {
		pollTimeout = defaultBidPollTimeout
		if offer.ClosesAt != "" {
			if closes, perr := time.Parse(time.RFC3339, offer.ClosesAt); perr == nil {
				until := time.Until(closes) + 30*time.Second
				if until > pollTimeout {
					pollTimeout = min(until, maxBidPollTimeout)
				}
			}
		}
	}
	pollCtx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()

	interval := clampBidPollInterval(cfg.PollInterval)
	maxAttempts := cfg.MaxPollAttempts
	if maxAttempts <= 0 {
		maxAttempts = maxBidPollAttempts
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := c.pause(pollCtx, interval); err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				return bidOutcome{}, fmt.Errorf("%w (bid_id=%s)", ErrBidTimeout, resp.BidID)
			}
			return bidOutcome{}, err
		}
		stResp, stCreds, stCode, err := c.pollBidStatus(pollCtx, statusURL, session, resp.BidID)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				return bidOutcome{}, fmt.Errorf("%w (bid_id=%s)", ErrBidTimeout, resp.BidID)
			}
			return bidOutcome{}, err
		}
		if stCode >= http.StatusBadRequest {
			fmt.Fprintf(out, "Bid status error (%d: %s; $0 charged); continuing to wait in line.\n",
				stCode, or(stResp.Reason, or(stResp.Error, "status error")))
			return bidOutcome{}, nil
		}
		if done, outcome := evaluateBidStatus(stResp, stCreds, offer.AuctionID, out); done {
			return outcome, nil
		}
	}
	return bidOutcome{}, fmt.Errorf("%w: exceeded %d status polls (bid_id=%s)", ErrBidTimeout, maxAttempts, resp.BidID)
}

// evaluateBidStatus interprets a bid status response and reports whether it
// reached a terminal state (settled, won, lost, rejected, settlement_failed).
//
// # Parameters
//
//   - resp: Decoded bidStatusResponse from submit or status poll.
//   - creds: Pass credentials extracted from HTTP headers and JSON body.
//   - auctionID: Auction identifier for user-facing status logs.
//   - out: Progress output writer.
//
// # Returns
//
// (true, outcome) for terminal states, or (false, zero) if still pending.
//
// # Example
//
//	// Internal helper called by attemptAuctionBid.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/bidding.go:764 (direct call)
//   - cmd/concert-client/bidding.go:764 (function value)
//   - cmd/concert-client/bidding.go:811 (direct call)
//   - cmd/concert-client/bidding.go:811 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func evaluateBidStatus(resp bidStatusResponse, creds passCredentials, auctionID string, out io.Writer) (bool, bidOutcome) {
	status := strings.ToLower(strings.TrimSpace(resp.Status))
	switch status {
	case string(bidding.BidStatusSettled), string(bidding.BidStatusWon):
		fmt.Fprintf(out, "Bid %s %s (tx=%s); attaching priority pass and retrying target.\n",
			resp.BidID, status, or(resp.Transaction, "confirmed"))
		return true, bidOutcome{settled: true, creds: creds}
	case string(bidding.BidStatusLost):
		fmt.Fprintf(out, "Bid %s lost auction %s ($0 charged); continuing to wait in line.\n",
			resp.BidID, or(auctionID, "(epoch)"))
		return true, bidOutcome{}
	case string(bidding.BidStatusRejected), string(bidding.BidStatusSettlementFailed):
		fmt.Fprintf(out, "Bid %s ended with status %s (%s; $0 charged); continuing to wait in line.\n",
			resp.BidID, status, or(resp.Reason, or(resp.Error, status)))
		return true, bidOutcome{}
	default:
		return false, bidOutcome{}
	}
}

// postBid submits a signed bid payload to bidURL with a bounded response read
// and extracts any returned fast-lane pass cookies or tokens.
//
// # Parameters
//
//   - ctx: Controls request cancellation and deadline.
//   - bidURL: Verified same-origin bid submission endpoint URL.
//   - session: Concert-Session header token.
//   - body: bidSubmitRequest JSON payload.
//
// # Returns
//
// Decoded bidStatusResponse, extracted passCredentials, HTTP status code, and
// any transport or decode error.
//
// # Example
//
//	// Internal helper called by attemptAuctionBid.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/bidding.go:753 (direct call)
//   - cmd/concert-client/bidding.go:753 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (c *client) postBid(ctx context.Context, bidURL, session string, body bidSubmitRequest) (bidStatusResponse, passCredentials, int, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return bidStatusResponse{}, passCredentials{}, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, bidURL, bytes.NewReader(raw))
	if err != nil {
		return bidStatusResponse{}, passCredentials{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if session != "" {
		req.Header.Set("Concert-Session", session)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return bidStatusResponse{}, passCredentials{}, 0, err
	}
	defer res.Body.Close()

	var out bidStatusResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, maxBidResponseBytes)).Decode(&out); err != nil {
		return bidStatusResponse{}, passCredentials{}, res.StatusCode, fmt.Errorf("decode bid response (%d): %w", res.StatusCode, err)
	}
	creds := extractPassCredentials(res, out)
	return out, creds, res.StatusCode, nil
}

// pollBidStatus queries GET <statusURL>?bid_id=<bidID> with a bounded response
// read and extracts any returned pass credentials.
//
// # Parameters
//
//   - ctx: Controls request cancellation and deadline.
//   - statusURL: Verified same-origin bid status endpoint URL.
//   - session: Concert-Session header token.
//   - bidID: Bid identifier returned by POST /_concert/bids.
//
// # Returns
//
// Decoded bidStatusResponse, extracted passCredentials, HTTP status code, and
// any transport or decode error.
//
// # Example
//
//	// Internal helper called by attemptAuctionBid.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/bidding.go:799 (direct call)
//   - cmd/concert-client/bidding.go:799 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (c *client) pollBidStatus(ctx context.Context, statusURL, session, bidID string) (bidStatusResponse, passCredentials, int, error) {
	u, err := url.Parse(statusURL)
	if err != nil {
		return bidStatusResponse{}, passCredentials{}, 0, err
	}
	q := u.Query()
	q.Set("bid_id", bidID)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return bidStatusResponse{}, passCredentials{}, 0, err
	}
	req.Header.Set("Accept", "application/json")
	if session != "" {
		req.Header.Set("Concert-Session", session)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return bidStatusResponse{}, passCredentials{}, 0, err
	}
	defer res.Body.Close()

	var out bidStatusResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, maxBidResponseBytes)).Decode(&out); err != nil {
		return bidStatusResponse{}, passCredentials{}, res.StatusCode, fmt.Errorf("decode bid status (%d): %w", res.StatusCode, err)
	}
	creds := extractPassCredentials(res, out)
	return out, creds, res.StatusCode, nil
}

// extractPassCredentials collects priority/fast-lane pass cookies and tokens
// returned via Set-Cookie headers or JSON response fields.
//
// # Parameters
//
//   - res: HTTP response whose Set-Cookie headers are inspected.
//   - body: Decoded bidStatusResponse JSON fields.
//
// # Returns
//
// Populated passCredentials value.
//
// # Example
//
//	// Internal helper called by postBid and pollBidStatus.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/bidding.go:919 (direct call)
//   - cmd/concert-client/bidding.go:919 (function value)
//   - cmd/concert-client/bidding.go:978 (direct call)
//   - cmd/concert-client/bidding.go:978 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func extractPassCredentials(res *http.Response, body bidStatusResponse) passCredentials {
	return passCredentials{
		cookies:   res.Cookies(),
		rawCookie: strings.TrimSpace(body.PassCookie),
		passToken: strings.TrimSpace(body.PassToken),
		session:   strings.TrimSpace(body.Session),
	}
}

// attachPassCredentials applies any settled fast-lane pass cookies, pass
// tokens, or upgraded session headers to an outgoing target HTTP request.
//
// # Parameters
//
//   - req: Outgoing HTTP request targeting the protected Concert path.
//   - baseSession: Default Concert-Session token from the waiting-room state.
//   - creds: Settled pass credentials (may be zero if no bid has settled).
//
// # Returns
//
// None. Mutates req headers in place.
//
// # Example
//
//	// Internal helper called by (*client).waitWithBidding before sending GET.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/main.go:733 (direct call)
//   - cmd/concert-client/main.go:733 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func attachPassCredentials(req *http.Request, baseSession string, creds passCredentials) {
	sess := baseSession
	if creds.session != "" {
		sess = creds.session
	}
	if sess != "" {
		req.Header.Set("Concert-Session", sess)
	}
	if creds.passToken != "" {
		req.Header.Set("X-Concert-Pass", creds.passToken)
	}
	for _, ck := range creds.cookies {
		req.AddCookie(ck)
	}
	if creds.rawCookie != "" {
		name, val, ok := strings.Cut(creds.rawCookie, "=")
		if ok && strings.TrimSpace(name) != "" {
			req.AddCookie(&http.Cookie{Name: strings.TrimSpace(name), Value: strings.TrimSpace(val)})
		} else {
			req.AddCookie(&http.Cookie{Name: "concert_fastlane", Value: creds.rawCookie})
		}
	}
}

// buildWaitBidConfig constructs a bidConfig from parsed CLI options and local
// wallet environment configuration when -bid is enabled.
//
// # Parameters
//
//   - opts: Parsed cliOptions with bidEnabled == true.
//   - network: Configured CONCERT_CLIENT_NETWORK string.
//   - getenv: Environment variable lookup function.
//
// # Returns
//
// Configured bidConfig with a local wallet signer, or an error if the chain or
// wallet configuration is invalid.
//
// # Example
//
//	// Internal helper called by waitInLineWithBidding when -bid is set.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/main.go:611 (direct call)
//   - cmd/concert-client/main.go:611 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func buildWaitBidConfig(opts cliOptions, network string, getenv func(string) string) (bidConfig, error) {
	chain := opts.bidChain
	if chain == "" {
		norm, ok := bidding.NormalizeChain(network)
		if !ok {
			return bidConfig{}, fmt.Errorf("%w: %q", ErrInvalidBidChain, network)
		}
		chain = norm
	}
	networks, err := gateway.LoadNetworks(env("CONCERT_NETWORKS_CONFIG", "examples/networks.json"))
	if err != nil {
		return bidConfig{}, err
	}
	n, ok := networks[network]
	if !ok {
		return bidConfig{}, errors.New("network configuration is missing")
	}
	w, err := walletFromEnvironment(network, n, getenv)
	if err != nil {
		return bidConfig{}, err
	}
	return bidConfig{
		Enabled:        true,
		MaxBidMicroUSD: opts.maxBidMicroUSD,
		Chain:          chain,
		Asset:          opts.bidAsset,
		PollInterval:   opts.bidPollInterval,
		Signer:         walletBidSigner(network, w),
	}, nil
}
