package concert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Concert agent bidding endpoint paths.
const (
	BidSubmitPath         = "/_concert/bids"
	BidStatusPath         = "/_concert/bids/status"
	DefaultMaxBidBodySize = 128 << 10 // 128 KiB
)

// Canonical crypto chains supported by Concert. Concert is 100% crypto-only.
const (
	ChainXRPL    = "xrpl"
	ChainStellar = "stellar"
	ChainHedera  = "hedera"
	ChainSolana  = "solana"
)

// BidStatus represents the lifecycle state of an AI agent crypto pass bid.
type BidStatus string

const (
	BidStatusPending          BidStatus = "pending"
	BidStatusWon              BidStatus = "won"
	BidStatusLost             BidStatus = "lost"
	BidStatusRejected         BidStatus = "rejected"
	BidStatusSettled          BidStatus = "settled"
	BidStatusSettlementFailed BidStatus = "settlement_failed"
)

// Offer mode values advertised in AuctionOffer.Mode.
const (
	OfferModeInstant = "instant"
	OfferModeAuction = "auction"
)

// Sentinel errors returned by AgentBidClient and ParseAuctionOffer. Match with
// errors.Is.
var (
	ErrUnsupportedChain = errors.New("concert: unsupported crypto chain (allowed: xrpl, stellar, hedera, solana)")
	ErrInvalidBid       = errors.New("concert: invalid bid submission")
	ErrNoAuctionOffer   = errors.New("concert: no auction offer present in response")
	ErrInvalidOffer     = errors.New("concert: invalid auction offer")
)

// SupportedChains returns a fresh slice of Concert's four supported crypto
// chains (xrpl, stellar, hedera, solana).
//
// # Parameters
//
// None.
//
// # Returns
//
// A newly allocated slice that callers may freely mutate without affecting the
// package.
//
// # Example
//
//	chains := concert.SupportedChains()
//	fmt.Println(chains) // [xrpl stellar hedera solana]
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:952 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func SupportedChains() []string {
	return []string{ChainXRPL, ChainStellar, ChainHedera, ChainSolana}
}

// IsSupportedChain reports whether chain is one of Concert's four supported
// crypto chains (xrpl, stellar, hedera, solana). Case and surrounding
// whitespace are normalized.
//
// # Parameters
//
//   - chain: Candidate chain identifier.
//
// # Returns
//
// true iff chain normalizes to xrpl, stellar, hedera, or solana.
//
// # Example
//
//	if !concert.IsSupportedChain("xrpl") {
//		return concert.ErrUnsupportedChain
//	}
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:314 (direct call)
//   - clients/go/src/bidding.go:610 (direct call)
//   - clients/go/src/doc.go:314 (symbol reference)
//   - clients/go/src/doc.go:610 (symbol reference)
//   - clients/go/src/priority.go:314 (symbol reference)
//   - clients/go/src/priority.go:610 (symbol reference)
//   - clients/go/src/purge.go:314 (symbol reference)
//   - clients/go/src/purge.go:610 (symbol reference)
//   - clients/go/src/rm1.go:314 (symbol reference)
//   - clients/go/src/rm1.go:610 (symbol reference)
//   - clients/go/src/signals.go:314 (symbol reference)
//   - clients/go/src/signals.go:610 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func IsSupportedChain(chain string) bool {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case ChainXRPL, ChainStellar, ChainHedera, ChainSolana:
		return true
	default:
		return false
	}
}

// AuctionOffer describes the live crypto-only admission terms advertised by
// Concert inside a queued 429 JSON response.
type AuctionOffer struct {
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

// QueuedAuctionEnvelope models the top-level JSON body emitted by Concert on
// queued 429 agent/API responses when agent bidding is active.
type QueuedAuctionEnvelope struct {
	Queued            bool          `json:"queued"`
	Position          int64         `json:"position,omitempty"`
	QueueDepth        int64         `json:"queue_depth,omitempty"`
	StatusURL         string        `json:"status_url,omitempty"`
	RetryAfterSeconds int           `json:"retry_after_seconds,omitempty"`
	Hint              string        `json:"hint,omitempty"`
	Auction           *AuctionOffer `json:"auction,omitempty"`
}

// BidSubmission is the crypto-only bid payload sent to POST /_concert/bids.
// PaymentPayload contains the signed non-custodial x402 v2 crypto payment
// authorization and is never logged or echoed in errors.
type BidSubmission struct {
	BidID          string          `json:"bid_id,omitempty"`
	AgentKey       string          `json:"agent_key,omitempty"`
	Scope          string          `json:"scope,omitempty"`
	Chain          string          `json:"chain"`
	Asset          string          `json:"asset"`
	AmountAtomic   string          `json:"amount_atomic"`
	PaymentPayload json.RawMessage `json:"payment_payload"`
	QueuedAt       string          `json:"queued_at,omitempty"`
}

// BidRecord is the secret-free bid lifecycle snapshot returned by Concert.
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

// BidResponse is returned by SubmitBid (HTTP 200 or 202) and GetBidStatus
// (HTTP 200). When PassIssued is true, PassToken and PriorityPass carry the
// issued priority pass token and Concert also attaches signed Set-Cookie
// headers on the HTTP response.
type BidResponse struct {
	Bid          BidRecord `json:"bid"`
	BidID        string    `json:"bid_id"`
	Status       BidStatus `json:"status"`
	StatusURL    string    `json:"status_url,omitempty"`
	PassIssued   bool      `json:"pass_issued"`
	PriorityPass string    `json:"priority_pass,omitempty"`
	PassToken    string    `json:"pass_token,omitempty"`
}

// ParseAuctionOffer extracts and validates a crypto-only AuctionOffer from a
// Concert 429 JSON response body. It accepts both the full queued 429 envelope
// ({"queued": true, "auction": {...}}) and a standalone AuctionOffer object.
//
// # Parameters
//
//   - body: Raw JSON bytes from a Concert 429 response. Bounded to
//     DefaultMaxBidBodySize bytes (R3).
//
// # Returns
//
// The validated AuctionOffer and nil error, or zero AuctionOffer and an error
// matching ErrResponseTooLarge, ErrNoAuctionOffer, ErrUnsupportedChain, or
// ErrInvalidOffer.
//
// # Example
//
//	offer, err := concert.ParseAuctionOffer(body)
//	if err != nil {
//		return err
//	}
//	fmt.Println(offer.Mode, offer.FloorMicroUSD, offer.SupportedChains)
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:794 (direct call)
//   - clients/go/src/concert_test.go:804 (direct call)
//   - clients/go/src/concert_test.go:810 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func ParseAuctionOffer(body []byte) (AuctionOffer, error) {
	if len(body) == 0 {
		return AuctionOffer{}, ErrNoAuctionOffer
	}
	if len(body) > DefaultMaxBidBodySize {
		return AuctionOffer{}, fmt.Errorf("%w: limit %d bytes", ErrResponseTooLarge, DefaultMaxBidBodySize)
	}

	var env QueuedAuctionEnvelope
	if err := decodeSingleJSON(body, &env); err != nil {
		return AuctionOffer{}, fmt.Errorf("%w: %v", ErrInvalidOffer, err)
	}

	var offer AuctionOffer
	if env.Auction != nil {
		offer = *env.Auction
	} else {
		// Fall back to decoding body as a direct AuctionOffer object.
		if err := decodeSingleJSON(body, &offer); err != nil {
			return AuctionOffer{}, fmt.Errorf("%w: %v", ErrInvalidOffer, err)
		}
		if offer.Mode == "" && offer.Scope == "" && offer.BidURL == "" {
			return AuctionOffer{}, ErrNoAuctionOffer
		}
	}

	if err := validateAuctionOffer(&offer); err != nil {
		return AuctionOffer{}, err
	}
	return offer, nil
}

// validateAuctionOffer normalizes and validates required fields and ensures
// every advertised chain is one of Concert's four crypto chains.
//
// # Parameters
//
//   - offer: Pointer to AuctionOffer to validate and normalize in place.
//
// # Returns
//
// nil on success, or an error matching ErrInvalidOffer or ErrUnsupportedChain.
//
// # Example
//
//	if err := validateAuctionOffer(&offer); err != nil {
//		return AuctionOffer{}, err
//	}
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:265 (direct call)
//   - clients/go/src/doc.go:265 (symbol reference)
//   - clients/go/src/priority.go:265 (symbol reference)
//   - clients/go/src/purge.go:265 (symbol reference)
//   - clients/go/src/rm1.go:265 (symbol reference)
//   - clients/go/src/signals.go:265 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func validateAuctionOffer(offer *AuctionOffer) error {
	offer.Mode = strings.ToLower(strings.TrimSpace(offer.Mode))
	if offer.Mode != OfferModeInstant && offer.Mode != OfferModeAuction {
		return fmt.Errorf("%w: unsupported mode %q", ErrInvalidOffer, offer.Mode)
	}
	if offer.FloorMicroUSD <= 0 {
		return fmt.Errorf("%w: floor_micro_usd must be positive", ErrInvalidOffer)
	}
	if len(offer.SupportedChains) == 0 {
		return fmt.Errorf("%w: supported_chains must not be empty", ErrInvalidOffer)
	}
	normalized := make([]string, 0, len(offer.SupportedChains))
	for _, ch := range offer.SupportedChains {
		c := strings.ToLower(strings.TrimSpace(ch))
		if !IsSupportedChain(c) {
			return fmt.Errorf("%w: %q", ErrUnsupportedChain, ch)
		}
		normalized = append(normalized, c)
	}
	offer.SupportedChains = normalized
	if strings.TrimSpace(offer.BidURL) == "" {
		offer.BidURL = BidSubmitPath
	}
	if strings.TrimSpace(offer.StatusURL) == "" {
		offer.StatusURL = BidStatusPath
	}
	return nil
}

// AgentBidConfig configures an AgentBidClient.
type AgentBidConfig struct {
	// BaseURL is the Concert origin base URL (http:// or https://, no userinfo).
	BaseURL string
	// ConcertSession optionally sets the Concert-Session header sent on bid
	// requests so Concert binds bids to the agent's existing waiting-room slot.
	ConcertSession string
	// HTTPClient optionally supplies a preconfigured *http.Client (for example
	// with a cookie jar to retain issued concert_admit/concert_priority cookies).
	HTTPClient *http.Client
	// Timeout sets the per-request timeout when HTTPClient is nil.
	// Defaults to DefaultHTTPTimeout (10s).
	Timeout time.Duration
	// MaxResponseBytes bounds response body reads (R3).
	// Defaults to DefaultMaxBidBodySize (128 KiB).
	MaxResponseBytes int64
}

// AgentBidClient submits non-custodial crypto-only bids to POST /_concert/bids
// and polls settlement/pass status via GET /_concert/bids/status.
//
// AgentBidClient is immutable after construction and safe for concurrent use
// by multiple goroutines.
type AgentBidClient struct {
	baseURL  string
	session  string
	client   *http.Client
	maxBody  int64
	baseHost string
}

// NewAgentBidClient validates cfg and constructs an AgentBidClient.
//
// # Parameters
//
//   - cfg: Client configuration. cfg.BaseURL must be a valid http/https URL
//     without embedded credentials.
//
// # Returns
//
// A ready-to-use *AgentBidClient and nil error, or nil and an error matching
// ErrInvalidBaseURL.
//
// # Example
//
//	c, err := concert.NewAgentBidClient(concert.AgentBidConfig{
//		BaseURL: "https://shop.example.com",
//	})
//	if err != nil {
//		return err
//	}
//	_ = c
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:901 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func NewAgentBidClient(cfg AgentBidConfig) (*AgentBidClient, error) {
	baseURL, baseHost, err := normalizeBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	maxBody := cfg.MaxResponseBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBidBodySize
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = newSafeHTTPClient(timeout, baseHost)
	}
	return &AgentBidClient{
		baseURL:  baseURL,
		baseHost: baseHost,
		session:  strings.TrimSpace(cfg.ConcertSession),
		client:   httpClient,
		maxBody:  maxBody,
	}, nil
}

// SubmitBid validates sub (strictly crypto-only: xrpl, stellar, hedera, solana)
// and submits it to POST /_concert/bids.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadlines; must be non-nil.
//   - sub: BidSubmission carrying a supported crypto chain, non-empty asset,
//     positive integer amount_atomic, and non-empty JSON payment_payload.
//
// # Returns
//
// BidResponse and nil error on HTTP 200 (instant settlement) or HTTP 202
// (accepted into sealed-bid epoch). On rejection or failure, returns zero
// BidResponse and an error matching ErrUnsupportedChain, ErrInvalidBid,
// ErrResponseTooLarge, *APIError, or a network/context error. PaymentPayload
// bytes are never included in errors.
//
// # Example
//
//	resp, err := client.SubmitBid(ctx, concert.BidSubmission{
//		Chain:          concert.ChainSolana,
//		Asset:          "USDC",
//		AmountAtomic:   "1500000",
//		PaymentPayload: json.RawMessage(`{"x402Version":2,"payload":{"tx":"..."}}`),
//	})
//	if err != nil {
//		return err
//	}
//	fmt.Println(resp.BidID, resp.Status)
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:915 (direct call)
//   - clients/go/src/concert_test.go:928 (direct call)
//   - clients/go/src/concert_test.go:940 (direct call)
//   - clients/go/src/concert_test.go:961 (direct call)
//   - clients/go/src/concert_test.go:994 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (c *AgentBidClient) SubmitBid(ctx context.Context, sub BidSubmission) (BidResponse, error) {
	if c == nil {
		return BidResponse{}, ErrInvalidBid
	}
	if ctx == nil {
		return BidResponse{}, fmt.Errorf("%w: nil context", ErrInvalidBid)
	}
	if err := validateBidSubmission(&sub); err != nil {
		return BidResponse{}, err
	}

	payload, err := json.Marshal(sub)
	if err != nil {
		return BidResponse{}, fmt.Errorf("concert: marshal bid submission: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+BidSubmitPath, bytes.NewReader(payload))
	if err != nil {
		return BidResponse{}, fmt.Errorf("concert: build bid request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if c.session != "" {
		httpReq.Header.Set("Concert-Session", c.session)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return BidResponse{}, fmt.Errorf("concert: submit bid failed: %w", sanitizeURLError(err))
	}
	defer resp.Body.Close()

	body, err := readBoundedBody(resp.Body, c.maxBody)
	if err != nil {
		return BidResponse{}, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return BidResponse{}, parseAPIError(resp.StatusCode, body)
	}

	var out BidResponse
	if err := decodeSingleJSON(body, &out); err != nil {
		return BidResponse{}, fmt.Errorf("concert: decode bid response: %w", err)
	}
	return out, nil
}

// GetBidStatus polls GET /_concert/bids/status?bid_id=<id> for a previously
// submitted bid. When the bid has cleared and settled on-chain, the returned
// BidResponse carries PassIssued == true and PassToken / PriorityPass.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadlines; must be non-nil.
//   - bidID: Non-empty bid identifier returned by SubmitBid.
//
// # Returns
//
// BidResponse and nil error on HTTP 200, or zero BidResponse and an error
// matching ErrInvalidBid, ErrResponseTooLarge, *APIError, or a network/context
// error.
//
// # Example
//
//	status, err := client.GetBidStatus(ctx, bidResp.BidID)
//	if err != nil {
//		return err
//	}
//	if status.PassIssued {
//		fmt.Println("won priority pass")
//	}
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:976 (direct call)
//   - clients/go/src/concert_test.go:1006 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (c *AgentBidClient) GetBidStatus(ctx context.Context, bidID string) (BidResponse, error) {
	if c == nil {
		return BidResponse{}, ErrInvalidBid
	}
	if ctx == nil {
		return BidResponse{}, fmt.Errorf("%w: nil context", ErrInvalidBid)
	}
	id := strings.TrimSpace(bidID)
	if id == "" {
		return BidResponse{}, fmt.Errorf("%w: bid_id is required", ErrInvalidBid)
	}

	endpoint := c.baseURL + BidStatusPath + "?bid_id=" + url.QueryEscape(id)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return BidResponse{}, fmt.Errorf("concert: build bid status request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	if c.session != "" {
		httpReq.Header.Set("Concert-Session", c.session)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return BidResponse{}, fmt.Errorf("concert: get bid status failed: %w", sanitizeURLError(err))
	}
	defer resp.Body.Close()

	body, err := readBoundedBody(resp.Body, c.maxBody)
	if err != nil {
		return BidResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return BidResponse{}, parseAPIError(resp.StatusCode, body)
	}

	var out BidResponse
	if err := decodeSingleJSON(body, &out); err != nil {
		return BidResponse{}, fmt.Errorf("concert: decode bid status response: %w", err)
	}
	return out, nil
}

// validateBidSubmission normalizes and validates a crypto-only BidSubmission
// before marshaling it onto the wire.
//
// # Parameters
//
//   - sub: Pointer to BidSubmission to validate and normalize in place.
//
// # Returns
//
// nil on success, or an error matching ErrUnsupportedChain or ErrInvalidBid.
//
// # Example
//
//	if err := validateBidSubmission(&sub); err != nil {
//		return BidResponse{}, err
//	}
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:463 (direct call)
//   - clients/go/src/doc.go:463 (symbol reference)
//   - clients/go/src/priority.go:463 (symbol reference)
//   - clients/go/src/purge.go:463 (symbol reference)
//   - clients/go/src/rm1.go:463 (symbol reference)
//   - clients/go/src/signals.go:463 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func validateBidSubmission(sub *BidSubmission) error {
	sub.Chain = strings.ToLower(strings.TrimSpace(sub.Chain))
	if !IsSupportedChain(sub.Chain) {
		return fmt.Errorf("%w: %q", ErrUnsupportedChain, sub.Chain)
	}
	sub.Asset = strings.TrimSpace(sub.Asset)
	if sub.Asset == "" {
		return fmt.Errorf("%w: asset is required", ErrInvalidBid)
	}
	sub.AmountAtomic = strings.TrimSpace(sub.AmountAtomic)
	if sub.AmountAtomic == "" {
		return fmt.Errorf("%w: amount_atomic is required", ErrInvalidBid)
	}
	// Parse as exact base-10 integer without floating point; reject <= 0.
	amt, ok := new(big.Int).SetString(sub.AmountAtomic, 10)
	if !ok || amt.Sign() <= 0 {
		return fmt.Errorf("%w: amount_atomic must be a positive base-10 integer", ErrInvalidBid)
	}
	trimmedPayload := bytes.TrimSpace(sub.PaymentPayload)
	if len(trimmedPayload) == 0 || !json.Valid(trimmedPayload) {
		return fmt.Errorf("%w: payment_payload must be non-empty valid JSON", ErrInvalidBid)
	}
	sub.PaymentPayload = trimmedPayload
	sub.BidID = strings.TrimSpace(sub.BidID)
	sub.AgentKey = strings.TrimSpace(sub.AgentKey)
	sub.Scope = strings.TrimSpace(sub.Scope)
	sub.QueuedAt = strings.TrimSpace(sub.QueuedAt)
	return nil
}
