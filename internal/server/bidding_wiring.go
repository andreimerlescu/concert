package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/bidding"
	"github.com/gin-gonic/gin"
)

const (
	biddingSubmitPath    = "/bids"
	biddingStatusPath    = "/bids/status"
	biddingPublicBidURL  = "/_concert/bids"
	biddingPublicStatURL = "/_concert/bids/status"
	biddingMaxReqBytes   = 128 << 10
	defaultBiddingFloor  = int64(1_000_000) // $1.00 in micro-USD
)

// failClosedBiddingSettler rejects all verification and settlement attempts
// when no chain gateway is configured (S7 fail-closed).
type failClosedBiddingSettler struct{}

// Verify rejects verification when no crypto chain gateway is attached.
//
// # Parameters
//
//   - ctx: Request context (unused).
//   - bid: Bid submission (unused).
//
// # Returns
//
// An invalid VerifyReceipt naming "gateway_not_configured" and nil error.
//
// # Example
//
//	var s bidding.PaymentSettler = failClosedBiddingSettler{}
//
// # Used By
//
// Returned by app.newBiddingSettler when no chain gateway is enabled.
func (failClosedBiddingSettler) Verify(_ context.Context, _ bidding.BidSubmission) (bidding.VerifyReceipt, error) {
	return bidding.VerifyReceipt{Valid: false, InvalidReason: "gateway_not_configured"}, nil
}

// Settle refuses on-chain settlement when no crypto chain gateway is attached.
//
// # Parameters
//
//   - ctx: Request context (unused).
//   - bid: Bid submission (unused).
//
// # Returns
//
// An unsettled SettleReceipt and bidding.ErrSettlementFailed.
//
// # Example
//
//	var s bidding.PaymentSettler = failClosedBiddingSettler{}
//
// # Used By
//
// Returned by app.newBiddingSettler when no chain gateway is enabled.
func (failClosedBiddingSettler) Settle(_ context.Context, _ bidding.BidSubmission) (bidding.SettleReceipt, error) {
	return bidding.SettleReceipt{Settled: false, ErrorReason: "gateway_not_configured"}, bidding.ErrSettlementFailed
}

// biddingEnabledConfig reports whether cfg enables hybrid AI agent bidding
// globally (-agent-bidding) or on any declarative site route.
//
// # Parameters
//
//   - cfg: Site configuration to inspect.
//
// # Returns
//
// true when the bidding engine should be initialized and started.
//
// # Example
//
//	if biddingEnabledConfig(cfg) { ... }
//
// # Used By
//
// Called by app.initBidding in internal/server/bidding_wiring.go.
func biddingEnabledConfig(cfg config) bool {
	if cfg.agentBidding {
		return true
	}
	for _, r := range cfg.siteRoutes {
		if r.AgentBidding {
			return true
		}
	}
	return false
}

// initBidding initializes and starts the app's non-custodial crypto-only
// internal/bidding.Engine when enabled globally or on any route, and registers
// Engine.Close on app shutdown (R2).
//
// # Parameters
//
//   - cfg: Normalized site configuration.
//
// # Returns
//
// nil on success (or when bidding is disabled), or a configuration/journal error.
//
// # Example
//
//	if err := a.initBidding(cfg); err != nil {
//	    return nil, err
//	}
//
// # Used By
//
// Called by newApp in internal/server/app.go.
func (a *app) initBidding(cfg config) error {
	if !biddingEnabledConfig(cfg) {
		return nil
	}
	settler := cfg.biddingSettler
	if settler == nil {
		settler = a.newBiddingSettler()
	}
	floor := cfg.agentBiddingFloorMicroUSD
	if floor <= 0 {
		floor = defaultBiddingFloor
	}
	epochDur := cfg.agentBiddingEpoch
	if epochDur <= 0 {
		epochDur = bidding.DefaultEpochDuration
	}
	slots := cfg.agentBiddingSlots
	if slots <= 0 {
		slots = bidding.DefaultSlotsPerEpoch
	}
	journalPath := ""
	if cfg.dataDir != "" {
		journalPath = filepath.Join(cfg.dataDir, "bidding.jsonl")
	}

	bcfg := bidding.Config{
		EpochDuration:   epochDur,
		SlotsPerEpoch:   slots,
		MinWaitDuration: cfg.agentBiddingMinWait,
		FloorMicroUSD:   floor,
		SupportedChains: []string{bidding.ChainXRPL, bidding.ChainStellar, bidding.ChainHedera, bidding.ChainSolana},
		BidURL:          biddingPublicBidURL,
		StatusURL:       biddingPublicStatURL,
		JournalPath:     journalPath,
		ClusterSync:     a.biddingClusterSync(),
		SlotProbe: func(_ string) bool {
			g := a.current()
			if g == nil || a.room == nil {
				return false
			}
			// Offer instant-buy when page/lane capacity is open and no queue is waiting;
			// switch automatically to sealed-bid auction mode under saturation.
			return a.room.Len() < int(a.room.Cap()) && a.room.LiveQueueDepth() == 0
		},
	}

	eng, err := bidding.NewEngine(bcfg, settler)
	if err != nil {
		return fmt.Errorf("agent bidding init: %w", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		_ = eng.Close()
		return fmt.Errorf("agent bidding start: %w", err)
	}
	a.bidding = eng
	a.onClose(func() {
		_ = eng.Close()
	})
	return nil
}

// biddingEnabledForRequest reports whether live auction offer metadata should
// be included on queued agent 429 responses for c.
//
// # Parameters
//
//   - c: Active request *gin.Context.
//
// # Returns
//
// true when the bidding engine is running and either -agent-bidding or the
// matched route's agent_bidding flag is true.
//
// # Example
//
//	if g.biddingEnabledForRequest(c) {
//	    body["auction"] = g.biddingOfferForRequest(c)
//	}
//
// # Used By
//
// Called by generation.writeAgentWait in internal/server/agent.go and
// apiQueueWriter.translateQueued in internal/server/api.go.
func (g *generation) biddingEnabledForRequest(c *gin.Context) bool {
	if g == nil || g.a == nil || g.a.bidding == nil {
		return false
	}
	if g.cfg.agentBidding {
		return true
	}
	if cr := matchedRouteFrom(c); cr != nil && cr.cfg.AgentBidding {
		return true
	}
	return false
}

// biddingScopeForRequest computes the auction scope key for c.
//
// # Parameters
//
//   - c: Active request *gin.Context.
//
// # Returns
//
// Scope string combining site host and matched route prefix (or "default").
//
// # Example
//
//	scope := g.biddingScopeForRequest(c)
//
// # Used By
//
// Called by generation.biddingOfferForRequest and generation.handleBidSubmit
// in internal/server/bidding_wiring.go.
func (g *generation) biddingScopeForRequest(c *gin.Context) string {
	host := strings.TrimSpace(g.cfg.siteHost)
	if host == "" {
		host = "default"
	}
	if cr := matchedRouteFrom(c); cr != nil && cr.prefix != "" {
		return host + ":" + cr.prefix
	}
	return host
}

// biddingOfferForRequest returns the live auction offer payload for c.
//
// # Parameters
//
//   - c: Active request *gin.Context.
//
// # Returns
//
// Live bidding.Offer metadata and true when an offer is available, or zero
// Offer and false if the engine is closed or scope limit is reached.
//
// # Example
//
//	if offer, ok := g.biddingOfferForRequest(c); ok {
//	    body["auction"] = offer
//	}
//
// # Used By
//
// Called by generation.writeAgentWait in internal/server/agent.go and
// apiQueueWriter.translateQueued in internal/server/api.go.
func (g *generation) biddingOfferForRequest(c *gin.Context) (bidding.Offer, bool) {
	if g == nil || g.a == nil || g.a.bidding == nil {
		return bidding.Offer{}, false
	}
	offer, err := g.a.bidding.Offer(g.biddingScopeForRequest(c))
	if err != nil {
		return bidding.Offer{}, false
	}
	return offer, true
}

// handleBiddingSubroute dispatches /_concert/bids (POST) and
// /_concert/bids/status (GET) across all three Concert editions.
//
// # Parameters
//
//   - c: Request *gin.Context.
//   - subPath: Request path trimmed of "/_concert" prefix.
//
// # Returns
//
// true when subPath matched a bidding endpoint and was handled.
//
// # Example
//
//	if g.handleBiddingSubroute(c, subPath) {
//	    return
//	}
//
// # Used By
//
// Called by registerConcertRoutes in internal/server/fastlane.go and
// internal/server/enterprise_stub.go.
func (g *generation) handleBiddingSubroute(c *gin.Context, subPath string) bool {
	switch subPath {
	case biddingSubmitPath:
		if c.Request.Method != http.MethodPost {
			c.Status(http.StatusMethodNotAllowed)
			return true
		}
		g.handleBidSubmit(c)
		return true

	case biddingStatusPath:
		if c.Request.Method != http.MethodGet {
			c.Status(http.StatusMethodNotAllowed)
			return true
		}
		g.handleBidStatus(c)
		return true
	}
	return false
}

type bidSubmitReq struct {
	BidID          string          `json:"bid_id"`
	AgentKey       string          `json:"agent_key"`
	Scope          string          `json:"scope"`
	Chain          string          `json:"chain"`
	Asset          string          `json:"asset"`
	AmountAtomic   string          `json:"amount_atomic"`
	PaymentPayload json.RawMessage `json:"payment_payload"`
	QueuedAt       string          `json:"queued_at"`
}

// handleBidSubmit accepts POST /_concert/bids, performs off-chain verification
// via internal/bidding.Engine (never settling losers), and issues a signed
// Priority + Admission pass immediately if the bid settled via instant-buy.
//
// # Parameters
//
//   - c: Request *gin.Context carrying the JSON bid payload.
//
// # Example
//
//	g.handleBidSubmit(c)
//
// # Used By
//
// Called by generation.handleBiddingSubroute in internal/server/bidding_wiring.go.
func (g *generation) handleBidSubmit(c *gin.Context) {
	c.Set(ctxSkipWaitingHeaders, true)
	c.Header("Cache-Control", "no-store")
	if g.a == nil || g.a.bidding == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent_bidding_disabled"})
		return
	}
	if c.Request.Body == nil {
		g.a.stats.biddingRejected.Add(1)
		c.JSON(http.StatusBadRequest, gin.H{"error": "request body is required"})
		return
	}
	var req bidSubmitReq
	if err := json.NewDecoder(io.LimitReader(c.Request.Body, biddingMaxReqBytes)).Decode(&req); err != nil {
		g.a.stats.biddingRejected.Add(1)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}

	payload := []byte(req.PaymentPayload)
	if len(payload) == 0 {
		if hdr := strings.TrimSpace(c.GetHeader("PAYMENT-SIGNATURE")); hdr != "" {
			if dec, err := base64.StdEncoding.DecodeString(hdr); err == nil && len(dec) > 0 {
				payload = dec
			} else if dec, err := base64.RawURLEncoding.DecodeString(hdr); err == nil && len(dec) > 0 {
				payload = dec
			} else {
				payload = []byte(hdr)
			}
		}
	}

	agentKey := strings.TrimSpace(req.AgentKey)
	if sid, ok := g.a.fastlaneSessionID(c.Request); ok && sid != "" {
		agentKey = agentKeyPrefix + sid
	}
	if agentKey == "" {
		if ip := clientIPFrom(c); ip.IsValid() {
			agentKey = "ip:" + ip.String()
		}
	}

	scope := strings.TrimSpace(req.Scope)
	if scope == "" {
		scope = g.biddingScopeForRequest(c)
	}

	now := time.Now().UTC()
	queuedAt := now
	if req.QueuedAt != "" {
		if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(req.QueuedAt)); err == nil {
			queuedAt = parsed.UTC()
		}
	} else if agentKey != "" && g.a.room != nil {
		if ti, ok := g.a.room.TicketByKey(agentKey); ok && !ti.IssuedAt.IsZero() {
			queuedAt = ti.IssuedAt.UTC()
		}
	}

	sub := bidding.BidSubmission{
		BidID:          strings.TrimSpace(req.BidID),
		AgentKey:       agentKey,
		Scope:          scope,
		Chain:          strings.TrimSpace(req.Chain),
		Asset:          strings.TrimSpace(req.Asset),
		AmountAtomic:   strings.TrimSpace(req.AmountAtomic),
		PaymentPayload: payload,
		QueuedAt:       queuedAt,
		ReceivedAt:     now,
	}

	rec, err := g.a.bidding.SubmitBid(c.Request.Context(), sub)
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, bidding.ErrReplayDetected), errors.Is(err, bidding.ErrRebidNotHigher):
			status = http.StatusConflict
		case errors.Is(err, bidding.ErrEpochFull):
			status = http.StatusTooManyRequests
		case errors.Is(err, bidding.ErrUnderFloor), errors.Is(err, bidding.ErrVerificationFailed), errors.Is(err, bidding.ErrSettlementFailed):
			status = http.StatusPaymentRequired
		case errors.Is(err, bidding.ErrEngineClosed):
			status = http.StatusServiceUnavailable
		}
		c.JSON(status, gin.H{
			"error":  err.Error(),
			"bid_id": rec.BidID,
			"status": string(rec.Status),
		})
		return
	}

	resp := gin.H{
		"bid":        rec,
		"bid_id":     rec.BidID,
		"status":     string(rec.Status),
		"status_url": biddingPublicStatURL + "?bid_id=" + rec.BidID,
	}
	if rec.Status == bidding.BidStatusSettled {
		passToken := g.issueBiddingPriorityPass(c, now)
		resp["pass_issued"] = true
		resp["priority_pass"] = passToken
		resp["pass_token"] = passToken
		c.JSON(http.StatusOK, resp)
		return
	}
	c.JSON(http.StatusAccepted, resp)
}

// handleBidStatus serves GET /_concert/bids/status?bid_id=<id>. When the bid
// has cleared and settled on-chain, Concert issues a signed Priority +
// Admission pass (both HttpOnly cookies and JSON pass_issued metadata) so the
// winning agent skips directly into the priority lane.
//
// # Parameters
//
//   - c: Request *gin.Context with bid_id (or id) query parameter.
//
// # Example
//
//	g.handleBidStatus(c)
//
// # Used By
//
// Called by generation.handleBiddingSubroute in internal/server/bidding_wiring.go.
func (g *generation) handleBidStatus(c *gin.Context) {
	c.Set(ctxSkipWaitingHeaders, true)
	c.Header("Cache-Control", "no-store")
	if g.a == nil || g.a.bidding == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent_bidding_disabled"})
		return
	}
	bidID := strings.TrimSpace(c.Query("bid_id"))
	if bidID == "" {
		bidID = strings.TrimSpace(c.Query("id"))
	}
	if bidID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bid_id query parameter is required"})
		return
	}
	rec, ok := g.a.bidding.GetBidStatus(bidID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "bid_not_found"})
		return
	}
	resp := gin.H{
		"bid":    rec,
		"bid_id": rec.BidID,
		"status": string(rec.Status),
	}
	if rec.Status == bidding.BidStatusSettled {
		passToken := g.issueBiddingPriorityPass(c, time.Now().UTC())
		resp["pass_issued"] = true
		resp["priority_pass"] = passToken
		resp["pass_token"] = passToken
	} else {
		resp["pass_issued"] = false
	}
	c.JSON(http.StatusOK, resp)
}

// issueBiddingPriorityPass mints and attaches a signed concert_admit cookie
// paired with a bound concert_priority cookie (at or above the configured lane
// rank) for a settled bidding winner, returning the signed priority token.
//
// # Parameters
//
//   - c: Request *gin.Context whose ResponseWriter receives the Set-Cookie headers.
//   - now: Current timestamp for pass expiry calculations.
//
// # Returns
//
// The minted concert_priority token string, or "" if signing state is unavailable.
//
// # Example
//
//	tok := g.issueBiddingPriorityPass(c, time.Now().UTC())
//
// # Used By
//
// Called by generation.handleBidSubmit and generation.handleBidStatus in
// internal/server/bidding_wiring.go.
func (g *generation) issueBiddingPriorityPass(c *gin.Context, now time.Time) string {
	if g == nil || g.a == nil || g.a.admit == nil || g.a.prio == nil || g.a.prio.grants == nil {
		return ""
	}
	id, _ := g.a.admit.refresh(c.Writer, c.Request, now)
	if id == (passID{}) {
		return ""
	}
	laneRank := priorityRank(g.cfg.priorityLaneRank)
	if laneRank < rankCheckout && rankCheckout < rankCount {
		laneRank = rankCheckout
	}
	if laneRank >= rankCount {
		laneRank = rankStaff
	}
	ttl := g.cfg.passDuration
	if ttl < priorityMinTTL {
		ttl = 30 * time.Minute
	}
	if ttl > priorityMaxTTL {
		ttl = priorityMaxTTL
	}
	token := g.a.prio.grants.mint(id, laneRank, now.Add(ttl))
	o := g.a.admit.opts.Load()
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     priorityCookie,
		Value:    token,
		Path:     o.path,
		Domain:   o.domain,
		MaxAge:   max(int(ttl/time.Second), 1),
		Secure:   o.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	g.a.prio.grants.issued.Add(1)
	return token
}

// biddingMetricsTotals returns cumulative submitted, settled, and rejected bid
// totals combining internal/bidding.Engine.Stats() with HTTP-level rejections.
//
// # Parameters
//
// None.
//
// # Returns
//
// (submitted, settled, rejected) counters for Prometheus exposition.
//
// # Example
//
//	sub, set, rej := a.biddingMetricsTotals()
//
// # Used By
//
// Called by app.renderPrometheusMetrics in internal/server/metrics.go.
func (a *app) biddingMetricsTotals() (submitted, settled, rejected int64) {
	if a == nil {
		return 0, 0, 0
	}
	if a.bidding != nil {
		st := a.bidding.Stats()
		submitted = st.Submitted
		settled = st.InstantSettled + st.WinnersSettled
		rejected = st.Rejected
	}
	if a.stats != nil {
		rejected += a.stats.biddingRejected.Load()
	}
	return submitted, settled, rejected
}
