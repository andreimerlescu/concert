package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/andreimerlescu/room"
	"github.com/gin-gonic/gin"
)

// waitingRoomSignalHeaders wraps gated catch-all responses ahead of room so
// every queued waiting-room response (HTML or JSON, regardless of whether the
// status is 200, 429, or 503) carries explicit Concert queue signal headers
// (X-Concert-Queue, Retry-After, X-Concert-Position, Cache-Control: no-store,
// and X-Concert-Status-Url when non-default) and clears any incoming
// concert_admit cookie.
//
// Registered routes (c.FullPath() != ""), admitted/proxied responses
// (ctxAdmitted), capacity-breaker 503s (ctxRoomFull), and keyed agent
// responses (handled in agent.go) pass through untouched without
// X-Concert-Queue.
//
// # Parameters
//
//   - a: Owning *app providing room ticket lookup and admitter cookie clearing.
//   - retryAfter: Positive Retry-After interval in seconds.
//
// # Returns
//
// A gin.HandlerFunc middleware attached ahead of apiQueueResponses and room.
//
// # Example
//
//	r.Use(waitingRoomSignalHeaders(g.a, cfg.retryAfter))
//
// # Used By
//
// Called by buildRouter in internal/server/router.go.
func waitingRoomSignalHeaders(a *app, retryAfter int) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.FullPath() != "" || c.GetString(ctxAgentKey) != "" {
			c.Next()
			return
		}
		c.Writer = &waitingRoomHeaderWriter{
			ResponseWriter: c.Writer,
			a:              a,
			c:              c,
			retryAfter:     retryAfter,
		}
		c.Next()
	}
}

// waitingRoomHeaderWriter intercepts the first header or body write on gated
// catch-all requests and injects Concert's explicit waiting-room signal
// headers exclusively when room emitted a queued waiting-room response.
//
// Admitted upstream responses (ctxAdmitted), room-full capacity-breaker 503s
// (ctxRoomFull), and non-queued error responses pass through unmodified so
// streaming, flushing, hijacking, and upstream 503 semantics are preserved.
type waitingRoomHeaderWriter struct {
	gin.ResponseWriter
	a          *app
	c          *gin.Context
	retryAfter int
	statusURL  string
	decided    bool
}

// apply inspects status code and headers once before the first write and adds
// waiting-room signal headers only when the response represents a queued
// waiting-room response.
//
// # Parameters
//
//   - code: HTTP status code about to be written.
//
// # Example
//
//	w.apply(http.StatusOK)
//
// # Used By
//
// Called by waitingRoomHeaderWriter write methods in internal/server/api.go.
func (w *waitingRoomHeaderWriter) apply(code int) {
	if w.decided {
		return
	}
	w.decided = true
	if w.c == nil || w.c.GetBool(ctxWaitingHeadersApplied) || w.c.GetBool(ctxSkipWaitingHeaders) {
		return
	}
	if !isQueuedWaitingRoomResponse(w.a, w.c, w.ResponseWriter.Header(), code) {
		return
	}
	applyWaitingRoomHeaders(w.a, w.c, w.ResponseWriter, w.retryAfter, w.statusURL)
}

// WriteHeader applies waiting-room signal headers when appropriate, then
// delegates to the underlying gin.ResponseWriter.
//
// # Parameters
//
//   - code: HTTP status code.
//
// # Example
//
//	w.WriteHeader(http.StatusOK)
//
// # Used By
//
// Implements http.ResponseWriter / gin.ResponseWriter.
func (w *waitingRoomHeaderWriter) WriteHeader(code int) {
	w.apply(code)
	w.ResponseWriter.WriteHeader(code)
}

// WriteHeaderNow ensures waiting-room signal headers are evaluated before
// flushing headers to the wire.
//
// # Parameters
//
// None.
//
// # Example
//
//	w.WriteHeaderNow()
//
// # Used By
//
// Implements gin.ResponseWriter.
func (w *waitingRoomHeaderWriter) WriteHeaderNow() {
	if !w.decided {
		w.apply(w.ResponseWriter.Status())
	}
	w.ResponseWriter.WriteHeaderNow()
}

// Write ensures waiting-room signal headers are evaluated on implicit header
// writes before writing b.
//
// # Parameters
//
//   - b: Response body bytes.
//
// # Returns
//
// Bytes written and any write error from the wrapped ResponseWriter.
//
// # Example
//
//	_, _ = w.Write([]byte("ok"))
//
// # Used By
//
// Implements io.Writer / http.ResponseWriter.
func (w *waitingRoomHeaderWriter) Write(b []byte) (int, error) {
	if !w.decided {
		w.apply(w.ResponseWriter.Status())
	}
	return w.ResponseWriter.Write(b)
}

// WriteString ensures waiting-room signal headers are evaluated on implicit
// header writes before writing s.
//
// # Parameters
//
//   - s: Response body string.
//
// # Returns
//
// Bytes written and any write error from the wrapped ResponseWriter.
//
// # Example
//
//	_, _ = w.WriteString("ok")
//
// # Used By
//
// Implements gin.ResponseWriter.
func (w *waitingRoomHeaderWriter) WriteString(s string) (int, error) {
	if !w.decided {
		w.apply(w.ResponseWriter.Status())
	}
	return w.ResponseWriter.WriteString(s)
}

// Flush ensures waiting-room signal headers are evaluated before flushing the
// underlying writer.
//
// # Parameters
//
// None.
//
// # Example
//
//	w.Flush()
//
// # Used By
//
// Implements http.Flusher / gin.ResponseWriter.
func (w *waitingRoomHeaderWriter) Flush() {
	if !w.decided {
		w.apply(w.ResponseWriter.Status())
	}
	w.ResponseWriter.Flush()
}

// Unwrap exposes the underlying http.ResponseWriter for http.ResponseController.
//
// # Parameters
//
// None.
//
// # Returns
//
// The wrapped gin.ResponseWriter as an http.ResponseWriter.
//
// # Example
//
//	rw := w.Unwrap()
//
// # Used By
//
// Used by net/http.ResponseController.
func (w *waitingRoomHeaderWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// isQueuedWaitingRoomResponse reports whether a response with status code and
// headers h on context c is a genuine queued waiting-room response (rather
// than an admitted upstream response, capacity-breaker 503, ban/rate-limit
// denial, or bare non-queued error).
//
// # Parameters
//
//   - a: Owning *app (may be nil in isolated unit tests).
//   - c: Request *gin.Context (may be nil in isolated unit tests).
//   - h: Response headers written so far (may be nil).
//   - code: HTTP status code being written.
//
// # Returns
//
// true only when the response is a queued waiting-room page/payload.
//
// # Example
//
//	queued := isQueuedWaitingRoomResponse(a, c, w.Header(), http.StatusOK)
//
// # Used By
//
// Called by waitingRoomHeaderWriter.apply and apiQueueWriter.WriteHeader in
// internal/server/api.go.
func isQueuedWaitingRoomResponse(a *app, c *gin.Context, h http.Header, code int) bool {
	if c == nil || c.FullPath() != "" || c.GetBool(ctxAdmitted) || c.GetBool(ctxRoomFull) {
		return false
	}
	if c.GetString(ctxAgentKey) != "" {
		return false
	}
	switch code {
	case http.StatusOK, http.StatusTooManyRequests, http.StatusServiceUnavailable:
	default:
		return false
	}
	if h != nil && issuedTicket(h) != "" {
		return true
	}
	if code == http.StatusOK {
		return true
	}
	// For 429 or 503 (not ctxRoomFull), distinguish a queued waiting-room
	// response from a bare timeout/error 503 or rate-limit 429 by verifying
	// either HTML waiting-room content or an active queued room_ticket.
	if h != nil && strings.HasPrefix(h.Get("Content-Type"), "text/html") {
		return true
	}
	if c.Request != nil && a != nil && a.room != nil {
		if ck, err := c.Request.Cookie("room_ticket"); err == nil && ck.Value != "" {
			if _, ok := a.room.Ticket(ck.Value); ok {
				return true
			}
		}
	}
	return false
}

// applyWaitingRoomHeaders sets Concert's explicit waiting-room headers
// (X-Concert-Queue, Retry-After, Cache-Control: no-store, optional
// X-Concert-Position and non-default X-Concert-Status-Url) and clears any
// incoming concert_admit cookie with Max-Age=0.
//
// # Parameters
//
//   - a: Owning *app providing room ticket lookup and admitter clearing.
//   - c: Request *gin.Context (may be nil).
//   - w: Destination http.ResponseWriter; must be non-nil.
//   - retryAfter: Positive retry interval in seconds (clamped to >= 1).
//   - statusURL: Optional status endpoint path; omitted when empty or "/queue/status".
//
// # Example
//
//	applyWaitingRoomHeaders(a, c, w, 5, "")
//
// # Used By
//
// Called by waitingRoomHeaderWriter.apply and apiQueueWriter.WriteHeader in
// internal/server/api.go.
func applyWaitingRoomHeaders(a *app, c *gin.Context, w http.ResponseWriter, retryAfter int, statusURL string) {
	if w == nil {
		return
	}
	if retryAfter < 1 {
		retryAfter = 1
	}
	h := w.Header()
	h.Set(headerConcertQueue, "1")
	h.Set("Retry-After", strconv.Itoa(retryAfter))
	h.Set("Cache-Control", "no-store")

	tok := issuedTicket(h)
	if tok == "" && c != nil && c.Request != nil {
		if ck, err := c.Request.Cookie("room_ticket"); err == nil {
			tok = ck.Value
		}
	}
	if tok != "" && a != nil && a.room != nil {
		if ti, ok := a.room.Ticket(tok); ok {
			pos := max(ti.Position, 0)
			h.Set(headerConcertPosition, strconv.FormatInt(pos, 10))
		}
	}

	if statusURL != "" && statusURL != defaultQueueStatusURL {
		h.Set(headerConcertStatusURL, statusURL)
	} else {
		h.Del(headerConcertStatusURL)
	}

	// Never leave a dead, forged, or re-queued concert_admit cookie alongside
	// a waiting-room response carrying room_ticket.
	if a != nil && a.admit != nil && c != nil && c.Request != nil {
		if _, err := c.Request.Cookie(admitCookie); err == nil {
			a.admit.clear(w)
		}
	}
	if c != nil {
		c.Set(ctxWaitingHeadersApplied, true)
	}
}

// apiQueueResponses rewrites room's own responses (waiting-room HTML, breaker
// 503) into JSON for clients that did not ask for HTML. It applies only to
// gated catch-all requests: registered routes (/queue/status, /_room/*,
// bypass, asset and stream paths) have a non-empty FullPath and are left alone.
//
// Keyed requests (agents; see agent.go) are not cookie clients: agentGate
// shapes their responses, with no cookies, whatever -api-json says.
func apiQueueResponses(a *app, retryAfter int) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.FullPath() != "" || wantsHTML(c.Request) || c.GetString(ctxAgentKey) != "" {
			c.Next()
			return
		}
		c.Writer = &apiQueueWriter{
			ResponseWriter: c.Writer,
			a:              a,
			c:              c,
			retryAfter:     retryAfter,
		}
		c.Next()
	}
}

func wantsHTML(r *http.Request) bool {
	return strings.Contains(strings.Join(r.Header.Values("Accept"), ","), "text/html")
}

// apiQueueWriter decides once, at the first header or body write, whether
// the response came from room (proxy not reached) or from the upstream
// (proxy reached). Upstream responses and FullResponder responses pass through
// untouched, including streaming, flushing, and connection hijacking for upgrades.
type apiQueueWriter struct {
	gin.ResponseWriter
	a          *app
	c          *gin.Context
	retryAfter int
	decided    bool
	swallow    bool
}

func (w *apiQueueWriter) WriteHeader(code int) {
	if w.decided {
		if !w.swallow {
			w.ResponseWriter.WriteHeader(code)
		}
		return
	}
	w.decided = true

	if w.c.GetBool(ctxAdmitted) || w.c.GetBool(ctxRoomFull) {
		w.ResponseWriter.WriteHeader(code)
		return
	}

	// room is answering this request itself. Keep its Set-Cookie headers so
	// clients with a cookie jar hold their place, replace everything else.
	w.swallow = true
	h := w.ResponseWriter.Header()
	queued := (code == http.StatusOK || code == http.StatusServiceUnavailable || code == http.StatusTooManyRequests) &&
		isQueuedWaitingRoomResponse(w.a, w.c, h, code)

	var status int
	var body []byte
	if queued {
		status, body = w.translateQueued()
	} else {
		status, body = w.translate(code)
	}

	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	if queued {
		applyWaitingRoomHeaders(w.a, w.c, w.ResponseWriter, w.retryAfter, defaultQueueStatusURL)
	} else {
		if w.c != nil {
			w.c.Set(ctxSkipWaitingHeaders, true)
		}
		h.Set("Cache-Control", "no-store")
		if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
			h.Set("Retry-After", strconv.Itoa(w.retryAfter))
		}
	}

	w.ResponseWriter.WriteHeader(status)
	w.ResponseWriter.WriteHeaderNow()
	_, _ = w.ResponseWriter.Write(body)
}

func (w *apiQueueWriter) WriteHeaderNow() {
	if !w.decided {
		w.WriteHeader(w.ResponseWriter.Status())
	}
	if !w.swallow {
		w.ResponseWriter.WriteHeaderNow()
	}
}

func (w *apiQueueWriter) Write(b []byte) (int, error) {
	if !w.decided {
		w.WriteHeader(w.ResponseWriter.Status())
	}
	if w.swallow {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func (w *apiQueueWriter) WriteString(s string) (int, error) {
	if !w.decided {
		w.WriteHeader(w.ResponseWriter.Status())
	}
	if w.swallow {
		return len(s), nil
	}
	return w.ResponseWriter.WriteString(s)
}

func (w *apiQueueWriter) Flush() {
	if !w.decided {
		w.WriteHeader(w.ResponseWriter.Status())
	}
	w.ResponseWriter.Flush()
}

func (w *apiQueueWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// translateQueued formats Concert's backward-compatible queued JSON payload
// returned to non-HTML clients under -api-json.
//
// # Parameters
//
// None.
//
// # Returns
//
// HTTP 429 Too Many Requests and JSON bytes with queued=true.
//
// # Example
//
//	status, body := w.translateQueued()
//
// # Used By
//
// Called by apiQueueWriter.WriteHeader and apiQueueWriter.translate in
// internal/server/api.go.
func (w *apiQueueWriter) translateQueued() (int, []byte) {
	payload := gin.H{
		"queued":              true,
		"status_url":          defaultQueueStatusURL,
		"retry_after_seconds": w.retryAfter,
		"hint":                "keep the room_ticket cookie and retry to hold your position",
	}
	if w.a != nil {
		if g := w.a.current(); g != nil && g.biddingEnabledForRequest(w.c) {
			if auctionOffer, ok := g.biddingOfferForRequest(w.c); ok {
				payload["auction"] = auctionOffer
			}
		}
	}
	return http.StatusTooManyRequests, mustJSON(payload)
}

func (w *apiQueueWriter) translate(code int) (int, []byte) {
	switch code {
	case http.StatusOK:
		// The waiting-room page. The client is queued.
		return w.translateQueued()
	case http.StatusServiceUnavailable:
		// Admission timed out or room fell back to a bare 503. Queue-full
		// rejections are handled and alerted solely via FullResponder / EventReject.
		return http.StatusServiceUnavailable, mustJSON(gin.H{
			"queued":              false,
			"error":               "waiting room is full",
			"retry_after_seconds": w.retryAfter,
		})
	default:
		return code, mustJSON(gin.H{"error": http.StatusText(code)})
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"error":"internal"}`)
	}
	return b
}

func stripCookies(req *http.Request, names ...string) {
	cookies := req.Cookies()
	if len(cookies) == 0 {
		return
	}
	drop := make(map[string]struct{}, len(names))
	for _, n := range names {
		drop[n] = struct{}{}
	}
	req.Header.Del("Cookie")
	for _, c := range cookies {
		if _, skip := drop[c.Name]; skip {
			continue
		}
		req.AddCookie(c)
	}
}

// ─── API: overview ───────────────────────────────────────────────────────────

func (p *portal) apiOverview(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		return
	}
	g := a.current()
	wr, stats := a.room, a.stats
	rate, surge := a.pricing()
	h := gin.H{
		"site":                              g.cfg.siteHost,
		"preset":                            g.cfg.preset,
		"config_managed":                    g.cfg.configManaged,
		"runtime_override":                  a.runtimeCapOverride.Load(),
		"cap":                               wr.Cap(),
		"occupancy":                         wr.Len(),
		"cap_draining":                      wr.Len() > int(wr.Cap()),
		"queue_depth":                       wr.QueueDepth(),
		"live_queue_depth":                  wr.LiveQueueDepth(),
		"max_queue_depth":                   wr.MaxQueueDepth(),
		"utilization":                       wr.UtilizationSmoothed(),
		"token_ttl":                         wr.TokenTTL().String(),
		"first_poll_grace":                  wr.FirstPollGrace().String(),
		"ready_grace":                       wr.ReadyGrace().String(),
		"idle_poll_ttl":                     wr.IdlePollTTL().String(),
		"reaper":                            wr.ReaperInterval().String(),
		"queued_total":                      stats.queued.Load(),
		"evicted_total":                     stats.evicted.Load(),
		"timeouts_total":                    stats.timeouts.Load(),
		"promoted_total":                    stats.promoted.Load(),
		"removed_total":                     stats.removed.Load(),
		"rejected_503_total":                stats.rejected503.Load(),
		"cleared_total":                     stats.cleared.Load(),
		"token_rejected_total":              stats.tokenRejected.Load(),
		"upstream_body_idle_timeouts_total": stats.upstreamBodyIdleTimeouts.Load(),
		"lease_ceiling":                     wr.LeaseCeiling(),
		"asset_cap":                         g.assets.global.Cap(),
		"asset_in_flight":                   g.assets.global.Len(),
		"asset_users":                       g.assets.users.count.Load(),
		"asset_served_total":                stats.assetServed.Load(),
		"asset_denied_total":                stats.assetDenied.Load(),
		"asset_user_throttled_total":        stats.assetUserThrottled.Load(),
		"asset_global_throttled_total":      stats.assetGlobalThrottled.Load(),
		"static_served_total":               stats.staticServed.Load(),
		"static_not_found_total":            stats.staticNotFound.Load(),
		"fcgi_requests_total":               stats.fcgiRequests.Load(),
		"fcgi_denied_total":                 stats.fcgiDenied.Load(),
		"stream_cap":                        g.streams.sem.Cap(),
		"stream_active":                     g.streams.sem.Len(),
		"stream_served_total":               stats.streamServed.Load(),
		"stream_denied_total":               stats.streamDenied.Load(),
		"stream_throttled_total":            stats.streamThrottled.Load(),
		"abuse_enabled":                     g.abuse != nil,
		"abuse_tracked":                     g.abuse.tracked(),
		"abuse_range_bans":                  g.abuse.rangeCount(),
		"abuse_strikes_total":               stats.abuseStrikes.Load(),
		"abuse_bans_total":                  stats.abuseBans.Load(),
		"abuse_rejected_total":              stats.abuseRejected.Load(),
		"abuse_dropped_total":               stats.abuseDropped.Load(),
		"active_bans":                       len(g.abuse.bans(time.Now())),
		"notes_tracked":                     p.notes.count(),
		"notes_dropped":                     p.notes.dropped.Load(),
		"kicked_active":                     p.kicked.count(),
		"history_clients":                   p.history.count.Load(),
		"rate":                              rate,
		"surge":                             surge,
		"skip_url":                          wr.SkipURL(),
	}
	for k, v := range g.priorityView() {
		h[k] = v
	}
	for k, v := range g.agentView() {
		h[k] = v
	}
	a.populateOverviewEnterprise(h)
	c.JSON(http.StatusOK, h)
}

// ─── API: queue ──────────────────────────────────────────────────────────────

// occupantView is one waiting visitor as the portal shows it. Raw tickets
// never leave concert; the UI addresses visitors by an opaque ID derived
// from the ticket.
type occupantView struct {
	ID          string    `json:"id"`
	Client      string    `json:"client"`
	UserAgent   string    `json:"user_agent"`
	Path        string    `json:"path"`
	Joined      time.Time `json:"joined"`
	LastSeen    time.Time `json:"last_seen"`
	IdleSeconds int       `json:"idle_seconds"`
	Position    int64     `json:"position"`
	Ready       bool      `json:"ready"`
	HasPass     bool      `json:"has_pass"`
	Promoted    bool      `json:"promoted"`
	Rank        string    `json:"rank"`
	// Agent is the first 8 characters of the session ID of a keyed place
	// (an agent waiting with Concert-Session), or "".
	Agent string `json:"agent"`
}

// ticketRankLabel is the label of a rank room recorded on a ticket.
func ticketRankLabel(r int) string {
	if r <= 0 || r >= int(rankCount) {
		return ""
	}
	return rankLabel(priorityRank(r))
}

func occupantID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}

// queueViews lists the front of room's line, in line order, with the path
// and browser noted when each visitor joined.
func (p *portal) queueViewsFor(a *app, now time.Time) []occupantView {
	line := a.room.Queue(portalQueueLimit)
	out := make([]occupantView, 0, len(line))
	for _, t := range line {
		note, _ := p.notes.get(t.Token)
		out = append(out, occupantView{
			ID:          occupantID(t.Token),
			Client:      t.ClientKey,
			UserAgent:   note.ua,
			Path:        note.path,
			Joined:      t.IssuedAt.UTC(),
			LastSeen:    t.LastSeen.UTC(),
			IdleSeconds: int(now.Sub(t.LastSeen) / time.Second),
			Position:    t.Position,
			Ready:       t.Position <= 0,
			HasPass:     t.HasPass,
			Promoted:    t.Promoted,
			Rank:        ticketRankLabel(t.Rank),
			Agent:       agentSessionLabel(t.Key),
		})
	}
	return out
}

func (p *portal) queueViews(now time.Time) []occupantView {
	return p.queueViewsFor(p.a, now)
}

func (p *portal) lookup(id string) (room.TicketInfo, bool) {
	return p.lookupFor(p.a, id)
}

func (p *portal) lookupFor(a *app, id string) (room.TicketInfo, bool) {
	for _, t := range a.room.Queue(portalQueueLimit) {
		if occupantID(t.Token) == id {
			return t, true
		}
	}
	return room.TicketInfo{}, false
}

func (p *portal) apiQueue(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		return
	}
	list := p.queueViewsFor(a, time.Now())
	c.JSON(http.StatusOK, gin.H{
		"occupants":        list,
		"listed":           len(list),
		"limit":            portalQueueLimit,
		"kicked":           p.kicked.count(),
		"live_queue_depth": a.room.LiveQueueDepth(),
	})
}

type occupantAction struct {
	ID  string `json:"id"`
	Ban bool   `json:"ban"`
}

// apiPromote moves a visitor to the front of the line. It is an operator
// promotion: no price, and no VIP pass, because only the visitor's own
// response could carry the pass cookie.
func (p *portal) apiPromote(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		return
	}
	var body occupantAction
	if err := c.ShouldBindJSON(&body); err != nil || body.ID == "" {
		jsonError(c, http.StatusBadRequest, "id is required")
		return
	}
	t, ok := p.lookupFor(a, body.ID)
	if !ok {
		jsonError(c, http.StatusNotFound, "that visitor is no longer in line")
		return
	}
	if err := a.room.AdminPromote(t.Token, 1); err != nil {
		jsonError(c, http.StatusConflict, "room refused the promotion: "+err.Error())
		return
	}
	log.Printf("portal: %s moved %s (%s) to the front", portalActor(c), body.ID, t.ClientKey)
	pr := portalPrincipal(c)
	a.recordAudit(auditEvent{
		Actor:    pr.Actor,
		Role:     pr.Role.String(),
		Source:   "portal",
		Action:   "queue.promote",
		Target:   body.ID,
		Outcome:  "allow",
		ClientIP: pr.IP.String(),
		Details:  map[string]any{"client": t.ClientKey},
	})
	c.JSON(http.StatusOK, gin.H{"promoted": body.ID})
}

// apiKick removes a visitor from the line and, with ban, bans their address.
// A removed visitor's next poll reloads their page into a removal notice,
// and they can rejoin at the back. A banned visitor's reload shows the block
// notice, and the ban drops everyone else waiting from the same address.
func (p *portal) apiKick(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		return
	}
	var body occupantAction
	if err := c.ShouldBindJSON(&body); err != nil || body.ID == "" {
		jsonError(c, http.StatusBadRequest, "id is required")
		return
	}
	t, ok := p.lookupFor(a, body.ID)
	if !ok {
		jsonError(c, http.StatusNotFound, "that visitor is no longer in line")
		return
	}

	now := time.Now()
	var banFor time.Duration
	if body.Ban {
		reg := a.current().abuse
		if reg == nil {
			jsonError(c, http.StatusConflict, errAbuseDisabled.Error())
			return
		}
		ip, err := netip.ParseAddr(t.ClientKey)
		if err != nil {
			jsonError(c, http.StatusConflict, "concert has no address for that visitor")
			return
		}
		left, banned := reg.banNow(ip, now)
		if !banned {
			jsonError(c, http.StatusConflict, errClientExempt.Error())
			return
		}
		banFor = left
		if k, ok := abuseKey(ip); ok {
			p.history.noteSource(keyPrefix(k), "removed from the line and banned in the portal by "+portalActor(c))
		}
		a.saveBansNow()
	} else {
		p.kicked.add(t.Token, now.Add(a.room.TokenTTL()+time.Minute))
	}

	if err := a.room.RemoveToken(t.Token); err != nil {
		var notFound room.ErrTokenNotFound
		if !errors.As(err, &notFound) {
			log.Printf("portal: removing %s: %v", body.ID, err)
		}
	}
	p.notes.remove(t.Token)
	if t.Key != "" {
		a.agents.forget(t.Key)
	}
	log.Printf("portal: %s removed %s (%s) from the line, ban=%v", portalActor(c), body.ID, t.ClientKey, body.Ban)
	pr := portalPrincipal(c)
	a.recordAudit(auditEvent{
		Actor:    pr.Actor,
		Role:     pr.Role.String(),
		Source:   "portal",
		Action:   "queue.kick",
		Target:   body.ID,
		Outcome:  "allow",
		ClientIP: pr.IP.String(),
		Details:  map[string]any{"client": t.ClientKey, "ban": body.Ban},
	})

	secs := int(banFor / time.Second)
	if banFor == banForeverLeft {
		secs = 0
	}
	c.JSON(http.StatusOK, gin.H{
		"kicked":      body.ID,
		"banned":      body.Ban,
		"ban_seconds": secs,
	})
}

// ─── API: bans ───────────────────────────────────────────────────────────────

func (p *portal) apiBans(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		return
	}
	reg := a.current().abuse
	c.JSON(http.StatusOK, gin.H{
		"enabled":   reg != nil,
		"tracked":   reg.tracked(),
		"ranges":    reg.rangeCount(),
		"persisted": a.bansPath != "",
		"bans":      reg.bans(time.Now()),
	})
}

// apiBanSave creates a ban or replaces an existing one. The client may be a
// single address (IPv6 is banned by its /64) or a CIDR range such as
// 203.0.0.0/16. A permanent ban lasts until it is lifted. Waiting visitors
// the ban covers are removed from the line at once; "dropped" counts them.
func (p *portal) apiBanSave(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		return
	}
	var body struct {
		Client    string `json:"client"`
		Duration  string `json:"duration"`
		Permanent bool   `json:"permanent"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		jsonError(c, http.StatusBadRequest, "client and duration are required")
		return
	}
	reg := a.current().abuse
	if reg == nil {
		jsonError(c, http.StatusConflict, errAbuseDisabled.Error())
		return
	}
	target, err := parseBanTarget(body.Client)
	if err != nil {
		jsonError(c, http.StatusBadRequest, err.Error())
		return
	}
	pr := portalPrincipal(c)
	// Permanent bans and CIDR range bans require the admin role.
	if (body.Permanent || !target.single) && !pr.Role.allows(roleAdmin) {
		a.recordAudit(auditEvent{
			Actor:    pr.Actor,
			Role:     pr.Role.String(),
			Source:   "portal",
			Action:   "ban.create",
			Target:   target.String(),
			Outcome:  "deny",
			ClientIP: pr.IP.String(),
			Details:  map[string]any{"permanent": body.Permanent, "range": !target.single, "required": roleAdmin.String()},
		})
		jsonError(c, http.StatusForbidden, "permanent bans and CIDR range bans require admin role")
		return
	}
	var d time.Duration // 0 = permanent
	if !body.Permanent {
		d, err = time.ParseDuration(strings.TrimSpace(body.Duration))
		if err != nil || d < time.Minute || d > 365*24*time.Hour {
			jsonError(c, http.StatusBadRequest, "duration must be between 1m and 8760h, for example 30m or 24h, or the ban must be permanent")
			return
		}
	}
	now := time.Now()
	var until any
	if !body.Permanent {
		until = now.Add(d).UTC()
	}
	lasting := "permanently"
	if !body.Permanent {
		lasting = "for " + d.String()
	}
	source := "banned in the portal by " + portalActor(c)

	if target.single {
		key, err := reg.banFor(target.prefix.Addr(), d, now)
		switch {
		case errors.Is(err, errAbuseDisabled), errors.Is(err, errClientExempt), errors.Is(err, errRegistryFull):
			jsonError(c, http.StatusConflict, err.Error())
			return
		case err != nil:
			jsonError(c, http.StatusBadRequest, err.Error())
			return
		}
		p.history.noteSource(target.scope(), source)
		dropped := a.dropWaiting(target.scope())
		a.saveBansNow()
		a.recordAudit(auditEvent{
			Actor:    pr.Actor,
			Role:     pr.Role.String(),
			Source:   "portal",
			Action:   "ban.create",
			Target:   displayKey(key),
			Outcome:  "allow",
			ClientIP: pr.IP.String(),
			Details:  map[string]any{"permanent": body.Permanent, "duration": d.String(), "dropped": dropped},
		})
		log.Printf("portal: %s banned %s %s, removed %d waiting", portalActor(c), displayKey(key), lasting, dropped)
		c.JSON(http.StatusOK, gin.H{
			"client":    displayKey(key),
			"until":     until,
			"range":     false,
			"permanent": body.Permanent,
			"dropped":   dropped,
		})
		return
	}

	if err := reg.banRange(target.prefix, d, now); err != nil {
		jsonError(c, http.StatusConflict, err.Error())
		return
	}
	p.history.noteSource(target.scope(), source)
	dropped := a.dropWaiting(target.scope())
	a.saveBansNow()
	exempt := reg.exemptWithin(target.prefix)
	a.recordAudit(auditEvent{
		Actor:    pr.Actor,
		Role:     pr.Role.String(),
		Source:   "portal",
		Action:   "ban.create_range",
		Target:   target.prefix.String(),
		Outcome:  "allow",
		ClientIP: pr.IP.String(),
		Details:  map[string]any{"permanent": body.Permanent, "duration": d.String(), "dropped": dropped},
	})
	log.Printf("portal: %s banned range %s %s, removed %d waiting (exempt within: %v)",
		portalActor(c), target.prefix, lasting, dropped, exempt)
	c.JSON(http.StatusOK, gin.H{
		"client":        target.prefix.String(),
		"until":         until,
		"range":         true,
		"permanent":     body.Permanent,
		"dropped":       dropped,
		"exempt_within": exempt,
	})
}

func (p *portal) apiUnban(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		return
	}
	reg := a.current().abuse
	if reg == nil {
		jsonError(c, http.StatusConflict, errAbuseDisabled.Error())
		return
	}
	target, err := parseBanTarget(c.Query("client"))
	if err != nil {
		jsonError(c, http.StatusBadRequest, err.Error())
		return
	}
	if !reg.unbanTarget(target) {
		jsonError(c, http.StatusNotFound, "that client is not tracked")
		return
	}
	p.history.lifted(target.scope(), time.Now(), "the portal ("+portalActor(c)+")")
	a.saveBansNow()
	a.publishClusterUnban(target)
	pr := portalPrincipal(c)
	a.recordAudit(auditEvent{
		Actor:    pr.Actor,
		Role:     pr.Role.String(),
		Source:   "portal",
		Action:   "ban.lift",
		Target:   target.String(),
		Outcome:  "allow",
		ClientIP: pr.IP.String(),
	})
	log.Printf("portal: %s unbanned %s", portalActor(c), target)
	c.JSON(http.StatusOK, gin.H{"unbanned": target.String()})
}

// ─── API: settings ───────────────────────────────────────────────────────────

func (p *portal) settingsViewFor(a *app) gin.H {
	views, file := a.settingsViews()
	g := a.current()
	return gin.H{
		"site":             g.cfg.siteHost,
		"config_managed":   g.cfg.configManaged,
		"runtime_override": a.runtimeCapOverride.Load(),
		"settings":         views,
		"persisted":        file != "" && !g.cfg.configManaged,
		"file":             file,
		"fixed":            a.fixedSettings(),
	}
}

func (p *portal) apiSettings(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, p.settingsViewFor(a))
}

// apiSettingsSave takes a JSON object of setting keys to new values, for
// example {"cap": 40, "abuse_cooldown": "10m"}, and applies them at once.
// Every value is validated before any is saved or applied; see
// app.changeSettings.
func (p *portal) apiSettingsSave(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		return
	}
	var set map[string]json.RawMessage
	if err := json.NewDecoder(io.LimitReader(c.Request.Body, settingsBodyLimit)).Decode(&set); err != nil || len(set) == 0 {
		jsonError(c, http.StatusBadRequest, "send a JSON object of the settings to change")
		return
	}
	ip, _ := remoteAddr(c.Request)
	pr := portalPrincipal(c)
	if err := a.changeSettings(set, nil, ip); err != nil {
		a.recordAudit(auditEvent{
			Actor:    pr.Actor,
			Role:     pr.Role.String(),
			Source:   "portal",
			Action:   "settings.update",
			Outcome:  "error",
			ClientIP: pr.IP.String(),
			Details:  map[string]any{"keys": sortedKeys(set), "error": err.Error()},
		})
		jsonError(c, settingsStatus(err), err.Error())
		return
	}
	a.recordAudit(auditEvent{
		Actor:    pr.Actor,
		Role:     pr.Role.String(),
		Source:   "portal",
		Action:   "settings.update",
		Outcome:  "allow",
		ClientIP: pr.IP.String(),
		Details:  map[string]any{"keys": sortedKeys(set)},
	})
	a.notifyAlert(alertEvent{
		Category:    alertCatSecurity,
		Severity:    alertSevInfo,
		Title:       "Portal settings modified",
		Summary:     fmt.Sprintf("Administrator %s updated settings: %s", pr.Actor, strings.Join(sortedKeys(set), ", ")),
		Fingerprint: "security:settings:" + pr.Actor,
		Details:     map[string]string{"actor": pr.Actor, "keys": strings.Join(sortedKeys(set), ", ")},
	})
	log.Printf("portal: %s changed settings: %s", portalActor(c), strings.Join(sortedKeys(set), ", "))
	c.JSON(http.StatusOK, p.settingsViewFor(a))
}

// apiSettingsReset removes ?key=… (repeatable) from settings.json, so those
// settings follow flags, environment or defaults again, and applies them.
func (p *portal) apiSettingsReset(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		return
	}
	keys := c.QueryArray("key")
	if len(keys) == 0 {
		jsonError(c, http.StatusBadRequest, "key is required")
		return
	}
	ip, _ := remoteAddr(c.Request)
	pr := portalPrincipal(c)
	if err := a.changeSettings(nil, keys, ip); err != nil {
		a.recordAudit(auditEvent{
			Actor:    pr.Actor,
			Role:     pr.Role.String(),
			Source:   "portal",
			Action:   "settings.reset",
			Outcome:  "error",
			ClientIP: pr.IP.String(),
			Details:  map[string]any{"keys": keys, "error": err.Error()},
		})
		jsonError(c, settingsStatus(err), err.Error())
		return
	}
	a.recordAudit(auditEvent{
		Actor:    pr.Actor,
		Role:     pr.Role.String(),
		Source:   "portal",
		Action:   "settings.reset",
		Outcome:  "allow",
		ClientIP: pr.IP.String(),
		Details:  map[string]any{"keys": keys},
	})
	a.notifyAlert(alertEvent{
		Category:    alertCatSecurity,
		Severity:    alertSevInfo,
		Title:       "Portal settings reset",
		Summary:     fmt.Sprintf("Administrator %s reset settings: %s", pr.Actor, strings.Join(keys, ", ")),
		Fingerprint: "security:settings-reset:" + pr.Actor,
		Details:     map[string]string{"actor": pr.Actor, "keys": strings.Join(keys, ", ")},
	})
	log.Printf("portal: %s reset settings: %s", portalActor(c), strings.Join(keys, ", "))
	c.JSON(http.StatusOK, p.settingsViewFor(a))
}

// ─── the main listener: history, kicks and visitor notes ─────────────────────

// wrap records every request on the main listener in the history (see
// history.go), enforces kicks, and notes the path and browser of each
// visitor who joins the line. It sits outside the main handler, so it also
// sees requests from banned clients, which the access log never does.
func (p *portal) wrap(next http.Handler) http.Handler {
	if p == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g := p.a.current()
		hw := p.history.begin(w, r, g)
		defer hw.finish()
		p.serveMain(hw, r, g, next)
	})
}

// serveMain enforces kicks and notes visitors joining the line. Asset,
// bypass, stream and ops paths are passed straight through: room never
// issues tickets there.
//
// Everything else about the line comes from room itself. The only thing
// read from responses is a room_ticket value different from the one the
// request carried, which is a visitor joining the line; room's refreshes of
// an existing ticket send the same value and are ignored.
func (p *portal) serveMain(w http.ResponseWriter, r *http.Request, g *generation, next http.Handler) {
	reqPath := r.URL.Path
	for _, rule := range g.untracked {
		if rule.matches(reqPath) {
			next.ServeHTTP(w, r)
			return
		}
	}

	now := time.Now()
	var token string
	if ck, err := r.Cookie("room_ticket"); err == nil {
		token = ck.Value
	}
	isStatus := reqPath == "/queue/status"
	if isTicketStatus(reqPath) {
		// A keyed ticket's public place: it reads a place by ID, carries no
		// ticket of the viewer's own, and never issues one.
		next.ServeHTTP(w, r)
		return
	}
	if token != "" && p.kicked.has(token, now) {
		// A banned visitor is answered by the ban check in the main
		// handler, which shows the block notice rather than the removal notice.
		if _, banned := g.abuse.banned(clientIP(r, g.cfg.trusted), now); !banned {
			p.rejectKicked(w, r, isStatus, g.cfg)
			return
		}
	}
	if isStatus {
		next.ServeHTTP(w, r)
		return
	}

	tw := &ticketWriter{ResponseWriter: w}
	next.ServeHTTP(tw, r)
	tw.inspect()
	if tw.issued != "" && tw.issued != token {
		p.notes.add(tw.issued, r.UserAgent(), reqPath)
	}
}

// rejectKicked answers a removed visitor. Status polls get ready=true so the
// waiting room page reloads; the reload gets the removal notice and the
// ticket cookie is cleared, so returning means rejoining at the back.
func (p *portal) rejectKicked(w http.ResponseWriter, r *http.Request, isStatus bool, cfg config) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	if isStatus {
		h.Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ready":true}`))
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "room_ticket", Value: "", Path: cfg.cookiePath, Domain: cfg.cookieDomain,
		MaxAge: -1, Secure: cfg.secureCookie, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	if wantsHTML(r) {
		h.Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(kickedPage))
		return
	}
	h.Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"removed from the queue","removed":true}`))
}

const kickedPage = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Removed from the line</title>
<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem;text-align:center;color:#111;background:#fff}@media(prefers-color-scheme:dark){body{color:#f3f4f6;background:#111827}a{color:#60a5fa}}</style></head>
<body><main role="main"><h1 role="alert">You were removed from the line</h1>
<p>An administrator removed your place in the queue. You can rejoin at the back.</p>
<p><a href="/">Rejoin the line</a></p></main></body></html>`
