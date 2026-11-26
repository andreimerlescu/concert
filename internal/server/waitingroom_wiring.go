package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/andreimerlescu/concert/internal/drop"
	"github.com/andreimerlescu/concert/internal/i18n"
	"github.com/andreimerlescu/concert/internal/waitingroom"
	"github.com/gin-gonic/gin"
)

const (
	waitingRoomFileName       = "waitingroom.json"
	waitingRoomRenderMaxBytes = 512 << 10
	queueStatusMaxBytes       = 32 << 10
	waitingRoomAPIMaxBytes    = 64 << 10
)

// waitingRoomRuntime manages the active Waiting Room Studio configuration,
// persisted atomically to <data-dir>/waitingroom.json (0600) when -data-dir is
// configured or kept validated in memory when persistence is disabled.
type waitingRoomRuntime struct {
	store *waitingroom.Store

	// mu guards memCfg when store is nil (ephemeral / -data-dir="" mode).
	mu     sync.RWMutex
	memCfg waitingroom.Config
}

// newWaitingRoomRuntime initializes a waitingRoomRuntime backed by
// waitingroom.Store at <dataDir>/waitingroom.json when dataDir != "", or an
// in-memory validated store otherwise.
//
// # Parameters
//
//   - dataDir: Optional persistence directory (-data-dir).
//
// # Returns
//
// A ready *waitingRoomRuntime or a startup error if an existing
// waitingroom.json file is malformed or invalid.
//
// # Example
//
//	wr, err := newWaitingRoomRuntime(cfg.dataDir)
//
// # Used By
//
// Called by newApp in internal/server/app.go.
func newWaitingRoomRuntime(dataDir string) (*waitingRoomRuntime, error) {
	if strings.TrimSpace(dataDir) != "" {
		st, err := waitingroom.NewStore(filepath.Join(dataDir, waitingRoomFileName))
		if err != nil {
			return nil, fmt.Errorf("waitingroom store: %w", err)
		}
		return &waitingRoomRuntime{store: st}, nil
	}
	return &waitingRoomRuntime{memCfg: waitingroom.DefaultConfig()}, nil
}

// Get returns an immutable copy of the active waitingroom.Config.
//
// # Parameters
//
// None.
//
// # Returns
//
// Current validated waitingroom.Config snapshot.
//
// # Example
//
//	cfg := wr.Get()
//
// # Used By
//
// Called by app.waitingRoomConfig in internal/server/waitingroom_wiring.go.
func (w *waitingRoomRuntime) Get() waitingroom.Config {
	if w == nil {
		return waitingroom.DefaultConfig()
	}
	if w.store != nil {
		return w.store.Get()
	}
	w.mu.RLock()
	cfg := w.memCfg
	w.mu.RUnlock()
	return cfg
}

// Save validates and atomically updates the Waiting Room Studio configuration.
//
// # Parameters
//
//   - cfg: Candidate waitingroom.Config to normalize, validate, and persist.
//
// # Returns
//
// nil on success, or a validation/persistence error leaving prior state intact.
//
// # Example
//
//	if err := wr.Save(cfg); err != nil {
//	    return err
//	}
//
// # Used By
//
// Called by portal.apiWaitingRoomPut in internal/server/waitingroom_wiring.go.
func (w *waitingRoomRuntime) Save(cfg waitingroom.Config) error {
	if w.store != nil {
		return w.store.Save(cfg)
	}
	norm, err := cfg.Normalized()
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.memCfg = norm
	w.mu.Unlock()
	return nil
}

// UpdateBroadcast validates and updates the live operator broadcast banner.
//
// # Parameters
//
//   - msg: Plain-text announcement (<= 280 runes), or "" to clear.
//   - now: Update timestamp in UTC.
//
// # Returns
//
// Updated waitingroom.Config snapshot and nil error, or zero Config and error.
//
// # Example
//
//	updated, err := wr.UpdateBroadcast("Doors open shortly!", time.Now().UTC())
//
// # Used By
//
// Called by portal.apiWaitingRoomBroadcast in internal/server/waitingroom_wiring.go.
func (w *waitingRoomRuntime) UpdateBroadcast(msg string, now time.Time) (waitingroom.Config, error) {
	if w.store != nil {
		return w.store.UpdateBroadcast(msg, now)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	next := w.memCfg
	trimmed := strings.TrimSpace(msg)
	next.Broadcast.Message = trimmed
	if trimmed == "" {
		next.Broadcast.UpdatedAt = time.Time{}
	} else {
		if now.IsZero() {
			now = time.Now().UTC()
		}
		next.Broadcast.UpdatedAt = now.UTC()
	}
	norm, err := next.Normalized()
	if err != nil {
		return waitingroom.Config{}, err
	}
	w.memCfg = norm
	return norm, nil
}

// waitingRoomConfig returns the active Waiting Room Studio Config for a.
//
// # Parameters
//
// None.
//
// # Returns
//
// Validated waitingroom.Config snapshot.
//
// # Example
//
//	wrCfg := a.waitingRoomConfig()
//
// # Used By
//
// Called by drop_wiring.go, waitingroom_wiring.go, fastlane.go, and enterprise_stub.go.
func (a *app) waitingRoomConfig() waitingroom.Config {
	if a == nil || a.wr == nil {
		return waitingroom.DefaultConfig()
	}
	return a.wr.Get()
}

// recordAdmission records one waiting-room admission sample in a.eta.
//
// # Parameters
//
//   - now: Admission timestamp (UTC).
//
// # Example
//
//	a.recordAdmission(time.Now().UTC())
//
// # Used By
//
// Called by generation.gated in internal/server/router.go.
func (a *app) recordAdmission(now time.Time) {
	if a != nil && a.eta != nil {
		a.eta.RecordAdmission(now)
	}
}

// etaEstimate computes the live EWMA wait estimate for position at instant now.
//
// # Parameters
//
//   - position: 1-based queue position.
//   - now: Observation instant.
//
// # Returns
//
// An ETAEstimate struct (zeroed low-confidence if estimator is nil).
//
// # Example
//
//	eta := a.etaEstimate(5, time.Now().UTC())
//
// # Used By
//
// Called by drop_wiring.go and waitingroom_wiring.go.
func (a *app) etaEstimate(position int, now time.Time) waitingroom.ETAEstimate {
	if a == nil || a.eta == nil {
		return waitingroom.ETAEstimate{Confidence: waitingroom.ConfidenceLow}
	}
	return a.eta.Estimate(position, now)
}

// waitingRoomStudioMiddleware intercepts built-in waiting-room HTML responses
// emitted by room on gated catch-all traffic, renders them through
// waitingroom.RenderHTML with the visitor's negotiated locale (19 locales,
// including RTL dir="rtl"), live ETA, and operator broadcast, and enforces
// waitingroom.ContentSecurityPolicy (frame-src 'none' except youtube with a
// valid 11-char ID -> frame-src https://www.youtube-nocookie.com).
//
// Admitted upstream responses, API/JSON responses, capacity-breaker 503s, and
// custom operator -html files pass through untouched with zero buffering.
//
// # Parameters
//
//   - c: Active request *gin.Context.
//
// # Example
//
//	r.Use(g.waitingRoomStudioMiddleware)
//
// # Used By
//
// Registered by buildRouter in internal/server/router.go.
func (g *generation) waitingRoomStudioMiddleware(c *gin.Context) {
	if c.FullPath() != "" || !wantsHTML(c.Request) || c.GetString(ctxAgentKey) != "" || g.cfg.htmlFile != "" {
		c.Next()
		return
	}
	w := &waitingRoomStudioWriter{
		ResponseWriter: c.Writer,
		c:              c,
	}
	c.Writer = w
	c.Next()
	c.Writer = w.ResponseWriter

	if !w.decided && w.statusCode != 0 {
		w.ResponseWriter.WriteHeader(w.statusCode)
		return
	}
	if !w.buffered {
		return
	}

	now := time.Now().UTC()
	wrCfg := g.a.waitingRoomConfig()
	locale := negotiateWaitingRoomLocale(c, wrCfg.DefaultLocale, g.cfg.secureCookie)

	pos := 0
	tok := issuedTicket(w.ResponseWriter.Header())
	if tok == "" && c.Request != nil {
		if ck, err := c.Request.Cookie("room_ticket"); err == nil {
			tok = ck.Value
		}
	}
	if tok != "" && g.a != nil && g.a.room != nil {
		if ti, ok := g.a.room.Ticket(tok); ok && ti.Position > 0 {
			pos = int(ti.Position)
		}
	}
	eta := g.a.etaEstimate(pos, now)
	// Pass Position: 0 so room's already-substituted {{.Position}} stays exact
	// while still hydrating the computed ETA, locale, layout, theme, and broadcast.
	rendered, err := waitingroom.RenderHTML(w.buf.Bytes(), wrCfg, locale, waitingroom.RenderOptions{
		Position: 0,
		ETA:      &eta,
	})
	if err != nil {
		rendered = w.buf.Bytes()
	}

	h := w.ResponseWriter.Header()
	h.Del("Content-Length")
	h.Set("Content-Security-Policy", waitingroom.ContentSecurityPolicy(wrCfg))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	w.ResponseWriter.WriteHeader(w.statusCode)
	w.ResponseWriter.WriteHeaderNow()
	_, _ = w.ResponseWriter.Write(rendered)
}

// waitingRoomStudioWriter buffers only built-in waiting-room 200 text/html
// responses written by room; all admitted/proxied or error responses pass
// directly to the underlying ResponseWriter without buffering.
type waitingRoomStudioWriter struct {
	gin.ResponseWriter
	c          *gin.Context
	decided    bool
	buffered   bool
	statusCode int
	buf        bytes.Buffer
}

func (w *waitingRoomStudioWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *waitingRoomStudioWriter) decide() {
	if w.decided {
		return
	}
	w.decided = true
	code := w.statusCode
	if code == 0 {
		code = http.StatusOK
		w.statusCode = code
	}
	if !w.c.GetBool(ctxAdmitted) && !w.c.GetBool(ctxRoomFull) && !w.c.GetBool(ctxSkipWaitingHeaders) &&
		code == http.StatusOK && strings.HasPrefix(w.ResponseWriter.Header().Get("Content-Type"), "text/html") {
		w.buffered = true
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *waitingRoomStudioWriter) WriteHeader(code int) {
	if w.decided {
		if !w.buffered {
			w.ResponseWriter.WriteHeader(code)
		}
		return
	}
	w.statusCode = code
	if code != http.StatusOK {
		w.decide()
	}
}

func (w *waitingRoomStudioWriter) WriteHeaderNow() {
	w.decide()
	if !w.buffered {
		w.ResponseWriter.WriteHeaderNow()
	}
}

func (w *waitingRoomStudioWriter) Write(b []byte) (int, error) {
	w.decide()
	if w.buffered {
		if left := waitingRoomRenderMaxBytes - w.buf.Len(); left > 0 {
			w.buf.Write(b[:min(len(b), left)])
		}
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func (w *waitingRoomStudioWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func (w *waitingRoomStudioWriter) Flush() {
	w.decide()
	if !w.buffered {
		w.ResponseWriter.Flush()
	}
}

// queueStatusEnricherMiddleware wraps GET /queue/status (and /queue/status/:id)
// responses to attach live EWMA ETA fields (eta_seconds, admissions_per_minute,
// eta_confidence), active operator broadcast, and scheduled drop metadata
// (drop_phase, drop_countdown_seconds, drop_sold_out_message) while preserving
// all existing room status fields verbatim.
//
// # Parameters
//
//   - c: Active request *gin.Context.
//
// # Example
//
//	r.Use(g.queueStatusEnricherMiddleware)
//
// # Used By
//
// Registered by buildRouter in internal/server/router.go ahead of
// room.RegisterRoutes.
func (g *generation) queueStatusEnricherMiddleware(c *gin.Context) {
	p := c.Request.URL.Path
	if c.Request.Method != http.MethodGet || (p != "/queue/status" && !isTicketStatus(p)) {
		c.Next()
		return
	}

	now := time.Now().UTC()
	wrCfg := g.a.waitingRoomConfig()

	// If a scheduled drop is active and not yet open, answer /queue/status
	// directly so waiting.js never sees ready=true during idle/lobby/paused/sold_out.
	if snap, hasDrop := g.a.dropSnapshot(now); hasDrop && snap.Phase != drop.PhaseOpen {
		eta := g.a.etaEstimate(0, now)
		out := map[string]any{
			"ready":                  false,
			"position":               0,
			"eta_seconds":            eta.Seconds,
			"admissions_per_minute":  eta.AdmissionsPerMinute,
			"eta_confidence":         eta.Confidence,
			"drop_event_id":          snap.EventID,
			"drop_phase":             string(snap.Phase),
			"drop_countdown_seconds": snap.CountdownSeconds,
			"drop_lobby_count":       snap.LobbyCount,
			"drop_sold_out_message":  snap.SoldOutMessage,
		}
		if wrCfg.Broadcast.Message != "" {
			out["broadcast"] = wrCfg.Broadcast
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, out)
		c.Abort()
		return
	}

	w := &queueStatusCaptureWriter{ResponseWriter: c.Writer}
	c.Writer = w
	c.Next()
	c.Writer = w.ResponseWriter

	if !w.decided && w.statusCode != 0 {
		w.ResponseWriter.WriteHeader(w.statusCode)
		return
	}
	if !w.captured {
		return
	}

	var payload map[string]any
	if err := json.Unmarshal(w.buf.Bytes(), &payload); err != nil || payload == nil {
		// Pass through non-JSON or unexpected status bodies unmodified.
		w.ResponseWriter.Header().Del("Content-Length")
		w.ResponseWriter.WriteHeader(w.statusCode)
		w.ResponseWriter.WriteHeaderNow()
		_, _ = w.ResponseWriter.Write(w.buf.Bytes())
		return
	}

	pos := 0
	if rawPos, ok := payload["position"].(float64); ok && rawPos > 0 {
		pos = int(rawPos)
	}
	eta := g.a.etaEstimate(pos, now)
	payload["eta_seconds"] = eta.Seconds
	payload["admissions_per_minute"] = eta.AdmissionsPerMinute
	payload["eta_confidence"] = eta.Confidence
	if wrCfg.Broadcast.Message != "" {
		payload["broadcast"] = wrCfg.Broadcast
	}
	if snap, hasDrop := g.a.dropSnapshot(now); hasDrop {
		payload["drop_event_id"] = snap.EventID
		payload["drop_phase"] = string(snap.Phase)
		payload["drop_countdown_seconds"] = snap.CountdownSeconds
		payload["drop_sold_out_message"] = snap.SoldOutMessage
	}

	enriched := mustJSON(payload)
	h := w.ResponseWriter.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	w.ResponseWriter.WriteHeader(w.statusCode)
	w.ResponseWriter.WriteHeaderNow()
	_, _ = w.ResponseWriter.Write(enriched)
}

type queueStatusCaptureWriter struct {
	gin.ResponseWriter
	decided    bool
	captured   bool
	statusCode int
	buf        bytes.Buffer
}

func (w *queueStatusCaptureWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *queueStatusCaptureWriter) decide() {
	if w.decided {
		return
	}
	w.decided = true
	code := w.statusCode
	if code == 0 {
		code = http.StatusOK
		w.statusCode = code
	}
	if code == http.StatusOK && strings.HasPrefix(w.ResponseWriter.Header().Get("Content-Type"), "application/json") {
		w.captured = true
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *queueStatusCaptureWriter) WriteHeader(code int) {
	if w.decided {
		if !w.captured {
			w.ResponseWriter.WriteHeader(code)
		}
		return
	}
	w.statusCode = code
	if code != http.StatusOK {
		w.decide()
	}
}

func (w *queueStatusCaptureWriter) WriteHeaderNow() {
	w.decide()
	if !w.captured {
		w.ResponseWriter.WriteHeaderNow()
	}
}

func (w *queueStatusCaptureWriter) Write(b []byte) (int, error) {
	w.decide()
	if w.captured {
		if left := queueStatusMaxBytes - w.buf.Len(); left > 0 {
			w.buf.Write(b[:min(len(b), left)])
		}
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func (w *queueStatusCaptureWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func (w *queueStatusCaptureWriter) Flush() {
	w.decide()
	if !w.captured {
		w.ResponseWriter.Flush()
	}
}

// ─── Admin Portal Endpoints: Waiting Room Studio & Drop ──────────────────────

// apiWaitingRoomGet serves GET /api/waitingroom (roleViewer) returning the
// active Waiting Room Studio config, supported layouts, themes, 19 locales,
// live CSP header preview, and ETA snapshot.
//
// # Parameters
//
//   - c: Request *gin.Context.
//
// # Example
//
//	api.GET("/waitingroom", p.requireRole(roleViewer), p.apiWaitingRoomGet)
//
// # Used By
//
// Registered by portal.routes in internal/server/portal.go.
func (p *portal) apiWaitingRoomGet(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		return
	}
	cfg := a.waitingRoomConfig()
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"config":  cfg,
		"layouts": waitingroom.ValidLayouts(),
		"themes":  waitingroom.ValidThemes(),
		"locales": i18n.SupportedLocales(),
		"csp":     waitingroom.ContentSecurityPolicy(cfg),
		"eta":     a.etaEstimate(1, time.Now().UTC()),
	})
}

type waitingRoomPutReq struct {
	Layout         string `json:"layout"`
	Theme          string `json:"theme"`
	BrandName      string `json:"brand_name"`
	LogoURL        string `json:"logo_url"`
	AccentColor    string `json:"accent_color"`
	Headline       string `json:"headline"`
	Subheadline    string `json:"subheadline"`
	HeroImageURL   string `json:"hero_image_url"`
	YouTubeVideoID string `json:"youtube_video_id"`
	YouTubeURL     string `json:"youtube_url"`
	DefaultLocale  string `json:"default_locale"`
}

// apiWaitingRoomPut serves PUT /api/waitingroom (roleAdmin + CSRF + audit
// "waitingroom.update"), validating and atomically saving Waiting Room Studio
// configuration while preserving any active broadcast message.
//
// # Parameters
//
//   - c: Request *gin.Context.
//
// # Example
//
//	api.PUT("/waitingroom", p.requireRole(roleAdmin), p.apiWaitingRoomPut)
//
// # Used By
//
// Registered by portal.routes in internal/server/portal.go.
func (p *portal) apiWaitingRoomPut(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		return
	}
	pr := portalPrincipal(c)
	if c.Request.Body == nil {
		jsonError(c, http.StatusBadRequest, "request body is required")
		return
	}
	var req waitingRoomPutReq
	if err := json.NewDecoder(io.LimitReader(c.Request.Body, waitingRoomAPIMaxBytes)).Decode(&req); err != nil {
		jsonError(c, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	ytInput := strings.TrimSpace(req.YouTubeVideoID)
	if ytInput == "" && strings.TrimSpace(req.YouTubeURL) != "" {
		ytInput = strings.TrimSpace(req.YouTubeURL)
	}
	cur := a.waitingRoomConfig()
	next := waitingroom.Config{
		Layout:         req.Layout,
		Theme:          req.Theme,
		BrandName:      req.BrandName,
		LogoURL:        req.LogoURL,
		AccentColor:    req.AccentColor,
		Headline:       req.Headline,
		Subheadline:    req.Subheadline,
		HeroImageURL:   req.HeroImageURL,
		YouTubeVideoID: ytInput,
		DefaultLocale:  req.DefaultLocale,
		Broadcast:      cur.Broadcast,
	}

	if err := a.wr.Save(next); err != nil {
		a.recordAudit(auditEvent{
			Actor:    pr.Actor,
			Role:     pr.Role.String(),
			Source:   "portal",
			Action:   "waitingroom.update",
			Outcome:  "error",
			ClientIP: pr.IP.String(),
			Details:  map[string]any{"error": err.Error()},
		})
		jsonError(c, http.StatusBadRequest, err.Error())
		return
	}

	saved := a.waitingRoomConfig()
	a.recordAudit(auditEvent{
		Actor:    pr.Actor,
		Role:     pr.Role.String(),
		Source:   "portal",
		Action:   "waitingroom.update",
		Outcome:  "allow",
		ClientIP: pr.IP.String(),
		Details: map[string]any{
			"layout":           saved.Layout,
			"theme":            saved.Theme,
			"default_locale":   saved.DefaultLocale,
			"youtube_video_id": saved.YouTubeVideoID,
		},
	})
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"config": saved,
		"csp":    waitingroom.ContentSecurityPolicy(saved),
	})
}

// apiWaitingRoomBroadcast serves POST /api/waitingroom/broadcast (roleOperator
// + CSRF + audit "waitingroom.broadcast") to publish or clear a live waiting
// room banner message.
//
// # Parameters
//
//   - c: Request *gin.Context carrying {"message": "..."}.
//
// # Example
//
//	api.POST("/waitingroom/broadcast", p.requireRole(roleOperator), p.apiWaitingRoomBroadcast)
//
// # Used By
//
// Registered by portal.routes in internal/server/portal.go.
func (p *portal) apiWaitingRoomBroadcast(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		return
	}
	pr := portalPrincipal(c)
	if c.Request.Body == nil {
		jsonError(c, http.StatusBadRequest, "request body is required")
		return
	}
	var req struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(io.LimitReader(c.Request.Body, waitingRoomAPIMaxBytes)).Decode(&req); err != nil {
		jsonError(c, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	updated, err := a.wr.UpdateBroadcast(req.Message, time.Now().UTC())
	if err != nil {
		a.recordAudit(auditEvent{
			Actor:    pr.Actor,
			Role:     pr.Role.String(),
			Source:   "portal",
			Action:   "waitingroom.broadcast",
			Outcome:  "error",
			ClientIP: pr.IP.String(),
			Details:  map[string]any{"error": err.Error()},
		})
		jsonError(c, http.StatusBadRequest, err.Error())
		return
	}
	a.recordAudit(auditEvent{
		Actor:    pr.Actor,
		Role:     pr.Role.String(),
		Source:   "portal",
		Action:   "waitingroom.broadcast",
		Outcome:  "allow",
		ClientIP: pr.IP.String(),
		Details:  map[string]any{"cleared": updated.Broadcast.Message == ""},
	})
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"broadcast": updated.Broadcast,
		"config":    updated,
	})
}

// apiDropGet serves GET /api/drop (roleViewer) on the Admin Portal.
//
// # Parameters
//
//   - c: Request *gin.Context.
//
// # Example
//
//	api.GET("/drop", p.requireRole(roleViewer), p.apiDropGet)
//
// # Used By
//
// Registered by portal.routes in internal/server/portal.go.
func (p *portal) apiDropGet(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		return
	}
	handleDropGet(c, a)
}

// apiDropPost serves POST /api/drop (roleOperator + CSRF + audit "drop.update")
// on the Admin Portal.
//
// # Parameters
//
//   - c: Request *gin.Context.
//
// # Example
//
//	api.POST("/drop", p.requireRole(roleOperator), p.apiDropPost)
//
// # Used By
//
// Registered by portal.routes in internal/server/portal.go.
func (p *portal) apiDropPost(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		return
	}
	handleDropUpdate(c, a, portalPrincipal(c), "portal")
}
