package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/drop"
	"github.com/andreimerlescu/concert/internal/i18n"
	"github.com/andreimerlescu/concert/internal/waitingroom"
	"github.com/gin-gonic/gin"
)

const (
	dropTicketCookie = "concert_drop_ticket"
	dropPhaseHeader  = "X-Concert-Drop-Phase"
	dropBodyMaxBytes = 16 << 10
)

// initDrop initializes the site's scheduled drop aggregate from declarative
// Concertfile fields (drop_event_id, drop_lobby_at, drop_open_at) when present
// and hydrates clustered drop state fail-open via dropKVSync if configured.
//
// # Parameters
//
//   - cfg: Normalized site configuration.
//
// # Returns
//
// nil on success or when no drop is configured, or a validation error if
// partial/invalid drop schedule fields were supplied.
//
// # Example
//
//	if err := a.initDrop(cfg); err != nil {
//	    return nil, err
//	}
//
// # Used By
//
// Called by newApp in internal/server/app.go.
func (a *app) initDrop(cfg config) error {
	eventID := strings.TrimSpace(cfg.dropEventID)
	lobbyRaw := strings.TrimSpace(cfg.dropLobbyAt)
	openRaw := strings.TrimSpace(cfg.dropOpenAt)
	if eventID == "" && lobbyRaw == "" && openRaw == "" {
		return nil
	}
	if eventID == "" || lobbyRaw == "" || openRaw == "" {
		return errors.New("drop schedule requires drop_event_id, drop_lobby_at, and drop_open_at")
	}
	lobbyAt, err := time.Parse(time.RFC3339, lobbyRaw)
	if err != nil {
		return fmt.Errorf("invalid drop_lobby_at %q: %w", lobbyRaw, err)
	}
	openAt, err := time.Parse(time.RFC3339, openRaw)
	if err != nil {
		return fmt.Errorf("invalid drop_open_at %q: %w", openRaw, err)
	}

	syncer := a.dropKVSync()
	d, err := drop.New(drop.Config{
		EventID: eventID,
		LobbyAt: lobbyAt.UTC(),
		OpensAt: openAt.UTC(),
		Sync:    syncer,
	})
	if err != nil {
		return fmt.Errorf("drop init: %w", err)
	}
	if syncer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, loadErr := d.LoadState(ctx, syncer)
		cancel()
		if loadErr != nil {
			log.Printf("drop: cluster state hydration failed (continuing with local schedule): %v", loadErr)
		}
	}
	a.dropMu.Lock()
	a.drop = d
	a.dropMu.Unlock()
	return nil
}

// currentDrop returns the active *drop.Drop for a, or nil when no scheduled
// drop is configured. Safe for concurrent use.
//
// # Parameters
//
// None.
//
// # Returns
//
// The active *drop.Drop pointer or nil.
//
// # Example
//
//	if d := a.currentDrop(); d != nil {
//	    snap := d.Snapshot(time.Now().UTC())
//	}
//
// # Used By
//
// Called by dropSnapshot, dropMiddleware, and drop HTTP handlers in
// internal/server/drop_wiring.go.
func (a *app) currentDrop() *drop.Drop {
	if a == nil {
		return nil
	}
	a.dropMu.RLock()
	d := a.drop
	a.dropMu.RUnlock()
	return d
}

// dropSnapshot advances the active scheduled drop to now, persists cluster
// state fail-open on phase transition, and returns an immutable drop.Snapshot.
//
// # Parameters
//
//   - now: Evaluation timestamp; zero defaults to time.Now().UTC().
//
// # Returns
//
// The evaluated drop.Snapshot and true when a drop is configured, or zero
// Snapshot and false otherwise.
//
// # Example
//
//	if snap, ok := a.dropSnapshot(time.Now().UTC()); ok {
//	    fmt.Println(snap.Phase)
//	}
//
// # Used By
//
// Called by dropMiddleware, enrichQueueStatus, and drop HTTP handlers.
func (a *app) dropSnapshot(now time.Time) (drop.Snapshot, bool) {
	d := a.currentDrop()
	if d == nil {
		return drop.Snapshot{}, false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ev, err := d.Advance(now)
	if err == nil && ev.Changed {
		a.saveDropStateFailOpen(d)
	}
	return d.Snapshot(now), true
}

// saveDropStateFailOpen replicates d's state to concert-kv when configured,
// logging errors without blocking or failing caller operations.
//
// # Parameters
//
//   - d: Non-nil *drop.Drop to persist.
//
// # Example
//
//	a.saveDropStateFailOpen(d)
//
// # Used By
//
// Called by dropSnapshot and handleDropUpdate in internal/server/drop_wiring.go.
func (a *app) saveDropStateFailOpen(d *drop.Drop) {
	syncer := a.dropKVSync()
	if syncer == nil || d == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := d.SaveState(ctx, syncer, 0); err != nil {
		log.Printf("drop: cluster state save failed (fail-open): %v", err)
	}
}

// dropMiddleware integrates the active Scheduled Drop lifecycle into gated
// traffic ahead of the waiting room.
//
//   - PhaseSoldOut: short-circuits with HTTP 410 Gone (HTML or JSON) carrying
//     drop_phase="sold_out" and drop_sold_out_message.
//   - PhaseIdle / PhaseLobby / PhaseShuffling / PhasePaused: holds arrivals out
//     of the origin (registering unique lobby tickets during PhaseLobby) and
//     answers browsers with the Waiting Room Studio page or API clients with
//     HTTP 429 JSON containing drop_phase and drop_countdown_seconds.
//   - PhaseOpen: registers post-open arrivals into the drop's FIFO order and
//     hands off to the waiting room / upstream admission path.
//
// # Parameters
//
//   - c: Active request *gin.Context.
//
// # Example
//
//	r.Use(g.dropMiddleware)
//
// # Used By
//
// Registered by buildRouter in internal/server/router.go.
func (g *generation) dropMiddleware(c *gin.Context) {
	if c.FullPath() != "" || c.GetBool(ctxAdmitted) || isGuardExemptPath(c.Request.URL.Path) {
		c.Next()
		return
	}
	d := g.a.currentDrop()
	if d == nil {
		c.Next()
		return
	}

	now := time.Now().UTC()
	snap, _ := g.a.dropSnapshot(now)

	switch snap.Phase {
	case drop.PhaseOpen:
		// Record post-open FIFO ordering if the visitor carries a drop/room ticket.
		if tid := existingDropTicketID(c.Request); tid != "" {
			_, _ = d.EnqueuePostOpen(tid, now)
		}
		c.Next()
		return

	case drop.PhaseSoldOut:
		c.Set(ctxSkipWaitingHeaders, true)
		c.Header("Cache-Control", "no-store")
		c.Header(dropPhaseHeader, string(snap.Phase))
		msg := snap.SoldOutMessage
		if msg == "" {
			msg = "This event is sold out."
		}
		if wantsHTML(c.Request) {
			wrCfg := g.a.waitingRoomConfig()
			c.Header("Content-Security-Policy", waitingroom.ContentSecurityPolicy(wrCfg))
			c.Header("X-Content-Type-Options", "nosniff")
			c.Header("Referrer-Policy", "no-referrer")
			c.Header("X-Frame-Options", "DENY")
			page := renderDropSoldOutHTML(snap.EventID, msg)
			c.Data(http.StatusGone, "text/html; charset=utf-8", []byte(page))
		} else {
			c.Data(http.StatusGone, "application/json; charset=utf-8", mustJSON(gin.H{
				"queued":                 false,
				"sold_out":               true,
				"drop_event_id":          snap.EventID,
				"drop_phase":             string(snap.Phase),
				"drop_countdown_seconds": 0,
				"drop_sold_out_message":  msg,
			}))
		}
		c.Abort()
		return

	default:
		// PhaseIdle, PhaseLobby, PhaseShuffling, PhasePaused.
		ticketID := ensureDropTicketCookie(c, g.cfg)
		if snap.Phase == drop.PhaseLobby {
			if _, err := d.JoinLobby(ticketID, now); err == nil {
				snap = d.Snapshot(now)
			}
		}

		secs := max(g.cfg.retryAfter, 1)
		c.Set(ctxSkipWaitingHeaders, true)
		c.Header("Cache-Control", "no-store")
		c.Header("Retry-After", strconv.Itoa(secs))
		c.Header(dropPhaseHeader, string(snap.Phase))

		if wantsHTML(c.Request) {
			wrCfg := g.a.waitingRoomConfig()
			if wrCfg.Layout == waitingroom.LayoutDefault {
				wrCfg.Layout = waitingroom.LayoutDropCountdown
			}
			locale := negotiateWaitingRoomLocale(c, wrCfg.DefaultLocale, g.cfg.secureCookie)
			eta := g.a.etaEstimate(0, now)
			base := g.html
			if len(base) == 0 {
				base, _ = waitingWeb.ReadFile("web/waiting.html")
			}
			rendered, err := waitingroom.RenderHTML(base, wrCfg, locale, waitingroom.RenderOptions{
				Position: 0,
				ETA:      &eta,
			})
			if err != nil {
				rendered = base
			}
			c.Header("Content-Security-Policy", waitingroom.ContentSecurityPolicy(wrCfg))
			c.Header("X-Content-Type-Options", "nosniff")
			c.Header("Referrer-Policy", "no-referrer")
			c.Header("X-Frame-Options", "DENY")
			c.Data(http.StatusOK, "text/html; charset=utf-8", rendered)
		} else {
			c.Data(http.StatusTooManyRequests, "application/json; charset=utf-8", mustJSON(gin.H{
				"queued":                 true,
				"drop_event_id":          snap.EventID,
				"drop_phase":             string(snap.Phase),
				"drop_countdown_seconds": snap.CountdownSeconds,
				"drop_lobby_count":       snap.LobbyCount,
				"drop_sold_out_message":  snap.SoldOutMessage,
				"status_url":             defaultQueueStatusURL,
				"retry_after_seconds":    secs,
			}))
		}
		c.Abort()
	}
}

// renderDropSoldOutHTML renders a strict, HTML-escaped 410 Gone page for a
// sold-out scheduled drop without inline scripts or styles.
//
// # Parameters
//
//   - eventID: Drop event identifier.
//   - msg: Operator-supplied sold-out message.
//
// # Returns
//
// Safe HTML document string.
//
// # Example
//
//	doc := renderDropSoldOutHTML("drop-2026", "All tickets claimed.")
//
// # Used By
//
// Called by generation.dropMiddleware in internal/server/drop_wiring.go.
func renderDropSoldOutHTML(eventID, msg string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sold Out</title><link rel="stylesheet" href="/_concert/waiting.css"></head><body class="queue-page"><main id="main" class="queue-layout"><section class="queue-panel"><div class="ticket"><div class="ticket-top"><span class="eyebrow">` +
		html.EscapeString(eventID) +
		`</span><span class="tiny-tag">SOLD OUT</span></div><h1>Sold out</h1><p id="drop-sold-out-message">` +
		html.EscapeString(msg) +
		`</p></div></section></main></body></html>`
}

// existingDropTicketID returns the visitor's existing drop or room ticket ID
// from cookies, or "" if none is present.
//
// # Parameters
//
//   - r: Incoming *http.Request.
//
// # Returns
//
// Existing ticket string or "".
//
// # Example
//
//	tid := existingDropTicketID(c.Request)
//
// # Used By
//
// Called by generation.dropMiddleware and ensureDropTicketCookie in
// internal/server/drop_wiring.go.
func existingDropTicketID(r *http.Request) string {
	if r == nil {
		return ""
	}
	if ck, err := r.Cookie(dropTicketCookie); err == nil && ck.Value != "" {
		return ck.Value
	}
	if ck, err := r.Cookie("room_ticket"); err == nil && ck.Value != "" {
		return ck.Value
	}
	return ""
}

// ensureDropTicketCookie returns an existing lobby ticket cookie or mints a
// new CSPRNG 16-byte hex ticket cookie on c.Writer.
//
// # Parameters
//
//   - c: Active *gin.Context.
//   - cfg: Generation config controlling cookie Path, Domain, and Secure flags.
//
// # Returns
//
// Stable non-empty lobby ticket identifier for the visitor.
//
// # Example
//
//	tid := ensureDropTicketCookie(c, g.cfg)
//
// # Used By
//
// Called by generation.dropMiddleware in internal/server/drop_wiring.go.
func ensureDropTicketCookie(c *gin.Context, cfg config) string {
	if existing := existingDropTicketID(c.Request); existing != "" {
		return existing
	}
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	tid := "drop-" + hex.EncodeToString(raw[:])
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     dropTicketCookie,
		Value:    tid,
		Path:     cfg.cookiePath,
		Domain:   cfg.cookieDomain,
		MaxAge:   86400,
		Secure:   cfg.secureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return tid
}

// dropPayload builds the JSON response representation of the app's current
// drop state.
//
// # Parameters
//
//   - a: Owning *app.
//   - now: Evaluation timestamp.
//
// # Returns
//
// A gin.H JSON object suitable for /_room/drop and /api/drop responses.
//
// # Example
//
//	c.JSON(http.StatusOK, dropPayload(a, time.Now().UTC()))
//
// # Used By
//
// Called by handleDropGet and handleDropUpdate in internal/server/drop_wiring.go.
func dropPayload(a *app, now time.Time) gin.H {
	snap, ok := a.dropSnapshot(now)
	if !ok {
		return gin.H{
			"configured":             false,
			"phase":                  "none",
			"drop_phase":             "none",
			"countdown_seconds":      int64(0),
			"drop_countdown_seconds": int64(0),
		}
	}
	return gin.H{
		"configured":             true,
		"event_id":               snap.EventID,
		"phase":                  string(snap.Phase),
		"drop_phase":             string(snap.Phase),
		"paused_from":            string(snap.PausedFrom),
		"pause_reason":           snap.PauseReason,
		"lobby_at":               snap.LobbyAt.UTC().Format(time.RFC3339),
		"opens_at":               snap.OpensAt.UTC().Format(time.RFC3339),
		"countdown_seconds":      snap.CountdownSeconds,
		"drop_countdown_seconds": snap.CountdownSeconds,
		"lobby_count":            snap.LobbyCount,
		"shuffled_count":         snap.ShuffledCount,
		"post_open_count":        snap.PostOpenCount,
		"total_queue_count":      snap.TotalQueueCount,
		"max_lobby_tickets":      snap.MaxLobbyTickets,
		"sold_out_message":       snap.SoldOutMessage,
		"drop_sold_out_message":  snap.SoldOutMessage,
		"audit_seq":              snap.AuditSeq,
	}
}

// handleDropGet responds with the current scheduled drop state for GET
// /_room/drop and GET /api/drop.
//
// # Parameters
//
//   - c: Request *gin.Context.
//   - a: Target *app.
//
// # Example
//
//	handleDropGet(c, a)
//
// # Used By
//
// Called by registerOps in internal/server/generation.go and portal.routes in
// internal/server/portal.go.
func handleDropGet(c *gin.Context, a *app) {
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, dropPayload(a, time.Now().UTC()))
}

type dropControlReq struct {
	Action             string `json:"action"`
	EventID            string `json:"event_id"`
	LobbyAt            string `json:"lobby_at"`
	OpensAt            string `json:"opens_at"`
	OpenAt             string `json:"open_at"`
	MaxLobbyTickets    int    `json:"max_lobby_tickets"`
	MaxPostOpenTickets int    `json:"max_post_open_tickets"`
	Reason             string `json:"reason"`
	Message            string `json:"message"`
	SoldOutMessage     string `json:"sold_out_message"`
}

// handleDropUpdate processes operator lifecycle mutations ("schedule", "pause",
// "resume", "sold_out", "reset") for POST /_room/drop and POST /api/drop,
// persisting cluster sync state fail-open and writing an audit "drop.update"
// record on every attempt.
//
// # Parameters
//
//   - c: Request *gin.Context carrying the bounded JSON body.
//   - a: Target *app.
//   - actor: Authenticated operator/admin principal.
//   - source: Origin of the call ("api" or "portal").
//
// # Example
//
//	handleDropUpdate(c, a, actor, "api")
//
// # Used By
//
// Called by registerOps in internal/server/generation.go and portal.routes in
// internal/server/portal.go.
func handleDropUpdate(c *gin.Context, a *app, actor principal, source string) {
	c.Header("Cache-Control", "no-store")
	if c.Request.Body == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "request body is required"})
		return
	}
	var req dropControlReq
	if err := json.NewDecoder(io.LimitReader(c.Request.Body, dropBodyMaxBytes)).Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body: " + err.Error()})
		return
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	now := time.Now().UTC()

	audit := func(outcome string, details map[string]any) {
		if details == nil {
			details = map[string]any{}
		}
		details["action"] = action
		if site := a.current().cfg.siteHost; site != "" {
			details["site"] = site
		}
		a.recordAudit(auditEvent{
			Actor:    actor.Actor,
			Role:     actor.Role.String(),
			Source:   source,
			Action:   "drop.update",
			Target:   strings.TrimSpace(req.EventID),
			Outcome:  outcome,
			ClientIP: clientIPString(c),
			Details:  details,
		})
	}

	buildCfg := func() (drop.Config, error) {
		openRaw := strings.TrimSpace(req.OpensAt)
		if openRaw == "" {
			openRaw = strings.TrimSpace(req.OpenAt)
		}
		lobbyAt, err := time.Parse(time.RFC3339, strings.TrimSpace(req.LobbyAt))
		if err != nil {
			return drop.Config{}, fmt.Errorf("invalid lobby_at (RFC3339 required): %w", err)
		}
		opensAt, err := time.Parse(time.RFC3339, openRaw)
		if err != nil {
			return drop.Config{}, fmt.Errorf("invalid opens_at (RFC3339 required): %w", err)
		}
		return drop.Config{
			EventID:            strings.TrimSpace(req.EventID),
			LobbyAt:            lobbyAt.UTC(),
			OpensAt:            opensAt.UTC(),
			MaxLobbyTickets:    req.MaxLobbyTickets,
			MaxPostOpenTickets: req.MaxPostOpenTickets,
			SoldOutMessage:     strings.TrimSpace(req.SoldOutMessage),
			Sync:               a.dropKVSync(),
		}, nil
	}

	switch action {
	case "schedule":
		dcfg, err := buildCfg()
		if err != nil {
			audit("error", map[string]any{"error": err.Error()})
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		d, err := drop.New(dcfg)
		if err != nil {
			audit("error", map[string]any{"error": err.Error()})
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		_, _ = d.Advance(now)
		a.dropMu.Lock()
		a.drop = d
		a.dropMu.Unlock()
		a.saveDropStateFailOpen(d)
		audit("allow", map[string]any{"event_id": dcfg.EventID, "phase": string(d.Snapshot(now).Phase)})
		c.JSON(http.StatusOK, dropPayload(a, now))

	case "pause":
		d := a.currentDrop()
		if d == nil {
			audit("error", map[string]any{"error": "no drop configured"})
			c.JSON(http.StatusNotFound, gin.H{"error": "no scheduled drop configured"})
			return
		}
		_, _ = d.Advance(now)
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = strings.TrimSpace(req.Message)
		}
		if err := d.Pause(reason, now); err != nil {
			audit("error", map[string]any{"error": err.Error()})
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		a.saveDropStateFailOpen(d)
		audit("allow", map[string]any{"reason": reason})
		c.JSON(http.StatusOK, dropPayload(a, now))

	case "resume":
		d := a.currentDrop()
		if d == nil {
			audit("error", map[string]any{"error": "no drop configured"})
			c.JSON(http.StatusNotFound, gin.H{"error": "no scheduled drop configured"})
			return
		}
		if err := d.Resume(now); err != nil {
			audit("error", map[string]any{"error": err.Error()})
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		a.saveDropStateFailOpen(d)
		audit("allow", map[string]any{"phase": string(d.Snapshot(now).Phase)})
		c.JSON(http.StatusOK, dropPayload(a, now))

	case "sold_out":
		d := a.currentDrop()
		if d == nil {
			audit("error", map[string]any{"error": "no drop configured"})
			c.JSON(http.StatusNotFound, gin.H{"error": "no scheduled drop configured"})
			return
		}
		msg := strings.TrimSpace(req.SoldOutMessage)
		if msg == "" {
			msg = strings.TrimSpace(req.Message)
		}
		if err := d.MarkSoldOut(msg, now); err != nil {
			audit("error", map[string]any{"error": err.Error()})
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		a.saveDropStateFailOpen(d)
		audit("allow", map[string]any{"sold_out_message": msg})
		c.JSON(http.StatusOK, dropPayload(a, now))

	case "reset":
		if strings.TrimSpace(req.EventID) == "" && strings.TrimSpace(req.LobbyAt) == "" && strings.TrimSpace(req.OpensAt) == "" && strings.TrimSpace(req.OpenAt) == "" {
			a.dropMu.Lock()
			a.drop = nil
			a.dropMu.Unlock()
			audit("allow", map[string]any{"cleared": true})
			c.JSON(http.StatusOK, dropPayload(a, now))
			return
		}
		dcfg, err := buildCfg()
		if err != nil {
			audit("error", map[string]any{"error": err.Error()})
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		d := a.currentDrop()
		if d != nil {
			if err := d.Reset(dcfg, now); err != nil {
				audit("error", map[string]any{"error": err.Error()})
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
		} else {
			var cerr error
			d, cerr = drop.New(dcfg)
			if cerr != nil {
				audit("error", map[string]any{"error": cerr.Error()})
				c.JSON(http.StatusBadRequest, gin.H{"error": cerr.Error()})
				return
			}
			a.dropMu.Lock()
			a.drop = d
			a.dropMu.Unlock()
		}
		_, _ = d.Advance(now)
		a.saveDropStateFailOpen(d)
		audit("allow", map[string]any{"event_id": dcfg.EventID, "phase": string(d.Snapshot(now).Phase)})
		c.JSON(http.StatusOK, dropPayload(a, now))

	default:
		audit("error", map[string]any{"error": "unsupported drop action"})
		c.JSON(http.StatusBadRequest, gin.H{"error": `action must be "schedule", "pause", "resume", "sold_out", or "reset"`})
	}
}

// negotiateWaitingRoomLocale resolves the visitor's preferred locale from
// ?lang=, concert_lang cookie, Accept-Language header, and defaultLocale. When
// ?lang= selects a supported locale, it persists concert_lang for future visits.
//
// # Parameters
//
//   - c: Request *gin.Context.
//   - defaultLocale: Configured default locale fallback.
//   - secureCookie: Whether to set the Secure attribute on concert_lang.
//
// # Returns
//
// Validated BCP-47 locale tag supported by internal/i18n.
//
// # Example
//
//	loc := negotiateWaitingRoomLocale(c, wrCfg.DefaultLocale, g.cfg.secureCookie)
//
// # Used By
//
// Called by generation.dropMiddleware in internal/server/drop_wiring.go and
// generation.waitingRoomStudioMiddleware in internal/server/waitingroom_wiring.go.
func negotiateWaitingRoomLocale(c *gin.Context, defaultLocale string, secureCookie bool) string {
	queryLang := strings.TrimSpace(c.Query("lang"))
	cookieLang := ""
	if ck, err := c.Request.Cookie("concert_lang"); err == nil {
		cookieLang = ck.Value
	}
	acceptLang := c.GetHeader("Accept-Language")
	resolved := i18n.Negotiate(queryLang, cookieLang, acceptLang, defaultLocale)
	if queryLang != "" && i18n.IsSupported(resolved) && resolved != cookieLang {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "concert_lang",
			Value:    resolved,
			Path:     "/",
			MaxAge:   31536000,
			Secure:   secureCookie,
			SameSite: http.SameSiteLaxMode,
		})
	}
	return resolved
}
