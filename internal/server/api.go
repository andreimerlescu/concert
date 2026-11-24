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
// (proxy reached). Upstream responses pass through untouched, including
// streaming, flushing, and connection hijacking for upgrades.
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

	if w.c.GetBool(ctxAdmitted) {
		w.ResponseWriter.WriteHeader(code)
		return
	}

	// room is answering this request itself. Keep its Set-Cookie headers so
	// clients with a cookie jar hold their place, replace everything else.
	w.swallow = true
	status, body := w.translate(code)

	h := w.ResponseWriter.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
		h.Set("Retry-After", strconv.Itoa(w.retryAfter))
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

func (w *apiQueueWriter) translate(code int) (int, []byte) {
	switch code {
	case http.StatusOK:
		// The waiting-room page. The client is queued.
		return http.StatusTooManyRequests, mustJSON(gin.H{
			"queued":              true,
			"status_url":          "/queue/status",
			"retry_after_seconds": w.retryAfter,
			"hint":                "keep the room_ticket cookie and retry to hold your position",
		})
	case http.StatusServiceUnavailable:
		// Breaker tripped or admission timed out.
		if w.a != nil {
			w.a.notifyAlert(alertEvent{
				Category:    alertCatQueue,
				Severity:    alertSevCritical,
				Title:       "Waiting room refused request (503)",
				Summary:     "Waiting room queue-full breaker or admission timeout returned 503 Service Unavailable.",
				Fingerprint: "queue:breaker-503",
			})
		}
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
		"site":                         g.cfg.siteHost,
		"preset":                       g.cfg.preset,
		"config_managed":               g.cfg.configManaged,
		"runtime_override":             a.runtimeCapOverride.Load(),
		"cap":                          wr.Cap(),
		"occupancy":                    wr.Len(),
		"cap_draining":                 wr.Len() > int(wr.Cap()),
		"queue_depth":                  wr.QueueDepth(),
		"live_queue_depth":             wr.LiveQueueDepth(),
		"max_queue_depth":              wr.MaxQueueDepth(),
		"utilization":                  wr.UtilizationSmoothed(),
		"first_poll_grace":             wr.FirstPollGrace().String(),
		"queued_total":                 stats.queued.Load(),
		"evicted_total":                stats.evicted.Load(),
		"timeouts_total":               stats.timeouts.Load(),
		"promoted_total":               stats.promoted.Load(),
		"removed_total":                stats.removed.Load(),
		"token_rejected_total":         stats.tokenRejected.Load(),
		"lease_ceiling":                wr.LeaseCeiling(),
		"asset_cap":                    g.assets.global.Cap(),
		"asset_in_flight":              g.assets.global.Len(),
		"asset_users":                  g.assets.users.count.Load(),
		"asset_served_total":           stats.assetServed.Load(),
		"asset_denied_total":           stats.assetDenied.Load(),
		"asset_user_throttled_total":   stats.assetUserThrottled.Load(),
		"asset_global_throttled_total": stats.assetGlobalThrottled.Load(),
		"static_served_total":          stats.staticServed.Load(),
		"static_not_found_total":       stats.staticNotFound.Load(),
		"fcgi_requests_total":          stats.fcgiRequests.Load(),
		"fcgi_denied_total":            stats.fcgiDenied.Load(),
		"stream_cap":                   g.streams.sem.Cap(),
		"stream_active":                g.streams.sem.Len(),
		"stream_served_total":          stats.streamServed.Load(),
		"stream_denied_total":          stats.streamDenied.Load(),
		"stream_throttled_total":       stats.streamThrottled.Load(),
		"abuse_enabled":                g.abuse != nil,
		"abuse_tracked":                g.abuse.tracked(),
		"abuse_range_bans":             g.abuse.rangeCount(),
		"abuse_strikes_total":          stats.abuseStrikes.Load(),
		"abuse_bans_total":             stats.abuseBans.Load(),
		"abuse_rejected_total":         stats.abuseRejected.Load(),
		"abuse_dropped_total":          stats.abuseDropped.Load(),
		"active_bans":                  len(g.abuse.bans(time.Now())),
		"notes_tracked":                p.notes.count(),
		"notes_dropped":                p.notes.dropped.Load(),
		"kicked_active":                p.kicked.count(),
		"history_clients":              p.history.count.Load(),
		"rate":                         rate,
		"surge":                        surge,
		"skip_url":                     wr.SkipURL(),
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
