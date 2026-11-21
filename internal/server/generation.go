package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// identify resolves the client IP, rejects banned clients, and bans clients
// that touch a ban path. Hot path: one map lookup, no logging. The address
// it stores is also room's client key (see newApp).
func (g *generation) identify(c *gin.Context) {
	ip := clientIP(c.Request, g.cfg.trusted)
	c.Set(ctxClientIP, ip)
	if hopIP := g.identifyHop(c, ip); hopIP != ip {
		ip = hopIP
		c.Set(ctxClientIP, ip)
	}
	if g.abuse == nil {
		return
	}

	now := time.Now()
	if left, banned := g.abuse.banned(ip, now); banned {
		g.a.stats.abuseRejected.Add(1)
		g.rejectBanned(c, left)
		return
	}

	if len(g.banRules) == 0 {
		return
	}
	p := c.Request.URL.Path
	for _, rule := range g.banRules {
		if rule.matches(p) {
			if left, banned := g.abuse.banNow(ip, now); banned {
				g.rejectBanned(c, left)
			}
			return
		}
	}
}

// strike records weighted abuse against the request's client.
func (g *generation) strike(c *gin.Context, weight int) {
	if g.abuse == nil {
		return
	}
	g.abuse.strike(clientIPFrom(c), weight, time.Now())
}

func clientIPFrom(c *gin.Context) netip.Addr {
	if v, ok := c.Get(ctxClientIP); ok {
		if ip, ok := v.(netip.Addr); ok {
			return ip
		}
	}
	return netip.Addr{}
}

const blockedPage = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Access blocked</title>
<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem;text-align:center;color:#111;background:#fff}@media(prefers-color-scheme:dark){body{color:#f3f4f6;background:#111827}}</style></head>
<body><main role="main"><h1 role="alert">Access blocked</h1>
<p>%s</p></main></body></html>`

// rejectBanned answers a banned client.
//
// A waiting-room page polling /queue/status is told it is ready, so it
// reloads at once and the reload shows the block notice. The ban itself
// also removes the client's ticket from room's line (see queue.go). The
// room_ticket cookie is cleared, so a client whose ban ends rejoins at the
// back of the line.
//
// Temporary bans answer 429 with Retry-After; permanent bans answer 403.
// Browsers get a short HTML page, everything else JSON.
func (g *generation) rejectBanned(c *gin.Context, left time.Duration) {
	c.Header("Cache-Control", "no-store")
	if c.Request.URL.Path == "/queue/status" {
		c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(`{"ready":true}`))
		c.Abort()
		return
	}
	if _, err := c.Request.Cookie("room_ticket"); err == nil {
		http.SetCookie(c.Writer, &http.Cookie{
			Name: "room_ticket", Value: "", Path: g.cfg.cookiePath, Domain: g.cfg.cookieDomain,
			MaxAge: -1, Secure: g.cfg.secureCookie, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	}

	if left == banForeverLeft {
		if wantsHTML(c.Request) {
			c.Data(http.StatusForbidden, "text/html; charset=utf-8",
				[]byte(fmt.Sprintf(blockedPage, "Requests from your network are blocked.")))
		} else {
			c.Data(http.StatusForbidden, "application/json; charset=utf-8",
				[]byte(`{"error":"blocked","permanent":true}`))
		}
		c.Abort()
		return
	}

	secs := int((left + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	s := strconv.Itoa(secs)
	c.Header("Retry-After", s)
	if wantsHTML(c.Request) {
		wait := (time.Duration(secs) * time.Second).String()
		c.Data(http.StatusTooManyRequests, "text/html; charset=utf-8",
			[]byte(fmt.Sprintf(blockedPage, "Requests from your network are temporarily blocked. Try again in "+wait+".")))
	} else {
		c.Data(http.StatusTooManyRequests, "application/json; charset=utf-8",
			[]byte(`{"error":"temporarily blocked","retry_after_seconds":`+s+`}`))
	}
	c.Abort()
}

// requireRole authenticates a bearer token from CONCERT_ADMIN_TOKEN or
// CONCERT_ADMIN_TOKENS and verifies it has at least required RBAC role.
// Wrong tokens earn strikes and write a denied audit entry.
func (g *generation) requireRole(c *gin.Context, required rbacRole) (principal, bool) {
	if !g.cfg.apiTokens.enabled() {
		c.AbortWithStatus(http.StatusNotFound)
		return principal{}, false
	}
	authz := c.GetHeader("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		g.strike(c, strikeAdminAuth)
		g.a.recordAudit(auditEvent{
			Actor:    "anonymous",
			Source:   "api",
			Action:   c.Request.Method + " " + c.Request.URL.Path,
			Outcome:  "deny",
			ClientIP: clientIPFrom(c).String(),
			Details:  map[string]any{"reason": "missing_bearer_token"},
		})
		c.AbortWithStatus(http.StatusUnauthorized)
		return principal{}, false
	}
	got := strings.TrimPrefix(authz, "Bearer ")
	p, ok := g.cfg.apiTokens.authenticate(got)
	if !ok {
		// Backwards-compatible fallback if config was built directly in tests with adminToken only.
		if g.cfg.adminToken != "" && subtle.ConstantTimeCompare([]byte(got), []byte(g.cfg.adminToken)) == 1 {
			p = principal{Actor: "api:admin-token", Role: roleAdmin, Source: "token"}
			ok = true
		}
	}
	if !ok {
		g.strike(c, strikeAdminAuth)
		g.a.recordAudit(auditEvent{
			Actor:    "anonymous",
			Source:   "api",
			Action:   c.Request.Method + " " + c.Request.URL.Path,
			Outcome:  "deny",
			ClientIP: clientIPFrom(c).String(),
			Details:  map[string]any{"reason": "invalid_token"},
		})
		c.AbortWithStatus(http.StatusUnauthorized)
		return principal{}, false
	}
	p.IP = clientIPFrom(c)
	if !p.Role.allows(required) {
		g.a.recordAudit(auditEvent{
			Actor:    p.Actor,
			Role:     p.Role.String(),
			Source:   "api",
			Action:   c.Request.Method + " " + c.Request.URL.Path,
			Outcome:  "deny",
			ClientIP: p.IP.String(),
			Details:  map[string]any{"reason": "insufficient_role", "required": required.String()},
		})
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient role: requires " + required.String()})
		return principal{}, false
	}
	return p, true
}

func registerOps(r *gin.Engine, g *generation) {
	a, cfg := g.a, g.cfg
	wr, stats, assets, streams := a.room, a.stats, g.assets, g.streams

	r.GET("/_room/healthz", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.String(http.StatusOK, "ok")
	})

	r.GET("/_room/readyz", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		if a.draining.Load() {
			c.String(http.StatusServiceUnavailable, "draining")
			return
		}
		if g.upstreams != nil && len(g.upstreams.backends) > 0 && g.upstreams.healthyCount(time.Now()) == 0 {
			c.String(http.StatusServiceUnavailable, "upstream unhealthy")
			return
		}
		if !a.edgeReady(cfg) {
			c.String(http.StatusServiceUnavailable, "no usable leaf")
			return
		}
		c.String(http.StatusOK, "ok")
	})

	r.GET("/_room/metrics", func(c *gin.Context) {
		if cfg.statsAuth {
			if _, ok := g.requireRole(c, roleViewer); !ok {
				return
			}
		}
		serveMetrics(c, a)
	})

	r.GET("/_room/stats", func(c *gin.Context) {
		var actor principal
		if cfg.statsAuth {
			var ok bool
			actor, ok = g.requireRole(c, roleViewer)
			if !ok {
				return
			}
		}
		c.Header("Cache-Control", "no-store")
		out := gin.H{
			"cap":                          wr.Cap(),
			"occupancy":                    wr.Len(),
			"queue_depth":                  wr.QueueDepth(),
			"live_queue_depth":             wr.LiveQueueDepth(),
			"max_queue_depth":              wr.MaxQueueDepth(),
			"utilization":                  wr.UtilizationSmoothed(),
			"token_ttl":                    wr.TokenTTL().String(),
			"first_poll_grace":             wr.FirstPollGrace().String(),
			"queued_total":                 stats.queued.Load(),
			"evicted_total":                stats.evicted.Load(),
			"timeouts_total":               stats.timeouts.Load(),
			"promoted_total":               stats.promoted.Load(),
			"removed_total":                stats.removed.Load(),
			"asset_cap":                    assets.global.Cap(),
			"asset_in_flight":              assets.global.Len(),
			"asset_users":                  assets.users.count.Load(),
			"asset_user_cap_h1":            cfg.assetUserCapH1,
			"asset_user_cap_h2":            cfg.assetUserCapH2,
			"asset_served_total":           stats.assetServed.Load(),
			"asset_denied_total":           stats.assetDenied.Load(),
			"asset_user_throttled_total":   stats.assetUserThrottled.Load(),
			"asset_global_throttled_total": stats.assetGlobalThrottled.Load(),
			"stream_cap":                   streams.sem.Cap(),
			"stream_active":                streams.sem.Len(),
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
		}
		// Only disclose internal upstream URLs when unauthenticated legacy mode
		// is active or when the caller holds admin role.
		if !cfg.statsAuth || actor.Role.allows(roleAdmin) {
			out["upstream"] = cfg.upstream
		}
		if g.upstreams != nil {
			out["upstream_backends"] = len(g.upstreams.backends)
			out["upstream_healthy"] = g.upstreams.healthyCount(time.Now())
		}
		out["role"] = a.topo.role
		out["node"] = a.topo.node
		switch {
		case a.topo.isEdge():
			out["edge"] = a.edgeView()
		case a.topo.isLeaf():
			out["leaf"] = a.leafView(time.Now())
		}
		c.JSON(http.StatusOK, out)
	})

	// Changes the page cap and saves it to settings.json, like a change made
	// in the portal.
	r.POST("/_room/cap", func(c *gin.Context) {
		actor, ok := g.requireRole(c, roleOperator)
		if !ok {
			return
		}
		var body struct {
			Cap int32 `json:"cap"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		prevCap := wr.Cap()
		raw, _ := json.Marshal(body.Cap)
		if err := a.changeSettings(map[string]json.RawMessage{"cap": raw}, nil, netip.Addr{}); err != nil {
			a.recordAudit(auditEvent{
				Actor:    actor.Actor,
				Role:     actor.Role.String(),
				Source:   "api",
				Action:   "cap.update",
				Outcome:  "error",
				ClientIP: actor.IP.String(),
				Details:  map[string]any{"prev_cap": prevCap, "requested_cap": body.Cap, "error": err.Error()},
			})
			c.JSON(settingsStatus(err), gin.H{"error": err.Error()})
			return
		}
		a.recordAudit(auditEvent{
			Actor:    actor.Actor,
			Role:     actor.Role.String(),
			Source:   "api",
			Action:   "cap.update",
			Outcome:  "allow",
			ClientIP: actor.IP.String(),
			Details:  map[string]any{"prev_cap": prevCap, "new_cap": wr.Cap()},
		})
		c.JSON(http.StatusOK, gin.H{"cap": wr.Cap(), "occupancy": wr.Len()})
	})

	// POST /_room/promote promotes a queued ticket (by raw room_ticket or
	// client IP) to the requested position (default 1), completing the
	// skip-the-line payment webhook integration end-to-end.
	r.POST("/_room/promote", func(c *gin.Context) {
		actor, ok := g.requireRole(c, roleOperator)
		if !ok {
			return
		}
		var body struct {
			Ticket   string `json:"ticket"`
			Client   string `json:"client"`
			Position int64  `json:"position"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if body.Position < 1 {
			body.Position = 1
		}
		token := strings.TrimSpace(body.Ticket)
		if token == "" && strings.TrimSpace(body.Client) != "" {
			for _, t := range wr.Queue(10000) {
				if t.ClientKey == strings.TrimSpace(body.Client) {
					token = t.Token
					break
				}
			}
		}
		if token == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ticket or active queued client is required"})
			return
		}
		if err := wr.AdminPromote(token, body.Position); err != nil {
			a.recordAudit(auditEvent{
				Actor:    actor.Actor,
				Role:     actor.Role.String(),
				Source:   "api",
				Action:   "queue.promote",
				Target:   occupantID(token),
				Outcome:  "error",
				ClientIP: actor.IP.String(),
				Details:  map[string]any{"position": body.Position, "error": err.Error()},
			})
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		a.recordAudit(auditEvent{
			Actor:    actor.Actor,
			Role:     actor.Role.String(),
			Source:   "api",
			Action:   "queue.promote",
			Target:   occupantID(token),
			Outcome:  "allow",
			ClientIP: actor.IP.String(),
			Details:  map[string]any{"position": body.Position},
		})
		c.JSON(http.StatusOK, gin.H{"promoted": occupantID(token), "position": body.Position})
	})

	r.GET("/_room/abuse", func(c *gin.Context) {
		if _, ok := g.requireRole(c, roleViewer); !ok {
			return
		}
		if g.abuse == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "abuse registry disabled"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"tracked": g.abuse.tracked(),
			"ranges":  g.abuse.rangeCount(),
			"bans":    g.abuse.bans(time.Now()),
		})
	})

	// DELETE /_room/abuse?client=203.0.113.9, ?client=2001:db8::/64,
	// or a range such as ?client=203.0.0.0/16
	r.DELETE("/_room/abuse", func(c *gin.Context) {
		actor, ok := g.requireRole(c, roleOperator)
		if !ok {
			return
		}
		if g.abuse == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "abuse registry disabled"})
			return
		}
		t, err := parseBanTarget(c.Query("client"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if !g.abuse.unbanTarget(t) {
			c.JSON(http.StatusNotFound, gin.H{"error": "client not tracked", "client": t.String()})
			return
		}
		a.saveBansNow()
		a.cluster.publishUnban(t)
		a.recordAudit(auditEvent{
			Actor:    actor.Actor,
			Role:     actor.Role.String(),
			Source:   "api",
			Action:   "ban.lift",
			Target:   t.String(),
			Outcome:  "allow",
			ClientIP: actor.IP.String(),
		})
		c.JSON(http.StatusOK, gin.H{"unbanned": t.String()})
	})

	// GDPR / CCPA DSAR endpoints (admin only).
	r.GET("/_room/privacy/export", func(c *gin.Context) {
		actor, ok := g.requireRole(c, roleAdmin)
		if !ok {
			return
		}
		handlePrivacyExport(c, a, actor, "api")
	})

	r.DELETE("/_room/privacy/erase", func(c *gin.Context) {
		actor, ok := g.requireRole(c, roleAdmin)
		if !ok {
			return
		}
		handlePrivacyErase(c, a, actor, "api")
	})
}
