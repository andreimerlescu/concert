package main

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
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Access blocked</title></head>
<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem;text-align:center">
<h1>Access blocked</h1>
<p>%s</p></body></html>`

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

// requireAdmin checks the bearer token. Wrong tokens earn strikes.
func (g *generation) requireAdmin(c *gin.Context) bool {
	if g.cfg.adminToken == "" {
		c.AbortWithStatus(http.StatusNotFound)
		return false
	}
	got := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(g.cfg.adminToken)) != 1 {
		g.strike(c, strikeAdminAuth)
		c.AbortWithStatus(http.StatusUnauthorized)
		return false
	}
	return true
}

func registerOps(r *gin.Engine, g *generation) {
	a, cfg := g.a, g.cfg
	wr, stats, assets, streams := a.room, a.stats, g.assets, g.streams

	r.GET("/_room/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	r.GET("/_room/stats", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"upstream":                     cfg.upstream,
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
		})
	})

	// Changes the page cap and saves it to settings.json, like a change made
	// in the portal.
	r.POST("/_room/cap", func(c *gin.Context) {
		if !g.requireAdmin(c) {
			return
		}
		var body struct {
			Cap int32 `json:"cap"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		raw, _ := json.Marshal(body.Cap)
		if err := a.changeSettings(map[string]json.RawMessage{"cap": raw}, nil, netip.Addr{}); err != nil {
			c.JSON(settingsStatus(err), gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"cap": wr.Cap(), "occupancy": wr.Len()})
	})

	r.GET("/_room/abuse", func(c *gin.Context) {
		if !g.requireAdmin(c) {
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
		if !g.requireAdmin(c) {
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
		c.JSON(http.StatusOK, gin.H{"unbanned": t.String()})
	})
}
