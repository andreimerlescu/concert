package server

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/hop"
	"github.com/gin-gonic/gin"
)

// buildRouter wires routes in the order that determines what is guarded:
// client identification and ban enforcement first, then ops, bypass, asset
// and stream routes (outside the room), then the priority gate, the agent
// gate and the API interceptor, then room's middleware, then the gated
// proxy catch-all.
// Route conflicts make gin panic; they are returned as errors instead.
func buildRouter(g *generation) (engine *gin.Engine, err error) {
	defer func() {
		if p := recover(); p != nil {
			engine = nil
			err = fmt.Errorf("route registration: %v", p)
		}
	}()

	cfg := g.cfg
	r := gin.New()

	// A proxy must forward paths exactly as received. Gin's defaults would
	// answer "/foo/" with a 301 to "/foo" instead of passing it upstream.
	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false
	r.HandleMethodNotAllowed = false
	_ = r.SetTrustedProxies(nil) // concert resolves client IPs itself

	r.Use(gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, _ any) {
		// Never dump payment authorizations, wallet sessions or cookies.
		log.Printf("request panic on %s", clip(c.Request.URL.Path, 256))
		c.AbortWithStatus(http.StatusInternalServerError)
	}))
	r.Use(correlateMiddleware)
	r.Use(g.mainSecurityHeaders)
	r.Use(g.identify) // before the logger: banned requests are never logged
	if cfg.accessLogEnabled {
		out := cfg.accessLog
		if out == nil {
			out = os.Stdout
		}
		if strings.EqualFold(strings.TrimSpace(cfg.logFormat), "json") {
			r.Use(jsonAccessLogger(out, cfg))
		} else {
			r.Use(gin.LoggerWithConfig(gin.LoggerConfig{
				Output: out,
				Skip:   accessLogSkipper(cfg),
			}))
		}
	}

	// ---- A leaf's verified hop requests skip everything below. ----
	if g.a.topo.isLeaf() {
		r.Use(g.hopFastPath)
	}

	// ---- Outside the room. ----
	registerOps(r, g)
	registerHopControl(r, g)
	registerConcertRoutes(r, g)
	registerPaths(r, parsePaths(cfg.bypass), g.forwardAs(hop.ClassBypass))
	registerPaths(r, parsePaths(cfg.assets), g.assets.private, g.forwardAs(hop.ClassAsset))
	registerPaths(r, parsePaths(cfg.assetPublic), g.assets.public, g.forwardAs(hop.ClassAsset))
	registerPaths(r, parsePaths(cfg.streamPaths), g.streams.handle, g.forwardAs(hop.ClassStream))

	// ---- Run ahead of room's middleware on gated requests only. ----
	// The priority gate comes first, so its lane requests and refused forms
	// are answered before the API interceptor wraps the writer.
	r.Use(g.priorityGate)
	r.Use(g.agentGate) // keyed places for Concert-Session clients; see agent.go
	if cfg.apiJSON {
		r.Use(apiQueueResponses(cfg.retryAfter))
	}

	// ---- Attaches room's middleware and GET /queue/status. ----
	g.a.room.RegisterRoutes(r)

	// ---- Everything else: gated, then proxied. ----
	// Gin rebuilds the NoRoute chain on every Use(), so this catch-all
	// inherits every middleware above plus room's.
	r.NoRoute(g.gated)

	return r, nil
}

func registerPaths(r *gin.Engine, rules []pathRule, handlers ...gin.HandlerFunc) {
	for _, rule := range rules {
		r.Any(rule.pattern(), handlers...)
	}
}

// statusRules are room's status routes and concert's health check: polled
// every few seconds by every waiting visitor, so they stay out of the access
// log and the history. /queue/status/{id} is a keyed ticket's public place.
var statusRules = []pathRule{
	{path: "/queue/status"},
	{path: "/queue/status", prefix: true},
	{path: "/_room/healthz"},
	{path: "/_room/readyz"},
	{path: "/_room/metrics"},
}

// isTicketStatus reports whether p is room's GET /queue/status/{id}.
func isTicketStatus(p string) bool {
	return strings.HasPrefix(p, "/queue/status/")
}

// accessLogSkipper keeps asset traffic and pollers out of the access log.
// Assets are the bulk of requests; a log line each would dominate I/O.
func accessLogSkipper(cfg config) func(*gin.Context) bool {
	quiet := append(parsePaths(cfg.assets), parsePaths(cfg.assetPublic)...)
	quiet = append(quiet, statusRules...)
	return func(c *gin.Context) bool {
		p := c.Request.URL.Path
		for _, rule := range quiet {
			if rule.matches(p) {
				return true
			}
		}
		return false
	}
}

// gated handles requests room has admitted, and priority-lane requests:
// issue or refresh the admission pass, then proxy. The pass the visitor
// ends up holding travels with the request, so a Concert-Priority grant
// from the origin is bound to it (see priority.go).
func (g *generation) gated(c *gin.Context) {
	id, status := g.a.admit.refresh(c.Writer, c.Request, time.Now())
	if status == passForged {
		g.strike(c, strikeForgedPass)
	}
	if id != (passID{}) {
		c.Request = c.Request.WithContext(withPassID(c.Request.Context(), id))
	}
	g.forwardPage(c)
}

// forwardTo marks the request as admitted and hands it to the proxy.
func forwardTo(proxy http.Handler) gin.HandlerFunc {
	return forwardToPool(proxy, nil)
}

// proxyForward marks the request as admitted, picks its upstream, attaches
// an edge's claim and hands it to the proxy.
func (g *generation) proxyForward(c *gin.Context) {
	c.Set(ctxAdmitted, true)
	req := selectBackendForRequest(c.Request, g.upstreams)
	req = g.edgeClaim(c, req)
	g.proxy.ServeHTTP(c.Writer, req)
}

func forwardToPool(proxy http.Handler, pool *upstreamPool) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(ctxAdmitted, true)
		req := selectBackendForRequest(c.Request, pool)
		proxy.ServeHTTP(c.Writer, req)
	}
}

func janitorInterval(d time.Duration) time.Duration {
	if iv := d / 2; iv > 10*time.Second {
		return iv
	}
	return 10 * time.Second
}
