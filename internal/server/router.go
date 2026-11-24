package server

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/static"
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
	registerPaths(r, parsePaths(cfg.bypass), g.serveStaticOrForward(false, classBypass))
	registerPaths(r, parsePaths(cfg.assets), g.assets.private, g.serveStaticOrForward(true, classAsset))
	registerPaths(r, parsePaths(cfg.assetPublic), g.assets.public, g.serveStaticOrForward(true, classAsset))
	registerPaths(r, parsePaths(cfg.streamPaths), g.streams.handle, g.forwardAs(classStream))

	// ---- Offload remaining mounted/root static files before the waiting room. ----
	if g.static != nil {
		r.Use(g.staticOffload)
	}

	// ---- Serve eligible anonymous GET/HEAD pages from the bounded micro-cache. ----
	if g.microCache != nil {
		r.Use(g.microCacheMiddleware)
	}

	// ---- Run ahead of room's middleware on gated requests only. ----
	// The priority gate comes first, so its lane requests and refused forms
	// are answered before the API interceptor wraps the writer.
	r.Use(g.priorityGate)
	r.Use(g.agentGate) // keyed places for Concert-Session clients; see agent.go
	if cfg.apiJSON {
		r.Use(apiQueueResponses(g.a, cfg.retryAfter))
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

// tryStatic attempts to serve c directly from local static roots/mounts.
// Returns true when the response was written or aborted (200/206/304/404) so
// the caller must not forward upstream.
func (g *generation) tryStatic(c *gin.Context, authoritative bool) bool {
	if g.static == nil {
		return false
	}
	switch g.static.Serve(c.Writer, c.Request, authoritative) {
	case static.ResultServed:
		g.a.stats.staticServed.Add(1)
		c.Set(ctxAdmitted, true)
		return true
	case static.ResultNotFound:
		g.a.stats.staticNotFound.Add(1)
		c.AbortWithStatus(http.StatusNotFound)
		return true
	case static.ResultForbidden:
		c.AbortWithStatus(http.StatusNotFound)
		return true
	default:
		return false
	}
}

func (g *generation) serveStaticOrForward(authoritative bool, class trafficClass) gin.HandlerFunc {
	fwd := g.forwardAs(class)
	return func(c *gin.Context) {
		if g.tryStatic(c, authoritative) {
			return
		}
		fwd(c)
	}
}

// staticOffload serves requests targeting explicit -static-mounts prefixes or
// existing safe static files inside -static-root (plus blocked dotfiles) under
// Concert's global asset cap, before they can consume a waiting-room slot or
// wake up the upstream / php-fpm.
func (g *generation) staticOffload(c *gin.Context) {
	if g.static == nil {
		return
	}
	p := c.Request.URL.Path
	if strings.HasPrefix(p, "/_room") || strings.HasPrefix(p, "/_concert") || p == "/queue/status" || isTicketStatus(p) {
		return
	}
	inMount := g.static.MatchMount(p)
	if !inMount && !g.static.HasRootStaticFile(c.Request) {
		return
	}
	prio := g.assets.priorityForRequest(c.Request, time.Now())
	if !acquirePriority(c.Request.Context(), g.assets.global, prio, g.cfg.assetWait) {
		g.a.stats.assetGlobalThrottled.Add(1)
		c.Header("Retry-After", "1")
		c.AbortWithStatus(http.StatusServiceUnavailable)
		return
	}
	handled := g.tryStatic(c, inMount)
	_ = g.assets.global.Release()
	if handled {
		g.a.stats.assetServed.Add(1)
		c.Abort()
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

// proxyForward marks the request as admitted, picks its upstream, attaches
// the resolved client IP, body read deadlines (for non-stream requests), and
// an edge's claim, and hands it to the proxy.
func (g *generation) proxyForward(c *gin.Context) {
	c.Set(ctxAdmitted, true)
	req := selectBackendForRequest(c.Request, g.upstreams)
	req = g.edgeClaim(c, req)
	if hopIP, ok := hopInClientIP(req.Context()); ok {
		req = withFastCGIClientIP(req, hopIP.String())
	} else if ip := clientIPFrom(c); ip.IsValid() {
		req = withFastCGIClientIP(req, ip.String())
	}
	if !c.GetBool(ctxIsStream) && req.Body != nil && req.Body != http.NoBody && req.ContentLength != 0 {
		db := newDeadlineBody(c.Writer, req.Body, g.cfg.bodyReadIdleTimeout, g.cfg.maxUploadTime)
		defer db.Finish()
		r2 := req.Clone(req.Context())
		r2.Body = db
		req = withFastCGIBodyAbort(r2, db.Abort)
	}
	g.proxy.ServeHTTP(c.Writer, req)
}

func janitorInterval(d time.Duration) time.Duration {
	if iv := d / 2; iv > 10*time.Second {
		return iv
	}
	return 10 * time.Second
}
