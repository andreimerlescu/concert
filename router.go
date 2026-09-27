package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

// buildRouter wires routes in the order that determines what is guarded:
// client identification and ban enforcement first, then ops, bypass, asset
// and stream routes (outside the room), then the priority gate and the API
// interceptor, then room's middleware, then the gated proxy catch-all.
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
	r.Use(g.identify) // before the logger: banned requests are never logged
	if cfg.accessLogEnabled {
		out := cfg.accessLog
		if out == nil {
			out = os.Stdout
		}
		r.Use(gin.LoggerWithConfig(gin.LoggerConfig{
			Output: out,
			Skip:   accessLogSkipper(cfg),
		}))
	}

	// ---- Outside the room. ----
	registerOps(r, g)
	registerConcertRoutes(r, g)
	registerPaths(r, parsePaths(cfg.bypass), g.forward)
	registerPaths(r, parsePaths(cfg.assets), g.assets.private, g.forward)
	registerPaths(r, parsePaths(cfg.assetPublic), g.assets.public, g.forward)
	registerPaths(r, parsePaths(cfg.streamPaths), g.streams.handle, g.forward)

	// ---- Run ahead of room's middleware on gated requests only. ----
	// The priority gate comes first, so its lane requests and refused forms
	// are answered before the API interceptor wraps the writer.
	r.Use(g.priorityGate)
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

// accessLogSkipper keeps asset traffic and pollers out of the access log.
// Assets are the bulk of requests; a log line each would dominate I/O.
func accessLogSkipper(cfg config) func(*gin.Context) bool {
	quiet := append(parsePaths(cfg.assets), parsePaths(cfg.assetPublic)...)
	quiet = append(quiet, pathRule{path: "/queue/status"}, pathRule{path: "/_room/healthz"})
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
	g.forward(c)
}

// forwardTo marks the request as admitted and hands it to the proxy.
func forwardTo(proxy http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(ctxAdmitted, true)
		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

func janitorInterval(d time.Duration) time.Duration {
	if iv := d / 2; iv > 10*time.Second {
		return iv
	}
	return 10 * time.Second
}
