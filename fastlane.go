package main

import (
	"embed"
	"net/http"
	"strings"

	"github.com/andreimerlescu/concert/internal/fastlane"
	"github.com/gin-gonic/gin"
)

//go:embed web
var concertWeb embed.FS

// Routes are registered outside room, after abuse checks. Wallet operations
// remain reachable while the ordinary queue is full.
func registerConcertRoutes(r *gin.Engine, g *generation) {
	r.Any("/_concert/*path", func(c *gin.Context) {
		path := strings.TrimPrefix(c.Request.URL.Path, fastlane.Prefix)
		file := ""
		switch path {
		case "/", "/access":
			file = "access.html"
		case "/waiting.css":
			file = "waiting.css"
		case "/waiting.js":
			file = "waiting.js"
		case "/access.js":
			file = "access.js"
		case "/wallet-adapters.js":
			file = "wallet-adapters.js"
		}
		if file != "" {
			if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
				c.Status(405)
				return
			}
			b, e := concertWeb.ReadFile("web/" + file)
			if e != nil {
				c.Status(404)
				return
			}
			ct := "text/html; charset=utf-8"
			if strings.HasSuffix(file, ".css") {
				ct = "text/css; charset=utf-8"
			}
			if strings.HasSuffix(file, ".js") {
				ct = "text/javascript; charset=utf-8"
			}
			c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data: https:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
			c.Header("Cache-Control", "no-store")
			c.Header("X-Content-Type-Options", "nosniff")
			c.Header("Referrer-Policy", "no-referrer")
			c.Data(200, ct, b)
			return
		}
		if path == "/config" && c.Request.Method == http.MethodGet {
			conf := map[string]any{"enabled": false}
			if lane := g.a.lane.Load(); lane != nil {
				conf = lane.PublicConfig()
			}
			conf["legacy_skip_url"] = g.cfg.skipURL
			c.Header("Cache-Control", "no-store")
			c.JSON(200, conf)
			return
		}
		lane := g.a.lane.Load()
		if lane == nil {
			if g.a.laneReloading.Load() {
				c.Header("Retry-After", "5")
				c.JSON(503, gin.H{"error": "fast_lane_reloading"})
				return
			}
			if path == "/config" {
				c.JSON(200, gin.H{"enabled": false})
				return
			}
			c.JSON(404, gin.H{"error": "fast_lane_disabled"})
			return
		}
		req := c.Request.Clone(c.Request.Context())
		req.RemoteAddr = clientIPFrom(c).String() // canonical IP; ignore user headers
		lane.ServeHTTP(c.Writer, req)
	})
}
