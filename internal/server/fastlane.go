//go:build enterprise

package server

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
		if g.handleChallengeSubroute(c, path) {
			return
		}
		if g.handleBiddingSubroute(c, path) {
			return
		}
		if path == "/email/unsubscribe" {
			g.a.handleEmailUnsubscribe(c)
			return
		}
		file := ""
		switch path {
		case "/", "/access":
			file = "access.html"
		case "/waiting.css":
			file = "waiting.css"
		case "/waiting.js":
			file = "waiting.js"
		case "/busy.js":
			file = "busy.js"
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
			cacheControl := "no-store"
			if strings.HasSuffix(file, ".css") {
				ct = "text/css; charset=utf-8"
			}
			if strings.HasSuffix(file, ".js") {
				ct = "text/javascript; charset=utf-8"
			}
			if file == "busy.js" {
				ct = "application/javascript; charset=utf-8"
				cacheControl = "public, max-age=300"
			}
			c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
			c.Header("Cache-Control", cacheControl)
			c.Header("X-Content-Type-Options", "nosniff")
			c.Header("Referrer-Policy", "no-referrer")
			c.Data(200, ct, b)
			return
		}
		if path == "/config" && c.Request.Method == http.MethodGet {
			conf := map[string]any{"enabled": false}
			if g.a.fastlane != nil {
				conf = g.a.fastlane.PublicConfig()
			}
			conf["legacy_skip_url"] = g.cfg.skipURL
			wrCfg := g.a.waitingRoomConfig()
			if wrCfg.Broadcast.Message != "" {
				conf["broadcast"] = wrCfg.Broadcast
			}
			c.Header("Cache-Control", "no-store")
			c.JSON(200, conf)
			return
		}
		if g.a.fastlane == nil {
			if path == "/config" {
				c.JSON(200, gin.H{"enabled": false})
				return
			}
			c.JSON(404, gin.H{"error": "fast_lane_disabled"})
			return
		}
		req := c.Request.Clone(c.Request.Context())
		req.RemoteAddr = clientIPFrom(c).String() // canonical IP; ignore user headers
		g.a.fastlane.ServeHTTP(c.Writer, req)
	})
}
