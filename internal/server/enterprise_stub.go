//go:build !enterprise

package server

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/andreimerlescu/room"
	"github.com/gin-gonic/gin"
)

func hasEnterpriseEdition() bool { return false }

type emailRateLimiter struct{}

func newEmailRateLimiter(int, time.Duration) *emailRateLimiter { return nil }

func hopInClientIP(context.Context) (netip.Addr, bool) { return netip.Addr{}, false }

// enterpriseAppState is empty in non-enterprise builds (concert, wpconcert).
type enterpriseAppState struct {
	topo *topology
}

// topology is a zero-overhead standalone stub in concert and wpconcert.
type topology struct{}

func (t *topology) isEdge() bool                          { return false }
func (t *topology) isLeaf() bool                          { return false }
func (t *topology) kickEdge()                             {}
func (t *topology) signHop(r *http.Request) *http.Request { return r }
func (t *topology) recordEdgeBackpressure()               {}
func (t *topology) recordEdgeRetry()                      {}

// Single-token API authentication in concert / wpconcert.
type apiTokenStore struct {
	tokens []string
}

func loadAPITokens(adminToken, adminTokensSpec string) (*apiTokenStore, error) {
	if strings.TrimSpace(adminTokensSpec) != "" {
		return nil, fmt.Errorf("CONCERT_ADMIN_TOKENS (scoped RBAC tokens) is provided by econcert; use CONCERT_ADMIN_TOKEN or build econcert")
	}
	s := &apiTokenStore{}
	if adminToken != "" {
		s.tokens = []string{adminToken}
	}
	return s, nil
}

func (s *apiTokenStore) enabled() bool { return s != nil && len(s.tokens) > 0 }

func (s *apiTokenStore) authenticate(got string) (principal, bool) {
	if s == nil {
		return principal{}, false
	}
	for _, tok := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(got), []byte(tok)) == 1 {
			return principal{Actor: "api:admin-token", Role: roleAdmin, Source: "token"}, true
		}
	}
	return principal{}, false
}

// userDirectory stub for non-enterprise builds (single-password portal only).
type portalUser struct {
	username string
	role     rbacRole
}

type userDirectory struct{}

func loadPortalUsers(spec string) (*userDirectory, error) {
	if strings.TrimSpace(spec) != "" {
		return nil, fmt.Errorf("CONCERT_PORTAL_USERS (multi-user RBAC) is provided by econcert; use CONCERT_PORTAL_PASS or build econcert")
	}
	return nil, nil
}

func (u *userDirectory) count() int { return 0 }

func (u *userDirectory) authenticate(string, string, string, time.Time) (*portalUser, bool) {
	return nil, false
}

func resolveSSOPrincipal(*http.Request, portalConfig, netip.Addr) (principal, bool) {
	return principal{}, false
}

// ─── generation & router stubs ───────────────────────────────────────────────

func (g *generation) identifyHop(c *gin.Context, ip netip.Addr) netip.Addr {
	// Always strip smuggled Concert-Hop headers even in standalone editions.
	c.Request.Header.Del(hopHeaderName)
	return ip
}

func (g *generation) hopFastPath(c *gin.Context) { c.Next() }

func (g *generation) forwardAs(trafficClass) gin.HandlerFunc {
	return g.proxyForward
}

func (g *generation) edgeClaim(_ *gin.Context, req *http.Request) *http.Request {
	return req
}

func (g *generation) wrapForwardPage(fn gin.HandlerFunc) gin.HandlerFunc {
	return fn
}

func (a *app) tierResponse(next func(*http.Response) error) func(*http.Response) error {
	return func(resp *http.Response) error {
		stripTierHeaders(resp.Header)
		return next(resp)
	}
}

func registerHopControl(*gin.Engine, *generation) {}

// registerConcertRoutes serves only the waiting room's static CSS/JS and a
// disabled /_concert/config payload in non-enterprise builds (no wallet JS or
// x402 payment routes).
func registerConcertRoutes(r *gin.Engine, g *generation) {
	r.Any("/_concert/*path", func(c *gin.Context) {
		p := strings.TrimPrefix(c.Request.URL.Path, "/_concert")
		if p == "/config" && c.Request.Method == http.MethodGet {
			c.Header("Cache-Control", "no-store")
			c.JSON(http.StatusOK, gin.H{
				"enabled":         false,
				"legacy_skip_url": g.cfg.skipURL,
			})
			return
		}
		var file, ct string
		switch p {
		case "/waiting.css":
			file, ct = "web/waiting.css", "text/css; charset=utf-8"
		case "/waiting.js":
			file, ct = "web/waiting.js", "text/javascript; charset=utf-8"
		default:
			c.JSON(http.StatusNotFound, gin.H{"error": "fast_lane_disabled"})
			return
		}
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Status(http.StatusMethodNotAllowed)
			return
		}
		b, err := waitingWeb.ReadFile(file)
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		c.Header("Cache-Control", "no-store")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "no-referrer")
		c.Data(http.StatusOK, ct, b)
	})
}

func registerEnterpriseOpsRoutes(*gin.Engine, *generation) {}

// ─── lifecycle & hook stubs ──────────────────────────────────────────────────

func (c *config) normalizeEnterprise() error {
	if c.role == "" {
		c.role = roleStandalone
	}
	if c.role != roleStandalone {
		return fmt.Errorf("-role %q is provided by econcert (build with: go build -tags \"wordpress,enterprise\" ./cmd/econcert)", c.role)
	}
	if c.hardened {
		return fmt.Errorf("-enterprise-hardened is provided by econcert")
	}
	if c.redisAddr != "" {
		return fmt.Errorf("-redis-addr is provided by econcert")
	}
	if c.fastlaneFile != "" {
		return fmt.Errorf("-fastlane-config is provided by econcert")
	}
	if c.upstreamRetries < 0 || c.upstreamRetries > 5 {
		return fmt.Errorf("invalid -upstream-retries %d: must be between 0 and 5", c.upstreamRetries)
	}
	return nil
}

func (a *app) edgeCap(cfg config) int32 { return int32(cfg.capacity) }
func (a *app) edgeReady(config) bool    { return true }

func (a *app) initEnterpriseEarly(config) error {
	a.topo = &topology{}
	return nil
}

func (a *app) initEnterpriseFastlane(config, *room.WaitingRoom) error { return nil }
func (a *app) initEnterpriseServices(config)                          {}
func (a *app) startEnterpriseLoops()                                  {}
func (a *app) closeEnterpriseOnStartupErr()                           {}
func (a *app) maybeBenchOnStart(context.Context, config)              {}
func (a *app) notifyAlert(alertEvent)                                 {}
func (a *app) recordAudit(auditEvent)                                 {}
func (a *app) publishClusterBan(banTarget, int64, int)                {}
func (a *app) publishClusterUnban(banTarget)                          {}
func (a *app) emailScopeLabel(scope netip.Prefix) string              { return scope.String() }
func (a *app) emailIPLabel(ip netip.Addr) string                      { return ip.String() }
func (a *app) eraseMailerIP(netip.Addr, string) int                   { return 0 }
func (a *app) applyEnterpriseReload(config)                           {}
func untrackedEnterprisePaths() []pathRule                            { return nil }
func (a *app) fastlaneEligible(*http.Request) bool                    { return false }
func (a *app) fastlaneSessionID(*http.Request) (string, bool)         { return "", false }
func (a *app) fastlaneEnabled() bool                                  { return false }
func (a *app) populateOverviewEnterprise(h gin.H)                     { h["edition"] = Edition() }
func (a *app) populateStatsEnterprise(out gin.H)                      { out["edition"] = Edition() }
func (a *app) writeEnterpriseMetrics(*strings.Builder, *counters)     {}
func (a *app) describeEnterpriseSecrets(_ config, out map[string]string) {
	out["Edition"] = Edition()
}
func (a *app) logEnterpriseStartup(config) {}

func (p *portal) registerEnterprisePortalRoutes(_ *gin.Engine, api *gin.RouterGroup) {
	api.GET("/fastlane", p.requireRole(roleViewer), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"enabled": false})
	})
}

func enterpriseSubcommand(name string) func([]string, io.Writer) error {
	switch name {
	case "reconcile", "archive-receipts", "example", "audit", "hash-password":
		return func([]string, io.Writer) error {
			return fmt.Errorf("subcommand %q is provided by econcert (build with: go build -tags \"wordpress,enterprise\" ./cmd/econcert)", name)
		}
	}
	return nil
}

func enterpriseSettingDefs() []settingDef { return nil }

func movedEnterpriseFlags() map[string]string {
	return map[string]string{
		"fastlane-config":         "econcert",
		"networks-config":         "econcert",
		"tls-client-ca":           "econcert",
		"tls-require-client-cert": "econcert",
		"portal-sso-header":       "econcert",
		"portal-sso-role-header":  "econcert",
		"portal-sso-default-role": "econcert",
		"portal-trusted-proxies":  "econcert",
		"enterprise-hardened":     "econcert",
		"audit-log":               "econcert",
		"redis-addr":              "econcert",
		"redis-tls":               "econcert",
		"redis-prefix":            "econcert",
		"role":                    "econcert",
		"node-id":                 "econcert",
		"hop-peers":               "econcert",
		"hop-max-skew":            "econcert",
		"hop-wait":                "econcert",
		"hop-replay-guard":        "econcert",
		"hop-require-nonce":       "econcert",
		"hop-require-mtls":        "econcert",
		"host-cap":                "econcert",
		"hop-leaves":              "econcert",
		"hop-poll":                "econcert",
		"hop-auto-cap":            "econcert",
		"bench-on-start":          "econcert",
		"bench-p95":               "econcert",
		"bench-max-lemmings":      "econcert",
		"email-provider":          "econcert",
		"email-smtp-host":         "econcert",
		"email-smtp-port":         "econcert",
		"email-smtp-tls":          "econcert",
		"email-smtp-user":         "econcert",
		"email-resend-url":        "econcert",
		"email-sendpanda-url":     "econcert",
		"email-from-name":         "econcert",
		"email-from-addr":         "econcert",
		"email-to":                "econcert",
		"email-dkim-selector":     "econcert",
		"email-cadence-max":       "econcert",
		"email-cadence-window":    "econcert",
		"email-cadence-unit":      "econcert",
		"email-events":            "econcert",
		"email-org-name":          "econcert",
		"email-postal-address":    "econcert",
		"email-privacy-url":       "econcert",
		"email-terms-url":         "econcert",
		"email-portal-url":        "econcert",
		"email-public-base-url":   "econcert",
		"email-cluster-dedupe":    "econcert",
	}
}
