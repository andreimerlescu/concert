package server

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/configfile"
	"github.com/andreimerlescu/concert/internal/guard"
	"github.com/andreimerlescu/sema"
	"github.com/gin-gonic/gin"
)

const ctxMatchedRoute = "concert.matched_route"

// forbiddenSiteResponseHeaders lists hop-by-hop and session-sensitive header
// names that SiteConfig.Headers must never mutate at runtime (S9).
var forbiddenSiteResponseHeaders = map[string]struct{}{
	"host":                {},
	"transfer-encoding":   {},
	"content-length":      {},
	"set-cookie":          {},
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"upgrade":             {},
}

// errorProtectedSecurityHeaders lists security-critical headers that
// SiteConfig.Headers must never weaken or override on error responses (>= 400).
var errorProtectedSecurityHeaders = map[string]struct{}{
	"content-security-policy":   {},
	"strict-transport-security": {},
	"x-content-type-options":    {},
	"x-frame-options":           {},
	"referrer-policy":           {},
}

// compiledRoute holds the compiled runtime state for one declarative
// configfile.RouteConfig entry. Immutable after buildRouteTable except for
// concurrency-safe limiter, pool, and semaphore internals.
type compiledRoute struct {
	cfg     configfile.RouteConfig
	prefix  string // normalized path prefix (leading "/", cleaned)
	pool    *upstreamPool
	proxy   *httputil.ReverseProxy
	limiter *guard.RouteLimiter
	sem     sema.Semaphore
}

// matches reports whether reqPath matches r.prefix on a segment boundary.
//
// # Parameters
//
//   - reqPath: Cleaned or raw HTTP request URL path.
//
// # Returns
//
// true when reqPath equals r.prefix or sits beneath r.prefix on a "/" boundary.
//
// # Example
//
//	ok := route.matches("/api/v1/items")
//
// # Used By
//
// Called by routeTable.match in internal/server/routes_wiring.go.
func (r *compiledRoute) matches(reqPath string) bool {
	if r == nil || r.prefix == "" {
		return false
	}
	if r.prefix == "/" {
		return strings.HasPrefix(reqPath, "/")
	}
	if reqPath == r.prefix {
		return true
	}
	if strings.HasSuffix(r.prefix, "/") {
		return strings.HasPrefix(reqPath, r.prefix)
	}
	return strings.HasPrefix(reqPath, r.prefix+"/")
}

// stripRequestPath returns reqPath with r.prefix removed when r.cfg.StripPrefix
// is enabled, guaranteeing a leading "/" on the returned path.
//
// # Parameters
//
//   - reqPath: Original request URL path.
//
// # Returns
//
// The rewritten request path with leading "/".
//
// # Example
//
//	rewritten := route.stripRequestPath("/api/v1/users") // "/users"
//
// # Used By
//
// Called by generation.forwardWithRoute in internal/server/routes_wiring.go.
func (r *compiledRoute) stripRequestPath(reqPath string) string {
	if r == nil || !r.cfg.StripPrefix || r.prefix == "" || r.prefix == "/" {
		return reqPath
	}
	trimmed := strings.TrimPrefix(reqPath, strings.TrimSuffix(r.prefix, "/"))
	if trimmed == "" || !strings.HasPrefix(trimmed, "/") {
		return "/" + strings.TrimLeft(trimmed, "/")
	}
	return trimmed
}

// routeTable holds compiled path-based upstream routes (sorted longest-prefix
// first), exact-path redirects, and safe response header rules for one
// generation. Immutable after construction; safe for concurrent use.
type routeTable struct {
	routes    []*compiledRoute
	redirects map[string]configfile.RedirectRule
	headers   []configfile.HeaderRule
}

// buildRouteTable compiles cfg.siteRoutes, cfg.siteRedirects, and
// cfg.siteHeaders into an immutable routeTable. Each route specifying its own
// upstream gets a dedicated upstreamPool and ReverseProxy inheriting circuit
// breaker, health check, body-idle timeout, and FastCGI settings from cfg.
//
// # Parameters
//
//   - cfg: Normalized site configuration.
//   - stats: Shared operational counters.
//   - modify: Base proxy ModifyResponse callback (tier headers + priority grants).
//   - topo: Topology helper for edge/leaf hop signing.
//   - onCircuitOpen: Optional circuit-breaker alert callback attached to per-route pools.
//
// # Returns
//
// A compiled *routeTable (nil when no routes, redirects, or headers are
// configured) or a validation/construction error. On error, any partially
// constructed route upstream pools are closed cleanly.
//
// # Example
//
//	rt, err := buildRouteTable(next, a.stats, modifyFn, a.topo, onCB)
//
// # Used By
//
// Called by app.buildGeneration in internal/server/reload.go.
func buildRouteTable(
	cfg config,
	stats *counters,
	modify func(*http.Response) error,
	topo *topology,
	onCircuitOpen func(target, reason string),
) (*routeTable, error) {
	if len(cfg.siteRoutes) == 0 && len(cfg.siteRedirects) == 0 && len(cfg.siteHeaders) == 0 {
		return nil, nil
	}

	rt := &routeTable{
		redirects: make(map[string]configfile.RedirectRule, len(cfg.siteRedirects)),
		headers:   append([]configfile.HeaderRule(nil), cfg.siteHeaders...),
	}
	cleanupOnErr := func() {
		rt.close()
	}

	for _, rr := range cfg.siteRedirects {
		from := normalizeRoutePrefix(rr.From)
		if from == "" {
			cleanupOnErr()
			return nil, fmt.Errorf("invalid redirect source %q", rr.From)
		}
		status := rr.Status
		if status == 0 {
			status = http.StatusFound
		}
		switch status {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		default:
			cleanupOnErr()
			return nil, fmt.Errorf("invalid redirect status %d for %q", status, from)
		}
		if !isSafeRedirectTarget(rr.To) {
			cleanupOnErr()
			return nil, fmt.Errorf("invalid redirect target %q for %q", rr.To, from)
		}
		rr.From = from
		rr.Status = status
		rt.redirects[from] = rr
	}

	wrappedModify := wrapSiteHeadersModify(modify, rt.headers)

	for _, rc := range cfg.siteRoutes {
		prefix := normalizeRoutePrefix(rc.Path)
		if prefix == "" {
			cleanupOnErr()
			return nil, fmt.Errorf("invalid route path %q", rc.Path)
		}
		rc.Path = prefix
		cr := &compiledRoute{
			cfg:    rc,
			prefix: prefix,
		}

		if strings.TrimSpace(rc.Upstream) != "" {
			routeCfg := cfg
			routeCfg.upstream = strings.TrimSpace(rc.Upstream)
			targets, err := parseUpstreams(routeCfg.upstream)
			if err != nil {
				cleanupOnErr()
				return nil, fmt.Errorf("route %s upstream: %w", prefix, err)
			}
			routeCfg.targets = targets
			routeCfg.target = targets[0]
			routeCfg.hasFastCGI = false
			for _, u := range targets {
				if isFastCGITarget(u) {
					routeCfg.hasFastCGI = true
				}
			}
			proxy, pool, err := newEnterpriseProxy(routeCfg, stats, wrappedModify, topo)
			if err != nil {
				cleanupOnErr()
				return nil, fmt.Errorf("route %s proxy: %w", prefix, err)
			}
			if onCircuitOpen != nil {
				pool.onCircuitOpen = onCircuitOpen
			}
			cr.pool = pool
			cr.proxy = proxy
		}

		if strings.TrimSpace(rc.RateLimit) != "" {
			rule, err := guard.ParseRouteRule(prefix, strings.TrimSpace(rc.RateLimit))
			if err != nil {
				if cr.pool != nil {
					cr.pool.close()
				}
				cleanupOnErr()
				return nil, fmt.Errorf("route %s rate_limit: %w", prefix, err)
			}
			rl, err := guard.NewRouteLimiter([]guard.Rule{rule}, 0)
			if err != nil {
				if cr.pool != nil {
					cr.pool.close()
				}
				cleanupOnErr()
				return nil, fmt.Errorf("route %s rate_limit: %w", prefix, err)
			}
			cr.limiter = rl
		}

		if rc.Cap > 0 {
			sem, err := sema.New(int(rc.Cap))
			if err != nil {
				if cr.pool != nil {
					cr.pool.close()
				}
				cleanupOnErr()
				return nil, fmt.Errorf("route %s cap: %w", prefix, err)
			}
			cr.sem = sem
		}

		rt.routes = append(rt.routes, cr)
	}

	// Longest prefix wins; ties break lexicographically for determinism.
	sort.Slice(rt.routes, func(i, j int) bool {
		if len(rt.routes[i].prefix) != len(rt.routes[j].prefix) {
			return len(rt.routes[i].prefix) > len(rt.routes[j].prefix)
		}
		return rt.routes[i].prefix < rt.routes[j].prefix
	})

	return rt, nil
}

// close shuts down all dedicated per-route upstream pools (health probes,
// idle HTTP connections, and FastCGI transports). Safe on nil receiver.
//
// # Parameters
//
// None.
//
// # Example
//
//	g.routes.close()
//
// # Used By
//
// Called by app.Close in internal/server/app.go and app.commit in
// internal/server/reload.go.
func (rt *routeTable) close() {
	if rt == nil {
		return
	}
	for _, r := range rt.routes {
		if r != nil && r.pool != nil {
			r.pool.close()
		}
	}
}

// match returns the longest-prefix compiledRoute matching reqPath, or nil.
//
// # Parameters
//
//   - reqPath: Request URL path.
//
// # Returns
//
// The most specific matching *compiledRoute, or nil if no route matches.
//
// # Example
//
//	cr := g.routes.match("/api/v2/items")
//
// # Used By
//
// Called by generation.routeDispatchMiddleware and generation.biddingEnabledForRequest.
func (rt *routeTable) match(reqPath string) *compiledRoute {
	if rt == nil || len(rt.routes) == 0 {
		return nil
	}
	for _, r := range rt.routes {
		if r.matches(reqPath) {
			return r
		}
	}
	return nil
}

// matchRedirect looks up an exact normalized redirect rule for reqPath.
//
// # Parameters
//
//   - reqPath: Incoming HTTP request URL path.
//
// # Returns
//
// The matching RedirectRule and true if found, or zero value and false.
//
// # Example
//
//	if rule, ok := g.routes.matchRedirect("/old"); ok {
//	    c.Redirect(rule.Status, rule.To)
//	}
//
// # Used By
//
// Called by generation.routeDispatchMiddleware in internal/server/routes_wiring.go.
func (rt *routeTable) matchRedirect(reqPath string) (configfile.RedirectRule, bool) {
	if rt == nil || len(rt.redirects) == 0 {
		return configfile.RedirectRule{}, false
	}
	cleaned := normalizeRoutePrefix(reqPath)
	rr, ok := rt.redirects[cleaned]
	return rr, ok
}

// normalizeRoutePrefix ensures p starts with "/" and cleans redundant slashes.
//
// # Parameters
//
//   - p: Raw path prefix.
//
// # Returns
//
// Cleaned path starting with "/", or "" when p is empty or lacks a leading "/".
//
// # Example
//
//	norm := normalizeRoutePrefix("/api/v1/") // "/api/v1"
//
// # Used By
//
// Called by buildRouteTable and routeTable.matchRedirect in internal/server/routes_wiring.go.
func normalizeRoutePrefix(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || !strings.HasPrefix(p, "/") {
		return ""
	}
	return path.Clean(p)
}

// isSafeRedirectTarget validates that target is either a single-slash relative
// path or an absolute http:// / https:// URL without control characters (S9).
//
// # Parameters
//
//   - target: Candidate HTTP Location header target.
//
// # Returns
//
// true when target is safe to emit in a Location header.
//
// # Example
//
//	ok := isSafeRedirectTarget("https://example.com/new")
//
// # Used By
//
// Called by buildRouteTable in internal/server/routes_wiring.go.
func isSafeRedirectTarget(target string) bool {
	if target == "" || strings.ContainsAny(target, "\r\n\x00") {
		return false
	}
	if strings.HasPrefix(target, "/") {
		return !strings.HasPrefix(target, "//") && !strings.HasPrefix(target, `/\`)
	}
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	return (scheme == "http" || scheme == "https") && u.Host != ""
}

// wrapSiteHeadersModify chains next with safe SiteConfig.Headers application
// on proxied upstream responses. Security-critical headers are never overridden
// on error (>= 400) responses, and forbidden hop-by-hop / Set-Cookie headers
// are never mutated (S9).
//
// # Parameters
//
//   - next: Existing ReverseProxy ModifyResponse callback (may be nil).
//   - rules: Validated site response header rules.
//
// # Returns
//
// A composite ModifyResponse function safe for ReverseProxy use.
//
// # Example
//
//	mod := wrapSiteHeadersModify(baseMod, cfg.siteHeaders)
//
// # Used By
//
// Called by buildRouteTable in internal/server/routes_wiring.go and
// app.buildGeneration in internal/server/reload.go.
func wrapSiteHeadersModify(next func(*http.Response) error, rules []configfile.HeaderRule) func(*http.Response) error {
	if len(rules) == 0 {
		return next
	}
	copied := append([]configfile.HeaderRule(nil), rules...)
	return func(resp *http.Response) error {
		if next != nil {
			if err := next(resp); err != nil {
				return err
			}
		}
		if resp == nil {
			return nil
		}
		applySiteResponseHeaders(resp.Header, resp.StatusCode, copied)
		return nil
	}
}

// applySiteResponseHeaders applies validated set/add/remove header rules to a
// proxied upstream response header map while protecting forbidden hop-by-hop
// headers and security-critical headers on error responses (>= 400).
//
// # Parameters
//
//   - h: Mutable http.Header map of a proxied upstream response.
//   - statusCode: HTTP status code returned by the upstream.
//   - rules: Ordered slice of configfile.HeaderRule actions.
//
// # Example
//
//	applySiteResponseHeaders(resp.Header, resp.StatusCode, rules)
//
// # Used By
//
// Called by wrapSiteHeadersModify in internal/server/routes_wiring.go.
func applySiteResponseHeaders(h http.Header, statusCode int, rules []configfile.HeaderRule) {
	if h == nil || len(rules) == 0 {
		return
	}
	isErr := statusCode >= http.StatusBadRequest
	for _, rule := range rules {
		name := strings.TrimSpace(rule.Name)
		if name == "" || strings.ContainsAny(name, "\r\n\x00") || strings.ContainsAny(rule.Value, "\r\n\x00") {
			continue
		}
		lower := strings.ToLower(name)
		if _, blocked := forbiddenSiteResponseHeaders[lower]; blocked {
			continue
		}
		if isErr {
			if _, protected := errorProtectedSecurityHeaders[lower]; protected {
				continue
			}
		}
		switch rule.Action {
		case configfile.HeaderSet:
			h.Set(name, rule.Value)
		case configfile.HeaderAdd:
			h.Add(name, rule.Value)
		case configfile.HeaderRemove:
			h.Del(name)
		}
	}
}

// routeDispatchMiddleware evaluates declarative SiteConfig.Redirects and
// SiteConfig.Routes ahead of static offload and the waiting room.
//
// Exempt internal paths (/_room/*, /_concert/*, /queue/status) always bypass
// site routes and redirects. Matching redirects abort immediately with the
// configured 301/302/307/308 status. Matching routes store their *compiledRoute
// in gin context, enforce per-route rate limits, and when bypass=true forward
// directly to the route's upstream without entering the waiting room.
//
// # Parameters
//
//   - c: Active request *gin.Context.
//
// # Example
//
//	if g.routes != nil {
//	    r.Use(g.routeDispatchMiddleware)
//	}
//
// # Used By
//
// Registered by buildRouter in internal/server/router.go.
func (g *generation) routeDispatchMiddleware(c *gin.Context) {
	rt := g.routes
	if rt == nil {
		c.Next()
		return
	}
	p := c.Request.URL.Path
	if isGuardExemptPath(p) {
		c.Next()
		return
	}

	if rr, ok := rt.matchRedirect(p); ok {
		c.Set(ctxSkipWaitingHeaders, true)
		c.Header("Cache-Control", "no-store")
		c.Redirect(rr.Status, rr.To)
		c.Abort()
		return
	}

	cr := rt.match(p)
	if cr == nil {
		c.Next()
		return
	}
	c.Set(ctxMatchedRoute, cr)

	if cr.limiter != nil {
		ip := clientIPFrom(c)
		if allowed, retryAfter := cr.limiter.Allow(p, ip, time.Now()); !allowed {
			g.a.stats.guardRateLimit.Add(1)
			c.Set(ctxSkipWaitingHeaders, true)
			secs := max(int((retryAfter+time.Second-1)/time.Second), 1)
			s := strconv.Itoa(secs)
			c.Header("Cache-Control", "no-store")
			c.Header("Retry-After", s)
			if wantsHTML(c.Request) {
				c.Data(http.StatusTooManyRequests, "text/html; charset=utf-8",
					[]byte(fmt.Sprintf(blockedPage, "Too many requests for this route. Try again in "+s+"s.")))
			} else {
				c.Data(http.StatusTooManyRequests, "application/json; charset=utf-8",
					mustJSON(gin.H{"error": "rate_limit_exceeded", "retry_after_seconds": secs}))
			}
			c.Abort()
			return
		}
	}

	if cr.cfg.Bypass {
		g.forwardAs(classBypass)(c)
		c.Abort()
		return
	}

	c.Next()
}

// matchedRouteFrom extracts the *compiledRoute attached by
// routeDispatchMiddleware, or nil when the site default upstream applies.
//
// # Parameters
//
//   - c: Active request *gin.Context.
//
// # Returns
//
// The matched *compiledRoute, or nil.
//
// # Example
//
//	cr := matchedRouteFrom(c)
//
// # Used By
//
// Called by generation.proxyForward in internal/server/router.go and
// generation.biddingEnabledForRequest in internal/server/bidding_wiring.go.
func matchedRouteFrom(c *gin.Context) *compiledRoute {
	if c == nil {
		return nil
	}
	v, ok := c.Get(ctxMatchedRoute)
	if !ok {
		return nil
	}
	cr, _ := v.(*compiledRoute)
	return cr
}

// sameSiteRoutes reports whether two configs have identical declarative routes,
// redirects, and headers so hot reload can carry over unchanged route pools.
//
// # Parameters
//
//   - a: Previous generation config.
//   - b: Next generation config.
//
// # Returns
//
// true when siteRoutes, siteRedirects, and siteHeaders match element-for-element.
//
// # Example
//
//	if prev != nil && sameProxy(prev.cfg, next) && sameSiteRoutes(prev.cfg, next) {
//	    g.routes = prev.routes
//	}
//
// # Used By
//
// Called by app.buildGeneration in internal/server/reload.go.
func sameSiteRoutes(a, b config) bool {
	if len(a.siteRoutes) != len(b.siteRoutes) ||
		len(a.siteRedirects) != len(b.siteRedirects) ||
		len(a.siteHeaders) != len(b.siteHeaders) {
		return false
	}
	for i := range a.siteRoutes {
		if a.siteRoutes[i] != b.siteRoutes[i] {
			return false
		}
	}
	for i := range a.siteRedirects {
		if a.siteRedirects[i] != b.siteRedirects[i] {
			return false
		}
	}
	for i := range a.siteHeaders {
		if a.siteHeaders[i] != b.siteHeaders[i] {
			return false
		}
	}
	return true
}
