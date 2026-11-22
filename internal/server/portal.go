package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/mailer"
	"github.com/gin-gonic/gin"
)

// portalFS holds the portal's templates and static assets. Files whose names
// start with "." or "_" are excluded by go:embed, which keeps stray files
// such as .DS_Store out of the binary.
//
//go:embed templates
var portalFS embed.FS

// Files inside templates/. Templates are named after their file by
// template.ParseFS, so templateIndex is also the name passed to
// ExecuteTemplate. Vendored assets are referenced by these constants in
// Go and passed to the templates, so the two can never disagree. The table
// fragments live in templateFragments; see fragments.go.
const (
	templateHeader = "header.tpl"
	templateFooter = "footer.tpl"
	templateIndex  = "index.tpl"

	assetBootstrapCSS = "lib/css/bootstrap.5.3.3.min.css"
	assetIconsCSS     = "lib/css/bootstrap-icons.1.13.1.min.css"
	assetBootstrapJS  = "lib/js/bootstrap.bundle.5.3.3.min.js"
	assetPortalLight  = "css/portal-light.css"
	assetPortalThemes = "css/portal-themes.css"
	assetPortalJS     = "js/portal.js"
	assetThemeJS      = "js/theme.js"
)

const (
	portalCookie       = "concert_portal"
	portalNonceLen     = 16
	portalExpOff       = portalNonceLen
	portalBodyLen      = portalExpOff + 8
	portalMACLen       = 16
	portalRawLen       = portalBodyLen + portalMACLen
	minPortalPassLen   = 16
	portalMaxNotes     = 100000 // path and browser notes kept for waiting visitors
	portalQueueLimit   = 500    // visitors the queue view lists, from the front
	portalGrace        = 5 * time.Second
	loginMaxFailures   = 5
	loginWindow        = 15 * time.Minute
	loginLockout       = 15 * time.Minute
	ctxPortalNonce     = "portal.nonce"
	ctxPortalPrincipal = "portal.principal"
	settingsBodyLimit  = 1 << 20
)

var (
	errAbuseDisabled = errors.New("the abuse registry is disabled (-abuse=false)")
	errClientExempt  = errors.New("that address is exempt from bans: it is listed in -abuse-allow or -trusted-proxies")
	errRegistryFull  = errors.New("the abuse registry is full (-abuse-max-entries)")
)

// ─── configuration ───────────────────────────────────────────────────────────

// portalConfig holds the admin portal's settings. Its flags are declared
// from settingDefs in settings.go with every other flag, and pass is read in
// parseConfig from CONCERT_PORTAL_PASS alongside concert's other secrets.
// The listen address is restart-only; the allowlist and session settings
// change while concert runs.
type portalConfig struct {
	listen       string
	allowSpec    string
	sessionTTL   time.Duration
	secureCookie bool

	tlsCert string
	tlsKey  string

	ssoHeader          string
	ssoRoleHeader      string
	ssoDefaultRole     string
	trustedProxiesSpec string

	pass      string // CONCERT_PORTAL_PASS; env/file only
	usersSpec string // CONCERT_PORTAL_USERS; env/file only

	allow                []netip.Prefix // parsed allowSpec
	trustedProxies       []netip.Prefix // parsed trustedProxiesSpec
	ssoDefaultRoleParsed rbacRole
	users                *userDirectory
}

func (pc *portalConfig) hasAuth() bool {
	return pc.pass != "" || (pc.users != nil && pc.users.count() > 0) || pc.ssoHeader != ""
}

// enabled reports whether the portal should be listening.
func (pc *portalConfig) enabled() bool {
	return pc.listen != "" && pc.hasAuth()
}

func (pc *portalConfig) normalize() error {
	allow, err := parsePrefixes(pc.allowSpec)
	if err != nil {
		return fmt.Errorf("invalid -portal-allow: %w", err)
	}
	pc.allow = allow
	tp, err := parsePrefixes(pc.trustedProxiesSpec)
	if err != nil {
		return fmt.Errorf("invalid -portal-trusted-proxies: %w", err)
	}
	pc.trustedProxies = tp

	if pc.usersSpec != "" {
		dir, err := loadPortalUsers(pc.usersSpec)
		if err != nil {
			return err
		}
		pc.users = dir
	}

	if pc.ssoHeader != "" {
		if len(pc.trustedProxies) == 0 {
			return errors.New("-portal-trusted-proxies must be set when -portal-sso-header is enabled")
		}
		defRole := pc.ssoDefaultRole
		if defRole == "" {
			defRole = "viewer"
		}
		r, ok := parseRole(defRole)
		if !ok {
			return fmt.Errorf("invalid -portal-sso-default-role %q: must be viewer, operator, or admin", pc.ssoDefaultRole)
		}
		pc.ssoDefaultRoleParsed = r
	}

	if (pc.tlsCert == "") != (pc.tlsKey == "") {
		return errors.New("-portal-tls-cert and -portal-tls-key must both be set")
	}

	if !pc.enabled() {
		return nil
	}
	if pc.pass != "" && len(pc.pass) < minPortalPassLen {
		return fmt.Errorf("CONCERT_PORTAL_PASS must be at least %d characters", minPortalPassLen)
	}
	if len(pc.allow) == 0 {
		return errors.New("-portal-allow must list at least one address when the portal is enabled")
	}
	if pc.sessionTTL < 5*time.Minute {
		return fmt.Errorf("invalid -portal-session-ttl %s: must be at least 5m", pc.sessionTTL)
	}
	return nil
}

// ─── lifecycle ───────────────────────────────────────────────────────────────

type portal struct {
	a             *app
	ln            net.Listener // bound by newPortal when -portal-listen is set; served by start
	tlsCfg        *tls.Config
	engine        *gin.Engine
	tmpl          *template.Template
	static        fs.FS
	sessionKey    []byte
	passDigest    [sha256.Size]byte
	hasPass       bool
	users         *userDirectory
	notes         *noteStore
	kicked        *kickList
	fails         *loginLimiter
	emailOpsLimit *emailRateLimiter
	history       *history // requests and bans on the main listener; see history.go
}

// newPortal builds the portal and, when -portal-listen is set, binds its
// listener. It returns nil when no portal auth (CONCERT_PORTAL_PASS,
// CONCERT_PORTAL_USERS, or -portal-sso-header) is configured.
func newPortal(a *app) (*portal, error) {
	cfg := a.current().cfg
	pc := cfg.portal
	if !pc.hasAuth() {
		if pc.listen != "" {
			log.Printf("portal disabled: set CONCERT_PORTAL_PASS, CONCERT_PORTAL_USERS, or -portal-sso-header to enable it on %s", pc.listen)
		}
		return nil, nil
	}

	portalTLS, err := newPortalTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("portal TLS: %w", err)
	}

	static, err := fs.Sub(portalFS, "templates")
	if err != nil {
		return nil, fmt.Errorf("portal: %w", err)
	}
	for _, req := range []string{
		templateHeader, templateFooter, templateIndex, templateFragments,
		assetBootstrapCSS, assetIconsCSS, assetBootstrapJS,
		assetPortalLight, assetPortalThemes, assetPortalJS, assetThemeJS,
	} {
		if _, err := fs.Stat(static, req); err != nil {
			return nil, fmt.Errorf("portal: templates/%s is missing", req)
		}
	}

	seed := []byte(pc.pass)
	if len(seed) == 0 {
		seed = cfg.admitSecret
	}
	keyMAC := hmac.New(sha256.New, seed)
	keyMAC.Write([]byte("concert/portal/session-key"))

	p := &portal{
		a:             a,
		tlsCfg:        portalTLS,
		static:        static,
		sessionKey:    keyMAC.Sum(nil),
		hasPass:       pc.pass != "",
		users:         pc.users,
		notes:         newNoteStore(portalMaxNotes),
		kicked:        &kickList{m: map[string]time.Time{}},
		fails:         &loginLimiter{m: map[netip.Addr]*loginState{}},
		emailOpsLimit: newEmailRateLimiter(10, time.Minute),
	}
	if p.hasPass {
		p.passDigest = sha256.Sum256([]byte(pc.pass))
	}
	tmpl, err := template.New(templateIndex).Funcs(p.templateFuncs()).
		ParseFS(static, templateHeader, templateFooter, templateIndex, templateFragments)
	if err != nil {
		return nil, fmt.Errorf("portal templates: %w", err)
	}
	p.tmpl = tmpl

	p.history = newHistory(a.abuse, a.prio.grants, a.ipinfo, historyLogPath(cfg), time.Now())
	p.history.setRetention(cfg.historyRetention)
	a.attachHistory(p.history)
	p.engine = p.routes()

	if pc.enabled() {
		ln, err := listen(pc.listen)
		if err != nil {
			return nil, fmt.Errorf("portal listen %s: %w", pc.listen, err)
		}
		p.ln = ln
	}

	// Every ban from here on opens a window in the history.
	p.history.attach(a.abuse)
	return p, nil
}

// start serves the portal until ctx is cancelled and returns its endpoint.
// Safe on a nil portal.
func (p *portal) start(ctx context.Context) *endpoint {
	if p == nil {
		return nil
	}
	ep := newEndpoint("portal", p.engine, portalGrace, portalServer)
	if p.tlsCfg != nil {
		ep.setTLS(p.tlsCfg)
	}
	if p.ln != nil {
		pc := p.pc()
		ep.serveOn(p.ln, pc.listen)
		proto := "HTTP"
		if p.tlsCfg != nil {
			proto = "HTTPS"
		}
		log.Printf("portal listening on %s (%s, allowed: %s)", p.ln.Addr(), proto, pc.allowSpec)
	} else {
		log.Printf("portal off: set CONCERT_PORTAL_LISTEN and restart to turn it on")
	}
	go p.janitor(ctx)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-ep.fatal:
				log.Printf("portal: %v", err)
			}
		}
	}()
	return ep
}

// closeListener releases the listener newPortal bound when start will never
// run, for example because the main listener failed to bind. Safe on a nil
// portal.
func (p *portal) closeListener() {
	if p != nil && p.ln != nil {
		_ = p.ln.Close()
	}
}

func portalServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// pc is the portal's current configuration.
func (p *portal) pc() portalConfig {
	return p.a.current().cfg.portal
}

// janitor forgets notes for tickets room no longer holds, expired kicks,
// old sign-in failures and old history, and notices bans lifted outside
// the portal.
func (p *portal) janitor(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			p.notes.prune(func(token string) bool {
				_, ok := p.a.room.Ticket(token)
				return ok
			})
			p.kicked.sweep(now)
			p.fails.sweep(now)
			p.history.sweep(now)
		}
	}
}

// price is the skip-the-line price at queue depth; see app.price.
func (p *portal) price(depth int64) float64 {
	return p.a.price(depth)
}

// ─── routes ──────────────────────────────────────────────────────────────────

func (p *portal) routes() *gin.Engine {
	r := gin.New()
	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false
	_ = r.SetTrustedProxies(nil)

	r.Use(gin.Recovery(), p.allowOnly, securityHeaders)

	r.GET("/assets/*filepath", p.asset)
	r.GET("/", p.index)
	r.POST("/login", p.login)
	r.POST("/logout", p.requireSession, p.requireFormCSRF, p.logout)
	r.GET(mailer.UnsubscribePortalPath, p.a.handleEmailUnsubscribe)
	r.POST(mailer.UnsubscribePortalPath, p.a.handleEmailUnsubscribe)

	api := r.Group("/api", p.requireSession, p.requireCSRF)
	api.GET("/me", func(c *gin.Context) {
		pr := portalPrincipal(c)
		c.JSON(http.StatusOK, gin.H{"actor": pr.Actor, "role": pr.Role.String(), "source": pr.Source})
	})
	api.GET("/metrics", p.requireRole(roleViewer), func(c *gin.Context) {
		serveMetrics(c, p.a)
	})
	api.GET("/overview", p.requireRole(roleViewer), p.apiOverview)
	api.POST("/topology/rebench", p.requireRole(roleAdmin), p.apiTopologyRebench)
	api.GET("/fastlane", p.requireRole(roleViewer), func(c *gin.Context) {
		if p.a.fastlane == nil {
			c.JSON(200, gin.H{"enabled": false})
			return
		}
		c.JSON(200, p.a.fastlane.Summary())
	})
	api.POST("/fastlane/reconcile", p.requireRole(roleAdmin), p.apiFastlaneReconcile)
	api.GET("/queue", p.requireRole(roleViewer), p.apiQueue)
	api.POST("/queue/promote", p.requireRole(roleOperator), p.apiPromote)
	api.POST("/queue/kick", p.requireRole(roleOperator), p.apiKick)
	api.GET("/bans", p.requireRole(roleViewer), p.apiBans)
	api.POST("/bans", p.requireRole(roleOperator), p.apiBanSave)
	api.DELETE("/bans", p.requireRole(roleOperator), p.apiUnban)
	api.GET("/history", p.requireRole(roleViewer), p.apiHistory)
	api.GET("/history/client", p.requireRole(roleViewer), p.apiHistoryClient)
	api.GET("/history/ban", p.requireRole(roleViewer), p.apiHistoryBan)
	api.GET("/settings", p.requireRole(roleViewer), p.apiSettings)
	api.POST("/settings", p.requireRole(roleAdmin), p.apiSettingsSave)
	api.DELETE("/settings", p.requireRole(roleAdmin), p.apiSettingsReset)
	api.GET("/email", p.requireRole(roleViewer), p.apiEmail)
	api.POST("/email/config", p.requireRole(roleAdmin), p.apiEmailConfigSave)
	api.DELETE("/email/secrets", p.requireRole(roleAdmin), p.apiEmailSecretDelete)
	api.POST("/email/pause", p.requireRole(roleAdmin), p.apiEmailPause)
	api.POST("/email/verify", p.requireRole(roleAdmin), p.apiEmailVerify)
	api.POST("/email/test", p.requireRole(roleAdmin), p.apiEmailTest)
	api.POST("/email/flush", p.requireRole(roleAdmin), p.apiEmailFlush)
	api.GET("/privacy/export", p.requireRole(roleAdmin), func(c *gin.Context) {
		handlePrivacyExport(c, p.a, portalPrincipal(c), "portal")
	})
	api.DELETE("/privacy/erase", p.requireRole(roleAdmin), func(c *gin.Context) {
		handlePrivacyErase(c, p.a, portalPrincipal(c), "portal")
	})

	// Server-rendered tables; see fragments.go.
	api.GET("/frag/queue", p.requireRole(roleViewer), p.fragQueue)
	api.GET("/frag/bans", p.requireRole(roleViewer), p.fragBans)
	api.GET("/frag/visitors", p.requireRole(roleViewer), p.fragVisitors)
	api.GET("/frag/visitor", p.requireRole(roleViewer), p.fragVisitor)
	api.GET("/frag/banlog", p.requireRole(roleViewer), p.fragBanLog)
	api.GET("/frag/ban", p.requireRole(roleViewer), p.fragBan)

	r.NoRoute(func(c *gin.Context) { c.String(http.StatusNotFound, "not found") })
	return r
}

// allowOnly admits only addresses in -portal-allow. The portal is reached
// directly, never through a proxy, so the connection address is authoritative.
func (p *portal) allowOnly(c *gin.Context) {
	ip, ok := remoteAddr(c.Request)
	if !ok || !containsAddr(p.pc().allow, ip) {
		c.AbortWithStatus(http.StatusForbidden)
	}
}

func securityHeaders(c *gin.Context) {
	h := c.Writer.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; font-src 'self'; "+
		"style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "+
		"form-action 'self'; base-uri 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
}

// asset serves only lib/, css/ and js/ from the embedded templates directory,
// never the .tpl sources.
func (p *portal) asset(c *gin.Context) {
	rel := strings.TrimPrefix(path.Clean("/"+c.Param("filepath")), "/")
	if !strings.HasPrefix(rel, "lib/") && !strings.HasPrefix(rel, "css/") && !strings.HasPrefix(rel, "js/") {
		c.Status(http.StatusNotFound)
		return
	}
	data, err := fs.ReadFile(p.static, rel)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.Header("Cache-Control", "private, max-age=300")
	c.Data(http.StatusOK, assetType(rel), data)
}

func assetType(name string) string {
	switch ext := strings.ToLower(path.Ext(name)); ext {
	case ".woff2":
		return "font/woff2"
	case ".woff":
		return "font/woff"
	default:
		if t := mime.TypeByExtension(ext); t != "" {
			return t
		}
		return "application/octet-stream"
	}
}

// ─── pages and sessions ──────────────────────────────────────────────────────

type portalPage struct {
	Title        string
	Error        string
	CSRF         string
	BootstrapCSS string
	IconsCSS     string
	BootstrapJS  string
	PortalLight  string
	PortalThemes string
	PortalJS     string
	ThemeJS      string
	Version      string
	Upstream     string
	HistoryNote  string
	IPInfo       string
	Actor        string
	Role         string
	MultiUser    bool
	Authed       bool
}

// historyNote explains the history's limits under the Visitors tab.
func (p *portal) historyNote() string {
	persist := "A restart starts the history again (no history log: -history-log off, or -data-dir empty)."
	if p.history.log != nil {
		persist = "It is also written to " + p.history.log.path + " and restored when concert restarts."
	}
	retH := int(p.history.getRetention() / time.Hour)
	return fmt.Sprintf("Kept in memory: the last %d requests from each of up to %s addresses, until %dh after an "+
		"address's last request; bans are kept %dh after they end. Requests from banned clients and every 4xx or 5xx "+
		"response are always recorded; successful asset and waiting-room status requests are not, as in the access log. %s",
		historyPerClient, fmtCount(historyMaxClients), retH, retH, persist)
}

func (p *portal) render(c *gin.Context, status int, page portalPage) {
	page.BootstrapCSS = assetBootstrapCSS
	page.IconsCSS = assetIconsCSS
	page.BootstrapJS = assetBootstrapJS
	page.PortalLight = assetPortalLight
	page.PortalThemes = assetPortalThemes
	page.PortalJS = assetPortalJS
	page.ThemeJS = assetThemeJS
	page.Version = BinaryVersion()
	page.Upstream = p.a.current().cfg.upstream
	page.HistoryNote = p.historyNote()
	page.IPInfo = p.a.ipinfo.describe()
	page.MultiUser = p.users != nil && p.users.count() > 0
	var buf bytes.Buffer
	if err := p.tmpl.ExecuteTemplate(&buf, templateIndex, page); err != nil {
		log.Printf("portal: render: %v", err)
		c.String(http.StatusInternalServerError, "template error")
		return
	}
	c.Data(status, "text/html; charset=utf-8", buf.Bytes())
}

func (p *portal) authenticateRequest(r *http.Request, now time.Time) ([]byte, principal, bool) {
	ip, _ := remoteAddr(r)
	if nonce, pr, ok := p.verifySessionPrincipal(r, now); ok {
		pr.IP = ip
		return nonce, pr, true
	}
	if pr, ok := resolveSSOPrincipal(r, p.pc(), ip); ok {
		m := hmac.New(sha256.New, p.sessionKey)
		m.Write([]byte("sso-csrf:"))
		m.Write([]byte(pr.Actor))
		return m.Sum(nil)[:portalNonceLen], pr, true
	}
	return nil, principal{}, false
}

func (p *portal) index(c *gin.Context) {
	if nonce, pr, ok := p.authenticateRequest(c.Request, time.Now()); ok {
		p.render(c, http.StatusOK, portalPage{
			Title:  "Dashboard",
			Authed: true,
			CSRF:   p.csrfToken(nonce),
			Actor:  pr.Actor,
			Role:   pr.Role.String(),
		})
		return
	}
	p.render(c, http.StatusOK, portalPage{Title: "Sign in"})
}

func (p *portal) login(c *gin.Context) {
	ip, _ := remoteAddr(c.Request)
	now := time.Now()
	if left, locked := p.fails.locked(ip, now); locked {
		c.Header("Retry-After", strconv.Itoa(int(left/time.Second)+1))
		p.a.recordAudit(auditEvent{
			Actor:    "anonymous",
			Source:   "portal",
			Action:   "auth.login",
			Outcome:  "deny",
			ClientIP: ip.String(),
			Details:  map[string]any{"reason": "locked_out"},
		})
		p.render(c, http.StatusTooManyRequests, portalPage{
			Title: "Sign in",
			Error: fmt.Sprintf("Too many failed attempts. Try again in %s.", left.Round(time.Second)),
		})
		return
	}

	username := strings.TrimSpace(c.PostForm("user"))
	pass := c.PostForm("pass")
	totp := c.PostForm("totp")

	var authed principal
	ok := false
	if p.users != nil && p.users.count() > 0 && username != "" {
		if u, matched := p.users.authenticate(username, pass, totp, now); matched {
			authed = principal{Actor: u.username, Role: u.role, Source: "user", IP: ip}
			ok = true
		}
	} else if p.hasPass {
		got := sha256.Sum256([]byte(pass))
		if subtle.ConstantTimeCompare(got[:], p.passDigest[:]) == 1 {
			authed = principal{Actor: "admin", Role: roleAdmin, Source: "password", IP: ip}
			ok = true
		}
	}

	if !ok {
		p.fails.fail(ip, now)
		log.Printf("portal: failed sign-in from %s", ip)
		p.a.recordAudit(auditEvent{
			Actor:    username,
			Source:   "portal",
			Action:   "auth.login",
			Outcome:  "deny",
			ClientIP: ip.String(),
			Details:  map[string]any{"reason": "invalid_credentials"},
		})
		if _, lockedNow := p.fails.locked(ip, now); lockedNow {
			ipLabel := p.a.emailIPLabel(ip)
			p.a.notifyEvent(mailer.Event{
				Category:    mailer.CatSecurity,
				Severity:    mailer.SevWarn,
				Title:       "Admin portal sign-in locked out",
				Summary:     fmt.Sprintf("Client %s exceeded failed sign-in attempts and was temporarily locked out.", ipLabel),
				Fingerprint: "security:login-lockout:" + ipLabel,
				Details:     map[string]string{"client": ipLabel},
			})
		}
		p.render(c, http.StatusUnauthorized, portalPage{Title: "Sign in", Error: "Invalid portal credentials."})
		return
	}
	p.fails.reset(ip)
	pc := p.pc()
	value, _ := p.mintSessionPrincipal(now, pc.sessionTTL, authed)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     portalCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   int(pc.sessionTTL / time.Second),
		Secure:   pc.secureCookie || p.tlsCfg != nil,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	log.Printf("portal: %s signed in", authed.label())
	p.a.recordAudit(auditEvent{
		Actor:    authed.Actor,
		Role:     authed.Role.String(),
		Source:   "portal",
		Action:   "auth.login",
		Outcome:  "allow",
		ClientIP: ip.String(),
		Details:  map[string]any{"auth_source": authed.Source},
	})
	c.Redirect(http.StatusSeeOther, "/")
}

func (p *portal) logout(c *gin.Context) {
	pr := portalPrincipal(c)
	p.a.recordAudit(auditEvent{
		Actor:    pr.Actor,
		Role:     pr.Role.String(),
		Source:   "portal",
		Action:   "auth.logout",
		Outcome:  "allow",
		ClientIP: pr.IP.String(),
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name: portalCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: p.pc().secureCookie || p.tlsCfg != nil, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	c.Redirect(http.StatusSeeOther, "/")
}

type portalSessionPayload struct {
	Nonce  string `json:"n"`
	Exp    int64  `json:"e"`
	Actor  string `json:"a"`
	Role   string `json:"r"`
	Source string `json:"s"`
}

// mintSession keeps backwards compatibility for tests calling mintSession directly.
func (p *portal) mintSession(now time.Time, ttl time.Duration) (string, []byte) {
	return p.mintSessionPrincipal(now, ttl, principal{Actor: "admin", Role: roleAdmin, Source: "password"})
}

func (p *portal) mintSessionPrincipal(now time.Time, ttl time.Duration, pr principal) (string, []byte) {
	// Legacy single-password admin logins use the compact 40-byte v1 binary format.
	if pr.Source == "password" && pr.Role == roleAdmin {
		var buf [portalRawLen]byte
		_, _ = rand.Read(buf[:portalNonceLen])
		binary.BigEndian.PutUint64(buf[portalExpOff:portalBodyLen], uint64(now.Add(ttl).Unix()))
		mac := hmac.New(sha256.New, p.sessionKey)
		mac.Write(buf[:portalBodyLen])
		copy(buf[portalBodyLen:], mac.Sum(nil)[:portalMACLen])
		return base64.RawURLEncoding.EncodeToString(buf[:]), append([]byte(nil), buf[:portalNonceLen]...)
	}
	nonce := make([]byte, portalNonceLen)
	_, _ = rand.Read(nonce)
	payload, _ := json.Marshal(portalSessionPayload{
		Nonce:  base64.RawURLEncoding.EncodeToString(nonce),
		Exp:    now.Add(ttl).Unix(),
		Actor:  pr.Actor,
		Role:   pr.Role.String(),
		Source: pr.Source,
	})
	body := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, p.sessionKey)
	mac.Write([]byte("v2."))
	mac.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:portalMACLen])
	return "v2." + body + "." + sig, nonce
}

func (p *portal) verifySession(r *http.Request, now time.Time) ([]byte, bool) {
	nonce, _, ok := p.verifySessionPrincipal(r, now)
	return nonce, ok
}

func (p *portal) verifySessionPrincipal(r *http.Request, now time.Time) ([]byte, principal, bool) {
	ck, err := r.Cookie(portalCookie)
	if err != nil {
		return nil, principal{}, false
	}
	if strings.HasPrefix(ck.Value, "v2.") {
		parts := strings.Split(ck.Value, ".")
		if len(parts) != 3 {
			return nil, principal{}, false
		}
		mac := hmac.New(sha256.New, p.sessionKey)
		mac.Write([]byte("v2."))
		mac.Write([]byte(parts[1]))
		wantSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:portalMACLen])
		if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(wantSig)) != 1 {
			return nil, principal{}, false
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, principal{}, false
		}
		var sp portalSessionPayload
		if err := json.Unmarshal(raw, &sp); err != nil {
			return nil, principal{}, false
		}
		if now.Unix() >= sp.Exp {
			return nil, principal{}, false
		}
		nonce, err := base64.RawURLEncoding.DecodeString(sp.Nonce)
		if err != nil || len(nonce) != portalNonceLen {
			return nil, principal{}, false
		}
		role, ok := parseRole(sp.Role)
		if !ok {
			return nil, principal{}, false
		}
		return nonce, principal{Actor: sp.Actor, Role: role, Source: sp.Source}, true
	}
	// Legacy v1 binary session cookie fallback.
	if base64.RawURLEncoding.DecodedLen(len(ck.Value)) != portalRawLen {
		return nil, principal{}, false
	}
	var buf [portalRawLen]byte
	if n, err := base64.RawURLEncoding.Decode(buf[:], []byte(ck.Value)); err != nil || n != portalRawLen {
		return nil, principal{}, false
	}
	mac := hmac.New(sha256.New, p.sessionKey)
	mac.Write(buf[:portalBodyLen])
	if !hmac.Equal(buf[portalBodyLen:], mac.Sum(nil)[:portalMACLen]) {
		return nil, principal{}, false
	}
	if now.Unix() >= int64(binary.BigEndian.Uint64(buf[portalExpOff:portalBodyLen])) {
		return nil, principal{}, false
	}
	return append([]byte(nil), buf[:portalNonceLen]...), principal{Actor: "admin", Role: roleAdmin, Source: "password"}, true
}

func (p *portal) csrfToken(nonce []byte) string {
	mac := hmac.New(sha256.New, p.sessionKey)
	mac.Write([]byte("csrf"))
	mac.Write(nonce)
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

func (p *portal) requireSession(c *gin.Context) {
	nonce, pr, ok := p.authenticateRequest(c.Request, time.Now())
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "sign in required"})
		return
	}
	c.Set(ctxPortalNonce, nonce)
	c.Set(ctxPortalPrincipal, pr)
}

func (p *portal) requireRole(required rbacRole) gin.HandlerFunc {
	return func(c *gin.Context) {
		pr := portalPrincipal(c)
		if !pr.Role.allows(required) {
			p.a.recordAudit(auditEvent{
				Actor:    pr.Actor,
				Role:     pr.Role.String(),
				Source:   "portal",
				Action:   c.Request.Method + " " + c.Request.URL.Path,
				Outcome:  "deny",
				ClientIP: pr.IP.String(),
				Details:  map[string]any{"reason": "insufficient_role", "required": required.String()},
			})
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient role: requires " + required.String()})
			return
		}
		c.Next()
	}
}

func portalPrincipal(c *gin.Context) principal {
	if v, ok := c.Get(ctxPortalPrincipal); ok {
		if pr, ok := v.(principal); ok {
			return pr
		}
	}
	ip, _ := remoteAddr(c.Request)
	return principal{IP: ip}
}

func portalActor(c *gin.Context) string {
	return portalPrincipal(c).label()
}

func (p *portal) sessionCSRF(c *gin.Context) string {
	v, _ := c.Get(ctxPortalNonce)
	nonce, _ := v.([]byte)
	return p.csrfToken(nonce)
}

// requireCSRF protects every state-changing API call.
func (p *portal) requireCSRF(c *gin.Context) {
	if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead {
		return
	}
	got := c.GetHeader("X-CSRF-Token")
	if subtle.ConstantTimeCompare([]byte(got), []byte(p.sessionCSRF(c))) != 1 {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "missing or invalid CSRF token; reload the page"})
	}
}

func (p *portal) requireFormCSRF(c *gin.Context) {
	if subtle.ConstantTimeCompare([]byte(c.PostForm("csrf")), []byte(p.sessionCSRF(c))) != 1 {
		c.AbortWithStatus(http.StatusForbidden)
	}
}

func jsonError(c *gin.Context, status int, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"error": msg})
}
