package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
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
	assetPortalDark   = "css/portal-dark.css"
	assetPortalJS     = "js/portal.js"
)

const (
	portalCookie      = "concert_portal"
	portalNonceLen    = 16
	portalExpOff      = portalNonceLen
	portalBodyLen     = portalExpOff + 8
	portalMACLen      = 16
	portalRawLen      = portalBodyLen + portalMACLen
	minPortalPassLen  = 16
	portalMaxNotes    = 100000 // path and browser notes kept for waiting visitors
	portalQueueLimit  = 500    // visitors the queue view lists, from the front
	portalGrace       = 5 * time.Second
	loginMaxFailures  = 5
	loginWindow       = 15 * time.Minute
	loginLockout      = 15 * time.Minute
	ctxPortalNonce    = "portal.nonce"
	settingsBodyLimit = 1 << 20
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

	pass  string         // CONCERT_PORTAL_PASS; env-only
	allow []netip.Prefix // parsed allowSpec
}

// enabled reports whether the portal should be listening.
func (pc *portalConfig) enabled() bool {
	return pc.listen != "" && pc.pass != ""
}

func (pc *portalConfig) normalize() error {
	allow, err := parsePrefixes(pc.allowSpec)
	if err != nil {
		return fmt.Errorf("invalid -portal-allow: %w", err)
	}
	pc.allow = allow
	if !pc.enabled() {
		return nil
	}
	if len(pc.pass) < minPortalPassLen {
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
	a          *app
	ln         net.Listener // bound by newPortal when -portal-listen is set; served by start
	engine     *gin.Engine
	tmpl       *template.Template
	static     fs.FS
	sessionKey []byte
	passDigest [sha256.Size]byte
	notes      *noteStore
	kicked     *kickList
	fails      *loginLimiter
	history    *history // requests and bans on the main listener; see history.go
}

// newPortal builds the portal and, when -portal-listen is set, binds its
// listener. It returns nil when CONCERT_PORTAL_PASS is unset: without a pass
// there is no portal. With a pass but no address the portal exists but
// does not listen. The history is created here, restored from its log, and
// closed with the app.
func newPortal(a *app) (*portal, error) {
	cfg := a.current().cfg
	pc := cfg.portal
	if pc.pass == "" {
		if pc.listen != "" {
			log.Printf("portal disabled: set CONCERT_PORTAL_PASS to enable it on %s", pc.listen)
		}
		return nil, nil
	}

	static, err := fs.Sub(portalFS, "templates")
	if err != nil {
		return nil, fmt.Errorf("portal: %w", err)
	}
	for _, req := range []string{
		templateHeader, templateFooter, templateIndex, templateFragments,
		assetBootstrapCSS, assetIconsCSS, assetBootstrapJS,
		assetPortalLight, assetPortalDark, assetPortalJS,
	} {
		if _, err := fs.Stat(static, req); err != nil {
			return nil, fmt.Errorf("portal: templates/%s is missing", req)
		}
	}

	keyMAC := hmac.New(sha256.New, []byte(pc.pass))
	keyMAC.Write([]byte("concert/portal/session-key"))

	p := &portal{
		a:          a,
		static:     static,
		sessionKey: keyMAC.Sum(nil),
		passDigest: sha256.Sum256([]byte(pc.pass)),
		notes:      newNoteStore(portalMaxNotes),
		kicked:     &kickList{m: map[string]time.Time{}},
		fails:      &loginLimiter{m: map[netip.Addr]*loginState{}},
	}
	tmpl, err := template.New(templateIndex).Funcs(p.templateFuncs()).
		ParseFS(static, templateHeader, templateFooter, templateIndex, templateFragments)
	if err != nil {
		return nil, fmt.Errorf("portal templates: %w", err)
	}
	p.tmpl = tmpl

	p.history = newHistory(a.abuse, a.prio.grants, a.ipinfo, historyLogPath(cfg), time.Now())
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
	if p.ln != nil {
		pc := p.pc()
		ep.serveOn(p.ln, pc.listen)
		log.Printf("portal listening on %s (allowed: %s)", p.ln.Addr(), pc.allowSpec)
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

	api := r.Group("/api", p.requireSession, p.requireCSRF)
	api.GET("/overview", p.apiOverview)
	api.GET("/fastlane", func(c *gin.Context) {
		if p.a.fastlane == nil {
			c.JSON(200, gin.H{"enabled": false})
			return
		}
		c.JSON(200, p.a.fastlane.Summary())
	})
	api.GET("/queue", p.apiQueue)
	api.POST("/queue/promote", p.apiPromote)
	api.POST("/queue/kick", p.apiKick)
	api.GET("/bans", p.apiBans)
	api.POST("/bans", p.apiBanSave)
	api.DELETE("/bans", p.apiUnban)
	api.GET("/history", p.apiHistory)
	api.GET("/history/client", p.apiHistoryClient)
	api.GET("/history/ban", p.apiHistoryBan)
	api.GET("/settings", p.apiSettings)
	api.POST("/settings", p.apiSettingsSave)
	api.DELETE("/settings", p.apiSettingsReset)

	// Server-rendered tables; see fragments.go.
	api.GET("/frag/queue", p.fragQueue)
	api.GET("/frag/bans", p.fragBans)
	api.GET("/frag/visitors", p.fragVisitors)
	api.GET("/frag/visitor", p.fragVisitor)
	api.GET("/frag/banlog", p.fragBanLog)
	api.GET("/frag/ban", p.fragBan)

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
	PortalDark   string
	PortalJS     string
	Version      string
	Upstream     string
	HistoryNote  string
	IPInfo       string
	Authed       bool
}

// historyNote explains the history's limits under the Visitors tab.
func (p *portal) historyNote() string {
	persist := "A restart starts the history again (no history log: -history-log off, or -data-dir empty)."
	if p.history.log != nil {
		persist = "It is also written to " + p.history.log.path + " and restored when concert restarts."
	}
	return fmt.Sprintf("Kept in memory: the last %d requests from each of up to %s addresses, until %dh after an "+
		"address's last request; bans are kept %dh after they end. Requests from banned clients and every 4xx or 5xx "+
		"response are always recorded; successful asset and waiting-room status requests are not, as in the access log. %s",
		historyPerClient, fmtCount(historyMaxClients), int(historyRetention/time.Hour), int(historyRetention/time.Hour), persist)
}

func (p *portal) render(c *gin.Context, status int, page portalPage) {
	page.BootstrapCSS = assetBootstrapCSS
	page.IconsCSS = assetIconsCSS
	page.BootstrapJS = assetBootstrapJS
	page.PortalLight = assetPortalLight
	page.PortalDark = assetPortalDark
	page.PortalJS = assetPortalJS
	page.Version = BinaryVersion()
	page.Upstream = p.a.current().cfg.upstream
	page.HistoryNote = p.historyNote()
	page.IPInfo = p.a.ipinfo.describe()
	var buf bytes.Buffer
	if err := p.tmpl.ExecuteTemplate(&buf, templateIndex, page); err != nil {
		log.Printf("portal: render: %v", err)
		c.String(http.StatusInternalServerError, "template error")
		return
	}
	c.Data(status, "text/html; charset=utf-8", buf.Bytes())
}

func (p *portal) index(c *gin.Context) {
	if nonce, ok := p.verifySession(c.Request, time.Now()); ok {
		p.render(c, http.StatusOK, portalPage{Title: "Dashboard", Authed: true, CSRF: p.csrfToken(nonce)})
		return
	}
	p.render(c, http.StatusOK, portalPage{Title: "Sign in"})
}

func (p *portal) login(c *gin.Context) {
	ip, _ := remoteAddr(c.Request)
	now := time.Now()
	if left, locked := p.fails.locked(ip, now); locked {
		c.Header("Retry-After", strconv.Itoa(int(left/time.Second)+1))
		p.render(c, http.StatusTooManyRequests, portalPage{
			Title: "Sign in",
			Error: fmt.Sprintf("Too many failed attempts. Try again in %s.", left.Round(time.Second)),
		})
		return
	}
	got := sha256.Sum256([]byte(c.PostForm("pass")))
	if subtle.ConstantTimeCompare(got[:], p.passDigest[:]) != 1 {
		p.fails.fail(ip, now)
		log.Printf("portal: failed sign-in from %s", ip)
		p.render(c, http.StatusUnauthorized, portalPage{Title: "Sign in", Error: "That portal pass is not correct."})
		return
	}
	p.fails.reset(ip)
	pc := p.pc()
	value, _ := p.mintSession(now, pc.sessionTTL)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     portalCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   int(pc.sessionTTL / time.Second),
		Secure:   pc.secureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	log.Printf("portal: %s signed in", ip)
	c.Redirect(http.StatusSeeOther, "/")
}

func (p *portal) logout(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: portalCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: p.pc().secureCookie, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	c.Redirect(http.StatusSeeOther, "/")
}

// Session cookie: nonce(16) | expiry unix seconds(8) | HMAC(16). The key is
// derived from CONCERT_PORTAL_PASS, so changing the pass signs everyone out.
// The expiry is fixed at sign-in, so a new -portal-session-ttl applies to
// sessions started after the change.
func (p *portal) mintSession(now time.Time, ttl time.Duration) (string, []byte) {
	var buf [portalRawLen]byte
	_, _ = rand.Read(buf[:portalNonceLen])
	binary.BigEndian.PutUint64(buf[portalExpOff:portalBodyLen], uint64(now.Add(ttl).Unix()))
	mac := hmac.New(sha256.New, p.sessionKey)
	mac.Write(buf[:portalBodyLen])
	copy(buf[portalBodyLen:], mac.Sum(nil)[:portalMACLen])
	return base64.RawURLEncoding.EncodeToString(buf[:]), append([]byte(nil), buf[:portalNonceLen]...)
}

func (p *portal) verifySession(r *http.Request, now time.Time) ([]byte, bool) {
	ck, err := r.Cookie(portalCookie)
	if err != nil || base64.RawURLEncoding.DecodedLen(len(ck.Value)) != portalRawLen {
		return nil, false
	}
	var buf [portalRawLen]byte
	if n, err := base64.RawURLEncoding.Decode(buf[:], []byte(ck.Value)); err != nil || n != portalRawLen {
		return nil, false
	}
	mac := hmac.New(sha256.New, p.sessionKey)
	mac.Write(buf[:portalBodyLen])
	if !hmac.Equal(buf[portalBodyLen:], mac.Sum(nil)[:portalMACLen]) {
		return nil, false
	}
	if now.Unix() >= int64(binary.BigEndian.Uint64(buf[portalExpOff:portalBodyLen])) {
		return nil, false
	}
	return append([]byte(nil), buf[:portalNonceLen]...), true
}

func (p *portal) csrfToken(nonce []byte) string {
	mac := hmac.New(sha256.New, p.sessionKey)
	mac.Write([]byte("csrf"))
	mac.Write(nonce)
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

func (p *portal) requireSession(c *gin.Context) {
	nonce, ok := p.verifySession(c.Request, time.Now())
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "sign in required"})
		return
	}
	c.Set(ctxPortalNonce, nonce)
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

func portalActor(c *gin.Context) string {
	ip, _ := remoteAddr(c.Request)
	return ip.String()
}
