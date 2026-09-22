package main

import (
	"bufio"
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
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
// Go and passed to the templates, so the two can never disagree.
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
	portalCookie       = "concert_portal"
	portalNonceLen     = 16
	portalExpOff       = portalNonceLen
	portalBodyLen      = portalExpOff + 8
	portalMACLen       = 16
	portalRawLen       = portalBodyLen + portalMACLen
	minPortalPassLen   = 16
	portalMaxOccupants = 100000
	portalGrace        = 5 * time.Second
	statusCaptureLimit = 2048
	loginMaxFailures   = 5
	loginWindow        = 15 * time.Minute
	loginLockout       = 15 * time.Minute
	readyForgetAfter   = time.Minute
	ctxPortalNonce     = "portal.nonce"
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
// Everything but pass can change while concert runs.
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
	occupants  *occupantStore
	kicked     *kickList
	fails      *loginLimiter
}

// newPortal builds the portal and, when -portal-listen is set, binds its
// listener. It returns nil when CONCERT_PORTAL_PASS is unset: without a pass
// there is no portal, and setting one needs a restart. With a pass but no
// address the portal exists but is off, and setting -portal-listen later
// turns it on without a restart.
func newPortal(a *app) (*portal, error) {
	pc := a.current().cfg.portal
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
		templateHeader, templateFooter, templateIndex,
		assetBootstrapCSS, assetIconsCSS, assetBootstrapJS,
		assetPortalLight, assetPortalDark, assetPortalJS,
	} {
		if _, err := fs.Stat(static, req); err != nil {
			return nil, fmt.Errorf("portal: templates/%s is missing", req)
		}
	}
	tmpl, err := template.ParseFS(static, templateHeader, templateFooter, templateIndex)
	if err != nil {
		return nil, fmt.Errorf("portal templates: %w", err)
	}

	keyMAC := hmac.New(sha256.New, []byte(pc.pass))
	keyMAC.Write([]byte("concert/portal/session-key"))

	p := &portal{
		a:          a,
		tmpl:       tmpl,
		static:     static,
		sessionKey: keyMAC.Sum(nil),
		passDigest: sha256.Sum256([]byte(pc.pass)),
		occupants:  newOccupantStore(portalMaxOccupants),
		kicked:     &kickList{m: map[string]time.Time{}},
		fails:      &loginLimiter{m: map[netip.Addr]*loginState{}},
	}

	// Every new ban drops that network's waiting visitors at once.
	a.abuse.setOnBan(p.dropBanned)

	p.engine = p.routes()

	if pc.enabled() {
		ln, err := listen(pc.listen)
		if err != nil {
			return nil, fmt.Errorf("portal listen %s: %w", pc.listen, err)
		}
		p.ln = ln
	}
	return p, nil
}

// start serves the portal until ctx is cancelled and returns its endpoint,
// so later changes to -portal-listen can move it. Safe on a nil portal.
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
		log.Printf("portal off: set -portal-listen to turn it on")
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

func (p *portal) janitor(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			p.occupants.sweep(now, p.a.room.TokenTTL(), readyForgetAfter)
			p.kicked.sweep(now)
			p.fails.sweep(now)
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
	api.GET("/queue", p.apiQueue)
	api.POST("/queue/promote", p.apiPromote)
	api.POST("/queue/kick", p.apiKick)
	api.GET("/bans", p.apiBans)
	api.POST("/bans", p.apiBanSave)
	api.DELETE("/bans", p.apiUnban)
	api.GET("/settings", p.apiSettings)
	api.POST("/settings", p.apiSettingsSave)
	api.DELETE("/settings", p.apiSettingsReset)

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
	Authed       bool
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

// ─── API: overview ───────────────────────────────────────────────────────────

func (p *portal) apiOverview(c *gin.Context) {
	a, g := p.a, p.a.current()
	wr, stats := a.room, a.stats
	rate, surge := a.pricing()
	c.JSON(http.StatusOK, gin.H{
		"cap":                          wr.Cap(),
		"occupancy":                    wr.Len(),
		"queue_depth":                  wr.QueueDepth(),
		"live_queue_depth":             wr.LiveQueueDepth(),
		"max_queue_depth":              wr.MaxQueueDepth(),
		"utilization":                  wr.UtilizationSmoothed(),
		"queued_total":                 stats.queued.Load(),
		"evicted_total":                stats.evicted.Load(),
		"timeouts_total":               stats.timeouts.Load(),
		"promoted_total":               stats.promoted.Load(),
		"asset_cap":                    g.assets.global.Cap(),
		"asset_in_flight":              g.assets.global.Len(),
		"asset_users":                  g.assets.users.count.Load(),
		"asset_served_total":           stats.assetServed.Load(),
		"asset_denied_total":           stats.assetDenied.Load(),
		"asset_user_throttled_total":   stats.assetUserThrottled.Load(),
		"asset_global_throttled_total": stats.assetGlobalThrottled.Load(),
		"abuse_enabled":                g.abuse != nil,
		"abuse_tracked":                g.abuse.tracked(),
		"abuse_range_bans":             g.abuse.rangeCount(),
		"abuse_strikes_total":          stats.abuseStrikes.Load(),
		"abuse_bans_total":             stats.abuseBans.Load(),
		"abuse_rejected_total":         stats.abuseRejected.Load(),
		"abuse_dropped_total":          stats.abuseDropped.Load(),
		"active_bans":                  len(g.abuse.bans(time.Now())),
		"occupants_tracked":            p.occupants.count(),
		"occupants_dropped":            p.occupants.dropped.Load(),
		"kicked_active":                p.kicked.count(),
		"rate":                         rate,
		"surge":                        surge,
		"skip_url":                     wr.SkipURL(),
	})
}

// ─── API: queue ──────────────────────────────────────────────────────────────

func (p *portal) apiQueue(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"occupants":        p.occupants.list(time.Now()),
		"tracked":          p.occupants.count(),
		"dropped":          p.occupants.dropped.Load(),
		"kicked":           p.kicked.count(),
		"live_queue_depth": p.a.room.LiveQueueDepth(),
	})
}

type occupantAction struct {
	ID  string `json:"id"`
	Ban bool   `json:"ban"`
}

func (p *portal) apiPromote(c *gin.Context) {
	var body occupantAction
	if err := c.ShouldBindJSON(&body); err != nil || body.ID == "" {
		jsonError(c, http.StatusBadRequest, "id is required")
		return
	}
	occ, ok := p.occupants.find(body.ID)
	if !ok {
		jsonError(c, http.StatusNotFound, "that visitor is no longer in line")
		return
	}
	if _, err := p.a.room.PromoteTokenToFront(occ.token); err != nil {
		jsonError(c, http.StatusConflict, "room refused the promotion: "+err.Error())
		return
	}
	p.occupants.setPosition(occ.token, 1)
	log.Printf("portal: %s moved %s (%s) to the front", portalActor(c), occ.id, occ.ip)
	c.JSON(http.StatusOK, gin.H{"promoted": occ.id})
}

func (p *portal) apiKick(c *gin.Context) {
	var body occupantAction
	if err := c.ShouldBindJSON(&body); err != nil || body.ID == "" {
		jsonError(c, http.StatusBadRequest, "id is required")
		return
	}
	occ, ok := p.occupants.find(body.ID)
	if !ok {
		jsonError(c, http.StatusNotFound, "that visitor is no longer in line")
		return
	}

	now := time.Now()
	var banFor time.Duration
	if body.Ban {
		reg := p.a.current().abuse
		if reg == nil {
			jsonError(c, http.StatusConflict, errAbuseDisabled.Error())
			return
		}
		left, banned := reg.banNow(occ.ip, now)
		if !banned {
			jsonError(c, http.StatusConflict, errClientExempt.Error())
			return
		}
		banFor = left
		p.a.saveBansNow()
	}

	p.kicked.add(occ.token, now.Add(p.a.room.TokenTTL()+time.Minute))
	p.occupants.remove(occ.token)
	releaseTicket(p.a.room, occ.token)
	log.Printf("portal: %s removed %s (%s) from the line, ban=%v", portalActor(c), occ.id, occ.ip, body.Ban)
	secs := int(banFor / time.Second)
	if banFor == banForeverLeft {
		secs = 0
	}
	c.JSON(http.StatusOK, gin.H{
		"kicked":      occ.id,
		"banned":      body.Ban,
		"ban_seconds": secs,
	})
}

// ─── API: bans ───────────────────────────────────────────────────────────────

func (p *portal) apiBans(c *gin.Context) {
	reg := p.a.current().abuse
	c.JSON(http.StatusOK, gin.H{
		"enabled":   reg != nil,
		"tracked":   reg.tracked(),
		"ranges":    reg.rangeCount(),
		"persisted": p.a.bansPath != "",
		"bans":      reg.bans(time.Now()),
	})
}

// apiBanSave creates a ban or replaces an existing one. The client may be a
// single address (IPv6 is banned by its /64) or a CIDR range such as
// 203.0.0.0/16. A permanent ban lasts until it is lifted. Waiting visitors
// the ban covers are dropped from the line at once; "dropped" counts them.
func (p *portal) apiBanSave(c *gin.Context) {
	var body struct {
		Client    string `json:"client"`
		Duration  string `json:"duration"`
		Permanent bool   `json:"permanent"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		jsonError(c, http.StatusBadRequest, "client and duration are required")
		return
	}
	reg := p.a.current().abuse
	if reg == nil {
		jsonError(c, http.StatusConflict, errAbuseDisabled.Error())
		return
	}
	target, err := parseBanTarget(body.Client)
	if err != nil {
		jsonError(c, http.StatusBadRequest, err.Error())
		return
	}
	var d time.Duration // 0 = permanent
	if !body.Permanent {
		d, err = time.ParseDuration(strings.TrimSpace(body.Duration))
		if err != nil || d < time.Minute || d > 365*24*time.Hour {
			jsonError(c, http.StatusBadRequest, "duration must be between 1m and 8760h, for example 30m or 24h, or the ban must be permanent")
			return
		}
	}
	now := time.Now()
	var until any
	if !body.Permanent {
		until = now.Add(d).UTC()
	}
	lasting := "permanently"
	if !body.Permanent {
		lasting = "for " + d.String()
	}

	// Counted before the ban, because the ban removes them from the line.
	dropped := p.occupants.countWhere(p.inScope(target.scope()))

	if target.single {
		key, err := reg.banFor(target.prefix.Addr(), d, now)
		switch {
		case errors.Is(err, errAbuseDisabled), errors.Is(err, errClientExempt), errors.Is(err, errRegistryFull):
			jsonError(c, http.StatusConflict, err.Error())
			return
		case err != nil:
			jsonError(c, http.StatusBadRequest, err.Error())
			return
		}
		p.a.saveBansNow()
		log.Printf("portal: %s banned %s %s, dropped %d waiting", portalActor(c), displayKey(key), lasting, dropped)
		c.JSON(http.StatusOK, gin.H{
			"client":    displayKey(key),
			"until":     until,
			"range":     false,
			"permanent": body.Permanent,
			"dropped":   dropped,
		})
		return
	}

	if err := reg.banRange(target.prefix, d, now); err != nil {
		jsonError(c, http.StatusConflict, err.Error())
		return
	}
	p.a.saveBansNow()
	exempt := reg.exemptWithin(target.prefix)
	log.Printf("portal: %s banned range %s %s, dropped %d waiting (exempt within: %v)",
		portalActor(c), target.prefix, lasting, dropped, exempt)
	c.JSON(http.StatusOK, gin.H{
		"client":        target.prefix.String(),
		"until":         until,
		"range":         true,
		"permanent":     body.Permanent,
		"dropped":       dropped,
		"exempt_within": exempt,
	})
}

func (p *portal) apiUnban(c *gin.Context) {
	reg := p.a.current().abuse
	if reg == nil {
		jsonError(c, http.StatusConflict, errAbuseDisabled.Error())
		return
	}
	target, err := parseBanTarget(c.Query("client"))
	if err != nil {
		jsonError(c, http.StatusBadRequest, err.Error())
		return
	}
	if !reg.unbanTarget(target) {
		jsonError(c, http.StatusNotFound, "that client is not tracked")
		return
	}
	p.a.saveBansNow()
	log.Printf("portal: %s unbanned %s", portalActor(c), target)
	c.JSON(http.StatusOK, gin.H{"unbanned": target.String()})
}

// ─── API: settings ───────────────────────────────────────────────────────────

func (p *portal) settingsView() gin.H {
	views, file := p.a.settingsViews()
	return gin.H{
		"settings":  views,
		"persisted": file != "",
		"file":      file,
		"fixed":     p.a.fixedSettings(),
	}
}

func (p *portal) apiSettings(c *gin.Context) {
	c.JSON(http.StatusOK, p.settingsView())
}

// apiSettingsSave takes a JSON object of setting keys to new values, for
// example {"cap": 40, "abuse_cooldown": "10m"}, and applies them at once.
// Every value is validated before any is saved or applied; see
// app.changeSettings.
func (p *portal) apiSettingsSave(c *gin.Context) {
	var set map[string]json.RawMessage
	if err := json.NewDecoder(io.LimitReader(c.Request.Body, settingsBodyLimit)).Decode(&set); err != nil || len(set) == 0 {
		jsonError(c, http.StatusBadRequest, "send a JSON object of the settings to change")
		return
	}
	ip, _ := remoteAddr(c.Request)
	if err := p.a.changeSettings(set, nil, ip); err != nil {
		jsonError(c, settingsStatus(err), err.Error())
		return
	}
	log.Printf("portal: %s changed settings: %s", portalActor(c), strings.Join(sortedKeys(set), ", "))
	c.JSON(http.StatusOK, p.settingsView())
}

// apiSettingsReset removes ?key=… (repeatable) from settings.json, so those
// settings follow flags, environment or defaults again, and applies them.
func (p *portal) apiSettingsReset(c *gin.Context) {
	keys := c.QueryArray("key")
	if len(keys) == 0 {
		jsonError(c, http.StatusBadRequest, "key is required")
		return
	}
	ip, _ := remoteAddr(c.Request)
	if err := p.a.changeSettings(nil, keys, ip); err != nil {
		jsonError(c, settingsStatus(err), err.Error())
		return
	}
	log.Printf("portal: %s reset settings: %s", portalActor(c), strings.Join(keys, ", "))
	c.JSON(http.StatusOK, p.settingsView())
}

// ─── dropping banned visitors ────────────────────────────────────────────────

// inScope matches waiting visitors a ban on scope covers. Exempt addresses
// stay reachable inside a banned range, so they are never matched.
func (p *portal) inScope(scope netip.Prefix) func(*occupant) bool {
	return func(o *occupant) bool {
		ip := o.ip.Unmap()
		return ip.IsValid() && scope.Contains(ip) && !p.a.abuse.isExempt(ip)
	}
}

// dropBanned is the abuse registry's ban callback. It removes every waiting
// visitor the ban covers from the line and invalidates their tickets, so an
// unban means rejoining at the back. The visitors' next status poll is
// answered by the ban check (see generation.rejectBanned) and their page
// reloads into the block notice. It runs outside every registry lock.
func (p *portal) dropBanned(scope netip.Prefix) {
	dropped := p.occupants.removeWhere(p.inScope(scope))
	if len(dropped) == 0 {
		return
	}
	until := time.Now().Add(p.a.room.TokenTTL() + time.Minute)
	for _, o := range dropped {
		p.kicked.add(o.token, until)
		releaseTicket(p.a.room, o.token)
	}
	log.Printf("portal: ban on %s dropped %d waiting visitor(s)", scope, len(dropped))
}

// ticketRemover is a waiting room that can release a ticket immediately.
// room v1.2.1 has no such call, so a dropped visitor's ticket still counts
// in room's queue_depth until the reaper removes it. When room gains
// RemoveToken with this signature, releaseTicket starts using it with no
// other change.
type ticketRemover interface {
	RemoveToken(token string) error
}

func releaseTicket(wr any, token string) {
	if r, ok := wr.(ticketRemover); ok {
		_ = r.RemoveToken(token)
	}
}

// ─── queue tracking on the main listener ─────────────────────────────────────

// wrap observes gated traffic on the main listener to maintain the portal's
// view of the line, and enforces kicks. Asset, bypass and ops paths are
// passed straight through: room never issues tickets there.
func (p *portal) wrap(next http.Handler) http.Handler {
	if p == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g := p.a.current()
		reqPath := r.URL.Path
		for _, rule := range g.untracked {
			if rule.matches(reqPath) {
				next.ServeHTTP(w, r)
				return
			}
		}

		now := time.Now()
		ip := clientIP(r, g.cfg.trusted)
		var token string
		if ck, err := r.Cookie("room_ticket"); err == nil {
			token = ck.Value
		}
		isStatus := reqPath == "/queue/status"
		if token != "" && p.kicked.has(token, now) {
			// A banned visitor is answered by the ban check in the main
			// handler, which shows the block notice rather than the removal notice.
			if _, banned := g.abuse.banned(ip, now); !banned {
				p.rejectKicked(w, r, isStatus, g.cfg)
				return
			}
		}

		tw := &trackWriter{ResponseWriter: w, capture: isStatus && token != ""}
		next.ServeHTTP(tw, r)
		tw.inspect()

		switch {
		case tw.issued != "":
			p.occupants.join(tw.issued, ip, r.UserAgent(), reqPath, now)
		case token != "":
			p.occupants.touch(token, ip, now)
		}
		if tw.capture && tw.status == http.StatusOK {
			p.occupants.observe(token, tw.body.Bytes(), now)
		}
	})
}

// rejectKicked answers a removed visitor. Status polls get ready=true so the
// waiting room page reloads; the reload gets the removal notice and the
// ticket cookie is cleared, so returning means rejoining at the back.
func (p *portal) rejectKicked(w http.ResponseWriter, r *http.Request, isStatus bool, cfg config) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	if isStatus {
		h.Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ready":true}`))
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "room_ticket", Value: "", Path: cfg.cookiePath, Domain: cfg.cookieDomain,
		MaxAge: -1, Secure: cfg.secureCookie, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	if wantsHTML(r) {
		h.Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(kickedPage))
		return
	}
	h.Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"removed from the queue","removed":true}`))
}

const kickedPage = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Removed from the line</title></head>
<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem;text-align:center">
<h1>You were removed from the line</h1>
<p>An administrator removed your place in the queue. You can rejoin at the back.</p>
<p><a href="/">Rejoin the line</a></p></body></html>`

// trackWriter notes the room_ticket a response issues and, for status polls,
// captures the small JSON body. It forwards Flush and Hijack because gin
// type-asserts the writer it wraps, and streaming and upgrades must survive.
// Client disconnects are observed through the request context, so the
// deprecated http.CloseNotifier is intentionally not implemented.
type trackWriter struct {
	http.ResponseWriter
	capture   bool
	body      bytes.Buffer
	status    int
	inspected bool
	issued    string
}

func (w *trackWriter) inspect() {
	if w.inspected {
		return
	}
	w.inspected = true
	for _, v := range w.Header().Values("Set-Cookie") {
		if !strings.HasPrefix(v, "room_ticket=") {
			continue
		}
		val := strings.TrimPrefix(v, "room_ticket=")
		if i := strings.IndexByte(val, ';'); i >= 0 {
			val = val[:i]
		}
		if val != "" {
			w.issued = val
		}
	}
}

func (w *trackWriter) WriteHeader(code int) {
	w.inspect()
	if w.status == 0 && code >= 200 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *trackWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.inspect()
		w.status = http.StatusOK
	}
	if w.capture && w.body.Len()+len(b) <= statusCaptureLimit {
		w.body.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *trackWriter) Flush() {
	w.inspect()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *trackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.inspect()
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (w *trackWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ─── occupant store ──────────────────────────────────────────────────────────

type occupant struct {
	id       string
	token    string
	ip       netip.Addr
	ua       string
	path     string
	joined   time.Time
	lastSeen time.Time
	position int64 // 0 until the first status poll
	ready    bool
	hasPass  bool
}

type occupantView struct {
	ID          string    `json:"id"`
	Client      string    `json:"client"`
	UserAgent   string    `json:"user_agent"`
	Path        string    `json:"path"`
	Joined      time.Time `json:"joined"`
	LastSeen    time.Time `json:"last_seen"`
	IdleSeconds int       `json:"idle_seconds"`
	Position    int64     `json:"position"`
	Ready       bool      `json:"ready"`
	HasPass     bool      `json:"has_pass"`
}

// occupantStore is the portal's view of the line. Raw tickets never leave
// it; the UI addresses visitors by an opaque ID derived from the ticket.
type occupantStore struct {
	mu      sync.Mutex
	byToken map[string]*occupant
	byID    map[string]*occupant
	max     int
	dropped atomic.Int64
}

func newOccupantStore(max int) *occupantStore {
	return &occupantStore{byToken: map[string]*occupant{}, byID: map[string]*occupant{}, max: max}
}

func occupantID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *occupantStore) join(token string, ip netip.Addr, ua, reqPath string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if o := s.byToken[token]; o != nil {
		o.lastSeen, o.ip = now, ip
		return
	}
	if len(s.byToken) >= s.max {
		s.dropped.Add(1)
		return
	}
	o := &occupant{
		id: occupantID(token), token: token, ip: ip,
		ua: clip(ua, 256), path: clip(reqPath, 256),
		joined: now, lastSeen: now,
	}
	s.byToken[token] = o
	s.byID[o.id] = o
}

func (s *occupantStore) touch(token string, ip netip.Addr, now time.Time) {
	s.mu.Lock()
	if o := s.byToken[token]; o != nil {
		o.lastSeen, o.ip = now, ip
	}
	s.mu.Unlock()
}

// observe records what room told the visitor in its status reply.
func (s *occupantStore) observe(token string, body []byte, now time.Time) {
	var st struct {
		Ready    bool  `json:"ready"`
		Position int64 `json:"position"`
		HasPass  bool  `json:"has_pass"`
	}
	if json.Unmarshal(body, &st) != nil {
		return
	}
	s.mu.Lock()
	if o := s.byToken[token]; o != nil {
		o.lastSeen, o.ready, o.hasPass = now, st.Ready, st.HasPass
		if st.Position > 0 {
			o.position = st.Position
		}
	}
	s.mu.Unlock()
}

func (s *occupantStore) setPosition(token string, pos int64) {
	s.mu.Lock()
	if o := s.byToken[token]; o != nil {
		o.position = pos
	}
	s.mu.Unlock()
}

func (s *occupantStore) find(id string) (occupant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if o := s.byID[id]; o != nil {
		return *o, true
	}
	return occupant{}, false
}

func (s *occupantStore) remove(token string) {
	s.mu.Lock()
	if o := s.byToken[token]; o != nil {
		delete(s.byToken, token)
		delete(s.byID, o.id)
	}
	s.mu.Unlock()
}

// removeWhere removes and returns every visitor match accepts.
func (s *occupantStore) removeWhere(match func(*occupant) bool) []occupant {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []occupant
	for token, o := range s.byToken {
		if match(o) {
			out = append(out, *o)
			delete(s.byToken, token)
			delete(s.byID, o.id)
		}
	}
	return out
}

// countWhere counts the visitors match accepts.
func (s *occupantStore) countWhere(match func(*occupant) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, o := range s.byToken {
		if match(o) {
			n++
		}
	}
	return n
}

func (s *occupantStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byToken)
}

// list returns visitors in line order; unknown positions sort last by arrival.
func (s *occupantStore) list(now time.Time) []occupantView {
	s.mu.Lock()
	out := make([]occupantView, 0, len(s.byToken))
	for _, o := range s.byToken {
		out = append(out, occupantView{
			ID: o.id, Client: o.ip.String(), UserAgent: o.ua, Path: o.path,
			Joined: o.joined.UTC(), LastSeen: o.lastSeen.UTC(),
			IdleSeconds: int(now.Sub(o.lastSeen) / time.Second),
			Position:    o.position, Ready: o.ready, HasPass: o.hasPass,
		})
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		pi, pj := out[i].Position, out[j].Position
		switch {
		case pi > 0 && pj > 0 && pi != pj:
			return pi < pj
		case (pi > 0) != (pj > 0):
			return pi > 0
		}
		return out[i].Joined.Before(out[j].Joined)
	})
	return out
}

// sweep forgets visitors room itself would have reaped, and admitted
// visitors shortly after their last poll.
func (s *occupantStore) sweep(now time.Time, idle, readyIdle time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for token, o := range s.byToken {
		since := now.Sub(o.lastSeen)
		if since > idle || (o.ready && since > readyIdle) {
			delete(s.byToken, token)
			delete(s.byID, o.id)
			n++
		}
	}
	return n
}

// ─── kick list ───────────────────────────────────────────────────────────────

type kickList struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func (k *kickList) add(token string, until time.Time) {
	k.mu.Lock()
	k.m[token] = until
	k.mu.Unlock()
}

func (k *kickList) has(token string, now time.Time) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	until, ok := k.m[token]
	if ok && !now.Before(until) {
		delete(k.m, token)
		return false
	}
	return ok
}

func (k *kickList) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}

func (k *kickList) sweep(now time.Time) {
	k.mu.Lock()
	for t, until := range k.m {
		if !now.Before(until) {
			delete(k.m, t)
		}
	}
	k.mu.Unlock()
}

// ─── sign-in limiter ─────────────────────────────────────────────────────────

type loginState struct {
	fails       int
	first       time.Time
	lockedUntil time.Time
}

type loginLimiter struct {
	mu sync.Mutex
	m  map[netip.Addr]*loginState
}

func (l *loginLimiter) locked(ip netip.Addr, now time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s := l.m[ip]; s != nil && now.Before(s.lockedUntil) {
		return s.lockedUntil.Sub(now), true
	}
	return 0, false
}

func (l *loginLimiter) fail(ip netip.Addr, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.m[ip]
	if s == nil || now.Sub(s.first) > loginWindow {
		s = &loginState{first: now}
		l.m[ip] = s
	}
	s.fails++
	if s.fails >= loginMaxFailures {
		s.lockedUntil = now.Add(loginLockout)
		s.fails = 0
		s.first = now
	}
}

func (l *loginLimiter) reset(ip netip.Addr) {
	l.mu.Lock()
	delete(l.m, ip)
	l.mu.Unlock()
}

func (l *loginLimiter) sweep(now time.Time) {
	l.mu.Lock()
	for ip, s := range l.m {
		if now.After(s.lockedUntil) && now.Sub(s.first) > loginWindow {
			delete(l.m, ip)
		}
	}
	l.mu.Unlock()
}

func (l *loginLimiter) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}
