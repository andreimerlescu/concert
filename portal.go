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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/room"
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
// does not listen.
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
		notes:      newNoteStore(portalMaxNotes),
		kicked:     &kickList{m: map[string]time.Time{}},
		fails:      &loginLimiter{m: map[netip.Addr]*loginState{}},
		history:    newHistory(a.abuse, time.Now()),
	}
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
		"first_poll_grace":             wr.FirstPollGrace().String(),
		"queued_total":                 stats.queued.Load(),
		"evicted_total":                stats.evicted.Load(),
		"timeouts_total":               stats.timeouts.Load(),
		"promoted_total":               stats.promoted.Load(),
		"removed_total":                stats.removed.Load(),
		"asset_cap":                    g.assets.global.Cap(),
		"asset_in_flight":              g.assets.global.Len(),
		"asset_users":                  g.assets.users.count.Load(),
		"asset_served_total":           stats.assetServed.Load(),
		"asset_denied_total":           stats.assetDenied.Load(),
		"asset_user_throttled_total":   stats.assetUserThrottled.Load(),
		"asset_global_throttled_total": stats.assetGlobalThrottled.Load(),
		"stream_cap":                   g.streams.sem.Cap(),
		"stream_active":                g.streams.sem.Len(),
		"stream_served_total":          stats.streamServed.Load(),
		"stream_denied_total":          stats.streamDenied.Load(),
		"stream_throttled_total":       stats.streamThrottled.Load(),
		"abuse_enabled":                g.abuse != nil,
		"abuse_tracked":                g.abuse.tracked(),
		"abuse_range_bans":             g.abuse.rangeCount(),
		"abuse_strikes_total":          stats.abuseStrikes.Load(),
		"abuse_bans_total":             stats.abuseBans.Load(),
		"abuse_rejected_total":         stats.abuseRejected.Load(),
		"abuse_dropped_total":          stats.abuseDropped.Load(),
		"active_bans":                  len(g.abuse.bans(time.Now())),
		"notes_tracked":                p.notes.count(),
		"notes_dropped":                p.notes.dropped.Load(),
		"kicked_active":                p.kicked.count(),
		"history_clients":              p.history.count.Load(),
		"rate":                         rate,
		"surge":                        surge,
		"skip_url":                     wr.SkipURL(),
	})
}

// ─── API: queue ──────────────────────────────────────────────────────────────

// occupantView is one waiting visitor as the portal shows it. Raw tickets
// never leave concert; the UI addresses visitors by an opaque ID derived
// from the ticket.
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
	Promoted    bool      `json:"promoted"`
}

func occupantID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}

// queueViews lists the front of room's line, in line order, with the path
// and browser noted when each visitor joined.
func (p *portal) queueViews(now time.Time) []occupantView {
	line := p.a.room.Queue(portalQueueLimit)
	out := make([]occupantView, 0, len(line))
	for _, t := range line {
		note, _ := p.notes.get(t.Token)
		out = append(out, occupantView{
			ID:          occupantID(t.Token),
			Client:      t.ClientKey,
			UserAgent:   note.ua,
			Path:        note.path,
			Joined:      t.IssuedAt.UTC(),
			LastSeen:    t.LastSeen.UTC(),
			IdleSeconds: int(now.Sub(t.LastSeen) / time.Second),
			Position:    t.Position,
			Ready:       t.Position <= 0,
			HasPass:     t.HasPass,
			Promoted:    t.Promoted,
		})
	}
	return out
}

// lookup finds a listed visitor by the ID the UI shows. Only visitors the
// queue view lists can be acted on.
func (p *portal) lookup(id string) (room.TicketInfo, bool) {
	for _, t := range p.a.room.Queue(portalQueueLimit) {
		if occupantID(t.Token) == id {
			return t, true
		}
	}
	return room.TicketInfo{}, false
}

func (p *portal) apiQueue(c *gin.Context) {
	list := p.queueViews(time.Now())
	c.JSON(http.StatusOK, gin.H{
		"occupants":        list,
		"listed":           len(list),
		"limit":            portalQueueLimit,
		"kicked":           p.kicked.count(),
		"live_queue_depth": p.a.room.LiveQueueDepth(),
	})
}

type occupantAction struct {
	ID  string `json:"id"`
	Ban bool   `json:"ban"`
}

// apiPromote moves a visitor to the front of the line. It is an operator
// promotion: no price, and no VIP pass, because only the visitor's own
// response could carry the pass cookie.
func (p *portal) apiPromote(c *gin.Context) {
	var body occupantAction
	if err := c.ShouldBindJSON(&body); err != nil || body.ID == "" {
		jsonError(c, http.StatusBadRequest, "id is required")
		return
	}
	t, ok := p.lookup(body.ID)
	if !ok {
		jsonError(c, http.StatusNotFound, "that visitor is no longer in line")
		return
	}
	if err := p.a.room.AdminPromote(t.Token, 1); err != nil {
		jsonError(c, http.StatusConflict, "room refused the promotion: "+err.Error())
		return
	}
	log.Printf("portal: %s moved %s (%s) to the front", portalActor(c), body.ID, t.ClientKey)
	c.JSON(http.StatusOK, gin.H{"promoted": body.ID})
}

// apiKick removes a visitor from the line and, with ban, bans their address.
// A removed visitor's next poll reloads their page into a removal notice,
// and they can rejoin at the back. A banned visitor's reload shows the block
// notice, and the ban drops everyone else waiting from the same address.
func (p *portal) apiKick(c *gin.Context) {
	var body occupantAction
	if err := c.ShouldBindJSON(&body); err != nil || body.ID == "" {
		jsonError(c, http.StatusBadRequest, "id is required")
		return
	}
	t, ok := p.lookup(body.ID)
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
		ip, err := netip.ParseAddr(t.ClientKey)
		if err != nil {
			jsonError(c, http.StatusConflict, "concert has no address for that visitor")
			return
		}
		left, banned := reg.banNow(ip, now)
		if !banned {
			jsonError(c, http.StatusConflict, errClientExempt.Error())
			return
		}
		banFor = left
		if k, ok := abuseKey(ip); ok {
			p.history.noteSource(keyPrefix(k), "removed from the line and banned in the portal by "+portalActor(c))
		}
		p.a.saveBansNow()
	} else {
		p.kicked.add(t.Token, now.Add(p.a.room.TokenTTL()+time.Minute))
	}

	if err := p.a.room.RemoveToken(t.Token); err != nil {
		var notFound room.ErrTokenNotFound
		if !errors.As(err, &notFound) {
			log.Printf("portal: removing %s: %v", body.ID, err)
		}
	}
	p.notes.remove(t.Token)
	log.Printf("portal: %s removed %s (%s) from the line, ban=%v", portalActor(c), body.ID, t.ClientKey, body.Ban)

	secs := int(banFor / time.Second)
	if banFor == banForeverLeft {
		secs = 0
	}
	c.JSON(http.StatusOK, gin.H{
		"kicked":      body.ID,
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
// the ban covers are removed from the line at once; "dropped" counts them.
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
	source := "banned in the portal by " + portalActor(c)

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
		p.history.noteSource(target.scope(), source)
		// The ban's own drop runs moments later in a batch; removing now
		// gives the operator an exact count. The batch catches anyone who
		// joined in between.
		dropped := p.a.dropWaiting(target.scope())
		p.a.saveBansNow()
		log.Printf("portal: %s banned %s %s, removed %d waiting", portalActor(c), displayKey(key), lasting, dropped)
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
	p.history.noteSource(target.scope(), source)
	dropped := p.a.dropWaiting(target.scope())
	p.a.saveBansNow()
	exempt := reg.exemptWithin(target.prefix)
	log.Printf("portal: %s banned range %s %s, removed %d waiting (exempt within: %v)",
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
	p.history.lifted(target.scope(), time.Now(), "the portal ("+portalActor(c)+")")
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

// ─── the main listener: history, kicks and visitor notes ─────────────────────

// wrap records every request on the main listener in the history (see
// history.go), enforces kicks, and notes the path and browser of each
// visitor who joins the line. It sits outside the main handler, so it also
// sees requests from banned clients, which the access log never does.
func (p *portal) wrap(next http.Handler) http.Handler {
	if p == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g := p.a.current()
		hw := p.history.begin(w, r, g)
		defer hw.finish()
		p.serveMain(hw, r, g, next)
	})
}

// serveMain enforces kicks and notes visitors joining the line. Asset,
// bypass, stream and ops paths are passed straight through: room never
// issues tickets there.
//
// Everything else about the line comes from room itself. The only thing
// read from responses is a room_ticket value different from the one the
// request carried, which is a visitor joining the line; room's refreshes of
// an existing ticket send the same value and are ignored.
func (p *portal) serveMain(w http.ResponseWriter, r *http.Request, g *generation, next http.Handler) {
	reqPath := r.URL.Path
	for _, rule := range g.untracked {
		if rule.matches(reqPath) {
			next.ServeHTTP(w, r)
			return
		}
	}

	now := time.Now()
	var token string
	if ck, err := r.Cookie("room_ticket"); err == nil {
		token = ck.Value
	}
	isStatus := reqPath == "/queue/status"
	if token != "" && p.kicked.has(token, now) {
		// A banned visitor is answered by the ban check in the main
		// handler, which shows the block notice rather than the removal notice.
		if _, banned := g.abuse.banned(clientIP(r, g.cfg.trusted), now); !banned {
			p.rejectKicked(w, r, isStatus, g.cfg)
			return
		}
	}
	if isStatus {
		next.ServeHTTP(w, r)
		return
	}

	tw := &ticketWriter{ResponseWriter: w}
	next.ServeHTTP(tw, r)
	tw.inspect()
	if tw.issued != "" && tw.issued != token {
		p.notes.add(tw.issued, r.UserAgent(), reqPath)
	}
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

// ticketWriter notes the room_ticket value a response sets. It forwards
// Flush and Hijack because gin type-asserts the writer it wraps, and
// streaming and upgrades must survive. Client disconnects are observed
// through the request context, so the deprecated http.CloseNotifier is
// intentionally not implemented.
type ticketWriter struct {
	http.ResponseWriter
	inspected bool
	issued    string
}

func (w *ticketWriter) inspect() {
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

func (w *ticketWriter) WriteHeader(code int) {
	w.inspect()
	w.ResponseWriter.WriteHeader(code)
}

func (w *ticketWriter) Write(b []byte) (int, error) {
	w.inspect()
	return w.ResponseWriter.Write(b)
}

func (w *ticketWriter) Flush() {
	w.inspect()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *ticketWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.inspect()
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (w *ticketWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ─── visitor notes ───────────────────────────────────────────────────────────

// visitorNote is what room does not know about a waiting visitor: the path
// they asked for and their browser. Display only.
type visitorNote struct {
	ua   string
	path string
}

// noteStore keeps notes by ticket, at most max of them. The janitor forgets
// notes for tickets room no longer holds.
type noteStore struct {
	mu      sync.Mutex
	m       map[string]visitorNote
	max     int
	dropped atomic.Int64
}

func newNoteStore(max int) *noteStore {
	return &noteStore{m: map[string]visitorNote{}, max: max}
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *noteStore) add(token, ua, reqPath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[token]; ok {
		return
	}
	if len(s.m) >= s.max {
		s.dropped.Add(1)
		return
	}
	s.m[token] = visitorNote{ua: clip(ua, 256), path: clip(reqPath, 256)}
}

func (s *noteStore) get(token string) (visitorNote, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.m[token]
	return n, ok
}

func (s *noteStore) remove(token string) {
	s.mu.Lock()
	delete(s.m, token)
	s.mu.Unlock()
}

func (s *noteStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// prune forgets every note whose ticket keep rejects. keep is called
// without the store's lock held.
func (s *noteStore) prune(keep func(token string) bool) int {
	s.mu.Lock()
	tokens := make([]string, 0, len(s.m))
	for t := range s.m {
		tokens = append(tokens, t)
	}
	s.mu.Unlock()

	var gone []string
	for _, t := range tokens {
		if !keep(t) {
			gone = append(gone, t)
		}
	}
	if len(gone) == 0 {
		return 0
	}
	s.mu.Lock()
	for _, t := range gone {
		delete(s.m, t)
	}
	s.mu.Unlock()
	return len(gone)
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
