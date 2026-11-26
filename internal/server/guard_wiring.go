package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/concert/internal/guard"
	"github.com/gin-gonic/gin"
)

const (
	challengeVerifyPath = "/_concert/challenge/verify"
	challengeCSP        = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)

// guardState bundles all per-generation host-protection guardrails from
// internal/guard: per-IP waiting-room queue quotas, host memory/FD/connection
// shedding, declarative per-route token-bucket rate limits, Geo/ASN policies,
// and pre-ticket PoW / Turnstile bot challenges.
type guardState struct {
	quota         *guard.QueueQuota
	quotaMax      int
	quotaAllowMax int
	shedder       *guard.HostShedder
	routeLimiter  *guard.RouteLimiter
	geoPolicy     *guard.GeoASNPolicy
	challenge     *guard.ChallengeGate
	provSeq       atomic.Uint64
}

// buildGuardState constructs or carries over the generation's guardrails from
// next. Unchanged stateful guardrails (queue quota, host shedder, route
// limiter, challenge gate) are carried over from prev so reload preserves
// active counters and background samplers without leaks (R2).
func buildGuardState(next config, prev *generation, a *app) (*guardState, error) {
	var pg *guardState
	if prev != nil {
		pg = prev.guard
	}
	gs := &guardState{
		quotaMax:      next.maxQueuePerIP,
		quotaAllowMax: next.allowMaxQueuePerIP,
	}

	if next.maxQueuePerIP > 0 || next.allowMaxQueuePerIP > 0 {
		if pg != nil && pg.quota != nil && sameGuardQuota(prev.cfg, next) {
			gs.quota = pg.quota
		} else {
			maxPerIP := next.maxQueuePerIP
			if maxPerIP == 0 {
				maxPerIP = math.MaxInt
			}
			allowMax := next.allowMaxQueuePerIP
			if allowMax == 0 {
				allowMax = math.MaxInt
			}
			gs.quota = guard.NewQueueQuota(guard.QueueQuotaConfig{
				MaxPerIP:      maxPerIP,
				AllowMaxPerIP: allowMax,
				TicketTTL:     next.effectiveTokenTTL(),
			})
		}
	}

	if next.hostMaxMemMB > 0 || next.hostMaxFDs > 0 || next.hostMaxConns > 0 {
		if pg != nil && pg.shedder != nil && sameGuardShedder(prev.cfg, next) {
			gs.shedder = pg.shedder
		} else {
			gs.shedder = guard.NewHostShedder(guard.HostShedderConfig{
				MaxMemoryBytes: uint64(next.hostMaxMemMB) << 20,
				MaxOpenFDs:     next.hostMaxFDs,
				MaxActiveConns: next.hostMaxConns,
				RetryAfter:     time.Duration(next.retryAfter) * time.Second,
			})
		}
	}

	if len(next.parsedRateLimits) > 0 {
		if pg != nil && pg.routeLimiter != nil && sameGuardRateLimits(prev.cfg, next) {
			gs.routeLimiter = pg.routeLimiter
		} else {
			rl, err := guard.NewRouteLimiter(next.parsedRateLimits, 0)
			if err != nil {
				return nil, fmt.Errorf("route rate limiter: %w", err)
			}
			gs.routeLimiter = rl
		}
	}

	if len(next.parsedBlockASNs) > 0 || len(next.parsedAllowCountries) > 0 || len(next.parsedBlockCountries) > 0 {
		lookup := guard.IPLookupFunc(func(ip netip.Addr) (string, uint32, bool) {
			if a == nil || a.ipinfo == nil {
				return "", 0, false
			}
			info := a.ipinfo.get(ip)
			if !info.Found {
				return "", 0, false
			}
			return info.CountryCode, info.Number, true
		})
		pol, err := guard.NewGeoASNPolicy(guard.GeoASNConfig{
			AllowCountries: next.parsedAllowCountries,
			DenyCountries:  next.parsedBlockCountries,
			DenyASNs:       next.parsedBlockASNs,
			FailOpen:       true,
		}, lookup)
		if err != nil {
			return nil, fmt.Errorf("geo/asn policy: %w", err)
		}
		gs.geoPolicy = pol
	}

	if mode := guard.ChallengeMode(next.challengeMode); mode != "" && mode != guard.ModeOff {
		if pg != nil && pg.challenge != nil && sameGuardChallenge(prev.cfg, next) {
			gs.challenge = pg.challenge
		} else {
			gate, err := guard.NewChallengeGate(guard.ChallengeConfig{
				Mode:              mode,
				SigningKey:        guard.NewSecret(hex.EncodeToString(next.admitSecret)),
				Difficulty:        next.challengePowBits,
				InsecureCookie:    !next.secureCookie,
				TurnstileSiteKey:  next.challengeTurnstileSiteKey,
				TurnstileSecret:   next.turnstileSecret,
				TurnstileEndpoint: next.turnstileEndpoint,
			})
			if err != nil {
				return nil, fmt.Errorf("challenge gate: %w", err)
			}
			gs.challenge = gate
		}
	}

	return gs, nil
}

func sameGuardQuota(a, b config) bool {
	return a.maxQueuePerIP == b.maxQueuePerIP &&
		a.allowMaxQueuePerIP == b.allowMaxQueuePerIP &&
		a.effectiveTokenTTL() == b.effectiveTokenTTL()
}

func sameGuardShedder(a, b config) bool {
	return a.hostMaxMemMB == b.hostMaxMemMB &&
		a.hostMaxFDs == b.hostMaxFDs &&
		a.hostMaxConns == b.hostMaxConns &&
		a.retryAfter == b.retryAfter
}

func sameGuardRateLimits(a, b config) bool {
	if len(a.parsedRateLimits) != len(b.parsedRateLimits) {
		return false
	}
	for i := range a.parsedRateLimits {
		if a.parsedRateLimits[i] != b.parsedRateLimits[i] {
			return false
		}
	}
	return true
}

func sameGuardChallenge(a, b config) bool {
	return a.challengeMode == b.challengeMode &&
		a.challengePowBits == b.challengePowBits &&
		a.secureCookie == b.secureCookie &&
		a.challengeTurnstileSiteKey == b.challengeTurnstileSiteKey &&
		a.turnstileEndpoint == b.turnstileEndpoint &&
		a.turnstileSecret.Reveal() == b.turnstileSecret.Reveal()
}

func isGuardExemptPath(p string) bool {
	return strings.HasPrefix(p, "/_room") ||
		strings.HasPrefix(p, "/_concert") ||
		p == "/queue/status" ||
		isTicketStatus(p)
}

// guardEarlyMiddleware enforces Geo/ASN policy, per-route rate limits, and
// host memory/FD/connection shedding ahead of static/cache/waiting-room
// handling while keeping /_room/*, /_concert/*, and /queue/status reachable.
// Every rejection sets ctxSkipWaitingHeaders so X-Concert-Queue is never sent.
func (g *generation) guardEarlyMiddleware(c *gin.Context) {
	gs := g.guard
	if gs == nil {
		c.Next()
		return
	}
	p := c.Request.URL.Path
	if isGuardExemptPath(p) {
		c.Next()
		return
	}

	ip := clientIPFrom(c)
	now := time.Now()

	if gs.geoPolicy != nil {
		if allowed, reason := gs.geoPolicy.Check(ip); !allowed {
			g.a.stats.guardGeoBlocked.Add(1)
			c.Set(ctxSkipWaitingHeaders, true)
			c.Header("Cache-Control", "no-store")
			if wantsHTML(c.Request) {
				c.Data(http.StatusForbidden, "text/html; charset=utf-8",
					[]byte(fmt.Sprintf(blockedPage, "Access from your region or network is not permitted.")))
			} else {
				c.Data(http.StatusForbidden, "application/json; charset=utf-8",
					mustJSON(gin.H{"error": "geo_asn_blocked", "reason": reason}))
			}
			c.Abort()
			return
		}
	}

	if gs.routeLimiter != nil {
		if allowed, retryAfter := gs.routeLimiter.Allow(p, ip, now); !allowed {
			g.a.stats.guardRateLimit.Add(1)
			c.Set(ctxSkipWaitingHeaders, true)
			secs := int((retryAfter + time.Second - 1) / time.Second)
			if secs < 1 {
				secs = 1
			}
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

	if gs.shedder != nil {
		// Check shedding before counting this request as active so a
		// MaxActiveConns limit of N admits N concurrent requests and sheds N+1.
		if shed, reason := gs.shedder.ShouldShed(); shed {
			g.a.stats.guardShed.Add(1)
			c.Set(ctxSkipWaitingHeaders, true)
			gs.shedder.WriteShedResponse(c.Writer, reason)
			c.Abort()
			return
		}
		gs.shedder.IncActiveConns()
		defer gs.shedder.DecActiveConns()
	}

	c.Next()
}

// guardPreQueueMiddleware runs on gated catch-all traffic right before
// waitingRoomSignalHeaders and room's middleware, enforcing pre-ticket
// PoW/Turnstile challenges and per-IP waiting-room queue quotas (including
// capped allowlisted IPs). Rejections set ctxSkipWaitingHeaders and never emit
// X-Concert-Queue.
func (g *generation) guardPreQueueMiddleware(c *gin.Context) {
	gs := g.guard
	if gs == nil || c.FullPath() != "" {
		c.Next()
		return
	}
	// Already admitted via priority lane or active concert_admit continuity pass.
	if c.GetBool(ctxAdmitted) {
		c.Next()
		return
	}

	ip := clientIPFrom(c)
	now := time.Now()

	// Check whether the visitor already holds a live ticket in room or a valid
	// admission pass; returning/admitted visitors are not re-challenged and do
	// not consume a second queue quota slot.
	hasActiveTicket := false
	if ck, err := c.Request.Cookie("room_ticket"); err == nil && ck.Value != "" {
		if _, ok := g.a.room.Ticket(ck.Value); ok {
			hasActiveTicket = true
		}
	}
	hasValidAdmit := false
	if g.a.admit != nil {
		if ck, err := c.Request.Cookie(admitCookie); err == nil && ck.Value != "" {
			if _, _, status, _ := g.a.admit.verifyWithRotation(ck.Value, now); status == passValid {
				hasValidAdmit = true
			}
		}
	}

	if gs.challenge != nil && gs.challenge.Mode() != guard.ModeOff && !hasActiveTicket && !hasValidAdmit {
		if !gs.challenge.VerifyClearanceCookie(c.Request, ip, now) {
			g.serveChallenge(c, ip, now)
			return
		}
	}

	if gs.quota != nil && !hasActiveTicket && !hasValidAdmit && c.GetString(ctxAgentKey) == "" {
		allowlisted := containsAddr(g.cfg.allow, ip)
		quotaActive := (!allowlisted && gs.quotaMax > 0) || (allowlisted && gs.quotaAllowMax > 0)
		// Enforce per-IP queue quota whenever the waiting room is busy (slots
		// full or a queue is already forming) so normal uncontested traffic
		// flows freely while floods cannot exhaust global -max-queue.
		roomBusy := g.a.room.Len() >= int(g.a.room.Cap()) || g.a.room.QueueDepth() > 0
		if quotaActive && roomBusy {
			provID := "prov-" + strconv.FormatUint(gs.provSeq.Add(1), 36)
			if !gs.quota.TryAcquire(ip, provID, allowlisted, now) {
				g.a.stats.guardQuotaRejected.Add(1)
				c.Set(ctxSkipWaitingHeaders, true)
				secs := g.cfg.retryAfter
				if secs < 1 {
					secs = 1
				}
				s := strconv.Itoa(secs)
				c.Header("Cache-Control", "no-store")
				c.Header("Retry-After", s)
				if wantsHTML(c.Request) {
					c.Data(http.StatusTooManyRequests, "text/html; charset=utf-8",
						[]byte(fmt.Sprintf(blockedPage, "Too many queued requests from your network. Try again in "+s+"s.")))
				} else {
					c.Data(http.StatusTooManyRequests, "application/json; charset=utf-8",
						mustJSON(gin.H{"error": "queue_quota_exceeded", "retry_after_seconds": secs}))
				}
				c.Abort()
				return
			}

			c.Next()

			if c.GetBool(ctxAdmitted) || c.GetBool(ctxRoomFull) {
				gs.quota.Release(ip, provID)
				return
			}
			if tok := issuedTicket(c.Writer.Header()); tok != "" {
				gs.quota.Release(ip, provID)
				gs.quota.TryAcquire(ip, tok, allowlisted, time.Now())
				return
			}
			gs.quota.Release(ip, provID)
			return
		}
	}

	c.Next()
}

func (g *generation) serveChallenge(c *gin.Context, ip netip.Addr, now time.Time) {
	gs := g.guard
	c.Set(ctxSkipWaitingHeaders, true)
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Referrer-Policy", "no-referrer")

	switch gs.challenge.Mode() {
	case guard.ModePoW:
		ch, err := gs.challenge.IssuePoW(ip, now)
		if err != nil {
			c.Data(http.StatusServiceUnavailable, "application/json; charset=utf-8",
				mustJSON(gin.H{"error": "challenge_unavailable"}))
			c.Abort()
			return
		}
		if wantsHTML(c.Request) {
			c.Header("Content-Security-Policy", challengeCSP)
			page := guard.PoWChallengeHTML(ch, challengeVerifyPath, guard.DefaultPoWScriptPath)
			c.Data(http.StatusForbidden, "text/html; charset=utf-8", []byte(page))
		} else {
			c.Data(http.StatusForbidden, "application/json; charset=utf-8", mustJSON(gin.H{
				"challenge":  "pow",
				"nonce":      ch.Nonce,
				"difficulty": ch.Difficulty,
				"expires_at": ch.ExpiresAt.UTC().Format(time.RFC3339),
				"verify_url": challengeVerifyPath,
			}))
		}
	case guard.ModeTurnstile:
		if wantsHTML(c.Request) {
			siteKey := html.EscapeString(g.cfg.challengeTurnstileSiteKey)
			page := `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Verification required</title></head><body><main><h1>Verification required</h1><form method="POST" action="` + challengeVerifyPath + `"><div class="cf-turnstile" data-sitekey="` + siteKey + `"></div><button type="submit">Continue</button></form></main></body></html>`
			c.Data(http.StatusForbidden, "text/html; charset=utf-8", []byte(page))
		} else {
			c.Data(http.StatusForbidden, "application/json; charset=utf-8", mustJSON(gin.H{
				"challenge":  "turnstile",
				"site_key":   g.cfg.challengeTurnstileSiteKey,
				"verify_url": challengeVerifyPath,
			}))
		}
	}
	c.Abort()
}

// handleChallengeSubroute handles /_concert/pow.js and /_concert/challenge/verify
// across all three Concert editions (concert, wpconcert, econcert). Returns true
// when the path was handled.
func (g *generation) handleChallengeSubroute(c *gin.Context, subPath string) bool {
	switch subPath {
	case "/pow.js":
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Status(http.StatusMethodNotAllowed)
			return true
		}
		c.Header("Content-Security-Policy", challengeCSP)
		c.Header("Cache-Control", "public, max-age=300")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "no-referrer")
		c.Data(http.StatusOK, "application/javascript; charset=utf-8", []byte(guard.PoWSolverJS()))
		return true

	case "/challenge/verify":
		if c.Request.Method != http.MethodPost {
			c.Status(http.StatusMethodNotAllowed)
			return true
		}
		g.handleChallengeVerify(c)
		return true
	}
	return false
}

// handleChallengeVerify verifies a PoW or Turnstile submission at
// POST /_concert/challenge/verify, updates Prometheus challenge counters, and
// issues the signed clearance cookie on success.
func (g *generation) handleChallengeVerify(c *gin.Context) {
	c.Set(ctxSkipWaitingHeaders, true)
	c.Header("Cache-Control", "no-store")

	if g.guard == nil || g.guard.challenge == nil || g.guard.challenge.Mode() == guard.ModeOff {
		c.JSON(http.StatusNotFound, gin.H{"error": "challenge_disabled"})
		return
	}

	var (
		nonce          string
		counter        string
		turnstileToken string
		isForm         bool
	)
	ct := strings.ToLower(strings.TrimSpace(c.GetHeader("Content-Type")))
	if strings.HasPrefix(ct, "application/json") {
		var body struct {
			Nonce             string `json:"nonce"`
			Counter           string `json:"counter"`
			Token             string `json:"token"`
			TurnstileResponse string `json:"cf-turnstile-response"`
		}
		if err := json.NewDecoder(io.LimitReader(c.Request.Body, 8<<10)).Decode(&body); err != nil {
			g.a.stats.guardChallengeFailed.Add(1)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		nonce = body.Nonce
		counter = body.Counter
		turnstileToken = body.Token
		if turnstileToken == "" {
			turnstileToken = body.TurnstileResponse
		}
	} else {
		isForm = true
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8<<10)
		if err := c.Request.ParseForm(); err != nil {
			g.a.stats.guardChallengeFailed.Add(1)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_form"})
			return
		}
		nonce = c.Request.PostForm.Get("nonce")
		counter = c.Request.PostForm.Get("counter")
		turnstileToken = c.Request.PostForm.Get("cf-turnstile-response")
		if turnstileToken == "" {
			turnstileToken = c.Request.PostForm.Get("token")
		}
	}

	ip := clientIPFrom(c)
	now := time.Now()

	switch g.guard.challenge.Mode() {
	case guard.ModePoW:
		ok, err := g.guard.challenge.VerifyPoW(ip, nonce, counter, now)
		if err != nil || !ok {
			g.a.stats.guardChallengeFailed.Add(1)
			c.JSON(http.StatusForbidden, gin.H{"ok": false, "error": "challenge_failed"})
			return
		}
	case guard.ModeTurnstile:
		res, err := g.guard.challenge.VerifyTurnstile(c.Request.Context(), turnstileToken, ip)
		if err != nil || !res.Success {
			g.a.stats.guardChallengeFailed.Add(1)
			c.JSON(http.StatusForbidden, gin.H{"ok": false, "error": "challenge_failed"})
			return
		}
	default:
		c.JSON(http.StatusNotFound, gin.H{"error": "challenge_disabled"})
		return
	}

	ck, err := g.guard.challenge.IssueClearanceCookie(ip, now)
	if err != nil {
		g.a.stats.guardChallengeFailed.Add(1)
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "clearance_error"})
		return
	}
	if g.cfg.cookiePath != "" {
		ck.Path = g.cfg.cookiePath
	}
	if g.cfg.cookieDomain != "" {
		ck.Domain = g.cfg.cookieDomain
	}
	http.SetCookie(c.Writer, ck)
	g.a.stats.guardChallengePassed.Add(1)

	if isForm && wantsHTML(c.Request) {
		c.Redirect(http.StatusSeeOther, "/")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *app) releaseQuotaTicket(clientKey, token string) {
	if a == nil || clientKey == "" || token == "" {
		return
	}
	g := a.current()
	if g == nil || g.guard == nil || g.guard.quota == nil {
		return
	}
	if ip, err := netip.ParseAddr(clientKey); err == nil {
		g.guard.quota.Release(ip, token)
	}
}
