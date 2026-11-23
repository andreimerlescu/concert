//go:build enterprise

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/andreimerlescu/concert/internal/mailer"
	"github.com/gin-gonic/gin"
)

// emailConfig is declared in edition_core.go.

func (c *config) normalizeEmail() error {
	e := &c.email
	e.provider = strings.ToLower(strings.TrimSpace(e.provider))
	e.smtpTLS = strings.ToLower(strings.TrimSpace(e.smtpTLS))
	if e.smtpTLS == "" {
		e.smtpTLS = mailer.TLSStartTLS
	}
	if e.cadenceMax == 0 {
		e.cadenceMax = 1
	}
	if e.cadenceWindowValue == 0 {
		e.cadenceWindowValue = 15
	}
	if strings.TrimSpace(e.cadenceWindowUnit) == "" {
		e.cadenceWindowUnit = mailer.UnitMinutes
	} else {
		e.cadenceWindowUnit = mailer.NormalizeUnit(e.cadenceWindowUnit)
	}
	if strings.TrimSpace(e.fromName) == "" {
		e.fromName = "Concert"
	}
	mc, err := c.mailerConfig()
	if err != nil {
		return err
	}
	return mc.Validate()
}

func (c *config) mailerConfig() (mailer.Config, error) {
	toAddrs, err := mailer.ParseAddressList(c.email.toAddrs)
	if err != nil {
		return mailer.Config{}, fmt.Errorf("invalid -email-to: %w", err)
	}
	cats, err := mailer.ParseCategoryList(c.email.events)
	if err != nil {
		return mailer.Config{}, fmt.Errorf("invalid -email-events: %w", err)
	}
	nodeID := strings.TrimSpace(c.nodeID)
	if nodeID == "" {
		nodeID = derivedNodeID()
	}
	role := strings.TrimSpace(c.role)
	if role == "" {
		role = roleStandalone
	}
	return mailer.Config{
		Provider:         strings.ToLower(strings.TrimSpace(c.email.provider)),
		SMTPHost:         strings.TrimSpace(c.email.smtpHost),
		SMTPPort:         c.email.smtpPort,
		SMTPTLS:          c.email.smtpTLS,
		SMTPUser:         strings.TrimSpace(c.email.smtpUser),
		ResendBaseURL:    strings.TrimSpace(c.email.resendURL),
		SendPandaBaseURL: strings.TrimSpace(c.email.sendPandaURL),
		FromName:         strings.TrimSpace(c.email.fromName),
		FromAddr:         strings.TrimSpace(c.email.fromAddr),
		ToAddrs:          toAddrs,
		DKIMSelector:     strings.TrimSpace(c.email.dkimSelector),
		Cadence: mailer.Cadence{
			MaxEmails:   c.email.cadenceMax,
			WindowValue: c.email.cadenceWindowValue,
			WindowUnit:  c.email.cadenceWindowUnit,
		},
		Categories: cats,
		Compliance: mailer.ComplianceConfig{
			OrgName:       strings.TrimSpace(c.email.orgName),
			PostalAddress: strings.TrimSpace(c.email.postalAddress),
			PrivacyURL:    strings.TrimSpace(c.email.privacyURL),
			TermsURL:      strings.TrimSpace(c.email.termsURL),
			PortalURL:     strings.TrimSpace(c.email.portalURL),
			PublicBaseURL: strings.TrimSpace(c.email.publicBaseURL),
		},
		Hardened: c.hardened,
		NodeID:   nodeID,
		Role:     role,
		Version:  BinaryVersion(),
	}, nil
}

func (a *app) initMailer(cfg config) *mailer.Service {
	envSec := mailer.Secrets{
		SMTPPass:        cfg.email.smtpPass,
		ResendAPIKey:    cfg.email.resendAPIKey,
		SendPandaAPIKey: cfg.email.sendPandaAPIKey,
	}
	canPersist := cfg.dataDir != "" && !cfg.admitSecretGenerated && !cfg.readOnlySettings
	var persistNote string
	switch {
	case cfg.readOnlySettings:
		persistNote = "settings are read-only (-read-only-settings / GitOps mode); provide email credentials via CONCERT_* environment variables"
	case cfg.dataDir == "":
		persistNote = "-data-dir is empty; provide email credentials via CONCERT_* environment variables"
	case cfg.admitSecretGenerated:
		persistNote = "set an explicit CONCERT_ADMIT_SECRET to encrypt and save credentials in the portal, or provide them via CONCERT_* environment variables"
	}

	secStore, err := mailer.NewSecretStore(cfg.dataDir, cfg.admitSecret, cfg.admitSecretPrev, canPersist, persistNote, envSec)
	if err != nil {
		log.Printf("mailer: %v (falling back to environment credentials only)", err)
	}
	mcfg, err := cfg.mailerConfig()
	if err != nil {
		log.Printf("mailer: invalid config: %v", err)
	}
	svc := mailer.NewService(mailer.ServiceOptions{
		DataDir:         cfg.dataDir,
		Config:          mcfg,
		Secrets:         secStore,
		UnsubSecret:     cfg.admitSecret,
		UnsubSecretPrev: cfg.admitSecretPrev,
	})
	svc.Start()
	a.onClose(svc.Close)
	return svc
}

// isClusterSharedFingerprint reports whether an event fingerprint represents a
// cluster-wide incident (leaf outage, upstream circuit-breaker, or synced ban)
// that should be deduplicated across peers sharing Redis so operators do not
// receive N copies of the same digest alert. Node-local events (silence:<node>,
// security actions, local queue/fastlane receipts) always notify locally.
func isClusterSharedFingerprint(fp string) bool {
	return strings.HasPrefix(fp, "leaf-down:") ||
		strings.HasPrefix(fp, "leaf-up:") ||
		strings.HasPrefix(fp, "cb:") ||
		strings.HasPrefix(fp, "ban:")
}

// notifyEvent enqueues an operational event for scheduled administrator digest
// delivery. Safe to call on nil app/mailer and never blocks on network I/O.
func (a *app) notifyEvent(ev mailer.Event) {
	if a == nil || a.mailer == nil {
		return
	}
	if a.cluster != nil && ev.Fingerprint != "" && isClusterSharedFingerprint(ev.Fingerprint) {
		g := a.current()
		if g != nil && g.cfg.email.clusterDedupe {
			ttl := 15 * time.Minute
			if mcfg, err := g.cfg.mailerConfig(); err == nil {
				if p := mcfg.Cadence.Pace(); p >= time.Minute {
					ttl = p
				}
			}
			if ttl > time.Hour {
				ttl = time.Hour
			}
			a.cluster.claimEmailAsync(ev.Fingerprint, ttl, func() {
				a.mailer.Enqueue(ev)
			})
			return
		}
	}
	a.mailer.Enqueue(ev)
}

func (a *app) emailIPLabel(ip netip.Addr) string {
	if !ip.IsValid() {
		return "unknown"
	}
	g := a.current()
	if g != nil && g.cfg.privacyAnonymizeIP {
		return formatPrivacyIP(ip, true)
	}
	return ip.Unmap().String()
}

func (a *app) emailScopeLabel(scope netip.Prefix) string {
	if !scope.IsValid() {
		return "unknown"
	}
	g := a.current()
	if g != nil && g.cfg.privacyAnonymizeIP && scope.IsSingleIP() {
		return formatPrivacyIP(scope.Addr(), true)
	}
	if scope.IsSingleIP() {
		return scope.Addr().Unmap().String()
	}
	return scope.Masked().String()
}

// ─── Rate Limiter for Email Portal & Public Unsubscribe Actions ──────────────

type emailRateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[netip.Addr]*emailRateBucket
}

type emailRateBucket struct {
	start time.Time
	count int
}

func newEmailRateLimiter(limit int, window time.Duration) *emailRateLimiter {
	return &emailRateLimiter{
		limit:   limit,
		window:  window,
		entries: map[netip.Addr]*emailRateBucket{},
	}
}

func (l *emailRateLimiter) allow(ip netip.Addr, now time.Time) bool {
	if l == nil || !ip.IsValid() {
		return true
	}
	ip = ip.Unmap()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) >= 4096 {
		for k, b := range l.entries {
			if now.Sub(b.start) >= l.window {
				delete(l.entries, k)
			}
		}
	}
	b, ok := l.entries[ip]
	if !ok || now.Sub(b.start) >= l.window {
		l.entries[ip] = &emailRateBucket{start: now, count: 1}
		return true
	}
	if b.count >= l.limit {
		return false
	}
	b.count++
	return true
}

// ─── Portal API: Email Delivery ──────────────────────────────────────────────

func (p *portal) emailView() gin.H {
	cfg := p.a.current().cfg
	mcfg, _ := cfg.mailerConfig()
	status := p.a.mailer.Status()
	return gin.H{
		"config": gin.H{
			"provider":           mcfg.Provider,
			"smtp_host":          mcfg.SMTPHost,
			"smtp_port":          mcfg.EffectiveSMTPPort(),
			"smtp_tls":           mcfg.EffectiveSMTPTLS(),
			"smtp_user":          mcfg.SMTPUser,
			"resend_base_url":    cfg.email.resendURL,
			"sendpanda_base_url": cfg.email.sendPandaURL,
			"from_name":          mcfg.FromName,
			"from_addr":          mcfg.FromAddr,
			"to_addrs":           strings.Join(mcfg.ToAddrs, ", "),
			"dkim_selector":      mcfg.DKIMSelector,
			"cadence_max":        mcfg.Cadence.MaxEmails,
			"cadence_window":     mcfg.Cadence.WindowValue,
			"cadence_unit":       mcfg.Cadence.WindowUnit,
			"categories":         mcfg.Categories,
			"org_name":           mcfg.Compliance.OrgName,
			"postal_address":     mcfg.Compliance.PostalAddress,
			"privacy_url":        mcfg.Compliance.PrivacyURL,
			"terms_url":          mcfg.Compliance.TermsURL,
			"portal_url":         mcfg.Compliance.PortalURL,
			"public_base_url":    mcfg.Compliance.PublicBaseURL,
		},
		"defaults": gin.H{
			"resend_base_url":    mailer.DefaultResendBaseURL,
			"sendpanda_base_url": mailer.DefaultSendPandaBaseURL,
		},
		"categories_all":     mailer.AllCategories,
		"status":             status,
		"read_only_settings": cfg.readOnlySettings,
		"data_dir_persisted": cfg.dataDir != "",
		"hardened":           cfg.hardened,
	}
}

func (p *portal) apiEmail(c *gin.Context) {
	c.JSON(http.StatusOK, p.emailView())
}

type emailConfigSaveReq struct {
	Provider         *string         `json:"provider"`
	SMTPHost         *string         `json:"smtp_host"`
	SMTPPort         *int            `json:"smtp_port"`
	SMTPTLS          *string         `json:"smtp_tls"`
	SMTPUser         *string         `json:"smtp_user"`
	ResendBaseURL    *string         `json:"resend_base_url"`
	SendPandaBaseURL *string         `json:"sendpanda_base_url"`
	FromName         *string         `json:"from_name"`
	FromAddr         *string         `json:"from_addr"`
	ToAddrs          *string         `json:"to_addrs"`
	DKIMSelector     *string         `json:"dkim_selector"`
	CadenceMax       *int            `json:"cadence_max"`
	CadenceWindow    *int            `json:"cadence_window"`
	CadenceUnit      *string         `json:"cadence_unit"`
	Categories       map[string]bool `json:"categories"`
	OrgName          *string         `json:"org_name"`
	PostalAddress    *string         `json:"postal_address"`
	PrivacyURL       *string         `json:"privacy_url"`
	TermsURL         *string         `json:"terms_url"`
	PortalURL        *string         `json:"portal_url"`
	PublicBaseURL    *string         `json:"public_base_url"`
	Secrets          *struct {
		SMTPPass        *string `json:"smtp_pass"`
		ResendAPIKey    *string `json:"resend_api_key"`
		SendPandaAPIKey *string `json:"sendpanda_api_key"`
	} `json:"secrets"`
}

func (p *portal) apiEmailConfigSave(c *gin.Context) {
	if p.a.current().cfg.readOnlySettings {
		jsonError(c, http.StatusForbidden, "settings are read-only (-read-only-settings / GitOps mode)")
		return
	}
	var req emailConfigSaveReq
	if err := json.NewDecoder(io.LimitReader(c.Request.Body, settingsBodyLimit)).Decode(&req); err != nil {
		jsonError(c, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	set := map[string]json.RawMessage{}
	addStr := func(key string, v *string) {
		if v != nil {
			b, _ := json.Marshal(strings.TrimSpace(*v))
			set[key] = b
		}
	}
	addInt := func(key string, v *int) {
		if v != nil {
			b, _ := json.Marshal(*v)
			set[key] = b
		}
	}

	addStr("email_provider", req.Provider)
	addStr("email_smtp_host", req.SMTPHost)
	addInt("email_smtp_port", req.SMTPPort)
	addStr("email_smtp_tls", req.SMTPTLS)
	addStr("email_smtp_user", req.SMTPUser)
	addStr("email_resend_url", req.ResendBaseURL)
	addStr("email_sendpanda_url", req.SendPandaBaseURL)
	addStr("email_from_name", req.FromName)
	addStr("email_from_addr", req.FromAddr)
	addStr("email_to", req.ToAddrs)
	addStr("email_dkim_selector", req.DKIMSelector)
	addInt("email_cadence_max", req.CadenceMax)
	addInt("email_cadence_window", req.CadenceWindow)
	addStr("email_cadence_unit", req.CadenceUnit)
	addStr("email_org_name", req.OrgName)
	addStr("email_postal_address", req.PostalAddress)
	addStr("email_privacy_url", req.PrivacyURL)
	addStr("email_terms_url", req.TermsURL)
	addStr("email_portal_url", req.PortalURL)
	addStr("email_public_base_url", req.PublicBaseURL)
	if req.Categories != nil {
		formatted := mailer.FormatCategoryList(req.Categories)
		b, _ := json.Marshal(formatted)
		set["email_events"] = b
	}

	var secPatch mailer.SecretsPatch
	var secFields []string
	if req.Secrets != nil {
		if req.Secrets.SMTPPass != nil && *req.Secrets.SMTPPass != "" {
			v := *req.Secrets.SMTPPass
			secPatch.SMTPPass = &v
			secFields = append(secFields, "smtp_pass")
		}
		if req.Secrets.ResendAPIKey != nil && *req.Secrets.ResendAPIKey != "" {
			v := strings.TrimSpace(*req.Secrets.ResendAPIKey)
			secPatch.ResendAPIKey = &v
			secFields = append(secFields, "resend_api_key")
		}
		if req.Secrets.SendPandaAPIKey != nil && *req.Secrets.SendPandaAPIKey != "" {
			v := strings.TrimSpace(*req.Secrets.SendPandaAPIKey)
			secPatch.SendPandaAPIKey = &v
			secFields = append(secFields, "sendpanda_api_key")
		}
	}

	if len(set) == 0 && len(secFields) == 0 {
		jsonError(c, http.StatusBadRequest, "no email settings or credentials to update")
		return
	}

	pr := portalPrincipal(c)
	// Fail fast before mutating settings.json if a portal secret cannot be persisted.
	if len(secFields) > 0 {
		if st := p.a.mailer.Secrets().Status(); !st.CanPersist {
			msg := st.PersistNote
			if msg == "" {
				msg = "cannot persist encrypted email credentials without a stable CONCERT_ADMIT_SECRET and -data-dir"
			}
			jsonError(c, http.StatusBadRequest, msg)
			return
		}
	}

	if len(set) > 0 {
		ip, _ := remoteAddr(c.Request)
		if err := p.a.changeSettings(set, nil, ip); err != nil {
			p.a.recordAudit(auditEvent{
				Actor:    pr.Actor,
				Role:     pr.Role.String(),
				Source:   "portal",
				Action:   "email.config.update",
				Outcome:  "error",
				ClientIP: pr.IP.String(),
				Details:  map[string]any{"keys": sortedKeys(set), "error": err.Error()},
			})
			jsonError(c, settingsStatus(err), err.Error())
			return
		}
	}
	if len(secFields) > 0 {
		if err := p.a.mailer.Secrets().Update(secPatch); err != nil {
			p.a.recordAudit(auditEvent{
				Actor:    pr.Actor,
				Role:     pr.Role.String(),
				Source:   "portal",
				Action:   "email.secret.update",
				Outcome:  "error",
				ClientIP: pr.IP.String(),
				Details:  map[string]any{"fields": secFields, "error": err.Error()},
			})
			jsonError(c, http.StatusInternalServerError, "could not save encrypted credentials: "+err.Error())
			return
		}
	}

	p.a.recordAudit(auditEvent{
		Actor:    pr.Actor,
		Role:     pr.Role.String(),
		Source:   "portal",
		Action:   "email.config.update",
		Outcome:  "allow",
		ClientIP: pr.IP.String(),
		Details:  map[string]any{"keys": sortedKeys(set), "secret_fields_updated": secFields},
	})
	p.a.notifyEvent(mailer.Event{
		Category:    mailer.CatSecurity,
		Severity:    mailer.SevInfo,
		Title:       "Email delivery configuration updated",
		Summary:     fmt.Sprintf("Administrator %s updated email delivery settings (%d key(s), %d secret field(s)).", pr.Actor, len(set), len(secFields)),
		Fingerprint: "security:email-config:" + pr.Actor,
	})
	c.JSON(http.StatusOK, p.emailView())
}

func (p *portal) apiEmailSecretDelete(c *gin.Context) {
	if p.a.current().cfg.readOnlySettings {
		jsonError(c, http.StatusForbidden, "settings are read-only (-read-only-settings / GitOps mode)")
		return
	}
	field := strings.TrimSpace(c.Query("field"))
	if field == "" {
		jsonError(c, http.StatusBadRequest, "field query parameter is required (smtp_pass, resend_api_key, sendpanda_api_key, or all)")
		return
	}
	pr := portalPrincipal(c)
	if err := p.a.mailer.Secrets().Delete(field); err != nil {
		jsonError(c, http.StatusBadRequest, err.Error())
		return
	}
	p.a.recordAudit(auditEvent{
		Actor:    pr.Actor,
		Role:     pr.Role.String(),
		Source:   "portal",
		Action:   "email.secret.delete",
		Target:   field,
		Outcome:  "allow",
		ClientIP: pr.IP.String(),
	})
	c.JSON(http.StatusOK, p.emailView())
}

func (p *portal) apiEmailPause(c *gin.Context) {
	var body struct {
		Paused    bool   `json:"paused"`
		Recipient string `json:"recipient"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		jsonError(c, http.StatusBadRequest, "invalid JSON body")
		return
	}
	pr := portalPrincipal(c)
	if rcpt := strings.TrimSpace(body.Recipient); rcpt != "" {
		var err error
		action := "email.resubscribe"
		if body.Paused {
			action = "email.unsubscribe"
			err = p.a.mailer.Unsubscribe(rcpt)
		} else {
			err = p.a.mailer.Resubscribe(rcpt)
		}
		if err != nil {
			jsonError(c, http.StatusBadRequest, err.Error())
			return
		}
		p.a.recordAudit(auditEvent{
			Actor:    pr.Actor,
			Role:     pr.Role.String(),
			Source:   "portal",
			Action:   action,
			Target:   rcpt,
			Outcome:  "allow",
			ClientIP: pr.IP.String(),
		})
		c.JSON(http.StatusOK, p.emailView())
		return
	}
	if err := p.a.mailer.SetPaused(body.Paused); err != nil {
		jsonError(c, http.StatusInternalServerError, err.Error())
		return
	}
	action := "email.resume"
	if body.Paused {
		action = "email.pause"
	}
	p.a.recordAudit(auditEvent{
		Actor:    pr.Actor,
		Role:     pr.Role.String(),
		Source:   "portal",
		Action:   action,
		Outcome:  "allow",
		ClientIP: pr.IP.String(),
	})
	c.JSON(http.StatusOK, p.emailView())
}

func (p *portal) apiEmailVerify(c *gin.Context) {
	pr := portalPrincipal(c)
	if !p.emailOpsLimit.allow(pr.IP, time.Now()) {
		jsonError(c, http.StatusTooManyRequests, "too many verification requests; try again in a minute")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	report := p.a.mailer.Verify(ctx)
	outcome := "allow"
	if !report.OK {
		outcome = "warn"
	}
	p.a.recordAudit(auditEvent{
		Actor:    pr.Actor,
		Role:     pr.Role.String(),
		Source:   "portal",
		Action:   "email.verify",
		Outcome:  outcome,
		ClientIP: pr.IP.String(),
		Details:  map[string]any{"provider": report.Provider, "ok": report.OK, "checks": len(report.Checks)},
	})
	c.JSON(http.StatusOK, report)
}

func (p *portal) apiEmailTest(c *gin.Context) {
	pr := portalPrincipal(c)
	if !p.emailOpsLimit.allow(pr.IP, time.Now()) {
		jsonError(c, http.StatusTooManyRequests, "too many test email requests; try again in a minute")
		return
	}
	var body struct {
		To string `json:"to"`
	}
	_ = json.NewDecoder(io.LimitReader(c.Request.Body, 4096)).Decode(&body)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	res, err := p.a.mailer.SendTest(ctx, body.To)
	if err != nil {
		p.a.recordAudit(auditEvent{
			Actor:    pr.Actor,
			Role:     pr.Role.String(),
			Source:   "portal",
			Action:   "email.test",
			Target:   strings.TrimSpace(body.To),
			Outcome:  "error",
			ClientIP: pr.IP.String(),
			Details:  map[string]any{"error": err.Error()},
		})
		jsonError(c, http.StatusBadGateway, err.Error())
		return
	}
	p.a.recordAudit(auditEvent{
		Actor:    pr.Actor,
		Role:     pr.Role.String(),
		Source:   "portal",
		Action:   "email.test",
		Target:   strings.TrimSpace(body.To),
		Outcome:  "allow",
		ClientIP: pr.IP.String(),
		Details:  map[string]any{"provider": res.Provider, "message_id": res.MessageID},
	})
	c.JSON(http.StatusOK, res)
}

func (p *portal) apiEmailFlush(c *gin.Context) {
	pr := portalPrincipal(c)
	var body struct {
		BypassCadence bool `json:"bypass_cadence"`
	}
	_ = json.NewDecoder(io.LimitReader(c.Request.Body, 4096)).Decode(&body)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
	defer cancel()
	rec, err := p.a.mailer.FlushNow(ctx, body.BypassCadence)
	if err != nil {
		p.a.recordAudit(auditEvent{
			Actor:    pr.Actor,
			Role:     pr.Role.String(),
			Source:   "portal",
			Action:   "email.flush",
			Outcome:  "error",
			ClientIP: pr.IP.String(),
			Details:  map[string]any{"bypass_cadence": body.BypassCadence, "error": err.Error()},
		})
		jsonError(c, http.StatusConflict, err.Error())
		return
	}
	p.a.recordAudit(auditEvent{
		Actor:    pr.Actor,
		Role:     pr.Role.String(),
		Source:   "portal",
		Action:   "email.flush",
		Outcome:  "allow",
		ClientIP: pr.IP.String(),
		Details:  map[string]any{"bypass_cadence": body.BypassCadence, "recipients": rec.Recipients, "events": rec.EventCount, "message_id": rec.MessageID},
	})
	c.JSON(http.StatusOK, gin.H{"delivery": rec, "email": p.emailView()})
}

// ─── Signed RFC 8058 One-Click Unsubscribe Handler ───────────────────────────

var unsubPageTmpl = template.Must(template.New("concert_unsub").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{.Title}} · Concert</title>
</head>
<body>
<main>
<h1>{{.Heading}}</h1>
<p>{{.Message}}</p>
{{if .ShowForm}}
<form method="post" action="{{.Action}}">
  <input type="hidden" name="token" value="{{.Token}}">
  <input type="hidden" name="List-Unsubscribe" value="One-Click">
  <button type="submit">Pause operational email alerts for {{.Recipient}}</button>
</form>
{{end}}
</main>
</body>
</html>
`))

func (a *app) handleEmailUnsubscribe(c *gin.Context) {
	c.Header("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	c.Header("X-Frame-Options", "DENY")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("Cache-Control", "no-store")

	ip := clientIPFrom(c)
	if !ip.IsValid() {
		ip, _ = remoteAddr(c.Request)
	}
	if a.unsubLimit != nil && !a.unsubLimit.allow(ip, time.Now()) {
		c.String(http.StatusTooManyRequests, "too many requests\n")
		return
	}
	if a.mailer == nil {
		c.String(http.StatusNotFound, "not found\n")
		return
	}

	tok := strings.TrimSpace(c.Query("token"))
	if tok == "" && c.Request.Method == http.MethodPost {
		tok = strings.TrimSpace(c.PostForm("token"))
	}
	rcpt, nodeID, err := a.mailer.VerifyUnsubscribe(tok)
	if err != nil {
		renderUnsubPage(c, http.StatusBadRequest, "Invalid Link", "Invalid or expired unsubscribe link",
			"This unsubscribe link is invalid or has expired. You can manage alert delivery in the Concert Admin Portal.", "", "", "", false)
		return
	}

	switch c.Request.Method {
	case http.MethodGet:
		// Never mutate state on GET so automated mail link-scanners cannot pause alerts.
		renderUnsubPage(c, http.StatusOK, "Pause Alerts", "Confirm Alert Pause",
			fmt.Sprintf("Confirm pausing operational digest emails from Concert node %s to %s.", nodeID, rcpt),
			c.Request.URL.Path, tok, rcpt, true)
	case http.MethodPost:
		if err := a.mailer.Unsubscribe(rcpt); err != nil {
			c.String(http.StatusInternalServerError, "could not update subscription\n")
			return
		}
		a.recordAudit(auditEvent{
			Actor:    rcpt,
			Role:     "recipient",
			Source:   "unsubscribe",
			Action:   "email.unsubscribe",
			Target:   rcpt,
			Outcome:  "allow",
			ClientIP: a.emailIPLabel(ip),
			Details:  map[string]any{"node": nodeID, "one_click": c.PostForm("List-Unsubscribe") == "One-Click"},
		})
		if wantsHTML(c.Request) {
			renderUnsubPage(c, http.StatusOK, "Alerts Paused", "Operational Alerts Paused",
				fmt.Sprintf("Email digests from Concert (%s) to %s are now paused. An administrator can re-enable delivery anytime in the Admin Portal Email tab.", nodeID, rcpt),
				"", "", rcpt, false)
			return
		}
		c.String(http.StatusOK, "Unsubscribed %s from Concert alerts.\n", rcpt)
	default:
		c.Header("Allow", "GET, POST")
		c.Status(http.StatusMethodNotAllowed)
	}
}

func renderUnsubPage(c *gin.Context, status int, title, heading, message, action, token, rcpt string, showForm bool) {
	if !wantsHTML(c.Request) && !showForm {
		c.String(status, "%s: %s\n", heading, message)
		return
	}
	var buf bytes.Buffer
	_ = unsubPageTmpl.Execute(&buf, struct {
		Title, Heading, Message, Action, Token, Recipient string
		ShowForm                                          bool
	}{title, heading, message, action, token, rcpt, showForm})
	c.Data(status, "text/html; charset=utf-8", buf.Bytes())
}
