package server

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/notify"
	"github.com/andreimerlescu/concert/internal/telemetry"
	"github.com/gin-gonic/gin"
)

const defaultPagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"

// normalizeObservability validates ChatOps notification settings and OTLP
// tracing parameters during config.normalize().
//
// # Parameters
//
// Receiver c is the *config being validated.
//
// # Returns
//
// nil on valid configuration, or an error describing the invalid flag/URL.
//
// # Example
//
//	if err := c.normalizeObservability(); err != nil {
//	    return err
//	}
//
// # Used By
//
// Called by config.normalize in internal/server/config.go.
func (c *config) normalizeObservability() error {
	if math.IsNaN(c.otlpSampleRate) || math.IsInf(c.otlpSampleRate, 0) || c.otlpSampleRate < 0 || c.otlpSampleRate > 1 {
		return fmt.Errorf("invalid -otlp-sample-rate %v: must be between 0.0 and 1.0", c.otlpSampleRate)
	}
	if ep := strings.TrimSpace(c.otlpEndpoint); ep != "" {
		if _, err := telemetry.ValidateEndpointURL(ep, c.observabilityAllowLoopbackHTTP); err != nil {
			return fmt.Errorf("invalid -otlp-endpoint: %w", err)
		}
	}
	if !c.notifySlackURL.IsZero() {
		if _, err := notify.ValidateEndpointURL(c.notifySlackURL.Reveal(), c.observabilityAllowLoopbackHTTP); err != nil {
			return fmt.Errorf("invalid -notify-slack-url: %w", err)
		}
	}
	if !c.notifyDiscordURL.IsZero() {
		if _, err := notify.ValidateEndpointURL(c.notifyDiscordURL.Reveal(), c.observabilityAllowLoopbackHTTP); err != nil {
			return fmt.Errorf("invalid -notify-discord-url: %w", err)
		}
	}
	if !c.notifyTeamsURL.IsZero() {
		if _, err := notify.ValidateEndpointURL(c.notifyTeamsURL.Reveal(), c.observabilityAllowLoopbackHTTP); err != nil {
			return fmt.Errorf("invalid -notify-teams-url: %w", err)
		}
	}
	if !c.notifyWebhookURL.IsZero() {
		if _, err := notify.ValidateEndpointURL(c.notifyWebhookURL.Reveal(), c.observabilityAllowLoopbackHTTP); err != nil {
			return fmt.Errorf("invalid -notify-webhook-url: %w", err)
		}
	}
	if !c.notifyPagerDutyKey.IsZero() {
		pdURL := strings.TrimSpace(c.notifyPagerDutyURL)
		if pdURL == "" {
			pdURL = defaultPagerDutyEventsURL
		}
		if _, err := notify.ValidateEndpointURL(pdURL, c.observabilityAllowLoopbackHTTP); err != nil {
			return fmt.Errorf("invalid pagerduty endpoint: %w", err)
		}
	}
	return nil
}

// initObservability starts the optional ChatOps notify.Dispatcher and pure-
// stdlib OTLP/HTTP JSON telemetry.Tracer, registering bounded graceful
// shutdown hooks on a.Close() (R2).
//
// # Parameters
//
//   - cfg: Normalized site configuration.
//
// # Returns
//
// nil on success, or an error if dispatcher/tracer initialization fails.
//
// # Example
//
//	if err := a.initObservability(cfg); err != nil {
//	    return nil, err
//	}
//
// # Used By
//
// Called by newApp in internal/server/app.go.
func (a *app) initObservability(cfg config) error {
	var targets []notify.TargetConfig
	if !cfg.notifySlackURL.IsZero() {
		targets = append(targets, notify.TargetConfig{
			Name: "slack",
			Type: notify.ChannelSlack,
			URL:  cfg.notifySlackURL.Reveal(),
		})
	}
	if !cfg.notifyDiscordURL.IsZero() {
		targets = append(targets, notify.TargetConfig{
			Name: "discord",
			Type: notify.ChannelDiscord,
			URL:  cfg.notifyDiscordURL.Reveal(),
		})
	}
	if !cfg.notifyTeamsURL.IsZero() {
		targets = append(targets, notify.TargetConfig{
			Name: "teams",
			Type: notify.ChannelTeams,
			URL:  cfg.notifyTeamsURL.Reveal(),
		})
	}
	if !cfg.notifyWebhookURL.IsZero() {
		targets = append(targets, notify.TargetConfig{
			Name:   "webhook",
			Type:   notify.ChannelWebhook,
			URL:    cfg.notifyWebhookURL.Reveal(),
			Secret: cfg.notifyWebhookSecret,
		})
	}
	if !cfg.notifyPagerDutyKey.IsZero() {
		pdURL := strings.TrimSpace(cfg.notifyPagerDutyURL)
		if pdURL == "" {
			pdURL = defaultPagerDutyEventsURL
		}
		targets = append(targets, notify.TargetConfig{
			Name:   "pagerduty",
			Type:   notify.ChannelPagerDuty,
			URL:    pdURL,
			Secret: cfg.notifyPagerDutyKey,
		})
	}

	if len(targets) > 0 {
		disp, err := notify.NewDispatcher(notify.Config{
			Targets:           targets,
			AllowLoopbackHTTP: cfg.observabilityAllowLoopbackHTTP,
			DisableCoalesce:   cfg.notifyDisableCoalesce,
			OnError: func(target string, err error) {
				log.Printf("notify: delivery to %s failed: %v", target, err)
			},
		})
		if err != nil {
			return fmt.Errorf("notify dispatcher: %w", err)
		}
		a.notifier = disp
		a.onClose(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = disp.Close(ctx)
		})
	}

	if ep := strings.TrimSpace(cfg.otlpEndpoint); ep != "" {
		tcfg := telemetry.DefaultConfig(ep)
		tcfg.ServiceName = "concert"
		tcfg.ServiceVersion = BinaryVersion()
		tcfg.SampleRate = cfg.otlpSampleRate
		tcfg.AuthHeaderName = cfg.otlpAuthHeaderName
		tcfg.AuthHeaderValue = cfg.otlpAuthHeader
		tcfg.AllowLoopbackHTTP = cfg.observabilityAllowLoopbackHTTP
		tcfg.ResourceAttrs = []telemetry.Attribute{
			telemetry.StringAttr("concert.edition", Edition()),
		}
		if cfg.siteHost != "" {
			tcfg.ResourceAttrs = append(tcfg.ResourceAttrs, telemetry.StringAttr("concert.site", cfg.siteHost))
		}
		tcfg.OnExportError = func(err error) {
			log.Printf("telemetry: OTLP export error: %v", err)
		}
		tr, err := telemetry.NewTracer(tcfg)
		if err != nil {
			if a.notifier != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_ = a.notifier.Close(ctx)
				cancel()
				a.notifier = nil
			}
			return fmt.Errorf("telemetry tracer: %w", err)
		}
		a.tracer = tr
		a.onClose(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tr.Shutdown(ctx)
		})
	}

	return nil
}

// dispatchChatOps forwards an operational alertEvent to the app's non-blocking
// notify.Dispatcher when ChatOps alerting is configured.
//
// # Parameters
//
//   - ev: Operational alert event.
//
// # Example
//
//	a.dispatchChatOps(ev)
//
// # Used By
//
// Called by app.notifyAlert in internal/server/enterprise_hooks.go and
// internal/server/enterprise_stub.go.
func (a *app) dispatchChatOps(ev alertEvent) {
	if a == nil || a.notifier == nil {
		return
	}
	var cat string
	switch ev.Category {
	case alertCatQueue:
		cat = notify.CatQueue
	case alertCatBans:
		cat = notify.CatBans
	case alertCatSecurity:
		cat = notify.CatSecurity
	case alertCatSilence:
		cat = notify.CatSilence
	case alertCatCapacity:
		cat = notify.CatCapacity
	case alertCatFastlane:
		cat = notify.CatFastlane
	default:
		cat = string(ev.Category)
	}
	var sev string
	switch ev.Severity {
	case alertSevCritical:
		sev = notify.SevCritical
	case alertSevWarn:
		sev = notify.SevWarn
	default:
		sev = notify.SevInfo
	}
	site := ""
	if g := a.current(); g != nil {
		site = g.cfg.siteHost
	}
	_ = a.notifier.Enqueue(notify.Event{
		Category:  cat,
		Severity:  sev,
		Title:     ev.Title,
		Summary:   ev.Summary,
		Site:      site,
		Timestamp: time.Now().UTC(),
		Details:   ev.Details,
		DedupKey:  ev.Fingerprint,
	})
}

// telemetryMiddleware extracts any incoming W3C traceparent header, starts a
// server span via internal/telemetry.Tracer, propagates the child traceparent
// both upstream (c.Request.Header) and on the response, and records final HTTP
// status and error state on span.End(). Zero overhead when tracing is off.
//
// # Parameters
//
//   - c: Active request *gin.Context.
//
// # Example
//
//	if g.a.tracer != nil {
//	    r.Use(g.telemetryMiddleware)
//	}
//
// # Used By
//
// Registered by buildRouter in internal/server/router.go.
func (g *generation) telemetryMiddleware(c *gin.Context) {
	if g.a == nil || g.a.tracer == nil {
		c.Next()
		return
	}

	ctx := c.Request.Context()
	if rawTP := c.GetHeader(telemetry.TraceparentHeader); rawTP != "" {
		if remoteSC, err := telemetry.ParseTraceparent(rawTP); err == nil {
			ctx = telemetry.ContextWithRemoteSpanContext(ctx, remoteSC)
		}
	}

	spanName := c.Request.Method + " " + clip(c.Request.URL.Path, 128)
	ctx, span := g.a.tracer.StartSpan(ctx, spanName)
	span.SetKind(telemetry.SpanKindServer)
	span.SetAttributes(
		telemetry.StringAttr("http.method", c.Request.Method),
		telemetry.StringAttr("url.path", clip(c.Request.URL.Path, 256)),
		telemetry.StringAttr("concert.edition", Edition()),
	)
	if g.cfg.siteHost != "" {
		span.SetAttributes(telemetry.StringAttr("concert.site", g.cfg.siteHost))
	}

	tp := span.Traceparent()
	if tp != "" {
		c.Request.Header.Set(telemetry.TraceparentHeader, tp)
		c.Header(telemetry.TraceparentHeader, tp)
		c.Set(ctxTraceID, span.SpanContext().TraceID.String())
	}
	c.Request = c.Request.WithContext(ctx)

	defer func() {
		status := c.Writer.Status()
		span.SetAttributes(
			telemetry.IntAttr("http.status_code", int64(status)),
			telemetry.BoolAttr("concert.admitted", c.GetBool(ctxAdmitted)),
		)
		if status >= http.StatusInternalServerError {
			span.SetStatus(telemetry.StatusError, http.StatusText(status))
		} else {
			span.SetStatus(telemetry.StatusOK, "")
		}
		span.End()
	}()

	c.Next()
}
