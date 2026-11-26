package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Operational event categories aligned with internal/mailer.
const (
	CatSilence  = "silence"
	CatCapacity = "capacity"
	CatBans     = "bans"
	CatFastlane = "fastlane"
	CatQueue    = "queue"
	CatSecurity = "security"
)

// AllCategories lists every built-in operational event category in display order.
var AllCategories = []string{
	CatSilence,
	CatCapacity,
	CatBans,
	CatFastlane,
	CatQueue,
	CatSecurity,
}

// Operational event severity levels aligned with internal/mailer.
const (
	SevInfo     = "info"
	SevWarn     = "warn"
	SevCritical = "critical"
)

// Supported ChatOps delivery channel types.
const (
	ChannelSlack     = "slack"
	ChannelPagerDuty = "pagerduty"
	ChannelDiscord   = "discord"
	ChannelTeams     = "teams"
	ChannelWebhook   = "webhook"
)

// Webhook HMAC signature headers attached to generic webhook deliveries.
const (
	HeaderTimestamp = "X-Concert-Timestamp"
	HeaderSignature = "X-Concert-Signature"
)

// PagerDuty event action values.
const (
	PagerDutyTrigger = "trigger"
	PagerDutyResolve = "resolve"
)

// Queue, retry, and response bounds enforcing R3 and E4.
const (
	DefaultMaxQueueSize   = 256
	MaxAllowedQueueSize   = 4096
	DefaultWorkers        = 2
	MaxAllowedWorkers     = 8
	DefaultCoalesceWindow = 30 * time.Second
	DefaultMaxRetries     = 3
	MaxAllowedRetries     = 8
	DefaultBaseBackoff    = 250 * time.Millisecond
	DefaultMaxBackoff     = 5 * time.Second
	DefaultRequestTimeout = 10 * time.Second
	maxResponseBodyBytes  = 4096
	maxEndpointURLLen     = 2048
	maxCoalesceEntries    = 4096
)

// Sentinel errors returned by validation, formatting, and dispatch operations.
var (
	ErrInvalidURL          = errors.New("invalid notification endpoint URL")
	ErrInsecureScheme      = errors.New("endpoint URL must use https")
	ErrURLUserinfo         = errors.New("endpoint URL must not contain userinfo")
	ErrBlockedAddress      = errors.New("endpoint resolves to a blocked private or loopback address")
	ErrUnsupportedChannel  = errors.New("unsupported notification channel type")
	ErrMissingRoutingKey   = errors.New("pagerduty channel requires a non-zero routing key secret")
	ErrDispatcherClosed    = errors.New("notification dispatcher is closed")
	ErrQueueFull           = errors.New("notification queue is full")
	ErrRedirectDisallowed  = errors.New("notification endpoint redirects are disallowed")
	ErrInvalidTargetConfig = errors.New("invalid notification target configuration")
)

// Event represents an operational alert dispatched to ChatOps channels.
// Callers may mutate Details after Enqueue returns because Enqueue clones it.
type Event struct {
	Category  string            `json:"category"`
	Severity  string            `json:"severity"`
	Title     string            `json:"title"`
	Summary   string            `json:"summary"`
	Site      string            `json:"site,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	Details   map[string]string `json:"details,omitempty"`
	// Action optionally selects "trigger" (default) or "resolve" for PagerDuty.
	Action string `json:"action,omitempty"`
	// DedupKey optionally overrides the default deduplication key for PagerDuty.
	DedupKey string `json:"dedup_key,omitempty"`
}

// TargetConfig configures one outbound ChatOps destination.
type TargetConfig struct {
	// Name is a human-readable identifier used in error callbacks (never a secret).
	Name string
	// Type selects one of ChannelSlack, ChannelPagerDuty, ChannelDiscord,
	// ChannelTeams, or ChannelWebhook.
	Type string
	// URL is the target webhook or API endpoint. Must be HTTPS unless
	// Config.AllowLoopbackHTTP is enabled for loopback test servers.
	URL string
	// Secret holds the channel credential: PagerDuty Events API v2 routing_key,
	// or HMAC-SHA256 signing key for ChannelWebhook.
	Secret Secret
	// MinSeverity optionally suppresses events below this severity ("info",
	// "warn", "critical"). Empty allows all severities.
	MinSeverity string
	// Categories optionally restricts delivery to listed categories. Empty
	// subscribes to all categories.
	Categories []string
}

// Config configures a Dispatcher. Zero values use safe production defaults
// except CoalesceWindow where a zero duration disables coalescing only when
// DisableCoalesce is true; otherwise zero defaults to DefaultCoalesceWindow.
type Config struct {
	Targets           []TargetConfig
	MaxQueueSize      int
	Workers           int
	CoalesceWindow    time.Duration
	DisableCoalesce   bool
	MaxRetries        int
	BaseBackoff       time.Duration
	MaxBackoff        time.Duration
	RequestTimeout    time.Duration
	AllowLoopbackHTTP bool
	// Clock overrides time.Now for deterministic unit tests. Nil uses time.Now.
	Clock func() time.Time
	// Sleep overrides retry backoff waiting for deterministic unit tests.
	// Nil uses a cancellable time.Timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// OnError is optionally called outside all locks when a delivery to a target
	// fails permanently after exhausting retries.
	OnError func(target string, err error)
}

// Stats is a point-in-time snapshot of Dispatcher counters.
type Stats struct {
	Enqueued  uint64
	Delivered uint64
	Dropped   uint64
	Coalesced uint64
	Failed    uint64
	Retries   uint64
}

type compiledTarget struct {
	name        string
	channelType string
	endpointURL string
	redactedURL string
	secret      Secret
	minSevRank  int
	categories  map[string]bool
}

// Dispatcher asynchronously formats and delivers operational Event alerts to
// one or more configured ChatOps targets.
//
// Ownership and concurrency:
//   - targets, client, and configuration parameters are immutable after NewDispatcher.
//   - mu guards closed, coalesce map, and non-blocking sends/close on queue.
//   - queue (bounded channel) transfers deep-copied Event values to a fixed pool
//     of worker goroutines started in NewDispatcher and joined in Close.
//   - atomic counters track Enqueued, Delivered, Dropped, Coalesced, Failed, and Retries.
type Dispatcher struct {
	targets        []compiledTarget
	client         *http.Client
	coalesceWindow time.Duration
	maxRetries     int
	baseBackoff    time.Duration
	maxBackoff     time.Duration
	requestTimeout time.Duration
	now            func() time.Time
	sleep          func(ctx context.Context, d time.Duration) error
	onError        func(target string, err error)

	mu       sync.Mutex
	closed   bool
	coalesce map[string]time.Time
	queue    chan Event

	workerCtx    context.Context
	workerCancel context.CancelFunc
	wg           sync.WaitGroup
	closeOnce    sync.Once

	enqueued  atomic.Uint64
	delivered atomic.Uint64
	dropped   atomic.Uint64
	coalesced atomic.Uint64
	failed    atomic.Uint64
	retries   atomic.Uint64
}

// NewDispatcher validates cfg, builds an SSRF-hardened HTTP client, and starts
// a bounded pool of background delivery workers. Callers must call Close to
// drain queued alerts and join all worker goroutines.
//
// # Parameters
//
//   - cfg: Dispatcher settings including targets, queue bounds, coalescing
//     window, and retry parameters. Targets are copied; mutating cfg after
//     NewDispatcher returns does not affect the running dispatcher.
//
// # Returns
//
// A ready-to-use Dispatcher and nil error on success, or nil and a validation
// error if any target URL, channel type, secret requirement, or bound is invalid.
//
// # Example
//
//	d, err := notify.NewDispatcher(notify.Config{
//	    Targets: []notify.TargetConfig{{
//	        Name: "ops-slack",
//	        Type: notify.ChannelSlack,
//	        URL:  "https://hooks.slack.com/services/T000/B000/XXX",
//	    }},
//	})
//	if err != nil {
//	    return err
//	}
//	defer d.Close(context.Background())
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :357 (direct call)
//   - :432 (direct call)
//   - :520 (direct call)
//   - :594 (direct call)
//   - :667 (direct call)
//   - :736 (direct call)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func NewDispatcher(cfg Config) (*Dispatcher, error) {
	maxQueue := cfg.MaxQueueSize
	if maxQueue < 0 || maxQueue > MaxAllowedQueueSize {
		return nil, fmt.Errorf("%w: MaxQueueSize %d out of range [0, %d]", ErrInvalidTargetConfig, maxQueue, MaxAllowedQueueSize)
	}
	if maxQueue == 0 {
		maxQueue = DefaultMaxQueueSize
	}

	workers := cfg.Workers
	if workers < 0 || workers > MaxAllowedWorkers {
		return nil, fmt.Errorf("%w: Workers %d out of range [0, %d]", ErrInvalidTargetConfig, workers, MaxAllowedWorkers)
	}
	if workers == 0 {
		workers = DefaultWorkers
	}

	coalesceWindow := cfg.CoalesceWindow
	if coalesceWindow < 0 {
		return nil, fmt.Errorf("%w: CoalesceWindow must be non-negative", ErrInvalidTargetConfig)
	}
	if coalesceWindow == 0 && !cfg.DisableCoalesce {
		coalesceWindow = DefaultCoalesceWindow
	}

	maxRetries := cfg.MaxRetries
	if maxRetries < 0 || maxRetries > MaxAllowedRetries {
		return nil, fmt.Errorf("%w: MaxRetries %d out of range [0, %d]", ErrInvalidTargetConfig, maxRetries, MaxAllowedRetries)
	}
	if maxRetries == 0 && cfg.BaseBackoff == 0 {
		maxRetries = DefaultMaxRetries
	}

	baseBackoff := cfg.BaseBackoff
	if baseBackoff < 0 {
		return nil, fmt.Errorf("%w: BaseBackoff must be non-negative", ErrInvalidTargetConfig)
	}
	if baseBackoff == 0 {
		baseBackoff = DefaultBaseBackoff
	}

	maxBackoff := cfg.MaxBackoff
	if maxBackoff < 0 {
		return nil, fmt.Errorf("%w: MaxBackoff must be non-negative", ErrInvalidTargetConfig)
	}
	if maxBackoff == 0 {
		maxBackoff = DefaultMaxBackoff
	}
	if maxBackoff < baseBackoff {
		maxBackoff = baseBackoff
	}

	reqTimeout := cfg.RequestTimeout
	if reqTimeout < 0 {
		return nil, fmt.Errorf("%w: RequestTimeout must be non-negative", ErrInvalidTargetConfig)
	}
	if reqTimeout == 0 {
		reqTimeout = DefaultRequestTimeout
	}

	compiled := make([]compiledTarget, 0, len(cfg.Targets))
	for i, tc := range cfg.Targets {
		ct, err := compileTarget(i, tc, cfg.AllowLoopbackHTTP)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, ct)
	}

	nowFn := cfg.Clock
	if nowFn == nil {
		nowFn = time.Now
	}
	sleepFn := cfg.Sleep
	if sleepFn == nil {
		sleepFn = defaultSleep
	}

	client := newHardenedHTTPClient(cfg.AllowLoopbackHTTP, reqTimeout)
	wctx, wcancel := context.WithCancel(context.Background())

	d := &Dispatcher{
		targets:        compiled,
		client:         client,
		coalesceWindow: coalesceWindow,
		maxRetries:     maxRetries,
		baseBackoff:    baseBackoff,
		maxBackoff:     maxBackoff,
		requestTimeout: reqTimeout,
		now:            nowFn,
		sleep:          sleepFn,
		onError:        cfg.OnError,
		coalesce:       make(map[string]time.Time),
		queue:          make(chan Event, maxQueue),
		workerCtx:      wctx,
		workerCancel:   wcancel,
	}

	for range workers {
		d.wg.Go(d.workerLoop)
	}
	return d, nil
}

// compileTarget validates one TargetConfig and produces an immutable
// compiledTarget snapshot for worker goroutines.
//
// # Parameters
//
//   - index: Zero-based target position used for fallback naming in diagnostics.
//   - tc: Caller-supplied TargetConfig to validate.
//   - allowLoopbackHTTP: Whether loopback HTTP targets are permitted.
//
// # Returns
//
// A validated compiledTarget or an error wrapping ErrUnsupportedChannel,
// ErrInvalidURL, ErrInsecureScheme, ErrURLUserinfo, ErrBlockedAddress, or
// ErrMissingRoutingKey.
//
// # Example
//
//	ct, err := compileTarget(0, tc, false)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :330 (direct call)
//   - :330 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func compileTarget(index int, tc TargetConfig, allowLoopbackHTTP bool) (compiledTarget, error) {
	chType := strings.ToLower(strings.TrimSpace(tc.Type))
	switch chType {
	case ChannelSlack, ChannelPagerDuty, ChannelDiscord, ChannelTeams, ChannelWebhook:
	default:
		return compiledTarget{}, fmt.Errorf("target[%d]: %w %q", index, ErrUnsupportedChannel, tc.Type)
	}

	parsed, err := ValidateEndpointURL(tc.URL, allowLoopbackHTTP)
	if err != nil {
		return compiledTarget{}, fmt.Errorf("target[%d] (%s): %w", index, chType, err)
	}
	if chType == ChannelPagerDuty && tc.Secret.IsZero() {
		return compiledTarget{}, fmt.Errorf("target[%d] (%s): %w", index, chType, ErrMissingRoutingKey)
	}

	name := strings.TrimSpace(tc.Name)
	if name == "" {
		name = fmt.Sprintf("%s-%d", chType, index)
	}

	minRank := 0
	if s := strings.ToLower(strings.TrimSpace(tc.MinSeverity)); s != "" {
		switch s {
		case SevInfo, SevWarn, SevCritical:
			minRank = SeverityRank(s)
		default:
			return compiledTarget{}, fmt.Errorf("target[%d] (%s): %w: unknown MinSeverity %q", index, name, ErrInvalidTargetConfig, tc.MinSeverity)
		}
	}

	var cats map[string]bool
	if len(tc.Categories) > 0 {
		cats = make(map[string]bool, len(tc.Categories))
		for _, c := range tc.Categories {
			if norm := strings.ToLower(strings.TrimSpace(c)); norm != "" {
				cats[norm] = true
			}
		}
	}

	return compiledTarget{
		name:        name,
		channelType: chType,
		endpointURL: parsed.String(),
		redactedURL: RedactURL(parsed),
		secret:      tc.Secret,
		minSevRank:  minRank,
		categories:  cats,
	}, nil
}

// Enqueue submits ev for asynchronous delivery without blocking the caller.
// It applies per-category coalescing within CoalesceWindow and drops new events
// cleanly with an incremented Dropped counter when the bounded queue is full.
// Safe for concurrent use by any number of proxy handler goroutines.
//
// # Parameters
//
//   - ev: Operational event to queue. Details is cloned before queuing, so the
//     caller may continue mutating ev.Details after Enqueue returns.
//
// # Returns
//
// nil if the event was enqueued or coalesced; ErrDispatcherClosed if Close has
// been called; ErrQueueFull if the bounded queue is saturated and the event was
// dropped.
//
// # Example
//
//	err := d.Enqueue(notify.Event{
//	    Category: notify.CatCapacity,
//	    Severity: notify.SevCritical,
//	    Title:    "Capacity breaker active",
//	    Summary:  "Waiting room rejecting arrivals with 503",
//	})
//	if errors.Is(err, notify.ErrQueueFull) {
//	    // Backpressure drop is already accounted for in d.Stats().Dropped.
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :374 (direct call)
//   - :449 (direct call)
//   - :540 (direct call)
//   - :609 (direct call)
//   - :614 (direct call)
//   - :619 (direct call)
//   - :682 (direct call)
//   - :688 (direct call)
//   - :691 (direct call)
//   - :694 (direct call)
//   - :706 (direct call)
//   - :753 (direct call)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (d *Dispatcher) Enqueue(ev Event) error {
	now := d.now()
	cloned := cloneEvent(ev, now)

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return ErrDispatcherClosed
	}

	if d.coalesceWindow > 0 {
		key := coalesceKey(cloned)
		if last, ok := d.coalesce[key]; ok && now.Sub(last) < d.coalesceWindow {
			d.mu.Unlock()
			d.coalesced.Add(1)
			return nil
		}
		if len(d.coalesce) >= maxCoalesceEntries {
			pruneCoalesceMapLocked(d.coalesce, now, d.coalesceWindow)
		}
		d.coalesce[key] = now
	}

	// Non-blocking send under mu guarantees Close cannot race to close d.queue
	// while a send is in progress, and guarantees proxy handlers never block.
	select {
	case d.queue <- cloned:
		d.mu.Unlock()
		d.enqueued.Add(1)
		return nil
	default:
		d.mu.Unlock()
		d.dropped.Add(1)
		return ErrQueueFull
	}
}

// Stats returns a point-in-time snapshot of dispatcher counters. Safe for
// concurrent use.
//
// # Parameters
//
// None.
//
// # Returns
//
// A Stats value populated from atomic counters.
//
// # Example
//
//	st := d.Stats()
//	fmt.Println(st.Delivered, st.Dropped, st.Coalesced)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :466 (direct call)
//   - :547 (direct call)
//   - :627 (direct call)
//   - :710 (direct call)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (d *Dispatcher) Stats() Stats {
	return Stats{
		Enqueued:  d.enqueued.Load(),
		Delivered: d.delivered.Load(),
		Dropped:   d.dropped.Load(),
		Coalesced: d.coalesced.Load(),
		Failed:    d.failed.Load(),
		Retries:   d.retries.Load(),
	}
}

// Close stops accepting new events, drains queued events across worker
// goroutines until either the queue empties or ctx expires, and joins all
// worker goroutines before returning. Subsequent calls to Close are idempotent
// no-ops that return nil.
//
// # Parameters
//
//   - ctx: Controls the maximum time to wait for graceful draining of queued
//     events. Must be non-nil. When ctx expires, in-flight HTTP deliveries and
//     retry sleeps are cancelled so workers exit promptly.
//
// # Returns
//
// nil if all queued events drained cleanly before ctx expired, or ctx.Err() if
// shutdown had to cancel in-flight work.
//
// # Example
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//	if err := d.Close(ctx); err != nil {
//	    return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :377 (direct call)
//   - :462 (direct call)
//   - :543 (direct call)
//   - :623 (direct call)
//   - :699 (direct call)
//   - :703 (direct call)
//   - :762 (direct call)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (d *Dispatcher) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		close(d.queue)
		d.mu.Unlock()
	})

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		d.workerCancel()
		d.client.CloseIdleConnections()
		return nil
	case <-ctx.Done():
		// Cancel workerCtx to abort active HTTP requests and retry backoff
		// timers, then wait for workers to join so no goroutines leak (R2).
		d.workerCancel()
		<-done
		d.client.CloseIdleConnections()
		return ctx.Err()
	}
}

// workerLoop consumes queued events until d.queue is closed and drained,
// delivering each event to matching targets.
//
// # Parameters
//
// None.
//
// # Example
//
//	d.wg.Go(d.workerLoop)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :367 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (d *Dispatcher) workerLoop() {
	for ev := range d.queue {
		if d.workerCtx.Err() != nil {
			return
		}
		for _, target := range d.targets {
			if d.workerCtx.Err() != nil {
				return
			}
			if !targetMatchesEvent(target, ev) {
				continue
			}
			if err := d.deliverWithRetry(d.workerCtx, target, ev); err != nil {
				d.failed.Add(1)
				if d.onError != nil {
					d.onError(target.name, err)
				}
			} else {
				d.delivered.Add(1)
			}
		}
	}
}

// targetMatchesEvent reports whether target subscribes to ev's severity and
// category.
//
// # Parameters
//
//   - target: Immutable compiled target configuration.
//   - ev: Normalized operational event.
//
// # Returns
//
// true if the event passes the target's severity and category filters.
//
// # Example
//
//	if targetMatchesEvent(target, ev) {
//	    _ = d.deliverWithRetry(ctx, target, ev)
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :668 (direct call)
//   - :668 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func targetMatchesEvent(target compiledTarget, ev Event) bool {
	if target.minSevRank > 0 && SeverityRank(ev.Severity) < target.minSevRank {
		return false
	}
	if len(target.categories) > 0 && !target.categories[ev.Category] {
		return false
	}
	return true
}

// deliverWithRetry formats ev for target and delivers it over HTTP with bounded
// exponential backoff retries on transient 5xx, 429, or transport errors.
//
// # Parameters
//
//   - ctx: Worker lifecycle context; cancellation aborts requests and backoff.
//   - target: Immutable compiled target to deliver to.
//   - ev: Normalized event to format and send.
//
// # Returns
//
// nil on HTTP 2xx delivery, or a secret-free error after retries are exhausted
// or on non-retryable failure.
//
// # Example
//
//	err := d.deliverWithRetry(ctx, target, ev)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :671 (direct call)
//   - :671 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (d *Dispatcher) deliverWithRetry(ctx context.Context, target compiledTarget, ev Event) error {
	body, err := formatForTarget(target, ev)
	if err != nil {
		return fmt.Errorf("format %s payload for %s: %w", target.channelType, target.name, err)
	}

	var lastErr error
	for attempt := 0; attempt <= d.maxRetries; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		retryable, retryAfter, err := d.sendOnce(ctx, target, body)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retryable || attempt == d.maxRetries {
			return lastErr
		}

		d.retries.Add(1)
		delay := computeBackoff(attempt, d.baseBackoff, d.maxBackoff, retryAfter)
		if sleepErr := d.sleep(ctx, delay); sleepErr != nil {
			return sleepErr
		}
	}
	return lastErr
}

// sendOnce executes a single bounded HTTP POST delivery to target.
//
// # Parameters
//
//   - ctx: Parent context for request cancellation.
//   - target: Immutable compiled target holding endpoint URL and optional secret.
//   - body: Pre-encoded JSON payload bytes.
//
// # Returns
//
// retryable indicating whether the caller should retry (true for transport
// errors, 429, and 5xx), retryAfter parsed from a numeric Retry-After header if
// present, and any secret-free delivery error.
//
// # Example
//
//	retryable, retryAfter, err := d.sendOnce(ctx, target, payload)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :757 (direct call)
//   - :757 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (d *Dispatcher) sendOnce(ctx context.Context, target compiledTarget, body []byte) (bool, time.Duration, error) {
	reqCtx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, target.endpointURL, bytes.NewReader(body))
	if err != nil {
		return false, 0, fmt.Errorf("build request to %s: %w", target.redactedURL, sanitizeURLError(err, target.redactedURL))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "concert-notify/1.0")

	if target.channelType == ChannelWebhook {
		ts := d.now().UTC().Unix()
		req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
		if !target.secret.IsZero() {
			req.Header.Set(HeaderSignature, SignWebhookPayload(target.secret, ts, body))
		}
	}

	resp, err := d.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return false, 0, ctx.Err()
		}
		if errors.Is(err, ErrBlockedAddress) || errors.Is(err, ErrRedirectDisallowed) {
			return false, 0, fmt.Errorf("deliver to %s: %w", target.redactedURL, sanitizeURLError(err, target.redactedURL))
		}
		return true, 0, fmt.Errorf("deliver to %s: %w", target.redactedURL, sanitizeURLError(err, target.redactedURL))
	}
	defer func() { _ = resp.Body.Close() }()

	// Bound response body reads so a hostile/broken receiver cannot exhaust memory (R3).
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBodyBytes))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, 0, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return true, parseRetryAfter(resp.Header.Get("Retry-After")), fmt.Errorf("deliver to %s: HTTP %d", target.redactedURL, resp.StatusCode)
	}
	return false, 0, fmt.Errorf("deliver to %s: non-retryable HTTP %d", target.redactedURL, resp.StatusCode)
}

// formatForTarget selects the built-in formatter matching target.channelType.
//
// # Parameters
//
//   - target: Compiled target describing the channel type and optional secret.
//   - ev: Normalized event to serialize.
//
// # Returns
//
// JSON payload bytes or an encoding/validation error.
//
// # Example
//
//	body, err := formatForTarget(target, ev)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :746 (direct call)
//   - :746 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func formatForTarget(target compiledTarget, ev Event) ([]byte, error) {
	switch target.channelType {
	case ChannelSlack:
		return FormatSlackPayload(ev)
	case ChannelPagerDuty:
		return FormatPagerDutyPayload(ev, target.secret)
	case ChannelDiscord:
		return FormatDiscordPayload(ev)
	case ChannelTeams:
		return FormatTeamsPayload(ev)
	case ChannelWebhook:
		return FormatWebhookPayload(ev)
	default:
		return nil, fmt.Errorf("%w %q", ErrUnsupportedChannel, target.channelType)
	}
}

// FormatSlackPayload formats ev into a Slack Incoming Webhook JSON payload
// combining Block Kit blocks with a severity-colored attachment.
//
// # Parameters
//
//   - ev: Operational event to format.
//
// # Returns
//
// Valid JSON bytes suitable for posting to a Slack webhook endpoint, or a
// marshaling error.
//
// # Example
//
//	body, err := notify.FormatSlackPayload(notify.Event{
//	    Category: notify.CatCapacity,
//	    Severity: notify.SevCritical,
//	    Title:    "Capacity breaker active",
//	    Summary:  "Queue reached ceiling",
//	})
//	if err != nil {
//	    return err
//	}
//	_ = body
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :199 (direct call)
//   - :870 (direct call)
//   - :870 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func FormatSlackPayload(ev Event) ([]byte, error) {
	ev = normalizeEvent(ev)
	color := "#1570ef"
	switch ev.Severity {
	case SevCritical:
		color = "#d92d20"
	case SevWarn:
		color = "#f79009"
	}

	headerText := fmt.Sprintf("[%s] %s", strings.ToUpper(ev.Severity), ev.Title)
	if len(headerText) > 150 {
		headerText = headerText[:147] + "..."
	}

	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{
				"type":  "plain_text",
				"text":  headerText,
				"emoji": false,
			},
		},
		{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": ev.Summary,
			},
		},
	}

	fields := make([]map[string]any, 0, len(ev.Details)+2)
	fields = append(fields,
		map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("*Category:*\n%s", ev.Category)},
		map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("*Severity:*\n%s", ev.Severity)},
	)
	if ev.Site != "" {
		fields = append(fields, map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("*Site:*\n%s", ev.Site)})
	}
	for _, k := range sortedKeys(ev.Details) {
		fields = append(fields, map[string]any{
			"type": "mrkdwn",
			"text": fmt.Sprintf("*%s:*\n%s", k, ev.Details[k]),
		})
	}
	if len(fields) > 0 {
		blocks = append(blocks, map[string]any{
			"type":   "section",
			"fields": fields,
		})
	}
	blocks = append(blocks, map[string]any{
		"type": "context",
		"elements": []map[string]any{
			{
				"type": "mrkdwn",
				"text": fmt.Sprintf("Concert alert at %s", ev.Timestamp.UTC().Format(time.RFC3339)),
			},
		},
	})

	payload := map[string]any{
		"text":   fmt.Sprintf("[%s] %s: %s", strings.ToUpper(ev.Severity), ev.Title, ev.Summary),
		"blocks": blocks,
		"attachments": []map[string]any{
			{
				"color": color,
				"title": ev.Title,
				"text":  ev.Summary,
				"ts":    ev.Timestamp.UTC().Unix(),
			},
		},
	}
	return json.Marshal(payload)
}

// FormatPagerDutyPayload formats ev into a PagerDuty Events API v2 JSON
// payload using routingKey as the routing_key and deriving a deterministic
// dedup_key when ev.DedupKey is empty.
//
// # Parameters
//
//   - ev: Operational event to format. ev.Action defaults to PagerDutyTrigger
//     ("trigger") unless set to PagerDutyResolve ("resolve").
//   - routingKey: Redacted PagerDuty integration routing key; must be non-zero.
//
// # Returns
//
// Valid JSON bytes for PagerDuty Events API v2, or ErrMissingRoutingKey when
// routingKey is zero.
//
// # Example
//
//	body, err := notify.FormatPagerDutyPayload(ev, routingKey)
//	if err != nil {
//	    return err
//	}
//	_ = body
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :216 (direct call)
//   - :220 (direct call)
//   - :238 (direct call)
//   - :872 (direct call)
//   - :872 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func FormatPagerDutyPayload(ev Event, routingKey Secret) ([]byte, error) {
	if routingKey.IsZero() {
		return nil, ErrMissingRoutingKey
	}
	ev = normalizeEvent(ev)

	action := strings.ToLower(strings.TrimSpace(ev.Action))
	if action != PagerDutyResolve {
		action = PagerDutyTrigger
	}

	pdSeverity := "info"
	switch ev.Severity {
	case SevCritical:
		pdSeverity = "critical"
	case SevWarn:
		pdSeverity = "warning"
	}

	source := ev.Site
	if source == "" {
		source = "concert"
	}

	dedupKey := strings.TrimSpace(ev.DedupKey)
	if dedupKey == "" {
		dedupKey = defaultDedupKey(ev)
	}

	summary := ev.Title
	if ev.Summary != "" {
		summary = ev.Title + ": " + ev.Summary
	}
	if len(summary) > 1024 {
		summary = summary[:1024]
	}

	customDetails := make(map[string]string, len(ev.Details)+2)
	maps.Copy(customDetails, ev.Details)
	customDetails["category"] = ev.Category
	if ev.Site != "" {
		customDetails["site"] = ev.Site
	}

	payload := map[string]any{
		"routing_key":  routingKey.Reveal(),
		"event_action": action,
		"dedup_key":    dedupKey,
		"payload": map[string]any{
			"summary":        summary,
			"source":         source,
			"severity":       pdSeverity,
			"timestamp":      ev.Timestamp.UTC().Format(time.RFC3339),
			"component":      "concert",
			"group":          ev.Category,
			"custom_details": customDetails,
		},
	}
	return json.Marshal(payload)
}

// FormatDiscordPayload formats ev into a Discord Webhook JSON payload with a
// severity-colored rich embed and sorted detail fields.
//
// # Parameters
//
//   - ev: Operational event to format.
//
// # Returns
//
// Valid JSON bytes for a Discord webhook endpoint, or a marshaling error.
//
// # Example
//
//	body, err := notify.FormatDiscordPayload(ev)
//	if err != nil {
//	    return err
//	}
//	_ = body
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :251 (direct call)
//   - :874 (direct call)
//   - :874 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func FormatDiscordPayload(ev Event) ([]byte, error) {
	ev = normalizeEvent(ev)
	color := 0x1570ef
	switch ev.Severity {
	case SevCritical:
		color = 0xd92d20
	case SevWarn:
		color = 0xf79009
	}

	fields := make([]map[string]any, 0, len(ev.Details)+3)
	fields = append(fields,
		map[string]any{"name": "Category", "value": ev.Category, "inline": true},
		map[string]any{"name": "Severity", "value": ev.Severity, "inline": true},
	)
	if ev.Site != "" {
		fields = append(fields, map[string]any{"name": "Site", "value": ev.Site, "inline": true})
	}
	for _, k := range sortedKeys(ev.Details) {
		fields = append(fields, map[string]any{
			"name":   k,
			"value":  ev.Details[k],
			"inline": true,
		})
	}

	payload := map[string]any{
		"username": "Concert",
		"embeds": []map[string]any{
			{
				"title":       ev.Title,
				"description": ev.Summary,
				"color":       color,
				"timestamp":   ev.Timestamp.UTC().Format(time.RFC3339),
				"fields":      fields,
				"footer": map[string]any{
					"text": "Concert Operational Alert",
				},
			},
		},
	}
	return json.Marshal(payload)
}

// FormatTeamsPayload formats ev into a Microsoft Teams Adaptive Card webhook
// JSON payload with severity accent styling and a sorted FactSet.
//
// # Parameters
//
//   - ev: Operational event to format.
//
// # Returns
//
// Valid JSON bytes for a Microsoft Teams webhook endpoint, or a marshaling error.
//
// # Example
//
//	body, err := notify.FormatTeamsPayload(ev)
//	if err != nil {
//	    return err
//	}
//	_ = body
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :265 (direct call)
//   - :876 (direct call)
//   - :876 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func FormatTeamsPayload(ev Event) ([]byte, error) {
	ev = normalizeEvent(ev)
	color := "accent"
	switch ev.Severity {
	case SevCritical:
		color = "attention"
	case SevWarn:
		color = "warning"
	}

	facts := make([]map[string]string, 0, len(ev.Details)+4)
	facts = append(facts,
		map[string]string{"title": "Category", "value": ev.Category},
		map[string]string{"title": "Severity", "value": ev.Severity},
		map[string]string{"title": "Timestamp", "value": ev.Timestamp.UTC().Format(time.RFC3339)},
	)
	if ev.Site != "" {
		facts = append(facts, map[string]string{"title": "Site", "value": ev.Site})
	}
	for _, k := range sortedKeys(ev.Details) {
		facts = append(facts, map[string]string{"title": k, "value": ev.Details[k]})
	}

	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body": []map[string]any{
			{
				"type":   "TextBlock",
				"size":   "Large",
				"weight": "Bolder",
				"color":  color,
				"text":   fmt.Sprintf("[%s] %s", strings.ToUpper(ev.Severity), ev.Title),
				"wrap":   true,
			},
			{
				"type": "TextBlock",
				"text": ev.Summary,
				"wrap": true,
			},
			{
				"type":  "FactSet",
				"facts": facts,
			},
		},
	}

	payload := map[string]any{
		"type": "message",
		"attachments": []map[string]any{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"contentUrl":  nil,
				"content":     card,
			},
		},
	}
	return json.Marshal(payload)
}

// FormatWebhookPayload formats ev into Concert's canonical generic JSON
// webhook body.
//
// # Parameters
//
//   - ev: Operational event to serialize.
//
// # Returns
//
// JSON bytes encoding the normalized Event, or a marshaling error.
//
// # Example
//
//	body, err := notify.FormatWebhookPayload(ev)
//	if err != nil {
//	    return err
//	}
//	sig := notify.SignWebhookPayload(secret, time.Now().Unix(), body)
//	_ = sig
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :279 (direct call)
//   - :878 (direct call)
//   - :878 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func FormatWebhookPayload(ev Event) ([]byte, error) {
	ev = normalizeEvent(ev)
	return json.Marshal(ev)
}

// SignWebhookPayload computes the X-Concert-Signature header value
// ("sha256=<hex>") as HMAC-SHA256(secret, "<timestamp>.<body>").
//
// # Parameters
//
//   - secret: Redacting HMAC signing key; returns "" if zero.
//   - timestamp: Unix epoch seconds also transmitted in X-Concert-Timestamp.
//   - body: Exact raw JSON payload bytes transmitted in the HTTP request body.
//
// # Returns
//
// A "sha256=<64-hex>" signature string, or "" when secret is zero.
//
// # Example
//
//	ts := time.Now().UTC().Unix()
//	sig := notify.SignWebhookPayload(secret, ts, body)
//	req.Header.Set(notify.HeaderTimestamp, strconv.FormatInt(ts, 10))
//	req.Header.Set(notify.HeaderSignature, sig)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :284 (direct call)
//   - :783 (direct call)
//   - :816 (direct call)
//   - :816 (function value)
//   - :1372 (direct call)
//   - :1372 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func SignWebhookPayload(secret Secret, timestamp int64, body []byte) string {
	if secret.IsZero() {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret.Reveal()))
	_, _ = mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature validates X-Concert-Timestamp and X-Concert-Signature
// against body using constant-time HMAC comparison.
//
// # Parameters
//
//   - secret: Redacting HMAC signing key; returns false if zero.
//   - timestampHeader: Value of the X-Concert-Timestamp HTTP header.
//   - signatureHeader: Value of the X-Concert-Signature HTTP header.
//   - body: Exact raw HTTP request body bytes received.
//
// # Returns
//
// true if timestampHeader is a valid integer Unix timestamp and signatureHeader
// matches the expected HMAC-SHA256 digest in constant time.
//
// # Example
//
//	ok := notify.VerifyWebhookSignature(
//	    secret,
//	    r.Header.Get(notify.HeaderTimestamp),
//	    r.Header.Get(notify.HeaderSignature),
//	    body,
//	)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :289 (direct call)
//   - :292 (direct call)
//   - :295 (direct call)
//   - :420 (direct call)
//   - :785 (direct call)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func VerifyWebhookSignature(secret Secret, timestampHeader, signatureHeader string, body []byte) bool {
	if secret.IsZero() {
		return false
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(timestampHeader), 10, 64)
	if err != nil {
		return false
	}
	expected := SignWebhookPayload(secret, ts, body)
	return hmac.Equal([]byte(expected), []byte(strings.TrimSpace(signatureHeader)))
}

// ValidateEndpointURL enforces strict S9 URL rules for notification endpoints:
// rejects control characters, userinfo, non-HTTPS schemes (except explicit
// loopback opt-in for tests), and private/link-local/loopback literal IPs.
//
// # Parameters
//
//   - rawURL: Candidate endpoint URL string.
//   - allowLoopbackHTTP: When true, permits http:// and https:// targets bound
//     strictly to loopback hosts (localhost, 127.0.0.1, ::1) for local tests.
//
// # Returns
//
// The parsed *url.URL on success, or an error wrapping ErrInvalidURL,
// ErrURLUserinfo, ErrInsecureScheme, or ErrBlockedAddress.
//
// # Example
//
//	u, err := notify.ValidateEndpointURL("https://hooks.slack.com/services/a/b/c", false)
//	if err != nil {
//	    return err
//	}
//	_ = u
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :337 (direct call)
//   - :407 (direct call)
//   - :407 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func ValidateEndpointURL(rawURL string, allowLoopbackHTTP bool) (*url.URL, error) {
	s := strings.TrimSpace(rawURL)
	if s == "" || len(s) > maxEndpointURLLen || strings.ContainsAny(s, "\r\n\x00 \t\"<>") {
		return nil, ErrInvalidURL
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return nil, ErrInvalidURL
	}
	if u.User != nil {
		return nil, ErrURLUserinfo
	}
	host := u.Hostname()
	if host == "" {
		return nil, ErrInvalidURL
	}
	if port := u.Port(); port != "" {
		p, perr := strconv.Atoi(port)
		if perr != nil || p < 1 || p > 65535 {
			return nil, ErrInvalidURL
		}
	}

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
	case "http":
		if !allowLoopbackHTTP || !isLoopbackHost(host) {
			return nil, ErrInsecureScheme
		}
	default:
		return nil, ErrInsecureScheme
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		if isBlockedAddr(ip, allowLoopbackHTTP) {
			return nil, ErrBlockedAddress
		}
	} else if strings.EqualFold(host, "localhost") && !allowLoopbackHTTP {
		return nil, ErrBlockedAddress
	}

	return u, nil
}

// RedactURL returns a log-safe scheme://host string for u without userinfo,
// path tokens, query parameters, or fragments.
//
// # Parameters
//
//   - u: Parsed URL to redact; nil returns "".
//
// # Returns
//
// A redacted string safe for inclusion in errors and logs.
//
// # Example
//
//	u, _ := url.Parse("https://hooks.slack.com/services/T/B/secret")
//	fmt.Println(notify.RedactURL(u)) // https://hooks.slack.com
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :444 (direct call)
//   - :444 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func RedactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// SeverityRank maps a severity string to a comparable ordering weight where
// higher values indicate higher urgency (info=1, warn=2, critical=3).
//
// # Parameters
//
//   - sev: Severity label ("info", "warn", or "critical", case-insensitive).
//
// # Returns
//
// Integer rank 1, 2, or 3. Unknown values default to 1.
//
// # Example
//
//	if notify.SeverityRank(ev.Severity) >= notify.SeverityRank(notify.SevWarn) {
//	    _ = d.Enqueue(ev)
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :424 (direct call)
//   - :424 (function value)
//   - :710 (direct call)
//   - :710 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func SeverityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case SevCritical:
		return 3
	case SevWarn:
		return 2
	default:
		return 1
	}
}

// newHardenedHTTPClient constructs a reusable http.Client with TLS >= 1.2,
// disabled redirects, bounded timeouts, and a custom DialContext SSRF guard.
//
// # Parameters
//
//   - allowLoopback: Permits connections to loopback addresses when true.
//   - timeout: Overall per-request HTTP timeout.
//
// # Returns
//
// A configured *http.Client safe for concurrent use by worker goroutines.
//
// # Example
//
//	client := newHardenedHTTPClient(false, 10*time.Second)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :346 (direct call)
//   - :346 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func newHardenedHTTPClient(allowLoopback bool, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           ssrfGuardedDialContext(dialer, allowLoopback),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrRedirectDisallowed
		},
	}
}

// ssrfGuardedDialContext returns a DialContext function that resolves host IPs,
// rejects any blocked private/link-local/loopback IP before connecting, and
// dials the verified literal IP directly to prevent DNS rebinding.
//
// # Parameters
//
//   - dialer: Underlying *net.Dialer used once an IP passes policy checks.
//   - allowLoopback: Whether loopback addresses are permitted.
//
// # Returns
//
// A DialContext function compatible with http.Transport.DialContext.
//
// # Example
//
//	tr := &http.Transport{DialContext: ssrfGuardedDialContext(&net.Dialer{}, false)}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :1553 (direct call)
//   - :1553 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func ssrfGuardedDialContext(dialer *net.Dialer, allowLoopback bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidURL, err)
		}

		// Literal IP addresses bypass DNS lookup and are checked directly.
		if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
			if isBlockedAddr(ip, allowLoopback) {
				return nil, ErrBlockedAddress
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		}

		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, ErrBlockedAddress
		}

		var allowed []netip.Addr
		for _, ipAddr := range ips {
			parsed, ok := netip.AddrFromSlice(ipAddr.IP)
			if !ok {
				continue
			}
			// Reject the whole resolution if ANY record points to a blocked
			// range so dual-homed DNS records cannot smuggle SSRF traffic.
			if isBlockedAddr(parsed, allowLoopback) {
				return nil, ErrBlockedAddress
			}
			allowed = append(allowed, parsed.Unmap())
		}
		if len(allowed) == 0 {
			return nil, ErrBlockedAddress
		}

		var lastErr error
		for _, ip := range allowed {
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// isBlockedAddr reports whether addr falls in a private, link-local,
// unspecified, multicast, CGNAT, or (unless allowLoopback is true) loopback
// address range.
//
// # Parameters
//
//   - addr: Candidate IP address (IPv4, IPv6, or IPv4-mapped IPv6).
//   - allowLoopback: When true, loopback addresses (127.0.0.0/8, ::1) are allowed.
//
// # Returns
//
// true if outbound connections to addr must be blocked.
//
// # Example
//
//	blocked := isBlockedAddr(netip.MustParseAddr("169.254.169.254"), false)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :1443 (direct call)
//   - :1443 (function value)
//   - :1607 (direct call)
//   - :1607 (function value)
//   - :1629 (direct call)
//   - :1629 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func isBlockedAddr(addr netip.Addr, allowLoopback bool) bool {
	if !addr.IsValid() {
		return true
	}
	ip := addr.Unmap()
	if ip.IsLoopback() {
		return !allowLoopback
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	if ip.Is4() && cgnatPrefix.Contains(ip) {
		return true
	}
	return false
}

// isLoopbackHost reports whether host is "localhost" or a loopback IP literal.
//
// # Parameters
//
//   - host: Hostname or IP literal without port.
//
// # Returns
//
// true if host identifies the local loopback interface.
//
// # Example
//
//	if isLoopbackHost("127.0.0.1") {
//	    // Allowed only when AllowLoopbackHTTP is enabled.
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :1435 (direct call)
//   - :1435 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

// cloneEvent returns an isolated copy of ev with normalized fields and a
// non-zero UTC timestamp so queued events share no mutable maps with callers.
//
// # Parameters
//
//   - ev: Caller-supplied operational event.
//   - now: Fallback timestamp used when ev.Timestamp is zero.
//
// # Returns
//
// A normalized Event whose Details map is freshly cloned.
//
// # Example
//
//	isolated := cloneEvent(ev, time.Now())
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :499 (direct call)
//   - :499 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func cloneEvent(ev Event, now time.Time) Event {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = now.UTC()
	}
	ev = normalizeEvent(ev)
	if ev.Details != nil {
		ev.Details = maps.Clone(ev.Details)
	}
	return ev
}

// normalizeEvent canonicalizes Category, Severity, Title, Summary, Site, and
// Timestamp on a value copy of ev.
//
// # Parameters
//
//   - ev: Event value to normalize.
//
// # Returns
//
// Normalized Event value.
//
// # Example
//
//	norm := normalizeEvent(ev)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :919 (direct call)
//   - :919 (function value)
//   - :1034 (direct call)
//   - :1034 (function value)
//   - :1120 (direct call)
//   - :1120 (function value)
//   - :1192 (direct call)
//   - :1192 (function value)
//   - :1282 (direct call)
//   - :1282 (function value)
//   - :1759 (direct call)
//   - :1759 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func normalizeEvent(ev Event) Event {
	ev.Category = strings.ToLower(strings.TrimSpace(ev.Category))
	if ev.Category == "" {
		ev.Category = "general"
	}
	ev.Severity = strings.ToLower(strings.TrimSpace(ev.Severity))
	switch ev.Severity {
	case SevCritical, SevWarn, SevInfo:
	default:
		ev.Severity = SevInfo
	}
	ev.Title = strings.TrimSpace(ev.Title)
	if ev.Title == "" {
		ev.Title = "Concert Alert"
	}
	ev.Summary = strings.TrimSpace(ev.Summary)
	ev.Site = strings.TrimSpace(ev.Site)
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	} else {
		ev.Timestamp = ev.Timestamp.UTC()
	}
	return ev
}

// coalesceKey computes the per-category deduplication key for ev.
//
// # Parameters
//
//   - ev: Normalized Event.
//
// # Returns
//
// A deterministic coalescing key scoped by category, site, and severity so
// severity escalations notify immediately while repeated alerts coalesce.
//
// # Example
//
//	key := coalesceKey(ev)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :508 (direct call)
//   - :508 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func coalesceKey(ev Event) string {
	return ev.Category + "\x00" + ev.Site + "\x00" + ev.Severity
}

// defaultDedupKey derives a deterministic SHA-256 PagerDuty dedup_key from
// ev's category, site, and title.
//
// # Parameters
//
//   - ev: Normalized Event.
//
// # Returns
//
// A 32-character lowercase hex deduplication key prefixed with "concert-".
//
// # Example
//
//	key := defaultDedupKey(ev)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :1056 (direct call)
//   - :1056 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func defaultDedupKey(ev Event) string {
	h := sha256.Sum256([]byte(ev.Category + "\x00" + ev.Site + "\x00" + ev.Title))
	return "concert-" + hex.EncodeToString(h[:16])
}

// pruneCoalesceMapLocked removes expired entries from m (and drops the oldest
// entry if still at capacity) so the coalescing map remains strictly bounded.
// Caller must hold d.mu.
//
// # Parameters
//
//   - m: Coalescing map guarded by Dispatcher.mu.
//   - now: Current timestamp.
//   - window: Active coalescing duration.
//
// # Example
//
//	pruneCoalesceMapLocked(d.coalesce, now, d.coalesceWindow)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :515 (direct call)
//   - :515 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func pruneCoalesceMapLocked(m map[string]time.Time, now time.Time, window time.Duration) {
	for k, ts := range m {
		if now.Sub(ts) >= window {
			delete(m, k)
		}
	}
	if len(m) < maxCoalesceEntries {
		return
	}
	var oldestKey string
	var oldestTS time.Time
	first := true
	for k, ts := range m {
		if first || ts.Before(oldestTS) {
			oldestKey = k
			oldestTS = ts
			first = false
		}
	}
	if !first {
		delete(m, oldestKey)
	}
}

// sortedKeys returns the keys of m in ascending lexical order.
//
// # Parameters
//
//   - m: Input map; nil or empty returns nil.
//
// # Returns
//
// Sorted slice of keys.
//
// # Example
//
//	for _, k := range sortedKeys(ev.Details) {
//	    fmt.Println(k, ev.Details[k])
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :959 (direct call)
//   - :959 (function value)
//   - :1137 (direct call)
//   - :1137 (function value)
//   - :1210 (direct call)
//   - :1210 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// computeBackoff returns a bounded jittered exponential backoff delay for retry
// attempt, honoring a positive retryAfter hint up to maxBackoff.
//
// # Parameters
//
//   - attempt: Zero-based retry index.
//   - base: Initial backoff duration.
//   - maxBackoff: Upper bound on delay.
//   - retryAfter: Optional server Retry-After duration (0 if absent).
//
// # Returns
//
// Delay duration in [0, maxBackoff].
//
// # Example
//
//	delay := computeBackoff(0, 250*time.Millisecond, 5*time.Second, 0)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :767 (direct call)
//   - :767 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func computeBackoff(attempt int, base, maxBackoff, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		if retryAfter > maxBackoff {
			return maxBackoff
		}
		return retryAfter
	}
	d := base
	for range attempt {
		if d >= maxBackoff/2 {
			d = maxBackoff
			break
		}
		d *= 2
	}
	if d > maxBackoff {
		d = maxBackoff
	}
	if d <= 0 {
		return 0
	}
	// Apply 50%-100% jitter to avoid synchronized retry storms (E4).
	half := d / 2
	if half <= 0 {
		return d
	}
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

// parseRetryAfter parses a numeric Retry-After header value in seconds.
//
// # Parameters
//
//   - raw: Value of the HTTP Retry-After header.
//
// # Returns
//
// Parsed positive duration, or 0 if empty or non-numeric.
//
// # Example
//
//	d := parseRetryAfter(resp.Header.Get("Retry-After"))
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :839 (direct call)
//   - :839 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func parseRetryAfter(raw string) time.Duration {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0
	}
	secs, err := strconv.Atoi(s)
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// defaultSleep waits for duration d or returns early if ctx is cancelled.
//
// # Parameters
//
//   - ctx: Context controlling cancellation.
//   - d: Wait duration; non-positive returns nil immediately.
//
// # Returns
//
// nil when d elapses, or ctx.Err() on cancellation.
//
// # Example
//
//	if err := defaultSleep(ctx, 250*time.Millisecond); err != nil {
//	    return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :343 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func defaultSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sanitizeURLError strips any embedded full URL (which may contain webhook path
// tokens or query secrets) from a *url.Error before returning it to callers.
//
// # Parameters
//
//   - err: Original error returned by net/http.
//   - redactedURL: Safe scheme://host replacement string.
//
// # Returns
//
// A sanitized error preserving errors.Is/errors.As matching on the underlying
// cause without exposing secret URL paths or queries.
//
// # Example
//
//	return sanitizeURLError(err, target.redactedURL)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :807 (direct call)
//   - :807 (function value)
//   - :826 (direct call)
//   - :826 (function value)
//   - :828 (direct call)
//   - :828 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func sanitizeURLError(err error, redactedURL string) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return &url.Error{
			Op:  ue.Op,
			URL: redactedURL,
			Err: ue.Err,
		}
	}
	return err
}
