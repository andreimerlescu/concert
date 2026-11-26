package telemetry

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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

	"github.com/andreimerlescu/concert/internal/opt"
)

// Default OTLP/HTTP JSON exporter limits and timings enforcing R3 and R2.
const (
	DefaultServiceName    = "concert"
	DefaultScopeName      = "github.com/andreimerlescu/concert/internal/telemetry"
	DefaultScopeVersion   = "1.0.0"
	DefaultMaxSpans       = 1024
	MaxAllowedSpans       = 65536
	DefaultBatchSize      = 64
	DefaultFlushInterval  = 5 * time.Second
	DefaultExportTimeout  = 10 * time.Second
	maxResponseBodyBytes  = 4096
	maxEndpointURLLen     = 2048
	defaultTracesEndpoint = "/v1/traces"
)

// Sentinel errors returned by Tracer configuration and OTLP transport checks.
var (
	ErrInvalidConfig      = errors.New("invalid telemetry configuration")
	ErrInvalidEndpoint    = errors.New("invalid OTLP endpoint URL")
	ErrInsecureScheme     = errors.New("OTLP endpoint must use https")
	ErrURLUserinfo        = errors.New("OTLP endpoint must not contain userinfo")
	ErrBlockedAddress     = errors.New("OTLP endpoint resolves to a blocked private or loopback address")
	ErrRedirectDisallowed = errors.New("OTLP endpoint redirects are disallowed")
	ErrInvalidHeaderName  = errors.New("invalid OTLP auth header name")
)

// Config configures a pure-stdlib OTLP/HTTP JSON Tracer.
type Config struct {
	// Endpoint is the OTLP/HTTP collector URL (e.g. "https://otel.example.com/v1/traces").
	// If the URL path is empty or "/", "/v1/traces" is appended automatically.
	Endpoint string
	// ServiceName sets the OTLP "service.name" resource attribute (default "concert").
	ServiceName string
	// ServiceVersion optionally sets the OTLP "service.version" resource attribute.
	ServiceVersion string
	// ResourceAttrs appends extra immutable attributes to the OTLP resource.
	ResourceAttrs []Attribute
	// AuthHeaderName sets the HTTP header carrying AuthHeaderValue (default "Authorization").
	AuthHeaderName string
	// AuthHeaderValue holds the optional redacted credential sent on OTLP exports.
	AuthHeaderValue Secret
	// SampleRate controls root-span sampling in [0.0, 1.0]. 0.0 drops all root
	// spans; 1.0 samples all root spans. Child spans inherit their parent's flag.
	SampleRate float64
	// MaxSpans bounds the in-memory ring buffer (default DefaultMaxSpans).
	MaxSpans int
	// BatchSize sets the maximum spans per OTLP HTTP request (default DefaultBatchSize).
	BatchSize int
	// FlushInterval controls periodic background flushing (default DefaultFlushInterval).
	FlushInterval time.Duration
	// ExportTimeout bounds each OTLP HTTP POST request (default DefaultExportTimeout).
	ExportTimeout time.Duration
	// AllowLoopbackHTTP allows http:// loopback targets strictly for local tests.
	AllowLoopbackHTTP bool
	// Clock optionally overrides time.Now for deterministic unit tests.
	Clock func() time.Time
	// OnExportError is optionally called outside locks when an OTLP POST fails.
	OnExportError func(err error)
}

// DefaultConfig returns a Config with safe production defaults and 100%
// sampling for the given OTLP collector endpoint.
//
// # Parameters
//
//   - endpoint: OTLP/HTTP collector URL.
//
// # Returns
//
// A Config populated with production defaults.
//
// # Example
//
//	cfg := telemetry.DefaultConfig("https://collector.example.com/v1/traces")
//	cfg.SampleRate = 0.1
//	tracer, err := telemetry.NewTracer(cfg)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:130 (direct call)
//   - internal/telemetry/telemetry_test.go:298 (direct call)
//   - internal/telemetry/telemetry_test.go:356 (direct call)
//   - internal/telemetry/telemetry_test.go:386 (direct call)
//   - internal/telemetry/telemetry_test.go:479 (direct call)
//   - internal/telemetry/telemetry_test.go:483 (direct call)
//   - internal/telemetry/telemetry_test.go:486 (direct call)
//   - internal/telemetry/telemetry_test.go:489 (direct call)
//   - internal/telemetry/telemetry_test.go:514 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func DefaultConfig(endpoint string) Config {
	return Config{
		Endpoint:       endpoint,
		ServiceName:    DefaultServiceName,
		AuthHeaderName: "Authorization",
		SampleRate:     1.0,
		MaxSpans:       DefaultMaxSpans,
		BatchSize:      DefaultBatchSize,
		FlushInterval:  DefaultFlushInterval,
		ExportTimeout:  DefaultExportTimeout,
	}
}

// spanRing is a fixed-capacity circular buffer of completed SpanData values.
// Every access must hold the owning Tracer's mu.
type spanRing struct {
	buf   []SpanData
	head  int
	count int
}

// push appends s to r. When r is full, it overwrites the oldest buffered span
// and returns dropped=true so tracing never blocks request handlers (R3).
//
// # Parameters
//
//   - s: Completed immutable SpanData snapshot.
//
// # Returns
//
// true if an older span was overwritten due to capacity saturation.
//
// # Example
//
//	if r.push(spanData) {
//	    dropped.Add(1)
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:668 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (r *spanRing) push(s SpanData) (dropped bool) {
	if len(r.buf) == 0 {
		return true
	}
	if r.count == len(r.buf) {
		r.buf[r.head] = s
		r.head = (r.head + 1) % len(r.buf)
		return true
	}
	tail := (r.head + r.count) % len(r.buf)
	r.buf[tail] = s
	r.count++
	return false
}

// popBatch removes up to limit spans in FIFO order and returns them in a new
// slice owned by the caller.
//
// # Parameters
//
//   - limit: Maximum number of spans to dequeue; must be > 0.
//
// # Returns
//
// Slice of up to limit spans, or nil when the buffer is empty.
//
// # Example
//
//	batch := r.popBatch(64)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:745 (direct call)
//   - internal/telemetry/otlp.go:787 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (r *spanRing) popBatch(limit int) []SpanData {
	if r.count == 0 || limit <= 0 {
		return nil
	}
	n := min(r.count, limit)
	out := make([]SpanData, n)
	for i := range n {
		out[i] = r.buf[r.head]
		r.buf[r.head] = SpanData{} // release slice references for GC
		r.head = (r.head + 1) % len(r.buf)
	}
	r.count -= n
	return out
}

// Tracer creates W3C spans and asynchronously exports sampled spans to an
// OTLP/HTTP JSON collector using a bounded ring buffer.
//
// Ownership and concurrency:
//   - Configuration fields, resourceAttrs, and client are immutable after NewTracer.
//   - mu guards ring and closed.
//   - A single background exporter goroutine drains ring on batch threshold,
//     periodic flush ticks, explicit Flush, or Shutdown, and is joined in Shutdown.
type Tracer struct {
	endpoint       string
	redactedURL    string
	authHeaderName string
	authHeaderVal  Secret
	sampleRate     float64
	batchSize      int
	flushInterval  time.Duration
	exportTimeout  time.Duration
	resourceAttrs  []Attribute
	client         *http.Client
	now            func() time.Time
	onExportError  func(err error)

	mu     sync.Mutex
	ring   spanRing
	closed bool

	notifyCh   chan struct{}
	flushReqCh chan chan error
	stopCh     chan struct{}
	doneCh     chan struct{}
	closeOnce  sync.Once

	droppedSpans  atomic.Uint64
	exportedSpans atomic.Uint64
	exportErrors  atomic.Uint64
}

// NewTracer validates cfg and starts a single background OTLP/HTTP JSON
// exporter goroutine. Callers must call Shutdown(ctx) to flush remaining spans
// and join the background goroutine.
//
// # Parameters
//
//   - cfg: Tracer configuration including endpoint URL, sampling ratio, buffer
//     bounds, and optional redacting auth header secret.
//
// # Returns
//
// A ready-to-use *Tracer and nil error on success, or nil and a validation error.
//
// # Example
//
//	tracer, err := telemetry.NewTracer(telemetry.DefaultConfig("https://otel.example.com/v1/traces"))
//	if err != nil {
//	    return err
//	}
//	defer tracer.Shutdown(context.Background())
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:138 (direct call)
//   - internal/telemetry/telemetry_test.go:304 (direct call)
//   - internal/telemetry/telemetry_test.go:360 (direct call)
//   - internal/telemetry/telemetry_test.go:390 (direct call)
//   - internal/telemetry/telemetry_test.go:479 (direct call)
//   - internal/telemetry/telemetry_test.go:483 (direct call)
//   - internal/telemetry/telemetry_test.go:486 (direct call)
//   - internal/telemetry/telemetry_test.go:489 (direct call)
//   - internal/telemetry/telemetry_test.go:520 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func NewTracer(cfg Config) (*Tracer, error) {
	u, err := ValidateEndpointURL(cfg.Endpoint, cfg.AllowLoopbackHTTP)
	if err != nil {
		return nil, err
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = defaultTracesEndpoint
	}

	if math.IsNaN(cfg.SampleRate) || cfg.SampleRate < 0 || cfg.SampleRate > 1 {
		return nil, fmt.Errorf("%w: SampleRate %v must be in [0.0, 1.0]", ErrInvalidConfig, cfg.SampleRate)
	}

	maxSpans := cfg.MaxSpans
	if maxSpans < 0 || maxSpans > MaxAllowedSpans {
		return nil, fmt.Errorf("%w: MaxSpans %d out of range [0, %d]", ErrInvalidConfig, maxSpans, MaxAllowedSpans)
	}
	if maxSpans == 0 {
		maxSpans = DefaultMaxSpans
	}

	batchSize := cfg.BatchSize
	if batchSize < 0 || batchSize > maxSpans {
		return nil, fmt.Errorf("%w: BatchSize %d out of range [0, %d]", ErrInvalidConfig, batchSize, maxSpans)
	}
	if batchSize == 0 {
		batchSize = min(DefaultBatchSize, maxSpans)
	}

	flushInterval := cfg.FlushInterval
	if flushInterval < 0 {
		return nil, fmt.Errorf("%w: FlushInterval must be non-negative", ErrInvalidConfig)
	}
	if flushInterval == 0 {
		flushInterval = DefaultFlushInterval
	}

	exportTimeout := cfg.ExportTimeout
	if exportTimeout < 0 {
		return nil, fmt.Errorf("%w: ExportTimeout must be non-negative", ErrInvalidConfig)
	}
	if exportTimeout == 0 {
		exportTimeout = DefaultExportTimeout
	}

	headerName := strings.TrimSpace(cfg.AuthHeaderName)
	if headerName == "" {
		headerName = "Authorization"
	}
	if strings.ContainsAny(headerName, "\r\n\x00 \t:") {
		return nil, ErrInvalidHeaderName
	}
	if !cfg.AuthHeaderValue.IsZero() && strings.ContainsAny(cfg.AuthHeaderValue.Reveal(), "\r\n\x00") {
		return nil, fmt.Errorf("%w: auth header value contains control characters", ErrInvalidConfig)
	}

	serviceName := strings.TrimSpace(cfg.ServiceName)
	if serviceName == "" {
		serviceName = DefaultServiceName
	}
	resAttrs := make([]Attribute, 0, len(cfg.ResourceAttrs)+2)
	resAttrs = append(resAttrs, StringAttr("service.name", serviceName))
	if v := strings.TrimSpace(cfg.ServiceVersion); v != "" {
		resAttrs = append(resAttrs, StringAttr("service.version", v))
	}
	resAttrs = append(resAttrs, slices.Clone(cfg.ResourceAttrs)...)

	nowFn := cfg.Clock
	if nowFn == nil {
		nowFn = time.Now
	}

	t := &Tracer{
		endpoint:       u.String(),
		redactedURL:    u.Scheme + "://" + u.Host + u.Path,
		authHeaderName: headerName,
		authHeaderVal:  cfg.AuthHeaderValue,
		sampleRate:     cfg.SampleRate,
		batchSize:      batchSize,
		flushInterval:  flushInterval,
		exportTimeout:  exportTimeout,
		resourceAttrs:  resAttrs,
		client:         newHardenedHTTPClient(cfg.AllowLoopbackHTTP, exportTimeout),
		now:            nowFn,
		onExportError:  cfg.OnExportError,
		ring:           spanRing{buf: make([]SpanData, maxSpans)},
		notifyCh:       make(chan struct{}, 1),
		flushReqCh:     make(chan chan error, 1),
		stopCh:         make(chan struct{}),
		doneCh:         make(chan struct{}),
	}

	go t.exportLoop()
	return t, nil
}

// StartSpan creates a child span linked to any active local or remote
// SpanContext in ctx (or starts a new root trace if none is present), attaches
// it to the returned context, and records initial attributes.
//
// # Parameters
//
//   - ctx: Parent context; if nil, context.Background() is used.
//   - name: Operation name for the span (e.g. "http.proxy").
//   - attrs: Optional initial span attributes.
//
// # Returns
//
// A derived context containing the new active span and the *Span handle.
// Callers must call span.End() when the operation finishes.
//
// # Example
//
//	ctx, span := tracer.StartSpan(ctx, "waiting_room.admit",
//	    telemetry.StringAttr("concert.site", "tickets.example.com"),
//	)
//	defer span.End()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:148 (direct call)
//   - internal/telemetry/telemetry_test.go:159 (direct call)
//   - internal/telemetry/telemetry_test.go:311 (direct call)
//   - internal/telemetry/telemetry_test.go:318 (direct call)
//   - internal/telemetry/telemetry_test.go:365 (direct call)
//   - internal/telemetry/telemetry_test.go:373 (direct call)
//   - internal/telemetry/telemetry_test.go:396 (direct call)
//   - internal/telemetry/telemetry_test.go:529 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (t *Tracer) StartSpan(ctx context.Context, name string, attrs ...Attribute) (context.Context, *Span) {
	if ctx == nil {
		ctx = context.Background()
	}
	var sc SpanContext
	var parentID SpanID

	if parent, ok := SpanContextFromContext(ctx); ok {
		sc.TraceID = parent.TraceID
		sc.TraceFlags = parent.TraceFlags
		parentID = parent.SpanID
	} else {
		sc.TraceID = newTraceID()
		if shouldSampleTrace(sc.TraceID, t.sampleRate) {
			sc.TraceFlags = FlagSampled
		}
	}
	sc.SpanID = newSpanID()

	sp := &Span{
		tracer:   t,
		sc:       sc,
		parentID: parentID,
		name:     name,
		kind:     SpanKindInternal,
		start:    t.now(),
	}
	if len(attrs) > 0 {
		sp.attrs = slices.Clone(attrs)
	}
	return ContextWithSpan(ctx, sp), sp
}

// DroppedSpans returns the cumulative number of sampled spans dropped because
// the bounded ring buffer reached MaxSpans under export backpressure.
//
// # Parameters
//
// None.
//
// # Returns
//
// Count of dropped spans.
//
// # Example
//
//	fmt.Println("dropped spans:", tracer.DroppedSpans())
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:322 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (t *Tracer) DroppedSpans() uint64 {
	return t.droppedSpans.Load()
}

// ExportedSpans returns the cumulative number of spans accepted by the OTLP
// collector with a 2xx HTTP status.
//
// # Parameters
//
// None.
//
// # Returns
//
// Count of exported spans.
//
// # Example
//
//	fmt.Println("exported spans:", tracer.ExportedSpans())
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:179 (direct call)
//   - internal/telemetry/telemetry_test.go:180 (direct call)
//   - internal/telemetry/telemetry_test.go:330 (direct call)
//   - internal/telemetry/telemetry_test.go:381 (direct call)
//   - internal/telemetry/telemetry_test.go:382 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (t *Tracer) ExportedSpans() uint64 {
	return t.exportedSpans.Load()
}

// ExportErrors returns the cumulative number of failed OTLP HTTP batch exports.
//
// # Parameters
//
// None.
//
// # Returns
//
// Count of failed batch export attempts.
//
// # Example
//
//	fmt.Println("export errors:", tracer.ExportErrors())
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:179 (direct call)
//   - internal/telemetry/telemetry_test.go:180 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (t *Tracer) ExportErrors() uint64 {
	return t.exportErrors.Load()
}

// Flush synchronously triggers export of all currently buffered spans and waits
// until the flush completes or ctx expires.
//
// # Parameters
//
//   - ctx: Controls deadline/cancellation while waiting for flush completion.
//
// # Returns
//
// Any export error encountered during the flush, or ctx.Err() if cancelled.
//
// # Example
//
//	if err := tracer.Flush(ctx); err != nil {
//	    return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:535 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (t *Tracer) Flush(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	reply := make(chan error, 1)
	select {
	case t.flushReqCh <- reply:
	case <-t.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-reply:
		return err
	case <-t.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Shutdown stops accepting new spans into the ring buffer, drains and exports
// all buffered spans within ctx, and joins the background exporter goroutine.
// Subsequent calls to Shutdown are idempotent and return nil.
//
// # Parameters
//
//   - ctx: Deadline/cancellation context for the final flush and drain.
//
// # Returns
//
// Any error from draining buffered spans, or ctx.Err() if shutdown timed out.
//
// # Example
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//	if err := tracer.Shutdown(ctx); err != nil {
//	    return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:171 (direct call)
//   - internal/telemetry/telemetry_test.go:175 (direct call)
//   - internal/telemetry/telemetry_test.go:327 (direct call)
//   - internal/telemetry/telemetry_test.go:378 (direct call)
//   - internal/telemetry/telemetry_test.go:402 (direct call)
//   - internal/telemetry/telemetry_test.go:537 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (t *Tracer) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	var firstShutdown bool
	t.closeOnce.Do(func() {
		firstShutdown = true
		t.mu.Lock()
		t.closed = true
		t.mu.Unlock()
		close(t.stopCh)
	})

	// Wait for the background loop to exit its periodic loop before performing
	// the final bounded drain under the caller's ctx.
	select {
	case <-t.doneCh:
	case <-ctx.Done():
		t.client.CloseIdleConnections()
		return ctx.Err()
	}

	defer t.client.CloseIdleConnections()
	if !firstShutdown {
		return nil
	}
	return t.drainAll(ctx)
}

// recordSpan pushes a completed span into the bounded ring buffer without
// blocking and wakes the exporter goroutine when a full batch is ready.
//
// # Parameters
//
//   - data: Immutable completed SpanData snapshot.
//
// # Example
//
//	t.recordSpan(spanData)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/trace.go:954 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (t *Tracer) recordSpan(data SpanData) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	dropped := t.ring.push(data)
	shouldNotify := t.ring.count >= t.batchSize
	t.mu.Unlock()

	if dropped {
		t.droppedSpans.Add(1)
	}
	if shouldNotify {
		select {
		case t.notifyCh <- struct{}{}:
		default:
		}
	}
}

// exportLoop runs in the single background exporter goroutine owned by Tracer,
// flushing batches when notifyCh fires, on periodic flush ticks, or on explicit
// Flush requests until stopCh is closed.
//
// # Parameters
//
// None.
//
// # Example
//
//	go t.exportLoop()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:381 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (t *Tracer) exportLoop() {
	defer close(t.doneCh)

	ticker := time.NewTicker(t.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-t.notifyCh:
			_ = t.drainBatch(context.Background())
		case <-ticker.C:
			_ = t.drainAll(context.Background())
		case reply := <-t.flushReqCh:
			reply <- t.drainAll(context.Background())
		}
	}
}

// drainBatch pops and exports at most one batch of spans from the ring buffer.
//
// # Parameters
//
//   - ctx: Context controlling cancellation of the OTLP HTTP request.
//
// # Returns
//
// Any OTLP export error, or nil if the buffer was empty or export succeeded.
//
// # Example
//
//	err := t.drainBatch(ctx)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:713 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (t *Tracer) drainBatch(ctx context.Context) error {
	t.mu.Lock()
	batch := t.ring.popBatch(t.batchSize)
	t.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	return t.exportBatch(ctx, batch)
}

// drainAll exports all currently buffered spans in batches of at most batchSize
// until the buffer is empty or ctx is cancelled.
//
// # Parameters
//
//   - ctx: Context controlling overall drain deadline.
//
// # Returns
//
// The last non-nil export error encountered, or ctx.Err() if cancelled.
//
// # Example
//
//	err := t.drainAll(ctx)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:641 (direct call)
//   - internal/telemetry/otlp.go:715 (direct call)
//   - internal/telemetry/otlp.go:717 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (t *Tracer) drainAll(ctx context.Context) error {
	var firstErr error
	for {
		if ctx.Err() != nil {
			if firstErr != nil {
				return firstErr
			}
			return ctx.Err()
		}
		t.mu.Lock()
		batch := t.ring.popBatch(t.batchSize)
		t.mu.Unlock()
		if len(batch) == 0 {
			return firstErr
		}
		if err := t.exportBatch(ctx, batch); err != nil && firstErr == nil {
			firstErr = err
		}
	}
}

// exportBatch serializes batch into an OTLP/HTTP JSON ExportTraceServiceRequest
// and POSTs it to the configured collector endpoint.
//
// # Parameters
//
//   - ctx: Context controlling request cancellation.
//   - batch: Non-empty slice of immutable SpanData snapshots.
//
// # Returns
//
// nil on HTTP 2xx response, or a secret-free error.
//
// # Example
//
//	err := t.exportBatch(ctx, batch)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:750 (direct call)
//   - internal/telemetry/otlp.go:792 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (t *Tracer) exportBatch(ctx context.Context, batch []SpanData) error {
	body, err := MarshalOTLPTracesJSON(t.resourceAttrs, batch)
	if err != nil {
		t.exportErrors.Add(1)
		if t.onExportError != nil {
			t.onExportError(err)
		}
		return err
	}

	reqCtx, cancel := context.WithTimeout(ctx, t.exportTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		safeErr := sanitizeURLError(err, t.redactedURL)
		t.exportErrors.Add(1)
		if t.onExportError != nil {
			t.onExportError(safeErr)
		}
		return safeErr
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "concert-telemetry/1.0")
	if !t.authHeaderVal.IsZero() {
		// Single point of use: reveal auth header credential strictly on the wire.
		req.Header.Set(t.authHeaderName, t.authHeaderVal.Reveal())
	}

	resp, err := t.client.Do(req)
	if err != nil {
		safeErr := sanitizeURLError(err, t.redactedURL)
		t.exportErrors.Add(1)
		if t.onExportError != nil {
			t.onExportError(safeErr)
		}
		return safeErr
	}
	defer func() { _ = resp.Body.Close() }()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBodyBytes))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		statusErr := fmt.Errorf("otlp export to %s: HTTP %d", t.redactedURL, resp.StatusCode)
		t.exportErrors.Add(1)
		if t.onExportError != nil {
			t.onExportError(statusErr)
		}
		return statusErr
	}
	t.exportedSpans.Add(uint64(len(batch)))
	return nil
}

// OTLP/HTTP JSON wire structures matching opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest.
type otlpExportTraceRequest struct {
	ResourceSpans []otlpResourceSpans `json:"resourceSpans"`
}

type otlpResourceSpans struct {
	Resource   otlpResource     `json:"resource"`
	ScopeSpans []otlpScopeSpans `json:"scopeSpans"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes,omitempty"`
}

type otlpScopeSpans struct {
	Scope otlpScope  `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type otlpSpan struct {
	TraceID           string         `json:"traceId"`
	SpanID            string         `json:"spanId"`
	ParentSpanID      string         `json:"parentSpanId,omitempty"`
	Name              string         `json:"name"`
	Kind              int            `json:"kind"`
	StartTimeUnixNano string         `json:"startTimeUnixNano"`
	EndTimeUnixNano   string         `json:"endTimeUnixNano"`
	Attributes        []otlpKeyValue `json:"attributes,omitempty"`
	Status            otlpStatus     `json:"status"`
}

type otlpStatus struct {
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

type otlpKeyValue struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

type otlpAnyValue struct {
	StringValue opt.Option[string]  `json:"stringValue,omitzero"`
	IntValue    opt.Option[string]  `json:"intValue,omitzero"`
	DoubleValue opt.Option[float64] `json:"doubleValue,omitzero"`
	BoolValue   opt.Option[bool]    `json:"boolValue,omitzero"`
}

// MarshalOTLPTracesJSON encodes resourceAttrs and spans into a schema-accurate
// OTLP/HTTP JSON ExportTraceServiceRequest document (resourceSpans ->
// scopeSpans -> spans) using Proto3 JSON conventions (64-bit timestamps and
// integer attributes serialized as decimal strings, trace/span IDs as lowercase
// hex).
//
// # Parameters
//
//   - resourceAttrs: Immutable resource attributes (such as "service.name").
//   - spans: Completed SpanData slice to encode.
//
// # Returns
//
// JSON-encoded OTLP ExportTraceServiceRequest bytes or a marshaling error.
//
// # Example
//
//	payload, err := telemetry.MarshalOTLPTracesJSON(
//	    []telemetry.Attribute{telemetry.StringAttr("service.name", "concert")},
//	    spans,
//	)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:823 (direct call)
//   - internal/telemetry/telemetry_test.go:620 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func MarshalOTLPTracesJSON(resourceAttrs []Attribute, spans []SpanData) ([]byte, error) {
	wireSpans := make([]otlpSpan, 0, len(spans))
	for _, sp := range spans {
		kind := int(sp.Kind)
		if kind == 0 {
			kind = int(SpanKindInternal)
		}
		ws := otlpSpan{
			TraceID:           sp.TraceID.String(),
			SpanID:            sp.SpanID.String(),
			Name:              sp.Name,
			Kind:              kind,
			StartTimeUnixNano: strconv.FormatInt(sp.StartTime.UnixNano(), 10),
			EndTimeUnixNano:   strconv.FormatInt(sp.EndTime.UnixNano(), 10),
			Attributes:        encodeOTLPAttrs(sp.Attributes),
			Status: otlpStatus{
				Code:    int(sp.StatusCode),
				Message: sp.StatusMessage,
			},
		}
		if sp.ParentSpanID.IsValid() {
			ws.ParentSpanID = sp.ParentSpanID.String()
		}
		wireSpans = append(wireSpans, ws)
	}

	req := otlpExportTraceRequest{
		ResourceSpans: []otlpResourceSpans{
			{
				Resource: otlpResource{
					Attributes: encodeOTLPAttrs(resourceAttrs),
				},
				ScopeSpans: []otlpScopeSpans{
					{
						Scope: otlpScope{
							Name:    DefaultScopeName,
							Version: DefaultScopeVersion,
						},
						Spans: wireSpans,
					},
				},
			},
		},
	}
	return json.Marshal(req)
}

// encodeOTLPAttrs converts internal Attributes into OTLP KeyValue wire objects.
//
// # Parameters
//
//   - attrs: Input slice of typed Attributes.
//
// # Returns
//
// Encoded slice of otlpKeyValue, or nil when attrs is empty.
//
// # Example
//
//	kvs := encodeOTLPAttrs(span.Attributes)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:973 (direct call)
//   - internal/telemetry/otlp.go:989 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func encodeOTLPAttrs(attrs []Attribute) []otlpKeyValue {
	if len(attrs) == 0 {
		return nil
	}
	out := make([]otlpKeyValue, 0, len(attrs))
	for _, a := range attrs {
		if a.Key == "" {
			continue
		}
		var val otlpAnyValue
		switch a.Kind {
		case AttrString:
			val.StringValue = opt.Some(a.StrVal)
		case AttrInt:
			val.IntValue = opt.Some(strconv.FormatInt(a.IntVal, 10))
		case AttrFloat64:
			f := a.FltVal
			if math.IsNaN(f) || math.IsInf(f, 0) {
				f = 0
			}
			val.DoubleValue = opt.Some(f)
		case AttrBool:
			val.BoolValue = opt.Some(a.BolVal)
		default:
			continue
		}
		out = append(out, otlpKeyValue{Key: a.Key, Value: val})
	}
	return out
}

// ValidateEndpointURL enforces HTTPS, forbids URL userinfo, and rejects
// private/link-local/loopback literal IPs unless allowLoopbackHTTP is enabled
// for local test servers.
//
// # Parameters
//
//   - rawURL: Candidate OTLP collector URL.
//   - allowLoopbackHTTP: Permits http:// and https:// loopback targets for tests.
//
// # Returns
//
// Parsed *url.URL on success, or an error wrapping ErrInvalidEndpoint,
// ErrURLUserinfo, ErrInsecureScheme, or ErrBlockedAddress.
//
// # Example
//
//	u, err := telemetry.ValidateEndpointURL("https://otel.example.com/v1/traces", false)
//	if err != nil {
//	    return err
//	}
//	_ = u
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:290 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func ValidateEndpointURL(rawURL string, allowLoopbackHTTP bool) (*url.URL, error) {
	s := strings.TrimSpace(rawURL)
	if s == "" || len(s) > maxEndpointURLLen || strings.ContainsAny(s, "\r\n\x00 \t\"<>") {
		return nil, ErrInvalidEndpoint
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return nil, ErrInvalidEndpoint
	}
	if u.User != nil {
		return nil, ErrURLUserinfo
	}
	host := u.Hostname()
	if host == "" {
		return nil, ErrInvalidEndpoint
	}
	if port := u.Port(); port != "" {
		p, perr := strconv.Atoi(port)
		if perr != nil || p < 1 || p > 65535 {
			return nil, ErrInvalidEndpoint
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

// newHardenedHTTPClient builds an http.Client with TLS >= 1.2, disabled
// redirects, bounded timeouts, and an SSRF-guarded DialContext.
//
// # Parameters
//
//   - allowLoopback: Permits dialing loopback targets when true.
//   - timeout: Per-export HTTP timeout.
//
// # Returns
//
// A configured *http.Client owned by Tracer.
//
// # Example
//
//	client := newHardenedHTTPClient(false, 10*time.Second)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:371 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func newHardenedHTTPClient(allowLoopback bool, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           ssrfGuardedDialContext(dialer, allowLoopback),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
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

// ssrfGuardedDialContext resolves target hosts, validates every resolved IP
// against private/link-local/loopback rules, and dials the verified IP directly.
//
// # Parameters
//
//   - dialer: Underlying *net.Dialer.
//   - allowLoopback: Permits loopback addresses when true.
//
// # Returns
//
// A DialContext function for http.Transport.
//
// # Example
//
//	tr := &http.Transport{DialContext: ssrfGuardedDialContext(&net.Dialer{}, false)}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:1162 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func ssrfGuardedDialContext(dialer *net.Dialer, allowLoopback bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidEndpoint, err)
		}
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

// isBlockedAddr reports whether addr falls in a disallowed private, link-local,
// CGNAT, multicast, unspecified, or loopback range.
//
// # Parameters
//
//   - addr: Candidate IP address.
//   - allowLoopback: Permits loopback addresses when true.
//
// # Returns
//
// true if connections to addr must be rejected.
//
// # Example
//
//	blocked := isBlockedAddr(netip.MustParseAddr("10.0.0.1"), false)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:1123 (direct call)
//   - internal/telemetry/otlp.go:1212 (direct call)
//   - internal/telemetry/otlp.go:1230 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
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
// true if host refers to the local loopback interface.
//
// # Example
//
//	ok := isLoopbackHost("127.0.0.1")
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:1115 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

// sanitizeURLError replaces any embedded full URL in a *url.Error with
// redactedURL so query parameters or credentials cannot leak into errors.
//
// # Parameters
//
//   - err: Original error returned by net/http.
//   - redactedURL: Safe scheme://host/path string.
//
// # Returns
//
// A sanitized error preserving error-chain matching on the underlying cause.
//
// # Example
//
//	return sanitizeURLError(err, t.redactedURL)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:837 (direct call)
//   - internal/telemetry/otlp.go:853 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
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
