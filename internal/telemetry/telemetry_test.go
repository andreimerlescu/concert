package telemetry_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/telemetry"
)

// TestTraceparentParseFormat verifies W3C Trace Context Level 1 traceparent
// parsing, validation error paths, and round-trip formatting.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -run '^TestTraceparentParseFormat$' ./internal/telemetry
//
// # Used By
//
// Invoked by the Go test runner.
func TestTraceparentParseFormat(t *testing.T) {
	const valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	sc, err := telemetry.ParseTraceparent(valid)
	if err != nil {
		t.Fatalf("ParseTraceparent(valid) failed: %v", err)
	}
	if !sc.IsValid() || !sc.IsSampled() || !sc.Remote {
		t.Fatalf("unexpected SpanContext flags: %+v", sc)
	}
	if got := telemetry.FormatTraceparent(sc); got != valid {
		t.Fatalf("FormatTraceparent() = %q, want %q", got, valid)
	}

	// Forward-compatible version 01 with trailing extension fields.
	const future = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00-extra"
	scFuture, err := telemetry.ParseTraceparent(future)
	if err != nil {
		t.Fatalf("ParseTraceparent(future) failed: %v", err)
	}
	if scFuture.IsSampled() {
		t.Fatal("expected unsampled future traceparent")
	}

	invalid := []string{
		"",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra", // v00 disallows trailing
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",       // reserved version ff
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",       // all-zero trace id
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",       // all-zero span id
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",       // uppercase hex disallowed
		"00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",       // wrong separator
	}
	for _, hdr := range invalid {
		if _, err := telemetry.ParseTraceparent(hdr); !errors.Is(err, telemetry.ErrInvalidTraceparent) {
			t.Fatalf("ParseTraceparent(%q) err = %v, want ErrInvalidTraceparent", hdr, err)
		}
	}
}

// TestOTLPExportSchemaAndPropagation verifies W3C context propagation, parent-
// child linkage, auth header delivery, and schema-accurate OTLP/HTTP JSON
// payloads received by a mock collector.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -run '^TestOTLPExportSchemaAndPropagation$' ./internal/telemetry
//
// # Used By
//
// Invoked by the Go test runner.
func TestOTLPExportSchemaAndPropagation(t *testing.T) {
	authSecret := telemetry.NewSecret("Bearer synthetic-otlp-token-xyz")

	var mu sync.Mutex
	var capturedBodies [][]byte
	var capturedAuth string
	var capturedCT string
	var capturedPath string

	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		mu.Lock()
		capturedPath = r.URL.Path
		capturedCT = r.Header.Get("Content-Type")
		capturedAuth = r.Header.Get("Authorization")
		capturedBodies = append(capturedBodies, body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	baseTime := time.Date(2026, 11, 26, 18, 30, 0, 0, time.UTC)
	var tick int64
	var clockMu sync.Mutex
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		tick++
		return baseTime.Add(time.Duration(tick) * time.Millisecond)
	}

	cfg := telemetry.DefaultConfig(collector.URL)
	cfg.ServiceName = "concert-proxy"
	cfg.ServiceVersion = "1.2.3"
	cfg.AuthHeaderValue = authSecret
	cfg.AllowLoopbackHTTP = true
	cfg.FlushInterval = time.Hour
	cfg.Clock = clock

	tracer, err := telemetry.NewTracer(cfg)
	if err != nil {
		t.Fatalf("NewTracer: %v", err)
	}

	remote, err := telemetry.ParseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if err != nil {
		t.Fatal(err)
	}
	ctx := telemetry.ContextWithRemoteSpanContext(context.Background(), remote)
	ctx, parentSpan := tracer.StartSpan(ctx, "http.proxy",
		telemetry.StringAttr("http.method", "GET"),
		telemetry.IntAttr("http.status_code", 200),
		telemetry.Float64Attr("concert.utilization", 0.42),
		telemetry.BoolAttr("concert.cache.hit", true),
	)
	parentSpan.SetKind(telemetry.SpanKindServer)
	if telemetry.SpanFromContext(ctx) != parentSpan {
		t.Fatal("SpanFromContext did not return parentSpan")
	}

	childCtx, childSpan := tracer.StartSpan(ctx, "upstream.roundtrip")
	childSpan.SetKind(telemetry.SpanKindClient)
	childSpan.RecordError(errors.New("origin timeout"))
	if telemetry.SpanFromContext(childCtx) != childSpan {
		t.Fatal("SpanFromContext did not return childSpan")
	}
	childSpan.End()
	parentSpan.SetStatus(telemetry.StatusOK, "")
	parentSpan.End()
	// Second End must be an idempotent no-op.
	parentSpan.End()

	if err := tracer.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	// Second Shutdown must be idempotent.
	if err := tracer.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}

	if tracer.ExportedSpans() != 2 || tracer.ExportErrors() != 0 {
		t.Fatalf("exported=%d errors=%d, want 2 and 0", tracer.ExportedSpans(), tracer.ExportErrors())
	}

	mu.Lock()
	defer mu.Unlock()
	if capturedPath != "/v1/traces" {
		t.Fatalf("collector path = %q, want /v1/traces", capturedPath)
	}
	if capturedCT != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", capturedCT)
	}
	if capturedAuth != authSecret.Reveal() {
		t.Fatalf("Authorization header mismatch")
	}
	if len(capturedBodies) != 1 {
		t.Fatalf("expected 1 OTLP batch, got %d", len(capturedBodies))
	}

	var doc struct {
		ResourceSpans []struct {
			Resource struct {
				Attributes []struct {
					Key   string         `json:"key"`
					Value map[string]any `json:"value"`
				} `json:"attributes"`
			} `json:"resource"`
			ScopeSpans []struct {
				Scope struct {
					Name string `json:"name"`
				} `json:"scope"`
				Spans []struct {
					TraceID           string `json:"traceId"`
					SpanID            string `json:"spanId"`
					ParentSpanID      string `json:"parentSpanId"`
					Name              string `json:"name"`
					Kind              int    `json:"kind"`
					StartTimeUnixNano string `json:"startTimeUnixNano"`
					EndTimeUnixNano   string `json:"endTimeUnixNano"`
					Attributes        []struct {
						Key   string         `json:"key"`
						Value map[string]any `json:"value"`
					} `json:"attributes"`
					Status struct {
						Code    int    `json:"code"`
						Message string `json:"message"`
					} `json:"status"`
				} `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(capturedBodies[0], &doc); err != nil {
		t.Fatalf("unmarshal OTLP JSON: %v", err)
	}
	if len(doc.ResourceSpans) != 1 || len(doc.ResourceSpans[0].ScopeSpans) != 1 {
		t.Fatalf("unexpected OTLP envelope: %s", capturedBodies[0])
	}
	spans := doc.ResourceSpans[0].ScopeSpans[0].Spans
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2", len(spans))
	}
	// First completed span is childSpan, second is parentSpan.
	childWire, parentWire := spans[0], spans[1]
	if parentWire.TraceID != remote.TraceID.String() || parentWire.ParentSpanID != remote.SpanID.String() {
		t.Fatalf("parent span did not link to remote traceparent: %+v", parentWire)
	}
	if childWire.TraceID != parentWire.TraceID || childWire.ParentSpanID != parentWire.SpanID {
		t.Fatalf("child span did not link to parent span: child=%+v parent=%+v", childWire, parentWire)
	}
	if childWire.Status.Code != int(telemetry.StatusError) || childWire.Status.Message != "origin timeout" {
		t.Fatalf("child status mismatch: %+v", childWire.Status)
	}
	if parentWire.StartTimeUnixNano == "" || parentWire.EndTimeUnixNano == "" {
		t.Fatalf("missing nanosecond timestamps: %+v", parentWire)
	}
	// Verify Proto3 JSON intValue string encoding on http.status_code.
	foundIntAttr := false
	for _, a := range parentWire.Attributes {
		if a.Key == "http.status_code" && a.Value["intValue"] == "200" {
			foundIntAttr = true
		}
	}
	if !foundIntAttr {
		t.Fatalf("expected intValue:\"200\" for http.status_code in %+v", parentWire.Attributes)
	}
}

// TestBackpressureRingDrop verifies that saturating MaxSpans while the
// collector is blocked never stalls request spans and accurately increments
// DroppedSpans.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -run '^TestBackpressureRingDrop$' ./internal/telemetry
//
// # Used By
//
// Invoked by the Go test runner.
func TestBackpressureRingDrop(t *testing.T) {
	blocked := make(chan struct{}, 1)
	release := make(chan struct{})

	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case blocked <- struct{}{}:
		default:
		}
		select {
		case <-release:
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	defer collector.Close()

	cfg := telemetry.DefaultConfig(collector.URL)
	cfg.MaxSpans = 4
	cfg.BatchSize = 2
	cfg.FlushInterval = time.Hour
	cfg.AllowLoopbackHTTP = true

	tracer, err := telemetry.NewTracer(cfg)
	if err != nil {
		t.Fatalf("NewTracer: %v", err)
	}

	// Trigger the first batch so the single exporter goroutine blocks in HTTP POST.
	for i := range 2 {
		_, sp := tracer.StartSpan(context.Background(), fmt.Sprintf("init-%d", i))
		sp.End()
	}
	<-blocked

	// Push 12 more spans while exporter is blocked; ring holds 4, so at least 8 drop.
	for i := range 12 {
		_, sp := tracer.StartSpan(context.Background(), fmt.Sprintf("burst-%d", i))
		sp.End()
	}

	if dropped := tracer.DroppedSpans(); dropped < 8 {
		t.Fatalf("DroppedSpans() = %d, want >= 8", dropped)
	}

	close(release)
	if err := tracer.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if tracer.ExportedSpans() == 0 {
		t.Fatal("expected retained spans to flush on Shutdown")
	}
}

// TestSamplingRatios verifies SampleRate 0.0, 1.0, fractional sampling, and
// remote parent sampled flag inheritance.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -run '^TestSamplingRatios$' ./internal/telemetry
//
// # Used By
//
// Invoked by the Go test runner.
func TestSamplingRatios(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	// Rate 0.0 drops all root spans.
	cfgZero := telemetry.DefaultConfig(collector.URL)
	cfgZero.SampleRate = 0.0
	cfgZero.AllowLoopbackHTTP = true
	cfgZero.FlushInterval = time.Hour
	tZero, err := telemetry.NewTracer(cfgZero)
	if err != nil {
		t.Fatalf("NewTracer(0.0): %v", err)
	}
	for range 20 {
		_, sp := tZero.StartSpan(context.Background(), "root-unsampled")
		if sp.SpanContext().IsSampled() {
			t.Fatal("expected unsampled span at SampleRate=0.0")
		}
		sp.End()
	}
	// Remote sampled parent overrides local root sampling rate.
	remoteSampled, _ := telemetry.ParseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	_, childOfRemote := tZero.StartSpan(telemetry.ContextWithRemoteSpanContext(context.Background(), remoteSampled), "remote-child")
	if !childOfRemote.SpanContext().IsSampled() {
		t.Fatal("expected child of sampled remote traceparent to be sampled")
	}
	childOfRemote.End()
	if err := tZero.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown(0.0): %v", err)
	}
	if tZero.ExportedSpans() != 1 {
		t.Fatalf("exported = %d, want 1 (only remote-sampled child)", tZero.ExportedSpans())
	}

	// Fractional SampleRate=0.5 samples a non-trivial subset.
	cfgHalf := telemetry.DefaultConfig(collector.URL)
	cfgHalf.SampleRate = 0.5
	cfgHalf.AllowLoopbackHTTP = true
	cfgHalf.FlushInterval = time.Hour
	tHalf, err := telemetry.NewTracer(cfgHalf)
	if err != nil {
		t.Fatalf("NewTracer(0.5): %v", err)
	}
	sampledCount := 0
	for range 400 {
		_, sp := tHalf.StartSpan(context.Background(), "half-sampled")
		if sp.SpanContext().IsSampled() {
			sampledCount++
		}
		sp.End()
	}
	if err := tHalf.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown(0.5): %v", err)
	}
	if sampledCount < 120 || sampledCount > 280 {
		t.Fatalf("sampledCount = %d / 400 at rate 0.5, expected near 200", sampledCount)
	}
}

// TestSecretRedactionAndEndpointSecurity verifies Secret redaction, 0600 file
// permission checks, and HTTPS/SSRF/userinfo rejection for OTLP endpoints.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -run '^TestSecretRedactionAndEndpointSecurity$' ./internal/telemetry
//
// # Used By
//
// Invoked by the Go test runner.
func TestSecretRedactionAndEndpointSecurity(t *testing.T) {
	const raw = "synthetic-otlp-auth-header-secret"
	s := telemetry.NewSecret(raw)

	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("otlp", "auth", s)
	for _, out := range []string{
		s.String(),
		s.GoString(),
		fmt.Sprintf("%+v", s),
		fmt.Sprintf("%#v", s),
		logBuf.String(),
	} {
		if strings.Contains(out, raw) {
			t.Fatalf("secret leaked in %q", out)
		}
		if !strings.Contains(out, telemetry.RedactedPlaceholder) {
			t.Fatalf("missing placeholder in %q", out)
		}
	}
	if b, err := json.Marshal(s); err != nil || strings.Contains(string(b), raw) {
		t.Fatalf("json.Marshal leaked secret: %q (%v)", string(b), err)
	}
	if b, err := s.MarshalText(); err != nil || string(b) != telemetry.RedactedPlaceholder {
		t.Fatalf("MarshalText = (%q, %v)", string(b), err)
	}

	dir := t.TempDir()
	okFile := filepath.Join(dir, "auth.secret")
	if err := os.WriteFile(okFile, []byte("synthetic-file-otlp-auth\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := telemetry.SecretFromFile(okFile)
	if err != nil || loaded.Reveal() != "synthetic-file-otlp-auth" {
		t.Fatalf("SecretFromFile(0600) = (%v, %v)", loaded, err)
	}
	if runtime.GOOS != "windows" {
		badFile := filepath.Join(dir, "world.secret")
		if err := os.WriteFile(badFile, []byte("synthetic-file-otlp-auth\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(badFile, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := telemetry.SecretFromFile(badFile); !errors.Is(err, telemetry.ErrSecretPermissions) {
			t.Fatalf("SecretFromFile(0644) err = %v, want ErrSecretPermissions", err)
		}
	}

	t.Setenv("CONCERT_TEST_OTLP_AUTH", "synthetic-env-otlp-auth")
	if envSec, err := telemetry.SecretFromEnv("CONCERT_TEST_OTLP_AUTH"); err != nil || envSec.Reveal() != "synthetic-env-otlp-auth" {
		t.Fatalf("SecretFromEnv = (%v, %v)", envSec, err)
	}

	// Endpoint S9 security checks.
	if _, err := telemetry.NewTracer(telemetry.DefaultConfig("http://collector.example.com/v1/traces")); !errors.Is(err, telemetry.ErrInsecureScheme) {
		t.Fatalf("http endpoint err = %v, want ErrInsecureScheme", err)
	}
	userinfoURL := (&url.URL{Scheme: "https", User: url.User("alice"), Host: "collector.example.com", Path: "/v1/traces"}).String()
	if _, err := telemetry.NewTracer(telemetry.DefaultConfig(userinfoURL)); !errors.Is(err, telemetry.ErrURLUserinfo) {
		t.Fatalf("userinfo endpoint err = %v, want ErrURLUserinfo", err)
	}
	if _, err := telemetry.NewTracer(telemetry.DefaultConfig("https://169.254.169.254/v1/traces")); !errors.Is(err, telemetry.ErrBlockedAddress) {
		t.Fatalf("metadata IP err = %v, want ErrBlockedAddress", err)
	}
	if _, err := telemetry.NewTracer(telemetry.DefaultConfig("https://127.0.0.1:4318/v1/traces")); !errors.Is(err, telemetry.ErrBlockedAddress) {
		t.Fatalf("loopback without opt-in err = %v, want ErrBlockedAddress", err)
	}
}

// TestConcurrentSpanLifecycleAndShutdown stresses concurrent span creation,
// attribute mutation, End, Flush, and Shutdown under -race.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -race -run '^TestConcurrentSpanLifecycleAndShutdown$' ./internal/telemetry
//
// # Used By
//
// Invoked by the Go test runner.
func TestConcurrentSpanLifecycleAndShutdown(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	cfg := telemetry.DefaultConfig(collector.URL)
	cfg.AllowLoopbackHTTP = true
	cfg.MaxSpans = 64
	cfg.BatchSize = 8
	cfg.FlushInterval = time.Hour

	tracer, err := telemetry.NewTracer(cfg)
	if err != nil {
		t.Fatalf("NewTracer: %v", err)
	}

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 20 {
				_, sp := tracer.StartSpan(context.Background(), fmt.Sprintf("op-%d-%d", g, i))
				sp.SetAttributes(telemetry.IntAttr("worker", int64(g)))
				sp.End()
			}
		})
	}
	_ = tracer.Flush(context.Background())
	wg.Wait()
	if err := tracer.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// ExampleParseTraceparent demonstrates parsing and formatting a W3C
// traceparent header value.
//
// # Parameters
//
// None.
//
// # Example
//
//	go test -run '^ExampleParseTraceparent$' ./internal/telemetry
//
// # Used By
//
// Invoked by the Go test runner.
func ExampleParseTraceparent() {
	sc, err := telemetry.ParseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if err != nil {
		panic(err)
	}
	fmt.Println(sc.IsSampled())
	fmt.Println(telemetry.FormatTraceparent(sc))
	// Output:
	// true
	// 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
}
