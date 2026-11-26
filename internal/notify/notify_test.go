package notify_test

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/notify"
)

// TestSecretRedaction verifies that Secret never reveals raw material through
// any fmt verb, JSON/text marshaling, or slog structured logging path.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -run '^TestSecretRedaction$' ./internal/notify
//
// # Used By
//
// Invoked by the Go test runner.
func TestSecretRedaction(t *testing.T) {
	const synthetic = "unit-test-only-synthetic-credential-value"
	s := notify.NewSecret(synthetic)

	if s.IsZero() {
		t.Fatal("expected non-zero Secret")
	}
	if s.Reveal() != synthetic {
		t.Fatalf("Reveal() = %q, want %q", s.Reveal(), synthetic)
	}
	if !s.Equal(synthetic) {
		t.Fatal("Equal() returned false for identical value")
	}
	if s.Equal("wrong-value") {
		t.Fatal("Equal() returned true for mismatched value")
	}

	checks := map[string]string{
		"String":   s.String(),
		"GoString": s.GoString(),
		"%v":       fmt.Sprintf("%v", s),
		"%+v":      fmt.Sprintf("%+v", s),
		"%#v":      fmt.Sprintf("%#v", s),
		"%s":       fmt.Sprintf("%s", s),
		"%q":       fmt.Sprintf("%q", s),
		"%x":       fmt.Sprintf("%x", s),
	}
	for label, got := range checks {
		if strings.Contains(got, synthetic) {
			t.Fatalf("%s leaked raw secret: %q", label, got)
		}
		if !strings.Contains(got, notify.RedactedPlaceholder) {
			t.Fatalf("%s = %q, want %q", label, got, notify.RedactedPlaceholder)
		}
	}

	if b, err := s.MarshalText(); err != nil || string(b) != notify.RedactedPlaceholder {
		t.Fatalf("MarshalText() = (%q, %v), want (%q, nil)", string(b), err, notify.RedactedPlaceholder)
	}
	if b, err := json.Marshal(struct {
		Key notify.Secret `json:"key"`
	}{Key: s}); err != nil || strings.Contains(string(b), synthetic) || !strings.Contains(string(b), notify.RedactedPlaceholder) {
		t.Fatalf("json.Marshal() = (%q, %v), want redacted JSON", string(b), err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	logger.Info("notify config", "secret", s, "cfg", notify.TargetConfig{Name: "pd", Type: notify.ChannelPagerDuty, Secret: s})
	if strings.Contains(logBuf.String(), synthetic) {
		t.Fatalf("slog output leaked raw secret: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), notify.RedactedPlaceholder) {
		t.Fatalf("slog output missing redacted placeholder: %s", logBuf.String())
	}
}

// TestSecretIngestion verifies SecretFromFile 0600 enforcement, placeholder
// rejection, empty rejection, and SecretFromEnv error semantics.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -run '^TestSecretIngestion$' ./internal/notify
//
// # Used By
//
// Invoked by the Go test runner.
func TestSecretIngestion(t *testing.T) {
	dir := t.TempDir()

	okFile := filepath.Join(dir, "ok.secret")
	if err := os.WriteFile(okFile, []byte("  synthetic-file-token-abc  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sec, err := notify.SecretFromFile(okFile)
	if err != nil {
		t.Fatalf("SecretFromFile(0600) failed: %v", err)
	}
	if sec.Reveal() != "synthetic-file-token-abc" {
		t.Fatalf("got %q, want trimmed value", sec.Reveal())
	}

	if runtime.GOOS != "windows" {
		openFile := filepath.Join(dir, "open.secret")
		if err := os.WriteFile(openFile, []byte("synthetic-file-token-xyz\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(openFile, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := notify.SecretFromFile(openFile); !errors.Is(err, notify.ErrSecretPermissions) {
			t.Fatalf("SecretFromFile(0644) err = %v, want ErrSecretPermissions", err)
		}
	}

	placeholderFile := filepath.Join(dir, "placeholder.secret")
	if err := os.WriteFile(placeholderFile, []byte("changeme\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := notify.SecretFromFile(placeholderFile); !errors.Is(err, notify.ErrSecretPlaceholder) {
		t.Fatalf("SecretFromFile(placeholder) err = %v, want ErrSecretPlaceholder", err)
	}

	emptyFile := filepath.Join(dir, "empty.secret")
	if err := os.WriteFile(emptyFile, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := notify.SecretFromFile(emptyFile); !errors.Is(err, notify.ErrSecretEmpty) {
		t.Fatalf("SecretFromFile(empty) err = %v, want ErrSecretEmpty", err)
	}

	if _, err := notify.SecretFromFile(""); !errors.Is(err, notify.ErrSecretNotSet) {
		t.Fatalf("SecretFromFile(\"\") err = %v, want ErrSecretNotSet", err)
	}

	const envName = "CONCERT_TEST_NOTIFY_SECRET"
	t.Setenv(envName, "synthetic-env-token-123")
	envSec, err := notify.SecretFromEnv(envName)
	if err != nil || envSec.Reveal() != "synthetic-env-token-123" {
		t.Fatalf("SecretFromEnv = (%v, %v), want valid secret", envSec, err)
	}
	if _, err := notify.SecretFromEnv("CONCERT_TEST_NOTIFY_UNSET_VAR_XYZ"); !errors.Is(err, notify.ErrSecretNotSet) {
		t.Fatalf("SecretFromEnv(unset) err = %v, want ErrSecretNotSet", err)
	}
}

// TestFormattersAndWebhookHMAC verifies all five built-in ChatOps payload
// formatters and HMAC-SHA256 webhook signature signing and verification.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -run '^TestFormattersAndWebhookHMAC$' ./internal/notify
//
// # Used By
//
// Invoked by the Go test runner.
func TestFormattersAndWebhookHMAC(t *testing.T) {
	ts := time.Date(2026, 11, 26, 18, 0, 0, 0, time.UTC)
	ev := notify.Event{
		Category:  notify.CatCapacity,
		Severity:  notify.SevCritical,
		Title:     "Capacity Breaker Active",
		Summary:   "Waiting room queue reached ceiling and is returning 503.",
		Site:      "tickets.example.com",
		Timestamp: ts,
		Details: map[string]string{
			"queue_depth": "2000",
			"cap":         "200",
		},
	}

	// 1. Slack
	slackBody, err := notify.FormatSlackPayload(ev)
	if err != nil {
		t.Fatalf("FormatSlackPayload: %v", err)
	}
	var slackDoc map[string]any
	if err := json.Unmarshal(slackBody, &slackDoc); err != nil {
		t.Fatalf("slack JSON invalid: %v", err)
	}
	if _, ok := slackDoc["blocks"].([]any); !ok {
		t.Fatalf("slack payload missing blocks: %s", slackBody)
	}
	atts, ok := slackDoc["attachments"].([]any)
	if !ok || len(atts) != 1 || atts[0].(map[string]any)["color"] != "#d92d20" {
		t.Fatalf("slack attachment mismatch: %s", slackBody)
	}

	// 2. PagerDuty trigger & resolve + missing routing key rejection
	if _, err := notify.FormatPagerDutyPayload(ev, notify.Secret{}); !errors.Is(err, notify.ErrMissingRoutingKey) {
		t.Fatalf("FormatPagerDutyPayload(zero) err = %v, want ErrMissingRoutingKey", err)
	}
	pdKey := notify.NewSecret("synthetic-pd-routing-key")
	pdBody, err := notify.FormatPagerDutyPayload(ev, pdKey)
	if err != nil {
		t.Fatalf("FormatPagerDutyPayload: %v", err)
	}
	var pdDoc map[string]any
	if err := json.Unmarshal(pdBody, &pdDoc); err != nil {
		t.Fatalf("pagerduty JSON invalid: %v", err)
	}
	if pdDoc["routing_key"] != pdKey.Reveal() || pdDoc["event_action"] != notify.PagerDutyTrigger {
		t.Fatalf("pagerduty envelope mismatch: %v", pdDoc)
	}
	if dk, _ := pdDoc["dedup_key"].(string); !strings.HasPrefix(dk, "concert-") {
		t.Fatalf("pagerduty dedup_key = %q, want concert- prefix", dk)
	}

	resolveEv := ev
	resolveEv.Action = notify.PagerDutyResolve
	resolveEv.DedupKey = "custom-dedup-1"
	pdResolveBody, err := notify.FormatPagerDutyPayload(resolveEv, pdKey)
	if err != nil {
		t.Fatalf("FormatPagerDutyPayload(resolve): %v", err)
	}
	var pdResolve map[string]any
	if err := json.Unmarshal(pdResolveBody, &pdResolve); err != nil {
		t.Fatal(err)
	}
	if pdResolve["event_action"] != notify.PagerDutyResolve || pdResolve["dedup_key"] != "custom-dedup-1" {
		t.Fatalf("pagerduty resolve mismatch: %v", pdResolve)
	}

	// 3. Discord
	discordBody, err := notify.FormatDiscordPayload(ev)
	if err != nil {
		t.Fatalf("FormatDiscordPayload: %v", err)
	}
	var discordDoc map[string]any
	if err := json.Unmarshal(discordBody, &discordDoc); err != nil {
		t.Fatalf("discord JSON invalid: %v", err)
	}
	embeds, ok := discordDoc["embeds"].([]any)
	if !ok || len(embeds) != 1 || int(embeds[0].(map[string]any)["color"].(float64)) != 0xd92d20 {
		t.Fatalf("discord embeds mismatch: %s", discordBody)
	}

	// 4. Teams Adaptive Card
	teamsBody, err := notify.FormatTeamsPayload(ev)
	if err != nil {
		t.Fatalf("FormatTeamsPayload: %v", err)
	}
	var teamsDoc map[string]any
	if err := json.Unmarshal(teamsBody, &teamsDoc); err != nil {
		t.Fatalf("teams JSON invalid: %v", err)
	}
	tAtts, ok := teamsDoc["attachments"].([]any)
	if !ok || len(tAtts) != 1 || tAtts[0].(map[string]any)["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("teams adaptive card mismatch: %s", teamsBody)
	}

	// 5. Generic Webhook + HMAC-SHA256 verification
	whBody, err := notify.FormatWebhookPayload(ev)
	if err != nil {
		t.Fatalf("FormatWebhookPayload: %v", err)
	}
	whSecret := notify.NewSecret("synthetic-webhook-hmac-key")
	sig := notify.SignWebhookPayload(whSecret, ts.Unix(), whBody)
	if !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("signature = %q, want sha256= prefix", sig)
	}
	tsStr := fmt.Sprintf("%d", ts.Unix())
	if !notify.VerifyWebhookSignature(whSecret, tsStr, sig, whBody) {
		t.Fatal("VerifyWebhookSignature returned false for valid signature")
	}
	if notify.VerifyWebhookSignature(whSecret, tsStr, sig, append(whBody, ' ')) {
		t.Fatal("VerifyWebhookSignature returned true for tampered body")
	}
	if notify.VerifyWebhookSignature(notify.NewSecret("different-key"), tsStr, sig, whBody) {
		t.Fatal("VerifyWebhookSignature returned true for wrong key")
	}
}

// TestURLValidationAndSSRFRejection verifies S9 endpoint validation: HTTPS
// enforcement, userinfo rejection, private/link-local/loopback IP blocking,
// and redirect refusal.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -run '^TestURLValidationAndSSRFRejection$' ./internal/notify
//
// # Used By
//
// Invoked by the Go test runner.
func TestURLValidationAndSSRFRejection(t *testing.T) {
	cases := []struct {
		name      string
		rawURL    string
		loopback  bool
		wantError error
	}{
		{name: "https public ok", rawURL: "https://hooks.slack.com/services/a/b/c", loopback: false, wantError: nil},
		{name: "http rejected by default", rawURL: "http://hooks.slack.com/services/a/b/c", loopback: false, wantError: notify.ErrInsecureScheme},
		{name: "http non-loopback rejected even with loopback flag", rawURL: "http://example.com/hook", loopback: true, wantError: notify.ErrInsecureScheme},
		{name: "userinfo rejected", rawURL: (&url.URL{Scheme: "https", User: url.User("alice"), Host: "hooks.slack.com", Path: "/hook"}).String(), loopback: false, wantError: notify.ErrURLUserinfo},
		{name: "metadata link-local rejected", rawURL: "https://169.254.169.254/latest/meta-data", loopback: false, wantError: notify.ErrBlockedAddress},
		{name: "rfc1918 private rejected", rawURL: "https://10.0.0.5/webhook", loopback: false, wantError: notify.ErrBlockedAddress},
		{name: "rfc1918 private rejected even with loopback flag", rawURL: "https://192.168.1.10/webhook", loopback: true, wantError: notify.ErrBlockedAddress},
		{name: "loopback rejected by default", rawURL: "https://127.0.0.1:8443/hook", loopback: false, wantError: notify.ErrBlockedAddress},
		{name: "localhost rejected by default", rawURL: "https://localhost:8443/hook", loopback: false, wantError: notify.ErrBlockedAddress},
		{name: "ipv6 ula rejected", rawURL: "https://[fd00::1]/hook", loopback: false, wantError: notify.ErrBlockedAddress},
		{name: "http loopback allowed when opted in", rawURL: "http://127.0.0.1:18080/hook", loopback: true, wantError: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := notify.ValidateEndpointURL(tc.rawURL, tc.loopback)
			if tc.wantError == nil {
				if err != nil {
					t.Fatalf("ValidateEndpointURL(%q) unexpected error: %v", tc.rawURL, err)
				}
				return
			}
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("ValidateEndpointURL(%q) err = %v, want %v", tc.rawURL, err, tc.wantError)
			}
		})
	}

	// Verify redirects are rejected at delivery time.
	redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/other", http.StatusFound)
	}))
	defer redirSrv.Close()

	errCh := make(chan error, 1)
	d, err := notify.NewDispatcher(notify.Config{
		Targets: []notify.TargetConfig{{
			Name: "redir",
			Type: notify.ChannelWebhook,
			URL:  redirSrv.URL,
		}},
		Workers:           1,
		MaxRetries:        0,
		DisableCoalesce:   true,
		AllowLoopbackHTTP: true,
		OnError: func(_ string, err error) {
			errCh <- err
		},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	if err := d.Enqueue(notify.Event{Category: notify.CatSecurity, Severity: notify.SevWarn, Title: "redirect test"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := d.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case gotErr := <-errCh:
		if !errors.Is(gotErr, notify.ErrRedirectDisallowed) {
			t.Fatalf("redirect error = %v, want ErrRedirectDisallowed", gotErr)
		}
	default:
		t.Fatal("expected OnError callback for disallowed redirect")
	}
}

// TestDispatcherEndToEndAllChannels verifies asynchronous delivery across all
// five channel types including live HMAC verification on the receiving server.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -run '^TestDispatcherEndToEndAllChannels$' ./internal/notify
//
// # Used By
//
// Invoked by the Go test runner.
func TestDispatcherEndToEndAllChannels(t *testing.T) {
	whSecret := notify.NewSecret("synthetic-e2e-webhook-key")
	pdSecret := notify.NewSecret("synthetic-e2e-pd-routing-key")

	var mu sync.Mutex
	received := make(map[string][]byte)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/webhook" {
			ts := r.Header.Get(notify.HeaderTimestamp)
			sig := r.Header.Get(notify.HeaderSignature)
			if !notify.VerifyWebhookSignature(whSecret, ts, sig, body) {
				http.Error(w, "invalid hmac", http.StatusUnauthorized)
				return
			}
		}
		mu.Lock()
		received[r.URL.Path] = body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d, err := notify.NewDispatcher(notify.Config{
		Targets: []notify.TargetConfig{
			{Name: "slack", Type: notify.ChannelSlack, URL: srv.URL + "/slack"},
			{Name: "pd", Type: notify.ChannelPagerDuty, URL: srv.URL + "/pd", Secret: pdSecret},
			{Name: "discord", Type: notify.ChannelDiscord, URL: srv.URL + "/discord"},
			{Name: "teams", Type: notify.ChannelTeams, URL: srv.URL + "/teams"},
			{Name: "webhook", Type: notify.ChannelWebhook, URL: srv.URL + "/webhook", Secret: whSecret},
		},
		Workers:           2,
		DisableCoalesce:   true,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	details := map[string]string{"origin": "origin-0"}
	if err := d.Enqueue(notify.Event{
		Category: notify.CatSilence,
		Severity: notify.SevCritical,
		Title:    "Origin Unhealthy",
		Summary:  "All backends unhealthy",
		Site:     "shop.example.com",
		Details:  details,
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	// Mutating caller map after Enqueue must not race with workers.
	details["origin"] = "mutated-by-caller"

	if err := d.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st := d.Stats()
	if st.Delivered != 5 || st.Failed != 0 {
		t.Fatalf("Stats = %+v, want Delivered=5 Failed=0", st)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{"/slack", "/pd", "/discord", "/teams", "/webhook"} {
		body, ok := received[path]
		if !ok || len(body) == 0 {
			t.Fatalf("missing delivery for %s", path)
		}
		if strings.Contains(string(body), "mutated-by-caller") {
			t.Fatalf("channel %s saw caller map mutation", path)
		}
	}
}

// TestDispatcherRetryAndBackoff verifies retries on HTTP 503 and 429 and
// immediate termination on non-retryable HTTP 400 without time.Sleep.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -run '^TestDispatcherRetryAndBackoff$' ./internal/notify
//
// # Used By
//
// Invoked by the Go test runner.
func TestDispatcherRetryAndBackoff(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/flaky":
			n := attempts.Add(1)
			switch n {
			case 1:
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
			case 2:
				w.WriteHeader(http.StatusServiceUnavailable)
			default:
				w.WriteHeader(http.StatusAccepted)
			}
		case "/bad":
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	var sleepCalls atomic.Int32
	d, err := notify.NewDispatcher(notify.Config{
		Targets: []notify.TargetConfig{
			{Name: "flaky", Type: notify.ChannelWebhook, URL: srv.URL + "/flaky"},
			{Name: "bad", Type: notify.ChannelWebhook, URL: srv.URL + "/bad"},
		},
		Workers:           1,
		MaxRetries:        3,
		BaseBackoff:       10 * time.Millisecond,
		MaxBackoff:        50 * time.Millisecond,
		DisableCoalesce:   true,
		AllowLoopbackHTTP: true,
		Sleep: func(ctx context.Context, _ time.Duration) error {
			sleepCalls.Add(1)
			return ctx.Err()
		},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	if err := d.Enqueue(notify.Event{Category: notify.CatQueue, Severity: notify.SevWarn, Title: "High queue"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := d.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st := d.Stats()
	if attempts.Load() != 3 {
		t.Fatalf("flaky attempts = %d, want 3", attempts.Load())
	}
	if sleepCalls.Load() != 2 || st.Retries != 2 {
		t.Fatalf("retries = %d (sleepCalls=%d), want 2", st.Retries, sleepCalls.Load())
	}
	if st.Delivered != 1 || st.Failed != 1 {
		t.Fatalf("Stats = %+v, want Delivered=1 Failed=1", st)
	}
}

// TestDispatcherCoalescing verifies per-category coalescing within
// CoalesceWindow and delivery once the window advances using an injected clock.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -run '^TestDispatcherCoalescing$' ./internal/notify
//
// # Used By
//
// Invoked by the Go test runner.
func TestDispatcherCoalescing(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var clockMu sync.Mutex
	now := time.Date(2026, 11, 26, 18, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	advance := func(dt time.Duration) {
		clockMu.Lock()
		now = now.Add(dt)
		clockMu.Unlock()
	}

	d, err := notify.NewDispatcher(notify.Config{
		Targets: []notify.TargetConfig{
			{Name: "wh", Type: notify.ChannelWebhook, URL: srv.URL},
		},
		Workers:           1,
		CoalesceWindow:    30 * time.Second,
		AllowLoopbackHTTP: true,
		Clock:             clock,
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	// First event delivered; second & third in same category+severity within 30s coalesce.
	for range 3 {
		if err := d.Enqueue(notify.Event{Category: notify.CatQueue, Severity: notify.SevWarn, Title: "Queue high"}); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}
	// Severity escalation in same category bypasses coalescing.
	if err := d.Enqueue(notify.Event{Category: notify.CatQueue, Severity: notify.SevCritical, Title: "Queue breaker"}); err != nil {
		t.Fatalf("Enqueue escalation: %v", err)
	}
	// Advance past window; next warn event delivers.
	advance(31 * time.Second)
	if err := d.Enqueue(notify.Event{Category: notify.CatQueue, Severity: notify.SevWarn, Title: "Queue still high"}); err != nil {
		t.Fatalf("Enqueue after window: %v", err)
	}

	if err := d.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st := d.Stats()
	if st.Coalesced != 2 || st.Delivered != 3 || hits.Load() != 3 {
		t.Fatalf("Stats = %+v, hits=%d; want Coalesced=2 Delivered=3", st, hits.Load())
	}
}

// TestDispatcherBoundedQueueDropAndShutdown verifies that saturating the
// bounded queue drops excess events immediately with ErrQueueFull rather than
// blocking producers, and that Close drains cleanly or cancels on deadline.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -run '^TestDispatcherBoundedQueueDropAndShutdown$' ./internal/notify
//
// # Used By
//
// Invoked by the Go test runner.
func TestDispatcherBoundedQueueDropAndShutdown(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var delivered atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-release:
			delivered.Add(1)
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	d, err := notify.NewDispatcher(notify.Config{
		Targets: []notify.TargetConfig{
			{Name: "slow", Type: notify.ChannelWebhook, URL: srv.URL},
		},
		MaxQueueSize:      2,
		Workers:           1,
		MaxRetries:        0,
		DisableCoalesce:   true,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	// First event occupies the single worker in the HTTP handler.
	if err := d.Enqueue(notify.Event{Category: notify.CatCapacity, Severity: notify.SevWarn, Title: "ev-0"}); err != nil {
		t.Fatalf("Enqueue ev-0: %v", err)
	}
	<-started

	// Next 2 fill the bounded buffer; subsequent Enqueue must drop immediately.
	if err := d.Enqueue(notify.Event{Category: notify.CatCapacity, Severity: notify.SevWarn, Title: "ev-1"}); err != nil {
		t.Fatalf("Enqueue ev-1: %v", err)
	}
	if err := d.Enqueue(notify.Event{Category: notify.CatCapacity, Severity: notify.SevWarn, Title: "ev-2"}); err != nil {
		t.Fatalf("Enqueue ev-2: %v", err)
	}
	if err := d.Enqueue(notify.Event{Category: notify.CatCapacity, Severity: notify.SevWarn, Title: "ev-3"}); !errors.Is(err, notify.ErrQueueFull) {
		t.Fatalf("Enqueue ev-3 err = %v, want ErrQueueFull", err)
	}

	close(release)
	if err := d.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Second Close is idempotent.
	if err := d.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := d.Enqueue(notify.Event{Category: notify.CatCapacity, Severity: notify.SevInfo, Title: "after-close"}); !errors.Is(err, notify.ErrDispatcherClosed) {
		t.Fatalf("Enqueue after Close err = %v, want ErrDispatcherClosed", err)
	}

	st := d.Stats()
	if st.Dropped != 1 || st.Delivered != 3 || delivered.Load() != 3 {
		t.Fatalf("Stats = %+v, delivered=%d; want Dropped=1 Delivered=3", st, delivered.Load())
	}
}

// TestDispatcherConcurrentEnqueueAndClose stresses concurrent producers racing
// with Close under -race to ensure no send-on-closed panic or data race occurs.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -race -run '^TestDispatcherConcurrentEnqueueAndClose$' ./internal/notify
//
// # Used By
//
// Invoked by the Go test runner.
func TestDispatcherConcurrentEnqueueAndClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d, err := notify.NewDispatcher(notify.Config{
		Targets: []notify.TargetConfig{
			{Name: "wh", Type: notify.ChannelWebhook, URL: srv.URL},
		},
		MaxQueueSize:      16,
		Workers:           2,
		DisableCoalesce:   true,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 25 {
				_ = d.Enqueue(notify.Event{
					Category: notify.CatSecurity,
					Severity: notify.SevWarn,
					Title:    fmt.Sprintf("alert-%d-%d", g, i),
					Details:  map[string]string{"worker": fmt.Sprintf("%d", g)},
				})
			}
		})
	}
	_ = d.Close(context.Background())
	wg.Wait()
}

// ExampleVerifyWebhookSignature demonstrates signing and verifying a generic
// Concert webhook payload with a redacting Secret.
//
// # Parameters
//
// None.
//
// # Example
//
//	go test -run '^ExampleVerifyWebhookSignature$' ./internal/notify
//
// # Used By
//
// Invoked by the Go test runner.
func ExampleVerifyWebhookSignature() {
	secret := notify.NewSecret("example-signing-key-only")
	body := []byte(`{"category":"capacity","severity":"critical"}`)
	sig := notify.SignWebhookPayload(secret, 1700000000, body)
	fmt.Println(secret)
	fmt.Println(notify.VerifyWebhookSignature(secret, "1700000000", sig, body))
	// Output:
	// [REDACTED]
	// true
}
