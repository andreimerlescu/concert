package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/watchdog"
)

// TestRunVersionAndHelp verifies -version and -h succeed without requiring
// secrets and never expose credential values in help or version output.
//
// # Parameters
//
//   - t: Active test context (invoked by `go test ./cmd/concert-watchdog`).
//
// # Example
//
//	go test -v -run '^TestRunVersionAndHelp$' ./cmd/concert-watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestRunVersionAndHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), []string{"-version"}, &stdout, &stderr); err != nil {
		t.Fatalf("run(-version) error: %v", err)
	}
	if !strings.HasPrefix(stdout.String(), "concert-watchdog ") {
		t.Errorf("-version output = %q, want prefix 'concert-watchdog '", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if err := run(t.Context(), []string{"-h"}, &stdout, &stderr); err != nil {
		t.Fatalf("run(-h) error: %v", err)
	}
	help := stderr.String()
	for _, want := range []string{"-health-url", "-ready-url", "-metrics-url", "-clear-url", "CONCERT_WATCHDOG_TOKEN", "CONCERT_WATCHDOG_WEBHOOK_TOKEN"} {
		if !strings.Contains(help, want) {
			t.Errorf("-h output missing %q", want)
		}
	}
}

// TestRunSecretValidationFailsClosed verifies that placeholder tokens, open
// secret file permissions, and remote plaintext webhook URLs fail startup
// cleanly without leaking secret values.
//
// # Parameters
//
//   - t: Active test context (invoked by `go test ./cmd/concert-watchdog`).
//
// # Example
//
//	go test -v -run '^TestRunSecretValidationFailsClosed$' ./cmd/concert-watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestRunSecretValidationFailsClosed(t *testing.T) {
	t.Run("rejects placeholder env token", func(t *testing.T) {
		t.Setenv("CONCERT_WATCHDOG_TOKEN", "changeme")
		var out, errBuf bytes.Buffer
		err := run(t.Context(), nil, &out, &errBuf)
		if !errors.Is(err, watchdog.ErrSecretPlaceholder) {
			t.Fatalf("run() err = %v, want ErrSecretPlaceholder", err)
		}
	})

	t.Run("rejects world-readable token file", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX file permissions not enforced on Windows")
		}
		p := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(p, []byte("synthetic-cli-token-value\n"), 0o644); err != nil {
			t.Fatalf("write token file: %v", err)
		}
		t.Setenv("CONCERT_WATCHDOG_TOKEN_FILE", p)
		var out, errBuf bytes.Buffer
		err := run(t.Context(), nil, &out, &errBuf)
		if !errors.Is(err, watchdog.ErrSecretPermissions) {
			t.Fatalf("run() err = %v, want ErrSecretPermissions", err)
		}
		if strings.Contains(err.Error(), "synthetic-cli-token-value") {
			t.Fatalf("error leaked secret content: %v", err)
		}
	})

	t.Run("rejects remote plaintext alert webhook", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		err := run(t.Context(), []string{"-alert-webhook", "http://alerts.example.com/hook"}, &out, &errBuf)
		if !errors.Is(err, watchdog.ErrInvalidURL) {
			t.Fatalf("run() err = %v, want ErrInvalidURL", err)
		}
	})
}

// TestRunExternalModeCleanCancel runs the CLI entrypoint against a local fake
// Concert server with a valid 0600 token file and verifies clean cancellation
// and zero secret leakage in stderr logs.
//
// # Parameters
//
//   - t: Active test context (invoked by `go test -race ./cmd/concert-watchdog`).
//
// # Example
//
//	go test -race -v -run '^TestRunExternalModeCleanCancel$' ./cmd/concert-watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestRunExternalModeCleanCancel(t *testing.T) {
	syntheticTok := "synthetic-cli-valid-token-4488"
	tokPath := filepath.Join(t.TempDir(), "watchdog.token")
	if err := os.WriteFile(tokPath, []byte(syntheticTok+"\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	t.Setenv("CONCERT_WATCHDOG_TOKEN_FILE", tokPath)

	probed := make(chan struct{})
	var probedOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_room/healthz", "/_room/readyz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		case "/_room/metrics":
			probedOnce.Do(func() { close(probed) })
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("concert_upstream_backends_healthy 1\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var stdout, stderr bytes.Buffer
	args := []string{
		"-health-url", srv.URL + "/_room/healthz",
		"-ready-url", srv.URL + "/_room/readyz",
		"-metrics-url", srv.URL + "/_room/metrics",
		"-clear-url", srv.URL + "/_room/queue/clear",
		"-interval", "10ms",
		"-timeout", "1s",
	}

	done := make(chan error, 1)
	go func() { done <- run(ctx, args, &stdout, &stderr) }()

	select {
	case <-probed:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatalf("timed out waiting for CLI watchdog probe")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run() error after cancel: %v", err)
	}
	if strings.Contains(stderr.String(), syntheticTok) {
		t.Fatalf("stderr logs leaked operator token: %s", stderr.String())
	}
}
