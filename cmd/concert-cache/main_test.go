package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/cache"
)

func TestRun_VersionAndHelp(t *testing.T) {
	var out, errBuf bytes.Buffer
	if err := run(t.Context(), []string{"-version"}, &out, &errBuf); err != nil {
		t.Fatalf("run(-version): %v", err)
	}
	if !strings.HasPrefix(out.String(), "concert-cache ") {
		t.Fatalf("version output = %q, want prefix 'concert-cache '", out.String())
	}

	out.Reset()
	errBuf.Reset()
	err := run(t.Context(), []string{"-h"}, &out, &errBuf)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("run(-h) error = %v, want flag.ErrHelp", err)
	}
	help := errBuf.String()
	if !strings.Contains(help, "CONCERT_CACHE_SECRET_FILE") {
		t.Fatalf("help text missing secret env guidance:\n%s", help)
	}
	if strings.Contains(help, "-secret ") {
		t.Fatalf("help text must never expose a CLI secret flag:\n%s", help)
	}
}

func TestRun_FailsClosedWithoutSecret(t *testing.T) {
	t.Setenv("CONCERT_CACHE_SECRET", "")
	t.Setenv("CONCERT_CACHE_SECRET_FILE", "")
	// Unset both variables explicitly so ResolveSecret observes them absent.
	if err := os.Unsetenv("CONCERT_CACHE_SECRET"); err != nil {
		t.Fatalf("Unsetenv: %v", err)
	}
	if err := os.Unsetenv("CONCERT_CACHE_SECRET_FILE"); err != nil {
		t.Fatalf("Unsetenv: %v", err)
	}

	var out, errBuf bytes.Buffer
	sock := filepath.Join(t.TempDir(), "c.sock")
	err := run(t.Context(), []string{"-unix", sock}, &out, &errBuf)
	if !errors.Is(err, cache.ErrSecretNotSet) {
		t.Fatalf("run without secret = %v, want ErrSecretNotSet", err)
	}
}

func TestRun_UnixLifecycleAndSecretRedaction(t *testing.T) {
	var rawBuf [24]byte
	if _, err := rand.Read(rawBuf[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	rawSecret := fmt.Sprintf("cli-ephemeral-%x", rawBuf[:])

	dir := t.TempDir()
	secFile := filepath.Join(dir, "cache.secret")
	if err := os.WriteFile(secFile, []byte(rawSecret+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("CONCERT_CACHE_SECRET_FILE", secFile)

	// Keep the Unix socket path well under the 104-byte macOS sun_path limit.
	sockDir, err := os.MkdirTemp("/tmp", "cc-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "c.sock")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var out, errBuf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-unix", sock, "-max-bytes", "4194304", "-shards", "8", "-max-conns", "16"}, &out, &errBuf)
	}()

	cli, err := cache.NewClient(cache.ClientConfig{
		Network:    "unix",
		Address:    sock,
		Secret:     cache.NewSecret(rawSecret),
		FailClosed: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = cli.Close() }()

	// Poll readiness via Ping using a bounded ticker (no bare time.Sleep).
	tk := time.NewTicker(5 * time.Millisecond)
	defer tk.Stop()
	readyDeadline := time.Now().Add(3 * time.Second)
	for {
		if err := cli.Ping(t.Context()); err == nil {
			break
		}
		if time.Now().After(readyDeadline) {
			t.Fatalf("timed out waiting for concert-cache daemon; stderr:\n%s", errBuf.String())
		}
		select {
		case runErr := <-done:
			t.Fatalf("daemon exited prematurely: %v\nstderr:\n%s", runErr, errBuf.String())
		case <-tk.C:
		}
	}

	if err := cli.Put(t.Context(), cache.Entry{
		Key:    "example.com\x00/\x00\x00raw",
		Status: http.StatusOK,
		Body:   []byte("ok"),
		TTL:    time.Minute,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	ent, ok, err := cli.Get(t.Context(), "example.com\x00/\x00\x00raw")
	if err != nil || !ok || string(ent.Body) != "ok" {
		t.Fatalf("Get = (%+v, %v, %v)", ent, ok, err)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("daemon graceful shutdown error = %v", err)
	}
	if strings.Contains(errBuf.String(), rawSecret) || strings.Contains(out.String(), rawSecret) {
		t.Fatal("daemon logs leaked raw secret")
	}
	if !strings.Contains(errBuf.String(), cache.SecretPlaceholder) {
		t.Fatalf("expected redacted secret placeholder in startup log:\n%s", errBuf.String())
	}
}
