package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/kv"
)

func TestCLI_VersionAndHelpDisclosure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), []string{"-version"}, &stdout, &stderr); err != nil {
		t.Fatalf("run -version: %v", err)
	}
	if !strings.HasPrefix(stdout.String(), "concert-kv v") {
		t.Fatalf("unexpected -version output: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	err := run(t.Context(), []string{"-h"}, &stdout, &stderr)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("run -h error = %v, want flag.ErrHelp", err)
	}
	help := stderr.String()
	// Confirm no password flag exists (S4) and env guidance is shown.
	if strings.Contains(help, "-password") {
		t.Fatalf("help output must not expose a -password CLI flag: %s", help)
	}
	if !strings.Contains(help, "CONCERT_KV_PASSWORD_FILE") {
		t.Fatalf("help output should document CONCERT_KV_PASSWORD_FILE: %s", help)
	}
}

func TestCLI_PasswordFailClosedAndLifecycle(t *testing.T) {
	// Empty CONCERT_KV_PASSWORD must fail closed (S7).
	t.Setenv("CONCERT_KV_PASSWORD", "")
	t.Setenv("CONCERT_KV_PASSWORD_FILE", "")
	var out, errBuf bytes.Buffer
	err := run(t.Context(), []string{"-listen", "", "-unix", filepath.Join(t.TempDir(), "s.sock")}, &out, &errBuf)
	if !errors.Is(err, kv.ErrSecretEmpty) {
		t.Fatalf("empty env password error = %v, want ErrSecretEmpty", err)
	}

	// World-readable password file must fail closed (S7, S8).
	if runtime.GOOS != "windows" {
		badFile := filepath.Join(t.TempDir(), "pass")
		if werr := os.WriteFile(badFile, []byte("runtime-ephemeral-val-123\n"), 0o644); werr != nil {
			t.Fatalf("write badFile: %v", werr)
		}
		t.Setenv("CONCERT_KV_PASSWORD_FILE", badFile)
		err = run(t.Context(), []string{"-listen", "", "-unix", filepath.Join(t.TempDir(), "s2.sock")}, &out, &errBuf)
		if !errors.Is(err, kv.ErrSecretPermissions) {
			t.Fatalf("world-readable password file error = %v, want ErrSecretPermissions", err)
		}
	}

	// Valid 0600 password file + Unix socket + WAL startup and graceful shutdown.
	dir := t.TempDir()
	goodFile := filepath.Join(dir, "pass.0600")
	const testToken = "runtime-ephemeral-val-98765"
	if werr := os.WriteFile(goodFile, []byte(testToken+"\n"), 0o600); werr != nil {
		t.Fatalf("write goodFile: %v", werr)
	}
	t.Setenv("CONCERT_KV_PASSWORD_FILE", goodFile)

	sockDir, err := os.MkdirTemp("/tmp", "ckv-*")
	if err != nil {
		t.Fatalf("MkdirTemp for unix socket: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "kv.sock")
	dataDir := filepath.Join(dir, "data")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	var runOut, runErr bytes.Buffer
	go func() {
		done <- run(ctx, []string{
			"-listen", "",
			"-unix", sock,
			"-data-dir", dataDir,
			"-max-memory", "8MiB",
			"-max-conns", "16",
		}, &runOut, &runErr)
	}()

	// Wait until the Unix socket accepts authenticated PING (bounded by deadline).
	cli, err := kv.NewClient(kv.ClientConfig{
		Addr:        "unix://" + sock,
		Password:    kv.NewSecret(testToken),
		DialTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		cancel()
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = cli.Close() }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		pingCtx, pingCancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
		perr := cli.Ping(pingCtx)
		pingCancel()
		if perr == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("daemon did not become ready: %v (logs: %s)", perr, runErr.String())
		}
		select {
		case rerr := <-done:
			t.Fatalf("daemon exited early: %v (logs: %s)", rerr, runErr.String())
		default:
		}
		runtime.Gosched()
	}

	// Trigger graceful shutdown and verify secret never leaked into logs.
	cancel()
	if rerr := <-done; rerr != nil {
		t.Fatalf("daemon shutdown error: %v", rerr)
	}
	if strings.Contains(runErr.String(), testToken) || strings.Contains(runOut.String(), testToken) {
		t.Fatalf("daemon output leaked password")
	}
}

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"64MiB", 64 << 20, false},
		{"128MB", 128_000_000, false},
		{"67108864", 67108864, false},
		{"1KiB", 1024, false},
		{"0", 0, true},
		{"-5MiB", 0, true},
		{"abc", 0, true},
	}
	for _, tc := range tests {
		got, err := parseByteSize(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseByteSize(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("parseByteSize(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
