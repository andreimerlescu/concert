// Command concert-cache runs the standalone pure-stdlib Concert page-cache
// daemon over Unix domain socket (0600) and/or TCP/TLS/mTLS with constant-time
// shared-secret authentication and optional local Prometheus metrics.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/andreimerlescu/concert/internal/cache"
)

// Version is the CLI version string reported by -version and may be overridden
// at build time with -ldflags "-X main.Version=...".
var Version = "dev"

const (
	authEnvVar          = "CONCERT_CACHE_SECRET"
	gracefulDrainWindow = 10 * time.Second
)

// main is the CLI entrypoint. It binds OS signals to a root context, executes
// run, and exits with a non-zero status on configuration or runtime failure.
//
// # Parameters
//
// None. Reads process arguments from os.Args and environment variables via
// cache.ResolveSecret.
//
// # Returns
//
// None. Terminates with exit code 2 on missing secret or flag parse error, or
// 1 on other errors.
//
// # Example
//
//	// Invoked directly by the Go runtime:
//	// CONCERT_CACHE_SECRET_FILE=/run/secrets/cache.key concert-cache -unix /run/concert-cache.sock
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "concert-cache:", err)
		if errors.Is(err, cache.ErrSecretNotSet) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

// run parses flags, validates configuration, loads the shared secret from
// CONCERT_CACHE_SECRET_FILE or CONCERT_CACHE_SECRET, starts the configured
// listeners, and performs bounded graceful shutdown when ctx is cancelled.
//
// # Parameters
//
//   - ctx: Controls daemon lifetime; cancelling ctx initiates graceful drain.
//   - args: CLI arguments excluding argv[0].
//   - stdout: Destination for -version output.
//   - stderr: Destination for flag usage and structured logs.
//
// # Returns
//
// nil on clean exit or -version, flag.ErrHelp on -h/-help, or a secret-free
// configuration/runtime error.
//
// # Example
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//	err := run(ctx, []string{"-version"}, os.Stdout, os.Stderr)
//	_ = err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main.go:66 (function value)
//   - cmd/concert-cache/main_test.go:22 (function value)
//   - cmd/concert-cache/main_test.go:31 (function value)
//   - cmd/concert-cache/main_test.go:57 (function value)
//   - cmd/concert-cache/main_test.go:90 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("concert-cache", flag.ContinueOnError)
	fs.SetOutput(stderr)

	listenAddr := fs.String("listen", "", "TCP listen address (for example 127.0.0.1:6390)")
	unixPath := fs.String("unix", "", "Unix domain socket path (created with mode 0600)")
	metricsAddr := fs.String("metrics-listen", "", "Optional local HTTP address for /_cache/metrics and /_cache/healthz")
	tlsCert := fs.String("tls-cert", "", "Path to TLS server certificate PEM file (for -listen)")
	tlsKey := fs.String("tls-key", "", "Path to TLS server private key PEM file (for -listen)")
	tlsClientCA := fs.String("tls-client-ca", "", "Optional path to client CA PEM bundle to enforce mTLS")
	maxBytes := fs.Int64("max-bytes", cache.DefaultMaxBytes, "Maximum cache memory footprint in bytes")
	shards := fs.Int("shards", cache.DefaultShards, "Number of independent LRU shards")
	maxConns := fs.Int("max-conns", cache.DefaultMaxConns, "Maximum concurrent client connections")
	showVersion := fs.Bool("version", false, "Print version and exit")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: concert-cache [flags]\n\n")
		fmt.Fprintf(stderr, "Authentication secret MUST be provided via %s_FILE (0600 file) or %s.\n\nFlags:\n", authEnvVar, authEnvVar)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		_, err := fmt.Fprintf(stdout, "concert-cache %s\n", Version)
		return err
	}

	tcpListen := strings.TrimSpace(*listenAddr)
	unixSocket := strings.TrimSpace(*unixPath)
	metricsListen := strings.TrimSpace(*metricsAddr)
	certPath := strings.TrimSpace(*tlsCert)
	keyPath := strings.TrimSpace(*tlsKey)
	clientCAPath := strings.TrimSpace(*tlsClientCA)

	if tcpListen == "" && unixSocket == "" {
		return errors.New("at least one of -listen or -unix must be specified")
	}
	if *maxBytes <= 0 {
		return errors.New("-max-bytes must be positive")
	}
	if *shards <= 0 || *shards > cache.MaxShards {
		return fmt.Errorf("-shards must be between 1 and %d", cache.MaxShards)
	}
	if *maxConns <= 0 {
		return errors.New("-max-conns must be positive")
	}
	if (certPath == "") != (keyPath == "") {
		return errors.New("-tls-cert and -tls-key must be specified together")
	}
	if clientCAPath != "" && certPath == "" {
		return errors.New("-tls-client-ca requires -tls-cert and -tls-key")
	}
	if certPath != "" && tcpListen == "" {
		return errors.New("-tls-cert/-tls-key require -listen")
	}

	// Fail closed: load shared secret exclusively from env file or env var.
	secret, err := cache.ResolveSecret("", authEnvVar)
	if err != nil {
		return fmt.Errorf("load secret: %w", err)
	}

	var tlsCfg *tls.Config
	if certPath != "" {
		tlsCfg, err = cache.BuildServerTLSConfig(certPath, keyPath, clientCAPath)
		if err != nil {
			return fmt.Errorf("configure TLS: %w", err)
		}
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	store := cache.NewStore(cache.StoreConfig{
		MaxBytes: *maxBytes,
		Shards:   *shards,
	})
	defer func() { _ = store.Close() }()

	srv, err := cache.NewServer(cache.ServerConfig{
		Store:     store,
		Secret:    secret,
		MaxConns:  *maxConns,
		TLSConfig: tlsCfg,
		Logger:    logger,
	})
	if err != nil {
		return fmt.Errorf("init server: %w", err)
	}

	var (
		wg          sync.WaitGroup
		errc        = make(chan error, 3)
		metricsSrv  *http.Server
		metricsLn   net.Listener
		activeCount int
	)

	if metricsListen != "" {
		metricsLn, err = net.Listen("tcp", metricsListen)
		if err != nil {
			return fmt.Errorf("listen metrics %q: %w", metricsListen, err)
		}
		metricsSrv = &http.Server{
			Handler:           srv.MetricsHandler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    8 << 10,
		}
		activeCount++
		wg.Go(func() {
			if serveErr := metricsSrv.Serve(metricsLn); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				errc <- fmt.Errorf("metrics server: %w", serveErr)
			}
		})
	}

	if tcpListen != "" {
		activeCount++
		wg.Go(func() {
			if serveErr := srv.ListenAndServeTCP(tcpListen); serveErr != nil {
				errc <- fmt.Errorf("tcp listener: %w", serveErr)
			}
		})
	}

	if unixSocket != "" {
		activeCount++
		wg.Go(func() {
			if serveErr := srv.ListenAndServeUnix(unixSocket); serveErr != nil {
				errc <- fmt.Errorf("unix listener: %w", serveErr)
			}
		})
	}

	logger.Info("concert-cache listening",
		"version", Version,
		"tcp", tcpListen,
		"unix", unixSocket,
		"metrics", metricsListen,
		"tls", tlsCfg != nil,
		"mtls", clientCAPath != "",
		"max_bytes", *maxBytes,
		"shards", *shards,
		"max_conns", *maxConns,
		"secret", secret,
	)

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-errc:
		runErr = err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), gracefulDrainWindow)
	defer cancel()

	var shutdownErr error
	if err := srv.Shutdown(shutdownCtx); err != nil {
		shutdownErr = errors.Join(shutdownErr, fmt.Errorf("cache server shutdown: %w", err))
	}
	if metricsSrv != nil {
		if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
			shutdownErr = errors.Join(shutdownErr, fmt.Errorf("metrics shutdown: %w", err), metricsSrv.Close())
		}
	}

	wg.Wait()
	_ = activeCount
	return errors.Join(runErr, shutdownErr)
}
