// Command concert-kv runs the standalone pure-stdlib RESP2 key-value, pub/sub,
// and shared waiting-room queue daemon replacing Redis for Concert clusters.
//
// Authentication credentials are read exclusively from the environment
// (CONCERT_KV_PASSWORD_FILE or CONCERT_KV_PASSWORD) and never from CLI flags.
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
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/andreimerlescu/concert"
	"github.com/andreimerlescu/concert/internal/kv"
)

const authEnvVar = "CONCERT_KV_PASSWORD"

// main invokes run with process arguments and signal cancellation, exiting
// with a nonzero code on startup or runtime errors.
//
// # Parameters
//
// None (reads os.Args, os.Stdout, os.Stderr).
//
// # Example
//
//	concert-kv -listen 127.0.0.1:6380 -data-dir /var/lib/concert-kv
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "concert-kv: %v\n", err)
		os.Exit(1)
	}
}

// run parses CLI flags, loads optional credentials and TLS configuration,
// replays any existing WAL/snapshot, starts the RESP2 server (and optional
// Replicator), and shuts down cleanly when ctx is cancelled.
//
// # Parameters
//
//   - ctx: Lifecycle context; cancelling ctx triggers graceful shutdown.
//   - args: CLI arguments excluding argv[0].
//   - stdout: Writer for -version output.
//   - stderr: Writer for flag usage and structured logs.
//
// # Returns
//
// nil on clean exit or -version; flag.ErrHelp on -h; or a descriptive error
// containing no secret material.
//
// # Example
//
//	if err := run(ctx, []string{"-version"}, os.Stdout, os.Stderr); err != nil {
//	    return err
//	}
func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("concert-kv", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		listenAddr  = fs.String("listen", "127.0.0.1:6380", "TCP address to listen on (empty disables TCP)")
		unixPath    = fs.String("unix", "", "Unix domain socket path (created with mode 0600)")
		tlsCert     = fs.String("tls-cert", "", "path to PEM-encoded TLS certificate")
		tlsKey      = fs.String("tls-key", "", "path to PEM-encoded TLS private key")
		tlsClientCA = fs.String("tls-client-ca", "", "path to PEM-encoded CA bundle for mTLS client verification")
		dataDir     = fs.String("data-dir", "", "optional directory for append-only WAL and 0600 snapshots")
		maxMemory   = fs.String("max-memory", "64MiB", "maximum tracked store memory (e.g. 64MiB, 128MB, or bytes)")
		maxConns    = fs.Int("max-conns", kv.DefaultMaxConns, "maximum concurrent client connections")
		replicaOf   = fs.String("replica-of", "", "primary concert-kv address to replicate from (host:port or unix:///path)")
		showVersion = fs.Bool("version", false, "print version and exit")
	)

	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: concert-kv [flags]\n\n")
		fmt.Fprintf(stderr, "Authentication password is read ONLY from %s_FILE (mode 0600) or %s.\n\n",
			authEnvVar, authEnvVar)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		_, err := fmt.Fprintf(stdout, "concert-kv %s\n", concert.Version())
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}

	memBytes, err := parseByteSize(*maxMemory)
	if err != nil {
		return fmt.Errorf("parse -max-memory: %w", err)
	}
	if *maxConns <= 0 {
		return fmt.Errorf("-max-conns must be positive (got %d)", *maxConns)
	}
	if strings.TrimSpace(*listenAddr) == "" && strings.TrimSpace(*unixPath) == "" {
		return errors.New("at least one of -listen or -unix must be specified")
	}

	// Password is never accepted on the command line (S4, S5, S6).
	password, err := kv.ResolveOptionalSecret(authEnvVar)
	if err != nil {
		return fmt.Errorf("configure authentication password: %w", err)
	}

	var serverTLS *tls.Config
	if *tlsCert != "" || *tlsKey != "" || *tlsClientCA != "" {
		if *tlsCert == "" || *tlsKey == "" {
			return errors.New("-tls-cert and -tls-key must both be set when TLS is enabled")
		}
		serverTLS, err = kv.LoadServerTLSConfig(*tlsCert, *tlsKey, *tlsClientCA)
		if err != nil {
			return fmt.Errorf("configure server TLS: %w", err)
		}
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	store := kv.NewStore(kv.StoreConfig{
		MaxMemoryBytes: memBytes,
	})

	var wal *kv.WAL
	if *dataDir != "" {
		wal, err = kv.OpenWAL(*dataDir, true)
		if err != nil {
			return fmt.Errorf("open WAL: %w", err)
		}
		defer func() {
			if cerr := wal.Close(); cerr != nil {
				logger.Error("close WAL failed", "error", cerr)
			}
		}()
		stats, err := wal.Replay(store)
		if err != nil {
			return fmt.Errorf("replay WAL: %w", err)
		}
		logger.Info("wal replay complete",
			"snapshot_loaded", stats.SnapshotLoaded,
			"wal_replayed", stats.WALReplayed,
			"last_seq", stats.LastSeq,
			"truncated_tail", stats.TruncatedTail,
		)
	}

	if *listenAddr != "" && password.IsZero() && !isLoopbackListen(*listenAddr) {
		logger.Warn("listening on non-loopback address without authentication password",
			"listen", *listenAddr,
			"hint", "set CONCERT_KV_PASSWORD_FILE or CONCERT_KV_PASSWORD",
		)
	}

	srv, err := kv.NewServer(kv.ServerConfig{
		ListenAddr: *listenAddr,
		UnixPath:   *unixPath,
		TLSConfig:  serverTLS,
		Password:   password,
		MaxConns:   *maxConns,
		Store:      store,
		WAL:        wal,
		Logger:     logger,
	})
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("start server: %w", err)
	}

	var rep *kv.Replicator
	if strings.TrimSpace(*replicaOf) != "" {
		var repTLS *tls.Config
		if *tlsClientCA != "" || (*tlsCert != "" && *tlsKey != "") {
			repTLS, err = kv.LoadClientTLSConfig(*tlsClientCA, *tlsCert, *tlsKey, "")
			if err != nil {
				_ = srv.Close()
				return fmt.Errorf("configure replica TLS: %w", err)
			}
		}
		rep, err = kv.NewReplicator(kv.ReplicaConfig{
			PrimaryAddr: *replicaOf,
			Password:    password,
			TLSConfig:   repTLS,
			Store:       store,
			WAL:         wal,
			Logger:      logger,
		})
		if err != nil {
			_ = srv.Close()
			return fmt.Errorf("create replicator: %w", err)
		}
		rep.Start(ctx)
	}

	logger.Info("concert-kv ready",
		"version", concert.Version(),
		"tcp", srv.TCPAddr(),
		"unix", srv.UnixAddr(),
		"max_memory_bytes", memBytes,
		"max_conns", *maxConns,
		"auth_enabled", !password.IsZero(),
		"replica_of", *replicaOf,
	)

	<-ctx.Done()

	if rep != nil {
		rep.Close()
	}
	closeErr := srv.Close()
	if wal != nil {
		if cerr := wal.Compact(store); cerr != nil {
			logger.Warn("shutdown snapshot compaction failed", "error", cerr)
		}
	}
	return closeErr
}

// parseByteSize parses a positive byte size expressed either as a plain
// integer ("67108864") or with a binary/decimal unit suffix ("64MiB", "128MB",
// "512K", "1GiB").
//
// # Parameters
//
//   - raw: Size string to parse.
//
// # Returns
//
// Positive byte count or a parsing error.
//
// # Example
//
//	n, err := parseByteSize("64MiB") // 67108864, nil
func parseByteSize(raw string) (int64, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, errors.New("empty byte size")
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("invalid byte size %q", raw)
	}
	num, err := strconv.ParseInt(s[:i], 10, 64)
	if err != nil || num <= 0 {
		return 0, fmt.Errorf("invalid byte size %q", raw)
	}
	unit := strings.ToLower(strings.TrimSpace(s[i:]))
	var mult int64 = 1
	switch unit {
	case "", "b":
		mult = 1
	case "k", "kb":
		mult = 1000
	case "ki", "kib":
		mult = 1 << 10
	case "m", "mb":
		mult = 1000 * 1000
	case "mi", "mib":
		mult = 1 << 20
	case "g", "gb":
		mult = 1000 * 1000 * 1000
	case "gi", "gib":
		mult = 1 << 30
	default:
		return 0, fmt.Errorf("unknown byte size unit %q", unit)
	}
	if num > (1<<62)/mult {
		return 0, fmt.Errorf("byte size %q overflows int64", raw)
	}
	return num * mult, nil
}

// isLoopbackListen reports whether a host:port listen address targets a
// loopback interface (127.0.0.1, ::1, or localhost).
//
// # Parameters
//
//   - addr: TCP listen address passed to -listen.
//
// # Returns
//
// true if host resolves syntactically to loopback; false otherwise.
//
// # Example
//
//	if !isLoopbackListen("0.0.0.0:6380") { ... }
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
