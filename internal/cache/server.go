package cache

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Server connection and timeout defaults.
const (
	DefaultMaxConns     = 512
	DefaultReadTimeout  = 5 * time.Second
	DefaultWriteTimeout = 5 * time.Second
	DefaultIdleTimeout  = 60 * time.Second
)

// ServerConfig configures a concert-cache daemon Server.
type ServerConfig struct {
	// Store is the backing sharded page cache. Required.
	Store *Store
	// Secret is the shared authentication credential required on every
	// connection. Must be non-zero (fail closed).
	Secret Secret
	// MaxConns caps simultaneous client connections. Values <= 0 default to
	// DefaultMaxConns.
	MaxConns int
	// MaxFrameBytes caps wire frame payload length. Values <= 0 default to
	// MaxFrameBytes.
	MaxFrameBytes int
	// ReadTimeout bounds the initial auth handshake and per-request context.
	// Values <= 0 default to DefaultReadTimeout.
	ReadTimeout time.Duration
	// WriteTimeout bounds writing each response frame. Values <= 0 default to
	// DefaultWriteTimeout.
	WriteTimeout time.Duration
	// IdleTimeout bounds idle wait between frames on an authenticated
	// connection. Values <= 0 default to DefaultIdleTimeout.
	IdleTimeout time.Duration
	// TLSConfig optionally enables TLS or mTLS on TCP listeners.
	TLSConfig *tls.Config
	// Logger receives structured boundary diagnostics. Defaults to slog.Default().
	Logger *slog.Logger
}

type trackedConn struct {
	conn net.Conn
	idle atomic.Bool
}

// Server serves the concert-cache binary protocol over Unix domain sockets or
// TCP/TLS/mTLS listeners with constant-time shared-secret authentication,
// bounded concurrency, strict deadlines, graceful shutdown, and Prometheus
// metrics.
type Server struct {
	store         *Store
	secret        Secret
	maxConns      int
	maxFrameBytes int
	readTimeout   time.Duration
	writeTimeout  time.Duration
	idleTimeout   time.Duration
	tlsConfig     *tls.Config
	logger        *slog.Logger

	connSem chan struct{}

	mu        sync.Mutex
	listeners map[net.Listener]struct{}
	conns     map[*trackedConn]struct{}

	baseCtx    context.Context
	baseCancel context.CancelFunc
	wg         sync.WaitGroup

	closing      atomic.Bool
	shutdownOnce sync.Once

	activeConns   atomic.Int64
	rejectedConns atomic.Int64
	authFailures  atomic.Int64
}

// NewServer validates cfg and constructs a ready-to-serve cache Server. It
// fails closed when cfg.Store is nil or cfg.Secret is zero.
//
// # Parameters
//
//   - cfg: Server configuration including backing Store and shared Secret.
//
// # Returns
//
// An initialized *Server or a configuration error (including ErrSecretNotSet).
//
// # Example
//
//	srv, err := cache.NewServer(cache.ServerConfig{
//	    Store:  store,
//	    Secret: secret,
//	})
//	if err != nil {
//	    return err
//	}
//	defer srv.Close()
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main.go:193 (function value)
//   - internal/cache/cache_test.go:521 (function value)
//   - internal/cache/cache_test.go:525 (function value)
//   - internal/cache/cache_test.go:662 (function value)
//   - internal/cache/cache_test.go:726 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("cache server requires a non-nil Store")
	}
	if cfg.Secret.IsZero() {
		return nil, ErrSecretNotSet
	}
	maxConns := cfg.MaxConns
	if maxConns <= 0 {
		maxConns = DefaultMaxConns
	}
	maxFrame := clampMaxFrame(cfg.MaxFrameBytes)
	readTO := cfg.ReadTimeout
	if readTO <= 0 {
		readTO = DefaultReadTimeout
	}
	writeTO := cfg.WriteTimeout
	if writeTO <= 0 {
		writeTO = DefaultWriteTimeout
	}
	idleTO := cfg.IdleTimeout
	if idleTO <= 0 {
		idleTO = DefaultIdleTimeout
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	var tlsCfg *tls.Config
	if cfg.TLSConfig != nil {
		tlsCfg = cfg.TLSConfig.Clone()
		if tlsCfg.MinVersion < tls.VersionTLS12 {
			tlsCfg.MinVersion = tls.VersionTLS12
		}
	}

	baseCtx, baseCancel := context.WithCancel(context.Background())
	return &Server{
		store:         cfg.Store,
		secret:        cfg.Secret,
		maxConns:      maxConns,
		maxFrameBytes: maxFrame,
		readTimeout:   readTO,
		writeTimeout:  writeTO,
		idleTimeout:   idleTO,
		tlsConfig:     tlsCfg,
		logger:        logger,
		connSem:       make(chan struct{}, maxConns),
		listeners:     make(map[net.Listener]struct{}),
		conns:         make(map[*trackedConn]struct{}),
		baseCtx:       baseCtx,
		baseCancel:    baseCancel,
	}, nil
}

// BuildServerTLSConfig loads server certificate/key files and optional client
// CA certificates for mutual TLS. Enforces TLS 1.2 minimum.
//
// # Parameters
//
//   - certFile: Path to PEM-encoded server certificate chain. Required.
//   - keyFile: Path to PEM-encoded server private key. Required.
//   - clientCAFile: Optional path to PEM-encoded client CA bundle; when
//     non-empty, mTLS client certificates are required and verified.
//
// # Returns
//
// Configured *tls.Config or an error if loading or parsing fails.
//
// # Example
//
//	tlsCfg, err := cache.BuildServerTLSConfig(certPath, keyPath, caPath)
//	if err != nil {
//	    return err
//	}
//	_ = tlsCfg
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main.go:180 (function value)
//   - internal/cache/cache_test.go:654 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func BuildServerTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("TLS requires both cert and key files")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS keypair: %w", err)
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if clientCAFile != "" {
		caPEM, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA %q: %w", clientCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse client CA %q: no valid PEM certificates", clientCAFile)
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsCfg, nil
}

// ListenAndServeTCP binds addr on TCP (wrapped with TLS/mTLS when configured)
// and serves until Shutdown or Close is called.
//
// # Parameters
//
//   - addr: TCP host:port address (for example "127.0.0.1:6390").
//
// # Returns
//
// nil on clean shutdown, or a bind/accept error.
//
// # Example
//
//	if err := srv.ListenAndServeTCP("127.0.0.1:6390"); err != nil {
//	    return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main.go:236 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Server) ListenAndServeTCP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen tcp %q: %w", addr, err)
	}
	if s.tlsConfig != nil {
		ln = tls.NewListener(ln, s.tlsConfig)
	}
	return s.Serve(ln)
}

// ListenAndServeUnix binds a Unix domain socket at socketPath with mode 0600
// and serves until Shutdown or Close is called. Any pre-existing stale socket
// file at socketPath is removed before binding; non-socket files are refused.
//
// # Parameters
//
//   - socketPath: Filesystem path for the Unix domain socket. Must be non-empty.
//
// # Returns
//
// nil on clean shutdown, or an error if binding or chmod fails.
//
// # Example
//
//	if err := srv.ListenAndServeUnix("/run/concert-cache.sock"); err != nil {
//	    return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main.go:245 (function value)
//   - internal/cache/cache_test.go:544 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Server) ListenAndServeUnix(socketPath string) error {
	if strings.TrimSpace(socketPath) == "" {
		return errors.New("unix socket path must not be empty")
	}
	if fi, err := os.Lstat(socketPath); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to overwrite non-socket file %q", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return fmt.Errorf("remove stale unix socket %q: %w", socketPath, err)
		}
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen unix %q: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(socketPath)
		return fmt.Errorf("chmod 0600 unix socket %q: %w", socketPath, err)
	}
	defer func() {
		// Best-effort cleanup of the socket path after listener closes.
		_ = os.Remove(socketPath)
	}()
	return s.Serve(ln)
}

// Serve accepts connections on ln until Shutdown or Close is called. Multiple
// listeners (for example Unix + TCP) may be served concurrently by one Server.
//
// # Parameters
//
//   - ln: Active network listener owned by Serve until return. Must be non-nil.
//
// # Returns
//
// nil when stopped via Shutdown/Close, ErrClosed if Server is already shutting
// down, or a fatal accept error.
//
// # Example
//
//	ln, err := net.Listen("tcp", "127.0.0.1:0")
//	if err != nil {
//	    return err
//	}
//	return srv.Serve(ln)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:676 (function value)
//   - internal/cache/cache_test.go:742 (function value)
//   - internal/cache/server.go:279 (function value)
//   - internal/cache/server.go:335 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Server) Serve(ln net.Listener) error {
	if ln == nil {
		return errors.New("listener must not be nil")
	}
	s.mu.Lock()
	if s.closing.Load() {
		s.mu.Unlock()
		_ = ln.Close()
		return ErrClosed
	}
	s.listeners[ln] = struct{}{}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.listeners, ln)
		s.mu.Unlock()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.closing.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}

		// Bound simultaneous connections without spawning excess goroutines.
		select {
		case s.connSem <- struct{}{}:
		default:
			s.rejectedConns.Add(1)
			_ = conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
			_ = WriteFrame(conn, RespErr, 0, EncodeError(ErrCodeTooManyConns, "max connections reached"), s.maxFrameBytes)
			_ = conn.Close()
			continue
		}

		tc := &trackedConn{conn: conn}
		s.mu.Lock()
		if s.closing.Load() {
			s.mu.Unlock()
			<-s.connSem
			_ = conn.Close()
			return nil
		}
		s.conns[tc] = struct{}{}
		s.mu.Unlock()

		s.activeConns.Add(1)
		s.wg.Go(func() {
			defer func() {
				s.mu.Lock()
				delete(s.conns, tc)
				s.mu.Unlock()
				_ = conn.Close()
				s.activeConns.Add(-1)
				<-s.connSem
			}()
			s.handleConn(tc)
		})
	}
}

// Shutdown stops accepting new connections, unblocks idle connections, and
// waits for in-flight requests to complete until ctx expires, force-closing
// any stragglers before returning so all handler goroutines are joined.
// Shutdown is idempotent.
//
// # Parameters
//
//   - ctx: Controls the graceful drain deadline. Must be non-nil.
//
// # Returns
//
// nil if all connections drained within ctx, or ctx.Err() if force-close was
// required after timeout.
//
// # Example
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//	return srv.Shutdown(ctx)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main.go:275 (function value)
//   - internal/cache/cache_test.go:641 (function value)
//   - internal/cache/cache_test.go:807 (function value)
//   - internal/cache/server.go:536 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdownOnce.Do(func() {
		s.closing.Store(true)
		s.baseCancel()

		s.mu.Lock()
		for ln := range s.listeners {
			_ = ln.Close()
		}
		// Immediately interrupt idle connections waiting for their next frame
		// while allowing in-flight requests to finish cleanly.
		now := time.Now()
		for tc := range s.conns {
			if tc.idle.Load() {
				_ = tc.conn.SetReadDeadline(now)
			}
		}
		s.mu.Unlock()
	})

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		// Force-close remaining connections and wait for goroutines to join.
		s.mu.Lock()
		for tc := range s.conns {
			_ = tc.conn.Close()
		}
		s.mu.Unlock()
		<-done
		return ctx.Err()
	}
}

// Close immediately stops accepting connections, closes all active connections,
// and waits for all handler goroutines to exit. Close is idempotent.
//
// # Parameters
//
// None.
//
// # Returns
//
// Always nil.
//
// # Example
//
//	_ = srv.Close()
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:678 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Server) Close() error {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = s.Shutdown(ctx)
	return nil
}

// MetricsHandler returns an http.Handler serving Prometheus exposition metrics
// at /_cache/metrics and liveness/readiness status at /_cache/healthz.
//
// # Parameters
//
// None.
//
// # Returns
//
// An http.Handler safe for concurrent HTTP requests.
//
// # Example
//
//	mux := srv.MetricsHandler()
//	_ = mux
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main.go:218 (function value)
//   - internal/cache/cache_test.go:777 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/_cache/healthz", s.handleHealthz)
	mux.HandleFunc("/_cache/metrics", s.handleMetrics)
	return mux
}

// handleHealthz responds 200 OK while the server is active and 503 Service
// Unavailable once shutting down.
//
// # Parameters
//
//   - w: HTTP response writer.
//   - r: Incoming HTTP request.
//
// # Returns
//
// None.
//
// # Example
//
//	// Invoked by net/http via Server.MetricsHandler.
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/server.go:568 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if s.closing.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, "shutting down\n")
		}
		return
	}
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, "ok\n")
	}
}

// handleMetrics writes Prometheus text-format metrics for store and server
// health counters without exposing any secrets or cache contents.
//
// # Parameters
//
//   - w: HTTP response writer.
//   - r: Incoming HTTP request.
//
// # Returns
//
// None.
//
// # Example
//
//	// Invoked by net/http via Server.MetricsHandler.
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/server.go:569 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	st, err := s.store.Stats(r.Context())
	if err != nil {
		http.Error(w, "stats unavailable", http.StatusServiceUnavailable)
		return
	}

	var b strings.Builder
	b.Grow(1024)
	writePromMetric(&b, "concert_cache_entries", "gauge", "Current number of entries stored in concert-cache.", st.Entries)
	writePromMetric(&b, "concert_cache_used_bytes", "gauge", "Current memory footprint in bytes of stored entries.", st.UsedBytes)
	writePromMetric(&b, "concert_cache_max_bytes", "gauge", "Configured memory ceiling in bytes.", st.MaxBytes)
	writePromMetric(&b, "concert_cache_tags", "gauge", "Current number of active shard tag buckets.", st.Tags)
	writePromMetric(&b, "concert_cache_hits_total", "counter", "Total cache hits served.", st.Hits)
	writePromMetric(&b, "concert_cache_misses_total", "counter", "Total cache misses observed.", st.Misses)
	writePromMetric(&b, "concert_cache_evictions_total", "counter", "Total LRU evictions triggered by byte ceiling.", st.Evictions)
	writePromMetric(&b, "concert_cache_purges_total", "counter", "Total entries removed by explicit purge commands.", st.Purges)
	writePromMetric(&b, "concert_cache_coalesced_total", "counter", "Total singleflight coalesced lookups.", st.Coalesced)
	writePromMetric(&b, "concert_cache_active_conns", "gauge", "Currently open client connections.", s.activeConns.Load())
	writePromMetric(&b, "concert_cache_rejected_conns_total", "counter", "Connections rejected due to max-conns limit.", s.rejectedConns.Load())
	writePromMetric(&b, "concert_cache_auth_failures_total", "counter", "Failed authentication attempts.", s.authFailures.Load())

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, b.String())
	}
}

// writePromMetric appends a single Prometheus HELP/TYPE/value metric stanza.
//
// # Parameters
//
//   - b: Destination string builder.
//   - name: Metric identifier.
//   - kind: Prometheus metric type ("gauge" or "counter").
//   - help: Human-readable metric description.
//   - val: Integer metric value.
//
// # Returns
//
// None.
//
// # Example
//
//	var b strings.Builder
//	writePromMetric(&b, "concert_cache_entries", "gauge", "Entries", 10)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/server.go:655 (function value)
//   - internal/cache/server.go:656 (function value)
//   - internal/cache/server.go:657 (function value)
//   - internal/cache/server.go:658 (function value)
//   - internal/cache/server.go:659 (function value)
//   - internal/cache/server.go:660 (function value)
//   - internal/cache/server.go:661 (function value)
//   - internal/cache/server.go:662 (function value)
//   - internal/cache/server.go:663 (function value)
//   - internal/cache/server.go:664 (function value)
//   - internal/cache/server.go:665 (function value)
//   - internal/cache/server.go:666 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func writePromMetric(b *strings.Builder, name, kind, help string, val int64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", name, help, name, kind, name, val)
}

// handleConn runs the authentication handshake and command loop for one client
// connection until EOF, error, auth failure, or server shutdown.
//
// # Parameters
//
//   - tc: Tracked client connection owned by this goroutine until return.
//
// # Returns
//
// None.
//
// # Example
//
//	// Invoked per accepted connection inside Server.Serve.
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/server.go:431 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Server) handleConn(tc *trackedConn) {
	conn := tc.conn
	br := bufio.NewReaderSize(conn, 16<<10)
	bw := bufio.NewWriterSize(conn, 16<<10)

	// Step 1: Mandatory constant-time shared-secret authentication handshake.
	_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	authFrame, err := ReadFrame(br, maxAuthPayloadBytes)
	if err != nil {
		if errors.Is(err, ErrFrameTooLarge) || errors.Is(err, ErrProtocol) {
			_ = s.writeResp(conn, bw, RespErr, EncodeError(ErrCodeUnauthorized, "invalid auth frame"))
		}
		return
	}
	if authFrame.Op != OpAuth || !s.secret.Equal(authFrame.Payload) {
		s.authFailures.Add(1)
		_ = s.writeResp(conn, bw, RespErr, EncodeError(ErrCodeUnauthorized, "unauthorized"))
		return
	}
	if err := s.writeResp(conn, bw, RespOK, nil); err != nil {
		return
	}

	// Step 2: Authenticated command loop.
	for {
		if s.closing.Load() {
			return
		}
		tc.idle.Store(true)
		_ = conn.SetReadDeadline(time.Now().Add(s.idleTimeout))
		fr, err := ReadFrame(br, s.maxFrameBytes)
		tc.idle.Store(false)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || s.closing.Load() {
				return
			}
			if errors.Is(err, ErrFrameTooLarge) {
				_ = s.writeResp(conn, bw, RespErr, EncodeError(ErrCodeTooLarge, "frame too large"))
			} else if errors.Is(err, ErrProtocol) {
				_ = s.writeResp(conn, bw, RespErr, EncodeError(ErrCodeBadRequest, "protocol error"))
			}
			return
		}

		respOp, respPayload := s.dispatch(fr)
		if err := s.writeResp(conn, bw, respOp, respPayload); err != nil {
			return
		}
	}
}

// dispatch executes one authenticated protocol frame against s.store and
// returns the response opcode and payload.
//
// # Parameters
//
//   - fr: Validated incoming request frame.
//
// # Returns
//
// (respOp, respPayload).
//
// # Example
//
//	op, payload := s.dispatch(frame)
//	_, _ = op, payload
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/server.go:786 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Server) dispatch(fr Frame) (byte, []byte) {
	ctx, cancel := context.WithTimeout(s.baseCtx, s.readTimeout)
	defer cancel()

	switch fr.Op {
	case OpAuth:
		if !s.secret.Equal(fr.Payload) {
			s.authFailures.Add(1)
			return RespErr, EncodeError(ErrCodeUnauthorized, "unauthorized")
		}
		return RespOK, nil

	case OpPing:
		if len(fr.Payload) != 0 {
			return RespErr, EncodeError(ErrCodeBadRequest, "ping takes no payload")
		}
		return RespOK, nil

	case OpGet:
		if len(fr.Payload) == 0 || len(fr.Payload) > MaxKeyBytes {
			return RespErr, EncodeError(ErrCodeBadRequest, "invalid key")
		}
		ent, ok, err := s.store.Get(ctx, string(fr.Payload))
		if err != nil {
			return mapStoreError(err)
		}
		if !ok {
			return RespMiss, nil
		}
		raw, err := EncodeEntry(ent)
		if err != nil {
			return RespErr, EncodeError(ErrCodeInternal, "encode entry failed")
		}
		return RespHit, raw

	case OpPut:
		ent, err := DecodeEntry(fr.Payload, int(s.store.maxEntryBytes))
		if err != nil {
			return mapStoreError(err)
		}
		if err := s.store.Put(ctx, ent); err != nil {
			return mapStoreError(err)
		}
		return RespOK, nil

	case OpPurgeURL:
		host, path, err := DecodePurgePair(fr.Payload)
		if err != nil {
			return mapStoreError(err)
		}
		n, err := s.store.PurgeURL(ctx, host, path)
		if err != nil {
			return mapStoreError(err)
		}
		return RespOK, EncodeUint64(uint64(n))

	case OpPurgePrefix:
		host, prefix, err := DecodePurgePair(fr.Payload)
		if err != nil {
			return mapStoreError(err)
		}
		n, err := s.store.PurgePrefix(ctx, host, prefix)
		if err != nil {
			return mapStoreError(err)
		}
		return RespOK, EncodeUint64(uint64(n))

	case OpPurgeTag:
		if len(fr.Payload) > MaxTagBytes {
			return RespErr, EncodeError(ErrCodeBadRequest, "invalid tag")
		}
		n, err := s.store.PurgeTag(ctx, string(fr.Payload))
		if err != nil {
			return mapStoreError(err)
		}
		return RespOK, EncodeUint64(uint64(n))

	case OpPurgeAll:
		if len(fr.Payload) != 0 {
			return RespErr, EncodeError(ErrCodeBadRequest, "purge-all takes no payload")
		}
		n, err := s.store.PurgeAll(ctx)
		if err != nil {
			return mapStoreError(err)
		}
		return RespOK, EncodeUint64(uint64(n))

	case OpStats:
		if len(fr.Payload) != 0 {
			return RespErr, EncodeError(ErrCodeBadRequest, "stats takes no payload")
		}
		st, err := s.store.Stats(ctx)
		if err != nil {
			return mapStoreError(err)
		}
		return RespOK, EncodeStats(st)

	default:
		return RespErr, EncodeError(ErrCodeBadRequest, "unknown opcode")
	}
}

// writeResp writes and flushes a response frame under s.writeTimeout.
//
// # Parameters
//
//   - conn: Underlying client connection.
//   - bw: Buffered writer wrapping conn.
//   - op: Response opcode.
//   - payload: Response payload bytes.
//
// # Returns
//
// Write or flush error, or nil on success.
//
// # Example
//
//	err := s.writeResp(conn, bw, RespOK, nil)
//	_ = err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/server.go:752 (function value)
//   - internal/cache/server.go:758 (function value)
//   - internal/cache/server.go:761 (function value)
//   - internal/cache/server.go:779 (function value)
//   - internal/cache/server.go:781 (function value)
//   - internal/cache/server.go:787 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s *Server) writeResp(conn net.Conn, bw *bufio.Writer, op byte, payload []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(s.writeTimeout)); err != nil {
		return err
	}
	if err := WriteFrame(bw, op, 0, payload, s.maxFrameBytes); err != nil {
		return err
	}
	return bw.Flush()
}

// mapStoreError translates store/codec errors into bounded wire error frames.
//
// # Parameters
//
//   - err: Non-nil error returned by store or decoder.
//
// # Returns
//
// (RespErr, encodedErrorPayload).
//
// # Example
//
//	op, payload := mapStoreError(err)
//	_, _ = op, payload
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/server.go:842 (function value)
//   - internal/cache/server.go:856 (function value)
//   - internal/cache/server.go:859 (function value)
//   - internal/cache/server.go:866 (function value)
//   - internal/cache/server.go:870 (function value)
//   - internal/cache/server.go:877 (function value)
//   - internal/cache/server.go:881 (function value)
//   - internal/cache/server.go:891 (function value)
//   - internal/cache/server.go:901 (function value)
//   - internal/cache/server.go:911 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func mapStoreError(err error) (byte, []byte) {
	switch {
	case errors.Is(err, ErrEntryTooLarge), errors.Is(err, ErrFrameTooLarge):
		return RespErr, EncodeError(ErrCodeTooLarge, "entry too large")
	case errors.Is(err, ErrInvalidKey), errors.Is(err, ErrInvalidTag),
		errors.Is(err, ErrTooManyTags), errors.Is(err, ErrInvalidTTL),
		errors.Is(err, ErrProtocol):
		return RespErr, EncodeError(ErrCodeBadRequest, err.Error())
	case errors.Is(err, ErrUnauthorized):
		return RespErr, EncodeError(ErrCodeUnauthorized, "unauthorized")
	default:
		return RespErr, EncodeError(ErrCodeInternal, "internal cache error")
	}
}
