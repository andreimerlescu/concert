package kv

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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Default server limits and connection deadlines (R2, R3).
const (
	DefaultMaxConns     = 1024
	DefaultReadTimeout  = 15 * time.Second
	DefaultWriteTimeout = 15 * time.Second
	DefaultIdleTimeout  = 5 * time.Minute
)

// ServerConfig configures a concert-kv RESP2 server listening on a Unix domain
// socket (0600) and/or TCP/TLS/mTLS endpoint.
type ServerConfig struct {
	ListenAddr     string
	UnixPath       string
	TLSConfig      *tls.Config
	Password       Secret
	MaxConns       int
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	HeartbeatEvery time.Duration
	ProtocolLimits ProtocolLimits
	Store          *Store
	WAL            *WAL
	Replication    *ReplicationLog
	Logger         *slog.Logger
}

// LoadServerTLSConfig loads a TLS 1.2+ server certificate and key, optionally
// enabling mutual TLS client certificate verification when clientCAFile is
// non-empty.
//
// # Parameters
//
//   - certFile: Path to PEM-encoded server certificate chain.
//   - keyFile: Path to PEM-encoded server private key.
//   - clientCAFile: Optional path to PEM-encoded CA bundle for mTLS verification.
//
// # Returns
//
// Configured *tls.Config enforcing MinVersion TLS 1.2, or an error.
//
// # Example
//
//	tlsCfg, err := kv.LoadServerTLSConfig("server.crt", "server.key", "ca.crt")
//	if err != nil {
//	    return err
//	}
//	_ = tlsCfg
func LoadServerTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("%w: both tls cert and key files are required", ErrInvalidArg)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server tls keypair: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if clientCAFile != "" {
		pemBytes, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read tls client CA %q: %w", clientCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("parse tls client CA %q: no valid certificates found", clientCAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// LoadClientTLSConfig builds a TLS 1.2+ client configuration for connecting to
// a TLS or mTLS concert-kv server. It never disables certificate verification.
//
// # Parameters
//
//   - caFile: Optional path to PEM-encoded root CA bundle; when empty, uses
//     system roots.
//   - certFile: Optional path to client certificate PEM for mTLS.
//   - keyFile: Optional path to client private key PEM for mTLS.
//   - serverName: Optional SNI / hostname override for certificate verification.
//
// # Returns
//
// Configured *tls.Config or an error.
//
// # Example
//
//	tlsCfg, err := kv.LoadClientTLSConfig("ca.crt", "client.crt", "client.key", "kv.internal")
//	if err != nil {
//	    return err
//	}
//	_ = tlsCfg
func LoadClientTLSConfig(caFile, certFile, keyFile, serverName string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read tls CA %q: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("parse tls CA %q: no valid certificates found", caFile)
		}
		cfg.RootCAs = pool
	}
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("%w: both client cert and key are required for mTLS", ErrInvalidArg)
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client tls keypair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// Server serves RESP2 KV, Pub/Sub, Concert queue (CQ.*), and replication
// commands over Unix sockets and/or TCP/TLS/mTLS. All active client goroutines
// are bounded by MaxConns and joined during Close (R2, R3).
type Server struct {
	cfg    ServerConfig
	store  *Store
	wal    *WAL
	repl   *ReplicationLog
	logger *slog.Logger

	// persistMu serializes WAL appends and ReplicationLog entries so both
	// observe strictly monotonic sequences without out-of-order gaps.
	persistMu  sync.Mutex
	persistSeq uint64

	connSem chan struct{}

	mu          sync.Mutex
	started     bool
	closed      bool
	tcpLn       net.Listener
	unixLn      net.Listener
	tcpAddr     string
	unixAddr    string
	connCtx     context.Context
	connCancel  context.CancelFunc
	wg          sync.WaitGroup
	activeConns atomic.Int64
	rejected    atomic.Int64
}

// NewServer validates cfg and constructs a stopped *Server. Call Start or
// Serve to bind listeners and accept connections.
//
// # Parameters
//
//   - cfg: Server configuration; at least one of ListenAddr or UnixPath must
//     be non-empty.
//
// # Returns
//
// A *Server ready to Start, or an error if cfg is invalid.
//
// # Example
//
//	srv, err := kv.NewServer(kv.ServerConfig{
//	    ListenAddr: "127.0.0.1:0",
//	    Store:      kv.NewStore(kv.StoreConfig{}),
//	})
//	if err != nil {
//	    return err
//	}
//	defer srv.Close()
func NewServer(cfg ServerConfig) (*Server, error) {
	if strings.TrimSpace(cfg.ListenAddr) == "" && strings.TrimSpace(cfg.UnixPath) == "" {
		return nil, fmt.Errorf("%w: at least one of ListenAddr or UnixPath must be set", ErrInvalidArg)
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = DefaultReadTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = DefaultWriteTimeout
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.HeartbeatEvery <= 0 {
		cfg.HeartbeatEvery = DefaultReplHeartbeat
	}
	if cfg.Store == nil {
		cfg.Store = NewStore(StoreConfig{})
	}
	if cfg.Replication == nil {
		cfg.Replication = NewReplicationLog(DefaultReplBacklogEntries, DefaultReplBacklogBytes)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.TLSConfig != nil {
		tlsCopy := cfg.TLSConfig.Clone()
		if tlsCopy.MinVersion < tls.VersionTLS12 {
			tlsCopy.MinVersion = tls.VersionTLS12
		}
		cfg.TLSConfig = tlsCopy
	}
	return &Server{
		cfg:        cfg,
		store:      cfg.Store,
		wal:        cfg.WAL,
		repl:       cfg.Replication,
		logger:     cfg.Logger,
		persistSeq: cfg.Store.MutationSeq(),
		connSem:    make(chan struct{}, cfg.MaxConns),
	}, nil
}

// Start binds configured TCP/TLS and/or Unix (0600) listeners and launches
// accept loops owned by s. Call Close to stop all listeners and join every
// active connection goroutine (R2).
//
// # Parameters
//
//   - ctx: Parent context whose cancellation tears down active connections.
//
// # Returns
//
// nil once listeners are bound and accepting, or a bind/permission error.
//
// # Example
//
//	if err := srv.Start(ctx); err != nil {
//	    return err
//	}
//	defer srv.Close()
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("kv server already started")
	}
	if s.closed {
		return errors.New("kv server already closed")
	}

	var tcpLn, unixLn net.Listener
	var err error

	if s.cfg.ListenAddr != "" {
		rawLn, listenErr := net.Listen("tcp", s.cfg.ListenAddr)
		if listenErr != nil {
			return fmt.Errorf("listen tcp %q: %w", s.cfg.ListenAddr, listenErr)
		}
		if s.cfg.TLSConfig != nil {
			tcpLn = tls.NewListener(rawLn, s.cfg.TLSConfig)
		} else {
			tcpLn = rawLn
		}
	}

	if s.cfg.UnixPath != "" {
		unixLn, err = listenUnix0600(s.cfg.UnixPath)
		if err != nil {
			if tcpLn != nil {
				_ = tcpLn.Close()
			}
			return err
		}
	}

	s.connCtx, s.connCancel = context.WithCancel(ctx)
	s.tcpLn = tcpLn
	s.unixLn = unixLn
	if tcpLn != nil {
		s.tcpAddr = tcpLn.Addr().String()
	}
	if unixLn != nil {
		s.unixAddr = s.cfg.UnixPath
	}
	s.started = true

	if tcpLn != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.acceptLoop(tcpLn)
		}()
	}
	if unixLn != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.acceptLoop(unixLn)
		}()
	}
	return nil
}

// Serve starts the server, blocks until ctx is cancelled, and then performs
// graceful shutdown via Close.
//
// # Parameters
//
//   - ctx: Lifecycle context; cancellation triggers graceful shutdown.
//
// # Returns
//
// Startup error if binding fails, or Close error after ctx is cancelled.
//
// # Example
//
//	if err := srv.Serve(ctx); err != nil {
//	    return err
//	}
func (s *Server) Serve(ctx context.Context) error {
	if err := s.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	return s.Close()
}

// Close stops all listeners, cancels active connection contexts (unblocking
// reads/writes immediately), waits for every connection goroutine to exit, and
// removes any Unix socket file created by Start. Safe to call multiple times.
//
// # Parameters
//
// None.
//
// # Returns
//
// First listener close error encountered, if any.
//
// # Example
//
//	if err := srv.Close(); err != nil {
//	    return err
//	}
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	tcpLn := s.tcpLn
	unixLn := s.unixLn
	unixPath := s.unixAddr
	cancel := s.connCancel
	s.mu.Unlock()

	var firstErr error
	if tcpLn != nil {
		if err := tcpLn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			firstErr = err
		}
	}
	if unixLn != nil {
		if err := unixLn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && firstErr == nil {
			firstErr = err
		}
	}
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()

	if unixPath != "" {
		_ = os.Remove(unixPath)
	}
	return firstErr
}

// TCPAddr returns the bound TCP address (useful when ListenAddr is ":0"), or
// empty string if TCP is disabled.
//
// # Parameters
//
// None.
//
// # Returns
//
// Bound "host:port" string or "".
//
// # Example
//
//	addr := srv.TCPAddr()
func (s *Server) TCPAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tcpAddr
}

// UnixAddr returns the bound Unix socket path, or empty string if Unix is
// disabled.
//
// # Parameters
//
// None.
//
// # Returns
//
// Unix socket filesystem path or "".
//
// # Example
//
//	sock := srv.UnixAddr()
func (s *Server) UnixAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unixAddr
}

// ActiveConns returns the current number of active client connections.
//
// # Parameters
//
// None.
//
// # Returns
//
// Current active connection count.
//
// # Example
//
//	n := srv.ActiveConns()
func (s *Server) ActiveConns() int64 {
	return s.activeConns.Load()
}

// RejectedConns returns the total number of connections rejected due to
// MaxConns saturation.
//
// # Parameters
//
// None.
//
// # Returns
//
// Cumulative rejected connection count.
//
// # Example
//
//	n := srv.RejectedConns()
func (s *Server) RejectedConns() int64 {
	return s.rejected.Load()
}

// listenUnix0600 removes any stale Unix socket at path, creates the parent
// directory (0700), binds a Unix listener, and restricts socket permissions to
// 0600 (S8).
//
// # Parameters
//
//   - path: Target Unix domain socket filesystem path.
//
// # Returns
//
// Bound net.Listener or an error if path exists as a non-socket or cannot bind.
//
// # Example
//
//	ln, err := listenUnix0600("/run/concert/kv.sock")
func listenUnix0600(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create unix socket dir %q: %w", dir, err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to overwrite non-socket file %q", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale unix socket %q: %w", path, err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen unix %q: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("chmod unix socket %q to 0600: %w", path, err)
	}
	return ln, nil
}

// acceptLoop accepts incoming connections on ln and dispatches each into a
// bounded handleConn goroutine until ln is closed.
//
// # Parameters
//
//   - ln: Active TCP/TLS or Unix listener.
//
// # Returns
//
// None.
//
// # Example
//
//	go s.acceptLoop(ln)
func (s *Server) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || s.connCtx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			s.logger.Warn("kv accept error", "error", err)
			return
		}

		// Enforce hard MaxConns ceiling before spawning a goroutine (R3).
		select {
		case s.connSem <- struct{}{}:
		default:
			s.rejected.Add(1)
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = conn.Write([]byte("-ERR max number of clients reached\r\n"))
			_ = conn.Close()
			continue
		}

		s.activeConns.Add(1)
		s.wg.Add(1)
		go func(c net.Conn) {
			defer func() {
				_ = c.Close()
				<-s.connSem
				s.activeConns.Add(-1)
				s.wg.Done()
			}()
			s.handleConn(c)
		}(conn)
	}
}

// handleConn serves one client connection from initial TLS handshake (if any)
// through AUTH, standard commands, Pub/Sub mode, or replication streaming.
//
// # Parameters
//
//   - conn: Accepted client connection; closed by caller when handleConn returns.
//
// # Returns
//
// None.
//
// # Example
//
//	s.handleConn(conn)
func (s *Server) handleConn(conn net.Conn) {
	// Ensure graceful server shutdown immediately unblocks any pending I/O.
	stopAbort := context.AfterFunc(s.connCtx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stopAbort()

	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.SetDeadline(time.Now().Add(s.cfg.ReadTimeout)); err != nil {
			return
		}
		if err := tlsConn.HandshakeContext(s.connCtx); err != nil {
			return
		}
	}

	br := bufio.NewReaderSize(conn, 16<<10)
	bw := bufio.NewWriterSize(conn, 16<<10)
	var writeMu sync.Mutex

	writeReply := func(v Value) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout)); err != nil {
			return err
		}
		if err := WriteValue(bw, v); err != nil {
			return err
		}
		return bw.Flush()
	}

	authed := s.cfg.Password.IsZero()
	var sub *Subscription
	var pubStop chan struct{}
	var pubWG sync.WaitGroup

	stopPubSub := func() {
		if sub != nil {
			sub.Close()
			sub = nil
		}
		if pubStop != nil {
			close(pubStop)
			pubWG.Wait()
			pubStop = nil
		}
	}
	defer stopPubSub()

	for {
		if s.connCtx.Err() != nil {
			return
		}
		if err := conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout)); err != nil {
			return
		}
		args, err := ReadCommand(br, s.cfg.ProtocolLimits)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || s.connCtx.Err() != nil {
				return
			}
			_ = writeReply(ErrorValue("ERR " + err.Error()))
			return
		}

		cmd := strings.ToUpper(args[0])

		// QUIT is always allowed even before AUTH or inside Pub/Sub mode.
		if cmd == "QUIT" {
			_ = writeReply(SimpleString("OK"))
			return
		}

		if cmd == "AUTH" {
			if len(args) != 2 {
				if err := writeReply(ErrorValue("ERR wrong number of arguments for 'AUTH' command")); err != nil {
					return
				}
				continue
			}
			if s.cfg.Password.IsZero() {
				authed = true
				if err := writeReply(SimpleString("OK")); err != nil {
					return
				}
				continue
			}
			if !s.cfg.Password.Equal(args[1]) {
				if err := writeReply(ErrorValue("WRONGPASS invalid username-password pair")); err != nil {
					return
				}
				continue
			}
			authed = true
			if err := writeReply(SimpleString("OK")); err != nil {
				return
			}
			continue
		}

		if !authed {
			if err := writeReply(ErrorValue("NOAUTH Authentication required.")); err != nil {
				return
			}
			continue
		}

		// Pub/Sub mode handling.
		if cmd == "SUBSCRIBE" {
			if len(args) < 2 {
				if err := writeReply(ErrorValue("ERR wrong number of arguments for 'SUBSCRIBE' command")); err != nil {
					return
				}
				continue
			}
			if sub == nil {
				created, err := s.store.Subscribe()
				if err != nil {
					if err := writeReply(ErrorValue(err.Error())); err != nil {
						return
					}
					continue
				}
				sub = created
				pubStop = make(chan struct{})
				curSub := sub
				curStop := pubStop
				pubWG.Add(1)
				go func() {
					defer pubWG.Done()
					s.pumpSubscription(conn, curSub, curStop, writeReply)
				}()
			}
			for _, ch := range args[1:] {
				n := s.store.AddChannels(sub, ch)
				ack := ArrayValue(BulkFromString("subscribe"), BulkFromString(ch), Integer(int64(n)))
				if err := writeReply(ack); err != nil {
					return
				}
			}
			continue
		}

		if cmd == "UNSUBSCRIBE" {
			if sub == nil {
				if len(args) == 1 {
					if err := writeReply(ArrayValue(BulkFromString("unsubscribe"), NullBulk(), Integer(0))); err != nil {
						return
					}
				} else {
					for _, ch := range args[1:] {
						if err := writeReply(ArrayValue(BulkFromString("unsubscribe"), BulkFromString(ch), Integer(0))); err != nil {
							return
						}
					}
				}
				continue
			}
			if len(args) == 1 {
				rem := sub.Unsubscribe()
				if err := writeReply(ArrayValue(BulkFromString("unsubscribe"), NullBulk(), Integer(int64(rem)))); err != nil {
					return
				}
				stopPubSub()
				continue
			}
			var rem int
			for _, ch := range args[1:] {
				rem = sub.Unsubscribe(ch)
				if err := writeReply(ArrayValue(BulkFromString("unsubscribe"), BulkFromString(ch), Integer(int64(rem)))); err != nil {
					return
				}
			}
			if rem == 0 {
				stopPubSub()
			}
			continue
		}

		if sub != nil {
			if cmd == "PING" {
				var resp Value
				if len(args) == 2 {
					resp = ArrayValue(BulkFromString("pong"), BulkFromString(args[1]))
				} else {
					resp = ArrayValue(BulkFromString("pong"), BulkFromString(""))
				}
				if err := writeReply(resp); err != nil {
					return
				}
				continue
			}
			if err := writeReply(ErrorValue("ERR only SUBSCRIBE / UNSUBSCRIBE / PING / QUIT allowed in subscribed mode")); err != nil {
				return
			}
			continue
		}

		// Replication streaming takeover.
		if cmd == "SYNC" || cmd == "REPL" {
			var sinceSeq uint64
			if len(args) == 2 {
				parsed, err := strconv.ParseUint(args[1], 10, 64)
				if err != nil {
					_ = writeReply(ErrorValue("ERR invalid replication sequence"))
					return
				}
				sinceSeq = parsed
			} else if len(args) > 2 {
				_ = writeReply(ErrorValue("ERR wrong number of arguments for 'REPL' command"))
				return
			}
			s.serveReplication(conn, bw, sinceSeq)
			return
		}

		reply, walArgs, _ := s.store.Execute(args)
		if len(walArgs) > 0 {
			if err := s.recordMutation(walArgs); err != nil {
				s.logger.Error("kv persist mutation failed", "command", cmd, "error", err)
				if werr := writeReply(ErrorValue("ERR persistence failure")); werr != nil {
					return
				}
				continue
			}
		}
		if err := writeReply(reply); err != nil {
			return
		}
	}
}

// recordMutation appends a committed mutation to the optional WAL and the
// ReplicationLog under persistMu so both observe strictly monotonic sequence
// numbers.
//
// # Parameters
//
//   - walArgs: Canonical command arguments returned by Store.Execute.
//
// # Returns
//
// Any WAL append error (replication append is in-memory and never fails).
//
// # Example
//
//	if err := s.recordMutation(walArgs); err != nil {
//	    return err
//	}
func (s *Server) recordMutation(walArgs []string) error {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	s.persistSeq++
	seq := s.persistSeq
	if s.wal != nil {
		if err := s.wal.Append(seq, walArgs); err != nil {
			return err
		}
	}
	s.repl.Append(seq, walArgs)
	return nil
}

// pumpSubscription forwards messages from sub.Messages() onto the client
// connection until stop closes, sub closes/evicts, or write fails.
//
// # Parameters
//
//   - conn: Client connection; closed if the subscriber is evicted as slow.
//   - sub: Active *Subscription owned by handleConn.
//   - stop: Signal channel closed when exiting Pub/Sub mode.
//   - writeReply: Thread-safe RESP2 writer callback.
//
// # Returns
//
// None.
//
// # Example
//
//	go s.pumpSubscription(conn, sub, stop, writeReply)
func (s *Server) pumpSubscription(conn net.Conn, sub *Subscription, stop <-chan struct{}, writeReply func(Value) error) {
	for {
		select {
		case <-stop:
			return
		case <-s.connCtx.Done():
			return
		case msg, ok := <-sub.Messages():
			if !ok {
				select {
				case <-sub.Evicted():
					_ = writeReply(ErrorValue("ERR slow pubsub consumer evicted"))
					_ = conn.SetDeadline(time.Now())
				default:
				}
				return
			}
			frame := ArrayValue(
				BulkFromString("message"),
				BulkFromString(msg.Channel),
				BulkString(msg.Payload),
			)
			if err := writeReply(frame); err != nil {
				_ = conn.SetDeadline(time.Now())
				return
			}
		}
	}
}

// serveReplication streams an initial snapshot (when required) followed by
// live replication operations and periodic heartbeats until disconnect or
// server shutdown.
//
// # Parameters
//
//   - conn: Client connection switched into replication streaming mode.
//   - bw: Buffered writer wrapping conn.
//   - sinceSeq: Last mutation sequence already applied by the replica (0 for fresh sync).
//
// # Returns
//
// None.
//
// # Example
//
//	s.serveReplication(conn, bw, 0)
func (s *Server) serveReplication(conn net.Conn, bw *bufio.Writer, sinceSeq uint64) {
	writeFrame := func(v Value) error {
		if err := conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout)); err != nil {
			return err
		}
		if err := WriteValue(bw, v); err != nil {
			return err
		}
		return bw.Flush()
	}

	sendSnapshot := func() (uint64, error) {
		s.persistMu.Lock()
		snap := s.store.Snapshot()
		if s.persistSeq > snap.Seq {
			snap.Seq = s.persistSeq
		}
		s.persistMu.Unlock()

		raw, err := EncodeSnapshot(snap)
		if err != nil {
			return 0, err
		}
		frame := ArrayValue(
			BulkFromString("REPL"),
			BulkFromString("SNAPSHOT"),
			Integer(int64(snap.Seq)),
			BulkString(raw),
		)
		if err := writeFrame(frame); err != nil {
			return 0, err
		}
		return snap.Seq, nil
	}

	s.persistMu.Lock()
	primarySeq := s.persistSeq
	if ms := s.store.MutationSeq(); ms > primarySeq {
		primarySeq = ms
	}
	s.persistMu.Unlock()

	cursor := sinceSeq
	// Send a full snapshot when the replica is fresh (cursor == 0), when its
	// cursor is ahead of this primary (e.g. primary restarted with fresh state),
	// or when the primary has pre-loaded store state with no delta backlog yet.
	_, _, _, replLast := s.repl.Stats()
	if cursor == 0 || cursor > primarySeq || (replLast == 0 && primarySeq > 0 && cursor != primarySeq) {
		seq, err := sendSnapshot()
		if err != nil {
			return
		}
		cursor = seq
	}

	heartbeat := time.NewTicker(s.cfg.HeartbeatEvery)
	defer heartbeat.Stop()

	for {
		if s.connCtx.Err() != nil {
			return
		}
		entries, needFull, waitCh := s.repl.ReadSince(cursor)
		if needFull {
			seq, err := sendSnapshot()
			if err != nil {
				return
			}
			cursor = seq
			continue
		}
		if len(entries) > 0 {
			for _, e := range entries {
				elems := make([]Value, 0, 3+len(e.Args))
				elems = append(elems,
					BulkFromString("REPL"),
					BulkFromString("OP"),
					Integer(int64(e.Seq)),
				)
				for _, a := range e.Args {
					elems = append(elems, BulkFromString(a))
				}
				if err := writeFrame(ArrayValue(elems...)); err != nil {
					return
				}
				cursor = e.Seq
			}
			continue
		}

		select {
		case <-s.connCtx.Done():
			return
		case <-waitCh:
		case <-heartbeat.C:
			ping := ArrayValue(
				BulkFromString("REPL"),
				BulkFromString("PING"),
				Integer(int64(cursor)),
			)
			if err := writeFrame(ping); err != nil {
				return
			}
		}
	}
}
