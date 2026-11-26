package cache

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Client connection pool and timeout defaults.
const (
	DefaultDialTimeout    = 1 * time.Second
	DefaultRequestTimeout = 2 * time.Second
	DefaultMaxIdleConns   = 8
)

// ClientConfig configures a pooled concert-cache network Client.
type ClientConfig struct {
	// Network is "tcp" or "unix". When empty, addresses starting with "/" or
	// "unix://" select "unix" and all others select "tcp".
	Network string
	// Address is the target daemon address (host:port or Unix socket path).
	// Required.
	Address string
	// Secret is the shared authentication credential presented on connection
	// establishment. Required (fail closed).
	Secret Secret
	// TLSConfig optionally enables TLS or mTLS for TCP connections.
	TLSConfig *tls.Config
	// DialTimeout bounds TCP/Unix dial and TLS handshake duration. Defaults to
	// DefaultDialTimeout.
	DialTimeout time.Duration
	// RequestTimeout bounds a single RPC round-trip when ctx has no earlier
	// deadline. Defaults to DefaultRequestTimeout.
	RequestTimeout time.Duration
	// MaxIdleConns caps pooled authenticated connections. Defaults to
	// DefaultMaxIdleConns.
	MaxIdleConns int
	// MaxFrameBytes caps wire frame payload length. Defaults to MaxFrameBytes.
	MaxFrameBytes int
	// FailClosed disables fail-open behavior on Get and Put when set to true.
	// By default (false), daemon transport outages cause Get to return a clean
	// miss and Put to return nil while incrementing Errors() and calling
	// OnError so a cache outage never breaks Concert page serving.
	FailClosed bool
	// OnError is an optional hook invoked on transport/protocol errors when
	// fail-open suppresses the returned error.
	OnError func(error)
}

type pooledConn struct {
	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer
}

// Close closes the underlying network connection.
//
// # Parameters
//
// None.
//
// # Returns
//
// The underlying net.Conn.Close error.
//
// # Example
//
//	_ = pc.Close()
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:624 (function value)
//   - internal/cache/client.go:724 (function value)
//   - internal/cache/client.go:734 (function value)
//   - internal/cache/client.go:907 (function value)
//   - internal/cache/client.go:911 (function value)
//   - internal/cache/client.go:944 (function value)
//   - internal/cache/client.go:953 (function value)
//   - internal/cache/client.go:958 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (pc *pooledConn) Close() error {
	if pc == nil || pc.conn == nil {
		return nil
	}
	return pc.conn.Close()
}

// Client is a pure-stdlib, concurrency-safe, connection-pooled client for the
// concert-cache daemon implementing PageCache. By default Get and Put fail open
// on daemon outages so page serving continues uninterrupted.
type Client struct {
	network        string
	address        string
	secret         Secret
	tlsConfig      *tls.Config
	dialTimeout    time.Duration
	requestTimeout time.Duration
	maxFrameBytes  int
	failClosed     bool
	onError        func(error)

	pool      chan *pooledConn
	errCount  atomic.Int64
	closed    atomic.Bool
	closeOnce sync.Once
}

var _ PageCache = (*Client)(nil)

// NewClient validates cfg and creates a pooled Client. Connections are dialed
// and authenticated lazily on first use.
//
// # Parameters
//
//   - cfg: Connection, authentication, timeout, and fail-open configuration.
//
// # Returns
//
// A configured *Client or an error if Address is empty or Secret is zero.
//
// # Example
//
//	cli, err := cache.NewClient(cache.ClientConfig{
//	    Network: "unix",
//	    Address: "/run/concert-cache.sock",
//	    Secret:  secret,
//	})
//	if err != nil {
//	    return err
//	}
//	defer cli.Close()
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main_test.go:93 (function value)
//   - internal/cache/cache_test.go:547 (function value)
//   - internal/cache/cache_test.go:574 (function value)
//   - internal/cache/cache_test.go:683 (function value)
//   - internal/cache/cache_test.go:704 (function value)
//   - internal/cache/cache_test.go:830 (function value)
//   - internal/cache/cache_test.go:863 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func NewClient(cfg ClientConfig) (*Client, error) {
	addr := strings.TrimSpace(cfg.Address)
	if addr == "" {
		return nil, errors.New("cache client requires a non-empty Address")
	}
	if cfg.Secret.IsZero() {
		return nil, ErrSecretNotSet
	}

	network := strings.TrimSpace(cfg.Network)
	if after, ok := strings.CutPrefix(addr, "unix://"); ok {
		network = "unix"
		addr = after
	}
	if network == "" {
		if strings.HasPrefix(addr, "/") {
			network = "unix"
		} else {
			network = "tcp"
		}
	}
	if network != "tcp" && network != "unix" {
		return nil, fmt.Errorf("unsupported cache network %q", network)
	}

	dialTO := cfg.DialTimeout
	if dialTO <= 0 {
		dialTO = DefaultDialTimeout
	}
	reqTO := cfg.RequestTimeout
	if reqTO <= 0 {
		reqTO = DefaultRequestTimeout
	}
	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = DefaultMaxIdleConns
	}

	var tlsCfg *tls.Config
	if cfg.TLSConfig != nil {
		tlsCfg = cfg.TLSConfig.Clone()
		if tlsCfg.MinVersion < tls.VersionTLS12 {
			tlsCfg.MinVersion = tls.VersionTLS12
		}
	}

	return &Client{
		network:        network,
		address:        addr,
		secret:         cfg.Secret,
		tlsConfig:      tlsCfg,
		dialTimeout:    dialTO,
		requestTimeout: reqTO,
		maxFrameBytes:  clampMaxFrame(cfg.MaxFrameBytes),
		failClosed:     cfg.FailClosed,
		onError:        cfg.OnError,
		pool:           make(chan *pooledConn, maxIdle),
	}, nil
}

// Ping verifies daemon reachability and authentication. Ping always returns
// real errors and never fails open.
//
// # Parameters
//
//   - ctx: Controls cancellation and request deadline. Must be non-nil.
//
// # Returns
//
// nil on success, or an authentication, timeout, or transport error.
//
// # Example
//
//	if err := cli.Ping(ctx); err != nil {
//	    return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main_test.go:109 (function value)
//   - internal/cache/cache_test.go:584 (function value)
//   - internal/cache/cache_test.go:694 (function value)
//   - internal/cache/cache_test.go:715 (function value)
//   - internal/cache/cache_test.go:855 (function value)
//   - internal/cache/cache_test.go:918 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) Ping(ctx context.Context) error {
	fr, err := c.roundTrip(ctx, OpPing, nil)
	if err != nil {
		return err
	}
	if fr.Op != RespOK {
		return fmt.Errorf("%w: unexpected ping opcode 0x%02x", ErrProtocol, fr.Op)
	}
	return nil
}

// Get fetches a cached entry from the remote daemon. When FailClosed is false
// (the default), daemon transport outages return (Entry{}, false, nil) and
// increment Errors() so callers fall back to origin cleanly.
//
// # Parameters
//
//   - ctx: Controls cancellation and request deadline. Must be non-nil.
//   - key: Non-empty cache key (<= MaxKeyBytes).
//
// # Returns
//
// (entry, true, nil) on hit, (Entry{}, false, nil) on miss (or fail-open
// outage), or an error on validation/auth/cancellation failure (or outage when
// FailClosed is true).
//
// # Example
//
//	ent, ok, err := cli.Get(ctx, key)
//	_, _, _ = ent, ok, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main_test.go:130 (function value)
//   - internal/cache/cache_test.go:612 (function value)
//   - internal/cache/cache_test.go:620 (function value)
//   - internal/cache/cache_test.go:844 (function value)
//   - internal/cache/cache_test.go:875 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) Get(ctx context.Context, key string) (Entry, bool, error) {
	if c.closed.Load() {
		return Entry{}, false, ErrClosed
	}
	if key == "" || len(key) > MaxKeyBytes {
		return Entry{}, false, ErrInvalidKey
	}
	fr, err := c.roundTrip(ctx, OpGet, []byte(key))
	if err != nil {
		if c.shouldFailOpen(ctx, err) {
			c.recordError(err)
			return Entry{}, false, nil
		}
		return Entry{}, false, err
	}
	switch fr.Op {
	case RespMiss:
		return Entry{}, false, nil
	case RespHit:
		ent, decErr := DecodeEntry(fr.Payload, c.maxFrameBytes)
		if decErr != nil {
			if c.shouldFailOpen(ctx, decErr) {
				c.recordError(decErr)
				return Entry{}, false, nil
			}
			return Entry{}, false, decErr
		}
		return ent, true, nil
	default:
		protoErr := fmt.Errorf("%w: unexpected get opcode 0x%02x", ErrProtocol, fr.Op)
		if c.shouldFailOpen(ctx, protoErr) {
			c.recordError(protoErr)
			return Entry{}, false, nil
		}
		return Entry{}, false, protoErr
	}
}

// Put writes entry to the remote daemon. When FailClosed is false (the
// default), daemon transport outages return nil and increment Errors() so
// response serving is never blocked.
//
// # Parameters
//
//   - ctx: Controls cancellation and request deadline. Must be non-nil.
//   - entry: Entry to encode and store.
//
// # Returns
//
// nil on success (or fail-open outage), or a validation, auth, cancellation,
// or transport error.
//
// # Example
//
//	err := cli.Put(ctx, entry)
//	_ = err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main_test.go:122 (function value)
//   - internal/cache/cache_test.go:602 (function value)
//   - internal/cache/cache_test.go:625 (function value)
//   - internal/cache/cache_test.go:626 (function value)
//   - internal/cache/cache_test.go:847 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) Put(ctx context.Context, entry Entry) error {
	if c.closed.Load() {
		return ErrClosed
	}
	payload, err := EncodeEntry(entry)
	if err != nil {
		return err
	}
	fr, err := c.roundTrip(ctx, OpPut, payload)
	if err != nil {
		if c.shouldFailOpen(ctx, err) {
			c.recordError(err)
			return nil
		}
		return err
	}
	if fr.Op != RespOK {
		protoErr := fmt.Errorf("%w: unexpected put opcode 0x%02x", ErrProtocol, fr.Op)
		if c.shouldFailOpen(ctx, protoErr) {
			c.recordError(protoErr)
			return nil
		}
		return protoErr
	}
	return nil
}

// PurgeURL removes all cached variants for (host, path) on the remote daemon.
// Always returns transport or protocol errors so callers know whether the purge
// succeeded.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadline. Must be non-nil.
//   - host: Optional host filter. Empty matches any host.
//   - path: Exact path to purge.
//
// # Returns
//
// Removed entry count and any error.
//
// # Example
//
//	n, err := cli.PurgeURL(ctx, "shop.example.com", "/product/tee/")
//	_, _ = n, err
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
func (c *Client) PurgeURL(ctx context.Context, host, path string) (int, error) {
	payload, err := EncodePurgePair(host, path)
	if err != nil {
		return 0, err
	}
	return c.purgeOp(ctx, OpPurgeURL, payload)
}

// PurgePrefix removes all cached entries matching (host, prefix) on the remote
// daemon.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadline. Must be non-nil.
//   - host: Optional host filter. Empty matches any host.
//   - prefix: Required path prefix.
//
// # Returns
//
// Removed entry count and any error.
//
// # Example
//
//	n, err := cli.PurgePrefix(ctx, "shop.example.com", "/product/")
//	_, _ = n, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:627 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) PurgePrefix(ctx context.Context, host, prefix string) (int, error) {
	payload, err := EncodePurgePair(host, prefix)
	if err != nil {
		return 0, err
	}
	return c.purgeOp(ctx, OpPurgePrefix, payload)
}

// PurgeTag removes all cached entries tagged with tag on the remote daemon.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadline. Must be non-nil.
//   - tag: Surrogate tag (<= MaxTagBytes).
//
// # Returns
//
// Removed entry count and any error.
//
// # Example
//
//	n, err := cli.PurgeTag(ctx, "product:42")
//	_, _ = n, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:616 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) PurgeTag(ctx context.Context, tag string) (int, error) {
	if len(tag) > MaxTagBytes {
		return 0, ErrInvalidTag
	}
	return c.purgeOp(ctx, OpPurgeTag, []byte(tag))
}

// PurgeAll clears every entry stored in the remote daemon.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadline. Must be non-nil.
//
// # Returns
//
// Removed entry count and any error.
//
// # Example
//
//	n, err := cli.PurgeAll(ctx)
//	_, _ = n, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:858 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) PurgeAll(ctx context.Context) (int, error) {
	return c.purgeOp(ctx, OpPurgeAll, nil)
}

// Stats retrieves a live Stats snapshot from the remote daemon.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadline. Must be non-nil.
//
// # Returns
//
// Remote Stats snapshot and any error.
//
// # Example
//
//	st, err := cli.Stats(ctx)
//	_, _ = st, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:631 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) Stats(ctx context.Context) (Stats, error) {
	fr, err := c.roundTrip(ctx, OpStats, nil)
	if err != nil {
		return Stats{}, err
	}
	if fr.Op != RespOK {
		return Stats{}, fmt.Errorf("%w: unexpected stats opcode 0x%02x", ErrProtocol, fr.Op)
	}
	return DecodeStats(fr.Payload)
}

// Errors reports the cumulative number of daemon transport or protocol errors
// observed (including errors absorbed in fail-open mode).
//
// # Parameters
//
// None.
//
// # Returns
//
// Total observed error count.
//
// # Example
//
//	n := cli.Errors()
//	_ = n
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:850 (function value)
//   - internal/cache/cache_test.go:851 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) Errors() int64 {
	return c.errCount.Load()
}

// Close marks the client closed and closes all idle pooled connections. Close
// is idempotent.
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
//	_ = cli.Close()
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main_test.go:102 (function value)
//   - internal/cache/cache_test.go:559 (function value)
//   - internal/cache/cache_test.go:583 (function value)
//   - internal/cache/cache_test.go:693 (function value)
//   - internal/cache/cache_test.go:714 (function value)
//   - internal/cache/cache_test.go:841 (function value)
//   - internal/cache/cache_test.go:874 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		for {
			select {
			case pc := <-c.pool:
				_ = pc.Close()
			default:
				return
			}
		}
	})
	return nil
}

// purgeOp executes a purge opcode and decodes its uint64 removal count.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadline.
//   - op: One of OpPurgeURL, OpPurgePrefix, OpPurgeTag, OpPurgeAll.
//   - payload: Encoded purge request payload.
//
// # Returns
//
// Removed entry count and any error.
//
// # Example
//
//	n, err := c.purgeOp(ctx, OpPurgeAll, nil)
//	_, _ = n, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:425 (function value)
//   - internal/cache/client.go:460 (function value)
//   - internal/cache/client.go:492 (function value)
//   - internal/cache/client.go:520 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) purgeOp(ctx context.Context, op byte, payload []byte) (int, error) {
	fr, err := c.roundTrip(ctx, op, payload)
	if err != nil {
		return 0, err
	}
	if fr.Op != RespOK {
		return 0, fmt.Errorf("%w: unexpected purge opcode 0x%02x", ErrProtocol, fr.Op)
	}
	n, err := DecodeUint64(fr.Payload)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// roundTrip sends one authenticated frame and reads its reply, retrying once
// on a fresh connection when a pooled idle connection was closed by the peer.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadline.
//   - op: Request opcode.
//   - payload: Encoded request payload.
//
// # Returns
//
// Decoded response Frame or error.
//
// # Example
//
//	fr, err := c.roundTrip(ctx, OpPing, nil)
//	_, _ = fr, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:252 (function value)
//   - internal/cache/client.go:302 (function value)
//   - internal/cache/client.go:373 (function value)
//   - internal/cache/client.go:548 (function value)
//   - internal/cache/client.go:663 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) roundTrip(ctx context.Context, op byte, payload []byte) (Frame, error) {
	if err := ctx.Err(); err != nil {
		return Frame{}, err
	}
	if c.closed.Load() {
		return Frame{}, ErrClosed
	}

	deadline := c.effectiveDeadline(ctx)
	pc, reused, err := c.acquireConn(ctx, deadline)
	if err != nil {
		return Frame{}, err
	}

	fr, err := c.exchange(ctx, pc, deadline, op, payload)
	if err != nil {
		_ = pc.Close()
		// Retry at most once when a previously idle pooled connection failed
		// due to a peer idle-timeout or restart, never on auth or ctx errors.
		if reused && ctx.Err() == nil && !errors.Is(err, ErrUnauthorized) && !errors.Is(err, ErrEntryTooLarge) && !errors.Is(err, ErrFrameTooLarge) {
			pc2, dialErr := c.dialAndAuth(ctx, deadline)
			if dialErr != nil {
				return Frame{}, dialErr
			}
			fr2, err2 := c.exchange(ctx, pc2, deadline, op, payload)
			if err2 != nil {
				_ = pc2.Close()
				return Frame{}, err2
			}
			c.releaseConn(pc2)
			return fr2, nil
		}
		return Frame{}, err
	}

	c.releaseConn(pc)
	return fr, nil
}

// exchange writes one frame and reads one response frame on pc while respecting
// both deadline and ctx cancellation.
//
// # Parameters
//
//   - ctx: Caller context for cancellation.
//   - pc: Authenticated pooled connection.
//   - deadline: Absolute I/O deadline.
//   - op: Request opcode.
//   - payload: Request payload bytes.
//
// # Returns
//
// Response Frame or error (including decoded RespErr errors).
//
// # Example
//
//	fr, err := c.exchange(ctx, pc, deadline, OpPing, nil)
//	_, _ = fr, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:722 (function value)
//   - internal/cache/client.go:732 (function value)
//   - internal/cache/client.go:905 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) exchange(ctx context.Context, pc *pooledConn, deadline time.Time, op byte, payload []byte) (Frame, error) {
	stopCancel := context.AfterFunc(ctx, func() {
		_ = pc.conn.SetDeadline(time.Now())
	})
	defer stopCancel()

	if err := pc.conn.SetDeadline(deadline); err != nil {
		return Frame{}, err
	}
	if err := WriteFrame(pc.bw, op, 0, payload, c.maxFrameBytes); err != nil {
		return Frame{}, err
	}
	if err := pc.bw.Flush(); err != nil {
		return Frame{}, err
	}
	fr, err := ReadFrame(pc.br, c.maxFrameBytes)
	if err != nil {
		if ctx.Err() != nil {
			return Frame{}, ctx.Err()
		}
		return Frame{}, err
	}
	if fr.Op == RespErr {
		return Frame{}, DecodeError(fr.Payload)
	}
	return fr, nil
}

// acquireConn pops an idle connection from the pool or dials and authenticates
// a fresh connection.
//
// # Parameters
//
//   - ctx: Caller context.
//   - deadline: Absolute deadline for dial and auth.
//
// # Returns
//
// (conn, reused, err).
//
// # Example
//
//	pc, reused, err := c.acquireConn(ctx, deadline)
//	_, _, _ = pc, reused, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:717 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) acquireConn(ctx context.Context, deadline time.Time) (*pooledConn, bool, error) {
	select {
	case pc := <-c.pool:
		return pc, true, nil
	default:
	}
	pc, err := c.dialAndAuth(ctx, deadline)
	if err != nil {
		return nil, false, err
	}
	return pc, false, nil
}

// dialAndAuth dials the daemon (with TLS/mTLS if configured) and completes the
// OpAuth shared-secret handshake.
//
// # Parameters
//
//   - ctx: Caller context.
//   - deadline: Overall request deadline.
//
// # Returns
//
// Authenticated *pooledConn or error.
//
// # Example
//
//	pc, err := c.dialAndAuth(ctx, deadline)
//	_, _ = pc, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:728 (function value)
//   - internal/cache/client.go:838 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) dialAndAuth(ctx context.Context, deadline time.Time) (*pooledConn, error) {
	dialDeadline := time.Now().Add(c.dialTimeout)
	if deadline.Before(dialDeadline) {
		dialDeadline = deadline
	}
	dialCtx, cancel := context.WithDeadline(ctx, dialDeadline)
	defer cancel()

	var (
		conn net.Conn
		err  error
	)
	if c.network == "tcp" && c.tlsConfig != nil {
		d := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: c.dialTimeout},
			Config:    c.tlsConfig,
		}
		conn, err = d.DialContext(dialCtx, c.network, c.address)
	} else {
		d := &net.Dialer{Timeout: c.dialTimeout}
		conn, err = d.DialContext(dialCtx, c.network, c.address)
	}
	if err != nil {
		return nil, fmt.Errorf("dial cache %s://%s: %w", c.network, c.address, err)
	}

	pc := &pooledConn{
		conn: conn,
		br:   bufio.NewReaderSize(conn, 16<<10),
		bw:   bufio.NewWriterSize(conn, 16<<10),
	}

	// Single point of secret reveal on the client wire boundary.
	fr, err := c.exchange(ctx, pc, deadline, OpAuth, []byte(c.secret.Reveal()))
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	if fr.Op != RespOK {
		_ = pc.Close()
		return nil, fmt.Errorf("%w: unexpected auth opcode 0x%02x", ErrProtocol, fr.Op)
	}
	return pc, nil
}

// releaseConn returns pc to the idle pool or closes it if the pool is full or
// the client has been closed.
//
// # Parameters
//
//   - pc: Healthy authenticated connection to return.
//
// # Returns
//
// None.
//
// # Example
//
//	c.releaseConn(pc)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:737 (function value)
//   - internal/cache/client.go:743 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) releaseConn(pc *pooledConn) {
	if c.closed.Load() {
		_ = pc.Close()
		return
	}
	_ = pc.conn.SetDeadline(time.Time{})
	select {
	case c.pool <- pc:
		if c.closed.Load() {
			select {
			case stale := <-c.pool:
				_ = stale.Close()
			default:
			}
		}
	default:
		_ = pc.Close()
	}
}

// effectiveDeadline returns the earlier of ctx's deadline and now+requestTimeout.
//
// # Parameters
//
//   - ctx: Caller context.
//
// # Returns
//
// Effective request deadline instant.
//
// # Example
//
//	dl := c.effectiveDeadline(ctx)
//	_ = dl
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:716 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) effectiveDeadline(ctx context.Context) time.Time {
	dl := time.Now().Add(c.requestTimeout)
	if ctxDL, ok := ctx.Deadline(); ok && ctxDL.Before(dl) {
		return ctxDL
	}
	return dl
}

// shouldFailOpen reports whether err should be absorbed in fail-open mode.
// Validation, auth, closed-client, and explicit caller-cancellation errors are
// never swallowed.
//
// # Parameters
//
//   - ctx: Caller context.
//   - err: Error produced by an RPC call.
//
// # Returns
//
// true when fail-open mode should convert err into a cache miss / no-op.
//
// # Example
//
//	if c.shouldFailOpen(ctx, err) {
//	    return Entry{}, false, nil
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:304 (function value)
//   - internal/cache/client.go:316 (function value)
//   - internal/cache/client.go:325 (function value)
//   - internal/cache/client.go:375 (function value)
//   - internal/cache/client.go:383 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) shouldFailOpen(ctx context.Context, err error) bool {
	if c.failClosed {
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	if errors.Is(err, ErrClosed) || errors.Is(err, ErrUnauthorized) ||
		errors.Is(err, ErrInvalidKey) || errors.Is(err, ErrEntryTooLarge) ||
		errors.Is(err, ErrTooManyTags) || errors.Is(err, ErrInvalidTag) ||
		errors.Is(err, ErrInvalidTTL) {
		return false
	}
	return true
}

// recordError increments the client error counter and invokes the optional
// OnError callback.
//
// # Parameters
//
//   - err: Observed non-nil error.
//
// # Returns
//
// None.
//
// # Example
//
//	c.recordError(err)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:305 (function value)
//   - internal/cache/client.go:317 (function value)
//   - internal/cache/client.go:326 (function value)
//   - internal/cache/client.go:376 (function value)
//   - internal/cache/client.go:384 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (c *Client) recordError(err error) {
	c.errCount.Add(1)
	if c.onError != nil {
		c.onError(err)
	}
}
