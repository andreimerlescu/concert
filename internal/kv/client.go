package kv

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Default client pool and timeout parameters (R3).
const (
	DefaultClientPoolSize     = 8
	DefaultClientDialTimeout  = 2 * time.Second
	DefaultClientReadTimeout  = 2 * time.Second
	DefaultClientWriteTimeout = 2 * time.Second
)

// ErrClientClosed is returned when a command is issued on a closed Client.
var ErrClientClosed = errors.New("kv client is closed")

// ClientConfig configures a pooled concert-kv client for concert and econcert.
type ClientConfig struct {
	// Addr is the server endpoint ("host:port", "unix:///path", or "/path").
	Addr string
	// Password is an optional redacting Secret used for AUTH on new connections.
	Password Secret
	// TLSConfig optionally enables TLS/mTLS for TCP connections.
	TLSConfig *tls.Config
	// PoolSize caps idle pooled connections (default DefaultClientPoolSize).
	PoolSize int
	// DialTimeout, ReadTimeout, and WriteTimeout enforce strict per-op bounds.
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// FailOpen, when true, catches transport/protocol errors on read/write/CQ
	// helpers, increments FailOpenErrors(), and returns safe degraded results
	// so edge traffic is never blocked if concert-kv is unavailable.
	FailOpen bool
}

type pooledConn struct {
	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer
}

// Client is a pure-stdlib connection-pooled RESP2 client safe for concurrent
// use across goroutines. Call Close when finished to release pooled sockets.
type Client struct {
	cfg            ClientConfig
	mu             sync.Mutex
	closed         bool
	idle           []*pooledConn
	failOpenErrors atomic.Int64
}

// NewClient validates cfg and creates a pooled *Client. Connections are dialed
// lazily on first use.
//
// # Parameters
//
//   - cfg: Client address, optional credentials/TLS, pool size, timeouts, and
//     FailOpen flag.
//
// # Returns
//
// A ready-to-use *Client, or ErrInvalidArg if cfg.Addr is empty.
//
// # Example
//
//	cli, err := kv.NewClient(kv.ClientConfig{
//	    Addr:     "127.0.0.1:6380",
//	    FailOpen: true,
//	})
//	if err != nil {
//	    return err
//	}
//	defer cli.Close()
func NewClient(cfg ClientConfig) (*Client, error) {
	if strings.TrimSpace(cfg.Addr) == "" {
		return nil, fmt.Errorf("%w: client Addr is required", ErrInvalidArg)
	}
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = DefaultClientPoolSize
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = DefaultClientDialTimeout
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = DefaultClientReadTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = DefaultClientWriteTimeout
	}
	if cfg.TLSConfig != nil {
		tlsCopy := cfg.TLSConfig.Clone()
		if tlsCopy.MinVersion < tls.VersionTLS12 {
			tlsCopy.MinVersion = tls.VersionTLS12
		}
		cfg.TLSConfig = tlsCopy
	}
	return &Client{
		cfg:  cfg,
		idle: make([]*pooledConn, 0, cfg.PoolSize),
	}, nil
}

// Close closes all idle pooled connections and prevents further commands.
// Idempotent and safe for concurrent use.
//
// # Parameters
//
// None.
//
// # Returns
//
// First connection close error encountered, if any.
//
// # Example
//
//	_ = cli.Close()
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	conns := c.idle
	c.idle = nil
	c.mu.Unlock()

	var firstErr error
	for _, pc := range conns {
		if err := pc.conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// FailOpenErrors returns the total number of transport/server errors absorbed
// while FailOpen mode is enabled.
//
// # Parameters
//
// None.
//
// # Returns
//
// Cumulative absorbed error count.
//
// # Example
//
//	degraded := cli.FailOpenErrors()
func (c *Client) FailOpenErrors() int64 {
	return c.failOpenErrors.Load()
}

// acquire returns an idle pooled connection or dials and authenticates a fresh
// connection.
//
// # Parameters
//
//   - ctx: Cancellation and dial deadline context.
//
// # Returns
//
// A ready *pooledConn or an error.
//
// # Example
//
//	pc, err := c.acquire(ctx)
func (c *Client) acquire(ctx context.Context) (*pooledConn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClientClosed
	}
	if n := len(c.idle); n > 0 {
		pc := c.idle[n-1]
		c.idle[n-1] = nil
		c.idle = c.idle[:n-1]
		c.mu.Unlock()
		return pc, nil
	}
	c.mu.Unlock()

	return c.dialAndAuth(ctx)
}

// dialAndAuth establishes a new connection and performs AUTH when Password is
// configured.
//
// # Parameters
//
//   - ctx: Cancellation and dial deadline context.
//
// # Returns
//
// Authenticated *pooledConn or dial/auth error.
//
// # Example
//
//	pc, err := c.dialAndAuth(ctx)
func (c *Client) dialAndAuth(ctx context.Context) (*pooledConn, error) {
	conn, err := dialEndpoint(ctx, c.cfg.Addr, c.cfg.TLSConfig, c.cfg.DialTimeout)
	if err != nil {
		return nil, err
	}
	pc := &pooledConn{
		conn: conn,
		br:   bufio.NewReaderSize(conn, 16<<10),
		bw:   bufio.NewWriterSize(conn, 16<<10),
	}
	if !c.cfg.Password.IsZero() {
		reply, err := c.roundTrip(ctx, pc, "AUTH", c.cfg.Password.Reveal())
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("kv AUTH: %w", err)
		}
		if reply.Kind == KindError {
			_ = conn.Close()
			return nil, fmt.Errorf("kv AUTH failed: %s", reply.Str)
		}
	}
	return pc, nil
}

// release returns pc to the idle pool, or closes it if the pool is full or the
// client is closed.
//
// # Parameters
//
//   - pc: Connection to recycle.
//
// # Returns
//
// None.
//
// # Example
//
//	c.release(pc)
func (c *Client) release(pc *pooledConn) {
	c.mu.Lock()
	if c.closed || len(c.idle) >= c.cfg.PoolSize {
		c.mu.Unlock()
		_ = pc.conn.Close()
		return
	}
	c.idle = append(c.idle, pc)
	c.mu.Unlock()
}

// roundTrip sends one command over pc and reads one RESP2 reply while honoring
// ctx cancellation and strict read/write deadlines.
//
// # Parameters
//
//   - ctx: Request context.
//   - pc: Active connection.
//   - args: Command tokens.
//
// # Returns
//
// Decoded RESP2 Value or transport/protocol error.
//
// # Example
//
//	val, err := c.roundTrip(ctx, pc, "PING")
func (c *Client) roundTrip(ctx context.Context, pc *pooledConn, args ...string) (Value, error) {
	if err := ctx.Err(); err != nil {
		return Value{}, err
	}
	stopAbort := context.AfterFunc(ctx, func() {
		_ = pc.conn.SetDeadline(time.Now())
	})
	defer stopAbort()

	writeDeadline := time.Now().Add(c.cfg.WriteTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(writeDeadline) {
		writeDeadline = dl
	}
	if err := pc.conn.SetWriteDeadline(writeDeadline); err != nil {
		return Value{}, err
	}
	if err := WriteCommand(pc.bw, args...); err != nil {
		return Value{}, err
	}
	if err := pc.bw.Flush(); err != nil {
		return Value{}, err
	}

	readDeadline := time.Now().Add(c.cfg.ReadTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(readDeadline) {
		readDeadline = dl
	}
	if err := pc.conn.SetReadDeadline(readDeadline); err != nil {
		return Value{}, err
	}
	return ReadValue(pc.br, ProtocolLimits{})
}

// Do executes a raw RESP2 command using a pooled connection, retrying once on
// a stale pooled connection before surfacing an error.
//
// # Parameters
//
//   - ctx: Request cancellation and timeout context.
//   - args: Command name followed by arguments.
//
// # Returns
//
// Decoded RESP2 Value, or an error (including server KindError responses).
//
// # Example
//
//	v, err := cli.Do(ctx, "PING")
//	_, _ = v, err
func (c *Client) Do(ctx context.Context, args ...string) (Value, error) {
	for attempt := 0; attempt < 2; attempt++ {
		var pc *pooledConn
		var fromPool bool
		var err error
		if attempt == 0 {
			c.mu.Lock()
			if c.closed {
				c.mu.Unlock()
				return Value{}, ErrClientClosed
			}
			if n := len(c.idle); n > 0 {
				pc = c.idle[n-1]
				c.idle[n-1] = nil
				c.idle = c.idle[:n-1]
				fromPool = true
			}
			c.mu.Unlock()
		}
		if pc == nil {
			pc, err = c.dialAndAuth(ctx)
			if err != nil {
				return Value{}, err
			}
		}

		reply, err := c.roundTrip(ctx, pc, args...)
		if err != nil {
			_ = pc.conn.Close()
			if fromPool && ctx.Err() == nil {
				continue
			}
			return Value{}, err
		}
		c.release(pc)
		if reply.Kind == KindError {
			return Value{}, errors.New(reply.Str)
		}
		return reply, nil
	}
	return Value{}, errors.New("kv request failed")
}

// Ping verifies connectivity and authentication with the server.
//
// # Parameters
//
//   - ctx: Request context.
//
// # Returns
//
// nil on PONG; transport, auth, or timeout error otherwise (never swallowed by
// FailOpen so health probes observe true status).
//
// # Example
//
//	if err := cli.Ping(ctx); err != nil {
//	    return err
//	}
func (c *Client) Ping(ctx context.Context) error {
	v, err := c.Do(ctx, "PING")
	if err != nil {
		return err
	}
	s, ok := v.AsString()
	if !ok || strings.ToUpper(s) != "PONG" {
		return fmt.Errorf("unexpected PING reply: %q", s)
	}
	return nil
}

// Get fetches key from the server. When FailOpen is enabled and an error
// occurs, Get increments FailOpenErrors and returns (nil, false, nil).
//
// # Parameters
//
//   - ctx: Request context.
//   - key: Key name to read.
//
// # Returns
//
// (value, found, err).
//
// # Example
//
//	val, ok, err := cli.Get(ctx, "feature:flag")
//	_, _, _ = val, ok, err
func (c *Client) Get(ctx context.Context, key string) ([]byte, bool, error) {
	v, err := c.Do(ctx, "GET", key)
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return nil, false, nil
		}
		return nil, false, err
	}
	if v.Kind == KindNull {
		return nil, false, nil
	}
	b, ok := v.StringBytes()
	if !ok {
		return nil, false, fmt.Errorf("%w: unexpected GET reply kind %d", ErrProtocol, v.Kind)
	}
	return b, true, nil
}

// Set writes key=val with optional TTL and NX/XX flags. In FailOpen mode,
// transport errors increment FailOpenErrors and return (false, nil).
//
// # Parameters
//
//   - ctx: Request context.
//   - key: Key name to write.
//   - val: Byte payload.
//   - opts: Optional TTL/ExpiresAt and NX/XX conditions.
//
// # Returns
//
// (written, err) where written is false when an NX/XX condition did not match.
//
// # Example
//
//	ok, err := cli.Set(ctx, "dedupe:1", []byte("node-a"), kv.SetOptions{
//	    TTL: time.Minute,
//	    NX:  true,
//	})
//	_, _ = ok, err
func (c *Client) Set(ctx context.Context, key string, val []byte, opts SetOptions) (bool, error) {
	args := []string{"SET", key, string(val)}
	if !opts.ExpiresAt.IsZero() {
		args = append(args, "PXAT", strconv.FormatInt(opts.ExpiresAt.UnixMilli(), 10))
	} else if opts.TTL > 0 {
		ms := opts.TTL.Milliseconds()
		if ms <= 0 {
			ms = 1
		}
		args = append(args, "PX", strconv.FormatInt(ms, 10))
	}
	if opts.NX {
		args = append(args, "NX")
	}
	if opts.XX {
		args = append(args, "XX")
	}
	v, err := c.Do(ctx, args...)
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return false, nil
		}
		return false, err
	}
	if v.Kind == KindNull {
		return false, nil
	}
	return true, nil
}

// Del removes one or more keys and returns the number of deleted keys.
//
// # Parameters
//
//   - ctx: Request context.
//   - keys: Keys to remove.
//
// # Returns
//
// Count of deleted keys and any error (absorbed as (0, nil) in FailOpen mode).
//
// # Example
//
//	n, err := cli.Del(ctx, "k1", "k2")
//	_, _ = n, err
func (c *Client) Del(ctx context.Context, keys ...string) (int64, error) {
	if len(keys) == 0 {
		return 0, nil
	}
	args := append([]string{"DEL"}, keys...)
	v, err := c.Do(ctx, args...)
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return 0, nil
		}
		return 0, err
	}
	return v.Int, nil
}

// Exists returns the count of supplied keys that currently exist.
//
// # Parameters
//
//   - ctx: Request context.
//   - keys: Key names to inspect.
//
// # Returns
//
// Count of existing keys and any error.
//
// # Example
//
//	n, err := cli.Exists(ctx, "k1")
//	_, _ = n, err
func (c *Client) Exists(ctx context.Context, keys ...string) (int64, error) {
	if len(keys) == 0 {
		return 0, nil
	}
	args := append([]string{"EXISTS"}, keys...)
	v, err := c.Do(ctx, args...)
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return 0, nil
		}
		return 0, err
	}
	return v.Int, nil
}

// IncrBy atomically increments key by delta and returns the new value.
//
// # Parameters
//
//   - ctx: Request context.
//   - key: Counter key name.
//   - delta: Signed 64-bit increment.
//
// # Returns
//
// Updated integer value and any error.
//
// # Example
//
//	n, err := cli.IncrBy(ctx, "req:count", 1)
//	_, _ = n, err
func (c *Client) IncrBy(ctx context.Context, key string, delta int64) (int64, error) {
	v, err := c.Do(ctx, "INCRBY", key, strconv.FormatInt(delta, 10))
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return 0, nil
		}
		return 0, err
	}
	return v.Int, nil
}

// Expire sets a relative TTL in whole seconds on key.
//
// # Parameters
//
//   - ctx: Request context.
//   - key: Key name.
//   - ttl: Relative expiration duration.
//
// # Returns
//
// true if the timeout was set, false if key does not exist, and any error.
//
// # Example
//
//	ok, err := cli.Expire(ctx, "session:1", 30*time.Second)
//	_, _ = ok, err
func (c *Client) Expire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	secs := int64(ttl / time.Second)
	v, err := c.Do(ctx, "EXPIRE", key, strconv.FormatInt(secs, 10))
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return false, nil
		}
		return false, err
	}
	return v.Int == 1, nil
}

// TTL returns the remaining lifetime of key in seconds (-2 missing, -1 no TTL).
//
// # Parameters
//
//   - ctx: Request context.
//   - key: Key name.
//
// # Returns
//
// Remaining seconds and any error.
//
// # Example
//
//	secs, err := cli.TTL(ctx, "session:1")
//	_, _ = secs, err
func (c *Client) TTL(ctx context.Context, key string) (int64, error) {
	v, err := c.Do(ctx, "TTL", key)
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return -2, nil
		}
		return -2, err
	}
	return v.Int, nil
}

// HSet sets fields in the hash stored at key.
//
// # Parameters
//
//   - ctx: Request context.
//   - key: Hash key name.
//   - fields: Map of field names to byte values.
//
// # Returns
//
// Number of newly added fields and any error.
//
// # Example
//
//	n, err := cli.HSet(ctx, "bans", map[string][]byte{"192.0.2.1": []byte("1")})
//	_, _ = n, err
func (c *Client) HSet(ctx context.Context, key string, fields map[string][]byte) (int64, error) {
	if len(fields) == 0 {
		return 0, nil
	}
	args := make([]string, 0, 2+len(fields)*2)
	args = append(args, "HSET", key)
	for f, val := range fields {
		args = append(args, f, string(val))
	}
	v, err := c.Do(ctx, args...)
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return 0, nil
		}
		return 0, err
	}
	return v.Int, nil
}

// HGet fetches field from the hash stored at key.
//
// # Parameters
//
//   - ctx: Request context.
//   - key: Hash key name.
//   - field: Hash field name.
//
// # Returns
//
// (value, found, err).
//
// # Example
//
//	val, ok, err := cli.HGet(ctx, "bans", "192.0.2.1")
//	_, _, _ = val, ok, err
func (c *Client) HGet(ctx context.Context, key, field string) ([]byte, bool, error) {
	v, err := c.Do(ctx, "HGET", key, field)
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return nil, false, nil
		}
		return nil, false, err
	}
	if v.Kind == KindNull {
		return nil, false, nil
	}
	b, ok := v.StringBytes()
	return b, ok, nil
}

// HDel deletes fields from the hash stored at key.
//
// # Parameters
//
//   - ctx: Request context.
//   - key: Hash key name.
//   - fields: Field names to remove.
//
// # Returns
//
// Number of removed fields and any error.
//
// # Example
//
//	n, err := cli.HDel(ctx, "bans", "192.0.2.1")
//	_, _ = n, err
func (c *Client) HDel(ctx context.Context, key string, fields ...string) (int64, error) {
	if len(fields) == 0 {
		return 0, nil
	}
	args := make([]string, 0, 2+len(fields))
	args = append(args, "HDEL", key)
	args = append(args, fields...)
	v, err := c.Do(ctx, args...)
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return 0, nil
		}
		return 0, err
	}
	return v.Int, nil
}

// HGetAll retrieves all field/value pairs from the hash stored at key.
//
// # Parameters
//
//   - ctx: Request context.
//   - key: Hash key name.
//
// # Returns
//
// Map of field name to bytes and any error.
//
// # Example
//
//	all, err := cli.HGetAll(ctx, "bans")
//	_, _ = all, err
func (c *Client) HGetAll(ctx context.Context, key string) (map[string][]byte, error) {
	v, err := c.Do(ctx, "HGETALL", key)
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return map[string][]byte{}, nil
		}
		return nil, err
	}
	out := make(map[string][]byte, len(v.Array)/2)
	for i := 0; i+1 < len(v.Array); i += 2 {
		fk, _ := v.Array[i].AsString()
		fv, _ := v.Array[i+1].StringBytes()
		out[fk] = fv
	}
	return out, nil
}

// Publish broadcasts payload to all subscribers of channel.
//
// # Parameters
//
//   - ctx: Request context.
//   - channel: Channel name.
//   - payload: Message bytes.
//
// # Returns
//
// Number of receiving subscribers and any error (absorbed in FailOpen mode).
//
// # Example
//
//	n, err := cli.Publish(ctx, "concert:bans:events", []byte(`{"action":"ban"}`))
//	_, _ = n, err
func (c *Client) Publish(ctx context.Context, channel string, payload []byte) (int64, error) {
	v, err := c.Do(ctx, "PUBLISH", channel, string(payload))
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return 0, nil
		}
		return 0, err
	}
	return v.Int, nil
}

// ClientSubscription holds a dedicated Pub/Sub connection with a bounded
// message delivery channel and a single joined reader goroutine (R2, R3).
type ClientSubscription struct {
	pc      *pooledConn
	writeMu sync.Mutex
	msgCh   chan PubSubMessage
	cancel  context.CancelFunc
	once    sync.Once
	wg      sync.WaitGroup
}

// Messages returns the bounded channel receiving published messages. The
// channel closes when the connection drops or Close is called.
//
// # Parameters
//
// None.
//
// # Returns
//
// Receive-only channel of PubSubMessage values.
//
// # Example
//
//	for msg := range sub.Messages() {
//	    fmt.Println(msg.Channel, string(msg.Payload))
//	}
func (s *ClientSubscription) Messages() <-chan PubSubMessage {
	return s.msgCh
}

// Close closes the underlying Pub/Sub connection and waits for the reader
// goroutine to exit. Safe to call multiple times (R2).
//
// # Parameters
//
// None.
//
// # Returns
//
// None.
//
// # Example
//
//	defer sub.Close()
func (s *ClientSubscription) Close() {
	s.once.Do(func() {
		s.cancel()
		_ = s.pc.conn.SetDeadline(time.Now())
		_ = s.pc.conn.Close()
		s.wg.Wait()
	})
}

// Subscribe opens a dedicated Pub/Sub connection subscribed to channels and
// streams incoming messages onto a bounded channel (capacity DefaultPubSubBuffer).
// Callers must call Close when done.
//
// # Parameters
//
//   - ctx: Context controlling initial dial/subscribe and background lifetime.
//   - channels: One or more Pub/Sub channel names.
//
// # Returns
//
// A *ClientSubscription or a dial/auth/subscribe error.
//
// # Example
//
//	sub, err := cli.Subscribe(ctx, "concert:bans:events")
//	if err != nil {
//	    return err
//	}
//	defer sub.Close()
func (c *Client) Subscribe(ctx context.Context, channels ...string) (*ClientSubscription, error) {
	if len(channels) == 0 {
		return nil, fmt.Errorf("%w: at least one channel is required", ErrInvalidArg)
	}
	pc, err := c.dialAndAuth(ctx)
	if err != nil {
		return nil, err
	}

	args := append([]string{"SUBSCRIBE"}, channels...)
	if err := pc.conn.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout)); err != nil {
		_ = pc.conn.Close()
		return nil, err
	}
	if err := WriteCommand(pc.bw, args...); err != nil {
		_ = pc.conn.Close()
		return nil, err
	}
	if err := pc.bw.Flush(); err != nil {
		_ = pc.conn.Close()
		return nil, err
	}

	// Read one subscribe ack per requested channel before returning.
	if err := pc.conn.SetReadDeadline(time.Now().Add(c.cfg.ReadTimeout)); err != nil {
		_ = pc.conn.Close()
		return nil, err
	}
	for range channels {
		ack, err := ReadValue(pc.br, ProtocolLimits{})
		if err != nil {
			_ = pc.conn.Close()
			return nil, fmt.Errorf("read SUBSCRIBE ack: %w", err)
		}
		if ack.Kind == KindError {
			_ = pc.conn.Close()
			return nil, errors.New(ack.Str)
		}
	}
	_ = pc.conn.SetReadDeadline(time.Time{})

	subCtx, cancel := context.WithCancel(ctx)
	cs := &ClientSubscription{
		pc:     pc,
		msgCh:  make(chan PubSubMessage, DefaultPubSubBuffer),
		cancel: cancel,
	}
	stopAbort := context.AfterFunc(subCtx, func() {
		_ = pc.conn.SetDeadline(time.Now())
	})
	cs.wg.Add(1)
	go func() {
		defer func() {
			stopAbort()
			close(cs.msgCh)
			_ = pc.conn.Close()
			cs.wg.Done()
		}()
		for {
			if subCtx.Err() != nil {
				return
			}
			v, err := ReadValue(pc.br, ProtocolLimits{})
			if err != nil {
				return
			}
			if v.Kind != KindArray || len(v.Array) < 3 {
				continue
			}
			kind, _ := v.Array[0].AsString()
			if kind != "message" {
				continue
			}
			ch, _ := v.Array[1].AsString()
			payload, _ := v.Array[2].StringBytes()
			msg := PubSubMessage{Channel: ch, Payload: payload}
			select {
			case cs.msgCh <- msg:
			case <-subCtx.Done():
				return
			}
		}
	}()
	return cs, nil
}

// ─── Typed Concert Queue & Auction Helpers (CQ.*) ───────────────────────────

// CQJoin joins or refreshes ticket in a shared Concert waiting-room queue.
// In FailOpen mode, transport errors return CQJoinResult{Degraded: true}, nil.
//
// # Parameters
//
//   - ctx: Request context.
//   - queue: Queue name.
//   - ticket: Ticket/session identifier.
//   - clientKey: Client/IP identifier.
//   - ttl: Expiration duration (0 uses server default).
//   - bid: Non-negative auction bid.
//
// # Returns
//
// CQJoinResult and any error.
//
// # Example
//
//	res, err := cli.CQJoin(ctx, "drop-1", "tkt-1", "203.0.113.5", 2*time.Minute, 10)
//	_, _ = res, err
func (c *Client) CQJoin(ctx context.Context, queue, ticket, clientKey string, ttl time.Duration, bid int64) (CQJoinResult, error) {
	args := []string{"CQ.JOIN", queue, ticket, clientKey}
	if ttl > 0 {
		args = append(args, "TTL", strconv.FormatInt(ttl.Milliseconds(), 10))
	}
	if bid > 0 {
		args = append(args, "BID", strconv.FormatInt(bid, 10))
	}
	v, err := c.Do(ctx, args...)
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return CQJoinResult{Degraded: true}, nil
		}
		return CQJoinResult{}, err
	}
	if v.Kind != KindArray || len(v.Array) < 3 {
		return CQJoinResult{}, fmt.Errorf("%w: unexpected CQ.JOIN reply", ErrProtocol)
	}
	return CQJoinResult{
		Position: v.Array[0].Int,
		Depth:    v.Array[1].Int,
		Seq:      uint64(v.Array[2].Int),
	}, nil
}

// CQPoll checks the current waiting-room position and state of ticket,
// optionally extending its TTL when extendTTL > 0. In FailOpen mode, transport
// errors return CQPollResult{Status: "degraded", Degraded: true}, nil.
//
// # Parameters
//
//   - ctx: Request context.
//   - queue: Queue name.
//   - ticket: Ticket identifier.
//   - extendTTL: Optional TTL extension (> 0 refreshes expiration).
//
// # Returns
//
// CQPollResult and any error.
//
// # Example
//
//	res, err := cli.CQPoll(ctx, "drop-1", "tkt-1", 30*time.Second)
//	_, _ = res, err
func (c *Client) CQPoll(ctx context.Context, queue, ticket string, extendTTL time.Duration) (CQPollResult, error) {
	args := []string{"CQ.POLL", queue, ticket}
	if extendTTL > 0 {
		args = append(args, "TTL", strconv.FormatInt(extendTTL.Milliseconds(), 10))
	}
	v, err := c.Do(ctx, args...)
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return CQPollResult{Status: "degraded", Degraded: true}, nil
		}
		return CQPollResult{}, err
	}
	if v.Kind != KindArray || len(v.Array) < 5 {
		return CQPollResult{}, fmt.Errorf("%w: unexpected CQ.POLL reply", ErrProtocol)
	}
	status, _ := v.Array[0].AsString()
	return CQPollResult{
		Status:      status,
		Position:    v.Array[1].Int,
		Depth:       v.Array[2].Int,
		Bid:         v.Array[3].Int,
		RemainingMS: v.Array[4].Int,
	}, nil
}

// CQClaim atomically claims up to count highest-priority waiting tickets from
// queue for edgeID.
//
// # Parameters
//
//   - ctx: Request context.
//   - queue: Queue name.
//   - edgeID: Claiming edge identifier.
//   - count: Maximum tickets to claim (<= 0 defaults to 1).
//
// # Returns
//
// Slice of claimed CQClaimEntry items and any error (absorbed as nil, nil in
// FailOpen mode).
//
// # Example
//
//	claimed, err := cli.CQClaim(ctx, "drop-1", "edge-a", 4)
//	_, _ = claimed, err
func (c *Client) CQClaim(ctx context.Context, queue, edgeID string, count int) ([]CQClaimEntry, error) {
	if count <= 0 {
		count = 1
	}
	v, err := c.Do(ctx, "CQ.CLAIM", queue, edgeID, "COUNT", strconv.Itoa(count))
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return nil, nil
		}
		return nil, err
	}
	if v.Kind != KindArray {
		return nil, fmt.Errorf("%w: unexpected CQ.CLAIM reply", ErrProtocol)
	}
	out := make([]CQClaimEntry, 0, len(v.Array))
	for _, elem := range v.Array {
		if elem.Kind != KindArray || len(elem.Array) < 4 {
			return nil, fmt.Errorf("%w: malformed CQ.CLAIM entry", ErrProtocol)
		}
		tid, _ := elem.Array[0].AsString()
		ck, _ := elem.Array[1].AsString()
		out = append(out, CQClaimEntry{
			TicketID:  tid,
			ClientKey: ck,
			Bid:       elem.Array[2].Int,
			Seq:       uint64(elem.Array[3].Int),
		})
	}
	return out, nil
}

// CQBid atomically raises the auction bid for ticket in queue.
//
// # Parameters
//
//   - ctx: Request context.
//   - queue: Queue name.
//   - ticket: Waiting ticket identifier.
//   - amount: New bid amount (must exceed current bid).
//
// # Returns
//
// Updated CQBidResult and any error.
//
// # Example
//
//	res, err := cli.CQBid(ctx, "drop-1", "tkt-1", 500)
//	_, _ = res, err
func (c *Client) CQBid(ctx context.Context, queue, ticket string, amount int64) (CQBidResult, error) {
	v, err := c.Do(ctx, "CQ.BID", queue, ticket, strconv.FormatInt(amount, 10))
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return CQBidResult{Degraded: true}, nil
		}
		return CQBidResult{}, err
	}
	if v.Kind != KindArray || len(v.Array) < 3 {
		return CQBidResult{}, fmt.Errorf("%w: unexpected CQ.BID reply", ErrProtocol)
	}
	return CQBidResult{
		Position: v.Array[0].Int,
		Depth:    v.Array[1].Int,
		Bid:      v.Array[2].Int,
	}, nil
}

// CQPurge removes tickets from queue according to mode ("stale" or "all") and
// optional clientKey filter.
//
// # Parameters
//
//   - ctx: Request context.
//   - queue: Queue name.
//   - mode: "stale" (default) or "all".
//   - clientKey: Optional client filter to drop all tickets for one client.
//
// # Returns
//
// Count of purged tickets and any error.
//
// # Example
//
//	purged, err := cli.CQPurge(ctx, "drop-1", "stale", "")
//	_, _ = purged, err
func (c *Client) CQPurge(ctx context.Context, queue, mode, clientKey string) (int64, error) {
	if mode == "" {
		mode = "stale"
	}
	args := []string{"CQ.PURGE", queue, "MODE", mode}
	if clientKey != "" {
		args = append(args, "CLIENT", clientKey)
	}
	v, err := c.Do(ctx, args...)
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return 0, nil
		}
		return 0, err
	}
	return v.Int, nil
}

// CQStats retrieves queue statistics for queue.
//
// # Parameters
//
//   - ctx: Request context.
//   - queue: Queue name.
//
// # Returns
//
// CQQueueStats and any error (absorbed as Degraded: true in FailOpen mode).
//
// # Example
//
//	st, err := cli.CQStats(ctx, "drop-1")
//	_, _ = st, err
func (c *Client) CQStats(ctx context.Context, queue string) (CQQueueStats, error) {
	v, err := c.Do(ctx, "CQ.STATS", queue)
	if err != nil {
		if c.cfg.FailOpen {
			c.failOpenErrors.Add(1)
			return CQQueueStats{Degraded: true}, nil
		}
		return CQQueueStats{}, err
	}
	if v.Kind != KindArray {
		return CQQueueStats{}, fmt.Errorf("%w: unexpected CQ.STATS reply", ErrProtocol)
	}
	var st CQQueueStats
	for i := 0; i+1 < len(v.Array); i += 2 {
		k, _ := v.Array[i].AsString()
		val := v.Array[i+1].Int
		switch k {
		case "waiting":
			st.Waiting = val
		case "claimed":
			st.Claimed = val
		case "total_joined":
			st.TotalJoined = val
		case "total_claimed":
			st.TotalClaimed = val
		case "total_purged":
			st.TotalPurged = val
		case "highest_bid":
			st.HighestBid = val
		case "oldest_wait_ms":
			st.OldestWaitMS = val
		}
	}
	return st, nil
}
