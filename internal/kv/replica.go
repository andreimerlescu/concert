package kv

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default replication backlog and reconnect bounds (R3, E4).
const (
	DefaultReplBacklogEntries = 10000
	DefaultReplBacklogBytes   = 16 << 20 // 16 MiB
	DefaultReplInitialBackoff = 100 * time.Millisecond
	DefaultReplMaxBackoff     = 10 * time.Second
	DefaultReplHeartbeat      = 5 * time.Second
)

// ReplicationEntry holds one canonical mutating command stored in the primary's
// bounded replication backlog. Args is never mutated after insertion.
type ReplicationEntry struct {
	Seq  uint64
	Args []string
	Size int64
}

// ReplicationLog maintains a bounded ring of recent store mutations and wakes
// connected replicas immediately upon each Append. All methods are safe for
// concurrent use.
type ReplicationLog struct {
	maxEntries int
	maxBytes   int64

	// mu guards entries, totalBytes, baseSeq, lastSeq, and notify.
	mu         sync.Mutex
	entries    []ReplicationEntry
	totalBytes int64
	baseSeq    uint64
	lastSeq    uint64
	notify     chan struct{}
}

// NewReplicationLog constructs a ReplicationLog capped by maxEntries and
// maxBytes (zero values use DefaultReplBacklogEntries / DefaultReplBacklogBytes).
//
// # Parameters
//
//   - maxEntries: Maximum number of retained mutation entries.
//   - maxBytes: Maximum retained payload bytes across entries.
//
// # Returns
//
// A ready-to-use *ReplicationLog.
//
// # Example
//
//	rlog := kv.NewReplicationLog(10000, 16<<20)
//	rlog.Append(1, []string{"SET", "k", "v"})
func NewReplicationLog(maxEntries int, maxBytes int64) *ReplicationLog {
	if maxEntries <= 0 {
		maxEntries = DefaultReplBacklogEntries
	}
	if maxBytes <= 0 {
		maxBytes = DefaultReplBacklogBytes
	}
	return &ReplicationLog{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		notify:     make(chan struct{}),
	}
}

// Append records a canonical mutation in the bounded backlog, evicting oldest
// entries when maxEntries or maxBytes would be exceeded, and wakes all waiting
// replica streams.
//
// # Parameters
//
//   - seq: Monotonic sequence number for this mutation.
//   - args: Canonical command arguments; cloned before storage.
//
// # Returns
//
// None.
//
// # Example
//
//	rlog.Append(seq, walArgs)
func (r *ReplicationLog) Append(seq uint64, args []string) {
	if len(args) == 0 {
		return
	}
	cp := slices.Clone(args)
	var sz int64 = 64
	for _, a := range cp {
		sz += int64(len(a))
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if seq <= r.lastSeq {
		seq = r.lastSeq + 1
	}
	if r.baseSeq == 0 {
		r.baseSeq = seq
	}
	r.entries = append(r.entries, ReplicationEntry{
		Seq:  seq,
		Args: cp,
		Size: sz,
	})
	r.totalBytes += sz
	r.lastSeq = seq

	for len(r.entries) > 1 && (len(r.entries) > r.maxEntries || r.totalBytes > r.maxBytes) {
		r.totalBytes -= r.entries[0].Size
		r.entries = r.entries[1:]
		r.baseSeq = r.entries[0].Seq
	}
	// If a single entry alone exceeds maxBytes, clear backlog and advance baseSeq
	// beyond it so lagging replicas fall back to a full snapshot cleanly.
	if len(r.entries) == 1 && r.totalBytes > r.maxBytes {
		r.totalBytes = 0
		r.entries = nil
		r.baseSeq = seq + 1
	}

	// Broadcast wakeup by closing the current notification channel and swapping
	// in a fresh channel (C5: ReplicationLog is the sole closer).
	close(r.notify)
	r.notify = make(chan struct{})
}

// ReadSince returns entries strictly newer than sinceSeq. If sinceSeq fell
// behind the bounded backlog, needFullSync is true. When no newer entries are
// currently buffered, waitCh is closed as soon as the next Append occurs.
//
// # Parameters
//
//   - sinceSeq: Last mutation sequence applied by the requesting replica.
//
// # Returns
//
// (entries, needFullSync, waitCh).
//
// # Example
//
//	entries, full, waitCh := rlog.ReadSince(lastSeq)
//	_, _, _ = entries, full, waitCh
func (r *ReplicationLog) ReadSince(sinceSeq uint64) (entries []ReplicationEntry, needFullSync bool, waitCh <-chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.lastSeq == 0 {
		return nil, false, r.notify
	}
	if sinceSeq >= r.lastSeq {
		return nil, false, r.notify
	}
	if len(r.entries) == 0 || (sinceSeq > 0 && sinceSeq+1 < r.baseSeq) {
		return nil, true, nil
	}
	if sinceSeq == 0 && r.baseSeq > 1 {
		return nil, true, nil
	}

	var out []ReplicationEntry
	for _, e := range r.entries {
		if e.Seq > sinceSeq {
			out = append(out, ReplicationEntry{
				Seq:  e.Seq,
				Args: slices.Clone(e.Args),
				Size: e.Size,
			})
		}
	}
	if len(out) == 0 {
		return nil, false, r.notify
	}
	return out, false, nil
}

// Stats returns the current retained entry count, byte usage, base sequence,
// and latest sequence of the replication backlog.
//
// # Parameters
//
// None.
//
// # Returns
//
// (count, bytes, baseSeq, lastSeq).
//
// # Example
//
//	n, b, base, last := rlog.Stats()
//	_, _, _, _ = n, b, base, last
func (r *ReplicationLog) Stats() (count int, totalBytes int64, baseSeq, lastSeq uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries), r.totalBytes, r.baseSeq, r.lastSeq
}

// ReplicaConfig configures a Replicator streaming mutations from a primary
// concert-kv server into a local Store (and optional local WAL).
type ReplicaConfig struct {
	PrimaryAddr    string
	Password       Secret
	TLSConfig      *tls.Config
	DialTimeout    time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Store          *Store
	WAL            *WAL
	Logger         *slog.Logger
	// OnApply, if non-nil, is invoked synchronously after each snapshot or
	// replicated op commits to Store (with no Replicator locks held).
	OnApply func(seq uint64)
}

// ReplicaStatus snapshots the current runtime health of a Replicator.
type ReplicaStatus struct {
	Connected  bool
	LastSeq    uint64
	FullSyncs  int64
	OpsApplied int64
	Reconnects int64
	LastError  string
}

// Replicator streams snapshots and live operations from a primary concert-kv
// node over TCP, TLS/mTLS, or Unix sockets with bounded exponential backoff
// reconnect (E4). Call Start to launch the background stream and Close to stop
// and join it cleanly (R2).
type Replicator struct {
	cfg ReplicaConfig

	mu        sync.Mutex
	started   bool
	closed    bool
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	connected bool
	lastSeq   uint64
	fullSyncs int64
	opsCount  int64
	reconn    int64
	lastErr   string
}

// NewReplicator validates cfg and creates a stopped *Replicator.
//
// # Parameters
//
//   - cfg: Primary endpoint, optional credentials/TLS, target Store, and timeouts.
//
// # Returns
//
// A *Replicator or an error if PrimaryAddr or Store is missing.
//
// # Example
//
//	rep, err := kv.NewReplicator(kv.ReplicaConfig{
//	    PrimaryAddr: "127.0.0.1:6380",
//	    Store:       replicaStore,
//	})
//	if err != nil {
//	    return err
//	}
//	defer rep.Close()
func NewReplicator(cfg ReplicaConfig) (*Replicator, error) {
	if strings.TrimSpace(cfg.PrimaryAddr) == "" {
		return nil, fmt.Errorf("%w: PrimaryAddr is required", ErrInvalidArg)
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("%w: Store is required", ErrInvalidArg)
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 3 * time.Second
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 15 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 5 * time.Second
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = DefaultReplInitialBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = DefaultReplMaxBackoff
	}
	if cfg.MaxBackoff < cfg.InitialBackoff {
		cfg.MaxBackoff = cfg.InitialBackoff
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Replicator{
		cfg:     cfg,
		lastSeq: cfg.Store.MutationSeq(),
	}, nil
}

// Start launches the single owned replication loop goroutine. Calling Start
// more than once or after Close is a no-op.
//
// # Parameters
//
//   - ctx: Parent lifecycle context; cancelling ctx stops replication.
//
// # Returns
//
// None.
//
// # Example
//
//	rep.Start(ctx)
//	defer rep.Close()
func (r *Replicator) Start(ctx context.Context) {
	r.mu.Lock()
	if r.started || r.closed {
		r.mu.Unlock()
		return
	}
	r.started = true
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.wg.Add(1)
	r.mu.Unlock()

	go func() {
		defer r.wg.Done()
		r.loop(runCtx)
	}()
}

// Close cancels the replication loop and blocks until its goroutine exits.
// Safe to call multiple times (R2).
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
//	rep.Close()
func (r *Replicator) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	cancel := r.cancel
	r.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	r.wg.Wait()
}

// Status returns a point-in-time snapshot of replication state.
//
// # Parameters
//
// None.
//
// # Returns
//
// ReplicaStatus struct.
//
// # Example
//
//	st := rep.Status()
//	fmt.Println(st.Connected, st.LastSeq)
func (r *Replicator) Status() ReplicaStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return ReplicaStatus{
		Connected:  r.connected,
		LastSeq:    r.lastSeq,
		FullSyncs:  r.fullSyncs,
		OpsApplied: r.opsCount,
		Reconnects: r.reconn,
		LastError:  r.lastErr,
	}
}

// loop connects to the primary, streams frames until error or cancellation,
// and reconnects using bounded exponential backoff with jitter (E4).
//
// # Parameters
//
//   - ctx: Cancellation context owned by Start/Close.
//
// # Returns
//
// None.
//
// # Example
//
//	go r.loop(runCtx)
func (r *Replicator) loop(ctx context.Context) {
	backoff := r.cfg.InitialBackoff
	for {
		if ctx.Err() != nil {
			return
		}
		syncedAny, err := r.streamOnce(ctx)
		r.mu.Lock()
		r.connected = false
		if err != nil && ctx.Err() == nil {
			r.lastErr = err.Error()
			r.reconn++
		}
		r.mu.Unlock()

		if ctx.Err() != nil {
			return
		}
		if syncedAny {
			backoff = r.cfg.InitialBackoff
		}
		wait := jitterDuration(backoff)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff *= 2
		if backoff > r.cfg.MaxBackoff {
			backoff = r.cfg.MaxBackoff
		}
	}
}

// streamOnce performs a single primary connection lifecycle: dial, optional
// AUTH, REPL <lastSeq>, and frame processing until EOF, error, or cancel.
//
// # Parameters
//
//   - ctx: Cancellation context.
//
// # Returns
//
// (syncedAny, err) where syncedAny is true if at least one valid replication
// frame was processed during this connection.
//
// # Example
//
//	ok, err := r.streamOnce(ctx)
func (r *Replicator) streamOnce(ctx context.Context) (bool, error) {
	conn, err := dialEndpoint(ctx, r.cfg.PrimaryAddr, r.cfg.TLSConfig, r.cfg.DialTimeout)
	if err != nil {
		return false, fmt.Errorf("dial primary: %w", err)
	}
	defer func() { _ = conn.Close() }()

	stopAbort := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stopAbort()

	br := bufio.NewReaderSize(conn, 32<<10)
	bw := bufio.NewWriterSize(conn, 16<<10)

	// Authenticate before requesting replication stream.
	if !r.cfg.Password.IsZero() {
		if err := conn.SetWriteDeadline(time.Now().Add(r.cfg.WriteTimeout)); err != nil {
			return false, err
		}
		if err := WriteCommand(bw, "AUTH", r.cfg.Password.Reveal()); err != nil {
			return false, fmt.Errorf("write AUTH: %w", err)
		}
		if err := bw.Flush(); err != nil {
			return false, fmt.Errorf("flush AUTH: %w", err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(r.cfg.ReadTimeout)); err != nil {
			return false, err
		}
		reply, err := ReadValue(br, ProtocolLimits{})
		if err != nil {
			return false, fmt.Errorf("read AUTH reply: %w", err)
		}
		if reply.Kind == KindError {
			return false, fmt.Errorf("primary AUTH failed: %s", reply.Str)
		}
	}

	r.mu.Lock()
	sinceSeq := r.lastSeq
	r.mu.Unlock()

	if err := conn.SetWriteDeadline(time.Now().Add(r.cfg.WriteTimeout)); err != nil {
		return false, err
	}
	if err := WriteCommand(bw, "REPL", strconv.FormatUint(sinceSeq, 10)); err != nil {
		return false, fmt.Errorf("write REPL: %w", err)
	}
	if err := bw.Flush(); err != nil {
		return false, fmt.Errorf("flush REPL: %w", err)
	}

	r.mu.Lock()
	r.connected = true
	r.lastErr = ""
	r.mu.Unlock()

	replLimits := ProtocolLimits{
		MaxBulkBytes: maxSnapshotBytes,
		MaxArrayLen:  DefaultMaxArrayLen,
	}
	syncedAny := false
	for {
		if ctx.Err() != nil {
			return syncedAny, ctx.Err()
		}
		if err := conn.SetReadDeadline(time.Now().Add(r.cfg.ReadTimeout)); err != nil {
			return syncedAny, err
		}
		frame, err := ReadValue(br, replLimits)
		if err != nil {
			return syncedAny, err
		}
		if frame.Kind == KindError {
			return syncedAny, fmt.Errorf("primary replication error: %s", frame.Str)
		}
		if frame.Kind != KindArray || len(frame.Array) < 3 {
			return syncedAny, fmt.Errorf("%w: invalid replication frame", ErrProtocol)
		}
		tag, _ := frame.Array[0].AsString()
		kind, _ := frame.Array[1].AsString()
		if tag != "REPL" {
			return syncedAny, fmt.Errorf("%w: unexpected replication frame tag %q", ErrProtocol, tag)
		}
		seq := uint64(frame.Array[2].Int)
		switch kind {
		case "SNAPSHOT":
			if len(frame.Array) != 4 {
				return syncedAny, fmt.Errorf("%w: malformed SNAPSHOT frame", ErrProtocol)
			}
			raw, ok := frame.Array[3].StringBytes()
			if !ok {
				return syncedAny, fmt.Errorf("%w: SNAPSHOT payload not bulk string", ErrProtocol)
			}
			snap, err := DecodeSnapshot(raw)
			if err != nil {
				return syncedAny, fmt.Errorf("decode primary snapshot: %w", err)
			}
			if err := r.cfg.Store.LoadSnapshot(snap); err != nil {
				return syncedAny, fmt.Errorf("apply primary snapshot: %w", err)
			}
			if r.cfg.WAL != nil {
				if err := r.cfg.WAL.Compact(r.cfg.Store); err != nil {
					return syncedAny, fmt.Errorf("compact replica wal: %w", err)
				}
			}
			r.mu.Lock()
			r.lastSeq = seq
			r.fullSyncs++
			r.mu.Unlock()
			if r.cfg.OnApply != nil {
				r.cfg.OnApply(seq)
			}
			syncedAny = true

		case "OP":
			if len(frame.Array) < 4 {
				return syncedAny, fmt.Errorf("%w: malformed OP frame", ErrProtocol)
			}
			args := make([]string, 0, len(frame.Array)-3)
			for _, elem := range frame.Array[3:] {
				s, ok := elem.AsString()
				if !ok {
					return syncedAny, fmt.Errorf("%w: OP arg not string", ErrProtocol)
				}
				args = append(args, s)
			}
			reply, _, _ := r.cfg.Store.Execute(args)
			if reply.Kind == KindError {
				return syncedAny, fmt.Errorf("apply replicated op %s: %s", args[0], reply.Str)
			}
			if seq > r.cfg.Store.MutationSeq() {
				r.cfg.Store.mutations.Store(seq)
			}
			if r.cfg.WAL != nil {
				if err := r.cfg.WAL.Append(seq, args); err != nil {
					return syncedAny, fmt.Errorf("append replica wal: %w", err)
				}
			}
			r.mu.Lock()
			r.lastSeq = seq
			r.opsCount++
			r.mu.Unlock()
			if r.cfg.OnApply != nil {
				r.cfg.OnApply(seq)
			}
			syncedAny = true

		case "PING":
			syncedAny = true

		default:
			return syncedAny, fmt.Errorf("%w: unknown replication kind %q", ErrProtocol, kind)
		}
	}
}

// dialEndpoint opens a Unix domain socket or TCP/TLS connection to addr.
// Addresses beginning with "unix://" or "/" dial as Unix sockets; all others
// dial TCP (wrapping with TLS when tlsCfg != nil).
//
// # Parameters
//
//   - ctx: Cancellation and deadline context.
//   - addr: Endpoint address ("unix:///path", "/path", or "host:port").
//   - tlsCfg: Optional TLS configuration for TCP connections.
//   - timeout: Dial timeout when ctx has no earlier deadline.
//
// # Returns
//
// Connected net.Conn or dial/TLS handshake error.
//
// # Example
//
//	conn, err := dialEndpoint(ctx, "127.0.0.1:6380", nil, 2*time.Second)
func dialEndpoint(ctx context.Context, addr string, tlsCfg *tls.Config, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	if strings.HasPrefix(addr, "unix://") || strings.HasPrefix(addr, "/") {
		sockPath := strings.TrimPrefix(addr, "unix://")
		return dialer.DialContext(ctx, "unix", sockPath)
	}
	if tlsCfg != nil {
		cfg := tlsCfg.Clone()
		if cfg.MinVersion < tls.VersionTLS12 {
			cfg.MinVersion = tls.VersionTLS12
		}
		if cfg.ServerName == "" {
			if host, _, err := net.SplitHostPort(addr); err == nil {
				cfg.ServerName = host
			}
		}
		return (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, "tcp", addr)
	}
	return dialer.DialContext(ctx, "tcp", addr)
}

// jitterDuration applies ±25% cryptographic jitter to base to prevent
// thundering-herd reconnect storms across replicas (E4).
//
// # Parameters
//
//   - base: Nominal backoff duration; must be positive.
//
// # Returns
//
// Jittered duration in [0.75*base, 1.25*base].
//
// # Example
//
//	d := jitterDuration(200 * time.Millisecond)
func jitterDuration(base time.Duration) time.Duration {
	if base <= 0 {
		return time.Millisecond
	}
	var b [8]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return base
	}
	// Map random uint64 uniformly into [0.75, 1.25].
	frac := float64(binary.BigEndian.Uint64(b[:])%(1<<20)) / float64(1<<20)
	mult := 0.75 + 0.5*frac
	return time.Duration(float64(base) * mult)
}
