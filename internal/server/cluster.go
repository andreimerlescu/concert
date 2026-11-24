//go:build enterprise

package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Distributed cluster state synchronization over Redis/Valkey RESP2 (pure Go
// stdlib, zero external dependencies).
//
// When CONCERT_REDIS_ADDR is set, multiple Concert nodes synchronize abuse bans
// and unbans in near real time via Redis Pub/Sub and persist active bans in a
// Redis hash so newly started nodes hydrate cluster bans automatically.
//
// Fail-open guarantee: if Redis is unreachable or restarts, Concert continues
// operating with local in-memory state, increments clusterSyncErrors, and
// reconnects automatically with exponential backoff.

type clusterConfig struct {
	addr     string
	password string
	useTLS   bool
	prefix   string
}

type clusterBanEvent struct {
	Origin    string `json:"origin"`
	Action    string `json:"action"` // "ban" | "unban"
	Client    string `json:"client"`
	UntilUnix int64  `json:"until_unix,omitempty"`
	Permanent bool   `json:"permanent,omitempty"`
	Offenses  int    `json:"offenses,omitempty"`
}

type emailDedupeItem struct {
	fingerprint string
	ttl         time.Duration
	onAllow     func()
}

type clusterSync struct {
	cfg    clusterConfig
	nodeID string
	abuse  *abuseRegistry
	stats  *counters
	onDrop func(netip.Prefix)

	out      chan clusterBanEvent
	dedupeCh chan emailDedupeItem
	stop     chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
	applying atomic.Int32
}

func newClusterSync(cfg clusterConfig, abuse *abuseRegistry, stats *counters, onDrop func(netip.Prefix)) *clusterSync {
	if strings.TrimSpace(cfg.addr) == "" {
		return nil
	}
	if cfg.prefix == "" {
		cfg.prefix = "concert"
	}
	cs := &clusterSync{
		cfg:      cfg,
		nodeID:   randomHex(8),
		abuse:    abuse,
		stats:    stats,
		onDrop:   onDrop,
		out:      make(chan clusterBanEvent, 1024),
		dedupeCh: make(chan emailDedupeItem, 256),
		stop:     make(chan struct{}),
	}
	cs.wg.Add(3)
	go func() {
		defer cs.wg.Done()
		cs.publishLoop()
	}()
	go func() {
		defer cs.wg.Done()
		cs.subscribeLoop()
	}()
	go func() {
		defer cs.wg.Done()
		cs.emailDedupeLoop()
	}()
	return cs
}

func (cs *clusterSync) emailDedupeKey(fingerprint string) string {
	sum := sha256.Sum256([]byte(fingerprint))
	return cs.cfg.prefix + ":email:fp:" + hex.EncodeToString(sum[:16])
}

// claimEmailAsync deduplicates cluster-shared email alert fingerprints across
// Redis peers without ever blocking the caller. Fail-open: if Redis is down,
// slow, or the queue is saturated, onAllow runs locally so alerts are never lost.
func (cs *clusterSync) claimEmailAsync(fingerprint string, ttl time.Duration, onAllow func()) {
	if cs == nil || onAllow == nil {
		if onAllow != nil {
			onAllow()
		}
		return
	}
	if ttl < time.Second {
		ttl = time.Minute
	}
	select {
	case <-cs.stop:
		onAllow()
	case cs.dedupeCh <- emailDedupeItem{fingerprint: fingerprint, ttl: ttl, onAllow: onAllow}:
	default:
		onAllow()
	}
}

func (cs *clusterSync) emailDedupeLoop() {
	var rc *respConn
	defer func() {
		if rc != nil {
			_ = rc.close()
		}
	}()
	for {
		select {
		case <-cs.stop:
			return
		case item := <-cs.dedupeCh:
			if rc == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				c, err := cs.dial(ctx)
				cancel()
				if err != nil {
					if cs.stats != nil {
						cs.stats.clusterSyncErrors.Add(1)
					}
					item.onAllow()
					continue
				}
				rc = c
			}
			ms := strconv.FormatInt(item.ttl.Milliseconds(), 10)
			val, err := rc.do("SET", cs.emailDedupeKey(item.fingerprint), cs.nodeID, "NX", "PX", ms)
			if err != nil {
				if cs.stats != nil {
					cs.stats.clusterSyncErrors.Add(1)
				}
				_ = rc.close()
				rc = nil
				item.onAllow() // fail open
				continue
			}
			if val == nil {
				// Key already claimed by another peer within this window.
				if cs.stats != nil {
					cs.stats.emailClusterDeduped.Add(1)
				}
				continue
			}
			item.onAllow()
		}
	}
}

func (cs *clusterSync) channelName() string {
	return cs.cfg.prefix + ":bans:events"
}

func (cs *clusterSync) hashKey() string {
	return cs.cfg.prefix + ":bans:state"
}

func (cs *clusterSync) publishBan(target banTarget, until int64, offenses int) {
	if cs == nil || cs.applying.Load() > 0 {
		return
	}
	ev := clusterBanEvent{
		Origin:    cs.nodeID,
		Action:    "ban",
		Client:    target.String(),
		Permanent: until == banForever,
		Offenses:  offenses,
	}
	if !ev.Permanent {
		ev.UntilUnix = time.Unix(0, until).Unix()
	}
	select {
	case cs.out <- ev:
	default:
		if cs.stats != nil {
			cs.stats.clusterSyncErrors.Add(1)
		}
	}
}

func (cs *clusterSync) publishUnban(target banTarget) {
	if cs == nil {
		return
	}
	ev := clusterBanEvent{
		Origin: cs.nodeID,
		Action: "unban",
		Client: target.String(),
	}
	select {
	case cs.out <- ev:
	default:
		if cs.stats != nil {
			cs.stats.clusterSyncErrors.Add(1)
		}
	}
}

func (cs *clusterSync) close() {
	if cs == nil {
		return
	}
	cs.once.Do(func() {
		close(cs.stop)
		cs.wg.Wait()
	})
}

func (cs *clusterSync) dial(ctx context.Context) (*respConn, error) {
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	var conn net.Conn
	var err error
	if cs.cfg.useTLS {
		host, _, _ := net.SplitHostPort(cs.cfg.addr)
		conn, err = (&tls.Dialer{
			NetDialer: dialer,
			Config:    &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host},
		}).DialContext(ctx, "tcp", cs.cfg.addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", cs.cfg.addr)
	}
	if err != nil {
		return nil, err
	}
	rc := &respConn{conn: conn, r: bufio.NewReader(conn)}
	if cs.cfg.password != "" {
		if _, err := rc.do("AUTH", cs.cfg.password); err != nil {
			_ = rc.close()
			return nil, fmt.Errorf("redis AUTH: %w", err)
		}
	}
	return rc, nil
}

func (cs *clusterSync) publishLoop() {
	var rc *respConn
	defer func() {
		if rc != nil {
			_ = rc.close()
		}
	}()

	for {
		select {
		case <-cs.stop:
			return
		case ev := <-cs.out:
			if rc == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				c, err := cs.dial(ctx)
				cancel()
				if err != nil {
					if cs.stats != nil {
						cs.stats.clusterSyncErrors.Add(1)
					}
					continue
				}
				rc = c
			}
			payload, _ := json.Marshal(ev)
			var err error
			if ev.Action == "ban" {
				_, err = rc.do("HSET", cs.hashKey(), ev.Client, string(payload))
			} else {
				_, err = rc.do("HDEL", cs.hashKey(), ev.Client)
			}
			if err == nil {
				_, err = rc.do("PUBLISH", cs.channelName(), string(payload))
			}
			if err != nil {
				if cs.stats != nil {
					cs.stats.clusterSyncErrors.Add(1)
				}
				_ = rc.close()
				rc = nil
				continue
			}
			if cs.stats != nil {
				cs.stats.clusterSyncSent.Add(1)
			}
		}
	}
}

func (cs *clusterSync) subscribeLoop() {
	backoff := 250 * time.Millisecond
	for {
		select {
		case <-cs.stop:
			return
		default:
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		rc, err := cs.dial(ctx)
		cancel()
		if err != nil {
			if cs.stats != nil {
				cs.stats.clusterSyncErrors.Add(1)
			}
			if !cs.sleepBackoff(backoff) {
				return
			}
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 250 * time.Millisecond

		// Hydrate existing cluster bans before subscribing.
		cs.hydrate(rc)

		if _, err := rc.do("SUBSCRIBE", cs.channelName()); err != nil {
			_ = rc.close()
			if cs.stats != nil {
				cs.stats.clusterSyncErrors.Add(1)
			}
			continue
		}

		// Close connection promptly when stop is closed so Read unblocks.
		done := make(chan struct{})
		go func() {
			select {
			case <-cs.stop:
				_ = rc.close()
			case <-done:
			}
		}()

		for {
			_ = rc.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			val, err := rc.readReply()
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				break
			}
			arr, ok := val.([]any)
			if !ok || len(arr) != 3 {
				continue
			}
			kind, _ := arr[0].(string)
			msg, _ := arr[2].(string)
			if kind != "message" || msg == "" {
				continue
			}
			var ev clusterBanEvent
			if err := json.Unmarshal([]byte(msg), &ev); err != nil {
				continue
			}
			if ev.Origin == cs.nodeID {
				continue
			}
			cs.applyEvent(ev)
		}
		close(done)
		_ = rc.close()
	}
}

func (cs *clusterSync) hydrate(rc *respConn) {
	val, err := rc.do("HGETALL", cs.hashKey())
	if err != nil {
		return
	}
	arr, ok := val.([]any)
	if !ok {
		return
	}
	for i := 0; i+1 < len(arr); i += 2 {
		raw, _ := arr[i+1].(string)
		var ev clusterBanEvent
		if json.Unmarshal([]byte(raw), &ev) == nil && ev.Origin != cs.nodeID {
			cs.applyEvent(ev)
		}
	}
}

func (cs *clusterSync) applyEvent(ev clusterBanEvent) {
	if cs.abuse == nil {
		return
	}
	cs.applying.Add(1)
	defer cs.applying.Add(-1)
	t, err := parseBanTarget(ev.Client)
	if err != nil {
		return
	}
	now := time.Now()
	switch ev.Action {
	case "ban":
		var d time.Duration
		if !ev.Permanent {
			d = time.Until(time.Unix(ev.UntilUnix, 0))
			if d <= 0 {
				return
			}
		}
		if t.single {
			if _, err := cs.abuse.banFor(t.prefix.Addr(), d, now); err == nil && cs.onDrop != nil {
				cs.onDrop(t.scope())
			}
		} else {
			if err := cs.abuse.banRange(t.prefix, d, now); err == nil && cs.onDrop != nil {
				cs.onDrop(t.scope())
			}
		}
	case "unban":
		cs.abuse.unbanTarget(t)
	default:
		return
	}
	if cs.stats != nil {
		cs.stats.clusterSyncRecv.Add(1)
	}
}

func (cs *clusterSync) sleepBackoff(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-cs.stop:
		return false
	case <-t.C:
		return true
	}
}

// ─── Minimal RESP2 Wire Protocol Client ──────────────────────────────────────

type respConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func (c *respConn) close() error {
	return c.conn.Close()
}

func (c *respConn) do(args ...string) (any, error) {
	_ = c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	var sb strings.Builder
	fmt.Fprintf(&sb, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&sb, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := io.WriteString(c.conn, sb.String()); err != nil {
		return nil, err
	}
	return c.readReply()
}

func (c *respConn) readReply() (any, error) {
	line, err := c.r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 {
		return nil, errors.New("malformed RESP reply")
	}
	body := strings.TrimSuffix(strings.TrimSuffix(line[1:], "\n"), "\r")
	switch line[0] {
	case '+':
		return body, nil
	case '-':
		return nil, errors.New("redis error: " + body)
	case ':':
		return strconv.ParseInt(body, 10, 64)
	case '$':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(c.r, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		out := make([]any, n)
		for i := 0; i < n; i++ {
			v, err := c.readReply()
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	default:
		log.Printf("cluster: unexpected RESP prefix %q", line[0])
		return nil, errors.New("unexpected RESP prefix")
	}
}

// ─── Cross-Edge Fast-Lane Revocation & Settlement Deduplication (Fail-Open) ──

func (cs *clusterSync) fastlaneRevokeKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	return cs.cfg.prefix + ":fl:rev:" + hex.EncodeToString(sum[:16])
}

func (cs *clusterSync) fastlaneSettleKey(fp string) string {
	return cs.cfg.prefix + ":fl:settle:" + fp
}

// isFastlaneRevoked checks Redis for a revoked pass/session ID. Fail-open on Redis error.
func (cs *clusterSync) isFastlaneRevoked(id string) bool {
	if cs == nil || id == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	rc, err := cs.dial(ctx)
	if err != nil {
		return false
	}
	defer rc.close()
	res, err := rc.do("EXISTS", cs.fastlaneRevokeKey(id))
	if err != nil {
		return false
	}
	n, _ := res.(int64)
	return n > 0
}

// publishFastlaneRevoke records a revoked pass/session ID in Redis with TTL.
func (cs *clusterSync) publishFastlaneRevoke(id string, ttl time.Duration) {
	if cs == nil || id == "" {
		return
	}
	secs := int64(ttl.Seconds())
	if secs < 60 {
		secs = 60
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		rc, err := cs.dial(ctx)
		if err != nil {
			return
		}
		defer rc.close()
		_, _ = rc.do("SET", cs.fastlaneRevokeKey(id), "1", "EX", strconv.FormatInt(secs, 10))
	}()
}

// claimFastlaneSettlement attempts an atomic Redis SET NX EX to prevent two
// active-active edges from settling the identical payment fingerprint concurrently.
// Fail-open on Redis error so local single-writer settlement never stalls.
func (cs *clusterSync) claimFastlaneSettlement(fp string) (bool, error) {
	if cs == nil || fp == "" {
		return true, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rc, err := cs.dial(ctx)
	if err != nil {
		return true, err
	}
	defer rc.close()
	res, err := rc.do("SET", cs.fastlaneSettleKey(fp), cs.nodeID, "NX", "EX", "600")
	if err != nil {
		return true, err
	}
	s, ok := res.(string)
	return ok && strings.EqualFold(s, "OK"), nil
}
