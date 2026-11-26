//go:build enterprise

package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/concert/internal/acme"
	"github.com/andreimerlescu/concert/internal/bidding"
	"github.com/andreimerlescu/concert/internal/drop"
	"github.com/andreimerlescu/concert/internal/kv"
)

// Distributed cluster state synchronization over concert-kv (RESP2-compatible
// with concert-kv, Redis, and Valkey; pure Go stdlib, zero external deps).
//
// When -kv-addr / CONCERT_KV_ADDR (or legacy -redis-addr / CONCERT_REDIS_ADDR)
// is set, multiple Concert nodes synchronize abuse bans and unbans in near real
// time via Pub/Sub, persist active bans in a hash for node hydration,
// deduplicate cluster email alerts, coordinate fast-lane revocations and
// settlement leases, optionally mirror shared waiting-room queue state
// (-kv-shared-queue), and optionally sync encrypted ACME wildcard certificate
// bundles.
//
// Fail-open guarantee: if concert-kv is unreachable or restarts, Concert
// continues operating with local in-memory state, increments clusterSyncErrors,
// and reconnects automatically with exponential backoff.

type clusterConfig struct {
	addr        string
	password    kv.Secret
	useTLS      bool
	prefix      string
	sharedQueue bool
	queueScope  string
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

type fastlaneRevokeItem struct {
	id  string
	ttl time.Duration
}

type sharedQueueJoinItem struct {
	ticket    string
	clientKey string
	ttl       time.Duration
}

type clusterSync struct {
	cfg    clusterConfig
	nodeID string
	client *kv.Client
	abuse  *abuseRegistry
	stats  *counters
	onDrop func(netip.Prefix)

	out         chan clusterBanEvent
	dedupeCh    chan emailDedupeItem
	revokeCh    chan fastlaneRevokeItem
	queueJoinCh chan sharedQueueJoinItem

	ctx      context.Context
	cancel   context.CancelFunc
	stop     chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
	applying atomic.Int32
}

// newClusterSync builds a clusterSync backed by a pooled internal/kv.Client and
// starts its bounded background publisher, subscriber, email-dedupe,
// fastlane-revocation, and optional shared-queue mirror workers (R2).
//
// # Parameters
//
//   - cfg: KV endpoint, optional redacting password, TLS flag, key prefix, and
//     shared-queue toggle. An empty cfg.addr disables cluster sync and returns nil.
//   - abuse: Local abuse registry updated when peer ban/unban events arrive.
//   - stats: Shared counters updated on sync sends, receives, and errors.
//   - onDrop: Optional callback dropping queued visitors matching a peer ban scope.
//
// # Returns
//
// A running *clusterSync (caller must invoke close), or nil when disabled.
//
// # Example
//
//	cs := newClusterSync(cfg.effectiveKVConfig(), a.abuse, a.stats, a.queueDrop)
//	if cs != nil {
//	    defer cs.close()
//	}
func newClusterSync(cfg clusterConfig, abuse *abuseRegistry, stats *counters, onDrop func(netip.Prefix)) *clusterSync {
	addr := strings.TrimSpace(cfg.addr)
	if addr == "" {
		return nil
	}
	cfg.addr = addr
	if strings.TrimSpace(cfg.prefix) == "" {
		cfg.prefix = "concert"
	}
	var tlsCfg *tls.Config
	if cfg.useTLS {
		host, _, _ := net.SplitHostPort(cfg.addr)
		tlsCfg = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: host,
		}
	}
	client, err := kv.NewClient(kv.ClientConfig{
		Addr:         cfg.addr,
		Password:     cfg.password,
		TLSConfig:    tlsCfg,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		FailOpen:     false,
	})
	if err != nil {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cs := &clusterSync{
		cfg:         cfg,
		nodeID:      randomHex(8),
		client:      client,
		abuse:       abuse,
		stats:       stats,
		onDrop:      onDrop,
		out:         make(chan clusterBanEvent, 1024),
		dedupeCh:    make(chan emailDedupeItem, 256),
		revokeCh:    make(chan fastlaneRevokeItem, 256),
		queueJoinCh: make(chan sharedQueueJoinItem, 1024),
		ctx:         ctx,
		cancel:      cancel,
		stop:        make(chan struct{}),
	}
	cs.wg.Add(4)
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
	go func() {
		defer cs.wg.Done()
		cs.auxWorkerLoop()
	}()
	return cs
}

func (cs *clusterSync) emailDedupeKey(fingerprint string) string {
	sum := sha256.Sum256([]byte(fingerprint))
	return cs.cfg.prefix + ":email:fp:" + hex.EncodeToString(sum[:16])
}

// claimEmailAsync deduplicates cluster-shared email alert fingerprints across
// KV peers without ever blocking the caller. Fail-open: if concert-kv is down,
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
	for {
		select {
		case <-cs.stop:
			return
		case item := <-cs.dedupeCh:
			opCtx, cancel := context.WithTimeout(cs.ctx, 2*time.Second)
			claimed, err := cs.client.Set(opCtx, cs.emailDedupeKey(item.fingerprint), []byte(cs.nodeID), kv.SetOptions{
				NX:  true,
				TTL: item.ttl,
			})
			cancel()
			if err != nil {
				if cs.stats != nil {
					cs.stats.clusterSyncErrors.Add(1)
				}
				item.onAllow() // fail open
				continue
			}
			if !claimed {
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

func (cs *clusterSync) auxWorkerLoop() {
	for {
		select {
		case <-cs.stop:
			return
		case item := <-cs.revokeCh:
			opCtx, cancel := context.WithTimeout(cs.ctx, 2*time.Second)
			_, err := cs.client.Set(opCtx, cs.fastlaneRevokeKey(item.id), []byte("1"), kv.SetOptions{
				TTL: item.ttl,
			})
			cancel()
			if err != nil && cs.stats != nil {
				cs.stats.clusterSyncErrors.Add(1)
			}
		case item := <-cs.queueJoinCh:
			if !cs.cfg.sharedQueue {
				continue
			}
			opCtx, cancel := context.WithTimeout(cs.ctx, 1*time.Second)
			_, err := cs.client.CQJoin(opCtx, cs.sharedQueueName(), item.ticket, item.clientKey, item.ttl, 0)
			cancel()
			if err != nil && cs.stats != nil {
				cs.stats.clusterSyncErrors.Add(1)
			}
		}
	}
}

func (cs *clusterSync) channelName() string {
	return cs.cfg.prefix + ":bans:events"
}

func (cs *clusterSync) hashKey() string {
	return cs.cfg.prefix + ":bans:state"
}

func (cs *clusterSync) sharedQueueName() string {
	scope := strings.TrimSpace(cs.cfg.queueScope)
	if scope == "" {
		scope = "default"
	}
	return cs.cfg.prefix + ":queue:" + scope
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
		cs.cancel()
		close(cs.stop)
		cs.wg.Wait()
		_ = cs.client.Close()
	})
}

func (cs *clusterSync) publishLoop() {
	for {
		select {
		case <-cs.stop:
			return
		case ev := <-cs.out:
			payload, _ := json.Marshal(ev)
			opCtx, cancel := context.WithTimeout(cs.ctx, 3*time.Second)
			var err error
			if ev.Action == "ban" {
				_, err = cs.client.HSet(opCtx, cs.hashKey(), map[string][]byte{ev.Client: payload})
			} else {
				_, err = cs.client.HDel(opCtx, cs.hashKey(), ev.Client)
			}
			if err == nil {
				_, err = cs.client.Publish(opCtx, cs.channelName(), payload)
			}
			cancel()
			if err != nil {
				if cs.stats != nil {
					cs.stats.clusterSyncErrors.Add(1)
				}
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

		// Subscribe BEFORE hydrating so bans published concurrently while a
		// node starts cannot fall into a gap between HGETALL and SUBSCRIBE.
		sub, err := cs.client.Subscribe(cs.ctx, cs.channelName())
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

		hydCtx, hydCancel := context.WithTimeout(cs.ctx, 3*time.Second)
		hydErr := cs.hydrate(hydCtx)
		hydCancel()
		if hydErr != nil {
			sub.Close()
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

		for {
			select {
			case <-cs.stop:
				sub.Close()
				return
			case msg, ok := <-sub.Messages():
				if !ok {
					goto reconnect
				}
				if len(msg.Payload) == 0 {
					continue
				}
				var ev clusterBanEvent
				if err := json.Unmarshal(msg.Payload, &ev); err != nil {
					continue
				}
				if ev.Origin == cs.nodeID {
					continue
				}
				cs.applyEvent(ev)
			}
		}
	reconnect:
		sub.Close()
	}
}

func (cs *clusterSync) hydrate(ctx context.Context) error {
	all, err := cs.client.HGetAll(ctx, cs.hashKey())
	if err != nil {
		return err
	}
	for _, raw := range all {
		var ev clusterBanEvent
		if json.Unmarshal(raw, &ev) == nil && ev.Origin != cs.nodeID {
			cs.applyEvent(ev)
		}
	}
	return nil
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

// ─── Shared Waiting-Room Queue Mirror (Fail-Open) ────────────────────────────

// recordQueueJoinAsync mirrors a newly queued waiting-room ticket into
// concert-kv via CQ.JOIN without blocking the caller. Fail-open: when
// sharedQueue is false, the channel is full, or concert-kv is unavailable,
// local waiting-room serving continues uninterrupted.
func (cs *clusterSync) recordQueueJoinAsync(ticket, clientKey string, ttl time.Duration) {
	if cs == nil || !cs.cfg.sharedQueue || ticket == "" {
		return
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	select {
	case <-cs.stop:
	case cs.queueJoinCh <- sharedQueueJoinItem{ticket: ticket, clientKey: clientKey, ttl: ttl}:
	default:
		if cs.stats != nil {
			cs.stats.clusterSyncErrors.Add(1)
		}
	}
}

// purgeSharedQueue clears tickets from concert-kv's shared waiting-room queue.
// Fail-open: errors are counted and never block local queue clearing.
func (cs *clusterSync) purgeSharedQueue(ctx context.Context, mode string) {
	if cs == nil || !cs.cfg.sharedQueue {
		return
	}
	if ctx == nil {
		ctx = cs.ctx
	}
	opCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	if _, err := cs.client.CQPurge(opCtx, cs.sharedQueueName(), mode, ""); err != nil && cs.stats != nil {
		cs.stats.clusterSyncErrors.Add(1)
	}
}

// sharedQueueStats queries concert-kv for shared waiting-room statistics.
// Returns (stats, true) on success or (Degraded: true, false) when disabled or
// unreachable so callers cleanly fall back to local room stats.
func (cs *clusterSync) sharedQueueStats(ctx context.Context) (kv.CQQueueStats, bool) {
	if cs == nil || !cs.cfg.sharedQueue {
		return kv.CQQueueStats{}, false
	}
	if ctx == nil {
		ctx = cs.ctx
	}
	opCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	st, err := cs.client.CQStats(opCtx, cs.sharedQueueName())
	if err != nil {
		if cs.stats != nil {
			cs.stats.clusterSyncErrors.Add(1)
		}
		return kv.CQQueueStats{Degraded: true}, false
	}
	return st, true
}

// ─── ACME Encrypted Certificate Bundle Sync Adapter ──────────────────────────

// acmeKVAdapter adapts *kv.Client to internal/acme.KVBundleSync so multi-edge
// deployments share encrypted ACME certificate bundles through concert-kv.
type acmeKVAdapter struct {
	client *kv.Client
}

func (a acmeKVAdapter) Get(ctx context.Context, key string) ([]byte, bool, error) {
	return a.client.Get(ctx, key)
}

func (a acmeKVAdapter) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	_, err := a.client.Set(ctx, key, val, kv.SetOptions{TTL: ttl})
	return err
}

func (cs *clusterSync) acmeBundleSync() acme.KVBundleSync {
	if cs == nil || cs.client == nil {
		return nil
	}
	return acmeKVAdapter{client: cs.client}
}

// dropKVAdapter adapts *kv.Client to internal/drop.StateSync so multi-edge
// deployments share one canonical scheduled drop state and shuffled cohort.
type dropKVAdapter struct {
	client *kv.Client
	prefix string
}

func (a dropKVAdapter) Save(ctx context.Context, key string, payload []byte, ttl time.Duration) error {
	_, err := a.client.Set(ctx, a.prefix+":"+key, payload, kv.SetOptions{TTL: ttl})
	return err
}

func (a dropKVAdapter) Load(ctx context.Context, key string) ([]byte, bool, error) {
	return a.client.Get(ctx, a.prefix+":"+key)
}

func (cs *clusterSync) dropStateSync() drop.StateSync {
	if cs == nil || cs.client == nil {
		return nil
	}
	return dropKVAdapter{client: cs.client, prefix: cs.cfg.prefix}
}

// biddingKVAdapter adapts *kv.Client to internal/bidding.ClusterSync via CQ.BID.
type biddingKVAdapter struct {
	client *kv.Client
	prefix string
}

func (a biddingKVAdapter) SyncBid(ctx context.Context, scope, bidID string, normalizedMicroUSD int64) error {
	_, err := a.client.CQBid(ctx, a.prefix+":bid:"+scope, bidID, normalizedMicroUSD)
	return err
}

func (cs *clusterSync) biddingClusterSync() bidding.ClusterSync {
	if cs == nil || cs.client == nil {
		return nil
	}
	return biddingKVAdapter{client: cs.client, prefix: cs.cfg.prefix}
}

// ─── Cross-Edge Fast-Lane Revocation & Settlement Deduplication (Fail-Open) ──

func (cs *clusterSync) fastlaneRevokeKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	return cs.cfg.prefix + ":fl:rev:" + hex.EncodeToString(sum[:16])
}

func (cs *clusterSync) fastlaneSettleKey(fp string) string {
	return cs.cfg.prefix + ":fl:settle:" + fp
}

// isFastlaneRevoked checks concert-kv for a revoked pass/session ID. Fail-open on KV error.
func (cs *clusterSync) isFastlaneRevoked(id string) bool {
	if cs == nil || id == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(cs.ctx, 500*time.Millisecond)
	defer cancel()
	n, err := cs.client.Exists(ctx, cs.fastlaneRevokeKey(id))
	if err != nil {
		return false
	}
	return n > 0
}

// publishFastlaneRevoke records a revoked pass/session ID in concert-kv with TTL
// via the bounded auxiliary worker loop (R2, R3).
func (cs *clusterSync) publishFastlaneRevoke(id string, ttl time.Duration) {
	if cs == nil || id == "" {
		return
	}
	if ttl < time.Minute {
		ttl = time.Minute
	}
	select {
	case <-cs.stop:
	case cs.revokeCh <- fastlaneRevokeItem{id: id, ttl: ttl}:
	default:
		if cs.stats != nil {
			cs.stats.clusterSyncErrors.Add(1)
		}
	}
}

// claimFastlaneSettlement attempts an atomic SET NX EX to prevent two
// active-active edges from settling the identical payment fingerprint concurrently.
// Fail-open on KV error so local single-writer settlement never stalls.
func (cs *clusterSync) claimFastlaneSettlement(fp string) (bool, error) {
	if cs == nil || fp == "" {
		return true, nil
	}
	ctx, cancel := context.WithTimeout(cs.ctx, time.Second)
	defer cancel()
	claimed, err := cs.client.Set(ctx, cs.fastlaneSettleKey(fp), []byte(cs.nodeID), kv.SetOptions{
		NX:  true,
		TTL: 600 * time.Second,
	})
	if err != nil {
		return true, err
	}
	return claimed, nil
}
