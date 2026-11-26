package server

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/room"
	"github.com/gin-gonic/gin"
)

// app is concert's long-lived state plus the generation currently serving
// requests; see reload.go. The waiting room, the abuse registry, the
// admission pass signer, the priority grants, the IP database and the
// counters live as long as the process. Everything built from settings lives
// in the generation and is replaced when a setting changes.
type app struct {
	enterpriseAppState

	// agentOffer is the fast-lane offer a queued agent is shown, or nil
	// without payment offers; see agent.go. Atomically refreshed on live fast-lane config edits.
	agentOffer atomic.Pointer[agentOffer]

	cfg       config // as concert started; the running configuration is current().cfg
	room      *room.WaitingRoom
	stats     *counters
	admit     *admitter
	abuse     *abuseRegistry // always present; current().abuse is nil while -abuse=false
	prio      *priorityState // rank grants and counters; see priority.go
	handler   http.Handler   // serves every request with the current generation
	settings  *settingsManager
	drops     *dropper      // bans waiting to be removed from the line; see queue.go
	agents    *agentPlaces  // which address holds each keyed place; see agent.go
	bansPath  string        // bans.json, or "" when bans are not persisted
	queuePath string        // saved queue, or "" when the queue is not persisted
	rateBits  atomic.Uint64 // skip-the-line base price, float64 bits
	surgeBits atomic.Uint64 // skip-the-line surge, float64 bits
	gen       atomic.Pointer[generation]

	// ipinfo answers who owns an address, from naddr's ess package; see
	// ipinfo.go. Always present; it reports "off" when neither NADDR_DATA
	// nor NADDR_ADDR is usable.
	ipinfo *ipLookup

	// history is the portal's request history, set by newPortal; nil when
	// the portal is off. See history.go.
	history *history

	// draining flips true once shutdown starts so /_room/readyz returns 503.
	draining atomic.Bool

	// runtimeCapOverride is true when -config mode has an emergency live cap
	// override applied from the Portal/API (cleared on SIGHUP / reload).
	runtimeCapOverride atomic.Bool

	// skipQueueSave suppresses saveQueue in Close when an app is retired by a
	// multi-vhost hot reload so no orphaned queue.snapshot is written after the
	// replacement site app has already started.
	skipQueueSave atomic.Bool

	// Listeners, set by run once serving starts; guarded by settings.mu.
	mainEP, portalEP *endpoint

	closeMu sync.Mutex
	closers []func() // run by Close, newest first, after the background loops stop

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup // background writers and the drop loop, awaited on Close
}

// newApp builds the waiting room, abuse registry, admission signer, priority
// grants, the IP database and the first generation without binding a port.
// With -data-dir set it also restores bans.json and the saved queue, and
// starts the ban writer. Callers must Close the returned app.
//
// Order matters for the queue: room's settings (including the ticket TTL
// and first-poll grace, which judge what is stale) are applied by commit
// before the saved queue is imported, and nothing is served until newApp
// returns.
func newApp(cfg config) (*app, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	configureLogging(cfg.logFormat, cfg.logLevel)

	stats := &counters{}
	a := &app{
		cfg:    cfg,
		stats:  stats,
		admit:  newAdmitter(cfg.admitSecret, cfg.admitTTL, cfg.cookiePath, cfg.cookieDomain, cfg.secureCookie),
		abuse:  newAbuseRegistry(cfg, stats),
		drops:  newDropper(),
		agents: newAgentPlaces(),
		stop:   make(chan struct{}),
	}
	a.admit.setPrevSecret(cfg.admitSecretPrev)
	if err := a.initEnterpriseEarly(cfg); err != nil {
		return nil, err
	}
	a.settings = newSettingsManager(cfg)
	// Before the first generation: its proxy turns the origin's
	// Concert-Priority header into grants.
	a.prio = newPriorityState(cfg.admitSecret, a.admit)
	a.prio.grants.setPrevSecret(cfg.admitSecretPrev)

	wr := &room.WaitingRoom{}
	if err := wr.Init(int32(cfg.capacity)); err != nil {
		return nil, fmt.Errorf("room init: %w", err)
	}
	a.room = wr

	// room keys each queued visitor by the address concert resolved in
	// identify. gin's own ClientIP would name the TLS terminator: concert
	// turns gin's proxy trust off and applies -trusted-proxies itself.
	wr.SetClientKeyFunc(func(c *gin.Context) string {
		if ip := clientIPFrom(c); ip.IsValid() {
			return ip.String()
		}
		return ""
	})
	// Requests agentGate identified by a Concert-Session header are keyed
	// by session in room's line (see agent.go); every other request keeps
	// the cookie flow. The function only reads what agentGate left in the
	// context, so it costs nothing on the hot path.
	wr.SetTicketKeyFunc(agentKeyFromContext)
	wr.SetFullResponder(a.handleRoomFull)
	registerRoomEvents(wr, a)

	g, err := a.buildGeneration(cfg, nil)
	if err != nil {
		wr.Stop()
		return nil, err
	}
	if err := a.commit(g, nil); err != nil {
		g.assets.users.close()
		wr.Stop()
		return nil, fmt.Errorf("room config: %w", err)
	}
	if err := a.initEnterpriseFastlane(cfg, wr); err != nil {
		g.assets.users.close()
		wr.Stop()
		return nil, err
	}
	// All startup errors after this point close enterprise services cleanly.
	started := false
	defer func() {
		if !started {
			a.closeEnterpriseOnStartupErr()
		}
	}()
	a.handler = http.HandlerFunc(a.serveHTTP)
	a.initEnterpriseServices(cfg)

	if cfg.dataDir != "" {
		a.bansPath = bansFilePath(cfg.dataDir)
		n, err := a.abuse.loadBans(a.bansPath, time.Now())
		if err != nil {
			g.assets.users.close()
			wr.Stop()
			return nil, err
		}
		if n > 0 {
			log.Printf("bans: restored %d ban record(s) from %s", n, a.bansPath)
		}

		a.queuePath = queueFilePath(cfg.dataDir)
		if err := a.restoreQueue(); err != nil {
			g.assets.users.close()
			wr.Stop()
			return nil, err
		}
		if n := a.agents.seed(wr); n > 0 {
			log.Printf("queue: %d restored place(s) belong to agents", n)
		}
	}

	// IP details never stop startup: without a usable NADDR_DATA or
	// NADDR_ADDR the portal shows bare addresses.
	a.ipinfo = newIPLookup(ipInfoGetenv)

	// Every new ban drops that network's waiting visitors from room's line
	// and publishes to cluster peers when Redis sync is configured.
	a.abuse.setOnBan(func(scope netip.Prefix) {
		a.queueDrop(scope)
		a.topo.kickEdge() // leaves get the ban at once, not at the next poll
		now := time.Now()
		var matched *banView
		for _, b := range a.abuse.bans(now) {
			if t, err := parseBanTarget(b.Client); err == nil && t.scope() == scope {
				cp := b
				matched = &cp
				until := banForever
				if !b.Permanent {
					until = b.Until.UnixNano()
				}
				a.publishClusterBan(t, until, b.Offenses)
				break
			}
		}
		label := a.emailScopeLabel(scope)
		if (matched != nil && (matched.Permanent || matched.Range)) || !scope.IsSingleIP() {
			kind := "CIDR range ban"
			if matched != nil && matched.Permanent {
				kind = "Permanent ban"
			}
			a.notifyAlert(alertEvent{
				Category:    alertCatBans,
				Severity:    alertSevWarn,
				Title:       kind + " applied",
				Summary:     fmt.Sprintf("%s is now blocked by the abuse registry.", label),
				Fingerprint: "ban:" + label,
				Details:     map[string]string{"target": label},
			})
		} else {
			a.notifyAlert(alertEvent{
				Category:    alertCatBans,
				Severity:    alertSevInfo,
				Title:       "Abuse ban activity",
				Summary:     fmt.Sprintf("Automated temporary ban applied (most recent: %s).", label),
				Fingerprint: "ban:auto-surge",
				Details:     map[string]string{"latest_client": label},
			})
		}
	})

	go a.abuse.janitor(a.stop)
	a.startEnterpriseLoops()
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.dropLoop()
	}()
	if a.bansPath != "" {
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			a.abuse.persistLoop(a.bansPath, bansSaveEvery, a.stop)
		}()
	}
	started = true
	return a, nil
}

// serveHTTP hands the request to the current generation's engine. A request
// keeps that engine even if a setting changes while it runs.
func (a *app) serveHTTP(w http.ResponseWriter, r *http.Request) {
	a.current().engine.ServeHTTP(w, r)
}

// onClose registers f to run when the app closes, after the background
// loops have stopped and before the queue is saved. Closers run newest first.
func (a *app) onClose(f func()) {
	a.closeMu.Lock()
	a.closers = append(a.closers, f)
	a.closeMu.Unlock()
}

// attachHistory records the portal's history so the settings view can
// describe it, and closes it with the app, which flushes the history log.
func (a *app) attachHistory(h *history) {
	a.history = h
	a.onClose(h.close)
}

// recordAudit is implemented in enterprise_hooks.go / enterprise_stub.go.

// Close stops the janitors and the drop loop, flushes unsaved bans and the
// history log, stops the waiting room's reaper, saves the queue, and stops
// the IP database watcher. run calls it after the listeners have
// drained, so no new tickets or history arrive while they are being saved.
func (a *app) Close() {
	a.draining.Store(true)
	a.stopOnce.Do(func() {
		close(a.stop)
		a.wg.Wait()

		a.closeMu.Lock()
		closers := a.closers
		a.closers = nil
		a.closeMu.Unlock()
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}

		// Stop waits for room's reaper to exit (room v1.5.0), so no reaper
		// pass runs during or after the export below. The line itself
		// stays readable after Stop.
		a.room.Stop()
		if a.queuePath != "" && !a.skipQueueSave.Load() {
			a.saveQueue()
		}
		if g := a.current(); g != nil {
			g.assets.users.close()
			g.upstreams.close()
			if g.static != nil {
				_ = g.static.Close()
			}
		}
		a.ipinfo.close()
	})
}

// saveBansNow writes bans.json immediately when anything changed. Used after
// administrator actions so a ban is on disk before the API answers.
func (a *app) saveBansNow() {
	if a.bansPath != "" {
		a.abuse.flush(a.bansPath)
	}
}

// registerRoomEvents counts room's per-request events, logs its
// edge-triggered ones, and strikes ticket churn. Registered once; room keeps
// them across changes. Callbacks run in their own goroutines, so none of
// them may block. Snapshot.Token is a bearer credential and is never logged.
func registerRoomEvents(wr *room.WaitingRoom, a *app) {
	stats := a.stats
	wr.On(room.EventFull, func(s room.Snapshot) {
		live := wr.LiveQueueDepth()
		log.Printf("upstream saturated: %d/%d slots, %d queued (%d live)",
			s.Occupancy, s.Capacity, s.QueueDepth, live)
		sev := alertSevWarn
		title := "Waiting room saturated"
		if maxQ := wr.MaxQueueDepth(); maxQ > 0 && live >= maxQ {
			sev = alertSevCritical
			title = "Waiting room queue-full breaker active"
		}
		a.notifyAlert(alertEvent{
			Category:    alertCatQueue,
			Severity:    sev,
			Title:       title,
			Summary:     fmt.Sprintf("Origin slots full (%d/%d), %d queued (%d live).", s.Occupancy, s.Capacity, s.QueueDepth, live),
			Fingerprint: "queue:full",
			Details: map[string]string{
				"occupancy": fmt.Sprintf("%d/%d", s.Occupancy, s.Capacity),
				"live":      fmt.Sprintf("%d", live),
			},
		})
	})
	wr.On(room.EventDrain, func(s room.Snapshot) {
		log.Printf("draining: %d/%d slots, %d queued (%d live)",
			s.Occupancy, s.Capacity, s.QueueDepth, wr.LiveQueueDepth())
	})
	wr.On(room.EventQueue, func(s room.Snapshot) {
		stats.queued.Add(1)
		// A visitor who arrived with no room_ticket at all took a fresh
		// place in line: a script discarding cookies does this on every
		// retry. An unrecognised ticket (StaleTicket) is a browser whose old
		// ticket expired or was removed, and is not struck. A keyed arrival
		// (an agent's session, s.Key set) has an empty ClientKey, which
		// churnStrike ignores: agents are capped by -agent-places instead.
		if !s.StaleTicket {
			a.churnStrike(s.ClientKey)
		}
	})
	wr.On(room.EventEvict, func(room.Snapshot) { stats.evicted.Add(1) })
	wr.On(room.EventTimeout, func(room.Snapshot) { stats.timeouts.Add(1) })
	wr.On(room.EventPromote, func(room.Snapshot) { stats.promoted.Add(1) })
	wr.On(room.EventRemove, func(room.Snapshot) { stats.removed.Add(1) })
	wr.On(room.EventReject, func(s room.Snapshot) {
		stats.rejected503.Add(1)
		live := wr.LiveQueueDepth()
		a.notifyAlert(alertEvent{
			Category:    alertCatQueue,
			Severity:    alertSevCritical,
			Title:       "Waiting room refused request (503)",
			Summary:     fmt.Sprintf("Queue-full breaker refused a visitor (%d/%d slots, %d queued, %d live).", s.Occupancy, s.Capacity, s.QueueDepth, live),
			Fingerprint: "queue:breaker-503",
			Details: map[string]string{
				"occupancy": fmt.Sprintf("%d/%d", s.Occupancy, s.Capacity),
				"live":      fmt.Sprintf("%d", live),
			},
		})
	})
	wr.On(room.EventTokenRejected, func(s room.Snapshot) {
		stats.tokenRejected.Add(1)
		// Award a forged-pass strike on cryptographic tampering or cross-scope
		// / cross-kind / key-mismatch replay, while leaving normal token expiry
		// and key-rotation unknown_key misses unstruck.
		if isForgedTokenRejection(s.Reason) {
			a.tokenRejectionStrike(s.ClientKey)
		}
	})
}

var placeholderRetryAfter = []byte("{{.RetryAfter}}")

const busyPageCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// handleRoomFull is room's FullResponder, invoked when maxQueueDepth rejects an
// arrival. It sets ctxRoomFull before writing headers so apiQueueWriter and
// agentWaitWriter pass the formatted response through untouched.
func (a *app) handleRoomFull(c *gin.Context, _ room.Snapshot) {
	c.Set(ctxRoomFull, true)

	retryAfter := 5
	apiJSON := true
	var raw []byte
	if g := a.current(); g != nil {
		if g.cfg.retryAfter > 0 {
			retryAfter = g.cfg.retryAfter
		}
		apiJSON = g.cfg.apiJSON
		raw = g.busyHTML
	}
	retryStr := strconv.Itoa(retryAfter)
	c.Header("Cache-Control", "no-store")
	c.Header("Retry-After", retryStr)

	if c.GetString(ctxAgentKey) != "" {
		c.Data(http.StatusServiceUnavailable, "application/json; charset=utf-8", mustJSON(gin.H{
			"queued":              false,
			"error":               "waiting room is full",
			"retry_after_seconds": retryAfter,
		}))
		return
	}

	if wantsHTML(c.Request) {
		if len(raw) == 0 {
			raw = defaultBusyHTML
		}
		page := bytes.ReplaceAll(raw, placeholderRetryAfter, []byte(retryStr))
		c.Header("Content-Security-Policy", busyPageCSP)
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "no-referrer")
		c.Data(http.StatusServiceUnavailable, "text/html; charset=utf-8", page)
		return
	}

	if apiJSON {
		c.Data(http.StatusServiceUnavailable, "application/json; charset=utf-8", mustJSON(gin.H{
			"queued":              false,
			"error":               "waiting room is full",
			"retry_after_seconds": retryAfter,
		}))
		return
	}

	c.AbortWithStatus(http.StatusServiceUnavailable)
}

func isForgedTokenRejection(reason string) bool {
	switch reason {
	case room.RejectReasonInvalidSignature,
		room.RejectReasonWrongScope,
		room.RejectReasonWrongKind,
		room.RejectReasonKeyMismatch,
		room.RejectReasonMalformed:
		return true
	default:
		return false
	}
}

func (a *app) tokenRejectionStrike(key string) {
	reg := a.current().abuse
	if reg == nil || key == "" {
		return
	}
	ip, err := netip.ParseAddr(key)
	if err != nil {
		return
	}
	reg.strike(ip, strikeForgedPass, time.Now())
}

// churnStrike records a ticket-churn strike against the client room keyed
// the arrival by. The key is the address concert resolved in identify.
func (a *app) churnStrike(key string) {
	reg := a.current().abuse
	if reg == nil || key == "" {
		return
	}
	ip, err := netip.ParseAddr(key)
	if err != nil {
		return
	}
	reg.strike(ip, strikeTicketChurn, time.Now())
}

// run builds the app, starts the admin portal when configured, binds the
// main listener, and serves until ctx is cancelled. Both listeners are
// endpoints (see server.go); the deferred Close saves the queue and the
// history after they have drained.
func run(ctx context.Context, cfg config) error {
	if strings.TrimSpace(cfg.configFile) != "" {
		return runVhost(ctx, cfg)
	}
	a, err := newApp(cfg)
	if err != nil {
		return err
	}
	defer a.Close()
	a.maybeBenchOnStart(ctx, cfg)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // stops the portal if the main listener fails

	p, err := newPortal(a)
	if err != nil {
		return err
	}
	handler := p.wrap(a.handler)

	g := a.current()
	c := g.cfg

	// Built before binding, so a bad certificate cache fails fast.
	tlsCfg, acmeMgr, err := newACMETLSConfigWithManager(c)
	if err != nil {
		p.closeListener()
		return err
	}
	if c.http3 && tlsCfg != nil {
		handler = altSvcMiddleware(c.listen, handler)
	}

	var httpRedirectEP *endpoint
	if hl := strings.TrimSpace(c.tlsHTTPListen); hl != "" {
		httpLn, herr := listen(hl)
		if herr != nil {
			p.closeListener()
			return fmt.Errorf("tls-http-listen %s: %w", hl, herr)
		}
		httpRedirectEP = newEndpoint("http-redirect", httpsRedirectHandler(c, acmeMgr), 5*time.Second, newServer)
		httpRedirectEP.serveOn(httpLn, hl)
	}

	ln, err := listen(c.listen)
	if err != nil {
		if httpRedirectEP != nil {
			_ = httpRedirectEP.shutdown()
		}
		p.closeListener()
		return fmt.Errorf("listen %s: %w", c.listen, err)
	}

	var h3Closer func() error
	if c.http3 && tlsCfg != nil {
		h3Closer, err = startHTTP3Server(c.listen, tlsCfg, handler)
		if err != nil {
			_ = ln.Close()
			if httpRedirectEP != nil {
				_ = httpRedirectEP.shutdown()
			}
			p.closeListener()
			return err
		}
	}

	mainEP := newEndpoint("main", handler, shutdownGrace, newServer)
	mainEP.setTLS(tlsCfg)
	portalEP := p.start(ctx)
	a.attachEndpoints(mainEP, portalEP)

	derived := ""
	if c.assetCap == 0 {
		derived = " (derived)"
	}
	log.Printf("concert %s -> %s (cap=%d, max-queue=%d, token-ttl=%s, first-poll-grace=%s, ready-grace=%s, idle-poll-ttl=%s, reaper=%s, upstream-body-idle-timeout=%s, asset-cap=%d%s, asset-user-cap=%d h1 / %d h2)",
		ln.Addr(), c.target, c.capacity, c.maxQueue, a.room.TokenTTL(), a.room.FirstPollGrace(),
		a.room.ReadyGrace(), a.room.IdlePollTTL(), a.room.ReaperInterval(), c.upstreamBodyIdleTimeout,
		g.assets.global.Cap(), derived, c.assetUserCapH1, c.assetUserCapH2)
	logStartupDiagnostics("", c, hasCapacityFile(c.dataDir))
	if lr := priorityRank(c.priorityLaneRank); lr < rankCount {
		log.Printf("priority: %s and above use a lane of %d slot(s) while the room is busy; forms from admitted visitors %v",
			lr, g.lane.Cap(), c.priorityForms)
	}
	if rules := parsePaths(c.streamPaths); len(rules) > 0 {
		log.Printf("streams: %d path(s) outside the waiting room, admission pass required, at most %d at once",
			len(rules), c.streamCap)
	}
	if tlsCfg != nil {
		if c.tlsCert != "" {
			log.Printf("tls: PEM certificate %s (hot-reloaded on change)", c.tlsCert)
		} else {
			directory := "production"
			if c.tlsStaging {
				directory = "staging (untrusted certificates)"
			}
			log.Printf("tls: Let's Encrypt %s for %s, cache %s",
				directory, strings.Join(c.tlsHosts, ","), c.tlsCacheDir)
		}
		if httpRedirectEP != nil {
			log.Printf("tls: HTTP redirect & ACME HTTP-01 listening on %s -> HTTPS", c.tlsHTTPListen)
		}
		if h3Closer != nil {
			log.Printf("tls: HTTP/3 (QUIC) listening on udp %s (Alt-Svc advertised)", c.listen)
		}
		if !c.secureCookie {
			log.Printf("tls: browsers now reach concert over HTTPS; set CONCERT_SECURE_COOKIE=true")
		}
	}
	if g.static != nil {
		log.Printf("static: serving local assets (root=%q, mounts=%d, fallback=%v, compress=%v)",
			c.staticRoot, len(c.parsedStaticMounts), c.staticFallback, c.compress)
	}
	if c.hasFastCGI {
		log.Printf("fcgi: php-fpm upstream active (root=%s, index=%s, deny=%d rule(s))",
			c.staticRoot, c.fcgiIndex, len(c.parsedFCGIDenyPaths))
	}
	if c.abuseEnabled {
		log.Printf("abuse registry: %d strikes per %s, cooldown %s doubling to %s, %d ban paths",
			c.abuseStrikes, c.abuseWindow, c.abuseCooldown, c.abuseMaxCooldown, len(g.banRules))
	}
	if c.dataDir != "" {
		if err := ensureWritableDir(c.dataDir); err != nil {
			log.Printf("data dir: %v; settings, bans, the queue and the history changed now will not be saved", err)
		} else {
			log.Printf("data dir: %s (settings.json overrides flags and environment; bans, the queue and the history survive restarts)", c.dataDir)
		}
	}
	a.logEnterpriseStartup(c)
	if c.admitSecretGenerated {
		log.Printf("CONCERT_ADMIT_SECRET not set: using a random secret; admission passes and priority grants reset on restart and are not shared across instances")
	}

	mainEP.serveOn(ln, c.listen)
	go func() {
		<-ctx.Done()
		a.draining.Store(true)
	}()
	err = awaitShutdown(ctx, mainEP, portalEP, httpRedirectEP)
	if h3Closer != nil {
		if cerr := h3Closer(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// setPricing stores the skip-the-line price. It changes at runtime, so it
// is kept as atomic float64 bits.
func (a *app) setPricing(rate, surge float64) {
	a.rateBits.Store(math.Float64bits(rate))
	a.surgeBits.Store(math.Float64bits(surge))
}

func (a *app) pricing() (rate, surge float64) {
	return math.Float64frombits(a.rateBits.Load()), math.Float64frombits(a.surgeBits.Load())
}

// price is room's RateFunc while paid skip-the-line is configured (-rate or
// -surge above 0): base + depth × surge per position. See applyRoom.
func (a *app) price(depth int64) float64 {
	rate, surge := a.pricing()
	return rate + float64(depth)*surge
}

// hasCapacityFile reports whether dataDir contains a calibrated capacity.json.
func hasCapacityFile(dataDir string) bool {
	if strings.TrimSpace(dataDir) == "" {
		return false
	}
	info, err := os.Stat(filepath.Join(dataDir, "capacity.json"))
	return err == nil && !info.IsDir()
}

// logStartupDiagnostics emits non-fatal warnings for configurations prone to
// origin overload or waiting-room lockouts.
func logStartupDiagnostics(label string, cfg config, hasCapacityFile bool) {
	prefix := "startup"
	if strings.TrimSpace(label) != "" {
		prefix = "startup (" + strings.TrimSpace(label) + ")"
	}
	if cfg.role != roleEdge && cfg.capacity >= 400 && cfg.upstreamCBFailures == 0 && strings.TrimSpace(cfg.upstreamHealthPath) == "" && !hasCapacityFile {
		prioCap := cfg.effectivePriorityCap()
		log.Printf("%s: WARNING high uncalibrated -cap=%d (+ %d priority lane = %d max concurrent upstream page slots) with circuit breaker and active health checks disabled; calibrate with lemmings or -bench-on-start and consider -upstream-cb-failures 5 -upstream-health-path /healthz",
			prefix, cfg.capacity, prioCap, cfg.capacity+prioCap)
	}
	if cfg.maxQueue > 0 && (cfg.readyGrace == 0 || cfg.idlePollTTL == 0) {
		log.Printf("%s: WARNING waiting-room liveness guard disabled while -max-queue=%d is active (ready-grace=%s, idle-poll-ttl=%s); abandoned visitors may occupy queue slots until -token-ttl (%s)",
			prefix, cfg.maxQueue, cfg.readyGrace, cfg.idlePollTTL, cfg.effectiveTokenTTL())
	}
}
