package main

import (
	"context"
	"fmt"
	"github.com/andreimerlescu/concert/internal/fastlane"
	"log"
	"math"
	"net/http"
	"net/netip"
	"os"
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
	fastlane *fastlane.Service

	cfg       config // as concert started; the running configuration is current().cfg
	room      *room.WaitingRoom
	stats     *counters
	admit     *admitter
	abuse     *abuseRegistry // always present; current().abuse is nil while -abuse=false
	prio      *priorityState // rank grants, the ranked line and counters; see priority.go
	handler   http.Handler   // serves every request with the current generation
	settings  *settingsManager
	drops     *dropper      // bans waiting to be removed from the line; see queue.go
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

	stats := &counters{}
	a := &app{
		cfg:   cfg,
		stats: stats,
		admit: newAdmitter(cfg.admitSecret, cfg.admitTTL, cfg.cookiePath, cfg.cookieDomain, cfg.secureCookie),
		abuse: newAbuseRegistry(cfg, stats),
		drops: newDropper(),
		stop:  make(chan struct{}),
	}
	a.settings = newSettingsManager(cfg)
	// Before the first generation: its proxy turns the origin's
	// Concert-Priority header into grants.
	a.prio = newPriorityState(cfg.admitSecret, a.admit)

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
	if cfg.fastlaneFile != "" {
		fc, err := fastlane.Load(cfg.fastlaneFile)
		if err == nil && fc.Enabled && cfg.admitSecretGenerated {
			err = fmt.Errorf("fast lane requires a stable CONCERT_ADMIT_SECRET")
		}
		if err == nil {
			a.fastlane, err = fastlane.New(fc, cfg.dataDir, cfg.admitSecret, os.Getenv("CONCERT_GATEWAY_TOKEN"), os.Getenv("CONCERT_POLICY_TOKEN"))
		}
		if err != nil {
			g.assets.users.close()
			wr.Stop()
			return nil, fmt.Errorf("fast lane: %w", err)
		}
	}
	// All startup errors after this point close the fast lane's journal.
	started := false
	defer func() {
		if !started && a.fastlane != nil {
			a.fastlane.Close()
		}
	}()
	a.handler = http.HandlerFunc(a.serveHTTP)

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
	}

	// IP details never stop startup: without a usable NADDR_DATA or
	// NADDR_ADDR the portal shows bare addresses.
	a.ipinfo = newIPLookup(ipInfoGetenv)

	// Every new ban drops that network's waiting visitors from room's line.
	a.abuse.setOnBan(a.queueDrop)

	go a.abuse.janitor(a.stop)
	go a.prio.janitor(a.room, a.stop)
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
	if a.fastlane != nil {
		a.onClose(a.fastlane.Close)
	}
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

// Close stops the janitors and the drop loop, flushes unsaved bans and the
// history log, saves the queue, and stops the IP database watcher and the
// waiting room's background workers. run calls it after the listeners have
// drained, so no new tickets or history arrive while they are being saved.
func (a *app) Close() {
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

		if a.queuePath != "" {
			a.saveQueue()
		}
		if g := a.current(); g != nil {
			g.assets.users.close()
		}
		a.ipinfo.close()
		a.room.Stop()
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
		log.Printf("upstream saturated: %d/%d slots, %d queued (%d live)",
			s.Occupancy, s.Capacity, s.QueueDepth, wr.LiveQueueDepth())
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
		// ticket expired or was removed, and is not struck.
		if !s.StaleTicket {
			a.churnStrike(s.ClientKey)
		}
	})
	wr.On(room.EventEvict, func(room.Snapshot) { stats.evicted.Add(1) })
	wr.On(room.EventTimeout, func(room.Snapshot) { stats.timeouts.Add(1) })
	wr.On(room.EventPromote, func(room.Snapshot) { stats.promoted.Add(1) })
	wr.On(room.EventRemove, func(room.Snapshot) { stats.removed.Add(1) })
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
	a, err := newApp(cfg)
	if err != nil {
		return err
	}
	defer a.Close()

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
	tlsCfg, err := newACMETLSConfig(c)
	if err != nil {
		p.closeListener()
		return err
	}

	ln, err := listen(c.listen)
	if err != nil {
		p.closeListener()
		return fmt.Errorf("listen %s: %w", c.listen, err)
	}

	mainEP := newEndpoint("main", handler, shutdownGrace, newServer)
	mainEP.setTLS(tlsCfg)
	portalEP := p.start(ctx)
	a.attachEndpoints(mainEP, portalEP)

	derived := ""
	if c.assetCap == 0 {
		derived = " (derived)"
	}
	log.Printf("concert %s -> %s (cap=%d, max-queue=%d, token-ttl=%s, first-poll-grace=%s, asset-cap=%d%s, asset-user-cap=%d h1 / %d h2)",
		ln.Addr(), c.target, c.capacity, c.maxQueue, a.room.TokenTTL(), a.room.FirstPollGrace(),
		g.assets.global.Cap(), derived, c.assetUserCapH1, c.assetUserCapH2)
	if lr := priorityRank(c.priorityLaneRank); lr < rankCount {
		log.Printf("priority: %s and above use a lane of %d slot(s) while the room is busy; forms from admitted visitors %v",
			lr, g.lane.Cap(), c.priorityForms)
	}
	if rules := parsePaths(c.streamPaths); len(rules) > 0 {
		log.Printf("streams: %d path(s) outside the waiting room, admission pass required, at most %d at once",
			len(rules), c.streamCap)
	}
	if tlsCfg != nil {
		directory := "production"
		if c.tlsStaging {
			directory = "staging (untrusted certificates)"
		}
		log.Printf("tls: Let's Encrypt %s for %s, cache %s",
			directory, strings.Join(c.tlsHosts, ","), c.tlsCacheDir)
		if !c.secureCookie {
			log.Printf("tls: browsers now reach concert over HTTPS; set CONCERT_SECURE_COOKIE=true")
		}
	}
	if a.fastlane != nil {
		fc := a.fastlane.Config()
		mode := "live networks"
		if fc.TestMode {
			mode = "test networks only"
		}
		log.Printf("fast lane: %s, %d payment offer(s), %d NFT rule(s), %ds pass, gateway %s",
			mode, len(fc.Offers), len(fc.Collections), fc.PassSeconds, fc.GatewayURL)
	} else if c.fastlaneFile != "" {
		log.Printf("fast lane: %s has \"enabled\": false; wallet access is off", c.fastlaneFile)
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
	if c.admitSecretGenerated {
		log.Printf("CONCERT_ADMIT_SECRET not set: using a random secret; admission passes and priority grants reset on restart and are not shared across instances")
	}

	mainEP.serveOn(ln, c.listen)
	return awaitShutdown(ctx, mainEP, portalEP)
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
