package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/andreimerlescu/room"
	"github.com/andreimerlescu/sema"
	"github.com/gin-gonic/gin"
)

// Hot reconfiguration.
//
// Everything concert serves is built from one configuration into a
// generation: the gin engine with its routes and middleware, the reverse
// proxy, the asset pools and the ban rules. Each request loads the current
// generation once, so a change never alters the rules halfway through a
// request. Changing a setting builds a complete new generation, binds any
// new listen address, saves settings.json, and then swaps everything in at
// once. If any step before the save fails, nothing that is running changes.
//
// State that must outlive a change is not rebuilt: the waiting room and its
// queue, the abuse registry with its bans and strikes, the admission pass
// signer, and the counters. They are reconfigured in place; room documents
// every setter as safe to call while traffic flows.
//
// Pools whose size changes are replaced rather than resized, because sema
// drains every slot when shrinking. Requests already holding a slot finish
// on the old pool, so for a moment the total in flight can exceed the new
// limit by what the old pool still holds.

// roomDefaultTokenTTL is room's ticket TTL when none is set. -token-ttl 0
// means this value.
const roomDefaultTokenTTL = 5 * time.Minute

// generation is everything built from one configuration.
type generation struct {
	a         *app
	cfg       config
	abuse     *abuseRegistry // a.abuse, or nil when -abuse=false
	banRules  []pathRule
	untracked []pathRule // paths the portal's queue view ignores
	assets    *assetGuard
	proxy     *httputil.ReverseProxy
	forward   gin.HandlerFunc
	engine    *gin.Engine
	html      []byte // custom waiting room page; nil means room's own
}

// current is the generation serving requests now.
func (a *app) current() *generation {
	return a.gen.Load()
}

// buildGeneration builds a generation from next, which must already be
// normalized, without changing anything that is running. Pieces whose
// settings did not change are carried over from prev so that in-flight
// requests, idle upstream connections and per-visitor asset limits are kept.
func (a *app) buildGeneration(next config, prev *generation) (*generation, error) {
	html, err := readWaitingRoomHTML(next)
	if err != nil {
		return nil, err
	}

	g := &generation{a: a, cfg: next, html: html, banRules: parsePaths(next.banPaths)}
	if next.abuseEnabled {
		g.abuse = a.abuse
	}
	g.untracked = append(g.untracked, parsePaths(next.assets)...)
	g.untracked = append(g.untracked, parsePaths(next.assetPublic)...)
	g.untracked = append(g.untracked, parsePaths(next.bypass)...)
	g.untracked = append(g.untracked, pathRule{path: "/_room", prefix: true})

	if prev != nil && sameProxy(prev.cfg, next) {
		g.proxy = prev.proxy
	} else {
		g.proxy = newProxy(next.target, next.preserveHost, next.headerTimeout, next.trusted)
	}
	g.forward = forwardTo(g.proxy)

	var users *userStore
	if prev != nil && sameUserPools(prev.cfg, next) {
		users = prev.assets.users
	} else {
		users = newUserStore(next.assetUserCapH1, next.assetUserCapH2)
	}
	var global sema.Semaphore
	if prev != nil && prev.assets.global.Cap() == next.effectiveAssetCap() {
		global = prev.assets.global
	} else if global, err = sema.New(next.effectiveAssetCap()); err != nil {
		return nil, fmt.Errorf("asset semaphore: %w", err)
	}
	g.assets = &assetGuard{
		admit:       a.admit,
		users:       users,
		global:      global,
		userWait:    next.assetUserWait,
		globalWait:  next.assetWait,
		protoHeader: next.clientProtoHeader,
		stats:       a.stats,
		strike:      g.strike,
	}

	engine, err := buildRouter(g)
	if err != nil {
		return nil, err
	}
	g.engine = engine
	return g, nil
}

func sameProxy(a, b config) bool {
	return a.upstream == b.upstream && a.preserveHost == b.preserveHost &&
		a.headerTimeout == b.headerTimeout && a.trustedProxies == b.trustedProxies
}

func sameUserPools(a, b config) bool {
	return a.assetUserCapH1 == b.assetUserCapH1 && a.assetUserCapH2 == b.assetUserCapH2 && a.admitTTL == b.admitTTL
}

func readWaitingRoomHTML(cfg config) ([]byte, error) {
	if cfg.htmlFile == "" {
		return nil, nil
	}
	html, err := os.ReadFile(cfg.htmlFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read -html %s: %w", cfg.htmlFile, err)
	}
	return html, nil
}

// applyRoom configures the waiting room from cfg. A nil html restores
// room's built-in page. Every value is validated before it gets here, so an
// error means room's own limits changed.
func applyRoom(wr *room.WaitingRoom, cfg config, html []byte) error {
	ttl := cfg.tokenTTL
	if ttl == 0 {
		ttl = roomDefaultTokenTTL
	}
	wr.SetSecureCookie(cfg.secureCookie)
	wr.SetCookiePath(cfg.cookiePath)
	wr.SetCookieDomain(cfg.cookieDomain)
	wr.SetHTML(html)
	wr.SetSkipURL(cfg.skipURL)
	return errors.Join(
		wr.SetCap(int32(cfg.capacity)),
		wr.SetMaxQueueDepth(cfg.maxQueue),
		wr.SetReaperInterval(cfg.reaper),
		wr.SetTokenTTL(ttl),
		wr.SetPassDuration(cfg.passDuration),
	)
}

// commit makes g the running generation and applies lp. It is used at
// startup (prev is nil, lp is nil) and for every change after that. It
// returns only the waiting room's error; everything else cannot fail.
func (a *app) commit(g *generation, lp *listenPlan) error {
	prev := a.current()
	cfg := g.cfg

	roomErr := applyRoom(a.room, cfg, g.html)
	a.admit.configure(cfg.admitTTL, cfg.cookiePath, cfg.cookieDomain, cfg.secureCookie)
	a.abuse.setParams(abuseParamsFrom(cfg))
	a.setPricing(cfg.rate, cfg.surge)
	if prev == nil || prev.assets.users != g.assets.users {
		g.assets.users.startJanitor(janitorInterval(cfg.admitTTL), cfg.admitTTL)
	}
	if cfg.htmlFile != "" && (prev == nil || prev.cfg.htmlFile != cfg.htmlFile) {
		log.Printf("custom waiting room loaded from %s — it must treat cookies_required as terminal "+
			"and check document.cookie for room_probe before its first poll", cfg.htmlFile)
	}

	a.gen.Store(g)

	if prev != nil {
		if prev.assets.users != g.assets.users {
			prev.assets.users.close()
		}
		if prev.proxy != g.proxy {
			if t, ok := prev.proxy.Transport.(*http.Transport); ok {
				t.CloseIdleConnections()
			}
		}
	}
	lp.commit()
	return roomErr
}

// ─── listeners ───────────────────────────────────────────────────────────────

// listenPlan is the listener changes one reconfiguration needs. prepare
// binds every new address and builds any new certificate configuration, so
// a failure changes nothing; commit switches over; abort releases whatever
// prepare bound.
type listenPlan struct {
	main, portal *endpoint

	setTLS bool
	tls    *tls.Config

	mainLn, portalLn     net.Listener
	mainAddr, portalAddr string
	portalOff            bool
}

// attachEndpoints records the running listeners so later changes can move
// them. Called by run once they exist.
func (a *app) attachEndpoints(main, portal *endpoint) {
	a.settings.mu.Lock()
	a.mainEP, a.portalEP = main, portal
	a.settings.mu.Unlock()
}

// prepareListeners binds what next needs. Caller holds a.settings.mu.
// Without running listeners (tests, or before run starts serving) it still
// validates the certificate configuration.
func (a *app) prepareListeners(next config) (*listenPlan, error) {
	lp := &listenPlan{main: a.mainEP, portal: a.portalEP}

	if cur := a.current().cfg; tlsChanged(cur, next) {
		tc, err := newACMETLSConfig(next)
		if err != nil {
			return nil, err
		}
		lp.setTLS, lp.tls = true, tc
	}

	if ep := a.mainEP; ep != nil && next.listen != ep.addr() {
		ln, err := bindMove(ep, next.listen)
		if err != nil {
			return nil, err
		}
		lp.mainLn, lp.mainAddr = ln, next.listen
	}

	if ep := a.portalEP; ep != nil {
		if want := portalAddress(next); want != ep.addr() {
			if want == "" {
				lp.portalOff = true
			} else {
				ln, err := bindMove(ep, want)
				if err != nil {
					lp.abort()
					return nil, err
				}
				lp.portalLn, lp.portalAddr = ln, want
			}
		}
	}
	return lp, nil
}

func (lp *listenPlan) commit() {
	if lp == nil {
		return
	}
	if lp.setTLS && lp.main != nil {
		lp.main.setTLS(lp.tls)
		if lp.tls != nil {
			log.Printf("main: TLS on for new connections")
		} else {
			log.Printf("main: TLS off for new connections")
		}
	}
	if lp.mainLn != nil && lp.main != nil {
		lp.main.serveOn(lp.mainLn, lp.mainAddr)
	}
	if lp.portal != nil {
		switch {
		case lp.portalOff:
			lp.portal.stopServing()
		case lp.portalLn != nil:
			lp.portal.serveOn(lp.portalLn, lp.portalAddr)
		}
	}
}

func (lp *listenPlan) abort() {
	if lp == nil {
		return
	}
	for _, ln := range []net.Listener{lp.mainLn, lp.portalLn} {
		if ln != nil {
			_ = ln.Close()
		}
	}
}

// portalAddress is where the portal should listen, or "" for off.
func portalAddress(cfg config) string {
	if cfg.portal.enabled() {
		return cfg.portal.listen
	}
	return ""
}

func tlsChanged(a, b config) bool {
	return strings.Join(a.tlsHosts, ",") != strings.Join(b.tlsHosts, ",") ||
		a.tlsEmail != b.tlsEmail || a.tlsCacheDir != b.tlsCacheDir || a.tlsStaging != b.tlsStaging
}
