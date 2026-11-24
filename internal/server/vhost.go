package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/andreimerlescu/concert/internal/configfile"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Multi-vhost declarative runtime (-config Concertfile / .json).
//
// Each virtual host owns an independent *app (waiting room, capacity,
// upstream pool, os.Root static server, priority lane, abuse registry, and
// optional micro-cache) while sharing one :443 listener (TCP + optional
// HTTP/3), one :80 ACME/redirect listener, one autocert.Manager, and one
// Admin Portal with a site switcher.

type siteRuntime struct {
	primaryHost string
	hosts       []string
	preset      string
	app         *app
	cert        *certReloader
}

type vhostSnapshot struct {
	file        *configfile.File
	sites       []*siteRuntime
	byHost      map[string]*siteRuntime
	defaultSite *siteRuntime
	globalCert  *certReloader
	acmeHosts   map[string]bool
	hasTLS      bool
}

type vhostManager struct {
	configPath string
	baseCfg    config

	mu   sync.Mutex
	snap atomic.Pointer[vhostSnapshot]
}

func newVhostManager(baseCfg config) (*vhostManager, error) {
	if strings.TrimSpace(baseCfg.configFile) == "" {
		return nil, errors.New("vhost: -config path is required")
	}
	vm := &vhostManager{
		configPath: baseCfg.configFile,
		baseCfg:    baseCfg,
	}
	snap, err := vm.loadSnapshot(nil)
	if err != nil {
		return nil, err
	}
	vm.snap.Store(snap)
	return vm, nil
}

func (vm *vhostManager) current() *vhostSnapshot {
	if vm == nil {
		return nil
	}
	return vm.snap.Load()
}

func (vm *vhostManager) primaryApp() *app {
	snap := vm.current()
	if snap == nil || len(snap.sites) == 0 {
		return nil
	}
	return snap.sites[0].app
}

func (vm *vhostManager) siteByName(name string) (*siteRuntime, bool) {
	snap := vm.current()
	if snap == nil || len(snap.sites) == 0 {
		return nil, false
	}
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return snap.sites[0], true
	}
	if sr, ok := snap.byHost[name]; ok {
		return sr, true
	}
	for _, sr := range snap.sites {
		if sr.primaryHost == name {
			return sr, true
		}
	}
	return nil, false
}

// Reload re-parses -config and validates every virtual host before swapping
// live traffic. If the new file has any error, the previous snapshot keeps
// serving with zero downtime. Active fast-lane/gateway journals for unchanged
// site data directories are hot-reloaded and handed off atomically so SIGHUP
// never collides on fastlane.lock or settlements.lock.
func (vm *vhostManager) Reload() error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	prev := vm.snap.Load()
	next, err := vm.loadSnapshot(prev)
	if err != nil {
		return err
	}
	vm.snap.Swap(next)
	if prev != nil {
		prev.closeApps()
	}
	log.Printf("config: reloaded %s (%d site(s))", vm.configPath, len(next.sites))
	return nil
}

func (vm *vhostManager) Close() {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	if snap := vm.snap.Swap(nil); snap != nil {
		snap.closeApps()
	}
}

func (s *vhostSnapshot) closeApps() {
	if s == nil {
		return
	}
	for _, sr := range s.sites {
		if sr.app != nil {
			sr.app.Close()
		}
	}
}

func (vm *vhostManager) loadSnapshot(prev *vhostSnapshot) (*vhostSnapshot, error) {
	f, err := configfile.Load(vm.configPath)
	if err != nil {
		return nil, err
	}
	snap := &vhostSnapshot{
		file:      f,
		byHost:    make(map[string]*siteRuntime),
		acmeHosts: make(map[string]bool),
	}
	fail := func(err error) (*vhostSnapshot, error) {
		snap.closeApps()
		return nil, err
	}

	prevByDataDir := map[string]*app{}
	if prev != nil {
		for _, psr := range prev.sites {
			if psr.app != nil && psr.app.cfg.dataDir != "" && psr.app.fastlaneEnabled() {
				prevByDataDir[psr.app.cfg.dataDir] = psr.app
			}
		}
	}

	if f.Global.TLSCert != "" {
		cr, err := newCertReloader(f.Global.TLSCert, f.Global.TLSKey)
		if err != nil {
			return fail(fmt.Errorf("global TLS: %w", err))
		}
		snap.globalCert = cr
		snap.hasTLS = true
	}

	type pendingTransfer struct {
		dst *app
		src *app
		cfg config
	}
	var transfers []pendingTransfer

	for _, sc := range f.Sites {
		siteCfg, err := buildSiteConfig(vm.baseCfg, f.Global, sc)
		if err != nil {
			return fail(fmt.Errorf("site %s: %w", sc.Hosts[0], err))
		}
		var siteCert *certReloader
		if sc.TLSCert != "" {
			cr, cerr := newCertReloader(sc.TLSCert, sc.TLSKey)
			if cerr != nil {
				return fail(fmt.Errorf("site %s TLS: %w", sc.Hosts[0], cerr))
			}
			siteCert = cr
			snap.hasTLS = true
		}
		var prevHolder *app
		if siteCfg.dataDir != "" && siteCfg.fastlaneFile != "" {
			if pa, ok := prevByDataDir[siteCfg.dataDir]; ok {
				if err := validateFastlaneReloadConfig(siteCfg); err != nil {
					return fail(fmt.Errorf("site %s fastlane: %w", sc.Hosts[0], err))
				}
				siteCfg.skipFastlaneInit = true
				prevHolder = pa
			}
		}
		a, err := newApp(siteCfg)
		if err != nil {
			return fail(fmt.Errorf("site %s: %w", sc.Hosts[0], err))
		}
		if prevHolder != nil {
			transfers = append(transfers, pendingTransfer{dst: a, src: prevHolder, cfg: siteCfg})
		}
		sr := &siteRuntime{
			primaryHost: sc.Hosts[0],
			hosts:       append([]string(nil), sc.Hosts...),
			preset:      sc.Preset,
			app:         a,
			cert:        siteCert,
		}
		snap.sites = append(snap.sites, sr)
		for _, h := range sc.Hosts {
			if h == "*" {
				snap.defaultSite = sr
			} else {
				snap.byHost[h] = sr
				if siteCert == nil && snap.globalCert == nil && isACMEEligibleHost(h) {
					snap.acmeHosts[h] = true
				}
			}
		}
	}
	for _, tr := range transfers {
		if err := tr.dst.transferFastlaneFrom(tr.src, tr.cfg); err != nil {
			return fail(fmt.Errorf("site %s fastlane handoff: %w", tr.cfg.siteHost, err))
		}
	}
	if len(snap.acmeHosts) > 0 && strings.TrimSpace(f.Global.TLSCache) != "" {
		snap.hasTLS = true
	}
	return snap, nil
}

func isACMEEligibleHost(h string) bool {
	if h == "" || h == "*" || h == "localhost" || !strings.Contains(h, ".") {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return false
	}
	return true
}

func sanitizeHostDir(host string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(host) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "._")
	if out == "" {
		return "default"
	}
	return out
}

func buildSiteConfig(base config, gf configfile.GlobalConfig, sc configfile.SiteConfig) (config, error) {
	cfg := base
	cfg.configFile = ""
	cfg.configManaged = true
	cfg.siteHost = sc.Hosts[0]
	cfg.preset = sc.Preset
	cfg.settingBase = nil
	cfg.settingBaseSources = nil
	cfg.settingFile = nil

	// Global defaults.
	if gf.Listen != "" {
		cfg.listen = gf.Listen
	}
	if gf.HTTPListen != "" {
		cfg.tlsHTTPListen = gf.HTTPListen
	}
	if gf.TLSEmail != "" {
		cfg.tlsEmail = gf.TLSEmail
	}
	if gf.TLSCache != "" {
		cfg.tlsCacheDir = gf.TLSCache
	}
	cfg.tlsStaging = gf.TLSStaging
	if gf.TLSMinVersion != "" {
		cfg.tlsMinVersion = gf.TLSMinVersion
	}
	if gf.HSTSMaxAge > 0 {
		cfg.hstsMaxAge = gf.HSTSMaxAge
	}
	cfg.http3 = gf.HTTP3
	if gf.PortalListen != "" {
		cfg.portal.listen = gf.PortalListen
	}
	if gf.PortalAllow != "" {
		cfg.portal.allowSpec = gf.PortalAllow
	}
	if gf.PortalTLSCert != "" {
		cfg.portal.tlsCert = gf.PortalTLSCert
		cfg.portal.tlsKey = gf.PortalTLSKey
	}
	if gf.PortalSecureCookie != nil {
		cfg.portal.secureCookie = *gf.PortalSecureCookie
	}
	if gf.TrustedProxies != "" {
		cfg.trustedProxies = gf.TrustedProxies
	}
	if gf.LogFormat != "" {
		cfg.logFormat = gf.LogFormat
	}
	if gf.LogLevel != "" {
		cfg.logLevel = gf.LogLevel
	}
	if gf.StatsAuth != nil {
		cfg.statsAuth = *gf.StatsAuth
	}
	if gf.RoomVerifyKeys != "" {
		cfg.roomVerifyKeys = gf.RoomVerifyKeys
	}
	if gf.RoomSignedMaxTTL != "" {
		d, err := time.ParseDuration(gf.RoomSignedMaxTTL)
		if err != nil {
			return config{}, fmt.Errorf("invalid global room_signed_max_ttl %q: %w", gf.RoomSignedMaxTTL, err)
		}
		cfg.roomSignedMaxTTL = d
	}
	if gf.RoomLeaseFraction != nil {
		cfg.roomLeaseFraction = *gf.RoomLeaseFraction
	}
	if gf.BodyReadIdleTimeout != "" {
		d, err := time.ParseDuration(gf.BodyReadIdleTimeout)
		if err != nil {
			return config{}, fmt.Errorf("invalid global body_read_idle_timeout %q: %w", gf.BodyReadIdleTimeout, err)
		}
		cfg.bodyReadIdleTimeout = d
	}
	if gf.MaxUploadTime != "" {
		d, err := time.ParseDuration(gf.MaxUploadTime)
		if err != nil {
			return config{}, fmt.Errorf("invalid global max_upload_time %q: %w", gf.MaxUploadTime, err)
		}
		cfg.maxUploadTime = d
	}
	if gf.UpstreamTimeout != "" {
		d, err := time.ParseDuration(gf.UpstreamTimeout)
		if err != nil {
			return config{}, fmt.Errorf("invalid global upstream_timeout %q: %w", gf.UpstreamTimeout, err)
		}
		cfg.headerTimeout = d
	}
	// Global networks_config can be shared across sites, whereas fastlane_config is
	// per-site (or global fallback when a single site is declared) so origins stay distinct.
	if gf.NetworksConfig != "" {
		cfg.networksFile = gf.NetworksConfig
	}
	if gf.FastlaneConfig != "" {
		cfg.fastlaneFile = gf.FastlaneConfig
	}
	if gf.FastlaneLockDestinations != nil {
		cfg.fastlaneLockDestinations = *gf.FastlaneLockDestinations
	}
	if gf.DataDir != "" {
		cfg.dataDir = filepath.Join(gf.DataDir, "sites", sanitizeHostDir(sc.Hosts[0]))
	} else {
		cfg.dataDir = ""
	}

	// Clear global TLS fields on per-site app configs (TLS is terminated at
	// the shared multi-vhost listener, so site normalize() validates routing
	// without re-checking shared ACME/PEM settings).
	cfg.tlsCert = ""
	cfg.tlsKey = ""
	cfg.tlsDomains = ""
	cfg.tlsHosts = nil
	cfg.tlsHTTPListen = ""

	// Apply per-site directives.
	if sc.Upstream != "" {
		cfg.upstream = sc.Upstream
	}
	if sc.Root != "" {
		cfg.staticRoot = sc.Root
	}
	if len(sc.Mounts) > 0 {
		cfg.staticMounts = strings.Join(sc.Mounts, ",")
	}
	if sc.StaticAllowExt != "" {
		cfg.staticAllowExt = sc.StaticAllowExt
	}
	if sc.StaticCacheControl != "" {
		cfg.staticCacheControl = sc.StaticCacheControl
	}
	if sc.StaticFallback != nil {
		cfg.staticFallback = *sc.StaticFallback
	}
	if sc.Compress != nil {
		cfg.compress = *sc.Compress
	}
	if sc.Assets != "" {
		cfg.assets = sc.Assets
	}
	if sc.AssetPublic != "" {
		cfg.assetPublic = sc.AssetPublic
	}
	if sc.Bypass != "" {
		cfg.bypass = sc.Bypass
	}
	if sc.StreamPaths != "" {
		cfg.streamPaths = sc.StreamPaths
	}
	if sc.Cap > 0 {
		cfg.capacity = sc.Cap
	}
	if sc.MaxQueue != nil {
		cfg.maxQueue = *sc.MaxQueue
	}
	if sc.PriorityCap > 0 {
		cfg.priorityCap = sc.PriorityCap
	}
	if sc.PriorityLaneRank > 0 {
		cfg.priorityLaneRank = sc.PriorityLaneRank
	}
	if sc.SecureCookie != nil {
		cfg.secureCookie = *sc.SecureCookie
	}
	if sc.PreserveHost != nil {
		cfg.preserveHost = *sc.PreserveHost
	}
	if sc.FCGIIndex != "" {
		cfg.fcgiIndex = sc.FCGIIndex
	}
	if sc.FCGIDenyPaths != "" {
		cfg.fcgiDenyPaths = sc.FCGIDenyPaths
	}
	if sc.MicroCache != "" && !strings.EqualFold(sc.MicroCache, "off") && sc.MicroCache != "0" {
		d, err := time.ParseDuration(sc.MicroCache)
		if err != nil {
			return config{}, fmt.Errorf("invalid micro_cache %q: %w", sc.MicroCache, err)
		}
		cfg.microCacheTTL = d
	}
	if sc.MicroCacheMaxMB > 0 {
		cfg.microCacheMaxMB = sc.MicroCacheMaxMB
	}
	if sc.Abuse != nil {
		cfg.abuseEnabled = *sc.Abuse
	}
	if sc.AbuseStrikes > 0 {
		cfg.abuseStrikes = sc.AbuseStrikes
	}
	if sc.BanPaths != "" {
		cfg.banPaths = sc.BanPaths
	}
	if sc.RoomVerifyKeys != "" {
		cfg.roomVerifyKeys = sc.RoomVerifyKeys
	}
	if sc.RoomScope != "" {
		cfg.roomScope = sc.RoomScope
	} else if strings.TrimSpace(cfg.roomVerifyKeys) != "" && sc.Hosts[0] != "*" {
		// Automatically isolate signed room tokens per virtual host so a token
		// minted for one site can never be replayed against another tenant.
		cfg.roomScope = sc.Hosts[0]
	}
	if sc.RoomSignedMaxTTL != "" {
		d, err := time.ParseDuration(sc.RoomSignedMaxTTL)
		if err != nil {
			return config{}, fmt.Errorf("invalid room_signed_max_ttl %q: %w", sc.RoomSignedMaxTTL, err)
		}
		cfg.roomSignedMaxTTL = d
	}
	if sc.RoomLeaseFraction != nil {
		cfg.roomLeaseFraction = *sc.RoomLeaseFraction
	}
	if sc.BodyReadIdleTimeout != "" {
		d, err := time.ParseDuration(sc.BodyReadIdleTimeout)
		if err != nil {
			return config{}, fmt.Errorf("invalid body_read_idle_timeout %q: %w", sc.BodyReadIdleTimeout, err)
		}
		cfg.bodyReadIdleTimeout = d
	}
	if sc.MaxUploadTime != "" {
		d, err := time.ParseDuration(sc.MaxUploadTime)
		if err != nil {
			return config{}, fmt.Errorf("invalid max_upload_time %q: %w", sc.MaxUploadTime, err)
		}
		cfg.maxUploadTime = d
	}
	if sc.UpstreamTimeout != "" {
		d, err := time.ParseDuration(sc.UpstreamTimeout)
		if err != nil {
			return config{}, fmt.Errorf("invalid upstream_timeout %q: %w", sc.UpstreamTimeout, err)
		}
		cfg.headerTimeout = d
	}
	if sc.FastlaneConfig != "" {
		cfg.fastlaneFile = sc.FastlaneConfig
	}
	if sc.NetworksConfig != "" {
		cfg.networksFile = sc.NetworksConfig
	}
	if sc.FastlaneLockDestinations != nil {
		cfg.fastlaneLockDestinations = *sc.FastlaneLockDestinations
	}

	// Apply edition preset (e.g., wordpress) after explicit fields so explicit
	// overrides in the site block always win.
	if sc.Preset == "wordpress" {
		if err := applyWordPressPreset(&cfg); err != nil {
			return config{}, err
		}
	}
	return cfg, nil
}

// ServeHTTP dispatches incoming requests to the matching virtual host based on
// the normalized Host header. Unknown hosts are rejected with 421 Misdirected
// Request rather than leaking into another tenant's waiting room.
func (vm *vhostManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	snap := vm.current()
	if snap == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	host, ok := normalizeRedirectHost(r.Host)
	var sr *siteRuntime
	if ok {
		sr = snap.byHost[host]
	}
	if sr == nil {
		sr = snap.defaultSite
	}
	if sr == nil {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
		return
	}
	sr.app.handler.ServeHTTP(w, r)
}

func (vm *vhostManager) buildTLS() (*tls.Config, *autocert.Manager, error) {
	snap := vm.current()
	if snap == nil || !snap.hasTLS {
		return nil, nil, nil
	}
	gf := snap.file.Global
	minVer, err := parseTLSMinVersion(gf.TLSMinVersion)
	if err != nil {
		return nil, nil, err
	}

	var mgr *autocert.Manager
	if strings.TrimSpace(gf.TLSCache) != "" && len(snap.acmeHosts) > 0 {
		if err := ensureWritableDir(gf.TLSCache); err != nil {
			return nil, nil, err
		}
		mgr = &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(gf.TLSCache),
			Email:  gf.TLSEmail,
			HostPolicy: func(_ context.Context, host string) error {
				s := vm.current()
				h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
				if s != nil && s.acmeHosts[h] {
					return nil
				}
				return fmt.Errorf("acme/autocert: host %q not configured in Concertfile", host)
			},
		}
		if gf.TLSStaging {
			mgr.Client = &acme.Client{DirectoryURL: letsEncryptStagingURL}
		}
	}

	protos := []string{"h2", "http/1.1"}
	if mgr != nil {
		protos = append(protos, acme.ALPNProto)
	}
	tc := &tls.Config{
		MinVersion:   minVer,
		CipherSuites: strongCipherSuites,
		NextProtos:   protos,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			s := vm.current()
			if s == nil {
				return nil, errors.New("no active configuration")
			}
			sn := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hello.ServerName)), ".")
			if sr, ok := s.byHost[sn]; ok && sr.cert != nil {
				return sr.cert.getCertificate(hello)
			}
			if s.globalCert != nil {
				return s.globalCert.getCertificate(hello)
			}
			if mgr != nil {
				return mgr.GetCertificate(hello)
			}
			if len(s.sites) > 0 && s.sites[0].cert != nil {
				return s.sites[0].cert.getCertificate(hello)
			}
			return nil, fmt.Errorf("no TLS certificate configured for %q", hello.ServerName)
		},
	}
	return tc, mgr, nil
}

func (vm *vhostManager) httpRedirectHandler(listenAddr string, mgr *autocert.Manager) http.Handler {
	_, httpsPort, _ := net.SplitHostPort(listenAddr)
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		host, ok := normalizeRedirectHost(r.Host)
		if !ok {
			http.Error(w, "invalid Host header", http.StatusBadRequest)
			return
		}
		s := vm.current()
		if s == nil || (s.byHost[host] == nil && s.defaultSite == nil) {
			http.Error(w, "host not configured for HTTPS", http.StatusMisdirectedRequest)
			return
		}
		dstHost := host
		if httpsPort != "" && httpsPort != "443" {
			dstHost = net.JoinHostPort(host, httpsPort)
		} else if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
			dstHost = "[" + host + "]"
		}
		target := "https://" + dstHost + r.URL.RequestURI()
		code := http.StatusPermanentRedirect
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			code = http.StatusMovedPermanently
		}
		http.Redirect(w, r, target, code)
	})
	if mgr != nil {
		return mgr.HTTPHandler(fallback)
	}
	return fallback
}

type siteSummary struct {
	Host             string   `json:"host"`
	Aliases          []string `json:"aliases,omitempty"`
	Preset           string   `json:"preset,omitempty"`
	Active           int      `json:"active"`
	Cap              int32    `json:"cap"`
	Queued           int64    `json:"queued"`
	StaticServed     int64    `json:"static_served"`
	FCGIRequests     int64    `json:"fcgi_requests"`
	MicroCacheHits   int64    `json:"microcache_hits"`
	UpstreamHealthy  int      `json:"upstream_healthy"`
	UpstreamBackends int      `json:"upstream_backends"`
	RuntimeOverride  bool     `json:"runtime_override"`
}

type vhostSummary struct {
	ConfigManaged bool          `json:"config_managed"`
	ConfigFile    string        `json:"config_file,omitempty"`
	Edition       string        `json:"edition"`
	Sites         []siteSummary `json:"sites"`
	Totals        struct {
		Sites          int   `json:"sites"`
		Active         int   `json:"active"`
		Cap            int64 `json:"cap"`
		Queued         int64 `json:"queued"`
		StaticServed   int64 `json:"static_served"`
		MicroCacheHits int64 `json:"microcache_hits"`
		UnhealthySites int   `json:"unhealthy_sites"`
	} `json:"totals"`
}

func (vm *vhostManager) summary() vhostSummary {
	snap := vm.current()
	out := vhostSummary{
		ConfigManaged: true,
		ConfigFile:    vm.configPath,
		Edition:       Edition(),
	}
	if snap == nil {
		return out
	}
	now := time.Now()
	for _, sr := range snap.sites {
		a := sr.app
		g := a.current()
		active := a.room.Len()
		capVal := a.room.Cap()
		queued := a.room.LiveQueueDepth()
		staticServed := a.stats.staticServed.Load()
		fcgiReq := a.stats.fcgiRequests.Load()
		mcHits := a.stats.microCacheHits.Load()
		totalB, healthyB := 0, 0
		if g.upstreams != nil {
			totalB = len(g.upstreams.backends)
			healthyB = g.upstreams.healthyCount(now)
		}
		var aliases []string
		if len(sr.hosts) > 1 {
			aliases = sr.hosts[1:]
		}
		out.Sites = append(out.Sites, siteSummary{
			Host:             sr.primaryHost,
			Aliases:          aliases,
			Preset:           sr.preset,
			Active:           active,
			Cap:              capVal,
			Queued:           queued,
			StaticServed:     staticServed,
			FCGIRequests:     fcgiReq,
			MicroCacheHits:   mcHits,
			UpstreamHealthy:  healthyB,
			UpstreamBackends: totalB,
			RuntimeOverride:  a.runtimeCapOverride.Load(),
		})
		out.Totals.Sites++
		out.Totals.Active += active
		out.Totals.Cap += int64(capVal)
		out.Totals.Queued += queued
		out.Totals.StaticServed += staticServed
		out.Totals.MicroCacheHits += mcHits
		if totalB > 0 && healthyB == 0 {
			out.Totals.UnhealthySites++
		}
	}
	return out
}

func (vm *vhostManager) renderPrometheusMetrics(selected *app) string {
	var b strings.Builder
	snap := vm.current()
	if snap != nil {
		writePromMetric(&b, "concert_vhost_sites_total", "gauge", "Total configured virtual host sites.", len(snap.sites))
		b.WriteString("# HELP concert_site_room_active Active waiting-room slots per virtual host.\n# TYPE concert_site_room_active gauge\n")
		for _, sr := range snap.sites {
			fmt.Fprintf(&b, "concert_site_room_active{site=%q} %d\n", sr.primaryHost, sr.app.room.Len())
		}
		b.WriteString("# HELP concert_site_room_cap Configured capacity cap per virtual host.\n# TYPE concert_site_room_cap gauge\n")
		for _, sr := range snap.sites {
			fmt.Fprintf(&b, "concert_site_room_cap{site=%q} %d\n", sr.primaryHost, sr.app.room.Cap())
		}
		b.WriteString("# HELP concert_site_room_queue_depth Live waiting queue depth per virtual host.\n# TYPE concert_site_room_queue_depth gauge\n")
		for _, sr := range snap.sites {
			fmt.Fprintf(&b, "concert_site_room_queue_depth{site=%q} %d\n", sr.primaryHost, sr.app.room.LiveQueueDepth())
		}
		b.WriteString("# HELP concert_site_static_served_total Local static files served per virtual host.\n# TYPE concert_site_static_served_total counter\n")
		for _, sr := range snap.sites {
			fmt.Fprintf(&b, "concert_site_static_served_total{site=%q} %d\n", sr.primaryHost, sr.app.stats.staticServed.Load())
		}
	}
	if selected == nil {
		selected = vm.primaryApp()
	}
	if selected != nil {
		b.WriteString(selected.renderPrometheusMetrics())
	}
	return b.String()
}

// runVhost boots Concert in declarative multi-vhost mode (-config).
func runVhost(ctx context.Context, baseCfg config) error {
	vm, err := newVhostManager(baseCfg)
	if err != nil {
		return err
	}
	defer vm.Close()

	snap := vm.current()
	gf := snap.file.Global
	listenAddr := gf.Listen
	if listenAddr == "" {
		listenAddr = baseCfg.listen
	}
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	tlsCfg, acmeMgr, err := vm.buildTLS()
	if err != nil {
		return err
	}
	if gf.HTTP3 && tlsCfg == nil {
		return errors.New("http3 requires TLS (global tls_cert/tls_key, per-site tls_cert/tls_key, or tls_cache with ACME domains)")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p, err := newVhostPortal(vm)
	if err != nil {
		return err
	}
	var handler http.Handler = vm
	if gf.HTTP3 && tlsCfg != nil {
		handler = altSvcMiddleware(listenAddr, handler)
	}
	if p != nil {
		handler = p.wrap(handler)
	}

	var httpRedirectEP *endpoint
	if hl := strings.TrimSpace(gf.HTTPListen); hl != "" {
		if tlsCfg == nil {
			p.closeListener()
			return errors.New("global http_listen requires TLS")
		}
		httpLn, herr := listen(hl)
		if herr != nil {
			p.closeListener()
			return fmt.Errorf("http_listen %s: %w", hl, herr)
		}
		httpRedirectEP = newEndpoint("http-redirect", vm.httpRedirectHandler(listenAddr, acmeMgr), 5*time.Second, newServer)
		httpRedirectEP.serveOn(httpLn, hl)
	}

	ln, err := listen(listenAddr)
	if err != nil {
		if httpRedirectEP != nil {
			_ = httpRedirectEP.shutdown()
		}
		p.closeListener()
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}

	mainEP := newEndpoint("main", handler, shutdownGrace, newServer)
	mainEP.setTLS(tlsCfg)
	portalEP := p.start(ctx)

	var h3Closer func() error
	if gf.HTTP3 && tlsCfg != nil {
		h3Closer, err = startHTTP3Server(listenAddr, tlsCfg, handler)
		if err != nil {
			_ = ln.Close()
			if httpRedirectEP != nil {
				_ = httpRedirectEP.shutdown()
			}
			p.closeListener()
			return err
		}
	}

	// SIGHUP reloads the Concertfile atomically without dropping listeners.
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sighup:
				if rerr := vm.Reload(); rerr != nil {
					log.Printf("config: SIGHUP reload failed (keeping active config): %v", rerr)
				}
			}
		}
	}()

	hosts := make([]string, 0, len(snap.sites))
	for _, sr := range snap.sites {
		hosts = append(hosts, strings.Join(sr.hosts, ","))
	}
	log.Printf("%s multi-vhost listening on %s (%d site(s): %s, config=%s, http3=%v)",
		Edition(), ln.Addr(), len(snap.sites), strings.Join(hosts, " | "), vm.configPath, gf.HTTP3)

	mainEP.serveOn(ln, listenAddr)
	err = awaitShutdown(ctx, mainEP, portalEP, httpRedirectEP)
	if h3Closer != nil {
		if cerr := h3Closer(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}
