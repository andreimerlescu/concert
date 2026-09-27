package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/naddr/ess"
)

// IP details for the admin portal, from the ess package of naddr.
//
// concert learns who owns an address in one of two ways, tried in order:
//
//  1. NADDR_DATA names a local IPtoASN file (plain or .gz). ess loads it into
//     memory and answers in microseconds. NADDR_DATA_POLL sets how often the
//     file is checked for changes; a replaced file is reloaded without a
//     restart.
//  2. NADDR_ADDR names a running naddr service (host:port or an http(s)
//     URL). concert asks its /ip endpoint and caches the answers.
//
// When neither works, IP details are off and the portal shows bare
// addresses. Nothing else depends on them, so this never stops startup.
// When NADDR_DATA is set but cannot be loaded yet (the first download has
// not finished, for example), concert tries again every minute and switches
// to it as soon as it loads.
//
// Lookups never block a request. The local database answers from memory;
// the naddr service is asked in the background, and pages that list
// addresses warm the cache first, waiting at most ipInfoWarmWait.

const envNaddrAddr = "NADDR_ADDR"

const (
	ipInfoOff    = "off"
	ipInfoLocal  = "local"
	ipInfoRemote = "remote"

	ipInfoCacheMax   = 65536
	ipInfoLocalTTL   = 10 * time.Minute
	ipInfoRemoteTTL  = time.Hour // naddr marks /ip answers cacheable for an hour
	ipInfoMissTTL    = 10 * time.Minute
	ipInfoFailTTL    = time.Minute
	ipInfoTimeout    = 3 * time.Second
	ipInfoWarmWait   = 600 * time.Millisecond
	ipInfoParallel   = 8
	ipInfoInflight   = 1024
	ipInfoBodyLimit  = 64 << 10
	ipInfoRetryEvery = time.Minute
)

// ipInfoGetenv reads NADDR_*. Tests replace it so a developer's shell cannot
// load a full database into every test.
var ipInfoGetenv = os.Getenv

// ipInfo is everything the portal shows about one address. Found reports
// whether the IP database knew it; the address fields are filled either way.
type ipInfo struct {
	Found       bool
	Version     int // 4, 6 or 8
	IP4         string
	IP6         string
	IP8         string // 8-octet form, r.r.r.r.n.n.n.n
	IP8ASN      string // ASN dot form, asn.n.n.n.n
	Country     string
	CountryCode string
	Flag        string // regional-indicator emoji
	Number      uint32
	ASN         string
	Description string
	Routed      bool
	Range       string // IPv4 or IPv6 range
	Range8      string
	Range8ASN   string
}

// ipBadge is one of the 4 / 6 / 8 address badges. Tip is the tooltip body
// and Copy what a click copies.
type ipBadge struct {
	Label string
	Tip   string
	Copy  string
}

// Badges are the address forms shown for i: an IPv4 address shows 4 and 8,
// an IPv6 address shows 6, and an IPv8 address shows its IPv4 host and 8.
func (i ipInfo) Badges() []ipBadge {
	var out []ipBadge
	switch i.Version {
	case 4, 8:
		if i.IP4 != "" {
			out = append(out, ipBadge{Label: "4", Tip: "IPv4\n" + i.IP4, Copy: i.IP4})
		}
		if i.IP8 != "" {
			out = append(out, ipBadge{Label: "8", Tip: "IPv8\n" + i.IP8 + "\n" + i.IP8ASN, Copy: i.IP8})
		}
	case 6:
		if i.IP6 != "" {
			out = append(out, ipBadge{Label: "6", Tip: "IPv6\n" + i.IP6, Copy: i.IP6})
		}
	}
	return out
}

// CountryTitle is the flag's tooltip.
func (i ipInfo) CountryTitle() string {
	if i.CountryCode == "" || i.CountryCode == "None" {
		return "No country assigned"
	}
	return i.Country + " (" + i.CountryCode + ")"
}

// ipCell is an address, IPv6 /64 or CIDR range as a table cell shows it.
type ipCell struct {
	Text       string
	Info       ipInfo
	Prefix     bool // Text is a network, looked up by its first address
	RangeBadge bool // a range rather than one IPv6 client's /64
}

// flagEmoji turns a two-letter country code into its flag. None and
// unknown codes get a globe; ZZ, IPtoASN's "unknown" code, a white flag.
func flagEmoji(cc string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	switch cc {
	case "", "NONE", "UNKNOWN":
		return "🌐"
	case "ZZ":
		return "🏳️"
	}
	if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return "🌐"
	}
	return string([]rune{0x1F1E6 + rune(cc[0]-'A'), 0x1F1E6 + rune(cc[1]-'A')})
}

func basicInfo(a netip.Addr) ipInfo {
	var i ipInfo
	if !a.IsValid() {
		return i
	}
	if a.Is4() {
		i.Version, i.IP4 = 4, a.String()
	} else {
		i.Version, i.IP6 = 6, a.String()
	}
	return i
}

func infoFromResult(r ess.Result) ipInfo {
	i := ipInfo{
		Found:       true,
		Version:     r.Version,
		IP8:         r.IP8,
		IP8ASN:      r.IP8ASN,
		Country:     r.Country,
		CountryCode: r.CountryCode,
		Flag:        flagEmoji(r.CountryCode),
		Number:      r.Number,
		ASN:         r.ASN,
		Description: r.Description,
		Routed:      r.Routed,
		Range:       r.Range,
		Range8:      r.Range8,
		Range8ASN:   r.Range8ASN,
	}
	switch r.Version {
	case 4:
		i.IP4 = r.Address.String()
	case 6:
		i.IP6 = r.Address.String()
	case 8:
		if h := r.Address8.Host(); h.IsValid() {
			i.IP4 = h.String()
		}
	}
	return i
}

// ─── the lookup ──────────────────────────────────────────────────────────────

type ipSource struct {
	mode   string
	detail string
	res    *ess.Resolver // local
	base   string        // remote, such as http://127.0.0.1:8080
}

type ipCacheEntry struct {
	info ipInfo
	exp  time.Time
}

// ipLookup answers lookups from the source in use and caches them.
type ipLookup struct {
	src    atomic.Pointer[ipSource]
	client *http.Client

	mu       sync.Mutex
	cache    map[netip.Addr]ipCacheEntry
	inflight map[netip.Addr]chan struct{}
	sem      chan struct{}

	lookups  atomic.Int64
	failures atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
}

// newIPLookup picks NADDR_DATA, then NADDR_ADDR, then off. It never fails.
func newIPLookup(getenv func(string) string) *ipLookup {
	if getenv == nil {
		getenv = os.Getenv
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &ipLookup{
		client:   &http.Client{Timeout: ipInfoTimeout},
		cache:    map[netip.Addr]ipCacheEntry{},
		inflight: map[netip.Addr]chan struct{}{},
		sem:      make(chan struct{}, ipInfoParallel),
		ctx:      ctx,
		cancel:   cancel,
	}
	l.src.Store(&ipSource{mode: ipInfoOff,
		detail: "set NADDR_DATA to an IPtoASN file, or NADDR_ADDR to a naddr service"})

	dataSet := strings.TrimSpace(getenv(ess.EnvDataPath)) != ""
	var localErr error
	if dataSet {
		if localErr = l.openLocal(getenv); localErr == nil {
			return l
		}
	}
	if raw := strings.TrimSpace(getenv(envNaddrAddr)); raw != "" {
		if base, err := naddrBaseURL(raw); err == nil {
			l.src.Store(&ipSource{mode: ipInfoRemote, base: base, detail: "naddr service at " + base})
			log.Printf("ipinfo: asking the naddr service at %s", base)
		} else {
			log.Printf("ipinfo: %s: %v", envNaddrAddr, err)
		}
	}
	if dataSet {
		if l.mode() == ipInfoOff {
			l.src.Store(&ipSource{mode: ipInfoOff,
				detail: fmt.Sprintf("%s could not be loaded (%v); retrying every %s", ess.EnvDataPath, localErr, ipInfoRetryEvery)})
		}
		log.Printf("ipinfo: %s could not be loaded (%v); retrying every %s", ess.EnvDataPath, localErr, ipInfoRetryEvery)
		l.wg.Add(1)
		go l.retryLocal(getenv)
	}
	if l.mode() == ipInfoOff {
		log.Printf("ipinfo: IP details are off: %s", l.source().detail)
	}
	return l
}

// openLocal loads NADDR_DATA and watches it for changes.
func (l *ipLookup) openLocal(getenv func(string) string) error {
	cfg, err := ess.ConfigFromEnv(getenv)
	if err != nil {
		return err
	}
	res, err := ess.OpenConfig(cfg)
	if err != nil {
		return err
	}
	s := res.Stats()
	detail := fmt.Sprintf("%s (%d IPv4 | %d IPv6 | %d ASNs)", filepath.Base(cfg.Path), s.IPv4Ranges, s.IPv6Ranges, s.ASNs)
	l.src.Store(&ipSource{mode: ipInfoLocal, res: res, detail: detail})
	l.purge()
	log.Printf("ipinfo: using %s", detail)

	if cfg.PollInterval > 0 {
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			err := res.Watch(l.ctx, ess.WatchOptions{
				OnReload: func(s ess.Stats) {
					l.purge()
					log.Printf("ipinfo: %s reloaded (%d IPv4 and %d IPv6 ranges)", filepath.Base(cfg.Path), s.IPv4Ranges, s.IPv6Ranges)
				},
				OnError: func(err error) {
					log.Printf("ipinfo: reloading %s failed; still using the previous data: %v", cfg.Path, err)
				},
			})
			if err != nil && !errors.Is(err, ess.ErrNoSource) {
				log.Printf("ipinfo: watcher stopped: %v", err)
			}
		}()
	}
	return nil
}

func (l *ipLookup) retryLocal(getenv func(string) string) {
	defer l.wg.Done()
	t := time.NewTicker(ipInfoRetryEvery)
	defer t.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-t.C:
			if err := l.openLocal(getenv); err == nil {
				return
			}
		}
	}
}

// naddrBaseURL accepts host:port or an http(s) URL.
func naddrBaseURL(raw string) (string, error) {
	s := raw
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("%q is not host:port or an http(s) URL", raw)
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/"), nil
}

func (l *ipLookup) source() *ipSource {
	return l.src.Load()
}

func (l *ipLookup) mode() string {
	if l == nil {
		return ipInfoOff
	}
	return l.source().mode
}

// enabled reports whether any IP database is in use.
func (l *ipLookup) enabled() bool {
	return l.mode() != ipInfoOff
}

// describe is the source for operators.
func (l *ipLookup) describe() string {
	if l == nil {
		return "off"
	}
	s := l.source()
	switch s.mode {
	case ipInfoLocal:
		return s.detail
	case ipInfoRemote:
		return fmt.Sprintf("NADDR_ADDR %s (%d lookups failed)", s.detail, l.failures.Load())
	}
	return "off: " + s.detail
}

func (l *ipLookup) purge() {
	l.mu.Lock()
	clear(l.cache)
	l.mu.Unlock()
}

func (l *ipLookup) cached(a netip.Addr, now time.Time) (ipInfo, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.cache[a]
	if !ok || !now.Before(e.exp) {
		return ipInfo{}, false
	}
	return e.info, true
}

func (l *ipLookup) storeLocked(a netip.Addr, info ipInfo, exp time.Time) {
	if len(l.cache) >= ipInfoCacheMax {
		n := 0
		for k := range l.cache {
			delete(l.cache, k)
			if n++; n >= ipInfoCacheMax/16 {
				break
			}
		}
	}
	l.cache[a] = ipCacheEntry{info: info, exp: exp}
}

// get answers without blocking. With the naddr service, an address not yet
// cached is fetched in the background and returned bare this time.
func (l *ipLookup) get(a netip.Addr) ipInfo {
	a = a.Unmap().WithZone("")
	base := basicInfo(a)
	if l == nil || !a.IsValid() {
		return base
	}
	src := l.source()
	if src.mode == ipInfoOff {
		return base
	}
	now := time.Now()
	if info, ok := l.cached(a, now); ok {
		return info
	}
	l.lookups.Add(1)
	if src.mode == ipInfoLocal {
		info := base
		if r, found := src.res.Lookup(a); found {
			info = infoFromResult(r)
		}
		l.mu.Lock()
		l.storeLocked(a, info, now.Add(ipInfoLocalTTL))
		l.mu.Unlock()
		return info
	}
	l.fetchAsync(src, a)
	return base
}

// warm fetches the addresses a page is about to show from the naddr
// service, waiting at most ipInfoWarmWait. It does nothing for local data.
func (l *ipLookup) warm(addrs []netip.Addr) {
	if l == nil {
		return
	}
	src := l.source()
	if src.mode != ipInfoRemote {
		return
	}
	var waits []chan struct{}
	for _, a := range addrs {
		a = a.Unmap().WithZone("")
		if !a.IsValid() {
			continue
		}
		if ch := l.fetchAsync(src, a); ch != nil {
			waits = append(waits, ch)
		}
	}
	if len(waits) == 0 {
		return
	}
	t := time.NewTimer(ipInfoWarmWait)
	defer t.Stop()
	for _, ch := range waits {
		select {
		case <-ch:
		case <-t.C:
			return
		}
	}
}

// fetchAsync starts fetching a, or joins a fetch already running. It
// returns nil when a is cached or too many fetches are running.
func (l *ipLookup) fetchAsync(src *ipSource, a netip.Addr) chan struct{} {
	if l.ctx.Err() != nil {
		return nil
	}
	l.mu.Lock()
	if e, ok := l.cache[a]; ok && time.Now().Before(e.exp) {
		l.mu.Unlock()
		return nil
	}
	if ch, ok := l.inflight[a]; ok {
		l.mu.Unlock()
		return ch
	}
	if len(l.inflight) >= ipInfoInflight {
		l.mu.Unlock()
		return nil
	}
	ch := make(chan struct{})
	l.inflight[a] = ch
	l.wg.Add(1)
	l.mu.Unlock()

	go func() {
		defer l.wg.Done()
		info, ttl := l.fetchRemote(src.base, a)
		l.mu.Lock()
		l.storeLocked(a, info, time.Now().Add(ttl))
		delete(l.inflight, a)
		l.mu.Unlock()
		close(ch)
	}()
	return ch
}

// naddrIPResponse is naddr's /ip answer.
type naddrIPResponse struct {
	Success     bool   `json:"success"`
	V           int    `json:"v"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	N           uint32 `json:"n"`
	ASN         string `json:"asn"`
	Description string `json:"description"`
	Routed      bool   `json:"routed"`
	IP4         string `json:"ip4"`
	IP6         string `json:"ip6"`
	IP8         string `json:"ip8"`
	IP8ASN      string `json:"ip8asn"`
	Range4      string `json:"range4"`
	Range6      string `json:"range6"`
	Range8      string `json:"range8"`
	Range8ASN   string `json:"range8asn"`
}

func (r naddrIPResponse) info(a netip.Addr) ipInfo {
	i := basicInfo(a)
	i.Found = true
	if r.V != 0 {
		i.Version = r.V
	}
	if r.IP4 != "" {
		i.IP4 = r.IP4
	}
	if r.IP6 != "" {
		i.IP6 = r.IP6
	}
	i.IP8, i.IP8ASN = r.IP8, r.IP8ASN
	i.Country, i.CountryCode, i.Flag = r.Country, r.CountryCode, flagEmoji(r.CountryCode)
	i.Number, i.ASN, i.Description, i.Routed = r.N, r.ASN, r.Description, r.Routed
	i.Range = r.Range4
	if i.Range == "" {
		i.Range = r.Range6
	}
	i.Range8, i.Range8ASN = r.Range8, r.Range8ASN
	return i
}

// fetchRemote asks naddr about a. Unknown addresses are remembered for
// ipInfoMissTTL, failures for ipInfoFailTTL.
func (l *ipLookup) fetchRemote(base string, a netip.Addr) (ipInfo, time.Duration) {
	fallback := basicInfo(a)
	select {
	case l.sem <- struct{}{}:
		defer func() { <-l.sem }()
	case <-l.ctx.Done():
		return fallback, ipInfoFailTTL
	}
	ctx, cancel := context.WithTimeout(l.ctx, ipInfoTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/ip?addr="+url.QueryEscape(a.String()), nil)
	if err != nil {
		l.failures.Add(1)
		return fallback, ipInfoFailTTL
	}
	req.Header.Set("Accept", "application/json")
	resp, err := l.client.Do(req)
	if err != nil {
		l.failures.Add(1)
		return fallback, ipInfoFailTTL
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, ipInfoBodyLimit)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		_, _ = io.Copy(io.Discard, body)
		return fallback, ipInfoMissTTL
	default:
		_, _ = io.Copy(io.Discard, body)
		l.failures.Add(1)
		return fallback, ipInfoFailTTL
	}
	var r naddrIPResponse
	if err := json.NewDecoder(body).Decode(&r); err != nil || !r.Success {
		l.failures.Add(1)
		return fallback, ipInfoFailTTL
	}
	return r.info(a), ipInfoRemoteTTL
}

// cell is the ipcell template function: an address, an IPv6 /64 or a CIDR
// range, with what the IP database knows about it.
func (l *ipLookup) cell(text string) ipCell {
	c := ipCell{Text: text}
	s := strings.TrimSpace(text)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return c
		}
		p = p.Masked()
		c.Prefix = true
		c.RangeBadge = !(p.Addr().Is6() && p.Bits() == 64)
		c.Info = l.get(p.Addr())
		return c
	}
	if a, err := netip.ParseAddr(s); err == nil {
		c.Info = l.get(a)
	}
	return c
}

// logInfo is what the history log records about ip, or nil when unknown.
func (l *ipLookup) logInfo(ip netip.Addr) *logInfo {
	if l == nil || l.mode() == ipInfoOff {
		return nil
	}
	i := l.get(ip)
	if !i.Found {
		return nil
	}
	return &logInfo{CC: i.CountryCode, Country: i.Country, N: i.Number, ASN: i.ASN,
		Desc: i.Description, Range: i.Range, IP8: i.IP8}
}

// close stops the watcher, the retry loop and any fetches.
func (l *ipLookup) close() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		l.cancel()
		l.wg.Wait()
	})
}
