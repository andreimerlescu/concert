package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Multi-upstream pool with least-inflight load balancing, circuit breaking,
// optional active health probing, custom CA trust, and upstream mTLS.

type upstreamBackend struct {
	target   *url.URL
	inFlight atomic.Int64

	mu           sync.Mutex
	failures     int
	openUntil    time.Time
	activeFailed bool
	lastErr      string
}

func (b *upstreamBackend) isHealthy(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.activeFailed {
		return false
	}
	if !b.openUntil.IsZero() && now.Before(b.openUntil) {
		return false
	}
	return true
}

func (b *upstreamBackend) recordSuccess() {
	b.mu.Lock()
	b.failures = 0
	b.openUntil = time.Time{}
	b.activeFailed = false
	b.lastErr = ""
	b.mu.Unlock()
}

func (b *upstreamBackend) recordFailure(threshold int, cooldown time.Duration, errMsg string, now time.Time) {
	if threshold <= 0 {
		return
	}
	b.mu.Lock()
	b.failures++
	b.lastErr = errMsg
	if b.failures >= threshold {
		b.openUntil = now.Add(cooldown)
	}
	b.mu.Unlock()
}

func (b *upstreamBackend) setActiveHealth(ok bool, errMsg string) {
	b.mu.Lock()
	if ok {
		b.activeFailed = false
		b.failures = 0
		b.openUntil = time.Time{}
		b.lastErr = ""
	} else {
		b.activeFailed = true
		b.lastErr = errMsg
	}
	b.mu.Unlock()
}

type upstreamPool struct {
	backends    []*upstreamBackend
	rr          atomic.Uint64
	cbThreshold int
	cbCooldown  time.Duration
	healthPath  string
	healthEvery time.Duration
	transport   *http.Transport
	stop        chan struct{}
	stopOnce    sync.Once
}

func parseUpstreams(spec string) ([]*url.URL, error) {
	var out []*url.URL
	seen := map[string]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		u, err := url.Parse(part)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("invalid -upstream entry %q: must look like http://host:port", part)
		}
		if seen[u.String()] {
			continue
		}
		seen[u.String()] = true
		out = append(out, u)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("invalid -upstream %q: must look like http://host:port", spec)
	}
	return out, nil
}

func buildUpstreamTLSConfig(caFile, clientCert, clientKey string) (*tls.Config, error) {
	if caFile == "" && clientCert == "" && clientKey == "" {
		return &tls.Config{MinVersion: tls.VersionTLS12}, nil
	}
	tc := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if caFile != "" {
		pemData, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read -upstream-ca %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("parse -upstream-ca %s: no valid PEM certificates found", caFile)
		}
		tc.RootCAs = pool
	}
	if clientCert != "" || clientKey != "" {
		if clientCert == "" || clientKey == "" {
			return nil, errors.New("-upstream-client-cert and -upstream-client-key must both be set for upstream mTLS")
		}
		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("load upstream mTLS client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}

func newUpstreamPool(cfg config, transport *http.Transport) *upstreamPool {
	targets := cfg.targets
	if len(targets) == 0 && cfg.target != nil {
		targets = []*url.URL{cfg.target}
	}
	backends := make([]*upstreamBackend, len(targets))
	for i, u := range targets {
		backends[i] = &upstreamBackend{target: u}
	}
	p := &upstreamPool{
		backends:    backends,
		cbThreshold: cfg.upstreamCBFailures,
		cbCooldown:  cfg.upstreamCBCooldown,
		healthPath:  cfg.upstreamHealthPath,
		healthEvery: cfg.upstreamHealthInterval,
		transport:   transport,
		stop:        make(chan struct{}),
	}
	if p.healthPath != "" && p.healthEvery > 0 {
		go p.probeLoop()
	}
	return p
}

func (p *upstreamPool) close() {
	if p == nil {
		return
	}
	p.stopOnce.Do(func() {
		close(p.stop)
		if p.transport != nil {
			p.transport.CloseIdleConnections()
		}
	})
}

// pick selects the healthy backend with the fewest in-flight requests (breaking
// ties by round-robin). Returns (backend, true) if at least one backend is
// healthy; if all are open/unhealthy, returns (fallback, false) when there is
// only one backend (or nil, false if circuit breaking is active on multi-node).
func (p *upstreamPool) pick(now time.Time) (*upstreamBackend, bool) {
	n := len(p.backends)
	if n == 1 {
		b := p.backends[0]
		return b, b.isHealthy(now)
	}
	start := int(p.rr.Add(1) % uint64(n))
	var best *upstreamBackend
	var bestLoad int64 = 1<<62 - 1
	for i := 0; i < n; i++ {
		b := p.backends[(start+i)%n]
		if !b.isHealthy(now) {
			continue
		}
		load := b.inFlight.Load()
		if load < bestLoad {
			best = b
			bestLoad = load
		}
	}
	if best != nil {
		return best, true
	}
	// All backends open: pick round-robin candidate so half-open probes can recover.
	return p.backends[start], false
}

func (p *upstreamPool) healthyCount(now time.Time) int {
	if p == nil {
		return 0
	}
	n := 0
	for _, b := range p.backends {
		if b.isHealthy(now) {
			n++
		}
	}
	return n
}

func (p *upstreamPool) probeLoop() {
	client := &http.Client{
		Transport: p.transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	t := time.NewTicker(p.healthEvery)
	defer t.Stop()
	// Run an initial check quickly without blocking startup.
	p.probeAll(client)
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.probeAll(client)
		}
	}
}

func (p *upstreamPool) probeAll(client *http.Client) {
	for _, b := range p.backends {
		u := *b.target
		u.Path = p.healthPath
		u.RawQuery = ""
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "concert-healthcheck/"+BinaryVersion())
		resp, err := client.Do(req)
		cancel()
		if err != nil {
			b.setActiveHealth(false, err.Error())
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			b.setActiveHealth(true, "")
		} else {
			b.setActiveHealth(false, fmt.Sprintf("HTTP %d", resp.StatusCode))
		}
	}
}

type ctxBackendKey struct{}

// newEnterpriseProxy builds a reverse proxy backed by upstreamPool with mTLS,
// circuit breaking, active health probing, latency tracking, and request-id
// forwarding.
func newEnterpriseProxy(cfg config, stats *counters, modify func(*http.Response) error) (*httputil.ReverseProxy, *upstreamPool, error) {
	tlsCfg, err := buildUpstreamTLSConfig(cfg.upstreamCA, cfg.upstreamClientCert, cfg.upstreamClientKey)
	if err != nil {
		return nil, nil, err
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: cfg.headerTimeout,
	}

	pool := newUpstreamPool(cfg, transport)
	rt := &trackedTransport{
		base:  transport,
		pool:  pool,
		stats: stats,
	}

	proxy := &httputil.ReverseProxy{
		Transport:      rt,
		FlushInterval:  -1,
		ModifyResponse: modify,
		Rewrite: func(pr *httputil.ProxyRequest) {
			b, ok := pr.In.Context().Value(ctxBackendKey{}).(*upstreamBackend)
			if !ok || b == nil {
				b, _ = pool.pick(time.Now())
			}
			pr.SetURL(b.target)

			ra, hasAddr := remoteAddr(pr.In)
			fromTrusted := hasAddr && containsAddr(cfg.trusted, ra)
			if fromTrusted {
				if v := pr.In.Header.Values("X-Forwarded-For"); len(v) > 0 {
					pr.Out.Header["X-Forwarded-For"] = append([]string(nil), v...)
				}
			}
			pr.SetXForwarded()
			if fromTrusted {
				if p := pr.In.Header.Get("X-Forwarded-Proto"); p != "" {
					pr.Out.Header.Set("X-Forwarded-Proto", p)
				}
			}

			if cfg.preserveHost {
				pr.Out.Host = pr.In.Host
				pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			}
			stripCookies(pr.Out, proxyCookies...)
			for _, name := range []string{"PAYMENT-SIGNATURE", "PAYMENT-REQUIRED", "PAYMENT-RESPONSE", "Concert-Session", "X-Concert-CSRF"} {
				pr.Out.Header.Del(name)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return
			}
			if stats != nil {
				stats.upstreamErrors.Add(1)
			}
			if errors.Is(err, errCircuitOpen) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("Retry-After", "5")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("upstream circuit open\n"))
				return
			}
			log.Printf("upstream error %s %s: %v", req.Method, req.URL.Path, err)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("upstream unavailable\n"))
		},
	}
	return proxy, pool, nil
}

var errCircuitOpen = errors.New("upstream circuit breaker open")

type trackedTransport struct {
	base  http.RoundTripper
	pool  *upstreamPool
	stats *counters
}

func (t *trackedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	now := time.Now()
	b, ok := req.Context().Value(ctxBackendKey{}).(*upstreamBackend)
	healthy := true
	if !ok || b == nil {
		b, healthy = t.pool.pick(now)
	} else {
		healthy = b.isHealthy(now)
	}
	if !healthy && t.pool.cbThreshold > 0 {
		// If circuit is explicitly open (not just active health failed on single node with CB disabled), fail fast.
		return nil, errCircuitOpen
	}

	b.inFlight.Add(1)
	defer b.inFlight.Add(-1)

	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	dur := time.Since(start)
	if t.stats != nil {
		t.stats.upstreamLatency.observe(dur)
	}
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			b.recordFailure(t.pool.cbThreshold, t.pool.cbCooldown, err.Error(), time.Now())
		}
		return nil, err
	}
	if t.stats != nil {
		switch {
		case resp.StatusCode >= 500:
			t.stats.upstream5xx.Add(1)
		case resp.StatusCode >= 400:
			t.stats.upstream4xx.Add(1)
		case resp.StatusCode >= 300:
			t.stats.upstream3xx.Add(1)
		default:
			t.stats.upstream2xx.Add(1)
		}
	}
	if resp.StatusCode >= 502 && resp.StatusCode <= 504 {
		b.recordFailure(t.pool.cbThreshold, t.pool.cbCooldown, fmt.Sprintf("HTTP %d", resp.StatusCode), time.Now())
	} else {
		b.recordSuccess()
	}
	return resp, nil
}

// selectBackendForRequest attaches a chosen backend to req before proxying so
// Rewrite and trackedTransport use the same target.
func selectBackendForRequest(req *http.Request, pool *upstreamPool) *http.Request {
	if pool == nil || len(pool.backends) == 0 {
		return req
	}
	b, _ := pool.pick(time.Now())
	return req.WithContext(context.WithValue(req.Context(), ctxBackendKey{}, b))
}
