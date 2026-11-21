package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
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

	"github.com/andreimerlescu/concert/internal/hop"
)

// Multi-upstream pool with least-inflight load balancing, circuit breaking,
// optional active health probing, custom CA trust, and upstream mTLS.

type upstreamBackend struct {
	target   *url.URL
	inFlight atomic.Int64
	// slots is the page capacity a leaf behind this target offers this
	// edge, from the control plane; 0 when unknown. See hop_control.go.
	slots atomic.Int64
	// fullUntil (unix nanos) marks a leaf that just answered with
	// backpressure; pick avoids it briefly while others have room.
	fullUntil atomic.Int64

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
	retries     int // extra attempts for bodyless requests; see trackedTransport
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
		retries:     cfg.upstreamRetries,
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

// backpressureHold is how long pick avoids a leaf that refused a request
// for capacity, while another has room.
const backpressureHold = time.Second

// pick selects a backend for a new request; see pickExcept.
func (p *upstreamPool) pick(now time.Time) (*upstreamBackend, bool) {
	return p.pickExcept(now, nil)
}

// pickExcept selects the healthy backend with the most free capacity,
// skipping those in tried. When every healthy backend reports its slots
// (leaves on an edge), free capacity is slots minus in-flight; otherwise it
// is the fewest in flight. Backends that just answered with backpressure
// are used only when nothing else is healthy. Ties break round-robin.
// Returns (backend, true) if a healthy backend was found; otherwise a
// round-robin fallback (so half-open probes can recover) and false.
func (p *upstreamPool) pickExcept(now time.Time, tried []*upstreamBackend) (*upstreamBackend, bool) {
	n := len(p.backends)
	if n == 1 {
		b := p.backends[0]
		return b, b.isHealthy(now)
	}
	start := int(p.rr.Add(1) % uint64(n))
	isTried := func(b *upstreamBackend) bool {
		for _, t := range tried {
			if t == b {
				return true
			}
		}
		return false
	}
	nowNS := now.UnixNano()
	slotAware := true
	for _, b := range p.backends {
		if b.isHealthy(now) && b.slots.Load() <= 0 {
			slotAware = false
			break
		}
	}
	var best, bestFull *upstreamBackend
	var bestScore, bestFullScore int64 = -(1 << 62), -(1 << 62)
	for i := 0; i < n; i++ {
		b := p.backends[(start+i)%n]
		if isTried(b) || !b.isHealthy(now) {
			continue
		}
		score := -b.inFlight.Load()
		if slotAware {
			score += b.slots.Load()
		}
		if b.fullUntil.Load() > nowNS {
			if score > bestFullScore {
				bestFull, bestFullScore = b, score
			}
			continue
		}
		if score > bestScore {
			best, bestScore = b, score
		}
	}
	if best != nil {
		return best, true
	}
	if bestFull != nil {
		return bestFull, true
	}
	// Nothing healthy and untried: a round-robin candidate.
	for i := 0; i < n; i++ {
		if b := p.backends[(start+i)%n]; !isTried(b) {
			return b, false
		}
	}
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
func newEnterpriseProxy(cfg config, stats *counters, modify func(*http.Response) error, topo *topology) (*httputil.ReverseProxy, *upstreamPool, error) {
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
		TLSClientConfig:   tlsCfg,
		ForceAttemptHTTP2: true,
		// A proxy passes Accept-Encoding through as the browser sent it.
		// Left on, Go asks the origin for gzip on the browser's behalf and
		// unzips it here: the browser loses Content-Length (no download
		// progress) and Concert spends CPU on every asset.
		DisableCompression:    true,
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
		topo:  topo,
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
			if claim, ok := hopInFrom(pr.In.Context()); ok {
				// A leaf knows the client from the edge's signed claim;
				// the application sees it first, then the hop it came
				// through, however the tiers are connected.
				pr.Out.Header["X-Forwarded-For"] = []string{claim.Client.String()}
			} else if fromTrusted {
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
			for _, name := range []string{"PAYMENT-SIGNATURE", "PAYMENT-REQUIRED", "PAYMENT-RESPONSE", "Concert-Session", "X-Concert-CSRF", hop.Header, hop.BackpressureHeader, hop.NodeHeader} {
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
	topo  *topology // signs an edge's claims; nil or standalone signs nothing
}

// RoundTrip sends req to the backend chosen for it. On an edge it signs the
// request's hop claim for each attempt. With several backends and
// -upstream-retries, a request without a body is sent again to another
// backend when the first could not be reached or answered with a leaf's
// backpressure 503: in both cases nothing reached the application. Requests
// with a body are never retried, because the body may already be consumed.
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

	attempts := 1
	if t.pool.retries > 0 && len(t.pool.backends) > 1 && (req.Body == nil || req.Body == http.NoBody) {
		attempts += t.pool.retries
	}
	first := b
	var tried []*upstreamBackend
	for i := 0; ; i++ {
		out := req
		if b != first {
			out = retarget(req, first.target, b.target)
		}
		out = t.topo.signHop(out)
		resp, err := t.attempt(b, out)
		if err == nil && t.topo.isEdge() && resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get(hop.BackpressureHeader) != "" {
			t.topo.edge.backpressure.Add(1)
		}
		if i+1 >= attempts || !retryable(resp, err) {
			return resp, err
		}
		if resp != nil {
			b.fullUntil.Store(time.Now().Add(backpressureHold).UnixNano())
		}
		tried = append(tried, b)
		next, ok := t.pool.pickExcept(time.Now(), tried)
		if !ok {
			// Nothing else healthy: this answer is the best there is.
			return resp, err
		}
		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
		}
		if t.topo.isEdge() {
			t.topo.edge.retries.Add(1)
		}
		b = next
	}
}

// attempt sends one request to b and records the outcome.
func (t *trackedTransport) attempt(b *upstreamBackend, req *http.Request) (*http.Response, error) {
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
	switch {
	case resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get(hop.BackpressureHeader) != "":
		// A leaf at capacity is healthy: no circuit-breaker failure.
	case resp.StatusCode >= 502 && resp.StatusCode <= 504:
		b.recordFailure(t.pool.cbThreshold, t.pool.cbCooldown, fmt.Sprintf("HTTP %d", resp.StatusCode), time.Now())
	default:
		b.recordSuccess()
	}
	return resp, nil
}

// retryable reports whether an attempt failed without reaching the
// application: a leaf's backpressure answer, or no connection at all.
func retryable(resp *http.Response, err error) bool {
	if err == nil {
		return resp != nil && resp.StatusCode == http.StatusServiceUnavailable &&
			resp.Header.Get(hop.BackpressureHeader) != ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

// retarget points req, already rewritten for from, at to instead.
func retarget(req *http.Request, from, to *url.URL) *http.Request {
	out := new(http.Request)
	*out = *req
	u := *req.URL
	u.Scheme, u.Host = to.Scheme, to.Host
	if from.Path != to.Path {
		rest := strings.TrimPrefix(u.Path, strings.TrimSuffix(from.Path, "/"))
		u.Path = strings.TrimSuffix(to.Path, "/") + rest
		u.RawPath = ""
	}
	out.URL = &u
	if req.Host == from.Host {
		out.Host = to.Host
	}
	return out
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
