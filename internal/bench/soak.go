package bench

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Benchmark profile names accepted by -profile.
const (
	// ProfileCapacity runs the default ramp-and-bisect lemming capacity benchmark.
	ProfileCapacity = "capacity"
	// ProfileSoak100k runs the 100k-connection mixed human + flood soak profile.
	ProfileSoak100k = "soak-100k"
	// ProfileFairness runs a mixed human visitor + flood queue-fairness test.
	ProfileFairness = "fairness"
)

const (
	defaultReservoirCap   = 4096 // bounded streaming latency sample cap per cohort (R3)
	maxSoakInspectBytes   = 64 << 10
	maxSoakDrainBytes     = 16 << 20
	soak100kDefaultConns  = 100_000
	soak100kDefaultHumans = 200
	soak100kDefaultFlood  = 1000
	defaultMixHumans      = 64
	defaultMixFlood       = 256
	defaultPollInterval   = 250 * time.Millisecond
	defaultSoakDuration   = 30 * time.Second
	defaultBrowsePathsCap = 32
	concertAdmitCookie    = "concert_admit"
	roomTicketCookie      = "room_ticket"
	roomProbeCookie       = "room_probe"
	queueStatusPath       = "/queue/status"
)

// SoakOptions configures a mixed real-human + flood soak and queue-fairness run.
type SoakOptions struct {
	// Target is the root HTTP(S) URL of the Concert front door under test. Required.
	Target *url.URL
	// Profile names the profile label recorded in SoakReport (e.g. "soak-100k"
	// or "fairness"). Defaults to ProfileFairness.
	Profile string
	// Duration bounds how long the soak runs when MaxRequests is 0 or not yet
	// reached. Defaults to 30s.
	Duration time.Duration
	// MaxRequests optionally stops the soak once total completed requests across
	// both cohorts reach MaxRequests (0 means run for the full Duration).
	MaxRequests int64
	// HumanSessions is the number of concurrent legitimate browser-like sessions
	// carrying cookie jars, polling /queue/status when queued, and browsing
	// after admission. Defaults to 64 (200 for soak-100k).
	HumanSessions int
	// FloodWorkers is the number of concurrent flood/bot workers simulating a
	// whitelisted or untrusted lemmings surge. Defaults to 256 (1000 for
	// soak-100k). Set to 0 to test humans alone.
	FloodWorkers int
	// FloodKeepCookies controls whether flood workers keep cookie jars (true)
	// or act as stateless flooders (false, default).
	FloodKeepCookies bool
	// PollInterval is how frequently a queued human session polls /queue/status
	// when the server does not send a Retry-After header. Defaults to 250ms.
	PollInterval time.Duration
	// RequestTimeout bounds each individual HTTP request. Defaults to 10s.
	RequestTimeout time.Duration
	// HumanP95Limit is the maximum acceptable p95 latency for human requests.
	// Defaults to 2s; set negative to disable the latency threshold.
	HumanP95Limit time.Duration
	// MinHumanAdmissions is the minimum number of unique human sessions that
	// must gain admission for the fairness check to pass. Defaults to 1 when
	// HumanSessions > 0.
	MinHumanAdmissions int64
	// MaxRequeueAfterAdmit is the maximum tolerated count of already-admitted
	// human sessions being pushed back into the waiting room. Defaults to 0.
	MaxRequeueAfterAdmit int64
	// MaxHumanUpstream5xx is the maximum tolerated upstream 5xx responses seen
	// by human sessions. Defaults to 0.
	MaxHumanUpstream5xx int64
	// ReservoirSize caps the latency samples retained per cohort (R3). Defaults
	// to 4096.
	ReservoirSize int
	// BrowsePaths lists relative or absolute paths human sessions browse after
	// admission. Defaults to []string{"/"}.
	BrowsePaths []string
	// Header holds extra headers sent on every request from both cohorts.
	Header http.Header
	// FloodHeader holds extra headers sent only by the flood cohort (for example
	// X-Forwarded-For or an allowlist header to simulate a whitelisted surge).
	FloodHeader http.Header
	// Insecure skips TLS certificate verification (staging only).
	Insecure bool
	// Seed seeds deterministic reservoir sampling and path selection; 0 uses the
	// current time.
	Seed uint64
	// Logf optionally receives progress lines.
	Logf func(format string, args ...any)
	// Transport optionally overrides the HTTP RoundTripper (used by tests).
	Transport http.RoundTripper
}

// SoakProfileDefaults returns recommended SoakOptions populated for profile.
//
// # Parameters
//
//   - profile: Either ProfileSoak100k or ProfileFairness (empty selects
//     ProfileFairness).
//
// # Returns
//
// A SoakOptions value with profile defaults populated (Target remains nil).
//
// # Example
//
//	opts := bench.SoakProfileDefaults(bench.ProfileSoak100k)
//	opts.Target = targetURL
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/cli.go:131 (direct call)
//   - internal/bench/cli.go:131 (function value)
//   - internal/bench/soak_test.go:299 (direct call)
//   - internal/bench/soak_test.go:299 (function value)
//   - internal/bench/soak_test.go:362 (direct call)
//   - internal/bench/soak_test.go:362 (function value)
//   - internal/bench/soak_test.go:394 (direct call)
//   - internal/bench/soak_test.go:394 (function value)
//   - internal/bench/soak_test.go:446 (direct call)
//   - internal/bench/soak_test.go:446 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func SoakProfileDefaults(profile string) SoakOptions {
	switch profile {
	case ProfileSoak100k:
		return SoakOptions{
			Profile:            ProfileSoak100k,
			Duration:           defaultSoakDuration,
			MaxRequests:        soak100kDefaultConns,
			HumanSessions:      soak100kDefaultHumans,
			FloodWorkers:       soak100kDefaultFlood,
			PollInterval:       defaultPollInterval,
			RequestTimeout:     Defaults.RequestTimeout,
			HumanP95Limit:      Defaults.P95Limit,
			MinHumanAdmissions: 1,
			ReservoirSize:      defaultReservoirCap,
		}
	default:
		return SoakOptions{
			Profile:            ProfileFairness,
			Duration:           defaultSoakDuration,
			HumanSessions:      defaultMixHumans,
			FloodWorkers:       defaultMixFlood,
			PollInterval:       defaultPollInterval,
			RequestTimeout:     Defaults.RequestTimeout,
			HumanP95Limit:      Defaults.P95Limit,
			MinHumanAdmissions: 1,
			ReservoirSize:      defaultReservoirCap,
		}
	}
}

// withDefaults validates and fills default fields on o.
//
// # Parameters
//
// None (operates on receiver o).
//
// # Returns
//
// nil on valid options, or a validation error.
//
// # Example
//
//	if err := opts.withDefaults(); err != nil {
//		return nil, err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:854 (direct call)
//   - internal/bench/soak.go:854 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (o *SoakOptions) withDefaults() error {
	if o.Target == nil || (o.Target.Scheme != "http" && o.Target.Scheme != "https") || o.Target.Host == "" {
		return errors.New("bench soak: target must be an http(s) URL")
	}
	if o.Profile == "" {
		o.Profile = ProfileFairness
	}
	if o.Duration == 0 {
		o.Duration = defaultSoakDuration
	}
	if o.Duration < 50*time.Millisecond {
		return errors.New("bench soak: duration must be at least 50ms")
	}
	if o.MaxRequests < 0 {
		return errors.New("bench soak: max requests must be non-negative")
	}
	if o.HumanSessions < 0 || o.FloodWorkers < 0 {
		return errors.New("bench soak: human sessions and flood workers must be non-negative")
	}
	if o.HumanSessions == 0 && o.FloodWorkers == 0 {
		if o.Profile == ProfileSoak100k {
			o.HumanSessions = soak100kDefaultHumans
			o.FloodWorkers = soak100kDefaultFlood
		} else {
			o.HumanSessions = defaultMixHumans
			o.FloodWorkers = defaultMixFlood
		}
	}
	if o.PollInterval <= 0 {
		o.PollInterval = defaultPollInterval
	}
	if o.RequestTimeout <= 0 {
		o.RequestTimeout = Defaults.RequestTimeout
	}
	if o.HumanP95Limit == 0 {
		o.HumanP95Limit = Defaults.P95Limit
	}
	if o.MinHumanAdmissions == 0 && o.HumanSessions > 0 {
		o.MinHumanAdmissions = 1
	}
	if o.MaxRequeueAfterAdmit < 0 || o.MaxHumanUpstream5xx < 0 {
		return errors.New("bench soak: fairness thresholds must be non-negative")
	}
	if o.ReservoirSize <= 0 {
		o.ReservoirSize = defaultReservoirCap
	}
	if o.Seed == 0 {
		o.Seed = uint64(time.Now().UnixNano())
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return nil
}

// LatencySummary reports bounded-memory latency statistics in milliseconds.
type LatencySummary struct {
	Count  int64   `json:"count"`
	MinMs  float64 `json:"min_ms"`
	MeanMs float64 `json:"mean_ms"`
	P50Ms  float64 `json:"p50_ms"`
	P95Ms  float64 `json:"p95_ms"`
	P99Ms  float64 `json:"p99_ms"`
	MaxMs  float64 `json:"max_ms"`
}

// LatencyReservoir implements a bounded-memory streaming latency tracker using
// Vitter's Algorithm R reservoir sampling so arbitrarily long 100k+ connection
// soaks consume O(capacity) memory (R3). It is safe for concurrent use.
type LatencyReservoir struct {
	mu      sync.Mutex
	cap     int
	samples []time.Duration
	count   int64
	sumNs   int64
	minDur  time.Duration
	maxDur  time.Duration
	rng     *rand.Rand
}

// NewLatencyReservoir creates a bounded LatencyReservoir retaining at most
// capacity duration samples.
//
// # Parameters
//
//   - capacity: Maximum retained samples (clamped to defaultReservoirCap when
//     <= 0).
//   - seed: PRNG seed for deterministic Algorithm R reservoir replacement.
//
// # Returns
//
// A ready *LatencyReservoir safe for concurrent Add and Snapshot calls.
//
// # Example
//
//	res := bench.NewLatencyReservoir(4096, 1)
//	res.Add(12 * time.Millisecond)
//	sum := res.Snapshot()
//	_ = sum.P95Ms
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:559 (direct call)
//   - internal/bench/soak.go:559 (function value)
//   - internal/bench/soak_test.go:23 (direct call)
//   - internal/bench/soak_test.go:23 (function value)
//   - internal/bench/soak_test.go:260 (direct call)
//   - internal/bench/soak_test.go:260 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func NewLatencyReservoir(capacity int, seed uint64) *LatencyReservoir {
	if capacity <= 0 {
		capacity = defaultReservoirCap
	}
	return &LatencyReservoir{
		cap:     capacity,
		samples: make([]time.Duration, 0, capacity),
		rng:     rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
	}
}

// Add records a single latency duration into the bounded reservoir and updates
// exact running count, sum, min, and max.
//
// # Parameters
//
//   - d: Observed request duration (negative values are clamped to 0).
//
// # Concurrency
//
// Safe for concurrent calls across worker goroutines.
//
// # Example
//
//	res.Add(15 * time.Millisecond)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:1135 (direct call)
//   - internal/bench/soak.go:1135 (function value)
//   - internal/bench/soak.go:1149 (direct call)
//   - internal/bench/soak.go:1149 (function value)
//   - internal/bench/soak.go:1327 (direct call)
//   - internal/bench/soak.go:1327 (function value)
//   - internal/bench/soak.go:1336 (direct call)
//   - internal/bench/soak.go:1336 (function value)
//   - internal/bench/soak_test.go:30 (direct call)
//   - internal/bench/soak_test.go:30 (function value)
//   - internal/bench/soak_test.go:262 (direct call)
//   - internal/bench/soak_test.go:262 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (r *LatencyReservoir) Add(d time.Duration) {
	if d < 0 {
		d = 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.count++
	r.sumNs += d.Nanoseconds()
	if r.count == 1 || d < r.minDur {
		r.minDur = d
	}
	if r.count == 1 || d > r.maxDur {
		r.maxDur = d
	}
	if len(r.samples) < r.cap {
		r.samples = append(r.samples, d)
		return
	}
	// Algorithm R: keep each incoming item with probability cap/count.
	j := r.rng.Int64N(r.count)
	if j < int64(r.cap) {
		r.samples[j] = d
	}
}

// Capacity returns the maximum number of samples retained in memory.
//
// # Parameters
//
// None.
//
// # Returns
//
// The fixed sample slice capacity configured at construction.
//
// # Example
//
//	cap := res.Capacity()
//	_ = cap
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak_test.go:264 (direct call)
//   - internal/bench/soak_test.go:264 (function value)
//   - internal/bench/soak_test.go:265 (direct call)
//   - internal/bench/soak_test.go:265 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (r *LatencyReservoir) Capacity() int {
	return r.cap
}

// Snapshot computes exact min/mean/max and reservoir-estimated p50/p95/p99
// latencies in milliseconds without mutating the retained sample slice order.
//
// # Parameters
//
// None.
//
// # Returns
//
// A LatencySummary snapshot. Returns the zero LatencySummary when empty.
//
// # Example
//
//	s := res.Snapshot()
//	fmt.Printf("p95=%.2fms\n", s.P95Ms)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:604 (direct call)
//   - internal/bench/soak.go:604 (function value)
//   - internal/bench/soak_test.go:32 (direct call)
//   - internal/bench/soak_test.go:32 (function value)
//   - internal/bench/soak_test.go:270 (direct call)
//   - internal/bench/soak_test.go:270 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (r *LatencyReservoir) Snapshot() LatencySummary {
	r.mu.Lock()
	if r.count == 0 {
		r.mu.Unlock()
		return LatencySummary{}
	}
	cp := make([]time.Duration, len(r.samples))
	copy(cp, r.samples)
	count := r.count
	sumNs := r.sumNs
	minDur := r.minDur
	maxDur := r.maxDur
	r.mu.Unlock()

	sortDur(cp)
	meanDur := time.Duration(sumNs / count)
	return LatencySummary{
		Count:  count,
		MinMs:  ms(minDur),
		MeanMs: ms(meanDur),
		P50Ms:  percentile(cp, 0.50),
		P95Ms:  percentile(cp, 0.95),
		P99Ms:  percentile(cp, 0.99),
		MaxMs:  ms(maxDur),
	}
}

// CohortStats summarizes bounded streaming metrics for one traffic cohort
// ("human" or "flood").
type CohortStats struct {
	Workers            int            `json:"workers"`
	Requests           int64          `json:"requests"`
	Bytes              int64          `json:"bytes"`
	OK2xx              int64          `json:"ok_2xx"`
	Admissions         int64          `json:"admissions"`
	RequeuedAfterAdmit int64          `json:"requeued_after_admit"`
	QueuedResponses    int64          `json:"queued_responses"`
	StatusPolls        int64          `json:"status_polls"`
	WaitingRoom503     int64          `json:"waiting_room_503"`
	CapacityBreaker503 int64          `json:"capacity_breaker_503"`
	Upstream5xx        int64          `json:"upstream_5xx"`
	Throttled429       int64          `json:"throttled_429"`
	Client4xx          int64          `json:"client_4xx"`
	TransportErrors    int64          `json:"transport_errors"`
	Latency            LatencySummary `json:"latency"`
}

// SoakReport holds the complete outcome of a soak or queue-fairness benchmark.
type SoakReport struct {
	Profile       string        `json:"profile"`
	Target        string        `json:"target"`
	Started       time.Time     `json:"started"`
	Finished      time.Time     `json:"finished"`
	Duration      time.Duration `json:"duration_ns"`
	TotalRequests int64         `json:"total_requests"`
	RPS           float64       `json:"rps"`
	Human         CohortStats   `json:"human"`
	Flood         CohortStats   `json:"flood"`
	Pass          bool          `json:"pass"`
	Reasons       []string      `json:"reasons,omitempty"`
	Verdict       string        `json:"verdict"`
}

type cohortRecorder struct {
	workers            int
	requests           atomic.Int64
	bytes              atomic.Int64
	ok2xx              atomic.Int64
	admissions         atomic.Int64
	requeuedAfterAdmit atomic.Int64
	queuedResponses    atomic.Int64
	statusPolls        atomic.Int64
	waitingRoom503     atomic.Int64
	capacityBreaker503 atomic.Int64
	upstream5xx        atomic.Int64
	throttled429       atomic.Int64
	client4xx          atomic.Int64
	transportErrors    atomic.Int64
	latency            *LatencyReservoir
}

// newCohortRecorder creates a bounded streaming recorder for one cohort.
//
// # Parameters
//
//   - workers: Configured worker concurrency for this cohort.
//   - reservoirCap: Maximum latency samples retained.
//   - seed: PRNG seed for reservoir sampling.
//
// # Returns
//
// An initialized *cohortRecorder.
//
// # Example
//
//	rec := newCohortRecorder(64, 4096, 1)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:868 (direct call)
//   - internal/bench/soak.go:868 (function value)
//   - internal/bench/soak.go:869 (direct call)
//   - internal/bench/soak.go:869 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func newCohortRecorder(workers, reservoirCap int, seed uint64) *cohortRecorder {
	return &cohortRecorder{
		workers: workers,
		latency: NewLatencyReservoir(reservoirCap, seed),
	}
}

// snapshot materializes CohortStats from atomic counters and the reservoir.
//
// # Parameters
//
// None.
//
// # Returns
//
// A point-in-time CohortStats value.
//
// # Example
//
//	stats := rec.snapshot()
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:904 (direct call)
//   - internal/bench/soak.go:904 (function value)
//   - internal/bench/soak.go:905 (direct call)
//   - internal/bench/soak.go:905 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (c *cohortRecorder) snapshot() CohortStats {
	return CohortStats{
		Workers:            c.workers,
		Requests:           c.requests.Load(),
		Bytes:              c.bytes.Load(),
		OK2xx:              c.ok2xx.Load(),
		Admissions:         c.admissions.Load(),
		RequeuedAfterAdmit: c.requeuedAfterAdmit.Load(),
		QueuedResponses:    c.queuedResponses.Load(),
		StatusPolls:        c.statusPolls.Load(),
		WaitingRoom503:     c.waitingRoom503.Load(),
		CapacityBreaker503: c.capacityBreaker503.Load(),
		Upstream5xx:        c.upstream5xx.Load(),
		Throttled429:       c.throttled429.Load(),
		Client4xx:          c.client4xx.Load(),
		TransportErrors:    c.transportErrors.Load(),
		Latency:            c.latency.Snapshot(),
	}
}

type soakOutcome int

const (
	outcomeOK soakOutcome = iota
	outcomeQueued
	outcomeWaitingRoom503
	outcomeCapacityBreaker503
	outcomeUpstream5xx
	outcomeThrottled429
	outcomeClient4xx
)

type soakClassification struct {
	outcome    soakOutcome
	queued     bool
	gotAdmit   bool
	retryAfter time.Duration
}

// classifySoakResponse categorizes a response from Concert or its upstream into
// waiting-room queue, waiting-room 503, capacity-breaker 503, upstream 5xx,
// 429 throttle, client 4xx, or 2xx success, and detects concert_admit issuance.
//
// # Parameters
//
//   - resp: Completed *http.Response (must be non-nil).
//   - body: Bounded prefix of the response body (up to maxSoakInspectBytes).
//
// # Returns
//
// A soakClassification describing the queue, breaker, admission, and error state.
//
// # Example
//
//	cls := classifySoakResponse(resp, bodyPrefix)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:1346 (direct call)
//   - internal/bench/soak.go:1346 (function value)
//   - internal/bench/soak_test.go:241 (direct call)
//   - internal/bench/soak_test.go:241 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func classifySoakResponse(resp *http.Response, body []byte) soakClassification {
	var cls soakClassification
	if resp == nil {
		return cls
	}

	for _, c := range resp.Cookies() {
		if c.Name == concertAdmitCookie && c.Value != "" && c.MaxAge >= 0 {
			cls.gotAdmit = true
		}
	}
	cls.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))

	queueHeader := strings.TrimSpace(resp.Header.Get("X-Concert-Queue")) == "1"
	hasRoomCookie := false
	for _, c := range resp.Cookies() {
		if c.Name == roomTicketCookie || c.Name == roomProbeCookie {
			hasRoomCookie = true
			break
		}
	}
	lowerBody := strings.ToLower(string(body))
	bodyQueuedJSON := strings.Contains(lowerBody, `"queued":true`) || strings.Contains(lowerBody, `"queued": true`)
	bodyStatusRef := strings.Contains(lowerBody, queueStatusPath) || strings.Contains(lowerBody, "room_probe=")
	bodyBreaker := strings.Contains(lowerBody, "waiting room is full") ||
		strings.Contains(lowerBody, "data-retry-after=") ||
		strings.Contains(lowerBody, `"queued":false`) ||
		strings.Contains(lowerBody, `"queued": false`)

	isQueued := queueHeader || hasRoomCookie || bodyQueuedJSON || bodyStatusRef
	breakerHeader := resp.Header.Get("X-Concert-Breaker") != "" || resp.Header.Get("X-Concert-Shed") != ""

	switch {
	case resp.StatusCode == http.StatusServiceUnavailable:
		if isQueued {
			cls.outcome = outcomeWaitingRoom503
			cls.queued = true
			return cls
		}
		if breakerHeader || bodyBreaker || resp.Header.Get("Retry-After") != "" {
			cls.outcome = outcomeCapacityBreaker503
			return cls
		}
		cls.outcome = outcomeUpstream5xx
		return cls
	case resp.StatusCode >= 500:
		cls.outcome = outcomeUpstream5xx
		return cls
	case resp.StatusCode == http.StatusTooManyRequests:
		if isQueued {
			cls.outcome = outcomeQueued
			cls.queued = true
			return cls
		}
		cls.outcome = outcomeThrottled429
		return cls
	case resp.StatusCode >= 400:
		cls.outcome = outcomeClient4xx
		return cls
	case isQueued:
		cls.outcome = outcomeQueued
		cls.queued = true
		return cls
	default:
		cls.outcome = outcomeOK
		return cls
	}
}

// parseRetryAfter parses an integer seconds Retry-After header value.
//
// # Parameters
//
//   - raw: Value of the HTTP Retry-After header.
//
// # Returns
//
// The parsed positive duration, or 0 when absent or non-positive.
//
// # Example
//
//	d := parseRetryAfter("4")
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:666 (direct call)
//   - internal/bench/soak.go:666 (function value)
//   - internal/bench/soak.go:1178 (direct call)
//   - internal/bench/soak.go:1178 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func parseRetryAfter(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// newSoakTransport creates a reusable high-concurrency http.Transport sized
// for soak workloads with explicit dial, TLS, and header timeouts.
//
// # Parameters
//
//   - opts: Validated SoakOptions.
//
// # Returns
//
// A configured *http.Transport; caller must call CloseIdleConnections on exit.
//
// # Example
//
//	tr := newSoakTransport(&opts)
//	defer tr.CloseIdleConnections()
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:860 (direct call)
//   - internal/bench/soak.go:860 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func newSoakTransport(opts *SoakOptions) *http.Transport {
	totalWorkers := opts.HumanSessions + opts.FloodWorkers
	idlePool := max(64, min(totalWorkers*2, 4096))
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          idlePool,
		MaxIdleConnsPerHost:   idlePool,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: opts.RequestTimeout,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.Insecure},
	}
}

// RunSoak executes a concurrent mixed human-visitor and flood-cohort soak and
// queue-fairness benchmark against opts.Target.
//
// # Parameters
//
//   - ctx: Controls cancellation and shutdown for all worker goroutines. Must
//     be non-nil.
//   - opts: Soak and fairness configuration. Target must be a valid http(s) URL.
//
// # Returns
//
// A populated *SoakReport containing per-cohort bounded streaming metrics and
// a pass/fail fairness verdict, or an error if opts is invalid. All spawned
// worker goroutines are joined before RunSoak returns (R2).
//
// # Concurrency
//
// Spawns exactly opts.HumanSessions + opts.FloodWorkers bounded goroutines
// owned by RunSoak and joined via sync.WaitGroup before returning.
//
// # Example
//
//	opts := bench.SoakProfileDefaults(bench.ProfileFairness)
//	opts.Target = targetURL
//	opts.Duration = 10 * time.Second
//	rep, err := bench.RunSoak(ctx, opts)
//	if err != nil {
//		return err
//	}
//	bench.SummarizeSoak(os.Stdout, rep)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/cli.go:159 (direct call)
//   - internal/bench/cli.go:159 (function value)
//   - internal/bench/soak_test.go:310 (direct call)
//   - internal/bench/soak_test.go:310 (function value)
//   - internal/bench/soak_test.go:371 (direct call)
//   - internal/bench/soak_test.go:371 (function value)
//   - internal/bench/soak_test.go:403 (direct call)
//   - internal/bench/soak_test.go:403 (function value)
//   - internal/bench/soak_test.go:454 (direct call)
//   - internal/bench/soak_test.go:454 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func RunSoak(ctx context.Context, opts SoakOptions) (*SoakReport, error) {
	if ctx == nil {
		return nil, errors.New("bench soak: context must not be nil")
	}
	if err := opts.withDefaults(); err != nil {
		return nil, err
	}

	transport := opts.Transport
	if transport == nil {
		tr := newSoakTransport(&opts)
		defer tr.CloseIdleConnections()
		transport = tr
	}

	browseURLs := resolveBrowseURLs(opts.Target, opts.BrowsePaths)
	statusURL := opts.Target.ResolveReference(&url.URL{Path: queueStatusPath}).String()

	humanRec := newCohortRecorder(opts.HumanSessions, opts.ReservoirSize, opts.Seed^0x1111)
	floodRec := newCohortRecorder(opts.FloodWorkers, opts.ReservoirSize, opts.Seed^0x2222)

	started := time.Now().UTC()
	runCtx, cancel := context.WithTimeout(ctx, opts.Duration)
	defer cancel()

	var totalCompleted atomic.Int64
	recordDone := func() {
		if opts.MaxRequests > 0 && totalCompleted.Add(1) >= opts.MaxRequests {
			cancel()
		}
	}

	// Goroutine ownership (C1/R2):
	//   Owner: RunSoak
	//   Count: exactly opts.HumanSessions + opts.FloodWorkers (bounded)
	//   Stop:  runCtx cancellation (parent ctx, opts.Duration, or MaxRequests)
	//   Join:  wg.Wait() before RunSoak returns
	var wg sync.WaitGroup
	for i := range opts.HumanSessions {
		id := i
		wg.Go(func() {
			runHumanSession(runCtx, id, &opts, transport, browseURLs, statusURL, humanRec, recordDone)
		})
	}
	for i := range opts.FloodWorkers {
		id := i
		wg.Go(func() {
			runFloodWorker(runCtx, id, &opts, transport, browseURLs[0], floodRec, recordDone)
		})
	}
	wg.Wait()

	finished := time.Now().UTC()
	elapsed := finished.Sub(started)
	human := humanRec.snapshot()
	flood := floodRec.snapshot()
	total := human.Requests + flood.Requests

	rep := &SoakReport{
		Profile:       opts.Profile,
		Target:        opts.Target.String(),
		Started:       started,
		Finished:      finished,
		Duration:      elapsed,
		TotalRequests: total,
		Human:         human,
		Flood:         flood,
	}
	if elapsed > 0 {
		rep.RPS = math.Round(float64(total)/elapsed.Seconds()*10) / 10
	}
	judgeSoak(rep, &opts)
	return rep, nil
}

// resolveBrowseURLs resolves browse path entries against target, defaulting to
// the target root URL and capping the slice to defaultBrowsePathsCap.
//
// # Parameters
//
//   - target: Base target URL.
//   - paths: Optional relative/absolute paths to browse.
//
// # Returns
//
// A non-empty slice of absolute target-origin URL strings.
//
// # Example
//
//	urls := resolveBrowseURLs(target, []string{"/", "/products"})
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:865 (direct call)
//   - internal/bench/soak.go:865 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func resolveBrowseURLs(target *url.URL, paths []string) []string {
	out := make([]string, 0, max(1, len(paths)))
	seen := make(map[string]struct{}, len(paths))
	for _, raw := range paths {
		if len(out) >= defaultBrowsePathsCap {
			break
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		ref, err := url.Parse(trimmed)
		if err != nil {
			continue
		}
		resolved := target.ResolveReference(ref)
		if !strings.EqualFold(resolved.Host, target.Host) {
			continue
		}
		s := resolved.String()
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		out = append(out, target.String())
	}
	return out
}

// runHumanSession executes one legitimate browser-like visitor session with a
// persistent cookie jar. When queued, it polls /queue/status until ready, then
// resumes browsing while tracking post-admission re-queues.
//
// # Parameters
//
//   - ctx: Run cancellation context.
//   - id: 0-based worker index for deterministic User-Agent and path selection.
//   - opts: Shared immutable SoakOptions.
//   - transport: Shared HTTP RoundTripper.
//   - browseURLs: Target URLs to browse in round-robin order.
//   - statusURL: Resolved /queue/status endpoint URL.
//   - rec: Human cohort streaming recorder.
//   - onRequest: Callback invoked after each completed request for MaxRequests
//     enforcement.
//
// # Example
//
//	runHumanSession(ctx, 0, &opts, tr, urls, statusURL, humanRec, recordDone)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:891 (direct call)
//   - internal/bench/soak.go:891 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func runHumanSession(
	ctx context.Context,
	id int,
	opts *SoakOptions,
	transport http.RoundTripper,
	browseURLs []string,
	statusURL string,
	rec *cohortRecorder,
	onRequest func(),
) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Transport:     transport,
		Jar:           jar,
		Timeout:       opts.RequestTimeout,
		CheckRedirect: stayOnTarget(opts.Target),
	}

	admitted := false
	pathIdx := id % len(browseURLs)

	for ctx.Err() == nil {
		u := browseURLs[pathIdx%len(browseURLs)]
		pathIdx++

		cls, ok := doSoakRequest(ctx, client, u, opts.Header, nil, "concert-bench human/"+strconv.Itoa(id), rec)
		if !ok {
			if ctx.Err() != nil {
				return
			}
			onRequest()
			continue
		}
		onRequest()

		if cls.queued {
			if admitted {
				// Regression signal: an already-admitted session with concert_admit
				// was pushed back into the waiting room.
				rec.requeuedAfterAdmit.Add(1)
			}
			if !pollQueueUntilReady(ctx, client, statusURL, opts, id, rec, onRequest) {
				return
			}
			continue
		}

		if cls.outcome == outcomeOK {
			if cls.gotAdmit || hasAdmitCookie(jar, opts.Target) {
				if !admitted {
					admitted = true
					rec.admissions.Add(1)
				}
			}
		} else if cls.retryAfter > 0 {
			waitCtx(ctx, min(cls.retryAfter, opts.PollInterval))
		}
	}
}

// pollQueueUntilReady polls /queue/status using the human session's cookie jar
// until ready==true or ctx is cancelled.
//
// # Parameters
//
//   - ctx: Run cancellation context.
//   - client: Human session *http.Client carrying room_ticket/room_probe cookies.
//   - statusURL: Resolved /queue/status URL.
//   - opts: Shared SoakOptions providing PollInterval and Header.
//   - id: Human worker identifier.
//   - rec: Human cohort recorder.
//   - onRequest: Completion callback for MaxRequests tracking.
//
// # Returns
//
// true when the waiting room reports ready==true, false when ctx ends first.
//
// # Example
//
//	if !pollQueueUntilReady(ctx, client, statusURL, &opts, 0, rec, onReq) {
//		return
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:1052 (direct call)
//   - internal/bench/soak.go:1052 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func pollQueueUntilReady(
	ctx context.Context,
	client *http.Client,
	statusURL string,
	opts *SoakOptions,
	id int,
	rec *cohortRecorder,
	onRequest func(),
) bool {
	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
		if err != nil {
			return false
		}
		for k, vals := range opts.Header {
			req.Header[k] = append([]string(nil), vals...)
		}
		req.Header.Set("Accept", "application/json")
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", "concert-bench human/"+strconv.Itoa(id))
		}

		start := time.Now()
		resp, err := client.Do(req)
		dur := time.Since(start)
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			rec.requests.Add(1)
			rec.statusPolls.Add(1)
			rec.transportErrors.Add(1)
			rec.latency.Add(dur)
			onRequest()
			if !waitCtx(ctx, opts.PollInterval) {
				return false
			}
			continue
		}

		body, n, readErr := readInspectAndDrain(resp.Body, maxSoakInspectBytes, maxSoakDrainBytes)
		_ = resp.Body.Close() // read side; close error not material

		rec.requests.Add(1)
		rec.statusPolls.Add(1)
		rec.bytes.Add(n)
		rec.latency.Add(dur)
		onRequest()

		if readErr != nil {
			if ctx.Err() != nil {
				return false
			}
			rec.transportErrors.Add(1)
			if !waitCtx(ctx, opts.PollInterval) {
				return false
			}
			continue
		}

		if resp.StatusCode == http.StatusOK {
			rec.ok2xx.Add(1)
			var status struct {
				Ready bool `json:"ready"`
			}
			if err := json.Unmarshal(body, &status); err == nil && status.Ready {
				return true
			}
		} else if resp.StatusCode == http.StatusTooManyRequests {
			rec.throttled429.Add(1)
		} else if resp.StatusCode >= 500 {
			rec.upstream5xx.Add(1)
		}

		delay := opts.PollInterval
		if ra := parseRetryAfter(resp.Header.Get("Retry-After")); ra > 0 && ra < delay {
			delay = ra
		}
		if !waitCtx(ctx, delay) {
			return false
		}
	}
	return false
}

// runFloodWorker executes one flood/bot worker simulating a high-volume surge
// (whitelisted or untrusted lemmings) against targetURL until ctx ends.
//
// # Parameters
//
//   - ctx: Run cancellation context.
//   - id: 0-based worker index.
//   - opts: Shared immutable SoakOptions.
//   - transport: Shared HTTP RoundTripper.
//   - targetURL: Target URL to flood.
//   - rec: Flood cohort streaming recorder.
//   - onRequest: Callback invoked after each completed request.
//
// # Example
//
//	runFloodWorker(ctx, 0, &opts, tr, targetURL, floodRec, recordDone)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:897 (direct call)
//   - internal/bench/soak.go:897 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func runFloodWorker(
	ctx context.Context,
	id int,
	opts *SoakOptions,
	transport http.RoundTripper,
	targetURL string,
	rec *cohortRecorder,
	onRequest func(),
) {
	var jar http.CookieJar
	if opts.FloodKeepCookies {
		jar, _ = cookiejar.New(nil)
	}
	client := &http.Client{
		Transport:     transport,
		Jar:           jar,
		Timeout:       opts.RequestTimeout,
		CheckRedirect: stayOnTarget(opts.Target),
	}

	admitted := false
	ua := "concert-bench flood-lemming/" + strconv.Itoa(id)

	for ctx.Err() == nil {
		cls, ok := doSoakRequest(ctx, client, targetURL, opts.Header, opts.FloodHeader, ua, rec)
		if !ok {
			if ctx.Err() != nil {
				return
			}
			onRequest()
			continue
		}
		onRequest()

		if cls.queued && admitted {
			rec.requeuedAfterAdmit.Add(1)
		}
		if cls.outcome == outcomeOK && cls.gotAdmit && !admitted {
			admitted = true
			rec.admissions.Add(1)
		}
	}
}

// doSoakRequest performs one GET request, drains up to maxSoakDrainBytes,
// classifies the response, and records all bounded cohort counters.
//
// # Parameters
//
//   - ctx: Request cancellation context.
//   - client: Per-worker *http.Client.
//   - rawURL: Target URL to fetch.
//   - baseHdr: Common headers applied to all cohorts.
//   - extraHdr: Optional cohort-specific headers (override/add over baseHdr).
//   - defaultUA: User-Agent used when not set in headers.
//   - rec: Cohort streaming recorder.
//
// # Returns
//
// (classification, true) on HTTP response, or (zero, false) on transport error.
//
// # Example
//
//	cls, ok := doSoakRequest(ctx, client, u, opts.Header, nil, ua, rec)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:1036 (direct call)
//   - internal/bench/soak.go:1036 (function value)
//   - internal/bench/soak.go:1238 (direct call)
//   - internal/bench/soak.go:1238 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func doSoakRequest(
	ctx context.Context,
	client *http.Client,
	rawURL string,
	baseHdr http.Header,
	extraHdr http.Header,
	defaultUA string,
	rec *cohortRecorder,
) (soakClassification, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		rec.requests.Add(1)
		rec.transportErrors.Add(1)
		return soakClassification{}, false
	}
	for k, vals := range baseHdr {
		req.Header[k] = append([]string(nil), vals...)
	}
	for k, vals := range extraHdr {
		req.Header[k] = append([]string(nil), vals...)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", defaultUA)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
	}

	start := time.Now()
	resp, err := client.Do(req)
	dur := time.Since(start)
	if err != nil {
		if ctx.Err() != nil {
			return soakClassification{}, false
		}
		rec.requests.Add(1)
		rec.transportErrors.Add(1)
		rec.latency.Add(dur)
		return soakClassification{}, false
	}

	body, n, readErr := readInspectAndDrain(resp.Body, maxSoakInspectBytes, maxSoakDrainBytes)
	_ = resp.Body.Close() // read side; close error not material

	rec.requests.Add(1)
	rec.bytes.Add(n)
	rec.latency.Add(dur)

	if readErr != nil {
		if ctx.Err() != nil {
			return soakClassification{}, false
		}
		rec.transportErrors.Add(1)
		return soakClassification{}, false
	}

	cls := classifySoakResponse(resp, body)
	switch cls.outcome {
	case outcomeOK:
		rec.ok2xx.Add(1)
	case outcomeQueued:
		rec.queuedResponses.Add(1)
	case outcomeWaitingRoom503:
		rec.queuedResponses.Add(1)
		rec.waitingRoom503.Add(1)
	case outcomeCapacityBreaker503:
		rec.capacityBreaker503.Add(1)
	case outcomeUpstream5xx:
		rec.upstream5xx.Add(1)
	case outcomeThrottled429:
		rec.throttled429.Add(1)
	case outcomeClient4xx:
		rec.client4xx.Add(1)
	}
	return cls, true
}

// readInspectAndDrain reads up to inspectCap bytes into memory for response
// classification and drains up to drainCap total bytes for connection reuse (R3).
//
// # Parameters
//
//   - r: HTTP response body reader.
//   - inspectCap: Maximum bytes retained in the returned slice.
//   - drainCap: Maximum total bytes read from r.
//
// # Returns
//
// The retained prefix bytes, total bytes read, and any read error.
//
// # Example
//
//	prefix, n, err := readInspectAndDrain(resp.Body, 64<<10, 16<<20)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:1143 (direct call)
//   - internal/bench/soak.go:1143 (function value)
//   - internal/bench/soak.go:1331 (direct call)
//   - internal/bench/soak.go:1331 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func readInspectAndDrain(r io.Reader, inspectCap, drainCap int64) ([]byte, int64, error) {
	var buf bytes.Buffer
	n1, err := io.Copy(&buf, io.LimitReader(r, inspectCap))
	if err != nil {
		return buf.Bytes(), n1, err
	}
	rem := drainCap - n1
	if rem <= 0 {
		return buf.Bytes(), n1, nil
	}
	n2, err := io.Copy(io.Discard, io.LimitReader(r, rem))
	return buf.Bytes(), n1 + n2, err
}

// hasAdmitCookie reports whether jar currently holds a non-empty concert_admit
// cookie for target.
//
// # Parameters
//
//   - jar: Session cookie jar.
//   - target: Target URL.
//
// # Returns
//
// true if concert_admit is stored in jar for target.
//
// # Example
//
//	ok := hasAdmitCookie(jar, opts.Target)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:1059 (direct call)
//   - internal/bench/soak.go:1059 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func hasAdmitCookie(jar http.CookieJar, target *url.URL) bool {
	if jar == nil || target == nil {
		return false
	}
	for _, c := range jar.Cookies(target) {
		if c.Name == concertAdmitCookie && c.Value != "" {
			return true
		}
	}
	return false
}

// waitCtx waits for d or returns false immediately if ctx is cancelled (C6).
//
// # Parameters
//
//   - ctx: Cancellation context.
//   - d: Wait duration.
//
// # Returns
//
// true if d elapsed, false if ctx was cancelled.
//
// # Example
//
//	if !waitCtx(ctx, opts.PollInterval) {
//		return false
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:1066 (direct call)
//   - internal/bench/soak.go:1066 (function value)
//   - internal/bench/soak.go:1137 (direct call)
//   - internal/bench/soak.go:1137 (function value)
//   - internal/bench/soak.go:1157 (direct call)
//   - internal/bench/soak.go:1157 (function value)
//   - internal/bench/soak.go:1181 (direct call)
//   - internal/bench/soak.go:1181 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func waitCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// judgeSoak evaluates queue-fairness invariants on rep and populates Pass,
// Reasons, and Verdict.
//
// # Parameters
//
//   - rep: SoakReport to evaluate and mutate in place.
//   - opts: Fairness threshold options.
//
// # Example
//
//	judgeSoak(rep, &opts)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:921 (direct call)
//   - internal/bench/soak.go:921 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func judgeSoak(rep *SoakReport, opts *SoakOptions) {
	var reasons []string
	if opts.HumanSessions > 0 {
		if rep.Human.Admissions < opts.MinHumanAdmissions {
			reasons = append(reasons, fmt.Sprintf("human admissions %d below minimum %d", rep.Human.Admissions, opts.MinHumanAdmissions))
		}
		if rep.Human.RequeuedAfterAdmit > opts.MaxRequeueAfterAdmit {
			reasons = append(reasons, fmt.Sprintf("admitted humans re-queued %d times (max %d)", rep.Human.RequeuedAfterAdmit, opts.MaxRequeueAfterAdmit))
		}
		if rep.Human.Upstream5xx > opts.MaxHumanUpstream5xx {
			reasons = append(reasons, fmt.Sprintf("human upstream 5xx %d exceeds max %d", rep.Human.Upstream5xx, opts.MaxHumanUpstream5xx))
		}
		if opts.HumanP95Limit > 0 {
			limitMs := float64(opts.HumanP95Limit) / float64(time.Millisecond)
			if rep.Human.Latency.P95Ms > limitMs {
				reasons = append(reasons, fmt.Sprintf("human p95 %.1fms exceeds %s", rep.Human.Latency.P95Ms, opts.HumanP95Limit))
			}
		}
	}
	if rep.TotalRequests == 0 {
		reasons = append(reasons, "no requests completed")
	}

	sort.Strings(reasons)
	rep.Reasons = reasons
	rep.Pass = len(reasons) == 0
	if rep.Pass {
		rep.Verdict = fmt.Sprintf("PASS: %d human admissions, %d post-admit re-queues, %d human upstream 5xx (human p95 %.1fms; flood breaker-503=%d)",
			rep.Human.Admissions, rep.Human.RequeuedAfterAdmit, rep.Human.Upstream5xx, rep.Human.Latency.P95Ms, rep.Flood.CapacityBreaker503)
	} else {
		rep.Verdict = "FAIL: " + strings.Join(reasons, "; ")
	}
}

// SummarizeSoak writes a clear human-readable pass/fail fairness summary of rep
// to w, breaking down human and flood cohorts side-by-side.
//
// # Parameters
//
//   - w: Destination io.Writer (typically os.Stdout).
//   - rep: Completed *SoakReport. If nil, nothing is written.
//
// # Example
//
//	bench.SummarizeSoak(os.Stdout, rep)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/cli.go:163 (direct call)
//   - internal/bench/cli.go:163 (function value)
//   - internal/bench/soak_test.go:343 (direct call)
//   - internal/bench/soak_test.go:343 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func SummarizeSoak(w io.Writer, rep *SoakReport) {
	if w == nil || rep == nil {
		return
	}
	fmt.Fprintf(w, "profile:  %s\n", rep.Profile)
	fmt.Fprintf(w, "target:   %s\n", rep.Target)
	fmt.Fprintf(w, "verdict:  %s\n", rep.Verdict)
	fmt.Fprintf(w, "totals:   %d requests in %s (%.1f req/s)\n", rep.TotalRequests, rep.Duration.Round(time.Millisecond), rep.RPS)
	writeCohortSummary(w, "human", rep.Human)
	writeCohortSummary(w, "flood", rep.Flood)
}

// writeCohortSummary formats one cohort's counters and bounded latency
// percentiles to w.
//
// # Parameters
//
//   - w: Destination writer.
//   - name: Cohort display label ("human" or "flood").
//   - c: CohortStats to print.
//
// # Example
//
//	writeCohortSummary(os.Stdout, "human", rep.Human)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/bench/soak.go:1578 (direct call)
//   - internal/bench/soak.go:1578 (function value)
//   - internal/bench/soak.go:1579 (direct call)
//   - internal/bench/soak.go:1579 (function value)
//
// Scope: internal/bench and cmd/bench-concert (including tests); build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func writeCohortSummary(w io.Writer, name string, c CohortStats) {
	fmt.Fprintf(w, "\ncohort %s (%d workers):\n", name, c.Workers)
	fmt.Fprintf(w, "  requests=%d  ok_2xx=%d  admissions=%d  requeued_after_admit=%d  queued=%d  status_polls=%d\n",
		c.Requests, c.OK2xx, c.Admissions, c.RequeuedAfterAdmit, c.QueuedResponses, c.StatusPolls)
	fmt.Fprintf(w, "  waiting_room_503=%d  capacity_breaker_503=%d  upstream_5xx=%d  throttled_429=%d  transport_err=%d\n",
		c.WaitingRoom503, c.CapacityBreaker503, c.Upstream5xx, c.Throttled429, c.TransportErrors)
	fmt.Fprintf(w, "  latency_ms: p50=%.2f  p95=%.2f  p99=%.2f  max=%.2f  mean=%.2f\n",
		c.Latency.P50Ms, c.Latency.P95Ms, c.Latency.P99Ms, c.Latency.MaxMs, c.Latency.MeanMs)
}
