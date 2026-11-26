package guard

import (
	"context"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultShedPollInterval is the default sampling cadence for HostShedder.
	DefaultShedPollInterval = 500 * time.Millisecond

	// DefaultShedRetryAfter is the default Retry-After duration advertised on
	// HTTP 503 responses written when HostShedder sheds a request.
	DefaultShedRetryAfter = 5 * time.Second

	maxProcStatmBytes = 4096
	fdReadDirBatch    = 512
)

// ShedReason explains why [HostShedder] is shedding incoming non-admitted
// traffic. ShedNone indicates healthy host headroom.
type ShedReason string

const (
	// ShedNone indicates no host resource threshold is exceeded.
	ShedNone ShedReason = ""

	// ShedMemory indicates process memory usage reached or exceeded MaxMemoryBytes.
	ShedMemory ShedReason = "memory"

	// ShedFDs indicates open file descriptor count reached or exceeded MaxOpenFDs.
	ShedFDs ShedReason = "fds"

	// ShedConnections indicates active connection count reached or exceeded MaxActiveConns.
	ShedConnections ShedReason = "connections"
)

// HostSample holds a point-in-time snapshot of process resource utilization.
type HostSample struct {
	// MemoryBytes is the observed process memory usage in bytes (the maximum of
	// Go HeapInuse and Linux /proc/self/statm RSS when available).
	MemoryBytes uint64

	// OpenFDs is the observed open file descriptor count, or -1 when
	// unavailable on the current platform.
	OpenFDs int

	// ActiveConns is the observed active connection count.
	ActiveConns int64

	// SampledAt is the timestamp when the sample was collected.
	SampledAt time.Time
}

// HostSampler collects a [HostSample]. Custom samplers can be injected via
// [HostShedderConfig.Sampler] for deterministic tests.
type HostSampler func() HostSample

// HostShedderConfig configures a [HostShedder]. Any zero or negative threshold
// disables shedding for that specific resource.
type HostShedderConfig struct {
	// MaxMemoryBytes is the memory ceiling in bytes at or above which arrivals
	// are shed with ShedMemory. Zero disables memory-based shedding.
	MaxMemoryBytes uint64

	// MaxOpenFDs is the open file descriptor ceiling at or above which arrivals
	// are shed with ShedFDs. Zero or negative disables FD-based shedding.
	MaxOpenFDs int

	// MaxActiveConns is the active connection ceiling at or above which arrivals
	// are shed with ShedConnections. Zero or negative disables connection shedding.
	MaxActiveConns int64

	// PollInterval controls how often the background loop refreshes resource
	// samples. Defaults to DefaultShedPollInterval (500ms) when <= 0.
	PollInterval time.Duration

	// RetryAfter is the duration advertised in the HTTP Retry-After header when
	// WriteShedResponse sends a 503 response. Defaults to DefaultShedRetryAfter (5s).
	RetryAfter time.Duration

	// ActiveConns optionally returns the current active connection count for
	// the default sampler. When nil, the shedder's internal atomic counter
	// (updated via SetActiveConns / IncActiveConns / DecActiveConns) is used.
	ActiveConns func() int64

	// Sampler overrides the default OS/runtime sampler. Intended for
	// deterministic tests and custom telemetry adapters.
	Sampler HostSampler
}

// shedSnapshot is published atomically by HostShedder and is immutable after
// publication so ShouldShed requires zero locks on the request hot path.
type shedSnapshot struct {
	shed   bool
	reason ShedReason
	sample HostSample
}

// HostShedder monitors host memory, open file descriptors, and active
// connections and sheds excess non-admitted arrivals cleanly before the host
// approaches OOM or FD exhaustion.
//
// Lifecycle: call [HostShedder.Start] to begin periodic background sampling and
// [HostShedder.Stop] (or cancel the context passed to Start) to stop and join
// the background goroutine cleanly (R2). [HostShedder.ShouldShed] is safe to
// call concurrently at any time, including before Start or after Stop.
type HostShedder struct {
	maxMemoryBytes uint64
	maxOpenFDs     int
	maxActiveConns int64
	pollInterval   time.Duration
	retryAfter     time.Duration
	activeConnsFn  func() int64
	sampler        HostSampler

	activeConns atomic.Int64
	snap        atomic.Pointer[shedSnapshot]

	// mu guards the background sampler goroutine lifecycle (running, cancel, done).
	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// NewHostShedder constructs a [HostShedder] with the provided configuration.
// It does not start a background goroutine until [HostShedder.Start] is called.
//
// # Parameters
//
//   - cfg: Resource limits, poll interval, Retry-After value, and optional sampler.
//
// # Returns
//
// A ready-to-use *HostShedder whose initial snapshot is non-shedding until
// SampleNow or Start runs.
//
// # Example
//
//	shedder := guard.NewHostShedder(guard.HostShedderConfig{
//	    MaxMemoryBytes: 512 << 20,
//	    MaxOpenFDs:     4096,
//	    MaxActiveConns: 10000,
//	})
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//	shedder.Start(ctx)
//	defer shedder.Stop()
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:251 (function value)
//   - internal/guard/fuzz_test.go:359 (function value)
//   - internal/guard/guard_test.go:251 (direct call)
//   - internal/guard/guard_test.go:359 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func NewHostShedder(cfg HostShedderConfig) *HostShedder {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultShedPollInterval
	}
	if cfg.RetryAfter <= 0 {
		cfg.RetryAfter = DefaultShedRetryAfter
	}
	s := &HostShedder{
		maxMemoryBytes: cfg.MaxMemoryBytes,
		maxOpenFDs:     cfg.MaxOpenFDs,
		maxActiveConns: cfg.MaxActiveConns,
		pollInterval:   cfg.PollInterval,
		retryAfter:     cfg.RetryAfter,
		activeConnsFn:  cfg.ActiveConns,
		sampler:        cfg.Sampler,
	}
	s.snap.Store(&shedSnapshot{})
	return s
}

// Start begins periodic background sampling until ctx is cancelled or
// [HostShedder.Stop] is called. An initial sample is taken synchronously before
// Start returns so callers immediately observe current host headroom.
//
// Calling Start while already running is a safe no-op.
//
// # Parameters
//
//   - ctx: Parent context controlling the background sampler lifetime. If nil,
//     context.Background() is used.
//
// # Side Effects / Concurrency
//
// Spawns at most one background goroutine owned by the receiver. Call Stop (or
// cancel ctx and call Stop) to guarantee the goroutine has exited.
//
// # Example
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//	s := guard.NewHostShedder(guard.HostShedderConfig{MaxMemoryBytes: 1 << 30})
//	s.Start(ctx)
//	defer s.Stop()
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:274 (function value)
//   - internal/guard/fuzz_test.go:276 (function value)
//   - internal/guard/guard_test.go:274 (direct call)
//   - internal/guard/guard_test.go:276 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (s *HostShedder) Start(ctx context.Context) {
	if s == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	s.running = true
	s.cancel = cancel
	s.done = done
	s.mu.Unlock()

	// Take one synchronous sample before starting the ticker so ShouldShed
	// immediately reflects the host's state without waiting for the first tick.
	s.SampleNow()

	go func() {
		defer func() {
			s.mu.Lock()
			s.running = false
			s.cancel = nil
			s.mu.Unlock()
			close(done)
		}()

		ticker := time.NewTicker(s.pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				s.SampleNow()
			}
		}
	}()
}

// Stop stops the background sampler goroutine if running and waits until it
// has exited cleanly. Calling Stop before Start or calling Stop multiple times
// is safe and non-blocking.
//
// # Parameters
//
// None.
//
// # Example
//
//	s := guard.NewHostShedder(guard.HostShedderConfig{})
//	s.Start(context.Background())
//	s.Stop()
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:270 (function value)
//   - internal/guard/fuzz_test.go:340 (function value)
//   - internal/guard/fuzz_test.go:341 (function value)
//   - internal/guard/guard_test.go:270 (direct call)
//   - internal/guard/guard_test.go:340 (direct call)
//   - internal/guard/guard_test.go:341 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (s *HostShedder) Stop() {
	if s == nil {
		return
	}

	s.mu.Lock()
	cancel := s.cancel
	done := s.done
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// SampleNow collects one resource sample immediately and publishes the updated
// shedding decision atomically.
//
// # Parameters
//
// None.
//
// # Returns
//
// The newly collected HostSample.
//
// # Example
//
//	s := guard.NewHostShedder(guard.HostShedderConfig{MaxMemoryBytes: 1 << 30})
//	sample := s.SampleNow()
//	_ = sample
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:247 (function value)
//   - internal/guard/challenge.go:266 (function value)
//   - internal/guard/fuzz_test.go:287 (function value)
//   - internal/guard/fuzz_test.go:296 (function value)
//   - internal/guard/fuzz_test.go:305 (function value)
//   - internal/guard/fuzz_test.go:334 (function value)
//   - internal/guard/fuzz_test.go:378 (function value)
//   - internal/guard/geoasn.go:247 (function value)
//   - internal/guard/geoasn.go:266 (function value)
//   - internal/guard/guard_test.go:287 (direct call)
//   - internal/guard/guard_test.go:296 (direct call)
//   - internal/guard/guard_test.go:305 (direct call)
//   - internal/guard/guard_test.go:334 (direct call)
//   - internal/guard/guard_test.go:378 (direct call)
//   - internal/guard/queue_quota.go:247 (function value)
//   - internal/guard/queue_quota.go:266 (function value)
//   - internal/guard/ratelimit.go:247 (function value)
//   - internal/guard/ratelimit.go:266 (function value)
//   - internal/guard/secret.go:247 (function value)
//   - internal/guard/secret.go:266 (function value)
//   - internal/guard/shedder.go:247 (direct call)
//   - internal/guard/shedder.go:266 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (s *HostShedder) SampleNow() HostSample {
	if s == nil {
		return HostSample{}
	}
	var sample HostSample
	if s.sampler != nil {
		sample = s.sampler()
		if sample.SampledAt.IsZero() {
			sample.SampledAt = time.Now()
		}
	} else {
		sample = s.defaultSample()
	}

	shed, reason := s.evaluate(sample)
	s.snap.Store(&shedSnapshot{
		shed:   shed,
		reason: reason,
		sample: sample,
	})
	return sample
}

// ShouldShed reports whether incoming non-admitted arrivals should currently be
// rejected with HTTP 503 and returns the primary [ShedReason].
//
// When no custom Sampler is configured and MaxActiveConns > 0, the live
// connection counter is also checked immediately so sudden connection spikes
// shed without waiting for the next poll tick.
//
// # Parameters
//
// None.
//
// # Returns
//
// (true, reason) when any configured host ceiling is reached or exceeded;
// (false, ShedNone) when the host has headroom.
//
// # Example
//
//	s := guard.NewHostShedder(guard.HostShedderConfig{MaxActiveConns: 100})
//	if shed, reason := s.ShouldShed(); shed {
//	    _ = reason
//	}
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:279 (function value)
//   - internal/guard/fuzz_test.go:288 (function value)
//   - internal/guard/fuzz_test.go:297 (function value)
//   - internal/guard/fuzz_test.go:306 (function value)
//   - internal/guard/fuzz_test.go:335 (function value)
//   - internal/guard/fuzz_test.go:365 (function value)
//   - internal/guard/fuzz_test.go:371 (function value)
//   - internal/guard/guard_test.go:279 (direct call)
//   - internal/guard/guard_test.go:288 (direct call)
//   - internal/guard/guard_test.go:297 (direct call)
//   - internal/guard/guard_test.go:306 (direct call)
//   - internal/guard/guard_test.go:335 (direct call)
//   - internal/guard/guard_test.go:365 (direct call)
//   - internal/guard/guard_test.go:371 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (s *HostShedder) ShouldShed() (bool, ShedReason) {
	if s == nil {
		return false, ShedNone
	}
	snap := s.snap.Load()
	if snap != nil && snap.shed {
		return true, snap.reason
	}
	// Check live connection headroom when not overridden by a custom sampler
	// so connection bursts are shed immediately between poll ticks.
	if s.sampler == nil && s.maxActiveConns > 0 {
		if s.currentActiveConns() >= s.maxActiveConns {
			return true, ShedConnections
		}
	}
	return false, ShedNone
}

// LastSample returns the most recently published [HostSample].
//
// # Parameters
//
// None.
//
// # Returns
//
// Copy of the latest sampled host resource metrics.
//
// # Example
//
//	s := guard.NewHostShedder(guard.HostShedderConfig{})
//	s.SampleNow()
//	sample := s.LastSample()
//	_ = sample
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:382 (function value)
//   - internal/guard/guard_test.go:382 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (s *HostShedder) LastSample() HostSample {
	if s == nil {
		return HostSample{}
	}
	snap := s.snap.Load()
	if snap == nil {
		return HostSample{}
	}
	return snap.sample
}

// SetActiveConns sets the shedder's internal active connection counter.
// Ignored when [HostShedderConfig.ActiveConns] or [HostShedderConfig.Sampler]
// is supplied.
//
// # Parameters
//
//   - n: Current number of active connections (negative values are clamped to 0).
//
// # Example
//
//	s := guard.NewHostShedder(guard.HostShedderConfig{MaxActiveConns: 100})
//	s.SetActiveConns(42)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (s *HostShedder) SetActiveConns(n int64) {
	if s == nil {
		return
	}
	if n < 0 {
		n = 0
	}
	s.activeConns.Store(n)
}

// IncActiveConns increments the internal active connection counter by 1 and
// returns the new count.
//
// # Parameters
//
// None.
//
// # Returns
//
// Updated active connection count.
//
// # Example
//
//	s := guard.NewHostShedder(guard.HostShedderConfig{MaxActiveConns: 100})
//	n := s.IncActiveConns()
//	_ = n
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:362 (function value)
//   - internal/guard/guard_test.go:362 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (s *HostShedder) IncActiveConns() int64 {
	if s == nil {
		return 0
	}
	return s.activeConns.Add(1)
}

// DecActiveConns decrements the internal active connection counter by 1,
// clamping at 0, and returns the updated count.
//
// # Parameters
//
// None.
//
// # Returns
//
// Updated active connection count (never negative).
//
// # Example
//
//	s := guard.NewHostShedder(guard.HostShedderConfig{MaxActiveConns: 100})
//	s.IncActiveConns()
//	n := s.DecActiveConns()
//	_ = n
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:368 (function value)
//   - internal/guard/fuzz_test.go:374 (function value)
//   - internal/guard/fuzz_test.go:375 (function value)
//   - internal/guard/guard_test.go:368 (direct call)
//   - internal/guard/guard_test.go:374 (direct call)
//   - internal/guard/guard_test.go:375 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (s *HostShedder) DecActiveConns() int64 {
	if s == nil {
		return 0
	}
	for {
		cur := s.activeConns.Load()
		if cur <= 0 {
			return 0
		}
		if s.activeConns.CompareAndSwap(cur, cur-1) {
			return cur - 1
		}
	}
}

// RetryAfter returns the configured Retry-After duration for 503 responses.
//
// # Parameters
//
// None.
//
// # Returns
//
// Positive duration advertised to shed clients.
//
// # Example
//
//	s := guard.NewHostShedder(guard.HostShedderConfig{RetryAfter: 10 * time.Second})
//	d := s.RetryAfter()
//	_ = d
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:660 (function value)
//   - internal/guard/geoasn.go:660 (function value)
//   - internal/guard/queue_quota.go:660 (function value)
//   - internal/guard/ratelimit.go:660 (function value)
//   - internal/guard/secret.go:660 (function value)
//   - internal/guard/shedder.go:660 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (s *HostShedder) RetryAfter() time.Duration {
	if s == nil || s.retryAfter <= 0 {
		return DefaultShedRetryAfter
	}
	return s.retryAfter
}

// WriteShedResponse writes a clean HTTP 503 Service Unavailable response with
// Retry-After and Cache-Control: no-store headers.
//
// # Parameters
//
//   - w: Destination HTTP response writer; must be non-nil.
//   - reason: Resource reason triggering load shedding.
//
// # Example
//
//	s := guard.NewHostShedder(guard.HostShedderConfig{RetryAfter: 5 * time.Second})
//	if shed, reason := s.ShouldShed(); shed {
//	    s.WriteShedResponse(w, reason)
//	    return
//	}
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:312 (function value)
//   - internal/guard/guard_test.go:312 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (s *HostShedder) WriteShedResponse(w http.ResponseWriter, reason ShedReason) {
	if w == nil {
		return
	}
	secs := max(int(s.RetryAfter().Round(time.Second)/time.Second), 1)
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if reason != ShedNone {
		w.Header().Set("X-Concert-Shed-Reason", string(reason))
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = io.WriteString(w, "service temporarily overloaded; please retry\n")
}

// evaluate compares sample against configured ceilings in priority order:
// memory, open FDs, then active connections.
//
// # Parameters
//
//   - sample: Collected process resource sample.
//
// # Returns
//
// (true, reason) when any ceiling is reached or exceeded; (false, ShedNone) otherwise.
//
// # Example
//
//	shed, reason := s.evaluate(sample)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:377 (function value)
//   - internal/guard/geoasn.go:377 (function value)
//   - internal/guard/queue_quota.go:377 (function value)
//   - internal/guard/ratelimit.go:377 (function value)
//   - internal/guard/secret.go:377 (function value)
//   - internal/guard/shedder.go:377 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (s *HostShedder) evaluate(sample HostSample) (bool, ShedReason) {
	if s.maxMemoryBytes > 0 && sample.MemoryBytes >= s.maxMemoryBytes {
		return true, ShedMemory
	}
	if s.maxOpenFDs > 0 && sample.OpenFDs >= 0 && sample.OpenFDs >= s.maxOpenFDs {
		return true, ShedFDs
	}
	if s.maxActiveConns > 0 && sample.ActiveConns >= s.maxActiveConns {
		return true, ShedConnections
	}
	return false, ShedNone
}

// currentActiveConns reads the live active connection count from the optional
// callback or internal atomic counter.
//
// # Parameters
//
// None.
//
// # Returns
//
// Current active connection count.
//
// # Example
//
//	n := s.currentActiveConns()
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:441 (function value)
//   - internal/guard/challenge.go:800 (function value)
//   - internal/guard/geoasn.go:441 (function value)
//   - internal/guard/geoasn.go:800 (function value)
//   - internal/guard/queue_quota.go:441 (function value)
//   - internal/guard/queue_quota.go:800 (function value)
//   - internal/guard/ratelimit.go:441 (function value)
//   - internal/guard/ratelimit.go:800 (function value)
//   - internal/guard/secret.go:441 (function value)
//   - internal/guard/secret.go:800 (function value)
//   - internal/guard/shedder.go:441 (direct call)
//   - internal/guard/shedder.go:800 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (s *HostShedder) currentActiveConns() int64 {
	if s.activeConnsFn != nil {
		return s.activeConnsFn()
	}
	return s.activeConns.Load()
}

// defaultSample reads runtime.MemStats, Linux /proc/self/statm RSS (when
// available), Linux /proc/self/fd count (when available), and active conns.
//
// # Parameters
//
// None.
//
// # Returns
//
// A populated HostSample for the current process.
//
// # Example
//
//	sample := s.defaultSample()
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:374 (function value)
//   - internal/guard/geoasn.go:374 (function value)
//   - internal/guard/queue_quota.go:374 (function value)
//   - internal/guard/ratelimit.go:374 (function value)
//   - internal/guard/secret.go:374 (function value)
//   - internal/guard/shedder.go:374 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (s *HostShedder) defaultSample() HostSample {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	// HeapInuse reflects live Go memory retained from the OS; prefer the
	// larger of HeapInuse and Linux RSS so cgo/mmap/stack growth is also caught.
	memBytes := ms.HeapInuse
	if rss, ok := readProcStatmRSS("/proc/self/statm", os.Getpagesize()); ok && rss > memBytes {
		memBytes = rss
	}

	openFDs := -1
	if n, ok := countProcOpenFDs("/proc/self/fd"); ok {
		openFDs = n
	}

	return HostSample{
		MemoryBytes: memBytes,
		OpenFDs:     openFDs,
		ActiveConns: s.currentActiveConns(),
		SampledAt:   time.Now(),
	}
}

// readProcStatmRSS parses the resident set size (second whitespace-delimited
// field in pages) from a Linux procfs statm file and converts it to bytes.
//
// # Parameters
//
//   - path: Path to statm file (typically "/proc/self/statm").
//   - pageSize: OS memory page size in bytes; must be positive.
//
// # Returns
//
// (rssBytes, true) on success; (0, false) when the file is unavailable or malformed.
//
// # Example
//
//	rss, ok := readProcStatmRSS("/proc/self/statm", os.Getpagesize())
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:788 (function value)
//   - internal/guard/geoasn.go:788 (function value)
//   - internal/guard/queue_quota.go:788 (function value)
//   - internal/guard/ratelimit.go:788 (function value)
//   - internal/guard/secret.go:788 (function value)
//   - internal/guard/shedder.go:788 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func readProcStatmRSS(path string, pageSize int) (uint64, bool) {
	if pageSize <= 0 {
		return 0, false
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()

	// Bound read to protect against non-procfs files if a test passes a custom path.
	raw, err := io.ReadAll(io.LimitReader(f, maxProcStatmBytes))
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return 0, false
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return pages * uint64(pageSize), true
}

// countProcOpenFDs counts open file descriptors in dir (typically
// "/proc/self/fd") using bounded batched ReadDirNames calls, subtracting one
// for the directory handle opened to perform the scan.
//
// # Parameters
//
//   - dir: Path to the fd directory (typically "/proc/self/fd").
//
// # Returns
//
// (count, true) on success; (-1, false) when the directory cannot be read.
//
// # Example
//
//	n, ok := countProcOpenFDs("/proc/self/fd")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:793 (function value)
//   - internal/guard/geoasn.go:793 (function value)
//   - internal/guard/queue_quota.go:793 (function value)
//   - internal/guard/ratelimit.go:793 (function value)
//   - internal/guard/secret.go:793 (function value)
//   - internal/guard/shedder.go:793 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func countProcOpenFDs(dir string) (int, bool) {
	f, err := os.Open(dir)
	if err != nil {
		return -1, false
	}
	defer f.Close()

	total := 0
	for {
		names, readErr := f.Readdirnames(fdReadDirBatch)
		total += len(names)
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return -1, false
		}
	}
	// Subtract the directory handle opened above when at least one entry exists.
	if total > 0 {
		total--
	}
	return total, true
}
