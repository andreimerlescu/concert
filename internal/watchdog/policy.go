package watchdog

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ActionKind names the recovery action selected by Policy.Evaluate.
type ActionKind string

const (
	// ActionNone means no recovery action should be taken on this observation.
	ActionNone ActionKind = "none"
	// ActionAlertOnly means an operator alert should be emitted without
	// restarting or mutating Concert (for example when upstream origin is down
	// or the restart-loop circuit breaker is open).
	ActionAlertOnly ActionKind = "alert_only"
	// ActionFlushStale means the supervisor should POST {"mode":"stale"} to
	// /_room/queue/clear before escalating to a process restart.
	ActionFlushStale ActionKind = "flush_stale"
	// ActionRestart means the supervisor should gracefully drain (SIGTERM) and
	// restart Concert, subject to exponential backoff.
	ActionRestart ActionKind = "restart"
)

// FailureReason classifies the primary health condition observed on a probe.
type FailureReason string

const (
	// ReasonHealthy indicates all enabled health, metric, and resource checks passed.
	ReasonHealthy FailureReason = "healthy"
	// ReasonOriginDown indicates Concert itself is alive but all upstream origin
	// backends are unhealthy; Concert must NEVER be restarted for this condition.
	ReasonOriginDown FailureReason = "origin_down"
	// ReasonHealthzFailed indicates /_room/healthz failed or returned non-200.
	ReasonHealthzFailed FailureReason = "healthz_failed"
	// ReasonMetricsFailed indicates /_room/metrics could not be scraped or parsed.
	ReasonMetricsFailed FailureReason = "metrics_failed"
	// ReasonRSSExceeded indicates resident memory exceeded MaxRSSBytes.
	ReasonRSSExceeded FailureReason = "rss_exceeded"
	// ReasonFDsExceeded indicates open file descriptors exceeded MaxFDs.
	ReasonFDsExceeded FailureReason = "fds_exceeded"
	// ReasonInternal5xxStorm indicates elevated 5xx/503/timeout ratio while
	// upstream backends are healthy.
	ReasonInternal5xxStorm FailureReason = "internal_5xx_storm"
	// ReasonQueueWedged indicates visitors are stuck in the waiting room queue
	// without forward progress while /_room/healthz remains responsive.
	ReasonQueueWedged FailureReason = "queue_wedged"
)

// PolicyConfig configures the recovery escalation state machine. Zero values
// for positive-required fields are filled with safe defaults by NewPolicy.
type PolicyConfig struct {
	// ConsecutiveFailures is the number of consecutive unhealthy probes required
	// before escalating to flush or restart. Defaults to 3.
	ConsecutiveFailures int
	// MaxRSSBytes is the resident memory ceiling in bytes. 0 disables RSS checks.
	MaxRSSBytes uint64
	// MaxFDs is the open file descriptor ceiling. 0 disables FD checks.
	MaxFDs int
	// Max5xxRatio is the failure ratio in (0, 1] of Concert 5xx/503/timeout
	// deltas over total request deltas that trips ReasonInternal5xxStorm when
	// upstream is healthy. 0 disables the ratio check.
	Max5xxRatio float64
	// MinSamplesFor5xxRatio is the minimum total request delta in a probe
	// interval before Max5xxRatio is evaluated. Defaults to 10.
	MinSamplesFor5xxRatio float64
	// WedgedQueueMinDepth is the minimum LiveQueueDepth considered when
	// detecting a wedged waiting room queue. Defaults to 1.
	WedgedQueueMinDepth int
	// FlushCooldown is the minimum interval between ActionFlushStale attempts.
	// Defaults to 2 minutes.
	FlushCooldown time.Duration
	// FlushGraceWindow is how long Policy waits after ActionFlushStale before
	// escalating to ActionRestart if the target remains unhealthy.
	// Defaults to 30 seconds.
	FlushGraceWindow time.Duration
	// MaxRestartsPerWindow caps restarts within RestartWindow. Once reached, the
	// restart-loop circuit breaker opens and Policy returns ActionAlertOnly.
	// Defaults to 5.
	MaxRestartsPerWindow int
	// RestartWindow is the sliding window over which restarts are counted for
	// the circuit breaker and exponential backoff. Defaults to 15 minutes.
	RestartWindow time.Duration
	// InitialBackoff is the base restart backoff duration. Defaults to 2 seconds.
	InitialBackoff time.Duration
	// MaxBackoff is the maximum exponential backoff cap. Defaults to 2 minutes.
	MaxBackoff time.Duration
	// AlertCooldown throttles duplicate alerts for the same ongoing condition.
	// Defaults to 1 minute.
	AlertCooldown time.Duration
}

// DefaultPolicyConfig returns production-safe defaults for PolicyConfig.
//
// # Parameters
//
// None.
//
// # Returns
//
// A PolicyConfig populated with conservative failure thresholds, grace windows,
// exponential backoff bounds, and circuit-breaker limits.
//
// # Example
//
//	cfg := watchdog.DefaultPolicyConfig()
//	cfg.MaxRSSBytes = 512 << 20
//	policy, err := watchdog.NewPolicy(cfg)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-watchdog/main.go:154 (direct call)
//   - internal/watchdog/policy.go:234 (direct call)
//   - internal/watchdog/watchdog_test.go:1073 (direct call)
//   - internal/watchdog/watchdog_test.go:1246 (direct call)
//   - internal/watchdog/watchdog_test.go:1320 (direct call)
//   - internal/watchdog/watchdog_test.go:1406 (direct call)
//   - internal/watchdog/watchdog_test.go:1546 (direct call)
//   - internal/watchdog/watchdog_test.go:1646 (direct call)
//   - internal/watchdog/watchdog_test.go:1717 (direct call)
//   - internal/watchdog/watchdog_test.go:1786 (direct call)
//   - internal/watchdog/watchdog_test.go:1882 (direct call)
//   - internal/watchdog/watchdog_test.go:2042 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		ConsecutiveFailures:   3,
		Max5xxRatio:           0.5,
		MinSamplesFor5xxRatio: 10,
		WedgedQueueMinDepth:   1,
		FlushCooldown:         2 * time.Minute,
		FlushGraceWindow:      30 * time.Second,
		MaxRestartsPerWindow:  5,
		RestartWindow:         15 * time.Minute,
		InitialBackoff:        2 * time.Second,
		MaxBackoff:            2 * time.Minute,
		AlertCooldown:         time.Minute,
	}
}

// Observation captures the result of a single watchdog probe cycle. All fields
// are pure values with no shared references.
type Observation struct {
	ObservedAt    time.Time
	HealthzOK     bool
	HealthzStatus int
	HealthzErr    string
	ReadyzOK      bool
	ReadyzStatus  int
	ReadyzBody    string
	MetricsOK     bool
	MetricsErr    string
	Metrics       MetricsSnapshot
	Proc          ProcStats
}

// Decision is the deterministic output of Policy.Evaluate for one Observation.
type Decision struct {
	Action              ActionKind
	Reason              FailureReason
	EmitAlert           bool
	AlertSeverity       string
	Message             string
	Backoff             time.Duration
	CircuitOpen         bool
	ConsecutiveFailures int
	RestartsInWindow    int
}

// Policy implements the pure Concert recovery escalation state machine.
//
// Invariants enforced:
//  1. Origin/upstream outages (UpstreamBackendsHealthy == 0 or readyz reporting
//     "upstream unhealthy" while healthz is OK) NEVER trigger a Concert restart
//     or queue flush; they emit ActionAlertOnly.
//  2. Wedged queues with a responsive /_room/healthz always attempt
//     ActionFlushStale before escalating to ActionRestart after FlushGraceWindow.
//  3. Restarts use bounded exponential backoff and a sliding-window circuit
//     breaker (MaxRestartsPerWindow) to prevent restart loops.
//
// Policy is safe for concurrent use; all mutable state is guarded by mu.
type Policy struct {
	cfg PolicyConfig

	mu                  sync.Mutex
	consecutiveFailures int
	stuckQueueProbes    int
	prevMetrics         MetricsSnapshot
	hasPrevMetrics      bool
	lastFlushAt         time.Time
	flushInGrace        bool
	restartTimes        []time.Time
	lastAlertAt         time.Time
	lastAlertReason     FailureReason
	circuitWasOpen      bool
}

// NewPolicy validates cfg, applies defaults for omitted positive fields, and
// constructs a new Policy state machine.
//
// # Parameters
//
//   - cfg: Policy tuning parameters. Negative counts, durations, or out-of-range
//     Max5xxRatio (> 1 or < 0) are rejected with an error.
//
// # Returns
//
// A ready-to-use *Policy, or nil and a descriptive validation error.
//
// # Example
//
//	p, err := watchdog.NewPolicy(watchdog.DefaultPolicyConfig())
//	if err != nil {
//		return err
//	}
//	_ = p
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:420 (direct call)
//   - internal/watchdog/watchdog_test.go:1717 (direct call)
//   - internal/watchdog/watchdog_test.go:2042 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func NewPolicy(cfg PolicyConfig) (*Policy, error) {
	def := DefaultPolicyConfig()
	if cfg.ConsecutiveFailures < 0 {
		return nil, fmt.Errorf("consecutive failures must be non-negative, got %d", cfg.ConsecutiveFailures)
	}
	if cfg.ConsecutiveFailures == 0 {
		cfg.ConsecutiveFailures = def.ConsecutiveFailures
	}
	if cfg.MaxFDs < 0 {
		return nil, fmt.Errorf("max FDs must be non-negative, got %d", cfg.MaxFDs)
	}
	if cfg.Max5xxRatio < 0 || cfg.Max5xxRatio > 1 {
		return nil, fmt.Errorf("max 5xx ratio must be in [0, 1], got %v", cfg.Max5xxRatio)
	}
	if cfg.MinSamplesFor5xxRatio < 0 {
		return nil, fmt.Errorf("min samples for 5xx ratio must be non-negative, got %v", cfg.MinSamplesFor5xxRatio)
	}
	if cfg.MinSamplesFor5xxRatio == 0 {
		cfg.MinSamplesFor5xxRatio = def.MinSamplesFor5xxRatio
	}
	if cfg.WedgedQueueMinDepth < 0 {
		return nil, fmt.Errorf("wedged queue min depth must be non-negative, got %d", cfg.WedgedQueueMinDepth)
	}
	if cfg.WedgedQueueMinDepth == 0 {
		cfg.WedgedQueueMinDepth = def.WedgedQueueMinDepth
	}
	if cfg.FlushCooldown < 0 {
		return nil, fmt.Errorf("flush cooldown must be non-negative, got %v", cfg.FlushCooldown)
	}
	if cfg.FlushCooldown == 0 {
		cfg.FlushCooldown = def.FlushCooldown
	}
	if cfg.FlushGraceWindow < 0 {
		return nil, fmt.Errorf("flush grace window must be non-negative, got %v", cfg.FlushGraceWindow)
	}
	if cfg.FlushGraceWindow == 0 {
		cfg.FlushGraceWindow = def.FlushGraceWindow
	}
	if cfg.MaxRestartsPerWindow < 0 {
		return nil, fmt.Errorf("max restarts per window must be non-negative, got %d", cfg.MaxRestartsPerWindow)
	}
	if cfg.MaxRestartsPerWindow == 0 {
		cfg.MaxRestartsPerWindow = def.MaxRestartsPerWindow
	}
	if cfg.RestartWindow < 0 {
		return nil, fmt.Errorf("restart window must be non-negative, got %v", cfg.RestartWindow)
	}
	if cfg.RestartWindow == 0 {
		cfg.RestartWindow = def.RestartWindow
	}
	if cfg.InitialBackoff < 0 {
		return nil, fmt.Errorf("initial backoff must be non-negative, got %v", cfg.InitialBackoff)
	}
	if cfg.InitialBackoff == 0 {
		cfg.InitialBackoff = def.InitialBackoff
	}
	if cfg.MaxBackoff < 0 {
		return nil, fmt.Errorf("max backoff must be non-negative, got %v", cfg.MaxBackoff)
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = def.MaxBackoff
	}
	if cfg.MaxBackoff < cfg.InitialBackoff {
		cfg.MaxBackoff = cfg.InitialBackoff
	}
	if cfg.AlertCooldown < 0 {
		return nil, fmt.Errorf("alert cooldown must be non-negative, got %v", cfg.AlertCooldown)
	}
	if cfg.AlertCooldown == 0 {
		cfg.AlertCooldown = def.AlertCooldown
	}
	return &Policy{cfg: cfg}, nil
}

// Evaluate advances the policy state machine by one Observation and returns the
// next recovery Decision.
//
// # Parameters
//
//   - obs: Probe snapshot. If obs.ObservedAt is zero, time.Now() is used.
//
// # Returns
//
// A Decision describing the action to take, whether to emit an alert, any
// restart backoff duration, and current circuit-breaker counters.
//
// # Concurrency
//
// Safe for concurrent calls; serializes state updates under p.mu without
// performing any I/O.
//
// # Example
//
//	dec := policy.Evaluate(watchdog.Observation{
//		ObservedAt: time.Now(),
//		HealthzOK:  true,
//		ReadyzOK:   true,
//		MetricsOK:  true,
//	})
//	fmt.Println(dec.Action, dec.Reason)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:684 (direct call)
//   - internal/watchdog/watchdog_test.go:1723 (direct call)
//   - internal/watchdog/watchdog_test.go:2046 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *Policy) Evaluate(obs Observation) Decision {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := obs.ObservedAt
	if now.IsZero() {
		now = time.Now()
	}
	p.pruneRestartsLocked(now)

	// Guard #1: distinguish origin/upstream outage from Concert-internal fault.
	// If Concert answered metrics with UpstreamBackendsHealthy == 0 (or readyz
	// explicitly reported upstream unhealthy while healthz is healthy), NEVER
	// restart Concert — restarting the waiting room cannot fix a dead origin.
	if isOriginDown(obs) {
		p.updateMetricsBaselineLocked(obs)
		p.consecutiveFailures = 0
		p.stuckQueueProbes = 0
		p.flushInGrace = false
		emit := p.shouldEmitAlertLocked(now, ReasonOriginDown, false)
		return Decision{
			Action:           ActionAlertOnly,
			Reason:           ReasonOriginDown,
			EmitAlert:        emit,
			AlertSeverity:    "warning",
			Message:          "upstream origin backends unhealthy (upstream_healthy=0); alerting only, not restarting concert",
			RestartsInWindow: len(p.restartTimes),
		}
	}

	// Compute metric deltas before overwriting the baseline snapshot.
	var d2xx, d3xx, d4xx, d5xx, dRejected503, dTimeouts float64
	var prevLiveDepth float64
	if obs.MetricsOK && p.hasPrevMetrics {
		d2xx = counterDelta(obs.Metrics.Upstream2xxTotal, p.prevMetrics.Upstream2xxTotal)
		d3xx = counterDelta(obs.Metrics.Upstream3xxTotal, p.prevMetrics.Upstream3xxTotal)
		d4xx = counterDelta(obs.Metrics.Upstream4xxTotal, p.prevMetrics.Upstream4xxTotal)
		d5xx = counterDelta(obs.Metrics.Upstream5xxTotal, p.prevMetrics.Upstream5xxTotal)
		dRejected503 = counterDelta(obs.Metrics.Rejected503Total, p.prevMetrics.Rejected503Total)
		dTimeouts = counterDelta(obs.Metrics.TimeoutsTotal, p.prevMetrics.TimeoutsTotal)
		prevLiveDepth = p.prevMetrics.LiveQueueDepth
	}
	hasPrev := p.hasPrevMetrics
	p.updateMetricsBaselineLocked(obs)

	rssBytes, hasRSS := effectiveRSS(obs)
	openFDs, hasFDs := effectiveOpenFDs(obs)
	rssExceeded := p.cfg.MaxRSSBytes > 0 && hasRSS && rssBytes > p.cfg.MaxRSSBytes
	fdsExceeded := p.cfg.MaxFDs > 0 && hasFDs && openFDs > p.cfg.MaxFDs

	totalDelta := d2xx + d3xx + d4xx + d5xx + dRejected503 + dTimeouts
	err5xxDelta := d5xx + dRejected503 + dTimeouts
	var ratio5xx float64
	if totalDelta > 0 {
		ratio5xx = err5xxDelta / totalDelta
	}
	high5xx := obs.MetricsOK && hasPrev && p.cfg.Max5xxRatio > 0 &&
		totalDelta >= p.cfg.MinSamplesFor5xxRatio && ratio5xx >= p.cfg.Max5xxRatio

	// Track wedged waiting-room queue state: a busy queue actively serving 2xx/3xx
	// traffic with no 503 rejections is healthy; a non-empty queue making zero
	// forward progress (or rejecting 503s with stale tickets) is wedged.
	queueStuckThisProbe := false
	if obs.HealthzOK && obs.MetricsOK {
		minDepth := float64(p.cfg.WedgedQueueMinDepth)
		if obs.Metrics.LiveQueueDepth >= minDepth {
			noProgress := (!hasPrev && obs.Metrics.RoomOccupancy == 0) ||
				(hasPrev && obs.Metrics.LiveQueueDepth >= prevLiveDepth && (d2xx+d3xx == 0 || obs.Metrics.RoomOccupancy == 0))
			staleRejections := obs.Metrics.QueueDepth > obs.Metrics.LiveQueueDepth && dRejected503 > 0
			if noProgress || staleRejections || high5xx {
				queueStuckThisProbe = true
				p.stuckQueueProbes++
			} else {
				p.stuckQueueProbes = 0
			}
		} else if obs.Metrics.QueueDepth > 0 && dRejected503 > 0 {
			queueStuckThisProbe = true
			p.stuckQueueProbes++
		} else {
			p.stuckQueueProbes = 0
		}
	} else {
		p.stuckQueueProbes = 0
	}

	reason, msg := classifyUnhealthy(obs, rssExceeded, rssBytes, p.cfg.MaxRSSBytes, fdsExceeded, openFDs, p.cfg.MaxFDs, high5xx, ratio5xx, p.cfg.Max5xxRatio, queueStuckThisProbe)
	if reason == ReasonHealthy {
		p.consecutiveFailures = 0
		p.flushInGrace = false
		p.lastAlertReason = ReasonHealthy
		return Decision{
			Action:           ActionNone,
			Reason:           ReasonHealthy,
			RestartsInWindow: len(p.restartTimes),
		}
	}

	p.consecutiveFailures++
	if p.consecutiveFailures < p.cfg.ConsecutiveFailures {
		return Decision{
			Action:              ActionNone,
			Reason:              reason,
			Message:             msg,
			ConsecutiveFailures: p.consecutiveFailures,
			RestartsInWindow:    len(p.restartTimes),
		}
	}

	// Escalation step 1/2: when /_room/healthz is responsive and the fault is a
	// wedged queue (or 5xx storm with queued visitors), try flushing stale queue
	// tickets before restarting Concert.
	flushEligible := obs.HealthzOK && !rssExceeded && !fdsExceeded &&
		(reason == ReasonQueueWedged || (reason == ReasonInternal5xxStorm && (obs.Metrics.QueueDepth > 0 || obs.Metrics.LiveQueueDepth > 0)))
	if flushEligible && !p.flushInGrace && (p.lastFlushAt.IsZero() || now.Sub(p.lastFlushAt) >= p.cfg.FlushCooldown) {
		p.lastFlushAt = now
		p.flushInGrace = true
		p.lastAlertAt = now
		p.lastAlertReason = reason
		return Decision{
			Action:              ActionFlushStale,
			Reason:              reason,
			EmitAlert:           true,
			AlertSeverity:       "warning",
			Message:             fmt.Sprintf("%s; attempting stale queue flush before restart", msg),
			ConsecutiveFailures: p.consecutiveFailures,
			RestartsInWindow:    len(p.restartTimes),
		}
	}

	// Honor the post-flush grace window while Concert remains responsive and
	// within resource ceilings, giving the stale-queue flush time to recover.
	if p.flushInGrace && obs.HealthzOK && !rssExceeded && !fdsExceeded && now.Sub(p.lastFlushAt) < p.cfg.FlushGraceWindow {
		return Decision{
			Action:              ActionNone,
			Reason:              reason,
			Message:             fmt.Sprintf("%s; awaiting post-flush grace window", msg),
			ConsecutiveFailures: p.consecutiveFailures,
			RestartsInWindow:    len(p.restartTimes),
		}
	}

	// Escalation step 3: restart Concert, gated by the sliding-window restart
	// circuit breaker and exponential backoff.
	if len(p.restartTimes) >= p.cfg.MaxRestartsPerWindow {
		forceAlert := !p.circuitWasOpen
		p.circuitWasOpen = true
		emit := p.shouldEmitAlertLocked(now, reason, forceAlert)
		return Decision{
			Action:              ActionAlertOnly,
			Reason:              reason,
			EmitAlert:           emit,
			AlertSeverity:       "critical",
			CircuitOpen:         true,
			Message:             fmt.Sprintf("restart circuit breaker open (%d/%d restarts in %s); %s", len(p.restartTimes), p.cfg.MaxRestartsPerWindow, p.cfg.RestartWindow, msg),
			ConsecutiveFailures: p.consecutiveFailures,
			RestartsInWindow:    len(p.restartTimes),
		}
	}

	p.circuitWasOpen = false
	backoff := p.computeBackoffLocked(len(p.restartTimes))
	p.restartTimes = append(p.restartTimes, now)
	restartsNow := len(p.restartTimes)
	// Reset probe accumulators and metric baselines because the restarted
	// Concert process begins with fresh zeroed counters.
	consec := p.consecutiveFailures
	p.consecutiveFailures = 0
	p.stuckQueueProbes = 0
	p.flushInGrace = false
	p.hasPrevMetrics = false
	p.lastAlertAt = now
	p.lastAlertReason = reason

	return Decision{
		Action:              ActionRestart,
		Reason:              reason,
		EmitAlert:           true,
		AlertSeverity:       "critical",
		Message:             fmt.Sprintf("%s; restarting concert (attempt %d/%d in %s, backoff %s)", msg, restartsNow, p.cfg.MaxRestartsPerWindow, p.cfg.RestartWindow, backoff),
		Backoff:             backoff,
		ConsecutiveFailures: consec,
		RestartsInWindow:    restartsNow,
	}
}

// RecordCrash accounts for an unexpected child exit in parent-process mode
// against the same sliding-window restart circuit breaker and exponential
// backoff used for probe-triggered restarts.
//
// # Parameters
//
//   - at: Timestamp of the unexpected exit; zero defaults to time.Now().
//
// # Returns
//
// A Decision with ActionRestart and computed Backoff if respawning is allowed,
// or ActionAlertOnly with CircuitOpen == true when MaxRestartsPerWindow has
// been reached.
//
// # Concurrency
//
// Safe for concurrent calls; serializes state updates under p.mu.
//
// # Example
//
//	dec := policy.RecordCrash(time.Now())
//	if dec.CircuitOpen {
//		// Do not respawn until the restart window rolls over.
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:1228 (direct call)
//   - internal/watchdog/supervisor.go:1282 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *Policy) RecordCrash(at time.Time) Decision {
	p.mu.Lock()
	defer p.mu.Unlock()

	if at.IsZero() {
		at = time.Now()
	}
	p.pruneRestartsLocked(at)
	p.consecutiveFailures = 0
	p.stuckQueueProbes = 0
	p.flushInGrace = false
	p.hasPrevMetrics = false

	if len(p.restartTimes) >= p.cfg.MaxRestartsPerWindow {
		forceAlert := !p.circuitWasOpen
		p.circuitWasOpen = true
		emit := p.shouldEmitAlertLocked(at, ReasonHealthzFailed, forceAlert)
		return Decision{
			Action:           ActionAlertOnly,
			Reason:           ReasonHealthzFailed,
			EmitAlert:        emit,
			AlertSeverity:    "critical",
			CircuitOpen:      true,
			Message:          fmt.Sprintf("child process exited and restart circuit breaker is open (%d/%d restarts in %s)", len(p.restartTimes), p.cfg.MaxRestartsPerWindow, p.cfg.RestartWindow),
			RestartsInWindow: len(p.restartTimes),
		}
	}

	p.circuitWasOpen = false
	backoff := p.computeBackoffLocked(len(p.restartTimes))
	p.restartTimes = append(p.restartTimes, at)
	p.lastAlertAt = at
	p.lastAlertReason = ReasonHealthzFailed
	return Decision{
		Action:           ActionRestart,
		Reason:           ReasonHealthzFailed,
		EmitAlert:        true,
		AlertSeverity:    "critical",
		Message:          fmt.Sprintf("child process exited unexpectedly; respawning (attempt %d/%d in %s, backoff %s)", len(p.restartTimes), p.cfg.MaxRestartsPerWindow, p.cfg.RestartWindow, backoff),
		Backoff:          backoff,
		RestartsInWindow: len(p.restartTimes),
	}
}

// RestartsInWindow returns the number of restarts recorded within the active
// sliding window relative to now.
//
// # Parameters
//
//   - now: Reference instant; zero defaults to time.Now().
//
// # Returns
//
// Count of restarts inside [now-RestartWindow, now].
//
// # Concurrency
//
// Safe for concurrent calls; acquires p.mu.
//
// # Example
//
//	n := policy.RestartsInWindow(time.Now())
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:1279 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *Policy) RestartsInWindow(now time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if now.IsZero() {
		now = time.Now()
	}
	p.pruneRestartsLocked(now)
	return len(p.restartTimes)
}

// pruneRestartsLocked discards restart timestamps older than RestartWindow.
// Caller must hold p.mu.
//
// # Parameters
//
//   - now: Current timestamp.
//
// # Example
//
//	p.pruneRestartsLocked(now)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/policy.go:351 (direct call)
//   - internal/watchdog/policy.go:568 (direct call)
//   - internal/watchdog/policy.go:637 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *Policy) pruneRestartsLocked(now time.Time) {
	cutoff := now.Add(-p.cfg.RestartWindow)
	kept := p.restartTimes[:0]
	for _, ts := range p.restartTimes {
		if !ts.Before(cutoff) {
			kept = append(kept, ts)
		}
	}
	p.restartTimes = kept
	if len(p.restartTimes) < p.cfg.MaxRestartsPerWindow {
		p.circuitWasOpen = false
	}
}

// computeBackoffLocked calculates InitialBackoff * 2^attempt capped at MaxBackoff
// without integer overflow. Caller must hold p.mu.
//
// # Parameters
//
//   - attempt: Zero-based count of prior restarts already in the window.
//
// # Returns
//
// Bounded backoff duration in [InitialBackoff, MaxBackoff].
//
// # Example
//
//	d := p.computeBackoffLocked(len(p.restartTimes))
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/policy.go:503 (direct call)
//   - internal/watchdog/policy.go:590 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *Policy) computeBackoffLocked(attempt int) time.Duration {
	d := p.cfg.InitialBackoff
	for range attempt {
		if d >= p.cfg.MaxBackoff/2 {
			return p.cfg.MaxBackoff
		}
		d *= 2
	}
	if d > p.cfg.MaxBackoff {
		return p.cfg.MaxBackoff
	}
	return d
}

// shouldEmitAlertLocked reports whether an alert for reason should be emitted
// now, updating alert throttling state when returning true. Caller must hold p.mu.
//
// # Parameters
//
//   - now: Current timestamp.
//   - reason: Current failure classification.
//   - force: When true, bypasses AlertCooldown (for example on circuit-open transition).
//
// # Returns
//
// true when the caller should deliver an alert event.
//
// # Example
//
//	emit := p.shouldEmitAlertLocked(now, ReasonOriginDown, false)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/policy.go:362 (direct call)
//   - internal/watchdog/policy.go:489 (direct call)
//   - internal/watchdog/policy.go:577 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *Policy) shouldEmitAlertLocked(now time.Time, reason FailureReason, force bool) bool {
	if force || p.lastAlertAt.IsZero() || p.lastAlertReason != reason || now.Sub(p.lastAlertAt) >= p.cfg.AlertCooldown {
		p.lastAlertAt = now
		p.lastAlertReason = reason
		return true
	}
	return false
}

// updateMetricsBaselineLocked saves the latest metrics snapshot for delta
// computation on the next probe. Caller must hold p.mu.
//
// # Parameters
//
//   - obs: Latest probe observation.
//
// # Example
//
//	p.updateMetricsBaselineLocked(obs)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/policy.go:358 (direct call)
//   - internal/watchdog/policy.go:386 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *Policy) updateMetricsBaselineLocked(obs Observation) {
	if obs.MetricsOK {
		p.prevMetrics = obs.Metrics
		p.hasPrevMetrics = true
	}
}

// isOriginDown reports whether obs indicates that upstream origin backends are
// down rather than Concert itself being wedged.
//
// # Parameters
//
//   - obs: Probe observation to inspect.
//
// # Returns
//
// true when concert_upstream_backends_healthy is 0 or when healthz succeeded
// while readyz reported "upstream unhealthy".
//
// # Example
//
//	if isOriginDown(obs) {
//		return Decision{Action: ActionAlertOnly, Reason: ReasonOriginDown}
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/policy.go:357 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func isOriginDown(obs Observation) bool {
	if obs.MetricsOK && obs.Metrics.HasUpstreamBackendsHealthy && obs.Metrics.UpstreamBackendsHealthy == 0 {
		return true
	}
	if obs.HealthzOK && !obs.ReadyzOK && strings.Contains(strings.ToLower(obs.ReadyzBody), "upstream unhealthy") {
		return true
	}
	return false
}

// counterDelta computes the non-negative increase between two Prometheus
// monotonic counter samples, treating a decrease (process restart) as a reset
// from zero.
//
// # Parameters
//
//   - cur: Current counter value.
//   - prev: Previous counter value.
//
// # Returns
//
// Non-negative delta for the interval.
//
// # Example
//
//	delta := counterDelta(cur.Upstream5xxTotal, prev.Upstream5xxTotal)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/policy.go:377 (direct call)
//   - internal/watchdog/policy.go:378 (direct call)
//   - internal/watchdog/policy.go:379 (direct call)
//   - internal/watchdog/policy.go:380 (direct call)
//   - internal/watchdog/policy.go:381 (direct call)
//   - internal/watchdog/policy.go:382 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func counterDelta(cur, prev float64) float64 {
	if cur < 0 {
		return 0
	}
	if cur < prev {
		return cur
	}
	return cur - prev
}

// effectiveRSS picks the best available RSS measurement from obs, preferring
// Linux procfs inspection over Prometheus gauges.
//
// # Parameters
//
//   - obs: Probe observation.
//
// # Returns
//
// Resident memory in bytes and true if either source reported RSS.
//
// # Example
//
//	rss, ok := effectiveRSS(obs)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/policy.go:388 (direct call)
//   - internal/watchdog/supervisor.go:926 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func effectiveRSS(obs Observation) (uint64, bool) {
	if obs.Proc.HasRSS {
		return obs.Proc.RSSBytes, true
	}
	if obs.MetricsOK && obs.Metrics.HasResidentMemoryBytes {
		return obs.Metrics.ResidentMemoryBytes, true
	}
	return 0, false
}

// effectiveOpenFDs picks the best available open-FD count from obs, preferring
// Linux procfs inspection over Prometheus gauges.
//
// # Parameters
//
//   - obs: Probe observation.
//
// # Returns
//
// Open file descriptor count and true if either source reported it.
//
// # Example
//
//	fds, ok := effectiveOpenFDs(obs)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/policy.go:389 (direct call)
//   - internal/watchdog/supervisor.go:927 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func effectiveOpenFDs(obs Observation) (int, bool) {
	if obs.Proc.HasOpenFDs {
		return obs.Proc.OpenFDs, true
	}
	if obs.MetricsOK && obs.Metrics.HasOpenFDs {
		return obs.Metrics.OpenFDs, true
	}
	return 0, false
}

// classifyUnhealthy determines the highest-priority failure reason and human
// diagnostic message for a single non-origin-down observation.
//
// # Parameters
//
//   - obs: Current probe observation.
//   - rssExceeded: True when effective RSS exceeded maxRSS.
//   - rssBytes: Observed resident bytes.
//   - maxRSS: Configured RSS ceiling in bytes.
//   - fdsExceeded: True when effective open FDs exceeded maxFDs.
//   - openFDs: Observed open file descriptors.
//   - maxFDs: Configured FD ceiling.
//   - high5xx: True when Concert internal 5xx ratio breached max5xxRatio.
//   - ratio5xx: Observed 5xx ratio in [0, 1].
//   - max5xxRatio: Configured 5xx ratio ceiling.
//   - queueStuck: True when waiting room queue appears wedged on this probe.
//
// # Returns
//
// The primary FailureReason (or ReasonHealthy) and a secret-free description.
//
// # Example
//
//	reason, msg := classifyUnhealthy(obs, false, 0, 0, false, 0, 0, false, 0, 0.5, true)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/policy.go:428 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func classifyUnhealthy(
	obs Observation,
	rssExceeded bool, rssBytes, maxRSS uint64,
	fdsExceeded bool, openFDs, maxFDs int,
	high5xx bool, ratio5xx, max5xxRatio float64,
	queueStuck bool,
) (FailureReason, string) {
	if !obs.HealthzOK {
		if obs.HealthzErr != "" {
			return ReasonHealthzFailed, fmt.Sprintf("/_room/healthz probe failed: %s", obs.HealthzErr)
		}
		return ReasonHealthzFailed, fmt.Sprintf("/_room/healthz returned HTTP %d", obs.HealthzStatus)
	}
	if rssExceeded {
		return ReasonRSSExceeded, fmt.Sprintf("RSS %d bytes exceeded ceiling %d bytes", rssBytes, maxRSS)
	}
	if fdsExceeded {
		return ReasonFDsExceeded, fmt.Sprintf("open FDs %d exceeded ceiling %d", openFDs, maxFDs)
	}
	if queueStuck {
		return ReasonQueueWedged, fmt.Sprintf("waiting room queue wedged (live=%g total=%g occupancy=%g)", obs.Metrics.LiveQueueDepth, obs.Metrics.QueueDepth, obs.Metrics.RoomOccupancy)
	}
	if high5xx {
		return ReasonInternal5xxStorm, fmt.Sprintf("Concert internal 5xx ratio %.2f exceeded threshold %.2f", ratio5xx, max5xxRatio)
	}
	if !obs.MetricsOK {
		if obs.MetricsErr != "" {
			return ReasonMetricsFailed, fmt.Sprintf("/_room/metrics scrape failed: %s", obs.MetricsErr)
		}
		return ReasonMetricsFailed, "/_room/metrics scrape failed"
	}
	return ReasonHealthy, ""
}
