package waitingroom

import (
	"math"
	"sync"
	"time"
)

const (
	// ConfidenceHigh indicates at least 10 fresh admission samples back the ETA.
	ConfidenceHigh = "high"
	// ConfidenceMedium indicates 3 to 9 fresh admission samples back the ETA.
	ConfidenceMedium = "medium"
	// ConfidenceLow indicates fewer than 3 samples or stale throughput data.
	ConfidenceLow = "low"

	// defaultEWMAAlpha is the default smoothing factor for inter-admission intervals.
	defaultEWMAAlpha = 0.25
	// minIntervalSeconds floors burst inter-admission deltas to avoid divide-by-zero.
	minIntervalSeconds = 0.01
	// defaultStaleWindow marks estimates as low confidence after 5 minutes without admissions.
	defaultStaleWindow = 5 * time.Minute
	// maxETASeconds caps computed ETAs at 7 days to prevent integer overflow on extreme queues.
	maxETASeconds = 7 * 24 * 60 * 60
)

// ETAEstimate describes a human-friendly queue wait estimate computed from
// observed waiting-room admission throughput.
type ETAEstimate struct {
	// Seconds is the estimated remaining wait duration in whole seconds (0 when unknown or ready).
	Seconds int `json:"seconds"`
	// AdmissionsPerMinute is the smoothed admission throughput rate.
	AdmissionsPerMinute float64 `json:"admissions_per_minute"`
	// Confidence is "high", "medium", or "low".
	Confidence string `json:"confidence"`
}

// ETAEstimator maintains a concurrency-safe exponentially weighted moving
// average (EWMA) of inter-admission intervals to estimate visitor wait times.
// A zero-value ETAEstimator is ready to use with default smoothing parameters;
// use NewETAEstimator to customize alpha. Do not copy an ETAEstimator after
// first use.
type ETAEstimator struct {
	mu            sync.Mutex
	alpha         float64
	staleWindow   time.Duration
	samples       int
	lastAdmission time.Time
	ewmaInterval  float64 // smoothed seconds per admission; guarded by mu
}

// NewETAEstimator creates a concurrency-safe EWMA throughput estimator with
// smoothing factor alpha in (0, 1]. Out-of-range or NaN alpha values fall back
// to 0.25.
//
// # Parameters
//
//   - alpha: EWMA smoothing weight applied to each newly observed inter-admission
//     interval. Larger values react faster to rate changes; smaller values smooth
//     short-term bursts. Valid range is (0, 1]; invalid values default to 0.25.
//
// # Returns
//
// A ready *ETAEstimator safe for concurrent use across goroutines.
//
// # Example
//
//	est := waitingroom.NewETAEstimator(0.25)
//	now := time.Now().UTC()
//	est.RecordAdmission(now)
//	est.RecordAdmission(now.Add(2 * time.Second))
//	eta := est.Estimate(10, now.Add(2*time.Second))
//	fmt.Println(eta.Seconds) // 20
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/waitingroom_test.go:425 (direct call)
//   - internal/waitingroom/waitingroom_test.go:453 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func NewETAEstimator(alpha float64) *ETAEstimator {
	if math.IsNaN(alpha) || math.IsInf(alpha, 0) || alpha <= 0 || alpha > 1 {
		alpha = defaultEWMAAlpha
	}
	return &ETAEstimator{
		alpha:       alpha,
		staleWindow: defaultStaleWindow,
	}
}

// RecordAdmission records a single waiting-room admission occurring at now and
// updates the EWMA inter-admission interval. Non-monotonic timestamps earlier
// than the previously recorded admission are ignored so clock regressions never
// corrupt the throughput estimate.
//
// # Parameters
//
//   - e (receiver): Non-nil *ETAEstimator.
//   - now: Admission timestamp; if zero, time.Now().UTC() is used.
//
// # Concurrency
//
// Safe for concurrent use by multiple goroutines.
//
// # Example
//
//	est := waitingroom.NewETAEstimator(0.25)
//	est.RecordAdmission(time.Now().UTC())
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/waitingroom_test.go:431 (direct call)
//   - internal/waitingroom/waitingroom_test.go:438 (direct call)
//   - internal/waitingroom/waitingroom_test.go:455 (direct call)
//   - internal/waitingroom/waitingroom_test.go:468 (direct call)
//   - internal/waitingroom/waitingroom_test.go:487 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func (e *ETAEstimator) RecordAdmission(now time.Time) {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	alpha := e.effectiveAlphaLocked()
	if e.samples == 0 {
		e.lastAdmission = now
		e.samples = 1
		return
	}

	dt := now.Sub(e.lastAdmission).Seconds()
	if dt < 0 {
		// Ignore clock regressions or out-of-order timestamps rather than
		// introducing negative intervals into the EWMA.
		return
	}
	if dt < minIntervalSeconds {
		dt = minIntervalSeconds
	}

	if e.samples == 1 {
		e.ewmaInterval = dt
	} else {
		e.ewmaInterval = alpha*dt + (1-alpha)*e.ewmaInterval
	}
	e.lastAdmission = now
	e.samples++
}

// Estimate computes the estimated wait time for a visitor at 1-based queue
// position at observation instant now.
//
// # Parameters
//
//   - e (receiver): Non-nil *ETAEstimator.
//   - position: 1-based queue position. Values <= 0 yield Seconds == 0 while
//     still reporting current AdmissionsPerMinute and Confidence.
//   - now: Observation instant used to evaluate staleness; if zero, time.Now().UTC() is used.
//
// # Returns
//
// An ETAEstimate containing whole seconds (capped at 7 days), admissions per
// minute, and Confidence ("high" for >= 10 fresh samples, "medium" for 3..9
// fresh samples, or "low" for < 3 samples or stale observations).
//
// # Concurrency
//
// Safe for concurrent use by multiple goroutines.
//
// # Example
//
//	eta := est.Estimate(15, time.Now().UTC())
//	fmt.Println(eta.Seconds, eta.Confidence)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/waitingroom_test.go:428 (direct call)
//   - internal/waitingroom/waitingroom_test.go:432 (direct call)
//   - internal/waitingroom/waitingroom_test.go:441 (direct call)
//   - internal/waitingroom/waitingroom_test.go:457 (direct call)
//   - internal/waitingroom/waitingroom_test.go:463 (direct call)
//   - internal/waitingroom/waitingroom_test.go:469 (direct call)
//   - internal/waitingroom/waitingroom_test.go:475 (direct call)
//   - internal/waitingroom/waitingroom_test.go:488 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func (e *ETAEstimator) Estimate(position int, now time.Time) ETAEstimate {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.samples < 2 || e.ewmaInterval <= 0 || math.IsNaN(e.ewmaInterval) || math.IsInf(e.ewmaInterval, 0) {
		return ETAEstimate{
			Seconds:             0,
			AdmissionsPerMinute: 0,
			Confidence:          ConfidenceLow,
		}
	}

	rate := 60.0 / e.ewmaInterval
	staleWindow := e.staleWindow
	if staleWindow <= 0 {
		staleWindow = defaultStaleWindow
	}

	conf := ConfidenceLow
	if now.Sub(e.lastAdmission) <= staleWindow {
		switch {
		case e.samples >= 10:
			conf = ConfidenceHigh
		case e.samples >= 3:
			conf = ConfidenceMedium
		}
	}

	if position <= 0 {
		return ETAEstimate{
			Seconds:             0,
			AdmissionsPerMinute: rate,
			Confidence:          conf,
		}
	}

	rawSeconds := math.Round(float64(position) * e.ewmaInterval)
	var secs int
	switch {
	case rawSeconds < 1:
		secs = 1
	case rawSeconds > maxETASeconds:
		secs = maxETASeconds
	default:
		secs = int(rawSeconds)
	}

	return ETAEstimate{
		Seconds:             secs,
		AdmissionsPerMinute: rate,
		Confidence:          conf,
	}
}

// Reset clears all recorded admission samples and EWMA state.
//
// # Parameters
//
//   - e (receiver): Non-nil *ETAEstimator.
//
// # Concurrency
//
// Safe for concurrent use by multiple goroutines.
//
// # Example
//
//	est.Reset()
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/waitingroom_test.go:474 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func (e *ETAEstimator) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.samples = 0
	e.lastAdmission = time.Time{}
	e.ewmaInterval = 0
}

// effectiveAlphaLocked returns the active smoothing factor, defaulting to
// defaultEWMAAlpha for zero-value ETAEstimator instances. Caller must hold e.mu.
//
// # Parameters
//
//   - e (receiver): Non-nil *ETAEstimator with e.mu held.
//
// # Returns
//
// Valid alpha in (0, 1].
//
// # Example
//
//	// Internal helper invoked only while holding e.mu.
//	alpha := e.effectiveAlphaLocked()
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/waitingroom/eta.go:131 (direct call)
//
// Scope: internal/i18n and internal/waitingroom (including tests); default tags.
func (e *ETAEstimator) effectiveAlphaLocked() float64 {
	if math.IsNaN(e.alpha) || math.IsInf(e.alpha, 0) || e.alpha <= 0 || e.alpha > 1 {
		return defaultEWMAAlpha
	}
	return e.alpha
}
