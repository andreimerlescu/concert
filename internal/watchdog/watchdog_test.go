package watchdog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/opt"
	"github.com/andreimerlescu/concert/internal/watchdog"
)

// fakeClock provides deterministic, race-free time progression for tests
// without any time.Sleep synchronization.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// newFakeClock initializes a fakeClock anchored at start.
//
// # Parameters
//
//   - start: Initial instant returned by Now.
//
// # Returns
//
// A *fakeClock safe for concurrent reads and advances.
//
// # Example
//
//	clk := newFakeClock(time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC))
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:1059 (direct call)
//   - internal/watchdog/watchdog_test.go:1243 (direct call)
//   - internal/watchdog/watchdog_test.go:1317 (direct call)
//   - internal/watchdog/watchdog_test.go:1398 (direct call)
//   - internal/watchdog/watchdog_test.go:1543 (direct call)
//   - internal/watchdog/watchdog_test.go:1643 (direct call)
//   - internal/watchdog/watchdog_test.go:1879 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

// Now returns the current synthetic timestamp.
//
// # Parameters
//
// None.
//
// # Returns
//
// Current synthetic time.Time.
//
// # Example
//
//	t := clk.Now()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:1074 (function value)
//   - internal/watchdog/watchdog_test.go:1259 (function value)
//   - internal/watchdog/watchdog_test.go:1334 (function value)
//   - internal/watchdog/watchdog_test.go:1432 (function value)
//   - internal/watchdog/watchdog_test.go:1557 (function value)
//   - internal/watchdog/watchdog_test.go:1658 (function value)
//   - internal/watchdog/watchdog_test.go:1904 (function value)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the synthetic clock forward by d.
//
// # Parameters
//
//   - d: Duration to add to the current synthetic time.
//
// # Example
//
//	clk.Advance(10 * time.Second)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:1075 (direct call)
//   - internal/watchdog/watchdog_test.go:1100 (direct call)
//   - internal/watchdog/watchdog_test.go:1260 (direct call)
//   - internal/watchdog/watchdog_test.go:1281 (direct call)
//   - internal/watchdog/watchdog_test.go:1300 (direct call)
//   - internal/watchdog/watchdog_test.go:1335 (direct call)
//   - internal/watchdog/watchdog_test.go:1347 (direct call)
//   - internal/watchdog/watchdog_test.go:1354 (direct call)
//   - internal/watchdog/watchdog_test.go:1364 (direct call)
//   - internal/watchdog/watchdog_test.go:1437 (direct call)
//   - internal/watchdog/watchdog_test.go:1444 (direct call)
//   - internal/watchdog/watchdog_test.go:1558 (direct call)
//   - internal/watchdog/watchdog_test.go:1576 (direct call)
//   - internal/watchdog/watchdog_test.go:1584 (direct call)
//   - internal/watchdog/watchdog_test.go:1659 (direct call)
//   - internal/watchdog/watchdog_test.go:1682 (direct call)
//   - internal/watchdog/watchdog_test.go:1909 (direct call)
//   - internal/watchdog/watchdog_test.go:1931 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// fakeProcess models a ManagedProcess with explicit channels for SIGTERM,
// SIGKILL, and exit completion so tests verify graceful drain vs forced kill
// deterministically without time.Sleep.
type fakeProcess struct {
	pid         int
	ignoreTerm  bool
	sigCh       chan os.Signal
	killCh      chan struct{}
	exitCh      chan error
	exitOnce    sync.Once
	mu          sync.Mutex
	signalsSent []os.Signal
	killed      bool
}

// newFakeProcess creates a fakeProcess with the specified PID and SIGTERM
// behavior.
//
// # Parameters
//
//   - pid: Synthetic process ID.
//   - ignoreTerm: When true, SIGTERM does not exit the process so Supervisor
//     must fall back to Kill after DrainTimeout.
//
// # Returns
//
// An initialized *fakeProcess.
//
// # Example
//
//	fp := newFakeProcess(1001, false)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:466 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func newFakeProcess(pid int, ignoreTerm bool) *fakeProcess {
	return &fakeProcess{
		pid:        pid,
		ignoreTerm: ignoreTerm,
		sigCh:      make(chan os.Signal, 4),
		killCh:     make(chan struct{}, 1),
		exitCh:     make(chan error, 1),
	}
}

// PID returns the synthetic process ID.
//
// # Parameters
//
// None.
//
// # Returns
//
// The process ID assigned at construction.
//
// # Example
//
//	pid := fp.PID()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope
// (may be satisfied via interface dispatch or external callers).
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *fakeProcess) PID() int { return p.pid }

// Signal records sig and exits cleanly unless ignoreTerm is true.
//
// # Parameters
//
//   - sig: OS signal delivered by Supervisor.
//
// # Returns
//
// Always nil.
//
// # Example
//
//	_ = fp.Signal(syscall.SIGTERM)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope
// (may be satisfied via interface dispatch or external callers).
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *fakeProcess) Signal(sig os.Signal) error {
	p.mu.Lock()
	p.signalsSent = append(p.signalsSent, sig)
	p.mu.Unlock()
	select {
	case p.sigCh <- sig:
	default:
	}
	if !p.ignoreTerm {
		p.finish(nil)
	}
	return nil
}

// Kill records a SIGKILL and forces Wait to return immediately.
//
// # Parameters
//
// None.
//
// # Returns
//
// Always nil.
//
// # Example
//
//	_ = fp.Kill()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope
// (may be satisfied via interface dispatch or external callers).
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *fakeProcess) Kill() error {
	p.mu.Lock()
	p.killed = true
	p.mu.Unlock()
	select {
	case p.killCh <- struct{}{}:
	default:
	}
	p.finish(errors.New("signal: killed"))
	return nil
}

// Wait blocks until finish is called by Signal, Kill, or a test crash trigger.
//
// # Parameters
//
// None.
//
// # Returns
//
// The exit error passed to finish.
//
// # Example
//
//	err := fp.Wait()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope
// (may be satisfied via interface dispatch or external callers).
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *fakeProcess) Wait() error {
	return <-p.exitCh
}

// finish delivers exitErr exactly once to Wait.
//
// # Parameters
//
//   - err: Exit error to report from Wait.
//
// # Example
//
//	fp.finish(errors.New("exit status 2"))
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:244 (direct call)
//   - internal/watchdog/watchdog_test.go:279 (direct call)
//   - internal/watchdog/watchdog_test.go:1932 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *fakeProcess) finish(err error) {
	p.exitOnce.Do(func() {
		p.exitCh <- err
	})
}

// wasKilled reports whether Kill was invoked on p.
//
// # Parameters
//
// None.
//
// # Returns
//
// true if Kill was called.
//
// # Example
//
//	if !fp.wasKilled() { t.Fatal("expected SIGKILL") }
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:1481 (direct call)
//   - internal/watchdog/watchdog_test.go:1490 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *fakeProcess) wasKilled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.killed
}

// signals returns a copy of all signals sent via Signal.
//
// # Parameters
//
// None.
//
// # Returns
//
// Slice of OS signals sent to p.
//
// # Example
//
//	sigs := fp.signals()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:1478 (direct call)
//   - internal/watchdog/watchdog_test.go:1479 (direct call)
//   - internal/watchdog/watchdog_test.go:1487 (direct call)
//   - internal/watchdog/watchdog_test.go:1488 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *fakeProcess) signals() []os.Signal {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]os.Signal(nil), p.signalsSent...)
}

// fakeProcessManager records started fakeProcess instances in order.
type fakeProcessManager struct {
	mu          sync.Mutex
	nextPID     int
	ignoreTerms []bool
	started     []*fakeProcess
	startedCh   chan *fakeProcess
}

// newFakeProcessManager creates a ProcessManager test double whose children
// follow ignoreTerms per spawn index.
//
// # Parameters
//
//   - ignoreTerms: Optional per-spawn booleans controlling whether each child
//     ignores SIGTERM.
//
// # Returns
//
// An initialized *fakeProcessManager.
//
// # Example
//
//	pm := newFakeProcessManager(false, true)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:1401 (direct call)
//   - internal/watchdog/watchdog_test.go:1880 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func newFakeProcessManager(ignoreTerms ...bool) *fakeProcessManager {
	return &fakeProcessManager{
		nextPID:     1000,
		ignoreTerms: ignoreTerms,
		startedCh:   make(chan *fakeProcess, 32),
	}
}

// Start spawns the next synthetic fakeProcess and records it.
//
// # Parameters
//
//   - name: Command binary name (unused beyond non-empty validation).
//   - args: Command arguments.
//
// # Returns
//
// The newly created *fakeProcess as a watchdog.ManagedProcess.
//
// # Example
//
//	proc, err := pm.Start("concert", nil)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope
// (may be satisfied via interface dispatch or external callers).
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (m *fakeProcessManager) Start(name string, args []string) (watchdog.ManagedProcess, error) {
	_ = name
	_ = args
	m.mu.Lock()
	idx := len(m.started)
	m.nextPID++
	ignore := false
	if idx < len(m.ignoreTerms) {
		ignore = m.ignoreTerms[idx]
	}
	fp := newFakeProcess(m.nextPID, ignore)
	m.started = append(m.started, fp)
	m.mu.Unlock()
	select {
	case m.startedCh <- fp:
	default:
	}
	return fp, nil
}

// count returns the number of child processes started so far.
//
// # Parameters
//
// None.
//
// # Returns
//
// Count of Start calls.
//
// # Example
//
//	n := pm.count()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:1472 (direct call)
//   - internal/watchdog/watchdog_test.go:1953 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (m *fakeProcessManager) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.started)
}

// procAt returns the i-th spawned fakeProcess.
//
// # Parameters
//
//   - i: Zero-based spawn index.
//
// # Returns
//
// The *fakeProcess created on the i-th Start call.
//
// # Example
//
//	first := pm.procAt(0)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:1477 (direct call)
//   - internal/watchdog/watchdog_test.go:1486 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (m *fakeProcessManager) procAt(i int) *fakeProcess {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.started[i]
}

// fakeConcertServer simulates Concert's /_room/healthz, /_room/readyz,
// /_room/metrics, and /_room/queue/clear endpoints with race-safe state.
type fakeConcertServer struct {
	mu              sync.Mutex
	healthStatus    int
	readyStatus     int
	readyBody       string
	metricsBody     string
	metricsStatus   int
	expectedOpToken string
	clearOnFlush    bool
	clearCalls      int
	lastClearMode   string
	lastClearAuth   string
	lastMetricsAuth string
	srv             *httptest.Server
}

// newFakeConcertServer starts an httptest.Server backed by fakeConcertServer
// and registers cleanup with t.
//
// # Parameters
//
//   - t: Active testing.T for automatic server teardown.
//   - opToken: Expected operator bearer token for /_room/queue/clear (empty allows any).
//
// # Returns
//
// A running *fakeConcertServer.
//
// # Example
//
//	fc := newFakeConcertServer(t, "test-op-token")
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:1040 (direct call)
//   - internal/watchdog/watchdog_test.go:1238 (direct call)
//   - internal/watchdog/watchdog_test.go:1315 (direct call)
//   - internal/watchdog/watchdog_test.go:1395 (direct call)
//   - internal/watchdog/watchdog_test.go:1542 (direct call)
//   - internal/watchdog/watchdog_test.go:1641 (direct call)
//   - internal/watchdog/watchdog_test.go:1768 (direct call)
//   - internal/watchdog/watchdog_test.go:1877 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func newFakeConcertServer(t *testing.T, opToken string) *fakeConcertServer {
	t.Helper()
	fc := &fakeConcertServer{
		healthStatus:    http.StatusOK,
		readyStatus:     http.StatusOK,
		readyBody:       "ok",
		metricsStatus:   http.StatusOK,
		expectedOpToken: opToken,
		metricsBody:     healthyMetricsText(100, 0, 0, 2, 0, 0),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/_room/healthz", func(w http.ResponseWriter, r *http.Request) {
		fc.mu.Lock()
		st := fc.healthStatus
		fc.mu.Unlock()
		w.WriteHeader(st)
		if st == http.StatusOK {
			_, _ = io.WriteString(w, "ok")
		} else {
			_, _ = io.WriteString(w, "unhealthy")
		}
	})
	mux.HandleFunc("/_room/readyz", func(w http.ResponseWriter, r *http.Request) {
		fc.mu.Lock()
		st, body := fc.readyStatus, fc.readyBody
		fc.mu.Unlock()
		w.WriteHeader(st)
		_, _ = io.WriteString(w, body)
	})
	mux.HandleFunc("/_room/metrics", func(w http.ResponseWriter, r *http.Request) {
		fc.mu.Lock()
		fc.lastMetricsAuth = r.Header.Get("Authorization")
		st, body := fc.metricsStatus, fc.metricsBody
		fc.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(st)
		_, _ = io.WriteString(w, body)
	})
	mux.HandleFunc("/_room/queue/clear", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<10))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var req struct {
			Mode string `json:"mode"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fc.mu.Lock()
		fc.lastClearAuth = r.Header.Get("Authorization")
		wantAuth := ""
		if fc.expectedOpToken != "" {
			wantAuth = "Bearer " + fc.expectedOpToken
		}
		if wantAuth != "" && fc.lastClearAuth != wantAuth {
			fc.mu.Unlock()
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fc.clearCalls++
		fc.lastClearMode = req.Mode
		if fc.clearOnFlush && req.Mode == "stale" {
			fc.metricsBody = healthyMetricsText(120, 0, 0, 2, 0, 0)
		}
		fc.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"mode":"stale","removed":40,"live_queue_depth":0,"queue_depth":0}`)
	})
	fc.srv = httptest.NewServer(mux)
	t.Cleanup(fc.srv.Close)
	return fc
}

// setState replaces the server's healthz, readyz, and metrics responses safely.
//
// # Parameters
//
//   - healthStatus: HTTP status for /_room/healthz.
//   - readyStatus: HTTP status for /_room/readyz.
//   - readyBody: Response body for /_room/readyz.
//   - metricsBody: Prometheus text exposition returned by /_room/metrics.
//
// # Example
//
//	fc.setState(200, 503, "upstream unhealthy", metrics)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:1088 (direct call)
//   - internal/watchdog/watchdog_test.go:1271 (direct call)
//   - internal/watchdog/watchdog_test.go:1345 (direct call)
//   - internal/watchdog/watchdog_test.go:1396 (direct call)
//   - internal/watchdog/watchdog_test.go:1569 (direct call)
//   - internal/watchdog/watchdog_test.go:1577 (direct call)
//   - internal/watchdog/watchdog_test.go:1585 (direct call)
//   - internal/watchdog/watchdog_test.go:1642 (direct call)
//   - internal/watchdog/watchdog_test.go:1769 (direct call)
//   - internal/watchdog/watchdog_test.go:1878 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (fc *fakeConcertServer) setState(healthStatus, readyStatus int, readyBody, metricsBody string) {
	fc.mu.Lock()
	fc.healthStatus = healthStatus
	fc.readyStatus = readyStatus
	fc.readyBody = readyBody
	fc.metricsBody = metricsBody
	fc.mu.Unlock()
}

// healthyMetricsText builds a Concert-compatible Prometheus exposition payload.
//
// # Parameters
//
//   - ok2xx: concert_upstream_requests_total{status_class="2xx"} value.
//   - err5xx: concert_upstream_requests_total{status_class="5xx"} value.
//   - rej503: concert_room_rejected_503_total value.
//   - upstreamHealthy: concert_upstream_backends_healthy value.
//   - liveQueue: concert_room_live_queue_depth value.
//   - occupancy: concert_room_occupancy value.
//
// # Returns
//
// Formatted Prometheus 0.0.4 metrics text.
//
// # Example
//
//	body := healthyMetricsText(100, 0, 0, 2, 0, 5)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:588 (direct call)
//   - internal/watchdog/watchdog_test.go:649 (direct call)
//   - internal/watchdog/watchdog_test.go:1089 (direct call)
//   - internal/watchdog/watchdog_test.go:1271 (direct call)
//   - internal/watchdog/watchdog_test.go:1345 (direct call)
//   - internal/watchdog/watchdog_test.go:1569 (direct call)
//   - internal/watchdog/watchdog_test.go:1577 (direct call)
//   - internal/watchdog/watchdog_test.go:1585 (direct call)
//   - internal/watchdog/watchdog_test.go:1642 (direct call)
//   - internal/watchdog/watchdog_test.go:1769 (direct call)
//   - internal/watchdog/watchdog_test.go:1878 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func healthyMetricsText(ok2xx, err5xx, rej503, upstreamHealthy, liveQueue, occupancy int) string {
	ready := 1
	if upstreamHealthy == 0 {
		ready = 0
	}
	return fmt.Sprintf(`# HELP concert_build_info Build info.
# TYPE concert_build_info gauge
concert_build_info{version="v1.0.0",go_version="go1.27.4",fips="standard"} 1
concert_room_cap 20
concert_room_occupancy %d
concert_room_queue_depth %d
concert_room_live_queue_depth %d
concert_room_rejected_503_total %d
concert_room_timeouts_total 0
concert_upstream_backends_total 2
concert_upstream_backends_healthy %d
concert_upstream_requests_total{status_class="2xx"} %d
concert_upstream_requests_total{status_class="3xx"} 0
concert_upstream_requests_total{status_class="4xx"} 0
concert_upstream_requests_total{status_class="5xx"} %d
concert_upstream_errors_total 0
concert_ready %d
`, occupancy, liveQueue, liveQueue, rej503, upstreamHealthy, ok2xx, err5xx, ready)
}

// TestParsePrometheusMetrics verifies stdlib Prometheus parsing for all tracked
// Concert and process metrics, label escaping, comments, NaN/Inf skipping, and
// R3 payload size bounding.
//
// # Parameters
//
//   - t: Active test context (invoked by `go test ./internal/watchdog`).
//
// # Example
//
//	go test -v -run '^TestParsePrometheusMetrics$' ./internal/watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestParsePrometheusMetrics(t *testing.T) {
	payload := `# HELP concert_build_info Build and runtime information.
# TYPE concert_build_info gauge
concert_build_info{version="v2.1.0",note="escaped \"quote\" and } brace"} 1 1700000000000
concert_room_cap 50
concert_room_occupancy 12
concert_room_queue_depth 45
concert_room_live_queue_depth 30
concert_room_max_queue_depth 500
concert_room_rejected_503_total 7
concert_room_timeouts_total 3
concert_room_cleared_total 11
concert_upstream_backends_total 3
concert_upstream_backends_healthy 2
concert_upstream_requests_total{status_class="2xx"} 1.5e+03
concert_upstream_requests_total{status_class="3xx"} 20
concert_upstream_requests_total{status_class="4xx"} 5
concert_upstream_requests_total{status_class="5xx"} 9
concert_upstream_errors_total 4
concert_ready 1
concert_nan_metric NaN
concert_inf_metric +Inf
go_memstats_alloc_bytes 20971520
process_resident_memory_bytes 104857600
process_open_fds 128
process_max_fds 65536
`
	snap, err := watchdog.ParsePrometheusMetrics(strings.NewReader(payload))
	if err != nil {
		t.Fatalf("ParsePrometheusMetrics() unexpected error: %v", err)
	}
	if snap.RoomCap != 50 || !snap.HasRoomCap {
		t.Errorf("RoomCap = (%v, %v), want (50, true)", snap.RoomCap, snap.HasRoomCap)
	}
	if snap.RoomOccupancy != 12 || snap.QueueDepth != 45 || snap.LiveQueueDepth != 30 {
		t.Errorf("queue gauges = (%v, %v, %v), want (12, 45, 30)", snap.RoomOccupancy, snap.QueueDepth, snap.LiveQueueDepth)
	}
	if snap.Rejected503Total != 7 || snap.TimeoutsTotal != 3 || snap.ClearedTotal != 11 {
		t.Errorf("room counters = (%v, %v, %v), want (7, 3, 11)", snap.Rejected503Total, snap.TimeoutsTotal, snap.ClearedTotal)
	}
	if snap.UpstreamBackendsTotal != 3 || snap.UpstreamBackendsHealthy != 2 || !snap.HasUpstreamBackendsHealthy {
		t.Errorf("upstream backends = (%d/%d, has=%v), want (2/3, true)", snap.UpstreamBackendsHealthy, snap.UpstreamBackendsTotal, snap.HasUpstreamBackendsHealthy)
	}
	if snap.Upstream2xxTotal != 1500 || snap.Upstream3xxTotal != 20 || snap.Upstream4xxTotal != 5 || snap.Upstream5xxTotal != 9 {
		t.Errorf("upstream status totals = (%v, %v, %v, %v), want (1500, 20, 5, 9)",
			snap.Upstream2xxTotal, snap.Upstream3xxTotal, snap.Upstream4xxTotal, snap.Upstream5xxTotal)
	}
	if !snap.HasResidentMemoryBytes || snap.ResidentMemoryBytes != 104857600 {
		t.Errorf("ResidentMemoryBytes = (%d, %v), want (104857600, true)", snap.ResidentMemoryBytes, snap.HasResidentMemoryBytes)
	}
	if !snap.HasOpenFDs || snap.OpenFDs != 128 || !snap.HasMaxFDs || snap.MaxFDs != 65536 {
		t.Errorf("FDs = (%d/%d), want (128/65536)", snap.OpenFDs, snap.MaxFDs)
	}

	// Verify R3 size bound rejects oversized streams.
	oversized := bytes.NewReader(bytes.Repeat([]byte("a"), watchdog.MaxMetricsBodyBytes+1))
	if _, err := watchdog.ParsePrometheusMetrics(oversized); !errors.Is(err, watchdog.ErrMetricsTooLarge) {
		t.Fatalf("ParsePrometheusMetrics(oversized) err = %v, want ErrMetricsTooLarge", err)
	}
}

// TestInspectProcFS verifies Linux /proc/<pid>/statm and /proc/<pid>/fd parsing
// deterministically against a temporary procfs directory.
//
// # Parameters
//
//   - t: Active test context (invoked by `go test ./internal/watchdog`).
//
// # Example
//
//	go test -v -run '^TestInspectProcFS$' ./internal/watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestInspectProcFS(t *testing.T) {
	root := t.TempDir()
	pidDir := filepath.Join(root, "4242")
	fdDir := filepath.Join(pidDir, "fd")
	if err := os.MkdirAll(fdDir, 0o700); err != nil {
		t.Fatalf("mkdir fd dir: %v", err)
	}
	// statm fields: size resident shared text lib data dt
	if err := os.WriteFile(filepath.Join(pidDir, "statm"), []byte("10000 2500 500 100 0 2000 0\n"), 0o600); err != nil {
		t.Fatalf("write statm: %v", err)
	}
	for i := range 7 {
		if err := os.WriteFile(filepath.Join(fdDir, fmt.Sprintf("%d", i)), nil, 0o600); err != nil {
			t.Fatalf("write fd entry %d: %v", i, err)
		}
	}

	got, err := watchdog.InspectProcFS(root, 4242, 4096)
	if err != nil {
		t.Fatalf("InspectProcFS() unexpected error: %v", err)
	}
	wantRSS := uint64(2500 * 4096)
	if !got.HasRSS || got.RSSBytes != wantRSS {
		t.Errorf("RSS = (%d, %v), want (%d, true)", got.RSSBytes, got.HasRSS, wantRSS)
	}
	if !got.HasOpenFDs || got.OpenFDs != 7 {
		t.Errorf("OpenFDs = (%d, %v), want (7, true)", got.OpenFDs, got.HasOpenFDs)
	}
	if _, err := watchdog.InspectProcFS(root, 0, 4096); !errors.Is(err, watchdog.ErrInvalidPID) {
		t.Errorf("InspectProcFS(pid=0) err = %v, want ErrInvalidPID", err)
	}
}

// TestSecretRedactionAndValidation verifies S5/S6/S7 guarantees: secrets never
// leak through fmt, JSON, text, or slog, and file/env loading fails closed on
// open permissions, empty content, or placeholders.
//
// # Parameters
//
//   - t: Active test context (invoked by `go test ./internal/watchdog`).
//
// # Example
//
//	go test -v -run '^TestSecretRedactionAndValidation$' ./internal/watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestSecretRedactionAndValidation(t *testing.T) {
	// Synthesized test-only value; never a real credential.
	synthetic := "synthetic-unit-test-bearer-9911"
	sec := watchdog.NewSecret(synthetic)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	logger.Info("check", "token", sec)

	jsonBytes, err := json.Marshal(struct {
		Tok watchdog.Secret `json:"tok"`
	}{Tok: sec})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	textBytes, err := sec.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	outputs := []string{
		sec.String(),
		sec.GoString(),
		fmt.Sprintf("%v", sec),
		fmt.Sprintf("%+v", sec),
		fmt.Sprintf("%#v", sec),
		fmt.Sprintf("%q", sec),
		string(jsonBytes),
		string(textBytes),
		logBuf.String(),
	}
	for i, out := range outputs {
		if strings.Contains(out, synthetic) {
			t.Errorf("output[%d] leaked raw secret: %q", i, out)
		}
		if !strings.Contains(out, watchdog.RedactedPlaceholder) {
			t.Errorf("output[%d] missing placeholder: %q", i, out)
		}
	}
	if sec.Reveal() != synthetic {
		t.Fatalf("Reveal() did not return underlying value")
	}

	// File permission and placeholder checks.
	dir := t.TempDir()
	goodPath := filepath.Join(dir, "good.tok")
	if err := os.WriteFile(goodPath, []byte(synthetic+"\n"), 0o600); err != nil {
		t.Fatalf("write good secret: %v", err)
	}
	loaded, err := watchdog.LoadSecretFromFile(goodPath)
	if err != nil || loaded.Reveal() != synthetic {
		t.Fatalf("LoadSecretFromFile(0600) = (%v, %v), want valid secret", loaded, err)
	}

	if runtime.GOOS != "windows" {
		openPath := filepath.Join(dir, "open.tok")
		if err := os.WriteFile(openPath, []byte(synthetic), 0o644); err != nil {
			t.Fatalf("write open secret: %v", err)
		}
		if _, err := watchdog.LoadSecretFromFile(openPath); !errors.Is(err, watchdog.ErrSecretPermissions) {
			t.Errorf("LoadSecretFromFile(0644) err = %v, want ErrSecretPermissions", err)
		}
	}

	phPath := filepath.Join(dir, "placeholder.tok")
	if err := os.WriteFile(phPath, []byte("changeme\n"), 0o600); err != nil {
		t.Fatalf("write placeholder secret: %v", err)
	}
	if _, err := watchdog.LoadSecretFromFile(phPath); !errors.Is(err, watchdog.ErrSecretPlaceholder) {
		t.Errorf("LoadSecretFromFile(placeholder) err = %v, want ErrSecretPlaceholder", err)
	}

	// Webhook URL validation: HTTPS and localhost HTTP allowed; remote HTTP and userinfo rejected.
	if _, err := watchdog.ValidateWebhookURL("https://alerts.example.com/hook"); err != nil {
		t.Errorf("ValidateWebhookURL(https) unexpected error: %v", err)
	}
	if _, err := watchdog.ValidateWebhookURL("http://127.0.0.1:9000/hook"); err != nil {
		t.Errorf("ValidateWebhookURL(127.0.0.1) unexpected error: %v", err)
	}
	if _, err := watchdog.ValidateWebhookURL("http://alerts.example.com/hook"); !errors.Is(err, watchdog.ErrInvalidURL) {
		t.Errorf("ValidateWebhookURL(remote http) err = %v, want ErrInvalidURL", err)
	}
	withUser := (&url.URL{
		Scheme: "https",
		User:   url.UserPassword("testuser", "testval"),
		Host:   "alerts.example.com",
		Path:   "/hook",
	}).String()
	if _, err := watchdog.ValidateWebhookURL(withUser); !errors.Is(err, watchdog.ErrInvalidURL) {
		t.Errorf("ValidateWebhookURL(userinfo) err = %v, want ErrInvalidURL", err)
	}

	q := url.Values{}
	q.Set("token", "synthetic-query-val")
	q.Set("foo", "bar")
	withQuery := (&url.URL{
		Scheme:   "https",
		User:     url.UserPassword("testuser", "testval"),
		Host:     "alerts.example.com",
		Path:     "/hook",
		RawQuery: q.Encode(),
	}).String()
	redacted := watchdog.RedactURL(withQuery)
	if strings.Contains(redacted, "testval") || strings.Contains(redacted, "synthetic-query-val") {
		t.Errorf("RedactURL leaked secret: %q", redacted)
	}
}

// TestOriginDownNeverRestartsConcert proves the critical invariant that an
// origin/upstream outage (concert_upstream_backends_healthy == 0) emits alerts
// ONLY and NEVER issues a queue flush or Concert restart.
//
// # Parameters
//
//   - t: Active test context (invoked by `go test ./internal/watchdog`).
//
// # Example
//
//	go test -v -run '^TestOriginDownNeverRestartsConcert$' ./internal/watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestOriginDownNeverRestartsConcert(t *testing.T) {
	opTok := "synthetic-op-token-origin"
	whTok := "synthetic-wh-token-origin"
	fc := newFakeConcertServer(t, opTok)

	var alertsMu sync.Mutex
	var alerts []watchdog.AlertEvent
	var webhookAuth string
	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev watchdog.AlertEvent
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		alertsMu.Lock()
		webhookAuth = r.Header.Get("Authorization")
		alerts = append(alerts, ev)
		alertsMu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(whSrv.Close)

	clk := newFakeClock(time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC))
	var restarts atomic.Int32

	sup, err := watchdog.NewSupervisor(watchdog.SupervisorConfig{
		HealthURL:       fc.srv.URL + "/_room/healthz",
		ReadyURL:        fc.srv.URL + "/_room/readyz",
		MetricsURL:      fc.srv.URL + "/_room/metrics",
		ClearURL:        fc.srv.URL + "/_room/queue/clear",
		AlertWebhookURL: whSrv.URL + "/alert",
		OperatorToken:   watchdog.NewSecret(opTok),
		WebhookToken:    watchdog.NewSecret(whTok),
		Interval:        5 * time.Second,
		Timeout:         2 * time.Second,
		DrainTimeout:    time.Second,
		Policy:          watchdog.DefaultPolicyConfig(),
		Now:             clk.Now,
		Sleep:           func(_ context.Context, d time.Duration) error { clk.Advance(d); return nil },
		RestartFunc: func(_ context.Context, _ int) error {
			restarts.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	// Simulate severe origin outage: healthz=200, readyz=503 "upstream unhealthy",
	// upstream_healthy=0, and rising 5xx/503 counters over 10 consecutive probes.
	for i := range 10 {
		fc.setState(http.StatusOK, http.StatusServiceUnavailable, "upstream unhealthy",
			healthyMetricsText(100, (i+1)*50, (i+1)*20, 0, 30, 0))
		_, dec, err := sup.Step(t.Context())
		if err != nil {
			t.Fatalf("Step %d unexpected error: %v", i, err)
		}
		if dec.Action != watchdog.ActionAlertOnly {
			t.Fatalf("Step %d action = %q, want %q (origin down must NEVER restart)", i, dec.Action, watchdog.ActionAlertOnly)
		}
		if dec.Reason != watchdog.ReasonOriginDown {
			t.Fatalf("Step %d reason = %q, want %q", i, dec.Reason, watchdog.ReasonOriginDown)
		}
		clk.Advance(10 * time.Second)
	}

	if got := restarts.Load(); got != 0 {
		t.Fatalf("restarts = %d, want 0 when upstream origin is down", got)
	}
	fc.mu.Lock()
	flushes := fc.clearCalls
	fc.mu.Unlock()
	if flushes != 0 {
		t.Fatalf("queue clear calls = %d, want 0 when upstream origin is down", flushes)
	}

	alertsMu.Lock()
	defer alertsMu.Unlock()
	if len(alerts) == 0 {
		t.Fatalf("expected at least 1 alert webhook event for origin outage")
	}
	if webhookAuth != "Bearer "+whTok {
		t.Errorf("webhook Authorization header mismatch: got %q", webhookAuth)
	}
	if got, ok := alerts[0].UpstreamHealthy.Get(); !ok || got != 0 {
		t.Errorf("alert upstream_healthy = %v, want Some(0)", alerts[0].UpstreamHealthy)
	}
}

// TestAlertEvent_UpstreamHealthyJSON verifies that AlertEvent.UpstreamHealthy
// preserves the JSON wire distinction between unobserved (opt.None -> omitted)
// and observed zero healthy backends (opt.Some(0) -> `"upstream_healthy":0`).
//
// # Parameters
//
//   - t: Active test context (invoked by `go test ./internal/watchdog`).
//
// # Example
//
//	go test -v -run '^TestAlertEvent_UpstreamHealthyJSON$' ./internal/watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestAlertEvent_UpstreamHealthyJSON(t *testing.T) {
	base := watchdog.AlertEvent{
		Timestamp: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC),
		Severity:  "warning",
		Action:    watchdog.ActionAlertOnly,
		Reason:    watchdog.ReasonOriginDown,
		Message:   "upstream check",
	}

	// Unobserved (None) must omit "upstream_healthy".
	rawNone, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("json.Marshal(None): %v", err)
	}
	if strings.Contains(string(rawNone), "upstream_healthy") {
		t.Fatalf("expected upstream_healthy omitted for None, got %s", rawNone)
	}
	var decNone watchdog.AlertEvent
	if err := json.Unmarshal(rawNone, &decNone); err != nil {
		t.Fatalf("json.Unmarshal(None): %v", err)
	}
	if !decNone.UpstreamHealthy.IsNone() {
		t.Fatalf("expected None after unmarshaling omitted field, got %v", decNone.UpstreamHealthy)
	}

	// Observed 0 healthy backends (Some(0)) must emit "upstream_healthy":0.
	evZero := base
	evZero.UpstreamHealthy = opt.Some(0)
	rawZero, err := json.Marshal(evZero)
	if err != nil {
		t.Fatalf("json.Marshal(Some(0)): %v", err)
	}
	if !strings.Contains(string(rawZero), `"upstream_healthy":0`) {
		t.Fatalf(`expected "upstream_healthy":0 in JSON, got %s`, rawZero)
	}
	var decZero watchdog.AlertEvent
	if err := json.Unmarshal(rawZero, &decZero); err != nil {
		t.Fatalf("json.Unmarshal(Some(0)): %v", err)
	}
	if got, ok := decZero.UpstreamHealthy.Get(); !ok || got != 0 {
		t.Fatalf("unmarshaled Some(0) = (%d, %v), want (0, true)", got, ok)
	}

	// Observed positive backend count (Some(3)) must emit "upstream_healthy":3.
	evThree := base
	evThree.UpstreamHealthy = opt.Some(3)
	rawThree, err := json.Marshal(evThree)
	if err != nil {
		t.Fatalf("json.Marshal(Some(3)): %v", err)
	}
	if !strings.Contains(string(rawThree), `"upstream_healthy":3`) {
		t.Fatalf(`expected "upstream_healthy":3 in JSON, got %s`, rawThree)
	}
	var decThree watchdog.AlertEvent
	if err := json.Unmarshal(rawThree, &decThree); err != nil {
		t.Fatalf("json.Unmarshal(Some(3)): %v", err)
	}
	if got, ok := decThree.UpstreamHealthy.Get(); !ok || got != 3 {
		t.Fatalf("unmarshaled Some(3) = (%d, %v), want (3, true)", got, ok)
	}

	// Explicit JSON null decodes to None.
	if err := json.Unmarshal([]byte(`{"upstream_healthy":null}`), &decThree); err != nil {
		t.Fatalf("json.Unmarshal(null): %v", err)
	}
	if !decThree.UpstreamHealthy.IsNone() {
		t.Fatalf("expected JSON null to yield None, got %v", decThree.UpstreamHealthy)
	}
}

// TestWedgedQueueFlushesStaleBeforeRestart proves that when /_room/healthz is
// responsive and the waiting room queue is wedged, the watchdog first issues
// POST /_room/queue/clear {"mode":"stale"} with bearer auth, avoids restarting
// if that recovers, and escalates to restart after FlushGraceWindow if still wedged.
//
// # Parameters
//
//   - t: Active test context (invoked by `go test ./internal/watchdog`).
//
// # Example
//
//	go test -v -run '^TestWedgedQueueFlushesStaleBeforeRestart$' ./internal/watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestWedgedQueueFlushesStaleBeforeRestart(t *testing.T) {
	t.Run("recovers after stale flush without restarting", func(t *testing.T) {
		opTok := "synthetic-op-token-flush-ok"
		fc := newFakeConcertServer(t, opTok)
		fc.mu.Lock()
		fc.clearOnFlush = true
		fc.mu.Unlock()

		clk := newFakeClock(time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC))
		var restarts atomic.Int32

		cfg := watchdog.DefaultPolicyConfig()
		cfg.ConsecutiveFailures = 3
		cfg.FlushGraceWindow = 30 * time.Second

		sup, err := watchdog.NewSupervisor(watchdog.SupervisorConfig{
			HealthURL:     fc.srv.URL + "/_room/healthz",
			ReadyURL:      fc.srv.URL + "/_room/readyz",
			MetricsURL:    fc.srv.URL + "/_room/metrics",
			ClearURL:      fc.srv.URL + "/_room/queue/clear",
			OperatorToken: watchdog.NewSecret(opTok),
			Interval:      5 * time.Second,
			Timeout:       2 * time.Second,
			Policy:        cfg,
			Now:           clk.Now,
			Sleep:         func(_ context.Context, d time.Duration) error { clk.Advance(d); return nil },
			RestartFunc: func(_ context.Context, _ int) error {
				restarts.Add(1)
				return nil
			},
		})
		if err != nil {
			t.Fatalf("NewSupervisor: %v", err)
		}

		// Wedged queue: 40 live visitors stuck with 0 occupancy and zero 2xx progress.
		fc.setState(http.StatusOK, http.StatusOK, "ok", healthyMetricsText(100, 0, 0, 2, 40, 0))

		for i := range 2 {
			_, dec, err := sup.Step(t.Context())
			if err != nil {
				t.Fatalf("Step %d error: %v", i, err)
			}
			if dec.Action != watchdog.ActionNone {
				t.Fatalf("Step %d action = %q, want %q before threshold", i, dec.Action, watchdog.ActionNone)
			}
			clk.Advance(5 * time.Second)
		}

		// 3rd consecutive stuck probe triggers ActionFlushStale.
		_, dec, err := sup.Step(t.Context())
		if err != nil {
			t.Fatalf("Step 3 flush error: %v", err)
		}
		if dec.Action != watchdog.ActionFlushStale {
			t.Fatalf("Step 3 action = %q, want %q", dec.Action, watchdog.ActionFlushStale)
		}
		fc.mu.Lock()
		calls, mode, auth := fc.clearCalls, fc.lastClearMode, fc.lastClearAuth
		fc.mu.Unlock()
		if calls != 1 || mode != "stale" || auth != "Bearer "+opTok {
			t.Fatalf("queue clear = (calls=%d mode=%q auth_match=%v), want (1, stale, true)", calls, mode, auth == "Bearer "+opTok)
		}

		// Next probe sees recovered queue -> healthy, zero restarts.
		clk.Advance(5 * time.Second)
		_, dec, err = sup.Step(t.Context())
		if err != nil {
			t.Fatalf("post-flush Step error: %v", err)
		}
		if dec.Reason != watchdog.ReasonHealthy || dec.Action != watchdog.ActionNone {
			t.Fatalf("post-flush decision = (%q, %q), want (healthy, none)", dec.Reason, dec.Action)
		}
		if restarts.Load() != 0 {
			t.Fatalf("restarts = %d, want 0 after successful stale flush", restarts.Load())
		}
	})

	t.Run("escalates to restart if still wedged after grace window", func(t *testing.T) {
		opTok := "synthetic-op-token-flush-escalate"
		fc := newFakeConcertServer(t, opTok)
		// clearOnFlush remains false: queue stays wedged even after flush.
		clk := newFakeClock(time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC))
		var restarts atomic.Int32

		cfg := watchdog.DefaultPolicyConfig()
		cfg.ConsecutiveFailures = 2
		cfg.FlushGraceWindow = 20 * time.Second
		cfg.FlushCooldown = 2 * time.Minute

		sup, err := watchdog.NewSupervisor(watchdog.SupervisorConfig{
			HealthURL:     fc.srv.URL + "/_room/healthz",
			ReadyURL:      fc.srv.URL + "/_room/readyz",
			MetricsURL:    fc.srv.URL + "/_room/metrics",
			ClearURL:      fc.srv.URL + "/_room/queue/clear",
			OperatorToken: watchdog.NewSecret(opTok),
			Interval:      5 * time.Second,
			Timeout:       2 * time.Second,
			Policy:        cfg,
			Now:           clk.Now,
			Sleep:         func(_ context.Context, d time.Duration) error { clk.Advance(d); return nil },
			RestartFunc: func(_ context.Context, _ int) error {
				restarts.Add(1)
				return nil
			},
		})
		if err != nil {
			t.Fatalf("NewSupervisor: %v", err)
		}

		fc.setState(http.StatusOK, http.StatusOK, "ok", healthyMetricsText(100, 0, 0, 2, 40, 0))
		_, _, _ = sup.Step(t.Context()) // fail 1
		clk.Advance(5 * time.Second)
		_, dec, err := sup.Step(t.Context()) // fail 2 -> flush stale
		if err != nil || dec.Action != watchdog.ActionFlushStale {
			t.Fatalf("step 2 = (%q, %v), want ActionFlushStale", dec.Action, err)
		}

		// Inside grace window (10s < 20s): must wait, not restart yet.
		clk.Advance(10 * time.Second)
		_, dec, _ = sup.Step(t.Context())
		if dec.Action != watchdog.ActionNone {
			t.Fatalf("inside grace window action = %q, want ActionNone", dec.Action)
		}
		if restarts.Load() != 0 {
			t.Fatalf("restarted prematurely inside grace window")
		}

		// Past grace window (25s >= 20s): escalates to ActionRestart.
		clk.Advance(15 * time.Second)
		_, dec, err = sup.Step(t.Context())
		if err != nil || dec.Action != watchdog.ActionRestart {
			t.Fatalf("post-grace step = (%q, %v), want ActionRestart", dec.Action, err)
		}
		if restarts.Load() != 1 {
			t.Fatalf("restarts = %d, want 1", restarts.Load())
		}
	})
}

// TestHealthzFailureDrainBackoffAndCircuitBreaker proves sustained /_room/healthz
// failures trigger graceful SIGTERM drain, SIGKILL fallback on drain timeout,
// exponential backoff, and finally trip the restart-loop circuit breaker.
//
// # Parameters
//
//   - t: Active test context (invoked by `go test ./internal/watchdog`).
//
// # Example
//
//	go test -v -run '^TestHealthzFailureDrainBackoffAndCircuitBreaker$' ./internal/watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestHealthzFailureDrainBackoffAndCircuitBreaker(t *testing.T) {
	fc := newFakeConcertServer(t, "")
	fc.setState(http.StatusInternalServerError, http.StatusInternalServerError, "err", "")

	clk := newFakeClock(time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC))
	// Child 0 exits cleanly on SIGTERM; Child 1 ignores SIGTERM -> forces SIGKILL;
	// Child 2 exits cleanly on SIGTERM.
	pm := newFakeProcessManager(false, true, false, false)

	var sleepMu sync.Mutex
	var backoffs []time.Duration

	policyCfg := watchdog.DefaultPolicyConfig()
	policyCfg.ConsecutiveFailures = 2
	policyCfg.MaxRestartsPerWindow = 3
	policyCfg.RestartWindow = 10 * time.Minute
	policyCfg.InitialBackoff = 2 * time.Second
	policyCfg.MaxBackoff = 6 * time.Second

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var decisionsMu sync.Mutex
	var decisions []watchdog.Decision
	circuitHit := make(chan struct{})
	var circuitOnce sync.Once

	sup, err := watchdog.NewSupervisor(watchdog.SupervisorConfig{
		HealthURL:      fc.srv.URL + "/_room/healthz",
		ReadyURL:       fc.srv.URL + "/_room/readyz",
		MetricsURL:     fc.srv.URL + "/_room/metrics",
		ClearURL:       fc.srv.URL + "/_room/queue/clear",
		Interval:       5 * time.Millisecond,
		Timeout:        2 * time.Second,
		DrainTimeout:   25 * time.Millisecond,
		Policy:         policyCfg,
		ChildCommand:   []string{"fake-concert", "-listen", ":8080"},
		ProcessManager: pm,
		Now:            clk.Now,
		Sleep: func(_ context.Context, d time.Duration) error {
			sleepMu.Lock()
			backoffs = append(backoffs, d)
			sleepMu.Unlock()
			clk.Advance(d)
			return nil
		},
		OnDecision: func(_ watchdog.Observation, dec watchdog.Decision) {
			decisionsMu.Lock()
			decisions = append(decisions, dec)
			decisionsMu.Unlock()
			clk.Advance(5 * time.Second)
			if dec.CircuitOpen {
				circuitOnce.Do(func() { close(circuitHit) })
			}
		},
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	runErrCh := make(chan error, 1)
	go func() { runErrCh <- sup.Run(ctx) }()

	select {
	case <-circuitHit:
	case <-time.After(5 * time.Second):
		cancel()
		<-runErrCh
		t.Fatalf("timed out waiting for restart circuit breaker to trip")
	}

	cancel()
	if err := <-runErrCh; err != nil {
		t.Fatalf("Run() error after cancel: %v", err)
	}

	// Verify 1 initial start + 3 restarts = 4 total spawns, and circuit breaker
	// blocked any 4th restart.
	if got := pm.count(); got != 4 {
		t.Fatalf("spawn count = %d, want 4 (1 initial + 3 restarts before circuit open)", got)
	}

	// Verify child 0 exited via SIGTERM without SIGKILL.
	p0 := pm.procAt(0)
	if len(p0.signals()) == 0 || p0.signals()[0] != syscall.SIGTERM {
		t.Errorf("child 0 signals = %v, want [SIGTERM]", p0.signals())
	}
	if p0.wasKilled() {
		t.Errorf("child 0 should have exited cleanly on SIGTERM without SIGKILL")
	}

	// Verify child 1 received SIGTERM then fell back to SIGKILL after DrainTimeout.
	p1 := pm.procAt(1)
	if len(p1.signals()) == 0 || p1.signals()[0] != syscall.SIGTERM {
		t.Errorf("child 1 signals = %v, want [SIGTERM]", p1.signals())
	}
	if !p1.wasKilled() {
		t.Errorf("child 1 ignored SIGTERM and should have received SIGKILL fallback")
	}

	// Verify exponential backoff capped at MaxBackoff: 2s, 4s, 6s.
	sleepMu.Lock()
	gotBackoffs := append([]time.Duration(nil), backoffs...)
	sleepMu.Unlock()
	wantBackoffs := []time.Duration{2 * time.Second, 4 * time.Second, 6 * time.Second}
	if len(gotBackoffs) != len(wantBackoffs) {
		t.Fatalf("backoffs = %v, want %v", gotBackoffs, wantBackoffs)
	}
	for i := range wantBackoffs {
		if gotBackoffs[i] != wantBackoffs[i] {
			t.Errorf("backoff[%d] = %v, want %v", i, gotBackoffs[i], wantBackoffs[i])
		}
	}

	// Verify circuit-open decision emitted ActionAlertOnly.
	decisionsMu.Lock()
	var sawCircuitAlert bool
	for _, d := range decisions {
		if d.CircuitOpen && d.Action == watchdog.ActionAlertOnly {
			sawCircuitAlert = true
		}
	}
	decisionsMu.Unlock()
	if !sawCircuitAlert {
		t.Fatalf("expected ActionAlertOnly with CircuitOpen=true")
	}
}

// TestInternal5xxStormTriggersRestart proves that sustained Concert-internal
// 5xx responses while upstream backends are healthy and queue is empty trigger
// escalation to ActionRestart.
//
// # Parameters
//
//   - t: Active test context (invoked by `go test ./internal/watchdog`).
//
// # Example
//
//	go test -v -run '^TestInternal5xxStormTriggersRestart$' ./internal/watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestInternal5xxStormTriggersRestart(t *testing.T) {
	fc := newFakeConcertServer(t, "")
	clk := newFakeClock(time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC))
	var restarts atomic.Int32

	policyCfg := watchdog.DefaultPolicyConfig()
	policyCfg.ConsecutiveFailures = 2
	policyCfg.Max5xxRatio = 0.5
	policyCfg.MinSamplesFor5xxRatio = 10

	sup, err := watchdog.NewSupervisor(watchdog.SupervisorConfig{
		HealthURL:  fc.srv.URL + "/_room/healthz",
		ReadyURL:   fc.srv.URL + "/_room/readyz",
		MetricsURL: fc.srv.URL + "/_room/metrics",
		ClearURL:   fc.srv.URL + "/_room/queue/clear",
		Policy:     policyCfg,
		Now:        clk.Now,
		Sleep:      func(_ context.Context, d time.Duration) error { clk.Advance(d); return nil },
		RestartFunc: func(_ context.Context, _ int) error {
			restarts.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	// Baseline healthy observation (100 2xx, 0 5xx, 2 healthy upstreams).
	fc.setState(http.StatusOK, http.StatusOK, "ok", healthyMetricsText(100, 0, 0, 2, 0, 2))
	_, dec, _ := sup.Step(t.Context())
	if dec.Reason != watchdog.ReasonHealthy {
		t.Fatalf("baseline reason = %q, want healthy", dec.Reason)
	}

	// Storm probe 1: +2 2xx, +18 5xx => 90% 5xx with healthy upstreams and empty queue.
	clk.Advance(10 * time.Second)
	fc.setState(http.StatusOK, http.StatusOK, "ok", healthyMetricsText(102, 18, 0, 2, 0, 2))
	_, dec, _ = sup.Step(t.Context())
	if dec.Reason != watchdog.ReasonInternal5xxStorm || dec.Action != watchdog.ActionNone {
		t.Fatalf("storm probe 1 = (%q, %q), want (internal_5xx_storm, none)", dec.Reason, dec.Action)
	}

	// Storm probe 2: +2 2xx, +20 5xx => hits ConsecutiveFailures=2 -> ActionRestart.
	clk.Advance(10 * time.Second)
	fc.setState(http.StatusOK, http.StatusOK, "ok", healthyMetricsText(104, 38, 0, 2, 0, 2))
	_, dec, err = sup.Step(t.Context())
	if err != nil {
		t.Fatalf("storm probe 2 err: %v", err)
	}
	if dec.Reason != watchdog.ReasonInternal5xxStorm || dec.Action != watchdog.ActionRestart {
		t.Fatalf("storm probe 2 = (%q, %q), want (internal_5xx_storm, restart)", dec.Reason, dec.Action)
	}
	if restarts.Load() != 1 {
		t.Fatalf("restarts = %d, want 1", restarts.Load())
	}
}

// TestResourceCeilingViolationsTriggerEscalation proves that both RSS ceiling
// and open-FD ceiling violations escalate to ActionRestart even while
// /_room/healthz and upstream backends remain healthy.
//
// # Parameters
//
//   - t: Active test context (invoked by `go test ./internal/watchdog`).
//
// # Example
//
//	go test -v -run '^TestResourceCeilingViolationsTriggerEscalation$' ./internal/watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestResourceCeilingViolationsTriggerEscalation(t *testing.T) {
	cases := []struct {
		name       string
		maxRSS     uint64
		maxFDs     int
		proc       watchdog.ProcStats
		wantReason watchdog.FailureReason
	}{
		{
			name:       "RSS ceiling exceeded",
			maxRSS:     256 << 20,
			proc:       watchdog.ProcStats{PID: 555, RSSBytes: 300 << 20, HasRSS: true, OpenFDs: 20, HasOpenFDs: true},
			wantReason: watchdog.ReasonRSSExceeded,
		},
		{
			name:       "FD ceiling exceeded",
			maxFDs:     1000,
			proc:       watchdog.ProcStats{PID: 555, RSSBytes: 64 << 20, HasRSS: true, OpenFDs: 1500, HasOpenFDs: true},
			wantReason: watchdog.ReasonFDsExceeded,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := newFakeConcertServer(t, "")
			fc.setState(http.StatusOK, http.StatusOK, "ok", healthyMetricsText(100, 0, 0, 2, 0, 1))
			clk := newFakeClock(time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC))
			var restarts atomic.Int32

			policyCfg := watchdog.DefaultPolicyConfig()
			policyCfg.ConsecutiveFailures = 2
			policyCfg.MaxRSSBytes = tc.maxRSS
			policyCfg.MaxFDs = tc.maxFDs

			sup, err := watchdog.NewSupervisor(watchdog.SupervisorConfig{
				HealthURL:  fc.srv.URL + "/_room/healthz",
				ReadyURL:   fc.srv.URL + "/_room/readyz",
				MetricsURL: fc.srv.URL + "/_room/metrics",
				ClearURL:   fc.srv.URL + "/_room/queue/clear",
				PID:        tc.proc.PID,
				Policy:     policyCfg,
				Now:        clk.Now,
				Sleep:      func(_ context.Context, d time.Duration) error { clk.Advance(d); return nil },
				InspectProcess: func(pid int) (watchdog.ProcStats, error) {
					if pid != tc.proc.PID {
						t.Errorf("InspectProcess pid = %d, want %d", pid, tc.proc.PID)
					}
					return tc.proc, nil
				},
				RestartFunc: func(_ context.Context, pid int) error {
					if pid != tc.proc.PID {
						t.Errorf("RestartFunc pid = %d, want %d", pid, tc.proc.PID)
					}
					restarts.Add(1)
					return nil
				},
			})
			if err != nil {
				t.Fatalf("NewSupervisor: %v", err)
			}

			_, dec1, _ := sup.Step(t.Context())
			if dec1.Reason != tc.wantReason || dec1.Action != watchdog.ActionNone {
				t.Fatalf("step 1 = (%q, %q), want (%q, none)", dec1.Reason, dec1.Action, tc.wantReason)
			}
			clk.Advance(10 * time.Second)
			_, dec2, err := sup.Step(t.Context())
			if err != nil {
				t.Fatalf("step 2 error: %v", err)
			}
			if dec2.Reason != tc.wantReason || dec2.Action != watchdog.ActionRestart {
				t.Fatalf("step 2 = (%q, %q), want (%q, restart)", dec2.Reason, dec2.Action, tc.wantReason)
			}
			if restarts.Load() != 1 {
				t.Fatalf("restarts = %d, want 1", restarts.Load())
			}
		})
	}
}

// TestNormalBusyQueueNotFalsePositive ensures a healthy waiting room with
// visitors queued AND actively serving 2xx responses is never misclassified
// as wedged.
//
// # Parameters
//
//   - t: Active test context (invoked by `go test ./internal/watchdog`).
//
// # Example
//
//	go test -v -run '^TestNormalBusyQueueNotFalsePositive$' ./internal/watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestNormalBusyQueueNotFalsePositive(t *testing.T) {
	p, err := watchdog.NewPolicy(watchdog.DefaultPolicyConfig())
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	for i := range 6 {
		dec := p.Evaluate(watchdog.Observation{
			ObservedAt: now.Add(time.Duration(i) * 10 * time.Second),
			HealthzOK:  true,
			ReadyzOK:   true,
			MetricsOK:  true,
			Metrics: watchdog.MetricsSnapshot{
				RoomCap:                    20,
				HasRoomCap:                 true,
				RoomOccupancy:              20,
				QueueDepth:                 50,
				LiveQueueDepth:             50,
				UpstreamBackendsTotal:      2,
				HasUpstreamBackendsTotal:   true,
				UpstreamBackendsHealthy:    2,
				HasUpstreamBackendsHealthy: true,
				Upstream2xxTotal:           float64((i + 1) * 100),
			},
		})
		if dec.Action != watchdog.ActionNone || dec.Reason != watchdog.ReasonHealthy {
			t.Fatalf("probe %d = (%q, %q), want (none, healthy) for active queue", i, dec.Action, dec.Reason)
		}
	}
}

// TestCleanShutdownRealSubprocessNoGoroutineLeak proves that Supervisor.Run in
// real OS parent-process mode forwards SIGTERM cleanly on context.Cancel, joins
// all child waiter goroutines, and exits with zero goroutine leaks under -race.
//
// # Parameters
//
//   - t: Active test context (invoked by `go test -race ./internal/watchdog`).
//
// # Example
//
//	go test -race -v -run '^TestCleanShutdownRealSubprocessNoGoroutineLeak$' ./internal/watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestCleanShutdownRealSubprocessNoGoroutineLeak(t *testing.T) {
	t.Setenv("GO_WANT_WATCHDOG_HELPER", "1")
	fc := newFakeConcertServer(t, "")
	fc.setState(http.StatusOK, http.StatusOK, "ok", healthyMetricsText(100, 0, 0, 2, 0, 1))

	// Warm up runtime and capture baseline after httptest server is started.
	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()

	firstProbeDone := make(chan struct{})
	var probeOnce sync.Once

	sup, err := watchdog.NewSupervisor(watchdog.SupervisorConfig{
		HealthURL:    fc.srv.URL + "/_room/healthz",
		ReadyURL:     fc.srv.URL + "/_room/readyz",
		MetricsURL:   fc.srv.URL + "/_room/metrics",
		ClearURL:     fc.srv.URL + "/_room/queue/clear",
		Interval:     10 * time.Millisecond,
		Timeout:      2 * time.Second,
		DrainTimeout: 2 * time.Second,
		Policy:       watchdog.DefaultPolicyConfig(),
		ChildCommand: []string{os.Args[0], "-test.run=^TestHelperProcess$"},
		ProcessManager: watchdog.OSProcessManager{
			Stdout: io.Discard,
			Stderr: io.Discard,
		},
		OnDecision: func(_ watchdog.Observation, _ watchdog.Decision) {
			probeOnce.Do(func() { close(firstProbeDone) })
		},
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	runDone := make(chan error, 1)
	go func() {
		runDone <- sup.Run(ctx)
	}()

	// Wait deterministically for at least one probe cycle while child is alive.
	select {
	case <-firstProbeDone:
	case <-time.After(5 * time.Second):
		cancel()
		<-runDone
		t.Fatalf("timed out waiting for first probe cycle")
	}

	childPID := sup.CurrentPID()
	if childPID <= 0 {
		cancel()
		<-runDone
		t.Fatalf("expected positive supervised child PID, got %d", childPID)
	}

	// Cancel supervision context and wait for clean return.
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run() error = %v, want nil on clean cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Run() hung on context cancellation")
	}

	if got := sup.CurrentPID(); got != 0 {
		t.Errorf("CurrentPID() after shutdown = %d, want 0", got)
	}

	// Close idle keep-alive HTTP transport connections so net/http pool
	// goroutines exit cleanly before checking for leaks.
	fc.srv.CloseClientConnections()

	// Poll briefly (with context deadline, not sleep sync) for net/http
	// idle-conn teardown goroutines to settle back to baseline.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if runtime.NumGoroutine() <= baseGoroutines+2 {
			return
		}
		runtime.Gosched()
	}
	after := runtime.NumGoroutine()
	if after > baseGoroutines+2 {
		t.Fatalf("possible goroutine leak: before=%d after=%d", baseGoroutines, after)
	}
}

// TestUnexpectedChildCrashLoopTripsCircuitBreaker proves that repeated
// unexpected child exits in parent-process mode respect exponential backoff
// and trip the restart-loop circuit breaker instead of fork-bombing.
//
// # Parameters
//
//   - t: Active test context (invoked by `go test -race ./internal/watchdog`).
//
// # Example
//
//	go test -race -v -run '^TestUnexpectedChildCrashLoopTripsCircuitBreaker$' ./internal/watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestUnexpectedChildCrashLoopTripsCircuitBreaker(t *testing.T) {
	fc := newFakeConcertServer(t, "")
	fc.setState(http.StatusOK, http.StatusOK, "ok", healthyMetricsText(100, 0, 0, 2, 0, 1))
	clk := newFakeClock(time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC))
	pm := newFakeProcessManager(false, false, false, false)

	policyCfg := watchdog.DefaultPolicyConfig()
	policyCfg.MaxRestartsPerWindow = 2
	policyCfg.RestartWindow = 10 * time.Minute
	policyCfg.InitialBackoff = time.Second
	policyCfg.MaxBackoff = 4 * time.Second

	circuitOpen := make(chan struct{})
	var openOnce sync.Once
	var backoffsMu sync.Mutex
	var backoffs []time.Duration

	sup, err := watchdog.NewSupervisor(watchdog.SupervisorConfig{
		HealthURL:      fc.srv.URL + "/_room/healthz",
		ReadyURL:       fc.srv.URL + "/_room/readyz",
		MetricsURL:     fc.srv.URL + "/_room/metrics",
		ClearURL:       fc.srv.URL + "/_room/queue/clear",
		Interval:       time.Hour, // isolate crash handling from timer probes
		Timeout:        2 * time.Second,
		DrainTimeout:   time.Second,
		Policy:         policyCfg,
		ChildCommand:   []string{"fake-concert"},
		ProcessManager: pm,
		Now:            clk.Now,
		Sleep: func(_ context.Context, d time.Duration) error {
			backoffsMu.Lock()
			backoffs = append(backoffs, d)
			backoffsMu.Unlock()
			clk.Advance(d)
			return nil
		},
		OnDecision: func(_ watchdog.Observation, dec watchdog.Decision) {
			if dec.CircuitOpen {
				openOnce.Do(func() { close(circuitOpen) })
			}
		},
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- sup.Run(ctx) }()

	// Crash each spawned child until circuit breaker opens (initial + 2 respawns = 3 crashes).
	for i := range 3 {
		select {
		case p := <-pm.startedCh:
			clk.Advance(time.Second)
			p.finish(fmt.Errorf("exit status %d", i+1))
		case <-time.After(5 * time.Second):
			cancel()
			<-runDone
			t.Fatalf("timed out waiting for child spawn %d", i)
		}
	}

	select {
	case <-circuitOpen:
	case <-time.After(5 * time.Second):
		cancel()
		<-runDone
		t.Fatalf("timed out waiting for crash-loop circuit breaker")
	}

	cancel()
	if err := <-runDone; err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if got := pm.count(); got != 3 {
		t.Fatalf("spawn count = %d, want 3 (1 initial + 2 respawns before circuit breaker)", got)
	}
	backoffsMu.Lock()
	gotBackoffs := append([]time.Duration(nil), backoffs...)
	backoffsMu.Unlock()
	wantBackoffs := []time.Duration{time.Second, 2 * time.Second}
	if len(gotBackoffs) != len(wantBackoffs) || gotBackoffs[0] != wantBackoffs[0] || gotBackoffs[1] != wantBackoffs[1] {
		t.Fatalf("crash backoffs = %v, want %v", gotBackoffs, wantBackoffs)
	}
}

// TestHelperProcess is invoked as a real child subprocess by
// TestCleanShutdownRealSubprocessNoGoroutineLeak; it exits cleanly on SIGTERM.
// When run directly by `go test`, it returns immediately.
//
// # Parameters
//
//   - t: Active test context.
//
// # Example
//
//	os.Args[0] -test.run=^TestHelperProcess$ (with GO_WANT_WATCHDOG_HELPER=1)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_WATCHDOG_HELPER") != "1" {
		return
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, os.Interrupt)
	<-sigCh
	os.Exit(0)
}

// ExampleParsePrometheusMetrics demonstrates parsing Concert's Prometheus text
// exposition format using the standard-library parser.
//
// # Parameters
//
// None (executed by `go test ./internal/watchdog`).
//
// # Example
//
//	go test -v -run '^ExampleParsePrometheusMetrics$' ./internal/watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func ExampleParsePrometheusMetrics() {
	body := "concert_upstream_backends_healthy 2\nconcert_room_live_queue_depth 5\n"
	snap, err := watchdog.ParsePrometheusMetrics(strings.NewReader(body))
	if err != nil {
		panic(err)
	}
	fmt.Printf("healthy=%d live_queue=%g\n", snap.UpstreamBackendsHealthy, snap.LiveQueueDepth)
	// Output:
	// healthy=2 live_queue=5
}

// ExampleNewPolicy demonstrates that an origin outage (upstream_healthy == 0)
// produces ActionAlertOnly rather than restarting Concert.
//
// # Parameters
//
// None (executed by `go test ./internal/watchdog`).
//
// # Example
//
//	go test -v -run '^ExampleNewPolicy$' ./internal/watchdog
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func ExampleNewPolicy() {
	p, err := watchdog.NewPolicy(watchdog.DefaultPolicyConfig())
	if err != nil {
		panic(err)
	}
	dec := p.Evaluate(watchdog.Observation{
		ObservedAt: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC),
		HealthzOK:  true,
		ReadyzOK:   false,
		ReadyzBody: "upstream unhealthy",
		MetricsOK:  true,
		Metrics: watchdog.MetricsSnapshot{
			UpstreamBackendsTotal:      2,
			HasUpstreamBackendsTotal:   true,
			UpstreamBackendsHealthy:    0,
			HasUpstreamBackendsHealthy: true,
		},
	})
	fmt.Printf("action=%s reason=%s\n", dec.Action, dec.Reason)
	// Output:
	// action=alert_only reason=origin_down
}
