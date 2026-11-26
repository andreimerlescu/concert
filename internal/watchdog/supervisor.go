package watchdog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/andreimerlescu/concert/internal/opt"
)

const (
	// MaxProbeBodyBytes bounds /_room/healthz and /_room/readyz responses.
	MaxProbeBodyBytes = 16 << 10
	// MaxClearBodyBytes bounds POST /_room/queue/clear responses.
	MaxClearBodyBytes = 64 << 10
	// MaxWebhookBodyBytes bounds alert webhook responses.
	MaxWebhookBodyBytes = 16 << 10
	// maxPIDFileBytes bounds PID file reads in external-probe mode.
	maxPIDFileBytes = 64
	// defaultPollStep is the poll interval used when checking whether an
	// external PID has exited after SIGTERM.
	defaultPollStep = 50 * time.Millisecond
)

// ManagedProcess represents a running child process supervised in
// parent-process mode. Implementations must be safe to call Signal and Kill
// concurrently with a single Wait goroutine.
type ManagedProcess interface {
	// PID returns the OS process identifier of the running child, or 0 if unavailable.
	PID() int
	// Signal delivers sig (such as syscall.SIGTERM) to the child process.
	Signal(sig os.Signal) error
	// Kill forcefully terminates the child process (SIGKILL).
	Kill() error
	// Wait blocks until the child process exits and returns its exit error.
	Wait() error
}

// ProcessManager starts supervised child processes in parent-process mode.
type ProcessManager interface {
	// Start launches name with args without waiting for it to exit.
	Start(name string, args []string) (ManagedProcess, error)
}

// OSProcessManager launches real OS child processes using os/exec.
type OSProcessManager struct {
	// Stdout receives child stdout; defaults to os.Stdout when nil.
	Stdout io.Writer
	// Stderr receives child stderr; defaults to os.Stderr when nil.
	Stderr io.Writer
}

// Start launches name with args directly via os/exec without invoking a shell.
//
// # Parameters
//
//   - name: Executable path or binary name to start.
//   - args: Argument slice passed directly to the process (never shell-expanded).
//
// # Returns
//
// A ManagedProcess handle to the started child, or an error if spawning fails.
//
// # Example
//
//	pm := watchdog.OSProcessManager{}
//	proc, err := pm.Start("/usr/local/bin/concert", nil)
//	if err != nil {
//		return err
//	}
//	_ = proc.PID()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope
// (may be satisfied via interface dispatch or external callers).
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (m OSProcessManager) Start(name string, args []string) (ManagedProcess, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("child binary path is empty")
	}
	// Use exec.Command rather than exec.CommandContext because Supervisor
	// manages graceful SIGTERM -> DrainTimeout -> SIGKILL shutdown itself.
	cmd := exec.Command(name, args...)
	if m.Stdout != nil {
		cmd.Stdout = m.Stdout
	} else {
		cmd.Stdout = os.Stdout
	}
	if m.Stderr != nil {
		cmd.Stderr = m.Stderr
	} else {
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start child %q: %w", name, err)
	}
	return &osManagedProcess{cmd: cmd}, nil
}

type osManagedProcess struct {
	cmd *exec.Cmd
}

// PID returns the OS process ID of the started command.
//
// # Parameters
//
// None.
//
// # Returns
//
// The child PID, or 0 if cmd.Process is nil.
//
// # Example
//
//	pid := proc.PID()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope
// (may be satisfied via interface dispatch or external callers).
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *osManagedProcess) PID() int {
	if p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// Signal delivers sig to the started OS process.
//
// # Parameters
//
//   - sig: OS signal to send (for example syscall.SIGTERM).
//
// # Returns
//
// Any error returned by os.Process.Signal.
//
// # Example
//
//	err := proc.Signal(syscall.SIGTERM)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope
// (may be satisfied via interface dispatch or external callers).
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *osManagedProcess) Signal(sig os.Signal) error {
	if p.cmd == nil || p.cmd.Process == nil {
		return errors.New("process not started")
	}
	return p.cmd.Process.Signal(sig)
}

// Kill forcefully terminates the started OS process with SIGKILL.
//
// # Parameters
//
// None.
//
// # Returns
//
// Any error returned by os.Process.Kill.
//
// # Example
//
//	err := proc.Kill()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope
// (may be satisfied via interface dispatch or external callers).
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *osManagedProcess) Kill() error {
	if p.cmd == nil || p.cmd.Process == nil {
		return errors.New("process not started")
	}
	return p.cmd.Process.Kill()
}

// Wait blocks until the started OS process exits and releases OS resources.
//
// # Parameters
//
// None.
//
// # Returns
//
// The exit error returned by exec.Cmd.Wait, or nil on exit code 0.
//
// # Example
//
//	err := proc.Wait()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope
// (may be satisfied via interface dispatch or external callers).
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (p *osManagedProcess) Wait() error {
	if p.cmd == nil {
		return nil
	}
	return p.cmd.Wait()
}

// AlertEvent is the structured JSON payload sent to the optional alert webhook
// and emitted to structured logs. It never includes tokens or raw credentials.
// UpstreamHealthy uses opt.Option[int] with json omitzero so an unobserved
// backend count is omitted while an observed zero healthy backends marshals as
// `"upstream_healthy":0`.
type AlertEvent struct {
	Timestamp           time.Time       `json:"timestamp"`
	Severity            string          `json:"severity"`
	Action              ActionKind      `json:"action"`
	Reason              FailureReason   `json:"reason"`
	Message             string          `json:"message"`
	ConsecutiveFailures int             `json:"consecutive_failures"`
	RestartsInWindow    int             `json:"restarts_in_window"`
	CircuitOpen         bool            `json:"circuit_open"`
	PID                 int             `json:"pid,omitempty"`
	RSSBytes            uint64          `json:"rss_bytes,omitempty"`
	OpenFDs             int             `json:"open_fds,omitempty"`
	QueueDepth          float64         `json:"queue_depth,omitempty"`
	LiveQueueDepth      float64         `json:"live_queue_depth,omitempty"`
	UpstreamHealthy     opt.Option[int] `json:"upstream_healthy,omitzero"`
}

// SupervisorConfig configures Supervisor for either parent-process supervision
// (when ChildCommand is non-empty) or external-probe/PID monitoring.
type SupervisorConfig struct {
	// Concert probe and recovery endpoint URLs.
	HealthURL  string
	ReadyURL   string
	MetricsURL string
	ClearURL   string

	// Optional HTTPS (or localhost HTTP) alert webhook destination.
	AlertWebhookURL string

	// Credentials held in redacting Secret wrappers (never logged or serialized).
	OperatorToken Secret
	WebhookToken  Secret

	// Loop and I/O timing.
	Interval     time.Duration
	Timeout      time.Duration
	DrainTimeout time.Duration

	// Policy controls the recovery escalation state machine.
	Policy PolicyConfig

	// Parent-process mode: when non-empty, ChildCommand[0] is spawned with
	// ChildCommand[1:] and supervised directly.
	ChildCommand []string

	// External-probe/PID mode: target PID or PIDFile when ChildCommand is empty.
	PID     int
	PIDFile string

	// RestartFunc optionally overrides external-mode process restart (for example
	// invoking a supervisor hook or deterministic test recorder). Ignored in
	// parent-process mode.
	RestartFunc func(ctx context.Context, pid int) error

	// Optional dependencies for observability and deterministic testing.
	Logger         *slog.Logger
	HTTPClient     *http.Client
	ProcessManager ProcessManager
	InspectProcess func(pid int) (ProcStats, error)
	Now            func() time.Time
	Sleep          func(ctx context.Context, d time.Duration) error
	OnDecision     func(obs Observation, dec Decision)
}

// activeChild bundles a started child process with its single joined waiter.
// Ownership: created and stopped exclusively by Supervisor.Run / Supervisor.Step
// under a single control loop.
type activeChild struct {
	proc ManagedProcess
	done chan error // closed after sending the single Wait() result
}

// Supervisor probes Concert, evaluates recovery Policy decisions, executes
// stale-queue flushes and bounded restarts, and optionally supervises a child
// Concert process.
//
// Concurrency: Supervisor.Run must be called at most once at a time. Exported
// read-only getters (CurrentPID) are safe for concurrent calls via mu.
type Supervisor struct {
	cfg    SupervisorConfig
	policy *Policy
	client *http.Client
	logger *slog.Logger
	pm     ProcessManager

	mu    sync.Mutex
	child *activeChild // guarded by mu; mutated only by startChild/stopChild
}

// NewSupervisor validates cfg, constructs a bounded HTTP client and Policy,
// and returns a Supervisor ready for Step or Run.
//
// # Parameters
//
//   - cfg: Supervisor configuration including URLs, timeouts, policy limits,
//     optional secrets, and optional child command or PID settings.
//
// # Returns
//
// A configured *Supervisor, or nil and a descriptive secret-free error if any
// URL, timeout, or policy setting is invalid.
//
// # Example
//
//	sup, err := watchdog.NewSupervisor(watchdog.SupervisorConfig{
//		HealthURL:  "http://127.0.0.1:8080/_room/healthz",
//		ReadyURL:   "http://127.0.0.1:8080/_room/readyz",
//		MetricsURL: "http://127.0.0.1:8080/_room/metrics",
//		ClearURL:   "http://127.0.0.1:8080/_room/queue/clear",
//		Interval:   10 * time.Second,
//		Timeout:    3 * time.Second,
//		Policy:     watchdog.DefaultPolicyConfig(),
//	})
//	if err != nil {
//		return err
//	}
//	_ = sup
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-watchdog/main.go:165 (direct call)
//   - internal/watchdog/watchdog_test.go:1062 (direct call)
//   - internal/watchdog/watchdog_test.go:1250 (direct call)
//   - internal/watchdog/watchdog_test.go:1325 (direct call)
//   - internal/watchdog/watchdog_test.go:1421 (direct call)
//   - internal/watchdog/watchdog_test.go:1551 (direct call)
//   - internal/watchdog/watchdog_test.go:1651 (direct call)
//   - internal/watchdog/watchdog_test.go:1778 (direct call)
//   - internal/watchdog/watchdog_test.go:1893 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func NewSupervisor(cfg SupervisorConfig) (*Supervisor, error) {
	if _, err := ValidateProbeURL(cfg.HealthURL); err != nil {
		return nil, fmt.Errorf("health-url: %w", err)
	}
	if cfg.ReadyURL != "" {
		if _, err := ValidateProbeURL(cfg.ReadyURL); err != nil {
			return nil, fmt.Errorf("ready-url: %w", err)
		}
	}
	if _, err := ValidateProbeURL(cfg.MetricsURL); err != nil {
		return nil, fmt.Errorf("metrics-url: %w", err)
	}
	if cfg.ClearURL != "" {
		if _, err := ValidateProbeURL(cfg.ClearURL); err != nil {
			return nil, fmt.Errorf("clear-url: %w", err)
		}
	}
	if cfg.AlertWebhookURL != "" {
		if _, err := ValidateWebhookURL(cfg.AlertWebhookURL); err != nil {
			return nil, fmt.Errorf("alert-webhook: %w", err)
		}
	}
	if cfg.Interval < 0 {
		return nil, fmt.Errorf("interval must be non-negative, got %v", cfg.Interval)
	}
	if cfg.Interval == 0 {
		cfg.Interval = 10 * time.Second
	}
	if cfg.Timeout < 0 {
		return nil, fmt.Errorf("timeout must be non-negative, got %v", cfg.Timeout)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.DrainTimeout < 0 {
		return nil, fmt.Errorf("drain-timeout must be non-negative, got %v", cfg.DrainTimeout)
	}
	if cfg.DrainTimeout == 0 {
		cfg.DrainTimeout = 30 * time.Second
	}
	if cfg.PID < 0 {
		return nil, fmt.Errorf("pid must be non-negative, got %d", cfg.PID)
	}

	policy, err := NewPolicy(cfg.Policy)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}

	client := cfg.HTTPClient
	if client == nil {
		client = newBoundedHTTPClient(cfg.Timeout)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	pm := cfg.ProcessManager
	if pm == nil {
		pm = OSProcessManager{}
	}

	if cfg.InspectProcess == nil {
		cfg.InspectProcess = InspectProcess
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleepWithContext
	}
	// Clone ChildCommand so later caller mutations cannot race with Run.
	if len(cfg.ChildCommand) > 0 {
		cfg.ChildCommand = append([]string(nil), cfg.ChildCommand...)
	}

	return &Supervisor{
		cfg:    cfg,
		policy: policy,
		client: client,
		logger: logger,
		pm:     pm,
	}, nil
}

// newBoundedHTTPClient creates a reusable HTTP client with strict connect, TLS,
// response-header, and overall timeouts, and refuses automatic redirects so
// bearer credentials can never be forwarded to a redirect target.
//
// # Parameters
//
//   - timeout: Per-request deadline covering dial, headers, and body read.
//
// # Returns
//
// A configured *http.Client safe for concurrent reuse.
//
// # Example
//
//	cli := newBoundedHTTPClient(3 * time.Second)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:427 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func newBoundedHTTPClient(timeout time.Duration) *http.Client {
	dialTimeout := min(timeout, 5*time.Second)
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}
	tr := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   dialTimeout,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   4,
		ForceAttemptHTTP2:     false,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// CurrentPID returns the PID of the active supervised child process (in
// parent-process mode), or the currently resolved external PID.
//
// # Parameters
//
// None.
//
// # Returns
//
// Positive target PID, or 0 when no child is running and no external PID is set.
//
// # Concurrency
//
// Safe for concurrent calls; reads s.child under s.mu.
//
// # Example
//
//	pid := sup.CurrentPID()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:784 (direct call)
//   - internal/watchdog/supervisor.go:941 (direct call)
//   - internal/watchdog/watchdog_test.go:1815 (direct call)
//   - internal/watchdog/watchdog_test.go:1833 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) CurrentPID() int {
	s.mu.Lock()
	c := s.child
	s.mu.Unlock()
	if c != nil {
		return c.proc.PID()
	}
	return s.resolveExternalPID()
}

// Run executes the watchdog supervision loop until ctx is cancelled.
//
// In parent-process mode (ChildCommand non-empty), Run starts the target binary
// immediately, monitors unexpected exits with exponential backoff and the
// restart-loop circuit breaker, probes on each Interval tick, and on ctx
// cancellation forwards SIGTERM to the child, waits up to DrainTimeout, falls
// back to SIGKILL, and joins the child waiter goroutine before returning.
//
// In external-probe/PID mode, Run probes on each Interval tick and executes
// configured recovery actions until ctx is cancelled.
//
// # Parameters
//
//   - ctx: Controls lifetime of the supervision loop. Must be non-nil.
//
// # Returns
//
// nil on clean cancellation via ctx, or an error if the initial child process
// fails to start.
//
// # Example
//
//	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
//	defer cancel()
//	if err := sup.Run(ctx); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-watchdog/main.go:209 (direct call)
//   - internal/watchdog/watchdog_test.go:1455 (direct call)
//   - internal/watchdog/watchdog_test.go:1803 (direct call)
//   - internal/watchdog/watchdog_test.go:1925 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil context")
	}

	parentMode := len(s.cfg.ChildCommand) > 0
	if parentMode {
		if err := s.startChild(); err != nil {
			return err
		}
		// Always gracefully stop and join the active child before Run returns.
		defer s.stopActiveChild()
	}

	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()

	for {
		var childDone <-chan error
		if parentMode {
			childDone = s.currentChildDone()
		}

		select {
		case <-ctx.Done():
			return nil

		case exitErr, ok := <-childDone:
			if !ok {
				// Defensive: clear reference if channel closed without value.
				s.clearChildIfDone(childDone)
				continue
			}
			s.clearChildIfDone(childDone)
			if ctx.Err() != nil {
				return nil
			}
			s.handleUnexpectedChildExit(ctx, exitErr)

		case <-ticker.C:
			if ctx.Err() != nil {
				return nil
			}
			// If parent-mode child died while circuit breaker was open, check
			// whether the restart window has rolled over so we can respawn.
			if parentMode && s.currentChildDone() == nil {
				s.maybeRespawnAfterCircuitBreaker(ctx)
				continue
			}
			_, _, _ = s.Step(ctx)
		}
	}
}

// Step performs one complete probe, policy evaluation, alert emission, and
// recovery action cycle.
//
// # Parameters
//
//   - ctx: Context controlling probe and recovery HTTP/process I/O.
//
// # Returns
//
// The Observation gathered, the Decision made by Policy.Evaluate, and any
// action execution error (probe failures are recorded inside Observation rather
// than returned as errors).
//
// # Example
//
//	obs, dec, err := sup.Step(ctx)
//	if err != nil {
//		log.Printf("recovery action error: %v", err)
//	}
//	_, _ = obs, dec
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:636 (direct call)
//   - internal/watchdog/watchdog_test.go:1090 (direct call)
//   - internal/watchdog/watchdog_test.go:1274 (direct call)
//   - internal/watchdog/watchdog_test.go:1285 (direct call)
//   - internal/watchdog/watchdog_test.go:1301 (direct call)
//   - internal/watchdog/watchdog_test.go:1346 (direct call)
//   - internal/watchdog/watchdog_test.go:1348 (direct call)
//   - internal/watchdog/watchdog_test.go:1355 (direct call)
//   - internal/watchdog/watchdog_test.go:1365 (direct call)
//   - internal/watchdog/watchdog_test.go:1570 (direct call)
//   - internal/watchdog/watchdog_test.go:1578 (direct call)
//   - internal/watchdog/watchdog_test.go:1586 (direct call)
//   - internal/watchdog/watchdog_test.go:1678 (direct call)
//   - internal/watchdog/watchdog_test.go:1683 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) Step(ctx context.Context) (Observation, Decision, error) {
	obs := s.Probe(ctx)
	dec := s.policy.Evaluate(obs)

	if dec.EmitAlert {
		s.emitAlert(ctx, obs, dec)
	}

	var actionErr error
	switch dec.Action {
	case ActionFlushStale:
		actionErr = s.FlushStaleQueue(ctx)
		if actionErr != nil {
			s.logger.Warn("stale queue flush failed", "error", actionErr)
		} else {
			s.logger.Info("stale queue flush succeeded", "reason", dec.Reason)
		}
	case ActionRestart:
		actionErr = s.executeRestart(ctx, dec)
		if actionErr != nil {
			s.logger.Error("concert restart failed", "reason", dec.Reason, "error", actionErr)
		}
	case ActionAlertOnly:
		s.logger.Warn("watchdog alert only (no restart)",
			"reason", dec.Reason,
			"circuit_open", dec.CircuitOpen,
			"message", dec.Message,
		)
	}

	if s.cfg.OnDecision != nil {
		s.cfg.OnDecision(obs, dec)
	}
	return obs, dec, actionErr
}

// Probe queries Concert's healthz, readyz, and metrics endpoints plus optional
// Linux procfs stats for the supervised PID.
//
// # Parameters
//
//   - ctx: Context bounding probe HTTP calls.
//
// # Returns
//
// An Observation value containing all probe outcomes and parsed metrics.
//
// # Example
//
//	obs := sup.Probe(ctx)
//	fmt.Println(obs.HealthzOK, obs.Metrics.LiveQueueDepth)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:683 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) Probe(ctx context.Context) Observation {
	obs := Observation{
		ObservedAt: s.cfg.Now(),
	}

	// 1. /_room/healthz (unauthenticated liveness)
	status, _, err := s.doBoundedGET(ctx, s.cfg.HealthURL, MaxProbeBodyBytes, false)
	if err != nil {
		obs.HealthzErr = err.Error()
	} else {
		obs.HealthzStatus = status
		obs.HealthzOK = status == http.StatusOK
	}

	// 2. /_room/readyz (optional unauthenticated readiness)
	if s.cfg.ReadyURL != "" {
		rStatus, rBody, rErr := s.doBoundedGET(ctx, s.cfg.ReadyURL, MaxProbeBodyBytes, false)
		if rErr == nil {
			obs.ReadyzStatus = rStatus
			obs.ReadyzOK = rStatus == http.StatusOK
			obs.ReadyzBody = strings.TrimSpace(string(rBody))
		}
	} else {
		obs.ReadyzOK = obs.HealthzOK
	}

	// 3. /_room/metrics (optionally authenticated via OperatorToken)
	mStatus, mBody, mErr := s.doBoundedGET(ctx, s.cfg.MetricsURL, MaxMetricsBodyBytes, true)
	if mErr != nil {
		obs.MetricsErr = mErr.Error()
	} else if mStatus != http.StatusOK {
		obs.MetricsErr = fmt.Sprintf("HTTP %d", mStatus)
	} else {
		snap, parseErr := ParsePrometheusMetrics(bytes.NewReader(mBody))
		if parseErr != nil {
			obs.MetricsErr = parseErr.Error()
		} else {
			obs.MetricsOK = true
			obs.Metrics = snap
		}
	}

	// 4. Optional Linux /proc/<pid>/statm and /proc/<pid>/fd inspection
	if pid := s.CurrentPID(); pid > 0 {
		if ps, pErr := s.cfg.InspectProcess(pid); pErr == nil {
			obs.Proc = ps
		} else {
			obs.Proc = ProcStats{PID: pid}
		}
	}

	return obs
}

// FlushStaleQueue issues `POST /_room/queue/clear` with JSON body
// `{"mode":"stale"}` using the configured operator bearer token.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadline for the HTTP request.
//
// # Returns
//
// nil on a 2xx response, or a secret-free error describing the failure.
//
// # Example
//
//	if err := sup.FlushStaleQueue(ctx); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:693 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) FlushStaleQueue(ctx context.Context) error {
	if s.cfg.ClearURL == "" {
		return errors.New("clear URL is not configured")
	}
	payload := []byte(`{"mode":"stale"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.ClearURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build queue clear request for %s: %w", RedactURL(s.cfg.ClearURL), err)
	}
	req.Header.Set("Content-Type", "application/json")
	if !s.cfg.OperatorToken.IsZero() {
		req.Header.Set("Authorization", "Bearer "+s.cfg.OperatorToken.Reveal())
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", RedactURL(s.cfg.ClearURL), sanitizeNetError(err))
	}
	defer resp.Body.Close() // read side; close error not material

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxClearBodyBytes+1))
	if readErr != nil {
		return fmt.Errorf("read queue clear response from %s: %w", RedactURL(s.cfg.ClearURL), readErr)
	}
	if len(body) > MaxClearBodyBytes {
		return fmt.Errorf("queue clear response from %s exceeded %d bytes", RedactURL(s.cfg.ClearURL), MaxClearBodyBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s returned HTTP %d", RedactURL(s.cfg.ClearURL), resp.StatusCode)
	}
	return nil
}

// doBoundedGET executes an HTTP GET to rawURL, optionally attaching the
// operator bearer token, and reads at most maxBytes of response body.
//
// # Parameters
//
//   - ctx: Context controlling request cancellation.
//   - rawURL: Validated target URL.
//   - maxBytes: Maximum response body bytes to read.
//   - withOperatorAuth: When true and OperatorToken is non-zero, attaches
//     `Authorization: Bearer <token>`.
//
// # Returns
//
// HTTP status code, bounded body slice, and any transport/size error.
//
// # Example
//
//	status, body, err := sup.doBoundedGET(ctx, sup.cfg.HealthURL, MaxProbeBodyBytes, false)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:747 (direct call)
//   - internal/watchdog/supervisor.go:757 (direct call)
//   - internal/watchdog/supervisor.go:768 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) doBoundedGET(ctx context.Context, rawURL string, maxBytes int64, withOperatorAuth bool) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("build GET %s: %w", RedactURL(rawURL), err)
	}
	if withOperatorAuth && !s.cfg.OperatorToken.IsZero() {
		req.Header.Set("Authorization", "Bearer "+s.cfg.OperatorToken.Reveal())
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("GET %s: %w", RedactURL(rawURL), sanitizeNetError(err))
	}
	defer resp.Body.Close() // read side; close error not material

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read GET %s body: %w", RedactURL(rawURL), err)
	}
	if int64(len(body)) > maxBytes {
		return resp.StatusCode, nil, fmt.Errorf("GET %s response exceeded %d bytes", RedactURL(rawURL), maxBytes)
	}
	return resp.StatusCode, body, nil
}

// emitAlert logs a structured alert event and, if AlertWebhookURL is set,
// delivers the JSON AlertEvent over HTTP/HTTPS with optional WebhookToken auth.
//
// # Parameters
//
//   - ctx: Context bounding webhook delivery.
//   - obs: Probe observation that triggered the alert.
//   - dec: Policy decision specifying action, reason, severity, and message.
//
// # Example
//
//	sup.emitAlert(ctx, obs, dec)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:687 (direct call)
//   - internal/watchdog/supervisor.go:1234 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) emitAlert(ctx context.Context, obs Observation, dec Decision) {
	rssBytes, _ := effectiveRSS(obs)
	openFDs, _ := effectiveOpenFDs(obs)
	var upHealthy opt.Option[int]
	if obs.MetricsOK && obs.Metrics.HasUpstreamBackendsHealthy {
		upHealthy = opt.Some(obs.Metrics.UpstreamBackendsHealthy)
	}
	ev := AlertEvent{
		Timestamp:           obs.ObservedAt.UTC(),
		Severity:            dec.AlertSeverity,
		Action:              dec.Action,
		Reason:              dec.Reason,
		Message:             dec.Message,
		ConsecutiveFailures: dec.ConsecutiveFailures,
		RestartsInWindow:    dec.RestartsInWindow,
		CircuitOpen:         dec.CircuitOpen,
		PID:                 s.CurrentPID(),
		RSSBytes:            rssBytes,
		OpenFDs:             openFDs,
		QueueDepth:          obs.Metrics.QueueDepth,
		LiveQueueDepth:      obs.Metrics.LiveQueueDepth,
		UpstreamHealthy:     upHealthy,
	}

	s.logger.Warn("watchdog alert",
		"severity", ev.Severity,
		"action", ev.Action,
		"reason", ev.Reason,
		"message", ev.Message,
		"consecutive_failures", ev.ConsecutiveFailures,
		"restarts_in_window", ev.RestartsInWindow,
		"circuit_open", ev.CircuitOpen,
		"pid", ev.PID,
	)

	if s.cfg.AlertWebhookURL == "" {
		return
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		s.logger.Error("marshal alert webhook payload failed", "error", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.AlertWebhookURL, bytes.NewReader(payload))
	if err != nil {
		s.logger.Error("build alert webhook request failed", "url", RedactURL(s.cfg.AlertWebhookURL), "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if !s.cfg.WebhookToken.IsZero() {
		req.Header.Set("Authorization", "Bearer "+s.cfg.WebhookToken.Reveal())
	}
	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Warn("deliver alert webhook failed", "url", RedactURL(s.cfg.AlertWebhookURL), "error", sanitizeNetError(err))
		return
	}
	defer resp.Body.Close() // read side; close error not material
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxWebhookBodyBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.logger.Warn("alert webhook returned non-2xx status", "url", RedactURL(s.cfg.AlertWebhookURL), "status", resp.StatusCode)
	}
}

// executeRestart carries out ActionRestart in either parent-process mode or
// external-probe/PID mode, honoring DrainTimeout and dec.Backoff.
//
// # Parameters
//
//   - ctx: Context controlling cancellation during drain and backoff waits.
//   - dec: Policy decision containing the computed Backoff duration.
//
// # Returns
//
// nil on success (or ctx cancellation), or an error if restarting failed.
//
// # Example
//
//	if err := sup.executeRestart(ctx, dec); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:700 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) executeRestart(ctx context.Context, dec Decision) error {
	if len(s.cfg.ChildCommand) > 0 {
		s.stopActiveChild()
		if dec.Backoff > 0 {
			if err := s.cfg.Sleep(ctx, dec.Backoff); err != nil {
				return nil
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		return s.startChild()
	}

	pid := s.resolveExternalPID()
	var restartErr error
	if s.cfg.RestartFunc != nil {
		restartErr = s.cfg.RestartFunc(ctx, pid)
	} else if pid > 0 {
		restartErr = s.signalExternalPID(ctx, pid)
	} else {
		restartErr = errors.New("restart requested in external mode without PID, PIDFile, or RestartFunc")
	}

	if dec.Backoff > 0 && ctx.Err() == nil {
		_ = s.cfg.Sleep(ctx, dec.Backoff)
	}
	return restartErr
}

// startChild spawns ChildCommand via s.pm and starts a single joined waiter
// goroutine for it. Caller must ensure no previous child is active.
//
// # Parameters
//
// None.
//
// # Returns
//
// nil when the child process started, or an error if spawning failed.
//
// # Example
//
//	if err := sup.startChild(); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:594 (direct call)
//   - internal/watchdog/supervisor.go:1025 (direct call)
//   - internal/watchdog/supervisor.go:1250 (direct call)
//   - internal/watchdog/supervisor.go:1286 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) startChild() error {
	proc, err := s.pm.Start(s.cfg.ChildCommand[0], s.cfg.ChildCommand[1:])
	if err != nil {
		return err
	}
	c := &activeChild{
		proc: proc,
		done: make(chan error, 1),
	}
	// Single waiter goroutine owned by Supervisor; always joined by stopActiveChild
	// or received in Run before any replacement child is started.
	go func() {
		defer close(c.done)
		c.done <- proc.Wait()
	}()
	s.mu.Lock()
	s.child = c
	s.mu.Unlock()
	s.logger.Info("started supervised child", "binary", s.cfg.ChildCommand[0], "pid", proc.PID())
	return nil
}

// stopActiveChild gracefully stops the current supervised child by sending
// SIGTERM, waiting up to DrainTimeout, falling back to SIGKILL if it has not
// exited, and joining the child's waiter goroutine.
//
// # Parameters
//
// None.
//
// # Example
//
//	defer sup.stopActiveChild()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:598 (direct call)
//   - internal/watchdog/supervisor.go:1016 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) stopActiveChild() {
	s.mu.Lock()
	c := s.child
	s.child = nil
	s.mu.Unlock()
	if c == nil {
		return
	}

	// Check if already exited before signaling.
	select {
	case <-c.done:
		return
	default:
	}

	pid := c.proc.PID()
	if err := c.proc.Signal(syscall.SIGTERM); err != nil {
		s.logger.Warn("send SIGTERM to child failed", "pid", pid, "error", err)
	}

	timer := time.NewTimer(s.cfg.DrainTimeout)
	defer timer.Stop()
	select {
	case <-c.done:
		s.logger.Info("child exited cleanly after SIGTERM", "pid", pid)
		return
	case <-timer.C:
		s.logger.Warn("child exceeded drain timeout; sending SIGKILL", "pid", pid, "drain_timeout", s.cfg.DrainTimeout)
		if err := c.proc.Kill(); err != nil {
			s.logger.Warn("send SIGKILL to child failed", "pid", pid, "error", err)
		}
		<-c.done
	}
}

// currentChildDone returns the completion channel of the active child, or nil
// when no child is currently running.
//
// # Parameters
//
// None.
//
// # Returns
//
// Receive-only channel yielding the child's exit error, or nil.
//
// # Example
//
//	done := sup.currentChildDone()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:607 (direct call)
//   - internal/watchdog/supervisor.go:632 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) currentChildDone() <-chan error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.child == nil {
		return nil
	}
	return s.child.done
}

// clearChildIfDone clears s.child when its done channel matches ch.
//
// # Parameters
//
//   - ch: The done channel that has just yielded an exit result.
//
// # Example
//
//	sup.clearChildIfDone(childDone)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:617 (direct call)
//   - internal/watchdog/supervisor.go:620 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) clearChildIfDone(ch <-chan error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.child != nil && s.child.done == ch {
		s.child = nil
	}
}

// handleUnexpectedChildExit records an unexpected child exit against Policy's
// circuit breaker, emits an alert, and respawns after backoff if permitted.
//
// # Parameters
//
//   - ctx: Supervision context.
//   - exitErr: Error returned by ManagedProcess.Wait.
//
// # Example
//
//	sup.handleUnexpectedChildExit(ctx, exitErr)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:624 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) handleUnexpectedChildExit(ctx context.Context, exitErr error) {
	now := s.cfg.Now()
	dec := s.policy.RecordCrash(now)
	obs := Observation{ObservedAt: now}
	if exitErr != nil {
		obs.HealthzErr = exitErr.Error()
	}
	if dec.EmitAlert {
		s.emitAlert(ctx, obs, dec)
	}
	if s.cfg.OnDecision != nil {
		s.cfg.OnDecision(obs, dec)
	}
	if dec.Action != ActionRestart {
		return
	}
	if dec.Backoff > 0 {
		if err := s.cfg.Sleep(ctx, dec.Backoff); err != nil {
			return
		}
	}
	if ctx.Err() != nil {
		return
	}
	if err := s.startChild(); err != nil {
		s.logger.Error("respawn child failed", "error", err)
	}
}

// maybeRespawnAfterCircuitBreaker checks whether the restart sliding window has
// dropped below MaxRestartsPerWindow while no child is running, and if so
// attempts to respawn the child process.
//
// # Parameters
//
//   - ctx: Supervision context.
//
// # Example
//
//	sup.maybeRespawnAfterCircuitBreaker(ctx)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:633 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) maybeRespawnAfterCircuitBreaker(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	now := s.cfg.Now()
	if s.policy.RestartsInWindow(now) >= s.policy.cfg.MaxRestartsPerWindow {
		return
	}
	dec := s.policy.RecordCrash(now)
	if dec.Action != ActionRestart {
		return
	}
	if err := s.startChild(); err != nil {
		s.logger.Error("respawn child after circuit window reset failed", "error", err)
	}
}

// resolveExternalPID returns the configured static PID or parses the integer
// PID from PIDFile (bounded read).
//
// # Parameters
//
// None.
//
// # Returns
//
// Positive PID, or 0 if unavailable or invalid.
//
// # Example
//
//	pid := sup.resolveExternalPID()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:546 (direct call)
//   - internal/watchdog/supervisor.go:1028 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) resolveExternalPID() int {
	if s.cfg.PID > 0 {
		return s.cfg.PID
	}
	if s.cfg.PIDFile == "" {
		return 0
	}
	f, err := os.Open(s.cfg.PIDFile)
	if err != nil {
		return 0
	}
	defer f.Close() // read-only handle; close error not material

	raw, err := io.ReadAll(io.LimitReader(f, maxPIDFileBytes))
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

// signalExternalPID sends SIGTERM to pid, polls for exit up to DrainTimeout,
// and falls back to SIGKILL if the process is still alive.
//
// # Parameters
//
//   - ctx: Context controlling cancellation during the drain wait.
//   - pid: Positive target PID.
//
// # Returns
//
// nil once the process has been signaled and either exited or received SIGKILL,
// or an error if signaling failed.
//
// # Example
//
//	if err := sup.signalExternalPID(ctx, pid); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:1033 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s *Supervisor) signalExternalPID(ctx context.Context, pid int) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("SIGTERM pid %d: %w", pid, err)
	}

	deadline := s.cfg.Now().Add(s.cfg.DrainTimeout)
	for s.cfg.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return nil
		}
		step := defaultPollStep
		if rem := deadline.Sub(s.cfg.Now()); rem < step {
			step = rem
		}
		if step <= 0 {
			break
		}
		if err := s.cfg.Sleep(ctx, step); err != nil {
			return err
		}
	}

	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("SIGKILL pid %d: %w", pid, err)
	}
	return nil
}

// sleepWithContext blocks for d or until ctx is cancelled, always stopping the
// underlying timer before returning.
//
// # Parameters
//
//   - ctx: Context whose cancellation ends the wait early.
//   - d: Duration to wait; non-positive values return nil immediately.
//
// # Returns
//
// nil if d elapsed, or ctx.Err() if ctx was cancelled first.
//
// # Example
//
//	if err := sleepWithContext(ctx, 2*time.Second); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:447 (function value)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sanitizeNetError unwraps any *url.Error inside err so logged error messages
// redact embedded URL userinfo and sensitive query parameters.
//
// # Parameters
//
//   - err: Transport or HTTP client error.
//
// # Returns
//
// A sanitized error preserving the underlying cause without leaking URL secrets.
//
// # Example
//
//	return fmt.Errorf("probe failed: %w", sanitizeNetError(err))
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:835 (direct call)
//   - internal/watchdog/supervisor.go:890 (direct call)
//   - internal/watchdog/supervisor.go:979 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func sanitizeNetError(err error) error {
	if err == nil {
		return nil
	}
	if uerr, ok := errors.AsType[*url.Error](err); ok {
		return fmt.Errorf("%s %s: %w", uerr.Op, RedactURL(uerr.URL), uerr.Err)
	}
	return err
}
