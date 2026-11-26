// Command concert-watchdog is the external health, resource, and recovery
// supervisor for Concert proxies (concert, wpconcert, econcert).
//
// It runs either in parent-process supervision mode (passing the target binary
// and arguments after `--`) or in external-probe/PID mode (passing `-pid-file`
// or probing an already-running systemd service). Sensitive bearer tokens are
// read exclusively from environment variables or 0600 files
// (CONCERT_WATCHDOG_TOKEN[_FILE] and CONCERT_WATCHDOG_WEBHOOK_TOKEN[_FILE]) and
// are never accepted via command-line flags.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/andreimerlescu/concert"
	"github.com/andreimerlescu/concert/internal/watchdog"
)

const (
	envOperatorToken = "CONCERT_WATCHDOG_TOKEN"
	envWebhookToken  = "CONCERT_WATCHDOG_WEBHOOK_TOKEN"
)

// main is the CLI entrypoint invoked by the Go runtime. It delegates to run so
// argument parsing, secret loading, and supervision lifecycle can be tested
// without calling os.Exit.
//
// # Parameters
//
// None (reads os.Args[1:], writes stdout/stderr).
//
// # Example
//
//	concert-watchdog -health-url http://127.0.0.1:8080/_room/healthz -- /usr/local/bin/concert
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// Invoked by the Go runtime as the command entrypoint; no direct Go callers.
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "concert-watchdog:", err)
		os.Exit(1)
	}
}

// run parses CLI flags, loads optional credentials from environment variables
// or 0600 files, builds a watchdog.Supervisor, and runs it until ctx cancels.
//
// # Parameters
//
//   - ctx: Controls supervision loop lifetime and graceful child shutdown.
//   - args: CLI arguments excluding argv[0].
//   - stdout: Destination for `-version` output.
//   - stderr: Destination for flag usage, diagnostics, and structured logs.
//
// # Returns
//
// nil on `-version`, `-h`/`-help`, or clean shutdown after ctx cancellation;
// otherwise a secret-free configuration or runtime error.
//
// # Example
//
//	err := run(ctx, []string{"-version"}, os.Stdout, os.Stderr)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-watchdog/main.go:56 (direct call)
//   - cmd/concert-watchdog/main_test.go:40 (direct call)
//   - cmd/concert-watchdog/main_test.go:49 (direct call)
//   - cmd/concert-watchdog/main_test.go:83 (direct call)
//   - cmd/concert-watchdog/main_test.go:99 (direct call)
//   - cmd/concert-watchdog/main_test.go:110 (direct call)
//   - cmd/concert-watchdog/main_test.go:175 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("concert-watchdog", flag.ContinueOnError)
	fs.SetOutput(stderr)

	healthURL := fs.String("health-url", "http://127.0.0.1:8080/_room/healthz", "Concert /_room/healthz liveness URL")
	readyURL := fs.String("ready-url", "http://127.0.0.1:8080/_room/readyz", "Concert /_room/readyz readiness URL")
	metricsURL := fs.String("metrics-url", "http://127.0.0.1:8080/_room/metrics", "Concert /_room/metrics Prometheus URL")
	clearURL := fs.String("clear-url", "http://127.0.0.1:8080/_room/queue/clear", "Concert /_room/queue/clear recovery URL")
	interval := fs.Duration("interval", 10*time.Second, "Probe interval")
	timeout := fs.Duration("timeout", 3*time.Second, "Per-probe HTTP timeout")
	maxRSSMB := fs.Uint64("max-rss-mb", 0, "Maximum allowed RSS in MiB (0 disables)")
	maxFDs := fs.Int("max-fds", 0, "Maximum allowed open file descriptors (0 disables)")
	max5xxRatio := fs.Float64("max-5xx-ratio", 0.5, "Maximum Concert internal 5xx ratio in [0, 1] when upstream is healthy (0 disables)")
	failThreshold := fs.Int("fail-threshold", 3, "Consecutive unhealthy probes before escalating")
	maxRestarts := fs.Int("max-restarts", 5, "Maximum restarts allowed within -restart-window before opening circuit breaker")
	restartWindow := fs.Duration("restart-window", 15*time.Minute, "Sliding window for restart-loop circuit breaker")
	drainTimeout := fs.Duration("drain-timeout", 30*time.Second, "Grace period after SIGTERM before SIGKILL fallback")
	alertWebhook := fs.String("alert-webhook", "", "Optional HTTPS (or localhost HTTP) alert webhook URL")
	pidFile := fs.String("pid-file", "", "Optional PID file path for external-probe mode (ignored when target binary follows --)")
	showVersion := fs.Bool("version", false, "Print concert-watchdog version and exit")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: concert-watchdog [flags] [-- <target-binary> [target-args...]]\n\n")
		fmt.Fprintf(stderr, "Credentials are read ONLY from environment variables or 0600 files (never CLI flags):\n")
		fmt.Fprintf(stderr, "  %s_FILE or %s\n", envOperatorToken, envOperatorToken)
		fmt.Fprintf(stderr, "  %s_FILE or %s\n\n", envWebhookToken, envWebhookToken)
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if *showVersion {
		_, err := fmt.Fprintf(stdout, "concert-watchdog %s\n", concert.Version())
		return err
	}

	opToken, opTokenSet, err := watchdog.LoadOptionalSecret(envOperatorToken)
	if err != nil {
		return fmt.Errorf("load operator token: %w", err)
	}
	whToken, whTokenSet, err := watchdog.LoadOptionalSecret(envWebhookToken)
	if err != nil {
		return fmt.Errorf("load webhook token: %w", err)
	}

	var maxRSSBytes uint64
	if *maxRSSMB > 0 {
		const mib = 1 << 20
		if *maxRSSMB > (^uint64(0))/mib {
			return fmt.Errorf("invalid -max-rss-mb %d: overflows uint64 bytes", *maxRSSMB)
		}
		maxRSSBytes = *maxRSSMB * mib
	}

	policyCfg := watchdog.DefaultPolicyConfig()
	policyCfg.ConsecutiveFailures = *failThreshold
	policyCfg.MaxRSSBytes = maxRSSBytes
	policyCfg.MaxFDs = *maxFDs
	policyCfg.Max5xxRatio = *max5xxRatio
	policyCfg.MaxRestartsPerWindow = *maxRestarts
	policyCfg.RestartWindow = *restartWindow

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	childCmd := fs.Args()

	sup, err := watchdog.NewSupervisor(watchdog.SupervisorConfig{
		HealthURL:       *healthURL,
		ReadyURL:        *readyURL,
		MetricsURL:      *metricsURL,
		ClearURL:        *clearURL,
		AlertWebhookURL: *alertWebhook,
		OperatorToken:   opToken,
		WebhookToken:    whToken,
		Interval:        *interval,
		Timeout:         *timeout,
		DrainTimeout:    *drainTimeout,
		Policy:          policyCfg,
		ChildCommand:    childCmd,
		PIDFile:         *pidFile,
		Logger:          logger,
	})
	if err != nil {
		return err
	}

	mode := "external"
	if len(childCmd) > 0 {
		mode = "parent-supervisor"
	}
	logger.Info("starting concert-watchdog",
		"version", concert.Version(),
		"mode", mode,
		"health_url", watchdog.RedactURL(*healthURL),
		"metrics_url", watchdog.RedactURL(*metricsURL),
		"clear_url", watchdog.RedactURL(*clearURL),
		"alert_webhook", redactOptionalURL(*alertWebhook),
		"operator_token_configured", opTokenSet,
		"webhook_token_configured", whTokenSet,
		"interval", interval.String(),
		"timeout", timeout.String(),
		"drain_timeout", drainTimeout.String(),
		"max_rss_mb", *maxRSSMB,
		"max_fds", *maxFDs,
		"max_5xx_ratio", *max5xxRatio,
		"fail_threshold", *failThreshold,
		"max_restarts", *maxRestarts,
		"restart_window", restartWindow.String(),
	)

	return sup.Run(ctx)
}

// redactOptionalURL returns "" when raw is empty, or watchdog.RedactURL(raw)
// otherwise so startup logs never expose embedded query secrets.
//
// # Parameters
//
//   - raw: Optional URL string.
//
// # Returns
//
// Empty string if raw is empty, else the redacted URL.
//
// # Example
//
//	safe := redactOptionalURL(cfgWebhook)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-watchdog/main.go:195 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func redactOptionalURL(raw string) string {
	if raw == "" {
		return ""
	}
	return watchdog.RedactURL(raw)
}
