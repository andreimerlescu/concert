package watchdog

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// MaxMetricsBodyBytes is the hard upper bound on /_room/metrics payloads read
// by ParsePrometheusMetrics so a misbehaving or hostile endpoint cannot exhaust
// watchdog memory.
const MaxMetricsBodyBytes = 4 << 20

// ErrMetricsTooLarge is returned by ParsePrometheusMetrics when the input
// exceeds MaxMetricsBodyBytes.
var ErrMetricsTooLarge = errors.New("metrics payload exceeds maximum allowed size")

// ErrInvalidPID is returned by InspectProcess and InspectProcFS when pid <= 0.
var ErrInvalidPID = errors.New("pid must be positive")

// MetricsSnapshot holds the subset of Concert and Go/process Prometheus metrics
// extracted from /_room/metrics that govern watchdog recovery decisions.
// All fields are value types and safe to copy across goroutines.
type MetricsSnapshot struct {
	// Waiting room capacity, occupancy, and queue depth gauges.
	RoomCap        float64
	HasRoomCap     bool
	RoomOccupancy  float64
	QueueDepth     float64
	LiveQueueDepth float64
	MaxQueueDepth  float64

	// Waiting room counters.
	Rejected503Total float64
	TimeoutsTotal    float64
	ClearedTotal     float64

	// Upstream backend health and proxied request counters.
	UpstreamBackendsTotal      int
	HasUpstreamBackendsTotal   bool
	UpstreamBackendsHealthy    int
	HasUpstreamBackendsHealthy bool
	Upstream2xxTotal           float64
	Upstream3xxTotal           float64
	Upstream4xxTotal           float64
	Upstream5xxTotal           float64
	UpstreamErrorsTotal        float64

	// Concert readiness gauge (concert_ready).
	Ready    int
	HasReady bool

	// Optional memory and file-descriptor gauges when exported by the target.
	ResidentMemoryBytes    uint64
	HasResidentMemoryBytes bool
	OpenFDs                int
	HasOpenFDs             bool
	MaxFDs                 int
	HasMaxFDs              bool

	// SamplesParsed counts valid metric sample lines processed.
	SamplesParsed int
}

// ParsePrometheusMetrics parses a Prometheus text exposition stream (format
// 0.0.4) into a MetricsSnapshot using only the Go standard library.
//
// Reads are strictly bounded to MaxMetricsBodyBytes. Comment lines (# HELP,
// # TYPE), blank lines, unknown metrics, and non-finite sample values (NaN,
// +/-Inf) are skipped safely without failing the scrape.
//
// # Parameters
//
//   - r: Stream containing Prometheus text exposition output. Must be non-nil.
//     The caller retains ownership and is responsible for closing any
//     underlying io.ReadCloser.
//
// # Returns
//
// A populated MetricsSnapshot and a nil error on success. If r is nil or
// exceeds MaxMetricsBodyBytes, returns a zero MetricsSnapshot and an error
// (wrapping ErrMetricsTooLarge when the size cap is hit).
//
// # Example
//
//	snap, err := watchdog.ParsePrometheusMetrics(resp.Body)
//	if err != nil {
//		return err
//	}
//	fmt.Println(snap.UpstreamBackendsHealthy, snap.LiveQueueDepth)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:774 (direct call)
//   - internal/watchdog/watchdog_test.go:806 (direct call)
//   - internal/watchdog/watchdog_test.go:835 (direct call)
//   - internal/watchdog/watchdog_test.go:2014 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func ParsePrometheusMetrics(r io.Reader) (MetricsSnapshot, error) {
	if r == nil {
		return MetricsSnapshot{}, errors.New("nil metrics reader")
	}
	raw, err := io.ReadAll(io.LimitReader(r, MaxMetricsBodyBytes+1))
	if err != nil {
		return MetricsSnapshot{}, fmt.Errorf("read metrics body: %w", err)
	}
	if len(raw) > MaxMetricsBodyBytes {
		return MetricsSnapshot{}, fmt.Errorf("metrics body > %d bytes: %w", MaxMetricsBodyBytes, ErrMetricsTooLarge)
	}

	var snap MetricsSnapshot
	var fallbackMemBytes uint64
	var hasFallbackMem bool

	sc := bufio.NewScanner(bytes.NewReader(raw))
	// Allow long label lines while remaining strictly bounded by MaxMetricsBodyBytes.
	sc.Buffer(make([]byte, 0, 16<<10), 256<<10)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, labels, val, ok := parsePromSampleLine(line)
		if !ok {
			continue
		}
		snap.SamplesParsed++
		applyPromSample(&snap, name, labels, val, &fallbackMemBytes, &hasFallbackMem)
	}
	if err := sc.Err(); err != nil {
		return MetricsSnapshot{}, fmt.Errorf("scan metrics body: %w", err)
	}
	if !snap.HasResidentMemoryBytes && hasFallbackMem {
		snap.ResidentMemoryBytes = fallbackMemBytes
		snap.HasResidentMemoryBytes = true
	}
	return snap, nil
}

// parsePromSampleLine parses a single Prometheus text exposition sample line:
// `metric_name{k="v",...} value [timestamp]`.
//
// # Parameters
//
//   - line: Trimmed, non-empty, non-comment exposition line.
//
// # Returns
//
// Metric name, raw label block (without surrounding braces), parsed float64
// value, and ok == true when the line is well-formed with a finite value.
//
// # Example
//
//	name, labels, val, ok := parsePromSampleLine(`concert_upstream_requests_total{status_class="5xx"} 12`)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/metrics.go:133 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func parsePromSampleLine(line string) (name, labels string, val float64, ok bool) {
	// Split metric identifier (and optional {labels}) from the trailing value.
	var rest string
	if braceIdx := strings.IndexByte(line, '{'); braceIdx >= 0 {
		// Ensure the opening brace precedes any whitespace before the value.
		wsIdx := strings.IndexAny(line, " \t")
		if wsIdx >= 0 && wsIdx < braceIdx {
			name = line[:wsIdx]
			rest = strings.TrimSpace(line[wsIdx+1:])
		} else {
			name = strings.TrimSpace(line[:braceIdx])
			closeIdx := findClosingBrace(line, braceIdx+1)
			if closeIdx < 0 {
				return "", "", 0, false
			}
			labels = line[braceIdx+1 : closeIdx]
			rest = strings.TrimSpace(line[closeIdx+1:])
		}
	} else {
		wsIdx := strings.IndexAny(line, " \t")
		if wsIdx < 0 {
			return "", "", 0, false
		}
		name = line[:wsIdx]
		rest = strings.TrimSpace(line[wsIdx+1:])
	}
	if name == "" || rest == "" {
		return "", "", 0, false
	}

	// Value is the first whitespace-delimited token; optional timestamp follows.
	valToken := rest
	if wsIdx := strings.IndexAny(rest, " \t"); wsIdx >= 0 {
		valToken = rest[:wsIdx]
	}
	parsed, err := strconv.ParseFloat(valToken, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return "", "", 0, false
	}
	return name, labels, parsed, true
}

// findClosingBrace returns the index of the '}' matching an opening '{',
// respecting double-quoted label values and backslash escapes.
//
// # Parameters
//
//   - s: Full Prometheus sample line.
//   - start: Index immediately after the opening '{'.
//
// # Returns
//
// Index of the matching '}' in s, or -1 if unmatched.
//
// # Example
//
//	closeIdx := findClosingBrace(`m{a="b}c"} 1`, 2)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/metrics.go:184 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func findClosingBrace(s string, start int) int {
	inQuote := false
	escaped := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if inQuote {
			if c == '\\' {
				escaped = true
			} else if c == '"' {
				inQuote = false
			}
			continue
		}
		switch c {
		case '"':
			inQuote = true
		case '}':
			return i
		}
	}
	return -1
}

// extractPromLabel extracts the unescaped value of key from a raw Prometheus
// label list (the substring inside `{...}`).
//
// # Parameters
//
//   - labels: Raw label body without enclosing braces.
//   - key: Exact label key to look up.
//
// # Returns
//
// The label value and true when key is present and properly quoted; otherwise
// "", false.
//
// # Example
//
//	sc, ok := extractPromLabel(`status_class="5xx"`, "status_class")
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/metrics.go:396 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func extractPromLabel(labels, key string) (string, bool) {
	i := 0
	for i < len(labels) {
		for i < len(labels) && (labels[i] == ' ' || labels[i] == '\t' || labels[i] == ',') {
			i++
		}
		if i >= len(labels) {
			break
		}
		eq := strings.IndexByte(labels[i:], '=')
		if eq < 0 {
			break
		}
		k := strings.TrimSpace(labels[i : i+eq])
		i += eq + 1
		for i < len(labels) && (labels[i] == ' ' || labels[i] == '\t') {
			i++
		}
		if i >= len(labels) || labels[i] != '"' {
			break
		}
		i++ // skip opening quote
		var b strings.Builder
		closed := false
		for i < len(labels) {
			c := labels[i]
			i++
			if c == '\\' && i < len(labels) {
				next := labels[i]
				i++
				switch next {
				case 'n':
					b.WriteByte('\n')
				case '\\', '"':
					b.WriteByte(next)
				default:
					b.WriteByte('\\')
					b.WriteByte(next)
				}
				continue
			}
			if c == '"' {
				closed = true
				break
			}
			b.WriteByte(c)
		}
		if !closed {
			return "", false
		}
		if k == key {
			return b.String(), true
		}
	}
	return "", false
}

// applyPromSample records a single parsed metric sample into snap when it
// matches one of the tracked Concert or process metrics.
//
// # Parameters
//
//   - snap: Destination snapshot updated in place. Must be non-nil.
//   - name: Prometheus metric name.
//   - labels: Raw label block without surrounding braces.
//   - val: Finite numeric sample value.
//   - fallbackMem: Receives go_memstats_alloc_bytes if process_resident_memory_bytes
//     is absent. Must be non-nil.
//   - hasFallbackMem: Set to true when fallbackMem is populated. Must be non-nil.
//
// # Example
//
//	applyPromSample(&snap, "concert_room_live_queue_depth", "", 42, &fb, &hasFB)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/metrics.go:138 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func applyPromSample(snap *MetricsSnapshot, name, labels string, val float64, fallbackMem *uint64, hasFallbackMem *bool) {
	switch name {
	case "concert_room_cap":
		snap.RoomCap = val
		snap.HasRoomCap = true
	case "concert_room_occupancy":
		snap.RoomOccupancy = val
	case "concert_room_queue_depth":
		snap.QueueDepth = val
	case "concert_room_live_queue_depth":
		snap.LiveQueueDepth = val
	case "concert_room_max_queue_depth":
		snap.MaxQueueDepth = val
	case "concert_room_rejected_503_total":
		snap.Rejected503Total = val
	case "concert_room_timeouts_total":
		snap.TimeoutsTotal = val
	case "concert_room_cleared_total":
		snap.ClearedTotal = val
	case "concert_upstream_backends_total":
		snap.UpstreamBackendsTotal = int(math.Round(val))
		snap.HasUpstreamBackendsTotal = true
	case "concert_upstream_backends_healthy":
		snap.UpstreamBackendsHealthy = int(math.Round(val))
		snap.HasUpstreamBackendsHealthy = true
	case "concert_upstream_requests_total":
		sc, ok := extractPromLabel(labels, "status_class")
		if !ok {
			return
		}
		switch sc {
		case "2xx":
			snap.Upstream2xxTotal = val
		case "3xx":
			snap.Upstream3xxTotal = val
		case "4xx":
			snap.Upstream4xxTotal = val
		case "5xx":
			snap.Upstream5xxTotal = val
		}
	case "concert_upstream_errors_total":
		snap.UpstreamErrorsTotal = val
	case "concert_ready":
		snap.Ready = int(math.Round(val))
		snap.HasReady = true
	case "process_resident_memory_bytes":
		if val >= 0 {
			snap.ResidentMemoryBytes = uint64(val)
			snap.HasResidentMemoryBytes = true
		}
	case "go_memstats_alloc_bytes":
		if val >= 0 {
			*fallbackMem = uint64(val)
			*hasFallbackMem = true
		}
	case "process_open_fds":
		if val >= 0 {
			snap.OpenFDs = int(math.Round(val))
			snap.HasOpenFDs = true
		}
	case "process_max_fds":
		if val >= 0 {
			snap.MaxFDs = int(math.Round(val))
			snap.HasMaxFDs = true
		}
	}
}

// ProcStats holds OS-level resource counters inspected for a supervised PID.
type ProcStats struct {
	PID        int
	RSSBytes   uint64
	HasRSS     bool
	OpenFDs    int
	HasOpenFDs bool
}

// InspectProcess reads RSS and open file descriptor counts for pid from Linux
// procfs (/proc/<pid>/statm and /proc/<pid>/fd). On platforms without /proc
// (such as macOS), it returns a ProcStats with HasRSS=false, HasOpenFDs=false
// and a nil error when /proc does not exist.
//
// # Parameters
//
//   - pid: Target OS process ID. Must be positive.
//
// # Returns
//
// Populated ProcStats and nil on success (or when /proc is unavailable on the
// host OS); ErrInvalidPID when pid <= 0; or a read error when /proc exists but
// inspecting the target PID failed.
//
// # Example
//
//	stats, err := watchdog.InspectProcess(os.Getpid())
//	if err != nil {
//		return err
//	}
//	fmt.Println(stats.RSSBytes, stats.OpenFDs)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:441 (function value)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func InspectProcess(pid int) (ProcStats, error) {
	if pid <= 0 {
		return ProcStats{}, ErrInvalidPID
	}
	if _, err := os.Stat("/proc"); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ProcStats{PID: pid}, nil
		}
		return ProcStats{PID: pid}, fmt.Errorf("stat /proc: %w", err)
	}
	return InspectProcFS("/proc", pid, os.Getpagesize())
}

// InspectProcFS reads <procRoot>/<pid>/statm and counts entries in
// <procRoot>/<pid>/fd using pageSize bytes per resident page. Separating
// procRoot and pageSize allows deterministic testing across all platforms.
//
// # Parameters
//
//   - procRoot: Root directory of procfs (normally "/proc").
//   - pid: Positive target process ID.
//   - pageSize: System memory page size in bytes; values <= 0 default to os.Getpagesize().
//
// # Returns
//
// ProcStats containing whichever of RSSBytes and OpenFDs could be read, and an
// error if pid <= 0 or if neither statm nor fd could be inspected.
//
// # Example
//
//	stats, err := watchdog.InspectProcFS("/proc", 1234, os.Getpagesize())
//	if err != nil {
//		return err
//	}
//	fmt.Println(stats.RSSBytes, stats.OpenFDs)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/metrics.go:487 (direct call)
//   - internal/watchdog/watchdog_test.go:875 (direct call)
//   - internal/watchdog/watchdog_test.go:886 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func InspectProcFS(procRoot string, pid int, pageSize int) (ProcStats, error) {
	if pid <= 0 {
		return ProcStats{}, ErrInvalidPID
	}
	if pageSize <= 0 {
		pageSize = os.Getpagesize()
	}
	stats := ProcStats{PID: pid}
	pidDir := filepath.Join(procRoot, strconv.Itoa(pid))

	var statmErr, fdErr error
	if rss, err := readProcStatmRSS(filepath.Join(pidDir, "statm"), uint64(pageSize)); err == nil {
		stats.RSSBytes = rss
		stats.HasRSS = true
	} else {
		statmErr = err
	}

	if fds, err := countProcFDs(filepath.Join(pidDir, "fd")); err == nil {
		stats.OpenFDs = fds
		stats.HasOpenFDs = true
	} else {
		fdErr = err
	}

	if !stats.HasRSS && !stats.HasOpenFDs {
		return stats, fmt.Errorf("inspect pid %d: %w", pid, errors.Join(statmErr, fdErr))
	}
	return stats, nil
}

// readProcStatmRSS reads a Linux /proc/<pid>/statm file and computes resident
// set size in bytes from the second whitespace-separated field (resident pages).
//
// # Parameters
//
//   - path: Full path to the statm file.
//   - pageSize: Page size in bytes.
//
// # Returns
//
// Resident set size in bytes, or an error on I/O or parse failure.
//
// # Example
//
//	rss, err := readProcStatmRSS("/proc/1234/statm", 4096)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/metrics.go:533 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func readProcStatmRSS(path string, pageSize uint64) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open statm: %w", err)
	}
	defer f.Close() // read-only procfs handle; close error not material

	// statm is a single short line of 7 integers; 4 KiB is a generous bound.
	raw, err := io.ReadAll(io.LimitReader(f, 4<<10))
	if err != nil {
		return 0, fmt.Errorf("read statm: %w", err)
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return 0, fmt.Errorf("parse statm %q: expected at least 2 fields, got %d", path, len(fields))
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse resident pages in %q: %w", path, err)
	}
	if pageSize > 0 && pages > math.MaxUint64/pageSize {
		return math.MaxUint64, nil
	}
	return pages * pageSize, nil
}

// countProcFDs returns the number of entries in a Linux /proc/<pid>/fd
// directory without following symlinks.
//
// # Parameters
//
//   - dir: Full path to the /proc/<pid>/fd directory.
//
// # Returns
//
// Number of open file descriptor entries, or an error if the directory cannot
// be read.
//
// # Example
//
//	fds, err := countProcFDs("/proc/1234/fd")
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/metrics.go:540 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func countProcFDs(dir string) (int, error) {
	f, err := os.Open(dir)
	if err != nil {
		return 0, fmt.Errorf("open fd dir: %w", err)
	}
	defer f.Close() // read-only directory handle; close error not material

	names, err := f.Readdirnames(-1)
	if err != nil {
		return 0, fmt.Errorf("read fd dir: %w", err)
	}
	return len(names), nil
}
