package main

import (
	"net/http"
	"os"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// The monitor answers "how is Concert itself doing": request rate, latency
// and errors through the proxy, plus the Go runtime (CPU, memory, garbage
// collection, goroutines). A sampler keeps ten minutes of history so the
// portal can draw trends without an external metrics system.

const (
	sampleEvery   = 5 * time.Second
	sampleHistory = 120 // ten minutes
)

// latencyBoundsMS are histogram bucket upper bounds, in milliseconds.
var latencyBoundsMS = [...]float64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

type monitor struct {
	started  time.Time
	buckets  [len(latencyBoundsMS) + 1]atomic.Int64
	total    atomic.Int64
	classes  [6]atomic.Int64 // index status/100; 0 collects anything odd
	inflight atomic.Int64
	peak     atomic.Int64

	mu      sync.Mutex
	history []monitorSample
	last    monitorLast
}

type monitorLast struct {
	at      time.Time
	total   int64
	buckets [len(latencyBoundsMS) + 1]int64
	errs    int64
	busy    float64
	cpu     float64
}

// monitorSample is one point in the history.
type monitorSample struct {
	At         int64   `json:"t"`
	RPS        float64 `json:"rps"`
	P50        float64 `json:"p50_ms"`
	P95        float64 `json:"p95_ms"`
	Errors     float64 `json:"errors_per_s"`
	Inflight   int64   `json:"inflight"`
	Goroutines int     `json:"goroutines"`
	HeapMB     float64 `json:"heap_mb"`
	CPU        float64 `json:"cpu_pct"`
	Queue      int64   `json:"queue_depth"`
	Occupancy  int     `json:"occupancy"`
}

func newMonitor() *monitor { return &monitor{started: time.Now()} }

func bucketFor(ms float64) int {
	for i, b := range latencyBoundsMS {
		if ms <= b {
			return i
		}
	}
	return len(latencyBoundsMS)
}

// middleware records every request that reaches the main listener, including
// banned and refused ones, once it finishes.
func (m *monitor) middleware(c *gin.Context) {
	start := time.Now()
	n := m.inflight.Add(1)
	for {
		p := m.peak.Load()
		if n <= p || m.peak.CompareAndSwap(p, n) {
			break
		}
	}
	defer func() {
		m.inflight.Add(-1)
		ms := float64(time.Since(start)) / float64(time.Millisecond)
		m.buckets[bucketFor(ms)].Add(1)
		m.total.Add(1)
		class := c.Writer.Status() / 100
		if class < 1 || class > 5 {
			class = 0
		}
		m.classes[class].Add(1)
	}()
	c.Next()
}

// quantile estimates a latency quantile from bucket counts (upper bound of
// the bucket that holds it; the open top bucket reports its lower bound).
func quantile(counts []int64, q float64) float64 {
	var total int64
	for _, n := range counts {
		total += n
	}
	if total == 0 {
		return 0
	}
	target := int64(float64(total)*q + 0.999999)
	var run int64
	for i, n := range counts {
		run += n
		if run >= target {
			if i >= len(latencyBoundsMS) {
				return latencyBoundsMS[len(latencyBoundsMS)-1]
			}
			return latencyBoundsMS[i]
		}
	}
	return latencyBoundsMS[len(latencyBoundsMS)-1]
}

func cpuSeconds() (busy, total float64) {
	s := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}, {Name: "/cpu/classes/idle:cpu-seconds"}}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindFloat64 || s[1].Value.Kind() != metrics.KindFloat64 {
		return 0, 0
	}
	total = s[0].Value.Float64()
	return total - s[1].Value.Float64(), total
}

func (m *monitor) counts() (c [len(latencyBoundsMS) + 1]int64) {
	for i := range c {
		c[i] = m.buckets[i].Load()
	}
	return c
}

func (m *monitor) errors() int64 { return m.classes[5].Load() }

// sample appends one history point covering the time since the last one.
func (m *monitor) sample(a *app) {
	now := time.Now()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	busy, total := cpuSeconds()
	cur := m.counts()
	m.mu.Lock()
	defer m.mu.Unlock()
	s := monitorSample{At: now.UnixMilli(), Inflight: m.inflight.Load(), Goroutines: runtime.NumGoroutine(), HeapMB: float64(ms.HeapAlloc) / (1 << 20),
		Queue: a.room.QueueDepth(), Occupancy: a.room.Len()}
	if dt := now.Sub(m.last.at).Seconds(); !m.last.at.IsZero() && dt > 0 {
		var delta [len(latencyBoundsMS) + 1]int64
		var n int64
		for i := range cur {
			delta[i] = cur[i] - m.last.buckets[i]
			n += delta[i]
		}
		s.RPS = float64(n) / dt
		s.P50, s.P95 = quantile(delta[:], 0.5), quantile(delta[:], 0.95)
		s.Errors = float64(m.errors()-m.last.errs) / dt
		if dc := total - m.last.cpu; dc > 0 {
			s.CPU = 100 * (busy - m.last.busy) / dc
		}
	}
	m.last = monitorLast{at: now, total: m.total.Load(), buckets: cur, errs: m.errors(), busy: busy, cpu: total}
	m.history = append(m.history, s)
	if len(m.history) > sampleHistory {
		m.history = m.history[len(m.history)-sampleHistory:]
	}
}

func (m *monitor) run(a *app, stop <-chan struct{}) {
	m.sample(a)
	t := time.NewTicker(sampleEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			m.sample(a)
		}
	}
}

// procStatus reads a few Linux /proc values; they are omitted elsewhere.
func procStatus() map[string]any {
	out := map[string]any{}
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(line, ":"); ok && (k == "VmRSS" || k == "Threads") {
				f := strings.Fields(v)
				if len(f) > 0 {
					if n, err := strconv.ParseFloat(f[0], 64); err == nil {
						if k == "VmRSS" {
							out["rss_mb"] = n / 1024
						} else {
							out["threads"] = int(n)
						}
					}
				}
			}
		}
	}
	if d, err := os.ReadDir("/proc/self/fd"); err == nil {
		out["open_files"] = len(d)
	}
	return out
}

// health lists the parts of Concert that can be degraded, each ok or not.
func (p *portal) monitorHealth() []gin.H {
	a := p.a
	var out []gin.H
	add := func(name string, ok bool, detail string) {
		out = append(out, gin.H{"name": name, "ok": ok, "detail": detail})
	}
	util := a.room.UtilizationSmoothed()
	add("Waiting room", util < 0.98, strconv.Itoa(a.room.Len())+" of "+strconv.Itoa(int(a.room.Cap()))+" slots in use, "+strconv.FormatInt(a.room.QueueDepth(), 10)+" waiting")
	if lane := a.lane.Load(); lane != nil {
		sum := lane.Summary()
		healthy, _ := sum["healthy"].(bool)
		detail := "receipt journal healthy"
		if !healthy {
			detail = "receipt journal needs attention; admission suspended"
		}
		add("Fast lane", healthy, detail)
	} else if a.laneReloading.Load() {
		add("Fast lane", false, "reloading settings")
	}
	return out
}

func (p *portal) apiMonitor(c *gin.Context) {
	m := p.a.mon
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	busy, total := cpuSeconds()
	counts := m.counts()
	var pauseAvgMS, pauseLastMS float64
	if ms.NumGC > 0 {
		pauseAvgMS = float64(ms.PauseTotalNs) / float64(ms.NumGC) / 1e6
		pauseLastMS = float64(ms.PauseNs[(ms.NumGC+255)%256]) / 1e6
	}
	m.mu.Lock()
	history := append([]monitorSample(nil), m.history...)
	m.mu.Unlock()
	classes := gin.H{}
	for i, name := range []string{"other", "1xx", "2xx", "3xx", "4xx", "5xx"} {
		classes[name] = m.classes[i].Load()
	}
	proc := procStatus()
	proc["uptime_s"] = time.Since(m.started).Seconds()
	proc["go_version"] = runtime.Version()
	proc["os_arch"] = runtime.GOOS + "/" + runtime.GOARCH
	proc["cpus"] = runtime.NumCPU()
	proc["gomaxprocs"] = runtime.GOMAXPROCS(0)
	proc["goroutines"] = runtime.NumGoroutine()
	proc["cpu_busy_s"] = busy
	if total > 0 {
		proc["cpu_avg_pct"] = 100 * busy / total
	}
	c.JSON(http.StatusOK, gin.H{
		"process": proc,
		"memory": gin.H{"heap_alloc_mb": float64(ms.HeapAlloc) / (1 << 20), "heap_inuse_mb": float64(ms.HeapInuse) / (1 << 20), "heap_objects": ms.HeapObjects, "sys_mb": float64(ms.Sys) / (1 << 20), "stack_mb": float64(ms.StackInuse) / (1 << 20), "next_gc_mb": float64(ms.NextGC) / (1 << 20),
			"gc_cycles": ms.NumGC, "gc_pause_avg_ms": pauseAvgMS, "gc_pause_last_ms": pauseLastMS, "gc_cpu_pct": ms.GCCPUFraction * 100, "allocated_total_mb": float64(ms.TotalAlloc) / (1 << 20)},
		"traffic": gin.H{"requests_total": m.total.Load(), "inflight": m.inflight.Load(), "inflight_peak": m.peak.Load(), "status": classes,
			"p50_ms": quantile(counts[:], 0.5), "p95_ms": quantile(counts[:], 0.95), "p99_ms": quantile(counts[:], 0.99), "bounds_ms": latencyBoundsMS, "buckets": counts},
		"health":   p.monitorHealth(),
		"history":  history,
		"interval": int(sampleEvery / time.Second),
	})
}
