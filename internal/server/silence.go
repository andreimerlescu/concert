package server

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/andreimerlescu/concert/internal/capacity"
	"github.com/andreimerlescu/concert/internal/hop"
	"github.com/andreimerlescu/concert/internal/mailer"
)

// Silence reports.
//
// A leaf sits next to its application, so when the application stops
// answering it knows what load it was carrying at that moment. Once a
// second the leaf compares its upstream outcomes: if every upstream is
// unhealthy, or several requests failed (transport errors or 502–504) and
// none answered, the application has gone silent, and the leaf records a
// hop.SilenceReport with the host slots in use, the queue, the requests in
// flight to the application and the recent latency. The report is logged,
// returned in the leaf's state (so the edge's /_room/stats shows it), and
// appended to silence.jsonl in -data-dir (rotated when it grows past
// silenceLogMaxBytes). On bare metal it is the difference between "the box
// fell over at 40 concurrent requests" and "the box failed with nothing
// running".

// silenceFile is the log of silence reports in -data-dir.
const (
	silenceFile    = "silence.jsonl"
	silenceLogKeep = 4
)

// silenceLogMaxBytes bounds silence.jsonl before rotation (var for tests).
var silenceLogMaxBytes int64 = 16 << 20

// silenceErrors is how many failed upstream requests (transport errors or
// 502–504), with no answered responses, in one second count as silence.
const silenceErrors = 3

type silenceMonitor struct {
	mu          sync.Mutex
	writeMu     sync.Mutex // serializes silence.jsonl writes outside mu
	started     bool
	silent      bool
	lastHealthy time.Time
	last        *hop.SilenceReport
	latencyMs   float64 // exponentially weighted mean upstream response time
	prevOK      int64
	prevFail    int64
	prevCount   uint64
	prevSumNS   uint64
	peakHop     int64 // highest hop in-flight in the previous second
	peakDirect  int64
}

func (m *silenceMonitor) view() (float64, *hop.SilenceReport) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last == nil {
		return m.latencyMs, nil
	}
	cp := *m.last
	return m.latencyMs, &cp
}

// runLeafMonitor ticks the silence monitor every second until the app stops.
func (a *app) runLeafMonitor() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-a.stop:
			return
		case now := <-t.C:
			a.leafTick(now)
		}
	}
}

// leafTick samples the leaf once.
func (a *app) leafTick(now time.Time) {
	g := a.current()
	l := a.topo.leaf
	s := a.stats
	m := &l.monitor

	unavail := s.upstreamUnavail.Load()
	app5xx := s.upstream5xx.Load() - unavail
	if app5xx < 0 {
		app5xx = 0
	}
	// Application-generated responses (2xx–4xx and 500/501) mean the app is
	// answering; silence counts only transport errors and 502–504, matching
	// the circuit breaker.
	ok := s.upstream2xx.Load() + s.upstream3xx.Load() + s.upstream4xx.Load() + app5xx
	fail := unavail + s.upstreamErrors.Load()
	count, sum := s.upstreamLatency.count.Load(), s.upstreamLatency.sumNS.Load()
	hopNow := int64(l.gate.InUse(capacity.HopPriority) + l.gate.InUse(capacity.Hop))
	directNow := int64(l.gate.InUse(capacity.Direct))
	healthyUpstreams := g.upstreams == nil || g.upstreams.healthyCount(now) > 0
	var upstreamInFlight int64
	if g.upstreams != nil {
		for _, b := range g.upstreams.backends {
			upstreamInFlight += b.inFlight.Load()
		}
	}

	var toLog *hop.SilenceReport
	m.mu.Lock()
	if !m.started {
		m.started = true
		m.prevOK, m.prevFail, m.prevCount, m.prevSumNS = ok, fail, count, sum
		m.lastHealthy = now
		m.peakHop, m.peakDirect = hopNow, directNow
		m.mu.Unlock()
		return
	}
	dOK, dFail := ok-m.prevOK, fail-m.prevFail
	if dc := count - m.prevCount; dc > 0 {
		mean := float64(sum-m.prevSumNS) / float64(dc) / 1e6
		if m.latencyMs == 0 {
			m.latencyMs = mean
		} else {
			m.latencyMs = 0.7*m.latencyMs + 0.3*mean
		}
	}
	m.prevOK, m.prevFail, m.prevCount, m.prevSumNS = ok, fail, count, sum

	silent := !healthyUpstreams || (dFail >= silenceErrors && dOK == 0)
	switch {
	case !silent:
		if m.silent {
			m.silent = false
			if m.last != nil {
				m.last.Recovered = now.UTC()
				cp := *m.last
				toLog = &cp
				log.Printf("leaf: application answering again after %s", now.Sub(m.last.At).Round(time.Second))
			}
		}
		m.lastHealthy = now
	case !m.silent:
		m.silent = true
		reason := "upstream requests failing"
		if !healthyUpstreams {
			reason = "no healthy upstream"
		}
		// The load just before the failure is the evidence; take the
		// larger of now and the previous second.
		hopLoad, directLoad := max(hopNow, m.peakHop), max(directNow, m.peakDirect)
		r := hop.SilenceReport{
			At:               now.UTC(),
			Reason:           reason,
			HostCap:          l.gate.Cap(),
			HopInFlight:      hopLoad,
			DirectInFlight:   directLoad,
			QueueDepth:       a.room.LiveQueueDepth(),
			UpstreamInFlight: upstreamInFlight,
			LatencyMs:        m.latencyMs,
			Upstream5xx:      uint64(s.upstream5xx.Load()),
			UpstreamErrors:   uint64(s.upstreamErrors.Load()),
			LastHealthy:      m.lastHealthy.UTC(),
		}
		m.last = &r
		cp := r
		toLog = &cp
		log.Printf("leaf: application silent (%s) carrying %d hop + %d direct of %d host slots, %d in flight upstream, %.0fms mean latency",
			reason, hopLoad, directLoad, r.HostCap, upstreamInFlight, m.latencyMs)
	}
	m.peakHop, m.peakDirect = hopNow, directNow
	m.mu.Unlock()

	if toLog != nil {
		a.appendSilence(*toLog)
		if toLog.Recovered.IsZero() {
			a.notifyEvent(mailer.Event{
				Category:    mailer.CatSilence,
				Severity:    mailer.SevCritical,
				Title:       "Leaf application silent",
				Summary:     fmt.Sprintf("Leaf %s detected application silence (%s) while carrying %d hop + %d direct of %d host slots.", a.topo.node, toLog.Reason, toLog.HopInFlight, toLog.DirectInFlight, toLog.HostCap),
				Fingerprint: "silence:" + a.topo.node,
				Details: map[string]string{
					"node":               a.topo.node,
					"reason":             toLog.Reason,
					"host_cap":           fmt.Sprintf("%d", toLog.HostCap),
					"hop_in_flight":      fmt.Sprintf("%d", toLog.HopInFlight),
					"direct_in_flight":   fmt.Sprintf("%d", toLog.DirectInFlight),
					"upstream_in_flight": fmt.Sprintf("%d", toLog.UpstreamInFlight),
					"latency_ms":         fmt.Sprintf("%.0f", toLog.LatencyMs),
				},
			})
		} else {
			a.notifyEvent(mailer.Event{
				Category:    mailer.CatSilence,
				Severity:    mailer.SevInfo,
				Title:       "Leaf application recovered",
				Summary:     fmt.Sprintf("Leaf %s application is answering again after %s.", a.topo.node, toLog.Recovered.Sub(toLog.At).Round(time.Second)),
				Fingerprint: "silence-recovered:" + a.topo.node,
				Details:     map[string]string{"node": a.topo.node},
			})
		}
	}
}

// appendSilence adds r to silence.jsonl in -data-dir, rotating when the file
// exceeds silenceLogMaxBytes. Runs outside m.mu so disk I/O never blocks
// leafReport polls.
func (a *app) appendSilence(r hop.SilenceReport) {
	dir := a.current().cfg.dataDir
	if dir == "" {
		return
	}
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	line := append(b, '\n')
	path := filepath.Join(dir, silenceFile)

	m := &a.topo.leaf.monitor
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("leaf: silence log: %v", err)
		return
	}
	if st, err := os.Stat(path); err == nil && st.Size() > 0 && st.Size()+int64(len(line)) > silenceLogMaxBytes {
		rotateSilenceLog(path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		log.Printf("leaf: silence log: %v", err)
		return
	}
	defer f.Close()
	_ = f.Chmod(0o600)
	_, _ = f.Write(line)
}

func rotateSilenceLog(path string) {
	for i := silenceLogKeep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1))
	}
	_ = os.Rename(path, path+".1")
}
