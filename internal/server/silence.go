package server

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/andreimerlescu/concert/internal/capacity"
	"github.com/andreimerlescu/concert/internal/hop"
)

// Silence reports.
//
// A leaf sits next to its application, so when the application stops
// answering it knows what load it was carrying at that moment. Once a
// second the leaf compares its upstream outcomes: if every upstream is
// unhealthy, or several requests failed and none succeeded, the application
// has gone silent, and the leaf records a hop.SilenceReport with the host
// slots in use, the queue, the requests in flight to the application and
// the recent latency. The report is logged, returned in the leaf's state
// (so the edge's /_room/stats shows it), and appended to silence.jsonl in
// -data-dir. On bare metal it is the difference between "the box fell over
// at 40 concurrent requests" and "the box failed with nothing running".

// silenceFile is the log of silence reports in -data-dir.
const silenceFile = "silence.jsonl"

// silenceErrors is how many failed upstream requests, with no success, in
// one second count as silence.
const silenceErrors = 3

type silenceMonitor struct {
	mu          sync.Mutex
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

	ok := s.upstream2xx.Load() + s.upstream3xx.Load() + s.upstream4xx.Load()
	fail := s.upstream5xx.Load() + s.upstreamErrors.Load()
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

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started {
		m.started = true
		m.prevOK, m.prevFail, m.prevCount, m.prevSumNS = ok, fail, count, sum
		m.lastHealthy = now
		m.peakHop, m.peakDirect = hopNow, directNow
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
				log.Printf("leaf: application answering again after %s", now.Sub(m.last.At).Round(time.Second))
				a.appendSilence(*m.last)
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
		log.Printf("leaf: application silent (%s) carrying %d hop + %d direct of %d host slots, %d in flight upstream, %.0fms mean latency",
			reason, hopLoad, directLoad, r.HostCap, upstreamInFlight, m.latencyMs)
		a.appendSilence(r)
	}
	m.peakHop, m.peakDirect = hopNow, directNow
}

// appendSilence adds r to silence.jsonl in -data-dir, best effort.
func (a *app) appendSilence(r hop.SilenceReport) {
	dir := a.current().cfg.dataDir
	if dir == "" {
		return
	}
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, silenceFile), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		log.Printf("leaf: silence log: %v", err)
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}
