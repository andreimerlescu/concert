package server

import (
	"fmt"
	"math"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// Pure-stdlib Prometheus / OpenMetrics text exposition (version 0.0.4) and
// lock-free latency histograms. Zero external dependencies.

var latencyBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
}

type durationHistogram struct {
	buckets [12]atomic.Uint64
	count   atomic.Uint64
	sumNS   atomic.Uint64
}

func (h *durationHistogram) observe(d time.Duration) {
	if d < 0 {
		d = 0
	}
	sec := d.Seconds()
	for i, bound := range latencyBuckets {
		if sec <= bound {
			h.buckets[i].Add(1)
		}
	}
	h.count.Add(1)
	h.sumNS.Add(uint64(d.Nanoseconds()))
}

func (h *durationHistogram) writePrometheus(b *strings.Builder, name, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	for i, bound := range latencyBuckets {
		fmt.Fprintf(b, "%s_bucket{le=\"%g\"} %d\n", name, bound, h.buckets[i].Load())
	}
	total := h.count.Load()
	fmt.Fprintf(b, "%s_bucket{le=\"+Inf\"} %d\n", name, total)
	sumSec := float64(h.sumNS.Load()) / 1e9
	if math.IsNaN(sumSec) || math.IsInf(sumSec, 0) {
		sumSec = 0
	}
	fmt.Fprintf(b, "%s_sum %.9f\n", name, sumSec)
	fmt.Fprintf(b, "%s_count %d\n", name, total)
}

func writePromMetric(b *strings.Builder, name, mtype, help string, val any) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", name, help, name, mtype, name, val)
}

func fipsModeLabel() string {
	if v := strings.TrimSpace(os.Getenv("GOFIPS140")); v != "" && v != "off" {
		return v
	}
	return "standard"
}

// renderPrometheusMetrics serializes Concert's operational metrics in
// Prometheus text exposition format.
func (a *app) renderPrometheusMetrics() string {
	g := a.current()
	wr, stats := a.room, a.stats
	now := time.Now()

	var b strings.Builder
	b.Grow(4096)

	fmt.Fprintf(&b, "# HELP concert_build_info Build and runtime information.\n# TYPE concert_build_info gauge\n")
	fmt.Fprintf(&b, "concert_build_info{version=%q,go_version=%q,fips=%q} 1\n",
		BinaryVersion(), runtime.Version(), fipsModeLabel())

	// Waiting room
	writePromMetric(&b, "concert_room_cap", "gauge", "Configured maximum concurrent page requests.", wr.Cap())
	writePromMetric(&b, "concert_room_occupancy", "gauge", "Current in-flight page requests to upstream.", wr.Len())
	draining := 0
	if wr.Len() > int(wr.Cap()) {
		draining = 1
	}
	writePromMetric(&b, "concert_room_cap_draining", "gauge", "1 while in-flight occupancy is draining down to a lower capacity.", draining)
	writePromMetric(&b, "concert_room_queue_depth", "gauge", "Total tickets in queue including recently abandoned.", wr.QueueDepth())
	writePromMetric(&b, "concert_room_live_queue_depth", "gauge", "Active visitors currently waiting in queue.", wr.LiveQueueDepth())
	writePromMetric(&b, "concert_room_max_queue_depth", "gauge", "Configured max queue depth breaker (0 = unlimited).", wr.MaxQueueDepth())
	writePromMetric(&b, "concert_room_utilization", "gauge", "Smoothed waiting room utilization ratio.", wr.UtilizationSmoothed())
	writePromMetric(&b, "concert_room_queued_total", "counter", "Total visitors placed into the waiting room.", stats.queued.Load())
	writePromMetric(&b, "concert_room_evicted_total", "counter", "Total tickets evicted from the waiting room.", stats.evicted.Load())
	writePromMetric(&b, "concert_room_timeouts_total", "counter", "Total waiting room admission timeouts.", stats.timeouts.Load())
	writePromMetric(&b, "concert_room_promoted_total", "counter", "Total queue promotions.", stats.promoted.Load())
	writePromMetric(&b, "concert_room_removed_total", "counter", "Total tickets removed due to bans or operator kicks.", stats.removed.Load())
	writePromMetric(&b, "concert_room_rejected_503_total", "counter", "Total visitors refused with 503 because the waiting room queue was full.", stats.rejected503.Load())
	writePromMetric(&b, "concert_room_cleared_total", "counter", "Total waiting-room tickets cleared by operators.", stats.cleared.Load())
	writePromMetric(&b, "concert_room_token_rejected_total", "counter", "Total signed pass or lease tokens rejected during verification.", stats.tokenRejected.Load())
	writePromMetric(&b, "concert_room_lease_ceiling", "gauge", "Maximum slots reserved for the work-conserving signed lease pool.", wr.LeaseCeiling())

	// Assets
	writePromMetric(&b, "concert_assets_cap", "gauge", "Global concurrent asset request cap.", g.assets.global.Cap())
	writePromMetric(&b, "concert_assets_in_flight", "gauge", "Current in-flight asset requests.", g.assets.global.Len())
	assetsDraining := 0
	if g.assets.global.Len() > g.assets.global.Cap() {
		assetsDraining = 1
	}
	writePromMetric(&b, "concert_assets_cap_draining", "gauge", "1 while in-flight asset requests are draining down to a lower cap.", assetsDraining)
	waitPrioVal := 0
	if p, waiting := g.assets.global.HighestWaitingPriority(); waiting {
		waitPrioVal = int(p) + 2 // low=1, normal=2, high=3, critical=4
	}
	writePromMetric(&b, "concert_assets_waiting_priority", "gauge", "Highest priority tier currently queued on the global asset cap (0=none, 1=low, 2=normal, 3=high, 4=critical).", waitPrioVal)
	writePromMetric(&b, "concert_assets_active_passes", "gauge", "Active per-pass asset concurrency pools.", g.assets.users.count.Load())
	writePromMetric(&b, "concert_assets_served_total", "counter", "Total asset requests served.", stats.assetServed.Load())
	writePromMetric(&b, "concert_assets_denied_total", "counter", "Total asset requests denied (missing/invalid pass).", stats.assetDenied.Load())
	fmt.Fprintf(&b, "# HELP concert_assets_throttled_total Asset requests throttled by scope.\n# TYPE concert_assets_throttled_total counter\n")
	fmt.Fprintf(&b, "concert_assets_throttled_total{scope=\"user\"} %d\n", stats.assetUserThrottled.Load())
	fmt.Fprintf(&b, "concert_assets_throttled_total{scope=\"global\"} %d\n", stats.assetGlobalThrottled.Load())
	writePromMetric(&b, "concert_static_served_total", "counter", "Static assets served directly from local disk without hitting upstream.", stats.staticServed.Load())
	writePromMetric(&b, "concert_static_not_found_total", "counter", "Fast 404 responses for missing authoritative static assets.", stats.staticNotFound.Load())
	writePromMetric(&b, "concert_fcgi_requests_total", "counter", "Dynamic requests executed against FastCGI (php-fpm) upstreams.", stats.fcgiRequests.Load())
	writePromMetric(&b, "concert_fcgi_denied_total", "counter", "Requests blocked by FastCGI execution deny rules (403).", stats.fcgiDenied.Load())

	// Streams
	writePromMetric(&b, "concert_streams_cap", "gauge", "Maximum concurrent WebSocket/SSE stream connections.", g.streams.sem.Cap())
	writePromMetric(&b, "concert_streams_active", "gauge", "Current open stream connections.", g.streams.sem.Len())
	streamsDraining := 0
	if g.streams.sem.Len() > g.streams.sem.Cap() {
		streamsDraining = 1
	}
	writePromMetric(&b, "concert_streams_cap_draining", "gauge", "1 while active stream connections are draining down to a lower cap.", streamsDraining)
	writePromMetric(&b, "concert_streams_served_total", "counter", "Total stream connections served.", stats.streamServed.Load())
	writePromMetric(&b, "concert_streams_denied_total", "counter", "Total stream connections denied.", stats.streamDenied.Load())
	writePromMetric(&b, "concert_streams_throttled_total", "counter", "Total stream connections throttled.", stats.streamThrottled.Load())

	// Priority lane
	writePromMetric(&b, "concert_priority_lane_cap", "gauge", "Maximum concurrent priority lane requests.", g.lane.Cap())
	writePromMetric(&b, "concert_priority_lane_in_flight", "gauge", "Current in-flight priority lane requests.", g.lane.Len())
	writePromMetric(&b, "concert_priority_lane_waiting", "gauge", "Requests waiting for a priority lane slot.", g.lane.Waiting())

	// Abuse & bans
	var abuseTracked, rangeBans int64
	activeBans := 0
	if g.abuse != nil {
		abuseTracked = g.abuse.tracked()
		rangeBans = g.abuse.rangeCount()
		activeBans = len(g.abuse.bans(now))
	}
	writePromMetric(&b, "concert_abuse_tracked", "gauge", "Clients currently tracked in abuse registry.", abuseTracked)
	writePromMetric(&b, "concert_abuse_active_bans", "gauge", "Active client and range bans.", activeBans)
	writePromMetric(&b, "concert_abuse_range_bans", "gauge", "Active CIDR range bans.", rangeBans)
	writePromMetric(&b, "concert_abuse_strikes_total", "counter", "Total abuse strikes recorded.", stats.abuseStrikes.Load())
	writePromMetric(&b, "concert_abuse_bans_total", "counter", "Total bans triggered.", stats.abuseBans.Load())
	writePromMetric(&b, "concert_abuse_rejected_total", "counter", "Total requests rejected due to active bans.", stats.abuseRejected.Load())
	writePromMetric(&b, "concert_abuse_dropped_total", "counter", "Total strikes dropped because abuse table was full.", stats.abuseDropped.Load())

	// Upstream pool & latency
	healthyBackends := 0
	totalBackends := 0
	if g.upstreams != nil {
		totalBackends = len(g.upstreams.backends)
		healthyBackends = g.upstreams.healthyCount(now)
	}
	writePromMetric(&b, "concert_upstream_backends_total", "gauge", "Configured upstream origin backends.", totalBackends)
	writePromMetric(&b, "concert_upstream_backends_healthy", "gauge", "Currently healthy upstream origin backends.", healthyBackends)
	fmt.Fprintf(&b, "# HELP concert_upstream_requests_total Proxied upstream responses by status class.\n# TYPE concert_upstream_requests_total counter\n")
	fmt.Fprintf(&b, "concert_upstream_requests_total{status_class=\"2xx\"} %d\n", stats.upstream2xx.Load())
	fmt.Fprintf(&b, "concert_upstream_requests_total{status_class=\"3xx\"} %d\n", stats.upstream3xx.Load())
	fmt.Fprintf(&b, "concert_upstream_requests_total{status_class=\"4xx\"} %d\n", stats.upstream4xx.Load())
	fmt.Fprintf(&b, "concert_upstream_requests_total{status_class=\"5xx\"} %d\n", stats.upstream5xx.Load())
	writePromMetric(&b, "concert_upstream_errors_total", "counter", "Total upstream transport/circuit errors.", stats.upstreamErrors.Load())
	writePromMetric(&b, "concert_upstream_body_idle_timeouts_total", "counter", "Total non-stream upstream responses aborted due to response-body idle timeout.", stats.upstreamBodyIdleTimeouts.Load())
	stats.upstreamLatency.writePrometheus(&b, "concert_upstream_duration_seconds", "Upstream origin round-trip latency in seconds.")

	writeWordPressMetrics(&b, g, stats)
	a.writeEnterpriseMetrics(&b, stats)

	readyVal := 1
	if a.draining.Load() || (totalBackends > 0 && healthyBackends == 0) {
		readyVal = 0
	}
	writePromMetric(&b, "concert_ready", "gauge", "1 when Concert is ready to serve traffic, 0 when draining or all upstreams unhealthy.", readyVal)

	return b.String()
}

func serveMetrics(c *gin.Context, a *app) {
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "text/plain; version=0.0.4; charset=utf-8", []byte(a.renderPrometheusMetrics()))
}
