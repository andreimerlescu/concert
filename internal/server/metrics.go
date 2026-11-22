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

	"github.com/andreimerlescu/concert/internal/capacity"
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

	// Assets
	writePromMetric(&b, "concert_assets_cap", "gauge", "Global concurrent asset request cap.", g.assets.global.Cap())
	writePromMetric(&b, "concert_assets_in_flight", "gauge", "Current in-flight asset requests.", g.assets.global.Len())
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
	stats.upstreamLatency.writePrometheus(&b, "concert_upstream_duration_seconds", "Upstream origin round-trip latency in seconds.")

	// Audit & cluster sync
	var auditEvents, auditErrors int64
	if a.audit != nil {
		auditEvents = a.audit.written.Load()
		auditErrors = a.audit.errors.Load()
	}
	writePromMetric(&b, "concert_audit_events_total", "counter", "Total tamper-evident audit log events written.", auditEvents)
	writePromMetric(&b, "concert_audit_errors_total", "counter", "Total audit log write errors.", auditErrors)
	writePromMetric(&b, "concert_cluster_sync_sent_total", "counter", "Total cluster ban sync events published.", stats.clusterSyncSent.Load())
	writePromMetric(&b, "concert_cluster_sync_received_total", "counter", "Total cluster ban sync events applied from peers.", stats.clusterSyncRecv.Load())
	writePromMetric(&b, "concert_cluster_sync_errors_total", "counter", "Total cluster state synchronization errors.", stats.clusterSyncErrors.Load())

	var emailQueued int
	var emailSent, emailErrs int64
	if a.mailer != nil {
		emailQueued, emailSent, emailErrs = a.mailer.Metrics()
	}
	writePromMetric(&b, "concert_email_queued_events", "gauge", "Pending operational events queued for scheduled administrator email digest.", emailQueued)
	writePromMetric(&b, "concert_email_sent_total", "counter", "Total administrator digest emails successfully delivered.", emailSent)
	writePromMetric(&b, "concert_email_errors_total", "counter", "Total administrator digest email delivery failures.", emailErrs)
	writePromMetric(&b, "concert_email_cluster_deduped_total", "counter", "Shared cluster alert events deduplicated via Redis peer lease.", stats.emailClusterDeduped.Load())

	if a.fastlane != nil {
		used, maxRec, unresolved := a.fastlane.JournalStats()
		writePromMetric(&b, "concert_fastlane_records_used", "gauge", "Fast-lane receipt records currently stored in fastlane.jsonl.", used)
		writePromMetric(&b, "concert_fastlane_records_max", "gauge", "Configured max_records ceiling for fastlane.jsonl.", maxRec)
		writePromMetric(&b, "concert_fastlane_unresolved", "gauge", "Unresolved fast-lane receipts in pending or unknown state awaiting reconciliation.", unresolved)
	}

	a.writeTierMetrics(&b)

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

// writeTierMetrics adds the edge or leaf tier's metrics; see topology.go.
func (a *app) writeTierMetrics(b *strings.Builder) {
	t := a.topo
	if t == nil {
		return
	}
	fmt.Fprintf(b, "# HELP concert_node_info Node role and ID.\n# TYPE concert_node_info gauge\nconcert_node_info{role=%q,node=%q} 1\n", t.role, t.node)
	switch {
	case t.isEdge():
		e := t.edge
		if p := e.lastPlan.Load(); p != nil {
			writePromMetric(b, "concert_edge_leaves_usable", "gauge", "Leaves counted in the last capacity plan.", p.Leaves)
			writePromMetric(b, "concert_edge_leaf_slots", "gauge", "Page slots the leaves offer this edge.", p.Total)
			writePromMetric(b, "concert_edge_planned_cap", "gauge", "Room capacity planned from the leaves.", p.Cap)
		}
		writePromMetric(b, "concert_edge_leaf_backpressure_total", "counter", "Leaf answers refusing a request for capacity.", e.backpressure.Load())
		writePromMetric(b, "concert_edge_upstream_retries_total", "counter", "Requests re-sent to another upstream.", e.retries.Load())
		writePromMetric(b, "concert_edge_leaf_poll_errors_total", "counter", "Failed leaf state reads.", e.pollErrors.Load())
		writePromMetric(b, "concert_edge_ban_push_errors_total", "counter", "Failed ban snapshot pushes.", e.pushErrors.Load())
	case t.isLeaf():
		l := t.leaf
		writePromMetric(b, "concert_leaf_host_cap", "gauge", "Page requests the host serves at once.", l.gate.Cap())
		writePromMetric(b, "concert_leaf_hop_in_flight", "gauge", "Edge page requests holding host slots.", l.gate.InUse(capacity.HopPriority)+l.gate.InUse(capacity.Hop))
		writePromMetric(b, "concert_leaf_direct_in_flight", "gauge", "Direct page requests holding host slots.", l.gate.InUse(capacity.Direct))
		writePromMetric(b, "concert_leaf_hop_accepted_total", "counter", "Verified hop claims.", l.accepted.Load())
		writePromMetric(b, "concert_leaf_hop_rejected_total", "counter", "Refused hop claims.", l.rejected.Load())
		writePromMetric(b, "concert_leaf_hop_replayed_total", "counter", "Hop claims refused as replayed nonces.", l.replayed.Load())
		writePromMetric(b, "concert_leaf_hop_mtls_rejected_total", "counter", "Hop claims refused for missing verified mTLS client certificate.", l.mtlsRejected.Load())
		writePromMetric(b, "concert_leaf_hop_backpressure_total", "counter", "Hop requests refused for capacity.", l.backpressed.Load())
		writePromMetric(b, "concert_leaf_rebench_total", "counter", "Completed drained on-demand capacity re-benchmarks.", l.rebenchTotal.Load())
		silent := 0
		if _, r := l.monitor.view(); r != nil && r.Recovered.IsZero() {
			silent = 1
		}
		writePromMetric(b, "concert_leaf_app_silent", "gauge", "1 while the application is silent.", silent)
	}
}
