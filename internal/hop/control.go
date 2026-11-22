package hop

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Control-plane endpoints a leaf serves. They live under /_room, which
// Concert reserves, answer only hop-signed requests of ClassControl from
// -hop-peers, and are never queued.
const (
	StatePath   = "/_room/hop/state"   // GET: the leaf's LeafState
	BansPath    = "/_room/hop/bans"    // POST: a BanSnapshot from one edge
	RebenchPath = "/_room/hop/rebench" // POST: trigger drained leaf re-benchmark
)

// LeafState is what a leaf reports to every edge that polls it. The edge
// sizes its own room from HostCap, scaled by EdgesSeen so several edges
// sharing one leaf don't each assume all of it.
type LeafState struct {
	Node    string    `json:"node"`
	Version string    `json:"version"`
	At      time.Time `json:"at"`

	// HostCap is the page requests this host serves at once, from the
	// first of: -host-cap, the benchmark's capacity.json, -cap.
	HostCap   int    `json:"host_cap"`
	CapSource string `json:"cap_source"` // "flag", "bench" or "cap"

	HopInFlight    int64 `json:"hop_in_flight"`    // hop page requests holding host slots
	DirectInFlight int64 `json:"direct_in_flight"` // direct page requests holding host slots
	QueueDepth     int64 `json:"queue_depth"`      // direct visitors waiting in the leaf's room

	AppHealthy     bool    `json:"app_healthy"` // at least one of the leaf's upstreams is healthy
	Draining       bool    `json:"draining"`
	Rebenchmarking bool    `json:"rebenchmarking,omitempty"`
	LatencyMs      float64 `json:"latency_ms"` // recent mean upstream response time

	// EdgesSeen is how many distinct edges sent hop traffic or polled in
	// the last minute, at least 1.
	EdgesSeen int `json:"edges_seen"`

	// YourShare is this leaf's demand-weighted page-slot allocation for the
	// polling edge. Zero on legacy v0.2.0 leaves (fall back to HostCap/EdgesSeen).
	YourShare int `json:"your_share,omitempty"`

	// EdgeShares maps every active edge node ID to its current slot share.
	EdgeShares map[string]int `json:"edge_shares,omitempty"`

	// BanVersions is the last ban snapshot version applied, per edge.
	BanVersions map[string]string `json:"ban_versions,omitempty"`

	Bench   *BenchSummary  `json:"bench,omitempty"`
	Silence *SilenceReport `json:"last_silence,omitempty"`
}

// Share is the part of the leaf's capacity one edge may plan for.
func (s LeafState) Share() int {
	if s.HostCap <= 0 {
		return 0
	}
	if s.YourShare > 0 {
		if s.YourShare > s.HostCap {
			return s.HostCap
		}
		return s.YourShare
	}
	n := s.EdgesSeen
	if n < 1 {
		n = 1
	}
	share := s.HostCap / n
	if share < 1 {
		share = 1
	}
	return share
}

// AllocateShares divides hostCap across active edges proportionally to their
// observed demand weights while guaranteeing every active edge a starvation
// floor and preserving Σ shares == hostCap (when hostCap >= len(weights)).
// When all weights are <= 0 (idle edges), capacity splits evenly.
func AllocateShares(hostCap int, weights map[string]float64) map[string]int {
	n := len(weights)
	if hostCap <= 0 || n == 0 {
		return nil
	}
	ids := make([]string, 0, n)
	var total float64
	for id, w := range weights {
		ids = append(ids, id)
		if w > 0 {
			total += w
		}
	}
	sort.Strings(ids)

	out := make(map[string]int, n)
	if n == 1 {
		out[ids[0]] = hostCap
		return out
	}
	if hostCap < n {
		for _, id := range ids {
			out[id] = 1
		}
		return out
	}
	if total <= 0 {
		base := hostCap / n
		rem := hostCap % n
		for i, id := range ids {
			out[id] = base
			if i < rem {
				out[id]++
			}
		}
		return out
	}

	// Reserve a starvation-prevention floor (25% of even share, at least 1)
	// per active edge, then distribute remaining slots by largest remainder.
	floor := hostCap / (n * 4)
	if floor < 1 {
		floor = 1
	}
	if maxFloor := hostCap / n; floor > maxFloor {
		floor = maxFloor
	}
	remSlots := hostCap - n*floor

	type frac struct {
		id  string
		rem float64
	}
	fracs := make([]frac, 0, n)
	assigned := 0
	for _, id := range ids {
		w := weights[id]
		if w < 0 {
			w = 0
		}
		exact := float64(remSlots) * (w / total)
		whole := int(exact)
		out[id] = floor + whole
		assigned += whole
		fracs = append(fracs, frac{id: id, rem: exact - float64(whole)})
	}
	leftover := remSlots - assigned
	sort.Slice(fracs, func(i, j int) bool {
		if fracs[i].rem != fracs[j].rem {
			return fracs[i].rem > fracs[j].rem
		}
		return fracs[i].id < fracs[j].id
	})
	for i := 0; i < leftover && i < len(fracs); i++ {
		out[fracs[i].id]++
	}
	return out
}

// Usable reports whether an edge should plan capacity on this leaf.
func (s LeafState) Usable() bool {
	return s.AppHealthy && !s.Draining && s.HostCap > 0
}

// BenchSummary is the part of a capacity benchmark a leaf reports.
type BenchSummary struct {
	At           time.Time `json:"at"`
	Lemmings     int       `json:"lemmings"`
	P95Ms        float64   `json:"p95_ms"`
	PagesCovered int       `json:"pages_covered"`
	Target       string    `json:"target"`
}

// RebenchResult summarizes a completed drained on-demand leaf re-benchmark.
type RebenchResult struct {
	Node         string    `json:"node"`
	PreviousCap  int       `json:"previous_cap"`
	NewCap       int       `json:"new_cap"`
	CapSource    string    `json:"cap_source"`
	Lemmings     int       `json:"lemmings"`
	P95Ms        float64   `json:"p95_ms"`
	PagesCovered int       `json:"pages_covered"`
	Verdict      string    `json:"verdict"`
	At           time.Time `json:"at"`
}

// SilenceReport records the load a leaf was carrying when its application
// stopped answering: the evidence an operator of bare-metal hosts needs to
// tell overload from failure.
type SilenceReport struct {
	At               time.Time `json:"at"`
	Reason           string    `json:"reason"`
	HostCap          int       `json:"host_cap"`
	HopInFlight      int64     `json:"hop_in_flight"`
	DirectInFlight   int64     `json:"direct_in_flight"`
	QueueDepth       int64     `json:"queue_depth"`
	UpstreamInFlight int64     `json:"upstream_in_flight"`
	LatencyMs        float64   `json:"latency_ms"`
	Upstream5xx      uint64    `json:"upstream_5xx_total"`
	UpstreamErrors   uint64    `json:"upstream_errors_total"`
	LastHealthy      time.Time `json:"last_healthy"`
	Recovered        time.Time `json:"recovered,omitempty"`
}

// Ban is one entry of a BanSnapshot. Client is an address, an IPv6 /64 or
// a CIDR range, exactly as Concert's ban list shows it.
type Ban struct {
	Client    string    `json:"client"`
	Range     bool      `json:"range,omitempty"`
	Permanent bool      `json:"permanent,omitempty"`
	Until     time.Time `json:"until,omitempty"`
}

// BanSnapshot is an edge's complete ban list. A leaf mirrors it: bans in the
// snapshot are applied, and bans the same edge sent before but no longer
// lists are lifted. The edge is the source of truth.
type BanSnapshot struct {
	Edge    string `json:"edge"`
	Version string `json:"version"`
	// At is when the edge read its ban list. A leaf ignores a snapshot
	// older than the last one it applied from the same edge, so a delayed
	// push can never undo a newer one.
	At   time.Time `json:"at"`
	Bans []Ban     `json:"bans"`
}

// BanVersion is a stable digest of bans, independent of order, so an edge
// pushes a snapshot only when a leaf's applied version differs. Until is
// rounded to the second: re-reading a ban must not change its version.
func BanVersion(bans []Ban) string {
	keys := make([]string, len(bans))
	for i, b := range bans {
		u := "p"
		if !b.Permanent {
			u = strconv.FormatInt(b.Until.Unix(), 10)
		}
		r := "0"
		if b.Range {
			r = "1"
		}
		keys[i] = b.Client + "|" + r + "|" + u
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return hex.EncodeToString(sum[:8])
}
