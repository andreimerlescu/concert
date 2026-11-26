//go:build enterprise

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/hop"
)

func TestRoom_EdgePriorityCollapseWarning(t *testing.T) {
	leafSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == hop.StatePath {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(hop.LeafState{
				Node:       "leaf-1",
				At:         time.Now().UTC(),
				HostCap:    50,
				CapSource:  "bench",
				EdgesSeen:  1,
				AppHealthy: true,
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer leafSrv.Close()

	cfg := testConfig(leafSrv.URL)
	cfg.role = roleEdge
	cfg.hopAutoCap = true
	cfg.hopPoll = 500 * time.Millisecond
	cfg.hopSecret = []byte("0123456789abcdef0123456789abcdef")
	cfg.capacity = 434 // default priorityCap = 434/4 = 108 >= 50 leaf slots -> room cap clamps to 1

	logs := captureAppLogs(t, func() {
		a, err := newApp(cfg)
		if err != nil {
			t.Fatalf("newApp edge: %v", err)
		}
		defer a.Close()

		plan := a.edgeRound(context.Background())
		if plan.Leaves != 1 || plan.Total != 50 || plan.Cap != 1 {
			t.Fatalf("unexpected plan: %+v (want Leaves=1 Total=50 Cap=1)", plan)
		}
		// Run a second identical round to confirm rate-limiting suppresses duplicates.
		a.edgeRound(context.Background())
	})
	if count := strings.Count(logs, "clamping waiting room cap to 1"); count != 1 {
		t.Fatalf("expected exactly 1 priority collapse warning (rate-limited), got %d:\n%s", count, logs)
	}
}
