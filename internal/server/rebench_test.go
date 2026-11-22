package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/bench"
	"github.com/andreimerlescu/concert/internal/capacity"
	"github.com/andreimerlescu/concert/internal/hop"
	"github.com/andreimerlescu/concert/internal/testsite"
)

func fastBenchTuning(t *testing.T) {
	t.Helper()
	prev := benchStartTuning
	benchStartTuning = func(o *bench.Options) {
		o.Start = 1
		o.Max = 8
		o.StageDuration = 200 * time.Millisecond
		o.Cooldown = 100 * time.Millisecond
		o.PageHits = 2
		o.AssetsPerPage = 4
	}
	t.Cleanup(func() { benchStartTuning = prev })
}

func TestRebench_LeafDrainedCalibrationAndAtomicPersist(t *testing.T) {
	fastBenchTuning(t)

	site := testsite.New(testsite.Options{PageLimit: 4, PageDelay: 15 * time.Millisecond})
	origin := httptest.NewServer(site)
	defer origin.Close()

	dir := t.TempDir()
	secret := []byte("concert-rebench-leaf-secret-0123456789ab")

	leafCfg := testConfig(origin.URL)
	leafCfg.role = roleLeaf
	leafCfg.nodeID = "leaf-cal"
	leafCfg.capacity = 20
	leafCfg.dataDir = dir
	leafCfg.adminToken = "rebench-admin-tok"
	leafCfg.hopSecret = secret
	leafCfg.hopPeers = "127.0.0.1/32,::1/128"
	leafCfg.abuseEnabled = false
	leafApp, leafSrv := newTestApp(t, leafCfg, nil)

	req, _ := http.NewRequest(http.MethodPost, leafSrv.URL+"/_room/rebench", strings.NewReader(`{"drain_wait_seconds":1}`))
	req.Header.Set("Authorization", "Bearer rebench-admin-tok")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /_room/rebench: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_room/rebench status = %d, want 200", resp.StatusCode)
	}
	var res hop.RebenchResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if res.Node != "leaf-cal" || res.NewCap < 1 || res.CapSource != "bench" || res.Lemmings < 1 {
		t.Fatalf("unexpected rebench result: %+v", res)
	}
	if leafApp.topo.leaf.rebenchmarking.Load() {
		t.Fatal("rebenchmarking flag stuck true after completion")
	}
	if got := leafApp.topo.leaf.rebenchTotal.Load(); got != 1 {
		t.Fatalf("rebenchTotal = %d, want 1", got)
	}
	if got := leafApp.topo.leaf.gate.Cap(); got != res.NewCap {
		t.Fatalf("host gate Cap() = %d, want %d", got, res.NewCap)
	}
	if fi, err := os.Stat(capacity.Path(dir)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("capacity.json stat err=%v mode=%v, want 0600", err, fi)
	}
	if fi, err := os.Stat(filepath.Join(dir, "bench-report.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("bench-report.json stat err=%v mode=%v, want 0600", err, fi)
	}
}

func TestRebench_EdgeRemoteAndLastHealthyLeafGuard(t *testing.T) {
	fastBenchTuning(t)

	site := testsite.New(testsite.Options{PageLimit: 4, PageDelay: 15 * time.Millisecond})
	origin := httptest.NewServer(site)
	defer origin.Close()

	secret := []byte("concert-rebench-edge-secret-0123456789ab")

	leafCfg := testConfig(origin.URL)
	leafCfg.role = roleLeaf
	leafCfg.nodeID = "leaf-solo"
	leafCfg.capacity = 20
	leafCfg.dataDir = t.TempDir()
	leafCfg.hopSecret = secret
	leafCfg.hopPeers = "127.0.0.1/32,::1/128"
	leafCfg.hopReplayGuard = true
	leafCfg.hopRequireNonce = true
	leafCfg.abuseEnabled = false
	_, leafSrv := newTestApp(t, leafCfg, nil)

	edgeCfg := testConfig(leafSrv.URL)
	edgeCfg.role = roleEdge
	edgeCfg.nodeID = "edge-main"
	edgeCfg.capacity = 20
	edgeCfg.priorityCap = 1
	edgeCfg.adminToken = "edge-admin-tok"
	edgeCfg.hopSecret = secret
	edgeCfg.hopAutoCap = true
	edgeCfg.abuseEnabled = false
	edgeApp, edgeSrv := newTestApp(t, edgeCfg, nil)

	// Poll once so the edge knows leaf-solo is the single usable leaf.
	plan := edgeApp.edgeRound(context.Background())
	if plan.Leaves != 1 {
		t.Fatalf("initial usable leaves = %d, want 1", plan.Leaves)
	}

	// Without force=true, draining the last usable leaf must be refused with 409.
	req, _ := http.NewRequest(http.MethodPost, edgeSrv.URL+"/_room/rebench", strings.NewReader(`{"leaf":"leaf-solo"}`))
	req.Header.Set("Authorization", "Bearer edge-admin-tok")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("guarded rebench: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("guarded last-leaf rebench status = %d, want 409", resp.StatusCode)
	}

	// With force=true, remote signed re-benchmark succeeds and updates edge plan.
	req, _ = http.NewRequest(http.MethodPost, edgeSrv.URL+"/_room/rebench", strings.NewReader(`{"leaf":"leaf-solo","force":true,"drain_wait_seconds":1}`))
	req.Header.Set("Authorization", "Bearer edge-admin-tok")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("forced rebench: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("forced rebench status = %d, want 200", resp.StatusCode)
	}
	var res hop.RebenchResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("decode remote rebench: %v", err)
	}
	if res.Node != "leaf-solo" || res.NewCap < 1 {
		t.Fatalf("unexpected remote rebench result: %+v", res)
	}
}

func TestPortal_OverviewIncludesTierViews(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	secret := []byte("concert-portal-tier-secret-0123456789abc")

	leafCfg := testConfig(origin.URL)
	leafCfg.role = roleLeaf
	leafCfg.nodeID = "leaf-ui"
	leafCfg.hostCap = 12
	leafCfg.hopSecret = secret
	leafCfg.hopPeers = "127.0.0.1/32,::1/128"
	leafCfg.portal.listen = "127.0.0.1:0"
	leafCfg.portal.allowSpec = "127.0.0.1/32,::1/128"
	leafCfg.portal.sessionTTL = time.Hour
	leafCfg.portal.pass = testPortalPass
	leafCfg.abuseEnabled = false
	leafApp, _ := newTestApp(t, leafCfg, nil)

	p, err := newPortal(leafApp)
	if err != nil {
		t.Fatalf("newPortal: %v", err)
	}
	t.Cleanup(func() {
		if p.ln != nil {
			_ = p.ln.Close()
		}
	})
	psrv := httptest.NewServer(p.engine)
	defer psrv.Close()

	cookie, csrf := portalLogin(t, p)
	req, _ := http.NewRequest(http.MethodGet, psrv.URL+"/api/overview", nil)
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/overview: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overview status = %d, want 200", resp.StatusCode)
	}
	var ov map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&ov); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	if ov["role"] != roleLeaf || ov["node"] != "leaf-ui" {
		t.Fatalf("overview role/node = %v/%v, want leaf/leaf-ui", ov["role"], ov["node"])
	}
	leafObj, ok := ov["leaf"].(map[string]any)
	if !ok || int(leafObj["host_cap"].(float64)) != 12 {
		t.Fatalf("overview leaf view missing host_cap=12: %+v", ov["leaf"])
	}
}
