package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSetCap_ShrinkUnderLoad_StrictCeiling(t *testing.T) {
	const (
		initialCap = 8
		shrunkCap  = 3
		extraReqs  = 16
	)

	var (
		inFlight      atomic.Int32
		overallPeak   atomic.Int32
		postDrainPeak atomic.Int32
		phase2        atomic.Bool
		initialDone   atomic.Int32
	)
	recordPeak := func(p *atomic.Int32, cur int32) {
		for {
			old := p.Load()
			if cur <= old || p.CompareAndSwap(old, cur) {
				return
			}
		}
	}

	entered := make(chan struct{}, initialCap)
	releaseOne := make(chan struct{}, initialCap)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := inFlight.Add(1)
		recordPeak(&overallPeak, cur)
		if phase2.Load() {
			recordPeak(&postDrainPeak, cur)
		}
		defer inFlight.Add(-1)

		if r.URL.Path == "/hold" {
			entered <- struct{}{}
			<-releaseOne
			initialDone.Add(1)
		} else {
			time.Sleep(10 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.capacity = initialCap
	cfg.adminToken = "shrink-secret"
	cfg.abuseEnabled = false
	cfg.apiJSON = true
	a, front := newTestApp(t, cfg, nil)

	client := &http.Client{Timeout: 5 * time.Second}

	// Fill all initialCap slots with held requests.
	var holdWG sync.WaitGroup
	for i := 0; i < initialCap; i++ {
		holdWG.Add(1)
		go func() {
			defer holdWG.Done()
			resp, err := client.Get(front.URL + "/hold")
			if err != nil {
				t.Errorf("hold request: %v", err)
				return
			}
			_ = resp.Body.Close()
		}()
	}
	for i := 0; i < initialCap; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d/%d initial requests entered origin", i, initialCap)
		}
	}

	// Shrink capacity via POST /_room/cap while all 8 slots are occupied.
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/_room/cap", strings.NewReader(`{"cap":3}`))
	req.Header.Set("Authorization", "Bearer shrink-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /_room/cap: %v", err)
	}
	var capBody struct {
		Cap         int32 `json:"cap"`
		Occupancy   int   `json:"occupancy"`
		CapDraining bool  `json:"cap_draining"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&capBody); err != nil {
		t.Fatalf("decode /_room/cap: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_room/cap status = %d, want 200", resp.StatusCode)
	}
	if capBody.Cap != shrunkCap {
		t.Fatalf("cap = %d, want %d", capBody.Cap, shrunkCap)
	}
	if capBody.Occupancy != initialCap {
		t.Fatalf("occupancy = %d after shrink, want %d (in-flight slots must be preserved)", capBody.Occupancy, initialCap)
	}
	if !capBody.CapDraining {
		t.Fatalf("cap_draining = false while %d/%d in flight, want true", capBody.Occupancy, capBody.Cap)
	}
	if u := a.room.Utilization(); u < 0 || u > 1.0 {
		t.Fatalf("Utilization() = %f during shrink drain, want in [0,1]", u)
	}

	// Launch contending arrivals while oversubscribed: none may reach the origin
	// until enough held requests finish to bring occupancy strictly below shrunkCap.
	var newEnteredDuringDrain atomic.Int32
	for i := 0; i < 6; i++ {
		r, err := client.Get(front.URL + "/probe")
		if err != nil {
			t.Fatalf("probe request: %v", err)
		}
		if r.StatusCode == http.StatusOK {
			newEnteredDuringDrain.Add(1)
		}
		_ = r.Body.Close()
	}
	if got := newEnteredDuringDrain.Load(); got != 0 {
		t.Fatalf("%d new requests entered origin while %d/%d held during shrink drain", got, initialCap, shrunkCap)
	}

	// Release the first (initialCap - shrunkCap) = 5 held requests so occupancy falls
	// from 8 -> 3: still full, so no new request may enter yet.
	for i := 0; i < initialCap-shrunkCap; i++ {
		releaseOne <- struct{}{}
	}
	deadline := time.Now().Add(3 * time.Second)
	for a.room.Len() > shrunkCap && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := a.room.Len(); got != shrunkCap {
		t.Fatalf("Len() = %d after releasing 5 of 8, want %d", got, shrunkCap)
	}
	if r, err := client.Get(front.URL + "/probe"); err == nil {
		if r.StatusCode == http.StatusOK {
			t.Fatalf("new request entered origin while %d/%d still held", shrunkCap, shrunkCap)
		}
		_ = r.Body.Close()
	}

	// Release remaining 3 held requests and flood new traffic to verify strict shrunkCap ceiling.
	for i := 0; i < shrunkCap; i++ {
		releaseOne <- struct{}{}
	}
	holdWG.Wait()
	phase2.Store(true)

	var waveWG sync.WaitGroup
	for i := 0; i < extraReqs; i++ {
		waveWG.Add(1)
		go func() {
			defer waveWG.Done()
			r, err := client.Get(front.URL + "/wave")
			if err != nil {
				return
			}
			_ = r.Body.Close()
		}()
	}
	waveWG.Wait()

	if p := overallPeak.Load(); p > initialCap {
		t.Fatalf("overall peak concurrency = %d, exceeded initialCap %d during shrink", p, initialCap)
	}
	if p := postDrainPeak.Load(); p > shrunkCap {
		t.Fatalf("post-drain peak concurrency = %d, exceeded shrunkCap %d", p, shrunkCap)
	}
	if got := a.room.Len(); got != 0 {
		t.Fatalf("final Len() = %d, want 0", got)
	}
}

func TestSetCap_ShrinkViaSettings_PreservesInFlight(t *testing.T) {
	entered := make(chan struct{}, 6)
	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.capacity = 6
	cfg.abuseEnabled = false
	a, front := newTestApp(t, cfg, nil)

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := http.Get(front.URL + "/work")
			if err == nil {
				_ = r.Body.Close()
			}
		}()
	}
	for i := 0; i < 6; i++ {
		<-entered
	}

	raw, _ := json.Marshal(2)
	if err := a.changeSettings(map[string]json.RawMessage{"cap": raw}, nil, netip.Addr{}); err != nil {
		t.Fatalf("changeSettings cap=2: %v", err)
	}
	if a.room.Cap() != 2 || a.room.Len() != 6 {
		t.Fatalf("after settings shrink: cap=%d len=%d, want cap=2 len=6", a.room.Cap(), a.room.Len())
	}

	close(release)
	wg.Wait()
	if a.room.Len() != 0 {
		t.Fatalf("final Len() = %d, want 0", a.room.Len())
	}
}
