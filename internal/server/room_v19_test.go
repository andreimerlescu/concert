package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andreimerlescu/room"
)

func TestSettings_RoomV19ValidationAndConcertfileParity(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		clearConcertEnv(t)
		cfg, _, err := parseConfig(newFlagSet(), nil)
		if err != nil {
			t.Fatalf("parseConfig defaults: %v", err)
		}
		if cfg.reaper != 10*time.Second {
			t.Errorf("reaper default = %s, want 10s", cfg.reaper)
		}
		if cfg.readyGrace != 30*time.Second {
			t.Errorf("readyGrace default = %s, want 30s", cfg.readyGrace)
		}
		if cfg.idlePollTTL != 45*time.Second {
			t.Errorf("idlePollTTL default = %s, want 45s", cfg.idlePollTTL)
		}
		if cfg.upstreamBodyIdleTimeout != 30*time.Second {
			t.Errorf("upstreamBodyIdleTimeout default = %s, want 30s", cfg.upstreamBodyIdleTimeout)
		}
		if cfg.clearQueueOnStart {
			t.Errorf("clearQueueOnStart default = true, want false")
		}
		if cfg.busyHTMLFile != "" {
			t.Errorf("busyHTMLFile default = %q, want empty", cfg.busyHTMLFile)
		}
		if cfg.effectiveTokenTTL() != room.DefaultTokenTTL {
			t.Errorf("effectiveTokenTTL = %s, want %s", cfg.effectiveTokenTTL(), room.DefaultTokenTTL)
		}
	})

	t.Run("normalize bounds and cross-field rules", func(t *testing.T) {
		busyDir := t.TempDir()
		busyFile := filepath.Join(busyDir, "busy.html")
		if err := os.WriteFile(busyFile, []byte("<html>busy</html>"), 0o600); err != nil {
			t.Fatal(err)
		}

		bad := []struct {
			name   string
			mutate func(*config)
		}{
			{"ready_grace below min", func(c *config) { c.readyGrace = 4 * time.Second; c.retryAfter = 1 }},
			{"ready_grace above max", func(c *config) { c.readyGrace = 11 * time.Minute; c.tokenTTL = time.Hour }},
			{"ready_grace below 2*retry_after", func(c *config) { c.readyGrace = 10 * time.Second; c.retryAfter = 6 }},
			{"ready_grace above token_ttl", func(c *config) { c.readyGrace = 45 * time.Second; c.tokenTTL = 30 * time.Second }},
			{"ready_grace above default token_ttl", func(c *config) { c.readyGrace = 6 * time.Minute; c.tokenTTL = 0 }},
			{"idle_poll_ttl below min", func(c *config) { c.idlePollTTL = 9 * time.Second; c.retryAfter = 1 }},
			{"idle_poll_ttl above max", func(c *config) { c.idlePollTTL = 25 * time.Hour; c.tokenTTL = 24 * time.Hour }},
			{"idle_poll_ttl below 2*retry_after", func(c *config) { c.idlePollTTL = 10 * time.Second; c.retryAfter = 6 }},
			{"idle_poll_ttl above token_ttl", func(c *config) { c.idlePollTTL = 45 * time.Second; c.tokenTTL = 30 * time.Second }},
			{"idle_poll_ttl above default token_ttl", func(c *config) { c.idlePollTTL = 6 * time.Minute; c.tokenTTL = 0 }},
			{"upstream_body_idle_timeout below min", func(c *config) { c.upstreamBodyIdleTimeout = 500 * time.Millisecond }},
			{"upstream_body_idle_timeout above max", func(c *config) { c.upstreamBodyIdleTimeout = 25 * time.Hour }},
			{"busy_html missing", func(c *config) { c.busyHTMLFile = filepath.Join(busyDir, "missing.html") }},
			{"busy_html is dir", func(c *config) { c.busyHTMLFile = busyDir }},
		}
		for _, tc := range bad {
			t.Run(tc.name, func(t *testing.T) {
				cfg := testConfig("http://127.0.0.1:1")
				tc.mutate(&cfg)
				if err := cfg.normalize(); err == nil {
					t.Errorf("%s: expected normalize error", tc.name)
				}
			})
		}

		good := []struct {
			name   string
			mutate func(*config)
		}{
			{"all zero disabled", func(c *config) {
				c.readyGrace = 0
				c.idlePollTTL = 0
				c.upstreamBodyIdleTimeout = 0
			}},
			{"exact lower bounds", func(c *config) {
				c.retryAfter = 2
				c.readyGrace = 5 * time.Second
				c.idlePollTTL = 10 * time.Second
				c.upstreamBodyIdleTimeout = time.Second
			}},
			{"exact upper bounds", func(c *config) {
				c.tokenTTL = 24 * time.Hour
				c.readyGrace = 10 * time.Minute
				c.idlePollTTL = 24 * time.Hour
				c.upstreamBodyIdleTimeout = 24 * time.Hour
			}},
			{"valid busy_html", func(c *config) {
				c.busyHTMLFile = busyFile
			}},
		}
		for _, tc := range good {
			t.Run(tc.name, func(t *testing.T) {
				cfg := testConfig("http://127.0.0.1:1")
				tc.mutate(&cfg)
				if err := cfg.normalize(); err != nil {
					t.Errorf("%s: unexpected error: %v", tc.name, err)
				}
			})
		}
	})

	t.Run("unconditional room v1.9.0 setters and reset to zero", func(t *testing.T) {
		busyPath := filepath.Join(t.TempDir(), "custom-busy.html")
		if err := os.WriteFile(busyPath, []byte("<html>custom-503</html>"), 0o600); err != nil {
			t.Fatal(err)
		}

		cfg := portalTestConfig("http://127.0.0.1:1")
		cfg.readyGrace = 20 * time.Second
		cfg.idlePollTTL = 30 * time.Second
		cfg.reaper = 10 * time.Second
		cfg.upstreamBodyIdleTimeout = 25 * time.Second
		a, p, _ := newTestPortal(t, cfg, nil)

		if got := a.room.ReadyGrace(); got != 20*time.Second {
			t.Fatalf("initial ReadyGrace = %s, want 20s", got)
		}
		if got := a.room.IdlePollTTL(); got != 30*time.Second {
			t.Fatalf("initial IdlePollTTL = %s, want 30s", got)
		}
		if got := a.room.ReaperInterval(); got != 10*time.Second {
			t.Fatalf("initial ReaperInterval = %s, want 10s", got)
		}

		prevProxy := a.current().proxy
		ck, csrf := portalLogin(t, p)

		// Resetting ready_grace and idle_poll_ttl to 0s must actually disable them on room,
		// changing upstream_body_idle_timeout must rebuild the proxy, and busy_html must load.
		body, _ := json.Marshal(map[string]any{
			"ready_grace":                "0s",
			"idle_poll_ttl":              "0s",
			"upstream_body_idle_timeout": "15s",
			"busy_html":                  busyPath,
		})
		rec := portalDo(p, http.MethodPost, "/api/settings", string(body), ck, csrf, false)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST /api/settings: %d %s", rec.Code, rec.Body.String())
		}
		if got := a.room.ReadyGrace(); got != 0 {
			t.Errorf("ReadyGrace after reset to 0s = %s, want 0", got)
		}
		if got := a.room.IdlePollTTL(); got != 0 {
			t.Errorf("IdlePollTTL after reset to 0s = %s, want 0", got)
		}
		if a.current().proxy == prevProxy {
			t.Errorf("expected proxy rebuild when upstream_body_idle_timeout changed")
		}
		if got := string(a.current().busyHTML); got != "<html>custom-503</html>" {
			t.Errorf("busyHTML = %q, want custom content", got)
		}

		// Re-enabling both via hot reload applies cleanly.
		rec = portalDo(p, http.MethodPost, "/api/settings", `{"ready_grace":"15s","idle_poll_ttl":"25s"}`, ck, csrf, false)
		if rec.Code != http.StatusOK {
			t.Fatalf("re-enable: %d %s", rec.Code, rec.Body.String())
		}
		if got := a.room.ReadyGrace(); got != 15*time.Second || a.room.IdlePollTTL() != 25*time.Second {
			t.Errorf("after re-enable: ready=%s idle=%s, want 15s/25s", a.room.ReadyGrace(), a.room.IdlePollTTL())
		}

		// Restart-only clear_queue_on_start cannot be mutated live.
		rec = portalDo(p, http.MethodPost, "/api/settings", `{"clear_queue_on_start":true}`, ck, csrf, false)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("clear_queue_on_start live mutation: got %d, want 400", rec.Code)
		}
	})

	t.Run("Concertfile parity and off durations", func(t *testing.T) {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}))
		defer up.Close()

		dir := t.TempDir()
		busyPath := filepath.Join(dir, "busy.html")
		if err := os.WriteFile(busyPath, []byte("<html>site-busy</html>"), 0o600); err != nil {
			t.Fatal(err)
		}

		cfPath := filepath.Join(dir, "Concertfile")
		cf := fmt.Sprintf(`
{
    listen 127.0.0.1:0
    token_ttl 2m
    first_poll_grace 20s
    ready_grace 15s
    idle_poll_ttl 30s
    reaper 10s
    retry_after 3
    busy_html %q
    clear_queue_on_start off
    body_read_idle_timeout off
    max_upload_time off
    upstream_timeout off
    upstream_body_idle_timeout 20s
    upstream_cb_failures 5
    upstream_cb_cooldown 25s
    upstream_health_path /healthz
    upstream_health_interval 8s
}

alpha.example.test {
    upstream %s
    cap 5
}

beta.example.test {
    upstream %s
    cap 4
    first_poll_grace off
    ready_grace off
    idle_poll_ttl 0
    reaper 12s
    retry_after 4
    busy_html off
    clear_queue_on_start on
    upstream_body_idle_timeout off
    upstream_cb_failures 0
    upstream_health_path off
}
`, busyPath, up.URL, up.URL)
		if err := os.WriteFile(cfPath, []byte(cf), 0o600); err != nil {
			t.Fatal(err)
		}

		base := testConfig(up.URL)
		base.configFile = cfPath
		base.bodyReadIdleTimeout = 30 * time.Second
		base.maxUploadTime = 10 * time.Minute
		base.headerTimeout = 60 * time.Second

		vm, err := newVhostManager(base)
		if err != nil {
			t.Fatalf("newVhostManager: %v", err)
		}
		defer vm.Close()

		alpha, ok := vm.siteByName("alpha.example.test")
		if !ok {
			t.Fatal("missing alpha site")
		}
		ac := alpha.app.current().cfg
		if ac.tokenTTL != 2*time.Minute || ac.firstPollGrace != 20*time.Second ||
			ac.readyGrace != 15*time.Second || ac.idlePollTTL != 30*time.Second ||
			ac.reaper != 10*time.Second || ac.retryAfter != 3 ||
			ac.busyHTMLFile != busyPath || ac.clearQueueOnStart ||
			ac.bodyReadIdleTimeout != 0 || ac.maxUploadTime != 0 || ac.headerTimeout != 0 ||
			ac.upstreamBodyIdleTimeout != 20*time.Second || ac.upstreamCBFailures != 5 ||
			ac.upstreamCBCooldown != 25*time.Second || ac.upstreamHealthPath != "/healthz" ||
			ac.upstreamHealthInterval != 8*time.Second {
			t.Fatalf("alpha cfg mismatch: %+v", ac)
		}
		if alpha.app.room.ReadyGrace() != 15*time.Second || alpha.app.room.IdlePollTTL() != 30*time.Second || alpha.app.room.ReaperInterval() != 10*time.Second {
			t.Fatalf("alpha room timers mismatch: ready=%s idle=%s reaper=%s",
				alpha.app.room.ReadyGrace(), alpha.app.room.IdlePollTTL(), alpha.app.room.ReaperInterval())
		}

		beta, ok := vm.siteByName("beta.example.test")
		if !ok {
			t.Fatal("missing beta site")
		}
		bc := beta.app.current().cfg
		if bc.firstPollGrace != 0 || bc.readyGrace != 0 || bc.idlePollTTL != 0 ||
			bc.reaper != 12*time.Second || bc.retryAfter != 4 ||
			bc.busyHTMLFile != "" || !bc.clearQueueOnStart ||
			bc.upstreamBodyIdleTimeout != 0 || bc.upstreamCBFailures != 0 ||
			bc.upstreamHealthPath != "" {
			t.Fatalf("beta cfg mismatch: %+v", bc)
		}
		if beta.app.room.ReadyGrace() != 0 || beta.app.room.IdlePollTTL() != 0 || beta.app.room.FirstPollGrace() != 0 {
			t.Fatalf("beta room timers should be 0: ready=%s idle=%s first=%s",
				beta.app.room.ReadyGrace(), beta.app.room.IdlePollTTL(), beta.app.room.FirstPollGrace())
		}
	})
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *syncBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Reset()
}

func (s *syncBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Len()
}

func captureLogOutput(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	orig := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(orig) })
	return buf
}

// captureAppLogs redirects os.Stderr and stdlib log output while fn runs
// (including through configureLogging inside newApp). Callers must close any
// app created inside fn before fn returns so no goroutine races on os.Stderr.
func captureAppLogs(t *testing.T, fn func()) string {
	t.Helper()
	origErr := os.Stderr
	origLog := log.Writer()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	log.SetOutput(w)
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	var once sync.Once
	restore := func() {
		once.Do(func() {
			os.Stderr = origErr
			log.SetOutput(origLog)
			_ = w.Close()
			<-done
			_ = r.Close()
		})
	}
	defer restore()
	fn()
	restore()
	return buf.String()
}

func TestRestoreQueue_DropsStaleIdleAndReadyTickets(t *testing.T) {
	t.Run("drops stale idle and ready tickets on import", func(t *testing.T) {
		dir := t.TempDir()
		now := time.Now().UTC()

		snap := map[string]any{
			"version":     1,
			"exported_at": now,
			"tickets": []map[string]any{
				{
					"token":      "tok-fresh-0001",
					"created_at": now.Add(-10 * time.Second),
					"last_seen":  now.Add(-5 * time.Second),
					"last_poll":  now.Add(-5 * time.Second),
					"client_key": "203.0.113.1",
					"seen":       true,
				},
				{
					"token":      "tok-stale-idle-0002",
					"created_at": now.Add(-2 * time.Minute),
					"last_seen":  now.Add(-90 * time.Second), // > idlePollTTL (30s)
					"last_poll":  now.Add(-90 * time.Second),
					"client_key": "203.0.113.2",
					"seen":       true,
				},
				{
					"token":      "tok-stale-ready-0003",
					"created_at": now.Add(-40 * time.Second),
					"last_seen":  now.Add(-5 * time.Second),
					"last_poll":  now.Add(-5 * time.Second),
					"ready_at":   now.Add(-35 * time.Second), // > readyGrace (20s)
					"client_key": "203.0.113.3",
					"seen":       true,
				},
			},
			"passes": []any{},
		}
		raw, err := json.Marshal(snap)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(queueFilePath(dir), raw, 0o600); err != nil {
			t.Fatal(err)
		}

		cfg := testConfig("http://127.0.0.1:1")
		cfg.dataDir = dir
		cfg.readyGrace = 20 * time.Second
		cfg.idlePollTTL = 30 * time.Second
		logs := captureAppLogs(t, func() {
			a, err := newApp(cfg)
			if err != nil {
				t.Fatalf("newApp: %v", err)
			}
			defer a.Close()

			if got := a.room.LiveQueueDepth(); got != 1 {
				t.Fatalf("LiveQueueDepth = %d, want 1", got)
			}
			if _, ok := a.room.Ticket("tok-fresh-0001"); !ok {
				t.Error("expected tok-fresh-0001 to be restored")
			}
			if _, ok := a.room.Ticket("tok-stale-idle-0002"); ok {
				t.Error("expected stale idle ticket to be dropped")
			}
			if _, ok := a.room.Ticket("tok-stale-ready-0003"); ok {
				t.Error("expected stale ready ticket to be dropped")
			}
			if _, err := os.Stat(queueFilePath(dir)); !os.IsNotExist(err) {
				t.Errorf("expected queue.snapshot removed after restore, stat err=%v", err)
			}
		})
		if !strings.Contains(logs, "dropped_stale=2") {
			t.Errorf("expected dropped_stale=2 in logs, got:\n%s", logs)
		}
	})

	t.Run("discards snapshot older than effectiveTokenTTL", func(t *testing.T) {
		dir := t.TempDir()
		old := time.Now().UTC().Add(-10 * time.Minute) // > default 5m effectiveTokenTTL

		snap := map[string]any{
			"version":     1,
			"exported_at": old,
			"tickets": []map[string]any{
				{
					"token":      "tok-old-0001",
					"created_at": old.Add(-5 * time.Second),
					"last_seen":  old.Add(-1 * time.Second),
					"last_poll":  old.Add(-1 * time.Second),
					"client_key": "203.0.113.10",
					"seen":       true,
				},
			},
			"passes": []any{},
		}
		raw, _ := json.Marshal(snap)
		if err := os.WriteFile(queueFilePath(dir), raw, 0o600); err != nil {
			t.Fatal(err)
		}

		cfg := testConfig("http://127.0.0.1:1")
		cfg.dataDir = dir
		logs := captureAppLogs(t, func() {
			a, err := newApp(cfg)
			if err != nil {
				t.Fatalf("newApp: %v", err)
			}
			defer a.Close()

			if got := a.room.LiveQueueDepth(); got != 0 {
				t.Fatalf("LiveQueueDepth = %d, want 0 (stale snapshot should be discarded)", got)
			}
			if _, err := os.Stat(queueFilePath(dir)); !os.IsNotExist(err) {
				t.Errorf("stale snapshot should be removed, stat err=%v", err)
			}
		})
		if !strings.Contains(logs, "discarding stale snapshot") {
			t.Errorf("expected stale snapshot discard log, got:\n%s", logs)
		}
	})

	t.Run("discards stale snapshot using ModTime fallback when exported_at missing", func(t *testing.T) {
		dir := t.TempDir()
		p := queueFilePath(dir)
		if err := os.WriteFile(p, []byte(`{"version":1,"tickets":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-10 * time.Minute)
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}

		cfg := testConfig("http://127.0.0.1:1")
		cfg.dataDir = dir
		logs := captureAppLogs(t, func() {
			a, err := newApp(cfg)
			if err != nil {
				t.Fatalf("newApp: %v", err)
			}
			defer a.Close()

			if _, err := os.Stat(p); !os.IsNotExist(err) {
				t.Errorf("stale snapshot without exported_at should be removed via ModTime fallback, stat err=%v", err)
			}
		})
		if !strings.Contains(logs, "discarding stale snapshot") {
			t.Errorf("expected stale snapshot discard log, got:\n%s", logs)
		}
	})

	t.Run("clearQueueOnStart removes snapshot and boots empty", func(t *testing.T) {
		dir := t.TempDir()
		now := time.Now().UTC()
		snap := map[string]any{
			"version":     1,
			"exported_at": now,
			"tickets": []map[string]any{
				{
					"token":      "tok-clear-0001",
					"created_at": now.Add(-5 * time.Second),
					"last_seen":  now.Add(-1 * time.Second),
					"client_key": "203.0.113.20",
					"seen":       true,
				},
			},
			"passes": []any{},
		}
		raw, _ := json.Marshal(snap)
		if err := os.WriteFile(queueFilePath(dir), raw, 0o600); err != nil {
			t.Fatal(err)
		}

		cfg := testConfig("http://127.0.0.1:1")
		cfg.dataDir = dir
		cfg.clearQueueOnStart = true
		logs := captureAppLogs(t, func() {
			a, err := newApp(cfg)
			if err != nil {
				t.Fatalf("newApp: %v", err)
			}
			defer a.Close()

			if got := a.room.LiveQueueDepth(); got != 0 {
				t.Fatalf("LiveQueueDepth = %d, want 0", got)
			}
			if _, err := os.Stat(queueFilePath(dir)); !os.IsNotExist(err) {
				t.Errorf("snapshot should be removed by -clear-queue-on-start, stat err=%v", err)
			}
		})
		if !strings.Contains(logs, "-clear-queue-on-start") {
			t.Errorf("expected -clear-queue-on-start log, got:\n%s", logs)
		}
	})

	t.Run("warns when restored queue is at least 80 percent of maxQueue", func(t *testing.T) {
		dir := t.TempDir()
		now := time.Now().UTC()
		tickets := make([]map[string]any, 0, 4)
		for i := 0; i < 4; i++ {
			tickets = append(tickets, map[string]any{
				"token":      fmt.Sprintf("tok-hi-%04d", i),
				"created_at": now.Add(-5 * time.Second),
				"last_seen":  now.Add(-1 * time.Second),
				"client_key": fmt.Sprintf("203.0.113.%d", 30+i),
				"seen":       true,
			})
		}
		raw, _ := json.Marshal(map[string]any{
			"version":     1,
			"exported_at": now,
			"tickets":     tickets,
			"passes":      []any{},
		})
		if err := os.WriteFile(queueFilePath(dir), raw, 0o600); err != nil {
			t.Fatal(err)
		}

		cfg := testConfig("http://127.0.0.1:1")
		cfg.dataDir = dir
		cfg.maxQueue = 5 // 4 >= (5*4)/5 = 4
		logs := captureAppLogs(t, func() {
			a, err := newApp(cfg)
			if err != nil {
				t.Fatalf("newApp: %v", err)
			}
			defer a.Close()

			if got := a.room.LiveQueueDepth(); got != 4 {
				t.Fatalf("LiveQueueDepth = %d, want 4", got)
			}
		})
		if !strings.Contains(logs, ">=80% of -max-queue") {
			t.Errorf("expected >=80%% warning in log, got:\n%s", logs)
		}
	})
}

func TestVhost_ReloadDoesNotWriteOrphanQueueSnapshot(t *testing.T) {
	up := newFakeUpstream(t)
	dataDir := t.TempDir()
	cfPath := filepath.Join(t.TempDir(), "Concertfile")
	writeCF := func(capVal int) {
		cf := fmt.Sprintf(`
{
    listen 127.0.0.1:0
    data_dir %q
}

alpha.example.test {
    upstream %s
    cap %d
}
`, dataDir, up.URL(), capVal)
		if err := os.WriteFile(cfPath, []byte(cf), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeCF(1)

	base := testConfig(up.URL())
	base.configFile = cfPath
	vm, err := newVhostManager(base)
	if err != nil {
		t.Fatalf("newVhostManager: %v", err)
	}
	srv := httptest.NewServer(vm)
	defer srv.Close()

	// Park 1 slot and queue 1 visitor on alpha.example.test (setting req.Host explicitly).
	parkDone := make(chan struct{})
	go func() {
		defer close(parkDone)
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/slow", nil)
		if err != nil {
			return
		}
		req.Host = "alpha.example.test"
		resp, err := testClient.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-up.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("/slow never reached the upstream")
	}

	resp, _ := doReq(t, jarClient(), http.MethodGet, srv.URL+"/page", map[string]string{"Host": "alpha.example.test"}, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected queued 429, got %d", resp.StatusCode)
	}
	up.releaseAll()
	<-parkDone

	siteDataDir := filepath.Join(dataDir, "sites", sanitizeHostDir("alpha.example.test"))
	snapPath := queueFilePath(siteDataDir)

	// Hot reload must suppress prev's post-swap saveQueue() so no orphan snapshot is left behind.
	writeCF(2)
	if err := vm.Reload(); err != nil {
		t.Fatalf("vm.Reload: %v", err)
	}
	if _, err := os.Stat(snapPath); !os.IsNotExist(err) {
		t.Fatalf("expected no orphaned queue.snapshot after vm.Reload, stat err=%v", err)
	}

	// Real shutdown (vm.Close) still saves the snapshot normally.
	vm.Close()
	if _, err := os.Stat(snapPath); err != nil {
		t.Fatalf("expected queue.snapshot written on vm.Close, stat err=%v", err)
	}
}

func TestRoom_V19MetricsAndAgentReconcile(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	a, err := newApp(cfg)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	a.stats.rejected503.Add(7)
	a.stats.cleared.Add(11)
	a.stats.upstreamBodyIdleTimeouts.Add(3)

	m := a.renderPrometheusMetrics()
	for _, want := range []string{
		"concert_room_rejected_503_total 7\n",
		"concert_room_cleared_total 11\n",
		"concert_upstream_body_idle_timeouts_total 3\n",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %q", want)
		}
	}

	// agentPlaces.reconcile removes keys no longer present in room while keeping live ones.
	addr := netip.MustParseAddr("203.0.113.55")
	a.agents.reserve(a.room, agentKeyPrefix+"gone-session", addr, 4, time.Now())
	if got := a.agents.held(); got != 1 {
		t.Fatalf("held before reconcile = %d, want 1", got)
	}
	a.agents.reconcile(a.room)
	if got := a.agents.held(); got != 0 {
		t.Fatalf("held after reconcile = %d, want 0", got)
	}
	if got := a.agents.count(addr); got != 0 {
		t.Fatalf("addr count after reconcile = %d, want 0", got)
	}
}

func TestRoom_StartupDiagnostics(t *testing.T) {
	t.Run("warns on uncalibrated high cap and disabled liveness guards", func(t *testing.T) {
		buf := captureLogOutput(t)
		cfg := testConfig("http://127.0.0.1:1")
		cfg.capacity = 434
		cfg.maxQueue = 369
		cfg.readyGrace = 0
		cfg.idlePollTTL = 0

		logStartupDiagnostics("site shop.example.test", cfg, false)
		out := buf.String()
		if !strings.Contains(out, "high uncalibrated -cap=434") || !strings.Contains(out, "542 max concurrent upstream page slots") {
			t.Errorf("expected uncalibrated high cap warning with effective total 542, got:\n%s", out)
		}
		if !strings.Contains(out, "waiting-room liveness guard disabled") {
			t.Errorf("expected disabled liveness guard warning, got:\n%s", out)
		}
	})

	t.Run("no warnings when calibrated and liveness guards enabled", func(t *testing.T) {
		buf := captureLogOutput(t)
		cfg := testConfig("http://127.0.0.1:1")
		cfg.capacity = 434
		cfg.maxQueue = 369
		cfg.readyGrace = 30 * time.Second
		cfg.idlePollTTL = 45 * time.Second

		logStartupDiagnostics("", cfg, true)
		if buf.Len() != 0 {
			t.Errorf("expected no warnings with capacity.json and liveness guards, got:\n%s", buf.String())
		}

		cfg.upstreamCBFailures = 5
		logStartupDiagnostics("", cfg, false)
		if buf.Len() != 0 {
			t.Errorf("expected no warnings with CB enabled and liveness guards, got:\n%s", buf.String())
		}

		cfg.upstreamCBFailures = 0
		cfg.role = roleEdge
		logStartupDiagnostics("", cfg, false)
		if buf.Len() != 0 {
			t.Errorf("expected no high-cap warning on edge role, got:\n%s", buf.String())
		}
	})
}
