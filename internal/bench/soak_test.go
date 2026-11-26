package bench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ExampleLatencyReservoir demonstrates bounded-memory streaming percentile
// computation.
func ExampleLatencyReservoir() {
	r := NewLatencyReservoir(64, 42)
	for _, d := range []time.Duration{
		5 * time.Millisecond,
		10 * time.Millisecond,
		15 * time.Millisecond,
		20 * time.Millisecond,
	} {
		r.Add(d)
	}
	s := r.Snapshot()
	fmt.Printf("count=%d min=%.0fms max=%.0fms\n", s.Count, s.MinMs, s.MaxMs)
	// Output:
	// count=4 min=5ms max=20ms
}

// fakeConcertFrontDoor models Concert's waiting room, /queue/status readiness
// transitions, concert_admit cookie pass, capacity-breaker 503 shedding, and
// optional fault injection for deterministic fairness tests.
type fakeConcertFrontDoor struct {
	mu               sync.Mutex
	ticketSeq        int
	ticketPolls      map[string]int
	pollsUntilReady  int
	requeueAdmitted  bool
	emitUpstream5xx  bool
	floodHeaderKey   string
	floodHeaderVal   string
	floodHeaderSeen  atomic.Int64
	admittedBrowses  atomic.Int64
	waitingRoom503On bool
}

func newFakeConcertFrontDoor(pollsUntilReady int) *fakeConcertFrontDoor {
	return &fakeConcertFrontDoor{
		ticketPolls:     make(map[string]int),
		pollsUntilReady: pollsUntilReady,
	}
}

func (f *fakeConcertFrontDoor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.floodHeaderKey != "" && r.Header.Get(f.floodHeaderKey) == f.floodHeaderVal {
		f.floodHeaderSeen.Add(1)
		// Simulate capacity-breaker 503 shedding on stateless flood overflow.
		w.Header().Set("Retry-After", "4")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"waiting room is full","queued":false,"retry_after_seconds":4}`))
		return
	}

	if r.URL.Path == queueStatusPath {
		ticketCookie, err := r.Cookie(roomTicketCookie)
		if err != nil || ticketCookie.Value == "" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"cookies_required": true, "ready": false})
			return
		}
		f.mu.Lock()
		f.ticketPolls[ticketCookie.Value]++
		polls := f.ticketPolls[ticketCookie.Value]
		ready := polls >= f.pollsUntilReady
		pos := max(1, f.pollsUntilReady-polls+1)
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ready":    ready,
			"position": pos,
		})
		return
	}

	// Already-admitted browser carrying concert_admit.
	if admit, err := r.Cookie(concertAdmitCookie); err == nil && admit.Value != "" {
		if f.requeueAdmitted {
			// Inject the fairness bug: push an already-admitted session back into the queue.
			w.Header().Set("X-Concert-Queue", "1")
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>queued again: fetch('/queue/status')</body></html>`))
			return
		}
		if f.emitUpstream5xx {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("upstream bad gateway"))
			return
		}
		f.admittedBrowses.Add(1)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>admitted page</body></html>`))
		return
	}

	// Returning queued visitor whose ticket reached ready==true gets admitted.
	if ticketCookie, err := r.Cookie(roomTicketCookie); err == nil && ticketCookie.Value != "" {
		f.mu.Lock()
		ready := f.ticketPolls[ticketCookie.Value] >= f.pollsUntilReady
		f.mu.Unlock()
		if ready {
			http.SetCookie(w, &http.Cookie{
				Name:     concertAdmitCookie,
				Value:    "pass-" + ticketCookie.Value,
				Path:     "/",
				HttpOnly: true,
			})
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>welcome admitted visitor</body></html>`))
			return
		}
	}

	// First arrival without ticket: place in waiting room.
	f.mu.Lock()
	f.ticketSeq++
	ticket := fmt.Sprintf("t-%d", f.ticketSeq)
	f.mu.Unlock()

	http.SetCookie(w, &http.Cookie{Name: roomTicketCookie, Value: ticket, Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: roomProbeCookie, Value: "1", Path: "/"})
	w.Header().Set("X-Concert-Queue", "1")
	w.Header().Set("Content-Type", "text/html")
	if f.waitingRoom503On {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_, _ = w.Write([]byte(`<html><body>waiting room polling /queue/status</body></html>`))
}

func TestClassifySoakResponse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		status      int
		headers     http.Header
		body        string
		wantOutcome soakOutcome
		wantQueued  bool
		wantAdmit   bool
	}{
		{
			name:        "waiting room 200 via X-Concert-Queue",
			status:      http.StatusOK,
			headers:     http.Header{"X-Concert-Queue": []string{"1"}},
			body:        "<html>waiting</html>",
			wantOutcome: outcomeQueued,
			wantQueued:  true,
		},
		{
			name:        "waiting room 503 with room_ticket cookie",
			status:      http.StatusServiceUnavailable,
			headers:     http.Header{"Set-Cookie": []string{"room_ticket=abc; Path=/"}},
			body:        "<html>waiting /queue/status</html>",
			wantOutcome: outcomeWaitingRoom503,
			wantQueued:  true,
		},
		{
			name:        "capacity breaker 503 json",
			status:      http.StatusServiceUnavailable,
			headers:     http.Header{"Retry-After": []string{"4"}},
			body:        `{"error":"waiting room is full","queued":false,"retry_after_seconds":4}`,
			wantOutcome: outcomeCapacityBreaker503,
		},
		{
			name:        "capacity breaker 503 html data-retry-after",
			status:      http.StatusServiceUnavailable,
			headers:     http.Header{"Retry-After": []string{"5"}},
			body:        `<body data-retry-after="5">busy</body>`,
			wantOutcome: outcomeCapacityBreaker503,
		},
		{
			name:        "plain upstream 503 without breaker or queue markers",
			status:      http.StatusServiceUnavailable,
			headers:     http.Header{},
			body:        "origin unavailable",
			wantOutcome: outcomeUpstream5xx,
		},
		{
			name:        "upstream 502",
			status:      http.StatusBadGateway,
			headers:     http.Header{},
			body:        "bad gateway",
			wantOutcome: outcomeUpstream5xx,
		},
		{
			name:        "queued 429 json api",
			status:      http.StatusTooManyRequests,
			headers:     http.Header{"Retry-After": []string{"5"}},
			body:        `{"queued":true,"status_url":"/queue/status"}`,
			wantOutcome: outcomeQueued,
			wantQueued:  true,
		},
		{
			name:        "plain 429 throttle",
			status:      http.StatusTooManyRequests,
			headers:     http.Header{"Retry-After": []string{"2"}},
			body:        "rate limited",
			wantOutcome: outcomeThrottled429,
		},
		{
			name:        "admitted 200 with concert_admit cookie",
			status:      http.StatusOK,
			headers:     http.Header{"Set-Cookie": []string{"concert_admit=signed-pass; Path=/; HttpOnly"}},
			body:        "<html>shop home</html>",
			wantOutcome: outcomeOK,
			wantAdmit:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := &http.Response{
				StatusCode: tc.status,
				Header:     tc.headers,
			}
			cls := classifySoakResponse(resp, []byte(tc.body))
			if cls.outcome != tc.wantOutcome {
				t.Errorf("outcome = %v, want %v", cls.outcome, tc.wantOutcome)
			}
			if cls.queued != tc.wantQueued {
				t.Errorf("queued = %v, want %v", cls.queued, tc.wantQueued)
			}
			if cls.gotAdmit != tc.wantAdmit {
				t.Errorf("gotAdmit = %v, want %v", cls.gotAdmit, tc.wantAdmit)
			}
		})
	}
}

func TestLatencyReservoir_BoundedMemoryAndPercentiles(t *testing.T) {
	t.Parallel()
	const capN = 256
	const totalN = 100_000

	r := NewLatencyReservoir(capN, 99)
	for i := 1; i <= totalN; i++ {
		r.Add(time.Duration(i%100+1) * time.Millisecond)
	}
	if r.Capacity() != capN {
		t.Fatalf("Capacity() = %d, want %d", r.Capacity(), capN)
	}
	if len(r.samples) != capN {
		t.Fatalf("retained samples = %d, want strictly bounded %d", len(r.samples), capN)
	}
	snap := r.Snapshot()
	if snap.Count != totalN {
		t.Fatalf("Count = %d, want %d", snap.Count, totalN)
	}
	if snap.MinMs != 1 || snap.MaxMs != 100 {
		t.Errorf("min/max = (%.2f, %.2f), want (1, 100)", snap.MinMs, snap.MaxMs)
	}
	if snap.MeanMs < 49 || snap.MeanMs > 52 {
		t.Errorf("mean = %.2fms, want ~50.5ms", snap.MeanMs)
	}
	if snap.P50Ms < 35 || snap.P50Ms > 65 || snap.P95Ms < 80 || snap.P99Ms < 90 {
		t.Errorf("unexpected percentiles from uniform [1..100]ms: %+v", snap)
	}
}

func TestRunSoak_QueueFairnessPass(t *testing.T) {
	t.Parallel()
	front := newFakeConcertFrontDoor(2)
	front.floodHeaderKey = "X-Flood-Cohort"
	front.floodHeaderVal = "lemmings"
	front.waitingRoom503On = true

	srv := httptest.NewServer(front)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL + "/")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	opts := SoakProfileDefaults(ProfileFairness)
	opts.Target = u
	opts.Duration = 3 * time.Second
	opts.MaxRequests = 250
	opts.HumanSessions = 6
	opts.FloodWorkers = 8
	opts.PollInterval = 2 * time.Millisecond
	opts.BrowsePaths = []string{"/", "/catalog", "/checkout"}
	opts.FloodHeader = http.Header{"X-Flood-Cohort": []string{"lemmings"}}
	opts.Seed = 7

	rep, err := RunSoak(t.Context(), opts)
	if err != nil {
		t.Fatalf("RunSoak: %v", err)
	}
	if !rep.Pass {
		t.Fatalf("expected fairness PASS, got FAIL: %s (human=%+v flood=%+v)", rep.Verdict, rep.Human, rep.Flood)
	}
	if rep.Human.Admissions < 1 {
		t.Errorf("Human.Admissions = %d, want >= 1", rep.Human.Admissions)
	}
	if rep.Human.StatusPolls < 2 {
		t.Errorf("Human.StatusPolls = %d, want >= 2", rep.Human.StatusPolls)
	}
	if rep.Human.WaitingRoom503 < 1 {
		t.Errorf("Human.WaitingRoom503 = %d, want >= 1", rep.Human.WaitingRoom503)
	}
	if rep.Human.RequeuedAfterAdmit != 0 {
		t.Errorf("Human.RequeuedAfterAdmit = %d, want 0", rep.Human.RequeuedAfterAdmit)
	}
	if rep.Human.Upstream5xx != 0 {
		t.Errorf("Human.Upstream5xx = %d, want 0", rep.Human.Upstream5xx)
	}
	if rep.Flood.CapacityBreaker503 < 1 {
		t.Errorf("Flood.CapacityBreaker503 = %d, want >= 1", rep.Flood.CapacityBreaker503)
	}
	if front.admittedBrowses.Load() < 1 {
		t.Errorf("expected admitted humans to continue browsing after admission")
	}
	if front.floodHeaderSeen.Load() < 1 {
		t.Errorf("expected flood cohort custom header to reach server")
	}

	var summary bytes.Buffer
	SummarizeSoak(&summary, rep)
	for _, want := range []string{"profile:", "verdict:  PASS:", "cohort human", "cohort flood", "capacity_breaker_503=", "waiting_room_503="} {
		if !strings.Contains(summary.String(), want) {
			t.Errorf("SummarizeSoak missing %q:\n%s", want, summary.String())
		}
	}
}

func TestRunSoak_DetectsRequeueAfterAdmitAndUpstream5xx(t *testing.T) {
	t.Parallel()

	t.Run("requeue after admission fails fairness", func(t *testing.T) {
		t.Parallel()
		front := newFakeConcertFrontDoor(1)
		front.requeueAdmitted = true
		srv := httptest.NewServer(front)
		t.Cleanup(srv.Close)
		u, _ := url.Parse(srv.URL + "/")

		opts := SoakProfileDefaults(ProfileFairness)
		opts.Target = u
		opts.Duration = 2 * time.Second
		opts.MaxRequests = 80
		opts.HumanSessions = 4
		opts.FloodWorkers = 0
		opts.PollInterval = 2 * time.Millisecond
		opts.Seed = 11

		rep, err := RunSoak(t.Context(), opts)
		if err != nil {
			t.Fatalf("RunSoak: %v", err)
		}
		if rep.Pass {
			t.Fatalf("expected FAIL on post-admit re-queue, got PASS: %+v", rep)
		}
		if rep.Human.RequeuedAfterAdmit == 0 {
			t.Errorf("Human.RequeuedAfterAdmit = 0, want > 0")
		}
		if !strings.Contains(rep.Verdict, "re-queued") {
			t.Errorf("verdict %q should mention re-queued", rep.Verdict)
		}
	})

	t.Run("upstream 5xx on human session fails fairness", func(t *testing.T) {
		t.Parallel()
		front := newFakeConcertFrontDoor(1)
		front.emitUpstream5xx = true
		srv := httptest.NewServer(front)
		t.Cleanup(srv.Close)
		u, _ := url.Parse(srv.URL + "/")

		opts := SoakProfileDefaults(ProfileFairness)
		opts.Target = u
		opts.Duration = 2 * time.Second
		opts.MaxRequests = 80
		opts.HumanSessions = 4
		opts.FloodWorkers = 0
		opts.PollInterval = 2 * time.Millisecond
		opts.Seed = 13

		rep, err := RunSoak(t.Context(), opts)
		if err != nil {
			t.Fatalf("RunSoak: %v", err)
		}
		if rep.Pass {
			t.Fatalf("expected FAIL on human upstream 5xx, got PASS: %+v", rep)
		}
		if rep.Human.Upstream5xx == 0 {
			t.Errorf("Human.Upstream5xx = 0, want > 0")
		}
		if !strings.Contains(rep.Verdict, "upstream 5xx") {
			t.Errorf("verdict %q should mention upstream 5xx", rep.Verdict)
		}
	})
}

func TestRunSoak_ConcurrentCancellationUnderRace(t *testing.T) {
	t.Parallel()
	front := newFakeConcertFrontDoor(1)
	front.floodHeaderKey = "X-Flood"
	front.floodHeaderVal = "1"

	startedCh := make(chan struct{})
	var startOnce sync.Once
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startOnce.Do(func() { close(startedCh) })
		front.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(wrapped)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		select {
		case <-startedCh:
			cancel()
		case <-t.Context().Done():
		}
	}()

	opts := SoakProfileDefaults(ProfileFairness)
	opts.Target = u
	opts.Duration = 10 * time.Second
	opts.HumanSessions = 8
	opts.FloodWorkers = 12
	opts.PollInterval = 2 * time.Millisecond
	opts.FloodHeader = http.Header{"X-Flood": []string{"1"}}

	rep, err := RunSoak(ctx, opts)
	if err != nil {
		t.Fatalf("RunSoak under cancellation: %v", err)
	}
	if rep == nil {
		t.Fatal("expected non-nil SoakReport on cancellation")
	}
}

func TestCLI_SoakProfileAndMixRealAndFlood(t *testing.T) {
	t.Parallel()
	front := newFakeConcertFrontDoor(1)
	front.floodHeaderKey = "X-Allowlist-Surge"
	front.floodHeaderVal = "1"
	srv := httptest.NewServer(front)
	t.Cleanup(srv.Close)

	reportPath := filepath.Join(t.TempDir(), "soak-report.json")
	var out, errOut bytes.Buffer
	err := CLI([]string{
		"-target", srv.URL + "/",
		"-profile", "soak-100k",
		"-mix-real-and-flood",
		"-humans", "4",
		"-flood", "6",
		"-soak-connections", "120",
		"-soak-duration", "3s",
		"-poll-interval", "2ms",
		"-flood-header", "X-Allowlist-Surge: 1",
		"-out", reportPath,
		"-quiet",
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("CLI soak-100k failed: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errOut.String())
	}

	if !strings.Contains(out.String(), "profile:  soak-100k") || !strings.Contains(out.String(), "verdict:  PASS:") {
		t.Errorf("unexpected CLI summary:\n%s", out.String())
	}

	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read soak report json: %v", err)
	}
	var parsed SoakReport
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal soak report: %v", err)
	}
	if !parsed.Pass || parsed.Profile != ProfileSoak100k || parsed.Human.Admissions < 1 || parsed.Flood.CapacityBreaker503 < 1 {
		t.Errorf("unexpected JSON soak report: %+v", parsed)
	}

	// Unknown profile must be rejected cleanly.
	if err := CLI([]string{"-target", srv.URL + "/", "-profile", "unknown-profile"}, &out, &errOut); err == nil {
		t.Errorf("expected error for unknown -profile")
	}
}
