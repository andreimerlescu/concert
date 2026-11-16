package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// line fakes Concert's line for --wait: it answers queued twice, then
// admits. It records every session header it saw and any payment attempt.
type line struct {
	mu       sync.Mutex
	sessions []string
	paid     bool
	left     int
	offer    bool
}

func (l *line) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch r.URL.Path {
	case "/_concert/session":
		_ = json.NewEncoder(w).Encode(map[string]any{"session": "abc.1.mac"})
	case "/_concert/payment":
		l.paid = true
		w.WriteHeader(http.StatusPaymentRequired)
	case "/drop":
		l.sessions = append(l.sessions, r.Header.Get("Concert-Session"))
		if l.left == 0 {
			_, _ = w.Write([]byte("the drop"))
			return
		}
		body := map[string]any{"queued": true, "position": l.left, "queue_depth": 9, "status_url": "https://shop.example/queue/status/id1",
			"retry_after_seconds": 5, "hint": "send the same Concert-Session header and retry to hold your position"}
		if l.offer {
			body["fast_lane"] = map[string]any{"payment_url": "https://shop.example/_concert/payment", "pass_seconds": 300,
				"offers": []any{map[string]string{"network": "xrpl:1", "asset": "XRP", "amount": "100"}}}
		}
		l.left--
		w.Header().Set("Retry-After", []string{"120", "0"}[l.left%2])
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(body)
	}
}

func TestWaitHoldsPlaceAndNeverPays(t *testing.T) {
	l := &line{left: 2, offer: true}
	srv := httptest.NewServer(l)
	t.Cleanup(srv.Close)
	c := newClient(srv.URL)
	var slept []time.Duration
	c.pause = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }

	var out bytes.Buffer
	if err := c.wait(context.Background(), "/drop", "abc.1.mac", &out); err != nil {
		t.Fatal(err)
	}
	if len(l.sessions) != 3 || l.sessions[0] != "abc.1.mac" || l.sessions[2] != "abc.1.mac" {
		t.Errorf("every retry must carry the same Concert-Session: %v", l.sessions)
	}
	// Retry-After 0 is raised to a second, 120 is clamped to a minute.
	if len(slept) != 2 || slept[0] != minRetry || slept[1] != maxRetry {
		t.Errorf("pauses: %v, want [1s 1m]", slept)
	}
	got := out.String()
	for _, want := range []string{"position 2 of 9", "position 1 of 9", "https://shop.example/queue/status/id1",
		"fast lane", "100 XRP on xrpl:1", "does not pay", "200 OK\nthe drop"} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "fast lane") != 1 {
		t.Errorf("the offer should be reported once:\n%s", got)
	}
	if l.paid {
		t.Error("--wait must never pay")
	}
}

func TestWaitStopsWhenCancelled(t *testing.T) {
	srv := httptest.NewServer(&line{left: 5})
	t.Cleanup(srv.Close)
	c := newClient(srv.URL) // the real pause, which the context ends
	ctx, cancel := context.WithCancel(context.Background())
	c.pause = func(_ context.Context, d time.Duration) error {
		cancel()
		return pause(ctx, d)
	}
	err := c.wait(ctx, "/drop", "abc.1.mac", &bytes.Buffer{})
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "position 5") {
		t.Fatalf("cancelled wait: %v", err)
	}
}

func TestWaitReportsRefusals(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/capped":
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"queued":false,"error":"agent_places_exceeded"}`))
		case "/full":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"queued":false,"error":"waiting room is full"}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newClient(srv.URL)
	c.pause = func(context.Context, time.Duration) error { t.Error("a refusal must not be retried"); return nil }
	if err := c.wait(context.Background(), "/capped", "s", &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "agent_places_exceeded") {
		t.Errorf("capped: %v", err)
	}
	var out bytes.Buffer
	if err := c.wait(context.Background(), "/full", "s", &out); err == nil || !strings.Contains(out.String(), "waiting room is full") {
		t.Errorf("full: %v %q", err, out.String())
	}
}

// --wait renews the saved session, needs no wallet keys, and leaves the
// state file unlocked while it waits.
func TestRunWaitUsesSavedSession(t *testing.T) {
	s := newSetup(t)
	l := &line{left: 1}
	srv := httptest.NewServer(l)
	t.Cleanup(srv.Close)
	origin := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	t.Setenv("CONCERT_ORIGIN", origin)
	delete(s.env, "CONCERT_CLIENT_SOL_KEY")
	restore := pause
	t.Cleanup(func() { pause = restore })
	pause = func(context.Context, time.Duration) error {
		unlock, err := lockState(s.file) // a payment run could take the lock now
		if err != nil {
			t.Error("the state file must not be locked while waiting")
			return nil
		}
		unlock()
		return nil
	}
	if err := s.run("--wait", "/drop"); err != nil {
		t.Fatal(err)
	}
	if len(l.sessions) != 2 || l.sessions[0] != "abc.1.mac" {
		t.Errorf("sessions sent: %v", l.sessions)
	}
	for _, bad := range [][]string{{"--wait"}, {"--wait", "drop"}, {"--wait", "/a", "--nft"}, {"--nft", "--nft"}} {
		if err := s.run(bad...); err == nil || err.Error() != usage {
			t.Errorf("%v: %v, want the usage error", bad, err)
		}
	}
}
