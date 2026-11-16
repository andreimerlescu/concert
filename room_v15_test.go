package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// Concert on room v1.5.0 with none of its new features turned on: the new
// /queue/status/{id} route is reserved and quiet, and every response a
// queued visitor gets is the one it got on v1.4.0.

func TestRoomV15_TicketStatusPathsAreReserved(t *testing.T) {
	for name, args := range map[string][]string{
		"bypass under status": {"-bypass", "/queue/status/abc"},
		"assets under status": {"-assets", "/queue/status/x/*"},
		"ban path under it":   {"-ban-paths", "/queue/status/"},
	} {
		t.Run(name, func(t *testing.T) {
			clearConcertEnv(t)
			_, _, err := parseConfig(newFlagSet(), args)
			if err == nil || !strings.Contains(err.Error(), "reserved by concert") {
				t.Errorf("%v: got %v, want a reserved-path error", args, err)
			}
		})
	}
	clearConcertEnv(t)
	if _, _, err := parseConfig(newFlagSet(), []string{"-bypass", "/queue/statusboard"}); err != nil {
		t.Errorf("a path that only shares the prefix is not reserved: %v", err)
	}
}

func TestRoomV15_TicketStatusIsQuietAndNeverProxied(t *testing.T) {
	up := newFakeUpstream(t)
	_, front := newTestApp(t, testConfig(up.URL()), up)

	resp, body := get(t, front.URL+"/queue/status/not-a-ticket", nil)
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(body), `"waiting":false`) {
		t.Errorf("unknown ticket ID: got %d %s, want room's 404", resp.StatusCode, body)
	}
	if n := up.hitsFor("/queue/status/not-a-ticket"); n != 0 {
		t.Errorf("room's status route reached the origin %d time(s)", n)
	}

	skip := accessLogSkipper(testConfig(up.URL()))
	for path, want := range map[string]bool{
		"/queue/status": true, "/queue/status/abc": true, "/_room/healthz": true,
		"/queue/statusboard": false, "/page": false,
	} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, path, nil)
		if got := skip(c); got != want {
			t.Errorf("access log skips %s: %v, want %v", path, got, want)
		}
	}
}

// A successful /queue/status/{id} view is as quiet in the history as
// /queue/status; a failed one (an unknown ID) is still recorded.
func TestRoomV15_HistoryLeavesTicketStatusOut(t *testing.T) {
	a, p, _, _, _ := historyPortal(t, nil)
	quiet := p.history.quiet(a.current())
	for path, want := range map[string]bool{"/queue/status/abc": true, "/queue/status": true, "/queue/statusx": false} {
		if got := matchesAny(quiet, path); got != want {
			t.Errorf("history quiet for %s: %v, want %v", path, got, want)
		}
	}
}

// The waiting page and the 429 body are what v1.4.0 served, byte for byte.
func TestRoomV15_QueuedResponsesUnchanged(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	_, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	resp, body := get(t, front.URL+"/page", map[string]string{"Accept": "text/html"})
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") ||
		!hasCookie(resp, "room_ticket") || !strings.Contains(string(body), "<html") {
		t.Errorf("queued browser: got %d %s, want the waiting page with a room_ticket", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	resp, body = get(t, front.URL+"/api/x", nil)
	const want = `{"hint":"keep the room_ticket cookie and retry to hold your position","queued":true,"retry_after_seconds":5,"status_url":"/queue/status"}`
	if resp.StatusCode != http.StatusTooManyRequests || string(body) != want || resp.Header.Get("Retry-After") != "5" ||
		!hasCookie(resp, "room_ticket") {
		t.Errorf("queued API client: got %d Retry-After=%q %s, want 429 %s", resp.StatusCode, resp.Header.Get("Retry-After"), body, want)
	}
}

// With no leases in use room writes the version 1 format, which room v1.4.0
// can still import: a rollback keeps the saved line.
func TestRoomV15_SavedQueueIsVersion1(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.dataDir = t.TempDir()
	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(a.handler)
	fillSlot(t, front, up)
	queueJarClient(t, front)
	up.releaseAll()
	front.Close()
	a.Close()

	raw, err := os.ReadFile(queueFilePath(cfg.dataDir))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version int               `json:"version"`
		Tickets []json.RawMessage `json:"tickets"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 || len(doc.Tickets) != 1 {
		t.Errorf("queue.snapshot: version %d with %d ticket(s), want version 1 with 1", doc.Version, len(doc.Tickets))
	}
}
