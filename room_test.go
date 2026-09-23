package main

import (
	"bufio"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/andreimerlescu/room"
)

// Concert's use of room v1.3.0: client keys, churn strikes from room's
// events, bans removing waiting visitors, the queue across restarts, and
// stream paths outside the room.

func jarClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: testClient.CheckRedirect}
}

func TestRoom_ClientKeyIsResolvedAddress(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.trustedProxies = "127.0.0.1/32"
	a, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	resp, _ := doReq(t, jarClient(), http.MethodGet, front.URL+"/api/wait", withXFF("203.0.113.7"), nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected to be queued, got %d", resp.StatusCode)
	}
	line := a.room.Queue(10)
	if len(line) != 1 || line[0].ClientKey != "203.0.113.7" {
		t.Fatalf("room should key the visitor by the address behind the trusted proxy: %+v", line)
	}
}

func TestRoom_ChurnStrikesOnlyCookielessArrivals(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.trustedProxies = "127.0.0.1/32"
	cfg.abuseStrikes = 2
	a, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	for i := 0; i < 2; i++ {
		get(t, front.URL+"/api/x", withXFF("203.0.113.9"))
	}
	eventually(t, 2*time.Second, func() bool {
		_, banned := a.abuse.banned(netip.MustParseAddr("203.0.113.9"), time.Now())
		return banned
	}, "cookie-less arrivals were not struck against the visitor's address")

	stale := map[string]string{"X-Forwarded-For": "198.51.100.4", "Cookie": "room_ticket=not-a-real-ticket"}
	for i := 0; i < 3; i++ {
		get(t, front.URL+"/api/x", stale)
	}
	time.Sleep(300 * time.Millisecond) // callbacks are asynchronous
	if _, banned := a.abuse.banned(netip.MustParseAddr("198.51.100.4"), time.Now()); banned {
		t.Error("arrivals with a stale room_ticket must not earn churn strikes (room reports StaleTicket)")
	}
}

func TestRoom_BanDropsWaitingVisitorWithoutPortal(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.trustedProxies = "127.0.0.1/32"
	a, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)

	doReq(t, jarClient(), http.MethodGet, front.URL+"/api/wait", withXFF("203.0.113.7"), nil)
	doReq(t, jarClient(), http.MethodGet, front.URL+"/api/wait", withXFF("198.51.100.4"), nil)
	if n := a.room.LiveQueueDepth(); n != 2 {
		t.Fatalf("in line: %d, want 2", n)
	}

	if _, err := a.abuse.banFor(netip.MustParseAddr("203.0.113.7"), time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	eventually(t, 2*time.Second, func() bool { return a.room.LiveQueueDepth() == 1 },
		"the ban never removed the banned visitor from room's line")
	if line := a.room.Queue(10); len(line) != 1 || line[0].ClientKey != "198.51.100.4" {
		t.Errorf("the wrong visitor was removed: %+v", line)
	}
	eventually(t, 2*time.Second, func() bool { return a.stats.removed.Load() >= 1 },
		"EventRemove was not counted")
}

func TestRoom_QueueSurvivesRestart(t *testing.T) {
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
	client := queueJarClient(t, front)
	token := ticketOf(t, client, front)

	up.releaseAll() // lets the parked request finish so the server can close
	front.Close()
	a.Close()
	if _, err := os.Stat(queueFilePath(cfg.dataDir)); err != nil {
		t.Fatalf("queue was not saved on Close: %v", err)
	}

	b, err := newApp(cfg)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	defer b.Close()
	if _, ok := b.room.Ticket(token); !ok {
		t.Error("the waiting visitor's ticket was not restored")
	}
	if _, err := os.Stat(queueFilePath(cfg.dataDir)); !os.IsNotExist(err) {
		t.Errorf("the saved queue should be removed once restored: %v", err)
	}
}

func TestRoom_UnreadableQueueFileIsSetAside(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.dataDir = t.TempDir()
	path := queueFilePath(cfg.dataDir)
	if err := os.WriteFile(path, []byte("not a queue"), 0o600); err != nil {
		t.Fatal(err)
	}

	a, err := newApp(cfg)
	if err != nil {
		t.Fatalf("an unreadable queue file must not stop startup: %v", err)
	}
	if _, err := os.Stat(path + ".bad"); err != nil {
		t.Errorf("the unreadable file should be kept as .bad: %v", err)
	}
	a.Close()
}

func TestRoom_SettingsReachRoom(t *testing.T) {
	a, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)
	ck, csrf := portalLogin(t, p)

	rec := portalDo(p, http.MethodPost, "/api/settings", `{"first_poll_grace":"45s","token_ttl":"0s"}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if got := a.room.FirstPollGrace(); got != 45*time.Second {
		t.Errorf("first-poll grace: got %s, want 45s", got)
	}
	if got := a.room.TokenTTL(); got != room.DefaultTokenTTL {
		t.Errorf("token TTL 0 should restore room's default: got %s", got)
	}

	for name, body := range map[string]string{
		"below room's minimum": `{"first_poll_grace":"5s"}`,
		"below twice retries":  `{"first_poll_grace":"10s","retry_after":6}`,
	} {
		if rec := portalDo(p, http.MethodPost, "/api/settings", body, ck, csrf, false); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, rec.Code)
		}
	}
}

func TestStream_OutsideRoomWithPassAndCap(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity = 1
	cfg.streamPaths = "/sse"
	cfg.streamCap = 1
	a, front := newTestApp(t, cfg, up)
	pass := admitPass(t, front) // admitted while a page slot is free
	fillSlot(t, front, up)      // now the room is full

	if resp, _ := get(t, front.URL+"/sse", nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("stream without a pass: got %d, want 403", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/sse", nil)
	req.Header.Set("Cookie", admitCookie+"="+pass)
	resp, err := testClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream with a pass while the room is full: got %d, want 200", resp.StatusCode)
	}
	if line, _ := bufio.NewReader(resp.Body).ReadString('\n'); line != "data: hello\n" {
		t.Fatalf("stream did not flow: %q", line)
	}

	over, _ := get(t, front.URL+"/sse", withPass(pass, nil))
	if over.StatusCode != http.StatusServiceUnavailable || over.Header.Get("Retry-After") != "5" {
		t.Errorf("stream over the cap: got %d Retry-After=%q, want 503 and 5", over.StatusCode, over.Header.Get("Retry-After"))
	}
	if a.stats.streamServed.Load() != 1 || a.stats.streamThrottled.Load() != 1 || a.stats.streamDenied.Load() != 1 {
		t.Errorf("stream counters: served=%d throttled=%d denied=%d, want 1 each",
			a.stats.streamServed.Load(), a.stats.streamThrottled.Load(), a.stats.streamDenied.Load())
	}
}
