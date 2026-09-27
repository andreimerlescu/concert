package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func frag(t *testing.T, p *portal, ck *http.Cookie, target string) fragResponse {
	t.Helper()
	rec := portalDo(p, http.MethodGet, target, "", ck, "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", target, rec.Code, rec.Body.String())
	}
	var f fragResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &f); err != nil {
		t.Fatalf("%s: not JSON: %s", target, rec.Body.String())
	}
	return f
}

func rowsIn(html string) int {
	return strings.Count(html, "<tr data-key=")
}

func TestFragments_EssInTemplates(t *testing.T) {
	a, p, front, ck, _ := historyPortal(t, nil)
	old := a.ipinfo
	a.ipinfo = localLookup(t)
	old.close()

	get(t, front.URL+"/x", withXFF("45.138.12.24"))
	get(t, front.URL+"/y", withXFF("2001:1948::5"))

	f := frag(t, p, ck, "/api/frag/visitors")
	for _, want := range []string{
		"🇱🇹", "🇺🇸", "UAB Cherry Servers", "Internet2",
		`data-copy="45.138.12.24"`, `data-copy="0.3.86.161.45.138.12.24"`, `data-copy="2001:1948::5"`,
		"ip-badge-v4", "ip-badge-v6", "ip-badge-v8", "218785.45.138.12.24",
	} {
		if !strings.Contains(f.HTML, want) {
			t.Errorf("visitors fragment missing %q", want)
		}
	}
	if n := strings.Count(f.HTML, "ip-badge-v8"); n != 1 {
		t.Errorf("only the IPv4 client gets an 8 badge: %d", n)
	}

	d := frag(t, p, ck, "/api/frag/visitor?client=45.138.12.24")
	for _, want := range []string{"Lithuania", "45.138.12.0/24", "0.3.86.161.45.138.12.0/56"} {
		if !strings.Contains(d.HTML, want) {
			t.Errorf("visitor detail missing %q", want)
		}
	}

	if _, err := a.abuse.banFor(netip.MustParseAddr("45.138.12.24"), time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	if b := frag(t, p, ck, "/api/frag/bans"); !strings.Contains(b.HTML, "UAB Cherry Servers") {
		t.Error("the bans fragment should carry ess details")
	}
	if l := frag(t, p, ck, "/api/frag/banlog"); !strings.Contains(l.HTML, "🇱🇹") || rowsIn(l.HTML) != 1 {
		t.Errorf("the ban log fragment should carry ess details: %s", l.HTML)
	}
}

func TestFragments_VisitorDetailPaginates(t *testing.T) {
	_, p, front, ck, _ := historyPortal(t, nil)
	for i := 0; i < 30; i++ {
		get(t, front.URL+fmt.Sprintf("/r%d", i), withXFF("203.0.113.50"))
	}
	d := frag(t, p, ck, "/api/frag/visitor?client=203.0.113.50")
	if d.Total != 30 || d.Pages != 2 || !strings.Contains(d.HTML, "1–25 of 30") || !strings.Contains(d.HTML, "/r29") {
		t.Errorf("detail page 1: total=%d pages=%d", d.Total, d.Pages)
	}
	d2 := frag(t, p, ck, "/api/frag/visitor?client=203.0.113.50&page=2")
	if !strings.Contains(d2.HTML, "26–30 of 30") || !strings.Contains(d2.HTML, "/r0") {
		t.Error("detail page 2 should hold the oldest requests")
	}
	rec := portalDo(p, http.MethodGet, "/api/frag/visitor?client=192.0.2.99", "", ck, "", false)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown client: %d", rec.Code)
	}
}

func TestFragments_QueueAndBans(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := portalTestConfig(up.URL())
	cfg.capacity = 1
	a, p, front := newTestPortal(t, cfg, up)
	fillSlot(t, front, up)
	queueJarClient(t, front)
	ck, _ := portalLogin(t, p)

	q := frag(t, p, ck, "/api/frag/queue")
	if q.Total != 1 || rowsIn(q.HTML) != 1 || !strings.Contains(q.HTML, `data-action="promote"`) ||
		!strings.Contains(q.HTML, "/api/wait") {
		t.Errorf("queue fragment: total=%d %s", q.Total, q.HTML)
	}
	if none := frag(t, p, ck, "/api/frag/queue?q=nothing-matches"); none.Total != 0 {
		t.Errorf("queue filter: %d", none.Total)
	}

	if _, err := a.abuse.banFor(netip.MustParseAddr("203.0.113.9"), time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	b := frag(t, p, ck, "/api/frag/bans")
	if b.Total != 1 || !strings.Contains(b.HTML, `class="table-warning"`) || !b.Flags["enabled"] {
		t.Errorf("bans fragment: total=%d flags=%v", b.Total, b.Flags)
	}
}
