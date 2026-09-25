package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// historyPortal starts concert with the portal behind a trusted proxy, so
// tests choose each request's client address with X-Forwarded-For.
func historyPortal(t *testing.T, mutate func(*config)) (*app, *portal, *httptest.Server, *http.Cookie, string) {
	t.Helper()
	up := newFakeUpstream(t)
	cfg := portalTestConfig(up.URL())
	cfg.trustedProxies = "127.0.0.1/32"
	if mutate != nil {
		mutate(&cfg)
	}
	a, p, front := newTestPortal(t, cfg, up)
	ck, csrf := portalLogin(t, p)
	return a, p, front, ck, csrf
}

func historyOf(t *testing.T, p *portal, ck *http.Cookie, ip string) map[string]any {
	t.Helper()
	rec := portalDo(p, http.MethodGet, "/api/history/client?client="+url.QueryEscape(ip), "", ck, "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("history for %s: %d %s", ip, rec.Code, rec.Body.String())
	}
	return decodeJSON(t, rec)
}

func historyList(t *testing.T, p *portal, ck *http.Cookie) map[string]any {
	t.Helper()
	rec := portalDo(p, http.MethodGet, "/api/history", "", ck, "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("history: %d %s", rec.Code, rec.Body.String())
	}
	return decodeJSON(t, rec)
}

func maps(v any) []map[string]any {
	list, _ := v.([]any)
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		m, _ := x.(map[string]any)
		out = append(out, m)
	}
	return out
}

func hitsFor(list any, name string) float64 {
	for _, m := range maps(list) {
		if m["name"] == name {
			return m["hits"].(float64)
		}
	}
	return 0
}

func TestHistory_GroupsRequestsByClient(t *testing.T) {
	_, p, front, ck, _ := historyPortal(t, nil)

	get(t, front.URL+"/one?x=1", withXFF("203.0.113.1"))
	get(t, front.URL+"/two", withXFF("203.0.113.1"))
	get(t, front.URL+"/three", withXFF("198.51.100.2"))

	if clients := maps(historyList(t, p, ck)["clients"]); len(clients) != 2 {
		t.Fatalf("clients: %v", clients)
	}
	v := historyOf(t, p, ck, "203.0.113.1")
	entries := maps(v["entries"])
	if len(entries) != 2 || entries[0]["path"] != "/two" || entries[1]["path"] != "/one?x=1" {
		t.Errorf("entries should be this client's requests, newest first: %v", entries)
	}
	if c := v["client"].(map[string]any); c["requests"] != float64(2) || c["banned_now"] != false {
		t.Errorf("client: %v", c)
	}
}

func TestHistory_BanPathRecordsTriggerAndBlockedRequests(t *testing.T) {
	_, p, front, ck, csrf := historyPortal(t, func(c *config) { c.banPaths = "/.env" })
	const ip = "203.0.113.9"

	get(t, front.URL+"/.env", withXFF(ip))
	get(t, front.URL+"/wp-login.php", withXFF(ip))
	get(t, front.URL+"/hello", withXFF(ip))
	get(t, front.URL+"/hello", withXFF(ip))

	v := historyOf(t, p, ck, ip)
	bans := maps(v["bans"])
	if len(bans) != 1 {
		t.Fatalf("bans covering the client: %v", bans)
	}
	w := bans[0]
	if w["active"] != true || w["began"] == nil || w["requests"] != float64(3) {
		t.Errorf("ban window: %v", w)
	}
	trig, _ := w["trigger"].(map[string]any)
	if trig == nil || trig["path"] != "/.env" || trig["client"] != ip {
		t.Errorf("trigger: %v", w["trigger"])
	}
	if hitsFor(w["paths"], "/hello") != 2 || hitsFor(w["paths"], "/wp-login.php") != 1 {
		t.Errorf("paths during the ban: %v", w["paths"])
	}
	if hitsFor(w["clients"], ip) != 3 {
		t.Errorf("addresses during the ban: %v", w["clients"])
	}

	entries := maps(v["entries"])
	if len(entries) != 4 {
		t.Fatalf("entries: %v", entries)
	}
	if first := entries[3]; first["triggered_ban"] != true || first["blocked"] != false {
		t.Errorf("the ban path request should be marked as starting the ban: %v", first)
	}
	for _, e := range entries[:3] {
		if e["blocked"] != true {
			t.Errorf("request during the ban not marked blocked: %v", e)
		}
	}
	c := v["client"].(map[string]any)
	if c["banned_now"] != true || c["blocked"] != float64(3) || c["bans_triggered"] != float64(1) {
		t.Errorf("client: %v", c)
	}
	if log := maps(historyList(t, p, ck)["bans"]); len(log) != 1 || log[0]["target"] != ip {
		t.Errorf("ban log: %v", log)
	}

	// Unbanning in the portal ends the window.
	if rec := portalDo(p, http.MethodDelete, "/api/bans?client="+ip, "", ck, csrf, false); rec.Code != http.StatusOK {
		t.Fatalf("unban: %d %s", rec.Code, rec.Body.String())
	}
	w = maps(historyOf(t, p, ck, ip)["bans"])[0]
	if w["active"] != false || w["end_reason"] != "lifted" || w["ended"] == nil {
		t.Errorf("after unban: %v", w)
	}
	get(t, front.URL+"/hello", withXFF(ip))
	if newest := maps(historyOf(t, p, ck, ip)["entries"])[0]; newest["blocked"] != false || newest["status"] != float64(200) {
		t.Errorf("request after the unban: %v", newest)
	}
}

func TestHistory_SuccessfulAssetsNotRecorded(t *testing.T) {
	_, p, front, ck, _ := historyPortal(t, func(c *config) {
		c.assets = "/assets/*"
		c.trustedProxies = "" // the test client is the real client
	})

	pass := admitPass(t, front)
	if resp, _ := get(t, front.URL+"/assets/app.js", withPass(pass, nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("asset with a pass: %d", resp.StatusCode)
	}
	if resp, _ := get(t, front.URL+"/assets/app.js", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("asset without a pass: %d", resp.StatusCode)
	}

	entries := maps(historyOf(t, p, ck, "127.0.0.1")["entries"])
	if len(entries) != 2 {
		t.Fatalf("want the page and the denied asset only: %v", entries)
	}
	if entries[0]["path"] != "/assets/app.js" || entries[0]["status"] != float64(403) || entries[1]["path"] != "/page" {
		t.Errorf("entries: %v", entries)
	}
}

func TestHistory_RangeBanCountsEachAddress(t *testing.T) {
	_, p, front, ck, csrf := historyPortal(t, nil)
	rec := portalDo(p, http.MethodPost, "/api/bans", `{"client":"198.51.0.0/16","duration":"1h"}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("ban: %d %s", rec.Code, rec.Body.String())
	}

	get(t, front.URL+"/a", withXFF("198.51.1.1"))
	get(t, front.URL+"/b", withXFF("198.51.2.2"))
	get(t, front.URL+"/c", withXFF("198.52.0.1")) // outside the range

	log := maps(historyList(t, p, ck)["bans"])
	if len(log) != 1 {
		t.Fatalf("ban log: %v", log)
	}
	w := log[0]
	if w["range"] != true || w["requests"] != float64(2) || w["trigger"] != nil ||
		!strings.Contains(w["source"].(string), "portal") {
		t.Errorf("range ban: %v", w)
	}

	id := strconv.FormatInt(int64(w["id"].(float64)), 10)
	rec = portalDo(p, http.MethodGet, "/api/history/ban?id="+id, "", ck, "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("ban detail: %d %s", rec.Code, rec.Body.String())
	}
	full := decodeJSON(t, rec)["ban"].(map[string]any)
	if hitsFor(full["clients"], "198.51.1.1") != 1 || hitsFor(full["clients"], "198.51.2.2") != 1 {
		t.Errorf("addresses inside the range: %v", full["clients"])
	}
	if hitsFor(full["paths"], "/a") != 1 || hitsFor(full["paths"], "/b") != 1 {
		t.Errorf("paths inside the range: %v", full["paths"])
	}
}

func TestHistory_UnbanOutsidePortalIsNoticed(t *testing.T) {
	a, p, _, ck, _ := historyPortal(t, nil)
	ip := netip.MustParseAddr("203.0.113.7")
	if _, err := a.abuse.banFor(ip, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	a.abuse.unban(ip) // as DELETE /_room/abuse does
	p.history.sweep(time.Now())

	log := maps(historyList(t, p, ck)["bans"])
	if len(log) != 1 || log[0]["active"] != false || log[0]["end_reason"] != "lifted" ||
		!strings.Contains(log[0]["lifted_by"].(string), "admin API") {
		t.Errorf("ban log: %v", log)
	}
}

func TestHistory_BansInForceAtStartAreListed(t *testing.T) {
	a, err := newApp(portalTestConfig("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	if _, err := a.abuse.banFor(netip.MustParseAddr("203.0.113.9"), 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	p, err := newPortal(a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.closeListener)
	ck, _ := portalLogin(t, p)

	log := maps(historyList(t, p, ck)["bans"])
	if len(log) != 1 || log[0]["began"] != nil || log[0]["permanent"] != true || log[0]["active"] != true {
		t.Errorf("a ban restored at startup should be listed with an unknown start: %v", log)
	}
}
