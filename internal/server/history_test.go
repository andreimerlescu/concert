package server

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/opt"
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

// startLogged starts concert with a portal the test stops itself, so the
// history log can be closed and read back before a restart.
func startLogged(t *testing.T, cfg config) (*app, *portal, *httptest.Server) {
	t.Helper()
	a, err := newApp(cfg)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	p, err := newPortal(a)
	if err != nil {
		a.Close()
		t.Fatalf("newPortal: %v", err)
	}
	return a, p, httptest.NewServer(p.wrap(a.handler))
}

func stopLogged(a *app, p *portal, front *httptest.Server) {
	front.Close()
	p.closeListener()
	a.Close()
}

func readEvents(t *testing.T, path string) []historyEvent {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("history log: %v", err)
	}
	defer f.Close()
	var out []historyEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), historyLogLineMax)
	for sc.Scan() {
		var ev historyEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("history log line is not JSON: %q", sc.Text())
		}
		out = append(out, ev)
	}
	return out
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

// ─── the history log ─────────────────────────────────────────────────────────

func TestHistoryLogPath(t *testing.T) {
	cases := []struct {
		dataDir, setting, want string
	}{
		{"", "", ""},
		{"/var/lib/concert/data", "", filepath.Join("/var/lib/concert/data", historyLogName)},
		{"/var/lib/concert/data", "off", ""},
		{"/var/lib/concert/data", "/srv/concert/history.jsonl", "/srv/concert/history.jsonl"},
		{"", "/srv/concert/history.jsonl", "/srv/concert/history.jsonl"},
	}
	for _, c := range cases {
		if got := historyLogPath(config{dataDir: c.dataDir, historyLog: c.setting}); got != c.want {
			t.Errorf("dataDir=%q history-log=%q: got %q, want %q", c.dataDir, c.setting, got, c.want)
		}
	}
}

func TestHistory_LogSurvivesRestart(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := portalTestConfig(up.URL())
	cfg.trustedProxies = "127.0.0.1/32"
	cfg.banPaths = "/.env"
	cfg.dataDir = t.TempDir()
	const ip = "203.0.113.9"

	a, p, front := startLogged(t, cfg)
	get(t, front.URL+"/hello", withXFF(ip))
	get(t, front.URL+"/.env", withXFF(ip))
	get(t, front.URL+"/wp-login.php", withXFF(ip))
	get(t, front.URL+"/x", withXFF(ip))
	stopLogged(a, p, front)

	if _, err := os.Stat(filepath.Join(cfg.dataDir, historyLogName)); err != nil {
		t.Fatalf("history log not written: %v", err)
	}

	b, q, front2 := startLogged(t, cfg)
	defer stopLogged(b, q, front2)
	ck, _ := portalLogin(t, q)

	v := historyOf(t, q, ck, ip)
	entries := maps(v["entries"])
	if len(entries) != 4 {
		t.Fatalf("entries after restart: %v", entries)
	}
	if entries[2]["path"] != "/.env" || entries[2]["triggered_ban"] != true {
		t.Errorf("the request that started the ban was not restored: %v", entries[2])
	}
	if entries[0]["blocked"] != true || entries[3]["blocked"] != false {
		t.Errorf("blocked flags after restart: %v", entries)
	}
	bans := maps(v["bans"])
	if len(bans) != 1 {
		t.Fatalf("bans after restart: %v", bans)
	}
	w := bans[0]
	trig, _ := w["trigger"].(map[string]any)
	if w["began"] == nil || w["active"] != true || w["requests"] != float64(2) || trig == nil || trig["path"] != "/.env" {
		t.Errorf("ban window after restart (known start, trigger, 2 blocked): %v", w)
	}
	if log := maps(historyList(t, q, ck)["bans"]); len(log) != 1 {
		t.Errorf("a restart must not duplicate the ban in the log: %v", log)
	}
}

func TestHistory_BlockedFloodIsAggregated(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := portalTestConfig(up.URL())
	cfg.trustedProxies = "127.0.0.1/32"
	cfg.dataDir = t.TempDir()
	const ip = "203.0.113.20"
	n := historyRawPerBan + 30

	a, p, front := startLogged(t, cfg)
	if _, err := a.abuse.banFor(netip.MustParseAddr(ip), time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		get(t, front.URL+"/probe-"+strconv.Itoa(i%3), withXFF(ip))
	}
	stopLogged(a, p, front)

	raw, agg := 0, int64(0)
	for _, ev := range readEvents(t, filepath.Join(cfg.dataDir, historyLogName)) {
		switch {
		case ev.T == evRequest && ev.Blocked:
			raw++
		case ev.T == evAgg:
			agg += ev.Count
		}
	}
	if raw != historyRawPerBan || agg != 30 {
		t.Errorf("log lines: %d raw blocked requests and %d aggregated, want %d and 30", raw, agg, historyRawPerBan)
	}

	b, q, front2 := startLogged(t, cfg)
	defer stopLogged(b, q, front2)
	ck, _ := portalLogin(t, q)
	c := historyOf(t, q, ck, ip)["client"].(map[string]any)
	if c["blocked"] != float64(n) {
		t.Errorf("blocked after restart: %v, want %d", c["blocked"], n)
	}
	log := maps(historyList(t, q, ck)["bans"])
	if len(log) != 1 || log[0]["requests"] != float64(n) {
		t.Errorf("ban log after restart should count every blocked request: %v", log)
	}
}

func TestHistoryLog_RotatesAndReplaysInOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.jsonl")
	l, err := openHistoryLog(path, 400, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		l.emit(&historyEvent{T: evRequest, At: time.Now().UTC(), IP: "192.0.2.1", Path: "/" + strconv.Itoa(i), Status: 200})
	}
	l.close()

	for _, name := range []string{path, path + ".1", path + ".2"} {
		if _, err := os.Stat(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Errorf("only 2 rotated files should be kept: %v", err)
	}

	var got []int
	if _, err := replayHistoryLog(path, 2, time.Time{}, func(ev *historyEvent) {
		n, _ := strconv.Atoi(strings.TrimPrefix(ev.Path, "/"))
		got = append(got, n)
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || len(got) >= 50 || got[len(got)-1] != 49 {
		t.Fatalf("replayed %v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i] != got[i-1]+1 {
			t.Fatalf("replay out of order: %v", got)
		}
	}
}

func TestOptionTimeWireSemantics_HistoryAndPersist(t *testing.T) {
	ts := time.Date(2026, 11, 26, 17, 30, 0, 123456000, time.UTC)

	t.Run("banWindowView emits explicit JSON null when absent and RFC3339 when present", func(t *testing.T) {
		absent := banWindowView{ID: 1, Target: "203.0.113.1", Permanent: true, Active: true}
		raw, err := json.Marshal(absent)
		if err != nil {
			t.Fatalf("marshal absent banWindowView: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal absent banWindowView map: %v", err)
		}
		for _, key := range []string{"began", "until", "ended", "first_hit", "last_hit"} {
			v, exists := m[key]
			if !exists {
				t.Errorf("banWindowView JSON missing key %q (must emit null, not omit): %s", key, raw)
			}
			if v != nil {
				t.Errorf("banWindowView[%q] = %v, want nil", key, v)
			}
		}

		present := banWindowView{
			ID:       2,
			Target:   "203.0.113.2",
			Began:    optTime(ts),
			Until:    optTime(ts.Add(time.Hour)),
			Ended:    optTime(ts.Add(30 * time.Minute)),
			FirstHit: optTime(ts.Add(time.Minute)),
			LastHit:  optTime(ts.Add(2 * time.Minute)),
		}
		rawPresent, err := json.Marshal(present)
		if err != nil {
			t.Fatalf("marshal present banWindowView: %v", err)
		}
		var decoded banWindowView
		if err := json.Unmarshal(rawPresent, &decoded); err != nil {
			t.Fatalf("unmarshal present banWindowView: %v", err)
		}
		if got, ok := decoded.Began.Get(); !ok || !got.Equal(ts) {
			t.Errorf("decoded.Began = (%v, %v), want (%v, true)", got, ok, ts)
		}
		if got, ok := decoded.Until.Get(); !ok || !got.Equal(ts.Add(time.Hour)) {
			t.Errorf("decoded.Until = (%v, %v), want (%v, true)", got, ok, ts.Add(time.Hour))
		}
		if got, ok := decoded.Ended.Get(); !ok || !got.Equal(ts.Add(30*time.Minute)) {
			t.Errorf("decoded.Ended = (%v, %v), want (%v, true)", got, ok, ts.Add(30*time.Minute))
		}
		if got, ok := decoded.FirstHit.Get(); !ok || !got.Equal(ts.Add(time.Minute)) {
			t.Errorf("decoded.FirstHit = (%v, %v), want (%v, true)", got, ok, ts.Add(time.Minute))
		}
		if got, ok := decoded.LastHit.Get(); !ok || !got.Equal(ts.Add(2*time.Minute)) {
			t.Errorf("decoded.LastHit = (%v, %v), want (%v, true)", got, ok, ts.Add(2*time.Minute))
		}
		if !optTime(time.Time{}).IsNone() {
			t.Error("optTime(zero) should return None")
		}
	})

	t.Run("historyEvent omits absent times with omitzero and round-trips present times", func(t *testing.T) {
		evAbsent := historyEvent{T: evBan, At: ts, Ban: 1, Permanent: true}
		rawAbsent, err := json.Marshal(evAbsent)
		if err != nil {
			t.Fatalf("marshal absent historyEvent: %v", err)
		}
		for _, forbidden := range []string{`"begin"`, `"until"`, `"first"`} {
			if strings.Contains(string(rawAbsent), forbidden) {
				t.Errorf("historyEvent with None times emitted %s: %s", forbidden, rawAbsent)
			}
		}

		evPresent := historyEvent{
			T:     evBan,
			At:    ts,
			Ban:   2,
			Begin: opt.Some(ts),
			Until: opt.Some(ts.Add(time.Hour)),
			First: opt.Some(ts.Add(time.Minute)),
		}
		rawPresent, err := json.Marshal(evPresent)
		if err != nil {
			t.Fatalf("marshal present historyEvent: %v", err)
		}
		var dec historyEvent
		if err := json.Unmarshal(rawPresent, &dec); err != nil {
			t.Fatalf("unmarshal present historyEvent: %v", err)
		}
		if g, ok := dec.Begin.Get(); !ok || !g.Equal(ts) {
			t.Errorf("dec.Begin = (%v, %v), want (%v, true)", g, ok, ts)
		}
		if g, ok := dec.Until.Get(); !ok || !g.Equal(ts.Add(time.Hour)) {
			t.Errorf("dec.Until = (%v, %v), want (%v, true)", g, ok, ts.Add(time.Hour))
		}
		if g, ok := dec.First.Get(); !ok || !g.Equal(ts.Add(time.Minute)) {
			t.Errorf("dec.First = (%v, %v), want (%v, true)", g, ok, ts.Add(time.Minute))
		}
	})

	t.Run("savedBan omits until for permanent bans and preserves until for temporary bans", func(t *testing.T) {
		perm := savedBanOf("203.0.113.10", banForever, 3)
		rawPerm, err := json.Marshal(perm)
		if err != nil {
			t.Fatalf("marshal permanent savedBan: %v", err)
		}
		if strings.Contains(string(rawPerm), `"until"`) {
			t.Errorf("permanent savedBan emitted until field: %s", rawPerm)
		}
		var decPerm savedBan
		if err := json.Unmarshal(rawPerm, &decPerm); err != nil {
			t.Fatalf("unmarshal permanent savedBan: %v", err)
		}
		if until, ok := decPerm.until(); !ok || until != banForever {
			t.Errorf("decPerm.until() = (%d, %v), want (%d, true)", until, ok, banForever)
		}

		temp := savedBanOf("203.0.113.11", ts.UnixNano(), 2)
		rawTemp, err := json.Marshal(temp)
		if err != nil {
			t.Fatalf("marshal temporary savedBan: %v", err)
		}
		if !strings.Contains(string(rawTemp), `"until"`) {
			t.Errorf("temporary savedBan missing until field: %s", rawTemp)
		}
		var decTemp savedBan
		if err := json.Unmarshal(rawTemp, &decTemp); err != nil {
			t.Fatalf("unmarshal temporary savedBan: %v", err)
		}
		if until, ok := decTemp.until(); !ok || until != ts.UnixNano() {
			t.Errorf("decTemp.until() = (%d, %v), want (%d, true)", until, ok, ts.UnixNano())
		}

		var nullUntil savedBan
		if err := json.Unmarshal([]byte(`{"client":"203.0.113.12","until":null,"offenses":1}`), &nullUntil); err != nil {
			t.Fatalf("unmarshal null-until savedBan: %v", err)
		}
		if until, ok := nullUntil.until(); ok || until != 0 {
			t.Errorf("nullUntil.until() = (%d, %v), want (0, false)", until, ok)
		}
	})
}
