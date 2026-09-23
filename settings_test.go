package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func init() {
	// parseConfig defaults -data-dir to /var/lib/concert/data. Point the suite
	// at a directory that never exists, so a machine running concert cannot
	// leak its settings.json into tests.
	defaultDataDir = filepath.Join(os.TempDir(), fmt.Sprintf("concert-test-absent-%d", os.Getpid()))
}

func writeSettings(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, settingsFileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func findSetting(t *testing.T, v map[string]any, key string) map[string]any {
	t.Helper()
	list, _ := v["settings"].([]any)
	for _, s := range list {
		if m, _ := s.(map[string]any); m["key"] == key {
			return m
		}
	}
	t.Fatalf("setting %s missing from %v", key, v)
	return nil
}

// ─── definitions and precedence ──────────────────────────────────────────────

func TestSettingDefs_CoverEveryFlag(t *testing.T) {
	clearConcertEnv(t)
	fs := newFlagSet()
	cfg, _, err := parseConfig(fs, []string{"-version"})
	if err != nil {
		t.Fatal(err)
	}
	byFlag := map[string]bool{}
	for i := range settingDefs {
		d := &settingDefs[i]
		byFlag[d.flag] = true
		if fs.Lookup(d.flag) == nil {
			t.Errorf("%s: flag -%s is not registered", d.key, d.flag)
		}
		if got := d.get(&cfg); got != d.def {
			t.Errorf("%s: default %v, want %v", d.key, got, d.def)
		}
	}
	fs.VisitAll(func(f *flag.Flag) {
		if f.Name != "version" && f.Name != "data-dir" && !byFlag[f.Name] {
			t.Errorf("flag -%s has no setting definition", f.Name)
		}
	})
}

func TestParseConfig_FileBeatsFlagBeatsEnvBeatsDefault(t *testing.T) {
	clearConcertEnv(t)
	dir := t.TempDir()
	writeSettings(t, dir, `{"version":1,"settings":{"cap":77,"abuse_cooldown":"7m"}}`)
	t.Setenv("CONCERT_CAPACITY", "42")
	t.Setenv("CONCERT_MAX_QUEUE", "11")
	t.Setenv("CONCERT_ABUSE_COOLDOWN", "3m")

	cfg, _, err := parseConfig(newFlagSet(), []string{
		"-data-dir", dir, "-cap", "7", "-reaper", "40s", "-abuse-cooldown", "4m",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.capacity != 77 || cfg.abuseCooldown != 7*time.Minute {
		t.Errorf("file must beat flag and env: cap=%d cooldown=%s", cfg.capacity, cfg.abuseCooldown)
	}
	if cfg.reaper != 40*time.Second {
		t.Errorf("flag must beat default: reaper=%s", cfg.reaper)
	}
	if cfg.maxQueue != 11 {
		t.Errorf("env must beat default: max-queue=%d", cfg.maxQueue)
	}
	if cfg.retryAfter != 5 {
		t.Errorf("default: retry-after=%d", cfg.retryAfter)
	}

	m := newSettingsManager(cfg)
	for key, want := range map[string]string{
		"cap": sourceFile, "max_queue": sourceEnv, "reaper": sourceFlag, "retry_after": sourceDefault,
	} {
		if got := m.source(key); got != want {
			t.Errorf("%s source: got %s, want %s", key, got, want)
		}
	}
	if m.base["cap"] != 7 {
		t.Errorf("baseline for cap should be the flag value 7, got %v", m.base["cap"])
	}
}

func TestParseConfig_BadSettingsFile(t *testing.T) {
	cases := map[string]string{
		"not json":        `{`,
		"wrong type":      `{"version":1,"settings":{"cap":"lots"}}`,
		"failed check":    `{"version":1,"settings":{"rate":-1}}`,
		"bad duration":    `{"version":1,"settings":{"reaper":"soon"}}`,
		"reaper too fast": `{"version":1,"settings":{"reaper":"1s"}}`,
		"invalid cfg":     `{"version":1,"settings":{"upstream":"ftp://x"}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			clearConcertEnv(t)
			dir := t.TempDir()
			writeSettings(t, dir, body)
			if _, _, err := parseConfig(newFlagSet(), []string{"-data-dir", dir}); err == nil {
				t.Error("expected an error")
			}
		})
	}

	t.Run("restart-only key is ignored", func(t *testing.T) {
		clearConcertEnv(t)
		dir := t.TempDir()
		writeSettings(t, dir, `{"version":1,"settings":{"listen":":9999","cap":9}}`)
		cfg, _, err := parseConfig(newFlagSet(), []string{"-data-dir", dir})
		if err != nil || cfg.listen != ":8080" || cfg.capacity != 9 {
			t.Errorf("listen=%s cap=%d err=%v", cfg.listen, cfg.capacity, err)
		}
	})

	t.Run("unknown key is ignored", func(t *testing.T) {
		clearConcertEnv(t)
		dir := t.TempDir()
		writeSettings(t, dir, `{"version":1,"settings":{"from_the_future":1,"cap":9}}`)
		cfg, _, err := parseConfig(newFlagSet(), []string{"-data-dir", dir})
		if err != nil || cfg.capacity != 9 {
			t.Errorf("cap=%d err=%v", cfg.capacity, err)
		}
	})
}

// ─── portal changes ──────────────────────────────────────────────────────────

func TestSettings_SaveAppliesImmediatelyAndReloads(t *testing.T) {
	dir := t.TempDir()
	cfg := portalTestConfig("http://127.0.0.1:1")
	cfg.dataDir = dir
	a, p, _ := newTestPortal(t, cfg, nil)
	ck, csrf := portalLogin(t, p)

	rec := portalDo(p, http.MethodPost, "/api/settings",
		`{"cap":9,"abuse_strikes":7,"ban_paths":"/.env","abuse_window":"2m"}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if a.room.Cap() != 9 {
		t.Errorf("cap not applied: %d", a.room.Cap())
	}
	g := a.current()
	if g.cfg.abuseStrikes != 7 || a.abuse.p().threshold != 7 || a.abuse.p().window != int64(2*time.Minute) {
		t.Errorf("abuse tuning not applied: cfg=%d threshold=%d window=%d",
			g.cfg.abuseStrikes, a.abuse.p().threshold, a.abuse.p().window)
	}
	if len(g.banRules) != 1 || g.banRules[0].path != "/.env" {
		t.Errorf("ban paths not applied: %+v", g.banRules)
	}
	v := decodeJSON(t, rec)
	if s := findSetting(t, v, "abuse_strikes"); s["source"] != sourceFile || s["value"] != float64(7) {
		t.Errorf("abuse_strikes view: %v", s)
	}

	path := filepath.Join(dir, settingsFileName)
	values, err := readSettingsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if values["cap"] != 9 || values["abuse_strikes"] != 7 || values["ban_paths"] != "/.env" || values["abuse_window"] != 2*time.Minute {
		t.Errorf("file contents: %v", values)
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(path); err != nil || st.Mode().Perm()&0o077 != 0 {
			t.Errorf("settings.json must not be group or world readable: %v %v", st.Mode(), err)
		}
	}

	clearConcertEnv(t)
	next, _, err := parseConfig(newFlagSet(), []string{"-data-dir", dir, "-cap", "3"})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if next.capacity != 9 || next.abuseStrikes != 7 || next.banPaths != "/.env" {
		t.Errorf("reloaded: cap=%d strikes=%d ban-paths=%q", next.capacity, next.abuseStrikes, next.banPaths)
	}
}

func TestSettings_ResetRestoresBaseline(t *testing.T) {
	dir := t.TempDir()
	cfg := portalTestConfig("http://127.0.0.1:1")
	cfg.dataDir = dir
	a, p, _ := newTestPortal(t, cfg, nil)
	ck, csrf := portalLogin(t, p)

	portalDo(p, http.MethodPost, "/api/settings", `{"cap":4,"abuse_strikes":3}`, ck, csrf, false)
	rec := portalDo(p, http.MethodDelete, "/api/settings?key=cap&key=abuse_strikes", "", ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}
	if a.room.Cap() != 10 {
		t.Errorf("cap should return to its baseline 10, got %d", a.room.Cap())
	}
	if a.abuse.p().threshold != 20 {
		t.Errorf("abuse_strikes should return to its baseline 20, got %d", a.abuse.p().threshold)
	}
	v := decodeJSON(t, rec)
	if s := findSetting(t, v, "abuse_strikes"); s["source"] != sourceDefault {
		t.Errorf("abuse_strikes after reset: %v", s)
	}
	values, _ := readSettingsFile(filepath.Join(dir, settingsFileName))
	if len(values) != 0 {
		t.Errorf("file should be empty after reset: %v", values)
	}
}

func TestSettings_WithoutDataDirAppliedButNotSaved(t *testing.T) {
	a, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)
	ck, csrf := portalLogin(t, p)
	rec := portalDo(p, http.MethodPost, "/api/settings", `{"abuse_strikes":7}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if a.abuse.p().threshold != 7 {
		t.Errorf("not applied: %d", a.abuse.p().threshold)
	}
	if v := decodeJSON(t, rec); v["persisted"] != false {
		t.Errorf("persisted should be false without -data-dir: %v", v["persisted"])
	}
}

func TestSettings_InvalidValuesAreNeverSaved(t *testing.T) {
	dir := t.TempDir()
	cfg := portalTestConfig("http://127.0.0.1:1")
	cfg.dataDir = dir
	a, p, _ := newTestPortal(t, cfg, nil)
	ck, csrf := portalLogin(t, p)
	before := a.current()

	for name, body := range map[string]string{
		"bad upstream":      `{"cap":5,"upstream":"ftp://x"}`,
		"route conflict":    `{"bypass":"/static/*","assets":"/static/app.js"}`,
		"portal lockout":    `{"portal_allow":"10.0.0.0/8"}`,
		"unknown key":       `{"nope":1}`,
		"wrong type":        `{"abuse":"yes"}`,
		"missing html":      `{"html":"/does/not/exist.html"}`,
		"ban w/o registry":  `{"abuse":false,"ban_paths":"/.env"}`,
		"reaper too fast":   `{"reaper":"1s"}`,
		"token ttl too low": `{"token_ttl":"10s"}`,
	} {
		if rec := portalDo(p, http.MethodPost, "/api/settings", body, ck, csrf, false); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d %s, want 400", name, rec.Code, rec.Body.String())
		}
	}
	if a.room.Cap() != 10 || a.current() != before {
		t.Error("a rejected change must not apply anything")
	}
	if _, err := os.Stat(filepath.Join(dir, settingsFileName)); !os.IsNotExist(err) {
		t.Errorf("no settings file should have been written: %v", err)
	}
}

func TestSettings_AdminCapIsPersisted(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.adminToken = "secret"
	cfg.dataDir = t.TempDir()
	_, front := newTestApp(t, cfg, up)

	resp, _ := doReq(t, testClient, http.MethodPost, front.URL+"/_room/cap",
		map[string]string{"Authorization": "Bearer secret"}, strings.NewReader(`{"cap":6}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cap: %d", resp.StatusCode)
	}
	values, _ := readSettingsFile(filepath.Join(cfg.dataDir, settingsFileName))
	if values["cap"] != 6 {
		t.Errorf("cap change not saved: %v", values)
	}
}

// ─── permanent and persisted bans ────────────────────────────────────────────

func TestAbuse_PermanentBan(t *testing.T) {
	r, stats := testRegistry(t, nil)
	ip := netip.MustParseAddr("203.0.113.9")
	now := time.Now()

	if _, err := r.banFor(ip, 0, now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(10000 * time.Hour)
	if left, banned := r.banned(ip, later); !banned || left != banForeverLeft {
		t.Errorf("permanent ban: banned=%v left=%s", banned, left)
	}
	if n := r.sweep(later); n != 0 {
		t.Errorf("sweep removed a permanent ban: %d", n)
	}
	if left, banned := r.banNow(ip, later); !banned || left != banForeverLeft {
		t.Error("banNow must report the permanent ban")
	}
	if stats.abuseBans.Load() != 1 {
		t.Errorf("bans counter: %d", stats.abuseBans.Load())
	}
	list := r.bans(later)
	if len(list) != 1 || !list[0].Permanent || list[0].RemainingSeconds != 0 {
		t.Errorf("list: %+v", list)
	}

	// Converting to a timed ban is a change, not a new offense.
	if _, err := r.banFor(ip, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if left, _ := r.banned(ip, now); left > time.Hour || stats.abuseBans.Load() != 1 {
		t.Errorf("after converting: left=%s bans=%d", left, stats.abuseBans.Load())
	}

	p := netip.MustParsePrefix("198.51.0.0/16")
	if err := r.banRange(p, 0, now); err != nil {
		t.Fatal(err)
	}
	if left, banned := r.banned(netip.MustParseAddr("198.51.3.4"), later); !banned || left != banForeverLeft {
		t.Error("permanent range ban not enforced")
	}
	if n := r.sweepRanges(later); n != 0 {
		t.Errorf("sweepRanges removed a permanent range: %d", n)
	}
}

func TestAbuse_PermanentBanResponse(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.trustedProxies = "127.0.0.1/32"
	a, front := newTestApp(t, cfg, up)
	_, _ = a.abuse.banFor(netip.MustParseAddr("203.0.113.9"), 0, time.Now())

	resp, body := get(t, front.URL+"/hello", withXFF("203.0.113.9"))
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), `"permanent":true`) {
		t.Errorf("JSON client: %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Retry-After") != "" {
		t.Error("a permanent ban must not send Retry-After")
	}
	hdr := map[string]string{"X-Forwarded-For": "203.0.113.9", "Accept": "text/html"}
	if resp, body := get(t, front.URL+"/page", hdr); resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "Access blocked") {
		t.Errorf("browser: %d %s", resp.StatusCode, body)
	}
	if resp, body := get(t, front.URL+"/queue/status", withXFF("203.0.113.9")); resp.StatusCode != http.StatusOK || string(body) != `{"ready":true}` {
		t.Errorf("status poll from a banned client should trigger a reload: %d %s", resp.StatusCode, body)
	}
}

func TestAbuse_BansSurviveRestart(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.dataDir = t.TempDir()
	now := time.Now()

	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.abuse.banFor(netip.MustParseAddr("203.0.113.9"), 0, now)
	a.abuse.banNow(netip.MustParseAddr("203.0.113.10"), now)
	a.abuse.banNow(netip.MustParseAddr("2001:db8:1:2::5"), now)
	_ = a.abuse.banRange(netip.MustParsePrefix("198.51.0.0/16"), 0, now)
	_ = a.abuse.banRange(netip.MustParsePrefix("192.0.2.0/24"), time.Hour, now)
	a.Close()

	b, err := newApp(cfg)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	defer b.Close()
	checks := map[string]time.Duration{
		"203.0.113.9":         banForeverLeft,
		"203.0.113.10":        5 * time.Minute,
		"2001:db8:1:2:ffff::": 5 * time.Minute,
		"198.51.77.1":         banForeverLeft,
		"192.0.2.44":          time.Hour,
	}
	for s, want := range checks {
		left, banned := b.abuse.banned(netip.MustParseAddr(s), now)
		if !banned || left > want || (want != banForeverLeft && left < want-time.Second) {
			t.Errorf("%s after restart: banned=%v left=%s, want ~%s", s, banned, left, want)
		}
	}
	if b.abuse.rangeCount() != 2 {
		t.Errorf("ranges after restart: %d", b.abuse.rangeCount())
	}
	// Offense history survives, so the next ban escalates.
	if left, _ := b.abuse.banNow(netip.MustParseAddr("203.0.113.10"), now.Add(6*time.Minute)); left != 10*time.Minute {
		t.Errorf("escalation after restart: got %s, want 10m", left)
	}
}

func TestAbuse_CorruptBansFileFailsStartup(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.dataDir = t.TempDir()
	if err := os.WriteFile(bansFilePath(cfg.dataDir), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if a, err := newApp(cfg); err == nil {
		a.Close()
		t.Fatal("a corrupt bans.json must stop startup rather than drop bans silently")
	}
}

func TestAbuse_ExemptAddressesNotRestored(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.dataDir = t.TempDir()
	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.abuse.banFor(netip.MustParseAddr("203.0.113.9"), 0, time.Now())
	a.Close()

	cfg.abuseAllow = "203.0.113.0/24"
	b, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, banned := b.abuse.banned(netip.MustParseAddr("203.0.113.9"), time.Now()); banned {
		t.Error("an address allowlisted since the ban must not be restored as banned")
	}
}

// ─── bans drop waiting visitors ──────────────────────────────────────────────

func TestBan_PortalBanDropsWaitingVisitors(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := portalTestConfig(up.URL())
	cfg.capacity = 1
	_, p, front := newTestPortal(t, cfg, up)
	fillSlot(t, front, up)

	client := queueJarClient(t, front)
	if n := len(p.queueViews(time.Now())); n != 1 {
		t.Fatalf("in line: %d", n)
	}

	ck, csrf := portalLogin(t, p)
	rec := portalDo(p, http.MethodPost, "/api/bans", `{"client":"127.0.0.1","permanent":true}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("ban: %d %s", rec.Code, rec.Body.String())
	}
	v := decodeJSON(t, rec)
	if v["permanent"] != true || v["dropped"] != float64(1) || v["until"] != nil {
		t.Errorf("response: %v", v)
	}
	if n := len(p.queueViews(time.Now())); n != 0 {
		t.Error("banned visitor is still in the line")
	}

	_, body := doReq(t, client, http.MethodGet, front.URL+"/queue/status", nil, nil)
	if string(body) != `{"ready":true}` {
		t.Errorf("status poll should trigger a reload: %s", body)
	}
	resp, body := doReq(t, client, http.MethodGet, front.URL+"/page", map[string]string{"Accept": "text/html"}, nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "Access blocked") {
		t.Errorf("reload after ban: %d %s", resp.StatusCode, body)
	}

	list := decodeJSON(t, portalDo(p, http.MethodGet, "/api/bans", "", ck, "", false))
	bans, _ := list["bans"].([]any)
	if b, _ := bans[0].(map[string]any); len(bans) != 1 || b["permanent"] != true {
		t.Errorf("list: %v", list)
	}
}
func TestBan_BanPathDropsWaitingVisitor(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := portalTestConfig(up.URL())
	cfg.capacity = 1
	cfg.banPaths = "/.env"
	a, _, front := newTestPortal(t, cfg, up)
	fillSlot(t, front, up)

	client := queueJarClient(t, front)
	resp, body := doReq(t, client, http.MethodGet, front.URL+"/.env", nil, nil)
	if !isBlocked(resp, body) {
		t.Fatalf("ban path: %d %s", resp.StatusCode, body)
	}
	// A strike-path ban drops waiting visitors through the batched drop loop.
	eventually(t, 2*time.Second, func() bool { return a.room.LiveQueueDepth() == 0 },
		"a ban-path ban must drop the visitor from the line")
}
func TestBan_RangeBanSparesExemptVisitors(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := portalTestConfig(up.URL())
	cfg.capacity = 1
	cfg.abuseAllow = "127.0.0.1/32"
	_, p, front := newTestPortal(t, cfg, up)
	fillSlot(t, front, up)

	queueJarClient(t, front)
	ck, csrf := portalLogin(t, p)
	rec := portalDo(p, http.MethodPost, "/api/bans", `{"client":"127.0.0.0/8","duration":"1h"}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("ban: %d %s", rec.Code, rec.Body.String())
	}
	var v map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v["dropped"] != float64(0) || len(p.queueViews(time.Now())) != 1 {
		t.Errorf("an allowlisted visitor inside the range must stay in line: %v, %d", v, len(p.queueViews(time.Now())))
	}
}
