package configfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andreimerlescu/concert/internal/opt"
)

func TestParseConcertfile_MultiSiteAndRoundTrip(t *testing.T) {
	src := `
# Global server options
{
    listen :443
    http_listen :80
    tls_email ops@example.com
    tls_cache /var/lib/concert/acme
    hsts_max_age 31536000
    http3 on
    data_dir /var/lib/concert/data
}

shop.example.com, www.shop.example.com {
    preset wordpress
    root /var/www/shop
    upstream fcgi+unix:///run/php/php8.3-fpm.sock
    mount /cdn=/srv/cdn
    cap 12
    priority_cap 4
    micro_cache 15s
    micro_cache_max_mb 64
    static_cache_control "public, max-age=86400"
    secure_cookie on
}

blog.example.com {
    root /var/www/blog
    upstream http://127.0.0.1:3001
    cap 6; compress off
}
`
	f, err := ParseConcertfile([]byte(src))
	if err != nil {
		t.Fatalf("ParseConcertfile: %v", err)
	}
	if f.Global.Listen != ":443" || f.Global.HTTPListen != ":80" || !f.Global.HTTP3 || f.Global.HSTSMaxAge != 31536000 {
		t.Fatalf("unexpected global: %+v", f.Global)
	}
	if len(f.Sites) != 2 {
		t.Fatalf("sites=%d, want 2", len(f.Sites))
	}
	s0 := f.Sites[0]
	if len(s0.Hosts) != 2 || s0.Hosts[0] != "shop.example.com" || s0.Hosts[1] != "www.shop.example.com" {
		t.Fatalf("s0 hosts=%v", s0.Hosts)
	}
	if s0.Preset != "wordpress" || s0.Cap != 12 || s0.PriorityCap != 4 || s0.MicroCache != "15s" || s0.StaticCacheControl != "public, max-age=86400" {
		t.Fatalf("unexpected s0: %+v", s0)
	}
	if v, ok := s0.SecureCookie.Get(); !ok || !v {
		t.Fatalf("expected secure_cookie=true")
	}
	s1 := f.Sites[1]
	if v, ok := s1.Compress.Get(); s1.Cap != 6 || !ok || v {
		t.Fatalf("unexpected s1: %+v", s1)
	}

	// FormatConcertfile round-trip must parse cleanly back into equivalent config.
	formatted := FormatConcertfile(f)
	f2, err := ParseConcertfile([]byte(formatted))
	if err != nil {
		t.Fatalf("round-trip FormatConcertfile failed:\n%s\nerr: %v", formatted, err)
	}
	if len(f2.Sites) != 2 || f2.Sites[0].Cap != 12 || f2.Global.HTTP3 != true {
		t.Fatalf("round-trip mismatch: %+v", f2)
	}
}

func TestParseJSON_AndLoad(t *testing.T) {
	dir := t.TempDir()
	jp := filepath.Join(dir, "concert.json")
	raw := `{
		"global": {"listen": ":8443", "http3": true},
		"sites": [
			{"hosts": ["api.example.com"], "upstream": "http://127.0.0.1:4000", "cap": 20}
		]
	}`
	if err := os.WriteFile(jp, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(jp)
	if err != nil {
		t.Fatalf("Load json: %v", err)
	}
	if !f.Global.HTTP3 || len(f.Sites) != 1 || f.Sites[0].Hosts[0] != "api.example.com" || f.Sites[0].Cap != 20 {
		t.Fatalf("unexpected JSON config: %+v", f)
	}

	// Unknown JSON field rejected.
	if _, err := ParseJSON([]byte(`{"global":{"bogus":1},"sites":[{"hosts":["a.com"]}]}`)); err == nil {
		t.Fatal("expected unknown JSON field to fail")
	}
}

func TestParseConcertfile_Errors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"duplicate host", "a.com { cap 1 }\na.com { cap 2 }", "duplicate host"},
		{"unknown global directive", "{ bogus 1 }\na.com { cap 1 }", "unknown global directive"},
		{"unknown site directive", "a.com { bogus 1 }", "unknown site directive"},
		{"unclosed quote", "a.com { root \"/var/www }", "unterminated quoted string"},
		{"unclosed block", "a.com { cap 1", "unclosed site block"},
		{"invalid host", "https://a.com { cap 1 }", "bare hostname"},
		{"no sites", "{ listen :8080 }", "at least one site"},
		{"invalid micro_cache", "a.com { micro_cache bogus }", "invalid micro_cache"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConcertfile([]byte(tc.src))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestRoomV19AndUpstreamDirectivesRoundTrip(t *testing.T) {
	src := `{
    listen :8443
    token_ttl 2m
    first_poll_grace 20s
    ready_grace 15s
    idle_poll_ttl 30s
    reaper 10s
    retry_after 3
    busy_html /etc/concert/busy.html
    clear_queue_on_start off
    body_read_idle_timeout off
    max_upload_time off
    upstream_timeout 45s
    upstream_body_idle_timeout 20s
    upstream_cb_failures 5
    upstream_cb_cooldown 15s
    upstream_health_path /healthz
    upstream_health_interval 5s
}

alpha.example.com {
    upstream http://127.0.0.1:9001
    cap 20
}

beta.example.com {
    upstream http://127.0.0.1:9002
    cap 10
    token_ttl 0
    first_poll_grace off
    ready_grace off
    idle_poll_ttl off
    reaper 12s
    retry_after 4
    busy_html /etc/concert/beta-busy.html
    clear_queue_on_start on
    upstream_timeout off
    upstream_body_idle_timeout off
    upstream_cb_failures 0
    upstream_cb_cooldown 30s
    upstream_health_path off
    upstream_health_interval 15s
}
`
	f, err := ParseConcertfile([]byte(src))
	if err != nil {
		t.Fatalf("ParseConcertfile: %v", err)
	}
	if f.Global.TokenTTL != "2m" || f.Global.FirstPollGrace != "20s" || f.Global.ReadyGrace != "15s" ||
		f.Global.IdlePollTTL != "30s" || f.Global.Reaper != "10s" || f.Global.RetryAfter != 3 ||
		f.Global.BusyHTML != "/etc/concert/busy.html" || !opt.Equal(f.Global.ClearQueueOnStart, opt.Some(false)) ||
		f.Global.UpstreamTimeout != "45s" || f.Global.UpstreamBodyIdleTimeout != "20s" ||
		!opt.Equal(f.Global.UpstreamCBFailures, opt.Some(5)) ||
		f.Global.UpstreamCBCooldown != "15s" || f.Global.UpstreamHealthPath != "/healthz" ||
		f.Global.UpstreamHealthInterval != "5s" {
		t.Fatalf("unexpected global fields: %+v", f.Global)
	}
	s1 := f.Sites[1]
	if s1.TokenTTL != "0" || s1.FirstPollGrace != "off" || s1.ReadyGrace != "off" ||
		s1.IdlePollTTL != "off" || s1.Reaper != "12s" || s1.RetryAfter != 4 ||
		s1.BusyHTML != "/etc/concert/beta-busy.html" || !opt.Equal(s1.ClearQueueOnStart, opt.Some(true)) ||
		s1.UpstreamTimeout != "off" || s1.UpstreamBodyIdleTimeout != "off" ||
		!opt.Equal(s1.UpstreamCBFailures, opt.Some(0)) ||
		s1.UpstreamCBCooldown != "30s" || s1.UpstreamHealthPath != "off" ||
		s1.UpstreamHealthInterval != "15s" {
		t.Fatalf("unexpected site fields: %+v", s1)
	}

	out := FormatConcertfile(f)
	f2, err := ParseConcertfile([]byte(out))
	if err != nil {
		t.Fatalf("round-trip ParseConcertfile failed: %v\n%s", err, out)
	}
	if f2.Global.ReadyGrace != "15s" || f2.Global.IdlePollTTL != "30s" || f2.Global.Reaper != "10s" ||
		f2.Global.RetryAfter != 3 || f2.Global.BusyHTML != "/etc/concert/busy.html" ||
		!opt.Equal(f2.Global.ClearQueueOnStart, opt.Some(false)) ||
		f2.Global.UpstreamBodyIdleTimeout != "20s" || !opt.Equal(f2.Global.UpstreamCBFailures, opt.Some(5)) ||
		f2.Global.UpstreamHealthPath != "/healthz" || f2.Global.UpstreamHealthInterval != "5s" {
		t.Fatalf("global round-trip mismatch: %+v\n%s", f2.Global, out)
	}
	if f2.Sites[1].ReadyGrace != "off" || f2.Sites[1].IdlePollTTL != "off" ||
		!opt.Equal(f2.Sites[1].ClearQueueOnStart, opt.Some(true)) ||
		!opt.Equal(f2.Sites[1].UpstreamCBFailures, opt.Some(0)) ||
		f2.Sites[1].UpstreamHealthPath != "off" {
		t.Fatalf("site round-trip mismatch: %+v\n%s", f2.Sites[1], out)
	}

	// JSON parsing supports all new fields too.
	j := `{
		"global": {"ready_grace":"25s","idle_poll_ttl":"40s","upstream_body_idle_timeout":"15s","upstream_cb_failures":3,"clear_queue_on_start":true},
		"sites": [{"hosts":["j.example.com"],"upstream":"http://127.0.0.1:9000","ready_grace":"off","upstream_cb_failures":0}]
	}`
	jf, err := ParseJSON([]byte(j))
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	if jf.Global.ReadyGrace != "25s" || !opt.Equal(jf.Global.ClearQueueOnStart, opt.Some(true)) ||
		jf.Sites[0].ReadyGrace != "off" || !opt.Equal(jf.Sites[0].UpstreamCBFailures, opt.Some(0)) {
		t.Fatalf("unexpected JSON config: %+v", jf)
	}

	// Invalid directive bounds rejected.
	badCases := []struct {
		name string
		src  string
	}{
		{"ready_grace too low", "a.com { ready_grace 2s }"},
		{"ready_grace too high", "a.com { ready_grace 15m }"},
		{"idle_poll_ttl too low", "a.com { idle_poll_ttl 5s }"},
		{"reaper off", "a.com { reaper off }"},
		{"reaper too low", "a.com { reaper 1s }"},
		{"retry_after zero", "a.com { retry_after 0 }"},
		{"upstream_body_idle_timeout too low", "a.com { upstream_body_idle_timeout 500ms }"},
		{"upstream_cb_failures negative", "a.com { upstream_cb_failures -1 }"},
		{"upstream_cb_cooldown too low", "a.com { upstream_cb_cooldown 500ms }"},
		{"upstream_health_path no slash", "a.com { upstream_health_path healthz }"},
		{"upstream_health_interval too low", "a.com { upstream_health_interval 500ms }"},
		{"global ready_grace bad", "{ ready_grace 1s }\na.com { cap 1 }"},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseConcertfile([]byte(tc.src)); err == nil {
				t.Errorf("expected error for %s (%s)", tc.name, tc.src)
			}
		})
	}
}

func FuzzParseConcertfile(f *testing.F) {
	f.Add("{ listen :443; http3 on }\nshop.example.com { root /var/www; cap 12 }")
	f.Add("a.com, b.com { preset wordpress\n # comment\n micro_cache 10s }")
	f.Add("\"unterminated")
	f.Add("{ { } }")
	f.Fuzz(func(t *testing.T, in string) {
		cf, err := ParseConcertfile([]byte(in))
		if err != nil {
			return
		}
		if len(cf.Sites) == 0 {
			t.Fatal("parsed valid config with 0 sites")
		}
		for _, s := range cf.Sites {
			if len(s.Hosts) == 0 {
				t.Fatal("site with 0 hosts")
			}
		}
	})
}

func TestOptionFields_JSONAndConcertfileWireSemantics(t *testing.T) {
	// 1. Omitted and explicit JSON null decode to None, and marshaling omits all 16 optional keys.
	omittedOrNull := `{
		"global": {
			"portal_secure_cookie": null,
			"stats_auth": null,
			"room_lease_fraction": null,
			"clear_queue_on_start": null,
			"upstream_cb_failures": null,
			"fastlane_lock_destinations": null
		},
		"sites": [{
			"hosts": ["none.example.com"],
			"static_fallback": null,
			"compress": null,
			"max_queue": null,
			"secure_cookie": null,
			"preserve_host": null,
			"abuse": null,
			"room_lease_fraction": null,
			"clear_queue_on_start": null,
			"upstream_cb_failures": null,
			"fastlane_lock_destinations": null
		}]
	}`
	fNone, err := ParseJSON([]byte(omittedOrNull))
	if err != nil {
		t.Fatalf("ParseJSON(nulls): %v", err)
	}
	if fNone.Global.PortalSecureCookie.IsSome() || fNone.Global.StatsAuth.IsSome() ||
		fNone.Global.RoomLeaseFraction.IsSome() || fNone.Global.ClearQueueOnStart.IsSome() ||
		fNone.Global.UpstreamCBFailures.IsSome() || fNone.Global.FastlaneLockDestinations.IsSome() {
		t.Fatalf("expected all GlobalConfig options to be None, got %+v", fNone.Global)
	}
	sn := fNone.Sites[0]
	if sn.StaticFallback.IsSome() || sn.Compress.IsSome() || sn.MaxQueue.IsSome() ||
		sn.SecureCookie.IsSome() || sn.PreserveHost.IsSome() || sn.Abuse.IsSome() ||
		sn.RoomLeaseFraction.IsSome() || sn.ClearQueueOnStart.IsSome() ||
		sn.UpstreamCBFailures.IsSome() || sn.FastlaneLockDestinations.IsSome() {
		t.Fatalf("expected all SiteConfig options to be None, got %+v", sn)
	}
	wireNone, err := json.Marshal(fNone)
	if err != nil {
		t.Fatalf("json.Marshal(fNone): %v", err)
	}
	for _, key := range []string{
		"portal_secure_cookie", "stats_auth", "room_lease_fraction",
		"clear_queue_on_start", "upstream_cb_failures", "fastlane_lock_destinations",
		"static_fallback", "compress", "max_queue", "secure_cookie", "preserve_host", "abuse",
	} {
		if strings.Contains(string(wireNone), `"`+key+`"`) {
			t.Errorf("omitzero failed to omit absent key %q in %s", key, wireNone)
		}
	}

	// 2. Explicit zero values (false, 0, 0.0) decode as Some(zero) and stay present on marshal.
	explicitZeros := `{
		"global": {
			"portal_secure_cookie": false,
			"stats_auth": false,
			"room_lease_fraction": 0,
			"clear_queue_on_start": false,
			"upstream_cb_failures": 0,
			"fastlane_lock_destinations": false
		},
		"sites": [{
			"hosts": ["zero.example.com"],
			"static_fallback": false,
			"compress": false,
			"max_queue": 0,
			"secure_cookie": false,
			"preserve_host": false,
			"abuse": false,
			"room_lease_fraction": 0,
			"clear_queue_on_start": false,
			"upstream_cb_failures": 0,
			"fastlane_lock_destinations": false
		}]
	}`
	fZero, err := ParseJSON([]byte(explicitZeros))
	if err != nil {
		t.Fatalf("ParseJSON(zeros): %v", err)
	}
	if !opt.Equal(fZero.Global.PortalSecureCookie, opt.Some(false)) ||
		!opt.Equal(fZero.Global.StatsAuth, opt.Some(false)) ||
		!opt.Equal(fZero.Global.RoomLeaseFraction, opt.Some(0.0)) ||
		!opt.Equal(fZero.Global.ClearQueueOnStart, opt.Some(false)) ||
		!opt.Equal(fZero.Global.UpstreamCBFailures, opt.Some(0)) ||
		!opt.Equal(fZero.Global.FastlaneLockDestinations, opt.Some(false)) {
		t.Fatalf("expected all GlobalConfig options to be Some(zero), got %+v", fZero.Global)
	}
	sz := fZero.Sites[0]
	if !opt.Equal(sz.StaticFallback, opt.Some(false)) ||
		!opt.Equal(sz.Compress, opt.Some(false)) ||
		!opt.Equal(sz.MaxQueue, opt.Some(int64(0))) ||
		!opt.Equal(sz.SecureCookie, opt.Some(false)) ||
		!opt.Equal(sz.PreserveHost, opt.Some(false)) ||
		!opt.Equal(sz.Abuse, opt.Some(false)) ||
		!opt.Equal(sz.RoomLeaseFraction, opt.Some(0.0)) ||
		!opt.Equal(sz.ClearQueueOnStart, opt.Some(false)) ||
		!opt.Equal(sz.UpstreamCBFailures, opt.Some(0)) ||
		!opt.Equal(sz.FastlaneLockDestinations, opt.Some(false)) {
		t.Fatalf("expected all SiteConfig options to be Some(zero), got %+v", sz)
	}
	wireZero, err := json.Marshal(fZero)
	if err != nil {
		t.Fatalf("json.Marshal(fZero): %v", err)
	}
	var rawMap struct {
		Global map[string]any   `json:"global"`
		Sites  []map[string]any `json:"sites"`
	}
	if err := json.Unmarshal(wireZero, &rawMap); err != nil {
		t.Fatalf("unmarshal wireZero: %v", err)
	}
	for _, k := range []string{"portal_secure_cookie", "stats_auth", "room_lease_fraction", "clear_queue_on_start", "upstream_cb_failures", "fastlane_lock_destinations"} {
		if _, ok := rawMap.Global[k]; !ok {
			t.Errorf("expected explicit zero global key %q to be emitted in %s", k, wireZero)
		}
	}
	for _, k := range []string{"static_fallback", "compress", "max_queue", "secure_cookie", "preserve_host", "abuse", "room_lease_fraction", "clear_queue_on_start", "upstream_cb_failures", "fastlane_lock_destinations"} {
		if _, ok := rawMap.Sites[0][k]; !ok {
			t.Errorf("expected explicit zero site key %q to be emitted in %s", k, wireZero)
		}
	}

	// 3. Value copies of GlobalConfig and SiteConfig do not alias optional fields.
	gCopy := fZero.Global
	gCopy.UpstreamCBFailures = opt.Some(9)
	if !opt.Equal(fZero.Global.UpstreamCBFailures, opt.Some(0)) {
		t.Fatalf("mutating GlobalConfig copy mutated original: %v", fZero.Global.UpstreamCBFailures)
	}
	sCopy := fZero.Sites[0]
	sCopy.MaxQueue = opt.Some(int64(42))
	if !opt.Equal(fZero.Sites[0].MaxQueue, opt.Some(int64(0))) {
		t.Fatalf("mutating SiteConfig copy mutated original: %v", fZero.Sites[0].MaxQueue)
	}
}
