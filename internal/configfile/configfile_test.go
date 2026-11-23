package configfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if s0.SecureCookie == nil || !*s0.SecureCookie {
		t.Fatalf("expected secure_cookie=true")
	}
	s1 := f.Sites[1]
	if s1.Cap != 6 || s1.Compress == nil || *s1.Compress {
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
