package main

import (
	"net/http"
	"testing"
)

func TestCheckPathList(t *testing.T) {
	for _, ok := range []string{"", "/a", " /a , /b/* ", "/a,,/b,", "/x,/x/*"} {
		if err := checkPathList(ok); err != nil {
			t.Errorf("%q: unexpected error %v", ok, err)
		}
	}
	for _, bad := range []string{"a", "/a,b", "/a,/a", " /a , /a ", "/a b"} {
		if err := checkPathList(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestCheckCIDRList(t *testing.T) {
	for _, ok := range []string{"", "127.0.0.1/32", " 10.0.0.0/8 , ::1 ", "10.0.0.0/8,,192.0.2.1,", "2001:db8::/32,203.0.113.9"} {
		if err := checkCIDRList(ok); err != nil {
			t.Errorf("%q: unexpected error %v", ok, err)
		}
	}
	for _, bad := range []string{"nope", "10.0.0.0/33", "::1/129", "1.2.3", "10.0.0.0/8,10.0.0.0/8", "10.0.0.1 10.0.0.2"} {
		if err := checkCIDRList(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestCheckHostList(t *testing.T) {
	for _, ok := range []string{"", "example.com", " example.com , www.example.com ", "Example.com.", "a.example.com,,b.example.com,"} {
		if err := checkHostList(ok); err != nil {
			t.Errorf("%q: unexpected error %v", ok, err)
		}
	}
	for _, bad := range []string{"https://example.com", "localhost", "203.0.113.9", "*.example.com", "example.com:443", "example.com,EXAMPLE.com"} {
		if err := checkHostList(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

// Every comma-separated setting is marked with its list kind, so the
// portal edits it one entry per input.
func TestSettings_ListsMarkedForPortal(t *testing.T) {
	a, err := newApp(testConfig("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	want := map[string]string{
		"bypass": listPaths, "assets": listPaths, "asset_public": listPaths, "ban_paths": listPaths, "stream_paths": listPaths,
		"trusted_proxies": listCIDRs, "abuse_allow": listCIDRs, "portal_allow": listCIDRs,
		"tls_domains": listHosts,
	}
	views, _ := a.settingsViews()
	for _, v := range views {
		if v.List != want[v.Key] {
			t.Errorf("%s: list=%q, want %q", v.Key, v.List, want[v.Key])
		}
	}
}

func TestSettings_PathListEntriesValidated(t *testing.T) {
	a, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)
	ck, csrf := portalLogin(t, p)

	for name, body := range map[string]string{
		"no leading slash": `{"ban_paths":"/.env,.git/*"}`,
		"duplicate":        `{"ban_paths":"/.env,/.env"}`,
	} {
		if rec := portalDo(p, http.MethodPost, "/api/settings", body, ck, csrf, false); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d %s, want 400", name, rec.Code, rec.Body.String())
		}
	}
	if len(a.current().banRules) != 0 {
		t.Error("a rejected list must not apply")
	}

	rec := portalDo(p, http.MethodPost, "/api/settings", `{"ban_paths":"/.env, /.git/*"}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid list: %d %s", rec.Code, rec.Body.String())
	}
	if len(a.current().banRules) != 2 {
		t.Errorf("ban rules: %+v", a.current().banRules)
	}
	if s := findSetting(t, decodeJSON(t, rec), "ban_paths"); s["list"] != listPaths {
		t.Errorf("ban_paths view should carry the list kind: %v", s)
	}
}

func TestSettings_CIDRListEntriesValidated(t *testing.T) {
	a, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)
	ck, csrf := portalLogin(t, p)

	for name, body := range map[string]string{
		"not an address": `{"abuse_allow":"198.51.100.0/24,nope"}`,
		"bad prefix":     `{"abuse_allow":"198.51.100.0/40"}`,
		"duplicate":      `{"abuse_allow":"203.0.113.9,203.0.113.9"}`,
	} {
		if rec := portalDo(p, http.MethodPost, "/api/settings", body, ck, csrf, false); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d %s, want 400", name, rec.Code, rec.Body.String())
		}
	}
	if len(a.current().cfg.allow) != 0 {
		t.Error("a rejected list must not apply")
	}

	rec := portalDo(p, http.MethodPost, "/api/settings", `{"abuse_allow":"198.51.100.0/24, 203.0.113.9"}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid list: %d %s", rec.Code, rec.Body.String())
	}
	if n := len(a.current().cfg.allow); n != 2 {
		t.Errorf("allowlist entries: %d, want 2", n)
	}
	if s := findSetting(t, decodeJSON(t, rec), "abuse_allow"); s["list"] != listCIDRs {
		t.Errorf("abuse_allow view should carry the list kind: %v", s)
	}
}

func TestSettings_HostListEntriesValidated(t *testing.T) {
	a, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)
	ck, csrf := portalLogin(t, p)

	for name, body := range map[string]string{
		"ip address": `{"tls_domains":"203.0.113.9"}`,
		"wildcard":   `{"tls_domains":"*.example.com"}`,
		"duplicate":  `{"tls_domains":"example.com,EXAMPLE.com"}`,
	} {
		if rec := portalDo(p, http.MethodPost, "/api/settings", body, ck, csrf, false); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d %s, want 400", name, rec.Code, rec.Body.String())
		}
	}
	if len(a.current().cfg.tlsHosts) != 0 {
		t.Error("a rejected list must not apply")
	}
}
