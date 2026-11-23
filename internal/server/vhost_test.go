package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVhost_MultiSiteIsolationReloadAndPortalSwitcher(t *testing.T) {
	upA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ORIGIN-A:" + r.URL.Path))
	}))
	defer upA.Close()
	upB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ORIGIN-B:" + r.URL.Path))
	}))
	defer upB.Close()

	rootA := t.TempDir()
	rootB := t.TempDir()
	writeDiskFile(t, filepath.Join(rootA, "robots.txt"), []byte("site-a-robots"))
	writeDiskFile(t, filepath.Join(rootB, "robots.txt"), []byte("site-b-robots"))

	cfPath := filepath.Join(t.TempDir(), "Concertfile")
	writeConcertfile := func(capA int, extra string) {
		content := fmt.Sprintf(`
{
    listen 127.0.0.1:0
    portal_listen 127.0.0.1:0
    portal_allow 127.0.0.1/32, ::1/128
}

alpha.example.test {
    root %q
    upstream %s
    cap %d
}

beta.example.test {
    root %q
    upstream %s
    cap 4
}
%s
`, rootA, upA.URL, capA, rootB, upB.URL, extra)
		if err := os.WriteFile(cfPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeConcertfile(7, "")

	base := testConfig(upA.URL)
	base.configFile = cfPath
	base.portal.pass = testPortalPass
	base.portal.sessionTTL = time.Hour

	vm, err := newVhostManager(base)
	if err != nil {
		t.Fatalf("newVhostManager: %v", err)
	}
	defer vm.Close()

	srv := httptest.NewServer(vm)
	defer srv.Close()

	getHost := func(host, path string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Host = host
		resp, err := testClient.Do(req)
		if err != nil {
			t.Fatalf("%s%s: %v", host, path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	// 1. Strict virtual host isolation for both dynamic pages and os.Root static files.
	if code, body := getHost("alpha.example.test", "/hello"); code != 200 || body != "ORIGIN-A:/hello" {
		t.Fatalf("alpha dynamic: %d %q", code, body)
	}
	if code, body := getHost("beta.example.test", "/hello"); code != 200 || body != "ORIGIN-B:/hello" {
		t.Fatalf("beta dynamic: %d %q", code, body)
	}
	if code, body := getHost("alpha.example.test", "/robots.txt"); code != 200 || body != "site-a-robots" {
		t.Fatalf("alpha static: %d %q", code, body)
	}
	if code, body := getHost("beta.example.test", "/robots.txt"); code != 200 || body != "site-b-robots" {
		t.Fatalf("beta static: %d %q", code, body)
	}

	// 2. Unknown Host rejected with 421 Misdirected Request (zero cross-tenant fallback).
	if code, _ := getHost("evil.example.test", "/"); code != http.StatusMisdirectedRequest {
		t.Fatalf("unknown host status=%d, want 421", code)
	}

	// 3. Multi-vhost Portal: /api/sites, ?site= scoping, temporary cap override, and /api/reload!
	p, err := newVhostPortal(vm)
	if err != nil || p == nil {
		t.Fatalf("newVhostPortal: %v", err)
	}
	t.Cleanup(p.closeListener)
	ck, csrf := portalLogin(t, p)

	rec := portalDo(p, http.MethodGet, "/api/sites", "", ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/sites: %d %s", rec.Code, rec.Body.String())
	}
	var sum vhostSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	if !sum.ConfigManaged || len(sum.Sites) != 2 || sum.Sites[0].Cap != 7 || sum.Sites[1].Cap != 4 {
		t.Fatalf("unexpected /api/sites: %+v", sum)
	}

	// Scoped overview for beta.example.test.
	rec = portalDo(p, http.MethodGet, "/api/overview?site=beta.example.test", "", ck, csrf, false)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"cap":4`) {
		t.Fatalf("GET /api/overview?site=beta: %d %s", rec.Code, rec.Body.String())
	}

	// Unknown ?site= returns 404.
	rec = portalDo(p, http.MethodGet, "/api/overview?site=nope.example.test", "", ck, csrf, false)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown ?site=: %d, want 404", rec.Code)
	}

	// Non-cap settings mutation refused under -config mode.
	rec = portalDo(p, http.MethodPost, "/api/settings?site=alpha.example.test", `{"max_queue":99}`, ck, csrf, false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("non-cap edit in -config mode should fail: %d %s", rec.Code, rec.Body.String())
	}

	// Emergency live cap override succeeds and flags runtime_override=true without touching file.
	rec = portalDo(p, http.MethodPost, "/api/settings?site=alpha.example.test", `{"cap":19}`, ck, csrf, false)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"runtime_override":true`) {
		t.Fatalf("temporary cap override failed: %d %s", rec.Code, rec.Body.String())
	}

	// Bad Concertfile on reload preserves live traffic cleanly!
	if err := os.WriteFile(cfPath, []byte("broken { unknown_directive 123 }"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := vm.Reload(); err == nil {
		t.Fatal("expected bad Concertfile reload to fail")
	}
	if code, body := getHost("alpha.example.test", "/still-up"); code != 200 || body != "ORIGIN-A:/still-up" {
		t.Fatalf("bad reload broke live traffic: %d %q", code, body)
	}

	// Valid Concertfile update + POST /api/reload clears temporary override and adds gamma.example.test!
	writeConcertfile(11, fmt.Sprintf("\ngamma.example.test {\n    upstream %s\n    cap 3\n}\n", upA.URL))
	rec = portalDo(p, http.MethodPost, "/api/reload", `{}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/reload: %d %s", rec.Code, rec.Body.String())
	}
	if code, body := getHost("gamma.example.test", "/new"); code != 200 || body != "ORIGIN-A:/new" {
		t.Fatalf("gamma after reload: %d %q", code, body)
	}
	rec = portalDo(p, http.MethodGet, "/api/overview?site=alpha.example.test", "", ck, csrf, false)
	if !strings.Contains(rec.Body.String(), `"cap":11`) || !strings.Contains(rec.Body.String(), `"runtime_override":false`) {
		t.Fatalf("reload did not restore Concertfile cap and clear override: %s", rec.Body.String())
	}

	// Multi-site Prometheus metrics include per-site labels.
	m := vm.renderPrometheusMetrics(nil)
	for _, want := range []string{
		`concert_vhost_sites_total 3`,
		`concert_site_room_cap{site="alpha.example.test"} 11`,
		`concert_site_room_cap{site="beta.example.test"} 4`,
		`concert_site_room_cap{site="gamma.example.test"} 3`,
	} {
		if !strings.Contains(m, want) {
			t.Fatalf("multi-site metrics missing %q", want)
		}
	}
}
