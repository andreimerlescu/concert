package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

// ─── settings applied to live traffic ────────────────────────────────────────

func TestReload_UpstreamSwitchesLive(t *testing.T) {
	up1, up2 := newFakeUpstream(t), newFakeUpstream(t)
	_, p, front := newTestPortal(t, portalTestConfig(up1.URL()), up1)
	t.Cleanup(up2.releaseAll)

	get(t, front.URL+"/hello", nil)
	if up1.hitsFor("/hello") != 1 {
		t.Fatal("first request did not reach the first upstream")
	}

	ck, csrf := portalLogin(t, p)
	body, _ := json.Marshal(map[string]string{"upstream": up2.URL()})
	if rec := portalDo(p, http.MethodPost, "/api/settings", string(body), ck, csrf, false); rec.Code != http.StatusOK {
		t.Fatalf("switch upstream: %d %s", rec.Code, rec.Body.String())
	}

	get(t, front.URL+"/hello", nil)
	if up2.hitsFor("/hello") != 1 || up1.hitsFor("/hello") != 1 {
		t.Errorf("after the switch: up1=%d up2=%d, want 1 and 1", up1.hitsFor("/hello"), up2.hitsFor("/hello"))
	}
}

func TestReload_BanPathsApplyWithoutRestart(t *testing.T) {
	up := newFakeUpstream(t)
	_, p, front := newTestPortal(t, portalTestConfig(up.URL()), up)

	if resp, _ := get(t, front.URL+"/.env", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("before: got %d, want 200", resp.StatusCode)
	}
	ck, csrf := portalLogin(t, p)
	if rec := portalDo(p, http.MethodPost, "/api/settings", `{"ban_paths":"/.env"}`, ck, csrf, false); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if resp, body := get(t, front.URL+"/.env", nil); !isBlocked(resp, body) {
		t.Errorf("after: got %d %s, want blocked", resp.StatusCode, body)
	}
}

func TestReload_AbuseOffKeepsBans(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := portalTestConfig(up.URL())
	cfg.trustedProxies = "127.0.0.1/32"
	a, p, front := newTestPortal(t, cfg, up)
	_, _ = a.abuse.banFor(netip.MustParseAddr("203.0.113.9"), 0, time.Now())
	ck, csrf := portalLogin(t, p)

	if resp, _ := get(t, front.URL+"/hello", withXFF("203.0.113.9")); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("banned client: got %d, want 403", resp.StatusCode)
	}
	if rec := portalDo(p, http.MethodPost, "/api/settings", `{"abuse":false}`, ck, csrf, false); rec.Code != http.StatusOK {
		t.Fatalf("turn off: %d %s", rec.Code, rec.Body.String())
	}
	if resp, _ := get(t, front.URL+"/hello", withXFF("203.0.113.9")); resp.StatusCode != http.StatusOK {
		t.Errorf("registry off: got %d, want 200", resp.StatusCode)
	}
	if rec := portalDo(p, http.MethodPost, "/api/settings", `{"abuse":true}`, ck, csrf, false); rec.Code != http.StatusOK {
		t.Fatalf("turn on: %d %s", rec.Code, rec.Body.String())
	}
	if resp, _ := get(t, front.URL+"/hello", withXFF("203.0.113.9")); resp.StatusCode != http.StatusForbidden {
		t.Errorf("registry back on: got %d, want 403 (the ban must survive)", resp.StatusCode)
	}
}

func TestReload_AdmitTTLAppliesToNewPasses(t *testing.T) {
	up := newFakeUpstream(t)
	_, p, front := newTestPortal(t, portalTestConfig(up.URL()), up)
	ck, csrf := portalLogin(t, p)

	if rec := portalDo(p, http.MethodPost, "/api/settings", `{"admit_ttl":"2m"}`, ck, csrf, false); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	resp, _ := get(t, front.URL+"/page", map[string]string{"Accept": "text/html"})
	for _, c := range resp.Cookies() {
		if c.Name == admitCookie {
			if c.MaxAge != 120 {
				t.Errorf("pass MaxAge: got %d, want 120", c.MaxAge)
			}
			return
		}
	}
	t.Error("no admission pass issued")
}

// ─── listeners ───────────────────────────────────────────────────────────────

func fetch(c *http.Client, url string) (string, *http.Response, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), resp, err
}

func noKeepAlive() *http.Client {
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
}

func TestEndpoint_MovesToNewAddress(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hi")) })
	e := newEndpoint("test", h, time.Second, newServer)
	t.Cleanup(func() { _ = e.shutdown() })

	ln1, err := listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr1 := ln1.Addr().String()
	e.serveOn(ln1, addr1)
	c := noKeepAlive()
	if body, _, err := fetch(c, "http://"+addr1); err != nil || body != "hi" {
		t.Fatalf("first address: %q %v", body, err)
	}

	ln2, err := bindMove(e, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr2 := ln2.Addr().String()
	e.serveOn(ln2, addr2)
	if body, _, err := fetch(c, "http://"+addr2); err != nil || body != "hi" {
		t.Fatalf("second address: %q %v", body, err)
	}
	if e.addr() != addr2 {
		t.Errorf("addr: got %s, want %s", e.addr(), addr2)
	}
	eventually(t, 3*time.Second, func() bool {
		_, _, err := fetch(c, "http://"+addr1)
		return err != nil
	}, "the old address kept answering after the move")
}

func TestEndpoint_SwitchesTLSOnSameSocket(t *testing.T) {
	// Borrow httptest's certificate (valid for 127.0.0.1) and a client that
	// trusts it and speaks HTTP/2.
	ts := httptest.NewUnstartedServer(http.NotFoundHandler())
	ts.EnableHTTP2 = true
	ts.StartTLS()
	cert := ts.TLS.Certificates[0]
	tlsClient := ts.Client()
	ts.Close()

	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hi")) })
	e := newEndpoint("test", h, time.Second, newServer)
	t.Cleanup(func() { _ = e.shutdown() })
	ln, err := listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	e.serveOn(ln, addr)

	if body, _, err := fetch(noKeepAlive(), "http://"+addr); err != nil || body != "hi" {
		t.Fatalf("plain HTTP: %q %v", body, err)
	}

	e.setTLS(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12})
	body, resp, err := fetch(tlsClient, "https://"+addr)
	if err != nil || body != "hi" {
		t.Fatalf("TLS on the same socket: %q %v", body, err)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("TLS connection negotiated %s, want HTTP/2", resp.Proto)
	}

	e.setTLS(nil)
	if body, _, err := fetch(noKeepAlive(), "http://"+addr); err != nil || body != "hi" {
		t.Errorf("back to plain HTTP: %q %v", body, err)
	}
}

func TestReload_ListenIsFixedWhileRunning(t *testing.T) {
	a, err := newApp(testConfig("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	for _, key := range []string{"listen", "portal_listen"} {
		raw, _ := json.Marshal("127.0.0.1:9")
		err := a.changeSettings(map[string]json.RawMessage{key: raw}, nil, netip.Addr{})
		if settingsStatus(err) != http.StatusBadRequest {
			t.Errorf("%s: got %v, want a 400 error", key, err)
		}
	}
	if got := a.current().cfg.listen; got != "127.0.0.1:0" {
		t.Errorf("listen changed to %s", got)
	}
}
