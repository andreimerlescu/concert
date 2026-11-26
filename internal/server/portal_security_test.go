package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPortalLogin_SinglePasswordModeRejectsBlankOrUnexpectedUserField(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.portal.pass = testPortalPass
	cfg.portal.sessionTTL = time.Hour
	cfg.portal.allowSpec = "127.0.0.1/32,::1/128"
	a, _ := newTestApp(t, cfg, up)
	p, err := newPortal(a)
	if err != nil || p == nil {
		t.Fatalf("newPortal: %v", err)
	}
	t.Cleanup(p.closeListener)

	postLogin := func(form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.RemoteAddr = "127.0.0.1:42000"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		p.engine.ServeHTTP(rec, req)
		return rec
	}

	// Explicitly supplied blank/whitespace or non-empty username must be rejected
	// even in CONCERT_PORTAL_PASS-only mode so blank usernames never slip through.
	for _, badUser := range []string{"", "   ", "\t", "admin"} {
		form := url.Values{"user": {badUser}, "pass": {testPortalPass}}
		rec := postLogin(form)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("user=%q in pass-only mode: got %d, want 401", badUser, rec.Code)
		}
		if hasCookie(rec.Result(), portalCookie) {
			t.Fatalf("user=%q in pass-only mode issued session cookie", badUser)
		}
	}

	// Normal single-password login (no user field sent by the single-password form) succeeds.
	rec := postLogin(url.Values{"pass": {testPortalPass}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("standard pass-only login: got %d, want 303", rec.Code)
	}
	if !hasCookie(rec.Result(), portalCookie) {
		t.Fatal("standard pass-only login did not set session cookie")
	}
}
