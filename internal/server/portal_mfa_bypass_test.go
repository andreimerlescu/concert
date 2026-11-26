//go:build enterprise

package server

import (
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPortalLogin_BlankUsernameRejectedWhenUsersAndPassBothSet(t *testing.T) {
	hash, err := hashArgon2id("StrongUserPass!2026")
	if err != nil {
		t.Fatalf("hashArgon2idPassword: %v", err)
	}
	const totpSecret = "JBSWY3DPEHPK3PXP"
	usersJSON, err := json.Marshal([]portalUserSpec{
		{
			Username:     "alice",
			PasswordHash: hash,
			Role:         "admin",
			TOTPSecret:   totpSecret,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.portal.usersSpec = string(usersJSON)
	cfg.portal.pass = "legacy-shared-portal-pass-12345"
	cfg.portal.sessionTTL = time.Hour
	cfg.portal.allowSpec = "127.0.0.1/32,::1/128"
	a, _ := newTestApp(t, cfg, up)
	p, err := newPortal(a)
	if err != nil || p == nil {
		t.Fatalf("newPortal: %v", err)
	}
	t.Cleanup(p.closeListener)

	if p.hasPass {
		t.Fatal("expected p.hasPass to be disabled when CONCERT_PORTAL_USERS is configured")
	}

	postLogin := func(form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.RemoteAddr = "127.0.0.1:42001"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		p.engine.ServeHTTP(rec, req)
		return rec
	}

	// Regression: blank or whitespace username + shared password MUST NOT bypass MFA/RBAC.
	for _, form := range []url.Values{
		{"pass": {cfg.portal.pass}},
		{"user": {""}, "pass": {cfg.portal.pass}},
		{"user": {"   "}, "pass": {cfg.portal.pass}},
	} {
		rec := postLogin(form)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("MFA bypass attempt (%v): got %d, want 401", form, rec.Code)
		}
		if hasCookie(rec.Result(), portalCookie) {
			t.Fatalf("MFA bypass attempt (%v) issued session cookie!", form)
		}
	}

	// Legitimate multi-user login with valid password + TOTP still succeeds.
	totpKey, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(totpSecret)
	if err != nil {
		t.Fatal(err)
	}
	code := totpCodeAt(totpKey, time.Now().Unix()/30)
	rec := postLogin(url.Values{
		"user": {"alice"},
		"pass": {"StrongUserPass!2026"},
		"totp": {code},
	})
	if rec.Code != http.StatusSeeOther || !hasCookie(rec.Result(), portalCookie) {
		t.Fatalf("legitimate MFA login failed: status=%d cookie=%v", rec.Code, hasCookie(rec.Result(), portalCookie))
	}
}

func TestEnterpriseHardened_RejectsPortalUsersAndPassTogether(t *testing.T) {
	hash, err := hashArgon2id("StrongUserPass!2026")
	if err != nil {
		t.Fatalf("hashArgon2idPassword: %v", err)
	}
	usersJSON, err := json.Marshal([]portalUserSpec{
		{Username: "alice", PasswordHash: hash, Role: "admin"},
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := testConfig("http://127.0.0.1:9999")
	cfg.hardened = true
	cfg.secureCookie = true
	cfg.statsAuth = true
	cfg.adminToken = "0123456789abcdef0123456789abcdef"
	cfg.dataDir = t.TempDir()
	cfg.portal.listen = "127.0.0.1:8081"
	cfg.portal.allowSpec = "127.0.0.1/32"
	cfg.portal.secureCookie = true
	cfg.portal.trustedProxiesSpec = "127.0.0.1/32"
	cfg.portal.sessionTTL = time.Hour
	cfg.portal.usersSpec = string(usersJSON)
	cfg.portal.pass = "legacy-shared-portal-pass-12345"

	err = cfg.normalize()
	if err == nil || !strings.Contains(err.Error(), "CONCERT_PORTAL_PASS") {
		t.Fatalf("expected enterprise-hardened failure when both CONCERT_PORTAL_USERS and CONCERT_PORTAL_PASS are set, got %v", err)
	}
}
