package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func generateTestPKI(t *testing.T, dir string) (caFile, srvCert, srvKey, cliCert, cliKey string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Concert Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caFile = filepath.Join(dir, "ca.pem")
	writePEM(t, caFile, "CERTIFICATE", caDER)

	issue := func(serial int64, cn string, extUsage x509.ExtKeyUsage, certPath, keyPath string) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{extUsage},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		writePEM(t, certPath, "CERTIFICATE", der)
		writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)
	}

	srvCert = filepath.Join(dir, "srv.crt")
	srvKey = filepath.Join(dir, "srv.key")
	issue(2, "localhost", x509.ExtKeyUsageServerAuth, srvCert, srvKey)

	cliCert = filepath.Join(dir, "cli.crt")
	cliKey = filepath.Join(dir, "cli.key")
	issue(3, "concert-client", x509.ExtKeyUsageClientAuth, cliCert, cliKey)
	return
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// ─── 1. Tamper-evident hash-chained audit log ────────────────────────────────

func TestAuditLog_HashChainAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	secret := []byte(strings.Repeat("s", 40))

	al := newAuditLogger(path, secret)
	al.record(auditEvent{Actor: "alice", Role: "admin", Source: "portal", Action: "cap.update", Outcome: "allow"})
	al.record(auditEvent{Actor: "bob", Role: "operator", Source: "api", Action: "ban.lift", Target: "203.0.113.9", Outcome: "allow"})
	al.close()

	// Reopen and append — chain must continue seamlessly across restart.
	al2 := newAuditLogger(path, secret)
	al2.record(auditEvent{Actor: "alice", Role: "admin", Source: "portal", Action: "settings.update", Outcome: "allow"})
	al2.close()

	n, err := verifyAuditFile(path, secret)
	if err != nil || n != 3 {
		t.Fatalf("verifyAuditFile: n=%d err=%v, want n=3 nil", n, err)
	}

	// Wrong secret must fail HMAC verification.
	if _, err := verifyAuditFile(path, []byte(strings.Repeat("x", 40))); err == nil {
		t.Fatal("expected verification failure with wrong secret")
	}

	// Tamper with line 2 actor field and verify detection.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"bob"`, `"mallory"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAuditFile(path, secret); err == nil {
		t.Fatal("expected tamper detection after modifying audit log")
	}
}

// ─── 2. Dual-key zero-downtime secret rotation ───────────────────────────────

func TestSecretRotation_DualKeyAdmitAndPriority(t *testing.T) {
	oldSecret := []byte(strings.Repeat("A", 40))
	newSecret := []byte(strings.Repeat("B", 40))
	now := time.Now()

	oldAdmit := newAdmitter(oldSecret, 10*time.Minute, "/", "", false)
	id, _ := newPassID()
	oldPass := oldAdmit.mint(id, now)

	oldPrio := newPriorityGrants(oldSecret, oldAdmit)
	oldGrant := oldPrio.mint(id, rankCheckout, now.Add(30*time.Minute))

	// New instance configured with newSecret + prevSecret=oldSecret.
	newAdmit := newAdmitter(newSecret, 10*time.Minute, "/", "", false)
	newAdmit.setPrevSecret(oldSecret)

	newPrio := newPriorityGrants(newSecret, newAdmit)
	newPrio.setPrevSecret(oldSecret)

	// Old pass must verify as valid and indicate rotation, and refresh re-mints with newSecret.
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: admitCookie, Value: oldPass})
	rec := httptest.NewRecorder()
	gotID, status := newAdmit.refresh(rec, req, now.Add(time.Minute))
	if status != passValid || gotID != id {
		t.Fatalf("refresh rotated pass: status=%v idMatch=%v, want passValid & same id", status, gotID == id)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != admitCookie {
		t.Fatalf("expected re-signed concert_admit cookie on rotation, got %v", cookies)
	}
	// The newly re-minted cookie must validate even after oldSecret is retired!
	finalAdmit := newAdmitter(newSecret, 10*time.Minute, "/", "", false)
	if _, _, st := finalAdmit.verify(cookies[0].Value, now.Add(time.Minute)); st != passValid {
		t.Fatalf("re-minted cookie should validate under newSecret alone, got %v", st)
	}

	// Old priority grant must also remain valid during rotation.
	if rank, ok := newPrio.verify(oldGrant, id, now.Add(time.Minute)); !ok || rank != rankCheckout {
		t.Fatalf("priority grant rotation: rank=%v ok=%v, want checkout true", rank, ok)
	}
}

// ─── 3. RBAC: Multi-user Argon2id + TOTP MFA + SSO + Scoped API Tokens ───────

func TestEnterprise_RBAC_MultiUser_MFA_SSO_And_Tokens(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()

	viewerHash, err := hashArgon2id("viewer-super-secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	opHash, err := hashArgon2id("operator-super-secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	totpRaw := []byte("0123456789ABCDEF")
	totpB32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(totpRaw)

	usersJSON, _ := json.Marshal([]portalUserSpec{
		{Username: "alice", PasswordHash: viewerHash, Role: "viewer"},
		{Username: "bob", PasswordHash: opHash, Role: "operator", TOTPSecret: totpB32},
	})

	dir := t.TempDir()
	cfg := config{
		upstream:         origin.URL,
		capacity:         4,
		reaper:           time.Minute,
		admitTTL:         5 * time.Minute,
		assetUserCapH1:   8,
		assetUserCapH2:   128,
		streamCap:        10,
		cookiePath:       "/",
		trustedProxies:   "127.0.0.1/32",
		abuseEnabled:     true,
		abuseStrikes:     20,
		abuseWindow:      time.Minute,
		abuseCooldown:    time.Minute,
		abuseMaxCooldown: time.Hour,
		abuseMaxEntries:  1000,
		statsAuth:        true,
		dataDir:          dir,
		admitSecret:      []byte(strings.Repeat("k", 40)),
		adminTokensSpec:  "prom:viewer:viewer-token-123456,ops:operator:operator-token-123456,root:admin:admin-token-12345678",
		portal: portalConfig{
			listen:             "127.0.0.1:0",
			allowSpec:          "127.0.0.1/32",
			sessionTTL:         time.Hour,
			usersSpec:          string(usersJSON),
			ssoHeader:          "X-Forwarded-Email",
			ssoRoleHeader:      "X-Forwarded-Groups",
			ssoDefaultRole:     "viewer",
			trustedProxiesSpec: "127.0.0.1/32",
		},
	}

	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	p, err := newPortal(a)
	if err != nil {
		t.Fatal(err)
	}
	p.closeListener()

	mainSrv := httptest.NewServer(p.wrap(a.handler))
	defer mainSrv.Close()
	portalSrv := httptest.NewServer(p.engine)
	defer portalSrv.Close()

	// 1. Stats & Metrics require auth when -stats-auth=true.
	resp, _ := http.Get(mainSrv.URL + "/_room/stats")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /_room/stats: got %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	req, _ := http.NewRequest("GET", mainSrv.URL+"/_room/stats", nil)
	req.Header.Set("Authorization", "Bearer viewer-token-123456")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer /_room/stats: got %d, want 200", resp.StatusCode)
	}
	var statsBody map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&statsBody)
	resp.Body.Close()
	if _, leaked := statsBody["upstream"]; leaked {
		t.Fatal("viewer token should not see internal upstream URL when -stats-auth is true")
	}

	// Viewer token can scrape Prometheus metrics, cannot change cap.
	req, _ = http.NewRequest("GET", mainSrv.URL+"/_room/metrics", nil)
	req.Header.Set("Authorization", "Bearer viewer-token-123456")
	resp, _ = http.DefaultClient.Do(req)
	metricsBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(metricsBytes), "concert_room_cap 4") {
		t.Fatalf("metrics scrape failed: status=%d", resp.StatusCode)
	}

	req, _ = http.NewRequest("POST", mainSrv.URL+"/_room/cap", strings.NewReader(`{"cap":10}`))
	req.Header.Set("Authorization", "Bearer viewer-token-123456")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer POST /_room/cap: got %d, want 403", resp.StatusCode)
	}

	// Operator token can change cap.
	req, _ = http.NewRequest("POST", mainSrv.URL+"/_room/cap", strings.NewReader(`{"cap":10}`))
	req.Header.Set("Authorization", "Bearer operator-token-123456")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("operator POST /_room/cap: got %d, want 200", resp.StatusCode)
	}

	// 2. Portal multi-user login + TOTP MFA enforcement.
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Bob with wrong TOTP is denied.
	form := url.Values{"user": {"bob"}, "pass": {"operator-super-secret-pass"}, "totp": {"000000"}}
	resp, _ = noFollow.PostForm(portalSrv.URL+"/login", form)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bob wrong TOTP: got %d, want 401", resp.StatusCode)
	}

	// Bob with valid TOTP succeeds.
	validCode := totpCodeAt(totpRaw, time.Now().Unix()/30)
	form.Set("totp", validCode)
	resp, _ = noFollow.PostForm(portalSrv.URL+"/login", form)
	bobCookies := resp.Cookies()
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || len(bobCookies) == 0 {
		t.Fatalf("bob valid TOTP login failed: status=%d", resp.StatusCode)
	}

	// Fetch CSRF token for Bob and verify operator cannot create a permanent ban (requires admin).
	req, _ = http.NewRequest("GET", portalSrv.URL+"/", nil)
	for _, ck := range bobCookies {
		req.AddCookie(ck)
	}
	resp, _ = http.DefaultClient.Do(req)
	htmlBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf := extractCSRF(t, string(htmlBytes))

	req, _ = http.NewRequest("POST", portalSrv.URL+"/api/bans", strings.NewReader(`{"client":"198.51.100.77","permanent":true}`))
	for _, ck := range bobCookies {
		req.AddCookie(ck)
	}
	req.Header.Set("X-CSRF-Token", csrf)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator permanent ban: got %d, want 403", resp.StatusCode)
	}

	// 3. Trusted SSO header authentication grants admin role when group header includes concert-admin.
	req, _ = http.NewRequest("GET", portalSrv.URL+"/api/me", nil)
	req.Header.Set("X-Forwarded-Email", "ciso@enterprise.example")
	req.Header.Set("X-Forwarded-Groups", "engineering, concert-admin")
	resp, _ = http.DefaultClient.Do(req)
	var me map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&me)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || me["actor"] != "sso:ciso@enterprise.example" || me["role"] != "admin" {
		t.Fatalf("SSO /api/me: status=%d body=%v", resp.StatusCode, me)
	}

	// Verify tamper-evident audit log recorded the events cleanly.
	a.audit.close()
	auditPath := filepath.Join(dir, auditLogName)
	cnt, err := verifyAuditFile(auditPath, cfg.admitSecret)
	if err != nil || cnt < 4 {
		t.Fatalf("audit verification failed: count=%d err=%v", cnt, err)
	}
}

func extractCSRF(t *testing.T, html string) string {
	t.Helper()
	const marker = `name="csrf-token" content="`
	idx := strings.Index(html, marker)
	if idx < 0 {
		t.Fatalf("csrf-token meta tag not found")
	}
	rest := html[idx+len(marker):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		t.Fatalf("unterminated csrf-token")
	}
	return rest[:end]
}

// ─── 4. Multi-upstream load balancing, circuit breaker & /_room/readyz ───────

func TestEnterprise_MultiUpstream_CircuitBreaker_And_Readyz(t *testing.T) {
	var failFirst atomic.Bool
	var hits1, hits2 atomic.Int32

	up1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits1.Add(1)
		if failFirst.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("backend-1"))
	}))
	defer up1.Close()

	up2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits2.Add(1)
		_, _ = w.Write([]byte("backend-2"))
	}))
	defer up2.Close()

	cfg := config{
		upstream:           up1.URL + "," + up2.URL,
		capacity:           10,
		reaper:             time.Minute,
		admitTTL:           5 * time.Minute,
		assetUserCapH1:     8,
		assetUserCapH2:     128,
		streamCap:          10,
		cookiePath:         "/",
		trustedProxies:     "127.0.0.1/32",
		upstreamCBFailures: 2,
		upstreamCBCooldown: 30 * time.Second,
		admitSecret:        []byte(strings.Repeat("u", 40)),
	}
	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	front := httptest.NewServer(a.handler)
	defer front.Close()

	// Readyz is 200 ok before draining.
	resp, _ := http.Get(front.URL + "/_room/readyz")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/_room/readyz: got %d, want 200", resp.StatusCode)
	}

	// Make backend-1 return 502s until circuit trips; subsequent traffic must go only to backend-2.
	failFirst.Store(true)
	for i := 0; i < 6; i++ {
		r, err := http.Get(front.URL + "/hello")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(r.Body)
		r.Body.Close()
	}
	before := hits1.Load()
	for i := 0; i < 4; i++ {
		r, err := http.Get(front.URL + "/hello")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != http.StatusOK || string(body) != "backend-2" {
			t.Fatalf("expected failover to backend-2, got %d %q", r.StatusCode, string(body))
		}
	}
	if hits1.Load() != before {
		t.Fatalf("circuit-broken backend-1 still received requests: before=%d after=%d", before, hits1.Load())
	}

	// Flip draining -> /_room/readyz returns 503.
	a.draining.Store(true)
	resp, _ = http.Get(front.URL + "/_room/readyz")
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("draining /_room/readyz: got %d, want 503", resp.StatusCode)
	}
}

// ─── 5. Enterprise PEM TLS, Portal HTTPS & Upstream mTLS ─────────────────────

func TestEnterprise_CustomTLS_And_UpstreamMTLS(t *testing.T) {
	dir := t.TempDir()
	caFile, srvCert, srvKey, cliCert, cliKey := generateTestPKI(t, dir)

	caPEM, _ := os.ReadFile(caFile)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	// Start an origin requiring valid client certificates (mTLS).
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("mtls:" + r.TLS.PeerCertificates[0].Subject.CommonName))
	}))
	sCert, err := tls.LoadX509KeyPair(srvCert, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	origin.TLS = &tls.Config{
		Certificates: []tls.Certificate{sCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	origin.StartTLS()
	defer origin.Close()

	cfg := config{
		upstream:           origin.URL,
		capacity:           4,
		reaper:             time.Minute,
		admitTTL:           5 * time.Minute,
		assetUserCapH1:     8,
		assetUserCapH2:     128,
		streamCap:          10,
		cookiePath:         "/",
		trustedProxies:     "127.0.0.1/32",
		tlsCert:            srvCert,
		tlsKey:             srvKey,
		tlsMinVersion:      "1.3",
		hstsMaxAge:         31536000,
		upstreamCA:         caFile,
		upstreamClientCert: cliCert,
		upstreamClientKey:  cliKey,
		admitSecret:        []byte(strings.Repeat("t", 40)),
	}
	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	tc, err := newACMETLSConfig(a.current().cfg)
	if err != nil || tc == nil || tc.MinVersion != tls.VersionTLS13 {
		t.Fatalf("newACMETLSConfig PEM: tc=%v err=%v", tc, err)
	}

	ln, err := listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ep := newEndpoint("test-tls", a.handler, time.Second, newServer)
	ep.setTLS(tc)
	ep.serveOn(ln, ln.Addr().String())
	defer ep.shutdown()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/secure")
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK || string(body) != "mtls:concert-client" {
		t.Fatalf("upstream mTLS failed: status=%d body=%q", resp.StatusCode, string(body))
	}
	if hsts := resp.Header.Get("Strict-Transport-Security"); !strings.Contains(hsts, "max-age=31536000") {
		t.Fatalf("missing HSTS header: %q", hsts)
	}
	if resp.Header.Get("X-Request-ID") == "" {
		t.Fatal("missing X-Request-ID correlation header")
	}
}

// ─── 6. Privacy Scrubbing, IP Anonymization, DSAR Export/Erasure & JSON Logs ─

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestEnterprise_Privacy_DSAR_And_JSONLogs(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()

	var logBuf syncBuf
	dir := t.TempDir()
	cfg := config{
		upstream:          origin.URL,
		capacity:          4,
		reaper:            time.Minute,
		admitTTL:          5 * time.Minute,
		assetUserCapH1:    8,
		assetUserCapH2:    128,
		streamCap:         10,
		cookiePath:        "/",
		trustedProxies:    "127.0.0.1/32",
		accessLogEnabled:  true,
		accessLog:         &logBuf,
		logFormat:         "json",
		privacyScrubQuery: true,
		dataDir:           dir,
		adminToken:        "admin-secret-token-1234",
		admitSecret:       []byte(strings.Repeat("p", 40)),
		portal: portalConfig{
			listen:     "127.0.0.1:0",
			allowSpec:  "127.0.0.1/32",
			sessionTTL: time.Hour,
			pass:       "portal-secret-password-1234",
		},
	}
	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	p, err := newPortal(a)
	if err != nil {
		t.Fatal(err)
	}
	p.closeListener()

	front := httptest.NewServer(p.wrap(a.handler))
	defer front.Close()

	// Send request containing sensitive query param + W3C traceparent.
	req, _ := http.NewRequest("GET", front.URL+"/checkout?token=topsecret99&item=42", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.55")
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Wait briefly for Gin post-response logger to finish writing.
	deadline := time.Now().Add(time.Second)
	var logText string
	for time.Now().Before(deadline) {
		logText = logBuf.String()
		if strings.Contains(logText, "4bf92f3577b34da6a3ce929d0e0e4736") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Contains(logText, "topsecret99") {
		t.Fatalf("sensitive query param leaked to JSON access log: %s", logText)
	}
	if !strings.Contains(logText, "4bf92f3577b34da6a3ce929d0e0e4736") {
		t.Fatalf("trace_id missing from JSON access log: %s", logText)
	}

	// DSAR export must return history for 203.0.113.55 with redacted token.
	req, _ = http.NewRequest("GET", front.URL+"/_room/privacy/export?client=203.0.113.55", nil)
	req.Header.Set("Authorization", "Bearer admin-secret-token-1234")
	resp, _ = http.DefaultClient.Do(req)
	expBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(expBytes), "topsecret99") || !strings.Contains(string(expBytes), `"history_found":true`) {
		t.Fatalf("DSAR export unexpected: status=%d body=%s", resp.StatusCode, string(expBytes))
	}

	// DSAR erase must wipe the client's history.
	req, _ = http.NewRequest("DELETE", front.URL+"/_room/privacy/erase?client=203.0.113.55", nil)
	req.Header.Set("Authorization", "Bearer admin-secret-token-1234")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DSAR erase: got %d, want 200", resp.StatusCode)
	}

	req, _ = http.NewRequest("GET", front.URL+"/_room/privacy/export?client=203.0.113.55", nil)
	req.Header.Set("Authorization", "Bearer admin-secret-token-1234")
	resp, _ = http.DefaultClient.Do(req)
	expAfter, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(expAfter), `"history_found":false`) {
		t.Fatalf("DSAR erase did not remove client history: %s", string(expAfter))
	}

	// IP anonymization check.
	if got := anonymizeIP(netip.MustParseAddr("198.51.100.77")).String(); got != "198.51.100.0" {
		t.Fatalf("IPv4 anonymize: got %s, want 198.51.100.0", got)
	}
	if got := anonymizeIP(netip.MustParseAddr("2001:db8:abcd:1234::99")).String(); got != "2001:db8:abcd::" {
		t.Fatalf("IPv6 anonymize: got %s, want 2001:db8:abcd::", got)
	}
}

// ─── 7. GitOps Read-Only Settings, Hardened Preset, _FILE Secrets & Promote ──

func TestEnterprise_ReadOnlySettings_HardenedPreset_And_FileSecrets(t *testing.T) {
	dir := t.TempDir()
	secFile := filepath.Join(dir, "admit.secret")
	if err := os.WriteFile(secFile, []byte(strings.Repeat("z", 40)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONCERT_TEST_SECRET_FILE", secFile)
	if got := envOrFile("CONCERT_TEST_SECRET", ""); got != strings.Repeat("z", 40) {
		t.Fatalf("envOrFile: got %q", got)
	}

	// Hardened preset must reject default insecure config.
	bad := config{
		upstream:       "http://127.0.0.1:3000",
		capacity:       10,
		reaper:         time.Minute,
		admitTTL:       5 * time.Minute,
		assetUserCapH1: 8,
		assetUserCapH2: 128,
		streamCap:      10,
		cookiePath:     "/",
		trustedProxies: "127.0.0.1/32",
		hardened:       true,
	}
	if err := bad.normalize(); err == nil {
		t.Fatal("hardened preset should reject insecure configuration")
	}

	// Valid hardened config with read-only GitOps mode.
	good := bad
	good.admitSecret = []byte(strings.Repeat("h", 40))
	good.admitSecretGenerated = false
	good.adminToken = "hardened-admin-token-12345"
	good.secureCookie = true
	good.statsAuth = true
	good.dataDir = dir
	good.readOnlySettings = true

	a, err := newApp(good)
	if err != nil {
		t.Fatalf("valid hardened config failed: %v", err)
	}
	defer a.Close()

	// Read-only settings must reject live mutations with 403.
	err = a.changeSettings(map[string]json.RawMessage{"cap": json.RawMessage("20")}, nil, netip.Addr{})
	if settingsStatus(err) != http.StatusForbidden {
		t.Fatalf("read-only changeSettings: status=%d err=%v, want 403", settingsStatus(err), err)
	}
}

func TestEnterprise_PromoteEndpoint(t *testing.T) {
	block := make(chan struct{})
	inOrigin := make(chan struct{}, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			inOrigin <- struct{}{}
			<-block
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()

	cfg := config{
		upstream:       origin.URL,
		capacity:       1,
		maxQueue:       10,
		reaper:         time.Minute,
		admitTTL:       5 * time.Minute,
		assetUserCapH1: 8,
		assetUserCapH2: 128,
		streamCap:      10,
		cookiePath:     "/",
		trustedProxies: "127.0.0.1/32",
		apiJSON:        true,
		retryAfter:     5,
		adminToken:     "promote-token-123456",
		admitSecret:    []byte(strings.Repeat("q", 40)),
	}
	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	front := httptest.NewServer(a.handler)
	defer front.Close()

	// Occupy the only slot.
	doneHold := make(chan struct{})
	go func() {
		defer close(doneHold)
		r, err := http.Get(front.URL + "/hold")
		if err == nil {
			r.Body.Close()
		}
	}()
	<-inOrigin

	// Queue visitor 1 and visitor 2.
	r1, _ := http.Get(front.URL + "/page")
	r1.Body.Close()
	r2, _ := http.Get(front.URL + "/page")
	var ticket2 string
	for _, ck := range r2.Cookies() {
		if ck.Name == "room_ticket" {
			ticket2 = ck.Value
		}
	}
	r2.Body.Close()
	if ticket2 == "" {
		t.Fatal("expected visitor 2 to receive a room_ticket cookie")
	}

	// Promote visitor 2 to position 1 via POST /_room/promote.
	req, _ := http.NewRequest("POST", front.URL+"/_room/promote",
		strings.NewReader(fmt.Sprintf(`{"ticket":%q,"position":1}`, ticket2)))
	req.Header.Set("Authorization", "Bearer promote-token-123456")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /_room/promote: got %d, want 200", resp.StatusCode)
	}

	close(block)
	<-doneHold
}

// ─── 8. Distributed Cluster Ban Sync via Mock Redis RESP2 Server ─────────────

type mockRedisServer struct {
	ln   net.Listener
	mu   sync.Mutex
	hash map[string]map[string]string
	subs map[string][]net.Conn
}

func startMockRedis(t *testing.T) *mockRedisServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &mockRedisServer{
		ln:   ln,
		hash: map[string]map[string]string{},
		subs: map[string][]net.Conn{},
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConn(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *mockRedisServer) handleConn(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		args, err := readRESPCommand(r)
		if err != nil || len(args) == 0 {
			return
		}
		cmd := strings.ToUpper(args[0])
		switch cmd {
		case "AUTH":
			_, _ = io.WriteString(c, "+OK\r\n")
		case "HSET":
			if len(args) >= 4 {
				s.mu.Lock()
				if s.hash[args[1]] == nil {
					s.hash[args[1]] = map[string]string{}
				}
				s.hash[args[1]][args[2]] = args[3]
				s.mu.Unlock()
			}
			_, _ = io.WriteString(c, ":1\r\n")
		case "HDEL":
			if len(args) >= 3 {
				s.mu.Lock()
				delete(s.hash[args[1]], args[2])
				s.mu.Unlock()
			}
			_, _ = io.WriteString(c, ":1\r\n")
		case "HGETALL":
			s.mu.Lock()
			m := s.hash[args[1]]
			var sb strings.Builder
			fmt.Fprintf(&sb, "*%d\r\n", len(m)*2)
			for k, v := range m {
				fmt.Fprintf(&sb, "$%d\r\n%s\r\n$%d\r\n%s\r\n", len(k), k, len(v), v)
			}
			s.mu.Unlock()
			_, _ = io.WriteString(c, sb.String())
		case "SUBSCRIBE":
			ch := args[1]
			s.mu.Lock()
			s.subs[ch] = append(s.subs[ch], c)
			s.mu.Unlock()
			fmt.Fprintf(c, "*3\r\n$9\r\nsubscribe\r\n$%d\r\n%s\r\n:1\r\n", len(ch), ch)
			// Keep connection open until closed by peer.
			buf := make([]byte, 1)
			for {
				if _, err := r.Read(buf); err != nil {
					return
				}
			}
		case "PUBLISH":
			ch, msg := args[1], args[2]
			s.mu.Lock()
			conns := append([]net.Conn(nil), s.subs[ch]...)
			s.mu.Unlock()
			frame := fmt.Sprintf("*3\r\n$7\r\nmessage\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(ch), ch, len(msg), msg)
			for _, sc := range conns {
				_, _ = io.WriteString(sc, frame)
			}
			fmt.Fprintf(c, ":%d\r\n", len(conns))
		default:
			_, _ = io.WriteString(c, "+OK\r\n")
		}
	}
}

func readRESPCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("expected array, got %q", line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		lenLine, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		sz, err := strconv.Atoi(strings.TrimSpace(lenLine[1:]))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, sz+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		out[i] = string(buf[:sz])
	}
	return out, nil
}

func TestEnterprise_ClusterBanSync(t *testing.T) {
	redis := startMockRedis(t)
	addr := redis.ln.Addr().String()

	makeReg := func() (*abuseRegistry, *counters) {
		st := &counters{}
		c := config{
			abuseEnabled:     true,
			abuseStrikes:     20,
			abuseWindow:      time.Minute,
			abuseCooldown:    10 * time.Minute,
			abuseMaxCooldown: time.Hour,
			abuseMaxEntries:  1000,
		}
		return newAbuseRegistry(c, st), st
	}

	regA, stA := makeReg()
	regB, stB := makeReg()

	csA := newClusterSync(clusterConfig{addr: addr, prefix: "testcluster"}, regA, stA, nil)
	defer csA.close()
	csB := newClusterSync(clusterConfig{addr: addr, prefix: "testcluster"}, regB, stB, nil)
	defer csB.close()

	// Wait briefly for node B to subscribe.
	time.Sleep(100 * time.Millisecond)

	target, _ := parseBanTarget("198.51.100.88")
	until := time.Now().Add(15 * time.Minute).UnixNano()
	csA.publishBan(target, until, 1)

	// Node B must receive and apply the ban.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, banned := regB.banned(netip.MustParseAddr("198.51.100.88"), time.Now()); banned {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if _, banned := regB.banned(netip.MustParseAddr("198.51.100.88"), time.Now()); !banned {
		t.Fatal("node B did not receive replicated ban from node A")
	}

	// Newly joined node C must hydrate the existing ban from Redis HGETALL.
	regC, stC := makeReg()
	csC := newClusterSync(clusterConfig{addr: addr, prefix: "testcluster"}, regC, stC, nil)
	defer csC.close()

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, banned := regC.banned(netip.MustParseAddr("198.51.100.88"), time.Now()); banned {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if _, banned := regC.banned(netip.MustParseAddr("198.51.100.88"), time.Now()); !banned {
		t.Fatal("node C did not hydrate existing ban from Redis")
	}
}
