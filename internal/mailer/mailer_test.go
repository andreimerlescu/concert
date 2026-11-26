package mailer

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/opt"
)

// ─── Cadence & Config Validation ─────────────────────────────────────────────

func TestCadenceValidationAndPacing(t *testing.T) {
	valid := []struct {
		name       string
		c          Cadence
		wantWindow time.Duration
		wantPace   time.Duration
		wantStr    string
	}{
		{"1 per 15m", Cadence{1, 15, UnitMinutes}, 15 * time.Minute, 15 * time.Minute, "1 email every 15 minutes"},
		{"4 per 90m", Cadence{4, 90, UnitMinutes}, 90 * time.Minute, 22*time.Minute + 30*time.Second, "4 emails every 90 minutes"},
		{"1 per 1d", Cadence{1, 1, UnitDays}, 24 * time.Hour, 24 * time.Hour, "1 email every 1 day"},
		{"1 per 7d", Cadence{1, 7, UnitDays}, 7 * 24 * time.Hour, 7 * 24 * time.Hour, "1 email every 7 days"},
		{"333 per 28d", Cadence{333, 28, UnitDays}, 28 * 24 * time.Hour, (28 * 24 * time.Hour) / 333, "333 emails every 28 days"},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.c.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			w, err := tc.c.Window()
			if err != nil || w != tc.wantWindow {
				t.Fatalf("Window = (%v, %v), want %v", w, err, tc.wantWindow)
			}
			if got := tc.c.Pace(); got != tc.wantPace {
				t.Fatalf("Pace = %v, want %v", got, tc.wantPace)
			}
			if got := tc.c.String(); got != tc.wantStr {
				t.Fatalf("String = %q, want %q", got, tc.wantStr)
			}
		})
	}

	invalid := []Cadence{
		{0, 15, UnitMinutes},
		{1001, 28, UnitDays},
		{1, 10, UnitMinutes},  // below 15m minimum
		{1, 31, UnitDays},     // above 30d maximum
		{20, 15, UnitMinutes}, // paces faster than 1/min
		{1, 1, "weeks"},       // unsupported unit
	}
	for _, c := range invalid {
		if err := c.Validate(); err == nil {
			t.Errorf("expected error for invalid cadence %+v", c)
		}
	}
}

func TestConfigValidationAndHeaderInjectionGuard(t *testing.T) {
	base := Config{
		Provider: ProviderSMTP,
		SMTPHost: "smtp.example.com",
		SMTPPort: 587,
		SMTPTLS:  TLSStartTLS,
		FromName: "Concert Alerts",
		FromAddr: "alerts@example.com",
		ToAddrs:  []string{"admin@example.com"},
		Cadence:  DefaultCadence(),
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid config failed: %v", err)
	}

	bad := base
	bad.FromName = "Concert\r\nBcc: evil@attacker.test"
	if err := bad.Validate(); err == nil {
		t.Fatal("expected CRLF in FromName to fail validation")
	}

	badAddr := base
	badAddr.FromAddr = "alerts@example.com\nBcc: evil@attacker.test"
	if err := badAddr.Validate(); err == nil {
		t.Fatal("expected LF in FromAddr to fail validation")
	}

	hardenedPlain := base
	hardenedPlain.SMTPTLS = TLSNone
	hardenedPlain.Hardened = true
	if err := hardenedPlain.Validate(); err == nil {
		t.Fatal("expected SMTP TLS none to be rejected in hardened mode")
	}

	hardenedHTTPAPI := base
	hardenedHTTPAPI.Provider = ProviderResend
	hardenedHTTPAPI.ResendBaseURL = "http://api.resend.com"
	hardenedHTTPAPI.Hardened = true
	if err := hardenedHTTPAPI.Validate(); err == nil {
		t.Fatal("expected non-HTTPS Resend URL to be rejected in hardened mode")
	}
}

// ─── Encrypted Secret Vault ──────────────────────────────────────────────────

func TestSecretStore_AESGCMRotationTamperAndPrecedence(t *testing.T) {
	dir := t.TempDir()
	key1 := []byte("0123456789abcdef0123456789abcdef")
	key2 := []byte("fedcba9876543210fedcba9876543210")

	st, err := NewSecretStore(dir, key1, nil, true, "", Secrets{})
	if err != nil {
		t.Fatalf("NewSecretStore: %v", err)
	}
	p1 := "smtp-secret-value"
	r1 := "re_live_123456789"
	if err := st.Update(SecretsPatch{SMTPPass: opt.Some(p1), ResendAPIKey: opt.Some(r1)}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	secPath := filepath.Join(dir, SecretsFileName)
	raw, err := os.ReadFile(secPath)
	if err != nil {
		t.Fatalf("read secrets file: %v", err)
	}
	if strings.Contains(string(raw), p1) || strings.Contains(string(raw), r1) {
		t.Fatal("plaintext secret appeared in encrypted email-secrets.json")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(secPath)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("email-secrets.json permissions = %v, want 0600", fi.Mode().Perm())
		}
	}

	// Reload under rotated primary key2 with key1 as prevSecret, plus env override for Resend.
	st2, err := NewSecretStore(dir, key2, key1, true, "", Secrets{ResendAPIKey: "re_env_override"})
	if err != nil {
		t.Fatalf("reload with prevSecret: %v", err)
	}
	got := st2.Resolve()
	if got.SMTPPass != p1 {
		t.Fatalf("SMTPPass = %q, want %q", got.SMTPPass, p1)
	}
	if got.ResendAPIKey != "re_env_override" {
		t.Fatalf("env must override file: got %q", got.ResendAPIKey)
	}
	status := st2.Status()
	if status.SMTPPass != SecretSourceFile || status.ResendAPIKey != SecretSourceEnv || status.SendPandaAPIKey != SecretSourceNone {
		t.Fatalf("unexpected status: %+v", status)
	}

	// Next write re-encrypts under key2; loading with key2 alone succeeds.
	sp := "sp_live_abcdef"
	if err := st2.Update(SecretsPatch{SendPandaAPIKey: opt.Some(sp)}); err != nil {
		t.Fatalf("re-encrypt Update: %v", err)
	}
	st3, err := NewSecretStore(dir, key2, nil, true, "", Secrets{})
	if err != nil {
		t.Fatalf("reload under new key2: %v", err)
	}
	if st3.Resolve().SendPandaAPIKey != sp || st3.Resolve().SMTPPass != p1 {
		t.Fatalf("re-encrypted secrets mismatch: %+v", st3.Resolve())
	}

	// Tamper ciphertext -> fail closed!
	var env encryptedEnvelope
	raw2, _ := os.ReadFile(secPath)
	_ = json.Unmarshal(raw2, &env)
	ctBytes, _ := base64.StdEncoding.DecodeString(env.Ciphertext)
	ctBytes[0] ^= 0xff
	env.Ciphertext = base64.StdEncoding.EncodeToString(ctBytes)
	tampered, _ := json.Marshal(env)
	_ = os.WriteFile(secPath, tampered, 0o600)

	stBad, err := NewSecretStore(dir, key2, nil, true, "", Secrets{SMTPPass: "env-still-works"})
	if err == nil {
		t.Fatal("expected tampered ciphertext to return error")
	}
	if stBad.Resolve().SMTPPass != "env-still-works" || stBad.Resolve().SendPandaAPIKey != "" {
		t.Fatalf("tampered vault must fail closed on file secrets while keeping env: %+v", stBad.Resolve())
	}

	// Deleting all secrets removes the file.
	if err := st3.Delete("all"); err != nil {
		t.Fatalf("Delete(all): %v", err)
	}
	if _, err := os.Stat(secPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected email-secrets.json removed after Delete(all), got err=%v", err)
	}
}

// TestSecretStore_PatchThreeStateSemantics verifies SecretsPatch three-state
// opt.Option[string] behavior: None preserves existing credentials, Some("")
// explicitly clears a credential (and deletes email-secrets.json once all are
// empty), and Some(val) replaces the targeted credential.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -v -run '^TestSecretStore_PatchThreeStateSemantics$' ./internal/mailer
//
// # Used By
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
func TestSecretStore_PatchThreeStateSemantics(t *testing.T) {
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")

	st, err := NewSecretStore(dir, key, nil, true, "", Secrets{})
	if err != nil {
		t.Fatalf("NewSecretStore: %v", err)
	}

	// Explicit update (Some(val)) stores all three credentials.
	if err := st.Update(SecretsPatch{
		SMTPPass:        opt.Some("smtp-v1"),
		ResendAPIKey:    opt.Some("resend-v1"),
		SendPandaAPIKey: opt.Some("panda-v1"),
	}); err != nil {
		t.Fatalf("initial Update: %v", err)
	}

	// None leaves existing credentials unchanged; Some(newVal) replaces only its field.
	if err := st.Update(SecretsPatch{
		SMTPPass: opt.Some("smtp-v2"),
	}); err != nil {
		t.Fatalf("partial Update: %v", err)
	}
	got := st.Resolve()
	if got.SMTPPass != "smtp-v2" || got.ResendAPIKey != "resend-v1" || got.SendPandaAPIKey != "panda-v1" {
		t.Fatalf("after partial Update: got %+v, want smtp-v2 / resend-v1 / panda-v1", got)
	}

	// All-None patch is a no-op that preserves stored secrets.
	if err := st.Update(SecretsPatch{}); err != nil {
		t.Fatalf("empty SecretsPatch Update: %v", err)
	}
	got = st.Resolve()
	if got.SMTPPass != "smtp-v2" || got.ResendAPIKey != "resend-v1" || got.SendPandaAPIKey != "panda-v1" {
		t.Fatalf("after all-None Update: got %+v, want unchanged secrets", got)
	}

	// Some("") explicitly clears only the targeted credential without affecting others.
	if err := st.Update(SecretsPatch{ResendAPIKey: opt.Some("")}); err != nil {
		t.Fatalf("explicit clear ResendAPIKey: %v", err)
	}
	got = st.Resolve()
	if got.SMTPPass != "smtp-v2" || got.ResendAPIKey != "" || got.SendPandaAPIKey != "panda-v1" {
		t.Fatalf("after Some(\"\") clear: got %+v, want smtp-v2 / \"\" / panda-v1", got)
	}
	status := st.Status()
	if status.SMTPPass != SecretSourceFile || status.ResendAPIKey != SecretSourceNone || status.SendPandaAPIKey != SecretSourceFile {
		t.Fatalf("Status after partial clear = %+v", status)
	}

	// Clearing the remaining credentials via Some("") removes the vault file.
	if err := st.Update(SecretsPatch{
		SMTPPass:        opt.Some(""),
		SendPandaAPIKey: opt.Some(""),
	}); err != nil {
		t.Fatalf("clear remaining credentials: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, SecretsFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected vault file removed when all credentials cleared, got err=%v", err)
	}
}

// TestStatusSnapshot_OptionTimeJSON verifies that StatusSnapshot.NextEligibleAt
// and StatusSnapshot.BackoffUntil omit absent opt.None[time.Time]() values via
// json omitzero, serialize present opt.Some(t) values as RFC 3339 timestamps,
// and decode explicit JSON null back to None.
//
// # Parameters
//
//   - t: Testing handle injected by go test.
//
// # Example
//
//	go test -v -run '^TestStatusSnapshot_OptionTimeJSON$' ./internal/mailer
//
// # Used By
//
// Invoked by the Go test runner (`go test`); no direct Go callers.
func TestStatusSnapshot_OptionTimeJSON(t *testing.T) {
	// Absent Option[time.Time] fields must be omitted under json omitzero.
	absent := StatusSnapshot{Enabled: true, Provider: ProviderSMTP}
	rawAbsent, err := json.Marshal(absent)
	if err != nil {
		t.Fatalf("json.Marshal(absent): %v", err)
	}
	if strings.Contains(string(rawAbsent), "next_eligible_at") || strings.Contains(string(rawAbsent), "backoff_until") {
		t.Fatalf("expected absent timestamps omitted from JSON, got %s", rawAbsent)
	}
	var roundTripAbsent StatusSnapshot
	if err := json.Unmarshal(rawAbsent, &roundTripAbsent); err != nil {
		t.Fatalf("json.Unmarshal(absent): %v", err)
	}
	if !roundTripAbsent.NextEligibleAt.IsNone() || !roundTripAbsent.BackoffUntil.IsNone() {
		t.Fatalf("expected None after unmarshal of omitted fields: next=%v backoff=%v", roundTripAbsent.NextEligibleAt, roundTripAbsent.BackoffUntil)
	}

	// Present Option[time.Time] fields marshal as RFC 3339 strings and round-trip cleanly.
	nextTS := time.Date(2026, 11, 26, 18, 0, 0, 0, time.UTC)
	backoffTS := time.Date(2026, 11, 26, 18, 5, 0, 0, time.UTC)
	present := StatusSnapshot{
		Enabled:        true,
		Provider:       ProviderSMTP,
		NextEligibleAt: opt.Some(nextTS),
		BackoffUntil:   opt.Some(backoffTS),
	}
	rawPresent, err := json.Marshal(present)
	if err != nil {
		t.Fatalf("json.Marshal(present): %v", err)
	}
	if !strings.Contains(string(rawPresent), `"next_eligible_at":"2026-11-26T18:00:00Z"`) {
		t.Fatalf("expected RFC 3339 next_eligible_at in %s", rawPresent)
	}
	if !strings.Contains(string(rawPresent), `"backoff_until":"2026-11-26T18:05:00Z"`) {
		t.Fatalf("expected RFC 3339 backoff_until in %s", rawPresent)
	}
	var roundTripPresent StatusSnapshot
	if err := json.Unmarshal(rawPresent, &roundTripPresent); err != nil {
		t.Fatalf("json.Unmarshal(present): %v", err)
	}
	gotNext, okNext := roundTripPresent.NextEligibleAt.Get()
	gotBackoff, okBackoff := roundTripPresent.BackoffUntil.Get()
	if !okNext || !gotNext.Equal(nextTS) || !okBackoff || !gotBackoff.Equal(backoffTS) {
		t.Fatalf("round-trip timestamps mismatch: next=(%v,%v) backoff=(%v,%v)", gotNext, okNext, gotBackoff, okBackoff)
	}

	// Explicit JSON null resets Option[time.Time] back to None.
	if err := json.Unmarshal([]byte(`{"next_eligible_at":null,"backoff_until":null}`), &roundTripPresent); err != nil {
		t.Fatalf("json.Unmarshal(null): %v", err)
	}
	if !roundTripPresent.NextEligibleAt.IsNone() || !roundTripPresent.BackoffUntil.IsNone() {
		t.Fatalf("expected JSON null to yield None: next=%v backoff=%v", roundTripPresent.NextEligibleAt, roundTripPresent.BackoffUntil)
	}
}

// ─── SMTP Provider (STARTTLS & Implicit TLS) ─────────────────────────────────

type mockSMTPServer struct {
	addr     string
	port     int
	tlsCfg   *tls.Config
	mu       sync.Mutex
	authed   bool
	authUser string
	authPass string
	messages []string
	mailFrom []string
	rcptTo   []string
	closeFn  func()
}

func startMockSMTP(t *testing.T, implicitTLS bool, wantUser, wantPass string) (*mockSMTPServer, *tls.Config) {
	t.Helper()
	cert, pool := selfSignedCert(t, "127.0.0.1")
	srvTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	cliTLS := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}

	var ln net.Listener
	var err error
	if implicitTLS {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", srvTLS)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("listen mock smtp: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	m := &mockSMTPServer{
		addr:     host,
		port:     port,
		tlsCfg:   srvTLS,
		authUser: wantUser,
		authPass: wantPass,
		closeFn:  func() { _ = ln.Close() },
	}
	t.Cleanup(m.closeFn)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go m.handle(conn, implicitTLS)
		}
	}()
	return m, cliTLS
}

func (m *mockSMTPServer) handle(conn net.Conn, isTLS bool) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := func(line string) { _, _ = io.WriteString(conn, line+"\r\n") }
	w("220 127.0.0.1 ESMTP mock")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO ") || strings.HasPrefix(upper, "HELO "):
			w("250-127.0.0.1")
			if !isTLS {
				w("250-STARTTLS")
			}
			w("250 AUTH PLAIN LOGIN")
		case upper == "STARTTLS":
			w("220 Ready to start TLS")
			tlsConn := tls.Server(conn, m.tlsCfg)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			r = bufio.NewReader(conn)
			isTLS = true
		case strings.HasPrefix(upper, "AUTH PLAIN "):
			b64 := strings.TrimSpace(line[len("AUTH PLAIN "):])
			dec, err := base64.StdEncoding.DecodeString(b64)
			parts := strings.Split(string(dec), "\x00")
			if err != nil || len(parts) != 3 || parts[1] != m.authUser || parts[2] != m.authPass {
				w("535 Authentication failed")
				continue
			}
			m.mu.Lock()
			m.authed = true
			m.mu.Unlock()
			w("235 Authentication successful")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			m.mu.Lock()
			m.mailFrom = append(m.mailFrom, line)
			m.mu.Unlock()
			w("250 OK")
		case strings.HasPrefix(upper, "RCPT TO:"):
			m.mu.Lock()
			m.rcptTo = append(m.rcptTo, line)
			m.mu.Unlock()
			w("250 OK")
		case upper == "DATA":
			w("354 End data with <CR><LF>.<CR><LF>")
			var body strings.Builder
			for {
				dl, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if dl == ".\r\n" || dl == ".\n" {
					break
				}
				body.WriteString(dl)
			}
			m.mu.Lock()
			m.messages = append(m.messages, body.String())
			m.mu.Unlock()
			w("250 Queued")
		case upper == "NOOP":
			w("250 OK")
		case upper == "QUIT":
			w("221 Bye")
			return
		default:
			w("250 OK")
		}
	}
}

func selfSignedCert(t *testing.T, ipStr string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: ipStr},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP(ipStr)},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	parsed, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return cert, pool
}

func TestSMTPSender_StartTLSAndImplicitTLS(t *testing.T) {
	for _, tc := range []struct {
		name     string
		implicit bool
		mode     string
	}{
		{"STARTTLS", false, TLSStartTLS},
		{"ImplicitTLS", true, TLSImplicit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, cliTLS := startMockSMTP(t, tc.implicit, "ops@example.com", "super-secret-pass")
			sender := &SMTPSender{
				Host:      "127.0.0.1",
				Port:      srv.port,
				TLSMode:   tc.mode,
				User:      "ops@example.com",
				Pass:      "super-secret-pass",
				FromAddr:  "alerts@example.com",
				NodeID:    "edge-01",
				TLSConfig: cliTLS,
			}

			// VerifyConnection succeeds without sending any message.
			if err := sender.VerifyConnection(context.Background()); err != nil {
				t.Fatalf("VerifyConnection: %v", err)
			}
			srv.mu.Lock()
			if !srv.authed || len(srv.messages) != 0 {
				t.Fatalf("after VerifyConnection: authed=%v msgs=%d", srv.authed, len(srv.messages))
			}
			srv.mu.Unlock()

			// Send composed digest message.
			res, err := sender.Send(context.Background(), Message{
				FromName: "Concert Ops",
				FromAddr: "alerts@example.com",
				To:       []string{"admin@example.com"},
				Subject:  "[Concert] Test alert",
				TextBody: "Plain text body",
				HTMLBody: "<p>HTML body</p>",
				Headers: map[string]string{
					"Auto-Submitted":        "auto-generated",
					"List-Unsubscribe":      "<https://concert.example/_concert/email/unsubscribe?token=abc>",
					"List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
				},
			})
			if err != nil {
				t.Fatalf("Send: %v", err)
			}
			if res.MessageID == "" || res.Provider != ProviderSMTP {
				t.Fatalf("unexpected SendResult: %+v", res)
			}
			srv.mu.Lock()
			if len(srv.messages) != 1 {
				t.Fatalf("messages = %d, want 1", len(srv.messages))
			}
			rawMsg := srv.messages[0]
			srv.mu.Unlock()

			for _, want := range []string{
				"Auto-Submitted: auto-generated",
				"List-Unsubscribe-Post: List-Unsubscribe=One-Click",
				"multipart/alternative",
				"text/plain; charset=utf-8",
				"text/html; charset=utf-8",
			} {
				if !strings.Contains(rawMsg, want) {
					t.Errorf("SMTP message missing %q:\n%s", want, rawMsg)
				}
			}

			// Header injection attempt must fail before dialing.
			_, err = sender.Send(context.Background(), Message{
				FromAddr: "alerts@example.com",
				To:       []string{"admin@example.com"},
				Subject:  "Evil\r\nBcc: spy@attacker.test",
				TextBody: "hi",
			})
			if err == nil {
				t.Fatal("expected CRLF in Subject to be rejected")
			}

			// Wrong password must fail.
			badSender := *sender
			badSender.Pass = "wrong-pass"
			if err := badSender.VerifyConnection(context.Background()); err == nil {
				t.Fatal("expected wrong SMTP password to fail")
			}
		})
	}
}

// ─── Resend & SendPanda Providers ────────────────────────────────────────────

func TestResendAndSendPandaSenders(t *testing.T) {
	var gotAuth, gotUA, gotIdem, gotPath string
	var gotPayload restEmailPayload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
		gotIdem = r.Header.Get("Idempotency-Key")
		gotPath = r.URL.Path

		switch {
		case r.URL.Path == "/redirect/emails":
			http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/domains"):
			if gotAuth != "Bearer valid-key" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"Invalid API key"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"name":"example.com","status":"verified"}]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/emails"):
			if gotAuth != "Bearer valid-key" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
				return
			}
			_ = json.NewDecoder(r.Body).Decode(&gotPayload)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"msg_12345"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Resend
	resend := &ResendSender{
		BaseURL:  srv.URL,
		APIKey:   "valid-key",
		FromAddr: "alerts@example.com",
		Version:  "0.2.0",
		Client:   defaultHTTPClient(),
	}
	st, sum, _ := resend.VerifyDetail(context.Background())
	if st != CheckPass {
		t.Fatalf("Resend VerifyDetail = (%s, %s), want pass", st, sum)
	}
	res, err := resend.Send(context.Background(), Message{
		FromName:       "Concert",
		FromAddr:       "alerts@example.com",
		To:             []string{"admin@example.com"},
		Subject:        "Digest",
		TextBody:       "text",
		HTMLBody:       "<p>html</p>",
		Headers:        map[string]string{"List-Unsubscribe-Post": "List-Unsubscribe=One-Click"},
		IdempotencyKey: "idem-001",
	})
	if err != nil {
		t.Fatalf("Resend Send: %v", err)
	}
	if res.MessageID != "msg_12345" || gotPath != "/emails" || gotUA != "concert/0.2.0" || gotIdem != "idem-001" {
		t.Fatalf("Resend dispatch mismatch: res=%+v path=%s ua=%s idem=%s", res, gotPath, gotUA, gotIdem)
	}
	if gotPayload.Headers["List-Unsubscribe-Post"] != "List-Unsubscribe=One-Click" {
		t.Fatalf("Resend headers missing compliance header: %+v", gotPayload.Headers)
	}

	// SendPanda with custom base URL path (/v1)
	sp := &SendPandaSender{
		BaseURL:  srv.URL + "/v1",
		APIKey:   "valid-key",
		FromAddr: "alerts@example.com",
		Version:  "0.2.0",
		Client:   defaultHTTPClient(),
	}
	st, sum, _ = sp.VerifyDetail(context.Background())
	if st != CheckPass {
		t.Fatalf("SendPanda VerifyDetail = (%s, %s), want pass", st, sum)
	}
	res, err = sp.Send(context.Background(), Message{
		FromAddr:       "alerts@example.com",
		To:             []string{"admin@example.com"},
		Subject:        "Digest",
		TextBody:       "text",
		HTMLBody:       "<p>html</p>",
		IdempotencyKey: "idem-002",
	})
	if err != nil || res.MessageID != "msg_12345" || gotPath != "/v1/emails" {
		t.Fatalf("SendPanda Send: res=%+v err=%v path=%s", res, err, gotPath)
	}

	// Redirect refusal: API key must never follow 302 redirects!
	spRedirect := &SendPandaSender{
		BaseURL:  srv.URL + "/redirect",
		APIKey:   "valid-key",
		FromAddr: "alerts@example.com",
		Client:   defaultHTTPClient(),
	}
	if _, err := spRedirect.Send(context.Background(), Message{
		FromAddr: "alerts@example.com",
		To:       []string{"admin@example.com"},
		Subject:  "Test",
		TextBody: "hi",
	}); err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("expected redirect refusal error, got %v", err)
	}

	// Invalid API key must fail VerifyConnection and never leak the raw key in error text.
	badResend := *resend
	badResend.APIKey = "re_secret_should_not_appear_in_err"
	err = badResend.VerifyConnection(context.Background())
	if err == nil {
		t.Fatal("expected 401 on invalid API key")
	}
	if strings.Contains(err.Error(), badResend.APIKey) {
		t.Fatalf("API key leaked into error message: %v", err)
	}
}

// ─── DNS Verifier ────────────────────────────────────────────────────────────

type mockResolver struct {
	mx    map[string][]*net.MX
	txt   map[string][]string
	hosts map[string][]string
}

func (m *mockResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if v, ok := m.mx[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Name: name, IsNotFound: true}
}

func (m *mockResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := m.txt[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Name: name, IsNotFound: true}
}

func (m *mockResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if v, ok := m.hosts[host]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Name: host, IsNotFound: true}
}

type fakeSender struct {
	mu       sync.Mutex
	sent     []Message
	sendErr  error
	verifyOK bool
}

func (f *fakeSender) Name() string { return ProviderSMTP }
func (f *fakeSender) Send(_ context.Context, msg Message) (SendResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return SendResult{}, f.sendErr
	}
	f.sent = append(f.sent, msg)
	return SendResult{Provider: ProviderSMTP, MessageID: "fake-" + strconv.Itoa(len(f.sent)), SentAt: time.Now().UTC()}, nil
}
func (f *fakeSender) VerifyConnection(_ context.Context) error {
	if f.verifyOK {
		return nil
	}
	return errors.New("connection refused")
}

func TestDNSVerify(t *testing.T) {
	res := &mockResolver{
		mx: map[string][]*net.MX{
			"sender.example": {{Host: "mx.sender.example.", Pref: 10}},
			"admin.example":  {{Host: "mx.admin.example.", Pref: 10}},
		},
		txt: map[string][]string{
			"sender.example":               {"v=spf1 include:_spf.resend.com ~all"},
			"_dmarc.sender.example":        {"v=DMARC1; p=reject; rua=mailto:dmarc@sender.example"},
			"s1._domainkey.sender.example": {"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"},
		},
		hosts: map[string][]string{
			"smtp.sender.example": {"198.51.100.10"},
		},
	}
	cfg := Config{
		Provider:     ProviderSMTP,
		SMTPHost:     "smtp.sender.example",
		SMTPPort:     587,
		SMTPTLS:      TLSStartTLS,
		FromAddr:     "alerts@sender.example",
		ToAddrs:      []string{"ops@admin.example"},
		DKIMSelector: "s1",
		Cadence:      DefaultCadence(),
	}
	rep := Verify(context.Background(), cfg, &fakeSender{verifyOK: true}, res)
	if !rep.OK {
		t.Fatalf("expected Verify OK, got %+v", rep)
	}
	if len(rep.Checks) != 7 {
		t.Fatalf("expected 7 checks (MX, SPF, DMARC, DKIM, Rcpt MX, Provider DNS, Handshake), got %d", len(rep.Checks))
	}

	// Duplicate SPF should warn, missing DKIM selector should fail.
	res.txt["sender.example"] = []string{"v=spf1 include:a ~all", "v=spf1 include:b ~all"}
	delete(res.txt, "s1._domainkey.sender.example")
	rep2 := Verify(context.Background(), cfg, &fakeSender{verifyOK: false}, res)
	if rep2.OK {
		t.Fatal("expected Verify failure when DKIM selector and provider connection fail")
	}
	foundSPFWarn := false
	foundDKIMFail := false
	for _, c := range rep2.Checks {
		if c.Name == "SPF record" && c.Status == CheckWarn {
			foundSPFWarn = true
		}
		if c.Name == "DKIM selector" && c.Status == CheckFail {
			foundDKIMFail = true
		}
	}
	if !foundSPFWarn || !foundDKIMFail {
		t.Fatalf("expected SPF warn and DKIM fail in %+v", rep2.Checks)
	}
}

// ─── Compliance Composer, XSS Escaping & Signed Unsubscribe Tokens ───────────

func TestComposeDigest_ComplianceAndXSSEscaping(t *testing.T) {
	now := time.Date(2026, 11, 22, 16, 0, 0, 0, time.UTC)
	secret := []byte("0123456789abcdef0123456789abcdef")
	cfg := Config{
		Provider: ProviderResend,
		FromName: "Concert Security",
		FromAddr: "alerts@example.com",
		ToAddrs:  []string{"admin@example.com"},
		Cadence:  Cadence{MaxEmails: 4, WindowValue: 90, WindowUnit: UnitMinutes},
		Compliance: ComplianceConfig{
			OrgName:       "Acme Corp",
			PostalAddress: "100 Main St, Suite 400, Austin, TX 78701",
			PrivacyURL:    "https://acme.example/privacy",
			TermsURL:      "https://acme.example/terms",
			PortalURL:     "https://portal.acme.example",
			PublicBaseURL: "https://shop.acme.example",
		},
		NodeID:  "edge-us-east-1",
		Role:    "edge",
		Version: "0.2.0",
	}

	events := []QueuedEvent{
		{
			Event: Event{
				Category:    CatBans,
				Severity:    SevCritical,
				Title:       `Ban surge <script>alert("xss")</script>`,
				Summary:     `Hit path "/.env?x=<img src=x onerror=alert(1)>"`,
				Fingerprint: "ban:surge",
				Details:     map[string]string{"ua": `<b>bad</b>`},
				At:          now,
			},
			Count:   12,
			FirstAt: now.Add(-5 * time.Minute),
			LastAt:  now,
		},
	}

	msg, err := ComposeDigest(cfg, secret, "admin@example.com", events, 3, now)
	if err != nil {
		t.Fatalf("ComposeDigest: %v", err)
	}
	if msg.Headers["Auto-Submitted"] != "auto-generated" ||
		msg.Headers["Precedence"] != "bulk" ||
		msg.Headers["List-Unsubscribe-Post"] != "List-Unsubscribe=One-Click" ||
		!strings.Contains(msg.Headers["List-Unsubscribe"], "https://shop.acme.example/_concert/email/unsubscribe?token=") {
		t.Fatalf("missing compliance headers: %+v", msg.Headers)
	}
	// XSS payload must be HTML-escaped in HTMLBody!
	if strings.Contains(msg.HTMLBody, `<script>alert("xss")</script>`) || strings.Contains(msg.HTMLBody, `<img src=x`) {
		t.Fatalf("unescaped XSS payload found in HTML email body!")
	}
	for _, want := range []string{
		"Acme Corp",
		"100 Main St, Suite 400, Austin, TX 78701",
		"https://acme.example/privacy",
		"https://acme.example/terms",
		"https://portal.acme.example",
		"4 emails every 90 minutes",
		"Pause / Unsubscribe Alerts",
	} {
		if !strings.Contains(msg.HTMLBody, want) {
			t.Errorf("HTML digest missing %q", want)
		}
	}

	// Extract token from List-Unsubscribe header and verify it.
	unsubHdr := strings.Trim(msg.Headers["List-Unsubscribe"], "<>")
	parts := strings.Split(unsubHdr, "token=")
	if len(parts) != 2 {
		t.Fatalf("unexpected List-Unsubscribe header: %s", unsubHdr)
	}
	rcpt, nodeID, err := VerifyUnsubscribeToken(secret, nil, parts[1], now.Add(time.Hour))
	if err != nil || rcpt != "admin@example.com" || nodeID != "edge-us-east-1" {
		t.Fatalf("VerifyUnsubscribeToken = (%q, %q, %v)", rcpt, nodeID, err)
	}
	// Expired token must fail.
	if _, _, err := VerifyUnsubscribeToken(secret, nil, parts[1], now.Add(UnsubscribeTokenTTL+time.Minute)); err == nil {
		t.Fatal("expected expired unsubscribe token to fail")
	}
	// Key rotation via prevSecret must succeed.
	newSecret := []byte("fedcba9876543210fedcba9876543210")
	if rcpt, _, err := VerifyUnsubscribeToken(newSecret, secret, parts[1], now.Add(time.Hour)); err != nil || rcpt != "admin@example.com" {
		t.Fatalf("expected rotated prevSecret verification to succeed: rcpt=%q err=%v", rcpt, err)
	}
}

func FuzzVerifyUnsubscribeToken(f *testing.F) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Date(2026, 11, 22, 16, 0, 0, 0, time.UTC)
	validTok, _ := SignUnsubscribeToken(secret, "admin@example.com", "node-1", now.Add(time.Hour))
	f.Add(validTok)
	f.Add("")
	f.Add("not-a-token")
	f.Add("a.b.c")
	f.Add(strings.Repeat("A", 600))

	f.Fuzz(func(t *testing.T, tok string) {
		rcpt, _, err := VerifyUnsubscribeToken(secret, nil, tok, now)
		if err == nil {
			if rcpt == "" || !strings.Contains(rcpt, "@") {
				t.Fatalf("accepted token with invalid recipient %q", rcpt)
			}
		}
	})
}

// ─── Queue, Cadence Enforcement, Backoff, Persistence, DSAR & Concurrency ───

func TestService_CadencePacingRollingCapRestartAndBackoff(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	var nowMu sync.Mutex
	clock := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		nowMu.Lock()
		now = now.Add(d)
		nowMu.Unlock()
	}

	fake := &fakeSender{verifyOK: true}
	cats, _ := ParseCategoryList("")
	cfg := Config{
		Provider:   ProviderSMTP,
		SMTPHost:   "smtp.example.com",
		SMTPPort:   587,
		SMTPTLS:    TLSStartTLS,
		FromAddr:   "alerts@example.com",
		ToAddrs:    []string{"admin@example.com"},
		Cadence:    Cadence{MaxEmails: 4, WindowValue: 90, WindowUnit: UnitMinutes}, // pace = 22m30s
		Categories: cats,
		NodeID:     "edge-1",
	}
	unsubKey := []byte("0123456789abcdef0123456789abcdef")
	newSvc := func() *Service {
		return NewService(ServiceOptions{
			DataDir:       dir,
			Config:        cfg,
			UnsubSecret:   unsubKey,
			SenderFactory: func(Config, Secrets) (Sender, error) { return fake, nil },
			Now:           clock,
		})
	}

	svc := newSvc()

	// Coalesce 25 duplicate events into 1 queued item.
	for i := 0; i < 25; i++ {
		if !svc.Enqueue(Event{
			Category:    CatBans,
			Severity:    SevWarn,
			Title:       "Permanent ban",
			Summary:     "Banned 203.0.113.7",
			Fingerprint: "ban:203.0.113.7",
		}) {
			t.Fatal("Enqueue returned false")
		}
	}
	st := svc.Status()
	if st.QueuedUnique != 1 || st.QueuedTotal != 25 {
		t.Fatalf("coalescing failed: unique=%d total=%d", st.QueuedUnique, st.QueuedTotal)
	}

	// Send #1 at t=0 succeeds.
	if _, err := svc.FlushNow(context.Background(), false); err != nil {
		t.Fatalf("Send #1: %v", err)
	}

	// Enqueue another event at t=+10m: must be paced (pace = 22m30s).
	advance(10 * time.Minute)
	svc.Enqueue(Event{Category: CatSilence, Severity: SevCritical, Title: "Leaf silent", Fingerprint: "silence:leaf-1"})
	if _, err := svc.FlushNow(context.Background(), false); !errors.Is(err, errNotDue) {
		t.Fatalf("expected errNotDue at t=+10m, got %v", err)
	}

	// Simulate failed send at t=+23m: must back off without consuming a cadence slot or dropping events!
	advance(13 * time.Minute) // t=+23m
	fake.mu.Lock()
	fake.sendErr = errors.New("smtp timeout")
	fake.mu.Unlock()
	if _, err := svc.FlushNow(context.Background(), false); err == nil {
		t.Fatal("expected simulated send failure")
	}
	stFail := svc.Status()
	if stFail.SentInWindow != 1 || stFail.QueuedUnique != 1 || stFail.ConsecutiveFailures != 1 || stFail.BackoffUntil.IsNone() || stFail.NextEligibleAt.IsNone() {
		t.Fatalf("failed send corrupted state: %+v", stFail)
	}
	// Immediately retrying during 1m backoff must defer.
	fake.mu.Lock()
	fake.sendErr = nil
	fake.mu.Unlock()
	if _, err := svc.FlushNow(context.Background(), false); !errors.Is(err, errNotDue) {
		t.Fatalf("expected backoff to hold retry, got %v", err)
	}

	// After 1m backoff (t=+24m), Send #2 succeeds.
	advance(time.Minute)
	if _, err := svc.FlushNow(context.Background(), false); err != nil {
		t.Fatalf("Send #2 after backoff: %v", err)
	}

	// Restart service from disk: rolling SentAt budget (2 of 4 used) must survive!
	svc.Close()
	qPath := filepath.Join(dir, QueueFileName)
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(qPath); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("email-queue.json permissions = %v (err=%v), want 0600", fi.Mode().Perm(), err)
		}
	}
	svc = newSvc()
	if st := svc.Status(); st.SentInWindow != 2 || st.RemainingInWindow != 2 {
		t.Fatalf("rolling cadence budget lost across restart: %+v", st)
	}

	// Send #3 at t=+47m and Send #4 at t=+70m -> hits 4/90m cap!
	advance(23 * time.Minute) // t=+47m
	svc.Enqueue(Event{Category: CatCapacity, Severity: SevWarn, Title: "Cap drop", Fingerprint: "cap:1"})
	if _, err := svc.FlushNow(context.Background(), false); err != nil {
		t.Fatalf("Send #3: %v", err)
	}
	advance(23 * time.Minute) // t=+70m
	svc.Enqueue(Event{Category: CatQueue, Severity: SevWarn, Title: "Queue full", Fingerprint: "q:1"})
	if _, err := svc.FlushNow(context.Background(), false); err != nil {
		t.Fatalf("Send #4: %v", err)
	}

	// Even after pace elapses (t=+93m? wait: 70+23=93 > 90! Let's test at t=+89m, or better:
	// test hard cap when 4 sends happened inside 90m via manual bypass or tighter timestamps):
	// First check at t=+70m + 15m = +85m (before pace AND at cap).
	// Also test hard rolling cap directly with bypassCadence=true on a 1/15m? No, let's check:
	// Send #1 was at t=0, #2 at +24m, #3 at +47m, #4 at +70m.
	// Wait: at t=+89m, SentInWindow is still 4 (since #1 was at t=0, expires at t=90m).
	// Wait: #4 was at t=+70m, pace is 22m30s, so paceReady is +92m30s.
	// At t=+92m30s, #1 has rolled off so #5 succeeds!
	advance(22*time.Minute + 30*time.Second) // t=+92m30s
	svc.Enqueue(Event{Category: CatSecurity, Severity: SevWarn, Title: "Lockout", Fingerprint: "sec:1"})
	if _, err := svc.FlushNow(context.Background(), false); err != nil {
		t.Fatalf("Send #5 after window rolled: %v", err)
	}
	if len(fake.sent) != 5 {
		t.Fatalf("total sent = %d, want 5", len(fake.sent))
	}

	// Verify DSAR EraseIP removes exact IP without false-matching 198.51.100.10.
	svc.Enqueue(Event{Category: CatBans, Severity: SevWarn, Title: "Ban 198.51.100.1", Summary: "198.51.100.1 banned", Fingerprint: "ban:198.51.100.1"})
	svc.Enqueue(Event{Category: CatBans, Severity: SevWarn, Title: "Ban 198.51.100.10", Summary: "198.51.100.10 banned", Fingerprint: "ban:198.51.100.10"})
	erased := svc.EraseIP("198.51.100.1")
	if erased != 1 {
		t.Fatalf("EraseIP removed %d, want 1", erased)
	}
	if st := svc.Status(); st.QueuedUnique != 1 || st.Pending[0].Fingerprint != "ban:198.51.100.10" {
		t.Fatalf("EraseIP removed wrong entry: %+v", st.Pending)
	}

	// Verify Unsubscribe blocks further delivery to that recipient.
	if err := svc.Unsubscribe("admin@example.com"); err != nil {
		t.Fatalf("Unsubscribe: %v", err)
	}
	if _, err := svc.FlushNow(context.Background(), true); !errors.Is(err, errNoActiveTo) {
		t.Fatalf("expected errNoActiveTo after unsubscribe, got %v", err)
	}
	svc.Close()
}

func TestService_OverflowBoundingAndRaceStress(t *testing.T) {
	fake := &fakeSender{verifyOK: true}
	cats, _ := ParseCategoryList("")
	cfg := Config{
		Provider:   ProviderSMTP,
		SMTPHost:   "smtp.example.com",
		SMTPPort:   587,
		SMTPTLS:    TLSStartTLS,
		FromAddr:   "alerts@example.com",
		ToAddrs:    []string{"admin@example.com"},
		Cadence:    DefaultCadence(),
		Categories: cats,
	}
	svc := NewService(ServiceOptions{
		Config:        cfg,
		SenderFactory: func(Config, Secrets) (Sender, error) { return fake, nil },
		TickInterval:  5 * time.Millisecond,
	})
	svc.Start()
	defer svc.Close()

	var wg sync.WaitGroup
	var enqueued atomic.Int64
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				svc.Enqueue(Event{
					Category:    CatBans,
					Severity:    SevInfo,
					Title:       "Event",
					Summary:     "Burst",
					Fingerprint: "fp-" + strconv.Itoa(gid) + "-" + strconv.Itoa(i),
				})
				enqueued.Add(1)
				if i%25 == 0 {
					_ = svc.Status()
				}
			}
		}(g)
	}
	wg.Wait()
	st := svc.Status()
	if st.QueuedUnique > maxPendingEvents {
		t.Fatalf("queue exceeded bound %d: got %d", maxPendingEvents, st.QueuedUnique)
	}
	if enqueued.Load() != 800 {
		t.Fatalf("enqueued = %d", enqueued.Load())
	}
}
