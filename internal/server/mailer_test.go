//go:build enterprise

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/mailer"
)

func TestEmailPortal_RBACCSRFSecretsAndAudit(t *testing.T) {
	dir := t.TempDir()
	admitKey := []byte("0123456789abcdef0123456789abcdef")

	vHash, err := hashArgon2id("viewer-secret-pass-0123")
	if err != nil {
		t.Fatal(err)
	}
	oHash, err := hashArgon2id("oper-secret-pass-01234")
	if err != nil {
		t.Fatal(err)
	}
	aHash, err := hashArgon2id("admin-secret-pass-0123")
	if err != nil {
		t.Fatal(err)
	}
	usersJSON, err := json.Marshal([]portalUserSpec{
		{Username: "viewer1", Role: "viewer", PasswordHash: vHash},
		{Username: "op1", Role: "operator", PasswordHash: oHash},
		{Username: "adm1", Role: "admin", PasswordHash: aHash},
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := portalTestConfig("http://127.0.0.1:1")
	cfg.dataDir = dir
	cfg.admitSecret = admitKey
	cfg.admitSecretGenerated = false
	cfg.portal.pass = ""
	cfg.portal.usersSpec = string(usersJSON)

	a, p, _ := newTestPortal(t, cfg, nil)

	loginUser := func(user, pass string) (*http.Cookie, string) {
		body := "user=" + url.QueryEscape(user) + "&pass=" + url.QueryEscape(pass)
		rec := portalDo(p, http.MethodPost, "/login", body, nil, "", true)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("login %s: got %d", user, rec.Code)
		}
		var ck *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == portalCookie {
				ck = c
			}
		}
		page := portalDo(p, http.MethodGet, "/", "", ck, "", false)
		m := csrfMetaRe.FindStringSubmatch(page.Body.String())
		if m == nil {
			t.Fatalf("missing csrf for %s", user)
		}
		return ck, m[1]
	}

	vCk, vCSRF := loginUser("viewer1", "viewer-secret-pass-0123")
	oCk, oCSRF := loginUser("op1", "oper-secret-pass-01234")
	aCk, aCSRF := loginUser("adm1", "admin-secret-pass-0123")

	// Viewer can read /api/email, cannot mutate.
	if rec := portalDo(p, http.MethodGet, "/api/email", "", vCk, "", false); rec.Code != http.StatusOK {
		t.Fatalf("viewer GET /api/email: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portalDo(p, http.MethodPost, "/api/email/config", `{"provider":"resend"}`, vCk, vCSRF, false); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST /api/email/config = %d, want 403", rec.Code)
	}
	// Operator cannot mutate email config.
	if rec := portalDo(p, http.MethodPost, "/api/email/config", `{"provider":"resend"}`, oCk, oCSRF, false); rec.Code != http.StatusForbidden {
		t.Fatalf("operator POST /api/email/config = %d, want 403", rec.Code)
	}
	// Admin without CSRF is rejected.
	if rec := portalDo(p, http.MethodPost, "/api/email/config", `{"provider":"resend"}`, aCk, "", false); rec.Code != http.StatusForbidden {
		t.Fatalf("admin missing CSRF = %d, want 403", rec.Code)
	}

	// Admin saves Resend config + write-only encrypted secret + "4 emails every 90 minutes" cadence.
	secretKey := "dummy-resend-api-key-987654"
	savePayload := `{
		"provider":"resend",
		"from_name":"Concert Ops",
		"from_addr":"alerts@example.com",
		"to_addrs":"admin@example.com",
		"cadence_max":4,
		"cadence_window":90,
		"cadence_unit":"minutes",
		"org_name":"Acme Inc",
		"postal_address":"100 Main St, Austin, TX 78701",
		"privacy_url":"https://acme.example/privacy",
		"terms_url":"https://acme.example/terms",
		"portal_url":"https://portal.acme.example",
		"public_base_url":"https://shop.acme.example",
		"secrets":{"resend_api_key":"` + secretKey + `"}
	}`
	rec := portalDo(p, http.MethodPost, "/api/email/config", savePayload, aCk, aCSRF, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin POST /api/email/config: %d %s", rec.Code, rec.Body.String())
	}
	// Raw secret MUST never appear in response, settings.json, or ciphertext on disk.
	if strings.Contains(rec.Body.String(), secretKey) {
		t.Fatal("raw API key leaked in POST /api/email/config response")
	}
	getRec := portalDo(p, http.MethodGet, "/api/email", "", vCk, "", false)
	if strings.Contains(getRec.Body.String(), secretKey) {
		t.Fatal("raw API key leaked in GET /api/email response")
	}
	if !strings.Contains(getRec.Body.String(), `"resend_api_key":"encrypted_file"`) {
		t.Fatalf("expected encrypted_file status badge, got %s", getRec.Body.String())
	}

	settingsRaw, err := os.ReadFile(filepath.Join(dir, settingsFileName))
	if err != nil {
		t.Fatalf("read settings.json: %v", err)
	}
	if strings.Contains(string(settingsRaw), secretKey) {
		t.Fatal("secret leaked into settings.json")
	}

	secPath := filepath.Join(dir, mailer.SecretsFileName)
	secRaw, err := os.ReadFile(secPath)
	if err != nil {
		t.Fatalf("read email-secrets.json: %v", err)
	}
	if strings.Contains(string(secRaw), secretKey) {
		t.Fatal("plaintext secret appeared in email-secrets.json")
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(secPath); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("email-secrets.json mode = %v, want 0600", fi.Mode().Perm())
		}
	}

	// Admin deletes stored secret.
	delRec := portalDo(p, http.MethodDelete, "/api/email/secrets?field=resend_api_key", "", aCk, aCSRF, false)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE /api/email/secrets: %d %s", delRec.Code, delRec.Body.String())
	}
	if !strings.Contains(delRec.Body.String(), `"resend_api_key":"none"`) {
		t.Fatalf("expected secret cleared, got %s", delRec.Body.String())
	}

	// Audit log hash chain must verify cleanly and include email actions.
	auditPath := auditLogPath(cfg)
	a.audit.close()
	n, err := verifyAuditFile(auditPath, admitKey)
	if err != nil || n == 0 {
		t.Fatalf("verifyAuditFile: n=%d err=%v", n, err)
	}
	auditBytes, _ := os.ReadFile(auditPath)
	if !strings.Contains(string(auditBytes), `"email.config.update"`) || !strings.Contains(string(auditBytes), `"email.secret.delete"`) {
		t.Fatalf("expected email actions in audit.jsonl:\n%s", string(auditBytes))
	}
	if strings.Contains(string(auditBytes), secretKey) {
		t.Fatal("secret leaked into audit.jsonl")
	}
}

func TestEmailPortal_ReadOnlyAndEphemeralSecretGuards(t *testing.T) {
	t.Run("read-only-settings forbids mutations", func(t *testing.T) {
		cfg := portalTestConfig("http://127.0.0.1:1")
		cfg.dataDir = t.TempDir()
		cfg.admitSecret = []byte("0123456789abcdef0123456789abcdef")
		cfg.readOnlySettings = true
		_, p, _ := newTestPortal(t, cfg, nil)
		ck, csrf := portalLogin(t, p)

		if rec := portalDo(p, http.MethodPost, "/api/email/config", `{"provider":"smtp"}`, ck, csrf, false); rec.Code != http.StatusForbidden {
			t.Fatalf("read-only POST /api/email/config = %d, want 403", rec.Code)
		}
		if rec := portalDo(p, http.MethodDelete, "/api/email/secrets?field=all", "", ck, csrf, false); rec.Code != http.StatusForbidden {
			t.Fatalf("read-only DELETE /api/email/secrets = %d, want 403", rec.Code)
		}
	})

	t.Run("ephemeral admit secret rejects portal secret persistence", func(t *testing.T) {
		cfg := portalTestConfig("http://127.0.0.1:1")
		cfg.dataDir = t.TempDir()
		cfg.admitSecret = nil // normalize generates ephemeral secret
		_, p, _ := newTestPortal(t, cfg, nil)
		ck, csrf := portalLogin(t, p)

		rec := portalDo(p, http.MethodPost, "/api/email/config", `{"secrets":{"resend_api_key":"re_123"}}`, ck, csrf, false)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("ephemeral secret save = %d (%s), want 400", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "CONCERT_ADMIT_SECRET") {
			t.Fatalf("expected clear guidance mentioning CONCERT_ADMIT_SECRET, got %s", rec.Body.String())
		}
	})
}

func TestEmailEndToEnd_SendPandaEventsUnsubscribeAndDSARErase(t *testing.T) {
	type capturedMsg struct {
		From    string            `json:"from"`
		To      []string          `json:"to"`
		Subject string            `json:"subject"`
		HTML    string            `json:"html"`
		Text    string            `json:"text"`
		Headers map[string]string `json:"headers"`
	}
	var mu sync.Mutex
	var sent []capturedMsg
	var gotAuth string

	mockProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/domains":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"name":"example.com","status":"verified"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/emails":
			var m capturedMsg
			_ = json.NewDecoder(r.Body).Decode(&m)
			mu.Lock()
			sent = append(sent, m)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"sp_msg_001"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockProvider.Close()

	dir := t.TempDir()
	admitKey := []byte("0123456789abcdef0123456789abcdef")

	cfg := portalTestConfig("http://127.0.0.1:1")
	cfg.dataDir = dir
	cfg.admitSecret = admitKey
	cfg.privacyAnonymizeIP = false
	cfg.email = emailConfig{
		provider:           mailer.ProviderSendPanda,
		sendPandaURL:       mockProvider.URL + "/v1",
		sendPandaAPIKey:    "sp_env_live_key",
		fromName:           "Concert Security",
		fromAddr:           "alerts@example.com",
		toAddrs:            "admin@example.com",
		cadenceMax:         4,
		cadenceWindowValue: 90,
		cadenceWindowUnit:  mailer.UnitMinutes,
		orgName:            "Concert Enterprise",
		postalAddress:      "500 Market St, San Francisco, CA 94105",
		privacyURL:         "https://concert.example/privacy",
		termsURL:           "https://concert.example/terms",
		portalURL:          "https://portal.concert.example",
		publicBaseURL:      "https://shop.concert.example",
	}

	a, p, front := newTestPortal(t, cfg, nil)
	ck, csrf := portalLogin(t, p)

	// 1. Test Email send via portal hits mock SendPanda and includes compliance headers/footer.
	testRec := portalDo(p, http.MethodPost, "/api/email/test", `{}`, ck, csrf, false)
	if testRec.Code != http.StatusOK {
		t.Fatalf("POST /api/email/test: %d %s", testRec.Code, testRec.Body.String())
	}
	mu.Lock()
	if len(sent) != 1 || gotAuth != "Bearer sp_env_live_key" {
		mu.Unlock()
		t.Fatalf("mock provider received %d msgs, auth=%q", len(sent), gotAuth)
	}
	testMsg := sent[0]
	mu.Unlock()
	if testMsg.Headers["Auto-Submitted"] != "auto-generated" ||
		testMsg.Headers["List-Unsubscribe-Post"] != "List-Unsubscribe=One-Click" ||
		!strings.Contains(testMsg.HTML, "500 Market St, San Francisco, CA 94105") {
		t.Fatalf("test email missing compliance artifacts: headers=%+v", testMsg.Headers)
	}

	// 2. Trigger permanent ban & DSAR erase before flush: verify DSAR removes the IP from email-queue.json!
	banRec := portalDo(p, http.MethodPost, "/api/bans", `{"client":"198.51.100.42","permanent":true}`, ck, csrf, false)
	if banRec.Code != http.StatusOK {
		t.Fatalf("ban 198.51.100.42: %d %s", banRec.Code, banRec.Body.String())
	}
	banRec2 := portalDo(p, http.MethodPost, "/api/bans", `{"client":"198.51.100.99","permanent":true}`, ck, csrf, false)
	if banRec2.Code != http.StatusOK {
		t.Fatalf("ban 198.51.100.99: %d %s", banRec2.Code, banRec2.Body.String())
	}

	// Verify both queued before erase.
	if st := a.mailer.Status(); st.QueuedUnique < 2 {
		t.Fatalf("expected >= 2 queued ban events, got %+v", st.Pending)
	}

	// DSAR erase 198.51.100.42 -> must purge 198.51.100.42 from queue and never re-enqueue it!
	eraseRec := portalDo(p, http.MethodDelete, "/api/privacy/erase?client=198.51.100.42", "", ck, csrf, false)
	if eraseRec.Code != http.StatusOK {
		t.Fatalf("DSAR erase: %d %s", eraseRec.Code, eraseRec.Body.String())
	}
	for _, ev := range a.mailer.Status().Pending {
		if strings.Contains(ev.Summary, "198.51.100.42") || strings.Contains(ev.Fingerprint, "198.51.100.42") {
			t.Fatalf("erased IP still present in email queue: %+v", ev)
		}
	}

	// 3. Flush remaining queued events -> digest delivered & metrics incremented.
	flushRec := portalDo(p, http.MethodPost, "/api/email/flush", `{"bypass_cadence":true}`, ck, csrf, false)
	if flushRec.Code != http.StatusOK {
		t.Fatalf("POST /api/email/flush: %d %s", flushRec.Code, flushRec.Body.String())
	}
	mu.Lock()
	if len(sent) != 2 {
		mu.Unlock()
		t.Fatalf("expected 2 sent emails (test + digest), got %d", len(sent))
	}
	digestMsg := sent[1]
	mu.Unlock()
	if !strings.Contains(digestMsg.Text, "198.51.100.99") || strings.Contains(digestMsg.Text, "198.51.100.42") {
		t.Fatalf("digest content unexpected:\n%s", digestMsg.Text)
	}

	// Verify Prometheus metrics include email counters.
	metricsText := a.renderPrometheusMetrics()
	if !strings.Contains(metricsText, "concert_email_sent_total 1") {
		t.Fatalf("expected concert_email_sent_total 1 in metrics:\n%s", metricsText)
	}

	// 4. Signed RFC 8058 One-Click Unsubscribe on main listener (no portal cookie required!).
	unsubHdr := strings.Trim(digestMsg.Headers["List-Unsubscribe"], "<>")
	parsedUnsub, err := url.Parse(unsubHdr)
	if err != nil {
		t.Fatalf("parse List-Unsubscribe %q: %v", unsubHdr, err)
	}
	mainUnsubURL := front.URL + parsedUnsub.Path + "?" + parsedUnsub.RawQuery

	// GET must NOT unsubscribe (protects against email link-scanners).
	getResp, err := http.Get(mainUnsubURL)
	if err != nil {
		t.Fatalf("GET unsubscribe: %v", err)
	}
	_ = getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET unsubscribe = %d, want 200", getResp.StatusCode)
	}
	if len(a.mailer.Status().Unsubscribed) != 0 {
		t.Fatal("GET unsubscribe must not mutate subscription state")
	}

	// POST with RFC 8058 body unsubscribes recipient!
	postResp, err := http.Post(mainUnsubURL, "application/x-www-form-urlencoded", strings.NewReader("List-Unsubscribe=One-Click"))
	if err != nil {
		t.Fatalf("POST unsubscribe: %v", err)
	}
	_ = postResp.Body.Close()
	if postResp.StatusCode != http.StatusOK {
		t.Fatalf("POST unsubscribe = %d, want 200", postResp.StatusCode)
	}
	if _, ok := a.mailer.Status().Unsubscribed["admin@example.com"]; !ok {
		t.Fatalf("expected admin@example.com unsubscribed, got %+v", a.mailer.Status().Unsubscribed)
	}

	// Tampered token returns 400.
	badQuery := url.Values{}
	badQuery.Set("token", "bad.token")
	badResp, err := http.Post(front.URL+mailer.UnsubscribeMainPath+"?"+badQuery.Encode(), "application/x-www-form-urlencoded", strings.NewReader("List-Unsubscribe=One-Click"))
	if err != nil {
		t.Fatalf("POST bad unsubscribe: %v", err)
	}
	_ = badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad token status = %d, want 400", badResp.StatusCode)
	}

	// Admin can re-enable recipient via portal /api/email/pause.
	reRec := portalDo(p, http.MethodPost, "/api/email/pause", `{"recipient":"admin@example.com","paused":false}`, ck, csrf, false)
	if reRec.Code != http.StatusOK {
		t.Fatalf("re-enable recipient: %d %s", reRec.Code, reRec.Body.String())
	}
	if len(a.mailer.Status().Unsubscribed) != 0 {
		t.Fatalf("expected recipient re-enabled, got %+v", a.mailer.Status().Unsubscribed)
	}

	// Verify privacy IP anonymization on newly queued ban events when enabled.
	if rec := portalDo(p, http.MethodPost, "/api/settings", `{"privacy_anonymize_ip":true}`, ck, csrf, false); rec.Code != http.StatusOK {
		t.Fatalf("enable privacy_anonymize_ip: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portalDo(p, http.MethodPost, "/api/bans", `{"client":"203.0.113.77","permanent":true}`, ck, csrf, false); rec.Code != http.StatusOK {
		t.Fatalf("ban 203.0.113.77: %d %s", rec.Code, rec.Body.String())
	}
	foundAnon := false
	for _, ev := range a.mailer.Status().Pending {
		if strings.Contains(ev.Summary, "203.0.113.77") {
			t.Fatalf("unmasked IP leaked into queued email event when privacy_anonymize_ip=true: %+v", ev)
		}
		if strings.Contains(ev.Summary, "203.0.113.0") {
			foundAnon = true
		}
	}
	if !foundAnon {
		t.Fatalf("expected anonymized IP 203.0.113.0 in queued events, got %+v", a.mailer.Status().Pending)
	}
	_ = time.Now()
}

func TestEmailConfigSaveReq_OptionPatchSemantics(t *testing.T) {
	t.Run("unmarshal distinguishes omitted and null from explicit zero values", func(t *testing.T) {
		raw := `{
			"provider": null,
			"smtp_host": "",
			"smtp_port": 0,
			"cadence_max": 5,
			"secrets": {
				"smtp_pass": "",
				"resend_api_key": "re_test_key",
				"sendpanda_api_key": null
			}
		}`
		var req emailConfigSaveReq
		if err := json.Unmarshal([]byte(raw), &req); err != nil {
			t.Fatalf("unmarshal emailConfigSaveReq: %v", err)
		}
		if !req.Provider.IsNone() {
			t.Errorf("Provider = %v, want None for JSON null", req.Provider)
		}
		if !req.FromAddr.IsNone() {
			t.Errorf("FromAddr = %v, want None for omitted field", req.FromAddr)
		}
		if v, ok := req.SMTPHost.Get(); !ok || v != "" {
			t.Errorf("SMTPHost = (%q, %v), want (\"\", true)", v, ok)
		}
		if v, ok := req.SMTPPort.Get(); !ok || v != 0 {
			t.Errorf("SMTPPort = (%d, %v), want (0, true)", v, ok)
		}
		if v, ok := req.CadenceMax.Get(); !ok || v != 5 {
			t.Errorf("CadenceMax = (%d, %v), want (5, true)", v, ok)
		}
		if req.Secrets == nil {
			t.Fatal("Secrets = nil, want non-nil")
		}
		if v, ok := req.Secrets.SMTPPass.Get(); !ok || v != "" {
			t.Errorf("Secrets.SMTPPass = (%q, %v), want (\"\", true)", v, ok)
		}
		if v, ok := req.Secrets.ResendAPIKey.Get(); !ok || v != "re_test_key" {
			t.Errorf("Secrets.ResendAPIKey = (%q, %v), want (\"re_test_key\", true)", v, ok)
		}
		if !req.Secrets.SendPandaAPIKey.IsNone() {
			t.Errorf("Secrets.SendPandaAPIKey = %v, want None for JSON null", req.Secrets.SendPandaAPIKey)
		}
	})

	t.Run("partial portal patch preserves omitted settings and secrets", func(t *testing.T) {
		dir := t.TempDir()
		cfg := portalTestConfig("http://127.0.0.1:1")
		cfg.dataDir = dir
		cfg.admitSecret = []byte("0123456789abcdef0123456789abcdef")
		cfg.admitSecretGenerated = false
		_, p, _ := newTestPortal(t, cfg, nil)
		ck, csrf := portalLogin(t, p)

		initPayload := `{
			"provider": "resend",
			"from_name": "Initial Ops",
			"from_addr": "alerts@example.com",
			"to_addrs": "admin@example.com",
			"cadence_max": 3,
			"cadence_window": 30,
			"cadence_unit": "minutes",
			"secrets": {"resend_api_key": "dummy-initial-resend-key-001"}
		}`
		if rec := portalDo(p, http.MethodPost, "/api/email/config", initPayload, ck, csrf, false); rec.Code != http.StatusOK {
			t.Fatalf("initial save: %d %s", rec.Code, rec.Body.String())
		}

		// Patch only from_name and send empty/null secret fields: existing provider, cadence, and resend_api_key must remain intact.
		patchPayload := `{
			"provider": null,
			"from_name": "Updated Ops",
			"secrets": {"smtp_pass": "", "resend_api_key": null}
		}`
		rec := portalDo(p, http.MethodPost, "/api/email/config", patchPayload, ck, csrf, false)
		if rec.Code != http.StatusOK {
			t.Fatalf("partial patch: %d %s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		for _, want := range []string{
			`"provider":"resend"`,
			`"from_name":"Updated Ops"`,
			`"cadence_max":3`,
			`"resend_api_key":"encrypted_file"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("partial patch response missing %s: %s", want, body)
			}
		}

		// Sending only empty/null fields must return 400 (nothing to update).
		emptyRec := portalDo(p, http.MethodPost, "/api/email/config", `{"provider":null,"secrets":{"smtp_pass":""}}`, ck, csrf, false)
		if emptyRec.Code != http.StatusBadRequest {
			t.Fatalf("empty patch status = %d, want 400 (%s)", emptyRec.Code, emptyRec.Body.String())
		}
	})
}
