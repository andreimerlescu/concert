package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/fastlane"
)

func TestOnlineReconcile_AdminAPIAndPortalRBACAndAudit(t *testing.T) {
	var failSettle atomic.Bool
	failSettle.Store(true)

	gw := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/supported":
			_ = json.NewEncoder(w).Encode(map[string]any{"kinds": []any{map[string]any{"x402Version": 2, "scheme": "exact", "network": "xrpl:1"}}})
		case "/verify":
			_ = json.NewEncoder(w).Encode(map[string]any{"isValid": true, "payer": "rPayer"})
		case "/settle":
			if failSettle.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "payer": "rPayer", "network": "xrpl:1", "transaction": "tx-settle"})
		case "/reconcile":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "payer": "rPayer", "network": "xrpl:1", "transaction": "tx-online-reconciled"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	restore := newGateway
	newGateway = func(fastlane.Config, *config) (fastlane.Gateway, error) { return handlerGateway{gw}, nil }
	t.Cleanup(func() { newGateway = restore })

	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.dataDir = t.TempDir()
	cfg.auditLog = filepath.Join(cfg.dataDir, "audit.jsonl")
	cfg.admitSecret = []byte("concert-fastlane-reconcile-secret-0123456789")
	cfg.admitSecretGenerated = false
	cfg.adminTokensSpec = "op:operator:operator-token-0123456789,adm:admin:admin-token-0123456789"
	cfg.portal.listen = "127.0.0.1:0"
	cfg.portal.allowSpec = "127.0.0.1/32,::1/128"
	cfg.portal.sessionTTL = time.Hour
	cfg.portal.pass = testPortalPass
	cfg.fastlaneFile = filepath.Join(cfg.dataDir, "fastlane.json")

	req := fastlane.Requirements{Scheme: "exact", Network: "xrpl:1", Amount: "100", Asset: "XRP", PayTo: "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", MaxTimeoutSeconds: 60, Extra: map[string]any{"areFeesSponsored": false}}
	fc := fastlane.Config{
		Enabled: true, Origin: "http://127.0.0.1:8080", TestMode: true, Merchant: "Ops test",
		TermsURL: "http://127.0.0.1:8080/terms", PrivacyURL: "http://127.0.0.1:8080/privacy", RefundURL: "http://127.0.0.1:8080/refunds",
		MaxRecords: 100, PassSeconds: 120,
		Offers: []fastlane.Offer{{Label: "XRP", Requirements: req}},
	}
	b, _ := json.Marshal(fc)
	if err := os.WriteFile(cfg.fastlaneFile, b, 0600); err != nil {
		t.Fatal(err)
	}

	a, p, front := newTestPortal(t, cfg, up)

	// Create session and submit payment that fails into "unknown".
	resp, body := doReq(t, testClient, "POST", front.URL+"/_concert/session", nil, strings.NewReader("{}"))
	if resp.StatusCode != 200 {
		t.Fatalf("session: %d %s", resp.StatusCode, body)
	}
	var sess struct {
		Session string `json:"session"`
	}
	_ = json.Unmarshal(body, &sess)
	proof, _ := json.Marshal(map[string]any{"x402Version": 2, "accepted": req, "payload": map[string]string{"signedTxBlob": "blob-live-1"}})
	headers := map[string]string{fastlane.SessionHeader: sess.Session, "PAYMENT-SIGNATURE": base64.StdEncoding.EncodeToString(proof)}
	resp, body = doReq(t, testClient, "POST", front.URL+"/_concert/payment", headers, strings.NewReader("{}"))
	if resp.StatusCode != 503 {
		t.Fatalf("expected 503 unknown payment, got %d %s", resp.StatusCode, body)
	}

	unres := a.fastlane.UnresolvedReceipts()
	if len(unres) != 1 {
		t.Fatalf("unresolved = %d, want 1", len(unres))
	}
	fp := unres[0].Fingerprint

	// Prometheus metrics must expose fastlane journal stats.
	metrics := a.renderPrometheusMetrics()
	for _, want := range []string{
		"concert_fastlane_records_used 1",
		"concert_fastlane_records_max 100",
		"concert_fastlane_unresolved 1",
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("metrics missing %q", want)
		}
	}

	// Operator role must be forbidden (403) on /_room/fastlane/reconcile.
	recBody := `{"fingerprint":"` + fp + `"}`
	resp, _ = doReq(t, testClient, "POST", front.URL+"/_room/fastlane/reconcile", map[string]string{"Authorization": "Bearer operator-token-0123456789"}, strings.NewReader(recBody))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator reconcile status = %d, want 403", resp.StatusCode)
	}

	// Portal admin session + CSRF succeeds and unlocks payer immediately.
	ck, csrf := portalLogin(t, p)
	rec := portalDo(p, http.MethodPost, "/api/fastlane/reconcile", recBody, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("portal reconcile status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if len(a.fastlane.UnresolvedReceipts()) != 0 {
		t.Fatal("unresolved receipt still present after portal reconcile")
	}

	// Admin bearer token on /_room/fastlane/reconcile is idempotent for the settled receipt (200 OK).
	resp, body = doReq(t, testClient, "POST", front.URL+"/_room/fastlane/reconcile", map[string]string{"Authorization": "Bearer admin-token-0123456789"}, strings.NewReader(recBody))
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"reconciled":true`) {
		t.Fatalf("admin api reconcile status = %d, body=%s", resp.StatusCode, body)
	}

	// Verify audit chain contains fastlane.reconcile and validates cleanly.
	a.audit.close()
	n, err := verifyAuditFile(cfg.auditLog, cfg.admitSecret)
	if err != nil || n == 0 {
		t.Fatalf("verifyAuditFile: n=%d err=%v", n, err)
	}
	rawAudit, _ := os.ReadFile(cfg.auditLog)
	if !strings.Contains(string(rawAudit), `"action":"fastlane.reconcile"`) {
		t.Fatalf("audit log missing fastlane.reconcile entry: %s", rawAudit)
	}
}

func TestRunArchiveReceipts_CLI(t *testing.T) {
	dir := t.TempDir()
	secret := "concert-cli-archive-audit-secret-0123456789"
	t.Setenv("CONCERT_ADMIT_SECRET", secret)

	// Seed a single old expired settled receipt directly into fastlane.jsonl.
	old := time.Now().UTC().Add(-1000 * time.Hour)
	sum := sha256.Sum256([]byte("cli-archive-fp-1"))
	rec := fastlane.Receipt{
		Session:      "sess-old",
		Fingerprint:  hex.EncodeToString(sum[:]),
		State:        "settled",
		Kind:         "payment",
		Network:      "xrpl:1",
		Payer:        "rPayer",
		Requirements: fastlane.Requirements{Scheme: "exact", Network: "xrpl:1", Amount: "100", Asset: "XRP", PayTo: "rDest", MaxTimeoutSeconds: 60},
		Transaction:  "tx-old-1",
		Started:      old,
		Settled:      old,
		Expires:      old.Add(time.Minute),
	}
	line, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(dir, "fastlane.jsonl"), append(line, '\n'), 0600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runArchiveReceipts([]string{"-data-dir", dir, "-older-than", "24h"}, &out); err != nil {
		t.Fatalf("runArchiveReceipts: %v", err)
	}
	var rep fastlane.ArchiveReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("unmarshal CLI output: %v (%s)", err, out.String())
	}
	if rep.Archived != 1 || rep.Kept != 0 || rep.ArchiveFile == "" {
		t.Fatalf("unexpected CLI report: %+v", rep)
	}
	n, err := verifyAuditFile(filepath.Join(dir, auditLogName), []byte(secret))
	if err != nil || n != 1 {
		t.Fatalf("verifyAuditFile after archive CLI: n=%d err=%v", n, err)
	}
}
