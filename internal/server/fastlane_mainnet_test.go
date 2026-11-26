//go:build enterprise

package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

	"github.com/andreimerlescu/concert/internal/fastlane"
	"github.com/andreimerlescu/concert/internal/opt"
)

func mockMainnetGateway() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/supported":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"kinds": []any{
					map[string]any{"x402Version": 2, "scheme": "exact", "network": "xrpl:1"},
					map[string]any{"x402Version": 2, "scheme": "exact", "network": "xrpl:0"},
				},
			})
		case "/verify":
			_ = json.NewEncoder(w).Encode(map[string]any{"isValid": true, "payer": "rPayerWallet111111111111111111111"})
		case "/settle":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "payer": "rPayerWallet111111111111111111111", "network": "xrpl:1", "transaction": "tx-mainnet-test-1"})
		case "/gates/check":
			_ = json.NewEncoder(w).Encode(map[string]any{"passed": true})
		case "/sponsor/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"sponsors": []any{}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestFastLanePortal_LiveConfigEditAndPayToGuards(t *testing.T) {
	gw := mockMainnetGateway()
	restore := newGateway
	newGateway = func(fastlane.Config, *config) (fastlane.Gateway, error) { return handlerGateway{gw}, nil }
	t.Cleanup(func() { newGateway = restore })

	up := newFakeUpstream(t)
	dir := t.TempDir()
	cfg := testConfig(up.URL())
	cfg.dataDir = dir
	cfg.auditLog = filepath.Join(dir, "audit.jsonl")
	cfg.admitSecret = []byte("concert-fastlane-portal-edit-secret-0123456789")
	cfg.admitSecretGenerated = false
	cfg.portal.listen = "127.0.0.1:0"
	cfg.portal.allowSpec = "127.0.0.1/32,::1/128"
	cfg.portal.sessionTTL = time.Hour
	cfg.portal.pass = testPortalPass
	cfg.fastlaneFile = filepath.Join(dir, "fastlane.json")

	rlusdIssuer := "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De"
	payToInitial := "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe"
	payToUpdated := "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"

	fc := fastlane.Config{
		Enabled: true, Origin: "http://127.0.0.1:8080", TestMode: true, Merchant: "Live Portal Test",
		TermsURL: "http://127.0.0.1:8080/terms", PrivacyURL: "http://127.0.0.1:8080/privacy", RefundURL: "http://127.0.0.1:8080/refunds",
		PassSeconds: 300, PassIdleSeconds: 180, PassMaxSeconds: 1800, PassSliding: opt.Some(true),
		Offers: []fastlane.Offer{{
			Label:         "XRP Pass",
			AssetSymbol:   "XRP",
			AssetDecimals: 6,
			DisplayAmount: "1",
			Requirements:  fastlane.Requirements{Scheme: "exact", Network: "xrpl:1", Amount: "1000000", Asset: "XRP", PayTo: payToInitial, MaxTimeoutSeconds: 60},
		}},
	}
	raw, _ := json.Marshal(fc)
	if err := os.WriteFile(cfg.fastlaneFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	a, p, front := newTestPortal(t, cfg, up)
	ck, csrf := portalLogin(t, p)

	// 1. GET /api/fastlane returns the full editable config & metadata at the top level.
	rec := portalDo(p, http.MethodGet, "/api/fastlane", "", ck, "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/fastlane: %d %s", rec.Code, rec.Body.String())
	}
	var snapshot fastlane.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &snapshot); err != nil || !snapshot.Enabled || len(snapshot.Offers) != 1 {
		t.Fatalf("unexpected GET /api/fastlane response: %s", rec.Body.String())
	}

	// 2. Edit price to 0.99 RLUSD + NFT purchase gate + Trustline entry rule live via Portal.
	updated := snapshot
	updated.Offers = []fastlane.Offer{{
		Label:              "RLUSD Fast Pass",
		AssetSymbol:        "RLUSD",
		DisplayAmount:      "0.99",
		RequireCollections: []string{"founders"},
		GateMode:           "any",
		Requirements: fastlane.Requirements{
			Scheme:            "exact",
			Network:           "xrpl:1",
			Amount:            "0.99",
			Asset:             "RLUSD:" + rlusdIssuer,
			PayTo:             payToInitial,
			MaxTimeoutSeconds: 60,
		},
	}}
	updated.Collections = []fastlane.Collection{{
		ID:         "founders",
		Label:      "Founders NFT",
		Network:    "xrpl:1",
		Collection: payToInitial + ":0",
		Usage:      "both",
	}}
	updated.TokenGates = []fastlane.TokenGate{{
		ID:               "rlusd-holders",
		Label:            "10+ RLUSD",
		Network:          "xrpl:1",
		Asset:            "RLUSD:" + rlusdIssuer,
		AssetSymbol:      "RLUSD",
		MinAmount:        "10",
		DisplayMinAmount: "10",
		Usage:            "entry",
	}}
	payload := mustMarshal(t, map[string]any{"config": updated})
	rec = portalDo(p, http.MethodPost, "/api/fastlane/config", string(payload), ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/fastlane/config (RLUSD + gates): %d %s", rec.Code, rec.Body.String())
	}

	// Verify live agentOffer and /_concert/config reflect the new 0.99 RLUSD offer immediately.
	if ao := a.agentOffer.Load(); ao == nil {
		t.Fatal("agentOffer nil after live update")
	} else if !strings.Contains(string(mustMarshal(t, ao.body)), `"0.99"`) {
		t.Fatalf("agentOffer did not reflect live update: %+v", ao.body)
	}
	resp, body := doReq(t, testClient, http.MethodGet, front.URL+"/_concert/config", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"RLUSD"`) || !strings.Contains(string(body), `"0.99"`) || !strings.Contains(string(body), `"rlusd-holders"`) {
		t.Fatalf("/_concert/config after live update: %d %s", resp.StatusCode, body)
	}
	// Verify disk file persisted with 0600 permissions.
	st, err := os.Stat(cfg.fastlaneFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("fastlane.json mode = %o, want 0600", perm)
	}

	// 3. When -fastlane-lock-destinations is set, changing payTo is refused with 403 destinations_locked.
	a.current().cfg.fastlaneLockDestinations = true
	lockedAttempt := updated
	lockedAttempt.Offers = []fastlane.Offer{updated.Offers[0]}
	lockedAttempt.Offers[0].Requirements.PayTo = payToUpdated
	payload = mustMarshal(t, map[string]any{"config": lockedAttempt})
	rec = portalDo(p, http.MethodPost, "/api/fastlane/config", string(payload), ck, csrf, false)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "locked") {
		t.Fatalf("expected 403 destinations_locked, got %d %s", rec.Code, rec.Body.String())
	}

	// Price change while destinations are locked MUST still succeed!
	priceChange := updated
	priceChange.Offers = []fastlane.Offer{updated.Offers[0]}
	priceChange.Offers[0].DisplayAmount = "1.49"
	priceChange.Offers[0].Requirements.Amount = "1.49"
	payload = mustMarshal(t, map[string]any{"config": priceChange})
	rec = portalDo(p, http.MethodPost, "/api/fastlane/config", string(payload), ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("price-only edit under locked destinations should succeed: %d %s", rec.Code, rec.Body.String())
	}

	// 4. When -enterprise-hardened is set (and unlocked), changing payTo without MFA is refused with 403 mfa_required.
	a.current().cfg.fastlaneLockDestinations = false
	a.current().cfg.hardened = true
	rec = portalDo(p, http.MethodPost, "/api/fastlane/config", string(mustMarshal(t, map[string]any{"config": lockedAttempt})), ck, csrf, false)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "MFA") {
		t.Fatalf("expected 403 MFA requirement in hardened mode without MFA, got %d %s", rec.Code, rec.Body.String())
	}

	// Verify audit chain captured the live config update.
	a.audit.close()
	rawAudit, _ := os.ReadFile(cfg.auditLog)
	if !strings.Contains(string(rawAudit), `"action":"fastlane.config.update"`) {
		t.Fatalf("audit log missing fastlane.config.update: %s", rawAudit)
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFastLaneHardened_RefusesUnscreenedMainnet(t *testing.T) {
	dir := t.TempDir()
	fcPath := filepath.Join(dir, "fastlane.json")
	fc := fastlane.Config{
		Enabled: true, Origin: "https://shop.example.com", TestMode: false, PolicyMode: fastlane.PolicyModeNone,
		Merchant: "Mainnet Test", TermsURL: "https://shop.example.com/terms",
		PrivacyURL: "https://shop.example.com/privacy", RefundURL: "https://shop.example.com/refunds",
		Offers: []fastlane.Offer{{
			Label: "XRP",
			Requirements: fastlane.Requirements{
				Scheme: "exact", Network: "xrpl:0", Amount: "1000000", Asset: "XRP",
				PayTo: "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", MaxTimeoutSeconds: 60,
			},
		}},
	}
	if err := os.WriteFile(fcPath, mustMarshal(t, fc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config{fastlaneFile: fcPath, hardened: true}
	if err := validateFastlaneReloadConfig(cfg); err == nil || !strings.Contains(err.Error(), "allow_unscreened_mainnet") {
		t.Fatalf("expected hardened unscreened mainnet error, got %v", err)
	}

	// Explicit allow_unscreened_mainnet=true passes validation.
	fc.AllowUnscreenedMainnet = true
	if err := os.WriteFile(fcPath, mustMarshal(t, fc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateFastlaneReloadConfig(cfg); err != nil {
		t.Fatalf("expected allow_unscreened_mainnet=true to pass, got %v", err)
	}
}

func TestFastLaneOnlineArchiveAndRevoke(t *testing.T) {
	gw := mockMainnetGateway()
	restore := newGateway
	newGateway = func(fastlane.Config, *config) (fastlane.Gateway, error) { return handlerGateway{gw}, nil }
	t.Cleanup(func() { newGateway = restore })

	up := newFakeUpstream(t)
	dir := t.TempDir()
	cfg := testConfig(up.URL())
	cfg.dataDir = dir
	cfg.auditLog = filepath.Join(dir, "audit.jsonl")
	cfg.admitSecret = []byte("concert-fastlane-archive-revoke-secret-012345")
	cfg.admitSecretGenerated = false
	cfg.adminTokensSpec = "adm:admin:admin-token-0123456789"
	cfg.portal.listen = "127.0.0.1:0"
	cfg.portal.allowSpec = "127.0.0.1/32,::1/128"
	cfg.portal.sessionTTL = time.Hour
	cfg.portal.pass = testPortalPass
	cfg.fastlaneFile = filepath.Join(dir, "fastlane.json")

	// Seed an old expired receipt into fastlane.jsonl before startup.
	old := time.Now().UTC().Add(-72 * time.Hour)
	sum := sha256.Sum256([]byte("expired-online-archive-fp"))
	oldRec := fastlane.Receipt{
		Session: "old-sess", Fingerprint: hex.EncodeToString(sum[:]), State: "settled", Kind: "payment",
		Network: "xrpl:1", Payer: "rOldPayer", Transaction: "tx-old-1",
		Requirements: fastlane.Requirements{Scheme: "exact", Network: "xrpl:1", Amount: "100", Asset: "XRP", PayTo: "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", MaxTimeoutSeconds: 60},
		Started:      old, Settled: old, Expires: old.Add(time.Minute),
	}
	if err := os.WriteFile(filepath.Join(dir, "fastlane.jsonl"), append(mustMarshal(t, oldRec), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	req := fastlane.Requirements{Scheme: "exact", Network: "xrpl:1", Amount: "100", Asset: "XRP", PayTo: "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", MaxTimeoutSeconds: 60, Extra: map[string]any{"areFeesSponsored": false}}
	fc := fastlane.Config{
		Enabled: true, Origin: "http://127.0.0.1:8080", TestMode: true, Merchant: "Archive Revoke Test",
		TermsURL: "http://127.0.0.1:8080/terms", PrivacyURL: "http://127.0.0.1:8080/privacy", RefundURL: "http://127.0.0.1:8080/refunds",
		PassSeconds: 300, PassIdleSeconds: 180, PassMaxSeconds: 1800, PassSliding: opt.Some(true),
		Offers: []fastlane.Offer{{Label: "XRP", Requirements: req}},
	}
	if err := os.WriteFile(cfg.fastlaneFile, mustMarshal(t, fc), 0o600); err != nil {
		t.Fatal(err)
	}

	a, p, front := newTestPortal(t, cfg, up)
	ck, csrf := portalLogin(t, p)

	// 1. Acquire a live paid pass cookie.
	jc := jarClient()
	resp, body := doReq(t, jc, http.MethodPost, front.URL+"/_concert/session", nil, strings.NewReader("{}"))
	if resp.StatusCode != 200 {
		t.Fatalf("session: %d %s", resp.StatusCode, body)
	}
	var sess struct {
		Session string `json:"session"`
	}
	_ = json.Unmarshal(body, &sess)
	proof, _ := json.Marshal(map[string]any{"x402Version": 2, "accepted": req, "payload": map[string]string{"signedTxBlob": "blob-revoke-1"}})
	resp, body = doReq(t, jc, http.MethodPost, front.URL+"/_concert/payment", map[string]string{
		fastlane.SessionHeader: sess.Session,
		"PAYMENT-SIGNATURE":    base64.StdEncoding.EncodeToString(proof),
	}, strings.NewReader("{}"))
	if resp.StatusCode != 200 {
		t.Fatalf("payment: %d %s", resp.StatusCode, body)
	}
	sid, ok := a.fastlane.SessionID(&http.Request{Header: http.Header{fastlane.SessionHeader: []string{sess.Session}}})
	if !ok {
		t.Fatal("failed to resolve session ID")
	}

	// Verify pass is eligible right now.
	checkReq, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
	checkReq.Header.Set(fastlane.SessionHeader, sess.Session)
	for _, c := range resp.Cookies() {
		checkReq.AddCookie(c)
	}
	if !a.fastlane.Eligible(checkReq) {
		t.Fatal("expected paid session to be eligible before revocation")
	}

	// 2. Online archive removes the 72h-old receipt while keeping the live pass active!
	rec := portalDo(p, http.MethodPost, "/api/fastlane/archive", `{"older_than":"24h"}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/fastlane/archive: %d %s", rec.Code, rec.Body.String())
	}
	var archOut struct {
		Report fastlane.ArchiveReport `json:"report"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &archOut); err != nil || archOut.Report.Archived != 1 || archOut.Report.Kept != 1 {
		t.Fatalf("unexpected online archive report: %+v (%s)", archOut.Report, rec.Body.String())
	}
	if !a.fastlane.Eligible(checkReq) {
		t.Fatal("live pass should remain valid after online archive of expired receipts")
	}

	// 3. Revoke the session live via Portal -> immediately ineligible!
	rec = portalDo(p, http.MethodPost, "/api/fastlane/revoke", fmt.Sprintf(`{"session":%q}`, sid), ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/fastlane/revoke: %d %s", rec.Code, rec.Body.String())
	}
	if a.fastlane.Eligible(checkReq) {
		t.Fatal("expected revoked pass to be immediately ineligible")
	}

	// 4. Admin bearer API /_room/fastlane/archive also works.
	resp, body = doReq(t, testClient, http.MethodPost, front.URL+"/_room/fastlane/archive", map[string]string{
		"Authorization": "Bearer admin-token-0123456789",
	}, strings.NewReader(`{"older_than":"24h"}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/_room/fastlane/archive: %d %s", resp.StatusCode, body)
	}
}

func TestFastLaneSlidingPassAndSlowUpstream(t *testing.T) {
	gw := mockMainnetGateway()
	restore := newGateway
	newGateway = func(fastlane.Config, *config) (fastlane.Gateway, error) { return handlerGateway{gw}, nil }
	t.Cleanup(func() { newGateway = restore })

	slowUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow-checkout" {
			time.Sleep(1200 * time.Millisecond)
			_, _ = w.Write([]byte("CHECKOUT-OK"))
			return
		}
		_, _ = w.Write([]byte("OK:" + r.URL.Path))
	}))
	defer slowUpstream.Close()

	dir := t.TempDir()
	cfg := testConfig(slowUpstream.URL)
	cfg.dataDir = dir
	cfg.admitSecret = []byte("concert-fastlane-sliding-secret-0123456789")
	cfg.admitSecretGenerated = false
	cfg.capacity = 1
	cfg.priorityCap = 2
	cfg.fastlaneFile = filepath.Join(dir, "fastlane.json")

	req := fastlane.Requirements{Scheme: "exact", Network: "xrpl:1", Amount: "100", Asset: "XRP", PayTo: "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", MaxTimeoutSeconds: 60, Extra: map[string]any{"areFeesSponsored": false}}
	fc := fastlane.Config{
		Enabled: true, Origin: "http://127.0.0.1:8080", TestMode: true, Merchant: "Sliding Test",
		TermsURL: "http://127.0.0.1:8080/terms", PrivacyURL: "http://127.0.0.1:8080/privacy", RefundURL: "http://127.0.0.1:8080/refunds",
		PassSeconds: 60, PassIdleSeconds: 60, PassMaxSeconds: 600, PassSliding: opt.Some(true),
		Offers: []fastlane.Offer{{Label: "XRP", Requirements: req}},
	}
	if err := os.WriteFile(cfg.fastlaneFile, mustMarshal(t, fc), 0o600); err != nil {
		t.Fatal(err)
	}

	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	front := httptest.NewServer(a.handler)
	defer front.Close()

	jc := jarClient()
	resp, body := doReq(t, jc, http.MethodPost, front.URL+"/_concert/session", nil, strings.NewReader("{}"))
	if resp.StatusCode != 200 {
		t.Fatalf("session: %d %s", resp.StatusCode, body)
	}
	var sess struct {
		Session string `json:"session"`
		CSRF    string `json:"csrf"`
	}
	_ = json.Unmarshal(body, &sess)
	proof, _ := json.Marshal(map[string]any{"x402Version": 2, "accepted": req, "payload": map[string]string{"signedTxBlob": "blob-slide-1"}})
	// Browser flow uses the session cookie + X-Concert-CSRF header (not Concert-Session header).
	resp, body = doReq(t, jc, http.MethodPost, front.URL+"/_concert/payment", map[string]string{
		fastlane.CSRFHeader: sess.CSRF,
		"PAYMENT-SIGNATURE": base64.StdEncoding.EncodeToString(proof),
	}, strings.NewReader("{}"))
	if resp.StatusCode != 200 {
		t.Fatalf("payment: %d %s", resp.StatusCode, body)
	}
	var sawPassCookie bool
	for _, c := range resp.Cookies() {
		if c.Name == fastlane.PassCookie {
			sawPassCookie = true
		}
	}
	if !sawPassCookie {
		t.Fatalf("expected %s cookie on payment response", fastlane.PassCookie)
	}

	// Clicking around & hitting a slow upstream script completes cleanly with sliding pass refresh!
	resp, body = doReq(t, jc, http.MethodGet, front.URL+"/slow-checkout", nil, nil)
	if resp.StatusCode != 200 || string(body) != "CHECKOUT-OK" {
		t.Fatalf("slow checkout with fast-lane pass failed: %d %s", resp.StatusCode, body)
	}
	// Verify production default upstream timeout is at least 60s (90s for WordPress).
	if def, ok := settingByKey["upstream_timeout"]; !ok || def.def.(time.Duration) < 60*time.Second {
		t.Fatalf("default upstream_timeout = %v, want >= 60s", def)
	}
}

func TestVhost_ConcertfileFastLaneSIGHUPHandoff(t *testing.T) {
	gw := mockMainnetGateway()
	restore := newGateway
	newGateway = func(fastlane.Config, *config) (fastlane.Gateway, error) { return handlerGateway{gw}, nil }
	t.Cleanup(func() { newGateway = restore })

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("SHOP-ORIGIN"))
	}))
	defer up.Close()

	work := t.TempDir()
	fcPath := filepath.Join(work, "shop-fastlane.json")
	writeFL := func(amount string) {
		fc := fastlane.Config{
			Enabled: true, Origin: "https://shop.example.test", TestMode: true, Merchant: "Shop",
			TermsURL: "https://shop.example.test/terms", PrivacyURL: "https://shop.example.test/privacy", RefundURL: "https://shop.example.test/refunds",
			PassSeconds: 300,
			Offers: []fastlane.Offer{{
				Label:         "RLUSD",
				AssetSymbol:   "RLUSD",
				DisplayAmount: amount,
				Requirements: fastlane.Requirements{
					Scheme: "exact", Network: "xrpl:1", Amount: amount,
					Asset: "RLUSD:rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De", PayTo: "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", MaxTimeoutSeconds: 60,
				},
			}},
		}
		if err := os.WriteFile(fcPath, mustMarshal(t, fc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFL("0.99")

	cfPath := filepath.Join(work, "Concertfile")
	cfContent := fmt.Sprintf(`
{
    listen 127.0.0.1:0
    data_dir %q
    upstream_timeout 75s
}

shop.example.test {
    upstream %s
    cap 4
    priority_cap 2
    fastlane_config %q
}
`, filepath.Join(work, "data"), up.URL, fcPath)
	if err := os.WriteFile(cfPath, []byte(cfContent), 0o600); err != nil {
		t.Fatal(err)
	}

	base := testConfig(up.URL)
	base.configFile = cfPath
	base.admitSecret = []byte("concert-vhost-fastlane-sighup-secret-01234567")
	base.admitSecretGenerated = false

	vm, err := newVhostManager(base)
	if err != nil {
		t.Fatalf("newVhostManager: %v", err)
	}
	defer vm.Close()

	srv := httptest.NewServer(vm)
	defer srv.Close()

	getConfig := func() string {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/_concert/config", nil)
		req.Host = "shop.example.test"
		resp, err := testClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("/_concert/config: %d %s", resp.StatusCode, b)
		}
		return string(b)
	}

	if body := getConfig(); !strings.Contains(body, `"0.99"`) {
		t.Fatalf("initial vhost fastlane config missing 0.99: %s", body)
	}

	// Update fastlane.json price to 1.99 and trigger hot SIGHUP reload — must hand off fastlane.lock cleanly!
	writeFL("1.99")
	if err := vm.Reload(); err != nil {
		t.Fatalf("vm.Reload with active fastlane.lock failed: %v", err)
	}
	if body := getConfig(); !strings.Contains(body, `"1.99"`) {
		t.Fatalf("reloaded vhost fastlane config missing 1.99: %s", body)
	}
}
