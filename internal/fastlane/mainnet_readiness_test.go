package fastlane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type stubGateway struct {
	gatePass     bool
	directFound  bool
	directTx     string
	directPayer  string
	verifyPayer  string
	settleCalls  int
	lastGateAddr string
}

func (g *stubGateway) Handle(_ context.Context, op string, body []byte) (any, error) {
	switch op {
	case "/supported":
		return map[string]any{"kinds": []map[string]any{
			{"x402Version": 2, "scheme": "exact", "network": "xrpl:0"},
			{"x402Version": 2, "scheme": "exact", "network": "xrpl:1"},
			{"x402Version": 2, "scheme": "exact", "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"},
		}}, nil
	case "/gates/check":
		var in struct {
			Address string `json:"address"`
		}
		_ = json.Unmarshal(body, &in)
		g.lastGateAddr = in.Address
		return map[string]any{"passed": g.gatePass, "matched": "ok"}, nil
	case "/direct/verify":
		return map[string]any{"found": g.directFound, "transaction": g.directTx, "payer": g.directPayer}, nil
	case "/verify":
		return map[string]any{"isValid": true, "payer": g.verifyPayer}, nil
	case "/settle":
		g.settleCalls++
		return map[string]any{"success": true, "transaction": "TX_RLUSD_1", "network": "xrpl:1", "payer": g.verifyPayer}, nil
	}
	return map[string]any{}, nil
}

func TestConfig_MultiTokenRLUSDAndPolicyModes(t *testing.T) {
	base := Config{
		Enabled:    true,
		Origin:     "https://shop.example.com",
		TestMode:   false,
		Merchant:   "Concert Shop",
		TermsURL:   "https://shop.example.com/terms",
		PrivacyURL: "https://shop.example.com/privacy",
		RefundURL:  "https://shop.example.com/refunds",
		Offers: []Offer{
			{
				Label:         "0.99 RLUSD",
				DisplayAmount: "0.99",
				AssetSymbol:   "RLUSD",
				Requirements: Requirements{
					Scheme:            "exact",
					Network:           "xrpl:0",
					Asset:             "RLUSD:rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De",
					PayTo:             "rQLTGGRoGbQZLK2ErVKio1pxViAR8fvMBT",
					MaxTimeoutSeconds: 60,
					Extra:             map[string]any{"areFeesSponsored": false},
				},
			},
		},
	}
	// Default mainnet without policy_url must still fail closed.
	c := base
	if err := c.Validate(); err == nil {
		t.Fatal("expected mainnet without policy to fail")
	}
	// Blocklist mode requires file path.
	c = base
	c.PolicyMode = PolicyModeBlocklist
	if err := c.Validate(); err == nil {
		t.Fatal("expected blocklist mode without file to fail")
	}
	c.PolicyBlocklistFile = "/tmp/ofac.txt"
	if err := c.Validate(); err != nil {
		t.Fatalf("expected blocklist mode with file to pass: %v", err)
	}
	if c.Offers[0].Requirements.Amount != "0.99" {
		t.Fatalf("expected auto-derived XRPL IOU amount 0.99, got %q", c.Offers[0].Requirements.Amount)
	}
	// Explicit none mode allowed.
	c = base
	c.PolicyMode = PolicyModeNone
	if err := c.Validate(); err != nil {
		t.Fatalf("expected explicit policy_mode=none to pass: %v", err)
	}
}

func TestDirectProof_PrecheckDestTagMemo_SlidingCrossEdgeAndRevoke(t *testing.T) {
	secret := bytes.Repeat([]byte("k"), 32)
	blockFile := filepath.Join(t.TempDir(), "blocked.txt")
	if err := os.WriteFile(blockFile, []byte("# OFAC test\nrBLOCKED11111111111111111111111111\n"), 0600); err != nil {
		t.Fatal(err)
	}
	gw := &stubGateway{
		gatePass:    false,
		directFound: true,
		directTx:    "XRPL_PROOF_TX_1",
		directPayer: "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
		verifyPayer: "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
	}
	cfg := Config{
		Enabled:             true,
		Origin:              "https://shop.example.com",
		TestMode:            true,
		PolicyMode:          PolicyModeBlocklist,
		PolicyBlocklistFile: blockFile,
		PassSeconds:         60,
		PassIdleSeconds:     60,
		PassMaxSeconds:      300,
		NFTPassSeconds:      60,
		MaxRecords:          100,
		Merchant:            "Concert Shop",
		TermsURL:            "https://shop.example.com/terms",
		PrivacyURL:          "https://shop.example.com/privacy",
		RefundURL:           "https://shop.example.com/refunds",
		Offers: []Offer{
			{
				Label:             "0.99 RLUSD",
				DisplayAmount:     "0.99",
				AssetSymbol:       "RLUSD",
				RequireTokenGates: []string{"hold-rlusd"},
				GateMode:          "all",
				Requirements: Requirements{
					Scheme:            "exact",
					Network:           "xrpl:1",
					Amount:            "0.99",
					Asset:             "RLUSD:rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De",
					PayTo:             "rQLTGGRoGbQZLK2ErVKio1pxViAR8fvMBT",
					MaxTimeoutSeconds: 60,
					Extra:             map[string]any{"areFeesSponsored": false},
				},
			},
		},
		Collections: []Collection{
			{ID: "founders", Label: "Founders XRPL", Network: "xrpl:1", Collection: "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De:42", Usage: "both"},
		},
		TokenGates: []TokenGate{
			{ID: "hold-rlusd", Label: "Hold 10 RLUSD", Network: "xrpl:1", Asset: "RLUSD:rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De", MinAmount: "10", Usage: "both"},
		},
	}

	now := time.Now().UTC()
	edgeA, err := New(cfg, t.TempDir(), secret, gw, "")
	if err != nil {
		t.Fatalf("New edgeA: %v", err)
	}
	defer edgeA.Close()
	edgeA.now = func() time.Time { return now }

	// Create browser session on Edge A
	wSess := httptest.NewRecorder()
	reqSess := httptest.NewRequest(http.MethodPost, "/_concert/session", bytes.NewReader([]byte("{}")))
	reqSess.Header.Set("Origin", cfg.Origin)
	reqSess.RemoteAddr = "198.51.100.10"
	edgeA.ServeHTTP(wSess, reqSess)
	if wSess.Code != 200 {
		t.Fatalf("session failed: %d %s", wSess.Code, wSess.Body.String())
	}
	var sessOut struct {
		Session string `json:"session"`
		CSRF    string `json:"csrf"`
	}
	_ = json.Unmarshal(wSess.Body.Bytes(), &sessOut)

	postJSON := func(path string, payload any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/_concert"+path, bytes.NewReader(b))
		req.Header.Set("Origin", cfg.Origin)
		req.Header.Set(CSRFHeader, sessOut.CSRF)
		req.AddCookie(&http.Cookie{Name: Cookie, Value: sessOut.Session})
		req.RemoteAddr = "198.51.100.10"
		rec := httptest.NewRecorder()
		edgeA.ServeHTTP(rec, req)
		return rec
	}

	// 1. Pre-check rejects BEFORE issuing challenge if wallet doesn't hold the NFT!
	wFail := postJSON("/direct/challenge", map[string]any{
		"kind":      "proof",
		"rule_kind": "nft",
		"rule_id":   "founders",
		"address":   "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
	})
	if wFail.Code != 403 {
		t.Fatalf("expected 403 when wallet lacks NFT, got %d %s", wFail.Code, wFail.Body.String())
	}

	// 2. Now wallet holds NFT -> challenge succeeds with Destination Tag + Memo + 1 drop!
	gw.gatePass = true
	wCh := postJSON("/direct/challenge", map[string]any{
		"kind":      "proof",
		"rule_kind": "nft",
		"rule_id":   "founders",
		"address":   "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
	})
	if wCh.Code != 200 {
		t.Fatalf("expected 200 direct challenge, got %d %s", wCh.Code, wCh.Body.String())
	}
	var chOut struct {
		ChallengeID    string `json:"challenge_id"`
		DestinationTag uint32 `json:"destination_tag"`
		Memo           string `json:"memo"`
		Amount         string `json:"amount"`
	}
	_ = json.Unmarshal(wCh.Body.Bytes(), &chOut)
	if chOut.DestinationTag < 100000 || chOut.Memo == "" || chOut.Amount != "1" {
		t.Fatalf("unexpected direct challenge: %+v", chOut)
	}

	// 3. Verify on-ledger 1-drop proof -> grants pass cookie!
	wVer := postJSON("/direct/verify", map[string]any{"challenge_id": chOut.ChallengeID})
	if wVer.Code != 200 {
		t.Fatalf("expected 200 direct verify, got %d %s", wVer.Code, wVer.Body.String())
	}
	var passCookie *http.Cookie
	for _, ck := range wVer.Result().Cookies() {
		if ck.Name == PassCookie {
			passCookie = ck
		}
	}
	if passCookie == nil {
		t.Fatal("expected stateless concert_fastlane_pass cookie")
	}

	// 4. Cross-edge continuity: Edge B (different data dir, same secret!) honors the pass cookie!
	edgeB, err := New(cfg, t.TempDir(), secret, gw, "")
	if err != nil {
		t.Fatalf("New edgeB: %v", err)
	}
	defer edgeB.Close()
	edgeB.now = func() time.Time { return now }

	// Advance 40s (past half of 60s idle window) -> Edge B accepts AND slides cookie!
	now = now.Add(40 * time.Second)
	browseReq := httptest.NewRequest(http.MethodGet, "/checkout", nil)
	browseReq.AddCookie(&http.Cookie{Name: Cookie, Value: sessOut.Session})
	browseReq.AddCookie(passCookie)
	slideRec := httptest.NewRecorder()
	if !edgeB.EligibleAndRefresh(slideRec, browseReq) {
		t.Fatal("Edge B should honor stateless pass cookie from Edge A")
	}
	var slidCookie *http.Cookie
	for _, ck := range slideRec.Result().Cookies() {
		if ck.Name == PassCookie {
			slidCookie = ck
		}
	}
	if slidCookie == nil || slidCookie.Value == passCookie.Value {
		t.Fatal("expected sliding idle pass cookie refresh on active navigation")
	}

	// Advance another 40s (80s total, past original 60s expiry, still inside slid 100s window!)
	now = now.Add(40 * time.Second)
	browseReq2 := httptest.NewRequest(http.MethodGet, "/checkout-step-2", nil)
	browseReq2.AddCookie(&http.Cookie{Name: Cookie, Value: sessOut.Session})
	browseReq2.AddCookie(slidCookie)
	if !edgeB.EligibleAndRefresh(httptest.NewRecorder(), browseReq2) {
		t.Fatal("slid pass should keep visitor admitted across refreshes while active")
	}

	// 5. Revocation immediately blocks the pass.
	sid, ok := edgeB.SessionID(&http.Request{Header: http.Header{SessionHeader: {sessOut.Session}}})
	if !ok {
		t.Fatal("expected valid SessionID")
	}
	edgeB.RevokeSession(sid)
	if edgeB.EligibleAndRefresh(httptest.NewRecorder(), browseReq2) {
		t.Fatal("revoked session should immediately lose eligibility")
	}

	// 6. Online archival compacts expired receipts without stopping Concert!
	now = now.Add(2 * time.Hour)
	rep, err := edgeA.ArchiveOnline(time.Minute, false)
	if err != nil {
		t.Fatalf("ArchiveOnline: %v", err)
	}
	if rep.Archived != 1 || rep.Kept != 0 || rep.ArchiveSHA256 == "" {
		t.Fatalf("unexpected online archive report: %+v", rep)
	}
}
