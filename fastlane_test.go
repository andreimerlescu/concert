package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/fastlane"
)

// Exercises the actual proxy routing and shared priority semaphore, while
// keeping the financial network mocked. No transaction is broadcast.
func TestFastLane_ProxyCapacityAndSession(t *testing.T) {
	var settlements atomic.Int64
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/supported":
			json.NewEncoder(w).Encode(map[string]any{"kinds": []any{map[string]any{"x402Version": 2, "scheme": "exact", "network": "xrpl:1"}}})
		case "/verify":
			json.NewEncoder(w).Encode(map[string]any{"isValid": true, "payer": "rPayer"})
		case "/settle":
			settlements.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"success": true, "payer": "rPayer", "network": "xrpl:1", "transaction": "test-transaction"})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(gateway.Close)
	t.Setenv("CONCERT_GATEWAY_TOKEN", strings.Repeat("g", 32))
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.capacity, cfg.priorityCap, cfg.priorityWait = 1, 1, 10*time.Millisecond
	cfg.dataDir = t.TempDir()
	cfg.fastlaneFile = filepath.Join(cfg.dataDir, "fastlane.json")
	req := fastlane.Requirements{Scheme: "exact", Network: "xrpl:1", Amount: "100", Asset: "XRP", PayTo: "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", MaxTimeoutSeconds: 60, Extra: map[string]any{"areFeesSponsored": false}}
	fc := fastlane.Config{Enabled: true, Origin: "http://127.0.0.1:8080", GatewayURL: gateway.URL, TestMode: true, Merchant: "Integration test", TermsURL: "http://127.0.0.1:8080/terms", PrivacyURL: "http://127.0.0.1:8080/privacy", RefundURL: "http://127.0.0.1:8080/refunds", Offers: []fastlane.Offer{{Label: "XRP", Requirements: req}}}
	b, _ := json.Marshal(fc)
	if err := os.WriteFile(cfg.fastlaneFile, b, 0600); err != nil {
		t.Fatal(err)
	}
	a, front := newTestApp(t, cfg, up)
	fillSlot(t, front, up)
	// Wallet routes remain accessible while the ordinary queue is full.
	response, body := doReq(t, testClient, "POST", front.URL+"/_concert/session", nil, strings.NewReader("{}"))
	if response.StatusCode != 200 {
		t.Fatalf("session: %d %s", response.StatusCode, body)
	}
	var session struct {
		Session string `json:"session"`
	}
	if err := json.Unmarshal(body, &session); err != nil {
		t.Fatal(err)
	}
	proof, _ := json.Marshal(map[string]any{"x402Version": 2, "accepted": req, "payload": map[string]string{"signedTxBlob": "test-proof"}})
	headers := map[string]string{fastlane.SessionHeader: session.Session, "PAYMENT-SIGNATURE": base64.StdEncoding.EncodeToString(proof)}
	response, body = doReq(t, testClient, "POST", front.URL+"/_concert/payment", headers, strings.NewReader("{}"))
	if response.StatusCode != 200 {
		t.Fatalf("settlement: %d %s", response.StatusCode, body)
	}
	if response, _ = get(t, front.URL+"/hello", headers); response.StatusCode != 200 {
		t.Fatalf("paid access: %d", response.StatusCode)
	}
	if response, _ = get(t, front.URL+"/hello", nil); response.StatusCode != 429 {
		t.Fatalf("free queue: %d", response.StatusCode)
	}
	park(t, front, up, "/slow", headers)
	response, body = doReq(t, testClient, "POST", front.URL+"/checkout", headers, strings.NewReader("order=123"))
	if response.StatusCode != 503 || !strings.Contains(string(body), "fast_lane_busy") || response.Header.Get("Retry-After") == "" {
		t.Fatalf("full priority lane: %d %s", response.StatusCode, body)
	}
	// A page request with a full lane joins the ordinary line instead of
	// failing; the pass stays valid for the next request.
	if response, body = get(t, front.URL+"/hello", headers); response.StatusCode != 429 {
		t.Fatalf("paid page request with a full lane: %d %s", response.StatusCode, body)
	}
	if settlements.Load() != 1 || a.prio.laneServed.Load() != 2 {
		t.Fatalf("settlements=%d served=%d", settlements.Load(), a.prio.laneServed.Load())
	}
	if a.prio.requests[rankCustomer].Load() != 4 {
		t.Fatal("paid requests must be counted at customer rank")
	}
	up.mu.Lock()
	hits := up.hits["/checkout"]
	up.mu.Unlock()
	if hits != 0 {
		t.Fatal("refused POST reached the origin")
	}
}

func TestFastLane_StripsPaymentCredentialsFromOrigin(t *testing.T) {
	var leaked atomic.Bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, key := range []string{"PAYMENT-SIGNATURE", "PAYMENT-REQUIRED", "PAYMENT-RESPONSE", fastlane.SessionHeader, fastlane.CSRFHeader} {
			if r.Header.Get(key) != "" {
				leaked.Store(true)
			}
		}
		if strings.Contains(r.Header.Get("Cookie"), fastlane.Cookie) {
			leaked.Store(true)
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(up.Close)
	_, front := newTestApp(t, testConfig(up.URL), nil)
	headers := map[string]string{"Cookie": fastlane.Cookie + "=secret; application=normal"}
	for _, key := range []string{"PAYMENT-SIGNATURE", "PAYMENT-REQUIRED", "PAYMENT-RESPONSE", fastlane.SessionHeader, fastlane.CSRFHeader} {
		headers[key] = "sensitive"
	}
	response, _ := get(t, front.URL+"/hello", headers)
	if response.StatusCode != 200 || leaked.Load() {
		t.Fatalf("status=%d leaked=%v", response.StatusCode, leaked.Load())
	}
}
