// Package testnet holds Concert's live testnet tests. Each one pays a real
// testnet payment and waits for Concert to find it on the real chain, through
// the real gateway and fast-lane service, in test mode. Nothing here is mocked.
//
// They are skipped unless CONCERT_TESTNET=1, because they need outbound
// access to the testnets and their faucets and take minutes:
//
//	CONCERT_TESTNET=1 go test -count=1 -v -timeout 30m ./internal/testnet
//
// See docs/FASTLANE.md ("Testnet tests") for what each chain needs.
package testnet

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/fastlane"
	"github.com/andreimerlescu/concert/internal/gateway"
)

func need(t *testing.T) {
	t.Helper()
	if os.Getenv("CONCERT_TESTNET") != "1" {
		t.Skip("live testnet test: set CONCERT_TESTNET=1 (needs outbound access to the testnets)")
	}
}

// reference is the value a payment carries besides its amount: an XRPL
// destination tag or a memo on the chains that have one.
type reference struct {
	Tag  uint32
	Memo string
}

// flow describes one chain's live test.
type flow struct {
	network      string
	networksJSON string // the networks file, as an operator would write it
	payTo        string // the merchant's receiving address, funded on the testnet
	price        string // the offer's price in atomic units
	// send makes a real testnet payment from a funded account to payTo. A nil
	// ref means send the amount alone.
	send func(ctx context.Context, amount string, ref *reference) error
}

type client struct {
	t       *testing.T
	svc     *fastlane.Service
	origin  string
	session string
}

func (c *client) do(method, path, body string) (int, map[string]any) {
	c.t.Helper()
	r := httptest.NewRequest(method, fastlane.Prefix+path, strings.NewReader(body))
	if c.session != "" {
		r.Header.Set(fastlane.SessionHeader, c.session)
	}
	w := httptest.NewRecorder()
	c.svc.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (c *client) start() {
	c.t.Helper()
	code, out := c.do("POST", "/session", "{}")
	if code != 200 {
		c.t.Fatalf("session: %d %v", code, out)
	}
	c.session, _ = out["session"].(string)
}

func newService(t *testing.T, f flow) *fastlane.Service {
	t.Helper()
	dir := t.TempDir()
	cfg := fastlane.Config{
		Enabled: true, Origin: "http://127.0.0.1:8080", TestMode: true, PassSeconds: 120, MaxRecords: 100,
		Merchant: "Concert testnet run", TermsURL: "http://127.0.0.1:8080/terms", PrivacyURL: "http://127.0.0.1:8080/privacy", RefundURL: "http://127.0.0.1:8080/refunds",
		Offers: []fastlane.Offer{{Label: f.network, DepositOnly: true, Requirements: fastlane.Requirements{Network: f.network, Amount: f.price, PayTo: f.payTo}}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the offer must be valid in test mode: %v", err)
	}
	nets, err := gateway.ParseNetworks(strings.NewReader(f.networksJSON))
	if err != nil {
		t.Fatal(err)
	}
	journal, err := gateway.OpenJournal(filepath.Join(dir, "gateway"))
	if err != nil {
		t.Fatal(err)
	}
	gw, err := gateway.New(cfg, nets, journal, os.Getenv)
	if err != nil {
		journal.Close()
		t.Fatal(err)
	}
	t.Cleanup(gw.Close)
	svc, err := fastlane.New(cfg, dir, []byte(strings.Repeat("k", 32)), gw, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	return svc
}

// run is the positive test: a visitor is shown payment details, a real
// payment is sent, and Concert must find it on the chain and grant the pass.
// With useReference the payment sends the plain price plus the visitor's tag or
// memo; otherwise it sends the visitor's exact amount and nothing else.
func (f flow) run(t *testing.T, useReference bool) {
	t.Helper()
	need(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	svc := newService(t, f)
	buyer := &client{t: t, svc: svc}
	buyer.start()
	body, _ := json.Marshal(map[string]string{"network": f.network})
	code, intent := buyer.do("POST", "/deposit", string(body))
	if code != 200 {
		t.Fatalf("payment details: %d %v", code, intent)
	}
	amount, _ := intent["amount"].(string)
	if intent["address"] != f.payTo || amount == "" || amount <= f.price && len(amount) <= len(f.price) {
		t.Fatalf("intent must name the merchant and an amount above the price %s: %v", f.price, intent)
	}
	ref := &reference{}
	if tag, ok := intent["tag"].(float64); ok {
		ref.Tag = uint32(tag)
	}
	ref.Memo, _ = intent["memo"].(string)

	// Before any payment exists, the check must say "not yet".
	code, out := buyer.do("POST", "/deposit/check", string(body))
	if code != 200 || out["eligible"] == true {
		t.Fatalf("before paying, the visitor must not be admitted: %d %v", code, out)
	}

	sendAmount, sendRef := amount, (*reference)(nil)
	if useReference {
		sendAmount, sendRef = f.price, ref
	}
	t.Logf("sending %s (reference %+v) to %s on %s", sendAmount, sendRef, f.payTo, f.network)
	if err := f.send(ctx, sendAmount, sendRef); err != nil {
		t.Fatalf("sending the testnet payment: %v", err)
	}

	// Chains finalize in seconds to a minute; the mirror and Horizon add lag.
	var last map[string]any
	for ctx.Err() == nil {
		time.Sleep(5 * time.Second)
		code, last = buyer.do("POST", "/deposit/check", string(body))
		if code == 200 && last["eligible"] == true {
			break
		}
		t.Logf("waiting for the payment to be found: %d %v", code, last)
	}
	if last["eligible"] != true {
		t.Fatalf("Concert never found the real payment (timed out): %v", last)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set(fastlane.SessionHeader, buyer.session)
	if !svc.Eligible(r) {
		t.Fatal("a found payment must grant the fast-lane pass")
	}

	// The same on-chain payment must not admit anyone else.
	other := &client{t: t, svc: svc}
	other.start()
	if code, _ = other.do("POST", "/deposit", string(body)); code != 200 {
		t.Fatalf("second visitor's payment details: %d", code)
	}
	time.Sleep(5 * time.Second)
	if _, out = other.do("POST", "/deposit/check", string(body)); out["eligible"] == true {
		t.Fatal("one payment must not admit two visitors")
	}
}

// post sends a JSON or form request and returns the body, failing on a non-2xx.
func post(ctx context.Context, url, contentType, body string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return roundTrip(req)
}

func get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return roundTrip(req)
}

func roundTrip(req *http.Request) ([]byte, error) {
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return b, &httpError{req.URL.Host, resp.StatusCode, string(b)}
	}
	return b, nil
}

type httpError struct {
	host string
	code int
	body string
}

func (e *httpError) Error() string {
	b := e.body
	if len(b) > 300 {
		b = b[:300]
	}
	return e.host + " answered HTTP " + http.StatusText(e.code) + ": " + b
}

func parseUint(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) }
func parseInt(s string) (int64, error)   { return strconv.ParseInt(s, 10, 64) }
