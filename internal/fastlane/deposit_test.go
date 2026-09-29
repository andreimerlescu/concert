package fastlane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// depositHarness answers /deposit/check like the gateway: it reports payments
// only for the tag it was told about.
func depositHarness(t *testing.T) (*harness, *sync.Mutex, *[]map[string]string, *map[string]any) {
	t.Helper()
	h := newHarness(t)
	var mu sync.Mutex
	var paid []map[string]string
	var seen map[string]any
	inner := h.gateway
	h.gateway = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/deposit/check" {
			inner.ServeHTTP(w, r)
			return
		}
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		mu.Lock()
		defer mu.Unlock()
		seen = in
		reply(w, 200, map[string]any{"deposits": paid})
	})
	h.s.Close()
	h.open(t)
	return h, &mu, &paid, &seen
}

func tagOf(t *testing.T, h *harness, session string) string {
	t.Helper()
	w := request(h.s, "/deposit", session, `{"network":"xrpl:1"}`, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var d struct {
		Tag     uint32 `json:"tag"`
		Address string `json:"address"`
		Amount  string `json:"amount"`
		Content string `json:"qr_content"`
		QR      string `json:"qr"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &d)
	if d.Tag == 0 || d.Address != h.cfg.Offers[0].Requirements.PayTo || d.Content != d.Address || d.Amount <= "100" || !strings.HasPrefix(d.QR, "data:image/png;base64,") {
		t.Fatalf("bad deposit response: %s", w.Body.String())
	}
	return d.Amount + "/" + strconv.FormatUint(uint64(d.Tag), 10)
}

func TestDepositTagIsStablePerSessionAndUniqueAcrossSessions(t *testing.T) {
	h, _, _, _ := depositHarness(t)
	a, b := newSession(t, h.s), newSession(t, h.s)
	ta := tagOf(t, h, a)
	if ta != tagOf(t, h, a) {
		t.Error("a session must keep one tag")
	}
	if ta == tagOf(t, h, b) {
		t.Error("two sessions must not share a tag")
	}
}

func TestDepositMatchGrantsPassOnceAndReplayFails(t *testing.T) {
	h, mu, paid, seen := depositHarness(t)
	s := newSession(t, h.s)
	tag := tagOf(t, h, s)
	check := func() map[string]any {
		h.now = h.now.Add(10 * time.Second) // past the per-session poll gap
		w := request(h.s, "/deposit/check", s, `{"network":"xrpl:1"}`, "")
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	if check()["eligible"] != false || eligible(h.s, s) {
		t.Fatal("no payment yet: must not be eligible")
	}
	if want := strings.Split(tag, "/"); (*seen)["amount"] != want[0] || (*seen)["price"] != "100" {
		t.Errorf("gateway asked for the wrong tag or amount: %v", *seen)
	}
	mu.Lock()
	*paid = []map[string]string{{"transaction": "TX1", "payer": "rPayer", "amount": "100"}}
	mu.Unlock()
	if check()["eligible"] != true || !eligible(h.s, s) {
		t.Fatal("matched deposit must grant a pass")
	}
	// A second visitor cannot redeem the same transaction.
	other := newSession(t, h.s)
	tagOf(t, h, other)
	h.now = h.now.Add(10 * time.Second)
	if w := request(h.s, "/deposit/check", other, `{"network":"xrpl:1"}`, ""); w.Code != 200 || eligible(h.s, other) {
		t.Fatalf("a transaction another session redeemed must not grant a pass: %d %s", w.Code, w.Body.String())
	}
	// After the pass lapses the same transaction never buys another.
	h.now = h.now.Add(time.Hour)
	if check()["eligible"] != false || eligible(h.s, s) {
		t.Error("a redeemed deposit must not renew the pass")
	}
}

func TestDepositRequiresSessionAndOffer(t *testing.T) {
	h, _, _, _ := depositHarness(t)
	if w := request(h.s, "/deposit", "", `{"network":"xrpl:1"}`, ""); w.Code != 401 {
		t.Errorf("no session: %d", w.Code)
	}
	s := newSession(t, h.s)
	if w := request(h.s, "/deposit", s, `{"network":"stellar:testnet"}`, ""); w.Code != 400 {
		t.Errorf("unoffered network: %d", w.Code)
	}
	if got := h.s.PublicConfig()["deposit_networks"].([]string); len(got) != 1 || got[0] != "xrpl:1" {
		t.Errorf("deposit_networks: %v", got)
	}
}

func shopHarness(t *testing.T) (*harness, *sync.Mutex, *[]map[string]string) {
	t.Helper()
	h, mu, paid, _ := depositHarness(t)
	h.s.Close()
	h.cfg.Listings = []Listing{{ID: "founder-1", Name: "Founder #1", Network: "xrpl:1", Token: "000800AB", Price: "5000", Collection: "club"}}
	if err := h.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h.open(t)
	return h, mu, paid
}

func buy(h *harness, session, listing string) (*httptest.ResponseRecorder, string) {
	w := request(h.s, "/deposit", session, `{"network":"xrpl:1","listing":"`+listing+`"}`, "")
	var d struct {
		Amount string `json:"amount"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &d)
	return w, d.Amount
}

func TestNFTSaleGrantsPassSellsOnceAndFlagsConflicts(t *testing.T) {
	h, mu, paid := shopHarness(t)
	a, b := newSession(t, h.s), newSession(t, h.s)
	w, amount := buy(h, a, "founder-1")
	_, lateAmount := buy(h, b, "founder-1") // b is shown its QR code before the sale
	if w.Code != 200 || amount <= "5000" {
		t.Fatalf("intent: %d %s", w.Code, w.Body.String())
	}
	if w, _ := buy(h, a, "nope"); w.Code != 409 {
		t.Errorf("unknown listing: %d", w.Code)
	}
	mu.Lock()
	*paid = []map[string]string{{"transaction": "SALE1", "payer": "rBuyer", "amount": amount}}
	mu.Unlock()
	h.now = h.now.Add(10 * time.Second)
	w = request(h.s, "/deposit/check", a, `{"network":"xrpl:1","listing":"founder-1"}`, "")
	if w.Code != 200 || !eligible(h.s, a) {
		t.Fatalf("sale must grant a pass: %d %s", w.Code, w.Body.String())
	}
	if shop := h.s.Shop(); shop[0]["sold"] != true {
		t.Error("listing must be sold")
	}
	if w, _ := buy(h, newSession(t, h.s), "founder-1"); w.Code != 409 || !strings.Contains(w.Body.String(), "listing_already_sold") {
		t.Errorf("no new payment details for a sold listing: %d %s", w.Code, w.Body.String())
	}
	// b pays from the QR code shown before the sale: the money is found, b gets
	// a pass, and the sale is flagged for the merchant instead of vanishing.
	mu.Lock()
	*paid = []map[string]string{{"transaction": "SALE2", "payer": "rLate", "amount": lateAmount}}
	mu.Unlock()
	h.now = h.now.Add(10 * time.Second)
	if w := request(h.s, "/deposit/check", b, `{"network":"xrpl:1","listing":"founder-1"}`, ""); w.Code != 200 || !eligible(h.s, b) || w.Header().Get("Concert-Listing-Conflict") != "1" {
		t.Fatalf("a payment for a sold listing must be found and flagged: %d %s", w.Code, w.Body.String())
	}
	if n := len(h.s.Sales()); n != 2 || h.s.Sales()[0]["conflict"] != true {
		t.Fatalf("the conflict must be listed for the merchant: %v", h.s.Sales())
	}
	sales := h.s.Sales()
	sales = sales[len(sales)-1:] // oldest is the real sale
	if sales[0]["buyer"] != "rBuyer" || sales[0]["token_id"] != "000800AB" || sales[0]["delivered"] != (*time.Time)(nil) {
		t.Fatalf("sales: %v", sales)
	}
	fp := sales[0]["fingerprint"].(string)
	if err := h.s.MarkDelivered(fp); err != nil {
		t.Errorf("mark delivered: %v", err)
	}
	for _, x := range h.s.Sales() {
		if x["fingerprint"] == fp && x["delivered"] == (*time.Time)(nil) {
			t.Error("the sale must show as delivered")
		}
	}
	// A restart remembers the sale.
	h.s.Close()
	h.open(t)
	if h.s.Shop()[0]["sold"] != true {
		t.Error("a restart must remember that the listing sold")
	}
}

func TestMarketListsOnLedgerSalesWithBuyLinks(t *testing.T) {
	h := newHarness(t)
	calls := 0
	inner := h.gateway
	h.gateway = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/market/sales" {
			inner.ServeHTTP(w, r)
			return
		}
		calls++
		id := strings.Repeat("AB", 32)
		reply(w, 200, map[string]any{"sales": []map[string]string{{"token_id": id, "offer": "O", "seller": "rS", "price": "5000000"}, {"token_id": "not-hex", "price": "1"}}})
	})
	h.s.Close()
	h.open(t)
	get := func() map[string]any {
		r := httptest.NewRequest("GET", Prefix+"/market?rule=club", nil)
		w := httptest.NewRecorder()
		h.s.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	out := get()
	sales := out["sales"].([]any)
	if len(sales) != 1 || sales[0].(map[string]any)["price_display"] != "5.000000" || !strings.HasPrefix(sales[0].(map[string]any)["buy_url"].(string), "https://test.bithomp.com/nft/") {
		t.Fatalf("%v", out)
	}
	get()
	if calls != 1 {
		t.Errorf("the market must be cached: %d gateway calls", calls)
	}
	r := httptest.NewRequest("GET", Prefix+"/market?rule=nope", nil)
	w := httptest.NewRecorder()
	h.s.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Errorf("unknown rule: %d", w.Code)
	}
}

func TestEntryWindowKeepsPassHolderInAfterThePassLapses(t *testing.T) {
	h := newHarness(t) // 30 s pass
	ttl := 5 * time.Minute
	h.s.SetEntryTTL(func() time.Duration { return ttl })
	pay := func(session, tx string) {
		if w := request(h.s, "/payment", session, "{}", signed(h, tx)); w.Code != 200 {
			t.Fatalf("pay: %d %s", w.Code, w.Body.String())
		}
	}
	entered, never := newSession(t, h.s), newSession(t, h.s)
	pay(entered, "tx-entered")
	pay(never, "tx-never")
	if !eligible(h.s, entered) {
		t.Fatal("a fresh pass must be eligible")
	}
	// Asking for status must not open a window for the visitor who never entered.
	sr := httptest.NewRequest("GET", Prefix+"/status", nil)
	sr.Header.Set(SessionHeader, never)
	sw := httptest.NewRecorder()
	h.s.ServeHTTP(sw, sr)
	if sw.Code != 200 || !strings.Contains(sw.Body.String(), `"eligible":true`) {
		t.Fatalf("status while the pass lasts: %d %s", sw.Code, sw.Body.String())
	}
	h.now = h.now.Add(2 * time.Minute) // the 30 s pass has lapsed
	if !eligible(h.s, entered) {
		t.Error("a visitor who presented the pass must stay in for the entry window")
	}
	if eligible(h.s, never) {
		t.Error("a pass that lapsed before it was ever presented must not open a window")
	}
	h.now = h.now.Add(4 * time.Minute) // past 5 minutes from entry
	if eligible(h.s, entered) {
		t.Error("the entry window must end")
	}
	// Buying again opens a fresh window.
	pay(entered, "tx-again")
	if !eligible(h.s, entered) {
		t.Error("a new payment must be eligible")
	}
	h.now = h.now.Add(time.Minute)
	if !eligible(h.s, entered) {
		t.Error("a new grant opens its own window")
	}
	// Off means the pass's own length only.
	ttl = 0
	other := newSession(t, h.s)
	pay(other, "tx-other")
	if !eligible(h.s, other) {
		t.Fatal("eligible while the pass lasts")
	}
	h.now = h.now.Add(time.Minute)
	if eligible(h.s, other) {
		t.Error("with the window off, the pass's own length applies")
	}
}
