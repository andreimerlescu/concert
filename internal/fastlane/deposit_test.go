package fastlane

import (
	"encoding/json"
	"net/http"
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

func tagOf(t *testing.T, h *harness, session string) uint32 {
	t.Helper()
	w := request(h.s, "/deposit", session, `{"network":"xrpl:1"}`, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var d struct {
		Tag     uint32 `json:"tag"`
		Address string `json:"address"`
		URI     string `json:"uri"`
		QR      string `json:"qr"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &d)
	if d.Tag == 0 || d.Address != h.cfg.Offers[0].Requirements.PayTo || !strings.Contains(d.URI, "dt=") || !strings.HasPrefix(d.QR, "data:image/png;base64,") {
		t.Fatalf("bad deposit response: %s", w.Body.String())
	}
	return d.Tag
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
	if uint32((*seen)["tag"].(float64)) != tag || (*seen)["amount"] != "100" {
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
	if w := request(h.s, "/deposit/check", other, `{"network":"xrpl:1"}`, ""); w.Code != 409 || eligible(h.s, other) {
		t.Fatalf("replay must be refused: %d %s", w.Code, w.Body.String())
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
