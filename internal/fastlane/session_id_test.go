package fastlane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func headerRequest(session string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/drop", nil)
	if session != "" {
		r.Header.Set(SessionHeader, session)
	}
	return r
}

// SessionID names a waiting agent: it accepts only a valid header, never
// the browser's cookie, and keeps the same ID when the token is renewed.
func TestSessionIDFromHeaderOnly(t *testing.T) {
	h := newHarness(t)
	token := newSession(t, h.s)

	id, ok := h.s.SessionID(headerRequest(token))
	if !ok || len(id) != 64 {
		t.Fatalf("valid header: got %q %v, want a 64-character ID", id, ok)
	}
	if want, _, _, _ := h.s.session(headerRequest(token)); id != want {
		t.Errorf("SessionID %q differs from the ID receipts are stored under %q", id, want)
	}

	cookieOnly := httptest.NewRequest(http.MethodGet, "/drop", nil)
	cookieOnly.AddCookie(&http.Cookie{Name: Cookie, Value: token})
	if _, ok := h.s.SessionID(cookieOnly); ok {
		t.Error("the concert_fastlane cookie must not identify an agent")
	}
	for name, bad := range map[string]string{"empty": "", "forged": token + "x", "garbage": "a.b.c"} {
		if _, ok := h.s.SessionID(headerRequest(bad)); ok {
			t.Errorf("%s token accepted", name)
		}
	}

	h.now = h.now.Add(time.Minute) // a renewal later on carries a new expiry
	renewed := request(h.s, "/session", token, "{}", "")
	if renewed.Code != http.StatusOK {
		t.Fatal(renewed.Body.String())
	}
	var body struct {
		Session string `json:"session"`
	}
	if err := json.Unmarshal(renewed.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Session == "" || body.Session == token {
		t.Fatalf("renewal did not issue a new token: %q", body.Session)
	}
	if again, ok := h.s.SessionID(headerRequest(body.Session)); !ok || again != id {
		t.Errorf("renewed token: got %q %v, want the same ID %q", again, ok, id)
	}

	h.now = h.now.Add(sessionLifetime + 2*time.Hour)
	if _, ok := h.s.SessionID(headerRequest(token)); ok {
		t.Error("an expired token must not identify an agent")
	}
}
