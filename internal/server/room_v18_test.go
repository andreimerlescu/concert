package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andreimerlescu/room"
)

func generateTestEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

func TestRoomV18_ConfigValidation(t *testing.T) {
	pub, _ := generateTestEd25519(t)
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)

	// Verify keys without scope must fail closed.
	cfg := testConfig("http://127.0.0.1:9999")
	cfg.roomVerifyKeys = "k1=" + pubB64
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "-room-scope") {
		t.Fatalf("expected -room-scope required error, got %v", err)
	}

	// Malformed key must fail closed.
	cfg = testConfig("http://127.0.0.1:9999")
	cfg.roomVerifyKeys = "k1=not-a-valid-key"
	cfg.roomScope = "shop.example.test"
	if err := cfg.normalize(); err == nil {
		t.Fatal("expected malformed pubkey error")
	}

	// Signed max TTL > 1h must fail closed.
	cfg = testConfig("http://127.0.0.1:9999")
	cfg.roomSignedMaxTTL = 2 * time.Hour
	if err := cfg.normalize(); err == nil {
		t.Fatal("expected >1h signed max TTL error")
	}

	// Duplicate kid must fail closed.
	cfg = testConfig("http://127.0.0.1:9999")
	cfg.roomVerifyKeys = "k1=" + pubB64 + ",k1=" + hex.EncodeToString(pub)
	cfg.roomScope = "shop.example.test"
	if err := cfg.normalize(); err == nil {
		t.Fatal("expected duplicate kid error")
	}
}

func TestRoomV18_Ed25519VerifyOnlySplitMode(t *testing.T) {
	pub1, priv1 := generateTestEd25519(t)
	pub2, priv2 := generateTestEd25519(t)

	signer1, err := room.NewEd25519Signer("k1", priv1)
	if err != nil {
		t.Fatalf("NewEd25519Signer k1: %v", err)
	}
	signer2, err := room.NewEd25519Signer("k2", priv2)
	if err != nil {
		t.Fatalf("NewEd25519Signer k2: %v", err)
	}
	issuer1, err := room.NewTokenIssuer("shop.example.test", signer1)
	if err != nil {
		t.Fatalf("NewTokenIssuer k1: %v", err)
	}
	issuer2, err := room.NewTokenIssuer("shop.example.test", signer2)
	if err != nil {
		t.Fatalf("NewTokenIssuer k2: %v", err)
	}

	var leakedPass, leakedLease atomic.Bool
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Room-Pass") != "" {
			leakedPass.Store(true)
		}
		if r.Header.Get("X-Room-Lease") != "" {
			leakedLease.Store(true)
		}
		_, _ = fmt.Fprint(w, "origin-ok")
	}))
	t.Cleanup(origin.Close)

	// Mix base64url (k1) and hex (k2) encodings in -room-verify-keys.
	cfg := testConfig(origin.URL)
	cfg.capacity = 4
	cfg.passDuration = 5 * time.Minute
	cfg.roomVerifyKeys = "k1=" + base64.RawURLEncoding.EncodeToString(pub1) + ",k2=" + hex.EncodeToString(pub2)
	cfg.roomScope = "shop.example.test"
	cfg.roomSignedMaxTTL = 10 * time.Minute
	cfg.roomLeaseFraction = 0.5
	a, front := newTestApp(t, cfg, nil)

	// 1. Verify-only fail closed: Concert itself cannot mint passes.
	if _, err := a.room.GrantPassE(); !errors.As(err, &room.ErrNoSigner{}) {
		t.Fatalf("expected ErrNoSigner on verify-only room, got %v", err)
	}

	// 2. LeaseCeiling matches floor(4 * 0.5) = 2 and surfaces in Prometheus metrics.
	if got := a.room.LeaseCeiling(); got != 2 {
		t.Fatalf("LeaseCeiling() = %d, want 2", got)
	}
	if m := a.renderPrometheusMetrics(); !strings.Contains(m, "concert_room_lease_ceiling 2\n") {
		t.Fatalf("expected concert_room_lease_ceiling 2 in metrics:\n%s", m)
	}

	// 3. Valid k1-signed pass verifies, succeeds, and strips X-Room-Pass upstream.
	passK1, err := issuer1.MintPass("", 5*time.Minute)
	if err != nil {
		t.Fatalf("MintPass k1: %v", err)
	}
	resp, body := get(t, front.URL+"/hello", map[string]string{
		"X-Room-Pass": passK1,
	})
	if resp.StatusCode != http.StatusOK || string(body) != "origin-ok" {
		t.Fatalf("valid k1 pass: got %d %q, want 200 origin-ok", resp.StatusCode, body)
	}
	if leakedPass.Load() {
		t.Fatal("X-Room-Pass leaked to upstream origin")
	}

	// 3b. Malformed X-Room-Lease is rejected fail-closed with 401 and never reaches upstream.
	respBadLease, _ := get(t, front.URL+"/hello", map[string]string{
		"X-Room-Lease": "not-a-valid-lease",
	})
	if respBadLease.StatusCode != http.StatusUnauthorized && respBadLease.StatusCode != http.StatusForbidden {
		t.Fatalf("malformed X-Room-Lease: got %d, want 401/403", respBadLease.StatusCode)
	}
	if leakedLease.Load() {
		t.Fatal("X-Room-Lease leaked to upstream origin")
	}

	// 4. Zero-downtime rotation: k2-signed pass also verifies locally.
	passK2, err := issuer2.MintPass("", 5*time.Minute)
	if err != nil {
		t.Fatalf("MintPass k2: %v", err)
	}
	if !a.room.HasValidPass(passK2) {
		t.Fatal("expected k2-signed pass to verify during key rotation")
	}

	// 5. Tampered X-Room-Pass header aborts with 401/403, fires EventTokenRejected,
	// increments concert_room_token_rejected_total, and awards strikeForgedPass.
	waitUntil(t, func() bool { return a.stats.tokenRejected.Load() >= 1 })
	rejBeforeTamper := a.stats.tokenRejected.Load()
	strikesBefore := a.stats.abuseStrikes.Load()
	tampered := passK1[:len(passK1)-4] + "AAAA"
	respBad, _ := get(t, front.URL+"/hello", map[string]string{"X-Room-Pass": tampered})
	if respBad.StatusCode != http.StatusUnauthorized && respBad.StatusCode != http.StatusForbidden {
		t.Fatalf("tampered X-Room-Pass status = %d, want 401 or 403", respBad.StatusCode)
	}
	waitUntil(t, func() bool { return a.stats.tokenRejected.Load() > rejBeforeTamper })
	waitUntil(t, func() bool { return a.stats.abuseStrikes.Load() > strikesBefore })
	if m := a.renderPrometheusMetrics(); !strings.Contains(m, "concert_room_token_rejected_total ") {
		t.Fatalf("expected concert_room_token_rejected_total in metrics:\n%s", m)
	}

	// 6. Expired token increments tokenRejected without awarding a forgery strike.
	expiredPass, err := issuer1.MintPass("", time.Second)
	if err != nil {
		t.Fatalf("MintPass 1s: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	strikesBeforeExp := a.stats.abuseStrikes.Load()
	rejBeforeExp := a.stats.tokenRejected.Load()
	respExp, _ := get(t, front.URL+"/hello", map[string]string{"X-Room-Pass": expiredPass})
	if respExp.StatusCode != http.StatusOK {
		t.Fatalf("expired X-Room-Pass on open room should fall through to 200, got %d", respExp.StatusCode)
	}
	waitUntil(t, func() bool { return a.stats.tokenRejected.Load() > rejBeforeExp })
	// Give async callback a brief beat and verify no forgery strike was added.
	time.Sleep(30 * time.Millisecond)
	if a.stats.abuseStrikes.Load() != strikesBeforeExp {
		t.Fatalf("expired token must not award forgery strike: before=%d after=%d", strikesBeforeExp, a.stats.abuseStrikes.Load())
	}
}

func TestRoomV18_MultiVhostCrossScopeIsolation(t *testing.T) {
	pub, priv := generateTestEd25519(t)
	signer, err := room.NewEd25519Signer("shared-k1", priv)
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	shopIssuer, err := room.NewTokenIssuer("shop.example.test", signer)
	if err != nil {
		t.Fatalf("NewTokenIssuer shop: %v", err)
	}
	shopPass, err := shopIssuer.MintPass("", 5*time.Minute)
	if err != nil {
		t.Fatalf("MintPass shop: %v", err)
	}

	shopUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "SHOP_OK")
	}))
	t.Cleanup(shopUp.Close)
	blogUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "BLOG_OK")
	}))
	t.Cleanup(blogUp.Close)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "Concertfile")
	cf := fmt.Sprintf(`
{
    listen 127.0.0.1:0
    room_verify_keys shared-k1=%s
    room_signed_max_ttl 10m
}

shop.example.test {
    upstream %s
    cap 4
}

blog.example.test {
    upstream %s
    cap 4
}
`, base64.RawURLEncoding.EncodeToString(pub), shopUp.URL, blogUp.URL)
	if err := os.WriteFile(cfgPath, []byte(cf), 0o600); err != nil {
		t.Fatal(err)
	}

	base := testConfig("http://127.0.0.1:1")
	base.configFile = cfgPath
	vm, err := newVhostManager(base)
	if err != nil {
		t.Fatalf("newVhostManager: %v", err)
	}
	t.Cleanup(vm.Close)

	shopSite, ok := vm.siteByName("shop.example.test")
	if !ok || shopSite.app.room.Scope() != "shop.example.test" {
		t.Fatalf("shop scope = %q, want shop.example.test", shopSite.app.room.Scope())
	}
	blogSite, ok := vm.siteByName("blog.example.test")
	if !ok || blogSite.app.room.Scope() != "blog.example.test" {
		t.Fatalf("blog scope = %q, want blog.example.test", blogSite.app.room.Scope())
	}

	srv := httptest.NewServer(vm)
	t.Cleanup(srv.Close)

	doHost := func(host, path, pass string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Host = host
		if pass != "" {
			req.Header.Set("X-Room-Pass", pass)
		}
		resp, err := testClient.Do(req)
		if err != nil {
			t.Fatalf("%s%s: %v", host, path, err)
		}
		defer resp.Body.Close()
		var buf [128]byte
		n, _ := resp.Body.Read(buf[:])
		return resp.StatusCode, string(buf[:n])
	}

	// Pass minted for shop.example.test succeeds on shop.example.test.
	if code, body := doHost("shop.example.test", "/cart", shopPass); code != http.StatusOK || body != "SHOP_OK" {
		t.Fatalf("shop pass on shop host: got %d %q, want 200 SHOP_OK", code, body)
	}

	// Replaying the EXACT same validly-signed pass against blog.example.test MUST
	// fail closed (wrong_scope -> 403), increment tokenRejected, and award a strike!
	if code, _ := doHost("blog.example.test", "/post", shopPass); code != http.StatusForbidden && code != http.StatusUnauthorized {
		t.Fatalf("cross-vhost replay of shop pass on blog host: got %d, want 403/401", code)
	}
	waitUntil(t, func() bool { return blogSite.app.stats.tokenRejected.Load() >= 1 })
	waitUntil(t, func() bool { return blogSite.app.stats.abuseStrikes.Load() >= 1 })
}
