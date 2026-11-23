package microcache

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMicroCache_StampedeCollapseAndBypass(t *testing.T) {
	var hits, misses, bypasses, coalesced atomic.Int64
	mc := New(Config{
		TTL:           5 * time.Second,
		MaxBytes:      1 << 20,
		MaxEntryBytes: 64 << 10,
		OnHit:         func() { hits.Add(1) },
		OnMiss:        func() { misses.Add(1) },
		OnBypass:      func() { bypasses.Add(1) },
		OnCoalesced:   func() { coalesced.Add(1) },
	})

	var originCalls atomic.Int64
	fetch := func(w http.ResponseWriter, r *http.Request) {
		originCalls.Add(1)
		time.Sleep(30 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html>product-page</html>"))
	}

	// 1. 100 concurrent cold anonymous requests collapse into 1 origin call!
	const n = 100
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodGet, "https://shop.example.com/product/tee/", nil)
			req.AddCookie(&http.Cookie{Name: "concert_admit", Value: "signed"})
			rec := httptest.NewRecorder()
			if !mc.Serve(rec, req, fetch) {
				t.Errorf("expected anonymous request to be handled by microcache")
				return
			}
			if rec.Code != 200 || rec.Body.String() != "<html>product-page</html>" {
				t.Errorf("unexpected response: %d %q", rec.Code, rec.Body.String())
			}
		}()
	}
	close(start)
	wg.Wait()

	if originCalls.Load() != 1 {
		t.Fatalf("stampede leaked: originCalls=%d, want 1", originCalls.Load())
	}
	if misses.Load() != 1 || coalesced.Load() != n-1 {
		t.Fatalf("misses=%d coalesced=%d, want 1, %d", misses.Load(), coalesced.Load(), n-1)
	}

	// 2. Subsequent hit is immediate with X-Concert-Cache: HIT.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://shop.example.com/product/tee/", nil)
	if !mc.Serve(rec, req, fetch) || rec.Header().Get("X-Concert-Cache") != "HIT" {
		t.Fatalf("expected HIT, got %q", rec.Header().Get("X-Concert-Cache"))
	}

	// 3. WordPress / WooCommerce bypasses NEVER hit the cache.
	bypassReqs := []*http.Request{
		func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "https://shop.example.com/product/tee/", nil)
			r.AddCookie(&http.Cookie{Name: "wordpress_logged_in_deadbeef", Value: "user"})
			return r
		}(),
		func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "https://shop.example.com/product/tee/", nil)
			r.AddCookie(&http.Cookie{Name: "woocommerce_items_in_cart", Value: "1"})
			return r
		}(),
		httptest.NewRequest(http.MethodPost, "https://shop.example.com/product/tee/", nil),
		httptest.NewRequest(http.MethodGet, "https://shop.example.com/checkout/", nil),
		httptest.NewRequest(http.MethodGet, "https://shop.example.com/?s=hoodie", nil),
		httptest.NewRequest(http.MethodGet, "https://shop.example.com/wp-admin/index.php", nil),
	}
	for i, br := range bypassReqs {
		rec := httptest.NewRecorder()
		if mc.Serve(rec, br, fetch) {
			t.Errorf("bypass case #%d (%s %s) was served from cache!", i, br.Method, br.URL.String())
		}
		if rec.Header().Get("X-Concert-Cache") != "BYPASS" {
			t.Errorf("bypass case #%d header=%q, want BYPASS", i, rec.Header().Get("X-Concert-Cache"))
		}
	}

	// 4. Response with Set-Cookie or Cache-Control: private is NEVER stored.
	recPriv := httptest.NewRecorder()
	reqPriv := httptest.NewRequest(http.MethodGet, "https://shop.example.com/dynamic", nil)
	mc.Serve(recPriv, reqPriv, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "wp_session=abc")
		_, _ = w.Write([]byte("session-specific"))
	})
	if recPriv.Header().Get("X-Concert-Cache") != "BYPASS" {
		t.Fatalf("Set-Cookie response got %q, want BYPASS", recPriv.Header().Get("X-Concert-Cache"))
	}
	if mc.Entries() != 1 {
		t.Fatalf("entries=%d, want 1 (Set-Cookie response must not be cached)", mc.Entries())
	}
}

func TestMicroCache_ByteBoundedEvictionAndExpiry(t *testing.T) {
	mc := New(Config{
		TTL:           80 * time.Millisecond,
		MaxBytes:      1200,
		MaxEntryBytes: 600,
	})
	payload := strings.Repeat("a", 400)
	for _, path := range []string{"/p1", "/p2", "/p3"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://example.com"+path, nil)
		mc.Serve(rec, req, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(payload))
		})
	}
	if mc.BytesUsed() > 1200 {
		t.Fatalf("BytesUsed=%d exceeded MaxBytes=1200", mc.BytesUsed())
	}
	time.Sleep(100 * time.Millisecond)
	var called atomic.Int64
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/p3", nil)
	mc.Serve(rec, req, func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		_, _ = w.Write([]byte("refreshed"))
	})
	if called.Load() != 1 || rec.Body.String() != "refreshed" {
		t.Fatalf("expired entry was not refreshed: called=%d body=%q", called.Load(), rec.Body.String())
	}
}

func FuzzCacheKeyAndBypass(f *testing.F) {
	f.Add("GET", "shop.example.com", "/product/a?s=1", "wordpress_logged_in_1=x", "gzip, br", "private, no-store", "Cookie")
	f.Add("HEAD", "example.com", "/wp-admin/edit.php", "concert_admit=ok", "identity", "public, max-age=60", "Accept-Encoding")
	f.Add("POST", "example.com", "/", "", "", "", "*")
	f.Fuzz(func(t *testing.T, method, host, rawURL, cookie, ae, cc, vary string) {
		mc := New(Config{TTL: 10 * time.Second})
		if method == "" || strings.ContainsAny(method, " \t\r\n") {
			method = "GET"
		}
		req, err := http.NewRequest(method, "https://example.test/", nil)
		if err != nil {
			return
		}
		req.Host = host
		req.URL.Path = "/" + strings.TrimLeft(rawURL, "/")
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		if ae != "" {
			req.Header.Set("Accept-Encoding", ae)
		}
		_ = mc.ShouldBypassRequest(req)
		_ = BuildKey(req)
		hdr := http.Header{}
		if cc != "" {
			hdr.Set("Cache-Control", cc)
		}
		if vary != "" {
			hdr.Set("Vary", vary)
		}
		ok := ShouldCacheResponse(200, hdr, 512, 1024)
		if ok && (strings.Contains(strings.ToLower(cc), "private") || strings.Contains(strings.ToLower(cc), "no-store")) {
			t.Fatalf("cached private/no-store response: cc=%q", cc)
		}
	})
}
