//go:build wordpress || enterprise

package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWordPress_MicroCacheStampedeAdmitAndBypass(t *testing.T) {
	root := t.TempDir()
	writeDiskFile(t, filepath.Join(root, "index.php"), []byte("<?php"))
	writeDiskFile(t, filepath.Join(root, "wp-content", "themes", "shop.css"), []byte("body{color:#00d4ff}"))

	sockPath, fpmCalls := startTestFPM(t, func(params map[string]string, _ []byte) []byte {
		time.Sleep(25 * time.Millisecond)
		var out bytes.Buffer
		out.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		if strings.HasPrefix(params["REQUEST_URI"], "/checkout") {
			out.WriteString("Concert-Priority: checkout\r\n")
		}
		out.WriteString("\r\n")
		fmt.Fprintf(&out, "<html>WP %s</html>", params["REQUEST_URI"])
		return out.Bytes()
	})

	cfg := testConfig("fcgi+unix://" + sockPath)
	cfg.staticRoot = root
	cfg.wpPreset = true
	cfg.microCacheTTL = 10 * time.Second
	cfg.microCacheMaxMB = 16
	a, front := newTestApp(t, cfg, nil)

	// 1. 80 concurrent anonymous GETs to /product/hoodie/ collapse into EXACTLY 1 php-fpm call,
	// AND every visitor gets a valid concert_admit pass so /wp-content/* assets load off disk!
	const n = 80
	var wg sync.WaitGroup
	start := make(chan struct{})
	var firstAdmit *http.Cookie
	var ckMu sync.Mutex
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp, err := testClient.Get(front.URL + "/product/hoodie/")
			if err != nil {
				t.Errorf("GET product: %v", err)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || string(body) != "<html>WP /product/hoodie/</html>" {
				t.Errorf("unexpected response: %d %q", resp.StatusCode, string(body))
				return
			}
			var gotAdmit *http.Cookie
			for _, ck := range resp.Cookies() {
				if ck.Name == admitCookie {
					gotAdmit = ck
				}
			}
			if gotAdmit == nil {
				t.Errorf("micro-cache response did not issue concert_admit cookie")
				return
			}
			ckMu.Lock()
			if firstAdmit == nil {
				firstAdmit = gotAdmit
			}
			ckMu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if fpmCalls.Load() != 1 {
		t.Fatalf("stampede reached php-fpm %d times, want 1", fpmCalls.Load())
	}

	// 2. Use the micro-cache-issued concert_admit cookie to load a pass-gated static asset off disk (0 extra FPM calls!).
	reqCSS, _ := http.NewRequest(http.MethodGet, front.URL+"/wp-content/themes/shop.css", nil)
	reqCSS.AddCookie(firstAdmit)
	resp, err := testClient.Do(reqCSS)
	if err != nil {
		t.Fatal(err)
	}
	cssBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(cssBody) != "body{color:#00d4ff}" {
		t.Fatalf("static asset with micro-cache admit cookie: %d %q", resp.StatusCode, string(cssBody))
	}
	if fpmCalls.Load() != 1 {
		t.Fatalf("static asset leaked to php-fpm: calls=%d", fpmCalls.Load())
	}

	// 3. Logged-in WordPress user & WooCommerce cart user ALWAYS bypass micro-cache.
	for _, ck := range []*http.Cookie{
		{Name: "wordpress_logged_in_abc", Value: "alice"},
		{Name: "woocommerce_items_in_cart", Value: "1"},
	} {
		r, _ := http.NewRequest(http.MethodGet, front.URL+"/product/hoodie/", nil)
		r.AddCookie(ck)
		resp, err := testClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Concert-Cache") != "BYPASS" {
			t.Fatalf("cookie %s: status=%d cache=%q, want 200 BYPASS", ck.Name, resp.StatusCode, resp.Header.Get("X-Concert-Cache"))
		}
	}
	if fpmCalls.Load() != 3 {
		t.Fatalf("bypass requests should hit php-fpm: calls=%d, want 3", fpmCalls.Load())
	}

	// 4. Checkout path bypasses micro-cache AND still grants origin-signed Concert-Priority cookie.
	resp, err = testClient.Get(front.URL + "/checkout/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.Header.Get("X-Concert-Cache") != "BYPASS" {
		t.Fatalf("/checkout/ cache=%q, want BYPASS", resp.Header.Get("X-Concert-Cache"))
	}
	foundPrio := false
	for _, ck := range resp.Cookies() {
		if ck.Name == priorityCookie {
			foundPrio = true
		}
	}
	if !foundPrio {
		t.Fatal("/checkout/ did not grant signed concert_priority cookie")
	}

	// 5. Verify Prometheus metrics report micro-cache counters.
	prom := a.renderPrometheusMetrics()
	for _, want := range []string{
		"concert_microcache_misses_total 1",
		"concert_microcache_hits_total 79",
		"concert_microcache_coalesced_total 79",
		"concert_microcache_bypasses_total 3",
	} {
		if !strings.Contains(prom, want) {
			t.Fatalf("metrics missing %q", want)
		}
	}
}
