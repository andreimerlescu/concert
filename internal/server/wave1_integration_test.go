package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/cache"
	"github.com/andreimerlescu/concert/internal/configfile"
	"github.com/andreimerlescu/concert/internal/guard"
	"github.com/andreimerlescu/concert/internal/kv"
)

// TestWave1_KVIntegrationAndRedisAlias exercises real in-process concert-kv
// integration via -kv-addr (ban sync, shared queue mirroring, fail-open on KV
// outage) and verifies -redis-addr / CONCERT_REDIS_* backward-compatible aliases.
func TestWave1_KVIntegrationAndRedisAlias(t *testing.T) {
	if !hasEnterpriseEdition() {
		for _, args := range [][]string{
			{"-kv-addr", "127.0.0.1:6380"},
			{"-redis-addr", "127.0.0.1:6379"},
		} {
			fs := flag.NewFlagSet("kv-edition-check", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			_, _, err := parseConfig(fs, args)
			if err == nil || !strings.Contains(err.Error(), "econcert") {
				t.Fatalf("args %v: err=%v, want econcert migration hint", args, err)
			}
		}
		return
	}

	kvPass := "kv-wave1-integration-pass-9876543210"
	kvSrv, err := kv.NewServer(kv.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		Password:   kv.NewSecret(kvPass),
	})
	if err != nil {
		t.Fatalf("kv.NewServer: %v", err)
	}
	kvCtx, kvCancel := context.WithCancel(context.Background())
	if err := kvSrv.Start(kvCtx); err != nil {
		kvCancel()
		t.Fatalf("kvSrv.Start: %v", err)
	}
	kvAddr := kvSrv.TCPAddr()
	kvClosed := false
	stopKV := func() {
		if !kvClosed {
			kvClosed = true
			kvCancel()
			_ = kvSrv.Close()
		}
	}
	t.Cleanup(stopKV)

	origin := newFakeUpstream(t)

	// 1. Verify parseConfig flag + env resolution for -kv-* and -redis-* aliases.
	t.Setenv("CONCERT_KV_PASSWORD", kvPass)
	fsKV := flag.NewFlagSet("kv-flags", flag.ContinueOnError)
	fsKV.SetOutput(io.Discard)
	parsedKV, _, err := parseConfig(fsKV, []string{
		"-data-dir", "",
		"-upstream", origin.URL(),
		"-kv-addr", kvAddr,
		"-kv-prefix", "w1cluster",
		"-kv-shared-queue=true",
	})
	if err != nil {
		t.Fatalf("parseConfig(-kv-*): %v", err)
	}
	if parsedKV.effectiveKVAddr() != kvAddr || parsedKV.effectiveKVPrefix() != "w1cluster" || !parsedKV.kvSharedQueue {
		t.Fatalf("unexpected kv config: addr=%q prefix=%q shared=%v",
			parsedKV.effectiveKVAddr(), parsedKV.effectiveKVPrefix(), parsedKV.kvSharedQueue)
	}
	if parsedKV.effectiveKVPassword().Reveal() != kvPass {
		t.Fatal("CONCERT_KV_PASSWORD not resolved into redacting Secret")
	}

	t.Setenv("CONCERT_KV_PASSWORD", "")
	t.Setenv("CONCERT_REDIS_PASSWORD", kvPass)
	fsRedis := flag.NewFlagSet("redis-alias", flag.ContinueOnError)
	fsRedis.SetOutput(io.Discard)
	parsedAlias, _, err := parseConfig(fsRedis, []string{
		"-data-dir", "",
		"-upstream", origin.URL(),
		"-redis-addr", kvAddr,
		"-redis-prefix", "legacy-pfx",
	})
	if err != nil {
		t.Fatalf("parseConfig(-redis-*): %v", err)
	}
	if parsedAlias.effectiveKVAddr() != kvAddr || parsedAlias.effectiveKVPrefix() != "legacy-pfx" {
		t.Fatalf("unexpected redis alias config: addr=%q prefix=%q",
			parsedAlias.effectiveKVAddr(), parsedAlias.effectiveKVPrefix())
	}
	if parsedAlias.effectiveKVPassword().Reveal() != kvPass {
		t.Fatal("CONCERT_REDIS_PASSWORD alias not resolved")
	}

	// 2. Live multi-node ban sync + shared queue mirroring against real concert-kv.
	makeNode := func(useAlias bool) (*app, *httptest.Server) {
		cfg := testConfig(origin.URL())
		cfg.capacity = 1
		cfg.trustedProxies = "127.0.0.1/32"
		cfg.banPaths = "/.env"
		cfg.kvSharedQueue = true
		if useAlias {
			cfg.redisAddr = kvAddr
			cfg.redisPrefix = "w1sync"
			cfg.redisPassword = kvPass
		} else {
			cfg.kvAddr = kvAddr
			cfg.kvPrefix = "w1sync"
			cfg.kvPassword = kv.NewSecret(kvPass)
		}
		return newTestApp(t, cfg, nil)
	}

	nodeA, srvA := makeNode(false)
	nodeB, srvB := makeNode(true)

	// Wait until nodeB's subscribe loop is connected by sending a ban from nodeA.
	attackerIP := "198.51.100.77"
	reqBan, _ := http.NewRequest(http.MethodGet, srvA.URL+"/.env", nil)
	reqBan.Header.Set("X-Forwarded-For", attackerIP)
	respBan, err := testClient.Do(reqBan)
	if err != nil {
		t.Fatalf("trigger ban on nodeA: %v", err)
	}
	_ = respBan.Body.Close()
	if respBan.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("nodeA ban path status=%d, want 429", respBan.StatusCode)
	}

	// Poll nodeB until peer ban sync arrives via concert-kv Pub/Sub or Hash.
	synced := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, banned := nodeB.abuse.banned(netip.MustParseAddr(attackerIP), time.Now()); banned {
			synced = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !synced {
		t.Fatalf("nodeB did not receive ban from nodeA via concert-kv (sent=%d recv=%d errs=%d)",
			nodeA.stats.clusterSyncSent.Load(), nodeB.stats.clusterSyncRecv.Load(), nodeB.stats.clusterSyncErrors.Load())
	}

	// Verify nodeB blocks the synced attacker IP.
	reqCheck, _ := http.NewRequest(http.MethodGet, srvB.URL+"/", nil)
	reqCheck.Header.Set("X-Forwarded-For", attackerIP)
	respCheck, err := testClient.Do(reqCheck)
	if err != nil {
		t.Fatalf("GET nodeB as banned IP: %v", err)
	}
	_ = respCheck.Body.Close()
	if respCheck.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("nodeB synced ban status=%d, want 429", respCheck.StatusCode)
	}

	// Verify shared queue mirroring populates CQ.STATS on concert-kv.
	slowDone := make(chan struct{})
	go func() {
		defer close(slowDone)
		r, err := testClient.Get(srvA.URL + "/slow")
		if err == nil {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		}
	}()
	<-origin.entered

	reqQ, _ := http.NewRequest(http.MethodGet, srvA.URL+"/queued", nil)
	reqQ.Header.Set("X-Forwarded-For", "203.0.113.40")
	respQ, err := testClient.Do(reqQ)
	if err != nil {
		t.Fatalf("GET queued on nodeA: %v", err)
	}
	_ = respQ.Body.Close()
	if respQ.Header.Get(headerConcertQueue) != "1" {
		t.Fatalf("expected queued response on nodeA, got status=%d headers=%v", respQ.StatusCode, respQ.Header)
	}

	kvCli, err := kv.NewClient(kv.ClientConfig{
		Addr:     kvAddr,
		Password: kv.NewSecret(kvPass),
	})
	if err != nil {
		t.Fatalf("kv.NewClient: %v", err)
	}
	defer func() { _ = kvCli.Close() }()

	mirrored := false
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st, err := kvCli.CQStats(context.Background(), "w1sync:queue:default")
		if err == nil && st.TotalJoined >= 1 {
			mirrored = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !mirrored {
		t.Fatal("expected concert-kv CQ.STATS to reflect mirrored waiting-room ticket")
	}

	origin.releaseAll()
	<-slowDone
	nodeA.room.ClearQueue()

	// 3. Kill concert-kv -> Concert must fail open and keep serving requests locally.
	stopKV()
	respAfter, err := testClient.Get(srvA.URL + "/after-kv-outage")
	if err != nil {
		t.Fatalf("GET after KV outage: %v", err)
	}
	bodyAfter, _ := io.ReadAll(respAfter.Body)
	_ = respAfter.Body.Close()
	if respAfter.StatusCode != http.StatusOK || string(bodyAfter) != "ok" {
		t.Fatalf("fail-open after KV outage: status=%d body=%q", respAfter.StatusCode, string(bodyAfter))
	}
}

// TestWave1_CachePurgeAndExternalCacheClient verifies active cache purging
// (url, prefix, tag, all) via POST /_room/cache/purge and Portal
// POST /api/cache/purge (with RBAC, CSRF, and audit logging) against both
// built-in microcache and a real in-process concert-cache daemon.
func TestWave1_CachePurgeAndExternalCacheClient(t *testing.T) {
	if !hasWordPressEdition() {
		fs := flag.NewFlagSet("cache-edition-check", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		_, _, err := parseConfig(fs, []string{"-cache-addr", "127.0.0.1:6390"})
		if err == nil || !strings.Contains(err.Error(), "wpconcert") {
			t.Fatalf("-cache-addr err=%v, want wpconcert migration hint", err)
		}
		return
	}

	var originHits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := originHits.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if strings.HasPrefix(r.URL.Path, "/product/") {
			w.Header().Set("Surrogate-Key", "products catalog")
		} else if strings.HasPrefix(r.URL.Path, "/blog/") {
			w.Header().Set("Cache-Tag", "blog-posts")
		}
		fmt.Fprintf(w, "page:%s:%d", r.URL.Path, n)
	}))
	defer origin.Close()

	// Start a real in-process concert-cache daemon.
	cacheSecretStr := "wave1-cache-daemon-secret-0123456789abcdef"
	cacheStore := cache.NewStore(cache.StoreConfig{MaxBytes: 8 << 20})
	t.Cleanup(func() { _ = cacheStore.Close() })
	cacheSrv, err := cache.NewServer(cache.ServerConfig{
		Store:  cacheStore,
		Secret: cache.NewSecret(cacheSecretStr),
	})
	if err != nil {
		t.Fatalf("cache.NewServer: %v", err)
	}
	cacheLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen cache: %v", err)
	}
	go func() { _ = cacheSrv.Serve(cacheLn) }()
	cacheClosed := false
	stopCache := func() {
		if !cacheClosed {
			cacheClosed = true
			_ = cacheSrv.Close()
		}
	}
	t.Cleanup(stopCache)

	// Fail closed when -cache-addr is set without CONCERT_CACHE_SECRET.
	badCfg := testConfig(origin.URL)
	badCfg.cacheAddr = cacheLn.Addr().String()
	if err := badCfg.normalize(); err == nil || !strings.Contains(err.Error(), "CONCERT_CACHE_SECRET") {
		t.Fatalf("expected fail-closed error for missing cache secret, got: %v", err)
	}

	// Run full purge matrix against BOTH built-in microcache and external concert-cache.
	for _, tc := range []struct {
		name      string
		cacheAddr string
	}{
		{name: "builtin_microcache", cacheAddr: ""},
		{name: "external_concert_cache", cacheAddr: cacheLn.Addr().String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
			cfg := portalTestConfig(origin.URL)
			cfg.microCacheTTL = 30 * time.Second
			cfg.microCacheMaxMB = 8
			cfg.cacheAddr = tc.cacheAddr
			if tc.cacheAddr != "" {
				cfg.cacheSecret = cache.NewSecret(cacheSecretStr)
			}
			cfg.adminToken = "op-admin-token-0123456789abcdef"
			if hasEnterpriseEdition() {
				cfg.adminTokensSpec = "ci-viewer:viewer:viewer-tok-1234567890,ci-ops:operator:op-tok-1234567890"
				cfg.auditLog = auditPath
			}

			_, p, front := newTestPortal(t, cfg, nil)

			fetch := func(path string) (string, string) {
				resp, err := testClient.Get(front.URL + path)
				if err != nil {
					t.Fatalf("GET %s: %v", path, err)
				}
				b, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("GET %s: status=%d body=%q", path, resp.StatusCode, string(b))
				}
				return resp.Header.Get("X-Concert-Cache"), string(b)
			}

			// Warm 3 distinct URLs.
			if st, _ := fetch("/product/shoe"); st != "MISS" {
				t.Fatalf("/product/shoe first fetch cache=%q, want MISS", st)
			}
			if st, _ := fetch("/product/shoe"); st != "HIT" {
				t.Fatalf("/product/shoe second fetch cache=%q, want HIT", st)
			}
			if st, _ := fetch("/product/hat"); st != "MISS" {
				t.Fatalf("/product/hat first fetch cache=%q, want MISS", st)
			}
			if st, _ := fetch("/blog/post-1"); st != "MISS" {
				t.Fatalf("/blog/post-1 first fetch cache=%q, want MISS", st)
			}
			if st, _ := fetch("/blog/post-2"); st != "MISS" {
				t.Fatalf("/blog/post-2 first fetch cache=%q, want MISS", st)
			}

			purgeToken := cfg.adminToken
			if hasEnterpriseEdition() {
				// Viewer token must be rejected with 403 on POST /_room/cache/purge.
				reqDeny, _ := http.NewRequest(http.MethodPost, front.URL+"/_room/cache/purge",
					strings.NewReader(`{"mode":"all"}`))
				reqDeny.Header.Set("Authorization", "Bearer viewer-tok-1234567890")
				respDeny, err := testClient.Do(reqDeny)
				if err != nil {
					t.Fatal(err)
				}
				_ = respDeny.Body.Close()
				if respDeny.StatusCode != http.StatusForbidden {
					t.Fatalf("viewer cache purge status=%d, want 403", respDeny.StatusCode)
				}
				purgeToken = "op-tok-1234567890"
			}

			apiPurge := func(body string) (int, map[string]any) {
				req, _ := http.NewRequest(http.MethodPost, front.URL+"/_room/cache/purge", strings.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+purgeToken)
				req.Header.Set("Content-Type", "application/json")
				resp, err := testClient.Do(req)
				if err != nil {
					t.Fatalf("POST /_room/cache/purge: %v", err)
				}
				b, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				var out map[string]any
				_ = json.Unmarshal(b, &out)
				return resp.StatusCode, out
			}

			// 1. mode=url purges /product/shoe only; /product/hat remains HIT.
			code, out := apiPurge(`{"mode":"url","target":"/product/shoe"}`)
			if code != http.StatusOK || out["mode"] != "url" || int(out["purged"].(float64)) < 1 {
				t.Fatalf("url purge: code=%d out=%v", code, out)
			}
			if st, _ := fetch("/product/shoe"); st != "MISS" {
				t.Fatalf("/product/shoe after url purge=%q, want MISS", st)
			}
			if st, _ := fetch("/product/hat"); st != "HIT" {
				t.Fatalf("/product/hat should still be HIT, got %q", st)
			}

			// 2. mode=tag purges both /product/* entries tagged "products".
			code, out = apiPurge(`{"mode":"tag","target":"products"}`)
			if code != http.StatusOK || out["mode"] != "tag" || int(out["purged"].(float64)) < 2 {
				t.Fatalf("tag purge: code=%d out=%v", code, out)
			}
			if st, _ := fetch("/product/hat"); st != "MISS" {
				t.Fatalf("/product/hat after tag purge=%q, want MISS", st)
			}

			// 3. mode=prefix via Portal POST /api/cache/purge (CSRF enforced!).
			ck, csrf := portalLogin(t, p)
			recNoCSRF := portalDo(p, http.MethodPost, "/api/cache/purge", `{"mode":"prefix","target":"/blog/"}`, ck, "", false)
			if recNoCSRF.Code != http.StatusForbidden {
				t.Fatalf("portal cache purge without CSRF: status=%d, want 403", recNoCSRF.Code)
			}
			recPortal := portalDo(p, http.MethodPost, "/api/cache/purge", `{"mode":"prefix","target":"/blog/"}`, ck, csrf, false)
			if recPortal.Code != http.StatusOK {
				t.Fatalf("portal prefix purge: status=%d body=%s", recPortal.Code, recPortal.Body.String())
			}
			var portalOut map[string]any
			if err := json.Unmarshal(recPortal.Body.Bytes(), &portalOut); err != nil {
				t.Fatal(err)
			}
			if portalOut["mode"] != "prefix" || int(portalOut["purged"].(float64)) < 2 {
				t.Fatalf("portal prefix purge response=%v", portalOut)
			}
			if st, _ := fetch("/blog/post-1"); st != "MISS" {
				t.Fatalf("/blog/post-1 after prefix purge=%q, want MISS", st)
			}

			// 4. mode=all purges everything.
			code, out = apiPurge(`{"mode":"all"}`)
			if code != http.StatusOK || out["mode"] != "all" || int(out["purged"].(float64)) < 1 {
				t.Fatalf("all purge: code=%d out=%v", code, out)
			}
			if st, _ := fetch("/blog/post-1"); st != "MISS" {
				t.Fatalf("/blog/post-1 after all purge=%q, want MISS", st)
			}

			// 5. Verify audit event "cache.purge" recorded in econcert.
			if hasEnterpriseEdition() {
				rawAudit, err := os.ReadFile(auditPath)
				if err != nil {
					t.Fatalf("read audit log: %v", err)
				}
				if !strings.Contains(string(rawAudit), `"action":"cache.purge"`) {
					t.Fatalf("audit log missing cache.purge event:\n%s", string(rawAudit))
				}
			}

			// 6. For external concert-cache, shut down daemon and verify fail-open serving.
			if tc.cacheAddr != "" {
				stopCache()
				_, body := fetch("/product/after-cache-down")
				if !strings.HasPrefix(body, "page:/product/after-cache-down:") {
					t.Fatalf("fail-open after cache daemon stop failed: body=%q", body)
				}
			}
		})
	}
}

// TestWave1_GuardrailsAndMetrics verifies QueueQuota (allowlisted flood cap
// letting real visitors through), RouteLimiter (429 without X-Concert-Queue),
// HostShedder (503 without X-Concert-Queue), GeoASNPolicy (403 without
// X-Concert-Queue), ChallengeGate (PoW solve + clearance cookie flow), and all
// 6 Prometheus guard counters.
func TestWave1_GuardrailsAndMetrics(t *testing.T) {
	t.Run("AllowlistedQueueQuotaProtectsRealUsers", func(t *testing.T) {
		origin := newFakeUpstream(t)
		cfg := testConfig(origin.URL())
		cfg.capacity = 1
		cfg.maxQueue = 10
		cfg.trustedProxies = "127.0.0.1/32"
		cfg.abuseAllow = "198.51.100.10/32"
		cfg.maxQueuePerIP = 2
		cfg.allowMaxQueuePerIP = 3
		a, front := newTestApp(t, cfg, nil)

		// Occupy the single origin slot so arrivals must queue.
		slowDone := make(chan struct{})
		go func() {
			defer close(slowDone)
			r, err := testClient.Get(front.URL + "/slow")
			if err == nil {
				_, _ = io.Copy(io.Discard, r.Body)
				_ = r.Body.Close()
			}
		}()
		<-origin.entered

		// Flood 8 fresh requests from the ALLOWLISTED IP (no cookies): only 3
		// may queue; the rest must receive 429 without X-Concert-Queue.
		queuedAllow := 0
		rejectedAllow := 0
		for i := 0; i < 8; i++ {
			req, _ := http.NewRequest(http.MethodGet, front.URL+"/flood", nil)
			req.Header.Set("X-Forwarded-For", "198.51.100.10")
			resp, err := testClient.Do(req)
			if err != nil {
				t.Fatalf("flood req %d: %v", i, err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.Header.Get(headerConcertQueue) == "1" {
				queuedAllow++
			} else if resp.StatusCode == http.StatusTooManyRequests {
				if strings.Contains(string(body), "queue_quota_exceeded") {
					rejectedAllow++
				} else {
					t.Fatalf("unexpected 429 body: %s", string(body))
				}
			} else {
				t.Fatalf("unexpected flood response: status=%d headers=%v body=%s", resp.StatusCode, resp.Header, string(body))
			}
		}
		if queuedAllow != 3 || rejectedAllow != 5 {
			t.Fatalf("allowlisted flood: queued=%d rejected=%d, want 3 and 5", queuedAllow, rejectedAllow)
		}

		// A real visitor from a different IP still enters the waiting room cleanly.
		reqReal, _ := http.NewRequest(http.MethodGet, front.URL+"/real-visitor", nil)
		reqReal.Header.Set("X-Forwarded-For", "203.0.113.55")
		respReal, err := testClient.Do(reqReal)
		if err != nil {
			t.Fatalf("real visitor req: %v", err)
		}
		_ = respReal.Body.Close()
		if respReal.Header.Get(headerConcertQueue) != "1" {
			t.Fatalf("real visitor was blocked instead of queued: status=%d headers=%v", respReal.StatusCode, respReal.Header)
		}

		prom := a.renderPrometheusMetrics()
		if !strings.Contains(prom, "concert_guard_quota_rejected_total 5") {
			t.Fatalf("metrics missing expected quota counter:\n%s", prom)
		}

		origin.releaseAll()
		<-slowDone
	})

	t.Run("RouteRateLimitAndHostShedderNoQueueHeaders", func(t *testing.T) {
		origin := newFakeUpstream(t)
		cfg := testConfig(origin.URL())
		cfg.capacity = 5
		cfg.trustedProxies = "127.0.0.1/32"
		cfg.rateLimits = "/api/login=2/1m"
		cfg.hostMaxConns = 1
		a, front := newTestApp(t, cfg, nil)

		// 1. Route rate limit: 2 allowed, 3rd gets 429 without X-Concert-Queue.
		for i := 0; i < 3; i++ {
			req, _ := http.NewRequest(http.MethodGet, front.URL+"/api/login", nil)
			req.Header.Set("X-Forwarded-For", "203.0.113.88")
			resp, err := testClient.Do(req)
			if err != nil {
				t.Fatalf("login req %d: %v", i, err)
			}
			_ = resp.Body.Close()
			if i < 2 && resp.StatusCode != http.StatusOK {
				t.Fatalf("login req %d status=%d, want 200", i, resp.StatusCode)
			}
			if i == 2 {
				if resp.StatusCode != http.StatusTooManyRequests {
					t.Fatalf("3rd login req status=%d, want 429", resp.StatusCode)
				}
				if resp.Header.Get(headerConcertQueue) != "" {
					t.Fatalf("route rate-limit 429 must NEVER set %s", headerConcertQueue)
				}
				if resp.Header.Get("Retry-After") == "" {
					t.Fatal("route rate-limit 429 missing Retry-After")
				}
			}
		}

		// 2. Host shedder: 1 slow request fills hostMaxConns=1; 2nd gets 503
		// without X-Concert-Queue while /_room/healthz stays 200.
		slowDone := make(chan struct{})
		go func() {
			defer close(slowDone)
			r, err := testClient.Get(front.URL + "/slow")
			if err == nil {
				_, _ = io.Copy(io.Discard, r.Body)
				_ = r.Body.Close()
			}
		}()
		<-origin.entered

		respShed, err := testClient.Get(front.URL + "/other")
		if err != nil {
			t.Fatalf("shed req: %v", err)
		}
		_ = respShed.Body.Close()
		if respShed.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("host shed status=%d, want 503", respShed.StatusCode)
		}
		if respShed.Header.Get(headerConcertQueue) != "" {
			t.Fatalf("host shed 503 must NEVER set %s", headerConcertQueue)
		}
		if respShed.Header.Get("Retry-After") == "" {
			t.Fatal("host shed 503 missing Retry-After")
		}

		// Healthz remains reachable while shedding.
		respHealth, err := testClient.Get(front.URL + "/_room/healthz")
		if err != nil {
			t.Fatalf("healthz while shedding: %v", err)
		}
		_ = respHealth.Body.Close()
		if respHealth.StatusCode != http.StatusOK {
			t.Fatalf("healthz while shedding status=%d, want 200", respHealth.StatusCode)
		}

		origin.releaseAll()
		<-slowDone

		prom := a.renderPrometheusMetrics()
		for _, want := range []string{
			"concert_guard_ratelimit_total 1",
			"concert_guard_shed_total 1",
			"concert_guard_geo_blocked_total 0",
		} {
			if !strings.Contains(prom, want) {
				t.Fatalf("metrics missing %q", want)
			}
		}
	})

	t.Run("PoWChallengeClearanceFlowAndMetrics", func(t *testing.T) {
		origin := newFakeUpstream(t)
		cfg := testConfig(origin.URL())
		cfg.challengeMode = "pow"
		cfg.challengePowBits = 8
		a, front := newTestApp(t, cfg, nil)

		// 1. Self-hosted solver JS is served under strict CSP.
		respJS, err := testClient.Get(front.URL + "/_concert/pow.js")
		if err != nil {
			t.Fatalf("GET pow.js: %v", err)
		}
		jsBody, _ := io.ReadAll(respJS.Body)
		_ = respJS.Body.Close()
		if respJS.StatusCode != http.StatusOK || !strings.Contains(string(jsBody), "SHA-256") {
			t.Fatalf("pow.js: status=%d len=%d", respJS.StatusCode, len(jsBody))
		}

		// 2. HTML visitor gets PoW HTML challenge page (403, no X-Concert-Queue).
		reqHTML, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
		reqHTML.Header.Set("Accept", "text/html")
		respHTML, err := testClient.Do(reqHTML)
		if err != nil {
			t.Fatalf("GET / HTML: %v", err)
		}
		htmlBody, _ := io.ReadAll(respHTML.Body)
		_ = respHTML.Body.Close()
		if respHTML.StatusCode != http.StatusForbidden || respHTML.Header.Get(headerConcertQueue) != "" {
			t.Fatalf("HTML challenge: status=%d X-Concert-Queue=%q", respHTML.StatusCode, respHTML.Header.Get(headerConcertQueue))
		}
		if !strings.Contains(string(htmlBody), "/_concert/challenge/verify") {
			t.Fatalf("HTML challenge missing verify endpoint: %s", string(htmlBody))
		}

		// 3. API client gets JSON PoW challenge (403, no X-Concert-Queue).
		respCh, err := testClient.Get(front.URL + "/protected")
		if err != nil {
			t.Fatalf("GET /protected: %v", err)
		}
		chBytes, _ := io.ReadAll(respCh.Body)
		_ = respCh.Body.Close()
		if respCh.StatusCode != http.StatusForbidden || respCh.Header.Get(headerConcertQueue) != "" {
			t.Fatalf("JSON challenge: status=%d X-Concert-Queue=%q", respCh.StatusCode, respCh.Header.Get(headerConcertQueue))
		}
		var chPayload struct {
			Challenge  string `json:"challenge"`
			Nonce      string `json:"nonce"`
			Difficulty int    `json:"difficulty"`
			VerifyURL  string `json:"verify_url"`
		}
		if err := json.Unmarshal(chBytes, &chPayload); err != nil {
			t.Fatalf("decode challenge JSON: %v (%s)", err, string(chBytes))
		}
		if chPayload.Challenge != "pow" || chPayload.Nonce == "" || chPayload.Difficulty != 8 || chPayload.VerifyURL != "/_concert/challenge/verify" {
			t.Fatalf("unexpected challenge payload: %+v", chPayload)
		}

		// 4. Invalid solution fails verification and increments failed counter.
		respBad, err := testClient.Post(front.URL+chPayload.VerifyURL, "application/json",
			strings.NewReader(fmt.Sprintf(`{"nonce":%q,"counter":"invalid"}`, chPayload.Nonce)))
		if err != nil {
			t.Fatal(err)
		}
		_ = respBad.Body.Close()
		if respBad.StatusCode != http.StatusForbidden {
			t.Fatalf("bad PoW verify status=%d, want 403", respBad.StatusCode)
		}

		// 5. Valid solution succeeds and mints concert_pow clearance cookie.
		counter, ok := guard.SolvePoW(chPayload.Nonce, chPayload.Difficulty)
		if !ok {
			t.Fatal("guard.SolvePoW failed")
		}
		respOK, err := testClient.Post(front.URL+chPayload.VerifyURL, "application/json",
			strings.NewReader(fmt.Sprintf(`{"nonce":%q,"counter":%q}`, chPayload.Nonce, counter)))
		if err != nil {
			t.Fatal(err)
		}
		_ = respOK.Body.Close()
		if respOK.StatusCode != http.StatusOK {
			t.Fatalf("valid PoW verify status=%d, want 200", respOK.StatusCode)
		}
		var clearCookie *http.Cookie
		for _, ck := range respOK.Cookies() {
			if ck.Name == guard.DefaultClearanceCookieName {
				clearCookie = ck
			}
		}
		if clearCookie == nil {
			t.Fatalf("missing %s clearance cookie after PoW verify", guard.DefaultClearanceCookieName)
		}

		// 6. Retry /protected with clearance cookie -> admitted to origin!
		reqAdmit, _ := http.NewRequest(http.MethodGet, front.URL+"/protected", nil)
		reqAdmit.AddCookie(clearCookie)
		respAdmit, err := testClient.Do(reqAdmit)
		if err != nil {
			t.Fatal(err)
		}
		admitBody, _ := io.ReadAll(respAdmit.Body)
		_ = respAdmit.Body.Close()
		if respAdmit.StatusCode != http.StatusOK || string(admitBody) != "ok" {
			t.Fatalf("cleared visitor: status=%d body=%q", respAdmit.StatusCode, string(admitBody))
		}

		// 7. Verify Prometheus counters for all 6 guard metrics.
		prom := a.renderPrometheusMetrics()
		for _, want := range []string{
			"concert_guard_quota_rejected_total ",
			"concert_guard_shed_total ",
			"concert_guard_ratelimit_total ",
			"concert_guard_geo_blocked_total ",
			"concert_guard_challenge_passed_total 1",
			"concert_guard_challenge_failed_total 1",
		} {
			if !strings.Contains(prom, want) {
				t.Fatalf("metrics missing %q:\n%s", want, prom)
			}
		}
	})
}

// TestWave1_ConcertfileWildcardAndRateLimit verifies Concertfile wildcard host
// parsing & round-trip formatting, rate_limit directive enforcement, exact vs
// wildcard SNI/Host precedence, and ACME DNS-01 config validation.
func TestWave1_ConcertfileWildcardAndRateLimit(t *testing.T) {
	upWild := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("WILD:" + r.URL.Path))
	}))
	defer upWild.Close()
	upExact := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("EXACT:" + r.URL.Path))
	}))
	defer upExact.Close()

	// Create an ephemeral self-signed wildcard PEM keypair for SNI verification.
	certPath, keyPath := writeSelfSignedTestCert(t, "*.tenant.example.test")

	cfSrc := fmt.Sprintf(`
{
    listen 127.0.0.1:0
    tls_dns_provider webhook
    tls_dns_webhook_url https://dns.example.test/hook
}

*.tenant.example.test {
    upstream %s
    cap 4
    rate_limit /login 2/1m
    tls_cert %q
    tls_key %q
}

vip.tenant.example.test {
    upstream %s
    cap 4
}
`, upWild.URL, certPath, keyPath, upExact.URL)

	parsed, err := configfile.ParseConcertfile([]byte(cfSrc))
	if err != nil {
		t.Fatalf("ParseConcertfile: %v", err)
	}
	if parsed.Global.TLSDNSProvider != "webhook" || parsed.Global.TLSDNSWebhookURL != "https://dns.example.test/hook" {
		t.Fatalf("unexpected global DNS-01 fields: %+v", parsed.Global)
	}
	if len(parsed.Sites) != 2 || parsed.Sites[0].Hosts[0] != "*.tenant.example.test" {
		t.Fatalf("unexpected sites: %+v", parsed.Sites)
	}
	if len(parsed.Sites[0].RateLimits) != 1 || parsed.Sites[0].RateLimits[0] != "/login 2/1m" {
		t.Fatalf("unexpected rate_limits: %+v", parsed.Sites[0].RateLimits)
	}

	// FormatConcertfile round-trip preserves wildcard host, rate_limit, and DNS-01 directives.
	formatted := configfile.FormatConcertfile(parsed)
	reparsed, err := configfile.ParseConcertfile([]byte(formatted))
	if err != nil {
		t.Fatalf("FormatConcertfile round-trip failed:\n%s\nerr: %v", formatted, err)
	}
	if reparsed.Sites[0].Hosts[0] != "*.tenant.example.test" || len(reparsed.Sites[0].RateLimits) != 1 {
		t.Fatalf("round-trip mismatch: %+v", reparsed.Sites[0])
	}

	// Reject malformed wildcards (*.*.a.com, *.localhost, *.127.0.0.1).
	for _, badHost := range []string{"*.*.example.test", "*.localhost", "*.127.0.0.1", "a.*.example.test"} {
		if _, err := configfile.NormalizeHost(badHost); err == nil {
			t.Errorf("NormalizeHost(%q) unexpectedly succeeded", badHost)
		}
	}

	// Boot vhostManager and test wildcard vs exact Host routing + rate_limit + SNI TLS lookup.
	cfPath := filepath.Join(t.TempDir(), "Concertfile")
	if err := os.WriteFile(cfPath, []byte(cfSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	base := testConfig(upWild.URL)
	base.configFile = cfPath

	vm, err := newVhostManager(base)
	if err != nil {
		t.Fatalf("newVhostManager: %v", err)
	}
	defer vm.Close()

	srv := httptest.NewServer(vm)
	defer srv.Close()

	doHost := func(host, path string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Host = host
		resp, err := testClient.Do(req)
		if err != nil {
			t.Fatalf("%s%s: %v", host, path, err)
		}
		return resp
	}

	// Single-label subdomain matches *.tenant.example.test.
	resp := doHost("alpha.tenant.example.test", "/hello")
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "WILD:/hello" {
		t.Fatalf("wildcard host: %d %q", resp.StatusCode, string(body))
	}

	// Exact host vip.tenant.example.test wins over *.tenant.example.test.
	resp = doHost("vip.tenant.example.test", "/hello")
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "EXACT:/hello" {
		t.Fatalf("exact host precedence: %d %q", resp.StatusCode, string(body))
	}

	// Multi-label subdomain does NOT match RFC 6125 single-label wildcard -> 421.
	resp = doHost("deep.sub.tenant.example.test", "/hello")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("multi-label host status=%d, want 421", resp.StatusCode)
	}

	// Concertfile rate_limit /login 2/1m enforced on wildcard site without X-Concert-Queue.
	for i := 0; i < 3; i++ {
		r := doHost("alpha.tenant.example.test", "/login")
		_ = r.Body.Close()
		if i < 2 && r.StatusCode != http.StatusOK {
			t.Fatalf("wildcard /login #%d: status=%d, want 200", i, r.StatusCode)
		}
		if i == 2 {
			if r.StatusCode != http.StatusTooManyRequests || r.Header.Get(headerConcertQueue) != "" {
				t.Fatalf("wildcard /login #3: status=%d queue=%q, want 429 without queue header",
					r.StatusCode, r.Header.Get(headerConcertQueue))
			}
		}
	}

	// SNI lookup matches wildcard site's PEM certificate for alpha.tenant.example.test.
	tc, _, tlsClose, err := vm.buildTLS(context.Background())
	if err != nil {
		t.Fatalf("vm.buildTLS: %v", err)
	}
	if tlsClose != nil {
		defer tlsClose()
	}
	cert, err := tc.GetCertificate(&tls.ClientHelloInfo{ServerName: "alpha.tenant.example.test"})
	if err != nil || cert == nil {
		t.Fatalf("SNI GetCertificate for wildcard subdomain failed: cert=%v err=%v", cert, err)
	}

	// Validate -tls-dns-provider fail-closed checks in config.normalize().
	cfMissingTok := testConfig(upWild.URL)
	cfMissingTok.tlsDomains = "*.example.com"
	cfMissingTok.tlsCacheDir = t.TempDir()
	cfMissingTok.tlsDNSProvider = "cloudflare"
	if err := cfMissingTok.normalize(); err == nil || !strings.Contains(err.Error(), "CONCERT_DNS_API_TOKEN") {
		t.Fatalf("cloudflare without token: err=%v, want CONCERT_DNS_API_TOKEN error", err)
	}

	whMissingURL := testConfig(upWild.URL)
	whMissingURL.tlsDomains = "*.example.com"
	whMissingURL.tlsCacheDir = t.TempDir()
	whMissingURL.tlsDNSProvider = "webhook"
	if err := whMissingURL.normalize(); err == nil || !strings.Contains(err.Error(), "-tls-dns-webhook-url") {
		t.Fatalf("webhook without URL: err=%v, want -tls-dns-webhook-url error", err)
	}
}

func writeSelfSignedTestCert(t *testing.T, dnsName string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	var certBuf, keyBuf bytes.Buffer
	_ = pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = pem.Encode(&keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certBuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyBuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
