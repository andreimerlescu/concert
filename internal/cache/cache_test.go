package cache_test

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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/andreimerlescu/concert/internal/cache"
)

// newEphemeralTestSecret generates a random non-hardcoded secret for tests.
func newEphemeralTestSecret(t *testing.T) (cache.Secret, string) {
	t.Helper()
	var buf [24]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	raw := fmt.Sprintf("test-ephemeral-%x", buf[:])
	return cache.NewSecret(raw), raw
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func TestSecret_Redaction(t *testing.T) {
	sec, raw := newEphemeralTestSecret(t)

	if sec.IsZero() {
		t.Fatal("non-empty secret reported IsZero")
	}
	if !sec.Equal([]byte(raw)) {
		t.Fatal("Equal returned false for matching secret")
	}
	if sec.Equal([]byte("wrong-value")) {
		t.Fatal("Equal returned true for mismatched secret")
	}
	if (cache.Secret{}).Equal([]byte("")) {
		t.Fatal("zero secret must never match empty candidate")
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	logger.Info("auth-check", "secret", sec)

	jsonBytes, err := json.Marshal(struct {
		S cache.Secret `json:"s"`
	}{S: sec})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	textBytes, err := sec.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	outputs := []string{
		sec.String(),
		sec.GoString(),
		fmt.Sprintf("%v", sec),
		fmt.Sprintf("%+v", sec),
		fmt.Sprintf("%#v", sec),
		fmt.Sprintf("%s", sec),
		fmt.Sprintf("%q", sec),
		fmt.Sprintf("%x", sec),
		string(jsonBytes),
		string(textBytes),
		logBuf.String(),
	}
	for i, out := range outputs {
		if strings.Contains(out, raw) {
			t.Fatalf("output #%d leaked raw secret: %q", i, out)
		}
		if !strings.Contains(out, cache.SecretPlaceholder) {
			t.Fatalf("output #%d missing placeholder %q: %q", i, cache.SecretPlaceholder, out)
		}
	}
}

func TestSecret_LoadAndValidation(t *testing.T) {
	dir := t.TempDir()
	_, raw := newEphemeralTestSecret(t)

	goodFile := filepath.Join(dir, "good.key")
	if err := os.WriteFile(goodFile, []byte("  "+raw+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	loaded, err := cache.SecretFromFile(goodFile)
	if err != nil {
		t.Fatalf("SecretFromFile(good) error = %v", err)
	}
	if !loaded.Equal([]byte(raw)) {
		t.Fatal("loaded secret did not match written value")
	}

	if runtime.GOOS != "windows" {
		openFile := filepath.Join(dir, "world.key")
		if err := os.WriteFile(openFile, []byte(raw), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := cache.SecretFromFile(openFile); !errors.Is(err, cache.ErrSecretPermissions) {
			t.Fatalf("SecretFromFile(0644) error = %v, want ErrSecretPermissions", err)
		}
	}

	if _, err := cache.SecretFromFile(dir); !errors.Is(err, cache.ErrSecretNotRegular) {
		t.Fatalf("SecretFromFile(dir) error = %v, want ErrSecretNotRegular", err)
	}

	placeholderFile := filepath.Join(dir, "placeholder.key")
	if err := os.WriteFile(placeholderFile, []byte("changeme\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := cache.SecretFromFile(placeholderFile); !errors.Is(err, cache.ErrSecretPlaceholder) {
		t.Fatalf("SecretFromFile(placeholder) error = %v, want ErrSecretPlaceholder", err)
	}

	emptyFile := filepath.Join(dir, "empty.key")
	if err := os.WriteFile(emptyFile, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := cache.SecretFromFile(emptyFile); !errors.Is(err, cache.ErrSecretEmpty) {
		t.Fatalf("SecretFromFile(empty) error = %v, want ErrSecretEmpty", err)
	}

	t.Setenv("TEST_CACHE_SEC", "")
	t.Setenv("TEST_CACHE_SEC_FILE", "")
	if _, err := cache.ResolveSecret("", "UNSET_TEST_CACHE_SEC_XYZ"); !errors.Is(err, cache.ErrSecretNotSet) {
		t.Fatalf("ResolveSecret(unset) error = %v, want ErrSecretNotSet", err)
	}

	t.Setenv("TEST_CACHE_SEC_FILE", goodFile)
	resolved, err := cache.ResolveSecret("", "TEST_CACHE_SEC")
	if err != nil || !resolved.Equal([]byte(raw)) {
		t.Fatalf("ResolveSecret(env file) = (%v, %v), want match", resolved, err)
	}
}

func TestStore_CRUD_TTL_AndDeepCopy(t *testing.T) {
	ctx := t.Context()
	clk := newFakeClock(time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC))
	s := cache.NewStore(cache.StoreConfig{
		MaxBytes:   1 << 20,
		Shards:     8,
		DefaultTTL: 30 * time.Second,
		Clock:      clk.Now,
	})
	t.Cleanup(func() { _ = s.Close() })

	key := "shop.example.com\x00/product/tee\x00color=blue\x00gz"
	body := []byte("<html>tee</html>")
	hdr := http.Header{"Content-Type": {"text/html"}}
	tags := []string{"Product:1", "catalog"}

	if err := s.Put(ctx, cache.Entry{
		Key:     key,
		Status:  http.StatusOK,
		Headers: hdr,
		Body:    body,
		Tags:    tags,
		TTL:     10 * time.Second,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Mutate caller inputs after Put to prove deep-copy isolation.
	body[0] = 'X'
	hdr.Set("Content-Type", "text/plain")
	tags[0] = "mutated"

	got, ok, err := s.Get(ctx, key)
	if err != nil || !ok {
		t.Fatalf("Get = (%v, %v, %v), want hit", got, ok, err)
	}
	if string(got.Body) != "<html>tee</html>" {
		t.Fatalf("Body = %q, want %q", got.Body, "<html>tee</html>")
	}
	if got.Headers.Get("Content-Type") != "text/html" {
		t.Fatalf("Content-Type = %q, want text/html", got.Headers.Get("Content-Type"))
	}
	if got.Host != "shop.example.com" || got.Path != "/product/tee" {
		t.Fatalf("Host/Path = (%q, %q), want (shop.example.com, /product/tee)", got.Host, got.Path)
	}

	// Mutate returned entry and verify subsequent Get still sees original data.
	got.Body[0] = 'Y'
	got2, ok, err := s.Get(ctx, key)
	if err != nil || !ok || string(got2.Body) != "<html>tee</html>" {
		t.Fatalf("second Get corrupted after caller mutation: ok=%v body=%q err=%v", ok, got2.Body, err)
	}

	// Advance fake clock past TTL: entry expires without any time.Sleep.
	clk.Advance(10 * time.Second)
	_, ok, err = s.Get(ctx, key)
	if err != nil || ok {
		t.Fatalf("Get after TTL = (ok=%v, err=%v), want miss", ok, err)
	}

	st, err := s.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Entries != 0 || st.UsedBytes != 0 || st.Tags != 0 {
		t.Fatalf("after expiry stats = %+v, want Entries=0 UsedBytes=0 Tags=0", st)
	}
	if st.Hits != 2 || st.Misses != 1 {
		t.Fatalf("Hits/Misses = %d/%d, want 2/1", st.Hits, st.Misses)
	}

	// Idempotent Close and ErrClosed after close.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, _, err := s.Get(ctx, key); !errors.Is(err, cache.ErrClosed) {
		t.Fatalf("Get after Close error = %v, want ErrClosed", err)
	}
}

func TestStore_ByteBoundedLRUEviction(t *testing.T) {
	ctx := t.Context()
	const maxBytes int64 = 1800
	s := cache.NewStore(cache.StoreConfig{
		MaxBytes:      maxBytes,
		MaxEntryBytes: 900,
		Shards:        4,
		DefaultTTL:    time.Minute,
	})
	t.Cleanup(func() { _ = s.Close() })

	// Oversized entry is rejected cleanly.
	if err := s.Put(ctx, cache.Entry{
		Key:  "example.com\x00/huge\x00\x00raw",
		Body: bytes.Repeat([]byte("z"), 1000),
	}); !errors.Is(err, cache.ErrEntryTooLarge) {
		t.Fatalf("oversized Put error = %v, want ErrEntryTooLarge", err)
	}

	payload := bytes.Repeat([]byte("a"), 350)
	for i := range 20 {
		key := fmt.Sprintf("example.com\x00/item/%d\x00\x00raw", i)
		if err := s.Put(ctx, cache.Entry{Key: key, Body: payload}); err != nil {
			t.Fatalf("Put(%d): %v", i, err)
		}
		st, err := s.Stats(ctx)
		if err != nil {
			t.Fatalf("Stats: %v", err)
		}
		if st.UsedBytes > maxBytes {
			t.Fatalf("step %d: UsedBytes=%d exceeded MaxBytes=%d", i, st.UsedBytes, maxBytes)
		}
	}

	st, err := s.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Evictions == 0 {
		t.Fatalf("expected Evictions > 0 under byte pressure, got 0")
	}
}

func TestStore_PurgeURLPrefixTagAll(t *testing.T) {
	ctx := t.Context()
	s := cache.NewStore(cache.StoreConfig{
		MaxBytes:   1 << 20,
		Shards:     16,
		DefaultTTL: time.Minute,
	})
	t.Cleanup(func() { _ = s.Close() })

	entries := []cache.Entry{
		{Key: "shop.example.com\x00/product/a\x00\x00raw", Body: []byte("a-raw"), Tags: []string{"prod:a", "catalog"}},
		{Key: "shop.example.com\x00/product/a\x00\x00gz", Body: []byte("a-gz"), Tags: []string{"prod:a", "catalog"}},
		{Key: "shop.example.com\x00/product/a\x00page=2\x00raw", Body: []byte("a-p2"), Tags: []string{"prod:a"}},
		{Key: "shop.example.com\x00/product/b\x00\x00raw", Body: []byte("b-raw"), Tags: []string{"prod:b", "catalog"}},
		{Key: "shop.example.com\x00/blog/post-1\x00\x00raw", Body: []byte("blog1"), Tags: []string{"blog"}},
		{Key: "other.example.com\x00/product/a\x00\x00raw", Body: []byte("other-a"), Tags: []string{"catalog"}},
	}
	for _, e := range entries {
		if err := s.Put(ctx, e); err != nil {
			t.Fatalf("Put(%q): %v", e.Key, err)
		}
	}

	// PurgeURL removes all 3 variants of shop.example.com /product/a, leaving other.example.com intact.
	n, err := s.PurgeURL(ctx, "SHOP.EXAMPLE.COM", "/product/a")
	if err != nil || n != 3 {
		t.Fatalf("PurgeURL = (%d, %v), want (3, nil)", n, err)
	}
	if _, ok, _ := s.Get(ctx, "other.example.com\x00/product/a\x00\x00raw"); !ok {
		t.Fatal("PurgeURL erroneously removed another host's entry")
	}

	// PurgeTag removes remaining entries with tag "catalog" (shop /product/b and other /product/a).
	n, err = s.PurgeTag(ctx, "CATALOG")
	if err != nil || n != 2 {
		t.Fatalf("PurgeTag(catalog) = (%d, %v), want (2, nil)", n, err)
	}

	// Re-add two blog entries and purge by prefix.
	_ = s.Put(ctx, cache.Entry{Key: "shop.example.com\x00/blog/post-2\x00\x00raw", Body: []byte("blog2")})
	n, err = s.PurgePrefix(ctx, "shop.example.com", "/blog/")
	if err != nil || n != 2 {
		t.Fatalf("PurgePrefix(/blog/) = (%d, %v), want (2, nil)", n, err)
	}

	// PurgeAll empties everything and resets byte and tag accounting.
	_ = s.Put(ctx, cache.Entry{Key: "shop.example.com\x00/\x00\x00raw", Body: []byte("home"), Tags: []string{"home"}})
	n, err = s.PurgeAll(ctx)
	if err != nil || n != 1 {
		t.Fatalf("PurgeAll = (%d, %v), want (1, nil)", n, err)
	}
	st, err := s.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Entries != 0 || st.UsedBytes != 0 || st.Tags != 0 {
		t.Fatalf("after PurgeAll stats = %+v, want zeroed", st)
	}
}

func TestStore_SingleflightCoalescingAndCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		s := cache.NewStore(cache.StoreConfig{MaxBytes: 1 << 20, Shards: 8, DefaultTTL: time.Minute})
		defer func() { _ = s.Close() }()

		const waiters = 48
		key := "example.com\x00/hot\x00\x00raw"
		leaderStarted := make(chan struct{})
		releaseLeader := make(chan struct{})
		var calls atomic.Int64

		loader := func(ctx context.Context) (cache.Entry, error) {
			if calls.Add(1) == 1 {
				close(leaderStarted)
			}
			<-releaseLeader
			return cache.Entry{
				Key:    key,
				Status: http.StatusOK,
				Body:   []byte("coalesced-payload"),
				TTL:    time.Minute,
			}, nil
		}

		// Launch leader first so we deterministically hold it in flight.
		leaderDone := make(chan error, 1)
		go func() {
			ent, shared, err := s.Do(ctx, key, loader)
			if err != nil {
				leaderDone <- err
				return
			}
			if shared || string(ent.Body) != "coalesced-payload" {
				leaderDone <- fmt.Errorf("unexpected leader result: shared=%v body=%q", shared, ent.Body)
				return
			}
			leaderDone <- nil
		}()
		<-leaderStarted

		// Launch one waiter, wait until it is durably blocked in Do, then cancel it.
		cancelCtx, cancelWaiter := context.WithCancel(ctx)
		cancelDone := make(chan error, 1)
		go func() {
			_, _, err := s.Do(cancelCtx, key, loader)
			cancelDone <- err
		}()
		synctest.Wait()
		cancelWaiter()
		if err := <-cancelDone; !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled waiter err = %v, want context.Canceled", err)
		}

		// Launch waiters and wait until every waiter is durably parked on call.done.
		var wg sync.WaitGroup
		var sharedCount atomic.Int64
		errCh := make(chan error, waiters)
		for range waiters {
			wg.Go(func() {
				ent, shared, err := s.Do(ctx, key, loader)
				if err != nil {
					errCh <- err
					return
				}
				if string(ent.Body) != "coalesced-payload" {
					errCh <- fmt.Errorf("waiter body = %q", ent.Body)
					return
				}
				if shared {
					sharedCount.Add(1)
				}
			})
		}
		synctest.Wait()

		close(releaseLeader)
		wg.Wait()
		close(errCh)
		if err := <-leaderDone; err != nil {
			t.Fatalf("leader: %v", err)
		}
		for err := range errCh {
			t.Fatalf("waiter error: %v", err)
		}
		if calls.Load() != 1 {
			t.Fatalf("loader calls = %d, want 1", calls.Load())
		}
		if sharedCount.Load() != waiters {
			t.Fatalf("coalesced waiters = %d, want %d", sharedCount.Load(), waiters)
		}
	})
}

func TestStore_ConcurrentStress(t *testing.T) {
	ctx := t.Context()
	const maxBytes int64 = 16 << 10
	s := cache.NewStore(cache.StoreConfig{
		MaxBytes:      maxBytes,
		MaxEntryBytes: 2 << 10,
		Shards:        16,
		DefaultTTL:    time.Minute,
	})
	t.Cleanup(func() { _ = s.Close() })

	const workers = 24
	const iters = 120
	start := make(chan struct{})
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			<-start
			payload := bytes.Repeat([]byte{'a' + byte(w%26)}, 256)
			for i := range iters {
				k := fmt.Sprintf("h%d.example.com\x00/p/%d\x00\x00raw", w%3, i%15)
				tag := fmt.Sprintf("tag:%d", i%5)
				_ = s.Put(ctx, cache.Entry{Key: k, Body: payload, Tags: []string{tag}, TTL: time.Minute})
				_, _, _ = s.Get(ctx, k)
				switch i % 11 {
				case 0:
					_, _ = s.PurgeTag(ctx, tag)
				case 3:
					_, _ = s.PurgeURL(ctx, fmt.Sprintf("h%d.example.com", w%3), fmt.Sprintf("/p/%d", i%15))
				case 7:
					_, _ = s.PurgePrefix(ctx, "", "/p/1")
				case 10:
					st, err := s.Stats(ctx)
					if err == nil && (st.UsedBytes < 0 || st.UsedBytes > maxBytes) {
						t.Errorf("invariant violated: UsedBytes=%d MaxBytes=%d", st.UsedBytes, maxBytes)
					}
				}
			}
		})
	}
	close(start)
	wg.Wait()

	st, err := s.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.UsedBytes < 0 || st.UsedBytes > maxBytes {
		t.Fatalf("final UsedBytes=%d out of [0, %d]", st.UsedBytes, maxBytes)
	}
}

func TestServerClient_UnixSocketAuthAndPurge(t *testing.T) {
	ctx := t.Context()
	sec, _ := newEphemeralTestSecret(t)
	wrongSec, _ := newEphemeralTestSecret(t)

	store := cache.NewStore(cache.StoreConfig{MaxBytes: 4 << 20, Shards: 8, DefaultTTL: time.Minute})
	t.Cleanup(func() { _ = store.Close() })

	// Fail closed when secret is zero.
	if _, err := cache.NewServer(cache.ServerConfig{Store: store}); !errors.Is(err, cache.ErrSecretNotSet) {
		t.Fatalf("NewServer without secret = %v, want ErrSecretNotSet", err)
	}

	srv, err := cache.NewServer(cache.ServerConfig{
		Store:        store,
		Secret:       sec,
		MaxConns:     16,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		IdleTimeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	sockDir, err := os.MkdirTemp("/tmp", "cc-u-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "c.sock")
	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.ListenAndServeUnix(sockPath) }()

	// Wait deterministically for socket listener to accept connections.
	cli, err := cache.NewClient(cache.ClientConfig{
		Network:        "unix",
		Address:        sockPath,
		Secret:         sec,
		DialTimeout:    time.Second,
		RequestTimeout: 2 * time.Second,
		MaxIdleConns:   4,
		FailClosed:     true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	waitUntilReady(t, ctx, cli)

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(sockPath)
		if err != nil {
			t.Fatalf("Stat(%q): %v", sockPath, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("unix socket mode = %04o, want 0600", fi.Mode().Perm())
		}
	}

	// Wrong secret must fail with ErrUnauthorized.
	badCli, err := cache.NewClient(cache.ClientConfig{
		Network:    "unix",
		Address:    sockPath,
		Secret:     wrongSec,
		FailClosed: true,
	})
	if err != nil {
		t.Fatalf("NewClient(bad): %v", err)
	}
	t.Cleanup(func() { _ = badCli.Close() })
	if err := badCli.Ping(ctx); !errors.Is(err, cache.ErrUnauthorized) {
		t.Fatalf("bad secret Ping error = %v, want ErrUnauthorized", err)
	}

	// Unauthenticated raw frame must be rejected immediately.
	rawConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Dial unix: %v", err)
	}
	_ = cache.WriteFrame(rawConn, cache.OpPing, 0, nil, cache.MaxFrameBytes)
	fr, err := cache.ReadFrame(rawConn, cache.MaxFrameBytes)
	_ = rawConn.Close()
	if err != nil || fr.Op != cache.RespErr || !errors.Is(cache.DecodeError(fr.Payload), cache.ErrUnauthorized) {
		t.Fatalf("unauthenticated OpPing got (%+v, %v), want RespErr(ErrUnauthorized)", fr, err)
	}

	// Full PageCache RPC flow over Unix socket.
	key := "shop.example.com\x00/product/hat\x00\x00gz"
	if err := cli.Put(ctx, cache.Entry{
		Key:     key,
		Status:  http.StatusOK,
		Headers: http.Header{"Content-Type": {"text/html"}},
		Body:    []byte("<html>hat</html>"),
		Tags:    []string{"product:hat", "hats"},
		TTL:     time.Minute,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok, err := cli.Get(ctx, key)
	if err != nil || !ok || string(got.Body) != "<html>hat</html>" {
		t.Fatalf("Get = (%+v, %v, %v)", got, ok, err)
	}
	n, err := cli.PurgeTag(ctx, "hats")
	if err != nil || n != 1 {
		t.Fatalf("PurgeTag = (%d, %v), want (1, nil)", n, err)
	}
	_, ok, err = cli.Get(ctx, key)
	if err != nil || ok {
		t.Fatalf("Get after PurgeTag = (ok=%v, err=%v), want miss", ok, err)
	}

	_ = cli.Put(ctx, cache.Entry{Key: "shop.example.com\x00/cat/1\x00\x00raw", Body: []byte("1"), TTL: time.Minute})
	_ = cli.Put(ctx, cache.Entry{Key: "shop.example.com\x00/cat/2\x00\x00raw", Body: []byte("2"), TTL: time.Minute})
	if n, err := cli.PurgePrefix(ctx, "shop.example.com", "/cat/"); err != nil || n != 2 {
		t.Fatalf("PurgePrefix = (%d, %v), want (2, nil)", n, err)
	}

	st, err := cli.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Purges != 3 || st.Entries != 0 {
		t.Fatalf("Stats = %+v, want Purges=3 Entries=0", st)
	}

	shutdownCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("ListenAndServeUnix: %v", err)
	}
}

func TestServerClient_MTLS(t *testing.T) {
	ctx := t.Context()
	sec, _ := newEphemeralTestSecret(t)
	pki := generateTestPKI(t)

	srvTLS, err := cache.BuildServerTLSConfig(pki.serverCert, pki.serverKey, pki.caCert)
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}

	store := cache.NewStore(cache.StoreConfig{MaxBytes: 1 << 20, Shards: 4, DefaultTTL: time.Minute})
	t.Cleanup(func() { _ = store.Close() })

	srv, err := cache.NewServer(cache.ServerConfig{
		Store:     store,
		Secret:    sec,
		TLSConfig: srvTLS,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	tlsLn := tls.NewListener(rawLn, srvTLS)
	srvDone := make(chan error, 1)
	go func() { srvDone <- srv.Serve(tlsLn) }()
	t.Cleanup(func() {
		_ = srv.Close()
		<-srvDone
	})

	// Valid mTLS client succeeds.
	goodCli, err := cache.NewClient(cache.ClientConfig{
		Network:    "tcp",
		Address:    rawLn.Addr().String(),
		Secret:     sec,
		TLSConfig:  pki.clientTLS,
		FailClosed: true,
	})
	if err != nil {
		t.Fatalf("NewClient(mTLS): %v", err)
	}
	t.Cleanup(func() { _ = goodCli.Close() })
	if err := goodCli.Ping(ctx); err != nil {
		t.Fatalf("mTLS Ping: %v", err)
	}

	// Client without client cert must fail mTLS handshake.
	noCertTLS := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pki.caPool,
		ServerName: "127.0.0.1",
	}
	badCli, err := cache.NewClient(cache.ClientConfig{
		Network:    "tcp",
		Address:    rawLn.Addr().String(),
		Secret:     sec,
		TLSConfig:  noCertTLS,
		FailClosed: true,
	})
	if err != nil {
		t.Fatalf("NewClient(no cert): %v", err)
	}
	t.Cleanup(func() { _ = badCli.Close() })
	if err := badCli.Ping(ctx); err == nil {
		t.Fatal("expected mTLS handshake failure without client certificate")
	}
}

func TestServer_MaxConnsAndMetrics(t *testing.T) {
	ctx := t.Context()
	sec, rawSec := newEphemeralTestSecret(t)
	store := cache.NewStore(cache.StoreConfig{MaxBytes: 1 << 20, Shards: 4, DefaultTTL: time.Minute})
	t.Cleanup(func() { _ = store.Close() })

	srv, err := cache.NewServer(cache.ServerConfig{
		Store:        store,
		Secret:       sec,
		MaxConns:     2,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		IdleTimeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srvDone := make(chan error, 1)
	go func() { srvDone <- srv.Serve(ln) }()

	// Hold 2 authenticated connections open.
	openAndAuth := func() net.Conn {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if err := cache.WriteFrame(c, cache.OpAuth, 0, []byte(rawSec), cache.MaxFrameBytes); err != nil {
			t.Fatalf("WriteFrame auth: %v", err)
		}
		fr, err := cache.ReadFrame(c, cache.MaxFrameBytes)
		if err != nil || fr.Op != cache.RespOK {
			t.Fatalf("auth reply = (%+v, %v), want RespOK", fr, err)
		}
		return c
	}

	c1 := openAndAuth()
	defer c1.Close()
	c2 := openAndAuth()
	defer c2.Close()

	// 3rd simultaneous connection must be rejected with ErrTooManyConns.
	c3, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("Dial 3rd: %v", err)
	}
	defer c3.Close()
	fr, err := cache.ReadFrame(c3, cache.MaxFrameBytes)
	if err != nil || fr.Op != cache.RespErr || !errors.Is(cache.DecodeError(fr.Payload), cache.ErrTooManyConns) {
		t.Fatalf("3rd conn got (%+v, %v), want ErrTooManyConns", fr, err)
	}

	// Inspect metrics and healthz HTTP endpoints.
	h := srv.MetricsHandler()

	recHealth := httptest.NewRecorder()
	h.ServeHTTP(recHealth, httptest.NewRequest(http.MethodGet, "/_cache/healthz", nil))
	if recHealth.Code != http.StatusOK {
		t.Fatalf("healthz code = %d, want 200", recHealth.Code)
	}

	recMetrics := httptest.NewRecorder()
	h.ServeHTTP(recMetrics, httptest.NewRequest(http.MethodGet, "/_cache/metrics", nil))
	if recMetrics.Code != http.StatusOK {
		t.Fatalf("metrics code = %d, want 200", recMetrics.Code)
	}
	body := recMetrics.Body.String()
	if strings.Contains(body, rawSec) {
		t.Fatal("metrics endpoint leaked raw secret")
	}
	for _, want := range []string{
		"concert_cache_entries 0",
		"concert_cache_active_conns 2",
		"concert_cache_rejected_conns_total 1",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}

	// Healthz returns 503 after Shutdown begins.
	shutdownCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	<-srvDone

	recDown := httptest.NewRecorder()
	h.ServeHTTP(recDown, httptest.NewRequest(http.MethodGet, "/_cache/healthz", nil))
	if recDown.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz after shutdown = %d, want 503", recDown.Code)
	}
}

func TestClient_FailOpenOnOutage(t *testing.T) {
	ctx := t.Context()
	sec, _ := newEphemeralTestSecret(t)

	// Bind an ephemeral address and immediately close it so dials fail immediately.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	closedAddr := ln.Addr().String()
	_ = ln.Close()

	var hookCalls atomic.Int64
	cli, err := cache.NewClient(cache.ClientConfig{
		Network:        "tcp",
		Address:        closedAddr,
		Secret:         sec,
		DialTimeout:    300 * time.Millisecond,
		RequestTimeout: 500 * time.Millisecond,
		OnError:        func(error) { hookCalls.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	// Default fail-open: Get returns clean miss and Put returns nil.
	if _, ok, err := cli.Get(ctx, "example.com\x00/\x00\x00raw"); err != nil || ok {
		t.Fatalf("fail-open Get = (ok=%v, err=%v), want (false, nil)", ok, err)
	}
	if err := cli.Put(ctx, cache.Entry{Key: "example.com\x00/\x00\x00raw", Body: []byte("ok"), TTL: time.Minute}); err != nil {
		t.Fatalf("fail-open Put err = %v, want nil", err)
	}
	if cli.Errors() != 2 || hookCalls.Load() != 2 {
		t.Fatalf("Errors=%d hookCalls=%d, want 2/2", cli.Errors(), hookCalls.Load())
	}

	// Ping and PurgeAll always surface outage errors.
	if err := cli.Ping(ctx); err == nil {
		t.Fatal("Ping must return error during daemon outage")
	}
	if _, err := cli.PurgeAll(ctx); err == nil {
		t.Fatal("PurgeAll must return error during daemon outage")
	}

	// FailClosed client surfaces Get error directly.
	strictCli, err := cache.NewClient(cache.ClientConfig{
		Network:        "tcp",
		Address:        closedAddr,
		Secret:         sec,
		DialTimeout:    300 * time.Millisecond,
		RequestTimeout: 500 * time.Millisecond,
		FailClosed:     true,
	})
	if err != nil {
		t.Fatalf("NewClient(strict): %v", err)
	}
	t.Cleanup(func() { _ = strictCli.Close() })
	if _, _, err := strictCli.Get(ctx, "example.com\x00/\x00\x00raw"); err == nil {
		t.Fatal("FailClosed Get must return error during outage")
	}
}

func ExampleNewStore() {
	ctx := context.Background()
	store := cache.NewStore(cache.StoreConfig{
		MaxBytes:   16 << 20,
		Shards:     16,
		DefaultTTL: 30 * time.Second,
	})
	defer func() { _ = store.Close() }()

	key := "shop.example.com\x00/product/1\x00\x00raw"
	if err := store.Put(ctx, cache.Entry{
		Key:    key,
		Status: http.StatusOK,
		Body:   []byte("ok"),
		Tags:   []string{"product:1"},
		TTL:    30 * time.Second,
	}); err != nil {
		panic(err)
	}
	ent, ok, err := store.Get(ctx, key)
	if err != nil {
		panic(err)
	}
	removed, err := store.PurgeTag(ctx, "product:1")
	if err != nil {
		panic(err)
	}
	fmt.Println(ok, string(ent.Body), removed)
	// Output:
	// true ok 1
}

func waitUntilReady(t *testing.T, ctx context.Context, cli *cache.Client) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	tk := time.NewTicker(5 * time.Millisecond)
	defer tk.Stop()
	for {
		if err := cli.Ping(ctx); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for cache server readiness")
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context cancelled waiting for server: %v", ctx.Err())
		case <-tk.C:
		}
	}
}

type testPKI struct {
	caCert     string
	serverCert string
	serverKey  string
	caPool     *x509.CertPool
	clientTLS  *tls.Config
}

func generateTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(CA): %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "concert-cache-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(CA): %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caCertPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caCertPath, caPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(CA): %v", err)
	}

	caParsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate(CA): %v", err)
	}

	issueLeaf := func(cn string, eku x509.ExtKeyUsage, ips []net.IP) (certPath, keyPath string, tlsCert tls.Certificate) {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", cn, err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{eku},
			IPAddresses:  ips,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caParsed, &leafKey.PublicKey, caKey)
		if err != nil {
			t.Fatalf("CreateCertificate(%s): %v", cn, err)
		}
		keyDER, err := x509.MarshalECPrivateKey(leafKey)
		if err != nil {
			t.Fatalf("MarshalECPrivateKey(%s): %v", cn, err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

		certPath = filepath.Join(dir, cn+".crt")
		keyPath = filepath.Join(dir, cn+".key")
		if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
			t.Fatalf("WriteFile(%s cert): %v", cn, err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			t.Fatalf("WriteFile(%s key): %v", cn, err)
		}
		tlsCert, err = tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("X509KeyPair(%s): %v", cn, err)
		}
		return certPath, keyPath, tlsCert
	}

	srvCert, srvKey, _ := issueLeaf("server", x509.ExtKeyUsageServerAuth, []net.IP{net.ParseIP("127.0.0.1")})
	_, _, cliCert := issueLeaf("client", x509.ExtKeyUsageClientAuth, nil)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to parse CA pool")
	}

	return testPKI{
		caCert:     caCertPath,
		serverCert: srvCert,
		serverKey:  srvKey,
		caPool:     pool,
		clientTLS: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			RootCAs:      pool,
			Certificates: []tls.Certificate{cliCert},
			ServerName:   "127.0.0.1",
		},
	}
}

// Verify WriteFrame rejects payloads larger than maxFrame without writing partial bytes.
func TestProtocol_FrameBounds(t *testing.T) {
	var buf bytes.Buffer
	if err := cache.WriteFrame(&buf, cache.OpPut, 0, make([]byte, 128), 64); !errors.Is(err, cache.ErrFrameTooLarge) {
		t.Fatalf("WriteFrame oversized error = %v, want ErrFrameTooLarge", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("oversized WriteFrame wrote %d bytes, want 0", buf.Len())
	}

	// Hostile header declaring 4 GiB payload must be rejected before allocating.
	hostile := []byte{cache.FrameMagic0, cache.FrameMagic1, cache.OpPut, 0, 0xFF, 0xFF, 0xFF, 0xFF}
	if _, err := cache.ReadFrame(bytes.NewReader(hostile), 4096); !errors.Is(err, cache.ErrFrameTooLarge) {
		t.Fatalf("hostile ReadFrame error = %v, want ErrFrameTooLarge", err)
	}

	// Truncated header returns io.ErrUnexpectedEOF or io.EOF cleanly.
	if _, err := cache.ReadFrame(bytes.NewReader([]byte{cache.FrameMagic0, cache.FrameMagic1}), 4096); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated header error = %v, want ErrUnexpectedEOF", err)
	}
}
