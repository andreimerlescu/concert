package kv_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/kv"
)

// fakeClock provides deterministic, race-free time control without time.Sleep.
type fakeClock struct {
	mu  sync.Mutex
	cur time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{cur: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.cur = c.cur.Add(d)
	c.mu.Unlock()
}

// shortSocketPath creates a temporary Unix socket path under /tmp so it stays
// well below macOS's 104-byte sockaddr_un sun_path limit.
func shortSocketPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ckv-*")
	if err != nil {
		t.Fatalf("MkdirTemp for unix socket: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

// testPassword generates a random ephemeral fake credential at test runtime
// so no credential-like literal ever appears in test source (S1).
func testPassword(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generate random test password: %v", err)
	}
	return fmt.Sprintf("ephemeral-test-%x", b)
}

// testPKI generates an ephemeral CA, server cert, and client cert in t.TempDir
// for TLS and mTLS verification tests.
type testPKI struct {
	caCert     string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "concert-kv-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	caCertPath := filepath.Join(dir, "ca.crt")
	writePEM(t, caCertPath, "CERTIFICATE", caDER)

	issue := func(name string, extUsage x509.ExtKeyUsage, ips []net.IP) (string, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate %s key: %v", name, err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: name},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{extUsage},
			IPAddresses:  ips,
			DNSNames:     []string{"localhost"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("create %s cert: %v", name, err)
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatalf("marshal %s key: %v", name, err)
		}
		cp := filepath.Join(dir, name+".crt")
		kp := filepath.Join(dir, name+".key")
		writePEM(t, cp, "CERTIFICATE", der)
		writePEM(t, kp, "EC PRIVATE KEY", keyDER)
		return cp, kp
	}

	sCert, sKey := issue("server", x509.ExtKeyUsageServerAuth, []net.IP{net.ParseIP("127.0.0.1")})
	cCert, cKey := issue("client", x509.ExtKeyUsageClientAuth, nil)
	return testPKI{
		caCert:     caCertPath,
		serverCert: sCert,
		serverKey:  sKey,
		clientCert: cCert,
		clientKey:  cKey,
	}
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestProtocol_RoundTripAndBounds(t *testing.T) {
	t.Parallel()

	values := []kv.Value{
		kv.SimpleString("OK"),
		kv.ErrorValue("ERR sample"),
		kv.Integer(-42),
		kv.Integer(0),
		kv.BulkString([]byte("hello\r\nworld")),
		kv.BulkString([]byte{}),
		kv.NullBulk(),
		kv.ArrayValue(kv.BulkFromString("SET"), kv.BulkFromString("k"), kv.Integer(7)),
	}

	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	for _, v := range values {
		if err := kv.WriteValue(bw, v); err != nil {
			t.Fatalf("WriteValue(%+v): %v", v, err)
		}
	}
	if err := bw.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	br := bufio.NewReader(&buf)
	for i, want := range values {
		got, err := kv.ReadValue(br, kv.ProtocolLimits{})
		if err != nil {
			t.Fatalf("ReadValue[%d]: %v", i, err)
		}
		if got.Kind != want.Kind {
			t.Fatalf("ReadValue[%d] kind = %d, want %d", i, got.Kind, want.Kind)
		}
		switch want.Kind {
		case kv.KindSimpleString, kv.KindError:
			if got.Str != want.Str {
				t.Fatalf("ReadValue[%d] Str = %q, want %q", i, got.Str, want.Str)
			}
		case kv.KindInteger:
			if got.Int != want.Int {
				t.Fatalf("ReadValue[%d] Int = %d, want %d", i, got.Int, want.Int)
			}
		case kv.KindBulkString:
			if !bytes.Equal(got.Bulk, want.Bulk) {
				t.Fatalf("ReadValue[%d] Bulk = %q, want %q", i, got.Bulk, want.Bulk)
			}
		case kv.KindArray:
			if len(got.Array) != len(want.Array) {
				t.Fatalf("ReadValue[%d] Array len = %d, want %d", i, len(got.Array), len(want.Array))
			}
		}
	}

	// Verify strict R3 limits reject oversized bulk, oversized array, long line, and deep nesting.
	limits := kv.ProtocolLimits{
		MaxBulkBytes: 16,
		MaxArrayLen:  4,
		MaxLineBytes: 32,
		MaxNesting:   2,
	}
	cases := []struct {
		name    string
		wire    string
		wantErr error
	}{
		{name: "bulk too large", wire: "$17\r\n12345678901234567\r\n", wantErr: kv.ErrBulkTooLarge},
		{name: "array too large", wire: "*5\r\n:1\r\n:2\r\n:3\r\n:4\r\n:5\r\n", wantErr: kv.ErrArrayTooLarge},
		{name: "line too long", wire: "+" + strings.Repeat("a", 40) + "\r\n", wantErr: kv.ErrLineTooLong},
		{name: "nesting too deep", wire: "*1\r\n*1\r\n*1\r\n*1\r\n:1\r\n", wantErr: kv.ErrNestingTooDeep},
		{name: "bad prefix", wire: "!oops\r\n", wantErr: kv.ErrProtocol},
		{name: "negative bulk", wire: "$-2\r\n", wantErr: kv.ErrProtocol},
		{name: "missing crlf bulk", wire: "$3\r\nabcXX", wantErr: kv.ErrProtocol},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := kv.ReadValue(bufio.NewReader(strings.NewReader(tc.wire)), limits)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ReadValue(%q) error = %v, want %v", tc.wire, err, tc.wantErr)
			}
		})
	}

	// Verify inline command parsing.
	cmd, err := kv.ReadCommand(bufio.NewReader(strings.NewReader("\r\nSET \"hello world\" 123\r\n")), limits)
	if err != nil {
		t.Fatalf("ReadCommand inline: %v", err)
	}
	if len(cmd) != 3 || cmd[0] != "SET" || cmd[1] != "hello world" || cmd[2] != "123" {
		t.Fatalf("ReadCommand inline = %v, want [SET 'hello world' 123]", cmd)
	}
}

func TestStore_KVHashTTLAndMaxMemory(t *testing.T) {
	t.Parallel()

	clk := newFakeClock()
	st := kv.NewStore(kv.StoreConfig{
		MaxMemoryBytes: 64 << 20,
		Now:            clk.Now,
	})

	// SET NX/XX + EX/PX + TTL with deterministic clock.
	ok, err := st.Set("k1", []byte("v1"), kv.SetOptions{TTL: 10 * time.Second, NX: true})
	if err != nil || !ok {
		t.Fatalf("Set NX initial = (%v, %v), want (true, nil)", ok, err)
	}
	ok, err = st.Set("k1", []byte("v2"), kv.SetOptions{NX: true})
	if err != nil || ok {
		t.Fatalf("Set NX existing = (%v, %v), want (false, nil)", ok, err)
	}
	ok, err = st.Set("k1", []byte("v2"), kv.SetOptions{XX: true, TTL: 20 * time.Second})
	if err != nil || !ok {
		t.Fatalf("Set XX existing = (%v, %v), want (true, nil)", ok, err)
	}
	if got := st.TTL("k1"); got != 20 {
		t.Fatalf("TTL(k1) = %d, want 20", got)
	}
	clk.Advance(5 * time.Second)
	if got := st.TTL("k1"); got != 15 {
		t.Fatalf("TTL(k1) after 5s = %d, want 15", got)
	}
	clk.Advance(16 * time.Second)
	if _, found := st.Get("k1"); found {
		t.Fatalf("Get(k1) after expiry = found, want missing")
	}
	if got := st.TTL("k1"); got != -2 {
		t.Fatalf("TTL(k1) expired = %d, want -2", got)
	}

	// INCRBY & overflow protection.
	n, err := st.IncrBy("ctr", 5)
	if err != nil || n != 5 {
		t.Fatalf("IncrBy = (%d, %v), want (5, nil)", n, err)
	}
	if _, err := st.IncrBy("ctr", math.MaxInt64); !errors.Is(err, kv.ErrIntOverflow) {
		t.Fatalf("IncrBy overflow error = %v, want ErrIntOverflow", err)
	}

	// HSET / HGET / HGETALL / HDEL + WRONGTYPE.
	added, err := st.HSet("bans", map[string][]byte{"ip1": []byte("a"), "ip2": []byte("b")})
	if err != nil || added != 2 {
		t.Fatalf("HSet = (%d, %v), want (2, nil)", added, err)
	}
	if _, err := st.HSet("ctr", map[string][]byte{"f": []byte("1")}); !errors.Is(err, kv.ErrWrongType) {
		t.Fatalf("HSet on string error = %v, want ErrWrongType", err)
	}
	val, found, err := st.HGet("bans", "ip1")
	if err != nil || !found || string(val) != "a" {
		t.Fatalf("HGet = (%q, %v, %v), want ('a', true, nil)", val, found, err)
	}
	all, err := st.HGetAll("bans")
	if err != nil || len(all) != 2 {
		t.Fatalf("HGetAll len = %d, err = %v", len(all), err)
	}
	if removed, err := st.HDel("bans", "ip1", "ip2"); err != nil || removed != 2 {
		t.Fatalf("HDel = (%d, %v), want (2, nil)", removed, err)
	}
	if st.Exists("bans") != 0 {
		t.Fatalf("Exists(bans) after deleting all fields = %d, want 0", st.Exists("bans"))
	}

	// MaxMemoryBytes: EvictOldest evicts deterministically; EvictReject returns OOM.
	evictStore := kv.NewStore(kv.StoreConfig{
		MaxMemoryBytes: 300,
		EvictionPolicy: kv.EvictOldest,
		Now:            clk.Now,
	})
	payload := bytes.Repeat([]byte("x"), 100) // ~167 bytes each -> only 1 fits under 300
	if _, err := evictStore.Set("a", payload, kv.SetOptions{}); err != nil {
		t.Fatalf("Set a: %v", err)
	}
	if _, err := evictStore.Set("b", payload, kv.SetOptions{}); err != nil {
		t.Fatalf("Set b (should evict a): %v", err)
	}
	if _, found := evictStore.Get("a"); found {
		t.Fatalf("expected oldest key 'a' to be evicted")
	}
	if _, found := evictStore.Get("b"); !found {
		t.Fatalf("expected newest key 'b' to remain")
	}
	if evictStore.Stats().Evictions == 0 {
		t.Fatalf("expected Evictions > 0")
	}

	rejectStore := kv.NewStore(kv.StoreConfig{
		MaxMemoryBytes: 250,
		EvictionPolicy: kv.EvictReject,
		Now:            clk.Now,
	})
	if _, err := rejectStore.Set("a", payload, kv.SetOptions{}); err != nil {
		t.Fatalf("Set a in rejectStore: %v", err)
	}
	if _, err := rejectStore.Set("b", payload, kv.SetOptions{}); !errors.Is(err, kv.ErrMaxMemoryExceeded) {
		t.Fatalf("Set b in rejectStore error = %v, want ErrMaxMemoryExceeded", err)
	}
}

func TestStore_ConcertQueuesAndAuctions(t *testing.T) {
	t.Parallel()

	clk := newFakeClock()
	st := kv.NewStore(kv.StoreConfig{Now: clk.Now})

	r1, err := st.CQJoin("drop", "t1", "client-a", time.Minute, 0)
	if err != nil || r1.Position != 1 || r1.Depth != 1 {
		t.Fatalf("CQJoin t1 = (%+v, %v)", r1, err)
	}
	r2, err := st.CQJoin("drop", "t2", "client-b", time.Minute, 0)
	if err != nil || r2.Position != 2 || r2.Depth != 2 {
		t.Fatalf("CQJoin t2 = (%+v, %v)", r2, err)
	}
	r3, err := st.CQJoin("drop", "t3", "client-c", time.Minute, 50)
	if err != nil || r3.Position != 1 || r3.Depth != 3 {
		t.Fatalf("CQJoin t3 with bid 50 = (%+v, %v), want pos 1", r3, err)
	}

	// Raise t2's bid above t3: t2 moves to position 1.
	bidRes, err := st.CQBid("drop", "t2", 100)
	if err != nil || bidRes.Position != 1 || bidRes.Bid != 100 {
		t.Fatalf("CQBid t2 = (%+v, %v), want pos 1 bid 100", bidRes, err)
	}
	// Lower or equal bid must be rejected.
	if _, err := st.CQBid("drop", "t2", 100); !errors.Is(err, kv.ErrBidTooLow) {
		t.Fatalf("CQBid equal error = %v, want ErrBidTooLow", err)
	}

	// Claim top 2 tickets: must return t2 (bid 100), then t3 (bid 50).
	claimed, err := st.CQClaim("drop", "edge-1", 2)
	if err != nil || len(claimed) != 2 {
		t.Fatalf("CQClaim = (%+v, %v)", claimed, err)
	}
	if claimed[0].TicketID != "t2" || claimed[1].TicketID != "t3" {
		t.Fatalf("CQClaim order = [%s, %s], want [t2, t3]", claimed[0].TicketID, claimed[1].TicketID)
	}

	// Poll claimed ticket vs remaining waiting ticket.
	p2, err := st.CQPoll("drop", "t2", 0)
	if err != nil || p2.Status != "claimed" {
		t.Fatalf("CQPoll t2 = (%+v, %v), want claimed", p2, err)
	}
	p1, err := st.CQPoll("drop", "t1", 2*time.Minute)
	if err != nil || p1.Status != "waiting" || p1.Position != 1 || p1.Depth != 1 {
		t.Fatalf("CQPoll t1 = (%+v, %v), want waiting pos 1", p1, err)
	}

	// Purge by clientKey drops banned client's waiting ticket.
	_, _ = st.CQJoin("drop", "t4", "banned-ip", time.Minute, 10)
	purged, err := st.CQPurge("drop", "stale", "banned-ip")
	if err != nil || purged != 1 {
		t.Fatalf("CQPurge client = (%d, %v), want 1", purged, err)
	}

	// Advance clock past t1's TTL and purge stale.
	clk.Advance(3 * time.Minute)
	purged, err = st.CQPurge("drop", "stale", "")
	if err != nil || purged < 1 {
		t.Fatalf("CQPurge stale = (%d, %v), want >= 1", purged, err)
	}
	stats := st.CQStats("drop")
	if stats.Waiting != 0 || stats.TotalJoined != 4 || stats.TotalClaimed != 2 {
		t.Fatalf("CQStats = %+v, unexpected counters", stats)
	}
}

func TestStore_BoundedPubSubAndSlowConsumerEviction(t *testing.T) {
	t.Parallel()

	st := kv.NewStore(kv.StoreConfig{
		PubSubBuffer:      2,
		SlowConsumerLimit: 2,
	})

	fast, err := st.Subscribe("ch")
	if err != nil {
		t.Fatalf("Subscribe fast: %v", err)
	}
	defer fast.Close()

	slow, err := st.Subscribe("ch")
	if err != nil {
		t.Fatalf("Subscribe slow: %v", err)
	}
	defer slow.Close()

	// Publish 4 messages while only draining fast; slow fills buffer (2) then
	// drops 2 consecutive messages and is evicted without blocking Publish.
	for i := 0; i < 4; i++ {
		st.Publish("ch", []byte(fmt.Sprintf("msg-%d", i)))
		msg := <-fast.Messages()
		if string(msg.Payload) != fmt.Sprintf("msg-%d", i) {
			t.Fatalf("fast got %q, want msg-%d", msg.Payload, i)
		}
	}

	select {
	case <-slow.Evicted():
	default:
		t.Fatalf("expected slow consumer to be evicted after consecutive drops")
	}

	stats := st.Stats()
	if stats.PubSubEvicted != 1 || stats.PubSubDropped < 2 {
		t.Fatalf("PubSub stats = evicted:%d dropped:%d, want evicted:1 dropped>=2",
			stats.PubSubEvicted, stats.PubSubDropped)
	}
}

func TestStore_ConcurrentStressRace(t *testing.T) {
	t.Parallel()

	st := kv.NewStore(kv.StoreConfig{
		MaxMemoryBytes:    16 << 20,
		PubSubBuffer:      64,
		SlowConsumerLimit: 1000,
	})

	const workers = 16
	const opsPerWorker = 100

	start := make(chan struct{})
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			for i := range opsPerWorker {
				key := fmt.Sprintf("k:%d:%d", id, i%8)
				_, _ = st.Set(key, []byte("payload"), kv.SetOptions{TTL: time.Minute})
				_, _ = st.Get(key)
				_, _ = st.IncrBy("global-counter", 1)
				_, _ = st.HSet("shared-hash", map[string][]byte{key: []byte("1")})
				_, _ = st.CQJoin("shared-q", fmt.Sprintf("t:%d:%d", id, i), fmt.Sprintf("c:%d", id), time.Minute, int64(i%5))
				if i%10 == 0 {
					_, _ = st.CQClaim("shared-q", fmt.Sprintf("edge-%d", id), 1)
				}
				st.Publish("events", []byte("tick"))
			}
		}(w)
	}

	close(start)
	wg.Wait()

	val, ok := st.Get("global-counter")
	if !ok {
		t.Fatalf("global-counter missing after concurrent stress")
	}
	want := fmt.Sprintf("%d", workers*opsPerWorker)
	if string(val) != want {
		t.Fatalf("global-counter = %q, want %q", string(val), want)
	}
}

func TestWAL_CompactCrashRecoveryAndPermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	clk := newFakeClock()
	st := kv.NewStore(kv.StoreConfig{Now: clk.Now})

	wal, err := kv.OpenWAL(dir, true)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}

	apply := func(seq uint64, args ...string) {
		t.Helper()
		reply, walArgs, _ := st.Execute(args)
		if reply.Kind == kv.KindError {
			t.Fatalf("Execute(%v): %s", args, reply.Str)
		}
		if err := wal.Append(seq, walArgs); err != nil {
			t.Fatalf("WAL.Append(%d): %v", seq, err)
		}
	}

	apply(1, "SET", "alpha", "one")
	apply(2, "HSET", "bans", "192.0.2.9", "blocked")
	apply(3, "CQ.JOIN", "drop", "t1", "c1", "TTL", "60000", "BID", "25")

	// Compact to atomic 0600 snapshot.
	if err := wal.Compact(st); err != nil {
		t.Fatalf("WAL.Compact: %v", err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(wal.SnapshotPath())
		if err != nil {
			t.Fatalf("Stat snapshot: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("snapshot permissions = %04o, want 0600", fi.Mode().Perm())
		}
	}

	// Append post-snapshot WAL records.
	apply(4, "SET", "beta", "two")
	apply(5, "INCRBY", "hits", "7")
	if err := wal.Close(); err != nil {
		t.Fatalf("WAL.Close: %v", err)
	}

	// Simulate crash leaving a torn trailing record at the end of WAL.
	f, err := os.OpenFile(wal.WALPath(), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open wal to append torn tail: %v", err)
	}
	if _, err := f.Write([]byte("WAL1\x00\x00\x00\x00\x00\x00\x00\x06\xde\xad")); err != nil {
		_ = f.Close()
		t.Fatalf("write torn tail: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close torn wal: %v", err)
	}

	// Reopen and replay into a brand-new Store.
	wal2, err := kv.OpenWAL(dir, true)
	if err != nil {
		t.Fatalf("reopen WAL: %v", err)
	}
	defer func() { _ = wal2.Close() }()

	recovered := kv.NewStore(kv.StoreConfig{Now: clk.Now})
	stats, err := wal2.Replay(recovered)
	if err != nil {
		t.Fatalf("WAL.Replay: %v", err)
	}
	if !stats.SnapshotLoaded || stats.WALReplayed != 2 || !stats.TruncatedTail {
		t.Fatalf("ReplayStats = %+v, want SnapshotLoaded=true WALReplayed=2 TruncatedTail=true", stats)
	}

	if v, ok := recovered.Get("alpha"); !ok || string(v) != "one" {
		t.Fatalf("recovered alpha = (%q, %v), want ('one', true)", v, ok)
	}
	if v, ok := recovered.Get("beta"); !ok || string(v) != "two" {
		t.Fatalf("recovered beta = (%q, %v), want ('two', true)", v, ok)
	}
	if v, ok := recovered.Get("hits"); !ok || string(v) != "7" {
		t.Fatalf("recovered hits = (%q, %v), want ('7', true)", v, ok)
	}
	if hv, ok, err := recovered.HGet("bans", "192.0.2.9"); err != nil || !ok || string(hv) != "blocked" {
		t.Fatalf("recovered hash = (%q, %v, %v)", hv, ok, err)
	}
	poll, err := recovered.CQPoll("drop", "t1", 0)
	if err != nil || poll.Status != "waiting" || poll.Bid != 25 {
		t.Fatalf("recovered queue ticket = (%+v, %v)", poll, err)
	}
}

func TestSecret_RedactionAndFilePermissions(t *testing.T) {
	t.Parallel()

	raw := testPassword(t)
	sec := kv.NewSecret(raw)

	if !sec.Equal(raw) {
		t.Fatalf("Secret.Equal(correct) = false, want true")
	}
	if sec.Equal(raw + "x") {
		t.Fatalf("Secret.Equal(wrong) = true, want false")
	}

	// Verify every formatting, JSON, text, and slog path redacts raw.
	outputs := []string{
		sec.String(),
		sec.GoString(),
		fmt.Sprintf("%v", sec),
		fmt.Sprintf("%+v", sec),
		fmt.Sprintf("%#v", sec),
		fmt.Sprintf("%s", sec),
		fmt.Sprintf("%q", sec),
	}
	jb, err := json.Marshal(struct {
		Pass kv.Secret `json:"pass"`
	}{Pass: sec})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	outputs = append(outputs, string(jb))

	tb, err := sec.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	outputs = append(outputs, string(tb))

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	logger.Info("auth check", "password", sec)
	outputs = append(outputs, logBuf.String())

	for i, out := range outputs {
		if strings.Contains(out, raw) {
			t.Fatalf("redaction leak in output[%d]: %q contains secret", i, out)
		}
		if !strings.Contains(out, kv.RedactedPlaceholder) {
			t.Fatalf("output[%d] = %q missing placeholder %q", i, out, kv.RedactedPlaceholder)
		}
	}

	// File permission enforcement (0600 passes, 0644 fails closed) and placeholder rejection.
	dir := t.TempDir()
	goodPath := filepath.Join(dir, "pass.0600")
	if err := os.WriteFile(goodPath, []byte(raw+"\n"), 0o600); err != nil {
		t.Fatalf("write good secret file: %v", err)
	}
	loaded, err := kv.SecretFromFile(goodPath)
	if err != nil || !loaded.Equal(raw) {
		t.Fatalf("SecretFromFile(0600) = (%v, %v)", loaded, err)
	}

	if runtime.GOOS != "windows" {
		badModePath := filepath.Join(dir, "pass.0644")
		if err := os.WriteFile(badModePath, []byte(raw+"\n"), 0o644); err != nil {
			t.Fatalf("write bad-mode secret file: %v", err)
		}
		if _, err := kv.SecretFromFile(badModePath); !errors.Is(err, kv.ErrSecretPermissions) {
			t.Fatalf("SecretFromFile(0644) error = %v, want ErrSecretPermissions", err)
		}
	}

	placeholderPath := filepath.Join(dir, "pass.placeholder")
	if err := os.WriteFile(placeholderPath, []byte("changeme\n"), 0o600); err != nil {
		t.Fatalf("write placeholder file: %v", err)
	}
	if _, err := kv.SecretFromFile(placeholderPath); !errors.Is(err, kv.ErrSecretPlaceholder) {
		t.Fatalf("SecretFromFile(placeholder) error = %v, want ErrSecretPlaceholder", err)
	}
}

func TestServerAndClient_AuthUnixTLSAndFailOpen(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	pki := newTestPKI(t)
	srvTLS, err := kv.LoadServerTLSConfig(pki.serverCert, pki.serverKey, pki.caCert)
	if err != nil {
		t.Fatalf("LoadServerTLSConfig: %v", err)
	}
	cliTLS, err := kv.LoadClientTLSConfig(pki.caCert, pki.clientCert, pki.clientKey, "localhost")
	if err != nil {
		t.Fatalf("LoadClientTLSConfig: %v", err)
	}

	pass := kv.NewSecret(testPassword(t))
	sockPath := shortSocketPath(t, "kv.sock")

	srv, err := kv.NewServer(kv.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		UnixPath:   sockPath,
		TLSConfig:  srvTLS,
		Password:   pass,
		MaxConns:   8,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Server.Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	// Verify Unix socket 0600 permissions.
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(sockPath)
		if err != nil {
			t.Fatalf("Stat unix socket: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("unix socket mode = %04o, want 0600", fi.Mode().Perm())
		}
	}

	// Unauthenticated client over Unix socket must fail with NOAUTH.
	unauthCli, err := kv.NewClient(kv.ClientConfig{Addr: "unix://" + sockPath})
	if err != nil {
		t.Fatalf("NewClient unauth: %v", err)
	}
	defer func() { _ = unauthCli.Close() }()
	if err := unauthCli.Ping(ctx); err == nil || !strings.Contains(err.Error(), "NOAUTH") {
		t.Fatalf("unauthenticated Ping error = %v, want NOAUTH", err)
	}

	// Wrong password must fail with WRONGPASS.
	badPassCli, err := kv.NewClient(kv.ClientConfig{
		Addr:     "unix://" + sockPath,
		Password: kv.NewSecret(testPassword(t)),
	})
	if err != nil {
		t.Fatalf("NewClient badPass: %v", err)
	}
	defer func() { _ = badPassCli.Close() }()
	if err := badPassCli.Ping(ctx); err == nil || !strings.Contains(err.Error(), "WRONGPASS") {
		t.Fatalf("wrong password Ping error = %v, want WRONGPASS", err)
	}

	// Client without client cert must be rejected by mTLS server.
	noCertTLS, err := kv.LoadClientTLSConfig(pki.caCert, "", "", "localhost")
	if err != nil {
		t.Fatalf("LoadClientTLSConfig noCert: %v", err)
	}
	noCertCli, err := kv.NewClient(kv.ClientConfig{
		Addr:      srv.TCPAddr(),
		Password:  pass,
		TLSConfig: noCertTLS,
	})
	if err != nil {
		t.Fatalf("NewClient noCert: %v", err)
	}
	defer func() { _ = noCertCli.Close() }()
	if err := noCertCli.Ping(ctx); err == nil {
		t.Fatalf("expected mTLS server to reject client without client certificate")
	}

	// Authenticated mTLS client exercises KV, Pub/Sub, and typed CQ helpers.
	cli, err := kv.NewClient(kv.ClientConfig{
		Addr:      srv.TCPAddr(),
		Password:  pass,
		TLSConfig: cliTLS,
		PoolSize:  4,
	})
	if err != nil {
		t.Fatalf("NewClient mTLS: %v", err)
	}
	defer func() { _ = cli.Close() }()

	if err := cli.Ping(ctx); err != nil {
		t.Fatalf("mTLS Ping: %v", err)
	}
	if ok, err := cli.Set(ctx, "hello", []byte("world"), kv.SetOptions{TTL: time.Minute}); err != nil || !ok {
		t.Fatalf("Client.Set = (%v, %v)", ok, err)
	}
	if got, ok, err := cli.Get(ctx, "hello"); err != nil || !ok || string(got) != "world" {
		t.Fatalf("Client.Get = (%q, %v, %v)", got, ok, err)
	}

	// End-to-end Pub/Sub over mTLS.
	sub, err := cli.Subscribe(ctx, "bans")
	if err != nil {
		t.Fatalf("Client.Subscribe: %v", err)
	}
	defer sub.Close()

	if n, err := cli.Publish(ctx, "bans", []byte("192.0.2.55")); err != nil || n != 1 {
		t.Fatalf("Client.Publish = (%d, %v), want (1, nil)", n, err)
	}
	select {
	case msg := <-sub.Messages():
		if msg.Channel != "bans" || string(msg.Payload) != "192.0.2.55" {
			t.Fatalf("unexpected PubSubMessage: %+v", msg)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for Pub/Sub message")
	}

	// End-to-end CQ.* helpers.
	jr, err := cli.CQJoin(ctx, "room1", "t1", "client-1", time.Minute, 10)
	if err != nil || jr.Position != 1 || jr.Depth != 1 {
		t.Fatalf("Client.CQJoin = (%+v, %v)", jr, err)
	}
	br, err := cli.CQBid(ctx, "room1", "t1", 99)
	if err != nil || br.Bid != 99 {
		t.Fatalf("Client.CQBid = (%+v, %v)", br, err)
	}
	pr, err := cli.CQPoll(ctx, "room1", "t1", 0)
	if err != nil || pr.Status != "waiting" || pr.Bid != 99 {
		t.Fatalf("Client.CQPoll = (%+v, %v)", pr, err)
	}
	claimed, err := cli.CQClaim(ctx, "room1", "edge-a", 1)
	if err != nil || len(claimed) != 1 || claimed[0].TicketID != "t1" {
		t.Fatalf("Client.CQClaim = (%+v, %v)", claimed, err)
	}
	st, err := cli.CQStats(ctx, "room1")
	if err != nil || st.TotalClaimed != 1 {
		t.Fatalf("Client.CQStats = (%+v, %v)", st, err)
	}
	if _, err := cli.CQPurge(ctx, "room1", "all", ""); err != nil {
		t.Fatalf("Client.CQPurge: %v", err)
	}

	// Stop server and verify FailOpen client degrades cleanly with zero error.
	sub.Close()
	if err := srv.Close(); err != nil {
		t.Fatalf("Server.Close: %v", err)
	}

	failOpenCli, err := kv.NewClient(kv.ClientConfig{
		Addr:        "unix://" + sockPath,
		DialTimeout: 200 * time.Millisecond,
		FailOpen:    true,
	})
	if err != nil {
		t.Fatalf("NewClient failOpen: %v", err)
	}
	defer func() { _ = failOpenCli.Close() }()

	if val, ok, err := failOpenCli.Get(ctx, "hello"); err != nil || ok || val != nil {
		t.Fatalf("FailOpen Get = (%v, %v, %v), want (nil, false, nil)", val, ok, err)
	}
	if jres, err := failOpenCli.CQJoin(ctx, "room1", "t2", "c2", time.Minute, 0); err != nil || !jres.Degraded {
		t.Fatalf("FailOpen CQJoin = (%+v, %v), want Degraded=true nil err", jres, err)
	}
	if failOpenCli.FailOpenErrors() < 2 {
		t.Fatalf("FailOpenErrors = %d, want >= 2", failOpenCli.FailOpenErrors())
	}
}

func TestServer_MaxConnsBound(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	srv, err := kv.NewServer(kv.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		MaxConns:   2,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	// Open 2 connections and confirm each completed PING so both slots are held.
	held := make([]net.Conn, 0, 2)
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for i := range 2 {
		c, err := net.DialTimeout("tcp", srv.TCPAddr(), time.Second)
		if err != nil {
			t.Fatalf("dial held[%d]: %v", i, err)
		}
		held = append(held, c)
		bw := bufio.NewWriter(c)
		if err := kv.WriteCommand(bw, "PING"); err != nil {
			t.Fatalf("write PING: %v", err)
		}
		if err := bw.Flush(); err != nil {
			t.Fatalf("flush PING: %v", err)
		}
		reply, err := kv.ReadValue(bufio.NewReader(c), kv.ProtocolLimits{})
		if err != nil || reply.Str != "PONG" {
			t.Fatalf("held[%d] PING = (%+v, %v)", i, reply, err)
		}
	}

	// 3rd connection must be rejected immediately without blocking.
	extra, err := net.DialTimeout("tcp", srv.TCPAddr(), time.Second)
	if err != nil {
		t.Fatalf("dial extra: %v", err)
	}
	defer func() { _ = extra.Close() }()
	_ = extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply, err := kv.ReadValue(bufio.NewReader(extra), kv.ProtocolLimits{})
	if err != nil {
		t.Fatalf("read rejection reply: %v", err)
	}
	if reply.Kind != kv.KindError || !strings.Contains(reply.Str, "max number of clients") {
		t.Fatalf("extra reply = %+v, want max clients error", reply)
	}
	if srv.RejectedConns() < 1 {
		t.Fatalf("RejectedConns = %d, want >= 1", srv.RejectedConns())
	}
}

func TestReplication_SnapshotLiveStreamAndReconnect(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	pass := kv.NewSecret(testPassword(t))
	primaryStore := kv.NewStore(kv.StoreConfig{})
	// Pre-populate state before replica connects so full SNAPSHOT sync is tested.
	if _, err := primaryStore.Set("seed", []byte("initial"), kv.SetOptions{}); err != nil {
		t.Fatalf("primary seed Set: %v", err)
	}

	sockPath := shortSocketPath(t, "p.sock")
	primarySrv, err := kv.NewServer(kv.ServerConfig{
		UnixPath:       sockPath,
		Password:       pass,
		Store:          primaryStore,
		HeartbeatEvery: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewServer primary: %v", err)
	}
	if err := primarySrv.Start(ctx); err != nil {
		t.Fatalf("primary Start: %v", err)
	}

	applied := make(chan uint64, 32)
	replicaStore := kv.NewStore(kv.StoreConfig{})
	rep, err := kv.NewReplicator(kv.ReplicaConfig{
		PrimaryAddr:    "unix://" + sockPath,
		Password:       pass,
		Store:          replicaStore,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
		OnApply: func(seq uint64) {
			select {
			case applied <- seq:
			default:
			}
		},
	})
	if err != nil {
		_ = primarySrv.Close()
		t.Fatalf("NewReplicator: %v", err)
	}
	rep.Start(ctx)
	t.Cleanup(func() {
		rep.Close()
		_ = primarySrv.Close()
	})

	// Wait for initial snapshot application.
	select {
	case <-applied:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for initial replica snapshot")
	}
	if v, ok := replicaStore.Get("seed"); !ok || string(v) != "initial" {
		t.Fatalf("replica seed = (%q, %v), want ('initial', true)", v, ok)
	}

	// Write live mutations through primary server and observe them on replica.
	cli, err := kv.NewClient(kv.ClientConfig{Addr: "unix://" + sockPath, Password: pass})
	if err != nil {
		t.Fatalf("NewClient primary: %v", err)
	}
	defer func() { _ = cli.Close() }()

	if _, err := cli.Set(ctx, "live-key", []byte("live-val"), kv.SetOptions{}); err != nil {
		t.Fatalf("primary live Set: %v", err)
	}
	if _, err := cli.CQJoin(ctx, "q-repl", "t-1", "client-x", time.Minute, 77); err != nil {
		t.Fatalf("primary live CQJoin: %v", err)
	}

	waitForKey := func(k, want string) {
		t.Helper()
		for {
			if v, ok := replicaStore.Get(k); ok && string(v) == want {
				return
			}
			select {
			case <-applied:
			case <-ctx.Done():
				t.Fatalf("timed out waiting for replicated key %q=%q (status=%+v)", k, want, rep.Status())
			}
		}
	}
	waitForKey("live-key", "live-val")

	for {
		pr, err := replicaStore.CQPoll("q-repl", "t-1", 0)
		if err == nil && pr.Status == "waiting" && pr.Bid == 77 {
			break
		}
		select {
		case <-applied:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for replicated CQ.JOIN")
		}
	}

	// Simulate primary restart at the same Unix socket path and verify backoff reconnect.
	_ = cli.Close()
	if err := primarySrv.Close(); err != nil {
		t.Fatalf("primarySrv.Close: %v", err)
	}

	primaryStore2 := kv.NewStore(kv.StoreConfig{})
	if _, err := primaryStore2.Set("post-restart", []byte("ok"), kv.SetOptions{}); err != nil {
		t.Fatalf("primaryStore2 Set: %v", err)
	}
	primarySrv2, err := kv.NewServer(kv.ServerConfig{
		UnixPath:       sockPath,
		Password:       pass,
		Store:          primaryStore2,
		HeartbeatEvery: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewServer primary2: %v", err)
	}
	if err := primarySrv2.Start(ctx); err != nil {
		t.Fatalf("primary2 Start: %v", err)
	}
	t.Cleanup(func() { _ = primarySrv2.Close() })

	waitForKey("post-restart", "ok")
	if st := rep.Status(); st.Reconnects < 1 || st.FullSyncs < 2 {
		t.Fatalf("expected reconnect + resync, got status %+v", st)
	}
}

func ExampleStore_CQJoin() {
	st := kv.NewStore(kv.StoreConfig{})
	res, err := st.CQJoin("drop-1", "tkt-1", "203.0.113.10", time.Minute, 50)
	if err != nil {
		panic(err)
	}
	fmt.Println(res.Position, res.Depth)
	// Output:
	// 1 1
}

func ExampleSecret() {
	s := kv.NewSecret("ephemeral-example-only")
	fmt.Println(s)
	// Output:
	// [REDACTED]
}
