//go:build enterprise

package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/mailer"
)

func TestMultiEdge_DemandWeightedShares(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()

	secret := []byte("concert-hop-multiedge-secret-0123456789")

	leafCfg := testConfig(origin.URL)
	leafCfg.role = roleLeaf
	leafCfg.nodeID = "leaf-1"
	leafCfg.hostCap = 20
	leafCfg.hopSecret = secret
	leafCfg.hopPeers = "127.0.0.1/32,::1/128"
	leafCfg.abuseEnabled = false
	leafApp, leafSrv := newTestApp(t, leafCfg, nil)

	edgeHotCfg := testConfig(leafSrv.URL)
	edgeHotCfg.role = roleEdge
	edgeHotCfg.nodeID = "edge-hot"
	edgeHotCfg.capacity = 20
	edgeHotCfg.priorityCap = 2
	edgeHotCfg.hopSecret = secret
	edgeHotCfg.hopAutoCap = true
	edgeHotCfg.abuseEnabled = false
	edgeHot, _ := newTestApp(t, edgeHotCfg, nil)

	edgeCoolCfg := testConfig(leafSrv.URL)
	edgeCoolCfg.role = roleEdge
	edgeCoolCfg.nodeID = "edge-cool"
	edgeCoolCfg.capacity = 20
	edgeCoolCfg.priorityCap = 2
	edgeCoolCfg.hopSecret = secret
	edgeCoolCfg.hopAutoCap = true
	edgeCoolCfg.abuseEnabled = false
	edgeCool, _ := newTestApp(t, edgeCoolCfg, nil)

	// Simulate active traffic on edge-hot while edge-cool stays idle.
	now := time.Now()
	for i := 0; i < 40; i++ {
		leafApp.topo.leaf.sawEdgeTraffic("edge-hot", now)
	}
	leafApp.topo.leaf.sawEdgePoll("edge-hot", 18, now)
	leafApp.topo.leaf.sawEdgePoll("edge-cool", 0, now)

	// Both edges poll the leaf through the real signed control plane.
	planHot := edgeHot.edgeRound(context.Background())
	planCool := edgeCool.edgeRound(context.Background())

	if planHot.Total <= planCool.Total {
		t.Fatalf("expected busy edge-hot share (%d) > idle edge-cool share (%d)", planHot.Total, planCool.Total)
	}
	if planCool.Total < 2 {
		t.Fatalf("expected idle edge-cool to keep starvation floor >= 2, got %d", planCool.Total)
	}
	if sum := planHot.Total + planCool.Total; sum != 20 {
		t.Fatalf("expected weighted shares to sum to hostCap=20, got %d (%d + %d)", sum, planHot.Total, planCool.Total)
	}

	// Expire edge-hot (>1m ago) and confirm edge-cool automatically reclaims full 20 slots.
	leafApp.topo.leaf.edgesMu.Lock()
	leafApp.topo.leaf.edges["edge-hot"].lastSeen = time.Now().Add(-2 * time.Minute)
	leafApp.topo.leaf.edgesMu.Unlock()

	planReclaimed := edgeCool.edgeRound(context.Background())
	if planReclaimed.Total != 20 {
		t.Fatalf("expected surviving edge-cool to reclaim all 20 slots, got %d", planReclaimed.Total)
	}
}

// startMockRedisSetNX starts a minimal RESP2 server supporting SET k v NX PX ms
// and basic AUTH/HGETALL/SUBSCRIBE so clusterSync's email dedupe can be tested.
func startMockRedisSetNX(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	keys := map[string]time.Time{}
	conns := map[net.Conn]struct{}{}
	var wg sync.WaitGroup

	readArg := func(r *bufio.Reader) (string, error) {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(hdr, "$") {
			return "", fmt.Errorf("bad bulk len %q", hdr)
		}
		n, err := strconv.Atoi(strings.TrimSpace(hdr[1:]))
		if err != nil {
			return "", err
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns[conn] = struct{}{}
			mu.Unlock()
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer func() {
					mu.Lock()
					delete(conns, c)
					mu.Unlock()
					_ = c.Close()
				}()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if !strings.HasPrefix(line, "*") {
						return
					}
					argc, err := strconv.Atoi(strings.TrimSpace(line[1:]))
					if err != nil || argc < 1 {
						return
					}
					args := make([]string, argc)
					for i := 0; i < argc; i++ {
						args[i], err = readArg(r)
						if err != nil {
							return
						}
					}
					cmd := strings.ToUpper(args[0])
					switch cmd {
					case "SET":
						key := args[1]
						now := time.Now()
						mu.Lock()
						exp, exists := keys[key]
						if exists && now.Before(exp) {
							mu.Unlock()
							_, _ = io.WriteString(c, "$-1\r\n")
						} else {
							keys[key] = now.Add(time.Hour)
							mu.Unlock()
							_, _ = io.WriteString(c, "+OK\r\n")
						}
					case "HGETALL":
						_, _ = io.WriteString(c, "*0\r\n")
					case "SUBSCRIBE":
						_, _ = io.WriteString(c, "*3\r\n$9\r\nsubscribe\r\n$1\r\nx\r\n:1\r\n")
						// Keep open until closed.
						for {
							if _, err := r.ReadByte(); err != nil {
								return
							}
						}
					default:
						_, _ = io.WriteString(c, "+OK\r\n")
					}
				}
			}(conn)
		}
	}()

	var closeOnce sync.Once
	stop := func() {
		closeOnce.Do(func() {
			_ = ln.Close()
			mu.Lock()
			for c := range conns {
				_ = c.Close()
			}
			mu.Unlock()
			wg.Wait()
		})
	}
	t.Cleanup(stop)
	return ln.Addr().String(), stop
}

func TestClusterEmailDedupe_RedisAndFailOpen(t *testing.T) {
	redisAddr, stopRedis := startMockRedisSetNX(t)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	makeNode := func(id string) *app {
		cfg := testConfig(origin.URL)
		cfg.nodeID = id
		cfg.redisAddr = redisAddr
		cfg.email.provider = mailer.ProviderResend
		cfg.email.fromAddr = "alerts@example.com"
		cfg.email.toAddrs = "ops@example.com"
		cfg.email.resendAPIKey = "re_test_key"
		cfg.email.clusterDedupe = true
		cfg.abuseEnabled = false
		a, _ := newTestApp(t, cfg, nil)
		return a
	}

	nodeA := makeNode("edge-a")
	nodeB := makeNode("edge-b")

	shared := mailer.Event{
		Category:    mailer.CatCapacity,
		Severity:    mailer.SevWarn,
		Title:       "Leaf node unreachable",
		Summary:     "Leaf down",
		Fingerprint: "leaf-down:https://leaf-1:8443",
	}

	// Node A claims the shared fingerprint first.
	nodeA.notifyEvent(shared)
	deadline := time.Now().Add(2 * time.Second)
	for nodeA.mailer.Status().QueuedTotal == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := nodeA.mailer.Status().QueuedTotal; got != 1 {
		t.Fatalf("nodeA queued = %d, want 1", got)
	}

	// Node B reports the same shared fingerprint -> deduplicated via Redis.
	nodeB.notifyEvent(shared)
	deadline = time.Now().Add(2 * time.Second)
	for nodeB.stats.emailClusterDeduped.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := nodeB.stats.emailClusterDeduped.Load(); got != 1 {
		t.Fatalf("nodeB emailClusterDeduped = %d, want 1", got)
	}
	if got := nodeB.mailer.Status().QueuedTotal; got != 0 {
		t.Fatalf("nodeB queued = %d after dedupe, want 0", got)
	}

	// Node-local event (silence:<node>) is never suppressed across peers.
	nodeB.notifyEvent(mailer.Event{
		Category:    mailer.CatSilence,
		Severity:    mailer.SevCritical,
		Title:       "Local silence",
		Summary:     "Local app silent",
		Fingerprint: "silence:edge-b",
	})
	if got := nodeB.mailer.Status().QueuedTotal; got != 1 {
		t.Fatalf("nodeB local silence event queued = %d, want 1", got)
	}

	// Kill Redis -> fail-open delivers a new shared event locally instead of dropping it.
	stopRedis()
	nodeB.notifyEvent(mailer.Event{
		Category:    mailer.CatCapacity,
		Severity:    mailer.SevWarn,
		Title:       "Leaf 2 unreachable",
		Summary:     "Leaf 2 down while Redis unavailable",
		Fingerprint: "leaf-down:https://leaf-2:8443",
	})
	deadline = time.Now().Add(3 * time.Second)
	for nodeB.mailer.Status().QueuedTotal < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := nodeB.mailer.Status().QueuedTotal; got < 2 {
		t.Fatalf("nodeB fail-open queued = %d, want >= 2", got)
	}
}
