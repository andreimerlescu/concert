//go:build enterprise

package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestLeafHop_StaticOffload(t *testing.T) {
	var originHits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("page-from-origin"))
	}))
	defer origin.Close()

	root := t.TempDir()
	writeDiskFile(t, filepath.Join(root, "static", "app.js"), []byte("console.log('leaf-disk');"))
	secret := []byte("concert-leaf-static-offload-secret-0123456789")

	leafCfg := testConfig(origin.URL)
	leafCfg.role = roleLeaf
	leafCfg.nodeID = "leaf-static"
	leafCfg.hostCap = 10
	leafCfg.hopSecret = secret
	leafCfg.hopPeers = "127.0.0.1/32,::1/128"
	leafCfg.staticRoot = root
	leafCfg.assets = "/static/*"
	_, leafSrv := newTestApp(t, leafCfg, nil)

	edgeCfg := testConfig(leafSrv.URL)
	edgeCfg.role = roleEdge
	edgeCfg.nodeID = "edge-static"
	edgeCfg.hopSecret = secret
	edgeCfg.hopPoll = 500 * time.Millisecond
	edgeCfg.assets = "/static/*"
	_, edgeSrv := newTestApp(t, edgeCfg, nil)

	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := testClient.Get(edgeSrv.URL + "/_room/readyz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("edge never became ready")
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Hit a page through edge -> hits origin once and gets concert_admit cookie.
	resp, err := testClient.Get(edgeSrv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var admitCk *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == admitCookie {
			admitCk = c
		}
	}
	if admitCk == nil {
		t.Fatal("edge did not issue admit cookie")
	}

	// Hit asset through edge -> leaf serves straight off disk with ZERO origin hits!
	req, _ := http.NewRequest(http.MethodGet, edgeSrv.URL+"/static/app.js", nil)
	req.AddCookie(admitCk)
	resp, err = testClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "console.log('leaf-disk');" {
		t.Fatalf("leaf static asset: status=%d body=%q", resp.StatusCode, string(body))
	}
	if originHits.Load() != 1 {
		t.Fatalf("leaf static offload leaked to origin: hits=%d, want 1", originHits.Load())
	}
}
