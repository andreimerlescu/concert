//go:build enterprise

package server

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/testsite"
)

// Asset delivery for every file type an electronic-commerce site serves,
// through each way Concert can be deployed. Each file must arrive byte for
// byte with its type and length, honour HEAD, byte ranges (seeking in audio
// and video, resuming downloads), conditional requests and precompressed
// encodings, exactly as the origin serves it.

// shopPaths routes the fake shop's files the way an operator would.
func shopPaths(c *config) {
	c.assets = "/static/*,/media/*,/downloads/*"
	c.assetPublic = "/files/*,/api/*"
	c.bypass = "/feed.xml,/manifest.webmanifest"
}

type deployment struct {
	name  string
	front string // where the browser connects
}

// deployments starts the shop behind standalone Concert, an edge with one
// leaf, and an edge balancing two leaves.
func deployments(t *testing.T, site http.Handler) []deployment {
	t.Helper()
	origin := httptest.NewServer(site)
	t.Cleanup(origin.Close)
	origin2 := httptest.NewServer(site)
	t.Cleanup(origin2.Close)

	cfg := testConfig(origin.URL)
	shopPaths(&cfg)
	_, standalone := newTestApp(t, cfg, nil)

	_, leaf := newLeaf(t, origin.URL, shopPaths)
	_, edge := newEdge(t, []string{leaf.URL}, shopPaths)

	_, leafA := newLeaf(t, origin.URL, shopPaths)
	_, leafB := newLeaf(t, origin2.URL, shopPaths)
	_, edge2 := newEdge(t, []string{leafA.URL, leafB.URL}, shopPaths)

	return []deployment{
		{"standalone", standalone.URL},
		{"edge-leaf", edge.URL},
		{"edge-2-leaves", edge2.URL},
	}
}

// rawClient keeps cookies and does not decompress, so tests see exactly
// what Concert sent.
func rawClient(t *testing.T) *http.Client {
	c := tierClient(t)
	c.Transport = &http.Transport{DisableCompression: true}
	return c
}

func admitted(t *testing.T, front string) *http.Client {
	t.Helper()
	c := rawClient(t)
	resp := getOK(t, c, front+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("home page %d", resp.StatusCode)
	}
	return c
}

func do(t *testing.T, c *http.Client, method, u string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, u, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: read: %v", method, u, err)
	}
	return resp, b
}

func TestAssets_EveryFileTypeEveryDeployment(t *testing.T) {
	site := testsite.New(testsite.Options{Pages: 8, MediaSize: 512 << 10})
	classes := map[string]bool{}
	for _, f := range site.Files {
		classes[f.Class] = true
	}
	for _, want := range []string{"style", "script", "font", "image", "audio", "video", "archive", "document", "text", "data"} {
		if !classes[want] {
			t.Fatalf("fixture lacks %s files", want)
		}
	}
	for _, d := range deployments(t, site) {
		d := d
		t.Run(d.name, func(t *testing.T) {
			c := admitted(t, d.front)
			for _, p := range site.FilePaths() {
				f := site.Files[p]
				u := d.front + p

				resp, body := do(t, c, http.MethodGet, u, nil)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("%s: GET %d", p, resp.StatusCode)
				}
				if sha256.Sum256(body) != f.SHA256 {
					t.Fatalf("%s (%s): body differs (%d bytes, want %d)", p, f.Class, len(body), len(f.Body))
				}
				if got := resp.Header.Get("Content-Type"); got != f.ContentType {
					t.Errorf("%s: Content-Type %q, want %q", p, got, f.ContentType)
				}
				if resp.ContentLength != int64(len(f.Body)) {
					t.Errorf("%s: Content-Length %d, want %d", p, resp.ContentLength, len(f.Body))
				}
				etag := resp.Header.Get("ETag")

				resp, body = do(t, c, http.MethodHead, u, nil)
				if resp.StatusCode != http.StatusOK || len(body) != 0 || resp.ContentLength != int64(len(f.Body)) {
					t.Errorf("%s: HEAD %d, %d body bytes, length %d", p, resp.StatusCode, len(body), resp.ContentLength)
				}

				if n := len(f.Body); n > 1200 {
					resp, body = do(t, c, http.MethodGet, u, map[string]string{"Range": "bytes=100-1123"})
					want := fmt.Sprintf("bytes 100-1123/%d", n)
					if resp.StatusCode != http.StatusPartialContent || resp.Header.Get("Content-Range") != want || !bytes.Equal(body, f.Body[100:1124]) {
						t.Errorf("%s: range %d %q, %d bytes", p, resp.StatusCode, resp.Header.Get("Content-Range"), len(body))
					}
					resp, body = do(t, c, http.MethodGet, u, map[string]string{"Range": "bytes=-500"})
					if resp.StatusCode != http.StatusPartialContent || !bytes.Equal(body, f.Body[n-500:]) {
						t.Errorf("%s: suffix range %d, %d bytes", p, resp.StatusCode, len(body))
					}
					resp, _ = do(t, c, http.MethodGet, u, map[string]string{"Range": fmt.Sprintf("bytes=%d-", n+10)})
					if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
						t.Errorf("%s: unsatisfiable range %d", p, resp.StatusCode)
					}
				}

				if etag != "" {
					resp, body = do(t, c, http.MethodGet, u, map[string]string{"If-None-Match": etag})
					if resp.StatusCode != http.StatusNotModified || len(body) != 0 {
						t.Errorf("%s: If-None-Match %d", p, resp.StatusCode)
					}
				}
				resp, _ = do(t, c, http.MethodGet, u, map[string]string{"If-Modified-Since": time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC).Format(http.TimeFormat)})
				if resp.StatusCode != http.StatusNotModified {
					t.Errorf("%s: If-Modified-Since %d", p, resp.StatusCode)
				}

				if f.Gzip != nil {
					resp, body = do(t, c, http.MethodGet, u, map[string]string{"Accept-Encoding": "gzip"})
					if resp.Header.Get("Content-Encoding") != "gzip" || !bytes.Equal(body, f.Gzip) {
						t.Fatalf("%s: gzip not passed through: %q, %d bytes", p, resp.Header.Get("Content-Encoding"), len(body))
					}
					zr, err := gzip.NewReader(bytes.NewReader(body))
					if err != nil {
						t.Fatal(err)
					}
					plain, _ := io.ReadAll(zr)
					if !bytes.Equal(plain, f.Body) {
						t.Fatalf("%s: gzip body does not decompress to the file", p)
					}
				}
			}
		})
	}
}

// Without an admission pass, private assets are refused at the front door in
// every deployment, while public and bypass files still load.
func TestAssets_PassRequiredAtTheFront(t *testing.T) {
	site := testsite.New(testsite.Options{Pages: 2, MediaSize: 4 << 10})
	for _, d := range deployments(t, site) {
		c := rawClient(t)
		for p, want := range map[string]int{
			"/static/css/site.css":   http.StatusForbidden,
			"/media/video/demo.mp4":  http.StatusForbidden,
			"/downloads/catalog.zip": http.StatusForbidden,
			"/files/readme.txt":      http.StatusOK,
			"/api/products.json":     http.StatusOK,
			"/feed.xml":              http.StatusOK,
			"/manifest.webmanifest":  http.StatusOK,
		} {
			if resp, _ := do(t, c, http.MethodGet, d.front+p, nil); resp.StatusCode != want {
				t.Errorf("%s %s: %d, want %d", d.name, p, resp.StatusCode, want)
			}
		}
	}
}

// A page loads its assets in parallel, as a browser does, through every
// deployment, without a refusal.
func TestAssets_ParallelLoad(t *testing.T) {
	site := testsite.New(testsite.Options{Pages: 2, MediaSize: 64 << 10})
	for _, d := range deployments(t, site) {
		c := admitted(t, d.front)
		var wg sync.WaitGroup
		errs := make(chan string, len(site.Files))
		for _, p := range site.FilePaths() {
			p := p
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := c.Get(d.front + p)
				if err != nil {
					errs <- err.Error()
					return
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK || sha256.Sum256(b) != site.Files[p].SHA256 {
					errs <- fmt.Sprintf("%s: %d", p, resp.StatusCode)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Errorf("%s: %s", d.name, e)
		}
	}
}

// Large media streams through every tier as it is produced: the first bytes
// reach the browser while the origin is still writing, and the whole file
// arrives intact. Nothing buffers the response.
func TestAssets_LargeMediaStreams(t *testing.T) {
	const chunk = 256 << 10
	const chunks = 32 // 8 MiB
	release := make(chan struct{})
	var once sync.Once
	body := bytes.Repeat([]byte("v"), chunk*chunks)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/media/video/live.mp4" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<html></html>")
			return
		}
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body[:chunk])
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
		_, _ = w.Write(body[chunk:])
	})
	for _, d := range deployments(t, h) {
		release = make(chan struct{})
		once = sync.Once{}
		c := admitted(t, d.front)
		resp, err := c.Get(d.front + "/media/video/live.mp4")
		if err != nil {
			t.Fatal(err)
		}
		first := make([]byte, chunk)
		start := time.Now()
		if _, err := io.ReadFull(resp.Body, first); err != nil {
			t.Fatalf("%s: first chunk: %v", d.name, err)
		}
		if time.Since(start) > 3*time.Second {
			t.Fatalf("%s: first chunk took %s; the response was buffered", d.name, time.Since(start))
		}
		once.Do(func() { close(release) })
		rest, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || len(first)+len(rest) != len(body) {
			t.Fatalf("%s: got %d bytes, %v", d.name, len(first)+len(rest), err)
		}
		if !strings.HasPrefix(resp.Header.Get("Content-Type"), "video/mp4") {
			t.Fatalf("%s: Content-Type %q", d.name, resp.Header.Get("Content-Type"))
		}
	}
}
