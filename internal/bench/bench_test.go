package bench

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/capacity"
	"github.com/andreimerlescu/concert/internal/testsite"
)

func serve(t *testing.T, h http.Handler) *url.URL {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/")
	return u
}

func quick(u *url.URL) Options {
	return Options{
		Target:         u,
		StageDuration:  400 * time.Millisecond,
		P95Limit:       time.Second,
		RequestTimeout: 2 * time.Second,
		Start:          1,
		Max:            32,
		Assets:         true,
		AssetsPerPage:  4,
		RangeChecks:    true,
		Seed:           1,
		// Longer than the slowest test page, so a stage never starts
		// while the server still serves the last one's cancelled pages.
		Cooldown: 150 * time.Millisecond,
	}
}

// A site that refuses its 7th concurrent page is measured at exactly 6,
// with the refusals named as the reason.
func TestRun_FindsConcurrencyLimit(t *testing.T) {
	site := testsite.New(testsite.Options{PageLimit: 6, PageDelay: 30 * time.Millisecond})
	rep, err := Run(context.Background(), quick(serve(t, site)))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Lemmings != 6 {
		t.Fatalf("measured %d lemmings, want 6; stages %+v", rep.Lemmings, stageSummary(rep))
	}
	if rep.HostCap != 5 {
		t.Fatalf("host cap %d, want floor(6 × 0.9) = 5", rep.HostCap)
	}
	f := rep.FirstFailure
	if f == nil || f.Lemmings != 7 || f.Failures["status_503"] == 0 {
		t.Fatalf("first failure %+v", f)
	}
	if len(f.FailingURLs) == 0 || !strings.Contains(f.Reason, "status_503") {
		t.Fatalf("failure not explained: %q %+v", f.Reason, f.FailingURLs)
	}
	most := 0
	for _, s := range rep.Stages {
		most = max(most, s.Lemmings)
	}
	if site.Peak() > int64(most) {
		t.Fatalf("site saw %d pages at once with at most %d lemmings; each must hold at most one page", site.Peak(), most)
	}
	if !strings.Contains(rep.Verdict, "6 lemmings") {
		t.Fatalf("verdict %q", rep.Verdict)
	}
}

func stageSummary(r *Report) []string {
	var out []string
	for _, s := range r.Stages {
		out = append(out, fmt.Sprintf("%d %v %s", s.Lemmings, s.Pass, s.Reason))
	}
	return out
}

// A site slower than the limit at one lemming has no capacity.
func TestRun_LatencyLimit(t *testing.T) {
	site := testsite.New(testsite.Options{PageDelay: 60 * time.Millisecond})
	o := quick(serve(t, site))
	o.P95Limit = 20 * time.Millisecond
	o.Start, o.Max = 2, 8
	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Lemmings != 0 || rep.HostCap != 0 {
		t.Fatalf("lemmings %d host cap %d, want 0", rep.Lemmings, rep.HostCap)
	}
	if !strings.Contains(rep.Verdict, "even 1 lemming") || !strings.Contains(rep.Verdict, "p95") {
		t.Fatalf("verdict %q", rep.Verdict)
	}
}

// countingTransport records every host requested.
type countingTransport struct {
	base  http.RoundTripper
	mu    sync.Mutex
	hosts map[string]int
	paths map[string]int
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.hosts[r.URL.Host]++
	c.paths[r.URL.Path]++
	c.mu.Unlock()
	return c.base.RoundTrip(r)
}

// The crawl walks the whole site and every kind of file a shop serves,
// stays on the target host, checks media byte ranges, and reports broken
// links as findings, not failures.
func TestRun_CoverageAndFileTypes(t *testing.T) {
	site := testsite.New(testsite.Options{Pages: 30, Fanout: 4})
	u := serve(t, site)
	o := quick(u)
	o.Start, o.Max = 4, 4
	o.StageDuration = 1500 * time.Millisecond
	o.PageHits = 2
	o.AssetsPerPage = 64
	base := newTransport(&o)
	t.Cleanup(base.CloseIdleConnections)
	ct := &countingTransport{base: base, hosts: map[string]int{}, paths: map[string]int{}}
	o.Transport = ct
	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Ceiling || rep.Lemmings != 4 {
		t.Fatalf("lemmings %d ceiling %v: %v", rep.Lemmings, rep.Ceiling, stageSummary(rep))
	}
	st := rep.Stages[0]
	if st.Failed != 0 {
		t.Fatalf("failures on a healthy site: %v %+v", st.Failures, st.FailingURLs)
	}
	if st.Coverage.Discovered < 31 || st.Coverage.Visited < 31 {
		t.Fatalf("coverage %+v, want all 31 pages", st.Coverage)
	}
	if st.Coverage.MaxDepth < 2 || st.Coverage.MaxDepth > 14 {
		t.Fatalf("max depth %d", st.Coverage.MaxDepth)
	}
	for _, class := range []string{ClassHTML, ClassStyle, ClassScript, ClassFont, ClassImage, ClassAudio, ClassVideo, ClassArchive, ClassDocument, ClassText, ClassData} {
		cs := st.ByClass[class]
		if cs == nil || cs.Requests == 0 || cs.Bytes == 0 {
			t.Errorf("class %s not exercised: %+v", class, cs)
		}
	}
	for _, class := range []string{ClassAudio, ClassVideo} {
		cs := st.ByClass[class]
		if cs == nil || cs.RangeChecked == 0 || cs.RangeOK != cs.RangeChecked {
			t.Errorf("%s ranges %+v", class, cs)
		}
	}
	if st.Findings[FindNotFound] == 0 {
		t.Error("the broken link was not reported")
	}
	for _, p := range []string{"/static/fonts/shop.woff2", "/static/css/print.css", "/static/img/bg.webp", "/media/video/demo.vtt", "/static/img/hero.avif"} {
		if ct.paths[p] == 0 {
			t.Errorf("%s (referenced from CSS, srcset, track or style) never fetched", p)
		}
	}
	for h := range ct.hosts {
		if h != u.Host {
			t.Errorf("left the target host for %s", h)
		}
	}
	if len(st.Timeline) == 0 || st.Timeline[0].Requests == 0 {
		t.Error("no timeline")
	}
}

// Each kind of failure is named.
func TestRun_FailureKinds(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/slow">s</a><a href="/short">t</a><a href="/boom">b</a><a href="/teapot">x</a>`))
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	})
	mux.HandleFunc("/short", func(w http.ResponseWriter, r *http.Request) {
		hj := w.(http.Hijacker)
		conn, buf, _ := hj.Hijack()
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\nshort")
		_ = buf.Flush()
		conn.Close()
	})
	mux.HandleFunc("/boom", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	mux.HandleFunc("/teapot", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	o := quick(serve(t, mux))
	o.Start, o.Max = 2, 2
	o.StageDuration = 900 * time.Millisecond
	o.RequestTimeout = 150 * time.Millisecond
	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	st := rep.Stages[0]
	for _, k := range []string{FailTimeout, FailTruncated, "status_500"} {
		if st.Failures[k] == 0 {
			t.Errorf("no %s failure: %v", k, st.Failures)
		}
	}
	if st.Findings[FindClientErr] == 0 {
		t.Errorf("403 not a finding: %v", st.Findings)
	}
	if st.Failures[FindClientErr] != 0 {
		t.Error("a 403 failed the stage")
	}
	if st.Pass {
		t.Fatal("stage with failures passed")
	}
}

func TestFailKind(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{context.DeadlineExceeded, FailTimeout},
		{&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, FailRefused},
		{&net.OpError{Op: "read", Err: syscall.ECONNRESET}, FailReset},
		{&net.DNSError{Err: "no such host", Name: "x"}, FailDNS},
		{errors.New("tls: handshake failure"), FailTLS},
		{errors.New("something"), FailConnOther},
	}
	for _, tc := range cases {
		if got := failKind(tc.err); got != tc.want {
			t.Errorf("%v: %s, want %s", tc.err, got, tc.want)
		}
	}
	for code, want := range map[int][2]string{
		200: {"", ""}, 404: {"", FindNotFound}, 410: {"", FindNotFound}, 403: {"", FindClientErr},
		429: {FailThrottled, ""}, 500: {"status_500", ""}, 503: {"status_503", ""},
	} {
		f, fd := statusKind(code)
		if f != want[0] || fd != want[1] {
			t.Errorf("%d: %q %q", code, f, fd)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := map[[2]string]string{
		{"text/html; charset=utf-8", "/"}:              ClassHTML,
		{"image/avif", "/x"}:                           ClassImage,
		{"text/css", "/x"}:                             ClassStyle,
		{"application/javascript", "/x"}:               ClassScript,
		{"font/woff2", "/x"}:                           ClassFont,
		{"audio/mpeg", "/x"}:                           ClassAudio,
		{"video/webm", "/x"}:                           ClassVideo,
		{"application/vnd.apple.mpegurl", "/x"}:        ClassVideo,
		{"application/zip", "/x"}:                      ClassArchive,
		{"application/pdf", "/x"}:                      ClassDocument,
		{"application/manifest+json", "/x"}:            ClassData,
		{"text/csv", "/x"}:                             ClassText,
		{"application/octet-stream", "/a/b.woff2?v=3"}: ClassFont,
		{"", "/downloads/x.TAR"}:                       ClassArchive,
		{"application/octet-stream", "/unknown"}:       ClassOther,
	}
	for in, want := range cases {
		if got := classify(in[0], in[1]); got != want {
			t.Errorf("%v: %s, want %s", in, got, want)
		}
	}
}

func TestExtractHTML(t *testing.T) {
	base, _ := url.Parse("https://shop.example/dir/page")
	doc := `<html><head><base href="https://shop.example/root/"><link rel="stylesheet" href="a.css">
<link rel="canonical" href="/canon"><link rel="preload" href="/f.woff2"><style>.x{background:url('bg.png')}</style></head>
<body style="background:url(/b.webp)"><a href="p1">1</a><a href="/p2#frag">2</a><a href="#top">t</a><a href="mailto:x@y">m</a>
<a href="https://other.example/">o</a><a href="//shop.example/p3">3</a><a href="/doc.pdf">pdf</a>
<img srcset="i1.jpg 1x, /i2.jpg 2x"><video poster="v.jpg"><source src="v.mp4"></video><script src="s.js"></script>
<a href="javascript:void(0)">j</a><img src="data:image/png;base64,AA=="></body></html>`
	got := extractHTML(strings.NewReader(doc), base, 1<<20)
	pages, assets := map[string]bool{}, map[string]bool{}
	for _, f := range got {
		if f.kind == KindPage {
			pages[f.url] = true
		} else {
			assets[f.url] = true
		}
	}
	wantPages := []string{"https://shop.example/root/p1", "https://shop.example/p2", "https://shop.example/p3"}
	wantAssets := []string{"https://shop.example/root/a.css", "https://shop.example/f.woff2", "https://shop.example/root/bg.png",
		"https://shop.example/b.webp", "https://shop.example/doc.pdf", "https://shop.example/root/i1.jpg", "https://shop.example/i2.jpg",
		"https://shop.example/root/v.jpg", "https://shop.example/root/v.mp4", "https://shop.example/root/s.js"}
	for _, p := range wantPages {
		if !pages[p] {
			t.Errorf("page %s missing (pages %v)", p, pages)
		}
	}
	for _, a := range wantAssets {
		if !assets[a] {
			t.Errorf("asset %s missing (assets %v)", a, assets)
		}
	}
	if len(pages) != len(wantPages) {
		t.Errorf("extra pages: %v", pages)
	}
	if assets["https://shop.example/canon"] || pages["https://shop.example/canon"] {
		t.Error("rel=canonical fetched")
	}
}

func TestOptionsValidation(t *testing.T) {
	u, _ := url.Parse("http://x/")
	bad := []Options{
		{},
		{Target: &url.URL{Scheme: "ftp", Host: "x"}},
		{Target: u, Start: 5, Max: 2},
		{Target: u, Growth: 1},
		{Target: u, Safety: 1.5},
		{Target: u, MaxFailRate: 1},
	}
	for i, o := range bad {
		if err := o.withDefaults(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

// The command line writes the report and the capacity file a leaf reads.
func TestCLI(t *testing.T) {
	site := testsite.New(testsite.Options{PageLimit: 3, PageDelay: 25 * time.Millisecond})
	u := serve(t, site)
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(reportPath, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	err := CLI([]string{"-target", u.String(), "-stage", "300ms", "-cooldown", "150ms", "-max", "8",
		"-out", reportPath, "-data-dir", dir, "-header", "X-Bench: 1", "-quiet"}, &out, &errOut)
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut.String())
	}
	f, err := capacity.Load(capacity.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if f.Lemmings != 3 || f.HostCap != 2 || f.Report == "" {
		t.Fatalf("capacity file %+v", f)
	}
	fi, err := os.Stat(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("report.json mode %v, want 0600 after atomic replace", fi.Mode().Perm())
	}
	s := out.String()
	for _, want := range []string{"verdict:", "by file type", "at 4 lemmings it failed"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q:\n%s", want, s)
		}
	}
	if err := CLI([]string{}, &out, &errOut); err == nil {
		t.Error("missing -target accepted")
	}
	if err := CLI([]string{"-target", "x", "-header", "nocolon"}, &out, &errOut); err == nil {
		t.Error("bad header accepted")
	}
}

// A lemming reads large media without holding it in memory, and a truncated
// response is a failure even with a 200 status.
func TestFetchStreamsAndChecksLength(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 8<<20)
	mux := http.NewServeMux()
	mux.HandleFunc("/big.mp4", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		http.ServeContent(w, r, "big.mp4", time.Time{}, bytes.NewReader(big))
	})
	u := serve(t, mux)
	o := quick(u)
	if err := o.withDefaults(); err != nil {
		t.Fatal(err)
	}
	rec := newRecorder(time.Now())
	base := newTransport(&o)
	t.Cleanup(base.CloseIdleConnections)
	l := newLemming(0, &o, base, newSite(u.String(), 14), rec, 1)
	body, ct, _, ok := l.fetch(context.Background(), u.String()+"big.mp4", false)
	if !ok || ct != "video/mp4" || body != nil {
		t.Fatalf("ok %v ct %q kept %d bytes", ok, ct, len(body))
	}
	if rec.samples[0].bytes != int64(len(big)) {
		t.Fatalf("counted %d bytes", rec.samples[0].bytes)
	}
}
