package bench

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A redirect off the target host is not followed. Before, the lemming's
// client followed it, parsed the other site's page against that site's own
// host, and crawled and loaded it at full benchmark concurrency, sending
// every -header (such as an Authorization the operator set for the target)
// with each request. The off-site redirect is reported as a finding, not a
// failure, and the run still measures the target.
func TestRun_OffHostRedirectNotFollowed(t *testing.T) {
	var other atomic.Int64
	var leaked atomic.Int64
	third := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		other.Add(1)
		if r.Header.Get("X-Bench-Key") != "" {
			leaked.Add(1)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<a href="/a">a</a><a href="/b">b</a><img src="/big.jpg">`)
	}))
	t.Cleanup(third.Close)

	u := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<a href="/login">login</a><a href="/same">same</a>`)
		case "/login":
			http.Redirect(w, r, third.URL+"/oauth", http.StatusFound)
		case "/same":
			http.Redirect(w, r, "/", http.StatusFound) // same host: followed
		default:
			http.NotFound(w, r)
		}
	}))
	o := quick(u)
	o.Start, o.Max = 2, 2
	o.Header = http.Header{"X-Bench-Key": {"secret"}}
	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := other.Load(); n != 0 {
		t.Fatalf("the third-party host got %d requests (%d with the operator's header)", n, leaked.Load())
	}
	st := rep.Stages[0]
	if st.Findings[FindOffsite] == 0 {
		t.Fatalf("off-site redirect not reported: findings %v", st.Findings)
	}
	if st.Failed != 0 {
		t.Fatalf("an off-site redirect failed the stage: %v", st.Failures)
	}
}
