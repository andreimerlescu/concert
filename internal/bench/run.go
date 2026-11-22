// Package bench is Concert's capacity benchmark: how many concurrent
// visitors ("lemmings") an application really serves before latency or
// errors say it has had enough.
//
// Each lemming is one browser session with its own cookie jar and asset
// cache. It starts at the root URL, loads the page and what the page loads
// (stylesheets, scripts, fonts, images, audio, video, downloads), picks a
// random link to a page that has not yet had -page-hits visits this stage,
// and follows it, up to -depth links deep; then it starts again from the
// root. A page every link of which is saturated sends the lemming to
// another open page, so the whole site is walked, not just the home page.
//
// A run holds each concurrency for one stage, doubling from -start until a
// stage fails, then bisects between the last passing and the first failing
// concurrency. A stage passes when the page p95 is within -p95 and no
// request failed for load: timeouts, refused or reset connections,
// truncated bodies, 5xx and 429 all fail it. Broken links (404) and media
// served without byte ranges are reported as findings but do not fail it,
// because they are properties of the site, not of its load.
//
// The result is the largest passing concurrency, and a host capacity for
// Concert of that times -safety. The report says what went wrong at the
// first failing concurrency, second by second, and which URLs were slowest
// and failed most.
package bench

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Options configure a run. Zero values take the defaults in Defaults.
type Options struct {
	Target         *url.URL      // the root URL to crawl
	MaxDepth       int           // links followed from the root before starting over
	PageHits       int           // visits per page per stage before lemmings skip it
	P95Limit       time.Duration // the page p95 a stage must stay within
	MaxFailRate    float64       // failed / requests a stage may have (0: none)
	StageDuration  time.Duration // how long each concurrency is held
	Cooldown       time.Duration // pause between stages so the target recovers
	Start          int           // first concurrency
	Max            int           // highest concurrency tried
	Growth         float64       // ramp factor while stages pass
	Precision      float64       // bisect until the gap is within this fraction of the result
	RequestTimeout time.Duration // a request taking longer has failed
	Assets         bool          // load what pages reference
	AssetsPerPage  int           // most new assets a lemming loads per page view
	RangeChecks    bool          // check byte-range support on audio and video
	Safety         float64       // host capacity = passing lemmings × Safety
	Header         http.Header   // extra request headers (e.g. a bypass token)
	Insecure       bool          // skip TLS verification (staging only)
	Seed           uint64        // link choices; 0 uses the time
	Logf           func(format string, args ...any)
	Transport      http.RoundTripper // tests; nil builds one
}

// Defaults are the documented defaults.
var Defaults = Options{
	MaxDepth:       14,
	PageHits:       14,
	P95Limit:       2 * time.Second,
	StageDuration:  15 * time.Second,
	Cooldown:       2 * time.Second,
	Start:          1,
	Max:            1024,
	Growth:         2,
	Precision:      0.05,
	RequestTimeout: 10 * time.Second,
	Assets:         true,
	AssetsPerPage:  8,
	RangeChecks:    true,
	Safety:         0.9,
}

func (o *Options) withDefaults() error {
	d := Defaults
	if o.Target == nil || (o.Target.Scheme != "http" && o.Target.Scheme != "https") || o.Target.Host == "" {
		return errors.New("bench: target must be an http(s) URL")
	}
	if o.MaxDepth == 0 {
		o.MaxDepth = d.MaxDepth
	}
	if o.PageHits == 0 {
		o.PageHits = d.PageHits
	}
	if o.P95Limit == 0 {
		o.P95Limit = d.P95Limit
	}
	if o.StageDuration == 0 {
		o.StageDuration = d.StageDuration
	}
	if o.Start == 0 {
		o.Start = d.Start
	}
	if o.Max == 0 {
		o.Max = d.Max
	}
	if o.Growth == 0 {
		o.Growth = d.Growth
	}
	if o.Precision == 0 {
		o.Precision = d.Precision
	}
	if o.RequestTimeout == 0 {
		o.RequestTimeout = d.RequestTimeout
	}
	if o.AssetsPerPage == 0 {
		o.AssetsPerPage = d.AssetsPerPage
	}
	if o.Safety == 0 {
		o.Safety = d.Safety
	}
	switch {
	case o.MaxDepth < 1 || o.PageHits < 1:
		return errors.New("bench: depth and page hits must be at least 1")
	case o.Start < 1 || o.Max < o.Start:
		return errors.New("bench: need 1 <= start <= max")
	case o.Growth <= 1:
		return errors.New("bench: growth must be above 1")
	case o.MaxFailRate < 0 || o.MaxFailRate >= 1:
		return errors.New("bench: max fail rate must be in [0, 1)")
	case o.Safety <= 0 || o.Safety > 1:
		return errors.New("bench: safety must be in (0, 1]")
	case o.P95Limit < time.Millisecond || o.StageDuration < 100*time.Millisecond:
		return errors.New("bench: p95 limit or stage duration too small")
	}
	if o.Seed == 0 {
		o.Seed = uint64(time.Now().UnixNano())
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return nil
}

// Report is a run's result.
type Report struct {
	Target   string    `json:"target"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	P95Limit string    `json:"p95_limit"`
	Depth    int       `json:"depth"`
	PageHits int       `json:"page_hits"`
	Safety   float64   `json:"safety"`

	// Lemmings is the largest concurrency that passed; 0 if none did.
	Lemmings int `json:"lemmings"`
	// HostCap is what Concert should allow at once: Lemmings × Safety.
	HostCap int `json:"host_cap"`
	// P95Ms is the page p95 at Lemmings.
	P95Ms float64 `json:"p95_ms"`
	// Verdict says in one sentence what was found.
	Verdict string `json:"verdict"`
	// Ceiling is true when the run passed at -max: the real capacity is
	// higher than measured.
	Ceiling bool `json:"ceiling"`

	Pages  int     `json:"pages_discovered"`
	Stages []Stage `json:"stages"`
	// FirstFailure is the failing stage closest above Lemmings: what went
	// wrong when the application had had enough.
	FirstFailure *Stage `json:"first_failure,omitempty"`
}

func newTransport(opts *Options) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          opts.Max * 2,
		MaxIdleConnsPerHost:   opts.Max * 2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: opts.RequestTimeout,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.Insecure},
	}
}

// Run measures opts.Target. It returns a report even when ctx ends early,
// with the stages completed so far.
func Run(ctx context.Context, opts Options) (*Report, error) {
	if err := opts.withDefaults(); err != nil {
		return nil, err
	}
	transport := opts.Transport
	if transport == nil {
		t := newTransport(&opts)
		defer t.CloseIdleConnections()
		transport = t
	}
	rep := &Report{
		Target:   opts.Target.String(),
		Started:  time.Now().UTC(),
		P95Limit: opts.P95Limit.String(),
		Depth:    opts.MaxDepth,
		PageHits: opts.PageHits,
		Safety:   opts.Safety,
	}
	s := newSite(opts.Target.String(), opts.PageHits)
	results := map[int]*Stage{}
	stage := func(n int) (*Stage, error) {
		if st, ok := results[n]; ok {
			return st, nil
		}
		if len(results) > 0 && opts.Cooldown > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(opts.Cooldown):
			}
		}
		st := runStage(ctx, &opts, transport, s, n)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		results[n] = &st
		rep.Stages = append(rep.Stages, st)
		verdict := "pass"
		if !st.Pass {
			verdict = "FAIL: " + st.Reason
		}
		opts.Logf("bench: %4d lemmings  %7.1f req/s  p95 %7.1fms  failed %d/%d  %s",
			n, st.RPS, st.PageP95Ms, st.Failed, st.Requests, verdict)
		return &st, nil
	}

	good, bad := 0, 0
	var err error
	for n := opts.Start; ; {
		var st *Stage
		if st, err = stage(n); err != nil {
			break
		}
		if !st.Pass {
			bad = n
			break
		}
		good = n
		if n >= opts.Max {
			rep.Ceiling = true
			break
		}
		next := int(math.Ceil(float64(n) * opts.Growth))
		if next <= n {
			next = n + 1
		}
		if next > opts.Max {
			next = opts.Max
		}
		n = next
	}
	for err == nil && bad > 0 && bad-good > 1 && float64(bad-good) > opts.Precision*float64(max(good, 1)) {
		mid := good + (bad-good)/2
		var st *Stage
		if st, err = stage(mid); err != nil {
			break
		}
		if st.Pass {
			good = mid
		} else {
			bad = mid
		}
	}

	rep.Finished = time.Now().UTC()
	rep.Pages = s.coverage().Discovered
	rep.Lemmings = good
	if good > 0 {
		rep.P95Ms = results[good].PageP95Ms
		rep.HostCap = max(1, int(math.Floor(float64(good)*opts.Safety)))
	}
	if bad > 0 {
		rep.FirstFailure = results[bad]
	}
	rep.Verdict = verdict(rep, opts)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return rep, err
	}
	if err != nil {
		return rep, fmt.Errorf("bench: stopped early: %w", err)
	}
	return rep, nil
}

func verdict(r *Report, o Options) string {
	switch {
	case r.Lemmings == 0 && r.FirstFailure != nil:
		return fmt.Sprintf("even %d lemming(s) failed: %s", r.FirstFailure.Lemmings, r.FirstFailure.Reason)
	case r.Lemmings == 0:
		return "no stage completed"
	case r.Ceiling:
		return fmt.Sprintf("passed at the -max of %d lemmings (p95 %.0fms); the application can take more than was tried", r.Lemmings, r.P95Ms)
	case r.FirstFailure != nil:
		return fmt.Sprintf("%d lemmings at p95 %.0fms within %s; at %d: %s; host capacity %d",
			r.Lemmings, r.P95Ms, o.P95Limit, r.FirstFailure.Lemmings, r.FirstFailure.Reason, r.HostCap)
	}
	return fmt.Sprintf("%d lemmings at p95 %.0fms; host capacity %d", r.Lemmings, r.P95Ms, r.HostCap)
}

// runStage holds n lemmings on the site for one stage and judges it.
func runStage(ctx context.Context, o *Options, transport http.RoundTripper, s *site, n int) Stage {
	s.resetHits()
	start := time.Now()
	rec := newRecorder(start)
	sctx, cancel := context.WithTimeout(ctx, o.StageDuration)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		l := newLemming(i, o, transport, s, rec, o.Seed+uint64(n))
		go func() {
			defer wg.Done()
			l.run(sctx)
		}()
	}
	wg.Wait()
	st := rec.summarize(n, time.Since(start))
	cov := s.coverage()
	cov.MaxDepth = st.Coverage.MaxDepth
	st.Coverage = cov
	judge(&st, o)
	return st
}

// judge decides whether a stage passed and why not.
func judge(st *Stage, o *Options) {
	limit := float64(o.P95Limit) / float64(time.Millisecond)
	var reasons []string
	if st.Pages == 0 {
		reasons = append(reasons, "no page completed")
	}
	if st.PageP95Ms > limit {
		reasons = append(reasons, fmt.Sprintf("page p95 %.0fms over %s", st.PageP95Ms, o.P95Limit))
	}
	if st.Requests > 0 && float64(st.Failed)/float64(st.Requests) > o.MaxFailRate {
		kinds := make([]string, 0, len(st.Failures))
		for k, v := range st.Failures {
			kinds = append(kinds, fmt.Sprintf("%s=%d", k, v))
		}
		sortStrings(kinds)
		reasons = append(reasons, fmt.Sprintf("%d of %d requests failed (%s)", st.Failed, st.Requests, strings.Join(kinds, ", ")))
	}
	st.Pass = len(reasons) == 0
	st.Reason = strings.Join(reasons, "; ")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
