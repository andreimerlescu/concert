package bench

import (
	"math"
	"sort"
	"sync"
	"time"
)

// Stage is one fixed concurrency held for one stage duration.
type Stage struct {
	Lemmings int           `json:"lemmings"`
	Duration time.Duration `json:"duration_ns"`
	Pass     bool          `json:"pass"`
	Reason   string        `json:"reason"`

	Requests int64   `json:"requests"`
	Pages    int64   `json:"pages"`
	Assets   int64   `json:"assets"`
	Bytes    int64   `json:"bytes"`
	RPS      float64 `json:"rps"`

	PageP50Ms  float64 `json:"page_p50_ms"`
	PageP95Ms  float64 `json:"page_p95_ms"`
	PageP99Ms  float64 `json:"page_p99_ms"`
	PageMaxMs  float64 `json:"page_max_ms"`
	AssetP95Ms float64 `json:"asset_p95_ms"`

	// Failures count load-induced problems by kind; Findings count
	// properties of the site (broken links, media without ranges).
	Failures map[string]int64 `json:"failures,omitempty"`
	Failed   int64            `json:"failed"`
	Findings map[string]int64 `json:"findings,omitempty"`

	ByClass  map[string]*ClassStats `json:"by_class"`
	Coverage Coverage               `json:"coverage"`

	// Timeline is the stage second by second, so the onset of trouble is
	// visible: when errors began, and whether latency climbed first.
	Timeline []Second `json:"timeline"`

	SlowestURLs []URLStat `json:"slowest_urls,omitempty"`
	FailingURLs []URLStat `json:"failing_urls,omitempty"`
}

// ClassStats is one asset class within a stage.
type ClassStats struct {
	Requests     int64            `json:"requests"`
	Bytes        int64            `json:"bytes"`
	Failed       int64            `json:"failed"`
	P95Ms        float64          `json:"p95_ms"`
	RangeChecked int64            `json:"range_checked,omitempty"`
	RangeOK      int64            `json:"range_ok,omitempty"`
	Failures     map[string]int64 `json:"failures,omitempty"`
	durs         []time.Duration
}

// Coverage is how much of the site the stage's lemmings walked.
type Coverage struct {
	Discovered int `json:"pages_discovered"` // distinct pages known so far
	Visited    int `json:"pages_visited"`    // distinct pages hit this stage
	Saturated  int `json:"pages_saturated"`  // pages that reached -page-hits this stage
	MaxDepth   int `json:"max_depth"`        // deepest link chain followed this stage
}

// Second is one second of a stage.
type Second struct {
	T        int     `json:"t"`
	Requests int64   `json:"requests"`
	Failed   int64   `json:"failed"`
	P95Ms    float64 `json:"p95_ms"`
}

// URLStat is one URL's results within a stage.
type URLStat struct {
	URL      string           `json:"url"`
	Requests int64            `json:"requests"`
	Failed   int64            `json:"failed"`
	MeanMs   float64          `json:"mean_ms"`
	MaxMs    float64          `json:"max_ms"`
	Failures map[string]int64 `json:"failures,omitempty"`
}

// sample is one finished request.
type sample struct {
	at      time.Duration // since stage start
	url     string
	class   string
	page    bool
	dur     time.Duration
	bytes   int64
	fail    string
	finding string
}

// recorder collects a stage's samples. Safe for concurrent use.
type recorder struct {
	mu        sync.Mutex
	start     time.Time
	samples   []sample
	rangeSeen map[string]bool
	ranges    map[string][2]int64 // class → checked, ok
	maxDepth  int
}

func newRecorder(start time.Time) *recorder {
	return &recorder{start: start, rangeSeen: map[string]bool{}, ranges: map[string][2]int64{}}
}

func (r *recorder) add(s sample) {
	r.mu.Lock()
	r.samples = append(r.samples, s)
	r.mu.Unlock()
}

func (r *recorder) depth(d int) {
	r.mu.Lock()
	if d > r.maxDepth {
		r.maxDepth = d
	}
	r.mu.Unlock()
}

// claimRange reports whether u has not been range-checked yet this stage,
// and marks it.
func (r *recorder) claimRange(u string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rangeSeen[u] {
		return false
	}
	r.rangeSeen[u] = true
	return true
}

func (r *recorder) rangeResult(class string, ok bool) {
	r.mu.Lock()
	v := r.ranges[class]
	v[0]++
	if ok {
		v[1]++
	}
	r.ranges[class] = v
	r.mu.Unlock()
}

// percentile of sorted durations, in milliseconds (nearest rank).
func percentile(sorted []time.Duration, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(p*float64(len(sorted)))) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return ms(sorted[i])
}

func ms(d time.Duration) float64 {
	return math.Round(float64(d)/float64(time.Millisecond)*100) / 100
}

func sortDur(d []time.Duration) {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
}

// summarize turns the samples into a Stage. It does not judge it.
func (r *recorder) summarize(lemmings int, elapsed time.Duration) Stage {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := Stage{
		Lemmings: lemmings,
		Duration: elapsed,
		Failures: map[string]int64{},
		Findings: map[string]int64{},
		ByClass:  map[string]*ClassStats{},
	}
	var pageDur, assetDur []time.Duration
	type urlAcc struct {
		URLStat
		sum time.Duration
		max time.Duration
	}
	urls := map[string]*urlAcc{}
	secs := map[int]*struct {
		n, f int64
		d    []time.Duration
	}{}
	for _, s := range r.samples {
		st.Requests++
		st.Bytes += s.bytes
		if s.page {
			st.Pages++
			pageDur = append(pageDur, s.dur)
		} else {
			st.Assets++
			assetDur = append(assetDur, s.dur)
		}
		cs := st.ByClass[s.class]
		if cs == nil {
			cs = &ClassStats{}
			st.ByClass[s.class] = cs
		}
		cs.Requests++
		cs.Bytes += s.bytes
		cs.durs = append(cs.durs, s.dur)
		u := urls[s.url]
		if u == nil {
			u = &urlAcc{URLStat: URLStat{URL: s.url}}
			urls[s.url] = u
		}
		u.Requests++
		u.sum += s.dur
		if s.dur > u.max {
			u.max = s.dur
		}
		sec := int(s.at / time.Second)
		b := secs[sec]
		if b == nil {
			b = &struct {
				n, f int64
				d    []time.Duration
			}{}
			secs[sec] = b
		}
		b.n++
		b.d = append(b.d, s.dur)
		if s.fail != "" {
			st.Failed++
			st.Failures[s.fail]++
			cs.Failed++
			if cs.Failures == nil {
				cs.Failures = map[string]int64{}
			}
			cs.Failures[s.fail]++
			u.Failed++
			if u.Failures == nil {
				u.Failures = map[string]int64{}
			}
			u.Failures[s.fail]++
			b.f++
		}
		if s.finding != "" {
			st.Findings[s.finding]++
		}
	}
	sortDur(pageDur)
	sortDur(assetDur)
	st.PageP50Ms = percentile(pageDur, 0.50)
	st.PageP95Ms = percentile(pageDur, 0.95)
	st.PageP99Ms = percentile(pageDur, 0.99)
	if n := len(pageDur); n > 0 {
		st.PageMaxMs = ms(pageDur[n-1])
	}
	st.AssetP95Ms = percentile(assetDur, 0.95)
	if elapsed > 0 {
		st.RPS = math.Round(float64(st.Requests)/elapsed.Seconds()*10) / 10
	}
	for class, cs := range st.ByClass {
		sortDur(cs.durs)
		cs.P95Ms = percentile(cs.durs, 0.95)
		cs.durs = nil
		if v, ok := r.ranges[class]; ok {
			cs.RangeChecked, cs.RangeOK = v[0], v[1]
		}
	}
	maxSec := -1
	for s := range secs {
		if s > maxSec {
			maxSec = s
		}
	}
	for s := 0; s <= maxSec; s++ {
		sec := Second{T: s}
		if b := secs[s]; b != nil {
			sortDur(b.d)
			sec.Requests, sec.Failed, sec.P95Ms = b.n, b.f, percentile(b.d, 0.95)
		}
		st.Timeline = append(st.Timeline, sec)
	}
	all := make([]*urlAcc, 0, len(urls))
	for _, u := range urls {
		u.MeanMs = ms(u.sum / time.Duration(u.Requests))
		u.MaxMs = ms(u.max)
		all = append(all, u)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].MeanMs != all[j].MeanMs {
			return all[i].MeanMs > all[j].MeanMs
		}
		return all[i].URL < all[j].URL
	})
	for i := 0; i < len(all) && i < 10; i++ {
		st.SlowestURLs = append(st.SlowestURLs, all[i].URLStat)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Failed != all[j].Failed {
			return all[i].Failed > all[j].Failed
		}
		return all[i].URL < all[j].URL
	})
	for i := 0; i < len(all) && i < 10 && all[i].Failed > 0; i++ {
		st.FailingURLs = append(st.FailingURLs, all[i].URLStat)
	}
	st.Coverage.MaxDepth = r.maxDepth
	return st
}
