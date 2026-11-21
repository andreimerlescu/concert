package bench

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxParseBytes is how much of an HTML page or stylesheet is parsed for
// links. The rest of the body is still read and counted.
const maxParseBytes = 4 << 20

// page is one page the crawl has discovered.
type page struct {
	url   string
	depth int // shortest link distance from the root seen so far

	mu     sync.Mutex
	links  []string // pages it links to
	assets []string // what it loads
	parsed bool
}

// site is everything the lemmings have discovered. It persists across
// stages; hit counts are per stage.
type site struct {
	root string

	mu    sync.RWMutex
	pages map[string]*page
	order []string // discovery order, for deterministic picks
	hits  map[string]int
	cap   int // -page-hits
}

func newSite(root string, pageHits int) *site {
	s := &site{root: root, pages: map[string]*page{}, hits: map[string]int{}, cap: pageHits}
	s.discover(root, 0)
	return s
}

// discover records u as a page at depth, returning it.
func (s *site) discover(u string, depth int) *page {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.pages[u]; p != nil {
		if depth < p.depth {
			p.depth = depth
		}
		return p
	}
	p := &page{url: u, depth: depth}
	s.pages[u] = p
	s.order = append(s.order, u)
	return p
}

func (s *site) get(u string) *page {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pages[u]
}

// hit counts one visit to u this stage.
func (s *site) hit(u string) {
	s.mu.Lock()
	s.hits[u]++
	s.mu.Unlock()
}

func (s *site) saturated(u string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hits[u] >= s.cap
}

// resetHits starts a stage: every page is fresh again.
func (s *site) resetHits() {
	s.mu.Lock()
	s.hits = map[string]int{}
	s.mu.Unlock()
}

// fallback is where a lemming goes when its page offers nothing new: a
// random page that has not reached -page-hits this stage or, when every
// page has, the least visited one, so the load never stops.
func (s *site) fallback(rng *rand.Rand) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var open []string
	least, leastN := s.root, int(^uint(0)>>1)
	for _, u := range s.order {
		n := s.hits[u]
		if n < s.cap {
			open = append(open, u)
		}
		if n < leastN {
			least, leastN = u, n
		}
	}
	if len(open) > 0 {
		return open[rng.IntN(len(open))]
	}
	return least
}

func (s *site) coverage() Coverage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := Coverage{Discovered: len(s.pages)}
	for _, n := range s.hits {
		if n > 0 {
			c.Visited++
		}
		if n >= s.cap {
			c.Saturated++
		}
	}
	return c
}

// lemming is one simulated visitor: its own cookies (so a waiting room or
// session treats it as one browser) and its own asset cache.
type lemming struct {
	id     int
	opts   *Options
	client *http.Client
	site   *site
	rec    *recorder
	rng    *rand.Rand
	cached map[string]bool // assets this visitor already loaded this stage
}

func newLemming(id int, o *Options, transport http.RoundTripper, s *site, rec *recorder, seed uint64) *lemming {
	jar, _ := cookiejar.New(nil)
	return &lemming{
		id:   id,
		opts: o,
		client: &http.Client{
			Transport: transport,
			Jar:       jar,
			Timeout:   o.RequestTimeout,
		},
		site:   s,
		rec:    rec,
		rng:    rand.New(rand.NewPCG(seed, uint64(id))),
		cached: map[string]bool{},
	}
}

// run walks the site until ctx ends: from the root, follow a random link
// whose page has not reached -page-hits, load what the page loads, and
// repeat to -depth links deep, then start again from the root. A page with
// nothing new to follow sends the lemming to another open page.
func (l *lemming) run(ctx context.Context) {
	cur, depth := l.start(), 0
	for ctx.Err() == nil {
		p := l.visit(ctx, cur, depth)
		if ctx.Err() != nil {
			return
		}
		l.rec.depth(depth)
		next := ""
		if p != nil && depth < l.opts.MaxDepth {
			next = l.pickLink(p)
			if next != "" {
				depth++
			}
		}
		if next == "" {
			if depth >= l.opts.MaxDepth {
				next, depth = l.start(), 0
			} else {
				next = l.site.fallback(l.rng)
				if pp := l.site.get(next); pp != nil {
					depth = pp.depth
				}
			}
		}
		cur = next
	}
}

// start is the root, unless it already reached -page-hits this stage.
func (l *lemming) start() string {
	if !l.site.saturated(l.site.root) {
		return l.site.root
	}
	return l.site.fallback(l.rng)
}

// pickLink chooses a random link of p whose page is still open.
func (l *lemming) pickLink(p *page) string {
	p.mu.Lock()
	links := p.links
	p.mu.Unlock()
	if len(links) == 0 {
		return ""
	}
	off := l.rng.IntN(len(links))
	for i := range links {
		u := links[(off+i)%len(links)]
		if !l.site.saturated(u) {
			return u
		}
	}
	return ""
}

// visit loads one page and, the first time this lemming sees them, up to
// -assets-per-page of the assets it references. It returns the page with
// its links, or nil when the page could not be loaded.
func (l *lemming) visit(ctx context.Context, u string, depth int) *page {
	l.site.hit(u)
	body, ct, final, ok := l.fetch(ctx, u, true)
	p := l.site.discover(u, depth)
	if !ok {
		return nil
	}
	p.mu.Lock()
	if !p.parsed && (isHTML(ct) || (ct == "" && sniffHTML(body))) {
		base, _ := url.Parse(final)
		for _, f := range extractHTML(bytes.NewReader(body), base, maxParseBytes) {
			if f.kind == KindPage {
				p.links = append(p.links, f.url)
			} else {
				p.assets = append(p.assets, f.url)
			}
		}
		p.parsed = true
	}
	links, assets := p.links, p.assets
	p.mu.Unlock()
	for _, link := range links {
		l.site.discover(link, depth+1)
	}
	if l.opts.Assets {
		l.loadAssets(ctx, assets)
	}
	return p
}

func (l *lemming) loadAssets(ctx context.Context, assets []string) {
	loaded := 0
	queue := append([]string(nil), assets...)
	for len(queue) > 0 && loaded < l.opts.AssetsPerPage && ctx.Err() == nil {
		a := queue[0]
		queue = queue[1:]
		if l.cached[a] {
			continue
		}
		l.cached[a] = true
		loaded++
		body, ct, final, ok := l.fetch(ctx, a, false)
		if ok && isCSS(ct) {
			// Fonts and background images a stylesheet loads.
			base, _ := url.Parse(final)
			for _, f := range extractCSS(body, base) {
				if !l.cached[f.url] {
					queue = append(queue, f.url)
				}
			}
		}
		if ok && l.opts.RangeChecks {
			if c := classify(ct, a); (c == ClassAudio || c == ClassVideo) && l.rec.claimRange(a) {
				l.checkRange(ctx, a, c)
			}
		}
	}
}

// fetch performs one GET and records it. The body is kept only for HTML
// and CSS (up to maxParseBytes); everything else is read and discarded so
// large media is streamed, not held. ok is false on any failure.
func (l *lemming) fetch(ctx context.Context, u string, isPage bool) (body []byte, contentType, final string, ok bool) {
	start := time.Now()
	s := sample{at: start.Sub(l.rec.start), url: u, page: isPage}
	defer func() {
		s.dur = time.Since(start)
		if ctx.Err() != nil && s.fail != "" {
			return // the stage ended mid-request; not the server's fault
		}
		l.rec.add(s)
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		s.fail, s.class = FailConnOther, ClassOther
		return nil, "", u, false
	}
	for k, v := range l.opts.Header {
		req.Header[k] = v
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "concert-bench lemming/"+strconv.Itoa(l.id))
	}
	if isPage {
		req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
	}
	resp, err := l.client.Do(req)
	if err != nil {
		s.fail = failKind(err)
		s.class = classify("", u)
		if isPage {
			s.class = ClassHTML
		}
		return nil, "", u, false
	}
	defer resp.Body.Close()
	contentType = resp.Header.Get("Content-Type")
	final = resp.Request.URL.String()
	s.class = classify(contentType, final)
	keep := isHTML(contentType) || isCSS(contentType) || (contentType == "" && isPage)
	var buf bytes.Buffer
	var n int64
	if keep {
		n, err = io.Copy(&buf, io.LimitReader(resp.Body, maxParseBytes))
		if err == nil {
			var rest int64
			rest, err = io.Copy(io.Discard, resp.Body)
			n += rest
		}
	} else {
		n, err = io.Copy(io.Discard, resp.Body)
	}
	s.bytes = n
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "Client.Timeout") {
			s.fail = FailTimeout
		} else {
			s.fail = FailTruncated
		}
		return nil, contentType, final, false
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength && resp.Request.Method != http.MethodHead {
		s.fail = FailTruncated
		return nil, contentType, final, false
	}
	fail, finding := statusKind(resp.StatusCode)
	s.fail, s.finding = fail, finding
	if fail != "" || finding != "" || resp.StatusCode >= 300 {
		return nil, contentType, final, false
	}
	return buf.Bytes(), contentType, final, true
}

// checkRange asks for the first KiB of a media file, as a player seeking
// does, and records whether the server honoured the range.
func (l *lemming) checkRange(ctx context.Context, u, class string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return
	}
	req.Header.Set("Range", "bytes=0-1023")
	resp, err := l.client.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			l.rec.add(sample{at: time.Since(l.rec.start), url: u, class: class, fail: failKind(err)})
		}
		return
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, resp.Body)
	ok := resp.StatusCode == http.StatusPartialContent && strings.HasPrefix(resp.Header.Get("Content-Range"), "bytes 0-") && n > 0 && n <= 1024
	l.rec.rangeResult(class, ok)
	if !ok && resp.StatusCode == http.StatusOK {
		l.rec.add(sample{at: time.Since(l.rec.start), url: u + " (range)", class: class, bytes: n, finding: FindNoRange})
	}
}
