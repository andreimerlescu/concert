package bench

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/andreimerlescu/concert/internal/capacity"
)

type headerFlags http.Header

func (h headerFlags) String() string { return "" }

func (h headerFlags) Set(v string) error {
	k, val, ok := strings.Cut(v, ":")
	if !ok || strings.TrimSpace(k) == "" {
		return fmt.Errorf("header %q must look like Name: value", v)
	}
	http.Header(h).Add(strings.TrimSpace(k), strings.TrimSpace(val))
	return nil
}

// CLI runs the benchmark from command-line arguments: cmd/bench-concert and
// "concert bench" both call it. The human summary goes to out; progress to
// errOut.
func CLI(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	fs.SetOutput(errOut)
	d := Defaults
	target := fs.String("target", "", "root URL to crawl, such as http://127.0.0.1:3000/ (benchmark the application, not Concert, to size a leaf)")
	depth := fs.Int("depth", d.MaxDepth, "links a lemming follows from the root before starting over")
	pageHits := fs.Int("page-hits", d.PageHits, "visits a page takes per stage before lemmings skip it")
	p95 := fs.Duration("p95", d.P95Limit, "page p95 latency a stage must stay within")
	failRate := fs.Float64("max-fail-rate", 0, "fraction of requests a stage may fail (0: any failure fails it)")
	stage := fs.Duration("stage", d.StageDuration, "how long each concurrency is held")
	cooldown := fs.Duration("cooldown", d.Cooldown, "pause between stages")
	start := fs.Int("start", d.Start, "first concurrency")
	maxL := fs.Int("max", d.Max, "highest concurrency tried")
	growth := fs.Float64("growth", d.Growth, "ramp factor while stages pass")
	timeout := fs.Duration("timeout", d.RequestTimeout, "a request taking longer has failed")
	assets := fs.Bool("assets", d.Assets, "load the stylesheets, scripts, fonts, images and media pages reference")
	perPage := fs.Int("assets-per-page", d.AssetsPerPage, "most new assets a lemming loads per page view")
	ranges := fs.Bool("range-checks", d.RangeChecks, "check byte-range support on audio and video")
	safety := fs.Float64("safety", d.Safety, "host capacity = passing lemmings × safety")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification (staging only)")
	reportPath := fs.String("out", "", "write the full JSON report here")
	capPath := fs.String("capacity-file", "", "write capacity.json here for a leaf Concert (see -data-dir)")
	dataDir := fs.String("data-dir", "", "shorthand for -capacity-file <data-dir>/capacity.json")
	quiet := fs.Bool("quiet", false, "no progress lines")
	hdr := headerFlags{}
	fs.Var(hdr, "header", "extra request header, Name: value (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" {
		return errors.New("bench: -target is required")
	}
	u, err := url.Parse(*target)
	if err != nil {
		return fmt.Errorf("bench: -target: %w", err)
	}
	if *capPath == "" && *dataDir != "" {
		*capPath = capacity.Path(*dataDir)
	}
	logger := log.New(errOut, "", log.LstdFlags)
	opts := Options{
		Target: u, MaxDepth: *depth, PageHits: *pageHits, P95Limit: *p95, MaxFailRate: *failRate,
		StageDuration: *stage, Cooldown: *cooldown, Start: *start, Max: *maxL, Growth: *growth,
		RequestTimeout: *timeout, Assets: *assets, AssetsPerPage: *perPage, RangeChecks: *ranges,
		Safety: *safety, Insecure: *insecure, Header: http.Header(hdr),
	}
	if !*quiet {
		opts.Logf = logger.Printf
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rep, runErr := Run(ctx, opts)
	if rep == nil {
		return runErr
	}
	Summarize(out, rep)
	if *reportPath != "" {
		if err := writeJSON(*reportPath, rep); err != nil {
			return err
		}
		fmt.Fprintf(out, "report: %s\n", *reportPath)
	}
	if *capPath != "" && rep.HostCap > 0 && runErr == nil {
		if err := SaveCapacity(*capPath, rep, *reportPath); err != nil {
			return err
		}
		fmt.Fprintf(out, "capacity: %s (host_cap %d)\n", *capPath, rep.HostCap)
	}
	return runErr
}

// SaveCapacity writes the capacity file a leaf Concert reads.
func SaveCapacity(path string, rep *Report, reportPath string) error {
	limit, _ := time.ParseDuration(rep.P95Limit)
	return capacity.Save(path, capacity.File{
		At:       rep.Finished,
		Target:   rep.Target,
		HostCap:  rep.HostCap,
		Lemmings: rep.Lemmings,
		P95Ms:    rep.P95Ms,
		LimitMs:  float64(limit) / float64(time.Millisecond),
		Pages:    rep.Pages,
		Safety:   rep.Safety,
		Report:   reportPath,
	})
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// Summarize writes the human-readable result.
func Summarize(w io.Writer, r *Report) {
	fmt.Fprintf(w, "target:   %s\n", r.Target)
	fmt.Fprintf(w, "verdict:  %s\n", r.Verdict)
	fmt.Fprintf(w, "pages:    %d discovered, depth %d, %d hits per page per stage\n", r.Pages, r.Depth, r.PageHits)
	fmt.Fprintf(w, "stages:   %d in %s\n", len(r.Stages), r.Finished.Sub(r.Started).Round(time.Second))
	if f := r.FirstFailure; f != nil {
		fmt.Fprintf(w, "\nat %d lemmings it failed: %s\n", f.Lemmings, f.Reason)
		if first := firstBadSecond(f); first >= 0 {
			fmt.Fprintf(w, "  trouble began %ds into the stage\n", first)
		}
		for _, u := range f.FailingURLs {
			fmt.Fprintf(w, "  failing  %-60s %d/%d %v\n", clip(u.URL, 60), u.Failed, u.Requests, kinds(u.Failures))
		}
		for i, u := range f.SlowestURLs {
			if i == 5 {
				break
			}
			fmt.Fprintf(w, "  slowest  %-60s mean %.0fms max %.0fms\n", clip(u.URL, 60), u.MeanMs, u.MaxMs)
		}
	}
	if len(r.Stages) > 0 {
		last := r.Stages[len(r.Stages)-1]
		for _, s := range r.Stages {
			if s.Lemmings == r.Lemmings {
				last = s
			}
		}
		fmt.Fprintf(w, "\nby file type at %d lemmings:\n", last.Lemmings)
		classes := make([]string, 0, len(last.ByClass))
		for c := range last.ByClass {
			classes = append(classes, c)
		}
		sort.Strings(classes)
		for _, c := range classes {
			cs := last.ByClass[c]
			line := fmt.Sprintf("  %-9s %6d req %10d bytes  p95 %7.1fms  failed %d", c, cs.Requests, cs.Bytes, cs.P95Ms, cs.Failed)
			if cs.RangeChecked > 0 {
				line += fmt.Sprintf("  ranges %d/%d", cs.RangeOK, cs.RangeChecked)
			}
			fmt.Fprintln(w, line)
		}
		if len(last.Findings) > 0 {
			fmt.Fprintf(w, "findings: %v\n", kinds(last.Findings))
		}
	}
}

// firstBadSecond is the first second of s with a failed request, or -1.
func firstBadSecond(s *Stage) int {
	for _, sec := range s.Timeline {
		if sec.Failed > 0 {
			return sec.T
		}
	}
	return -1
}

func kinds(m map[string]int64) string {
	ks := make([]string, 0, len(m))
	for k, v := range m {
		ks = append(ks, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(ks)
	return strings.Join(ks, " ")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
