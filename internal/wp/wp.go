// Package wp provides WordPress & WooCommerce operator tooling for wpconcert
// (and econcert): PHP-FPM pool discovery and sizing, `wpconcert doctor`
// diagnostics, and `wpconcert init` Concertfile generation.
package wp

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/configfile"
)

// DefaultFPMPoolGlobs lists standard Linux and macOS PHP-FPM pool.d config locations.
var DefaultFPMPoolGlobs = []string{
	"/etc/php/*/fpm/pool.d/*.conf",
	"/etc/php-fpm.d/*.conf",
	"/usr/local/etc/php-fpm.d/*.conf",
	"/opt/homebrew/etc/php/*/php-fpm.d/*.conf",
}

// FPMPool describes one parsed PHP-FPM worker pool.
type FPMPool struct {
	ConfigPath      string `json:"config_path"`
	Name            string `json:"name"`
	Listen          string `json:"listen"`
	UpstreamURL     string `json:"upstream_url"`
	PM              string `json:"pm,omitempty"`
	MaxChildren     int    `json:"max_children"`
	SocketReachable bool   `json:"socket_reachable"`
	SocketError     string `json:"socket_error,omitempty"`
}

// ParseFPMPoolFile parses a PHP-FPM INI pool file (e.g. www.conf).
func ParseFPMPoolFile(path string) ([]FPMPool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pools []FPMPool
	var cur *FPMPool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(line[1 : len(line)-1])
			if name == "" || strings.EqualFold(name, "global") {
				cur = nil
				continue
			}
			pools = append(pools, FPMPool{ConfigPath: path, Name: name})
			cur = &pools[len(pools)-1]
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if idx := strings.IndexByte(v, ';'); idx >= 0 {
			v = v[:idx]
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "listen":
			cur.Listen = v
			cur.UpstreamURL = fpmListenToUpstream(v)
		case "pm":
			cur.PM = v
		case "pm.max_children":
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				cur.MaxChildren = n
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for i := range pools {
		probeFPMPool(&pools[i])
	}
	return pools, nil
}

func fpmListenToUpstream(listen string) string {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return ""
	}
	if strings.HasPrefix(listen, "/") {
		return "fcgi+unix://" + listen
	}
	if _, _, err := net.SplitHostPort(listen); err == nil {
		return "fcgi://" + listen
	}
	if _, err := strconv.Atoi(listen); err == nil {
		return "fcgi://127.0.0.1:" + listen
	}
	return "fcgi://" + listen
}

func probeFPMPool(p *FPMPool) {
	if p.Listen == "" {
		return
	}
	network, addr := "tcp", p.Listen
	if strings.HasPrefix(p.Listen, "/") {
		network = "unix"
	} else if _, err := strconv.Atoi(p.Listen); err == nil {
		addr = "127.0.0.1:" + p.Listen
	}
	conn, err := net.DialTimeout(network, addr, 500*time.Millisecond)
	if err != nil {
		p.SocketReachable = false
		p.SocketError = err.Error()
		return
	}
	_ = conn.Close()
	p.SocketReachable = true
}

// DiscoverFPMPools scans globs (or DefaultFPMPoolGlobs when empty) for PHP-FPM
// pool definitions, sorted deterministically by config path.
func DiscoverFPMPools(globs ...string) []FPMPool {
	if len(globs) == 0 {
		globs = DefaultFPMPoolGlobs
	}
	seen := map[string]bool{}
	var paths []string
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				paths = append(paths, m)
			}
		}
	}
	sort.Strings(paths)
	var out []FPMPool
	for _, p := range paths {
		pools, err := ParseFPMPoolFile(p)
		if err == nil {
			out = append(out, pools...)
		}
	}
	return out
}

// RecommendedCaps splits a PHP-FPM pool's pm.max_children safely into Concert's
// main waiting-room cap (~75%) and checkout/logged-in priority lane (~25%) so
// cap + priority_cap never exceeds pm.max_children.
func RecommendedCaps(maxChildren int) (capSlots, prioritySlots int) {
	if maxChildren <= 1 {
		return 1, 1
	}
	if maxChildren <= 4 {
		return maxChildren - 1, 1
	}
	prioritySlots = max(1, maxChildren/4)
	capSlots = maxChildren - prioritySlots
	if capSlots < 1 {
		capSlots = 1
	}
	return capSlots, prioritySlots
}

// CheckStatus is pass, warn, or fail.
type CheckStatus string

const (
	StatusPass CheckStatus = "pass"
	StatusWarn CheckStatus = "warn"
	StatusFail CheckStatus = "fail"
)

// DoctorCheck is one structured diagnostic line.
type DoctorCheck struct {
	Name    string      `json:"name"`
	Status  CheckStatus `json:"status"`
	Summary string      `json:"summary"`
	Detail  string      `json:"detail,omitempty"`
}

// DoctorReport holds the complete output of `wpconcert doctor`.
type DoctorReport struct {
	OK     bool          `json:"ok"`
	Pools  []FPMPool     `json:"fpm_pools,omitempty"`
	Checks []DoctorCheck `json:"checks"`
}

// DoctorOptions controls what RunDoctor inspects.
type DoctorOptions struct {
	ConfigPath string
	RootDir    string
	FPMGlobs   []string
}

// RunDoctor inspects PHP-FPM pools, optional WordPress document root, and
// optional Concertfile configuration.
func RunDoctor(opts DoctorOptions) DoctorReport {
	rep := DoctorReport{OK: true}
	add := func(name string, st CheckStatus, summary, detail string) {
		if st == StatusFail {
			rep.OK = false
		}
		rep.Checks = append(rep.Checks, DoctorCheck{Name: name, Status: st, Summary: summary, Detail: detail})
	}

	pools := DiscoverFPMPools(opts.FPMGlobs...)
	rep.Pools = pools
	poolByUpstream := map[string]FPMPool{}
	if len(pools) == 0 {
		add("php-fpm", StatusWarn, "no local php-fpm pool configs found", "pass --fpm-glob or configure upstream manually in Concertfile")
	} else {
		for _, p := range pools {
			if p.UpstreamURL != "" {
				poolByUpstream[p.UpstreamURL] = p
			}
			recCap, recPrio := RecommendedCaps(p.MaxChildren)
			st := StatusPass
			if !p.SocketReachable {
				st = StatusWarn
			}
			add("php-fpm:"+p.Name, st,
				fmt.Sprintf("listen=%s pm.max_children=%d (recommended cap=%d priority_cap=%d)", p.Listen, p.MaxChildren, recCap, recPrio),
				fmt.Sprintf("config=%s reachable=%v %s", p.ConfigPath, p.SocketReachable, p.SocketError))
		}
	}

	checkRoot := func(label, dir string) {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			add(label, StatusFail, fmt.Sprintf("root directory %q does not exist", dir), "")
			return
		}
		if _, err := os.Stat(filepath.Join(dir, "index.php")); err != nil {
			add(label, StatusWarn, fmt.Sprintf("%s has no index.php", dir), "FastCGI try_files expects index.php in root")
		} else {
			add(label, StatusPass, fmt.Sprintf("WordPress root %s verified (index.php present)", dir), "")
		}
		if info, err := os.Stat(filepath.Join(dir, "wp-config.php")); err == nil && info.Mode().Perm()&0o004 != 0 {
			add(label+":wp-config-perms", StatusWarn, "wp-config.php is world-readable", "recommend chmod 640 wp-config.php (Concert blocks HTTP access regardless)")
		}
	}

	if opts.RootDir != "" {
		checkRoot("root", opts.RootDir)
	}

	if opts.ConfigPath != "" {
		cf, err := configfile.Load(opts.ConfigPath)
		if err != nil {
			add("config", StatusFail, fmt.Sprintf("invalid config %s", opts.ConfigPath), err.Error())
		} else {
			add("config", StatusPass, fmt.Sprintf("loaded %s (%d site(s), http3=%v)", opts.ConfigPath, len(cf.Sites), cf.Global.HTTP3), "")
			for _, s := range cf.Sites {
				host := s.Hosts[0]
				if s.Root != "" {
					checkRoot("site:"+host+":root", s.Root)
				} else if strings.HasPrefix(s.Upstream, "fcgi") {
					add("site:"+host+":root", StatusFail, "FastCGI upstream requires root directive", s.Upstream)
				}
				if pool, ok := poolByUpstream[s.Upstream]; ok && pool.MaxChildren > 0 {
					total := s.Cap + s.PriorityCap
					if total > pool.MaxChildren {
						recCap, recPrio := RecommendedCaps(pool.MaxChildren)
						add("site:"+host+":sizing", StatusWarn,
							fmt.Sprintf("cap (%d) + priority_cap (%d) = %d exceeds pm.max_children (%d)", s.Cap, s.PriorityCap, total, pool.MaxChildren),
							fmt.Sprintf("recommended: cap %d, priority_cap %d so PHP-FPM never queues internally", recCap, recPrio))
					} else if s.Cap > 0 {
						add("site:"+host+":sizing", StatusPass,
							fmt.Sprintf("cap (%d) + priority_cap (%d) fits inside pm.max_children (%d)", s.Cap, s.PriorityCap, pool.MaxChildren), "")
					}
				}
				if s.Preset != "wordpress" && strings.HasPrefix(s.Upstream, "fcgi") {
					add("site:"+host+":preset", StatusWarn, "site uses FastCGI without `preset wordpress`", "add `preset wordpress` for automatic asset gating, /xmlrpc.php denial, and uploads PHP block")
				}
			}
		}
	}
	return rep
}

// RunDoctorCLI executes `wpconcert doctor`.
func RunDoctorCLI(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(out)
	var opts DoctorOptions
	var fpmGlob string
	var asJSON bool
	fs.StringVar(&opts.ConfigPath, "config", "", "Concertfile or .json to validate")
	fs.StringVar(&opts.RootDir, "root", "", "WordPress document root to inspect")
	fs.StringVar(&fpmGlob, "fpm-glob", "", "custom glob for PHP-FPM pool configs (e.g. /etc/php/*/fpm/pool.d/*.conf)")
	fs.BoolVar(&asJSON, "json", false, "output report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fpmGlob != "" {
		opts.FPMGlobs = []string{fpmGlob}
	}
	rep := RunDoctor(opts)
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	for _, c := range rep.Checks {
		tag := strings.ToUpper(string(c.Status))
		fmt.Fprintf(out, "[%-4s] %-26s %s\n", tag, c.Name, c.Summary)
		if c.Detail != "" {
			fmt.Fprintf(out, "       %s\n", c.Detail)
		}
	}
	if !rep.OK {
		return errors.New("doctor found one or more failing checks")
	}
	return nil
}

// RunInit executes `wpconcert init` to generate a ready-to-run Concertfile
// sized to the host's discovered PHP-FPM pool (or explicit flags).
func RunInit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(out)
	var (
		domain     string
		rootDir    string
		upstream   string
		email      string
		fpmGlob    string
		microCache string
		outPath    string
		capSlots   int
		prioSlots  int
		http3      bool
	)
	fs.StringVar(&domain, "domain", "", "site domain name (e.g. shop.example.com)")
	fs.StringVar(&rootDir, "root", "/var/www/html", "WordPress document root")
	fs.StringVar(&upstream, "upstream", "", "FastCGI upstream URL (auto-discovered from php-fpm if empty)")
	fs.StringVar(&email, "tls-email", "", "Let's Encrypt contact email")
	fs.StringVar(&fpmGlob, "fpm-glob", "", "custom glob for PHP-FPM pool discovery")
	fs.StringVar(&microCache, "micro-cache", "15s", "anonymous GET page micro-cache TTL (e.g. 15s, or off)")
	fs.IntVar(&capSlots, "cap", 0, "waiting room capacity (auto-sized from pm.max_children if 0)")
	fs.IntVar(&prioSlots, "priority-cap", 0, "priority lane slots (auto-sized from pm.max_children if 0)")
	fs.BoolVar(&http3, "http3", false, "enable HTTP/3 (QUIC) alongside HTTP/2 and HTTP/1.1")
	fs.StringVar(&outPath, "out", "", "write Concertfile to this path instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(domain) == "" {
		return errors.New("init: --domain is required (e.g. wpconcert init --domain shop.example.com --root /var/www/shop)")
	}
	var globs []string
	if fpmGlob != "" {
		globs = []string{fpmGlob}
	}
	pools := DiscoverFPMPools(globs...)
	var chosen *FPMPool
	for i := range pools {
		if pools[i].SocketReachable {
			chosen = &pools[i]
			break
		}
	}
	if chosen == nil && len(pools) > 0 {
		chosen = &pools[0]
	}
	if upstream == "" {
		if chosen != nil && chosen.UpstreamURL != "" {
			upstream = chosen.UpstreamURL
		} else {
			upstream = "fcgi+unix:///run/php/php-fpm.sock"
		}
	}
	if capSlots == 0 {
		mc := 16
		if chosen != nil && chosen.MaxChildren > 0 {
			mc = chosen.MaxChildren
		}
		capSlots, prioSlots = RecommendedCaps(mc)
	} else if prioSlots == 0 {
		prioSlots = max(1, capSlots/4)
	}

	secure := true
	f := &configfile.File{
		Global: configfile.GlobalConfig{
			Listen:     ":443",
			HTTPListen: ":80",
			TLSEmail:   email,
			TLSCache:   "/var/lib/concert/acme",
			HSTSMaxAge: 31536000,
			HTTP3:      http3,
			DataDir:    "/var/lib/concert/data",
		},
		Sites: []configfile.SiteConfig{
			{
				Hosts:        []string{domain},
				Preset:       "wordpress",
				Root:         rootDir,
				Upstream:     upstream,
				Cap:          capSlots,
				PriorityCap:  prioSlots,
				MicroCache:   microCache,
				SecureCookie: &secure,
			},
		},
	}
	if err := f.NormalizeAndValidate(); err != nil {
		return err
	}
	rendered := configfile.FormatConcertfile(f)
	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(rendered), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(out, "Wrote %s (cap=%d, priority_cap=%d, upstream=%s)\n", outPath, capSlots, prioSlots, upstream)
		return nil
	}
	_, err := io.WriteString(out, rendered)
	return err
}
