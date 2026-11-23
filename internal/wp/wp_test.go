package wp

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andreimerlescu/concert/internal/configfile"
)

func TestParseFPMPoolFileAndSizing(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "www.conf")
	raw := `
; Default PHP-FPM pool
[www]
user = www-data
listen = /run/php/php8.3-fpm.sock
pm = dynamic
pm.max_children = 20

[api]
listen = 127.0.0.1:9000
pm = static
pm.max_children = 8
`
	if err := os.WriteFile(conf, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	pools, err := ParseFPMPoolFile(conf)
	if err != nil {
		t.Fatalf("ParseFPMPoolFile: %v", err)
	}
	if len(pools) != 2 {
		t.Fatalf("pools=%d, want 2", len(pools))
	}
	if pools[0].Name != "www" || pools[0].UpstreamURL != "fcgi+unix:///run/php/php8.3-fpm.sock" || pools[0].MaxChildren != 20 {
		t.Fatalf("unexpected pool[0]: %+v", pools[0])
	}
	if pools[1].Name != "api" || pools[1].UpstreamURL != "fcgi://127.0.0.1:9000" || pools[1].MaxChildren != 8 {
		t.Fatalf("unexpected pool[1]: %+v", pools[1])
	}
	c, p := RecommendedCaps(20)
	if c != 15 || p != 5 || c+p != 20 {
		t.Fatalf("RecommendedCaps(20) = (%d, %d), want (15, 5)", c, p)
	}
}

func TestDoctorAndInit(t *testing.T) {
	dir := t.TempDir()
	wpRoot := filepath.Join(dir, "wp")
	if err := os.MkdirAll(wpRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wpRoot, "index.php"), []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}
	fpmConf := filepath.Join(dir, "pool.conf")
	if err := os.WriteFile(fpmConf, []byte("[www]\nlisten = 127.0.0.1:9001\npm.max_children = 12\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. RunInit generates a valid Concertfile sized to pm.max_children=12 (cap=9, priority_cap=3).
	var buf bytes.Buffer
	if err := RunInit([]string{
		"--domain", "shop.example.com",
		"--root", wpRoot,
		"--fpm-glob", fpmConf,
		"--tls-email", "ops@example.com",
		"--http3",
	}, &buf); err != nil {
		t.Fatalf("RunInit: %v", err)
	}
	cf, err := configfile.ParseConcertfile(buf.Bytes())
	if err != nil {
		t.Fatalf("generated Concertfile failed to parse:\n%s\nerr: %v", buf.String(), err)
	}
	if !cf.Global.HTTP3 || cf.Sites[0].Cap != 9 || cf.Sites[0].PriorityCap != 3 || cf.Sites[0].Upstream != "fcgi://127.0.0.1:9001" {
		t.Fatalf("unexpected generated config: %+v", cf)
	}

	// 2. RunDoctor passes on the generated Concertfile.
	cfPath := filepath.Join(dir, "Concertfile")
	if err := os.WriteFile(cfPath, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	rep := RunDoctor(DoctorOptions{ConfigPath: cfPath, FPMGlobs: []string{fpmConf}})
	if !rep.OK {
		t.Fatalf("expected doctor OK, got checks=%+v", rep.Checks)
	}

	// 3. Doctor flags oversized cap > pm.max_children as warn.
	oversized := strings.Replace(buf.String(), "cap 9", "cap 50", 1)
	if err := os.WriteFile(cfPath, []byte(oversized), 0o600); err != nil {
		t.Fatal(err)
	}
	rep2 := RunDoctor(DoctorOptions{ConfigPath: cfPath, FPMGlobs: []string{fpmConf}})
	foundWarn := false
	for _, c := range rep2.Checks {
		if strings.Contains(c.Name, ":sizing") && c.Status == StatusWarn {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Fatalf("expected sizing warning when cap > pm.max_children, got %+v", rep2.Checks)
	}
}
