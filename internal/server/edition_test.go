package server

import (
	"flag"
	"io"
	"strings"
	"testing"
)

func TestEdition_MovedFlagsAndSubcommands(t *testing.T) {
	ed := Edition()
	switch ed {
	case "concert", "wpconcert", "econcert":
	default:
		t.Fatalf("unexpected Edition() = %q", ed)
	}

	if !hasEnterpriseEdition() {
		for _, args := range [][]string{
			{"-fastlane-config", "/tmp/fl.json"},
			{"-role", "leaf"},
			{"-redis-addr", "127.0.0.1:6379"},
			{"-email-provider=smtp"},
			{"-enterprise-hardened"},
		} {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			_, _, err := parseConfig(fs, args)
			if err == nil || !strings.Contains(err.Error(), "econcert") {
				t.Errorf("args %v: err=%v, want migration hint mentioning econcert", args, err)
			}
		}
		if fn := enterpriseSubcommand("reconcile"); fn == nil {
			t.Fatal("expected reconcile stub subcommand")
		} else if err := fn(nil, io.Discard); err == nil || !strings.Contains(err.Error(), "econcert") {
			t.Fatalf("reconcile stub err=%v, want econcert hint", err)
		}
	}

	if !hasWordPressEdition() {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		_, _, err := parseConfig(fs, []string{"-fcgi-index", "index.php"})
		if err == nil || !strings.Contains(err.Error(), "wpconcert") {
			t.Errorf("-fcgi-index err=%v, want migration hint mentioning wpconcert", err)
		}
		fs2 := flag.NewFlagSet("test", flag.ContinueOnError)
		fs2.SetOutput(io.Discard)
		_, _, err = parseConfig(fs2, []string{"-upstream", "fcgi+unix:///tmp/php.sock", "-data-dir", ""})
		if err == nil || !strings.Contains(err.Error(), "wpconcert") {
			t.Errorf("fcgi+unix upstream err=%v, want wpconcert hint", err)
		}
	}
}
