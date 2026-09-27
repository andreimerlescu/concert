package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andreimerlescu/naddr/ess"
)

func init() {
	// A developer's NADDR_DATA must not load a full database into every test.
	ipInfoGetenv = func(string) string { return "" }
}

const ipTestTSV = "" +
	"45.138.12.0\t45.138.12.255\t218785\tLT\tUAB Cherry Servers\n" +
	"100.64.0.0\t100.64.0.255\t0\tNone\tNot routed\n" +
	"2001:1948::\t2001:1948:ffff:ffff:ffff:ffff:ffff:ffff\t210\tUS\tInternet2\n"

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func localLookup(t *testing.T) *ipLookup {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ip2asn-combined.tsv")
	if err := os.WriteFile(path, []byte(ipTestTSV), 0o600); err != nil {
		t.Fatal(err)
	}
	l := newIPLookup(envMap(map[string]string{ess.EnvDataPath: path, ess.EnvDataPoll: "off"}))
	t.Cleanup(l.close)
	if l.mode() != ipInfoLocal {
		t.Fatalf("mode: %s (%s)", l.mode(), l.describe())
	}
	return l
}

func TestFlagEmoji(t *testing.T) {
	for in, want := range map[string]string{
		"LT": "🇱🇹", "us": "🇺🇸", "None": "🌐", "": "🌐", "ZZ": "🏳️", "X1": "🌐", "USA": "🌐",
	} {
		if got := flagEmoji(in); got != want {
			t.Errorf("flagEmoji(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIPInfo_Local(t *testing.T) {
	l := localLookup(t)

	i := l.get(netip.MustParseAddr("45.138.12.24"))
	if !i.Found || i.Flag != "🇱🇹" || i.Country != "Lithuania" || i.ASN != "AS218785" ||
		i.Description != "UAB Cherry Servers" || i.Range != "45.138.12.0/24" {
		t.Fatalf("IPv4 info: %+v", i)
	}
	if i.IP8 != "0.3.86.161.45.138.12.24" || i.IP8ASN != "218785.45.138.12.24" {
		t.Errorf("IPv8 forms: %q %q", i.IP8, i.IP8ASN)
	}
	b := i.Badges()
	if len(b) != 2 || b[0].Label != "4" || b[1].Label != "8" ||
		!strings.Contains(b[1].Tip, i.IP8) || !strings.Contains(b[1].Tip, i.IP8ASN) || b[1].Copy != i.IP8 {
		t.Errorf("IPv4 badges (4 and 8, 8 with both forms): %+v", b)
	}

	v6 := l.get(netip.MustParseAddr("2001:1948::5"))
	if b := v6.Badges(); !v6.Found || len(b) != 1 || b[0].Label != "6" || v6.IP8 != "" {
		t.Errorf("IPv6 shows only 6: %+v %+v", v6, b)
	}

	none := l.get(netip.MustParseAddr("100.64.0.1"))
	if !none.Found || none.Routed || none.Flag != "🌐" || none.CountryTitle() != "No country assigned" {
		t.Errorf("not routed: %+v", none)
	}

	miss := l.get(netip.MustParseAddr("8.8.8.8"))
	if b := miss.Badges(); miss.Found || len(b) != 1 || b[0].Label != "4" {
		t.Errorf("unknown address keeps its own badge only: %+v %+v", miss, b)
	}

	if c := l.cell("198.51.0.0/16"); !c.Prefix || !c.RangeBadge {
		t.Errorf("range cell: %+v", c)
	}
	if c := l.cell("2001:1948:0:1::/64"); !c.Prefix || c.RangeBadge || !c.Info.Found {
		t.Errorf("IPv6 client /64 cell: %+v", c)
	}
	if li := l.logInfo(netip.MustParseAddr("45.138.12.24")); li == nil || li.CC != "LT" || li.N != 218785 {
		t.Errorf("log info: %+v", li)
	}
}

func TestIPInfo_OffWithoutEnvironment(t *testing.T) {
	l := newIPLookup(envMap(nil))
	defer l.close()
	if l.enabled() || !strings.HasPrefix(l.describe(), "off") {
		t.Errorf("describe: %s", l.describe())
	}
	i := l.get(netip.MustParseAddr("45.138.12.24"))
	if i.Found || i.IP4 != "45.138.12.24" || len(i.Badges()) != 1 {
		t.Errorf("off: %+v", i)
	}
	if l.logInfo(netip.MustParseAddr("45.138.12.24")) != nil {
		t.Error("no log info while off")
	}
}

func TestIPInfo_MissingFileSoftFails(t *testing.T) {
	l := newIPLookup(envMap(map[string]string{ess.EnvDataPath: filepath.Join(t.TempDir(), "missing.tsv.gz")}))
	defer l.close()
	if l.enabled() || !strings.Contains(l.describe(), "retrying") {
		t.Errorf("a missing NADDR_DATA must soft-fail and retry: %s", l.describe())
	}
}

func TestIPInfo_RemoteNaddr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/ip" || r.URL.Query().Get("addr") != "45.138.12.24" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"address not found","success":false}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": nil, "success": true, "v": 4, "country": "Lithuania", "country_code": "LT",
			"n": 218785, "asn": "AS218785", "description": "UAB Cherry Servers", "routed": true,
			"ip4": "45.138.12.24", "ip6": "", "ip8": "0.3.86.161.45.138.12.24", "ip8asn": "218785.45.138.12.24",
			"range4": "45.138.12.0/24", "range6": "", "range8": "0.3.86.161.45.138.12.0/56",
			"range8asn": "218785.45.138.12.0/24",
		})
	}))
	defer srv.Close()

	l := newIPLookup(envMap(map[string]string{envNaddrAddr: strings.TrimPrefix(srv.URL, "http://")}))
	defer l.close()
	if l.mode() != ipInfoRemote {
		t.Fatalf("mode: %s (%s)", l.mode(), l.describe())
	}

	a := netip.MustParseAddr("45.138.12.24")
	l.warm([]netip.Addr{a, netip.MustParseAddr("8.8.8.8")})
	i := l.get(a)
	if !i.Found || i.Flag != "🇱🇹" || i.IP8 != "0.3.86.161.45.138.12.24" || i.Range != "45.138.12.0/24" {
		t.Errorf("remote info: %+v", i)
	}
	if miss := l.get(netip.MustParseAddr("8.8.8.8")); miss.Found {
		t.Errorf("404 from naddr must be a miss: %+v", miss)
	}
	if n := l.failures.Load(); n != 0 {
		t.Errorf("failures: %d, want 0 (a 404 is not a failure)", n)
	}
}

func TestNaddrBaseURL(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1:8080":          "http://127.0.0.1:8080",
		"https://naddr.internal/": "https://naddr.internal",
		"http://[::1]:8080":       "http://[::1]:8080",
	} {
		if got, err := naddrBaseURL(in); err != nil || got != want {
			t.Errorf("naddrBaseURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"ftp://x", "http://"} {
		if _, err := naddrBaseURL(bad); err == nil {
			t.Errorf("naddrBaseURL(%q) accepted", bad)
		}
	}
}
