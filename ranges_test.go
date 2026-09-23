package main

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"
)

func TestParseBanTarget(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		single bool
		err    error
	}{
		{"203.0.113.9", "203.0.113.9", true, nil},
		{"203.0.113.9/32", "203.0.113.9", true, nil},
		{" 10.1.2.3/16 ", "10.1.0.0/16", false, nil},
		{"10.0.0.0/8", "10.0.0.0/8", false, nil},
		{"10.0.0.0/7", "", false, errRangeTooBroad},
		{"0.0.0.0/0", "", false, errRangeTooBroad},
		{"2001:db8::1", "2001:db8::/64", true, nil},
		{"2001:db8:0:0:1::/80", "2001:db8::/64", true, nil},
		{"2001:db8::/48", "2001:db8::/48", false, nil},
		{"2001::/15", "", false, errRangeTooBroad},
		{"::ffff:10.1.2.3", "10.1.2.3", true, nil},
		{"::ffff:10.1.0.0/112", "10.1.0.0/16", false, nil},
		{"nope", "", false, errBadBanTarget},
		{"", "", false, errBadBanTarget},
		{"10.0.0.0/33", "", false, errBadBanTarget},
	}
	for _, c := range cases {
		got, err := parseBanTarget(c.in)
		if c.err != nil {
			if !errors.Is(err, c.err) {
				t.Errorf("%q: got err %v, want %v", c.in, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
			continue
		}
		if got.String() != c.want || got.single != c.single {
			t.Errorf("%q: got %s single=%v, want %s single=%v", c.in, got, got.single, c.want, c.single)
		}
	}
}

func TestAbuse_RangeBanBlocksWholeRange(t *testing.T) {
	r, stats := testRegistry(t, nil)
	now := time.Now()
	p := netip.MustParsePrefix("10.1.0.0/16")

	if err := r.banRange(p, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"10.1.0.1", "10.1.200.5", "10.1.255.255"} {
		if _, banned := r.banned(netip.MustParseAddr(s), now); !banned {
			t.Errorf("%s inside the range is not banned", s)
		}
	}
	for _, s := range []string{"10.2.0.1", "10.0.255.255", "2001:db8::1"} {
		if _, banned := r.banned(netip.MustParseAddr(s), now); banned {
			t.Errorf("%s outside the range is banned", s)
		}
	}
	if stats.abuseBans.Load() != 1 || r.rangeCount() != 1 {
		t.Errorf("bans=%d ranges=%d, want 1 and 1", stats.abuseBans.Load(), r.rangeCount())
	}

	list := r.bans(now)
	if len(list) != 1 || list[0].Client != "10.1.0.0/16" || !list[0].Range {
		t.Fatalf("bans: %+v", list)
	}

	if !r.unbanTarget(banTarget{prefix: p}) {
		t.Fatal("unbanTarget returned false")
	}
	if _, banned := r.banned(netip.MustParseAddr("10.1.200.5"), now); banned {
		t.Error("still banned after unban")
	}
	if r.rangeCount() != 0 {
		t.Errorf("ranges after unban: %d", r.rangeCount())
	}
}

func TestAbuse_RangeBanUpdateIsNotANewOffense(t *testing.T) {
	r, stats := testRegistry(t, nil)
	now := time.Now()
	p := netip.MustParsePrefix("10.1.0.0/16")

	_ = r.banRange(p, time.Hour, now)
	_ = r.banRange(p, 10*time.Minute, now)
	if stats.abuseBans.Load() != 1 {
		t.Errorf("changing an active range ban counted as a new offense: %d", stats.abuseBans.Load())
	}
	if left, _ := r.banned(netip.MustParseAddr("10.1.0.9"), now); left > 10*time.Minute {
		t.Errorf("update should replace the remaining time: %s", left)
	}
}

func TestAbuse_RangeBanSparesExemptAddresses(t *testing.T) {
	r, _ := testRegistry(t, func(c *config) {
		c.abuseAllow = "10.1.5.0/24"
		c.trustedProxies = "10.1.9.9"
	})
	now := time.Now()
	p := netip.MustParsePrefix("10.1.0.0/16")
	_ = r.banRange(p, time.Hour, now)

	for _, s := range []string{"10.1.5.9", "10.1.9.9"} {
		if _, banned := r.banned(netip.MustParseAddr(s), now); banned {
			t.Errorf("exempt %s was banned by the range", s)
		}
	}
	if _, banned := r.banned(netip.MustParseAddr("10.1.6.1"), now); !banned {
		t.Error("non-exempt address inside the range was not banned")
	}
	got := r.exemptWithin(p)
	if len(got) != 2 {
		t.Errorf("exemptWithin: got %v, want both exempt prefixes", got)
	}
}

func TestAbuse_RangeBansExpireAndSweep(t *testing.T) {
	r, _ := testRegistry(t, nil)
	now := time.Now()
	_ = r.banRange(netip.MustParsePrefix("10.1.0.0/16"), time.Minute, now)

	later := now.Add(2 * time.Minute)
	if _, banned := r.banned(netip.MustParseAddr("10.1.0.1"), later); banned {
		t.Error("range ban did not expire")
	}
	if n := r.sweepRanges(later); n != 1 {
		t.Errorf("sweepRanges: %d, want 1", n)
	}
	if r.rangeCount() != 0 {
		t.Errorf("ranges after sweep: %d", r.rangeCount())
	}
}

func TestAbuse_RangeBanLimit(t *testing.T) {
	r, _ := testRegistry(t, nil)
	now := time.Now()
	for i := 0; i < maxRangeBans; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
		if err := r.banRange(p, time.Hour, now); err != nil {
			t.Fatalf("range %d: %v", i, err)
		}
	}
	if err := r.banRange(netip.MustParsePrefix("192.0.2.0/24"), time.Hour, now); !errors.Is(err, errRangeLimit) {
		t.Errorf("over the limit: got %v, want errRangeLimit", err)
	}
}

func TestAbuse_RangeBanEnforcedOnRequests(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.trustedProxies = "127.0.0.1/32"
	a, front := newTestApp(t, cfg, up)

	if err := a.abuse.banRange(netip.MustParsePrefix("198.51.0.0/16"), time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	if resp, body := get(t, front.URL+"/hello", withXFF("198.51.100.4")); !isBlocked(resp, body) {
		t.Errorf("client inside the range: got %d, want blocked", resp.StatusCode)
	}
	if resp, _ := get(t, front.URL+"/hello", withXFF("198.52.0.1")); resp.StatusCode != http.StatusOK {
		t.Errorf("client outside the range: got %d, want 200", resp.StatusCode)
	}
	if resp, _ := get(t, front.URL+"/hello", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("the trusted proxy itself: got %d, want 200", resp.StatusCode)
	}
}

func TestAbuse_AdminUnbanRange(t *testing.T) {
	up := newFakeUpstream(t)
	cfg := testConfig(up.URL())
	cfg.trustedProxies = "127.0.0.1/32"
	cfg.adminToken = "secret"
	a, front := newTestApp(t, cfg, up)
	admin := map[string]string{"Authorization": "Bearer secret"}

	_ = a.abuse.banRange(netip.MustParsePrefix("198.51.0.0/16"), time.Hour, time.Now())

	target := front.URL + "/_room/abuse?client=" + url.QueryEscape("198.51.0.0/16")
	resp, body := doReq(t, testClient, http.MethodDelete, target, admin, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unban range: got %d %s", resp.StatusCode, body)
	}
	if resp, _ := get(t, front.URL+"/hello", withXFF("198.51.100.4")); resp.StatusCode != http.StatusOK {
		t.Errorf("after unbanning the range: got %d, want 200", resp.StatusCode)
	}

	target = front.URL + "/_room/abuse?client=" + url.QueryEscape("10.0.0.0/7")
	if resp, _ := doReq(t, testClient, http.MethodDelete, target, admin, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("too-broad range: got %d, want 400", resp.StatusCode)
	}
}

func TestPortal_BanRange(t *testing.T) {
	cfg := portalTestConfig("http://127.0.0.1:1")
	cfg.abuseAllow = "198.51.5.0/24"
	a, p, _ := newTestPortal(t, cfg, nil)
	ck, csrf := portalLogin(t, p)

	rec := portalDo(p, http.MethodPost, "/api/bans", `{"client":"198.51.7.9/16","duration":"1h"}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("ban range: got %d %s", rec.Code, rec.Body.String())
	}
	v := decodeJSON(t, rec)
	if v["client"] != "198.51.0.0/16" || v["range"] != true {
		t.Errorf("response: %v", v)
	}
	if ex, _ := v["exempt_within"].([]any); len(ex) != 1 || ex[0] != "198.51.5.0/24" {
		t.Errorf("exempt_within: %v", v["exempt_within"])
	}
	if _, banned := a.abuse.banned(netip.MustParseAddr("198.51.200.1"), time.Now()); !banned {
		t.Error("address inside the range is not banned")
	}

	list := decodeJSON(t, portalDo(p, http.MethodGet, "/api/bans", "", ck, "", false))
	bans, _ := list["bans"].([]any)
	if len(bans) != 1 {
		t.Fatalf("bans: %v", list)
	}
	if b, _ := bans[0].(map[string]any); b["range"] != true || b["client"] != "198.51.0.0/16" {
		t.Errorf("listed ban: %v", bans[0])
	}

	if rec := portalDo(p, http.MethodPost, "/api/bans", `{"client":"10.0.0.0/7","duration":"1h"}`, ck, csrf, false); rec.Code != http.StatusBadRequest {
		t.Errorf("too-broad range: got %d, want 400", rec.Code)
	}

	rec = portalDo(p, http.MethodDelete, "/api/bans?client="+url.QueryEscape("198.51.0.0/16"), "", ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("unban range: got %d %s", rec.Code, rec.Body.String())
	}
	if _, banned := a.abuse.banned(netip.MustParseAddr("198.51.200.1"), time.Now()); banned {
		t.Error("still banned after unbanning the range")
	}
}
