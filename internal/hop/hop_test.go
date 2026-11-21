package hop

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var (
	secretA = []byte("0123456789abcdef0123456789abcdef-a")
	secretB = []byte("0123456789abcdef0123456789abcdef-b")
)

func fixedSigner(t *testing.T, secret []byte, at time.Time) *Signer {
	t.Helper()
	s, err := NewSigner(secret, "edge-1")
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return at }
	return s
}

func fixedVerifier(t *testing.T, at time.Time, secrets ...[]byte) *Verifier {
	t.Helper()
	v, err := NewVerifier(0, secrets...)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return at }
	return v
}

func sampleClaim() Claim {
	return Claim{
		Client: netip.MustParseAddr("203.0.113.9"),
		Rank:   5,
		Paid:   true,
		Class:  ClassPage,
		Proto:  "h2",
	}
}

func TestRoundTrip(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_123)
	h := fixedSigner(t, secretA, now).Sign(sampleClaim(), "GET", "/shop?q=1", "")
	c, err := fixedVerifier(t, now, secretA).Verify(h, "GET", "/shop?q=1", "")
	if err != nil {
		t.Fatalf("verify: %v (header %q)", err, h)
	}
	want := sampleClaim()
	want.Edge, want.Issued = "edge-1", now
	if c != want {
		t.Fatalf("claim = %+v, want %+v", c, want)
	}
}

func TestEveryClassAndProtoRoundTrips(t *testing.T) {
	now := time.Now()
	s, v := fixedSigner(t, secretA, now), fixedVerifier(t, now, secretA)
	for _, k := range []Class{ClassPage, ClassAsset, ClassStream, ClassBypass, ClassControl} {
		for _, p := range []string{"", "h1", "h2"} {
			for r := uint8(0); r <= maxRank; r++ {
				c := Claim{Client: netip.MustParseAddr("2001:db8::7"), Rank: r, Class: k, Proto: p}
				got, err := v.Verify(s.Sign(c, "POST", "/x", ""), "POST", "/x", "")
				if err != nil || got.Class != k || got.Proto != p || got.Rank != r {
					t.Fatalf("class %s proto %q rank %d: %+v, %v", k, p, r, got, err)
				}
			}
		}
	}
}

// The signature binds the method, the URI and the body digest.
func TestBindings(t *testing.T) {
	now := time.Now()
	h := fixedSigner(t, secretA, now).Sign(sampleClaim(), "GET", "/a", "")
	v := fixedVerifier(t, now, secretA)
	cases := []struct{ method, uri, body string }{
		{"POST", "/a", ""},
		{"GET", "/b", ""},
		{"GET", "/a?x=1", ""},
		{"GET", "/a", BodyHash([]byte("x"))},
		{"get", "/a", ""},
	}
	for _, tc := range cases {
		if _, err := v.Verify(h, tc.method, tc.uri, tc.body); !errors.Is(err, ErrSignature) {
			t.Errorf("%s %s %q: err = %v, want ErrSignature", tc.method, tc.uri, tc.body, err)
		}
	}
}

// Changing any field invalidates the signature, even when the result still
// parses. A client cannot raise its own rank or claim to have paid.
func TestTamper(t *testing.T) {
	now := time.Now()
	h := fixedSigner(t, secretA, now).Sign(sampleClaim(), "GET", "/", "")
	v := fixedVerifier(t, now, secretA)
	edits := []struct{ from, to string }{
		{";r=5;", ";r=6;"},
		{";f=1;", ";f=0;"},
		{";k=page;", ";k=asset;"},
		{";p=h2;", ";p=h1;"},
		{";c=203.0.113.9;", ";c=203.0.113.8;"},
		{"e=edge-1;", "e=edge-2;"},
	}
	for _, e := range edits {
		if !strings.Contains(h, e.from) {
			t.Fatalf("header %q lacks %q", h, e.from)
		}
		bad := strings.Replace(h, e.from, e.to, 1)
		if _, err := v.Verify(bad, "GET", "/", ""); !errors.Is(err, ErrSignature) {
			t.Errorf("%s -> %s: err = %v, want ErrSignature", e.from, e.to, err)
		}
	}
	// Flip one signature bit.
	i := strings.LastIndex(h, ";s=") + 4
	b := []byte(h)
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	if _, err := v.Verify(string(b), "GET", "/", ""); err == nil {
		t.Error("flipped signature verified")
	}
}

func TestWrongSecret(t *testing.T) {
	now := time.Now()
	h := fixedSigner(t, secretA, now).Sign(sampleClaim(), "GET", "/", "")
	if _, err := fixedVerifier(t, now, secretB).Verify(h, "GET", "/", ""); !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

// During a rotation a leaf accepts the old and the new secret.
func TestRotation(t *testing.T) {
	now := time.Now()
	v := fixedVerifier(t, now, secretB, secretA)
	for _, s := range [][]byte{secretA, secretB} {
		h := fixedSigner(t, s, now).Sign(sampleClaim(), "GET", "/", "")
		if _, err := v.Verify(h, "GET", "/", ""); err != nil {
			t.Fatalf("rotation: %v", err)
		}
	}
}

func TestSkew(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000)
	s := fixedSigner(t, secretA, now)
	h := s.Sign(sampleClaim(), "GET", "/", "")
	for _, d := range []time.Duration{-DefaultMaxSkew, 0, DefaultMaxSkew} {
		if _, err := fixedVerifier(t, now.Add(d), secretA).Verify(h, "GET", "/", ""); err != nil {
			t.Errorf("skew %s: %v", d, err)
		}
	}
	for _, d := range []time.Duration{-DefaultMaxSkew - time.Millisecond, DefaultMaxSkew + time.Millisecond, time.Hour} {
		if _, err := fixedVerifier(t, now.Add(d), secretA).Verify(h, "GET", "/", ""); !errors.Is(err, ErrSkew) {
			t.Errorf("skew %s: err = %v, want ErrSkew", d, err)
		}
	}
}

func TestMalformed(t *testing.T) {
	now := time.Now()
	good := fixedSigner(t, secretA, now).Sign(sampleClaim(), "GET", "/", "")
	sig := good[strings.LastIndex(good, ";s="):]
	v := fixedVerifier(t, now, secretA)
	cases := []string{
		"garbage",
		";s=",
		"v=1" + sig,
		strings.Replace(good, "v=1;", "v=2;", 1),
		strings.Replace(good, ";r=5;", ";r=8;", 1),
		strings.Replace(good, ";r=5;", ";r=05;", 1),
		strings.Replace(good, ";r=5;", ";r=-1;", 1),
		strings.Replace(good, ";f=1;", ";f=yes;", 1),
		strings.Replace(good, ";k=page;", ";k=admin;", 1),
		strings.Replace(good, ";p=h2;", ";p=h3;", 1),
		strings.Replace(good, ";c=203.0.113.9;", ";c=not-an-ip;", 1),
		strings.Replace(good, ";c=203.0.113.9;", ";c=fe80::1%eth0;", 1),
		strings.Replace(good, "e=edge-1;", "e=;", 1),
		strings.Replace(good, "e=edge-1;", "e=edge/1;", 1),
		strings.Replace(good, ";t=", ";t=-", 1),
		strings.Replace(good, ";p=h2;", ";p=h2;x=1;", 1),
		strings.Replace(good, "v=1;e=", "e=", 1),
		good[:len(good)-2],
		good + "A",
		strings.Repeat("a", maxHeaderLen+1),
	}
	for _, h := range cases {
		if _, err := v.Verify(h, "GET", "/", ""); !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrSignature) {
			t.Errorf("%q: err = %v, want ErrMalformed or ErrSignature", h, err)
		}
	}
	if _, err := v.Verify("", "GET", "/", ""); !errors.Is(err, ErrMissing) {
		t.Errorf("empty: err = %v, want ErrMissing", err)
	}
}

// A non-canonical but parseable IPv6 spelling must not verify: two
// encodings of one claim never both pass.
func TestCanonicalClientOnly(t *testing.T) {
	now := time.Now()
	c := sampleClaim()
	c.Client = netip.MustParseAddr("2001:db8::1")
	h := fixedSigner(t, secretA, now).Sign(c, "GET", "/", "")
	alt := strings.Replace(h, ";c=2001:db8::1;", ";c=2001:0db8:0:0:0:0:0:1;", 1)
	if alt == h {
		t.Fatal("replacement did not apply")
	}
	if _, err := fixedVerifier(t, now, secretA).Verify(alt, "GET", "/", ""); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestConstructors(t *testing.T) {
	if _, err := NewSigner([]byte("short"), "edge"); err == nil {
		t.Error("short secret accepted by NewSigner")
	}
	for _, id := range []string{"", "has space", strings.Repeat("x", 33), "a;b", "ü"} {
		if _, err := NewSigner(secretA, id); err == nil {
			t.Errorf("node id %q accepted", id)
		}
	}
	if _, err := NewVerifier(0); err == nil {
		t.Error("verifier without secrets accepted")
	}
	if _, err := NewVerifier(0, []byte("short")); err == nil {
		t.Error("short secret accepted by NewVerifier")
	}
	if _, err := NewVerifier(0, nil, secretA); err != nil {
		t.Errorf("empty previous secret should be ignored: %v", err)
	}
}

func TestBanVersionIsOrderIndependentAndSensitive(t *testing.T) {
	until := time.Unix(1_800_000_000, 0)
	a := []Ban{{Client: "203.0.113.9", Until: until}, {Client: "10.0.0.0/8", Range: true, Permanent: true}}
	b := []Ban{a[1], a[0]}
	if BanVersion(a) != BanVersion(b) {
		t.Fatal("order changed the version")
	}
	// Sub-second differences must not change it.
	c := []Ban{{Client: "203.0.113.9", Until: until.Add(400 * time.Millisecond)}, a[1]}
	if BanVersion(a) != BanVersion(c) {
		t.Fatal("sub-second until changed the version")
	}
	d := []Ban{{Client: "203.0.113.9", Until: until.Add(time.Minute)}, a[1]}
	if BanVersion(a) == BanVersion(d) {
		t.Fatal("a longer ban kept the version")
	}
	if BanVersion(nil) != BanVersion([]Ban{}) {
		t.Fatal("nil and empty differ")
	}
}

func TestShare(t *testing.T) {
	cases := []struct {
		s    LeafState
		want int
	}{
		{LeafState{HostCap: 100, EdgesSeen: 0}, 100},
		{LeafState{HostCap: 100, EdgesSeen: 1}, 100},
		{LeafState{HostCap: 100, EdgesSeen: 3}, 33},
		{LeafState{HostCap: 2, EdgesSeen: 5}, 1},
		{LeafState{HostCap: 0, EdgesSeen: 1}, 0},
	}
	for _, tc := range cases {
		if got := tc.s.Share(); got != tc.want {
			t.Errorf("%+v: share %d, want %d", tc.s, got, tc.want)
		}
	}
}

func FuzzVerify(f *testing.F) {
	now := time.UnixMilli(1_800_000_000_000)
	s, _ := NewSigner(secretA, "edge-1")
	s.now = func() time.Time { return now }
	f.Add(s.Sign(sampleClaim(), "GET", "/", ""))
	f.Add("v=1;e=a;t=1;c=::1;r=0;f=0;k=page;p=;s=")
	f.Add("")
	v, _ := NewVerifier(0, secretA)
	v.now = func() time.Time { return now }
	f.Fuzz(func(t *testing.T, h string) {
		c, err := v.Verify(h, "GET", "/", "")
		if err == nil && (c.Edge != "edge-1" || !c.Client.IsValid()) {
			t.Fatalf("accepted forged claim %+v from %q", c, h)
		}
	})
}

func BenchmarkVerify(b *testing.B) {
	s, _ := NewSigner(secretA, "edge-1")
	v, _ := NewVerifier(0, secretA)
	h := s.Sign(sampleClaim(), "GET", "/products/42?ref=home", "")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := v.Verify(h, "GET", "/products/42?ref=home", ""); err != nil {
			b.Fatal(err)
		}
	}
}
