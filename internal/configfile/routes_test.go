package configfile

import (
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestRoutesHeadersRedirectsDrop_ConcertfileAndJSONRoundTrip(t *testing.T) {
	src := `
shop.example.com {
    upstream http://127.0.0.1:3000
    cap 50

    drop_event_id summer-drop-2026
    drop_lobby_at 2026-12-01T17:45:00Z
    drop_open_at 2026-12-01T18:00:00Z

    header set X-Frame-Options DENY
    header add Cache-Control "no-store"
    header +Vary Accept-Encoding
    header remove X-Powered-By
    header -Server

    redirect /old-shop /shop
    redirect /legacy/ https://archive.example.com/legacy 301
    redirect /temp-move /v2 307
    redirect /perm-move http://cdn.example.com/v2 308

    route /api/v1/ {
        upstream http://127.0.0.1:4001 http://127.0.0.1:4002
        strip_prefix on
        rate_limit 120/1m:20
        bypass off
        cap 25
        agent_bidding on
    }

    route /php {
        upstream fcgi+unix:///run/php/php8.3-fpm.sock
        rate_limit 30/s
        cap 10
    }

    route {
        path /health
        upstream fcgi://127.0.0.1:9000
        bypass on
    }
}
`
	f, err := ParseConcertfile([]byte(src))
	if err != nil {
		t.Fatalf("ParseConcertfile: %v", err)
	}
	if len(f.Sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(f.Sites))
	}
	s := f.Sites[0]

	// Verify drop schedule fields.
	if s.DropEventID != "summer-drop-2026" ||
		s.DropLobbyAt != "2026-12-01T17:45:00Z" ||
		s.DropOpenAt != "2026-12-01T18:00:00Z" {
		t.Fatalf("unexpected drop schedule: id=%q lobby=%q open=%q", s.DropEventID, s.DropLobbyAt, s.DropOpenAt)
	}

	// Verify headers (both explicit and +/- shorthand).
	wantHeaders := []HeaderRule{
		{Action: HeaderSet, Name: "X-Frame-Options", Value: "DENY"},
		{Action: HeaderAdd, Name: "Cache-Control", Value: "no-store"},
		{Action: HeaderAdd, Name: "Vary", Value: "Accept-Encoding"},
		{Action: HeaderRemove, Name: "X-Powered-By"},
		{Action: HeaderRemove, Name: "Server"},
	}
	if !reflect.DeepEqual(s.Headers, wantHeaders) {
		t.Fatalf("Headers =\n%#v\nwant:\n%#v", s.Headers, wantHeaders)
	}

	// Verify redirects (including default 302 and normalized /legacy/ -> /legacy).
	wantRedirects := []RedirectRule{
		{From: "/old-shop", To: "/shop", Status: 302},
		{From: "/legacy", To: "https://archive.example.com/legacy", Status: 301},
		{From: "/temp-move", To: "/v2", Status: 307},
		{From: "/perm-move", To: "http://cdn.example.com/v2", Status: 308},
	}
	if !reflect.DeepEqual(s.Redirects, wantRedirects) {
		t.Fatalf("Redirects =\n%#v\nwant:\n%#v", s.Redirects, wantRedirects)
	}

	// Verify routes (including normalized /api/v1/ -> /api/v1).
	wantRoutes := []RouteConfig{
		{
			Path:         "/api/v1",
			Upstream:     "http://127.0.0.1:4001,http://127.0.0.1:4002",
			StripPrefix:  true,
			RateLimit:    "120/1m:20",
			Bypass:       false,
			Cap:          25,
			AgentBidding: true,
		},
		{
			Path:      "/php",
			Upstream:  "fcgi+unix:///run/php/php8.3-fpm.sock",
			RateLimit: "30/s",
			Cap:       10,
		},
		{
			Path:     "/health",
			Upstream: "fcgi://127.0.0.1:9000",
			Bypass:   true,
		},
	}
	if !reflect.DeepEqual(s.Routes, wantRoutes) {
		t.Fatalf("Routes =\n%#v\nwant:\n%#v", s.Routes, wantRoutes)
	}

	// FormatConcertfile round-trip preserves all routes, headers, redirects, and drop schedule.
	formatted := FormatConcertfile(f)
	f2, err := ParseConcertfile([]byte(formatted))
	if err != nil {
		t.Fatalf("round-trip FormatConcertfile failed:\n%s\nerr: %v", formatted, err)
	}
	if !reflect.DeepEqual(f2.Sites[0].Routes, wantRoutes) {
		t.Fatalf("round-trip Routes mismatch:\ngot:  %#v\nwant: %#v", f2.Sites[0].Routes, wantRoutes)
	}
	if !reflect.DeepEqual(f2.Sites[0].Headers, wantHeaders) {
		t.Fatalf("round-trip Headers mismatch:\ngot:  %#v\nwant: %#v", f2.Sites[0].Headers, wantHeaders)
	}
	if !reflect.DeepEqual(f2.Sites[0].Redirects, wantRedirects) {
		t.Fatalf("round-trip Redirects mismatch:\ngot:  %#v\nwant: %#v", f2.Sites[0].Redirects, wantRedirects)
	}
	if f2.Sites[0].DropEventID != s.DropEventID ||
		f2.Sites[0].DropLobbyAt != s.DropLobbyAt ||
		f2.Sites[0].DropOpenAt != s.DropOpenAt {
		t.Fatalf("round-trip drop schedule mismatch: %+v", f2.Sites[0])
	}

	// Strict JSON parsing supports all new fields and defaults redirect status to 302.
	jsonCfg := `{
		"sites": [{
			"hosts": ["json.example.com"],
			"upstream": "http://127.0.0.1:8080",
			"drop_event_id": "json-drop",
			"drop_lobby_at": "2026-12-01T17:45:00+02:00",
			"drop_open_at": "2026-12-01T18:00:00+02:00",
			"headers": [
				{"action": "set", "name": "X-Content-Type-Options", "value": "nosniff"},
				{"action": "remove", "name": "Server"}
			],
			"redirects": [
				{"from": "/a/", "to": "/b"}
			],
			"routes": [
				{"path": "/api/", "upstream": "https://origin.example.com", "strip_prefix": true, "rate_limit": "60/1m", "cap": 15, "agent_bidding": true}
			]
		}]
	}`
	jf, err := ParseJSON([]byte(jsonCfg))
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	js := jf.Sites[0]
	if js.Routes[0].Path != "/api" || !js.Routes[0].AgentBidding || js.Routes[0].Cap != 15 {
		t.Fatalf("unexpected JSON route: %+v", js.Routes[0])
	}
	if js.Redirects[0].From != "/a" || js.Redirects[0].Status != 302 {
		t.Fatalf("unexpected JSON redirect: %+v", js.Redirects[0])
	}
	if js.Headers[0].Action != HeaderSet || js.Headers[1].Action != HeaderRemove {
		t.Fatalf("unexpected JSON headers: %+v", js.Headers)
	}
}

func TestRoutesValidation_Errors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "missing path",
			src:  "a.com { route { upstream http://127.0.0.1:3000 } }",
			want: "path must not be empty",
		},
		{
			name: "path without leading slash",
			src:  "a.com { route api { upstream http://127.0.0.1:3000 } }",
			want: "path must start with /",
		},
		{
			name: "duplicate route paths after normalization",
			src: `a.com {
				route /api { upstream http://127.0.0.1:3001 }
				route /api/ { upstream http://127.0.0.1:3002 }
			}`,
			want: "duplicate route path",
		},
		{
			name: "invalid upstream scheme",
			src:  "a.com { route /api { upstream ftp://127.0.0.1:21 } }",
			want: "must use http://, https://, fcgi://, or fcgi+unix://",
		},
		{
			name: "http upstream missing host",
			src:  "a.com { route /api { upstream http:// } }",
			want: "must include host",
		},
		{
			name: "fcgi+unix non-absolute socket",
			src:  "a.com { route /api { upstream fcgi+unix://relative/php.sock } }",
			want: "expected fcgi+unix:///absolute/socket.sock",
		},
		{
			name: "invalid rate_limit missing slash",
			src:  "a.com { route /api { rate_limit 100 } }",
			want: "expected <count>/<duration>",
		},
		{
			name: "invalid rate_limit zero count",
			src:  "a.com { route /api { rate_limit 0/1m } }",
			want: "invalid count",
		},
		{
			name: "invalid rate_limit bad duration",
			src:  "a.com { route /api { rate_limit 10/bogus } }",
			want: "invalid duration",
		},
		{
			name: "negative route cap",
			src:  "a.com { route /api { cap -5 } }",
			want: "cap must not be negative",
		},
		{
			name: "int32 overflow route cap",
			src:  "a.com { route /api { cap 999999999999 } }",
			want: "invalid int32",
		},
		{
			name: "unknown route directive",
			src:  "a.com { route /api { bogus on } }",
			want: "unknown route directive",
		},
		{
			name: "unclosed route block",
			src:  "a.com { route /api { cap 10 }",
			want: "unclosed site block",
		},
		{
			name: "conflicting route path inside block",
			src:  "a.com { route /api { path /v2 } }",
			want: "route path already set",
		},
		{
			name: "missing brace after route path",
			src:  "a.com { route /api cap 5 }",
			want: "expects '{'",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseConcertfile([]byte(tc.src)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseConcertfile err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestHeadersValidation_SecurityAndSyntax(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "CRLF injection in value via escaped newline",
			src:  `a.com { header set X-Test "ok\nX-Injected: evil" }`,
			want: "must not contain CR or LF",
		},
		{
			name: "invalid RFC 7230 token name with space",
			src:  `a.com { header set "Bad Name" value }`,
			want: "RFC 7230 token",
		},
		{
			name: "invalid RFC 7230 token name with colon",
			src:  `a.com { header set "X-Bad:Header" value }`,
			want: "RFC 7230 token",
		},
		{
			name: "forbidden Host header",
			src:  `a.com { header set Host evil.example.com }`,
			want: "forbidden",
		},
		{
			name: "forbidden Transfer-Encoding header",
			src:  `a.com { header set transfer-encoding chunked }`,
			want: "forbidden",
		},
		{
			name: "forbidden Content-Length header",
			src:  `a.com { header add Content-Length 0 }`,
			want: "forbidden",
		},
		{
			name: "forbidden Set-Cookie header",
			src:  `a.com { header set Set-Cookie "sid=1" }`,
			want: "forbidden",
		},
		{
			name: "forbidden Set-Cookie removal",
			src:  `a.com { header -Set-Cookie }`,
			want: "forbidden",
		},
		{
			name: "forbidden Connection hop-by-hop",
			src:  `a.com { header set Connection close }`,
			want: "forbidden",
		},
		{
			name: "invalid header action",
			src:  `a.com { header replace X-Foo bar }`,
			want: "invalid header action",
		},
		{
			name: "header set missing value",
			src:  `a.com { header set X-Foo }`,
			want: "expects <Name> <Value>",
		},
		{
			name: "header remove with value",
			src:  `a.com { header remove X-Foo bar }`,
			want: "expects <Name>",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseConcertfile([]byte(tc.src)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseConcertfile err = %v, want substring %q", err, tc.want)
			}
		})
	}

	// JSON-specific CR/LF and remove-with-value rejections.
	jsonBad := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "json CRLF in header value",
			raw:  `{"sites":[{"hosts":["a.com"],"headers":[{"action":"set","name":"X-A","value":"ok\r\nEvil: 1"}]}]}`,
			want: "must not contain CR or LF",
		},
		{
			name: "json CRLF in header name",
			raw:  `{"sites":[{"hosts":["a.com"],"headers":[{"action":"set","name":"X-A\r\n","value":"ok"}]}]}`,
			want: "RFC 7230 token",
		},
		{
			name: "json remove with non-empty value",
			raw:  `{"sites":[{"hosts":["a.com"],"headers":[{"action":"remove","name":"Server","value":"nginx"}]}]}`,
			want: "must not specify a value",
		},
	}
	for _, tc := range jsonBad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseJSON([]byte(tc.raw)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseJSON err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestRedirectsValidation_SecurityAndSyntax(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "from without leading slash",
			src:  "a.com { redirect old /new }",
			want: "path must start with /",
		},
		{
			name: "duplicate redirect from",
			src:  "a.com { redirect /old /a\nredirect /old/ /b }",
			want: "duplicate redirect from path",
		},
		{
			name: "reject javascript scheme",
			src:  `a.com { redirect /xss "javascript:alert(1)" 302 }`,
			want: "unsupported scheme",
		},
		{
			name: "reject uppercase JAVASCRIPT scheme",
			src:  `a.com { redirect /xss "JAVASCRIPT:void(0)" }`,
			want: "unsupported scheme",
		},
		{
			name: "reject data scheme",
			src:  `a.com { redirect /data "data:text/html,<h1>x</h1>" 301 }`,
			want: "unsupported scheme",
		},
		{
			name: "reject protocol-relative open redirect",
			src:  `a.com { redirect /open //evil.example.com/phish }`,
			want: "must not start with //",
		},
		{
			name: "reject backslash open redirect",
			src:  `a.com { redirect /open "/\\evil.example.com" }`,
			want: "must not start with //",
		},
		{
			name: "reject CRLF in redirect target",
			src:  `a.com { redirect /inj "/ok\nSet-Cookie: evil=1" }`,
			want: "must not contain CR or LF",
		},
		{
			name: "reject unsupported status 200",
			src:  `a.com { redirect /a /b 200 }`,
			want: "unsupported redirect status",
		},
		{
			name: "reject unsupported status 303",
			src:  `a.com { redirect /a /b 303 }`,
			want: "unsupported redirect status",
		},
		{
			name: "reject non-numeric status",
			src:  `a.com { redirect /a /b permanent }`,
			want: "invalid status",
		},
		{
			name: "reject missing target",
			src:  `a.com { redirect /a }`,
			want: "expects <from> <to>",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseConcertfile([]byte(tc.src)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseConcertfile err = %v, want substring %q", err, tc.want)
			}
		})
	}

	// JSON CRLF in redirect target.
	raw := `{"sites":[{"hosts":["a.com"],"redirects":[{"from":"/a","to":"https://example.com/\r\nX-Bad: 1","status":302}]}]}`
	if _, err := ParseJSON([]byte(raw)); err == nil || !strings.Contains(err.Error(), "must not contain CR or LF") {
		t.Fatalf("ParseJSON CRLF redirect err = %v, want CR/LF rejection", err)
	}
}

func TestDropScheduleValidation(t *testing.T) {
	// Partial valid schedules (only lobby_at or only open_at or only event_id) are allowed.
	validCases := []string{
		`a.com { drop_event_id drop-1 }`,
		`a.com { drop_lobby_at 2026-12-01T17:45:00Z }`,
		`a.com { drop_open_at 2026-12-01T18:00:00Z }`,
		`a.com { drop_lobby_at 2026-12-01T17:45:00-05:00; drop_open_at 2026-12-01T23:00:00Z }`,
	}
	for _, src := range validCases {
		if _, err := ParseConcertfile([]byte(src)); err != nil {
			t.Errorf("ParseConcertfile(%q) unexpected error: %v", src, err)
		}
	}

	badCases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "invalid drop_lobby_at format",
			src:  `a.com { drop_lobby_at 2026-12-01 }`,
			want: "invalid drop_lobby_at",
		},
		{
			name: "invalid drop_open_at format",
			src:  `a.com { drop_open_at not-a-time }`,
			want: "invalid drop_open_at",
		},
		{
			name: "drop_open_at equal to drop_lobby_at",
			src:  `a.com { drop_lobby_at 2026-12-01T18:00:00Z; drop_open_at 2026-12-01T18:00:00Z }`,
			want: "strictly after drop_lobby_at",
		},
		{
			name: "drop_open_at before drop_lobby_at",
			src:  `a.com { drop_lobby_at 2026-12-01T18:15:00Z; drop_open_at 2026-12-01T18:00:00Z }`,
			want: "strictly after drop_lobby_at",
		},
		{
			name: "drop_open_at before drop_lobby_at across timezones",
			src:  `a.com { drop_lobby_at 2026-12-01T18:00:00Z; drop_open_at 2026-12-01T19:00:00+02:00 }`,
			want: "strictly after drop_lobby_at",
		},
		{
			name: "whitespace drop_event_id",
			src:  `a.com { drop_event_id "   " }`,
			want: "drop_event_id must not be whitespace",
		},
		{
			name: "control char in drop_event_id",
			src:  `a.com { drop_event_id "drop\n1" }`,
			want: "control characters",
		},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseConcertfile([]byte(tc.src)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseConcertfile err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestParseConcertfile_ConcurrentRace(t *testing.T) {
	src := []byte(`
drop.example.com {
    upstream http://127.0.0.1:3000
    drop_event_id tour-2026
    drop_lobby_at 2026-12-01T17:45:00Z
    drop_open_at 2026-12-01T18:00:00Z
    header set X-Frame-Options DENY
    header -Server
    redirect /old /new 301
    route /api {
        upstream http://127.0.0.1:4000
        strip_prefix on
        rate_limit 60/1m
        cap 20
        agent_bidding on
    }
}
`)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			<-start
			for range 25 {
				f, err := ParseConcertfile(src)
				if err != nil {
					t.Errorf("ParseConcertfile: %v", err)
					return
				}
				out := FormatConcertfile(f)
				if _, err := ParseConcertfile([]byte(out)); err != nil {
					t.Errorf("FormatConcertfile round-trip: %v", err)
					return
				}
			}
		})
	}
	close(start)
	wg.Wait()
}
