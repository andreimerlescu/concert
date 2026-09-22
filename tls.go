package main

import (
	"crypto/tls"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Let's Encrypt support. When -tls-domains lists at least one hostname,
// concert serves -listen over TLS and obtains and renews certificates itself
// through the TLS-ALPN-01 challenge on that same listener. No port 80
// listener and no certbot are needed, but -listen must be reachable from the
// internet on 443 for issuance to succeed.
//
// With TLS terminated here, concert sees the client's real protocol, so
// -client-proto-header is unnecessary and the HTTP/2 asset rule applies on
// its own. Set -secure-cookie too, since browsers now reach concert over
// HTTPS.

const letsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

// parseTLSDomains reads "example.com, www.example.com" style lists. Names are
// lowercased, a trailing dot is dropped, and duplicates are removed. Schemes,
// ports, wildcards and IP addresses are rejected: TLS-ALPN-01 validates one
// concrete hostname at a time.
func parseTLSDomains(spec string) ([]string, error) {
	var hosts []string
	seen := map[string]bool{}
	for _, part := range strings.Split(spec, ",") {
		h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(part)), ".")
		if h == "" {
			continue
		}
		if strings.ContainsAny(h, "/:*@ \t") {
			return nil, fmt.Errorf("%q: list bare hostnames such as example.com, without scheme, port or wildcard", strings.TrimSpace(part))
		}
		if _, err := netip.ParseAddr(h); err == nil {
			return nil, fmt.Errorf("%q: certificates are issued for hostnames, not IP addresses", h)
		}
		if !strings.Contains(h, ".") {
			return nil, fmt.Errorf("%q: not a fully qualified hostname", h)
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// newACMETLSConfig returns the TLS config for the main listener, or nil when
// -tls-domains is empty. The certificate cache is checked here so a bad path
// fails at startup instead of during the first handshake.
func newACMETLSConfig(cfg config) (*tls.Config, error) {
	if len(cfg.tlsHosts) == 0 {
		return nil, nil
	}
	if err := ensureWritableDir(cfg.tlsCacheDir); err != nil {
		return nil, err
	}

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.tlsHosts...),
		Cache:      autocert.DirCache(cfg.tlsCacheDir),
		Email:      cfg.tlsEmail,
	}
	if cfg.tlsStaging {
		m.Client = &acme.Client{DirectoryURL: letsEncryptStagingURL}
	}

	// TLSConfig advertises h2, http/1.1 and acme-tls/1, and answers
	// TLS-ALPN-01 challenges during the handshake.
	tc := m.TLSConfig()
	tc.MinVersion = tls.VersionTLS12
	return tc, nil
}

// ensureWritableDir creates dir when missing and proves it is writable by
// creating and removing a probe file.
func ensureWritableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("tls cache %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".concert-probe-*")
	if err != nil {
		return fmt.Errorf("tls cache %s is not writable: %w", dir, err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}
