package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// TLS configuration for both the main listener and the admin portal.
//
// Concert supports two mutually exclusive TLS modes on the main listener:
//  1. Enterprise PEM certificate files (-tls-cert and -tls-key), hot-reloaded
//     automatically when the files on disk change (cert-manager, Vault PKI, etc.).
//  2. Let's Encrypt ACME (-tls-domains) via TLS-ALPN-01.
//
// The admin portal supports PEM certificate files via -portal-tls-cert and
// -portal-tls-key, also hot-reloaded automatically.
//
// All TLS listeners enforce modern AEAD cipher suites and TLS 1.2+ (or TLS 1.3
// when -tls-min-version=1.3).

const letsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

// strongCipherSuites lists AEAD-only TLS 1.2 cipher suites with forward secrecy.
// TLS 1.3 cipher suites are managed by Go's crypto/tls automatically.
var strongCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

func parseTLSMinVersion(spec string) (uint16, error) {
	switch strings.TrimSpace(spec) {
	case "", "1.2", "tls1.2", "TLS1.2":
		return tls.VersionTLS12, nil
	case "1.3", "tls1.3", "TLS1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("invalid -tls-min-version %q: must be 1.2 or 1.3", spec)
	}
}

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

// certReloader caches a PEM keypair and transparently reloads it when either
// file's modification time changes (at most once per 5 seconds).
type certReloader struct {
	certFile string
	keyFile  string

	mu        sync.RWMutex
	cert      *tls.Certificate
	certMtime time.Time
	keyMtime  time.Time
	lastCheck time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	cr := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := cr.reload(); err != nil {
		return nil, err
	}
	return cr, nil
}

func (cr *certReloader) reload() error {
	cert, err := tls.LoadX509KeyPair(cr.certFile, cr.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate (%s, %s): %w", cr.certFile, cr.keyFile, err)
	}
	ci, err := os.Stat(cr.certFile)
	if err != nil {
		return err
	}
	ki, err := os.Stat(cr.keyFile)
	if err != nil {
		return err
	}
	cr.mu.Lock()
	cr.cert = &cert
	cr.certMtime = ci.ModTime()
	cr.keyMtime = ki.ModTime()
	cr.lastCheck = time.Now()
	cr.mu.Unlock()
	return nil
}

func (cr *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	now := time.Now()
	cr.mu.RLock()
	cert := cr.cert
	needCheck := now.Sub(cr.lastCheck) >= 5*time.Second
	cm, km := cr.certMtime, cr.keyMtime
	cr.mu.RUnlock()

	if !needCheck {
		return cert, nil
	}

	ci, err1 := os.Stat(cr.certFile)
	ki, err2 := os.Stat(cr.keyFile)
	if err1 == nil && err2 == nil && (ci.ModTime().After(cm) || ki.ModTime().After(km)) {
		if err := cr.reload(); err == nil {
			cr.mu.RLock()
			cert = cr.cert
			cr.mu.RUnlock()
			return cert, nil
		}
	} else {
		cr.mu.Lock()
		cr.lastCheck = now
		cr.mu.Unlock()
	}
	return cert, nil
}

// newPEMTLSConfig builds a TLS configuration backed by hot-reloading PEM files.
func newPEMTLSConfig(certFile, keyFile, minVerSpec string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("both TLS certificate and key paths must be set")
	}
	minVer, err := parseTLSMinVersion(minVerSpec)
	if err != nil {
		return nil, err
	}
	reloader, err := newCertReloader(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:     minVer,
		CipherSuites:   strongCipherSuites,
		NextProtos:     []string{"h2", "http/1.1"},
		GetCertificate: reloader.getCertificate,
	}, nil
}

// newACMETLSConfig returns the TLS config for the main listener (custom PEM
// certificate files or Let's Encrypt ACME), or nil when TLS is disabled.
func newACMETLSConfig(cfg config) (*tls.Config, error) {
	if cfg.tlsCert != "" || cfg.tlsKey != "" {
		if len(cfg.tlsHosts) > 0 {
			return nil, errors.New("-tls-cert/-tls-key cannot be combined with -tls-domains")
		}
		return newPEMTLSConfig(cfg.tlsCert, cfg.tlsKey, cfg.tlsMinVersion)
	}
	if len(cfg.tlsHosts) == 0 {
		return nil, nil
	}
	if err := ensureWritableDir(cfg.tlsCacheDir); err != nil {
		return nil, err
	}
	minVer, err := parseTLSMinVersion(cfg.tlsMinVersion)
	if err != nil {
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
	tc.MinVersion = minVer
	tc.CipherSuites = strongCipherSuites
	return tc, nil
}

func newPortalTLSConfig(cfg config) (*tls.Config, error) {
	return newPEMTLSConfig(cfg.portal.tlsCert, cfg.portal.tlsKey, cfg.tlsMinVersion)
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
