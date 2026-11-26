package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	concertacme "github.com/andreimerlescu/concert/internal/acme"
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
	return parseTLSDomainsMode(spec, false)
}

// parseTLSDomainsMode parses comma-separated TLS hostnames and, when
// allowWildcard is true (ACME DNS-01 mode), permits RFC 6125 single-label
// wildcard patterns such as "*.example.com".
func parseTLSDomainsMode(spec string, allowWildcard bool) ([]string, error) {
	var hosts []string
	seen := map[string]bool{}
	for _, part := range strings.Split(spec, ",") {
		h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(part)), ".")
		if h == "" {
			continue
		}
		wildcard := false
		checkHost := h
		if allowWildcard && strings.HasPrefix(h, "*.") {
			wildcard = true
			checkHost = strings.TrimPrefix(h, "*.")
			if checkHost == "" || !strings.Contains(checkHost, ".") {
				return nil, fmt.Errorf("%q: wildcard hostname must look like *.example.com", strings.TrimSpace(part))
			}
		}
		if strings.ContainsAny(checkHost, "/:*@ \t") {
			if allowWildcard {
				return nil, fmt.Errorf("%q: list bare hostnames or single-label wildcards such as *.example.com", strings.TrimSpace(part))
			}
			return nil, fmt.Errorf("%q: list bare hostnames such as example.com, without scheme, port or wildcard", strings.TrimSpace(part))
		}
		if _, err := netip.ParseAddr(checkHost); err == nil {
			return nil, fmt.Errorf("%q: certificates are issued for hostnames, not IP addresses", h)
		}
		if !strings.Contains(checkHost, ".") {
			return nil, fmt.Errorf("%q: not a fully qualified hostname", h)
		}
		if wildcard {
			h = "*." + checkHost
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// matchHostPattern reports whether host matches pattern (either exact equality
// or RFC 6125 single-label wildcard "*.example.com").
func matchHostPattern(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		label, rest, ok := strings.Cut(host, ".")
		return ok && label != "" && rest == suffix && !strings.Contains(label, ".")
	}
	return false
}

// buildDNS01Manager constructs an internal/acme.Manager for wildcard/exact
// DNS-01 certificate issuance using Cloudflare or Webhook DNS providers and
// optional AES-256-GCM encrypted KV certificate sync.
func buildDNS01Manager(cfg config, domains []string, kvSync concertacme.KVBundleSync) (*concertacme.Manager, error) {
	if err := ensureWritableDir(cfg.tlsCacheDir); err != nil {
		return nil, err
	}
	var provider concertacme.DNSProvider
	var err error
	switch strings.ToLower(strings.TrimSpace(cfg.tlsDNSProvider)) {
	case "cloudflare":
		provider, err = concertacme.NewCloudflareProvider(concertacme.CloudflareConfig{
			APIToken: cfg.dnsAPIToken,
		})
	case "webhook":
		provider, err = concertacme.NewWebhookProvider(concertacme.WebhookConfig{
			Endpoint:    cfg.tlsDNSWebhookURL,
			BearerToken: cfg.dnsWebhookToken,
		})
	default:
		return nil, fmt.Errorf("unsupported -tls-dns-provider %q", cfg.tlsDNSProvider)
	}
	if err != nil {
		return nil, err
	}

	acmeCfg := concertacme.Config{
		Domains:  domains,
		Email:    cfg.tlsEmail,
		CacheDir: cfg.tlsCacheDir,
		Provider: provider,
	}
	if cfg.tlsStaging {
		acmeCfg.DirectoryURL = letsEncryptStagingURL
	}
	if kvSync != nil && len(cfg.admitSecret) > 0 {
		acmeCfg.KVSync = kvSync
		acmeCfg.KVSecret = concertacme.NewSecretBytes(cfg.admitSecret)
		if pfx := cfg.effectiveKVPrefix(); pfx != "" {
			acmeCfg.KVKeyPrefix = pfx + ":acme:cert:"
		}
	}
	return concertacme.NewManager(acmeCfg)
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

// applyClientCA attaches a client CA pool to tc when caFile is set.
// By default it uses tls.VerifyClientCertIfGiven so public browsers can still
// visit the listener over HTTPS while edge Concert peers presenting client
// certificates are cryptographically authenticated (see -hop-require-mtls).
// Setting requireAll upgrades ClientAuth to tls.RequireAndVerifyClientCert.
func applyClientCA(tc *tls.Config, caFile string, requireAll bool) error {
	caFile = strings.TrimSpace(caFile)
	if caFile == "" {
		return nil
	}
	pemData, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("read -tls-client-ca %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return fmt.Errorf("invalid PEM certificates in -tls-client-ca %s", caFile)
	}
	tc.ClientCAs = pool
	if requireAll {
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		tc.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return nil
}

// newACMETLSConfig returns the TLS config for the main listener (custom PEM
// certificate files or Let's Encrypt ACME), or nil when TLS is disabled.
func newACMETLSConfig(cfg config) (*tls.Config, error) {
	tc, _, closeFn, err := newACMETLSConfigWithLifecycle(context.Background(), cfg, nil)
	if closeFn != nil {
		closeFn()
	}
	return tc, err
}

// newACMETLSConfigWithManager returns both the listener *tls.Config and, when
// Let's Encrypt ACME (-tls-domains) is enabled without DNS-01, the
// *autocert.Manager so a companion -tls-http-listen (:80) server can answer
// ACME HTTP-01 challenges.
func newACMETLSConfigWithManager(cfg config) (*tls.Config, *autocert.Manager, error) {
	tc, mgr, closeFn, err := newACMETLSConfigWithLifecycle(context.Background(), cfg, nil)
	if closeFn != nil {
		closeFn()
	}
	return tc, mgr, err
}

// newACMETLSConfigWithLifecycle returns the listener *tls.Config, optional
// *autocert.Manager (for HTTP-01/TLS-ALPN-01), and optional lifecycle closer
// (for internal/acme.Manager DNS-01 background renewal loop, R2).
func newACMETLSConfigWithLifecycle(ctx context.Context, cfg config, kvSync concertacme.KVBundleSync) (*tls.Config, *autocert.Manager, func(), error) {
	if cfg.tlsCert != "" || cfg.tlsKey != "" {
		if len(cfg.tlsHosts) > 0 {
			return nil, nil, nil, errors.New("-tls-cert/-tls-key cannot be combined with -tls-domains")
		}
		tc, err := newPEMTLSConfig(cfg.tlsCert, cfg.tlsKey, cfg.tlsMinVersion)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := applyClientCA(tc, cfg.tlsClientCA, cfg.tlsRequireClientCert); err != nil {
			return nil, nil, nil, err
		}
		return tc, nil, nil, nil
	}
	if len(cfg.tlsHosts) == 0 {
		return nil, nil, nil, nil
	}
	minVer, err := parseTLSMinVersion(cfg.tlsMinVersion)
	if err != nil {
		return nil, nil, nil, err
	}

	if strings.TrimSpace(cfg.tlsDNSProvider) != "" {
		dnsMgr, err := buildDNS01Manager(cfg, cfg.tlsHosts, kvSync)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := dnsMgr.Start(ctx); err != nil {
			_ = dnsMgr.Close()
			return nil, nil, nil, err
		}
		tc := dnsMgr.TLSConfig()
		tc.MinVersion = minVer
		tc.CipherSuites = strongCipherSuites
		if err := applyClientCA(tc, cfg.tlsClientCA, cfg.tlsRequireClientCert); err != nil {
			_ = dnsMgr.Close()
			return nil, nil, nil, err
		}
		return tc, nil, func() { _ = dnsMgr.Close() }, nil
	}

	if err := ensureWritableDir(cfg.tlsCacheDir); err != nil {
		return nil, nil, nil, err
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
	if err := applyClientCA(tc, cfg.tlsClientCA, cfg.tlsRequireClientCert); err != nil {
		return nil, nil, nil, err
	}
	return tc, m, nil, nil
}

// httpsRedirectHandler answers Let's Encrypt ACME HTTP-01 challenges when mgr
// is non-nil and redirects all other plain-HTTP requests to HTTPS (301 for
// GET/HEAD, 308 for other methods) with strict Host validation to prevent open
// redirects.
func httpsRedirectHandler(cfg config, mgr *autocert.Manager) http.Handler {
	allowed := append([]string(nil), cfg.tlsHosts...)
	_, httpsPort, _ := net.SplitHostPort(cfg.listen)

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		host, ok := normalizeRedirectHost(r.Host)
		if !ok {
			http.Error(w, "invalid Host header", http.StatusBadRequest)
			return
		}
		if len(allowed) > 0 {
			matched := false
			for _, pat := range allowed {
				if matchHostPattern(pat, host) {
					matched = true
					break
				}
			}
			if !matched {
				http.Error(w, "host not configured for HTTPS", http.StatusMisdirectedRequest)
				return
			}
		}
		dstHost := host
		if httpsPort != "" && httpsPort != "443" {
			dstHost = net.JoinHostPort(host, httpsPort)
		} else if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
			dstHost = "[" + host + "]"
		}
		target := "https://" + dstHost + r.URL.RequestURI()
		code := http.StatusPermanentRedirect
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			code = http.StatusMovedPermanently
		}
		http.Redirect(w, r, target, code)
	})

	if mgr != nil {
		return mgr.HTTPHandler(fallback)
	}
	return fallback
}

func normalizeRedirectHost(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t\r\n/\\@?#") {
		return "", false
	}
	host := raw
	if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	} else if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		host = raw[1 : len(raw)-1]
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return host, true
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.'
		if !ok {
			return "", false
		}
	}
	return host, true
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
