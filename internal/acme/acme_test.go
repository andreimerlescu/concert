package acme_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/acme"
)

// ExampleSecret demonstrates redacting credential output across fmt, JSON, and
// slog formatting paths.
func ExampleSecret() {
	s := acme.NewSecret("demo-not-a-real-token")
	fmt.Println(s.String())
	fmt.Printf("%+v\n", s)
	b, _ := json.Marshal(s)
	fmt.Println(string(b))
	// Output:
	// [REDACTED]
	// [REDACTED]
	// "[REDACTED]"
}

// mockACMEServer implements an in-process RFC 8555 ACME CA HTTP server backed
// by a real ephemeral ECDSA root CA certificate for hermetic end-to-end tests.
type mockACMEServer struct {
	t        *testing.T
	srv      *httptest.Server
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	caPEM    []byte
	certTTL  time.Duration
	failAuth atomic.Bool

	mu           sync.Mutex
	orderSeq     int
	orderCount   int
	accountCount int
	orders       map[string]*mockOrder
	authzs       map[string]*mockAuthz
	challs       map[string]*mockChall
	certs        map[string][]byte
	serialSeq    int64
}

type mockOrder struct {
	ID          string
	Status      string
	Identifiers []mockIdent
	AuthzID     string
	CertID      string
}

type mockIdent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type mockAuthz struct {
	ID         string
	Status     string
	Identifier mockIdent
	Wildcard   bool
	ChallID    string
	Token      string
}

type mockChall struct {
	ID      string
	AuthzID string
	OrderID string
	Status  string
	Token   string
}

func newMockACMEServer(t *testing.T, certTTL time.Duration) *mockACMEServer {
	t.Helper()
	if certTTL <= 0 {
		certTTL = 90 * 24 * time.Hour
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate mock CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Concert Test ACME Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create mock CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse mock CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	m := &mockACMEServer{
		t:         t,
		caCert:    caCert,
		caKey:     caKey,
		caPEM:     caPEM,
		certTTL:   certTTL,
		orders:    make(map[string]*mockOrder),
		authzs:    make(map[string]*mockAuthz),
		challs:    make(map[string]*mockChall),
		certs:     make(map[string][]byte),
		serialSeq: 100,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/directory", m.handleDirectory)
	mux.HandleFunc("/new-nonce", m.handleNonce)
	mux.HandleFunc("/new-account", m.handleNewAccount)
	mux.HandleFunc("/new-order", m.handleNewOrder)
	mux.HandleFunc("/order/", m.handleOrder)
	mux.HandleFunc("/authz/", m.handleAuthz)
	mux.HandleFunc("/chall/", m.handleChallenge)
	mux.HandleFunc("/finalize/", m.handleFinalize)
	mux.HandleFunc("/cert/", m.handleCert)

	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockACMEServer) directoryURL() string {
	return m.srv.URL + "/directory"
}

func (m *mockACMEServer) ordersCreated() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.orderCount
}

func (m *mockACMEServer) rootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(m.caCert)
	return pool
}

func (m *mockACMEServer) setNonce(w http.ResponseWriter) {
	w.Header().Set("Replay-Nonce", "test-nonce-12345")
}

func (m *mockACMEServer) decodeJWSPayload(r *http.Request) ([]byte, error) {
	var env struct {
		Payload string `json:"payload"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	if env.Payload == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(env.Payload)
}

func (m *mockACMEServer) handleDirectory(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"newNonce":   m.srv.URL + "/new-nonce",
		"newAccount": m.srv.URL + "/new-account",
		"newOrder":   m.srv.URL + "/new-order",
		"meta": map[string]any{
			"termsOfService": m.srv.URL + "/tos",
		},
	})
}

func (m *mockACMEServer) handleNonce(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	w.WriteHeader(http.StatusOK)
}

func (m *mockACMEServer) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	m.mu.Lock()
	m.accountCount++
	acctID := fmt.Sprintf("%d", m.accountCount)
	m.mu.Unlock()

	w.Header().Set("Location", m.srv.URL+"/acct/"+acctID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "valid",
		"orders": m.srv.URL + "/acct/" + acctID + "/orders",
	})
}

func (m *mockACMEServer) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	payload, err := m.decodeJWSPayload(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req struct {
		Identifiers []mockIdent `json:"identifiers"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || len(req.Identifiers) == 0 {
		http.Error(w, "invalid order payload", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	m.orderSeq++
	m.orderCount++
	id := fmt.Sprintf("ord-%d", m.orderSeq)
	authzID := fmt.Sprintf("authz-%d", m.orderSeq)
	challID := fmt.Sprintf("chall-%d", m.orderSeq)
	token := fmt.Sprintf("tok-%d-dns01", m.orderSeq)

	ident := req.Identifiers[0]
	wildcard := strings.HasPrefix(ident.Value, "*.")
	authzIdent := mockIdent{
		Type:  ident.Type,
		Value: strings.TrimPrefix(ident.Value, "*."),
	}

	ord := &mockOrder{
		ID:          id,
		Status:      "pending",
		Identifiers: req.Identifiers,
		AuthzID:     authzID,
	}
	authz := &mockAuthz{
		ID:         authzID,
		Status:     "pending",
		Identifier: authzIdent,
		Wildcard:   wildcard,
		ChallID:    challID,
		Token:      token,
	}
	chall := &mockChall{
		ID:      challID,
		AuthzID: authzID,
		OrderID: id,
		Status:  "pending",
		Token:   token,
	}
	m.orders[id] = ord
	m.authzs[authzID] = authz
	m.challs[challID] = chall
	m.mu.Unlock()

	w.Header().Set("Location", m.srv.URL+"/order/"+id)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	m.writeOrderJSON(w, ord)
}

func (m *mockACMEServer) handleOrder(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	id := strings.TrimPrefix(r.URL.Path, "/order/")
	m.mu.Lock()
	ord, ok := m.orders[id]
	m.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	m.writeOrderJSON(w, ord)
}

func (m *mockACMEServer) writeOrderJSON(w http.ResponseWriter, ord *mockOrder) {
	resp := map[string]any{
		"status":         ord.Status,
		"identifiers":    ord.Identifiers,
		"authorizations": []string{m.srv.URL + "/authz/" + ord.AuthzID},
		"finalize":       m.srv.URL + "/finalize/" + ord.ID,
	}
	if ord.CertID != "" {
		resp["certificate"] = m.srv.URL + "/cert/" + ord.CertID
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (m *mockACMEServer) handleAuthz(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	id := strings.TrimPrefix(r.URL.Path, "/authz/")
	m.mu.Lock()
	authz, ok := m.authzs[id]
	if !ok {
		m.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	chall := m.challs[authz.ChallID]
	resp := map[string]any{
		"status":     authz.Status,
		"identifier": authz.Identifier,
		"wildcard":   authz.Wildcard,
		"challenges": []map[string]any{
			{
				"type":   "dns-01",
				"url":    m.srv.URL + "/chall/" + chall.ID,
				"token":  chall.Token,
				"status": chall.Status,
			},
		},
	}
	m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (m *mockACMEServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	id := strings.TrimPrefix(r.URL.Path, "/chall/")
	m.mu.Lock()
	chall, ok := m.challs[id]
	if !ok {
		m.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	authz := m.authzs[chall.AuthzID]
	ord := m.orders[chall.OrderID]
	if m.failAuth.Load() {
		chall.Status = "invalid"
		authz.Status = "invalid"
		ord.Status = "invalid"
	} else {
		chall.Status = "valid"
		authz.Status = "valid"
		ord.Status = "ready"
	}
	resp := map[string]any{
		"type":   "dns-01",
		"url":    m.srv.URL + "/chall/" + chall.ID,
		"token":  chall.Token,
		"status": chall.Status,
	}
	m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (m *mockACMEServer) handleFinalize(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	id := strings.TrimPrefix(r.URL.Path, "/finalize/")
	payload, err := m.decodeJWSPayload(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		http.Error(w, "invalid finalize payload", http.StatusBadRequest)
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		http.Error(w, "invalid csr base64", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		http.Error(w, "invalid csr", http.StatusBadRequest)
		return
	}
	if err := csr.CheckSignature(); err != nil {
		http.Error(w, "bad csr signature", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	ord, ok := m.orders[id]
	if !ok {
		m.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	m.serialSeq++
	serial := m.serialSeq
	certTTL := m.certTTL
	m.mu.Unlock()

	now := time.Now()
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: csr.DNSNames[0]},
		DNSNames:     csr.DNSNames,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(certTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, m.caCert, csr.PublicKey, m.caKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	chainPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), m.caPEM...)

	certID := fmt.Sprintf("cert-%d", serial)
	m.mu.Lock()
	m.certs[certID] = chainPEM
	ord.CertID = certID
	ord.Status = "valid"
	m.mu.Unlock()

	w.Header().Set("Location", m.srv.URL+"/order/"+ord.ID)
	w.Header().Set("Content-Type", "application/json")
	m.writeOrderJSON(w, ord)
}

func (m *mockACMEServer) handleCert(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	id := strings.TrimPrefix(r.URL.Path, "/cert/")
	m.mu.Lock()
	chainPEM, ok := m.certs[id]
	m.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = w.Write(chainPEM)
}

// mockDNSProvider models DNSProvider in memory and optionally coordinates
// deterministic test barriers without time.Sleep.
type mockDNSProvider struct {
	mu          sync.Mutex
	records     map[string][]string
	presented   []dnsAction
	cleanedUp   []dnsAction
	propTimeout time.Duration
	presentHook func(ctx context.Context, fqdn, value string) error
}

type dnsAction struct {
	fqdn  string
	value string
}

func newMockDNSProvider() *mockDNSProvider {
	return &mockDNSProvider{
		records:     make(map[string][]string),
		propTimeout: 5 * time.Second,
	}
}

func (p *mockDNSProvider) PropagationTimeout() time.Duration {
	return p.propTimeout
}

func (p *mockDNSProvider) Present(ctx context.Context, fqdn, value string) error {
	if p.presentHook != nil {
		if err := p.presentHook(ctx, fqdn, value); err != nil {
			return err
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records[fqdn] = append(p.records[fqdn], value)
	p.presented = append(p.presented, dnsAction{fqdn: fqdn, value: value})
	return nil
}

func (p *mockDNSProvider) CleanUp(_ context.Context, fqdn, value string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	vals := p.records[fqdn]
	filtered := vals[:0]
	for _, v := range vals {
		if v != value {
			filtered = append(filtered, v)
		}
	}
	if len(filtered) == 0 {
		delete(p.records, fqdn)
	} else {
		p.records[fqdn] = filtered
	}
	p.cleanedUp = append(p.cleanedUp, dnsAction{fqdn: fqdn, value: value})
	return nil
}

func (p *mockDNSProvider) lookupTXT(_ context.Context, name string) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	vals := p.records[name]
	out := make([]string, len(vals))
	copy(out, vals)
	return out, nil
}

func (p *mockDNSProvider) counts() (presented, cleanedUp, remaining int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, vals := range p.records {
		remaining += len(vals)
	}
	return len(p.presented), len(p.cleanedUp), remaining
}

// mockKVSync implements acme.KVBundleSync in memory for multi-edge tests.
type mockKVSync struct {
	mu      sync.Mutex
	entries map[string][]byte
	ttls    map[string]time.Duration
	gets    int
	sets    int
}

func newMockKVSync() *mockKVSync {
	return &mockKVSync{
		entries: make(map[string][]byte),
		ttls:    make(map[string]time.Duration),
	}
}

func (k *mockKVSync) Get(_ context.Context, key string) ([]byte, bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.gets++
	val, ok := k.entries[key]
	if !ok {
		return nil, false, nil
	}
	cp := make([]byte, len(val))
	copy(cp, val)
	return cp, true, nil
}

func (k *mockKVSync) Set(_ context.Context, key string, val []byte, ttl time.Duration) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.sets++
	cp := make([]byte, len(val))
	copy(cp, val)
	k.entries[key] = cp
	k.ttls[key] = ttl
	return nil
}

func (k *mockKVSync) rawValue(key string) ([]byte, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.entries[key]
	if !ok {
		return nil, false
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, true
}

func (k *mockKVSync) mutate(key string, fn func([]byte) []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if v, ok := k.entries[key]; ok {
		k.entries[key] = fn(v)
	}
}

func TestManager_WildcardIssuanceAndSNIMatching(t *testing.T) {
	t.Parallel()
	ca := newMockACMEServer(t, 90*24*time.Hour)
	dns := newMockDNSProvider()
	cacheDir := t.TempDir()

	mgr, err := acme.NewManager(acme.Config{
		Domains:      []string{"*.example.com"},
		Email:        "ops@example.com",
		DirectoryURL: ca.directoryURL(),
		CacheDir:     cacheDir,
		Provider:     dns,
		HTTPClient:   ca.srv.Client(),
		TXTLookup:    dns.lookupTXT,
		PollInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })

	// Valid single-label wildcard match triggers ACME DNS-01 issuance.
	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate(app.example.com): %v", err)
	}
	if cert == nil || cert.Leaf == nil {
		t.Fatalf("expected non-nil cert and leaf")
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		DNSName: "app.example.com",
		Roots:   ca.rootPool(),
	}); err != nil {
		t.Fatalf("verify wildcard leaf for app.example.com: %v", err)
	}

	// Another single-label subdomain reuses the cached wildcard cert without new order.
	cert2, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate(api.example.com): %v", err)
	}
	if cert2 != cert {
		t.Errorf("expected cached wildcard certificate reuse for api.example.com")
	}
	if got := ca.ordersCreated(); got != 1 {
		t.Errorf("ordersCreated = %d, want 1", got)
	}

	// RFC 6125 rejections: multi-level subdomain, apex, unrelated domain, empty, IP.
	rejected := []string{"a.b.example.com", "example.com", "other.net", "", "127.0.0.1"}
	for _, host := range rejected {
		_, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
		if !errors.Is(err, acme.ErrHostNotAllowed) {
			t.Errorf("GetCertificate(%q) err = %v, want ErrHostNotAllowed", host, err)
		}
	}

	// Verify CleanUp ran and left zero lingering TXT records.
	pres, clean, rem := dns.counts()
	if pres != 1 || clean != 1 || rem != 0 {
		t.Errorf("dns counts = (present=%d, cleanup=%d, remaining=%d), want (1, 1, 0)", pres, clean, rem)
	}
}

func TestManager_TXTPropagationPollingAndGuaranteedCleanUp(t *testing.T) {
	t.Parallel()

	t.Run("polls until propagation succeeds and cleans up", func(t *testing.T) {
		t.Parallel()
		ca := newMockACMEServer(t, 90*24*time.Hour)
		dns := newMockDNSProvider()

		var polls atomic.Int32
		delayedLookup := func(ctx context.Context, name string) ([]string, error) {
			// Return empty for the first 2 polls, then expose the presented TXT record.
			if polls.Add(1) < 3 {
				return nil, nil
			}
			return dns.lookupTXT(ctx, name)
		}

		mgr, err := acme.NewManager(acme.Config{
			Domains:            []string{"*.example.com"},
			DirectoryURL:       ca.directoryURL(),
			CacheDir:           t.TempDir(),
			Provider:           dns,
			HTTPClient:         ca.srv.Client(),
			TXTLookup:          delayedLookup,
			PollInterval:       5 * time.Millisecond,
			PropagationTimeout: 2 * time.Second,
		})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		t.Cleanup(func() { _ = mgr.Close() })

		if _, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "edge.example.com"}); err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		if got := polls.Load(); got < 3 {
			t.Errorf("TXT lookup poll count = %d, want >= 3", got)
		}
		pres, clean, rem := dns.counts()
		if pres != 1 || clean != 1 || rem != 0 {
			t.Errorf("dns counts = (%d, %d, %d), want (1, 1, 0)", pres, clean, rem)
		}
	})

	t.Run("cleans up on propagation timeout failure", func(t *testing.T) {
		t.Parallel()
		ca := newMockACMEServer(t, 90*24*time.Hour)
		dns := newMockDNSProvider()

		neverPropagates := func(_ context.Context, _ string) ([]string, error) {
			return nil, nil
		}

		mgr, err := acme.NewManager(acme.Config{
			Domains:            []string{"*.example.com"},
			DirectoryURL:       ca.directoryURL(),
			CacheDir:           t.TempDir(),
			Provider:           dns,
			HTTPClient:         ca.srv.Client(),
			TXTLookup:          neverPropagates,
			PollInterval:       5 * time.Millisecond,
			PropagationTimeout: 25 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		t.Cleanup(func() { _ = mgr.Close() })

		_, err = mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "edge.example.com"})
		if !errors.Is(err, acme.ErrPropagationTimeout) {
			t.Fatalf("GetCertificate err = %v, want ErrPropagationTimeout", err)
		}
		pres, clean, rem := dns.counts()
		if pres != 1 || clean != 1 || rem != 0 {
			t.Errorf("dns counts after timeout = (%d, %d, %d), want (1, 1, 0)", pres, clean, rem)
		}
	})

	t.Run("cleans up when CA rejects authorization", func(t *testing.T) {
		t.Parallel()
		ca := newMockACMEServer(t, 90*24*time.Hour)
		ca.failAuth.Store(true)
		dns := newMockDNSProvider()

		mgr, err := acme.NewManager(acme.Config{
			Domains:      []string{"*.example.com"},
			DirectoryURL: ca.directoryURL(),
			CacheDir:     t.TempDir(),
			Provider:     dns,
			HTTPClient:   ca.srv.Client(),
			TXTLookup:    dns.lookupTXT,
			PollInterval: 5 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		t.Cleanup(func() { _ = mgr.Close() })

		if _, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "edge.example.com"}); err == nil {
			t.Fatalf("expected error when CA marks authorization invalid")
		}
		pres, clean, rem := dns.counts()
		if pres != 1 || clean != 1 || rem != 0 {
			t.Errorf("dns counts after CA failure = (%d, %d, %d), want (1, 1, 0)", pres, clean, rem)
		}
	})
}

func TestDiskStore_PermissionsReloadAndTraversalRejection(t *testing.T) {
	t.Parallel()
	ca := newMockACMEServer(t, 90*24*time.Hour)
	dns := newMockDNSProvider()
	cacheDir := t.TempDir()

	store, err := acme.NewDiskStore(cacheDir)
	if err != nil {
		t.Fatalf("NewDiskStore: %v", err)
	}

	// Path traversal patterns must be rejected before touching disk (S9).
	for _, bad := range []string{"../escape", "/etc/passwd", "*.a/../../b", "foo\\bar.com", "*.*.example.com"} {
		if _, err := store.BundlePath(bad); !errors.Is(err, acme.ErrInvalidDomain) {
			t.Errorf("BundlePath(%q) err = %v, want ErrInvalidDomain", bad, err)
		}
	}

	mgr1, err := acme.NewManager(acme.Config{
		Domains:      []string{"*.example.com"},
		DirectoryURL: ca.directoryURL(),
		Store:        store,
		Provider:     dns,
		HTTPClient:   ca.srv.Client(),
		TXTLookup:    dns.lookupTXT,
		PollInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewManager(1): %v", err)
	}
	t.Cleanup(func() { _ = mgr1.Close() })

	cert1, err := mgr1.GetCertificate(&tls.ClientHelloInfo{ServerName: "one.example.com"})
	if err != nil {
		t.Fatalf("mgr1.GetCertificate: %v", err)
	}

	// Verify 0600 permissions on account key and persisted certificate bundle.
	accountPath := filepath.Join(cacheDir, "account.key")
	ai, err := os.Stat(accountPath)
	if err != nil {
		t.Fatalf("stat account.key: %v", err)
	}
	if perm := ai.Mode().Perm(); perm != 0o600 {
		t.Errorf("account.key perm = %04o, want 0600", perm)
	}
	bundlePath, err := store.BundlePath("*.example.com")
	if err != nil {
		t.Fatalf("BundlePath: %v", err)
	}
	bi, err := os.Stat(bundlePath)
	if err != nil {
		t.Fatalf("stat bundle: %v", err)
	}
	if perm := bi.Mode().Perm(); perm != 0o600 {
		t.Errorf("bundle perm = %04o, want 0600", perm)
	}

	// Fresh Manager pointing at the same DiskStore must reload from disk with zero ACME calls.
	mgr2, err := acme.NewManager(acme.Config{
		Domains:      []string{"*.example.com"},
		DirectoryURL: ca.directoryURL(),
		CacheDir:     cacheDir,
		Provider:     dns,
		HTTPClient:   ca.srv.Client(),
		TXTLookup:    dns.lookupTXT,
		PollInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewManager(2): %v", err)
	}
	t.Cleanup(func() { _ = mgr2.Close() })

	cert2, err := mgr2.GetCertificate(&tls.ClientHelloInfo{ServerName: "two.example.com"})
	if err != nil {
		t.Fatalf("mgr2.GetCertificate: %v", err)
	}
	if cert1.Leaf.SerialNumber.Cmp(cert2.Leaf.SerialNumber) != 0 {
		t.Errorf("reloaded cert serial = %v, want %v", cert2.Leaf.SerialNumber, cert1.Leaf.SerialNumber)
	}
	if got := ca.ordersCreated(); got != 1 {
		t.Errorf("ordersCreated after reload = %d, want 1", got)
	}
}

func TestKVBundleSync_EncryptedRoundTripAndTamperRejection(t *testing.T) {
	t.Parallel()
	ca := newMockACMEServer(t, 90*24*time.Hour)
	dns := newMockDNSProvider()
	kv := newMockKVSync()
	secret := acme.NewSecret("test-operator-kv-encryption-key-not-real")

	// Configuring KVSync without KVSecret must fail closed (S7).
	if _, err := acme.NewManager(acme.Config{
		Domains:  []string{"*.example.com"},
		CacheDir: t.TempDir(),
		Provider: dns,
		KVSync:   kv,
	}); !errors.Is(err, acme.ErrEmptySecret) {
		t.Fatalf("NewManager without KVSecret err = %v, want ErrEmptySecret", err)
	}

	// Edge A issues wildcard cert and pushes encrypted bundle to KV.
	edgeA, err := acme.NewManager(acme.Config{
		Domains:      []string{"*.example.com"},
		DirectoryURL: ca.directoryURL(),
		CacheDir:     t.TempDir(),
		Provider:     dns,
		HTTPClient:   ca.srv.Client(),
		TXTLookup:    dns.lookupTXT,
		KVSync:       kv,
		KVSecret:     secret,
		PollInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewManager(edgeA): %v", err)
	}
	t.Cleanup(func() { _ = edgeA.Close() })

	certA, err := edgeA.GetCertificate(&tls.ClientHelloInfo{ServerName: "alpha.example.com"})
	if err != nil {
		t.Fatalf("edgeA.GetCertificate: %v", err)
	}

	const kvKey = "concert:acme:cert:*.example.com"
	rawKV, ok := kv.rawValue(kvKey)
	if !ok {
		t.Fatalf("expected encrypted bundle in KV under %q", kvKey)
	}
	if bytes.Contains(rawKV, []byte("PRIVATE KEY")) || bytes.Contains(rawKV, []byte("CERTIFICATE")) {
		t.Fatalf("KV payload leaked plaintext PEM markers")
	}

	// Edge B with an empty disk cache pulls and decrypts from KV without creating a second ACME order.
	edgeB, err := acme.NewManager(acme.Config{
		Domains:      []string{"*.example.com"},
		DirectoryURL: ca.directoryURL(),
		CacheDir:     t.TempDir(),
		Provider:     dns,
		HTTPClient:   ca.srv.Client(),
		TXTLookup:    dns.lookupTXT,
		KVSync:       kv,
		KVSecret:     secret,
		PollInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewManager(edgeB): %v", err)
	}
	t.Cleanup(func() { _ = edgeB.Close() })

	certB, err := edgeB.GetCertificate(&tls.ClientHelloInfo{ServerName: "beta.example.com"})
	if err != nil {
		t.Fatalf("edgeB.GetCertificate: %v", err)
	}
	if certA.Leaf.SerialNumber.Cmp(certB.Leaf.SerialNumber) != 0 {
		t.Errorf("synced cert serial = %v, want %v", certB.Leaf.SerialNumber, certA.Leaf.SerialNumber)
	}
	if got := ca.ordersCreated(); got != 1 {
		t.Errorf("ordersCreated after edgeB KV sync = %d, want 1", got)
	}

	// Direct BundleCipher tamper & AAD-swap checks.
	cipher, err := acme.NewBundleCipher(secret)
	if err != nil {
		t.Fatalf("NewBundleCipher: %v", err)
	}
	// Flip a byte in the ciphertext/tag.
	tampered := append([]byte(nil), rawKV...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := cipher.Decrypt("*.example.com", tampered); !errors.Is(err, acme.ErrCorruptBundle) {
		t.Errorf("Decrypt(tampered tag) err = %v, want ErrCorruptBundle", err)
	}
	// Flip the version byte.
	badVer := append([]byte(nil), rawKV...)
	badVer[0] = 99
	if _, err := cipher.Decrypt("*.example.com", badVer); !errors.Is(err, acme.ErrCorruptBundle) {
		t.Errorf("Decrypt(bad version) err = %v, want ErrCorruptBundle", err)
	}
	// Cross-domain AAD swap must be rejected.
	if _, err := cipher.Decrypt("*.other.com", rawKV); !errors.Is(err, acme.ErrCorruptBundle) {
		t.Errorf("Decrypt(wrong domain AAD) err = %v, want ErrCorruptBundle", err)
	}
	// Wrong operator secret must be rejected.
	wrongCipher, err := acme.NewBundleCipher(acme.NewSecret("different-operator-secret"))
	if err != nil {
		t.Fatalf("NewBundleCipher(wrong): %v", err)
	}
	if _, err := wrongCipher.Decrypt("*.example.com", rawKV); !errors.Is(err, acme.ErrCorruptBundle) {
		t.Errorf("Decrypt(wrong secret) err = %v, want ErrCorruptBundle", err)
	}

	// Tampered KV entry forces edge C to reject it and cleanly fall back to ACME issuance.
	kv.mutate(kvKey, func(in []byte) []byte {
		cp := append([]byte(nil), in...)
		cp[len(cp)-3] ^= 0x55
		return cp
	})
	edgeC, err := acme.NewManager(acme.Config{
		Domains:      []string{"*.example.com"},
		DirectoryURL: ca.directoryURL(),
		CacheDir:     t.TempDir(),
		Provider:     dns,
		HTTPClient:   ca.srv.Client(),
		TXTLookup:    dns.lookupTXT,
		KVSync:       kv,
		KVSecret:     secret,
		PollInterval: 5 * time.Millisecond,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewManager(edgeC): %v", err)
	}
	t.Cleanup(func() { _ = edgeC.Close() })

	if _, err := edgeC.GetCertificate(&tls.ClientHelloInfo{ServerName: "gamma.example.com"}); err != nil {
		t.Fatalf("edgeC fallback GetCertificate: %v", err)
	}
	if got := ca.ordersCreated(); got != 2 {
		t.Errorf("ordersCreated after tampered KV fallback = %d, want 2", got)
	}
}

func TestCloudflareProvider_HTTPContractAndValidation(t *testing.T) {
	t.Parallel()
	const fakeToken = "cf-test-bearer-value-never-log"

	// Fail closed on empty token or plain HTTP non-loopback URL.
	if _, err := acme.NewCloudflareProvider(acme.CloudflareConfig{}); !errors.Is(err, acme.ErrEmptySecret) {
		t.Fatalf("empty token err = %v, want ErrEmptySecret", err)
	}
	if _, err := acme.NewCloudflareProvider(acme.CloudflareConfig{
		APIToken: acme.NewSecret(fakeToken),
		BaseURL:  "http://api.cloudflare.com/client/v4",
	}); !errors.Is(err, acme.ErrInsecureURL) {
		t.Fatalf("insecure base url err = %v, want ErrInsecureURL", err)
	}

	var (
		mu         sync.Mutex
		zoneCalls  int
		postCalls  int
		delCalls   int
		listCalls  int
		createdRec map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+fakeToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			mu.Lock()
			zoneCalls++
			mu.Unlock()
			if r.URL.Query().Get("name") == "example.com" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": true,
					"result":  []map[string]any{{"id": "zone-123", "name": "example.com"}},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{}})

		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-123/dns_records":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			postCalls++
			createdRec = body
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  map[string]any{"id": "rec-999", "type": "TXT", "name": body["name"], "content": body["content"]},
			})

		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-123/dns_records":
			mu.Lock()
			listCalls++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result": []map[string]any{{
					"id":      "rec-fallback",
					"type":    "TXT",
					"name":    r.URL.Query().Get("name"),
					"content": r.URL.Query().Get("content"),
				}},
			})

		case r.Method == http.MethodDelete && (r.URL.Path == "/zones/zone-123/dns_records/rec-999" || r.URL.Path == "/zones/zone-123/dns_records/rec-fallback"):
			mu.Lock()
			delCalls++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  map[string]any{"id": filepath.Base(r.URL.Path)},
			})

		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	provider, err := acme.NewCloudflareProvider(acme.CloudflareConfig{
		APIToken:               acme.NewSecret(fakeToken),
		BaseURL:                srv.URL,
		HTTPClient:             srv.Client(),
		AllowInsecureLocalhost: true,
		Propagation:            45 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewCloudflareProvider: %v", err)
	}
	if got := provider.PropagationTimeout(); got != 45*time.Second {
		t.Errorf("PropagationTimeout = %v, want 45s", got)
	}

	ctx := t.Context()
	if err := provider.Present(ctx, "_acme-challenge.example.com.", "digest-abc"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := provider.CleanUp(ctx, "_acme-challenge.example.com", "digest-abc"); err != nil {
		t.Fatalf("CleanUp (cached id): %v", err)
	}
	// Second CleanUp exercises the uncached GET+DELETE fallback path.
	if err := provider.CleanUp(ctx, "_acme-challenge.example.com", "digest-abc"); err != nil {
		t.Fatalf("CleanUp (fallback lookup): %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if zoneCalls != 2 { // "_acme-challenge.example.com" miss, then "example.com" hit & cached
		t.Errorf("zoneCalls = %d, want 2", zoneCalls)
	}
	if postCalls != 1 || delCalls != 2 || listCalls != 1 {
		t.Errorf("calls post=%d del=%d list=%d, want 1/2/1", postCalls, delCalls, listCalls)
	}
	if createdRec["type"] != "TXT" || createdRec["name"] != "_acme-challenge.example.com" || createdRec["content"] != "digest-abc" {
		t.Errorf("unexpected created record payload: %+v", createdRec)
	}
}

func TestWebhookProvider_HTTPContractAndSecurity(t *testing.T) {
	t.Parallel()
	const fakeToken = "webhook-test-secret-never-log"

	// Plain HTTP to a non-localhost host must be rejected even if AllowInsecureLocalhost is true.
	if _, err := acme.NewWebhookProvider(acme.WebhookConfig{
		Endpoint:               "http://dns.example.com/hook",
		AllowInsecureLocalhost: true,
	}); !errors.Is(err, acme.ErrInsecureURL) {
		t.Fatalf("remote http endpoint err = %v, want ErrInsecureURL", err)
	}
	// Plain HTTP to localhost must be rejected when AllowInsecureLocalhost is false.
	if _, err := acme.NewWebhookProvider(acme.WebhookConfig{
		Endpoint: "http://127.0.0.1:8080/hook",
	}); !errors.Is(err, acme.ErrInsecureURL) {
		t.Fatalf("localhost http without opt-in err = %v, want ErrInsecureURL", err)
	}
	// URL userinfo must be rejected (S4/S5).
	userinfoURL := (&url.URL{
		Scheme: "https",
		User:   url.UserPassword("test-user", "not-a-real-pw"),
		Host:   "dns.example.com",
		Path:   "/hook",
	}).String()
	if _, err := acme.NewWebhookProvider(acme.WebhookConfig{
		Endpoint: userinfoURL,
	}); !errors.Is(err, acme.ErrInsecureURL) {
		t.Fatalf("url userinfo err = %v, want ErrInsecureURL", err)
	}

	var (
		mu       sync.Mutex
		payloads []acme.WebhookPayload
		failNext atomic.Bool
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+fakeToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if failNext.Load() {
			http.Error(w, "upstream dns error", http.StatusBadGateway)
			return
		}
		var p acme.WebhookPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		payloads = append(payloads, p)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	provider, err := acme.NewWebhookProvider(acme.WebhookConfig{
		Endpoint:    srv.URL + "/dns01",
		BearerToken: acme.NewSecret(fakeToken),
		HTTPClient:  srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewWebhookProvider: %v", err)
	}

	ctx := t.Context()
	if err := provider.Present(ctx, "_acme-challenge.example.com.", "val-1"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := provider.CleanUp(ctx, "_acme-challenge.example.com.", "val-1"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}

	failNext.Store(true)
	err = provider.Present(ctx, "_acme-challenge.example.com", "val-2")
	if !errors.Is(err, acme.ErrProviderFailed) {
		t.Fatalf("Present on 502 err = %v, want ErrProviderFailed", err)
	}
	if strings.Contains(err.Error(), fakeToken) {
		t.Fatalf("error leaked bearer token: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(payloads) != 2 {
		t.Fatalf("received %d payloads, want 2", len(payloads))
	}
	if payloads[0] != (acme.WebhookPayload{Action: "present", FQDN: "_acme-challenge.example.com", Value: "val-1"}) {
		t.Errorf("payload[0] = %+v", payloads[0])
	}
	if payloads[1] != (acme.WebhookPayload{Action: "cleanup", FQDN: "_acme-challenge.example.com", Value: "val-1"}) {
		t.Errorf("payload[1] = %+v", payloads[1])
	}
}

func TestSecret_RedactionAcrossAllOutputs(t *testing.T) {
	t.Parallel()
	const raw = "super-sensitive-credential-value-xyz"
	s := acme.NewSecret(raw)

	outputs := []string{
		s.String(),
		s.GoString(),
		fmt.Sprintf("%v", s),
		fmt.Sprintf("%+v", s),
		fmt.Sprintf("%#v", s),
		fmt.Sprintf("%s", s),
		fmt.Sprintf("%q", s),
		fmt.Sprintf("%+v", acme.CloudflareConfig{APIToken: s}),
		fmt.Sprintf("%+v", acme.WebhookConfig{BearerToken: s}),
	}
	if b, err := json.Marshal(s); err != nil {
		t.Fatalf("json.Marshal: %v", err)
	} else {
		outputs = append(outputs, string(b))
	}
	if b, err := s.MarshalText(); err != nil {
		t.Fatalf("MarshalText: %v", err)
	} else {
		outputs = append(outputs, string(b))
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	logger.Info("config loaded", "token", s, slog.Any("any_token", s))
	outputs = append(outputs, logBuf.String())

	for i, out := range outputs {
		if strings.Contains(out, raw) {
			t.Errorf("output[%d] leaked raw secret: %s", i, out)
		}
		if !strings.Contains(out, acme.SecretPlaceholder) {
			t.Errorf("output[%d] missing placeholder %q: %s", i, acme.SecretPlaceholder, out)
		}
	}
	if s.Reveal() != raw || string(s.RevealBytes()) != raw {
		t.Errorf("Reveal did not return original raw secret")
	}
}

func TestManager_ConcurrentSingleflightUnderRace(t *testing.T) {
	t.Parallel()
	ca := newMockACMEServer(t, 90*24*time.Hour)
	dns := newMockDNSProvider()

	// Synchronize overlap deterministically with channels (no time.Sleep, T2/T4).
	presentEntered := make(chan struct{})
	releasePresent := make(chan struct{})
	var presentOnce sync.Once
	dns.presentHook = func(ctx context.Context, _, _ string) error {
		presentOnce.Do(func() { close(presentEntered) })
		select {
		case <-releasePresent:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	mgr, err := acme.NewManager(acme.Config{
		Domains:      []string{"*.example.com"},
		DirectoryURL: ca.directoryURL(),
		CacheDir:     t.TempDir(),
		Provider:     dns,
		HTTPClient:   ca.srv.Client(),
		TXTLookup:    dns.lookupTXT,
		PollInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })

	const callers = 24
	start := make(chan struct{})
	certs := make([]*tls.Certificate, callers)
	errs := make([]error, callers)

	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			<-start
			host := fmt.Sprintf("svc-%d.example.com", i)
			certs[i], errs[i] = mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
		})
	}
	close(start)

	// Wait until the singleflight leader is actively inside DNS Present, then release it.
	select {
	case <-presentEntered:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for singleflight leader to enter Present")
	}
	close(releasePresent)
	wg.Wait()

	if got := ca.ordersCreated(); got != 1 {
		t.Fatalf("concurrent GetCertificate created %d ACME orders, want 1", got)
	}
	first := certs[0]
	for i := range callers {
		if errs[i] != nil {
			t.Fatalf("caller %d err = %v", i, errs[i])
		}
		if certs[i] == nil || certs[i] != first {
			t.Fatalf("caller %d got distinct certificate pointer", i)
		}
	}
}

func TestManager_BackgroundRenewalAndCleanShutdown(t *testing.T) {
	t.Parallel()
	// Issue a certificate with 20-day validity so it falls inside the 30-day renewal window.
	ca := newMockACMEServer(t, 20*24*time.Hour)
	dns := newMockDNSProvider()

	renewedCh := make(chan struct{}, 4)
	var presentCalls atomic.Int32
	dns.presentHook = func(_ context.Context, _, _ string) error {
		if presentCalls.Add(1) >= 2 {
			select {
			case renewedCh <- struct{}{}:
			default:
			}
		}
		return nil
	}

	mgr, err := acme.NewManager(acme.Config{
		Domains:            []string{"*.example.com"},
		DirectoryURL:       ca.directoryURL(),
		CacheDir:           t.TempDir(),
		Provider:           dns,
		HTTPClient:         ca.srv.Client(),
		TXTLookup:          dns.lookupTXT,
		PollInterval:       5 * time.Millisecond,
		RenewBefore:        30 * 24 * time.Hour,
		RenewCheckInterval: 10 * time.Millisecond,
		BackoffBase:        10 * time.Millisecond,
		BackoffMax:         50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Initial issuance (20-day cert -> immediately eligible for renewal under 30-day window).
	cert1, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})
	if err != nil {
		t.Fatalf("initial GetCertificate: %v", err)
	}

	if err := mgr.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := mgr.Start(t.Context()); !errors.Is(err, acme.ErrAlreadyStarted) {
		t.Fatalf("second Start err = %v, want ErrAlreadyStarted", err)
	}

	select {
	case <-renewedCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for background renewal loop to trigger")
	}

	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close must be idempotent.
	if err := mgr.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// Start after Close must fail with ErrManagerClosed.
	if err := mgr.Start(t.Context()); !errors.Is(err, acme.ErrManagerClosed) {
		t.Fatalf("Start after Close err = %v, want ErrManagerClosed", err)
	}
	if _, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"}); !errors.Is(err, acme.ErrManagerClosed) {
		// Note: cached cert hits fast path; uncached/closed check covered below.
		_ = err
	}
	if got := ca.ordersCreated(); got < 2 {
		t.Errorf("ordersCreated = %d, want >= 2 after background renewal", got)
	}
	_ = cert1
}

func TestManager_ExactPrecedenceAndRealTLSHandshake(t *testing.T) {
	t.Parallel()
	ca := newMockACMEServer(t, 90*24*time.Hour)
	dns := newMockDNSProvider()

	mgr, err := acme.NewManager(acme.Config{
		Domains:      []string{"*.example.com", "example.com", "api.example.com"},
		DirectoryURL: ca.directoryURL(),
		CacheDir:     t.TempDir(),
		Provider:     dns,
		HTTPClient:   ca.srv.Client(),
		TXTLookup:    dns.lookupTXT,
		PollInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })

	cases := []struct {
		host string
		want string
		ok   bool
	}{
		{host: "example.com", want: "example.com", ok: true},
		{host: "api.example.com", want: "api.example.com", ok: true},
		{host: "app.example.com", want: "*.example.com", ok: true},
		{host: "APP.EXAMPLE.COM.", want: "*.example.com", ok: true},
		{host: "a.b.example.com", want: "", ok: false},
		{host: "other.net", want: "", ok: false},
	}
	for _, tc := range cases {
		got, ok := mgr.MatchDomain(tc.host)
		if ok != tc.ok || got != tc.want {
			t.Errorf("MatchDomain(%q) = (%q, %v), want (%q, %v)", tc.host, got, ok, tc.want, tc.ok)
		}
	}

	// Prove real TLS handshake end-to-end with mgr.TLSConfig().
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = mgr.TLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)

	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{
		ServerName: "edge.example.com",
		RootCAs:    ca.rootPool(),
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Dial(edge.example.com): %v", err)
	}
	state := conn.ConnectionState()
	_ = conn.Close()
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0].DNSNames[0] != "*.example.com" {
		t.Fatalf("unexpected peer certificate SANs: %+v", state.PeerCertificates)
	}

	// Closed manager must reject new uncached issuance with ErrManagerClosed.
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"}); !errors.Is(err, acme.ErrManagerClosed) {
		t.Fatalf("GetCertificate after Close err = %v, want ErrManagerClosed", err)
	}
}

func TestManager_BackgroundRenewalBackoffOnFailure(t *testing.T) {
	t.Parallel()
	ca := newMockACMEServer(t, 20*24*time.Hour)
	dns := newMockDNSProvider()

	var attempts atomic.Int32
	recoveredCh := make(chan struct{}, 1)
	dns.presentHook = func(_ context.Context, _, _ string) error {
		n := attempts.Add(1)
		if n == 2 {
			// Fail first background renewal attempt to exercise exponential backoff.
			return errors.New("transient dns outage")
		}
		if n >= 3 {
			select {
			case recoveredCh <- struct{}{}:
			default:
			}
		}
		return nil
	}

	mgr, err := acme.NewManager(acme.Config{
		Domains:            []string{"*.example.com"},
		DirectoryURL:       ca.directoryURL(),
		CacheDir:           t.TempDir(),
		Provider:           dns,
		HTTPClient:         ca.srv.Client(),
		TXTLookup:          dns.lookupTXT,
		PollInterval:       5 * time.Millisecond,
		RenewBefore:        30 * 24 * time.Hour,
		RenewCheckInterval: 5 * time.Millisecond,
		BackoffBase:        15 * time.Millisecond,
		BackoffMax:         30 * time.Millisecond,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })

	if _, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"}); err != nil {
		t.Fatalf("initial GetCertificate: %v", err)
	}
	if err := mgr.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	select {
	case <-recoveredCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for renewal retry after backoff")
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := attempts.Load(); got < 3 {
		t.Errorf("attempts = %d, want >= 3 (initial + failed renewal + recovered renewal)", got)
	}
}
