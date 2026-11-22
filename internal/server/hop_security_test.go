package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/hop"
)

func TestHopReplay_LeafRejectsCapturedHeader(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()

	secret := []byte("concert-hop-replay-test-secret-0123456789")

	leafCfg := testConfig(origin.URL)
	leafCfg.role = roleLeaf
	leafCfg.nodeID = "leaf-replay"
	leafCfg.hostCap = 10
	leafCfg.hopSecret = secret
	leafCfg.hopPeers = "127.0.0.1/32,::1/128"
	leafCfg.hopReplayGuard = true
	leafCfg.hopRequireNonce = true
	leafCfg.abuseEnabled = false
	leafApp, leafSrv := newTestApp(t, leafCfg, nil)

	signer, err := hop.NewSigner(secret, "edge-1")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Control-plane claim replay returns 401 and increments hop_replayed_total.
	ctlClaim := hop.Claim{Client: netip.IPv4Unspecified(), Class: hop.ClassControl}
	ctlHdr := signer.Sign(ctlClaim, http.MethodGet, hop.StatePath, hop.BodyHash(nil))

	sendCtl := func() int {
		req, _ := http.NewRequest(http.MethodGet, leafSrv.URL+hop.StatePath, nil)
		req.Header.Set(hop.Header, ctlHdr)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := sendCtl(); code != http.StatusOK {
		t.Fatalf("first control request status = %d, want 200", code)
	}
	if code := sendCtl(); code != http.StatusUnauthorized {
		t.Fatalf("replayed control request status = %d, want 401", code)
	}
	if got := leafApp.topo.leaf.replayed.Load(); got != 1 {
		t.Fatalf("hop_replayed_total = %d, want 1", got)
	}

	// 2. Data-plane claim replay is rejected from fast path (accepted stays 1, replayed becomes 2).
	pageClaim := hop.Claim{Client: netip.MustParseAddr("198.51.100.7"), Class: hop.ClassPage, Proto: "h2"}
	pageHdr := signer.Sign(pageClaim, http.MethodGet, "/shop", "")

	sendPage := func() {
		req, _ := http.NewRequest(http.MethodGet, leafSrv.URL+"/shop", nil)
		req.Header.Set(hop.Header, pageHdr)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	sendPage()
	if got := leafApp.topo.leaf.accepted.Load(); got != 1 {
		t.Fatalf("after first page claim accepted = %d, want 1", got)
	}
	sendPage()
	if got := leafApp.topo.leaf.accepted.Load(); got != 1 {
		t.Fatalf("replayed page claim was accepted! accepted = %d, want 1", got)
	}
	if got := leafApp.topo.leaf.replayed.Load(); got != 2 {
		t.Fatalf("hop_replayed_total = %d, want 2", got)
	}
}

func generateHopTestPKI(t *testing.T, dir string) (caPath, srvCert, srvKey, cliCert, cliKey string) {
	t.Helper()
	writePEM := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "concert-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPath = writePEM("ca.pem", "CERTIFICATE", caDER)

	issue := func(serial int64, cn string, eku x509.ExtKeyUsage) (string, string) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{eku},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
			DNSNames:     []string{"localhost"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		kDER, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return writePEM(cn+".pem", "CERTIFICATE", der), writePEM(cn+"-key.pem", "EC PRIVATE KEY", kDER)
	}

	srvCert, srvKey = issue(2, "leaf-server", x509.ExtKeyUsageServerAuth)
	cliCert, cliKey = issue(3, "edge-client", x509.ExtKeyUsageClientAuth)
	return
}

func TestHopMTLS_PublicBrowserAllowedWhileHopRequiresClientCert(t *testing.T) {
	dir := t.TempDir()
	caPath, srvCert, srvKey, cliCert, cliKey := generateHopTestPKI(t, dir)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("origin-ok"))
	}))
	defer origin.Close()

	secret := []byte("concert-hop-mtls-test-secret-0123456789a")

	leafCfg := testConfig(origin.URL)
	leafCfg.role = roleLeaf
	leafCfg.nodeID = "leaf-mtls"
	leafCfg.hostCap = 10
	leafCfg.hopSecret = secret
	leafCfg.hopPeers = "127.0.0.1/32,::1/128"
	leafCfg.hopReplayGuard = true
	leafCfg.hopRequireNonce = true
	leafCfg.hopRequireMTLS = true
	leafCfg.tlsCert = srvCert
	leafCfg.tlsKey = srvKey
	leafCfg.tlsClientCA = caPath
	leafCfg.abuseEnabled = false

	leafApp, err := newApp(leafCfg)
	if err != nil {
		t.Fatalf("newApp leaf: %v", err)
	}
	t.Cleanup(leafApp.Close)

	tlsCfg, err := newACMETLSConfig(leafCfg)
	if err != nil {
		t.Fatalf("newACMETLSConfig: %v", err)
	}
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(rawLn, tlsCfg)
	leafHTTP := &http.Server{Handler: leafApp.handler}
	go func() { _ = leafHTTP.Serve(tlsLn) }()
	t.Cleanup(func() { _ = leafHTTP.Close() })
	leafURL := "https://" + rawLn.Addr().String()

	caBytes, _ := os.ReadFile(caPath)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caBytes)

	// 1. Public browser (no client cert) can still reach the leaf directly over HTTPS.
	browserClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool}},
		Timeout:   5 * time.Second,
	}
	resp, err := browserClient.Get(leafURL + "/public")
	if err != nil {
		t.Fatalf("public browser GET failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public browser status = %d, want 200", resp.StatusCode)
	}

	// 2. Peer WITHOUT client cert presenting a valid HMAC hop claim to /_room/hop/state is refused (401).
	signer, _ := hop.NewSigner(secret, "edge-no-cert")
	ctlHdr := signer.Sign(hop.Claim{Client: netip.IPv4Unspecified(), Class: hop.ClassControl}, http.MethodGet, hop.StatePath, hop.BodyHash(nil))
	req, _ := http.NewRequest(http.MethodGet, leafURL+hop.StatePath, nil)
	req.Header.Set(hop.Header, ctlHdr)
	resp, err = browserClient.Do(req)
	if err != nil {
		t.Fatalf("non-mTLS control request error: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-mTLS control request status = %d, want 401", resp.StatusCode)
	}
	if got := leafApp.topo.leaf.mtlsRejected.Load(); got != 1 {
		t.Fatalf("hop_mtls_rejected_total = %d, want 1", got)
	}

	// 3. Real Edge configured with mTLS client cert polls and forwards cleanly.
	edgeCfg := testConfig(leafURL)
	edgeCfg.role = roleEdge
	edgeCfg.nodeID = "edge-mtls"
	edgeCfg.capacity = 10
	edgeCfg.priorityCap = 2
	edgeCfg.hopSecret = secret
	edgeCfg.hopAutoCap = true
	edgeCfg.upstreamCA = caPath
	edgeCfg.upstreamClientCert = cliCert
	edgeCfg.upstreamClientKey = cliKey
	edgeCfg.abuseEnabled = false
	edgeApp, edgeSrv := newTestApp(t, edgeCfg, nil)

	plan := edgeApp.edgeRound(context.Background())
	if plan.Leaves != 1 || plan.Total != 10 {
		t.Fatalf("mTLS edgeRound plan = %+v, want Leaves=1 Total=10", plan)
	}
	resp, err = http.Get(edgeSrv.URL + "/via-mtls")
	if err != nil {
		t.Fatalf("GET via mTLS edge: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET via mTLS edge status = %d, want 200", resp.StatusCode)
	}
	if got := leafApp.topo.leaf.accepted.Load(); got != 1 {
		t.Fatalf("leaf accepted = %d, want 1", got)
	}
}
