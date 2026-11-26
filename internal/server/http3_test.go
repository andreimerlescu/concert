package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func generateTestSelfSignedCert(t *testing.T, dir string, dnsNames ...string) (certPath, keyPath string, pool *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              append([]string{"localhost"}, dnsNames...),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath = filepath.Join(dir, "srv.pem")
	keyPath = filepath.Join(dir, "srv.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to parse generated cert PEM")
	}
	return certPath, keyPath, pool
}

func TestHTTP3_ValidationRequiresTLS(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:3000")
	cfg.http3 = true
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "-http3 requires TLS") {
		t.Fatalf("expected -http3 without TLS to fail, got: %v", err)
	}
}

func TestHTTP3_EndToEndQUICAndAltSvc(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello-over-http3:" + r.URL.Path))
	}))
	defer origin.Close()

	dir := t.TempDir()
	root := filepath.Join(dir, "www")
	writeDiskFile(t, filepath.Join(root, "static", "style.css"), []byte("body{color:green}"))
	certPath, keyPath, pool := generateTestSelfSignedCert(t, dir, "h3.example.test")

	cfg := testConfig(origin.URL)
	cfg.tlsCert = certPath
	cfg.tlsKey = keyPath
	cfg.http3 = true
	cfg.staticRoot = root
	cfg.assets = "/static/*"

	a, err := newApp(cfg)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	tlsCfg, _, err := newACMETLSConfigWithManager(a.current().cfg)
	if err != nil {
		t.Fatalf("newACMETLSConfigWithManager: %v", err)
	}

	// Bind UDP ephemeral port for HTTP/3 and wrap handler with Alt-Svc.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	addr := pc.LocalAddr().String()
	handler := altSvcMiddleware(addr, a.handler)
	stopH3, err := startHTTP3OnPacketConn(pc, tlsCfg, handler)
	if err != nil {
		_ = pc.Close()
		t.Fatalf("startHTTP3OnPacketConn: %v", err)
	}
	defer func() {
		if cerr := stopH3(); cerr != nil {
			t.Errorf("stopH3: %v", cerr)
		}
	}()

	// 1. Verify Alt-Svc header is injected on HTTPS HTTP/1.1 / HTTP/2 requests.
	reqTCP := httptest.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
	reqTCP.TLS = &tls.ConnectionState{}
	recTCP := httptest.NewRecorder()
	handler.ServeHTTP(recTCP, reqTCP)
	_, port, _ := net.SplitHostPort(addr)
	wantAlt := `h3=":` + port + `"; ma=2592000`
	if got := recTCP.Header().Get("Alt-Svc"); got != wantAlt {
		t.Fatalf("Alt-Svc = %q, want %q", got, wantAlt)
	}

	// 2. Real QUIC HTTP/3 request through waiting room -> origin + concert_admit cookie!
	h3Tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: "h3.example.test",
		},
	}
	defer h3Tr.Close()
	h3Client := &http.Client{Transport: h3Tr, Timeout: 5 * time.Second}

	resp, err := h3Client.Get("https://" + addr + "/shop")
	if err != nil {
		t.Fatalf("HTTP/3 GET /shop: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 3 || string(body) != "hello-over-http3:/shop" {
		t.Fatalf("HTTP/3 /shop: status=%d proto=%s body=%q", resp.StatusCode, resp.Proto, string(body))
	}
	var admitCk *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == admitCookie {
			admitCk = ck
		}
	}
	if admitCk == nil {
		t.Fatal("HTTP/3 page did not issue concert_admit cookie")
	}

	// 3. Static asset over HTTP/3 with concert_admit cookie (uses H2/H3 multiplexed user cap!).
	reqAsset, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/static/style.css", nil)
	reqAsset.AddCookie(admitCk)
	resp, err = h3Client.Do(reqAsset)
	if err != nil {
		t.Fatalf("HTTP/3 GET /static/style.css: %v", err)
	}
	cssBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 3 || string(cssBody) != "body{color:green}" {
		t.Fatalf("HTTP/3 static asset: status=%d proto=%s body=%q", resp.StatusCode, resp.Proto, string(cssBody))
	}
}
