package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	randv2 "math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	xacme "golang.org/x/crypto/acme"
)

const (
	defaultRenewBefore        = 30 * 24 * time.Hour
	defaultRenewCheckInterval = 1 * time.Hour
	defaultPollInterval       = 2 * time.Second
	defaultIssueTimeout       = 5 * time.Minute
	defaultCleanupTimeout     = 30 * time.Second
	defaultBackoffBase        = 30 * time.Second
	defaultBackoffMax         = 6 * time.Hour
	defaultKVKeyPrefix        = "concert:acme:cert:"
	defaultKVMinTTL           = 1 * time.Hour
	maxRenewalBackoffShift    = 10
)

// TXTLookupFunc resolves DNS TXT records for name. It matches the signature of
// (*net.Resolver).LookupTXT so tests can inject deterministic resolvers.
type TXTLookupFunc func(ctx context.Context, name string) ([]string, error)

// Config configures a DNS-01 wildcard ACME certificate Manager.
type Config struct {
	// Domains lists the allowed exact hostnames ("example.com") and single-label
	// wildcard patterns ("*.example.com"). Required; must contain at least one
	// valid domain.
	Domains []string
	// Email is the optional contact email registered on the ACME account.
	Email string
	// DirectoryURL is the RFC 8555 ACME directory URL. Defaults to
	// xacme.LetsEncryptURL when empty.
	DirectoryURL string
	// CacheDir is the directory used to create a DiskStore when Store is nil.
	// Required if Store is nil.
	CacheDir string
	// Store optionally supplies a pre-initialized DiskStore. When nil, a new
	// DiskStore is created at CacheDir.
	Store *DiskStore
	// Provider provisions and cleans up DNS-01 TXT records. Required.
	Provider DNSProvider
	// HTTPClient optionally overrides the HTTP client used by the ACME client.
	// When nil, a hardened client with TLS 1.2+ and timeouts is created.
	HTTPClient *http.Client
	// TXTLookup optionally overrides DNS TXT propagation lookups. Defaults to
	// net.DefaultResolver.LookupTXT.
	TXTLookup TXTLookupFunc
	// KVSync optionally enables encrypted multi-edge certificate bundle sync.
	KVSync KVBundleSync
	// KVSecret is the operator secret used to derive AES-256-GCM keys when
	// KVSync is non-nil. Required when KVSync is configured (S7 fail-closed).
	KVSecret Secret
	// KVKeyPrefix prefixes keys written to KVSync. Defaults to
	// "concert:acme:cert:".
	KVKeyPrefix string
	// RenewBefore triggers background renewal when a certificate's remaining
	// validity is at or below this duration. Defaults to 30 days.
	RenewBefore time.Duration
	// RenewCheckInterval controls how often the background renewal loop checks
	// certificate expiry. Defaults to 1 hour.
	RenewCheckInterval time.Duration
	// PollInterval controls how often DNS TXT propagation is polled. Defaults
	// to 2 seconds.
	PollInterval time.Duration
	// PropagationTimeout overrides Provider.PropagationTimeout() when > 0.
	PropagationTimeout time.Duration
	// IssueTimeout bounds a single ACME issuance attempt. Defaults to 5 minutes.
	IssueTimeout time.Duration
	// BackoffBase sets the initial exponential backoff delay after a failed
	// background renewal attempt. Defaults to 30 seconds.
	BackoffBase time.Duration
	// BackoffMax caps the exponential backoff delay. Defaults to 6 hours.
	BackoffMax time.Duration
	// Now optionally supplies a clock function (defaults to time.Now).
	Now func() time.Time
	// Logger optionally receives renewal lifecycle diagnostics. Defaults to
	// slog.Default(). Secrets are never logged.
	Logger *slog.Logger
	// AcceptTOS decides whether to accept the CA's Terms of Service during
	// account registration. Defaults to xacme.AcceptTOS.
	AcceptTOS func(tosURL string) bool
}

// inflightCall tracks one deduplicated issuance/load operation for a single
// domain pattern. The creator is the sole writer of cert/err and the sole
// closer of done (C5).
type inflightCall struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

type renewalBackoff struct {
	failures    int
	nextAttempt time.Time
}

type presentedRecord struct {
	fqdn  string
	value string
}

// Manager issues, caches, persists, syncs, and renews exact and wildcard TLS
// certificates using RFC 8555 ACME DNS-01 challenges. It is safe for concurrent
// use.
//
// Concurrency ownership (C2):
//   - exactDomains and wildcardSuffixes are immutable after NewManager.
//   - mu guards certs (published *tls.Certificate pointers are immutable) and
//     inflight singleflight entries. Locks are never held across network or
//     disk I/O (C4).
//   - accountMu serializes lazy ACME account key creation and registration.
//   - lifecycleMu guards started, closed, cancel, and wg for the single
//     background renewal goroutine owned by Start/Close (R2).
type Manager struct {
	domains          []string
	exactDomains     map[string]struct{}
	wildcardSuffixes map[string]string // suffix "example.com" -> "*.example.com"

	email              string
	directoryURL       string
	store              *DiskStore
	provider           DNSProvider
	httpClient         *http.Client
	txtLookup          TXTLookupFunc
	kvSync             KVBundleSync
	cipher             *BundleCipher
	kvKeyPrefix        string
	renewBefore        time.Duration
	renewCheckInterval time.Duration
	pollInterval       time.Duration
	propagationTimeout time.Duration
	issueTimeout       time.Duration
	backoffBase        time.Duration
	backoffMax         time.Duration
	now                func() time.Time
	logger             *slog.Logger
	acceptTOS          func(string) bool

	accountMu    sync.Mutex
	acmeClient   *xacme.Client // guarded by accountMu
	accountReady bool          // guarded by accountMu

	mu       sync.RWMutex
	certs    map[string]*tls.Certificate // guarded by mu; values immutable after publish
	inflight map[string]*inflightCall    // guarded by mu

	lifecycleMu sync.Mutex
	started     bool
	closed      bool
	runCtx      context.Context
	runCancel   context.CancelFunc
	wg          sync.WaitGroup
}

// NewManager validates cfg and constructs an ACME DNS-01 Manager.
//
// # Parameters
//
//   - cfg: Manager configuration. Must provide at least one valid domain in
//     cfg.Domains, a non-nil cfg.Provider, either cfg.Store or cfg.CacheDir,
//     and a non-empty cfg.KVSecret whenever cfg.KVSync is set.
//
// # Returns
//
// A configured *Manager ready to serve GetCertificate and optional background
// renewal via Start/Close, or an error on invalid configuration.
//
// # Example
//
//	mgr, err := acme.NewManager(acme.Config{
//		Domains:  []string{"*.example.com", "example.com"},
//		CacheDir: "/var/lib/concert/acme",
//		Provider: provider,
//	})
//	if err != nil {
//		return err
//	}
//	defer mgr.Close()
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:609 (direct call)
//   - internal/acme/acme_test.go:684 (direct call)
//   - internal/acme/acme_test.go:720 (direct call)
//   - internal/acme/acme_test.go:751 (direct call)
//   - internal/acme/acme_test.go:793 (direct call)
//   - internal/acme/acme_test.go:834 (direct call)
//   - internal/acme/acme_test.go:868 (direct call)
//   - internal/acme/acme_test.go:878 (direct call)
//   - internal/acme/acme_test.go:909 (direct call)
//   - internal/acme/acme_test.go:972 (direct call)
//   - internal/acme/acme_test.go:1286 (direct call)
//   - internal/acme/acme_test.go:1356 (direct call)
//   - internal/acme/acme_test.go:1418 (direct call)
//   - internal/acme/acme_test.go:1504 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.Provider == nil {
		return nil, errors.New("acme: dns provider must not be nil")
	}
	if len(cfg.Domains) == 0 {
		return nil, fmt.Errorf("at least one domain is required: %w", ErrInvalidDomain)
	}

	exact := make(map[string]struct{})
	wildcards := make(map[string]string)
	seen := make(map[string]struct{}, len(cfg.Domains))
	domains := make([]string, 0, len(cfg.Domains))

	for _, raw := range cfg.Domains {
		norm, err := normalizeDomainPattern(raw)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		domains = append(domains, norm)
		if strings.HasPrefix(norm, "*.") {
			wildcards[norm[2:]] = norm
		} else {
			exact[norm] = struct{}{}
		}
	}

	store := cfg.Store
	if store == nil {
		var err error
		store, err = NewDiskStore(cfg.CacheDir)
		if err != nil {
			return nil, err
		}
	}

	var bundleCipher *BundleCipher
	if cfg.KVSync != nil {
		var err error
		bundleCipher, err = NewBundleCipher(cfg.KVSecret)
		if err != nil {
			return nil, fmt.Errorf("kv sync requires encryption secret: %w", err)
		}
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = newHardenedHTTPClient(defaultProviderTimeout)
	}
	txtLookup := cfg.TXTLookup
	if txtLookup == nil {
		txtLookup = net.DefaultResolver.LookupTXT
	}
	dirURL := strings.TrimSpace(cfg.DirectoryURL)
	if dirURL == "" {
		dirURL = xacme.LetsEncryptURL
	}
	kvPrefix := cfg.KVKeyPrefix
	if kvPrefix == "" {
		kvPrefix = defaultKVKeyPrefix
	}
	renewBefore := cfg.RenewBefore
	if renewBefore <= 0 {
		renewBefore = defaultRenewBefore
	}
	renewInterval := cfg.RenewCheckInterval
	if renewInterval <= 0 {
		renewInterval = defaultRenewCheckInterval
	}
	pollInterval := cfg.PollInterval
	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}
	propTimeout := cfg.PropagationTimeout
	if propTimeout <= 0 {
		propTimeout = cfg.Provider.PropagationTimeout()
	}
	if propTimeout <= 0 {
		propTimeout = DefaultPropagationTimeout
	}
	issueTimeout := cfg.IssueTimeout
	if issueTimeout <= 0 {
		issueTimeout = defaultIssueTimeout
	}
	backoffBase := cfg.BackoffBase
	if backoffBase <= 0 {
		backoffBase = defaultBackoffBase
	}
	backoffMax := cfg.BackoffMax
	if backoffMax <= 0 {
		backoffMax = defaultBackoffMax
	}
	if backoffMax < backoffBase {
		backoffMax = backoffBase
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	acceptTOS := cfg.AcceptTOS
	if acceptTOS == nil {
		acceptTOS = xacme.AcceptTOS
	}

	return &Manager{
		domains:            domains,
		exactDomains:       exact,
		wildcardSuffixes:   wildcards,
		email:              strings.TrimSpace(cfg.Email),
		directoryURL:       dirURL,
		store:              store,
		provider:           cfg.Provider,
		httpClient:         httpClient,
		txtLookup:          txtLookup,
		kvSync:             cfg.KVSync,
		cipher:             bundleCipher,
		kvKeyPrefix:        kvPrefix,
		renewBefore:        renewBefore,
		renewCheckInterval: renewInterval,
		pollInterval:       pollInterval,
		propagationTimeout: propTimeout,
		issueTimeout:       issueTimeout,
		backoffBase:        backoffBase,
		backoffMax:         backoffMax,
		now:                nowFn,
		logger:             logger,
		acceptTOS:          acceptTOS,
		certs:              make(map[string]*tls.Certificate),
		inflight:           make(map[string]*inflightCall),
	}, nil
}

// MatchDomain resolves serverName against the Manager's configured exact and
// single-label RFC 6125 wildcard patterns. Exact matches take precedence over
// wildcard matches. Wildcard patterns ("*.example.com") match only a single
// left-most label ("app.example.com") and never match multi-level subdomains
// ("a.b.example.com") or the apex ("example.com").
//
// # Parameters
//
//   - serverName: TLS SNI hostname from a ClientHello (case-insensitive; a
//     single trailing dot is ignored).
//
// # Returns
//
// The matched canonical pattern and true, or ("", false) when serverName is
// invalid or not allowed.
//
// # Example
//
//	pattern, ok := mgr.MatchDomain("app.example.com")
//	if !ok {
//		return acme.ErrHostNotAllowed
//	}
//	_ = pattern
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:1445 (direct call)
//   - internal/acme/manager.go:506 (direct call)
//   - internal/acme/manager.go:506 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) MatchDomain(serverName string) (string, bool) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(serverName)), ".")
	if !isValidConcreteHost(host) {
		return "", false
	}
	if _, ok := m.exactDomains[host]; ok {
		return host, true
	}
	left, rest, ok := strings.Cut(host, ".")
	if !ok || left == "" || rest == "" {
		return "", false
	}
	// Single-label RFC 6125 wildcard match: left has no '.' because strings.Cut
	// splits on the first dot, so "a.b.example.com" produces rest="b.example.com"
	// which will not match "*.example.com" (suffix "example.com").
	if pattern, found := m.wildcardSuffixes[rest]; found {
		return pattern, true
	}
	return "", false
}

// TLSConfig returns a hardened *tls.Config wired to m.GetCertificate with
// TLS 1.2 minimum version and HTTP/2 + HTTP/1.1 ALPN support.
//
// # Parameters
//
// None.
//
// # Returns
//
// A freshly allocated *tls.Config backed by m.GetCertificate.
//
// # Example
//
//	srv := &http.Server{
//		Addr:      ":443",
//		TLSConfig: mgr.TLSConfig(),
//	}
//	_ = srv
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:1455 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1"},
		GetCertificate: m.GetCertificate,
	}
}

// GetCertificate implements crypto/tls.Config.GetCertificate. It matches
// hello.ServerName against configured exact and wildcard domains, returns a
// valid cached certificate immediately when present, or deduplicates on-demand
// disk/KV loading and ACME DNS-01 issuance via per-pattern singleflight.
//
// # Parameters
//
//   - hello: Incoming TLS ClientHello metadata. Must be non-nil with a non-empty
//     ServerName matching a configured domain.
//
// # Returns
//
// A valid *tls.Certificate (immutable; callers must not mutate it), or an error
// wrapping ErrHostNotAllowed, ErrManagerClosed, or the underlying issuance
// failure.
//
// # Concurrency
//
// Safe for concurrent use across TLS handshakes. Concurrent misses for the same
// domain pattern trigger at most one ACME order.
//
// # Example
//
//	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})
//	if err != nil {
//		return err
//	}
//	_ = cert
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:625 (direct call)
//   - internal/acme/acme_test.go:640 (direct call)
//   - internal/acme/acme_test.go:654 (direct call)
//   - internal/acme/acme_test.go:699 (direct call)
//   - internal/acme/acme_test.go:735 (direct call)
//   - internal/acme/acme_test.go:765 (direct call)
//   - internal/acme/acme_test.go:807 (direct call)
//   - internal/acme/acme_test.go:848 (direct call)
//   - internal/acme/acme_test.go:894 (direct call)
//   - internal/acme/acme_test.go:925 (direct call)
//   - internal/acme/acme_test.go:989 (direct call)
//   - internal/acme/acme_test.go:1310 (direct call)
//   - internal/acme/acme_test.go:1374 (direct call)
//   - internal/acme/acme_test.go:1403 (direct call)
//   - internal/acme/acme_test.go:1477 (direct call)
//   - internal/acme/acme_test.go:1523 (direct call)
//   - internal/acme/manager.go:445 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil {
		return nil, fmt.Errorf("nil client hello: %w", ErrHostNotAllowed)
	}
	pattern, ok := m.MatchDomain(hello.ServerName)
	if !ok {
		return nil, fmt.Errorf("server name %q: %w", hello.ServerName, ErrHostNotAllowed)
	}

	now := m.now()
	m.mu.RLock()
	cached := m.certs[pattern]
	m.mu.RUnlock()
	if cached != nil && isCertUsable(cached, pattern, now) {
		return cached, nil
	}

	ctx := hello.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return m.ensureCert(ctx, pattern, false)
}

// Start launches the single bounded background renewal goroutine owned by m.
// The loop checks all configured domains on RenewCheckInterval, renews any
// certificate within RenewBefore of expiry with exponential backoff + jitter on
// failures (E4), and exits when ctx is cancelled or Close is called (R2).
//
// # Parameters
//
//   - ctx: Parent context controlling background renewal lifetime. Must be
//     non-nil.
//
// # Returns
//
// nil on start, ErrAlreadyStarted if already running, or ErrManagerClosed if
// Close was already called.
//
// # Example
//
//	if err := mgr.Start(ctx); err != nil {
//		return err
//	}
//	defer mgr.Close()
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:1379 (direct call)
//   - internal/acme/acme_test.go:1382 (direct call)
//   - internal/acme/acme_test.go:1400 (direct call)
//   - internal/acme/acme_test.go:1526 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("acme: start context must not be nil")
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()

	if m.closed {
		return ErrManagerClosed
	}
	if m.started {
		return ErrAlreadyStarted
	}
	runCtx, cancel := context.WithCancel(ctx)
	m.started = true
	m.runCtx = runCtx
	m.runCancel = cancel

	// Background goroutine ownership (C1/R2):
	//   Owner: Manager (started once by Start)
	//   Stop:  runCancel (via Close) or parent ctx cancellation
	//   Join:  m.wg.Wait() inside Close
	m.wg.Go(func() {
		m.renewalLoop(runCtx)
	})
	return nil
}

// Close stops the background renewal loop (if running) and waits for it to exit
// cleanly. Close is idempotent and safe to call even if Start was never called.
//
// # Parameters
//
// None.
//
// # Returns
//
// Always returns nil after the background goroutine has exited.
//
// # Example
//
//	if err := mgr.Close(); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:622 (direct call)
//   - internal/acme/acme_test.go:697 (direct call)
//   - internal/acme/acme_test.go:733 (direct call)
//   - internal/acme/acme_test.go:763 (direct call)
//   - internal/acme/acme_test.go:805 (direct call)
//   - internal/acme/acme_test.go:846 (direct call)
//   - internal/acme/acme_test.go:892 (direct call)
//   - internal/acme/acme_test.go:923 (direct call)
//   - internal/acme/acme_test.go:987 (direct call)
//   - internal/acme/acme_test.go:1298 (direct call)
//   - internal/acme/acme_test.go:1392 (direct call)
//   - internal/acme/acme_test.go:1396 (direct call)
//   - internal/acme/acme_test.go:1430 (direct call)
//   - internal/acme/acme_test.go:1474 (direct call)
//   - internal/acme/acme_test.go:1521 (direct call)
//   - internal/acme/acme_test.go:1535 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) Close() error {
	m.lifecycleMu.Lock()
	if m.closed {
		m.lifecycleMu.Unlock()
		return nil
	}
	m.closed = true
	cancel := m.runCancel
	m.lifecycleMu.Unlock()

	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
	return nil
}

// isClosed reports whether Close has been called on m.
//
// # Parameters
//
// None.
//
// # Returns
//
// true if Close was called, false otherwise.
//
// # Example
//
//	if m.isClosed() {
//		return nil, ErrManagerClosed
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:708 (direct call)
//   - internal/acme/manager.go:708 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) isClosed() bool {
	m.lifecycleMu.Lock()
	closed := m.closed
	m.lifecycleMu.Unlock()
	return closed
}

// ensureCert obtains a valid certificate for pattern using per-pattern
// singleflight deduplication so concurrent callers share a single disk/KV load
// or ACME issuance.
//
// # Parameters
//
//   - ctx: Caller context for waiting on the in-flight operation.
//   - pattern: Canonical domain or wildcard pattern.
//   - forceRenew: When true, bypasses cached/disk/KV reuse and issues a fresh
//     certificate via ACME.
//
// # Returns
//
// The valid *tls.Certificate, or an error if closed, cancelled, or issuance
// failed.
//
// # Example
//
//	cert, err := m.ensureCert(ctx, "*.example.com", false)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:523 (direct call)
//   - internal/acme/manager.go:523 (function value)
//   - internal/acme/manager.go:1347 (direct call)
//   - internal/acme/manager.go:1347 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) ensureCert(ctx context.Context, pattern string, forceRenew bool) (*tls.Certificate, error) {
	if m.isClosed() {
		return nil, ErrManagerClosed
	}

	m.mu.Lock()
	if !forceRenew {
		if cached := m.certs[pattern]; cached != nil && isCertUsable(cached, pattern, m.now()) {
			m.mu.Unlock()
			return cached, nil
		}
	}
	if call, ok := m.inflight[pattern]; ok {
		m.mu.Unlock()
		select {
		case <-call.done:
			return call.cert, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &inflightCall{done: make(chan struct{})}
	m.inflight[pattern] = call
	m.mu.Unlock()

	// Run the actual acquisition with a bounded timeout derived from a
	// non-cancelled base (unless the manager itself stops) so one TLS handshake
	// disconnecting cannot abort an ACME order shared by other waiting callers.
	opCtx, opCancel := m.operationContext(ctx)
	cert, err := m.acquireCert(opCtx, pattern, forceRenew)
	opCancel()

	m.mu.Lock()
	if err == nil && cert != nil {
		m.certs[pattern] = cert
	}
	delete(m.inflight, pattern)
	call.cert = cert
	call.err = err
	close(call.done) // sole closer (C5)
	m.mu.Unlock()

	return cert, err
}

// operationContext constructs the bounded context for a singleflight leader,
// tied to the manager's shutdown signal (if started) and IssueTimeout rather
// than a single transient caller handshake context.
//
// # Parameters
//
//   - callerCtx: Waiter context; if already cancelled before the operation
//     starts, cancellation is respected immediately.
//
// # Returns
//
// A cancellable child context and its cancel function (caller must invoke it).
//
// # Example
//
//	opCtx, cancel := m.operationContext(ctx)
//	defer cancel()
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:735 (direct call)
//   - internal/acme/manager.go:735 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) operationContext(callerCtx context.Context) (context.Context, context.CancelFunc) {
	if callerCtx.Err() != nil {
		return context.WithCancel(callerCtx)
	}
	m.lifecycleMu.Lock()
	base := m.runCtx
	m.lifecycleMu.Unlock()
	if base == nil {
		base = context.WithoutCancel(callerCtx)
	}
	return context.WithTimeout(base, m.issueTimeout)
}

// acquireCert resolves a certificate for pattern by checking local disk,
// optional encrypted KV sync, and finally RFC 8555 ACME DNS-01 issuance.
//
// # Parameters
//
//   - ctx: Bounded context for KV and ACME network operations.
//   - pattern: Canonical domain or wildcard pattern.
//   - forceRenew: When true, skips local disk reuse and forces a fresh check/issuance.
//
// # Returns
//
// A valid *tls.Certificate, or an error.
//
// # Example
//
//	cert, err := m.acquireCert(ctx, "*.example.com", false)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:736 (direct call)
//   - internal/acme/manager.go:736 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) acquireCert(ctx context.Context, pattern string, forceRenew bool) (*tls.Certificate, error) {
	now := m.now()

	if !forceRenew {
		if cert, err := m.store.LoadCertificate(pattern); err == nil && isCertUsable(cert, pattern, now) {
			return cert, nil
		}
	}

	if m.kvSync != nil {
		cert, bundlePEM, ok, err := m.loadFromKV(ctx, pattern)
		if err != nil {
			m.logger.Warn("acme kv bundle load failed; falling back to local issuance",
				"pattern", pattern, "error", err)
		} else if ok && isCertUsable(cert, pattern, now) && (!forceRenew || !m.needsRenewal(cert, now)) {
			// Persist synced bundle locally so subsequent restarts reload from disk.
			if serr := m.store.SaveBundlePEM(pattern, bundlePEM); serr != nil {
				m.logger.Warn("acme disk persist after kv sync failed",
					"pattern", pattern, "error", serr)
			}
			return cert, nil
		}
	}

	return m.issueACME(ctx, pattern)
}

// issueACME drives a complete RFC 8555 ACME DNS-01 order for pattern, always
// cleaning up presented TXT records via defer before returning.
//
// # Parameters
//
//   - ctx: Controls cancellation and timeout for ACME and DNS provider calls.
//   - pattern: Canonical domain or wildcard pattern (e.g. "*.example.com").
//
// # Returns
//
// The newly issued and persisted *tls.Certificate, or an error.
//
// # Example
//
//	cert, err := m.issueACME(ctx, "*.example.com")
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:842 (direct call)
//   - internal/acme/manager.go:842 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) issueACME(ctx context.Context, pattern string) (cert *tls.Certificate, retErr error) {
	client, err := m.ensureACMEClient(ctx)
	if err != nil {
		return nil, err
	}

	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(pattern))
	if err != nil {
		return nil, fmt.Errorf("acme authorize order %q: %w", pattern, err)
	}

	var presented []presentedRecord
	// Guarantee DNS-01 TXT cleanup on both success and failure using a detached
	// bounded timeout so caller cancellation cannot orphan TXT records.
	defer func() {
		if len(presented) == 0 {
			return
		}
		cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultCleanupTimeout)
		defer cancel()
		for _, rec := range presented {
			if cerr := m.provider.CleanUp(cleanCtx, rec.fqdn, rec.value); cerr != nil {
				m.logger.Warn("acme dns-01 cleanup failed",
					"fqdn", rec.fqdn, "error", cerr)
			}
		}
	}()

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, fmt.Errorf("acme get authorization %q: %w", pattern, err)
		}
		if authz.Status == xacme.StatusValid {
			continue
		}

		chal := findDNS01Challenge(authz.Challenges)
		if chal == nil {
			return nil, fmt.Errorf("acme authorization for %q has no dns-01 challenge", pattern)
		}

		val, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return nil, fmt.Errorf("acme compute dns-01 record %q: %w", pattern, err)
		}
		fqdn := challengeRecordFQDN(authz.Identifier.Value, pattern)

		if err := m.provider.Present(ctx, fqdn, val); err != nil {
			return nil, fmt.Errorf("acme present dns-01 %q: %w", fqdn, err)
		}
		// Record immediately after Present succeeds so the defer cleans it up
		// even if propagation polling or CA validation fails.
		presented = append(presented, presentedRecord{fqdn: fqdn, value: val})

		if err := m.waitTXTPropagation(ctx, fqdn, val); err != nil {
			return nil, err
		}
		if _, err := client.Accept(ctx, chal); err != nil {
			return nil, fmt.Errorf("acme accept dns-01 challenge %q: %w", pattern, err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			return nil, fmt.Errorf("acme wait authorization %q: %w", pattern, err)
		}
	}

	readyOrder, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("acme wait order %q: %w", pattern, err)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ecdsa p256 cert key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{pattern},
	}, certKey)
	if err != nil {
		return nil, fmt.Errorf("create csr %q: %w", pattern, err)
	}

	derChain, _, err := client.CreateOrderCert(ctx, readyOrder.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, fmt.Errorf("acme create order cert %q: %w", pattern, err)
	}

	bundlePEM, err := EncodeBundlePEM(derChain, certKey)
	if err != nil {
		return nil, fmt.Errorf("encode cert bundle %q: %w", pattern, err)
	}
	parsed, err := ParseBundlePEM(bundlePEM)
	if err != nil {
		return nil, fmt.Errorf("parse issued cert %q: %w", pattern, err)
	}
	if err := m.store.SaveBundlePEM(pattern, bundlePEM); err != nil {
		return nil, fmt.Errorf("persist cert bundle %q: %w", pattern, err)
	}
	if m.kvSync != nil {
		if err := m.saveToKV(ctx, pattern, bundlePEM, parsed.Leaf.NotAfter); err != nil {
			m.logger.Warn("acme kv bundle sync push failed",
				"pattern", pattern, "error", err)
		}
	}
	return parsed, nil
}

// ensureACMEClient lazily loads or generates the ECDSA P-256 ACME account key,
// persists it atomically (0600), and registers the account with the CA.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadlines for account registration.
//
// # Returns
//
// The initialized *xacme.Client, or an error.
//
// # Example
//
//	client, err := m.ensureACMEClient(ctx)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:871 (direct call)
//   - internal/acme/manager.go:871 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) ensureACMEClient(ctx context.Context) (*xacme.Client, error) {
	m.accountMu.Lock()
	defer m.accountMu.Unlock()

	if m.accountReady && m.acmeClient != nil {
		return m.acmeClient, nil
	}

	key, err := m.store.LoadAccountKey()
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("load acme account key: %w", err)
		}
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate acme account key: %w", err)
		}
		if err := m.store.SaveAccountKey(key); err != nil {
			return nil, fmt.Errorf("save acme account key: %w", err)
		}
	}

	client := &xacme.Client{
		Key:          key,
		HTTPClient:   m.httpClient,
		DirectoryURL: m.directoryURL,
		UserAgent:    "concert-acme-dns01/1.0",
	}

	acct := &xacme.Account{}
	if m.email != "" {
		acct.Contact = []string{"mailto:" + m.email}
	}
	if _, err := client.Register(ctx, acct, m.acceptTOS); err != nil {
		if !errors.Is(err, xacme.ErrAccountAlreadyExists) {
			return nil, fmt.Errorf("acme register account: %w", err)
		}
		if _, gerr := client.GetReg(ctx, ""); gerr != nil {
			return nil, fmt.Errorf("acme fetch existing registration: %w", gerr)
		}
	}

	m.acmeClient = client
	m.accountReady = true
	return client, nil
}

// waitTXTPropagation polls TXTLookup until expected appears in the TXT records
// for fqdn, or returns ErrPropagationTimeout / ctx.Err().
//
// # Parameters
//
//   - ctx: Controls cancellation and deadlines.
//   - fqdn: Challenge TXT domain name to query.
//   - expected: Exact RFC 8555 DNS-01 digest expected in the TXT record set.
//
// # Returns
//
// nil once expected is observed, or an error wrapping ErrPropagationTimeout or
// context cancellation.
//
// # Example
//
//	if err := m.waitTXTPropagation(ctx, "_acme-challenge.example.com", digest); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:925 (direct call)
//   - internal/acme/manager.go:925 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) waitTXTPropagation(ctx context.Context, fqdn, expected string) error {
	deadlineCtx, cancel := context.WithTimeout(ctx, m.propagationTimeout)
	defer cancel()

	// Check immediately before waiting for the first poll interval.
	if found, err := m.hasTXTRecord(deadlineCtx, fqdn, expected); err == nil && found {
		return nil
	}

	timer := time.NewTimer(m.pollInterval)
	defer timer.Stop()

	for {
		select {
		case <-deadlineCtx.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("txt record %q not observed within %s: %w", fqdn, m.propagationTimeout, ErrPropagationTimeout)
		case <-timer.C:
			if found, err := m.hasTXTRecord(deadlineCtx, fqdn, expected); err == nil && found {
				return nil
			}
			timer.Reset(m.pollInterval)
		}
	}
}

// hasTXTRecord executes a single TXT lookup for fqdn and reports whether
// expected is present.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadline for the DNS lookup.
//   - fqdn: Domain name to query.
//   - expected: Expected TXT value.
//
// # Returns
//
// (true, nil) if expected matches one of the returned records.
//
// # Example
//
//	ok, err := m.hasTXTRecord(ctx, "_acme-challenge.example.com", digest)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:1082 (direct call)
//   - internal/acme/manager.go:1082 (function value)
//   - internal/acme/manager.go:1097 (direct call)
//   - internal/acme/manager.go:1097 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) hasTXTRecord(ctx context.Context, fqdn, expected string) (bool, error) {
	records, err := m.txtLookup(ctx, fqdn)
	if err != nil {
		return false, err
	}
	for _, rec := range records {
		if strings.TrimSpace(rec) == expected {
			return true, nil
		}
	}
	return false, nil
}

// loadFromKV retrieves, decrypts, and parses a certificate bundle from KVSync.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadline for KVSync.Get.
//   - pattern: Canonical domain or wildcard pattern.
//
// # Returns
//
// (cert, bundlePEM, true, nil) when found and authenticated; (nil, nil, false, nil)
// on miss; or an error on KV I/O or tampering/decryption failure.
//
// # Example
//
//	cert, pemBytes, ok, err := m.loadFromKV(ctx, "*.example.com")
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:828 (direct call)
//   - internal/acme/manager.go:828 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) loadFromKV(ctx context.Context, pattern string) (*tls.Certificate, []byte, bool, error) {
	kvKey := m.kvKey(pattern)
	sealed, ok, err := m.kvSync.Get(ctx, kvKey)
	if err != nil || !ok {
		return nil, nil, ok, err
	}
	plain, err := m.cipher.Decrypt(pattern, sealed)
	if err != nil {
		return nil, nil, false, err
	}
	cert, err := ParseBundlePEM(plain)
	if err != nil {
		return nil, nil, false, err
	}
	return cert, plain, true, nil
}

// saveToKV encrypts bundlePEM and writes it to KVSync with a TTL derived from
// the certificate's remaining lifetime.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadline for KVSync.Set.
//   - pattern: Canonical domain or wildcard pattern.
//   - bundlePEM: Combined PEM certificate and private key bundle.
//   - notAfter: Leaf certificate expiration timestamp.
//
// # Returns
//
// nil on success, or an encryption/KV storage error.
//
// # Example
//
//	err := m.saveToKV(ctx, "*.example.com", bundlePEM, cert.Leaf.NotAfter)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:969 (direct call)
//   - internal/acme/manager.go:969 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) saveToKV(ctx context.Context, pattern string, bundlePEM []byte, notAfter time.Time) error {
	sealed, err := m.cipher.Encrypt(pattern, bundlePEM)
	if err != nil {
		return err
	}
	ttl := notAfter.Sub(m.now())
	if ttl < defaultKVMinTTL {
		ttl = defaultKVMinTTL
	}
	return m.kvSync.Set(ctx, m.kvKey(pattern), sealed, ttl)
}

// kvKey builds the namespaced KV storage key for pattern.
//
// # Parameters
//
//   - pattern: Canonical domain or wildcard pattern.
//
// # Returns
//
// The prefixed KV key string.
//
// # Example
//
//	key := m.kvKey("*.example.com")
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:1172 (direct call)
//   - internal/acme/manager.go:1172 (function value)
//   - internal/acme/manager.go:1224 (direct call)
//   - internal/acme/manager.go:1224 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) kvKey(pattern string) string {
	return m.kvKeyPrefix + pattern
}

// renewalLoop runs on the background goroutine owned by Start/Close, checking
// all configured domains periodically and renewing certificates approaching
// expiration with bounded exponential backoff and jitter (E4/R2).
//
// # Parameters
//
//   - ctx: Service-owned context cancelled by Close or parent cancellation.
//
// # Example
//
//	m.wg.Go(func() { m.renewalLoop(runCtx) })
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:582 (direct call)
//   - internal/acme/manager.go:582 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) renewalLoop(ctx context.Context) {
	backoffs := make(map[string]renewalBackoff, len(m.domains))
	m.checkRenewals(ctx, backoffs)

	ticker := time.NewTicker(m.renewCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkRenewals(ctx, backoffs)
		}
	}
}

// checkRenewals inspects each configured domain once and renews any certificate
// that is missing or within RenewBefore of expiry, respecting per-domain
// exponential backoff windows.
//
// # Parameters
//
//   - ctx: Background renewal context.
//   - backoffs: Per-domain failure backoff state owned exclusively by
//     renewalLoop.
//
// # Example
//
//	m.checkRenewals(ctx, backoffs)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:1279 (direct call)
//   - internal/acme/manager.go:1279 (function value)
//   - internal/acme/manager.go:1289 (direct call)
//   - internal/acme/manager.go:1289 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) checkRenewals(ctx context.Context, backoffs map[string]renewalBackoff) {
	for _, pattern := range m.domains {
		if ctx.Err() != nil {
			return
		}
		now := m.now()
		if st, ok := backoffs[pattern]; ok && now.Before(st.nextAttempt) {
			continue
		}

		cert := m.currentCert(pattern)
		if cert == nil {
			if loaded, err := m.store.LoadCertificate(pattern); err == nil && isCertUsable(loaded, pattern, now) {
				m.mu.Lock()
				if m.certs[pattern] == nil {
					m.certs[pattern] = loaded
				}
				m.mu.Unlock()
				cert = loaded
			}
		}

		if cert != nil && !m.needsRenewal(cert, now) {
			delete(backoffs, pattern)
			continue
		}

		forceRenew := cert != nil
		if _, err := m.ensureCert(ctx, pattern, forceRenew); err != nil {
			if ctx.Err() != nil {
				return
			}
			st := backoffs[pattern]
			st.failures++
			delay := m.computeBackoff(st.failures)
			st.nextAttempt = m.now().Add(delay)
			backoffs[pattern] = st
			m.logger.Warn("acme background renewal failed",
				"pattern", pattern,
				"failures", st.failures,
				"retry_in", delay,
				"error", err)
			continue
		}
		delete(backoffs, pattern)
	}
}

// currentCert returns the currently cached certificate for pattern, or nil.
//
// # Parameters
//
//   - pattern: Canonical domain or wildcard pattern.
//
// # Returns
//
// The cached *tls.Certificate, or nil if not cached in memory.
//
// # Example
//
//	cert := m.currentCert("*.example.com")
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:1329 (direct call)
//   - internal/acme/manager.go:1329 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) currentCert(pattern string) *tls.Certificate {
	m.mu.RLock()
	cert := m.certs[pattern]
	m.mu.RUnlock()
	return cert
}

// needsRenewal reports whether cert is expired or within m.renewBefore of
// expiration at instant now.
//
// # Parameters
//
//   - cert: Certificate with Leaf populated.
//   - now: Current timestamp.
//
// # Returns
//
// true if cert is nil, has a nil Leaf, or expires within m.renewBefore.
//
// # Example
//
//	if m.needsRenewal(cert, time.Now()) {
//		// Trigger renewal.
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:832 (direct call)
//   - internal/acme/manager.go:832 (function value)
//   - internal/acme/manager.go:1341 (direct call)
//   - internal/acme/manager.go:1341 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) needsRenewal(cert *tls.Certificate, now time.Time) bool {
	if cert == nil || cert.Leaf == nil {
		return true
	}
	return !now.Add(m.renewBefore).Before(cert.Leaf.NotAfter)
}

// computeBackoff calculates a bounded exponential backoff duration with
// symmetric jitter (50%-100% full jitter) for consecutive renewal failure n
// (E4).
//
// # Parameters
//
//   - failures: 1-based count of consecutive renewal failures.
//
// # Returns
//
// A positive duration bounded by m.backoffMax.
//
// # Example
//
//	delay := m.computeBackoff(3)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:1353 (direct call)
//   - internal/acme/manager.go:1353 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (m *Manager) computeBackoff(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	shift := failures - 1
	if shift > maxRenewalBackoffShift {
		shift = maxRenewalBackoffShift
	}
	delay := m.backoffBase
	for range shift {
		if delay >= m.backoffMax/2 {
			delay = m.backoffMax
			break
		}
		delay *= 2
	}
	if delay > m.backoffMax {
		delay = m.backoffMax
	}
	// Apply 50%..100% jitter so multiple edges do not retry in lockstep.
	half := delay / 2
	if half <= 0 {
		return delay
	}
	return half + time.Duration(randv2.Int64N(int64(half)+1))
}

// findDNS01Challenge selects the first "dns-01" challenge from challenges.
//
// # Parameters
//
//   - challenges: Slice of ACME challenges returned by an authorization.
//
// # Returns
//
// The matching *xacme.Challenge, or nil if none is present.
//
// # Example
//
//	chal := findDNS01Challenge(authz.Challenges)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:907 (direct call)
//   - internal/acme/manager.go:907 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func findDNS01Challenge(challenges []*xacme.Challenge) *xacme.Challenge {
	for _, c := range challenges {
		if c != nil && c.Type == "dns-01" {
			return c
		}
	}
	return nil
}

// challengeRecordFQDN computes the RFC 8555 §8.4 DNS-01 TXT record name
// ("_acme-challenge.<base-domain>") for an authorization identifier.
//
// # Parameters
//
//   - identValue: Identifier value returned by the ACME CA.
//   - fallbackPattern: Canonical order pattern used if identValue is empty.
//
// # Returns
//
// The normalized "_acme-challenge.<domain>" FQDN without a trailing dot.
//
// # Example
//
//	fqdn := challengeRecordFQDN("example.com", "*.example.com")
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:916 (direct call)
//   - internal/acme/manager.go:916 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func challengeRecordFQDN(identValue, fallbackPattern string) string {
	base := strings.TrimSpace(identValue)
	if base == "" {
		base = fallbackPattern
	}
	base = strings.TrimSuffix(strings.ToLower(base), ".")
	base = strings.TrimPrefix(base, "*.")
	return "_acme-challenge." + base
}

// isCertUsable reports whether cert has a parsed Leaf valid at now and covers
// pattern.
//
// # Parameters
//
//   - cert: Candidate *tls.Certificate.
//   - pattern: Canonical domain or wildcard pattern.
//   - now: Current timestamp.
//
// # Returns
//
// true if cert is valid at now and includes pattern in its SAN/Subject.
//
// # Example
//
//	if isCertUsable(cert, "*.example.com", time.Now()) {
//		return cert, nil
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:515 (direct call)
//   - internal/acme/manager.go:515 (function value)
//   - internal/acme/manager.go:714 (direct call)
//   - internal/acme/manager.go:714 (function value)
//   - internal/acme/manager.go:822 (direct call)
//   - internal/acme/manager.go:822 (function value)
//   - internal/acme/manager.go:832 (direct call)
//   - internal/acme/manager.go:832 (function value)
//   - internal/acme/manager.go:1331 (direct call)
//   - internal/acme/manager.go:1331 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func isCertUsable(cert *tls.Certificate, pattern string, now time.Time) bool {
	if cert == nil || cert.Leaf == nil {
		return false
	}
	if now.Before(cert.Leaf.NotBefore) || !now.Before(cert.Leaf.NotAfter) {
		return false
	}
	for _, dnsName := range cert.Leaf.DNSNames {
		if strings.EqualFold(strings.TrimSuffix(dnsName, "."), pattern) {
			return true
		}
	}
	return strings.EqualFold(strings.TrimSuffix(cert.Leaf.Subject.CommonName, "."), pattern)
}

// normalizeDomainPattern validates and canonicalizes an exact hostname or
// single-label wildcard pattern ("*.example.com").
//
// # Parameters
//
//   - raw: User-supplied domain or wildcard pattern.
//
// # Returns
//
// Canonical lowercase pattern without trailing dot, or ErrInvalidDomain.
//
// # Example
//
//	norm, err := normalizeDomainPattern("*.Example.COM.")
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:234 (direct call)
//   - internal/acme/manager.go:234 (function value)
//   - internal/acme/store.go:525 (direct call)
//   - internal/acme/store.go:525 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func normalizeDomainPattern(raw string) (string, error) {
	s := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if s == "" {
		return "", fmt.Errorf("empty domain: %w", ErrInvalidDomain)
	}
	if strings.HasPrefix(s, "*.") {
		base := s[2:]
		if !isValidConcreteHost(base) {
			return "", fmt.Errorf("invalid wildcard domain %q: %w", raw, ErrInvalidDomain)
		}
		return "*." + base, nil
	}
	if strings.Contains(s, "*") {
		return "", fmt.Errorf("wildcard only permitted as single leading label in %q: %w", raw, ErrInvalidDomain)
	}
	if !isValidConcreteHost(s) {
		return "", fmt.Errorf("invalid domain %q: %w", raw, ErrInvalidDomain)
	}
	return s, nil
}

// isValidConcreteHost validates that host is a syntactically valid multi-label
// DNS hostname (not an IP address, no wildcards, valid RFC 1035/1123 labels).
//
// # Parameters
//
//   - host: Lowercase hostname without a trailing dot.
//
// # Returns
//
// true when host is a valid FQDN with at least two labels.
//
// # Example
//
//	ok := isValidConcreteHost("app.example.com") // true
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:395 (direct call)
//   - internal/acme/manager.go:395 (function value)
//   - internal/acme/manager.go:1636 (direct call)
//   - internal/acme/manager.go:1636 (function value)
//   - internal/acme/manager.go:1644 (direct call)
//   - internal/acme/manager.go:1644 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func isValidConcreteHost(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	if !strings.Contains(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			valid := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
			if !valid {
				return false
			}
		}
	}
	return true
}
