// Package acme implements a pure-stdlib RFC 8555 ACME DNS-01 wildcard TLS
// certificate manager built on golang.org/x/crypto/acme.
//
// It provides:
//   - Pluggable DNS-01 challenge providers (Cloudflare API v4 and generic
//     HTTPS webhook) with strict HTTP timeouts, bounded response reads, and
//     redacting credential wrappers.
//   - Atomic 0600 on-disk persistence for ACME account keys and certificate
//     bundles with strict filename sanitization.
//   - Optional AES-256-GCM authenticated bundle encryption (HKDF-SHA256 key
//     derivation) for multi-edge KV synchronization without storing plaintext
//     private keys in KV.
//   - Concurrent-safe GetCertificate matching exact and single-label RFC 6125
//     wildcard hostnames with per-pattern singleflight deduplication and a
//     bounded background renewal loop.
package acme

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// SecretPlaceholder is the fixed redaction marker emitted by Secret on
	// every formatting, logging, text, and JSON serialization path.
	SecretPlaceholder = "[REDACTED]"

	// DefaultCloudflareBaseURL is the production Cloudflare API v4 root URL.
	DefaultCloudflareBaseURL = "https://api.cloudflare.com/client/v4"

	// DefaultPropagationTimeout is the default maximum duration to wait for a
	// DNS-01 TXT record to become visible to resolvers.
	DefaultPropagationTimeout = 2 * time.Minute

	defaultCloudflareTTL     = 120
	defaultProviderTimeout   = 30 * time.Second
	maxProviderResponseBytes = 1 << 20 // 1 MiB response bound (R3)
	maxErrorSnippetBytes     = 512
)

// Sentinel errors returned by package acme. None of these errors or their
// wrappers embed raw secret values.
var (
	// ErrEmptySecret indicates a required credential or encryption secret was empty.
	ErrEmptySecret = errors.New("acme: secret must not be empty")
	// ErrInsecureURL indicates a provider endpoint violated the HTTPS policy.
	ErrInsecureURL = errors.New("acme: provider endpoint must use https")
	// ErrProviderFailed indicates a DNS-01 provider returned an error response.
	ErrProviderFailed = errors.New("acme: dns provider request failed")
	// ErrPropagationTimeout indicates a DNS-01 TXT record did not propagate in time.
	ErrPropagationTimeout = errors.New("acme: dns-01 txt propagation timed out")
	// ErrHostNotAllowed indicates the SNI hostname does not match any configured domain.
	ErrHostNotAllowed = errors.New("acme: hostname not allowed")
	// ErrInvalidDomain indicates a configured domain or wildcard pattern is invalid.
	ErrInvalidDomain = errors.New("acme: invalid domain pattern")
	// ErrCorruptBundle indicates a stored or synced certificate bundle failed validation or authentication.
	ErrCorruptBundle = errors.New("acme: corrupt or tampered certificate bundle")
	// ErrNotFound indicates a requested key or certificate bundle does not exist.
	ErrNotFound = errors.New("acme: item not found")
	// ErrManagerClosed indicates an operation was attempted on a closed Manager.
	ErrManagerClosed = errors.New("acme: manager closed")
	// ErrAlreadyStarted indicates Start was called more than once on a Manager.
	ErrAlreadyStarted = errors.New("acme: manager already started")
)

// Secret holds a sensitive credential or encryption key so it cannot leak into
// logs, fmt output, JSON, text encodings, or error strings. Its zero value is
// empty and reports IsZero() == true. Secret is an immutable value type.
type Secret struct {
	v string
}

// NewSecret wraps raw in a redacting Secret value.
//
// # Parameters
//
//   - raw: The raw credential string. Leading and trailing whitespace is
//     preserved; callers reading from files or environment variables should
//     trim as appropriate before calling NewSecret.
//
// # Returns
//
// A Secret whose formatting and marshaling methods always emit
// SecretPlaceholder, and whose Reveal method returns raw.
//
// # Example
//
//	tok := acme.NewSecret(os.Getenv("CLOUDFLARE_API_TOKEN"))
//	if tok.IsZero() {
//		return acme.ErrEmptySecret
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:37 (direct call)
//   - internal/acme/acme_test.go:865 (direct call)
//   - internal/acme/acme_test.go:958 (direct call)
//   - internal/acme/acme_test.go:1006 (direct call)
//   - internal/acme/acme_test.go:1085 (direct call)
//   - internal/acme/acme_test.go:1185 (direct call)
//   - internal/acme/acme_test.go:1225 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func NewSecret(raw string) Secret {
	return Secret{v: raw}
}

// NewSecretBytes wraps a copy of raw in a redacting Secret value.
//
// # Parameters
//
//   - raw: Sensitive bytes to wrap. The input slice is copied into an immutable
//     string and is not retained or mutated.
//
// # Returns
//
// A Secret containing a copy of raw.
//
// # Example
//
//	key := acme.NewSecretBytes([]byte("operator-kv-secret"))
//	_ = key.IsZero()
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func NewSecretBytes(raw []byte) Secret {
	return Secret{v: string(raw)}
}

// Reveal returns the raw secret string. Call Reveal only at the single point
// of use (such as setting an Authorization header or deriving a key) and never
// pass its result to logs, errors, metrics, or fmt verbs.
//
// # Parameters
//
// None.
//
// # Returns
//
// The underlying raw string (empty for the zero Secret).
//
// # Example
//
//	req.Header.Set("Authorization", "Bearer "+token.Reveal())
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:1262 (direct call)
//   - internal/acme/provider.go:894 (direct call)
//   - internal/acme/provider.go:894 (function value)
//   - internal/acme/provider.go:1226 (direct call)
//   - internal/acme/provider.go:1226 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (s Secret) Reveal() string {
	return s.v
}

// RevealBytes returns a fresh byte slice copy of the raw secret. Callers must
// not log or serialize the returned slice.
//
// # Parameters
//
// None.
//
// # Returns
//
// A newly allocated []byte containing the raw secret bytes, or nil if empty.
//
// # Example
//
//	raw := secret.RevealBytes()
//	if len(raw) == 0 {
//		return acme.ErrEmptySecret
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:1262 (direct call)
//   - internal/acme/store.go:766 (direct call)
//   - internal/acme/store.go:766 (function value)
//   - internal/acme/store.go:839 (direct call)
//   - internal/acme/store.go:839 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (s Secret) RevealBytes() []byte {
	if s.v == "" {
		return nil
	}
	return []byte(s.v)
}

// IsZero reports whether the Secret holds an empty value.
//
// # Parameters
//
// None.
//
// # Returns
//
// true if no non-empty secret value is stored, false otherwise.
//
// # Example
//
//	var s acme.Secret
//	fmt.Println(s.IsZero()) // true
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/provider.go:519 (direct call)
//   - internal/acme/provider.go:519 (function value)
//   - internal/acme/provider.go:1224 (direct call)
//   - internal/acme/provider.go:1224 (function value)
//   - internal/acme/store.go:716 (direct call)
//   - internal/acme/store.go:716 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (s Secret) IsZero() bool {
	return s.v == ""
}

// String implements fmt.Stringer and always returns SecretPlaceholder.
//
// # Parameters
//
// None.
//
// # Returns
//
// Always returns "[REDACTED]".
//
// # Example
//
//	fmt.Println(acme.NewSecret("sensitive").String()) // [REDACTED]
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:38 (direct call)
//   - internal/acme/acme_test.go:1228 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (Secret) String() string {
	return SecretPlaceholder
}

// GoString implements fmt.GoStringer and always returns a redacted Go-syntax
// representation.
//
// # Parameters
//
// None.
//
// # Returns
//
// Always returns "acme.Secret{[REDACTED]}".
//
// # Example
//
//	fmt.Printf("%#v\n", acme.NewSecret("sensitive")) // acme.Secret{[REDACTED]}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:1229 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (Secret) GoString() string {
	return "acme.Secret{" + SecretPlaceholder + "}"
}

// Format implements fmt.Formatter so every formatting verb (%v, %+v, %#v, %s,
// %q, %x, etc.) emits SecretPlaceholder instead of reflecting on the unexported
// secret field.
//
// # Parameters
//
//   - f: Destination fmt.State written to by fmt.
//   - verb: Formatting verb (ignored; output is always SecretPlaceholder).
//
// # Example
//
//	fmt.Printf("%+v\n", acme.NewSecret("sensitive")) // [REDACTED]
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (Secret) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, SecretPlaceholder)
}

// MarshalText implements encoding.TextMarshaler and always emits
// SecretPlaceholder.
//
// # Parameters
//
// None.
//
// # Returns
//
// The UTF-8 bytes of "[REDACTED]" and a nil error.
//
// # Example
//
//	b, err := acme.NewSecret("sensitive").MarshalText()
//	if err != nil {
//		return err
//	}
//	fmt.Println(string(b)) // [REDACTED]
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:1243 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (Secret) MarshalText() ([]byte, error) {
	return []byte(SecretPlaceholder), nil
}

// MarshalJSON implements json.Marshaler and always encodes SecretPlaceholder
// as a JSON string.
//
// # Parameters
//
// None.
//
// # Returns
//
// JSON bytes `"[REDACTED]"` and a nil error.
//
// # Example
//
//	b, err := json.Marshal(acme.NewSecret("sensitive"))
//	if err != nil {
//		return err
//	}
//	fmt.Println(string(b)) // "[REDACTED]"
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(SecretPlaceholder)
}

// LogValue implements slog.LogValuer so structured logs always record
// SecretPlaceholder even under slog.Any or slog.Group.
//
// # Parameters
//
// None.
//
// # Returns
//
// A slog.Value holding "[REDACTED]".
//
// # Example
//
//	slog.Info("configured provider", "token", acme.NewSecret("sensitive"))
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (Secret) LogValue() slog.Value {
	return slog.StringValue(SecretPlaceholder)
}

var (
	_ fmt.Stringer           = Secret{}
	_ fmt.GoStringer         = Secret{}
	_ fmt.Formatter          = Secret{}
	_ json.Marshaler         = Secret{}
	_ encoding.TextMarshaler = Secret{}
	_ slog.LogValuer         = Secret{}
)

// DNSProvider provisions and cleans up TXT records required by RFC 8555 ACME
// DNS-01 challenges. Implementations must be safe for concurrent use.
type DNSProvider interface {
	// Present creates a DNS TXT record at fqdn with the challenge digest value.
	Present(ctx context.Context, fqdn, value string) error
	// CleanUp removes the DNS TXT record previously created for fqdn and value.
	CleanUp(ctx context.Context, fqdn, value string) error
	// PropagationTimeout returns the maximum time the Manager should wait for
	// TXT records published by this provider to propagate.
	PropagationTimeout() time.Duration
}

// CloudflareConfig configures a CloudflareProvider backed by Cloudflare API v4.
type CloudflareConfig struct {
	// APIToken is a Cloudflare API token with Zone:Read and DNS:Edit permissions.
	// Required; must not be empty.
	APIToken Secret
	// ZoneID optionally pins the Cloudflare zone identifier. When empty, the
	// provider discovers the zone by querying GET /zones for progressively
	// shorter parent domains of the challenge FQDN.
	ZoneID string
	// BaseURL overrides the Cloudflare API v4 root URL. Defaults to
	// DefaultCloudflareBaseURL. Must use HTTPS unless AllowInsecureLocalhost is
	// true and the host is a loopback address.
	BaseURL string
	// HTTPClient optionally overrides the HTTP client used for API requests.
	// When nil, a hardened client with strict timeouts and TLS 1.2+ is created.
	HTTPClient *http.Client
	// Propagation specifies the duration returned by PropagationTimeout.
	// Defaults to DefaultPropagationTimeout when <= 0.
	Propagation time.Duration
	// TTL sets the DNS record TTL in seconds (Cloudflare accepts 1 for auto or
	// >= 60). Defaults to 120 when <= 0.
	TTL int
	// AllowInsecureLocalhost permits an http:// BaseURL strictly when the URL
	// host resolves to a loopback literal or "localhost" (intended for tests).
	AllowInsecureLocalhost bool
}

// CloudflareProvider implements DNSProvider using pure-stdlib net/http calls to
// Cloudflare API v4. It is safe for concurrent use.
type CloudflareProvider struct {
	token       Secret
	baseURL     string
	client      *http.Client
	propagation time.Duration
	ttl         int

	mu      sync.Mutex
	zoneID  string            // guarded by mu; static if configured
	zones   map[string]string // guarded by mu; domain suffix -> zoneID
	records map[string]string // guarded by mu; "name\x00value" -> recordID
}

// NewCloudflareProvider validates cfg and constructs a CloudflareProvider.
//
// # Parameters
//
//   - cfg: Provider configuration. cfg.APIToken must be non-empty. cfg.BaseURL
//     must use https unless cfg.AllowInsecureLocalhost is true and the host is
//     loopback.
//
// # Returns
//
// A ready-to-use *CloudflareProvider, or an error wrapping ErrEmptySecret or
// ErrInsecureURL on invalid configuration.
//
// # Example
//
//	p, err := acme.NewCloudflareProvider(acme.CloudflareConfig{
//		APIToken: acme.NewSecret(os.Getenv("CF_API_TOKEN")),
//	})
//	if err != nil {
//		return err
//	}
//	_ = p
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:1002 (direct call)
//   - internal/acme/acme_test.go:1005 (direct call)
//   - internal/acme/acme_test.go:1084 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func NewCloudflareProvider(cfg CloudflareConfig) (*CloudflareProvider, error) {
	if cfg.APIToken.IsZero() {
		return nil, fmt.Errorf("cloudflare api token: %w", ErrEmptySecret)
	}
	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		baseURL = DefaultCloudflareBaseURL
	}
	normalizedURL, err := validateEndpointURL(baseURL, cfg.AllowInsecureLocalhost)
	if err != nil {
		return nil, fmt.Errorf("cloudflare base url: %w", err)
	}

	client := cfg.HTTPClient
	if client == nil {
		client = newHardenedHTTPClient(defaultProviderTimeout)
	}
	prop := cfg.Propagation
	if prop <= 0 {
		prop = DefaultPropagationTimeout
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = defaultCloudflareTTL
	}

	return &CloudflareProvider{
		token:       cfg.APIToken,
		baseURL:     strings.TrimRight(normalizedURL, "/"),
		client:      client,
		propagation: prop,
		ttl:         ttl,
		zoneID:      strings.TrimSpace(cfg.ZoneID),
		zones:       make(map[string]string),
		records:     make(map[string]string),
	}, nil
}

// PropagationTimeout returns the configured DNS propagation wait budget.
//
// # Parameters
//
// None.
//
// # Returns
//
// A positive time.Duration for TXT propagation polling.
//
// # Example
//
//	timeout := provider.PropagationTimeout()
//	_ = timeout
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:1094 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (p *CloudflareProvider) PropagationTimeout() time.Duration {
	return p.propagation
}

// Present creates a TXT record in Cloudflare for fqdn with content value.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadlines for zone lookup and record
//     creation. Must be non-nil.
//   - fqdn: Fully qualified challenge domain name (with or without trailing dot).
//   - value: The RFC 8555 DNS-01 key authorization SHA-256 digest.
//
// # Returns
//
// nil on success, or an error wrapping ErrProviderFailed if Cloudflare rejects
// the request or returns an unexpected response.
//
// # Concurrency
//
// Safe for concurrent use; network I/O executes outside the internal mutex.
//
// # Example
//
//	if err := provider.Present(ctx, "_acme-challenge.example.com", digest); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:1099 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (p *CloudflareProvider) Present(ctx context.Context, fqdn, value string) error {
	name := normalizeChallengeFQDN(fqdn)
	if name == "" || strings.TrimSpace(value) == "" {
		return fmt.Errorf("cloudflare present: empty fqdn or value: %w", ErrInvalidDomain)
	}
	zoneID, err := p.resolveZoneID(ctx, name)
	if err != nil {
		return err
	}

	payload := cloudflareCreateRecordRequest{
		Type:    "TXT",
		Name:    name,
		Content: value,
		TTL:     p.ttl,
	}
	var resp cloudflareEnvelope[cloudflareDNSRecord]
	endpoint := p.baseURL + "/zones/" + url.PathEscape(zoneID) + "/dns_records"
	if err := p.doJSON(ctx, http.MethodPost, endpoint, payload, &resp); err != nil {
		return fmt.Errorf("cloudflare create txt record for %q: %w", name, err)
	}
	if !resp.Success {
		return fmt.Errorf("cloudflare create txt record for %q: %s: %w", name, resp.errorSummary(), ErrProviderFailed)
	}
	if resp.Result.ID != "" {
		p.mu.Lock()
		p.records[recordMapKey(name, value)] = resp.Result.ID
		p.mu.Unlock()
	}
	return nil
}

// CleanUp deletes the TXT record previously created for fqdn and value.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadlines for zone lookup and deletion.
//     Must be non-nil.
//   - fqdn: Fully qualified challenge domain name (with or without trailing dot).
//   - value: The TXT record content to delete.
//
// # Returns
//
// nil if the record was deleted or no matching record exists; an error wrapping
// ErrProviderFailed otherwise.
//
// # Concurrency
//
// Safe for concurrent use; network I/O executes outside the internal mutex.
//
// # Example
//
//	if err := provider.CleanUp(ctx, "_acme-challenge.example.com", digest); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:1102 (direct call)
//   - internal/acme/acme_test.go:1106 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (p *CloudflareProvider) CleanUp(ctx context.Context, fqdn, value string) error {
	name := normalizeChallengeFQDN(fqdn)
	if name == "" || strings.TrimSpace(value) == "" {
		return fmt.Errorf("cloudflare cleanup: empty fqdn or value: %w", ErrInvalidDomain)
	}
	zoneID, err := p.resolveZoneID(ctx, name)
	if err != nil {
		return err
	}

	key := recordMapKey(name, value)
	p.mu.Lock()
	recordID := p.records[key]
	delete(p.records, key)
	p.mu.Unlock()

	var recordIDs []string
	if recordID != "" {
		recordIDs = []string{recordID}
	} else {
		// Fall back to querying matching TXT records if this provider instance
		// did not cache the record ID (for example after restart).
		found, err := p.findTXTRecords(ctx, zoneID, name, value)
		if err != nil {
			return err
		}
		recordIDs = found
	}

	var errs []error
	for _, id := range recordIDs {
		endpoint := p.baseURL + "/zones/" + url.PathEscape(zoneID) + "/dns_records/" + url.PathEscape(id)
		var resp cloudflareEnvelope[cloudflareDeleteResult]
		if err := p.doJSON(ctx, http.MethodDelete, endpoint, nil, &resp); err != nil {
			errs = append(errs, fmt.Errorf("delete record %q: %w", id, err))
			continue
		}
		if !resp.Success {
			errs = append(errs, fmt.Errorf("delete record %q: %s: %w", id, resp.errorSummary(), ErrProviderFailed))
		}
	}
	return errors.Join(errs...)
}

// resolveZoneID discovers and caches the Cloudflare zone ID owning fqdn by
// walking parent domain suffixes from longest to shortest.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadlines for GET /zones queries.
//   - fqdn: Normalized lowercase challenge domain without a trailing dot.
//
// # Returns
//
// The Cloudflare zone identifier, or an error wrapping ErrProviderFailed if no
// active zone matches fqdn.
//
// # Example
//
//	zoneID, err := p.resolveZoneID(ctx, "_acme-challenge.example.com")
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/provider.go:620 (direct call)
//   - internal/acme/provider.go:620 (function value)
//   - internal/acme/provider.go:685 (direct call)
//   - internal/acme/provider.go:685 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (p *CloudflareProvider) resolveZoneID(ctx context.Context, fqdn string) (string, error) {
	p.mu.Lock()
	if p.zoneID != "" {
		id := p.zoneID
		p.mu.Unlock()
		return id, nil
	}
	labels := strings.Split(fqdn, ".")
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		if id, ok := p.zones[candidate]; ok {
			p.mu.Unlock()
			return id, nil
		}
	}
	p.mu.Unlock()

	// Walk candidate zone names from most specific to least specific (minimum two labels).
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		q := url.Values{}
		q.Set("name", candidate)
		q.Set("status", "active")
		endpoint := p.baseURL + "/zones?" + q.Encode()

		var resp cloudflareEnvelope[[]cloudflareZone]
		if err := p.doJSON(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
			return "", fmt.Errorf("cloudflare lookup zone %q: %w", candidate, err)
		}
		if !resp.Success {
			return "", fmt.Errorf("cloudflare lookup zone %q: %s: %w", candidate, resp.errorSummary(), ErrProviderFailed)
		}
		if len(resp.Result) > 0 && resp.Result[0].ID != "" {
			id := resp.Result[0].ID
			p.mu.Lock()
			p.zones[candidate] = id
			p.mu.Unlock()
			return id, nil
		}
	}
	return "", fmt.Errorf("cloudflare zone not found for %q: %w", fqdn, ErrProviderFailed)
}

// findTXTRecords queries Cloudflare for TXT records matching name and content.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadlines for GET /zones/:id/dns_records.
//   - zoneID: Target Cloudflare zone ID.
//   - name: Normalized DNS record name.
//   - value: Exact TXT record content to match.
//
// # Returns
//
// A slice of matching Cloudflare DNS record IDs, or an error.
//
// # Example
//
//	ids, err := p.findTXTRecords(ctx, zoneID, "_acme-challenge.example.com", digest)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/provider.go:702 (direct call)
//   - internal/acme/provider.go:702 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (p *CloudflareProvider) findTXTRecords(ctx context.Context, zoneID, name, value string) ([]string, error) {
	q := url.Values{}
	q.Set("type", "TXT")
	q.Set("name", name)
	q.Set("content", value)
	endpoint := p.baseURL + "/zones/" + url.PathEscape(zoneID) + "/dns_records?" + q.Encode()

	var resp cloudflareEnvelope[[]cloudflareDNSRecord]
	if err := p.doJSON(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, fmt.Errorf("cloudflare list txt records for %q: %w", name, err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("cloudflare list txt records for %q: %s: %w", name, resp.errorSummary(), ErrProviderFailed)
	}
	ids := make([]string, 0, len(resp.Result))
	for _, rec := range resp.Result {
		if rec.ID != "" && rec.Content == value {
			ids = append(ids, rec.ID)
		}
	}
	return ids, nil
}

// doJSON sends an authenticated JSON request to Cloudflare API v4 and decodes
// the bounded response body into out.
//
// # Parameters
//
//   - ctx: Controls request cancellation and deadline.
//   - method: HTTP method (GET, POST, DELETE).
//   - endpoint: Full API endpoint URL.
//   - reqBody: Optional value marshaled as JSON when non-nil.
//   - out: Pointer to decode the JSON response into.
//
// # Returns
//
// nil on 2xx with valid JSON, or an error wrapping ErrProviderFailed. Raw
// bearer tokens are never included in returned errors.
//
// # Example
//
//	err := p.doJSON(ctx, http.MethodGet, endpoint, nil, &resp)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/provider.go:633 (direct call)
//   - internal/acme/provider.go:633 (function value)
//   - internal/acme/provider.go:713 (direct call)
//   - internal/acme/provider.go:713 (function value)
//   - internal/acme/provider.go:778 (direct call)
//   - internal/acme/provider.go:778 (function value)
//   - internal/acme/provider.go:829 (direct call)
//   - internal/acme/provider.go:829 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (p *CloudflareProvider) doJSON(ctx context.Context, method, endpoint string, reqBody any, out any) error {
	var bodyReader io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	// Single point of use for the bearer token (S6).
	req.Header.Set("Authorization", "Bearer "+p.token.Reveal())
	req.Header.Set("Accept", "application/json")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s request failed: %w", method, err)
	}
	defer resp.Body.Close() // read side; close error not material

	body, err := readBoundedBody(resp.Body, maxProviderResponseBytes)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d (%s): %w", resp.StatusCode, sanitizeBodySnippet(body), ErrProviderFailed)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

type cloudflareCreateRecordRequest struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

type cloudflareZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cloudflareDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

type cloudflareDeleteResult struct {
	ID string `json:"id"`
}

type cloudflareAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cloudflareEnvelope[T any] struct {
	Success bool                 `json:"success"`
	Errors  []cloudflareAPIError `json:"errors"`
	Result  T                    `json:"result"`
}

// errorSummary formats Cloudflare API error codes and messages into a compact
// diagnostic string.
//
// # Parameters
//
// None.
//
// # Returns
//
// A comma-separated summary of e.Errors, or "unknown api error" when empty.
//
// # Example
//
//	msg := envelope.errorSummary()
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/provider.go:637 (direct call)
//   - internal/acme/provider.go:637 (function value)
//   - internal/acme/provider.go:718 (direct call)
//   - internal/acme/provider.go:718 (function value)
//   - internal/acme/provider.go:782 (direct call)
//   - internal/acme/provider.go:782 (function value)
//   - internal/acme/provider.go:833 (direct call)
//   - internal/acme/provider.go:833 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (e cloudflareEnvelope[T]) errorSummary() string {
	if len(e.Errors) == 0 {
		return "unknown api error"
	}
	parts := make([]string, 0, len(e.Errors))
	for _, item := range e.Errors {
		parts = append(parts, fmt.Sprintf("%d:%s", item.Code, item.Message))
	}
	return strings.Join(parts, ", ")
}

// WebhookConfig configures a generic HTTPS DNS-01 webhook provider.
type WebhookConfig struct {
	// Endpoint is the webhook URL that receives JSON POST payloads of the form
	// {"action":"present"|"cleanup","fqdn":"...","value":"..."}. Must use HTTPS
	// unless AllowInsecureLocalhost is true and the host is loopback.
	Endpoint string
	// BearerToken is an optional bearer credential sent in the Authorization
	// header. Held in a redacting Secret wrapper (S6).
	BearerToken Secret
	// HTTPClient optionally overrides the HTTP client used for webhook calls.
	// When nil, a hardened client with strict timeouts and TLS 1.2+ is created.
	HTTPClient *http.Client
	// Propagation specifies the duration returned by PropagationTimeout.
	// Defaults to DefaultPropagationTimeout when <= 0.
	Propagation time.Duration
	// AllowInsecureLocalhost permits an http:// Endpoint strictly when the host
	// is a loopback literal or "localhost" (intended for local tests).
	AllowInsecureLocalhost bool
}

// WebhookProvider implements DNSProvider by POSTing JSON challenge actions to
// an HTTPS webhook endpoint. It is safe for concurrent use.
type WebhookProvider struct {
	endpoint    string
	token       Secret
	client      *http.Client
	propagation time.Duration
}

// WebhookPayload is the JSON request body sent by WebhookProvider to its
// configured endpoint.
type WebhookPayload struct {
	Action string `json:"action"`
	FQDN   string `json:"fqdn"`
	Value  string `json:"value"`
}

// NewWebhookProvider validates cfg and constructs a WebhookProvider.
//
// # Parameters
//
//   - cfg: Webhook configuration. cfg.Endpoint must be a valid https URL
//     (without embedded userinfo) unless cfg.AllowInsecureLocalhost is true and
//     the host is loopback.
//
// # Returns
//
// A ready-to-use *WebhookProvider, or an error wrapping ErrInsecureURL if the
// endpoint violates transport security requirements.
//
// # Example
//
//	p, err := acme.NewWebhookProvider(acme.WebhookConfig{
//		Endpoint:    "https://dns.internal.example/acme-hook",
//		BearerToken: acme.NewSecret(os.Getenv("DNS_WEBHOOK_TOKEN")),
//	})
//	if err != nil {
//		return err
//	}
//	_ = p
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:1128 (direct call)
//   - internal/acme/acme_test.go:1135 (direct call)
//   - internal/acme/acme_test.go:1147 (direct call)
//   - internal/acme/acme_test.go:1183 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func NewWebhookProvider(cfg WebhookConfig) (*WebhookProvider, error) {
	endpoint, err := validateEndpointURL(cfg.Endpoint, cfg.AllowInsecureLocalhost)
	if err != nil {
		return nil, fmt.Errorf("webhook endpoint: %w", err)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = newHardenedHTTPClient(defaultProviderTimeout)
	}
	prop := cfg.Propagation
	if prop <= 0 {
		prop = DefaultPropagationTimeout
	}
	return &WebhookProvider{
		endpoint:    endpoint,
		token:       cfg.BearerToken,
		client:      client,
		propagation: prop,
	}, nil
}

// PropagationTimeout returns the configured DNS propagation wait budget.
//
// # Parameters
//
// None.
//
// # Returns
//
// A positive time.Duration for TXT propagation polling.
//
// # Example
//
//	timeout := provider.PropagationTimeout()
//	_ = timeout
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (p *WebhookProvider) PropagationTimeout() time.Duration {
	return p.propagation
}

// Present POSTs a JSON "present" action to the configured webhook endpoint.
//
// # Parameters
//
//   - ctx: Controls request cancellation and deadline. Must be non-nil.
//   - fqdn: Challenge domain name (normalized without trailing dot).
//   - value: DNS-01 TXT record value.
//
// # Returns
//
// nil on a 2xx HTTP response, or an error wrapping ErrProviderFailed.
//
// # Example
//
//	if err := provider.Present(ctx, "_acme-challenge.example.com", digest); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:1193 (direct call)
//   - internal/acme/acme_test.go:1201 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (p *WebhookProvider) Present(ctx context.Context, fqdn, value string) error {
	return p.post(ctx, "present", fqdn, value)
}

// CleanUp POSTs a JSON "cleanup" action to the configured webhook endpoint.
//
// # Parameters
//
//   - ctx: Controls request cancellation and deadline. Must be non-nil.
//   - fqdn: Challenge domain name (normalized without trailing dot).
//   - value: DNS-01 TXT record value.
//
// # Returns
//
// nil on a 2xx HTTP response, or an error wrapping ErrProviderFailed.
//
// # Example
//
//	if err := provider.CleanUp(ctx, "_acme-challenge.example.com", digest); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:1196 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (p *WebhookProvider) CleanUp(ctx context.Context, fqdn, value string) error {
	return p.post(ctx, "cleanup", fqdn, value)
}

// post marshals a WebhookPayload and sends it to the webhook endpoint with
// bounded response reading and optional bearer authentication.
//
// # Parameters
//
//   - ctx: Controls request cancellation and deadline.
//   - action: Either "present" or "cleanup".
//   - fqdn: Challenge FQDN.
//   - value: Challenge TXT digest.
//
// # Returns
//
// nil on 2xx, or an error wrapping ErrInvalidDomain or ErrProviderFailed.
//
// # Example
//
//	err := p.post(ctx, "present", "_acme-challenge.example.com", digest)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/provider.go:1142 (direct call)
//   - internal/acme/provider.go:1142 (function value)
//   - internal/acme/provider.go:1172 (direct call)
//   - internal/acme/provider.go:1172 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (p *WebhookProvider) post(ctx context.Context, action, fqdn, value string) error {
	name := normalizeChallengeFQDN(fqdn)
	if name == "" || strings.TrimSpace(value) == "" {
		return fmt.Errorf("webhook %s: empty fqdn or value: %w", action, ErrInvalidDomain)
	}
	raw, err := json.Marshal(WebhookPayload{
		Action: action,
		FQDN:   name,
		Value:  value,
	})
	if err != nil {
		return fmt.Errorf("webhook %s marshal: %w", action, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("webhook %s request: %w", action, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if !p.token.IsZero() {
		// Single point of use for the bearer token (S6).
		req.Header.Set("Authorization", "Bearer "+p.token.Reveal())
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook %s post: %w", action, err)
	}
	defer resp.Body.Close() // read side; close error not material

	body, err := readBoundedBody(resp.Body, maxProviderResponseBytes)
	if err != nil {
		return fmt.Errorf("webhook %s read response: %w", action, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook %s status %d (%s): %w", action, resp.StatusCode, sanitizeBodySnippet(body), ErrProviderFailed)
	}
	return nil
}

// validateEndpointURL enforces HTTPS transport, non-empty host, and absence of
// URL-embedded credentials (S4/S5/S9). Plain HTTP is rejected unless
// allowInsecureLocalhost is true and the host is a loopback address.
//
// # Parameters
//
//   - rawURL: Candidate endpoint URL string.
//   - allowInsecureLocalhost: When true, permits http:// only on localhost,
//     127.0.0.1, or ::1.
//
// # Returns
//
// The validated URL string, or an error wrapping ErrInsecureURL.
//
// # Example
//
//	u, err := validateEndpointURL("https://api.cloudflare.com/client/v4", false)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/provider.go:526 (direct call)
//   - internal/acme/provider.go:526 (function value)
//   - internal/acme/provider.go:1067 (direct call)
//   - internal/acme/provider.go:1067 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func validateEndpointURL(rawURL string, allowInsecureLocalhost bool) (string, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "", fmt.Errorf("empty url: %w", ErrInsecureURL)
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("parse url: %w", ErrInsecureURL)
	}
	if parsed.User != nil {
		// Reject credentials in URL userinfo so they never appear in url.Error or logs.
		return "", fmt.Errorf("credentials in url userinfo are forbidden: %w", ErrInsecureURL)
	}
	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("missing host: %w", ErrInsecureURL)
	}

	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return parsed.String(), nil
	case "http":
		if allowInsecureLocalhost && isLoopbackHost(host) {
			return parsed.String(), nil
		}
		return "", fmt.Errorf("scheme %q rejected: %w", parsed.Scheme, ErrInsecureURL)
	default:
		return "", fmt.Errorf("unsupported scheme %q: %w", parsed.Scheme, ErrInsecureURL)
	}
}

// isLoopbackHost reports whether host is "localhost" or a loopback IP literal.
//
// # Parameters
//
//   - host: Unbracketed hostname or IP string returned by url.URL.Hostname().
//
// # Returns
//
// true only for "localhost" (case-insensitive) or a valid loopback IP address.
//
// # Example
//
//	ok := isLoopbackHost("127.0.0.1") // true
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/provider.go:1296 (direct call)
//   - internal/acme/provider.go:1296 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// newHardenedHTTPClient builds a reusable http.Client with explicit dial, TLS
// handshake, response-header, and overall timeouts, TLS 1.2 minimum version,
// and a redirect policy that refuses automatic redirects so bearer tokens are
// never forwarded unexpectedly.
//
// # Parameters
//
//   - timeout: Overall client timeout for the entire HTTP exchange.
//
// # Returns
//
// A configured *http.Client safe for concurrent reuse.
//
// # Example
//
//	client := newHardenedHTTPClient(30 * time.Second)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:270 (direct call)
//   - internal/acme/manager.go:270 (function value)
//   - internal/acme/provider.go:533 (direct call)
//   - internal/acme/provider.go:533 (function value)
//   - internal/acme/provider.go:1073 (direct call)
//   - internal/acme/provider.go:1073 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func newHardenedHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// Refuse redirects on credentialed API/webhook calls so Authorization
		// headers cannot be silently bounced to an unintended target.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// readBoundedBody reads at most limit bytes from r and fails if the stream
// exceeds limit (R3).
//
// # Parameters
//
//   - r: Response body reader; not closed by this function.
//   - limit: Maximum permitted byte count.
//
// # Returns
//
// The read bytes when len(body) <= limit, or an error if reading fails or the
// body exceeds limit.
//
// # Example
//
//	body, err := readBoundedBody(resp.Body, maxProviderResponseBytes)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/provider.go:906 (direct call)
//   - internal/acme/provider.go:906 (function value)
//   - internal/acme/provider.go:1235 (direct call)
//   - internal/acme/provider.go:1235 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func readBoundedBody(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response body exceeds %d bytes", limit)
	}
	return body, nil
}

// sanitizeBodySnippet trims and bounds an error response body for safe
// diagnostic inclusion.
//
// # Parameters
//
//   - body: Raw HTTP error response bytes.
//
// # Returns
//
// A single-line, length-bounded snippet safe for error messages.
//
// # Example
//
//	snippet := sanitizeBodySnippet(body)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/provider.go:911 (direct call)
//   - internal/acme/provider.go:911 (function value)
//   - internal/acme/provider.go:1240 (direct call)
//   - internal/acme/provider.go:1240 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func sanitizeBodySnippet(body []byte) string {
	s := strings.TrimSpace(string(body))
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > maxErrorSnippetBytes {
		return s[:maxErrorSnippetBytes] + "..."
	}
	return s
}

// normalizeChallengeFQDN lowercases fqdn and strips surrounding whitespace and
// any trailing root dot.
//
// # Parameters
//
//   - fqdn: Raw DNS name.
//
// # Returns
//
// Normalized lowercase FQDN without trailing dot.
//
// # Example
//
//	name := normalizeChallengeFQDN("_acme-challenge.Example.COM.")
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/provider.go:616 (direct call)
//   - internal/acme/provider.go:616 (function value)
//   - internal/acme/provider.go:681 (direct call)
//   - internal/acme/provider.go:681 (function value)
//   - internal/acme/provider.go:1205 (direct call)
//   - internal/acme/provider.go:1205 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func normalizeChallengeFQDN(fqdn string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
}

// recordMapKey builds the composite lookup key for a (name, value) TXT record.
//
// # Parameters
//
//   - name: Normalized DNS record name.
//   - value: TXT record content.
//
// # Returns
//
// A delimiter-separated composite string key.
//
// # Example
//
//	k := recordMapKey("_acme-challenge.example.com", digest)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/provider.go:641 (direct call)
//   - internal/acme/provider.go:641 (function value)
//   - internal/acme/provider.go:690 (direct call)
//   - internal/acme/provider.go:690 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func recordMapKey(name, value string) string {
	return name + "\x00" + value
}
