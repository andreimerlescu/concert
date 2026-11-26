package concert

import (
	"bytes"
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RedactedPlaceholder is printed by every formatting, logging, and marshaling
// path on Secret instead of the underlying credential.
const RedactedPlaceholder = "[REDACTED]"

// CachePurgePath is Concert's authenticated active micro-cache purge endpoint.
const CachePurgePath = "/_room/cache/purge"

// Default client timeouts and response bounds (R3).
const (
	DefaultHTTPTimeout      = 10 * time.Second
	DefaultMaxResponseBytes = 64 << 10 // 64 KiB
)

// PurgeMode enumerates the active page-cache purge modes accepted by Concert.
type PurgeMode string

const (
	PurgeModeURL    PurgeMode = "url"
	PurgeModePrefix PurgeMode = "prefix"
	PurgeModeTag    PurgeMode = "tag"
	PurgeModeAll    PurgeMode = "all"
)

// Sentinel errors returned by Secret and CachePurgeClient. Match with errors.Is.
var (
	ErrEmptySecret       = errors.New("concert: secret token is empty")
	ErrPlaceholderSecret = errors.New("concert: secret token looks like a placeholder")
	ErrInvalidBaseURL    = errors.New("concert: invalid base URL")
	ErrInvalidPurge      = errors.New("concert: invalid cache purge request")
	ErrResponseTooLarge  = errors.New("concert: response body exceeds configured limit")
)

// Secret holds a sensitive credential (such as a Concert operator/admin Bearer
// token) so it cannot be printed, logged, or marshaled by accident (S6).
//
// Its zero value is empty (IsZero() == true). Secret is an immutable value
// type; copies share no mutable state. Call Reveal only at the single wire
// boundary where the raw token is required.
type Secret struct {
	v string
}

// NewSecret wraps raw inside a redacting Secret value. Callers should load raw
// at runtime from a secret file or environment variable, never from a source
// literal or flag default.
//
// # Parameters
//
//   - raw: Raw secret string. Surrounding whitespace is preserved verbatim;
//     use NewValidatedSecret to trim and fail closed on empty/placeholder values.
//
// # Returns
//
// A Secret wrapping raw.
//
// # Example
//
//	tok := concert.NewSecret(os.Getenv("CONCERT_ADMIN_TOKEN"))
//	fmt.Println(tok) // prints "[REDACTED]"
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:655 (direct call)
//   - clients/go/src/concert_test.go:666 (direct call)
//   - clients/go/src/concert_test.go:672 (direct call)
//   - clients/go/src/concert_test.go:679 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func NewSecret(raw string) Secret {
	return Secret{v: raw}
}

// NewValidatedSecret trims surrounding whitespace from raw and fails closed on
// empty or placeholder-looking values (S7).
//
// # Parameters
//
//   - raw: Raw credential string read from a runtime secret channel.
//
// # Returns
//
// A validated Secret and nil error, or a zero Secret and ErrEmptySecret or
// ErrPlaceholderSecret. Errors never include raw.
//
// # Example
//
//	tok, err := concert.NewValidatedSecret(os.Getenv("CONCERT_ADMIN_TOKEN"))
//	if err != nil {
//		return err
//	}
//	_ = tok
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:511 (symbol reference)
//   - clients/go/src/concert_test.go:543 (direct call)
//   - clients/go/src/concert_test.go:591 (direct call)
//   - clients/go/src/concert_test.go:594 (direct call)
//   - clients/go/src/doc.go:511 (symbol reference)
//   - clients/go/src/priority.go:511 (symbol reference)
//   - clients/go/src/purge.go:511 (direct call)
//   - clients/go/src/rm1.go:511 (symbol reference)
//   - clients/go/src/signals.go:511 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func NewValidatedSecret(raw string) (Secret, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Secret{}, ErrEmptySecret
	}
	if looksLikePlaceholder(trimmed) {
		return Secret{}, ErrPlaceholderSecret
	}
	return Secret{v: trimmed}, nil
}

// Reveal returns the raw secret value. Never pass the result to logs, errors,
// fmt verbs, metrics labels, or long-lived structures.
//
// # Parameters
//
//   - s (receiver): Secret to unwrap.
//
// # Returns
//
// The underlying raw string.
//
// # Example
//
//	req.Header.Set("Authorization", "Bearer "+tok.Reveal())
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:511 (symbol reference)
//   - clients/go/src/bidding.go:754 (symbol reference)
//   - clients/go/src/concert_test.go:547 (direct call)
//   - clients/go/src/doc.go:511 (symbol reference)
//   - clients/go/src/doc.go:754 (symbol reference)
//   - clients/go/src/priority.go:511 (symbol reference)
//   - clients/go/src/priority.go:754 (symbol reference)
//   - clients/go/src/purge.go:511 (direct call)
//   - clients/go/src/purge.go:754 (direct call)
//   - clients/go/src/rm1.go:511 (symbol reference)
//   - clients/go/src/rm1.go:754 (symbol reference)
//   - clients/go/src/signals.go:511 (symbol reference)
//   - clients/go/src/signals.go:754 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (s Secret) Reveal() string { return s.v }

// IsZero reports whether the Secret holds no value.
//
// # Parameters
//
//   - s (receiver): Secret to inspect.
//
// # Returns
//
// true when the wrapped value is empty; false otherwise.
//
// # Example
//
//	if tok.IsZero() {
//		return concert.ErrEmptySecret
//	}
//
// # Used By
//
// No statically resolvable in-repo references found in clients/go/src.
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (s Secret) IsZero() bool { return s.v == "" }

// String returns RedactedPlaceholder so fmt.Sprint and %s never leak the secret.
//
// # Parameters
//
//   - Secret (receiver): Unused; always redacted.
//
// # Returns
//
// RedactedPlaceholder ("[REDACTED]").
//
// # Example
//
//	fmt.Println(concert.NewSecret("runtime-val")) // [REDACTED]
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:570 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (Secret) String() string { return RedactedPlaceholder }

// GoString returns a redacted Go-syntax representation so %#v never leaks.
//
// # Parameters
//
//   - Secret (receiver): Unused; always redacted.
//
// # Returns
//
// "concert.Secret{[REDACTED]}".
//
// # Example
//
//	fmt.Printf("%#v\n", concert.NewSecret("runtime-val"))
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:571 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (Secret) GoString() string { return "concert.Secret{" + RedactedPlaceholder + "}" }

// Format intercepts every fmt verb (%v, %+v, %#v, %s, %q, %x, ...) so
// struct dumps containing Secret never expose raw bytes via reflection.
//
// # Parameters
//
//   - f: Target fmt.State writer.
//   - verb: Format verb rune (ignored).
//
// # Returns
//
// None.
//
// # Example
//
//	fmt.Printf("%+v\n", concert.CachePurgeConfig{BaseURL: "https://edge.example", Token: tok})
//
// # Used By
//
// No statically resolvable in-repo references found in clients/go/src.
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, RedactedPlaceholder) }

// MarshalText encodes Secret as RedactedPlaceholder.
//
// # Parameters
//
//   - Secret (receiver): Unused; always redacted.
//
// # Returns
//
// []byte("[REDACTED]") and nil error.
//
// # Example
//
//	b, _ := concert.NewSecret("runtime-val").MarshalText()
//	_ = b
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:564 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (Secret) MarshalText() ([]byte, error) { return []byte(RedactedPlaceholder), nil }

// MarshalJSON encodes Secret as the JSON string "[REDACTED]".
//
// # Parameters
//
//   - Secret (receiver): Unused; always redacted.
//
// # Returns
//
// JSON-encoded placeholder bytes and nil error.
//
// # Example
//
//	b, _ := json.Marshal(concert.CachePurgeConfig{BaseURL: "https://edge.example", Token: tok})
//	_ = b
//
// # Used By
//
// No statically resolvable in-repo references found in clients/go/src.
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (Secret) MarshalJSON() ([]byte, error) { return json.Marshal(RedactedPlaceholder) }

// LogValue ensures log/slog always records Secret as "[REDACTED]", even inside
// slog.Any or slog.Group.
//
// # Parameters
//
//   - Secret (receiver): Unused; always redacted.
//
// # Returns
//
// slog.StringValue("[REDACTED]").
//
// # Example
//
//	slog.Info("configured purge client", "token", tok)
//
// # Used By
//
// No statically resolvable in-repo references found in clients/go/src.
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (Secret) LogValue() slog.Value { return slog.StringValue(RedactedPlaceholder) }

var (
	_ fmt.Stringer           = Secret{}
	_ fmt.GoStringer         = Secret{}
	_ fmt.Formatter          = Secret{}
	_ json.Marshaler         = Secret{}
	_ encoding.TextMarshaler = Secret{}
	_ slog.LogValuer         = Secret{}
)

// looksLikePlaceholder reports whether s matches a common unconfigured
// placeholder token.
//
// # Parameters
//
//   - s: Trimmed candidate secret string.
//
// # Returns
//
// true if s is a recognized placeholder literal.
//
// # Example
//
//	if looksLikePlaceholder(candidate) {
//		return Secret{}, ErrPlaceholderSecret
//	}
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:132 (symbol reference)
//   - clients/go/src/doc.go:132 (symbol reference)
//   - clients/go/src/priority.go:132 (symbol reference)
//   - clients/go/src/purge.go:132 (direct call)
//   - clients/go/src/rm1.go:132 (symbol reference)
//   - clients/go/src/signals.go:132 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func looksLikePlaceholder(s string) bool {
	switch strings.ToLower(s) {
	case "changeme", "change-me", "replace-me", "your-api-key", "your_api_key",
		"your-token", "your_token", "xxx", "todo", "tbd", "none", "null",
		"<redacted>", "[redacted]":
		return true
	default:
		return false
	}
}

// APIError represents a non-2xx HTTP error returned by a Concert endpoint.
// It never contains authorization credentials or payment payloads.
type APIError struct {
	StatusCode int
	Message    string
}

// Error formats the HTTP status code and server-supplied error message.
//
// # Parameters
//
//   - e (receiver): Pointer to APIError.
//
// # Returns
//
// A secret-free error description suitable for logging.
//
// # Example
//
//	var apiErr *concert.APIError
//	if errors.As(err, &apiErr) {
//		fmt.Println(apiErr.StatusCode, apiErr.Message)
//	}
//
// # Used By
//
// No statically resolvable in-repo references found in clients/go/src.
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (e *APIError) Error() string {
	if e == nil {
		return "concert: api error"
	}
	if e.Message != "" {
		return fmt.Sprintf("concert: HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("concert: HTTP %d", e.StatusCode)
}

// CachePurgeConfig configures a CachePurgeClient.
type CachePurgeConfig struct {
	// BaseURL is the Concert origin base URL (http:// or https://, no userinfo).
	BaseURL string
	// Token is an operator or admin API Bearer token wrapped in Secret.
	// Required; NewCachePurgeClient fails closed if empty or placeholder.
	Token Secret
	// HTTPClient optionally supplies a preconfigured *http.Client. When nil, a
	// client with strict timeouts and cross-host redirect credential protection
	// is created automatically.
	HTTPClient *http.Client
	// Timeout sets the per-request timeout when HTTPClient is nil.
	// Defaults to DefaultHTTPTimeout (10s).
	Timeout time.Duration
	// MaxResponseBytes bounds response body reads (R3).
	// Defaults to DefaultMaxResponseBytes (64 KiB).
	MaxResponseBytes int64
}

// PurgeRequest is the JSON payload accepted by Concert's POST /_room/cache/purge.
type PurgeRequest struct {
	Mode   PurgeMode `json:"mode"`
	Host   string    `json:"host,omitempty"`
	Target string    `json:"target,omitempty"`
}

// PurgeResult is the JSON response returned by POST /_room/cache/purge.
type PurgeResult struct {
	Purged int64  `json:"purged"`
	Mode   string `json:"mode"`
}

// CachePurgeClient invokes Concert's authenticated active micro-cache purge API
// (POST /_room/cache/purge).
//
// CachePurgeClient is immutable after construction and safe for concurrent use
// by multiple goroutines. Its token is stored in Secret so formatting or
// logging the client never reveals the credential.
type CachePurgeClient struct {
	baseURL  string
	baseHost string
	token    Secret
	client   *http.Client
	maxBody  int64
}

// NewCachePurgeClient validates cfg and constructs a CachePurgeClient.
//
// # Parameters
//
//   - cfg: Client configuration. cfg.BaseURL must be a valid http/https URL
//     without embedded userinfo. cfg.Token must be non-empty and not a
//     placeholder.
//
// # Returns
//
// A ready-to-use *CachePurgeClient and nil error, or nil and an error matching
// ErrInvalidBaseURL, ErrEmptySecret, or ErrPlaceholderSecret.
//
// # Example
//
//	tok, err := concert.NewValidatedSecret(os.Getenv("CONCERT_ADMIN_TOKEN"))
//	if err != nil {
//		return err
//	}
//	c, err := concert.NewCachePurgeClient(concert.CachePurgeConfig{
//		BaseURL: "https://edge.example.com",
//		Token:   tok,
//	})
//	if err != nil {
//		return err
//	}
//	_ = c
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:653 (direct call)
//   - clients/go/src/concert_test.go:664 (direct call)
//   - clients/go/src/concert_test.go:670 (direct call)
//   - clients/go/src/concert_test.go:677 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func NewCachePurgeClient(cfg CachePurgeConfig) (*CachePurgeClient, error) {
	baseURL, baseHost, err := normalizeBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	tok, err := NewValidatedSecret(cfg.Token.Reveal())
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	maxBody := cfg.MaxResponseBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxResponseBytes
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = newSafeHTTPClient(timeout, baseHost)
	}
	return &CachePurgeClient{
		baseURL:  baseURL,
		baseHost: baseHost,
		token:    tok,
		client:   httpClient,
		maxBody:  maxBody,
	}, nil
}

// PurgeURL purges one exact cached URL path (and optional query string) on
// Concert.
//
// # Parameters
//
//   - ctx: Controls request cancellation and deadline; must be non-nil.
//   - host: Optional virtual host name (empty targets the default site).
//   - targetURL: Required exact path/URL to purge (e.g. "/products/widget").
//
// # Returns
//
// PurgeResult reporting the number of purged entries, or an error.
//
// # Example
//
//	res, err := client.PurgeURL(ctx, "shop.example.com", "/products/drop")
//	if err != nil {
//		return err
//	}
//	fmt.Println("purged:", res.Purged)
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:688 (direct call)
//   - clients/go/src/concert_test.go:706 (direct call)
//   - clients/go/src/concert_test.go:711 (direct call)
//   - clients/go/src/concert_test.go:721 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (c *CachePurgeClient) PurgeURL(ctx context.Context, host, targetURL string) (PurgeResult, error) {
	return c.Purge(ctx, PurgeRequest{Mode: PurgeModeURL, Host: host, Target: targetURL})
}

// PurgePrefix purges all cached entries whose path starts with prefix.
//
// # Parameters
//
//   - ctx: Controls request cancellation and deadline; must be non-nil.
//   - host: Optional virtual host name.
//   - prefix: Required path prefix (e.g. "/products/").
//
// # Returns
//
// PurgeResult reporting the number of purged entries, or an error.
//
// # Example
//
//	res, err := client.PurgePrefix(ctx, "shop.example.com", "/products/")
//	if err != nil {
//		return err
//	}
//	_ = res
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:692 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (c *CachePurgeClient) PurgePrefix(ctx context.Context, host, prefix string) (PurgeResult, error) {
	return c.Purge(ctx, PurgeRequest{Mode: PurgeModePrefix, Host: host, Target: prefix})
}

// PurgeTag purges all cached entries tagged with surrogate/cache tag.
//
// # Parameters
//
//   - ctx: Controls request cancellation and deadline; must be non-nil.
//   - host: Optional virtual host name.
//   - tag: Required cache tag name (e.g. "sku-42").
//
// # Returns
//
// PurgeResult reporting the number of purged entries, or an error.
//
// # Example
//
//	res, err := client.PurgeTag(ctx, "shop.example.com", "sku-42")
//	if err != nil {
//		return err
//	}
//	_ = res
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:696 (direct call)
//   - clients/go/src/concert_test.go:741 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (c *CachePurgeClient) PurgeTag(ctx context.Context, host, tag string) (PurgeResult, error) {
	return c.Purge(ctx, PurgeRequest{Mode: PurgeModeTag, Host: host, Target: tag})
}

// PurgeAll purges every cached page entry (optionally scoped to host).
//
// # Parameters
//
//   - ctx: Controls request cancellation and deadline; must be non-nil.
//   - host: Optional virtual host name; empty purges the default/all site cache.
//
// # Returns
//
// PurgeResult reporting the number of purged entries, or an error.
//
// # Example
//
//	res, err := client.PurgeAll(ctx, "shop.example.com")
//	if err != nil {
//		return err
//	}
//	_ = res
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/concert_test.go:700 (direct call)
//   - clients/go/src/concert_test.go:728 (direct call)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (c *CachePurgeClient) PurgeAll(ctx context.Context, host string) (PurgeResult, error) {
	return c.Purge(ctx, PurgeRequest{Mode: PurgeModeAll, Host: host})
}

// Purge sends a validated cache purge request to POST /_room/cache/purge.
//
// # Parameters
//
//   - ctx: Controls request cancellation and deadline; must be non-nil.
//   - req: PurgeRequest specifying mode ("url", "prefix", "tag", or "all"),
//     optional host, and target (required for url/prefix/tag).
//
// # Returns
//
// PurgeResult and nil error on HTTP 200, or zero PurgeResult and an error
// (ErrInvalidPurge, ErrResponseTooLarge, *APIError, or a network/context error).
// Returned errors never include the Bearer token.
//
// # Example
//
//	res, err := client.Purge(ctx, concert.PurgeRequest{
//		Mode:   concert.PurgeModeTag,
//		Host:   "shop.example.com",
//		Target: "homepage",
//	})
//	if err != nil {
//		return err
//	}
//	_ = res
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:568 (symbol reference)
//   - clients/go/src/bidding.go:599 (symbol reference)
//   - clients/go/src/bidding.go:631 (symbol reference)
//   - clients/go/src/bidding.go:662 (symbol reference)
//   - clients/go/src/doc.go:568 (symbol reference)
//   - clients/go/src/doc.go:599 (symbol reference)
//   - clients/go/src/doc.go:631 (symbol reference)
//   - clients/go/src/doc.go:662 (symbol reference)
//   - clients/go/src/priority.go:568 (symbol reference)
//   - clients/go/src/priority.go:599 (symbol reference)
//   - clients/go/src/priority.go:631 (symbol reference)
//   - clients/go/src/priority.go:662 (symbol reference)
//   - clients/go/src/purge.go:568 (direct call)
//   - clients/go/src/purge.go:599 (direct call)
//   - clients/go/src/purge.go:631 (direct call)
//   - clients/go/src/purge.go:662 (direct call)
//   - clients/go/src/rm1.go:568 (symbol reference)
//   - clients/go/src/rm1.go:599 (symbol reference)
//   - clients/go/src/rm1.go:631 (symbol reference)
//   - clients/go/src/rm1.go:662 (symbol reference)
//   - clients/go/src/signals.go:568 (symbol reference)
//   - clients/go/src/signals.go:599 (symbol reference)
//   - clients/go/src/signals.go:631 (symbol reference)
//   - clients/go/src/signals.go:662 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func (c *CachePurgeClient) Purge(ctx context.Context, req PurgeRequest) (PurgeResult, error) {
	if c == nil {
		return PurgeResult{}, ErrInvalidPurge
	}
	if ctx == nil {
		return PurgeResult{}, fmt.Errorf("%w: nil context", ErrInvalidPurge)
	}
	req.Mode = PurgeMode(strings.ToLower(strings.TrimSpace(string(req.Mode))))
	req.Host = strings.TrimSpace(req.Host)
	req.Target = strings.TrimSpace(req.Target)

	switch req.Mode {
	case PurgeModeURL, PurgeModePrefix, PurgeModeTag:
		if req.Target == "" {
			return PurgeResult{}, fmt.Errorf("%w: target is required for mode %q", ErrInvalidPurge, req.Mode)
		}
	case PurgeModeAll:
	default:
		return PurgeResult{}, fmt.Errorf("%w: unsupported mode %q", ErrInvalidPurge, req.Mode)
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return PurgeResult{}, fmt.Errorf("concert: marshal purge request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+CachePurgePath, bytes.NewReader(payload))
	if err != nil {
		return PurgeResult{}, fmt.Errorf("concert: build purge request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	// Single point of secret use (S6): Reveal only on the outgoing header.
	httpReq.Header.Set("Authorization", "Bearer "+c.token.Reveal())

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return PurgeResult{}, fmt.Errorf("concert: cache purge request failed: %w", sanitizeURLError(err))
	}
	defer resp.Body.Close()

	body, err := readBoundedBody(resp.Body, c.maxBody)
	if err != nil {
		return PurgeResult{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return PurgeResult{}, parseAPIError(resp.StatusCode, body)
	}

	var out PurgeResult
	if err := decodeSingleJSON(body, &out); err != nil {
		return PurgeResult{}, fmt.Errorf("concert: decode purge response: %w", err)
	}
	return out, nil
}

// normalizeBaseURL validates raw as an http/https origin URL without userinfo
// and strips any trailing slash.
//
// # Parameters
//
//   - raw: Base URL string (e.g. "https://edge.example.com").
//
// # Returns
//
// Normalized base URL string, parsed host, and nil error, or ("", "", err)
// matching ErrInvalidBaseURL.
//
// # Example
//
//	base, host, err := normalizeBaseURL("https://edge.example.com/")
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:390 (direct call)
//   - clients/go/src/bidding.go:507 (symbol reference)
//   - clients/go/src/doc.go:390 (symbol reference)
//   - clients/go/src/doc.go:507 (symbol reference)
//   - clients/go/src/priority.go:390 (symbol reference)
//   - clients/go/src/priority.go:507 (symbol reference)
//   - clients/go/src/purge.go:390 (symbol reference)
//   - clients/go/src/purge.go:507 (direct call)
//   - clients/go/src/rm1.go:390 (symbol reference)
//   - clients/go/src/rm1.go:507 (symbol reference)
//   - clients/go/src/signals.go:390 (symbol reference)
//   - clients/go/src/signals.go:507 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func normalizeBaseURL(raw string) (string, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", fmt.Errorf("%w: empty base URL", ErrInvalidBaseURL)
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrInvalidBaseURL, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", "", fmt.Errorf("%w: scheme must be http or https with non-empty host", ErrInvalidBaseURL)
	}
	if u.User != nil {
		return "", "", fmt.Errorf("%w: URL must not contain embedded credentials", ErrInvalidBaseURL)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("%w: base URL must not contain query or fragment", ErrInvalidBaseURL)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), u.Host, nil
}

// newSafeHTTPClient builds an *http.Client with explicit dial/TLS/header
// timeouts and a CheckRedirect policy that strips Authorization on cross-host
// redirects to prevent credential leakage.
//
// # Parameters
//
//   - timeout: Total request timeout.
//   - expectedHost: Origin host allowed to receive Authorization on redirects;
//     when empty, redirects are not followed with credentials.
//
// # Returns
//
// Configured *http.Client suitable for concurrent reuse.
//
// # Example
//
//	hc := newSafeHTTPClient(10*time.Second, "edge.example.com")
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:404 (direct call)
//   - clients/go/src/bidding.go:525 (symbol reference)
//   - clients/go/src/doc.go:404 (symbol reference)
//   - clients/go/src/doc.go:525 (symbol reference)
//   - clients/go/src/priority.go:404 (symbol reference)
//   - clients/go/src/priority.go:525 (symbol reference)
//   - clients/go/src/purge.go:404 (symbol reference)
//   - clients/go/src/purge.go:525 (direct call)
//   - clients/go/src/rm1.go:404 (symbol reference)
//   - clients/go/src/rm1.go:525 (symbol reference)
//   - clients/go/src/signals.go:404 (symbol reference)
//   - clients/go/src/signals.go:525 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func newSafeHTTPClient(timeout time.Duration, expectedHost string) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSHandshakeTimeout = min(timeout, 10*time.Second)
	tr.ResponseHeaderTimeout = timeout
	tr.IdleConnTimeout = 60 * time.Second
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}
			// Never forward Bearer tokens to a different host or downgrade scheme.
			if expectedHost != "" && !strings.EqualFold(req.URL.Host, expectedHost) {
				req.Header.Del("Authorization")
			}
			if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return errors.New("refusing https-to-http redirect")
			}
			return nil
		},
	}
}

// readBoundedBody reads at most maxBytes from r, returning ErrResponseTooLarge
// if the body exceeds maxBytes (R3).
//
// # Parameters
//
//   - r: Response body reader (not closed by this helper).
//   - maxBytes: Maximum permitted payload size in bytes (> 0).
//
// # Returns
//
// Body bytes and nil error, or nil and ErrResponseTooLarge / read error.
//
// # Example
//
//	body, err := readBoundedBody(resp.Body, DefaultMaxResponseBytes)
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:488 (direct call)
//   - clients/go/src/bidding.go:564 (direct call)
//   - clients/go/src/bidding.go:762 (symbol reference)
//   - clients/go/src/doc.go:488 (symbol reference)
//   - clients/go/src/doc.go:564 (symbol reference)
//   - clients/go/src/doc.go:762 (symbol reference)
//   - clients/go/src/priority.go:488 (symbol reference)
//   - clients/go/src/priority.go:564 (symbol reference)
//   - clients/go/src/priority.go:762 (symbol reference)
//   - clients/go/src/purge.go:488 (symbol reference)
//   - clients/go/src/purge.go:564 (symbol reference)
//   - clients/go/src/purge.go:762 (direct call)
//   - clients/go/src/rm1.go:488 (symbol reference)
//   - clients/go/src/rm1.go:564 (symbol reference)
//   - clients/go/src/rm1.go:762 (symbol reference)
//   - clients/go/src/signals.go:488 (symbol reference)
//   - clients/go/src/signals.go:564 (symbol reference)
//   - clients/go/src/signals.go:762 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func readBoundedBody(r io.Reader, maxBytes int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("concert: read response body: %w", err)
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%w: limit %d bytes", ErrResponseTooLarge, maxBytes)
	}
	return b, nil
}

// decodeSingleJSON decodes exactly one JSON value from data into dst and
// rejects trailing non-whitespace tokens.
//
// # Parameters
//
//   - data: JSON payload bytes.
//   - dst: Pointer to destination value.
//
// # Returns
//
// nil on success, or a decode error.
//
// # Example
//
//	var res PurgeResult
//	if err := decodeSingleJSON(body, &res); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:248 (direct call)
//   - clients/go/src/bidding.go:257 (direct call)
//   - clients/go/src/bidding.go:497 (direct call)
//   - clients/go/src/bidding.go:573 (direct call)
//   - clients/go/src/bidding.go:771 (symbol reference)
//   - clients/go/src/doc.go:248 (symbol reference)
//   - clients/go/src/doc.go:257 (symbol reference)
//   - clients/go/src/doc.go:497 (symbol reference)
//   - clients/go/src/doc.go:573 (symbol reference)
//   - clients/go/src/doc.go:771 (symbol reference)
//   - clients/go/src/priority.go:248 (symbol reference)
//   - clients/go/src/priority.go:257 (symbol reference)
//   - clients/go/src/priority.go:497 (symbol reference)
//   - clients/go/src/priority.go:573 (symbol reference)
//   - clients/go/src/priority.go:771 (symbol reference)
//   - clients/go/src/purge.go:248 (symbol reference)
//   - clients/go/src/purge.go:257 (symbol reference)
//   - clients/go/src/purge.go:497 (symbol reference)
//   - clients/go/src/purge.go:573 (symbol reference)
//   - clients/go/src/purge.go:771 (direct call)
//   - clients/go/src/rm1.go:248 (symbol reference)
//   - clients/go/src/rm1.go:257 (symbol reference)
//   - clients/go/src/rm1.go:497 (symbol reference)
//   - clients/go/src/rm1.go:573 (symbol reference)
//   - clients/go/src/rm1.go:771 (symbol reference)
//   - clients/go/src/signals.go:248 (symbol reference)
//   - clients/go/src/signals.go:257 (symbol reference)
//   - clients/go/src/signals.go:497 (symbol reference)
//   - clients/go/src/signals.go:573 (symbol reference)
//   - clients/go/src/signals.go:771 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func decodeSingleJSON(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

// parseAPIError extracts a short secret-free error message from a non-2xx
// Concert JSON or text error response.
//
// # Parameters
//
//   - statusCode: HTTP response status code.
//   - body: Bounded response body bytes.
//
// # Returns
//
// An *APIError containing statusCode and a bounded message.
//
// # Example
//
//	return parseAPIError(resp.StatusCode, body)
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:493 (direct call)
//   - clients/go/src/bidding.go:569 (direct call)
//   - clients/go/src/bidding.go:767 (symbol reference)
//   - clients/go/src/doc.go:493 (symbol reference)
//   - clients/go/src/doc.go:569 (symbol reference)
//   - clients/go/src/doc.go:767 (symbol reference)
//   - clients/go/src/priority.go:493 (symbol reference)
//   - clients/go/src/priority.go:569 (symbol reference)
//   - clients/go/src/priority.go:767 (symbol reference)
//   - clients/go/src/purge.go:493 (symbol reference)
//   - clients/go/src/purge.go:569 (symbol reference)
//   - clients/go/src/purge.go:767 (direct call)
//   - clients/go/src/rm1.go:493 (symbol reference)
//   - clients/go/src/rm1.go:569 (symbol reference)
//   - clients/go/src/rm1.go:767 (symbol reference)
//   - clients/go/src/signals.go:493 (symbol reference)
//   - clients/go/src/signals.go:569 (symbol reference)
//   - clients/go/src/signals.go:767 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func parseAPIError(statusCode int, body []byte) *APIError {
	var envelope struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && strings.TrimSpace(envelope.Error) != "" {
		return &APIError{StatusCode: statusCode, Message: strings.TrimSpace(envelope.Error)}
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 256 {
		msg = msg[:256]
	}
	return &APIError{StatusCode: statusCode, Message: msg}
}

// sanitizeURLError strips any query string from a *url.Error so query tokens
// cannot accidentally leak into error logs while preserving wrapped causes
// (such as context.Canceled and context.DeadlineExceeded).
//
// # Parameters
//
//   - err: Error returned by http.Client.Do.
//
// # Returns
//
// Original err or a sanitized *url.Error wrapping the same underlying error.
//
// # Example
//
//	return fmt.Errorf("request failed: %w", sanitizeURLError(err))
//
// # Used By
//
// Generated from typed AST references in clients/go/src:
//
//   - clients/go/src/bidding.go:484 (direct call)
//   - clients/go/src/bidding.go:560 (direct call)
//   - clients/go/src/bidding.go:758 (symbol reference)
//   - clients/go/src/doc.go:484 (symbol reference)
//   - clients/go/src/doc.go:560 (symbol reference)
//   - clients/go/src/doc.go:758 (symbol reference)
//   - clients/go/src/priority.go:484 (symbol reference)
//   - clients/go/src/priority.go:560 (symbol reference)
//   - clients/go/src/priority.go:758 (symbol reference)
//   - clients/go/src/purge.go:484 (symbol reference)
//   - clients/go/src/purge.go:560 (symbol reference)
//   - clients/go/src/purge.go:758 (direct call)
//   - clients/go/src/rm1.go:484 (symbol reference)
//   - clients/go/src/rm1.go:560 (symbol reference)
//   - clients/go/src/rm1.go:758 (symbol reference)
//   - clients/go/src/signals.go:484 (symbol reference)
//   - clients/go/src/signals.go:560 (symbol reference)
//   - clients/go/src/signals.go:758 (symbol reference)
//
// Scope: clients/go/src module including tests; external callers not enumerated.
func sanitizeURLError(err error) error {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	cleaned := ue.URL
	if parsed, parseErr := url.Parse(ue.URL); parseErr == nil {
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.Fragment = ""
		cleaned = parsed.String()
	}
	return &url.Error{Op: ue.Op, URL: cleaned, Err: ue.Err}
}
