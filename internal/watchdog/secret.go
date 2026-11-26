// Package watchdog implements the external health, resource, and recovery
// supervisor for Concert proxies (concert, wpconcert, econcert).
//
// It combines a pure-stdlib Prometheus text metrics parser, Linux procfs
// process inspection, a pure recovery-policy state machine that distinguishes
// origin/upstream outages from Concert-internal faults, and a bounded
// supervisor supporting both parent-process supervision and external PID
// monitoring.
package watchdog

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
)

// RedactedPlaceholder is printed by every Secret formatting, marshaling, and
// structured-logging path in place of raw credential material.
const RedactedPlaceholder = "[REDACTED]"

// maxSecretBytes bounds credential file reads so an accidental or hostile
// path cannot cause unbounded memory allocation.
const maxSecretBytes = 64 << 10

// Sentinel errors returned when loading or validating credentials and URLs.
// None of these errors include raw secret values.
var (
	// ErrSecretNotSet indicates that neither a file path nor an environment
	// variable supplied the requested credential.
	ErrSecretNotSet = errors.New("secret not set")
	// ErrSecretEmpty indicates that the configured credential source was empty
	// or contained only whitespace.
	ErrSecretEmpty = errors.New("secret is empty")
	// ErrSecretPlaceholder indicates that the configured credential value looks
	// like an unreplaced template placeholder.
	ErrSecretPlaceholder = errors.New("secret looks like a placeholder")
	// ErrSecretTooLarge indicates that a secret file exceeded maxSecretBytes.
	ErrSecretTooLarge = errors.New("secret source too large")
	// ErrSecretPermissions indicates that a secret file is readable by group or
	// other users on a Unix-like host (must be 0600 or stricter).
	ErrSecretPermissions = errors.New("secret file permissions too open (require 0600 or stricter)")
	// ErrSecretNotRegular indicates that a secret file path does not point to a
	// regular file.
	ErrSecretNotRegular = errors.New("secret source is not a regular file")
	// ErrInvalidURL indicates that a configured probe or webhook URL failed
	// scheme, host, or credential-free validation.
	ErrInvalidURL = errors.New("invalid URL")
)

// Secret holds a sensitive bearer token or credential value. Its zero value is
// empty and reports IsZero() == true. Secret is an immutable value type safe
// for concurrent use; all standard formatting, JSON, text, and slog paths
// output RedactedPlaceholder. Call Reveal only at the single point where an
// outbound Authorization header is constructed.
type Secret struct {
	v string
}

// NewSecret wraps raw in a redacting Secret value. Callers should normally
// obtain credentials through LoadSecretFromFile, LoadSecretFromEnv, or
// LoadOptionalSecret rather than passing literals.
//
// # Parameters
//
//   - raw: Raw credential string to protect. An empty string yields the zero Secret.
//
// # Returns
//
// A Secret value whose formatting methods emit RedactedPlaceholder.
//
// # Example
//
//	s := watchdog.NewSecret(os.Getenv("CONCERT_WATCHDOG_TOKEN"))
//	fmt.Println(s.String()) // [REDACTED]
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:913 (direct call)
//   - internal/watchdog/watchdog_test.go:1068 (direct call)
//   - internal/watchdog/watchdog_test.go:1069 (direct call)
//   - internal/watchdog/watchdog_test.go:1255 (direct call)
//   - internal/watchdog/watchdog_test.go:1330 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func NewSecret(raw string) Secret {
	return Secret{v: raw}
}

// Reveal returns the raw underlying credential string. Callers must invoke
// Reveal only at the exact point of use (such as setting an Authorization
// header) and must never pass the returned string to logs, errors, or metrics.
//
// # Parameters
//
// None.
//
// # Returns
//
// The raw credential string, or "" for the zero Secret.
//
// # Example
//
//	if !tok.IsZero() {
//		req.Header.Set("Authorization", "Bearer "+tok.Reveal())
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:830 (direct call)
//   - internal/watchdog/supervisor.go:886 (direct call)
//   - internal/watchdog/supervisor.go:975 (direct call)
//   - internal/watchdog/watchdog_test.go:949 (direct call)
//   - internal/watchdog/watchdog_test.go:960 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s Secret) Reveal() string {
	return s.v
}

// IsZero reports whether s holds no credential material.
//
// # Parameters
//
// None.
//
// # Returns
//
// true when the wrapped value is empty; false otherwise.
//
// # Example
//
//	var s watchdog.Secret
//	fmt.Println(s.IsZero()) // true
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:829 (direct call)
//   - internal/watchdog/supervisor.go:885 (direct call)
//   - internal/watchdog/supervisor.go:974 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (s Secret) IsZero() bool {
	return s.v == ""
}

// String implements fmt.Stringer and always returns RedactedPlaceholder.
//
// # Parameters
//
// None.
//
// # Returns
//
// RedactedPlaceholder regardless of whether s is empty or populated.
//
// # Example
//
//	fmt.Println(tok.String()) // [REDACTED]
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:931 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (Secret) String() string {
	return RedactedPlaceholder
}

// GoString implements fmt.GoStringer and always returns a redacted Go-syntax
// representation without exposing the wrapped credential.
//
// # Parameters
//
// None.
//
// # Returns
//
// The constant string "watchdog.Secret{[REDACTED]}".
//
// # Example
//
//	fmt.Printf("%#v\n", tok) // watchdog.Secret{[REDACTED]}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:932 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (Secret) GoString() string {
	return "watchdog.Secret{" + RedactedPlaceholder + "}"
}

// Format implements fmt.Formatter so every fmt verb (%v, %+v, %#v, %s, %q,
// %x, etc.) writes RedactedPlaceholder instead of reflecting on unexported fields.
//
// # Parameters
//
//   - f: Destination fmt.State written to by fmt.
//   - verb: Format verb (ignored; output is always redacted).
//
// # Example
//
//	fmt.Printf("%+v\n", tok) // [REDACTED]
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope
// (may be satisfied via interface dispatch or external callers).
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (Secret) Format(f fmt.State, verb rune) {
	_ = verb
	// Format cannot return an error; fmt.State records write failures internally.
	_, _ = io.WriteString(f, RedactedPlaceholder)
}

// MarshalText implements encoding.TextMarshaler and emits RedactedPlaceholder.
//
// # Parameters
//
// None.
//
// # Returns
//
// The UTF-8 bytes of RedactedPlaceholder and a nil error.
//
// # Example
//
//	b, err := tok.MarshalText()
//	if err != nil {
//		return err
//	}
//	fmt.Println(string(b)) // [REDACTED]
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/watchdog_test.go:925 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (Secret) MarshalText() ([]byte, error) {
	return []byte(RedactedPlaceholder), nil
}

// MarshalJSON implements json.Marshaler and marshals RedactedPlaceholder as a
// JSON string so structs containing Secret never serialize raw credentials.
//
// # Parameters
//
// None.
//
// # Returns
//
// JSON bytes for RedactedPlaceholder and any json.Marshal error.
//
// # Example
//
//	b, err := json.Marshal(tok)
//	if err != nil {
//		return err
//	}
//	fmt.Println(string(b)) // "[REDACTED]"
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope
// (may be satisfied via interface dispatch or external callers).
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(RedactedPlaceholder)
}

// LogValue implements slog.LogValuer so structured logs always record
// RedactedPlaceholder even under slog.Any or slog.Group.
//
// # Parameters
//
// None.
//
// # Returns
//
// An slog.Value holding RedactedPlaceholder.
//
// # Example
//
//	slog.Info("configured", "token", tok)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope
// (may be satisfied via interface dispatch or external callers).
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func (Secret) LogValue() slog.Value {
	return slog.StringValue(RedactedPlaceholder)
}

var (
	_ fmt.Stringer           = Secret{}
	_ fmt.GoStringer         = Secret{}
	_ fmt.Formatter          = Secret{}
	_ json.Marshaler         = Secret{}
	_ encoding.TextMarshaler = Secret{}
	_ slog.LogValuer         = Secret{}
)

// LoadSecretFromFile reads a credential from path after verifying the open file
// handle is a regular file with 0600 (or stricter) permissions on Unix-like
// hosts, bounds the read to maxSecretBytes, trims surrounding whitespace, and
// rejects empty or placeholder values.
//
// # Parameters
//
//   - path: Filesystem path to the secret file; empty returns ErrSecretNotSet.
//
// # Returns
//
// A validated Secret on success, or the zero Secret and a secret-free error
// matching one of the ErrSecret* sentinels (or an OS error) via errors.Is.
//
// # Example
//
//	tok, err := watchdog.LoadSecretFromFile("/run/credentials/concert.token")
//	if err != nil {
//		return err
//	}
//	_ = tok
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/secret.go:469 (direct call)
//   - internal/watchdog/watchdog_test.go:959 (direct call)
//   - internal/watchdog/watchdog_test.go:969 (direct call)
//   - internal/watchdog/watchdog_test.go:978 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func LoadSecretFromFile(path string) (Secret, error) {
	if path == "" {
		return Secret{}, ErrSecretNotSet
	}
	// Open first and inspect the open descriptor to avoid a stat/open TOCTOU race.
	f, err := os.Open(path)
	if err != nil {
		return Secret{}, fmt.Errorf("open secret file %q: %w", path, err)
	}
	defer f.Close() // read-only descriptor; close error is not material

	fi, err := f.Stat()
	if err != nil {
		return Secret{}, fmt.Errorf("stat secret file %q: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return Secret{}, fmt.Errorf("secret file %q: %w", path, ErrSecretNotRegular)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return Secret{}, fmt.Errorf("secret file %q has mode %04o: %w", path, fi.Mode().Perm(), ErrSecretPermissions)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSecretBytes+1))
	if err != nil {
		return Secret{}, fmt.Errorf("read secret file %q: %w", path, err)
	}
	if len(b) > maxSecretBytes {
		return Secret{}, fmt.Errorf("secret file %q: %w", path, ErrSecretTooLarge)
	}
	return validateSecret(strings.TrimSpace(string(b)), path)
}

// LoadSecretFromEnv reads and validates a credential from environment variable
// name, rejecting unset, empty, or placeholder values.
//
// # Parameters
//
//   - name: Environment variable name (for example "CONCERT_WATCHDOG_TOKEN").
//
// # Returns
//
// A validated Secret on success, or the zero Secret and a secret-free error
// wrapping ErrSecretNotSet, ErrSecretEmpty, or ErrSecretPlaceholder.
//
// # Example
//
//	tok, err := watchdog.LoadSecretFromEnv("CONCERT_WATCHDOG_TOKEN")
//	if err != nil {
//		return err
//	}
//	_ = tok
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/secret.go:476 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func LoadSecretFromEnv(name string) (Secret, error) {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return Secret{}, fmt.Errorf("environment variable %s: %w", name, ErrSecretNotSet)
	}
	return validateSecret(strings.TrimSpace(raw), "$"+name)
}

// LoadOptionalSecret resolves an optional credential from <envName>_FILE first,
// then <envName>. If neither variable is set in the environment, it returns
// (Secret{}, false, nil). If either variable is set, it fails closed on empty,
// placeholder, unreadable, or overly permissive secret sources.
//
// # Parameters
//
//   - envName: Base environment variable name (without the "_FILE" suffix).
//
// # Returns
//
// The loaded Secret, a boolean indicating whether a credential was configured,
// and any validation or I/O error.
//
// # Example
//
//	tok, ok, err := watchdog.LoadOptionalSecret("CONCERT_WATCHDOG_TOKEN")
//	if err != nil {
//		return err
//	}
//	_ = ok
//	_ = tok
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-watchdog/main.go:136 (direct call)
//   - cmd/concert-watchdog/main.go:140 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func LoadOptionalSecret(envName string) (Secret, bool, error) {
	fileEnv := envName + "_FILE"
	if p, ok := os.LookupEnv(fileEnv); ok {
		p = strings.TrimSpace(p)
		if p == "" {
			return Secret{}, false, fmt.Errorf("environment variable %s: %w", fileEnv, ErrSecretEmpty)
		}
		s, err := LoadSecretFromFile(p)
		if err != nil {
			return Secret{}, false, err
		}
		return s, true, nil
	}
	if _, ok := os.LookupEnv(envName); ok {
		s, err := LoadSecretFromEnv(envName)
		if err != nil {
			return Secret{}, false, err
		}
		return s, true, nil
	}
	return Secret{}, false, nil
}

// validateSecret checks that raw is non-empty and not a well-known placeholder
// string, attributing errors to src without leaking raw.
//
// # Parameters
//
//   - raw: Trimmed candidate secret value.
//   - src: Safe human-readable source name (file path or "$ENV_VAR").
//
// # Returns
//
// A Secret wrapping raw, or an error wrapping ErrSecretEmpty or
// ErrSecretPlaceholder.
//
// # Example
//
//	sec, err := validateSecret(trimmed, "$CONCERT_WATCHDOG_TOKEN")
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/secret.go:393 (direct call)
//   - internal/watchdog/secret.go:428 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func validateSecret(raw, src string) (Secret, error) {
	if raw == "" {
		return Secret{}, fmt.Errorf("secret from %s: %w", src, ErrSecretEmpty)
	}
	if looksLikePlaceholder(raw) {
		return Secret{}, fmt.Errorf("secret from %s: %w", src, ErrSecretPlaceholder)
	}
	return Secret{v: raw}, nil
}

// looksLikePlaceholder reports whether s matches common unreplaced template
// placeholders that must never be accepted as real credentials.
//
// # Parameters
//
//   - s: Trimmed secret value to inspect.
//
// # Returns
//
// true when s matches a known placeholder token case-insensitively.
//
// # Example
//
//	if looksLikePlaceholder(raw) {
//		return Secret{}, ErrSecretPlaceholder
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/secret.go:514 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func looksLikePlaceholder(s string) bool {
	switch strings.ToLower(s) {
	case "changeme", "change-me", "changeme-not-real", "replace-me",
		"your-api-key", "your_api_key", "your-token", "your_token",
		"xxx", "todo", "tbd", "none", "null", "<redacted>", "[redacted]":
		return true
	}
	return false
}

// ValidateProbeURL validates a Concert health, readiness, metrics, or clear URL.
// It requires an http or https scheme, a non-empty host, and no embedded URL
// credentials (userinfo).
//
// # Parameters
//
//   - raw: Candidate HTTP/HTTPS URL string.
//
// # Returns
//
// The parsed *url.URL on success, or an error wrapping ErrInvalidURL.
//
// # Example
//
//	u, err := watchdog.ValidateProbeURL("http://127.0.0.1:8080/_room/healthz")
//	if err != nil {
//		return err
//	}
//	_ = u
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/secret.go:638 (direct call)
//   - internal/watchdog/supervisor.go:377 (direct call)
//   - internal/watchdog/supervisor.go:381 (direct call)
//   - internal/watchdog/supervisor.go:385 (direct call)
//   - internal/watchdog/supervisor.go:389 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func ValidateProbeURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty URL: %w", ErrInvalidURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", errors.Join(ErrInvalidURL, err))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q (want http or https): %w", u.Scheme, ErrInvalidURL)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("missing host in %q: %w", RedactURL(raw), ErrInvalidURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("credentials in URL userinfo are forbidden: %w", ErrInvalidURL)
	}
	return u, nil
}

// ValidateWebhookURL validates an alert webhook destination. It enforces HTTPS
// for all remote hosts and permits plaintext HTTP only for explicit loopback
// hosts (localhost, 127.0.0.1, ::1). Embedded userinfo is always rejected.
//
// # Parameters
//
//   - raw: Candidate webhook URL string.
//
// # Returns
//
// The parsed *url.URL on success, or an error wrapping ErrInvalidURL.
//
// # Example
//
//	u, err := watchdog.ValidateWebhookURL("https://alerts.example.com/concert")
//	if err != nil {
//		return err
//	}
//	_ = u
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/supervisor.go:394 (direct call)
//   - internal/watchdog/watchdog_test.go:983 (direct call)
//   - internal/watchdog/watchdog_test.go:986 (direct call)
//   - internal/watchdog/watchdog_test.go:989 (direct call)
//   - internal/watchdog/watchdog_test.go:998 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func ValidateWebhookURL(raw string) (*url.URL, error) {
	u, err := ValidateProbeURL(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "https" {
		return u, nil
	}
	if isLoopbackHost(u.Hostname()) {
		return u, nil
	}
	return nil, fmt.Errorf("webhook URL must use https (http allowed only for localhost/loopback): %w", ErrInvalidURL)
}

// isLoopbackHost reports whether host is "localhost" or a loopback IP address.
//
// # Parameters
//
//   - host: Hostname or IP literal without port (as returned by url.URL.Hostname).
//
// # Returns
//
// true for "localhost" (case-insensitive) or any IP for which net.IP.IsLoopback
// is true.
//
// # Example
//
//	if isLoopbackHost(u.Hostname()) {
//		return u, nil
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/watchdog/secret.go:645 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// RedactURL strips embedded userinfo and sensitive query parameters from raw so
// URLs can be logged or wrapped in errors without disclosing credentials.
//
// # Parameters
//
//   - raw: URL string to sanitize; unparseable strings return RedactedPlaceholder.
//
// # Returns
//
// A sanitized URL string with userinfo removed and sensitive query values
// replaced by RedactedPlaceholder.
//
// # Example
//
//	safe := watchdog.RedactURL(endpoint)
//	fmt.Println(safe)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-watchdog/main.go:192 (direct call)
//   - cmd/concert-watchdog/main.go:193 (direct call)
//   - cmd/concert-watchdog/main.go:194 (direct call)
//   - cmd/concert-watchdog/main.go:238 (direct call)
//   - internal/watchdog/secret.go:598 (direct call)
//   - internal/watchdog/supervisor.go:826 (direct call)
//   - internal/watchdog/supervisor.go:835 (direct call)
//   - internal/watchdog/supervisor.go:841 (direct call)
//   - internal/watchdog/supervisor.go:844 (direct call)
//   - internal/watchdog/supervisor.go:847 (direct call)
//   - internal/watchdog/supervisor.go:883 (direct call)
//   - internal/watchdog/supervisor.go:890 (direct call)
//   - internal/watchdog/supervisor.go:896 (direct call)
//   - internal/watchdog/supervisor.go:899 (direct call)
//   - internal/watchdog/supervisor.go:970 (direct call)
//   - internal/watchdog/supervisor.go:979 (direct call)
//   - internal/watchdog/supervisor.go:985 (direct call)
//   - internal/watchdog/supervisor.go:1463 (direct call)
//   - internal/watchdog/watchdog_test.go:1012 (direct call)
//
// Scope: internal/watchdog and cmd/concert-watchdog (including tests); darwin/arm64, default tags.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return RedactedPlaceholder
	}
	u.User = nil
	if u.RawQuery != "" {
		q := u.Query()
		changed := false
		for k := range q {
			kl := strings.ToLower(k)
			if strings.Contains(kl, "token") || strings.Contains(kl, "key") ||
				strings.Contains(kl, "secret") || strings.Contains(kl, "pass") ||
				strings.Contains(kl, "auth") || strings.Contains(kl, "sig") {
				q.Set(k, RedactedPlaceholder)
				changed = true
			}
		}
		if changed {
			u.RawQuery = q.Encode()
		}
	}
	return u.String()
}
