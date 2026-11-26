// Package notify implements multi-channel operational ChatOps alerting for
// Concert across Slack, PagerDuty, Discord, Microsoft Teams, and HMAC-signed
// generic webhooks using only the Go standard library.
package notify

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
)

// RedactedPlaceholder is emitted by every formatting, serialization, and
// logging path for a Secret value so credential material is never disclosed.
const RedactedPlaceholder = "[REDACTED]"

const maxSecretFileBytes = 64 << 10

// Sentinel errors returned by secret ingestion helpers. None of them contain
// or wrap credential material.
var (
	ErrSecretNotSet      = errors.New("secret not set")
	ErrSecretEmpty       = errors.New("secret is empty")
	ErrSecretPlaceholder = errors.New("secret looks like a placeholder")
	ErrSecretTooLarge    = errors.New("secret file exceeds 64 KiB limit")
	ErrSecretPermissions = errors.New("secret file permissions too open (require 0600 or stricter)")
	ErrSecretNotRegular  = errors.New("secret source is not a regular file")
)

// Secret holds a sensitive credential value (such as a PagerDuty routing key,
// webhook signing key, or bearer token) so it cannot be printed, logged, or
// marshaled accidentally. The zero value is empty and reports IsZero() == true.
// Secret is an immutable value type safe for concurrent reads and copies.
type Secret struct {
	v string
}

// NewSecret wraps raw in a redacting Secret value. Callers should obtain raw
// from SecretFromFile or SecretFromEnv at runtime rather than source literals.
//
// # Parameters
//
//   - raw: The credential string to wrap. An empty string produces a zero Secret.
//
// # Returns
//
// A Secret whose String, GoString, Format, MarshalText, MarshalJSON, and
// LogValue methods always emit RedactedPlaceholder.
//
// # Example
//
//	s := notify.NewSecret(os.Getenv("CONCERT_WEBHOOK_SECRET"))
//	fmt.Println(s) // prints [REDACTED]
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :42 (direct call)
//   - :219 (direct call)
//   - :283 (direct call)
//   - :295 (direct call)
//   - :405 (direct call)
//   - :406 (direct call)
//   - :781 (direct call)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func NewSecret(raw string) Secret {
	return Secret{v: raw}
}

// Reveal returns the underlying raw credential value. Callers must invoke
// Reveal only at the single point of cryptographic or wire-protocol use and
// must never pass the result to logs, errors, or formatted output.
//
// # Parameters
//
// None.
//
// # Returns
//
// The raw credential string, or "" when s is zero.
//
// # Example
//
//	if !routingKey.IsZero() {
//	    _ = routingKey.Reveal()
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :47 (direct call)
//   - :48 (direct call)
//   - :121 (direct call)
//   - :122 (direct call)
//   - :161 (direct call)
//   - :228 (direct call)
//   - :1075 (direct call)
//   - :1075 (function value)
//   - :1322 (direct call)
//   - :1322 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (s Secret) Reveal() string {
	return s.v
}

// IsZero reports whether s holds no credential value.
//
// # Parameters
//
// None.
//
// # Returns
//
// true if the underlying value is empty; false otherwise.
//
// # Example
//
//	var s notify.Secret
//	fmt.Println(s.IsZero()) // true
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :44 (direct call)
//   - :411 (direct call)
//   - :411 (function value)
//   - :815 (direct call)
//   - :815 (function value)
//   - :1031 (direct call)
//   - :1031 (function value)
//   - :1319 (direct call)
//   - :1319 (function value)
//   - :1365 (direct call)
//   - :1365 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (s Secret) IsZero() bool {
	return s.v == ""
}

// Equal reports whether candidate matches s using constant-time comparisons
// over both SHA-256 digests (to avoid leaking secret length) and the raw byte
// slices. Safe for concurrent use.
//
// # Parameters
//
//   - candidate: Untrusted credential string to compare against s.
//
// # Returns
//
// true if and only if s is non-zero and candidate is byte-for-byte identical
// to s.
//
// # Example
//
//	if !signingKey.Equal(candidate) {
//	    return errors.New("mismatch")
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :50 (direct call)
//   - :53 (direct call)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (s Secret) Equal(candidate string) bool {
	if s.v == "" || candidate == "" {
		return false
	}
	// Compare fixed-length SHA-256 hashes first so timing does not reveal the
	// length of the configured secret, then confirm exact byte equality.
	wantHash := sha256.Sum256([]byte(s.v))
	gotHash := sha256.Sum256([]byte(candidate))
	hashMatch := subtle.ConstantTimeCompare(wantHash[:], gotHash[:])
	rawMatch := subtle.ConstantTimeCompare([]byte(s.v), []byte(candidate))
	return (hashMatch & rawMatch) == 1
}

// String implements fmt.Stringer and always returns RedactedPlaceholder.
//
// # Parameters
//
// None.
//
// # Returns
//
// RedactedPlaceholder.
//
// # Example
//
//	fmt.Println(secret.String()) // [REDACTED]
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :58 (direct call)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (Secret) String() string { return RedactedPlaceholder }

// GoString implements fmt.GoStringer and always returns a redacted marker.
//
// # Parameters
//
// None.
//
// # Returns
//
// A constant redacted Go-syntax representation.
//
// # Example
//
//	fmt.Printf("%#v\n", secret) // notify.Secret{[REDACTED]}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :59 (direct call)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (Secret) GoString() string { return "notify.Secret{" + RedactedPlaceholder + "}" }

// Format implements fmt.Formatter so every fmt verb (%v, %+v, %#v, %s, %q, %x)
// prints RedactedPlaceholder without reflecting over the unexported field.
//
// # Parameters
//
//   - f: Destination fmt.State; must be non-nil.
//   - verb: Ignored formatting verb.
//
// # Example
//
//	fmt.Printf("%+v\n", cfg) // Secret fields print [REDACTED]
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (Secret) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, RedactedPlaceholder)
}

// MarshalText implements encoding.TextMarshaler and always emits
// RedactedPlaceholder.
//
// # Parameters
//
// None.
//
// # Returns
//
// A copy of RedactedPlaceholder bytes and a nil error.
//
// # Example
//
//	b, err := secret.MarshalText()
//	_ = err
//	fmt.Println(string(b)) // [REDACTED]
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :76 (direct call)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (Secret) MarshalText() ([]byte, error) { return []byte(RedactedPlaceholder), nil }

// MarshalJSON implements json.Marshaler and always emits a JSON string
// containing RedactedPlaceholder.
//
// # Parameters
//
// None.
//
// # Returns
//
// JSON-encoded RedactedPlaceholder and any marshaling error.
//
// # Example
//
//	b, err := json.Marshal(secret)
//	_ = err
//	fmt.Println(string(b)) // "[REDACTED]"
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (Secret) MarshalJSON() ([]byte, error) { return json.Marshal(RedactedPlaceholder) }

// LogValue implements slog.LogValuer so structured logs always record
// RedactedPlaceholder even when logged via slog.Any or struct attributes.
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
//	slog.Info("notifier configured", "secret", secret)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (Secret) LogValue() slog.Value { return slog.StringValue(RedactedPlaceholder) }

var (
	_ fmt.Stringer           = Secret{}
	_ fmt.GoStringer         = Secret{}
	_ fmt.Formatter          = Secret{}
	_ json.Marshaler         = Secret{}
	_ encoding.TextMarshaler = Secret{}
	_ slog.LogValuer         = Secret{}
)

// SecretFromFile loads a credential from path, verifying the open file handle
// is a regular file with 0600 (or stricter) permissions on Unix, bounding the
// read to 64 KiB, trimming surrounding whitespace, and rejecting empty or
// placeholder contents. Errors name path and the failed check, never content.
//
// # Parameters
//
//   - path: Filesystem path to the secret file; empty path returns ErrSecretNotSet.
//
// # Returns
//
// A validated Secret on success, or zero Secret and an error matching one of
// ErrSecretNotSet, ErrSecretNotRegular, ErrSecretPermissions, ErrSecretTooLarge,
// ErrSecretEmpty, ErrSecretPlaceholder, or an OS I/O error.
//
// # Example
//
//	key, err := notify.SecretFromFile("/run/secrets/pagerduty_routing_key")
//	if err != nil {
//	    return err
//	}
//	_ = key
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :117 (direct call)
//   - :133 (direct call)
//   - :142 (direct call)
//   - :150 (direct call)
//   - :154 (direct call)
//   - :485 (direct call)
//   - :485 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func SecretFromFile(path string) (Secret, error) {
	if path == "" {
		return Secret{}, ErrSecretNotSet
	}
	f, err := os.Open(path)
	if err != nil {
		return Secret{}, fmt.Errorf("open secret file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	// Stat the open file descriptor rather than the path to avoid TOCTOU swaps.
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
	b, err := io.ReadAll(io.LimitReader(f, maxSecretFileBytes+1))
	if err != nil {
		return Secret{}, fmt.Errorf("read secret file %q: %w", path, err)
	}
	if len(b) > maxSecretFileBytes {
		return Secret{}, fmt.Errorf("secret file %q: %w", path, ErrSecretTooLarge)
	}
	return validateSecret(strings.TrimSpace(string(b)), path)
}

// SecretFromEnv loads and validates a credential from environment variable
// name. Errors name the variable, never its value.
//
// # Parameters
//
//   - name: Environment variable name to inspect via os.LookupEnv.
//
// # Returns
//
// A validated Secret, or zero Secret and an error wrapping ErrSecretNotSet,
// ErrSecretEmpty, or ErrSecretPlaceholder.
//
// # Example
//
//	key, err := notify.SecretFromEnv("CONCERT_PAGERDUTY_KEY")
//	if err != nil && !errors.Is(err, notify.ErrSecretNotSet) {
//	    return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :160 (direct call)
//   - :164 (direct call)
//   - :488 (direct call)
//   - :488 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func SecretFromEnv(name string) (Secret, error) {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return Secret{}, fmt.Errorf("environment variable %s: %w", name, ErrSecretNotSet)
	}
	return validateSecret(strings.TrimSpace(raw), "$"+name)
}

// ResolveOptionalSecret resolves a credential from <envName>_FILE first, then
// <envName>. If neither environment variable is set, it returns a zero Secret
// and a nil error. If either variable is present, it fails closed on empty,
// placeholder, missing-file, or overly permissive file mode.
//
// # Parameters
//
//   - envName: Base environment variable name (e.g. "CONCERT_WEBHOOK_SECRET").
//
// # Returns
//
// The resolved Secret (zero when unconfigured) and any validation or file error.
//
// # Example
//
//	key, err := notify.ResolveOptionalSecret("CONCERT_WEBHOOK_SECRET")
//	if err != nil {
//	    return err
//	}
//	_ = key
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func ResolveOptionalSecret(envName string) (Secret, error) {
	fileEnv := envName + "_FILE"
	if path, ok := os.LookupEnv(fileEnv); ok {
		if strings.TrimSpace(path) == "" {
			return Secret{}, fmt.Errorf("environment variable %s: %w", fileEnv, ErrSecretEmpty)
		}
		return SecretFromFile(strings.TrimSpace(path))
	}
	if _, ok := os.LookupEnv(envName); ok {
		return SecretFromEnv(envName)
	}
	return Secret{}, nil
}

// validateSecret enforces non-empty and non-placeholder invariants on a raw
// credential without echoing the credential into returned errors.
//
// # Parameters
//
//   - raw: Trimmed credential string to validate.
//   - src: Human-readable source label (file path or "$ENV_VAR") for errors.
//
// # Returns
//
// A wrapped Secret or an error matching ErrSecretEmpty or ErrSecretPlaceholder.
//
// # Example
//
//	s, err := validateSecret("non-placeholder-credential", "$CONCERT_WEBHOOK_SECRET")
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :411 (direct call)
//   - :411 (function value)
//   - :448 (direct call)
//   - :448 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func validateSecret(raw, src string) (Secret, error) {
	if raw == "" {
		return Secret{}, fmt.Errorf("secret from %s: %w", src, ErrSecretEmpty)
	}
	if looksLikePlaceholder(raw) {
		return Secret{}, fmt.Errorf("secret from %s: %w", src, ErrSecretPlaceholder)
	}
	return Secret{v: raw}, nil
}

// looksLikePlaceholder reports whether s matches a known insecure placeholder
// token (case-insensitive).
//
// # Parameters
//
//   - s: Trimmed credential string to check.
//
// # Returns
//
// true if s matches a disallowed placeholder literal.
//
// # Example
//
//	if looksLikePlaceholder("changeme") {
//	    return ErrSecretPlaceholder
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :523 (direct call)
//   - :523 (function value)
//
// Scope: current module (internal/notify, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func looksLikePlaceholder(s string) bool {
	switch strings.ToLower(s) {
	case "changeme", "change-me", "replace-me", "your-api-key", "your_api_key",
		"your-password", "your_password", "password", "secret", "xxx", "todo",
		"tbd", "none", "null", "<redacted>", "[redacted]":
		return true
	}
	return false
}
