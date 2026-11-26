// Package telemetry implements pure-stdlib W3C Trace Context propagation and an
// asynchronous, bounded-buffer OTLP/HTTP JSON span exporter for Concert with
// zero external dependencies.
package telemetry

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
// logging path for a Secret value so telemetry credentials are never disclosed.
const RedactedPlaceholder = "[REDACTED]"

const maxSecretFileBytes = 64 << 10

// Sentinel errors returned by telemetry secret ingestion helpers. None of them
// contain or wrap credential material.
var (
	ErrSecretNotSet      = errors.New("secret not set")
	ErrSecretEmpty       = errors.New("secret is empty")
	ErrSecretPlaceholder = errors.New("secret looks like a placeholder")
	ErrSecretTooLarge    = errors.New("secret file exceeds 64 KiB limit")
	ErrSecretPermissions = errors.New("secret file permissions too open (require 0600 or stricter)")
	ErrSecretNotRegular  = errors.New("secret source is not a regular file")
)

// Secret holds a sensitive telemetry credential (such as an OTLP Authorization
// header value) so it cannot be printed, logged, or marshaled accidentally. The
// zero value is empty and reports IsZero() == true. Secret is an immutable value
// type safe for concurrent reads and copies.
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
//	auth := telemetry.NewSecret(os.Getenv("OTEL_EXPORTER_OTLP_AUTH"))
//	fmt.Println(auth) // [REDACTED]
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :95 (direct call)
//   - :425 (direct call)
//
// Scope: current module (internal/telemetry, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func NewSecret(raw string) Secret {
	return Secret{v: raw}
}

// Reveal returns the underlying raw credential value. Callers must invoke
// Reveal only at the single point of outbound HTTP header construction and must
// never pass the result to logs, errors, spans, or formatted output.
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
//	if !auth.IsZero() {
//	    req.Header.Set("Authorization", auth.Reveal())
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :190 (direct call)
//   - :342 (direct call)
//   - :342 (function value)
//   - :456 (direct call)
//   - :473 (direct call)
//   - :857 (direct call)
//   - :857 (function value)
//
// Scope: current module (internal/telemetry, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
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
//	var s telemetry.Secret
//	fmt.Println(s.IsZero()) // true
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :342 (direct call)
//   - :342 (function value)
//   - :855 (direct call)
//   - :855 (function value)
//
// Scope: current module (internal/telemetry, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (s Secret) IsZero() bool {
	return s.v == ""
}

// Equal reports whether candidate matches s using constant-time comparisons
// over both SHA-256 digests and the raw byte slices. Safe for concurrent use.
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
//	if !auth.Equal(presented) {
//	    return errors.New("unauthorized")
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: current module (internal/telemetry, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (s Secret) Equal(candidate string) bool {
	if s.v == "" || candidate == "" {
		return false
	}
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
//	fmt.Println(auth.String()) // [REDACTED]
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :430 (direct call)
//
// Scope: current module (internal/telemetry, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
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
//	fmt.Printf("%#v\n", auth) // telemetry.Secret{[REDACTED]}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :431 (direct call)
//
// Scope: current module (internal/telemetry, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (Secret) GoString() string { return "telemetry.Secret{" + RedactedPlaceholder + "}" }

// Format implements fmt.Formatter so every fmt verb prints RedactedPlaceholder.
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
// Scope: current module (internal/telemetry, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
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
//	b, err := auth.MarshalText()
//	_ = err
//	fmt.Println(string(b)) // [REDACTED]
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :446 (direct call)
//
// Scope: current module (internal/telemetry, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
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
//	b, err := json.Marshal(auth)
//	_ = err
//	fmt.Println(string(b)) // "[REDACTED]"
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: current module (internal/telemetry, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func (Secret) MarshalJSON() ([]byte, error) { return json.Marshal(RedactedPlaceholder) }

// LogValue implements slog.LogValuer so structured logs always record
// RedactedPlaceholder.
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
//	slog.Info("otlp configured", "auth", auth)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: current module (internal/telemetry, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
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
// read to 64 KiB, trimming whitespace, and rejecting empty or placeholder data.
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
//	auth, err := telemetry.SecretFromFile("/run/secrets/otlp_auth")
//	if err != nil {
//	    return err
//	}
//	_ = auth
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :455 (direct call)
//   - :467 (direct call)
//
// Scope: current module (internal/telemetry, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func SecretFromFile(path string) (Secret, error) {
	if path == "" {
		return Secret{}, ErrSecretNotSet
	}
	f, err := os.Open(path)
	if err != nil {
		return Secret{}, fmt.Errorf("open secret file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

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
//	auth, err := telemetry.SecretFromEnv("CONCERT_OTLP_AUTH")
//	if err != nil && !errors.Is(err, telemetry.ErrSecretNotSet) {
//	    return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :473 (direct call)
//
// Scope: current module (internal/telemetry, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func SecretFromEnv(name string) (Secret, error) {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return Secret{}, fmt.Errorf("environment variable %s: %w", name, ErrSecretNotSet)
	}
	return validateSecret(strings.TrimSpace(raw), "$"+name)
}

// validateSecret enforces non-empty and non-placeholder invariants on a raw
// credential without echoing the credential into returned errors.
//
// # Parameters
//
//   - raw: Trimmed credential string to validate.
//   - src: Human-readable source label for errors.
//
// # Returns
//
// A wrapped Secret or an error matching ErrSecretEmpty or ErrSecretPlaceholder.
//
// # Example
//
//	s, err := validateSecret("non-placeholder-token", "$CONCERT_OTLP_AUTH")
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - :384 (direct call)
//   - :384 (function value)
//   - :418 (direct call)
//   - :418 (function value)
//
// Scope: current module (internal/telemetry, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
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
//   - :451 (direct call)
//   - :451 (function value)
//
// Scope: current module (internal/telemetry, including tests); darwin/arm64, default tags. Interface/runtime/external uses are not exhaustive.
func looksLikePlaceholder(s string) bool {
	switch strings.ToLower(s) {
	case "changeme", "change-me", "replace-me", "your-api-key", "your_api_key",
		"your-password", "your_password", "password", "secret", "xxx", "todo",
		"tbd", "none", "null", "<redacted>", "[redacted]":
		return true
	}
	return false
}
