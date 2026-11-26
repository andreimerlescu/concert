// Package cache implements a pure-stdlib sharded page-cache store, binary wire
// protocol, authenticated TCP/TLS/mTLS/Unix daemon server, and fail-open pooled
// client for Concert.
package cache

import (
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

// SecretPlaceholder is the fixed redaction string emitted by every formatting,
// serialization, and structured logging path on Secret.
const SecretPlaceholder = "[REDACTED]"

const maxSecretFileBytes = 64 << 10

// Sentinel errors returned when loading or validating a Secret. None of these
// errors or their wrapped messages ever contain secret material.
var (
	ErrSecretNotSet      = errors.New("cache secret not set")
	ErrSecretEmpty       = errors.New("cache secret is empty")
	ErrSecretPlaceholder = errors.New("cache secret looks like a placeholder")
	ErrSecretTooLarge    = errors.New("cache secret source exceeds maximum size")
	ErrSecretPermissions = errors.New("cache secret file permissions too open (require 0600 or stricter)")
	ErrSecretNotRegular  = errors.New("cache secret source is not a regular file")
)

// Secret holds a shared authentication credential and redacts itself across
// fmt, JSON, text, and slog paths. Its zero value is empty and reports IsZero.
// Secret is an immutable value type safe for concurrent read access.
type Secret struct {
	v string
}

// NewSecret wraps raw in a redacting Secret value. Callers should obtain raw
// from SecretFromFile, SecretFromEnv, or ResolveSecret rather than hardcoding
// literals.
//
// # Parameters
//
//   - raw: Raw credential bytes represented as a string. Empty values produce
//     a zero Secret where IsZero reports true.
//
// # Returns
//
// A Secret wrapping raw whose formatting and marshaling methods emit
// SecretPlaceholder.
//
// # Example
//
//	s := cache.NewSecret(os.Getenv("CONCERT_CACHE_SECRET"))
//	fmt.Println(s.String()) // [REDACTED]
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main_test.go:96 (function value)
//   - internal/cache/cache_test.go:43 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func NewSecret(raw string) Secret {
	return Secret{v: raw}
}

// Reveal returns the underlying raw credential string. Call Reveal only at the
// single boundary where the credential is compared or written to the wire;
// never pass its result to logs, errors, or formatting verbs.
//
// # Parameters
//
// None. Receiver s is a value; zero value returns "".
//
// # Returns
//
// The raw credential string.
//
// # Example
//
//	token := secret.Reveal()
//	_ = token
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:905 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
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
// true if s is empty; false otherwise.
//
// # Example
//
//	var s cache.Secret
//	fmt.Println(s.IsZero()) // true
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:70 (function value)
//   - internal/cache/client.go:165 (function value)
//   - internal/cache/server.go:134 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s Secret) IsZero() bool {
	return s.v == ""
}

// Equal compares candidate against s in constant time using
// subtle.ConstantTimeCompare. An empty Secret never matches any candidate.
//
// # Parameters
//
//   - candidate: Untrusted credential bytes supplied by a peer.
//
// # Returns
//
// true when s is non-empty and candidate equals s byte-for-byte; false
// otherwise.
//
// # Example
//
//	ok := expected.Equal(presented)
//	_ = ok
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:73 (function value)
//   - internal/cache/cache_test.go:76 (function value)
//   - internal/cache/cache_test.go:79 (function value)
//   - internal/cache/cache_test.go:133 (function value)
//   - internal/cache/cache_test.go:175 (function value)
//   - internal/cache/server.go:756 (function value)
//   - internal/cache/server.go:824 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (s Secret) Equal(candidate []byte) bool {
	if s.v == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(s.v), candidate) == 1
}

// String implements fmt.Stringer and always returns SecretPlaceholder.
//
// # Parameters
//
// None.
//
// # Returns
//
// SecretPlaceholder.
//
// # Example
//
//	fmt.Println(s.String()) // [REDACTED]
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:99 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (Secret) String() string {
	return SecretPlaceholder
}

// GoString implements fmt.GoStringer and always returns a redacted type
// representation.
//
// # Parameters
//
// None.
//
// # Returns
//
// A redacted Go syntax string containing SecretPlaceholder.
//
// # Example
//
//	fmt.Printf("%#v\n", s) // cache.Secret{[REDACTED]}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:100 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (Secret) GoString() string {
	return "cache.Secret{" + SecretPlaceholder + "}"
}

// Format implements fmt.Formatter so every formatting verb (%v, %+v, %#v, %s,
// %q, %x) writes SecretPlaceholder instead of reflecting on the raw field.
//
// # Parameters
//
//   - f: Target fmt.State writer provided by fmt.
//   - verb: Formatting verb rune (ignored).
//
// # Returns
//
// None.
//
// # Example
//
//	fmt.Printf("%+v\n", s) // [REDACTED]
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
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
// SecretPlaceholder as bytes and a nil error.
//
// # Example
//
//	b, err := s.MarshalText()
//	_, _ = b, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:93 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (Secret) MarshalText() ([]byte, error) {
	return []byte(SecretPlaceholder), nil
}

// MarshalJSON implements json.Marshaler and always emits a JSON string
// containing SecretPlaceholder.
//
// # Parameters
//
// None.
//
// # Returns
//
// JSON-encoded SecretPlaceholder and a nil error.
//
// # Example
//
//	b, err := json.Marshal(s)
//	_, _ = b, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(SecretPlaceholder)
}

// LogValue implements slog.LogValuer so structured log records always emit
// SecretPlaceholder.
//
// # Parameters
//
// None.
//
// # Returns
//
// A string slog.Value containing SecretPlaceholder.
//
// # Example
//
//	slog.Info("configured", "secret", s)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
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

// SecretFromFile reads a credential from path. It opens the file first and
// stats the open file descriptor to avoid stat/open races, verifies it is a
// regular file with mode 0600 or stricter on Unix systems, reads at most
// 64 KiB, trims surrounding whitespace, and rejects empty or placeholder values.
//
// # Parameters
//
//   - path: Filesystem path to the secret file. Empty path returns ErrSecretNotSet.
//
// # Returns
//
// The validated Secret, or a zero Secret and an error wrapping one of the
// ErrSecret* sentinels or an OS error. Errors never contain file contents.
//
// # Example
//
//	s, err := cache.SecretFromFile("/run/secrets/concert_cache_secret")
//	if err != nil {
//	    return err
//	}
//	_ = s
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:129 (function value)
//   - internal/cache/cache_test.go:142 (function value)
//   - internal/cache/cache_test.go:147 (function value)
//   - internal/cache/cache_test.go:155 (function value)
//   - internal/cache/cache_test.go:163 (function value)
//   - internal/cache/secret.go:501 (function value)
//   - internal/cache/secret.go:504 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func SecretFromFile(path string) (Secret, error) {
	if strings.TrimSpace(path) == "" {
		return Secret{}, ErrSecretNotSet
	}
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
	// Reject group/other permission bits on POSIX systems so credentials
	// cannot be read by unrelated local accounts.
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return Secret{}, fmt.Errorf("secret file %q has mode %04o: %w", path, fi.Mode().Perm(), ErrSecretPermissions)
	}

	raw, err := io.ReadAll(io.LimitReader(f, maxSecretFileBytes+1))
	if err != nil {
		return Secret{}, fmt.Errorf("read secret file %q: %w", path, err)
	}
	if len(raw) > maxSecretFileBytes {
		return Secret{}, fmt.Errorf("secret file %q: %w", path, ErrSecretTooLarge)
	}
	return validateSecret(strings.TrimSpace(string(raw)), path)
}

// SecretFromEnv reads and validates a credential from environment variable
// name. It fails closed when the variable is unset, empty, or placeholder-like.
//
// # Parameters
//
//   - name: Environment variable name (for example "CONCERT_CACHE_SECRET").
//
// # Returns
//
// The validated Secret, or a zero Secret and an error wrapping ErrSecretNotSet,
// ErrSecretEmpty, or ErrSecretPlaceholder.
//
// # Example
//
//	s, err := cache.SecretFromEnv("CONCERT_CACHE_SECRET")
//	if err != nil {
//	    return err
//	}
//	_ = s
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/secret.go:507 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func SecretFromEnv(name string) (Secret, error) {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return Secret{}, fmt.Errorf("environment variable %s: %w", name, ErrSecretNotSet)
	}
	if len(raw) > maxSecretFileBytes {
		return Secret{}, fmt.Errorf("environment variable %s: %w", name, ErrSecretTooLarge)
	}
	return validateSecret(strings.TrimSpace(raw), "$"+name)
}

// ResolveSecret resolves a credential using fail-closed precedence:
// 1) explicit filePath when non-empty,
// 2) file path stored in <envName>_FILE when non-empty,
// 3) raw value stored in <envName> when set.
// There is intentionally no default value or fallback literal.
//
// # Parameters
//
//   - filePath: Optional path to a 0600 secret file.
//   - envName: Base environment variable name (for example "CONCERT_CACHE_SECRET").
//
// # Returns
//
// The validated Secret, or a zero Secret and an error naming only the consulted
// sources (never secret content).
//
// # Example
//
//	s, err := cache.ResolveSecret("", "CONCERT_CACHE_SECRET")
//	if err != nil {
//	    return err
//	}
//	_ = s
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - cmd/concert-cache/main.go:173 (function value)
//   - internal/cache/cache_test.go:169 (function value)
//   - internal/cache/cache_test.go:174 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func ResolveSecret(filePath, envName string) (Secret, error) {
	if strings.TrimSpace(filePath) != "" {
		return SecretFromFile(filePath)
	}
	if p := strings.TrimSpace(os.Getenv(envName + "_FILE")); p != "" {
		return SecretFromFile(p)
	}
	if _, ok := os.LookupEnv(envName); ok {
		return SecretFromEnv(envName)
	}
	return Secret{}, fmt.Errorf("no cache secret supplied: set %s_FILE or %s: %w", envName, envName, ErrSecretNotSet)
}

// validateSecret checks that raw is non-empty and does not match common
// placeholder strings, returning errors that reference only src.
//
// # Parameters
//
//   - raw: Trimmed candidate credential string.
//   - src: Non-sensitive label describing where raw came from.
//
// # Returns
//
// A validated Secret or an error wrapping ErrSecretEmpty or ErrSecretPlaceholder.
//
// # Example
//
//	s, err := validateSecret(trimmed, "$CONCERT_CACHE_SECRET")
//	_, _ = s, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/secret.go:421 (function value)
//   - internal/cache/secret.go:461 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func validateSecret(raw, src string) (Secret, error) {
	if raw == "" {
		return Secret{}, fmt.Errorf("secret from %s: %w", src, ErrSecretEmpty)
	}
	if looksLikePlaceholder(raw) {
		return Secret{}, fmt.Errorf("secret from %s: %w", src, ErrSecretPlaceholder)
	}
	return Secret{v: raw}, nil
}

// looksLikePlaceholder reports whether s matches an obvious placeholder token
// that must never be accepted as a live shared secret.
//
// # Parameters
//
//   - s: Trimmed candidate credential string.
//
// # Returns
//
// true if s matches a known placeholder string (case-insensitive).
//
// # Example
//
//	bad := looksLikePlaceholder("changeme") // true
//	_ = bad
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/secret.go:543 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func looksLikePlaceholder(s string) bool {
	switch strings.ToLower(s) {
	case "changeme", "change-me", "replace-me", "secret", "password",
		"your-secret", "your_secret", "xxx", "todo", "tbd", "none", "null",
		"<redacted>", "[redacted]":
		return true
	}
	return false
}
