package guard

import (
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

// RedactedPlaceholder is printed by every formatting, logging, text, and JSON
// marshaling path for [Secret] values so credentials never leak into output (S6).
const RedactedPlaceholder = "[REDACTED]"

const maxSecretFileBytes = 64 << 10

// Sentinel errors returned by [SecretFromFile] and [SecretFromEnv]. None of
// these errors or their wrappers ever include raw secret content.
var (
	ErrSecretNotSet      = errors.New("guard: secret not set")
	ErrSecretEmpty       = errors.New("guard: secret is empty")
	ErrSecretPlaceholder = errors.New("guard: secret looks like a placeholder")
	ErrSecretTooLarge    = errors.New("guard: secret file too large")
	ErrSecretPermissions = errors.New("guard: secret file permissions too open (require 0600 or stricter)")
	ErrSecretNotRegular  = errors.New("guard: secret source is not a regular file")
)

// Secret holds a sensitive credential or signing key so it cannot be printed,
// logged, or marshaled by accident (S6).
//
// Secret is an immutable value type; copies share no mutable state. Every
// standard formatting, JSON, text, and slog path prints [RedactedPlaceholder].
// Call [Secret.Reveal] only at the single point of cryptographic or wire use.
type Secret struct {
	v string
}

// NewSecret wraps raw in a redacting [Secret]. Callers should load raw from a
// file, secret manager, or environment variable rather than source literals.
//
// # Parameters
//
//   - raw: Raw secret string; may be empty (IsZero will report true).
//
// # Returns
//
// A [Secret] wrapping raw.
//
// # Example
//
//	s := guard.NewSecret(os.Getenv("CONCERT_POW_KEY"))
//	fmt.Println(s) // [REDACTED]
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:62 (function value)
//   - internal/guard/fuzz_test.go:101 (direct call)
//   - internal/guard/guard_test.go:62 (direct call)
//   - internal/guard/guard_test.go:101 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func NewSecret(raw string) Secret {
	return Secret{v: raw}
}

// SecretFromFile reads a credential from path, checking the open handle to
// avoid stat/open races, requiring a regular file with 0600 or stricter
// permissions on Unix, bounding the read to 64 KiB, trimming surrounding
// whitespace, and rejecting empty or placeholder-looking values (S7).
//
// # Parameters
//
//   - path: Filesystem path to a secret file.
//
// # Returns
//
// A validated [Secret], or a secret-free error matching one of the
// ErrSecret* sentinels.
//
// # Example
//
//	sec, err := guard.SecretFromFile("/run/secrets/turnstile")
//	if err != nil {
//	    return err
//	}
//	_ = sec
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:691 (function value)
//   - internal/guard/fuzz_test.go:700 (function value)
//   - internal/guard/fuzz_test.go:708 (function value)
//   - internal/guard/guard_test.go:691 (direct call)
//   - internal/guard/guard_test.go:700 (direct call)
//   - internal/guard/guard_test.go:708 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func SecretFromFile(path string) (Secret, error) {
	if path == "" {
		return Secret{}, ErrSecretNotSet
	}
	f, err := os.Open(path)
	if err != nil {
		return Secret{}, fmt.Errorf("open secret file %q: %w", path, err)
	}
	defer f.Close()

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

	raw, err := io.ReadAll(io.LimitReader(f, maxSecretFileBytes+1))
	if err != nil {
		return Secret{}, fmt.Errorf("read secret file %q: %w", path, err)
	}
	if len(raw) > maxSecretFileBytes {
		return Secret{}, fmt.Errorf("secret file %q: %w", path, ErrSecretTooLarge)
	}
	return validateSecret(strings.TrimSpace(string(raw)), path)
}

// SecretFromEnv reads a credential from environment variable name, rejecting
// unset, empty, or placeholder-looking values (S7).
//
// # Parameters
//
//   - name: Environment variable name.
//
// # Returns
//
// A validated [Secret], or a secret-free error matching ErrSecret*.
//
// # Example
//
//	sec, err := guard.SecretFromEnv("TURNSTILE_SECRET")
//	if err != nil {
//	    return err
//	}
//	_ = sec
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:713 (function value)
//   - internal/guard/guard_test.go:713 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func SecretFromEnv(name string) (Secret, error) {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return Secret{}, fmt.Errorf("environment variable %s: %w", name, ErrSecretNotSet)
	}
	return validateSecret(strings.TrimSpace(raw), "$"+name)
}

// Reveal returns the raw credential value. Never pass the returned string to
// logs, error messages, fmt verbs, or metrics.
//
// # Parameters
//
// None.
//
// # Returns
//
// Underlying secret string.
//
// # Example
//
//	raw := sec.Reveal()
//	_ = raw
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:278 (direct call)
//   - internal/guard/challenge.go:281 (direct call)
//   - internal/guard/challenge.go:317 (direct call)
//   - internal/guard/challenge.go:1008 (direct call)
//   - internal/guard/challenge.go:1128 (direct call)
//   - internal/guard/challenge.go:1178 (direct call)
//   - internal/guard/fuzz_test.go:647 (function value)
//   - internal/guard/fuzz_test.go:692 (function value)
//   - internal/guard/fuzz_test.go:714 (function value)
//   - internal/guard/fuzz_test.go:854 (function value)
//   - internal/guard/geoasn.go:278 (function value)
//   - internal/guard/geoasn.go:281 (function value)
//   - internal/guard/geoasn.go:317 (function value)
//   - internal/guard/geoasn.go:1008 (function value)
//   - internal/guard/geoasn.go:1128 (function value)
//   - internal/guard/geoasn.go:1178 (function value)
//   - internal/guard/guard_test.go:647 (direct call)
//   - internal/guard/guard_test.go:692 (direct call)
//   - internal/guard/guard_test.go:714 (direct call)
//   - internal/guard/guard_test.go:854 (direct call)
//   - internal/guard/queue_quota.go:278 (function value)
//   - internal/guard/queue_quota.go:281 (function value)
//   - internal/guard/queue_quota.go:317 (function value)
//   - internal/guard/queue_quota.go:1008 (function value)
//   - internal/guard/queue_quota.go:1128 (function value)
//   - internal/guard/queue_quota.go:1178 (function value)
//   - internal/guard/ratelimit.go:278 (function value)
//   - internal/guard/ratelimit.go:281 (function value)
//   - internal/guard/ratelimit.go:317 (function value)
//   - internal/guard/ratelimit.go:1008 (function value)
//   - internal/guard/ratelimit.go:1128 (function value)
//   - internal/guard/ratelimit.go:1178 (function value)
//   - internal/guard/secret.go:278 (function value)
//   - internal/guard/secret.go:281 (function value)
//   - internal/guard/secret.go:317 (function value)
//   - internal/guard/secret.go:1008 (function value)
//   - internal/guard/secret.go:1128 (function value)
//   - internal/guard/secret.go:1178 (function value)
//   - internal/guard/shedder.go:278 (function value)
//   - internal/guard/shedder.go:281 (function value)
//   - internal/guard/shedder.go:317 (function value)
//   - internal/guard/shedder.go:1008 (function value)
//   - internal/guard/shedder.go:1128 (function value)
//   - internal/guard/shedder.go:1178 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (s Secret) Reveal() string {
	return s.v
}

// IsZero reports whether the secret holds no value.
//
// # Parameters
//
// None.
//
// # Returns
//
// true when the underlying string is empty.
//
// # Example
//
//	empty := guard.Secret{}.IsZero() // true
//	_ = empty
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:278 (direct call)
//   - internal/guard/challenge.go:317 (direct call)
//   - internal/guard/geoasn.go:278 (function value)
//   - internal/guard/geoasn.go:317 (function value)
//   - internal/guard/queue_quota.go:278 (function value)
//   - internal/guard/queue_quota.go:317 (function value)
//   - internal/guard/ratelimit.go:278 (function value)
//   - internal/guard/ratelimit.go:317 (function value)
//   - internal/guard/secret.go:278 (function value)
//   - internal/guard/secret.go:317 (function value)
//   - internal/guard/shedder.go:278 (function value)
//   - internal/guard/shedder.go:317 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (s Secret) IsZero() bool {
	return s.v == ""
}

// String implements [fmt.Stringer], always returning [RedactedPlaceholder].
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
//	_ = fmt.Sprint(sec) // "[REDACTED]"
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:650 (function value)
//   - internal/guard/guard_test.go:650 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (Secret) String() string {
	return RedactedPlaceholder
}

// GoString implements [fmt.GoStringer], always returning a redacted representation.
//
// # Parameters
//
// None.
//
// # Returns
//
// "guard.Secret{[REDACTED]}".
//
// # Example
//
//	_ = fmt.Sprintf("%#v", sec) // "[REDACTED]" via Format
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:651 (function value)
//   - internal/guard/guard_test.go:651 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (Secret) GoString() string {
	return "guard.Secret{" + RedactedPlaceholder + "}"
}

// Format implements [fmt.Formatter] so every fmt verb (%v, %+v, %#v, %s, %q,
// %x) emits [RedactedPlaceholder] rather than reflecting on the unexported field.
//
// # Parameters
//
//   - f: fmt output state.
//   - _: Ignored format verb.
//
// # Example
//
//	_ = fmt.Sprintf("%+v", sec) // "[REDACTED]"
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (Secret) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, RedactedPlaceholder)
}

// MarshalText implements [encoding.TextMarshaler], always returning
// [RedactedPlaceholder].
//
// # Parameters
//
// None.
//
// # Returns
//
// Redacted bytes and nil error.
//
// # Example
//
//	b, err := sec.MarshalText()
//	_, _ = b, err
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:665 (function value)
//   - internal/guard/guard_test.go:665 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (Secret) MarshalText() ([]byte, error) {
	return []byte(RedactedPlaceholder), nil
}

// MarshalJSON implements [json.Marshaler], always marshaling [RedactedPlaceholder].
//
// # Parameters
//
// None.
//
// # Returns
//
// JSON string `"[REDACTED]"` and nil error.
//
// # Example
//
//	b, err := json.Marshal(sec)
//	_, _ = b, err
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(RedactedPlaceholder)
}

// LogValue implements [slog.LogValuer], ensuring structured logs emit
// [RedactedPlaceholder] even under slog.Any or slog.Group.
//
// # Parameters
//
// None.
//
// # Returns
//
// A redacted slog.Value.
//
// # Example
//
//	slog.Info("configured", "secret", sec)
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
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

// validateSecret checks that raw is non-empty and not an obvious placeholder
// string, naming only src (never raw) in errors.
//
// # Parameters
//
//   - raw: Trimmed candidate secret value.
//   - src: Non-sensitive source label (file path or env var name).
//
// # Returns
//
// A [Secret] wrapping raw, or an error matching ErrSecretEmpty / ErrSecretPlaceholder.
//
// # Example
//
//	sec, err := validateSecret(trimmed, "$TURNSTILE_SECRET")
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:136 (function value)
//   - internal/guard/challenge.go:172 (function value)
//   - internal/guard/geoasn.go:136 (function value)
//   - internal/guard/geoasn.go:172 (function value)
//   - internal/guard/queue_quota.go:136 (function value)
//   - internal/guard/queue_quota.go:172 (function value)
//   - internal/guard/ratelimit.go:136 (function value)
//   - internal/guard/ratelimit.go:172 (function value)
//   - internal/guard/secret.go:136 (direct call)
//   - internal/guard/secret.go:172 (direct call)
//   - internal/guard/shedder.go:136 (function value)
//   - internal/guard/shedder.go:172 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func validateSecret(raw, src string) (Secret, error) {
	if raw == "" {
		return Secret{}, fmt.Errorf("secret from %s: %w", src, ErrSecretEmpty)
	}
	if looksLikePlaceholder(raw) {
		return Secret{}, fmt.Errorf("secret from %s: %w", src, ErrSecretPlaceholder)
	}
	return Secret{v: raw}, nil
}

// looksLikePlaceholder detects common non-production placeholder strings so
// misconfigured deployments fail closed at startup (S7).
//
// # Parameters
//
//   - s: Trimmed candidate secret string.
//
// # Returns
//
// true if s matches a known placeholder token.
//
// # Example
//
//	bad := looksLikePlaceholder("changeme") // true
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:281 (direct call)
//   - internal/guard/challenge.go:317 (direct call)
//   - internal/guard/challenge.go:493 (function value)
//   - internal/guard/geoasn.go:281 (function value)
//   - internal/guard/geoasn.go:317 (function value)
//   - internal/guard/geoasn.go:493 (function value)
//   - internal/guard/queue_quota.go:281 (function value)
//   - internal/guard/queue_quota.go:317 (function value)
//   - internal/guard/queue_quota.go:493 (function value)
//   - internal/guard/ratelimit.go:281 (function value)
//   - internal/guard/ratelimit.go:317 (function value)
//   - internal/guard/ratelimit.go:493 (function value)
//   - internal/guard/secret.go:281 (function value)
//   - internal/guard/secret.go:317 (function value)
//   - internal/guard/secret.go:493 (direct call)
//   - internal/guard/shedder.go:281 (function value)
//   - internal/guard/shedder.go:317 (function value)
//   - internal/guard/shedder.go:493 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func looksLikePlaceholder(s string) bool {
	switch strings.ToLower(s) {
	case "changeme", "change-me", "replace-me", "your-api-key", "your_api_key",
		"xxx", "todo", "tbd", "none", "null", "<redacted>", "[redacted]":
		return true
	}
	return false
}
