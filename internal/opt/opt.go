// Package opt provides a zero-dependency, pure-stdlib generic optional value
// type analogous to Rust's Option<T>.
//
// Option[T] replaces pointer-based optional struct fields (such as *bool,
// *int, *int64, *uint16, *uint32, *float64, *string, and *time.Time) with
// inline value semantics: zero heap allocations for the wrapper, no
// shallow-copy aliasing when copying structs by value, and no nil-pointer
// dereferences.
//
// # JSON Compatibility
//
// Option[T] implements [encoding/json.Marshaler], [encoding/json.Unmarshaler],
// and the Go 1.24+ IsZero() bool hook recognized by the `omitzero` struct tag
// option:
//
//   - On a struct field tagged `json:"name,omitzero"`, None[T]() is omitted
//     from marshaled JSON, while Some(0), Some(false), Some(""), and
//     Some(time.Time{}) are always emitted.
//   - On a struct field without `,omitzero` (for example `json:"name"`),
//     None[T]() marshals as JSON null.
//   - Avoid relying on `,omitempty` alone for Option[T] fields; encoding/json
//     does not omit struct types under `omitempty`.
//
// # Concurrency and Aliasing
//
// An Option[T] holds its value inline and performs no internal
// synchronization. Copying an Option[T] copies T by value; concurrent reads of
// an Option[T] value are safe as long as T itself is not mutated concurrently
// (including through interior pointers, slices, or maps held by T). Mutating an
// Option[T] (via assignment or [Option.UnmarshalJSON]) requires exclusive
// ownership or external synchronization.
package opt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Compile-time interface checks ensuring Option[T] satisfies standard JSON and
// formatting contracts with value-receiver MarshalJSON/String and
// pointer-receiver UnmarshalJSON.
var (
	_ json.Marshaler   = Option[int]{}
	_ json.Unmarshaler = (*Option[int])(nil)
	_ fmt.Stringer     = Option[int]{}
)

var errNilOption = errors.New("opt: UnmarshalJSON on nil Option")

// Option represents an optional value of type T.
//
// The zero value of Option[T] is None (absent), so uninitialized Option[T]
// fields behave identically to [None]. An Option[T] created with [Some] always
// distinguishes an explicitly present zero value of T (such as 0, false, "",
// or time.Time{}) from absence.
type Option[T any] struct {
	val T
	set bool
}

// Some constructs a present [Option] holding v, including when v is the zero
// value of T.
//
// # Parameters
//
//   - v: Value to wrap. If T contains reference types (slices, maps, or
//     pointers), Option retains them without cloning.
//
// # Returns
//
// An Option[T] whose [Option.IsSome] returns true and [Option.IsZero] returns
// false.
//
// # Example
//
//	port := opt.Some(0)
//	v, ok := port.Get()
//	fmt.Println(v, ok) // 0 true
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/opt/opt_test.go:100 (direct call)
//   - internal/opt/opt_test.go:111 (direct call)
//   - internal/opt/opt_test.go:122 (direct call)
//   - internal/opt/opt_test.go:133 (direct call)
//   - internal/opt/opt_test.go:217 (direct call)
//   - internal/opt/opt_test.go:218 (direct call)
//   - internal/opt/opt_test.go:219 (direct call)
//   - internal/opt/opt_test.go:220 (direct call)
//   - internal/opt/opt_test.go:221 (direct call)
//   - internal/opt/opt_test.go:222 (direct call)
//   - internal/opt/opt_test.go:223 (direct call)
//   - internal/opt/opt_test.go:224 (direct call)
//   - internal/opt/opt_test.go:265 (direct call)
//   - internal/opt/opt_test.go:266 (direct call)
//   - internal/opt/opt_test.go:267 (direct call)
//   - internal/opt/opt_test.go:268 (direct call)
//   - internal/opt/opt_test.go:269 (direct call)
//   - internal/opt/opt_test.go:270 (direct call)
//   - internal/opt/opt_test.go:271 (direct call)
//   - internal/opt/opt_test.go:272 (direct call)
//   - internal/opt/opt_test.go:298 (direct call)
//   - internal/opt/opt_test.go:299 (direct call)
//   - internal/opt/opt_test.go:335 (direct call)
//   - internal/opt/opt_test.go:336 (direct call)
//   - internal/opt/opt_test.go:391 (direct call)
//   - internal/opt/opt_test.go:392 (direct call)
//   - internal/opt/opt_test.go:393 (direct call)
//   - internal/opt/opt_test.go:394 (direct call)
//   - internal/opt/opt_test.go:395 (direct call)
//   - internal/opt/opt_test.go:396 (direct call)
//   - internal/opt/opt_test.go:397 (direct call)
//   - internal/opt/opt_test.go:398 (direct call)
//   - internal/opt/opt_test.go:419 (direct call)
//   - internal/opt/opt_test.go:488 (direct call)
//   - internal/opt/opt_test.go:501 (direct call)
//   - internal/opt/opt_test.go:504 (direct call)
//   - internal/opt/opt_test.go:536 (direct call)
//   - internal/opt/opt_test.go:537 (direct call)
//   - internal/opt/opt_test.go:538 (direct call)
//   - internal/opt/opt_test.go:539 (direct call)
//   - internal/opt/opt_test.go:540 (direct call)
//   - internal/opt/opt_test.go:541 (direct call)
//   - internal/opt/opt_test.go:542 (direct call)
//   - internal/opt/opt_test.go:543 (direct call)
//   - internal/opt/opt_test.go:547 (direct call)
//   - internal/opt/opt_test.go:548 (direct call)
//   - internal/opt/opt_test.go:550 (direct call)
//   - internal/opt/opt_test.go:552 (direct call)
//   - internal/opt/opt_test.go:553 (direct call)
//   - internal/opt/opt_test.go:554 (direct call)
//   - internal/opt/opt_test.go:688 (direct call)
//   - internal/opt/opt_test.go:691 (direct call)
//   - internal/opt/opt_test.go:694 (direct call)
//   - internal/opt/opt_test.go:697 (direct call)
//   - internal/opt/opt_test.go:700 (direct call)
//   - internal/opt/opt_test.go:713 (direct call)
//   - internal/opt/opt_test.go:716 (direct call)
//   - internal/opt/opt_test.go:724 (direct call)
//   - internal/opt/opt_test.go:731 (direct call)
//   - internal/opt/opt_test.go:736 (direct call)
//   - internal/opt/opt_test.go:737 (direct call)
//   - internal/opt/opt_test.go:738 (direct call)
//   - internal/opt/opt_test.go:770 (direct call)
//   - internal/opt/opt_test.go:773 (direct call)
//   - internal/opt/opt_test.go:776 (direct call)
//   - internal/opt/opt_test.go:779 (direct call)
//   - internal/opt/opt_test.go:807 (direct call)
//   - internal/opt/opt_test.go:808 (direct call)
//   - internal/opt/opt_test.go:809 (direct call)
//   - internal/opt/opt_test.go:820 (direct call)
//   - internal/opt/opt_test.go:874 (direct call)
//   - internal/opt/opt_test.go:919 (direct call)
//   - internal/opt/opt_test.go:954 (direct call)
//   - internal/opt/opt_test.go:955 (direct call)
//
// Scope: current module (github.com/andreimerlescu/concert), including tests;
// build configuration: darwin/arm64, default tags.
// Interface, reflection, callback, and external callers are not exhaustive.
func Some[T any](v T) Option[T] {
	return Option[T]{val: v, set: true}
}

// None constructs an absent [Option] of type T, identical to the zero value
// Option[T]{}.
//
// # Parameters
//
// None.
//
// # Returns
//
// An Option[T] whose [Option.IsNone] and [Option.IsZero] both return true.
//
// # Example
//
//	limit := opt.None[int]()
//	fmt.Println(limit.IsNone()) // true
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/opt/opt_test.go:147 (direct call)
//   - internal/opt/opt_test.go:300 (direct call)
//   - internal/opt/opt_test.go:357 (direct call)
//   - internal/opt/opt_test.go:549 (direct call)
//   - internal/opt/opt_test.go:551 (direct call)
//   - internal/opt/opt_test.go:685 (direct call)
//   - internal/opt/opt_test.go:688 (direct call)
//   - internal/opt/opt_test.go:691 (direct call)
//   - internal/opt/opt_test.go:710 (direct call)
//   - internal/opt/opt_test.go:713 (direct call)
//   - internal/opt/opt_test.go:716 (direct call)
//   - internal/opt/opt_test.go:767 (direct call)
//   - internal/opt/opt_test.go:920 (direct call)
//   - internal/opt/opt_test.go:991 (direct call)
//   - internal/opt/opt_test.go:992 (direct call)
//
// Scope: current module (github.com/andreimerlescu/concert), including tests;
// build configuration: darwin/arm64, default tags.
// Interface, reflection, callback, and external callers are not exhaustive.
func None[T any]() Option[T] {
	return Option[T]{}
}

// IsSome reports whether o holds a present value.
//
// # Parameters
//
// None. Operates on the value receiver o without mutating it.
//
// # Returns
//
// true when o was constructed with [Some] or successfully unmarshaled from a
// non-null JSON value; false when o is absent (zero value or [None]).
//
// # Example
//
//	enabled := opt.Some(false)
//	fmt.Println(enabled.IsSome()) // true
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/opt/opt_test.go:102 (direct call)
//   - internal/opt/opt_test.go:113 (direct call)
//   - internal/opt/opt_test.go:124 (direct call)
//   - internal/opt/opt_test.go:135 (direct call)
//   - internal/opt/opt_test.go:149 (direct call)
//   - internal/opt/opt_test.go:160 (direct call)
//   - internal/opt/opt_test.go:921 (direct call)
//   - internal/opt/opt_test.go:961 (direct call)
//
// Scope: current module (github.com/andreimerlescu/concert), including tests;
// build configuration: darwin/arm64, default tags.
// Interface, reflection, callback, and external callers are not exhaustive.
func (o Option[T]) IsSome() bool {
	return o.set
}

// IsNone reports whether o is absent.
//
// # Parameters
//
// None. Operates on the value receiver o without mutating it.
//
// # Returns
//
// true when o holds no value; false when a value is present.
//
// # Example
//
//	var label opt.Option[string]
//	fmt.Println(label.IsNone()) // true
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/opt/opt_test.go:102 (direct call)
//   - internal/opt/opt_test.go:113 (direct call)
//   - internal/opt/opt_test.go:124 (direct call)
//   - internal/opt/opt_test.go:135 (direct call)
//   - internal/opt/opt_test.go:149 (direct call)
//   - internal/opt/opt_test.go:160 (direct call)
//   - internal/opt/opt_test.go:406 (direct call)
//   - internal/opt/opt_test.go:407 (direct call)
//   - internal/opt/opt_test.go:408 (direct call)
//   - internal/opt/opt_test.go:423 (direct call)
//   - internal/opt/opt_test.go:424 (direct call)
//   - internal/opt/opt_test.go:629 (direct call)
//   - internal/opt/opt_test.go:921 (direct call)
//   - internal/opt/opt_test.go:998 (direct call)
//
// Scope: current module (github.com/andreimerlescu/concert), including tests;
// build configuration: darwin/arm64, default tags.
// Interface, reflection, callback, and external callers are not exhaustive.
func (o Option[T]) IsNone() bool {
	return !o.set
}

// IsZero reports whether o is absent so Go 1.24+ [encoding/json] omits None
// fields tagged with `omitzero` while always encoding present zero values such
// as Some(0), Some(false), Some(""), and Some(time.Time{}).
//
// # Parameters
//
// None. Operates on the value receiver o without mutating it.
//
// # Returns
//
// true if and only if o is absent (!o.IsSome()). Present values return false
// even when the wrapped value equals the zero value of T.
//
// # Example
//
//	fmt.Println(opt.None[int]().IsZero()) // true
//	fmt.Println(opt.Some(0).IsZero())     // false
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/opt/opt_test.go:102 (direct call)
//   - internal/opt/opt_test.go:113 (direct call)
//   - internal/opt/opt_test.go:124 (direct call)
//   - internal/opt/opt_test.go:135 (direct call)
//   - internal/opt/opt_test.go:149 (direct call)
//   - internal/opt/opt_test.go:160 (direct call)
//   - internal/opt/opt_test.go:423 (direct call)
//   - internal/opt/opt_test.go:424 (direct call)
//   - internal/opt/opt_test.go:921 (direct call)
//   - internal/opt/opt_test.go:961 (direct call)
//
// Scope: current module (github.com/andreimerlescu/concert), including tests;
// build configuration: darwin/arm64, default tags.
// Also invoked dynamically via encoding/json or fmt interface dispatch;
// static call sites are not an exhaustive runtime call graph.
func (o Option[T]) IsZero() bool {
	return !o.set
}

// Get returns the wrapped value and a boolean reporting whether a value is
// present.
//
// # Parameters
//
// None. Operates on the value receiver o without mutating it.
//
// # Returns
//
// (val, true) when o is present, or (zero, false) when o is absent, where zero
// is the zero value of T. If T holds slices, maps, or pointers, the returned
// value shares those underlying references with o.
//
// # Example
//
//	if v, ok := opt.Some(42).Get(); ok {
//		fmt.Println(v) // 42
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/opt/opt_test.go:101 (direct call)
//   - internal/opt/opt_test.go:112 (direct call)
//   - internal/opt/opt_test.go:123 (direct call)
//   - internal/opt/opt_test.go:134 (direct call)
//   - internal/opt/opt_test.go:148 (direct call)
//   - internal/opt/opt_test.go:159 (direct call)
//   - internal/opt/opt_test.go:411 (direct call)
//   - internal/opt/opt_test.go:414 (direct call)
//   - internal/opt/opt_test.go:432 (direct call)
//   - internal/opt/opt_test.go:493 (direct call)
//   - internal/opt/opt_test.go:556 (direct call)
//   - internal/opt/opt_test.go:559 (direct call)
//   - internal/opt/opt_test.go:562 (direct call)
//   - internal/opt/opt_test.go:565 (direct call)
//   - internal/opt/opt_test.go:568 (direct call)
//   - internal/opt/opt_test.go:571 (direct call)
//   - internal/opt/opt_test.go:574 (direct call)
//   - internal/opt/opt_test.go:577 (direct call)
//   - internal/opt/opt_test.go:623 (direct call)
//   - internal/opt/opt_test.go:626 (direct call)
//   - internal/opt/opt_test.go:632 (direct call)
//   - internal/opt/opt_test.go:635 (direct call)
//   - internal/opt/opt_test.go:638 (direct call)
//   - internal/opt/opt_test.go:641 (direct call)
//   - internal/opt/opt_test.go:645 (direct call)
//   - internal/opt/opt_test.go:821 (direct call)
//   - internal/opt/opt_test.go:878 (direct call)
//   - internal/opt/opt_test.go:922 (direct call)
//
// Scope: current module (github.com/andreimerlescu/concert), including tests;
// build configuration: darwin/arm64, default tags.
// Interface, reflection, callback, and external callers are not exhaustive.
func (o Option[T]) Get() (T, bool) {
	if !o.set {
		var zero T
		return zero, false
	}
	return o.val, true
}

// UnwrapOr returns the wrapped value when present, or fallback when o is
// absent.
//
// # Parameters
//
//   - fallback: Value returned unchanged when o is absent. Evaluated eagerly
//     at the call site before UnwrapOr is entered.
//
// # Returns
//
// The wrapped value if o is present, otherwise fallback.
//
// # Example
//
//	timeout := opt.None[int]().UnwrapOr(30)
//	fmt.Println(timeout) // 30
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/opt/opt_test.go:106 (direct call)
//   - internal/opt/opt_test.go:117 (direct call)
//   - internal/opt/opt_test.go:128 (direct call)
//   - internal/opt/opt_test.go:140 (direct call)
//   - internal/opt/opt_test.go:153 (direct call)
//   - internal/opt/opt_test.go:164 (direct call)
//   - internal/opt/opt_test.go:923 (direct call)
//   - internal/opt/opt_test.go:998 (direct call)
//
// Scope: current module (github.com/andreimerlescu/concert), including tests;
// build configuration: darwin/arm64, default tags.
// Interface, reflection, callback, and external callers are not exhaustive.
func (o Option[T]) UnwrapOr(fallback T) T {
	if !o.set {
		return fallback
	}
	return o.val
}

// Equal reports whether o and other are both absent, or both present with
// wrapped values considered equal by eq.
//
// # Parameters
//
//   - other: Second Option[T] to compare against receiver o.
//   - eq: Comparison function invoked synchronously at most once, only when
//     both o and other are present. Must be non-nil whenever both options are
//     present; it is never called if either option is absent.
//
// # Returns
//
// true if both options are absent or both are present and eq(oVal, otherVal)
// returns true; false otherwise.
//
// # Example
//
//	a := opt.Some(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
//	b := opt.Some(time.Date(2026, 1, 1, 0, 0, 0, 0, time.FixedZone("UTC+0", 0)))
//	fmt.Println(a.Equal(b, time.Time.Equal)) // true
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/opt/opt_test.go:256 (direct call)
//   - internal/opt/opt_test.go:290 (direct call)
//   - internal/opt/opt_test.go:710 (direct call)
//   - internal/opt/opt_test.go:713 (direct call)
//   - internal/opt/opt_test.go:716 (direct call)
//   - internal/opt/opt_test.go:724 (direct call)
//   - internal/opt/opt_test.go:731 (direct call)
//   - internal/opt/opt_test.go:739 (direct call)
//   - internal/opt/opt_test.go:742 (direct call)
//
// Scope: current module (github.com/andreimerlescu/concert), including tests;
// build configuration: darwin/arm64, default tags.
// Interface, reflection, callback, and external callers are not exhaustive.
func (o Option[T]) Equal(other Option[T], eq func(a, b T) bool) bool {
	if !o.set && !other.set {
		return true
	}
	if o.set != other.set {
		return false
	}
	return eq(o.val, other.val)
}

// Equal reports whether a and b are both absent, or both present with equal
// wrapped values using Go's == operator.
//
// For types where == is not the desired domain equivalence (such as
// [time.Time] instant comparison across locations, or NaN-sensitive floats),
// use [Option.Equal] with a custom comparator instead.
//
// # Parameters
//
//   - a: First Option[T] to compare.
//   - b: Second Option[T] to compare.
//
// # Returns
//
// true if both a and b are absent, or both are present and their values satisfy
// aVal == bVal; false otherwise.
//
// # Example
//
//	fmt.Println(opt.Equal(opt.Some(7), opt.Some(7)))   // true
//	fmt.Println(opt.Equal(opt.Some(0), opt.None[int]())) // false
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/opt/opt_test.go:249 (direct call)
//   - internal/opt/opt_test.go:250 (direct call)
//   - internal/opt/opt_test.go:251 (direct call)
//   - internal/opt/opt_test.go:252 (direct call)
//   - internal/opt/opt_test.go:253 (direct call)
//   - internal/opt/opt_test.go:254 (direct call)
//   - internal/opt/opt_test.go:255 (direct call)
//   - internal/opt/opt_test.go:283 (direct call)
//   - internal/opt/opt_test.go:284 (direct call)
//   - internal/opt/opt_test.go:285 (direct call)
//   - internal/opt/opt_test.go:286 (direct call)
//   - internal/opt/opt_test.go:287 (direct call)
//   - internal/opt/opt_test.go:288 (direct call)
//   - internal/opt/opt_test.go:289 (direct call)
//   - internal/opt/opt_test.go:685 (direct call)
//   - internal/opt/opt_test.go:688 (direct call)
//   - internal/opt/opt_test.go:691 (direct call)
//   - internal/opt/opt_test.go:694 (direct call)
//   - internal/opt/opt_test.go:697 (direct call)
//   - internal/opt/opt_test.go:700 (direct call)
//   - internal/opt/opt_test.go:891 (direct call)
//   - internal/opt/opt_test.go:921 (direct call)
//
// Scope: current module (github.com/andreimerlescu/concert), including tests;
// build configuration: darwin/arm64, default tags.
// Interface, reflection, callback, and external callers are not exhaustive.
func Equal[T comparable](a, b Option[T]) bool {
	if !a.set && !b.set {
		return true
	}
	if a.set != b.set {
		return false
	}
	return a.val == b.val
}

// MarshalJSON encodes o as JSON null when absent, or delegates to
// [encoding/json.Marshal] on the wrapped value when present.
//
// Using a value receiver ensures [encoding/json.Marshal] invokes MarshalJSON
// both for value structs and pointer structs. On struct fields tagged with
// `omitzero`, [encoding/json] checks [Option.IsZero] first and omits absent
// fields without calling MarshalJSON; on fields without `omitzero`, MarshalJSON
// emits literal null.
//
// # Parameters
//
// None. Operates on the value receiver o without mutating it.
//
// # Returns
//
// JSON encoding of the wrapped value, or []byte("null") when o is absent,
// along with any error returned by [encoding/json.Marshal] for T (for example
// NaN or Inf float64 values).
//
// # Example
//
//	b, err := json.Marshal(opt.Some(false))
//	if err != nil {
//		return err // inside a function returning error
//	}
//	fmt.Println(string(b)) // false
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/opt/opt_test.go:501 (direct call)
//   - internal/opt/opt_test.go:504 (direct call)
//
// Scope: current module (github.com/andreimerlescu/concert), including tests;
// build configuration: darwin/arm64, default tags.
// Also invoked dynamically via encoding/json or fmt interface dispatch;
// static call sites are not an exhaustive runtime call graph.
func (o Option[T]) MarshalJSON() ([]byte, error) {
	if !o.set {
		return []byte("null"), nil
	}
	return json.Marshal(o.val)
}

// UnmarshalJSON decodes a JSON value into receiver o.
//
// Leading and trailing RFC 8259 JSON whitespace (space, tab, CR, LF) is
// trimmed. A JSON null resets *o to the zero value (None), clearing any
// previously held value. Any other input is decoded into a fresh value of T
// before updating *o, so a decode error leaves *o unchanged.
//
// # Parameters
//
//   - o (receiver): Non-nil pointer to the target Option[T]. Calling
//     UnmarshalJSON on a nil receiver returns an error without panicking.
//   - data: Raw JSON bytes representing null or a value decodable into T. The
//     slice is read-only and not retained unless T's own unmarshaler retains it.
//
// # Returns
//
// nil on success, or an error if o is nil or [encoding/json.Unmarshal] fails
// to decode data into T. On error, *o is guaranteed to remain unmodified.
//
// # Example
//
//	var count opt.Option[int]
//	if err := json.Unmarshal([]byte(`0`), &count); err != nil {
//		return err // inside a function returning error
//	}
//	fmt.Println(count.IsSome(), count.UnwrapOr(-1)) // true 0
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/opt/opt_test.go:420 (direct call)
//   - internal/opt/opt_test.go:463 (direct call)
//   - internal/opt/opt_test.go:466 (direct call)
//   - internal/opt/opt_test.go:489 (direct call)
//   - internal/opt/opt_test.go:875 (direct call)
//
// Scope: current module (github.com/andreimerlescu/concert), including tests;
// build configuration: darwin/arm64, default tags.
// Also invoked dynamically via encoding/json or fmt interface dispatch;
// static call sites are not an exhaustive runtime call graph.
func (o *Option[T]) UnmarshalJSON(data []byte) error {
	if o == nil {
		return errNilOption
	}
	// Trim strictly RFC 8259 JSON whitespace (SP, HTAB, CR, LF) so invalid
	// non-ASCII whitespace such as U+00A0 before "null" is rejected by
	// json.Unmarshal rather than silently accepted as null.
	trimmed := bytes.Trim(data, " \t\r\n")
	if bytes.Equal(trimmed, []byte("null")) {
		*o = Option[T]{}
		return nil
	}
	// Decode into a fresh T so a failed decode never partially mutates *o.
	var v T
	if err := json.Unmarshal(trimmed, &v); err != nil {
		return err
	}
	o.val = v
	o.set = true
	return nil
}

// String formats o as "None" when absent or "Some(<value>)" using %v when
// present.
//
// # Parameters
//
// None. Operates on the value receiver o without mutating it.
//
// # Returns
//
// Human-readable representation suitable for logs, diagnostics, and tests.
//
// # Example
//
//	fmt.Println(opt.Some(42).String())   // Some(42)
//	fmt.Println(opt.None[int]().String()) // None
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/opt/opt_test.go:767 (direct call)
//   - internal/opt/opt_test.go:770 (direct call)
//   - internal/opt/opt_test.go:773 (direct call)
//   - internal/opt/opt_test.go:776 (direct call)
//   - internal/opt/opt_test.go:779 (direct call)
//
// Scope: current module (github.com/andreimerlescu/concert), including tests;
// build configuration: darwin/arm64, default tags.
// Also invoked dynamically via encoding/json or fmt interface dispatch;
// static call sites are not an exhaustive runtime call graph.
func (o Option[T]) String() string {
	if !o.set {
		return "None"
	}
	return fmt.Sprintf("Some(%v)", o.val)
}
