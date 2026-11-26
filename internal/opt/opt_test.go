package opt_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/opt"
)

// sampleOmitZero exercises every primary scalar and time field type tagged
// with Go 1.24+ omitzero.
type sampleOmitZero struct {
	Bool   opt.Option[bool]      `json:"bool,omitzero"`
	Int    opt.Option[int]       `json:"int,omitzero"`
	Int64  opt.Option[int64]     `json:"int64,omitzero"`
	Uint16 opt.Option[uint16]    `json:"uint16,omitzero"`
	Uint32 opt.Option[uint32]    `json:"uint32,omitzero"`
	Float  opt.Option[float64]   `json:"float,omitzero"`
	String opt.Option[string]    `json:"string,omitzero"`
	Time   opt.Option[time.Time] `json:"time,omitzero"`
}

// sampleNullable exercises Option fields without omitzero, where None must
// serialize explicitly as JSON null.
type sampleNullable struct {
	Bool   opt.Option[bool]      `json:"bool"`
	Int    opt.Option[int]       `json:"int"`
	Int64  opt.Option[int64]     `json:"int64"`
	Uint16 opt.Option[uint16]    `json:"uint16"`
	Uint32 opt.Option[uint32]    `json:"uint32"`
	Float  opt.Option[float64]   `json:"float"`
	String opt.Option[string]    `json:"string"`
	Time   opt.Option[time.Time] `json:"time"`
}

// TestOption_ZeroValuesDistinguishedFromNone verifies that Some wrapping zero
// values (0, false, "", time.Time{}) reports IsSome == true and IsZero == false,
// while None and default-initialized Option values report IsNone == true and
// IsZero == true.
//
// # Parameters
//
//   - t: Go test handle injected by `go test`.
//
// # Returns
//
// None. Fails the test if any predicate, accessor, or fallback disagrees.
//
// # Example
//
//	// Run with: go test -run '^TestOption_ZeroValuesDistinguishedFromNone$' ./internal/opt
//
// # Used By
//
// Executed by the Go test runner (`go test ./internal/opt`).
func TestOption_ZeroValuesDistinguishedFromNone(t *testing.T) {
	t.Parallel()

	assertPresentZero := func(t *testing.T, name string, isSome, isNone, isZero, ok bool) {
		t.Helper()
		if !isSome {
			t.Errorf("%s: IsSome() = false, want true", name)
		}
		if isNone {
			t.Errorf("%s: IsNone() = true, want false", name)
		}
		if isZero {
			t.Errorf("%s: IsZero() = true, want false", name)
		}
		if !ok {
			t.Errorf("%s: Get() ok = false, want true", name)
		}
	}

	assertAbsent := func(t *testing.T, name string, isSome, isNone, isZero, ok bool) {
		t.Helper()
		if isSome {
			t.Errorf("%s: IsSome() = true, want false", name)
		}
		if !isNone {
			t.Errorf("%s: IsNone() = false, want true", name)
		}
		if !isZero {
			t.Errorf("%s: IsZero() = false, want true", name)
		}
		if ok {
			t.Errorf("%s: Get() ok = true, want false", name)
		}
	}

	// Present zero values.
	{
		o := opt.Some(0)
		v, ok := o.Get()
		assertPresentZero(t, "Some(0)", o.IsSome(), o.IsNone(), o.IsZero(), ok)
		if v != 0 {
			t.Errorf("Some(0).Get() val = %d, want 0", v)
		}
		if got := o.UnwrapOr(42); got != 0 {
			t.Errorf("Some(0).UnwrapOr(42) = %d, want 0", got)
		}
	}
	{
		o := opt.Some(false)
		v, ok := o.Get()
		assertPresentZero(t, "Some(false)", o.IsSome(), o.IsNone(), o.IsZero(), ok)
		if v {
			t.Errorf("Some(false).Get() val = true, want false")
		}
		if got := o.UnwrapOr(true); got {
			t.Errorf("Some(false).UnwrapOr(true) = true, want false")
		}
	}
	{
		o := opt.Some("")
		v, ok := o.Get()
		assertPresentZero(t, `Some("")`, o.IsSome(), o.IsNone(), o.IsZero(), ok)
		if v != "" {
			t.Errorf(`Some("").Get() val = %q, want ""`, v)
		}
		if got := o.UnwrapOr("fallback"); got != "" {
			t.Errorf(`Some("").UnwrapOr("fallback") = %q, want ""`, got)
		}
	}
	{
		o := opt.Some(time.Time{})
		v, ok := o.Get()
		assertPresentZero(t, "Some(time.Time{})", o.IsSome(), o.IsNone(), o.IsZero(), ok)
		if !v.IsZero() {
			t.Errorf("Some(time.Time{}).Get() val = %v, want zero time", v)
		}
		fallback := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
		if got := o.UnwrapOr(fallback); !got.IsZero() {
			t.Errorf("Some(time.Time{}).UnwrapOr(fallback) = %v, want zero time", got)
		}
	}

	// Absent values: explicit None and zero-initialized Option.
	{
		o := opt.None[int]()
		v, ok := o.Get()
		assertAbsent(t, "None[int]()", o.IsSome(), o.IsNone(), o.IsZero(), ok)
		if v != 0 {
			t.Errorf("None[int]().Get() val = %d, want 0", v)
		}
		if got := o.UnwrapOr(99); got != 99 {
			t.Errorf("None[int]().UnwrapOr(99) = %d, want 99", got)
		}
	}
	{
		var o opt.Option[string]
		v, ok := o.Get()
		assertAbsent(t, "var Option[string]", o.IsSome(), o.IsNone(), o.IsZero(), ok)
		if v != "" {
			t.Errorf("var Option[string].Get() val = %q, want empty", v)
		}
		if got := o.UnwrapOr("default"); got != "default" {
			t.Errorf(`var Option[string].UnwrapOr("default") = %q, want "default"`, got)
		}
	}
}

// TestOption_JSONOmitZero verifies that Go 1.24+ `json:"...,omitzero"` omits
// None fields while always emitting Some(0), Some(false), Some(""), and
// Some(time.Time{}), and round-trips every supported scalar and time.Time type
// identically for both value and pointer structs.
//
// # Parameters
//
//   - t: Go test handle injected by `go test`.
//
// # Returns
//
// None. Fails on any wire mismatch or round-trip discrepancy.
//
// # Example
//
//	// Run with: go test -run '^TestOption_JSONOmitZero$' ./internal/opt
//
// # Used By
//
// Executed by the Go test runner (`go test ./internal/opt`).
func TestOption_JSONOmitZero(t *testing.T) {
	t.Parallel()

	t.Run("all None omitted for value and pointer structs", func(t *testing.T) {
		t.Parallel()
		in := sampleOmitZero{}

		valBytes, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("json.Marshal(value): %v", err)
		}
		if got, want := string(valBytes), `{}`; got != want {
			t.Errorf("json.Marshal(value) = %s, want %s", got, want)
		}

		ptrBytes, err := json.Marshal(&in)
		if err != nil {
			t.Fatalf("json.Marshal(ptr): %v", err)
		}
		if got, want := string(ptrBytes), `{}`; got != want {
			t.Errorf("json.Marshal(ptr) = %s, want %s", got, want)
		}
	})

	t.Run("explicit Some zero values emitted and round-trip", func(t *testing.T) {
		t.Parallel()
		in := sampleOmitZero{
			Bool:   opt.Some(false),
			Int:    opt.Some(0),
			Int64:  opt.Some(int64(0)),
			Uint16: opt.Some(uint16(0)),
			Uint32: opt.Some(uint32(0)),
			Float:  opt.Some(float64(0)),
			String: opt.Some(""),
			Time:   opt.Some(time.Time{}),
		}

		wantJSON := `{"bool":false,"int":0,"int64":0,"uint16":0,"uint32":0,"float":0,"string":"","time":"0001-01-01T00:00:00Z"}`

		valBytes, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("json.Marshal(value): %v", err)
		}
		if got := string(valBytes); got != wantJSON {
			t.Errorf("json.Marshal(value) = %s, want %s", got, wantJSON)
		}

		ptrBytes, err := json.Marshal(&in)
		if err != nil {
			t.Fatalf("json.Marshal(ptr): %v", err)
		}
		if got := string(ptrBytes); got != wantJSON {
			t.Errorf("json.Marshal(ptr) = %s, want %s", got, wantJSON)
		}

		var out sampleOmitZero
		if err := json.Unmarshal(valBytes, &out); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		if !opt.Equal(out.Bool, in.Bool) ||
			!opt.Equal(out.Int, in.Int) ||
			!opt.Equal(out.Int64, in.Int64) ||
			!opt.Equal(out.Uint16, in.Uint16) ||
			!opt.Equal(out.Uint32, in.Uint32) ||
			!opt.Equal(out.Float, in.Float) ||
			!opt.Equal(out.String, in.String) ||
			!out.Time.Equal(in.Time, time.Time.Equal) {
			t.Errorf("round-trip mismatch:\ngot  %+v\nwant %+v", out, in)
		}
	})

	t.Run("non-zero scalar and time values round-trip", func(t *testing.T) {
		t.Parallel()
		ts := time.Date(2026, 11, 26, 21, 52, 3, 123456789, time.UTC)
		in := sampleOmitZero{
			Bool:   opt.Some(true),
			Int:    opt.Some(-42),
			Int64:  opt.Some(int64(9_007_199_254_740_991)),
			Uint16: opt.Some(uint16(65535)),
			Uint32: opt.Some(uint32(4_294_967_295)),
			Float:  opt.Some(3.1415926535),
			String: opt.Some("concert"),
			Time:   opt.Some(ts),
		}

		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		var out sampleOmitZero
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		if !opt.Equal(out.Bool, in.Bool) ||
			!opt.Equal(out.Int, in.Int) ||
			!opt.Equal(out.Int64, in.Int64) ||
			!opt.Equal(out.Uint16, in.Uint16) ||
			!opt.Equal(out.Uint32, in.Uint32) ||
			!opt.Equal(out.Float, in.Float) ||
			!opt.Equal(out.String, in.String) ||
			!out.Time.Equal(in.Time, time.Time.Equal) {
			t.Errorf("round-trip mismatch:\ngot  %+v\nwant %+v", out, in)
		}
	})

	t.Run("mixed Some and None emits only Some fields", func(t *testing.T) {
		t.Parallel()
		in := sampleOmitZero{
			Bool:   opt.Some(false),
			Uint16: opt.Some(uint16(443)),
			String: opt.None[string](),
		}
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if got, want := string(raw), `{"bool":false,"uint16":443}`; got != want {
			t.Errorf("json.Marshal(mixed) = %s, want %s", got, want)
		}
	})
}

// TestOption_JSONWithoutOmitZero verifies that Option fields without
// `,omitzero` marshal None as explicit JSON null for both value and pointer
// structs, and marshal Some values directly.
//
// # Parameters
//
//   - t: Go test handle injected by `go test`.
//
// # Returns
//
// None. Fails if null emission or round-trip behavior diverges.
//
// # Example
//
//	// Run with: go test -run '^TestOption_JSONWithoutOmitZero$' ./internal/opt
//
// # Used By
//
// Executed by the Go test runner (`go test ./internal/opt`).
func TestOption_JSONWithoutOmitZero(t *testing.T) {
	t.Parallel()

	in := sampleNullable{
		Int:    opt.Some(0),
		String: opt.Some("ok"),
	}
	want := `{"bool":null,"int":0,"int64":null,"uint16":null,"uint32":null,"float":null,"string":"ok","time":null}`

	valBytes, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("json.Marshal(value): %v", err)
	}
	if got := string(valBytes); got != want {
		t.Errorf("json.Marshal(value) = %s, want %s", got, want)
	}

	ptrBytes, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("json.Marshal(ptr): %v", err)
	}
	if got := string(ptrBytes); got != want {
		t.Errorf("json.Marshal(ptr) = %s, want %s", got, want)
	}

	// Standalone Option[T] values marshal directly to null or the wrapped JSON value.
	standaloneNull, err := json.Marshal(opt.None[int]())
	if err != nil {
		t.Fatalf("json.Marshal(None): %v", err)
	}
	if got := string(standaloneNull); got != "null" {
		t.Errorf("json.Marshal(None) = %s, want null", got)
	}
}

// TestOption_UnmarshalNullOverwritesSome verifies that JSON null (including
// surrounding RFC 8259 whitespace) resets a pre-existing Some value cleanly to
// None, while a JSON string literal "null" still decodes as Some("null").
//
// # Parameters
//
//   - t: Go test handle injected by `go test`.
//
// # Returns
//
// None. Fails if any pre-existing value survives JSON null or if string "null"
// is misclassified as absent.
//
// # Example
//
//	// Run with: go test -run '^TestOption_UnmarshalNullOverwritesSome$' ./internal/opt
//
// # Used By
//
// Executed by the Go test runner (`go test ./internal/opt`).
func TestOption_UnmarshalNullOverwritesSome(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	s := sampleNullable{
		Bool:   opt.Some(true),
		Int:    opt.Some(123),
		Int64:  opt.Some(int64(456)),
		Uint16: opt.Some(uint16(8080)),
		Uint32: opt.Some(uint32(99999)),
		Float:  opt.Some(9.5),
		String: opt.Some("existing"),
		Time:   opt.Some(ts),
	}

	payload := `{"bool":null,"int": null ,"int64":` + "\n\t null \r\n" + `,"uint16":null,"uint32":null,"float":null,"string":null,"time":null}`
	if err := json.Unmarshal([]byte(payload), &s); err != nil {
		t.Fatalf("json.Unmarshal(nulls): %v", err)
	}

	if !s.Bool.IsNone() || !s.Int.IsNone() || !s.Int64.IsNone() ||
		!s.Uint16.IsNone() || !s.Uint32.IsNone() || !s.Float.IsNone() ||
		!s.String.IsNone() || !s.Time.IsNone() {
		t.Fatalf("expected all fields None after null overwrite, got %+v", s)
	}
	if v, ok := s.Int.Get(); ok || v != 0 {
		t.Errorf("Int.Get() after null = (%d, %v), want (0, false)", v, ok)
	}
	if v, ok := s.String.Get(); ok || v != "" {
		t.Errorf("String.Get() after null = (%q, %v), want (\"\", false)", v, ok)
	}

	// Direct UnmarshalJSON call with whitespace around null.
	direct := opt.Some(77)
	if err := direct.UnmarshalJSON([]byte(" \t\r\n null \r\n\t ")); err != nil {
		t.Fatalf("direct.UnmarshalJSON(whitespace null): %v", err)
	}
	if !direct.IsNone() || !direct.IsZero() {
		t.Errorf("direct after whitespace null: IsNone=%v IsZero=%v, want true true", direct.IsNone(), direct.IsZero())
	}

	// JSON string literal `"null"` must remain Some("null"), never None.
	var lit opt.Option[string]
	if err := json.Unmarshal([]byte(`"null"`), &lit); err != nil {
		t.Fatalf(`json.Unmarshal("\"null\""): %v`, err)
	}
	if got, ok := lit.Get(); !ok || got != "null" {
		t.Errorf(`Option[string] for JSON "null" = (%q, %v), want ("null", true)`, got, ok)
	}
}

// TestOption_UnmarshalErrorsPreserveState verifies that malformed JSON, type
// mismatches, empty slices, trailing tokens, non-JSON whitespace, nil
// receivers, and unmarshalable float values return errors and leave existing
// receiver values untouched.
//
// # Parameters
//
//   - t: Go test handle injected by `go test`.
//
// # Returns
//
// None. Fails if an invalid input succeeds or mutates the prior Option state.
//
// # Example
//
//	// Run with: go test -run '^TestOption_UnmarshalErrorsPreserveState$' ./internal/opt
//
// # Used By
//
// Executed by the Go test runner (`go test ./internal/opt`).
func TestOption_UnmarshalErrorsPreserveState(t *testing.T) {
	t.Parallel()

	t.Run("nil receiver returns error without panicking", func(t *testing.T) {
		t.Parallel()
		var p *opt.Option[int]
		if err := p.UnmarshalJSON([]byte("42")); err == nil {
			t.Fatal("(*Option[int])(nil).UnmarshalJSON(42) error = nil, want non-nil")
		}
		if err := p.UnmarshalJSON([]byte("null")); err == nil {
			t.Fatal("(*Option[int])(nil).UnmarshalJSON(null) error = nil, want non-nil")
		}
	})

	cases := []struct {
		name string
		raw  []byte
	}{
		{name: "empty input", raw: nil},
		{name: "whitespace only", raw: []byte("  \t\r\n ")},
		{name: "wrong type string for int", raw: []byte(`"not-an-int"`)},
		{name: "wrong type bool for int", raw: []byte(`true`)},
		{name: "truncated token", raw: []byte(`nul`)},
		{name: "trailing garbage", raw: []byte(`123 456`)},
		{name: "non-JSON NBSP whitespace before null", raw: []byte("\u00a0null")},
		{name: "overflow uint16/int", raw: []byte(`99999999999999999999999999999`)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := opt.Some(55)
			if err := o.UnmarshalJSON(tc.raw); err == nil {
				t.Fatalf("UnmarshalJSON(%q) error = nil, want non-nil", tc.raw)
			}
			// Prior value must remain intact after decode failure.
			if got, ok := o.Get(); !ok || got != 55 {
				t.Errorf("after failed UnmarshalJSON(%q), Get() = (%d, %v), want (55, true)", tc.raw, got, ok)
			}
		})
	}

	t.Run("MarshalJSON propagates error for NaN and Inf", func(t *testing.T) {
		t.Parallel()
		if _, err := opt.Some(math.NaN()).MarshalJSON(); err == nil {
			t.Error("Some(NaN).MarshalJSON() error = nil, want non-nil")
		}
		if _, err := opt.Some(math.Inf(1)).MarshalJSON(); err == nil {
			t.Error("Some(+Inf).MarshalJSON() error = nil, want non-nil")
		}
	})
}

// TestOption_ValueCopyNoAliasing verifies that copying a struct holding Option
// fields produces independent values so mutating fields on the copy never
// affects the original (and vice versa).
//
// # Parameters
//
//   - t: Go test handle injected by `go test`.
//
// # Returns
//
// None. Fails if any field exhibits pointer-like aliasing across struct copies.
//
// # Example
//
//	// Run with: go test -run '^TestOption_ValueCopyNoAliasing$' ./internal/opt
//
// # Used By
//
// Executed by the Go test runner (`go test ./internal/opt`).
func TestOption_ValueCopyNoAliasing(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)

	a := sampleOmitZero{
		Bool:   opt.Some(true),
		Int:    opt.Some(10),
		Int64:  opt.Some(int64(20)),
		Uint16: opt.Some(uint16(30)),
		Uint32: opt.Some(uint32(40)),
		Float:  opt.Some(1.5),
		String: opt.Some("orig"),
		Time:   opt.Some(t0),
	}

	b := a
	b.Bool = opt.Some(false)
	b.Int = opt.Some(99)
	b.Int64 = opt.None[int64]()
	b.Uint16 = opt.Some(uint16(999))
	b.Uint32 = opt.None[uint32]()
	b.Float = opt.Some(9.9)
	b.String = opt.Some("mutated")
	b.Time = opt.Some(t1)

	if got, ok := a.Bool.Get(); !ok || !got {
		t.Errorf("a.Bool = (%v, %v), want (true, true)", got, ok)
	}
	if got, ok := a.Int.Get(); !ok || got != 10 {
		t.Errorf("a.Int = (%d, %v), want (10, true)", got, ok)
	}
	if got, ok := a.Int64.Get(); !ok || got != 20 {
		t.Errorf("a.Int64 = (%d, %v), want (20, true)", got, ok)
	}
	if got, ok := a.Uint16.Get(); !ok || got != 30 {
		t.Errorf("a.Uint16 = (%d, %v), want (30, true)", got, ok)
	}
	if got, ok := a.Uint32.Get(); !ok || got != 40 {
		t.Errorf("a.Uint32 = (%d, %v), want (40, true)", got, ok)
	}
	if got, ok := a.Float.Get(); !ok || got != 1.5 {
		t.Errorf("a.Float = (%v, %v), want (1.5, true)", got, ok)
	}
	if got, ok := a.String.Get(); !ok || got != "orig" {
		t.Errorf("a.String = (%q, %v), want (\"orig\", true)", got, ok)
	}
	if got, ok := a.Time.Get(); !ok || !got.Equal(t0) {
		t.Errorf("a.Time = (%v, %v), want (%v, true)", got, ok, t0)
	}
}

// TestOption_DisallowUnknownFields verifies compatibility with
// json.Decoder.DisallowUnknownFields for structs containing Option fields of
// all scalar and time.Time types.
//
// # Parameters
//
//   - t: Go test handle injected by `go test`.
//
// # Returns
//
// None. Fails if valid payloads are rejected or unknown fields are accepted.
//
// # Example
//
//	// Run with: go test -run '^TestOption_DisallowUnknownFields$' ./internal/opt
//
// # Used By
//
// Executed by the Go test runner (`go test ./internal/opt`).
func TestOption_DisallowUnknownFields(t *testing.T) {
	t.Parallel()

	t.Run("accepts known present, zero, null, and omitted fields", func(t *testing.T) {
		t.Parallel()
		raw := `{
			"bool": false,
			"int": 0,
			"int64": null,
			"uint16": 443,
			"uint32": 0,
			"float": 0.25,
			"string": "",
			"time": "2026-11-26T21:52:03Z"
		}`
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()

		var got sampleOmitZero
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("Decode valid strict JSON: %v", err)
		}
		if v, ok := got.Bool.Get(); !ok || v {
			t.Errorf("Bool = (%v, %v), want (false, true)", v, ok)
		}
		if v, ok := got.Int.Get(); !ok || v != 0 {
			t.Errorf("Int = (%d, %v), want (0, true)", v, ok)
		}
		if !got.Int64.IsNone() {
			t.Errorf("Int64 = %v, want None", got.Int64)
		}
		if v, ok := got.Uint16.Get(); !ok || v != 443 {
			t.Errorf("Uint16 = (%d, %v), want (443, true)", v, ok)
		}
		if v, ok := got.Uint32.Get(); !ok || v != 0 {
			t.Errorf("Uint32 = (%d, %v), want (0, true)", v, ok)
		}
		if v, ok := got.Float.Get(); !ok || v != 0.25 {
			t.Errorf("Float = (%v, %v), want (0.25, true)", v, ok)
		}
		if v, ok := got.String.Get(); !ok || v != "" {
			t.Errorf("String = (%q, %v), want (\"\", true)", v, ok)
		}
		wantTime := time.Date(2026, 11, 26, 21, 52, 3, 0, time.UTC)
		if v, ok := got.Time.Get(); !ok || !v.Equal(wantTime) {
			t.Errorf("Time = (%v, %v), want (%v, true)", v, ok, wantTime)
		}
	})

	t.Run("rejects unknown field", func(t *testing.T) {
		t.Parallel()
		raw := `{"int": 7, "unexpected_key": true}`
		dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
		dec.DisallowUnknownFields()

		var got sampleOmitZero
		if err := dec.Decode(&got); err == nil {
			t.Fatalf("Decode with unknown field succeeded (%+v), want error", got)
		}
	})
}

// TestOption_Equal verifies both the package-level Equal[T comparable] helper
// and the (Option[T]).Equal custom-comparator method across absent, present,
// zero, time.Time location-independent, and slice cases.
//
// # Parameters
//
//   - t: Go test handle injected by `go test`.
//
// # Returns
//
// None. Fails on any equality mismatch or unexpected comparator invocation.
//
// # Example
//
//	// Run with: go test -run '^TestOption_Equal$' ./internal/opt
//
// # Used By
//
// Executed by the Go test runner (`go test ./internal/opt`).
func TestOption_Equal(t *testing.T) {
	t.Parallel()

	if !opt.Equal(opt.None[int](), opt.None[int]()) {
		t.Error("Equal(None, None) = false, want true")
	}
	if opt.Equal(opt.Some(0), opt.None[int]()) {
		t.Error("Equal(Some(0), None) = true, want false")
	}
	if opt.Equal(opt.None[int](), opt.Some(0)) {
		t.Error("Equal(None, Some(0)) = true, want false")
	}
	if !opt.Equal(opt.Some(42), opt.Some(42)) {
		t.Error("Equal(Some(42), Some(42)) = false, want true")
	}
	if opt.Equal(opt.Some(42), opt.Some(43)) {
		t.Error("Equal(Some(42), Some(43)) = true, want false")
	}
	if opt.Equal(opt.Some(math.NaN()), opt.Some(math.NaN())) {
		t.Error("Equal(Some(NaN), Some(NaN)) = true, want false per IEEE-754")
	}

	// Custom comparator must NOT be invoked when either operand is None.
	calls := 0
	countingEq := func(a, b int) bool {
		calls++
		return a == b
	}
	if !opt.None[int]().Equal(opt.None[int](), countingEq) {
		t.Error("None.Equal(None, eq) = false, want true")
	}
	if opt.Some(1).Equal(opt.None[int](), countingEq) {
		t.Error("Some(1).Equal(None, eq) = true, want false")
	}
	if opt.None[int]().Equal(opt.Some(1), countingEq) {
		t.Error("None.Equal(Some(1), eq) = true, want false")
	}
	if calls != 0 {
		t.Errorf("custom comparator called %d times when an operand was None, want 0", calls)
	}

	// Custom comparator called once when both are Some.
	if !opt.Some(7).Equal(opt.Some(7), countingEq) || calls != 1 {
		t.Errorf("Some(7).Equal(Some(7)) failed or calls=%d (want 1)", calls)
	}

	// Instant equality across distinct time.Location values.
	utc := time.Date(2026, 11, 26, 15, 0, 0, 0, time.UTC)
	est := utc.In(time.FixedZone("EST", -5*3600))
	if !opt.Some(utc).Equal(opt.Some(est), time.Time.Equal) {
		t.Error("Some(utc).Equal(Some(est), time.Time.Equal) = false, want true")
	}

	// Non-comparable T (slice) via Option.Equal.
	s1 := opt.Some([]string{"a", "b"})
	s2 := opt.Some([]string{"a", "b"})
	s3 := opt.Some([]string{"a", "c"})
	if !s1.Equal(s2, slices.Equal[[]string]) {
		t.Error("Some([a b]).Equal(Some([a b]), slices.Equal) = false, want true")
	}
	if s1.Equal(s3, slices.Equal[[]string]) {
		t.Error("Some([a b]).Equal(Some([a c]), slices.Equal) = true, want false")
	}
}

// TestOption_String verifies String formatting for None and Some values.
//
// # Parameters
//
//   - t: Go test handle injected by `go test`.
//
// # Returns
//
// None. Fails on any formatted output mismatch.
//
// # Example
//
//	// Run with: go test -run '^TestOption_String$' ./internal/opt
//
// # Used By
//
// Executed by the Go test runner (`go test ./internal/opt`).
func TestOption_String(t *testing.T) {
	t.Parallel()

	if got, want := opt.None[int]().String(), "None"; got != want {
		t.Errorf("None[int]().String() = %q, want %q", got, want)
	}
	if got, want := opt.Some(0).String(), "Some(0)"; got != want {
		t.Errorf("Some(0).String() = %q, want %q", got, want)
	}
	if got, want := opt.Some(false).String(), "Some(false)"; got != want {
		t.Errorf("Some(false).String() = %q, want %q", got, want)
	}
	if got, want := opt.Some("").String(), "Some()"; got != want {
		t.Errorf(`Some("").String() = %q, want %q`, got, want)
	}
	if got, want := opt.Some("ready").String(), "Some(ready)"; got != want {
		t.Errorf(`Some("ready").String() = %q, want %q`, got, want)
	}
}

// TestOption_ConcurrentReadSafety proves that sharing a read-only struct with
// Option fields across concurrent goroutines is race-free under -race and
// preserves value isolation when each goroutine mutates its own copy.
//
// # Parameters
//
//   - t: Go test handle injected by `go test`.
//
// # Returns
//
// None. Fails if any goroutine observes corrupted state or race detector fires.
//
// # Example
//
//	// Run with: go test -race -count=10 -run '^TestOption_ConcurrentReadSafety$' ./internal/opt
//
// # Used By
//
// Executed by the Go test runner (`go test ./internal/opt`).
func TestOption_ConcurrentReadSafety(t *testing.T) {
	t.Parallel()

	shared := sampleOmitZero{
		Bool:   opt.Some(false),
		Int:    opt.Some(42),
		String: opt.Some("shared"),
	}

	const workers = 16
	start := make(chan struct{})
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for id := range workers {
		wg.Go(func() {
			<-start
			local := shared
			local.Int = opt.Some(id)
			if v, ok := shared.Int.Get(); !ok || v != 42 {
				errCh <- fmt.Errorf("worker %d observed shared.Int=(%d,%v), want (42,true)", id, v, ok)
				return
			}
			if _, err := json.Marshal(local); err != nil {
				errCh <- fmt.Errorf("worker %d json.Marshal: %w", id, err)
			}
		})
	}
	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Error(err)
	}
}

// FuzzOption_UnmarshalJSON verifies that Option[int].UnmarshalJSON never panics
// on arbitrary byte inputs, leaves pre-existing state intact on error, and
// round-trips any successfully decoded value cleanly.
//
// # Parameters
//
//   - f: Go fuzzing harness injected by `go test`.
//
// # Returns
//
// None. Fails if an invariant is violated on any seed or fuzzed input.
//
// # Example
//
//	// Run seed corpus: go test -run '^FuzzOption_UnmarshalJSON$' ./internal/opt
//
// # Used By
//
// Executed by the Go test runner (`go test ./internal/opt`).
func FuzzOption_UnmarshalJSON(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("null"),
		[]byte(" \t\r\nnull\n "),
		[]byte("0"),
		[]byte("-42"),
		[]byte(`"null"`),
		[]byte(""),
		[]byte("\u00a0null"),
		[]byte("123 trailing"),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		const sentinel = 777
		o := opt.Some(sentinel)
		err := o.UnmarshalJSON(raw)
		if err != nil {
			// Failed decode must preserve the prior value.
			if v, ok := o.Get(); !ok || v != sentinel {
				t.Fatalf("failed UnmarshalJSON(%q) mutated option to (%d, %v)", raw, v, ok)
			}
			return
		}
		enc, err := json.Marshal(o)
		if err != nil {
			t.Fatalf("json.Marshal after successful UnmarshalJSON(%q): %v", raw, err)
		}
		var roundTrip opt.Option[int]
		if err := json.Unmarshal(enc, &roundTrip); err != nil {
			t.Fatalf("round-trip Unmarshal(%q): %v", enc, err)
		}
		if !opt.Equal(o, roundTrip) {
			t.Fatalf("round-trip mismatch for input %q: got %v, want %v", raw, roundTrip, o)
		}
	})
}

// BenchmarkOption_ValueOps measures the allocation and throughput cost of
// Option value construction, predicates, accessors, and equality checks.
//
// # Parameters
//
//   - b: Go benchmark handle injected by `go test -bench`.
//
// # Returns
//
// None. Reports ns/op and allocs/op via testing.B.
//
// # Example
//
//	// Run with: go test -run '^$' -bench '^BenchmarkOption_ValueOps$' -benchmem ./internal/opt
//
// # Used By
//
// Executed by the Go benchmark runner (`go test -bench . ./internal/opt`).
func BenchmarkOption_ValueOps(b *testing.B) {
	b.ReportAllocs()
	var sink int
	for b.Loop() {
		a := opt.Some(42)
		n := opt.None[int]()
		if a.IsSome() && n.IsNone() && !a.IsZero() && n.IsZero() && !opt.Equal(a, n) {
			v, _ := a.Get()
			sink += v + n.UnwrapOr(1)
		}
	}
	_ = sink
}

// ExampleSome demonstrates wrapping an explicit zero value with Some and
// marshaling a struct tagged with `omitzero`.
//
// # Parameters
//
// None. Executed by `go test ./internal/opt`.
//
// # Returns
//
// None. Verified via GoDoc Output comment.
//
// # Example
//
//	// Run with: go test -run '^ExampleSome$' ./internal/opt
//
// # Used By
//
// Executed by the Go test runner (`go test ./internal/opt`).
func ExampleSome() {
	type config struct {
		Retries opt.Option[int]  `json:"retries,omitzero"`
		Enabled opt.Option[bool] `json:"enabled,omitzero"`
	}

	cfg := config{
		Retries: opt.Some(0),
		Enabled: opt.Some(false),
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		panic(err)
	}
	fmt.Println(cfg.Retries.IsSome(), cfg.Retries.IsZero(), string(raw))
	// Output:
	// true false {"retries":0,"enabled":false}
}

// ExampleNone demonstrates omitting an absent Option field under `omitzero`,
// emitting null without `omitzero`, and applying a fallback via UnwrapOr.
//
// # Parameters
//
// None. Executed by `go test ./internal/opt`.
//
// # Returns
//
// None. Verified via GoDoc Output comment.
//
// # Example
//
//	// Run with: go test -run '^ExampleNone$' ./internal/opt
//
// # Used By
//
// Executed by the Go test runner (`go test ./internal/opt`).
func ExampleNone() {
	type payload struct {
		Omitted  opt.Option[int] `json:"omitted,omitzero"`
		Nullable opt.Option[int] `json:"nullable"`
	}

	p := payload{
		Omitted:  opt.None[int](),
		Nullable: opt.None[int](),
	}
	raw, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	fmt.Println(p.Omitted.IsNone(), p.Omitted.UnwrapOr(30), string(raw))
	// Output:
	// true 30 {"nullable":null}
}
