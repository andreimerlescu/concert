package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"time"
)

// W3C Trace Context constants.
const (
	TraceparentHeader = "traceparent"
	FlagSampled       = byte(0x01)
)

// SpanKind mirrors OpenTelemetry Span.SpanKind protobuf enum values.
type SpanKind int

const (
	SpanKindUnspecified SpanKind = 0
	SpanKindInternal    SpanKind = 1
	SpanKindServer      SpanKind = 2
	SpanKindClient      SpanKind = 3
	SpanKindProducer    SpanKind = 4
	SpanKindConsumer    SpanKind = 5
)

// StatusCode mirrors OpenTelemetry Status.StatusCode protobuf enum values.
type StatusCode int

const (
	StatusUnset StatusCode = 0
	StatusOK    StatusCode = 1
	StatusError StatusCode = 2
)

// ErrInvalidTraceparent indicates that a W3C traceparent header value failed
// structural, hex, version, or all-zero ID validation.
var ErrInvalidTraceparent = errors.New("invalid W3C traceparent header")

// TraceID is a 16-byte W3C Trace Context trace identifier.
type TraceID [16]byte

// IsValid reports whether id contains at least one non-zero byte.
//
// # Parameters
//
// None.
//
// # Returns
//
// true if id is not the all-zero TraceID.
//
// # Example
//
//	var id telemetry.TraceID
//	fmt.Println(id.IsValid()) // false
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/trace.go:210 (direct call)
//   - internal/telemetry/trace.go:981 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (id TraceID) IsValid() bool {
	for _, b := range id {
		if b != 0 {
			return true
		}
	}
	return false
}

// String encodes id as 32 lowercase hexadecimal characters.
//
// # Parameters
//
// None.
//
// # Returns
//
// Lowercase 32-character hex string.
//
// # Example
//
//	fmt.Println(sc.TraceID.String())
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:967 (direct call)
//   - internal/telemetry/telemetry_test.go:242 (direct call)
//   - internal/telemetry/trace.go:363 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (id TraceID) String() string {
	return hex.EncodeToString(id[:])
}

// SpanID is an 8-byte W3C Trace Context parent/span identifier.
type SpanID [8]byte

// IsValid reports whether id contains at least one non-zero byte.
//
// # Parameters
//
// None.
//
// # Returns
//
// true if id is not the all-zero SpanID.
//
// # Example
//
//	var id telemetry.SpanID
//	fmt.Println(id.IsValid()) // false
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:979 (direct call)
//   - internal/telemetry/trace.go:210 (direct call)
//   - internal/telemetry/trace.go:1010 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (id SpanID) IsValid() bool {
	for _, b := range id {
		if b != 0 {
			return true
		}
	}
	return false
}

// String encodes id as 16 lowercase hexadecimal characters.
//
// # Parameters
//
// None.
//
// # Returns
//
// Lowercase 16-character hex string.
//
// # Example
//
//	fmt.Println(sc.SpanID.String())
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:968 (direct call)
//   - internal/telemetry/otlp.go:980 (direct call)
//   - internal/telemetry/telemetry_test.go:242 (direct call)
//   - internal/telemetry/trace.go:363 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (id SpanID) String() string {
	return hex.EncodeToString(id[:])
}

// SpanContext holds the immutable W3C Trace Context identity of a span.
type SpanContext struct {
	TraceID    TraceID
	SpanID     SpanID
	TraceFlags byte
	Remote     bool
}

// IsValid reports whether both TraceID and SpanID are non-zero.
//
// # Parameters
//
// None.
//
// # Returns
//
// true if sc identifies a valid span context.
//
// # Example
//
//	if sc.IsValid() {
//	    req.Header.Set("traceparent", telemetry.FormatTraceparent(sc))
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:46 (direct call)
//   - internal/telemetry/trace.go:328 (direct call)
//   - internal/telemetry/trace.go:360 (direct call)
//   - internal/telemetry/trace.go:526 (direct call)
//   - internal/telemetry/trace.go:529 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (sc SpanContext) IsValid() bool {
	return sc.TraceID.IsValid() && sc.SpanID.IsValid()
}

// IsSampled reports whether the W3C sampled bit (0x01) is set in TraceFlags.
//
// # Parameters
//
// None.
//
// # Returns
//
// true when TraceFlags&FlagSampled != 0.
//
// # Example
//
//	if sc.IsSampled() {
//	    // Span will be exported on End.
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:46 (direct call)
//   - internal/telemetry/telemetry_test.go:59 (direct call)
//   - internal/telemetry/telemetry_test.go:366 (direct call)
//   - internal/telemetry/telemetry_test.go:374 (direct call)
//   - internal/telemetry/telemetry_test.go:397 (direct call)
//   - internal/telemetry/telemetry_test.go:561 (direct call)
//   - internal/telemetry/trace.go:953 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (sc SpanContext) IsSampled() bool {
	return sc.TraceFlags&FlagSampled != 0
}

// ParseTraceparent parses a W3C Trace Context traceparent header of the form
// "00-<32-hex-trace-id>-<16-hex-span-id>-<2-hex-flags>". It enforces lowercase
// hex digits, rejects version "ff", rejects all-zero trace or span IDs, and
// tolerates forward-compatible trailing fields for future versions (01..fe)
// per W3C Trace Context Level 1.
//
// # Parameters
//
//   - header: Raw traceparent header string. Leading and trailing ASCII
//     whitespace is trimmed before parsing.
//
// # Returns
//
// A SpanContext with Remote set to true on success, or zero SpanContext and an
// error matching ErrInvalidTraceparent.
//
// # Example
//
//	sc, err := telemetry.ParseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
//	if err != nil {
//	    return err
//	}
//	fmt.Println(sc.IsSampled()) // true
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:42 (direct call)
//   - internal/telemetry/telemetry_test.go:55 (direct call)
//   - internal/telemetry/telemetry_test.go:74 (direct call)
//   - internal/telemetry/telemetry_test.go:143 (direct call)
//   - internal/telemetry/telemetry_test.go:372 (direct call)
//   - internal/telemetry/telemetry_test.go:557 (direct call)
//   - internal/telemetry/telemetry_test.go:586 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func ParseTraceparent(header string) (SpanContext, error) {
	s := strings.TrimSpace(header)
	if len(s) < 55 {
		return SpanContext{}, fmt.Errorf("%w: too short", ErrInvalidTraceparent)
	}
	if s[2] != '-' || s[35] != '-' || s[52] != '-' {
		return SpanContext{}, fmt.Errorf("%w: invalid field separators", ErrInvalidTraceparent)
	}

	verHex := s[0:2]
	if !isLowerHex(verHex) {
		return SpanContext{}, fmt.Errorf("%w: version must be lowercase hex", ErrInvalidTraceparent)
	}
	if verHex == "ff" {
		return SpanContext{}, fmt.Errorf("%w: version ff is reserved", ErrInvalidTraceparent)
	}
	if verHex == "00" {
		if len(s) != 55 {
			return SpanContext{}, fmt.Errorf("%w: version 00 must be exactly 55 characters", ErrInvalidTraceparent)
		}
	} else if len(s) > 55 && s[55] != '-' {
		return SpanContext{}, fmt.Errorf("%w: invalid trailing field separator", ErrInvalidTraceparent)
	}

	traceHex := s[3:35]
	spanHex := s[36:52]
	flagsHex := s[53:55]
	if !isLowerHex(traceHex) || !isLowerHex(spanHex) || !isLowerHex(flagsHex) {
		return SpanContext{}, fmt.Errorf("%w: identifiers and flags must be lowercase hex", ErrInvalidTraceparent)
	}

	var sc SpanContext
	if _, err := hex.Decode(sc.TraceID[:], []byte(traceHex)); err != nil {
		return SpanContext{}, fmt.Errorf("%w: decode trace-id", ErrInvalidTraceparent)
	}
	if _, err := hex.Decode(sc.SpanID[:], []byte(spanHex)); err != nil {
		return SpanContext{}, fmt.Errorf("%w: decode parent-id", ErrInvalidTraceparent)
	}
	var flags [1]byte
	if _, err := hex.Decode(flags[:], []byte(flagsHex)); err != nil {
		return SpanContext{}, fmt.Errorf("%w: decode trace-flags", ErrInvalidTraceparent)
	}
	sc.TraceFlags = flags[0]
	sc.Remote = true

	if !sc.IsValid() {
		return SpanContext{}, fmt.Errorf("%w: trace-id and span-id must be non-zero", ErrInvalidTraceparent)
	}
	return sc, nil
}

// FormatTraceparent renders sc as a W3C Trace Context version-00 traceparent
// header string, or "" if sc is invalid.
//
// # Parameters
//
//   - sc: SpanContext to serialize.
//
// # Returns
//
// A 55-character lowercase traceparent string, or "" when !sc.IsValid().
//
// # Example
//
//	hdr := telemetry.FormatTraceparent(span.SpanContext())
//	req.Header.Set(telemetry.TraceparentHeader, hdr)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:49 (direct call)
//   - internal/telemetry/telemetry_test.go:562 (direct call)
//   - internal/telemetry/trace.go:762 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func FormatTraceparent(sc SpanContext) string {
	if !sc.IsValid() {
		return ""
	}
	return fmt.Sprintf("00-%s-%s-%02x", sc.TraceID.String(), sc.SpanID.String(), sc.TraceFlags)
}

// isLowerHex reports whether s contains exclusively ASCII lowercase hex digits
// ('0'-'9', 'a'-'f').
//
// # Parameters
//
//   - s: String slice to validate.
//
// # Returns
//
// true if every byte in s is a lowercase hexadecimal character.
//
// # Example
//
//	ok := isLowerHex("00f067aa0ba902b7")
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/trace.go:293 (direct call)
//   - internal/telemetry/trace.go:310 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func isLowerHex(s string) bool {
	for i := range len(s) {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return len(s) > 0
}

type spanContextKey struct{}
type remoteSpanContextKey struct{}

// ContextWithSpan returns a derived context carrying span as the active span.
//
// # Parameters
//
//   - ctx: Parent context; if nil, context.Background() is used.
//   - span: Active *Span to attach (may be nil to clear the active span).
//
// # Returns
//
// A derived context storing span.
//
// # Example
//
//	ctx = telemetry.ContextWithSpan(ctx, span)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:451 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func ContextWithSpan(ctx context.Context, span *Span) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, spanContextKey{}, span)
}

// SpanFromContext retrieves the active *Span from ctx, or nil if none is set.
//
// # Parameters
//
//   - ctx: Context to inspect; nil returns nil.
//
// # Returns
//
// The active *Span or nil.
//
// # Example
//
//	if sp := telemetry.SpanFromContext(ctx); sp != nil {
//	    sp.SetAttributes(telemetry.IntAttr("http.status_code", 200))
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:155 (direct call)
//   - internal/telemetry/telemetry_test.go:162 (direct call)
//   - internal/telemetry/trace.go:526 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func SpanFromContext(ctx context.Context) *Span {
	if ctx == nil {
		return nil
	}
	sp, _ := ctx.Value(spanContextKey{}).(*Span)
	return sp
}

// ContextWithRemoteSpanContext attaches a parsed remote SpanContext (such as
// one obtained from ParseTraceparent on an incoming HTTP request) to ctx so
// subsequent Tracer.StartSpan calls link as children of that remote trace.
//
// # Parameters
//
//   - ctx: Parent context; if nil, context.Background() is used.
//   - sc: Validated remote SpanContext to propagate.
//
// # Returns
//
// A derived context carrying sc.
//
// # Example
//
//	if sc, err := telemetry.ParseTraceparent(r.Header.Get("traceparent")); err == nil {
//	    ctx = telemetry.ContextWithRemoteSpanContext(ctx, sc)
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:147 (direct call)
//   - internal/telemetry/telemetry_test.go:373 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func ContextWithRemoteSpanContext(ctx context.Context, sc SpanContext) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, remoteSpanContextKey{}, sc)
}

// SpanContextFromContext returns the active SpanContext from ctx, preferring an
// active local *Span over a remote SpanContext.
//
// # Parameters
//
//   - ctx: Context to inspect; nil returns (SpanContext{}, false).
//
// # Returns
//
// The active SpanContext and true if a valid context was present.
//
// # Example
//
//	if sc, ok := telemetry.SpanContextFromContext(ctx); ok {
//	    req.Header.Set("traceparent", telemetry.FormatTraceparent(sc))
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:428 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func SpanContextFromContext(ctx context.Context) (SpanContext, bool) {
	if ctx == nil {
		return SpanContext{}, false
	}
	if sp := SpanFromContext(ctx); sp != nil && sp.sc.IsValid() {
		return sp.sc, true
	}
	if sc, ok := ctx.Value(remoteSpanContextKey{}).(SpanContext); ok && sc.IsValid() {
		return sc, true
	}
	return SpanContext{}, false
}

// AttrKind distinguishes typed Attribute values for OTLP AnyValue encoding.
type AttrKind uint8

const (
	AttrString AttrKind = iota + 1
	AttrInt
	AttrFloat64
	AttrBool
)

// Attribute is an immutable key-value pair attached to a span or resource.
type Attribute struct {
	Key    string
	Kind   AttrKind
	StrVal string
	IntVal int64
	FltVal float64
	BolVal bool
}

// StringAttr constructs a string-valued Attribute.
//
// # Parameters
//
//   - key: Attribute name (e.g. "http.method").
//   - val: Attribute string value; callers must never pass secret material.
//
// # Returns
//
// A string Attribute value.
//
// # Example
//
//	attr := telemetry.StringAttr("http.method", "GET")
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:350 (direct call)
//   - internal/telemetry/otlp.go:352 (direct call)
//   - internal/telemetry/telemetry_test.go:149 (direct call)
//   - internal/telemetry/telemetry_test.go:594 (direct call)
//   - internal/telemetry/telemetry_test.go:605 (direct call)
//   - internal/telemetry/telemetry_test.go:606 (direct call)
//   - internal/telemetry/trace.go:890 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func StringAttr(key, val string) Attribute {
	return Attribute{Key: key, Kind: AttrString, StrVal: val}
}

// IntAttr constructs a 64-bit integer Attribute.
//
// # Parameters
//
//   - key: Attribute name (e.g. "http.status_code").
//   - val: Integer value.
//
// # Returns
//
// An integer Attribute value.
//
// # Example
//
//	attr := telemetry.IntAttr("http.status_code", 200)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:150 (direct call)
//   - internal/telemetry/telemetry_test.go:530 (direct call)
//   - internal/telemetry/telemetry_test.go:607 (direct call)
//   - internal/telemetry/telemetry_test.go:608 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func IntAttr(key string, val int64) Attribute {
	return Attribute{Key: key, Kind: AttrInt, IntVal: val}
}

// Float64Attr constructs a floating-point Attribute.
//
// # Parameters
//
//   - key: Attribute name.
//   - val: Finite float64 value; NaN/Inf are encoded as 0 during serialization.
//
// # Returns
//
// A float64 Attribute value.
//
// # Example
//
//	attr := telemetry.Float64Attr("concert.utilization", 0.75)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:151 (direct call)
//   - internal/telemetry/telemetry_test.go:609 (direct call)
//   - internal/telemetry/telemetry_test.go:610 (direct call)
//   - internal/telemetry/telemetry_test.go:611 (direct call)
//   - internal/telemetry/telemetry_test.go:612 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func Float64Attr(key string, val float64) Attribute {
	return Attribute{Key: key, Kind: AttrFloat64, FltVal: val}
}

// BoolAttr constructs a boolean Attribute.
//
// # Parameters
//
//   - key: Attribute name.
//   - val: Boolean value.
//
// # Returns
//
// A boolean Attribute value.
//
// # Example
//
//	attr := telemetry.BoolAttr("concert.cache.hit", true)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:152 (direct call)
//   - internal/telemetry/telemetry_test.go:613 (direct call)
//   - internal/telemetry/telemetry_test.go:614 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func BoolAttr(key string, val bool) Attribute {
	return Attribute{Key: key, Kind: AttrBool, BolVal: val}
}

// SpanData is an immutable completed span snapshot queued for OTLP export.
type SpanData struct {
	TraceID       TraceID
	SpanID        SpanID
	ParentSpanID  SpanID
	Name          string
	Kind          SpanKind
	StartTime     time.Time
	EndTime       time.Time
	Attributes    []Attribute
	StatusCode    StatusCode
	StatusMessage string
}

// Span tracks an in-progress traced operation. All methods are safe for
// concurrent use. End must be called once when the operation finishes; extra
// calls to End are safe no-ops.
type Span struct {
	tracer   *Tracer
	sc       SpanContext
	parentID SpanID
	name     string
	kind     SpanKind
	start    time.Time

	mu        sync.Mutex
	ended     bool
	attrs     []Attribute
	status    StatusCode
	statusMsg string
}

// SpanContext returns the immutable W3C SpanContext of s.
//
// # Parameters
//
// None.
//
// # Returns
//
// The SpanContext identifying s, or the zero SpanContext if s is nil.
//
// # Example
//
//	sc := span.SpanContext()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:366 (direct call)
//   - internal/telemetry/telemetry_test.go:374 (direct call)
//   - internal/telemetry/telemetry_test.go:397 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (s *Span) SpanContext() SpanContext {
	if s == nil {
		return SpanContext{}
	}
	return s.sc
}

// Traceparent formats s's SpanContext as a W3C traceparent header string.
//
// # Parameters
//
// None.
//
// # Returns
//
// A 55-character traceparent string, or "" if s is nil or invalid.
//
// # Example
//
//	req.Header.Set(telemetry.TraceparentHeader, span.Traceparent())
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope
// (may be satisfied via interface dispatch or external callers).
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (s *Span) Traceparent() string {
	if s == nil {
		return ""
	}
	return FormatTraceparent(s.sc)
}

// SetAttributes appends attrs to s if s has not yet ended. Safe for concurrent
// use; calls after End or on a nil receiver are ignored.
//
// # Parameters
//
//   - attrs: Zero or more immutable Attributes to record on s.
//
// # Example
//
//	span.SetAttributes(telemetry.StringAttr("concert.site", "tickets.example.com"))
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:530 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (s *Span) SetAttributes(attrs ...Attribute) {
	if s == nil || len(attrs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	s.attrs = append(s.attrs, attrs...)
}

// SetKind sets the OpenTelemetry SpanKind on s before End is called.
//
// # Parameters
//
//   - kind: One of SpanKindInternal, SpanKindServer, SpanKindClient,
//     SpanKindProducer, or SpanKindConsumer.
//
// # Example
//
//	span.SetKind(telemetry.SpanKindServer)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:154 (direct call)
//   - internal/telemetry/telemetry_test.go:160 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (s *Span) SetKind(kind SpanKind) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	s.kind = kind
}

// SetStatus sets the completion status code and optional description on s
// before End is called.
//
// # Parameters
//
//   - code: One of StatusUnset, StatusOK, or StatusError.
//   - description: Human-readable status description (must not contain secrets).
//
// # Example
//
//	span.SetStatus(telemetry.StatusOK, "")
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:166 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (s *Span) SetStatus(code StatusCode, description string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	s.status = code
	s.statusMsg = description
}

// RecordError marks s with StatusError and attaches an "error.message"
// attribute when err is non-nil.
//
// # Parameters
//
//   - err: Error to record; nil is a no-op.
//
// # Example
//
//	if err != nil {
//	    span.RecordError(err)
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:161 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (s *Span) RecordError(err error) {
	if s == nil || err == nil {
		return
	}
	msg := err.Error()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	s.status = StatusError
	s.statusMsg = msg
	s.attrs = append(s.attrs, StringAttr("error.message", msg))
}

// End completes s, freezes its attributes and status, and enqueues an immutable
// SpanData snapshot into the owning Tracer's bounded ring buffer if s is
// sampled. End never blocks and is safe to call multiple times or on a nil
// receiver.
//
// # Parameters
//
// None.
//
// # Example
//
//	ctx, span := tracer.StartSpan(ctx, "proxy.forward")
//	defer span.End()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/telemetry_test.go:165 (direct call)
//   - internal/telemetry/telemetry_test.go:167 (direct call)
//   - internal/telemetry/telemetry_test.go:169 (direct call)
//   - internal/telemetry/telemetry_test.go:312 (direct call)
//   - internal/telemetry/telemetry_test.go:319 (direct call)
//   - internal/telemetry/telemetry_test.go:369 (direct call)
//   - internal/telemetry/telemetry_test.go:377 (direct call)
//   - internal/telemetry/telemetry_test.go:400 (direct call)
//   - internal/telemetry/telemetry_test.go:531 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func (s *Span) End() {
	if s == nil {
		return
	}
	var endTime time.Time
	if s.tracer != nil {
		endTime = s.tracer.now()
	} else {
		endTime = time.Now()
	}

	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	data := SpanData{
		TraceID:       s.sc.TraceID,
		SpanID:        s.sc.SpanID,
		ParentSpanID:  s.parentID,
		Name:          s.name,
		Kind:          s.kind,
		StartTime:     s.start,
		EndTime:       endTime,
		Attributes:    slices.Clone(s.attrs),
		StatusCode:    s.status,
		StatusMessage: s.statusMsg,
	}
	s.mu.Unlock()

	if s.tracer != nil && s.sc.IsSampled() {
		s.tracer.recordSpan(data)
	}
}

// newTraceID generates a cryptographically random non-zero 16-byte TraceID.
//
// # Parameters
//
// None.
//
// # Returns
//
// A non-zero TraceID.
//
// # Example
//
//	tid := newTraceID()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:433 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func newTraceID() TraceID {
	var id TraceID
	for !id.IsValid() {
		_, _ = rand.Read(id[:])
	}
	return id
}

// newSpanID generates a cryptographically random non-zero 8-byte SpanID.
//
// # Parameters
//
// None.
//
// # Returns
//
// A non-zero SpanID.
//
// # Example
//
//	sid := newSpanID()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:438 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func newSpanID() SpanID {
	var id SpanID
	for !id.IsValid() {
		_, _ = rand.Read(id[:])
	}
	return id
}

// shouldSampleTrace deterministically decides whether a root trace with tid
// should be sampled under rate in [0.0, 1.0].
//
// # Parameters
//
//   - tid: Non-zero 16-byte TraceID.
//   - rate: Configured sampling ratio in [0.0, 1.0].
//
// # Returns
//
// true if the trace should be sampled.
//
// # Example
//
//	sampled := shouldSampleTrace(tid, 0.25)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/telemetry/otlp.go:434 (direct call)
//
// Scope: internal/telemetry (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/telemetry are not exhaustive.
func shouldSampleTrace(tid TraceID, rate float64) bool {
	if rate <= 0 || math.IsNaN(rate) {
		return false
	}
	if rate >= 1 {
		return true
	}
	// Use the lower 64 bits of the cryptographically random TraceID to map
	// uniformly into [0, 1) without locks or global RNG contention.
	v := binary.BigEndian.Uint64(tid[8:])
	threshold := uint64(rate * float64(math.MaxUint64))
	return v < threshold
}
