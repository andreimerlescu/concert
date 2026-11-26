package cache

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Wire frame header constants for the concert-cache v1 binary protocol.
const (
	FrameMagic0     byte = 0xCC
	FrameMagic1     byte = 0x01
	FrameHeaderSize int  = 8

	maxAuthPayloadBytes = 4 << 10
	maxErrMsgBytes      = 512
	statsPayloadBytes   = 10 * 8
)

// Request opcodes sent from Client to Server.
const (
	OpAuth        byte = 0x01
	OpPing        byte = 0x02
	OpGet         byte = 0x03
	OpPut         byte = 0x04
	OpPurgeURL    byte = 0x05
	OpPurgePrefix byte = 0x06
	OpPurgeTag    byte = 0x07
	OpPurgeAll    byte = 0x08
	OpStats       byte = 0x09
)

// Response opcodes sent from Server to Client.
const (
	RespOK   byte = 0x80
	RespHit  byte = 0x81
	RespMiss byte = 0x82
	RespErr  byte = 0x83
)

// Structured wire error codes embedded as the first byte of RespErr payloads.
const (
	ErrCodeInternal     byte = 1
	ErrCodeBadRequest   byte = 2
	ErrCodeUnauthorized byte = 3
	ErrCodeTooLarge     byte = 4
	ErrCodeTooManyConns byte = 5
)

// Frame is a decoded binary wire frame with opcode, flags, and bounded payload.
type Frame struct {
	Op      byte
	Flags   byte
	Payload []byte
}

// WriteFrame serializes a single protocol frame to w while enforcing maxFrame.
//
// # Parameters
//
//   - w: Destination writer (typically a buffered net.Conn writer). Must be non-nil.
//   - op: Request or response opcode byte.
//   - flags: Reserved flag bits (currently 0).
//   - payload: Optional frame payload; length must not exceed maxFrame.
//   - maxFrame: Maximum allowed payload length; values <= 0 default to MaxFrameBytes.
//
// # Returns
//
// nil on full write, ErrFrameTooLarge if payload exceeds maxFrame, or the
// underlying writer error.
//
// # Example
//
//	err := cache.WriteFrame(buf, cache.OpPing, 0, nil, cache.MaxFrameBytes)
//	if err != nil {
//	    return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:593 (function value)
//   - internal/cache/cache_test.go:750 (function value)
//   - internal/cache/cache_test.go:1037 (function value)
//   - internal/cache/client.go:787 (function value)
//   - internal/cache/fuzz_test.go:41 (function value)
//   - internal/cache/fuzz_test.go:54 (function value)
//   - internal/cache/fuzz_test.go:61 (function value)
//   - internal/cache/fuzz_test.go:65 (function value)
//   - internal/cache/fuzz_test.go:69 (function value)
//   - internal/cache/fuzz_test.go:90 (function value)
//   - internal/cache/server.go:405 (function value)
//   - internal/cache/server.go:956 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func WriteFrame(w io.Writer, op, flags byte, payload []byte, maxFrame int) error {
	if w == nil {
		return fmt.Errorf("%w: nil writer", ErrProtocol)
	}
	limit := clampMaxFrame(maxFrame)
	if len(payload) > limit {
		return fmt.Errorf("%w: payload %d exceeds %d", ErrFrameTooLarge, len(payload), limit)
	}

	var hdr [FrameHeaderSize]byte
	hdr[0] = FrameMagic0
	hdr[1] = FrameMagic1
	hdr[2] = op
	hdr[3] = flags
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload)))

	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrame reads and validates a single protocol frame from r, rejecting
// invalid magic bytes and payloads larger than maxFrame before allocating.
//
// # Parameters
//
//   - r: Source reader (typically a buffered net.Conn reader). Must be non-nil.
//   - maxFrame: Maximum allowed payload length; values <= 0 default to MaxFrameBytes.
//
// # Returns
//
// The decoded Frame on success, io.EOF when cleanly closed at a frame boundary,
// ErrFrameTooLarge when the declared payload exceeds maxFrame, or ErrProtocol
// on malformed magic or truncated reads.
//
// # Example
//
//	fr, err := cache.ReadFrame(buf, cache.MaxFrameBytes)
//	if err != nil {
//	    return err
//	}
//	_ = fr
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:594 (function value)
//   - internal/cache/cache_test.go:753 (function value)
//   - internal/cache/cache_test.go:771 (function value)
//   - internal/cache/cache_test.go:1046 (function value)
//   - internal/cache/cache_test.go:1051 (function value)
//   - internal/cache/client.go:793 (function value)
//   - internal/cache/fuzz_test.go:80 (function value)
//   - internal/cache/fuzz_test.go:93 (function value)
//   - internal/cache/server.go:749 (function value)
//   - internal/cache/server.go:772 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func ReadFrame(r io.Reader, maxFrame int) (Frame, error) {
	if r == nil {
		return Frame{}, fmt.Errorf("%w: nil reader", ErrProtocol)
	}
	limit := clampMaxFrame(maxFrame)

	var hdr [FrameHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	if hdr[0] != FrameMagic0 || hdr[1] != FrameMagic1 {
		return Frame{}, fmt.Errorf("%w: invalid frame magic 0x%02x%02x", ErrProtocol, hdr[0], hdr[1])
	}
	payloadLen := binary.BigEndian.Uint32(hdr[4:8])
	// Enforce the frame cap strictly before allocating the payload slice so a
	// hostile peer cannot trigger an unbounded allocation.
	if uint64(payloadLen) > uint64(limit) {
		return Frame{}, fmt.Errorf("%w: declared length %d exceeds %d", ErrFrameTooLarge, payloadLen, limit)
	}

	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			if errors.Is(err, io.EOF) {
				return Frame{}, fmt.Errorf("%w: truncated frame payload", ErrProtocol)
			}
			return Frame{}, err
		}
	}
	return Frame{
		Op:      hdr[2],
		Flags:   hdr[3],
		Payload: payload,
	}, nil
}

// EncodeEntry serializes e into the binary payload format used by OpPut and
// RespHit, validating all field size limits before encoding.
//
// # Parameters
//
//   - e: Entry to encode. Key must be non-empty and <= MaxKeyBytes.
//
// # Returns
//
// Encoded payload bytes, or an error matching ErrInvalidKey, ErrEntryTooLarge,
// ErrTooManyTags, ErrInvalidTag, or ErrInvalidTTL.
//
// # Example
//
//	raw, err := cache.EncodeEntry(entry)
//	if err != nil {
//	    return err
//	}
//	_ = raw
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:369 (function value)
//   - internal/cache/fuzz_test.go:45 (function value)
//   - internal/cache/fuzz_test.go:104 (function value)
//   - internal/cache/server.go:847 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func EncodeEntry(e Entry) ([]byte, error) {
	if e.Key == "" || len(e.Key) > MaxKeyBytes {
		return nil, ErrInvalidKey
	}
	host := normalizeHost(e.Host)
	path := e.Path
	if host == "" || path == "" {
		ph, pp := ParseCanonicalKey(e.Key)
		if host == "" {
			host = ph
		}
		if path == "" {
			path = pp
		}
	}
	if len(host) > MaxHostBytes || len(path) > MaxPathBytes {
		return nil, ErrInvalidKey
	}
	if e.Status < 0 || e.Status > 999 {
		return nil, fmt.Errorf("%w: invalid HTTP status %d", ErrProtocol, e.Status)
	}
	if e.TTL < 0 {
		return nil, ErrInvalidTTL
	}
	hdrs, _, err := cloneAndMeasureHeaders(e.Headers)
	if err != nil {
		return nil, err
	}
	tags, _, err := normalizeTags(e.Tags)
	if err != nil {
		return nil, err
	}
	if len(e.Body) > MaxFrameBytes {
		return nil, ErrEntryTooLarge
	}

	// Pre-size buffer conservatively to avoid repeated reallocations.
	est := 64 + len(e.Key) + len(host) + len(path) + len(e.Body)
	buf := make([]byte, 0, est)

	buf = appendLenStr16(buf, e.Key)
	buf = appendLenStr16(buf, host)
	buf = appendLenStr16(buf, path)
	buf = binary.BigEndian.AppendUint16(buf, uint16(e.Status))
	buf = binary.BigEndian.AppendUint64(buf, uint64(e.TTL.Nanoseconds()))
	var storedNano, expiresNano int64
	if !e.StoredAt.IsZero() {
		storedNano = e.StoredAt.UTC().UnixNano()
	}
	if !e.ExpiresAt.IsZero() {
		expiresNano = e.ExpiresAt.UTC().UnixNano()
	}
	buf = binary.BigEndian.AppendUint64(buf, uint64(storedNano))
	buf = binary.BigEndian.AppendUint64(buf, uint64(expiresNano))

	buf = binary.BigEndian.AppendUint16(buf, uint16(len(hdrs)))
	for k, vals := range hdrs {
		buf = appendLenStr16(buf, k)
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(vals)))
		for _, v := range vals {
			buf = appendLenStr16(buf, v)
		}
	}

	buf = binary.BigEndian.AppendUint16(buf, uint16(len(tags)))
	for _, tag := range tags {
		buf = appendLenStr16(buf, tag)
	}

	buf = binary.BigEndian.AppendUint32(buf, uint32(len(e.Body)))
	buf = append(buf, e.Body...)

	if len(buf) > MaxFrameBytes {
		return nil, ErrFrameTooLarge
	}
	return buf, nil
}

// DecodeEntry parses a binary entry payload while enforcing strict bounds on
// key, host, path, headers, tags, and body length, rejecting any trailing data.
//
// # Parameters
//
//   - data: Wire payload bytes produced by EncodeEntry.
//   - maxBodyBytes: Maximum allowed body size; values <= 0 default to
//     DefaultMaxEntryBytes and are capped at MaxFrameBytes.
//
// # Returns
//
// Decoded Entry or a validation/protocol error (ErrProtocol, ErrInvalidKey,
// ErrEntryTooLarge, ErrTooManyTags, ErrInvalidTag, ErrInvalidTTL).
//
// # Example
//
//	ent, err := cache.DecodeEntry(payload, cache.DefaultMaxEntryBytes)
//	if err != nil {
//	    return err
//	}
//	_ = ent
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:314 (function value)
//   - internal/cache/fuzz_test.go:103 (function value)
//   - internal/cache/fuzz_test.go:108 (function value)
//   - internal/cache/server.go:854 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func DecodeEntry(data []byte, maxBodyBytes int) (Entry, error) {
	if maxBodyBytes <= 0 {
		maxBodyBytes = int(DefaultMaxEntryBytes)
	}
	if maxBodyBytes > MaxFrameBytes {
		maxBodyBytes = MaxFrameBytes
	}

	r := byteReader{b: data}
	key, err := r.readStr16(MaxKeyBytes)
	if err != nil {
		return Entry{}, err
	}
	if key == "" {
		return Entry{}, ErrInvalidKey
	}
	host, err := r.readStr16(MaxHostBytes)
	if err != nil {
		return Entry{}, err
	}
	path, err := r.readStr16(MaxPathBytes)
	if err != nil {
		return Entry{}, err
	}
	statusU16, err := r.readUint16()
	if err != nil {
		return Entry{}, err
	}
	if statusU16 > 999 {
		return Entry{}, fmt.Errorf("%w: invalid HTTP status %d", ErrProtocol, statusU16)
	}
	ttlRaw, err := r.readUint64()
	if err != nil {
		return Entry{}, err
	}
	ttl := time.Duration(int64(ttlRaw))
	if ttl < 0 {
		return Entry{}, ErrInvalidTTL
	}
	storedRaw, err := r.readUint64()
	if err != nil {
		return Entry{}, err
	}
	expiresRaw, err := r.readUint64()
	if err != nil {
		return Entry{}, err
	}

	hdrCount, err := r.readUint16()
	if err != nil {
		return Entry{}, err
	}
	if int(hdrCount) > MaxHeaderCount {
		return Entry{}, fmt.Errorf("%w: header count %d exceeds %d", ErrEntryTooLarge, hdrCount, MaxHeaderCount)
	}
	var hdrs http.Header
	if hdrCount > 0 {
		hdrs = make(http.Header, hdrCount)
		hdrBytes := 0
		for i := 0; i < int(hdrCount); i++ {
			hk, err := r.readStr16(MaxHeaderBytes)
			if err != nil {
				return Entry{}, err
			}
			vc, err := r.readUint16()
			if err != nil {
				return Entry{}, err
			}
			if int(vc) > MaxHeaderValues {
				return Entry{}, fmt.Errorf("%w: header value count %d exceeds %d", ErrEntryTooLarge, vc, MaxHeaderValues)
			}
			vals := make([]string, 0, vc)
			for j := 0; j < int(vc); j++ {
				hv, err := r.readStr16(MaxHeaderBytes)
				if err != nil {
					return Entry{}, err
				}
				hdrBytes += len(hk) + len(hv) + 4
				if hdrBytes > MaxHeaderBytes {
					return Entry{}, fmt.Errorf("%w: headers exceed %d bytes", ErrEntryTooLarge, MaxHeaderBytes)
				}
				vals = append(vals, hv)
			}
			hdrs[hk] = vals
		}
	}

	tagCount, err := r.readUint16()
	if err != nil {
		return Entry{}, err
	}
	if int(tagCount) > MaxTagsPerEntry {
		return Entry{}, fmt.Errorf("%w: tag count %d exceeds %d", ErrTooManyTags, tagCount, MaxTagsPerEntry)
	}
	var tags []string
	if tagCount > 0 {
		rawTags := make([]string, 0, tagCount)
		for i := 0; i < int(tagCount); i++ {
			t, err := r.readStr16(MaxTagBytes)
			if err != nil {
				return Entry{}, err
			}
			rawTags = append(rawTags, t)
		}
		tags, _, err = normalizeTags(rawTags)
		if err != nil {
			return Entry{}, err
		}
	}

	bodyLen, err := r.readUint32()
	if err != nil {
		return Entry{}, err
	}
	if uint64(bodyLen) > uint64(maxBodyBytes) {
		return Entry{}, fmt.Errorf("%w: body %d exceeds %d", ErrEntryTooLarge, bodyLen, maxBodyBytes)
	}
	body, err := r.readBytes(int(bodyLen))
	if err != nil {
		return Entry{}, err
	}
	if r.remaining() != 0 {
		return Entry{}, fmt.Errorf("%w: %d trailing bytes in entry", ErrProtocol, r.remaining())
	}

	var storedAt, expiresAt time.Time
	if storedNano := int64(storedRaw); storedNano > 0 {
		storedAt = time.Unix(0, storedNano).UTC()
	}
	if expiresNano := int64(expiresRaw); expiresNano > 0 {
		expiresAt = time.Unix(0, expiresNano).UTC()
	}

	return Entry{
		Key:       key,
		Host:      normalizeHost(host),
		Path:      path,
		Status:    int(statusU16),
		Headers:   hdrs,
		Body:      append([]byte(nil), body...),
		Tags:      tags,
		StoredAt:  storedAt,
		ExpiresAt: expiresAt,
		TTL:       ttl,
	}, nil
}

// EncodePurgePair encodes a (host, pathOrPrefix) pair for OpPurgeURL and
// OpPurgePrefix requests.
//
// # Parameters
//
//   - host: Optional host filter (<= MaxHostBytes).
//   - target: Exact path or path prefix (<= MaxPathBytes).
//
// # Returns
//
// Encoded bytes or ErrInvalidKey when bounds are exceeded.
//
// # Example
//
//	raw, err := cache.EncodePurgePair("example.com", "/blog/")
//	_, _ = raw, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:421 (function value)
//   - internal/cache/client.go:456 (function value)
//   - internal/cache/fuzz_test.go:59 (function value)
//   - internal/cache/fuzz_test.go:118 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func EncodePurgePair(host, target string) ([]byte, error) {
	if len(host) > MaxHostBytes || len(target) > MaxPathBytes {
		return nil, ErrInvalidKey
	}
	buf := make([]byte, 0, 4+len(host)+len(target))
	buf = appendLenStr16(buf, host)
	buf = appendLenStr16(buf, target)
	return buf, nil
}

// DecodePurgePair decodes a (host, pathOrPrefix) payload and rejects trailing
// or oversized fields.
//
// # Parameters
//
//   - data: Wire payload bytes produced by EncodePurgePair.
//
// # Returns
//
// (host, target, err).
//
// # Example
//
//	host, target, err := cache.DecodePurgePair(payload)
//	_, _, _ = host, target, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/fuzz_test.go:117 (function value)
//   - internal/cache/fuzz_test.go:122 (function value)
//   - internal/cache/server.go:864 (function value)
//   - internal/cache/server.go:875 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func DecodePurgePair(data []byte) (string, string, error) {
	r := byteReader{b: data}
	host, err := r.readStr16(MaxHostBytes)
	if err != nil {
		return "", "", err
	}
	target, err := r.readStr16(MaxPathBytes)
	if err != nil {
		return "", "", err
	}
	if r.remaining() != 0 {
		return "", "", fmt.Errorf("%w: %d trailing bytes in purge pair", ErrProtocol, r.remaining())
	}
	return host, target, nil
}

// EncodeUint64 encodes v as an 8-byte big-endian payload.
//
// # Parameters
//
//   - v: Unsigned 64-bit integer to encode.
//
// # Returns
//
// An 8-byte slice representing v.
//
// # Example
//
//	raw := cache.EncodeUint64(42)
//	_ = raw
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/fuzz_test.go:136 (function value)
//   - internal/cache/server.go:872 (function value)
//   - internal/cache/server.go:883 (function value)
//   - internal/cache/server.go:893 (function value)
//   - internal/cache/server.go:903 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func EncodeUint64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// DecodeUint64 decodes an exact 8-byte big-endian unsigned integer payload.
//
// # Parameters
//
//   - data: Payload bytes; must be exactly 8 bytes long.
//
// # Returns
//
// The decoded uint64 or ErrProtocol if len(data) != 8.
//
// # Example
//
//	n, err := cache.DecodeUint64(payload)
//	_, _ = n, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:670 (function value)
//   - internal/cache/fuzz_test.go:135 (function value)
//   - internal/cache/fuzz_test.go:136 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func DecodeUint64(data []byte) (uint64, error) {
	if len(data) != 8 {
		return 0, fmt.Errorf("%w: expected 8-byte uint64, got %d", ErrProtocol, len(data))
	}
	return binary.BigEndian.Uint64(data), nil
}

// EncodeStats serializes s into a fixed 80-byte big-endian payload.
//
// # Parameters
//
//   - s: Stats snapshot to encode.
//
// # Returns
//
// An 80-byte wire payload.
//
// # Example
//
//	raw := cache.EncodeStats(stats)
//	_ = raw
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/fuzz_test.go:65 (function value)
//   - internal/cache/fuzz_test.go:129 (function value)
//   - internal/cache/server.go:913 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func EncodeStats(s Stats) []byte {
	buf := make([]byte, statsPayloadBytes)
	binary.BigEndian.PutUint64(buf[0:8], uint64(s.Entries))
	binary.BigEndian.PutUint64(buf[8:16], uint64(s.UsedBytes))
	binary.BigEndian.PutUint64(buf[16:24], uint64(s.MaxBytes))
	binary.BigEndian.PutUint64(buf[24:32], uint64(s.Hits))
	binary.BigEndian.PutUint64(buf[32:40], uint64(s.Misses))
	binary.BigEndian.PutUint64(buf[40:48], uint64(s.Evictions))
	binary.BigEndian.PutUint64(buf[48:56], uint64(s.Purges))
	binary.BigEndian.PutUint64(buf[56:64], uint64(s.Coalesced))
	binary.BigEndian.PutUint64(buf[64:72], uint64(s.Tags))
	binary.BigEndian.PutUint64(buf[72:80], uint64(s.Shards))
	return buf
}

// DecodeStats parses an exact 80-byte Stats wire payload.
//
// # Parameters
//
//   - data: Payload bytes; must be exactly 80 bytes.
//
// # Returns
//
// Decoded Stats or ErrProtocol if len(data) != 80.
//
// # Example
//
//	st, err := cache.DecodeStats(payload)
//	_, _ = st, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:555 (function value)
//   - internal/cache/fuzz_test.go:128 (function value)
//   - internal/cache/fuzz_test.go:129 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func DecodeStats(data []byte) (Stats, error) {
	if len(data) != statsPayloadBytes {
		return Stats{}, fmt.Errorf("%w: expected %d-byte stats, got %d", ErrProtocol, statsPayloadBytes, len(data))
	}
	return Stats{
		Entries:   int64(binary.BigEndian.Uint64(data[0:8])),
		UsedBytes: int64(binary.BigEndian.Uint64(data[8:16])),
		MaxBytes:  int64(binary.BigEndian.Uint64(data[16:24])),
		Hits:      int64(binary.BigEndian.Uint64(data[24:32])),
		Misses:    int64(binary.BigEndian.Uint64(data[32:40])),
		Evictions: int64(binary.BigEndian.Uint64(data[40:48])),
		Purges:    int64(binary.BigEndian.Uint64(data[48:56])),
		Coalesced: int64(binary.BigEndian.Uint64(data[56:64])),
		Tags:      int64(binary.BigEndian.Uint64(data[64:72])),
		Shards:    int(binary.BigEndian.Uint64(data[72:80])),
	}, nil
}

// EncodeError builds a bounded RespErr payload containing a machine error code
// and a short non-sensitive diagnostic message.
//
// # Parameters
//
//   - code: One of ErrCode*.
//   - msg: Diagnostic string (truncated to 512 bytes; must never contain secrets).
//
// # Returns
//
// Encoded RespErr payload bytes.
//
// # Example
//
//	raw := cache.EncodeError(cache.ErrCodeUnauthorized, "unauthorized")
//	_ = raw
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/fuzz_test.go:69 (function value)
//   - internal/cache/server.go:405 (function value)
//   - internal/cache/server.go:752 (function value)
//   - internal/cache/server.go:758 (function value)
//   - internal/cache/server.go:779 (function value)
//   - internal/cache/server.go:781 (function value)
//   - internal/cache/server.go:826 (function value)
//   - internal/cache/server.go:832 (function value)
//   - internal/cache/server.go:838 (function value)
//   - internal/cache/server.go:849 (function value)
//   - internal/cache/server.go:887 (function value)
//   - internal/cache/server.go:897 (function value)
//   - internal/cache/server.go:907 (function value)
//   - internal/cache/server.go:916 (function value)
//   - internal/cache/server.go:998 (function value)
//   - internal/cache/server.go:1002 (function value)
//   - internal/cache/server.go:1004 (function value)
//   - internal/cache/server.go:1006 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func EncodeError(code byte, msg string) []byte {
	if len(msg) > maxErrMsgBytes {
		msg = msg[:maxErrMsgBytes]
	}
	buf := make([]byte, 1+len(msg))
	buf[0] = code
	copy(buf[1:], msg)
	return buf
}

// DecodeError converts a RespErr payload back into a Go error wrapping the
// matching sentinel error where applicable.
//
// # Parameters
//
//   - data: RespErr payload bytes (must be at least 1 byte).
//
// # Returns
//
// A non-nil error matching ErrUnauthorized, ErrEntryTooLarge, ErrTooManyConns,
// or ErrProtocol as appropriate.
//
// # Example
//
//	err := cache.DecodeError(frame.Payload)
//	_ = err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/cache_test.go:596 (function value)
//   - internal/cache/cache_test.go:772 (function value)
//   - internal/cache/client.go:801 (function value)
//   - internal/cache/fuzz_test.go:142 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func DecodeError(data []byte) error {
	if len(data) == 0 {
		return ErrProtocol
	}
	code := data[0]
	msg := string(data[1:])
	if len(msg) > maxErrMsgBytes {
		msg = msg[:maxErrMsgBytes]
	}
	switch code {
	case ErrCodeUnauthorized:
		if msg == "" {
			return ErrUnauthorized
		}
		return fmt.Errorf("%w: %s", ErrUnauthorized, msg)
	case ErrCodeTooLarge:
		if msg == "" {
			return ErrEntryTooLarge
		}
		return fmt.Errorf("%w: %s", ErrEntryTooLarge, msg)
	case ErrCodeTooManyConns:
		if msg == "" {
			return ErrTooManyConns
		}
		return fmt.Errorf("%w: %s", ErrTooManyConns, msg)
	case ErrCodeBadRequest:
		if msg == "" {
			return ErrProtocol
		}
		return fmt.Errorf("%w: %s", ErrProtocol, msg)
	default:
		if msg == "" {
			return errors.New("cache server internal error")
		}
		return fmt.Errorf("cache server error: %s", msg)
	}
}

// clampMaxFrame returns a bounded frame payload ceiling in [1, MaxFrameBytes].
//
// # Parameters
//
//   - maxFrame: Caller-supplied frame limit.
//
// # Returns
//
// Effective limit in bytes.
//
// # Example
//
//	lim := clampMaxFrame(0) // MaxFrameBytes
//	_ = lim
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/client.go:213 (function value)
//   - internal/cache/protocol.go:106 (function value)
//   - internal/cache/protocol.go:173 (function value)
//   - internal/cache/server.go:141 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func clampMaxFrame(maxFrame int) int {
	if maxFrame <= 0 || maxFrame > MaxFrameBytes {
		return MaxFrameBytes
	}
	return maxFrame
}

// appendLenStr16 appends a 2-byte big-endian length prefix followed by s to dst.
//
// # Parameters
//
//   - dst: Destination byte slice.
//   - s: String whose length must fit in uint16.
//
// # Returns
//
// Extended byte slice.
//
// # Example
//
//	out := appendLenStr16(nil, "example.com")
//	_ = out
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/protocol.go:278 (function value)
//   - internal/cache/protocol.go:279 (function value)
//   - internal/cache/protocol.go:280 (function value)
//   - internal/cache/protocol.go:295 (function value)
//   - internal/cache/protocol.go:298 (function value)
//   - internal/cache/protocol.go:304 (function value)
//   - internal/cache/protocol.go:531 (function value)
//   - internal/cache/protocol.go:532 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func appendLenStr16(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(s)))
	return append(dst, s...)
}

type byteReader struct {
	b   []byte
	off int
}

// remaining reports unread bytes in r.
//
// # Parameters
//
// None.
//
// # Returns
//
// Number of unread bytes.
//
// # Example
//
//	rem := r.remaining()
//	_ = rem
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/protocol.go:471 (function value)
//   - internal/cache/protocol.go:472 (function value)
//   - internal/cache/protocol.go:574 (function value)
//   - internal/cache/protocol.go:575 (function value)
//   - internal/cache/protocol.go:993 (function value)
//   - internal/cache/protocol.go:1026 (function value)
//   - internal/cache/protocol.go:1061 (function value)
//   - internal/cache/protocol.go:1095 (function value)
//   - internal/cache/protocol.go:1096 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (r *byteReader) remaining() int {
	return len(r.b) - r.off
}

// readUint16 reads a big-endian uint16 from r.
//
// # Parameters
//
// None.
//
// # Returns
//
// Decoded uint16 or ErrProtocol if fewer than 2 bytes remain.
//
// # Example
//
//	v, err := r.readUint16()
//	_, _ = v, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/protocol.go:374 (function value)
//   - internal/cache/protocol.go:398 (function value)
//   - internal/cache/protocol.go:414 (function value)
//   - internal/cache/protocol.go:437 (function value)
//   - internal/cache/protocol.go:1136 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (r *byteReader) readUint16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, fmt.Errorf("%w: unexpected EOF reading uint16", ErrProtocol)
	}
	v := binary.BigEndian.Uint16(r.b[r.off : r.off+2])
	r.off += 2
	return v, nil
}

// readUint32 reads a big-endian uint32 from r.
//
// # Parameters
//
// None.
//
// # Returns
//
// Decoded uint32 or ErrProtocol if fewer than 4 bytes remain.
//
// # Example
//
//	v, err := r.readUint32()
//	_, _ = v, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/protocol.go:460 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (r *byteReader) readUint32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, fmt.Errorf("%w: unexpected EOF reading uint32", ErrProtocol)
	}
	v := binary.BigEndian.Uint32(r.b[r.off : r.off+4])
	r.off += 4
	return v, nil
}

// readUint64 reads a big-endian uint64 from r.
//
// # Parameters
//
// None.
//
// # Returns
//
// Decoded uint64 or ErrProtocol if fewer than 8 bytes remain.
//
// # Example
//
//	v, err := r.readUint64()
//	_, _ = v, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/protocol.go:381 (function value)
//   - internal/cache/protocol.go:389 (function value)
//   - internal/cache/protocol.go:393 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (r *byteReader) readUint64() (uint64, error) {
	if r.remaining() < 8 {
		return 0, fmt.Errorf("%w: unexpected EOF reading uint64", ErrProtocol)
	}
	v := binary.BigEndian.Uint64(r.b[r.off : r.off+8])
	r.off += 8
	return v, nil
}

// readBytes slices n bytes from r without exceeding the underlying buffer.
//
// # Parameters
//
//   - n: Exact byte count to read; must be >= 0.
//
// # Returns
//
// Borrowed subslice of length n, or ErrProtocol if insufficient bytes remain.
//
// # Example
//
//	raw, err := r.readBytes(16)
//	_, _ = raw, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/protocol.go:467 (function value)
//   - internal/cache/protocol.go:1143 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (r *byteReader) readBytes(n int) ([]byte, error) {
	if n < 0 || r.remaining() < n {
		return nil, fmt.Errorf("%w: truncated payload (need %d, have %d)", ErrProtocol, n, r.remaining())
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out, nil
}

// readStr16 reads a uint16-prefixed string bounded by maxLen bytes.
//
// # Parameters
//
//   - maxLen: Maximum allowed string byte length.
//
// # Returns
//
// Decoded string, or ErrEntryTooLarge/ErrProtocol if length exceeds maxLen or
// the payload is truncated.
//
// # Example
//
//	s, err := r.readStr16(MaxKeyBytes)
//	_, _ = s, err
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/cache/protocol.go:359 (function value)
//   - internal/cache/protocol.go:366 (function value)
//   - internal/cache/protocol.go:370 (function value)
//   - internal/cache/protocol.go:410 (function value)
//   - internal/cache/protocol.go:423 (function value)
//   - internal/cache/protocol.go:448 (function value)
//   - internal/cache/protocol.go:566 (function value)
//   - internal/cache/protocol.go:570 (function value)
//
// Scope: internal/cache, internal/microcache, cmd/concert-cache (including tests),
// plus internal/server/fcgi_bridge.go; darwin/arm64, default build tags.
// Interface-dispatched, runtime, and external callers are not exhaustive.
func (r *byteReader) readStr16(maxLen int) (string, error) {
	n, err := r.readUint16()
	if err != nil {
		return "", err
	}
	if int(n) > maxLen {
		return "", fmt.Errorf("%w: string length %d exceeds %d", ErrEntryTooLarge, n, maxLen)
	}
	raw, err := r.readBytes(int(n))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
