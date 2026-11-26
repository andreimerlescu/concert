package kv

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Default protocol size bounds applied when ProtocolLimits fields are zero.
// These limits prevent untrusted peers from triggering unbounded allocations
// or deep recursion (R3).
const (
	DefaultMaxBulkBytes = 4 << 20 // 4 MiB per bulk string
	DefaultMaxArrayLen  = 1024    // 1024 elements per array
	DefaultMaxLineBytes = 64 << 10
	DefaultMaxNesting   = 8
)

// Sentinel errors returned by RESP2 parsing and encoding routines.
var (
	ErrProtocol       = errors.New("resp2 protocol error")
	ErrBulkTooLarge   = errors.New("resp2 bulk string exceeds limit")
	ErrArrayTooLarge  = errors.New("resp2 array length exceeds limit")
	ErrLineTooLong    = errors.New("resp2 line exceeds limit")
	ErrNestingTooDeep = errors.New("resp2 array nesting exceeds limit")
	ErrEmptyCommand   = errors.New("resp2 empty command")
)

// ProtocolLimits bounds memory and recursion during RESP2 parsing. Zero fields
// fall back to DefaultMaxBulkBytes, DefaultMaxArrayLen, DefaultMaxLineBytes,
// and DefaultMaxNesting.
type ProtocolLimits struct {
	MaxBulkBytes int
	MaxArrayLen  int
	MaxLineBytes int
	MaxNesting   int
}

// effective returns a copy of p with any non-positive bounds replaced by safe
// defaults.
//
// # Parameters
//
// None.
//
// # Returns
//
// A ProtocolLimits value with every bound strictly positive.
//
// # Example
//
//	lim := (ProtocolLimits{}).effective()
func (p ProtocolLimits) effective() ProtocolLimits {
	if p.MaxBulkBytes <= 0 {
		p.MaxBulkBytes = DefaultMaxBulkBytes
	}
	if p.MaxArrayLen <= 0 {
		p.MaxArrayLen = DefaultMaxArrayLen
	}
	if p.MaxLineBytes <= 0 {
		p.MaxLineBytes = DefaultMaxLineBytes
	}
	if p.MaxNesting <= 0 {
		p.MaxNesting = DefaultMaxNesting
	}
	return p
}

// ValueKind discriminates the wire type of a RESP2 Value.
type ValueKind uint8

const (
	KindNull ValueKind = iota
	KindSimpleString
	KindError
	KindInteger
	KindBulkString
	KindArray
)

// Value represents a single RESP2 value. Callers own the Str, Bulk, and Array
// fields after ReadValue returns; WriteValue reads Value without mutating it.
type Value struct {
	Kind  ValueKind
	Str   string
	Int   int64
	Bulk  []byte
	Array []Value
}

// SimpleString constructs a RESP2 simple string Value (`+s\r\n`).
//
// # Parameters
//
//   - s: Simple string content; must not contain CR or LF.
//
// # Returns
//
// A Value with KindSimpleString.
//
// # Example
//
//	v := kv.SimpleString("OK")
func SimpleString(s string) Value {
	return Value{Kind: KindSimpleString, Str: s}
}

// ErrorValue constructs a RESP2 error Value (`-msg\r\n`).
//
// # Parameters
//
//   - msg: Error message text without leading `-` or trailing CRLF.
//
// # Returns
//
// A Value with KindError.
//
// # Example
//
//	v := kv.ErrorValue("ERR unknown command")
func ErrorValue(msg string) Value {
	return Value{Kind: KindError, Str: msg}
}

// Integer constructs a RESP2 integer Value (`:n\r\n`).
//
// # Parameters
//
//   - n: Signed 64-bit integer payload.
//
// # Returns
//
// A Value with KindInteger.
//
// # Example
//
//	v := kv.Integer(1)
func Integer(n int64) Value {
	return Value{Kind: KindInteger, Int: n}
}

// BulkString constructs a RESP2 bulk string Value (`$len\r\n<bytes>\r\n`).
//
// # Parameters
//
//   - b: Payload bytes; stored directly (caller should not mutate after sharing).
//
// # Returns
//
// A Value with KindBulkString.
//
// # Example
//
//	v := kv.BulkString([]byte("value"))
func BulkString(b []byte) Value {
	if b == nil {
		b = []byte{}
	}
	return Value{Kind: KindBulkString, Bulk: b}
}

// BulkFromString constructs a RESP2 bulk string Value from a Go string.
//
// # Parameters
//
//   - s: Payload text.
//
// # Returns
//
// A Value with KindBulkString containing the UTF-8 bytes of s.
//
// # Example
//
//	v := kv.BulkFromString("PONG")
func BulkFromString(s string) Value {
	return Value{Kind: KindBulkString, Bulk: []byte(s)}
}

// NullBulk constructs a RESP2 null bulk string Value (`$-1\r\n`).
//
// # Parameters
//
// None.
//
// # Returns
//
// A Value with KindNull.
//
// # Example
//
//	v := kv.NullBulk()
func NullBulk() Value {
	return Value{Kind: KindNull}
}

// ArrayValue constructs a RESP2 array Value (`*len\r\n...`).
//
// # Parameters
//
//   - elems: Slice of child RESP2 values; nil encodes as an empty array `*0\r\n`.
//
// # Returns
//
// A Value with KindArray.
//
// # Example
//
//	v := kv.ArrayValue(kv.BulkFromString("PING"))
func ArrayValue(elems ...Value) Value {
	if elems == nil {
		elems = []Value{}
	}
	return Value{Kind: KindArray, Array: elems}
}

// StringBytes returns the payload bytes of a simple or bulk string Value.
//
// # Parameters
//
// None.
//
// # Returns
//
// The string bytes and true for KindBulkString or KindSimpleString; nil and
// false for other kinds (including KindNull).
//
// # Example
//
//	if b, ok := v.StringBytes(); ok {
//	    fmt.Println(string(b))
//	}
func (v Value) StringBytes() ([]byte, bool) {
	switch v.Kind {
	case KindBulkString:
		return v.Bulk, true
	case KindSimpleString:
		return []byte(v.Str), true
	default:
		return nil, false
	}
}

// AsString returns the string representation of a simple or bulk string Value.
//
// # Parameters
//
// None.
//
// # Returns
//
// The string text and true for KindBulkString or KindSimpleString; "" and
// false for other kinds.
//
// # Example
//
//	if s, ok := v.AsString(); ok {
//	    fmt.Println(s)
//	}
func (v Value) AsString() (string, bool) {
	switch v.Kind {
	case KindBulkString:
		return string(v.Bulk), true
	case KindSimpleString:
		return v.Str, true
	default:
		return "", false
	}
}

// ReadValue parses one RESP2 value from r enforcing limits. It supports simple
// strings (+), errors (-), integers (:), bulk strings ($), arrays (*), and
// null bulk/array markers ($-1, *-1). It does not close r and is not safe for
// concurrent calls on the same *bufio.Reader.
//
// # Parameters
//
//   - r: Buffered reader positioned at the start of a RESP2 frame; must be non-nil.
//   - limits: Maximum bulk size, array length, line length, and nesting depth.
//
// # Returns
//
// The decoded Value on success. On EOF before any byte is read, returns io.EOF.
// Malformed frames or limit violations return an error matching ErrProtocol,
// ErrBulkTooLarge, ErrArrayTooLarge, ErrLineTooLong, or ErrNestingTooDeep.
//
// # Example
//
//	r := bufio.NewReader(strings.NewReader("+PONG\r\n"))
//	val, err := kv.ReadValue(r, kv.ProtocolLimits{})
//	if err != nil {
//	    return err
//	}
//	fmt.Println(val.Str) // PONG
func ReadValue(r *bufio.Reader, limits ProtocolLimits) (Value, error) {
	if r == nil {
		return Value{}, fmt.Errorf("%w: nil reader", ErrProtocol)
	}
	return readValueDepth(r, limits.effective(), 0)
}

// readValueDepth parses a RESP2 value while tracking array recursion depth to
// guard against stack exhaustion on maliciously nested frames.
//
// # Parameters
//
//   - r: Buffered reader for the wire stream.
//   - limits: Normalized positive ProtocolLimits.
//   - depth: Current array nesting depth (0 at top level).
//
// # Returns
//
// Decoded Value or a protocol/I/O error.
//
// # Example
//
//	v, err := readValueDepth(r, limits.effective(), 0)
func readValueDepth(r *bufio.Reader, limits ProtocolLimits, depth int) (Value, error) {
	if depth > limits.MaxNesting {
		return Value{}, ErrNestingTooDeep
	}
	prefix, err := r.ReadByte()
	if err != nil {
		return Value{}, err
	}
	switch prefix {
	case '+':
		line, err := readBoundedCRLFLine(r, limits.MaxLineBytes)
		if err != nil {
			return Value{}, err
		}
		return SimpleString(string(line)), nil
	case '-':
		line, err := readBoundedCRLFLine(r, limits.MaxLineBytes)
		if err != nil {
			return Value{}, err
		}
		return ErrorValue(string(line)), nil
	case ':':
		line, err := readBoundedCRLFLine(r, limits.MaxLineBytes)
		if err != nil {
			return Value{}, err
		}
		n, err := parseStrictInt64(line)
		if err != nil {
			return Value{}, fmt.Errorf("%w: invalid integer: %v", ErrProtocol, err)
		}
		return Integer(n), nil
	case '$':
		line, err := readBoundedCRLFLine(r, limits.MaxLineBytes)
		if err != nil {
			return Value{}, err
		}
		n, err := parseStrictInt64(line)
		if err != nil {
			return Value{}, fmt.Errorf("%w: invalid bulk length: %v", ErrProtocol, err)
		}
		if n == -1 {
			return NullBulk(), nil
		}
		if n < -1 {
			return Value{}, fmt.Errorf("%w: negative bulk length %d", ErrProtocol, n)
		}
		if n > int64(limits.MaxBulkBytes) {
			return Value{}, fmt.Errorf("%w: %d > %d", ErrBulkTooLarge, n, limits.MaxBulkBytes)
		}
		buf := make([]byte, int(n)+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			if errors.Is(err, io.EOF) {
				return Value{}, io.ErrUnexpectedEOF
			}
			return Value{}, err
		}
		if buf[len(buf)-2] != '\r' || buf[len(buf)-1] != '\n' {
			return Value{}, fmt.Errorf("%w: bulk string missing CRLF terminator", ErrProtocol)
		}
		return BulkString(buf[:n]), nil
	case '*':
		line, err := readBoundedCRLFLine(r, limits.MaxLineBytes)
		if err != nil {
			return Value{}, err
		}
		n, err := parseStrictInt64(line)
		if err != nil {
			return Value{}, fmt.Errorf("%w: invalid array length: %v", ErrProtocol, err)
		}
		if n == -1 {
			return NullBulk(), nil
		}
		if n < -1 {
			return Value{}, fmt.Errorf("%w: negative array length %d", ErrProtocol, n)
		}
		if n > int64(limits.MaxArrayLen) {
			return Value{}, fmt.Errorf("%w: %d > %d", ErrArrayTooLarge, n, limits.MaxArrayLen)
		}
		// Avoid upfront multi-megabyte slice allocation on truncated frames:
		// cap initial capacity and let append grow as elements actually arrive.
		initCap := int(n)
		if initCap > 64 {
			initCap = 64
		}
		elems := make([]Value, 0, initCap)
		for i := int64(0); i < n; i++ {
			elem, err := readValueDepth(r, limits, depth+1)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return Value{}, io.ErrUnexpectedEOF
				}
				return Value{}, err
			}
			elems = append(elems, elem)
		}
		return Value{Kind: KindArray, Array: elems}, nil
	default:
		return Value{}, fmt.Errorf("%w: unknown prefix byte 0x%02x", ErrProtocol, prefix)
	}
}

// ReadCommand reads one client command from r, accepting both standard RESP2
// array-of-bulk-strings frames and whitespace-delimited inline commands (such
// as "PING\r\n"). Blank inline lines are skipped.
//
// # Parameters
//
//   - r: Buffered reader for a client connection; must be non-nil.
//   - limits: Bounds on line length, bulk payload length, and argument count.
//
// # Returns
//
// The command token slice (length >= 1) on success. Returns io.EOF when the
// peer closes cleanly between commands, or a protocol/limit error on malformed
// input.
//
// # Example
//
//	r := bufio.NewReader(strings.NewReader("*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n"))
//	args, err := kv.ReadCommand(r, kv.ProtocolLimits{})
//	if err != nil {
//	    return err
//	}
//	fmt.Println(args) // [GET foo]
func ReadCommand(r *bufio.Reader, limits ProtocolLimits) ([]string, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", ErrProtocol)
	}
	lim := limits.effective()
	for {
		b, err := r.Peek(1)
		if err != nil {
			return nil, err
		}
		if b[0] == '*' {
			v, err := readValueDepth(r, lim, 0)
			if err != nil {
				return nil, err
			}
			if v.Kind != KindArray || len(v.Array) == 0 {
				return nil, ErrEmptyCommand
			}
			args := make([]string, len(v.Array))
			for i, elem := range v.Array {
				s, ok := elem.AsString()
				if !ok {
					return nil, fmt.Errorf("%w: command argument %d is not a string", ErrProtocol, i)
				}
				args[i] = s
			}
			return args, nil
		}

		// Inline command fallback (e.g. telnet / netcat PING\r\n).
		line, err := readBoundedLine(r, lim.MaxLineBytes)
		if err != nil {
			return nil, err
		}
		tokens, err := splitInlineArgs(string(line), lim.MaxArrayLen)
		if err != nil {
			return nil, err
		}
		if len(tokens) == 0 {
			continue
		}
		return tokens, nil
	}
}

// WriteValue encodes v in RESP2 wire format into w. Callers are responsible
// for calling w.Flush() and checking its error.
//
// # Parameters
//
//   - w: Buffered writer destination; must be non-nil.
//   - v: RESP2 Value to encode.
//
// # Returns
//
// Any write or protocol encoding error (e.g. CR/LF inside a simple string or
// error message).
//
// # Example
//
//	bw := bufio.NewWriter(&buf)
//	if err := kv.WriteValue(bw, kv.SimpleString("OK")); err != nil {
//	    return err
//	}
//	if err := bw.Flush(); err != nil {
//	    return err
//	}
func WriteValue(w *bufio.Writer, v Value) error {
	if w == nil {
		return fmt.Errorf("%w: nil writer", ErrProtocol)
	}
	switch v.Kind {
	case KindNull:
		_, err := w.WriteString("$-1\r\n")
		return err
	case KindSimpleString:
		if strings.ContainsAny(v.Str, "\r\n") {
			return fmt.Errorf("%w: simple string contains CR or LF", ErrProtocol)
		}
		if err := w.WriteByte('+'); err != nil {
			return err
		}
		if _, err := w.WriteString(v.Str); err != nil {
			return err
		}
		_, err := w.WriteString("\r\n")
		return err
	case KindError:
		clean := strings.NewReplacer("\r", " ", "\n", " ").Replace(v.Str)
		if err := w.WriteByte('-'); err != nil {
			return err
		}
		if _, err := w.WriteString(clean); err != nil {
			return err
		}
		_, err := w.WriteString("\r\n")
		return err
	case KindInteger:
		if err := w.WriteByte(':'); err != nil {
			return err
		}
		var scratch [32]byte
		num := strconv.AppendInt(scratch[:0], v.Int, 10)
		if _, err := w.Write(num); err != nil {
			return err
		}
		_, err := w.WriteString("\r\n")
		return err
	case KindBulkString:
		if err := w.WriteByte('$'); err != nil {
			return err
		}
		var scratch [32]byte
		num := strconv.AppendInt(scratch[:0], int64(len(v.Bulk)), 10)
		if _, err := w.Write(num); err != nil {
			return err
		}
		if _, err := w.WriteString("\r\n"); err != nil {
			return err
		}
		if _, err := w.Write(v.Bulk); err != nil {
			return err
		}
		_, err := w.WriteString("\r\n")
		return err
	case KindArray:
		if err := w.WriteByte('*'); err != nil {
			return err
		}
		var scratch [32]byte
		num := strconv.AppendInt(scratch[:0], int64(len(v.Array)), 10)
		if _, err := w.Write(num); err != nil {
			return err
		}
		if _, err := w.WriteString("\r\n"); err != nil {
			return err
		}
		for _, elem := range v.Array {
			if err := WriteValue(w, elem); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("%w: invalid value kind %d", ErrProtocol, v.Kind)
	}
}

// WriteCommand encodes args as a RESP2 array of bulk strings into w. Callers
// must call w.Flush() and check its error.
//
// # Parameters
//
//   - w: Buffered writer destination; must be non-nil.
//   - args: Non-empty command tokens (command name followed by arguments).
//
// # Returns
//
// ErrEmptyCommand if len(args) == 0, or any write error.
//
// # Example
//
//	bw := bufio.NewWriter(conn)
//	if err := kv.WriteCommand(bw, "SET", "k", "v", "EX", "30"); err != nil {
//	    return err
//	}
//	return bw.Flush()
func WriteCommand(w *bufio.Writer, args ...string) error {
	if w == nil {
		return fmt.Errorf("%w: nil writer", ErrProtocol)
	}
	if len(args) == 0 {
		return ErrEmptyCommand
	}
	var scratch [32]byte
	if err := w.WriteByte('*'); err != nil {
		return err
	}
	if _, err := w.Write(strconv.AppendInt(scratch[:0], int64(len(args)), 10)); err != nil {
		return err
	}
	if _, err := w.WriteString("\r\n"); err != nil {
		return err
	}
	for _, a := range args {
		if err := w.WriteByte('$'); err != nil {
			return err
		}
		if _, err := w.Write(strconv.AppendInt(scratch[:0], int64(len(a)), 10)); err != nil {
			return err
		}
		if _, err := w.WriteString("\r\n"); err != nil {
			return err
		}
		if _, err := w.WriteString(a); err != nil {
			return err
		}
		if _, err := w.WriteString("\r\n"); err != nil {
			return err
		}
	}
	return nil
}

// readBoundedCRLFLine reads up to maxBytes until "\r\n" and returns the line
// without the trailing CRLF. Rejects bare LF or embedded CR without LF.
//
// # Parameters
//
//   - r: Buffered reader to consume from.
//   - maxBytes: Maximum permitted line payload bytes (excluding CRLF).
//
// # Returns
//
// A newly owned byte slice containing the line payload, or ErrLineTooLong /
// ErrProtocol / I/O error.
//
// # Example
//
//	line, err := readBoundedCRLFLine(r, DefaultMaxLineBytes)
func readBoundedCRLFLine(r *bufio.Reader, maxBytes int) ([]byte, error) {
	var out []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(out)+len(chunk) > maxBytes+2 {
			return nil, ErrLineTooLong
		}
		out = append(out, chunk...)
		if err == nil {
			if len(out) < 2 || out[len(out)-2] != '\r' {
				return nil, fmt.Errorf("%w: line missing CR before LF", ErrProtocol)
			}
			payload := out[:len(out)-2]
			if bytes.IndexByte(payload, '\r') >= 0 {
				return nil, fmt.Errorf("%w: unexpected CR inside line", ErrProtocol)
			}
			return payload, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(out) > 0 {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
}

// readBoundedLine reads an inline command line terminated by LF (with optional
// preceding CR), bounded to maxBytes.
//
// # Parameters
//
//   - r: Buffered reader to consume from.
//   - maxBytes: Maximum line length in bytes.
//
// # Returns
//
// The trimmed line bytes without trailing CR/LF, or ErrLineTooLong / I/O error.
//
// # Example
//
//	line, err := readBoundedLine(r, DefaultMaxLineBytes)
func readBoundedLine(r *bufio.Reader, maxBytes int) ([]byte, error) {
	var out []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(out)+len(chunk) > maxBytes+2 {
			return nil, ErrLineTooLong
		}
		out = append(out, chunk...)
		if err == nil {
			out = bytes.TrimSuffix(out, []byte{'\n'})
			out = bytes.TrimSuffix(out, []byte{'\r'})
			return out, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(out) > 0 {
			return bytes.TrimSuffix(out, []byte{'\r'}), nil
		}
		return nil, err
	}
}

// parseStrictInt64 parses a decimal integer with optional leading '-' and no
// whitespace or surrounding characters.
//
// # Parameters
//
//   - b: Raw ASCII bytes from a RESP2 integer or length header.
//
// # Returns
//
// The parsed int64 or a strconv error.
//
// # Example
//
//	n, err := parseStrictInt64([]byte("42"))
func parseStrictInt64(b []byte) (int64, error) {
	if len(b) == 0 {
		return 0, errors.New("empty integer")
	}
	if b[0] == '+' {
		return 0, errors.New("leading plus not permitted")
	}
	return strconv.ParseInt(string(b), 10, 64)
}

// splitInlineArgs tokenizes a RESP2 inline command line into arguments,
// supporting basic single/double quoting and capping token count at maxArgs.
//
// # Parameters
//
//   - line: Raw inline command line without trailing CRLF.
//   - maxArgs: Maximum permitted number of arguments.
//
// # Returns
//
// Parsed argument slice, or ErrProtocol (unterminated quote) / ErrArrayTooLarge.
//
// # Example
//
//	args, err := splitInlineArgs(`SET "hello world" 1`, DefaultMaxArrayLen)
func splitInlineArgs(line string, maxArgs int) ([]string, error) {
	var args []string
	var cur strings.Builder
	inToken := false
	var quote byte

	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == '\\' && quote == '"' && i+1 < len(line) {
				i++
				cur.WriteByte(line[i])
				continue
			}
			if c == quote {
				quote = 0
				continue
			}
			cur.WriteByte(c)
			continue
		}
		switch c {
		case ' ', '\t':
			if inToken {
				args = append(args, cur.String())
				if len(args) > maxArgs {
					return nil, fmt.Errorf("%w: inline args exceed %d", ErrArrayTooLarge, maxArgs)
				}
				cur.Reset()
				inToken = false
			}
		case '"', '\'':
			quote = c
			inToken = true
		default:
			cur.WriteByte(c)
			inToken = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("%w: unterminated quote in inline command", ErrProtocol)
	}
	if inToken {
		args = append(args, cur.String())
		if len(args) > maxArgs {
			return nil, fmt.Errorf("%w: inline args exceed %d", ErrArrayTooLarge, maxArgs)
		}
	}
	return args, nil
}
