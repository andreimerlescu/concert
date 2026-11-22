// Package fcgi implements a pure-stdlib FastCGI 1.0 client (RFC/FastCGI spec)
// supporting TCP (fcgi://) and Unix domain sockets (fcgi+unix://), WordPress
// try_files resolution confined by os.Root, streaming request/response bodies,
// and CGI/1.1 header parsing.
package fcgi

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const (
	fcgiVersion1 = 1

	typeBeginRequest = 1
	typeAbortRequest = 2
	typeEndRequest   = 3
	typeParams       = 4
	typeStdin        = 5
	typeStdout       = 6
	typeStderr       = 7

	roleResponder = 1

	maxRecordPayload  = 65535
	maxStderrCapture  = 4096
	maxCGIHeaderBytes = 64 << 10
)

var zeroPad [8]byte

type recordHeader struct {
	Version       uint8
	Type          uint8
	RequestID     uint16
	ContentLength uint16
	PaddingLength uint8
	Reserved      uint8
}

func writeRecord(w io.Writer, recType uint8, reqID uint16, payload []byte) error {
	if len(payload) == 0 {
		var hdr [8]byte
		hdr[0] = fcgiVersion1
		hdr[1] = recType
		binary.BigEndian.PutUint16(hdr[2:4], reqID)
		_, err := w.Write(hdr[:])
		return err
	}
	for len(payload) > 0 {
		n := len(payload)
		if n > maxRecordPayload {
			n = maxRecordPayload
		}
		pad := (8 - (n % 8)) % 8
		var hdr [8]byte
		hdr[0] = fcgiVersion1
		hdr[1] = recType
		binary.BigEndian.PutUint16(hdr[2:4], reqID)
		binary.BigEndian.PutUint16(hdr[4:6], uint16(n))
		hdr[6] = uint8(pad)
		if _, err := w.Write(hdr[:]); err != nil {
			return err
		}
		if _, err := w.Write(payload[:n]); err != nil {
			return err
		}
		if pad > 0 {
			if _, err := w.Write(zeroPad[:pad]); err != nil {
				return err
			}
		}
		payload = payload[n:]
	}
	return nil
}

func writeBeginRequest(w io.Writer, reqID uint16) error {
	var body [8]byte
	binary.BigEndian.PutUint16(body[0:2], roleResponder)
	// flags=0 asks the FastCGI server to close the connection when finished.
	body[2] = 0
	return writeRecord(w, typeBeginRequest, reqID, body[:])
}

func appendParamLen(dst []byte, n int) []byte {
	if n < 128 {
		return append(dst, byte(n))
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n)|0x80000000)
	return append(dst, b[:]...)
}

func encodeParams(params map[string]string) []byte {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	var lenBuf [8]byte
	for _, k := range keys {
		v := params[k]
		lb := appendParamLen(lenBuf[:0], len(k))
		lb = appendParamLen(lb, len(v))
		buf.Write(lb)
		buf.WriteString(k)
		buf.WriteString(v)
	}
	return buf.Bytes()
}

func readRecord(r io.Reader) (recordHeader, []byte, error) {
	var raw [8]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return recordHeader{}, nil, err
	}
	hdr := recordHeader{
		Version:       raw[0],
		Type:          raw[1],
		RequestID:     binary.BigEndian.Uint16(raw[2:4]),
		ContentLength: binary.BigEndian.Uint16(raw[4:6]),
		PaddingLength: raw[6],
		Reserved:      raw[7],
	}
	if hdr.Version != fcgiVersion1 {
		return recordHeader{}, nil, fmt.Errorf("fcgi: unsupported record version %d", hdr.Version)
	}
	var payload []byte
	if hdr.ContentLength > 0 {
		payload = make([]byte, hdr.ContentLength)
		if _, err := io.ReadFull(r, payload); err != nil {
			return recordHeader{}, nil, err
		}
	}
	if hdr.PaddingLength > 0 {
		var discard [256]byte
		if _, err := io.ReadFull(r, discard[:hdr.PaddingLength]); err != nil {
			return recordHeader{}, nil, err
		}
	}
	return hdr, payload, nil
}

// stdoutReader demultiplexes FastCGI response records, streaming FCGI_STDOUT
// payload bytes while capturing bounded FCGI_STDERR diagnostics.
type stdoutReader struct {
	r        io.Reader
	reqID    uint16
	buf      []byte
	ended    bool
	stderr   bytes.Buffer
	onStderr func(string)
	flushed  bool
}

func (s *stdoutReader) flushStderr() {
	if s.flushed {
		return
	}
	s.flushed = true
	if s.onStderr != nil && s.stderr.Len() > 0 {
		msg := strings.TrimSpace(s.stderr.String())
		if msg != "" {
			s.onStderr(msg)
		}
	}
}

func (s *stdoutReader) Read(p []byte) (int, error) {
	for len(s.buf) == 0 {
		if s.ended {
			s.flushStderr()
			return 0, io.EOF
		}
		hdr, payload, err := readRecord(s.r)
		if err != nil {
			s.flushStderr()
			if errors.Is(err, io.EOF) {
				s.ended = true
				return 0, io.EOF
			}
			return 0, err
		}
		if hdr.RequestID != s.reqID {
			continue
		}
		switch hdr.Type {
		case typeStdout:
			if len(payload) > 0 {
				s.buf = payload
			}
		case typeStderr:
			if len(payload) > 0 && s.stderr.Len() < maxStderrCapture {
				rem := maxStderrCapture - s.stderr.Len()
				if len(payload) > rem {
					payload = payload[:rem]
				}
				s.stderr.Write(payload)
			}
		case typeEndRequest:
			s.ended = true
			s.flushStderr()
			return 0, io.EOF
		}
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

// parseCGIHeaders parses RFC 3875 CGI/1.1 headers from a FastCGI STDOUT
// stream. It caps header bytes at maxCGIHeaderBytes, translates Status: to the
// HTTP status code, preserves multi-value headers (Set-Cookie), and rejects
// malformed or injected header lines.
func parseCGIHeaders(r *bufio.Reader) (int, string, http.Header, error) {
	hdr := make(http.Header)
	statusCode := http.StatusOK
	statusText := ""
	hasExplicitStatus := false
	totalBytes := 0

	for {
		line, err := readBoundedLine(r, maxCGIHeaderBytes-totalBytes)
		if err != nil {
			return 0, "", nil, fmt.Errorf("fcgi: read CGI headers: %w", err)
		}
		totalBytes += len(line) + 1
		if totalBytes > maxCGIHeaderBytes {
			return 0, "", nil, errors.New("fcgi: CGI headers exceed maximum size")
		}
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			break
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return 0, "", nil, fmt.Errorf("fcgi: malformed CGI header line")
		}
		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])
		if !validHeaderName(key) || strings.ContainsAny(val, "\r\n\x00") {
			return 0, "", nil, fmt.Errorf("fcgi: invalid CGI header")
		}
		if strings.EqualFold(key, "Status") {
			code, text, perr := parseCGIStatus(val)
			if perr != nil {
				return 0, "", nil, perr
			}
			statusCode = code
			statusText = text
			hasExplicitStatus = true
			continue
		}
		hdr.Add(key, val)
	}

	if !hasExplicitStatus && hdr.Get("Location") != "" {
		statusCode = http.StatusFound
		statusText = http.StatusText(http.StatusFound)
	}
	if statusText == "" {
		statusText = http.StatusText(statusCode)
	}
	return statusCode, statusText, hdr, nil
}

func readBoundedLine(r *bufio.Reader, limit int) (string, error) {
	if limit <= 0 {
		return "", errors.New("header limit exceeded")
	}
	var out []byte
	for {
		frag, isPrefix, err := r.ReadLine()
		if err != nil {
			return "", err
		}
		out = append(out, frag...)
		if len(out) > limit {
			return "", errors.New("header line exceeds maximum size")
		}
		if !isPrefix {
			return string(out), nil
		}
	}
}

func parseCGIStatus(val string) (int, string, error) {
	val = strings.TrimSpace(val)
	codeStr := val
	reason := ""
	if sp := strings.IndexByte(val, ' '); sp >= 0 {
		codeStr = val[:sp]
		reason = strings.TrimSpace(val[sp+1:])
	}
	code, err := strconv.Atoi(codeStr)
	if err != nil || code < 100 || code > 599 {
		return 0, "", fmt.Errorf("fcgi: invalid CGI Status %q", val)
	}
	return code, reason, nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c <= 0x20 || c >= 0x7f {
			return false
		}
		switch c {
		case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}':
			return false
		}
	}
	return true
}
