package main

import (
	"bufio"
	"net"
	"net/http"
	"strings"
)

// ticketWriter notes the room_ticket value a response sets. It forwards
// Flush and Hijack because gin type-asserts the writer it wraps, and
// streaming and upgrades must survive. Client disconnects are observed
// through the request context, so the deprecated http.CloseNotifier is
// intentionally not implemented.
type ticketWriter struct {
	http.ResponseWriter
	inspected bool
	issued    string
}

func (w *ticketWriter) inspect() {
	if w.inspected {
		return
	}
	w.inspected = true
	for _, v := range w.Header().Values("Set-Cookie") {
		if !strings.HasPrefix(v, "room_ticket=") {
			continue
		}
		val := strings.TrimPrefix(v, "room_ticket=")
		if i := strings.IndexByte(val, ';'); i >= 0 {
			val = val[:i]
		}
		if val != "" {
			w.issued = val
		}
	}
}

func (w *ticketWriter) WriteHeader(code int) {
	w.inspect()
	w.ResponseWriter.WriteHeader(code)
}

func (w *ticketWriter) Write(b []byte) (int, error) {
	w.inspect()
	return w.ResponseWriter.Write(b)
}

func (w *ticketWriter) Flush() {
	w.inspect()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *ticketWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.inspect()
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (w *ticketWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
