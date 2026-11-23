//go:build wordpress || enterprise

package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

const minFCGIGzipBytes = 1024

var fcgiGzipPool = sync.Pool{
	New: func() any {
		return gzip.NewWriter(io.Discard)
	},
}

// maybeGzipFastCGI compresses compressible FastCGI responses >= 1 KiB using
// stdlib gzip when the client accepts gzip and php-fpm did not already encode
// the response. Proxied HTTP upstreams are never passed through this function,
// preserving Concert's raw Accept-Encoding passthrough contract.
func maybeGzipFastCGI(req *http.Request, resp *http.Response) {
	if req == nil || resp == nil || resp.Body == nil || req.Method == http.MethodHead {
		return
	}
	if !clientAcceptsGzip(req) {
		return
	}
	if resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Upgrade") != "" {
		return
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Cache-Control")), "no-transform") {
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return
	}
	if !isFCGICompressible(resp.Header.Get("Content-Type")) {
		return
	}
	if resp.ContentLength >= 0 && resp.ContentLength < minFCGIGzipBytes {
		return
	}

	orig := resp.Body
	sniff := make([]byte, minFCGIGzipBytes)
	n, err := io.ReadFull(orig, sniff)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		// Response smaller than threshold: serve uncompressed cleanly.
		_ = orig.Close()
		resp.Body = io.NopCloser(bytes.NewReader(sniff[:n]))
		resp.ContentLength = int64(n)
		return
	}
	if err != nil {
		// Propagate read error via a small reader so caller sees it normally.
		resp.Body = &errCloserReader{r: io.MultiReader(bytes.NewReader(sniff[:n]), errReader{err: err}), c: orig}
		return
	}

	resp.Header.Del("Content-Length")
	resp.Header.Set("Content-Encoding", "gzip")
	addVaryHeader(resp.Header, "Accept-Encoding")
	resp.ContentLength = -1

	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer orig.Close()
		gw := fcgiGzipPool.Get().(*gzip.Writer)
		gw.Reset(pw)
		_, werr := gw.Write(sniff[:n])
		if werr == nil {
			_, werr = io.Copy(gw, orig)
		}
		cerr := gw.Close()
		gw.Reset(io.Discard)
		fcgiGzipPool.Put(gw)
		if werr != nil {
			_ = pw.CloseWithError(werr)
			return
		}
		if cerr != nil {
			_ = pw.CloseWithError(cerr)
			return
		}
		_ = pw.Close()
	}()

	resp.Body = &pipeCloser{pr: pr, done: done}
}

type pipeCloser struct {
	pr   *io.PipeReader
	done chan struct{}
	once sync.Once
}

func (p *pipeCloser) Read(b []byte) (int, error) { return p.pr.Read(b) }
func (p *pipeCloser) Close() error {
	var err error
	p.once.Do(func() {
		err = p.pr.Close()
		<-p.done
	})
	return err
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

type errCloserReader struct {
	r io.Reader
	c io.Closer
}

func (e *errCloserReader) Read(p []byte) (int, error) { return e.r.Read(p) }
func (e *errCloserReader) Close() error               { return e.c.Close() }

func clientAcceptsGzip(r *http.Request) bool {
	for _, hdr := range r.Header.Values("Accept-Encoding") {
		for _, part := range strings.Split(hdr, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name := part
			q := 1.0
			if semi := strings.IndexByte(part, ';'); semi >= 0 {
				name = strings.TrimSpace(part[:semi])
				params := strings.TrimSpace(part[semi+1:])
				if strings.HasPrefix(params, "q=") {
					if parsed, err := strconv.ParseFloat(strings.TrimSpace(params[2:]), 64); err == nil {
						q = parsed
					}
				}
			}
			if q > 0 && strings.EqualFold(name, "gzip") {
				return true
			}
		}
	}
	return false
}

func isFCGICompressible(ct string) bool {
	if semi := strings.IndexByte(ct, ';'); semi >= 0 {
		ct = ct[:semi]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" || ct == "text/event-stream" {
		return false
	}
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	switch ct {
	case "application/javascript", "application/json", "application/xml",
		"application/xhtml+xml", "application/rss+xml", "application/atom+xml",
		"application/manifest+json", "image/svg+xml":
		return true
	}
	return false
}

func addVaryHeader(h http.Header, token string) {
	for _, existing := range h.Values("Vary") {
		for _, part := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return
			}
		}
	}
	h.Add("Vary", token)
}
