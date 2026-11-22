package fcgi

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config configures a FastCGI Transport.
type Config struct {
	Root          string        // absolute DOCUMENT_ROOT confined by os.Root
	Index         string        // default "index.php"
	DenyPaths     []string      // paths forbidden from PHP execution (e.g. "/wp-content/uploads/*", "/wp-config.php")
	HeaderTimeout time.Duration // response header timeout (0 disables)
	DialTimeout   time.Duration // socket connect timeout (default 5s)
	OnStderr      func(msg string)
	OnRequest     func()
	OnDenied      func(path string)
}

type denyRule struct {
	path   string
	prefix bool
}

func parseDenyRules(specs []string) []denyRule {
	var out []denyRule
	for _, raw := range specs {
		p := strings.ToLower(strings.TrimSpace(raw))
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if strings.HasSuffix(p, "/*") {
			base := strings.TrimSuffix(p, "/*")
			if base == "" {
				base = "/"
			}
			out = append(out, denyRule{path: base, prefix: true})
		} else {
			out = append(out, denyRule{path: strings.TrimRight(p, "/"), prefix: false})
		}
	}
	return out
}

func (r denyRule) matches(cleanLowerPath string) bool {
	if r.prefix {
		if r.path == "/" {
			return true
		}
		return cleanLowerPath == r.path || strings.HasPrefix(cleanLowerPath, r.path+"/")
	}
	return cleanLowerPath == r.path
}

// IsFastCGI reports whether u uses one of Concert's FastCGI upstream schemes.
func IsFastCGI(u *url.URL) bool {
	return u != nil && (u.Scheme == "fcgi" || u.Scheme == "fcgi+unix")
}

// ParseTarget extracts the dial network and address from an fcgi:// or
// fcgi+unix:// URL.
func ParseTarget(u *url.URL) (network, address string, err error) {
	if u == nil {
		return "", "", errors.New("fcgi: nil target URL")
	}
	switch u.Scheme {
	case "fcgi":
		host, port, serr := net.SplitHostPort(u.Host)
		if serr != nil || host == "" || port == "" {
			return "", "", fmt.Errorf("invalid fcgi upstream %q: expected fcgi://host:port", u.String())
		}
		return "tcp", u.Host, nil
	case "fcgi+unix":
		if u.Host != "" {
			return "", "", fmt.Errorf("invalid fcgi+unix upstream %q: expected fcgi+unix:///absolute/socket.sock", u.String())
		}
		p := u.Path
		if p == "" || !strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.ContainsAny(p, "\x00\r\n") {
			return "", "", fmt.Errorf("invalid fcgi+unix socket path %q: must be an absolute path", u.String())
		}
		return "unix", p, nil
	default:
		return "", "", fmt.Errorf("unsupported FastCGI scheme %q", u.Scheme)
	}
}

// Transport executes HTTP requests against php-fpm / FastCGI responders using
// WordPress try_files script resolution inside an os.Root-confined document root.
type Transport struct {
	root          *os.Root
	rootAbs       string
	index         string
	denyRules     []denyRule
	headerTimeout time.Duration
	dialTimeout   time.Duration
	onStderr      func(string)
	onRequest     func()
	onDenied      func(string)
}

// NewTransport opens an os.Root on cfg.Root and prepares a FastCGI Transport.
func NewTransport(cfg Config) (*Transport, error) {
	if strings.TrimSpace(cfg.Root) == "" {
		return nil, errors.New("fcgi: -static-root is required when using fcgi:// or fcgi+unix:// upstreams")
	}
	absRoot, err := filepath.Abs(strings.TrimSpace(cfg.Root))
	if err != nil {
		return nil, fmt.Errorf("fcgi: resolve root %q: %w", cfg.Root, err)
	}
	info, err := os.Stat(absRoot)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("fcgi: root %q must be an existing directory", cfg.Root)
	}
	root, err := os.OpenRoot(absRoot)
	if err != nil {
		return nil, fmt.Errorf("fcgi: open root %q: %w", absRoot, err)
	}
	idx := strings.TrimLeft(strings.TrimSpace(cfg.Index), "/")
	if idx == "" {
		idx = "index.php"
	}
	if strings.Contains(idx, "..") || strings.ContainsAny(idx, "\\\x00\r\n") {
		_ = root.Close()
		return nil, fmt.Errorf("fcgi: invalid -fcgi-index %q", cfg.Index)
	}
	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}
	return &Transport{
		root:          root,
		rootAbs:       absRoot,
		index:         idx,
		denyRules:     parseDenyRules(cfg.DenyPaths),
		headerTimeout: cfg.HeaderTimeout,
		dialTimeout:   dialTimeout,
		onStderr:      cfg.OnStderr,
		onRequest:     cfg.OnRequest,
		onDenied:      cfg.OnDenied,
	}, nil
}

// Close releases the underlying os.Root handle. Safe on nil.
func (t *Transport) Close() error {
	if t == nil || t.root == nil {
		return nil
	}
	err := t.root.Close()
	t.root = nil
	return err
}

// DialCheck verifies that a FastCGI backend socket accepts a connection (for
// lightweight active health checks).
func (t *Transport) DialCheck(ctx context.Context, target *url.URL) error {
	network, addr, err := ParseTarget(target)
	if err != nil {
		return err
	}
	d := net.Dialer{Timeout: t.dialTimeout}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

type resolvedScript struct {
	scriptName     string
	scriptFilename string
	pathInfo       string
	redirectTo     string
	syntheticCode  int
	denied         bool
}

func (t *Transport) isDenied(cleanPath string) bool {
	lower := strings.ToLower(cleanPath)
	for _, r := range t.denyRules {
		if r.matches(lower) {
			return true
		}
	}
	return false
}

func hasUnsafeSegments(rawPath string) bool {
	if rawPath == "" || rawPath[0] != '/' || strings.ContainsAny(rawPath, "\x00\\") {
		return true
	}
	segs := strings.Split(rawPath[1:], "/")
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		if seg == "." || seg == ".." {
			return true
		}
		if seg[0] == '.' {
			if i == 0 && seg == ".well-known" {
				continue
			}
			return true
		}
	}
	return false
}

// splitPHP splits a URL path like "/wp-admin/post.php/extra" into
// ("/wp-admin/post.php", "/extra", true).
func splitPHP(cleanPath string) (scriptPath, pathInfo string, ok bool) {
	lower := strings.ToLower(cleanPath)
	idx := strings.Index(lower, ".php")
	for idx >= 0 {
		end := idx + 4
		if end == len(cleanPath) || cleanPath[end] == '/' {
			return cleanPath[:end], cleanPath[end:], true
		}
		next := strings.Index(lower[end:], ".php")
		if next < 0 {
			break
		}
		idx = end + next
	}
	return "", "", false
}

func (t *Transport) resolveScript(urlPath string) resolvedScript {
	if hasUnsafeSegments(urlPath) {
		return resolvedScript{syntheticCode: http.StatusForbidden, denied: true}
	}
	trailingSlash := strings.HasSuffix(urlPath, "/")
	cleanPath := path.Clean(urlPath)
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}

	if t.isDenied(cleanPath) {
		return resolvedScript{syntheticCode: http.StatusForbidden, denied: true}
	}

	// Case 1: Explicit .php request (with optional PATH_INFO).
	if scriptPath, pathInfo, isPHP := splitPHP(cleanPath); isPHP {
		if t.isDenied(scriptPath) {
			return resolvedScript{syntheticCode: http.StatusForbidden, denied: true}
		}
		rel := strings.TrimPrefix(scriptPath, "/")
		info, err := t.root.Stat(rel)
		if err != nil || !info.Mode().IsRegular() {
			return resolvedScript{syntheticCode: http.StatusNotFound}
		}
		return resolvedScript{
			scriptName:     scriptPath,
			scriptFilename: filepath.Join(t.rootAbs, filepath.FromSlash(rel)),
			pathInfo:       pathInfo,
		}
	}

	// Case 2: Root or subdirectory with an index script (e.g. / or /wp-admin/).
	rel := strings.TrimPrefix(cleanPath, "/")
	if rel == "" {
		if info, err := t.root.Stat(t.index); err == nil && info.Mode().IsRegular() {
			return resolvedScript{
				scriptName:     "/" + t.index,
				scriptFilename: filepath.Join(t.rootAbs, filepath.FromSlash(t.index)),
			}
		}
		return resolvedScript{syntheticCode: http.StatusNotFound}
	}

	if info, err := t.root.Stat(rel); err == nil && info.IsDir() {
		dirIndex := rel + "/" + t.index
		if ist, err2 := t.root.Stat(dirIndex); err2 == nil && ist.Mode().IsRegular() {
			if !trailingSlash {
				return resolvedScript{redirectTo: cleanPath + "/"}
			}
			return resolvedScript{
				scriptName:     "/" + dirIndex,
				scriptFilename: filepath.Join(t.rootAbs, filepath.FromSlash(dirIndex)),
			}
		}
	}

	// Case 3: WordPress try_files fallback to root index.php, preserving REQUEST_URI.
	if info, err := t.root.Stat(t.index); err == nil && info.Mode().IsRegular() {
		return resolvedScript{
			scriptName:     "/" + t.index,
			scriptFilename: filepath.Join(t.rootAbs, filepath.FromSlash(t.index)),
		}
	}
	return resolvedScript{syntheticCode: http.StatusNotFound}
}

func syntheticResponse(req *http.Request, code int, location string) *http.Response {
	h := make(http.Header)
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	if location != "" {
		h.Set("Location", location)
	}
	body := http.StatusText(code)
	return &http.Response{
		StatusCode:    code,
		Status:        fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// RoundTripTo executes req against the FastCGI responder named by target,
// preserving req.URL.Path and req.URL.RawQuery untouched (so Unix socket paths
// in target never pollute REQUEST_URI).
func (t *Transport) RoundTripTo(req *http.Request, target *url.URL) (*http.Response, error) {
	network, address, err := ParseTarget(target)
	if err != nil {
		return nil, err
	}
	res := t.resolveScript(req.URL.Path)
	if res.redirectTo != "" {
		loc := res.redirectTo
		if req.URL.RawQuery != "" {
			loc += "?" + req.URL.RawQuery
		}
		return syntheticResponse(req, http.StatusMovedPermanently, loc), nil
	}
	if res.syntheticCode != 0 {
		if res.denied && t.onDenied != nil {
			t.onDenied(req.URL.Path)
		}
		return syntheticResponse(req, res.syntheticCode, ""), nil
	}
	if t.onRequest != nil {
		t.onRequest()
	}

	ctx := req.Context()
	dialer := net.Dialer{Timeout: t.dialTimeout}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	if t.headerTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(t.headerTimeout))
	}

	const reqID uint16 = 1
	params := t.buildParams(req, res)
	var reqBuf []byte
	// Write BEGIN_REQUEST and PARAMS synchronously before streaming STDIN.
	if err := writeBeginRequest(conn, reqID); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if encoded := encodeParams(params); len(encoded) > 0 {
		if err := writeRecord(conn, typeParams, reqID, encoded); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	if err := writeRecord(conn, typeParams, reqID, nil); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = reqBuf

	// Stream request body in a goroutine so large POST uploads cannot deadlock
	// if php-fpm responds early.
	stdinDone := make(chan struct{})
	go func() {
		defer close(stdinDone)
		if req.Body != nil {
			buf := make([]byte, 32<<10)
			for {
				n, rerr := req.Body.Read(buf)
				if n > 0 {
					if werr := writeRecord(conn, typeStdin, reqID, buf[:n]); werr != nil {
						return
					}
				}
				if rerr != nil {
					break
				}
			}
		}
		_ = writeRecord(conn, typeStdin, reqID, nil)
	}()

	// Abort the connection immediately if the request context is cancelled.
	cancelDone := make(chan struct{})
	var closeOnce sync.Once
	closeConn := func() {
		closeOnce.Do(func() {
			_ = conn.Close()
		})
	}
	go func() {
		select {
		case <-ctx.Done():
			closeConn()
		case <-cancelDone:
		}
	}()

	sr := &stdoutReader{
		r:        conn,
		reqID:    reqID,
		onStderr: t.onStderr,
	}
	br := bufio.NewReaderSize(sr, 16<<10)
	statusCode, statusText, hdr, err := parseCGIHeaders(br)
	if err != nil {
		close(cancelDone)
		closeConn()
		<-stdinDone
		sr.flushStderr()
		return nil, err
	}

	// Clear the header deadline once response headers arrive so streaming
	// downloads/SSE are not cut off prematurely.
	if t.headerTimeout > 0 {
		_ = conn.SetDeadline(time.Time{})
	}

	contentLen := int64(-1)
	if clStr := hdr.Get("Content-Length"); clStr != "" {
		if parsed, perr := strconv.ParseInt(strings.TrimSpace(clStr), 10, 64); perr == nil && parsed >= 0 {
			contentLen = parsed
		}
	}

	body := &responseBody{
		br:         br,
		sr:         sr,
		closeConn:  closeConn,
		cancelDone: cancelDone,
		stdinDone:  stdinDone,
	}

	return &http.Response{
		StatusCode:    statusCode,
		Status:        fmt.Sprintf("%d %s", statusCode, statusText),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        hdr,
		Body:          body,
		ContentLength: contentLen,
		Request:       req,
	}, nil
}

type responseBody struct {
	br         *bufio.Reader
	sr         *stdoutReader
	closeConn  func()
	cancelDone chan struct{}
	stdinDone  chan struct{}
	closeOnce  sync.Once
}

func (b *responseBody) Read(p []byte) (int, error) {
	return b.br.Read(p)
}

func (b *responseBody) Close() error {
	b.closeOnce.Do(func() {
		close(b.cancelDone)
		b.closeConn()
		<-b.stdinDone
		b.sr.flushStderr()
	})
	return nil
}

func (t *Transport) buildParams(req *http.Request, res resolvedScript) map[string]string {
	reqURI := req.URL.RequestURI()
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	serverName := host
	serverPort := "80"
	isHTTPS := req.TLS != nil || strings.EqualFold(req.Header.Get("X-Forwarded-Proto"), "https")
	if isHTTPS {
		serverPort = "443"
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		serverName = h
		serverPort = p
	}
	remoteAddr := req.RemoteAddr
	remotePort := ""
	if h, p, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		remoteAddr = h
		remotePort = p
	}
	// Prefer the resolved client IP from X-Forwarded-For when Concert set it.
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		if first != "" {
			remoteAddr = first
		}
	}

	params := map[string]string{
		"GATEWAY_INTERFACE": "CGI/1.1",
		"SERVER_SOFTWARE":   "concert",
		"SERVER_PROTOCOL":   req.Proto,
		"SERVER_NAME":       serverName,
		"SERVER_PORT":       serverPort,
		"REQUEST_METHOD":    req.Method,
		"REQUEST_URI":       reqURI,
		"DOCUMENT_ROOT":     t.rootAbs,
		"DOCUMENT_URI":      res.scriptName,
		"SCRIPT_NAME":       res.scriptName,
		"SCRIPT_FILENAME":   res.scriptFilename,
		"QUERY_STRING":      req.URL.RawQuery,
		"REMOTE_ADDR":       remoteAddr,
		"REMOTE_HOST":       remoteAddr,
		"REMOTE_PORT":       remotePort,
		"REDIRECT_STATUS":   "200",
	}
	if res.pathInfo != "" {
		params["PATH_INFO"] = res.pathInfo
	}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		params["CONTENT_TYPE"] = ct
	}
	if req.ContentLength >= 0 {
		params["CONTENT_LENGTH"] = strconv.FormatInt(req.ContentLength, 10)
	} else if cl := req.Header.Get("Content-Length"); cl != "" {
		params["CONTENT_LENGTH"] = cl
	}
	if isHTTPS {
		params["HTTPS"] = "on"
		params["REQUEST_SCHEME"] = "https"
	} else {
		params["REQUEST_SCHEME"] = "http"
	}

	for k, vals := range req.Header {
		// Defend against httpoxy (CVE-2016-5385).
		if strings.EqualFold(k, "Proxy") {
			continue
		}
		envKey := "HTTP_" + strings.ToUpper(strings.ReplaceAll(k, "-", "_"))
		if strings.EqualFold(k, "Cookie") {
			params[envKey] = strings.Join(vals, "; ")
		} else {
			params[envKey] = strings.Join(vals, ", ")
		}
	}
	if host != "" {
		params["HTTP_HOST"] = host
	}
	return params
}
