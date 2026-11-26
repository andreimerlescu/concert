// Package static serves local static assets confined by Go's os.Root with
// fail-closed extension allowlisting, dotfile/secret rejection, precompressed
// .br/.gz sidecar negotiation, optional on-the-fly gzip compression, strong
// ETag/304 handling, and native HTTP Range support.
package static

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const minGzipBytes = 1024

// Result tells Concert's router what Serve did with a request.
type Result int

const (
	// ResultPassThrough means the static server did not handle the request
	// (non-GET/HEAD, .php script, directory in FastCGI mode, non-mounted miss
	// with fallback enabled, etc.) so Concert should forward it upstream.
	ResultPassThrough Result = iota
	// ResultServed means the static server wrote the full HTTP response (200,
	// 206, or 304) directly from disk with zero upstream load.
	ResultServed
	// ResultNotFound means the request targeted an authoritative static mount
	// or static-extension asset that does not exist on disk (fast 404).
	ResultNotFound
	// ResultForbidden means the request targeted a blocked dotfile, traversal
	// attempt, or forbidden script/secret extension under a static root/mount.
	ResultForbidden
)

// Mount maps a URL path prefix (e.g. "/wp-content") to a host directory.
type Mount struct {
	Prefix string
	Dir    string
}

// Config configures a static file Server.
type Config struct {
	Root          string   // optional -static-root (shared with FastCGI DOCUMENT_ROOT)
	Mounts        []Mount  // optional -static-mounts "/prefix=/dir"
	AllowExt      []string // optional extra extensions added to defaultAllowedExtensions
	CacheControl  string   // Cache-Control header applied to served static files
	Fallback      bool     // if true, missing files return ResultPassThrough instead of ResultNotFound
	Compress      bool     // if true, gzip compressible files >= 1 KiB when no sidecar exists
	ServeDirIndex bool     // if true, serve index.html for directory paths (off for FastCGI roots)
}

type openMount struct {
	prefix string
	dir    string
	root   *os.Root
}

// Server serves static assets from kernel-confined os.Root handles.
type Server struct {
	cfg        Config
	root       *os.Root
	mounts     []openMount // sorted by len(prefix) descending
	allowedExt map[string]bool
	gzPool     sync.Pool
}

// forbiddenExtensions can NEVER be served as static files off disk, even if
// listed in -static-allow-ext.
var forbiddenExtensions = map[string]bool{
	".php": true, ".phtml": true, ".phar": true, ".phps": true,
	".php3": true, ".php4": true, ".php5": true, ".php7": true, ".php8": true,
	".inc": true, ".cgi": true, ".pl": true, ".py": true, ".rb": true,
	".sh": true, ".bash": true, ".zsh": true,
	".env": true, ".sql": true, ".sqlite": true, ".sqlite3": true, ".db": true,
	".bak": true, ".backup": true, ".old": true, ".orig": true, ".save": true,
	".swp": true, ".swo": true, ".tmp": true, ".log": true,
	".key": true, ".pem": true, ".crt": true, ".cer": true, ".der": true,
	".p12": true, ".pfx": true, ".jks": true,
	".htpasswd": true, ".htaccess": true,
	".ini": true, ".conf": true, ".cfg": true, ".yaml": true, ".yml": true, ".toml": true,
	".lock": true, ".go": true, ".mod": true, ".sum": true,
}

var phpExtensions = map[string]bool{
	".php": true, ".phtml": true, ".phar": true, ".phps": true,
	".php3": true, ".php4": true, ".php5": true, ".php7": true, ".php8": true,
}

var defaultAllowedExtensions = map[string]bool{
	".css": true, ".js": true, ".mjs": true, ".cjs": true, ".map": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".avif": true, ".svg": true, ".ico": true, ".bmp": true, ".tif": true, ".tiff": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".mp4": true, ".webm": true, ".ogg": true, ".ogv": true, ".oga": true,
	".mp3": true, ".wav": true, ".flac": true, ".m4a": true, ".m4v": true, ".mov": true,
	".pdf": true, ".txt": true, ".xml": true, ".json": true, ".wasm": true,
	".webmanifest": true, ".csv": true, ".zip": true, ".html": true, ".htm": true,
}

var reservedMountPrefixes = []string{"/_room", "/_concert", "/queue/status"}

// ParseMounts parses comma-separated "/prefix=/abs/dir" static mount entries.
func ParseMounts(spec string) ([]Mount, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var mounts []Mount
	seen := map[string]bool{}
	for _, raw := range strings.Split(spec, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid -static-mounts entry %q: expected /prefix=/dir", raw)
		}
		prefix := strings.TrimSpace(parts[0])
		dir := strings.TrimSpace(parts[1])
		if !strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "*\\ \t\r\n\x00") || strings.Contains(prefix, "..") {
			return nil, fmt.Errorf("invalid -static-mounts prefix %q: must start with / and contain no wildcards or traversal", prefix)
		}
		prefix = strings.TrimRight(prefix, "/")
		if prefix == "" {
			return nil, errors.New("invalid -static-mounts prefix \"/\": use -static-root for the root directory")
		}
		for _, res := range reservedMountPrefixes {
			if prefix == res || strings.HasPrefix(prefix, res+"/") {
				return nil, fmt.Errorf("invalid -static-mounts prefix %q: reserved by concert", prefix)
			}
		}
		if seen[prefix] {
			return nil, fmt.Errorf("duplicate -static-mounts prefix %q", prefix)
		}
		seen[prefix] = true
		if dir == "" {
			return nil, fmt.Errorf("invalid -static-mounts entry %q: directory is empty", raw)
		}
		absDir, err := filepath.Abs(dir)
		if err != nil {
			return nil, fmt.Errorf("invalid -static-mounts dir %q: %w", dir, err)
		}
		info, err := os.Stat(absDir)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("invalid -static-mounts dir %q: must be an existing directory", dir)
		}
		mounts = append(mounts, Mount{Prefix: prefix, Dir: absDir})
	}
	sort.Slice(mounts, func(i, j int) bool {
		if len(mounts[i].Prefix) != len(mounts[j].Prefix) {
			return len(mounts[i].Prefix) > len(mounts[j].Prefix)
		}
		return mounts[i].Prefix < mounts[j].Prefix
	})
	return mounts, nil
}

// ParseAllowExt parses comma-separated extra static file extensions (e.g.
// ".epub,.dmg" or "epub,dmg") and refuses any forbidden script/secret extension.
func ParseAllowExt(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(spec, ",") {
		e := strings.ToLower(strings.TrimSpace(raw))
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		if len(e) < 2 || len(e) > 16 || strings.ContainsAny(e[1:], "./\\ \t\r\n\x00*") {
			return nil, fmt.Errorf("invalid -static-allow-ext entry %q", raw)
		}
		if forbiddenExtensions[e] {
			return nil, fmt.Errorf("extension %q is forbidden for static file serving", e)
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out, nil
}

// New constructs a static Server by opening os.Root handles for cfg.Root and
// every entry in cfg.Mounts. Returns (nil, nil) if neither Root nor Mounts is
// configured.
func New(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.Root) == "" && len(cfg.Mounts) == 0 {
		return nil, nil
	}
	allowed := make(map[string]bool, len(defaultAllowedExtensions)+len(cfg.AllowExt))
	for ext := range defaultAllowedExtensions {
		allowed[ext] = true
	}
	for _, ext := range cfg.AllowExt {
		norm := strings.ToLower(strings.TrimSpace(ext))
		if !strings.HasPrefix(norm, ".") {
			norm = "." + norm
		}
		if forbiddenExtensions[norm] {
			return nil, fmt.Errorf("extension %q is forbidden for static file serving", norm)
		}
		allowed[norm] = true
	}

	s := &Server{
		cfg:        cfg,
		allowedExt: allowed,
		gzPool: sync.Pool{
			New: func() any {
				return gzip.NewWriter(io.Discard)
			},
		},
	}
	fail := func(err error) (*Server, error) {
		_ = s.Close()
		return nil, err
	}
	if strings.TrimSpace(cfg.Root) != "" {
		absRoot, err := filepath.Abs(strings.TrimSpace(cfg.Root))
		if err != nil {
			return fail(fmt.Errorf("static root %q: %w", cfg.Root, err))
		}
		info, err := os.Stat(absRoot)
		if err != nil || !info.IsDir() {
			return fail(fmt.Errorf("static root %q must be an existing directory", cfg.Root))
		}
		r, err := os.OpenRoot(absRoot)
		if err != nil {
			return fail(fmt.Errorf("open static root %q: %w", absRoot, err))
		}
		s.root = r
	}

	mounts := append([]Mount(nil), cfg.Mounts...)
	sort.Slice(mounts, func(i, j int) bool {
		if len(mounts[i].Prefix) != len(mounts[j].Prefix) {
			return len(mounts[i].Prefix) > len(mounts[j].Prefix)
		}
		return mounts[i].Prefix < mounts[j].Prefix
	})
	for _, m := range mounts {
		r, err := os.OpenRoot(m.Dir)
		if err != nil {
			return fail(fmt.Errorf("open static mount %s=%s: %w", m.Prefix, m.Dir, err))
		}
		s.mounts = append(s.mounts, openMount{prefix: m.Prefix, dir: m.Dir, root: r})
	}
	return s, nil
}

// Close releases all os.Root file descriptors held by s. Safe on nil.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	var errs []error
	if s.root != nil {
		if err := s.root.Close(); err != nil {
			errs = append(errs, err)
		}
		s.root = nil
	}
	for i := range s.mounts {
		if s.mounts[i].root != nil {
			if err := s.mounts[i].root.Close(); err != nil {
				errs = append(errs, err)
			}
			s.mounts[i].root = nil
		}
	}
	return errors.Join(errs...)
}

// MatchMount reports whether urlPath falls under one of the explicit
// -static-mounts prefixes.
func (s *Server) MatchMount(urlPath string) bool {
	if s == nil {
		return false
	}
	for _, m := range s.mounts {
		if urlPath == m.prefix || strings.HasPrefix(urlPath, m.prefix+"/") {
			return true
		}
	}
	return false
}

// HasRootStaticFile reports whether a GET/HEAD request maps to an existing,
// allowed static file (or blocked dotfile/forbidden non-PHP file) under
// -static-root or -static-mounts. Used by Concert's router to offload static
// files outside -assets before they enter the waiting room.
func (s *Server) HasRootStaticFile(r *http.Request) bool {
	if s == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return false
	}
	root, subPath, inMount := s.lookupRoot(r.URL.Path)
	if root == nil {
		return false
	}
	rel, isDir, kind := resolvePath(subPath)
	switch kind {
	case pathBadTraversal, pathDotfile:
		// Let Serve handle forbidden dotfiles/traversals directly (never wake origin).
		return true
	case pathWellKnown:
		return false
	}
	if rel == "" || isDir {
		if !s.cfg.ServeDirIndex {
			return false
		}
		idx := "index.html"
		if rel != "" {
			idx = rel + "/index.html"
		}
		info, err := root.Stat(idx)
		return err == nil && info.Mode().IsRegular()
	}
	ext := strings.ToLower(path.Ext(rel))
	if ext == "" || phpExtensions[ext] {
		return false
	}
	if forbiddenExtensions[ext] {
		return true
	}
	if !s.allowedExt[ext] {
		return inMount && !s.cfg.Fallback
	}
	info, err := root.Stat(rel)
	if err != nil {
		return inMount && !s.cfg.Fallback
	}
	return info.Mode().IsRegular()
}

type pathKind int

const (
	pathOK pathKind = iota
	pathBadTraversal
	pathDotfile
	pathWellKnown
)

// resolvePath validates a URL path and returns a clean relative path suitable
// for os.Root.Open. It rejects NUL bytes, backslashes, ".." traversal, and
// dotfile segments before cleaning so sneaky encoded paths never escape.
func resolvePath(urlPath string) (rel string, isDir bool, kind pathKind) {
	if urlPath == "" || urlPath[0] != '/' {
		return "", false, pathBadTraversal
	}
	if strings.ContainsAny(urlPath, "\x00\\") {
		return "", false, pathBadTraversal
	}
	isDir = strings.HasSuffix(urlPath, "/")
	rawSegs := strings.Split(urlPath[1:], "/")
	segs := make([]string, 0, len(rawSegs))
	for i, seg := range rawSegs {
		if seg == "" {
			continue
		}
		if seg == ".." || seg == "." {
			return "", false, pathBadTraversal
		}
		if seg[0] == '.' {
			// Allow RFC 8615 /.well-known/* to pass through (e.g. ACME/security.txt)
			// unless a deeper segment is also hidden.
			if i == 0 && seg == ".well-known" {
				for _, rest := range rawSegs[1:] {
					if rest == ".." || rest == "." {
						return "", false, pathBadTraversal
					}
					if len(rest) > 0 && rest[0] == '.' {
						return "", false, pathDotfile
					}
				}
				return "", false, pathWellKnown
			}
			return "", false, pathDotfile
		}
		segs = append(segs, seg)
	}
	return strings.Join(segs, "/"), isDir, pathOK
}

func (s *Server) lookupRoot(urlPath string) (root *os.Root, subPath string, inMount bool) {
	for _, m := range s.mounts {
		if urlPath == m.prefix {
			return m.root, "/", true
		}
		if strings.HasPrefix(urlPath, m.prefix+"/") {
			return m.root, urlPath[len(m.prefix):], true
		}
	}
	if s.root != nil {
		return s.root, urlPath, false
	}
	return nil, "", false
}

// Serve attempts to serve r from disk. When authoritative is true (explicit
// -static-mounts or Concert -assets / -asset-public paths), missing allowed
// static files return ResultNotFound unless Config.Fallback is enabled.
// Serve writes the HTTP response ONLY when returning ResultServed.
func (s *Server) Serve(w http.ResponseWriter, r *http.Request, authoritative bool) Result {
	if s == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return ResultPassThrough
	}
	root, subPath, inMount := s.lookupRoot(r.URL.Path)
	if root == nil {
		return ResultPassThrough
	}
	if inMount {
		authoritative = true
	}

	rel, isDir, kind := resolvePath(subPath)
	switch kind {
	case pathBadTraversal, pathDotfile:
		return ResultForbidden
	case pathWellKnown:
		return ResultPassThrough
	}

	if rel == "" || isDir {
		if !s.cfg.ServeDirIndex {
			return ResultPassThrough
		}
		idx := "index.html"
		if rel != "" {
			idx = rel + "/index.html"
		}
		return s.serveFile(w, r, root, idx, ".html", false)
	}

	ext := strings.ToLower(path.Ext(rel))
	if ext == "" {
		if inMount && !s.cfg.Fallback {
			return ResultNotFound
		}
		return ResultPassThrough
	}
	if phpExtensions[ext] {
		// Never serve PHP source code as static text; hand off to FastCGI / upstream.
		return ResultPassThrough
	}
	if forbiddenExtensions[ext] {
		return ResultForbidden
	}
	if !s.allowedExt[ext] {
		if inMount && !s.cfg.Fallback {
			return ResultForbidden
		}
		return ResultPassThrough
	}

	return s.serveFile(w, r, root, rel, ext, authoritative)
}

func (s *Server) serveFile(w http.ResponseWriter, r *http.Request, root *os.Root, rel, ext string, authoritative bool) Result {
	f, err := root.Open(rel)
	if err != nil {
		if authoritative && !s.cfg.Fallback {
			return ResultNotFound
		}
		return ResultPassThrough
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		if err == nil && info.IsDir() && s.cfg.ServeDirIndex {
			idx := rel + "/index.html"
			if st, e := root.Stat(idx); e == nil && st.Mode().IsRegular() {
				return s.serveFile(w, r, root, idx, ".html", false)
			}
		}
		if err == nil && info.IsDir() {
			return ResultPassThrough
		}
		if authoritative && !s.cfg.Fallback {
			return ResultNotFound
		}
		return ResultPassThrough
	}

	contentType := mimeTypeFor(ext)
	hasRange := r.Header.Get("Range") != ""
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	if s.cfg.CacheControl != "" && h.Get("Cache-Control") == "" {
		h.Set("Cache-Control", s.cfg.CacheControl)
	}

	// 1. Precompressed sidecars (.br preferred over .gz) when no Range header is sent.
	if !hasRange {
		for _, cand := range []struct {
			enc    string
			suffix string
		}{
			{"br", ".br"},
			{"gzip", ".gz"},
		} {
			if !acceptsEncoding(r, cand.enc) {
				continue
			}
			sf, serr := root.Open(rel + cand.suffix)
			if serr != nil {
				continue
			}
			sinfo, stErr := sf.Stat()
			if stErr != nil || !sinfo.Mode().IsRegular() {
				_ = sf.Close()
				continue
			}
			_ = f.Close()
			defer sf.Close()
			etag := makeETag(sinfo, cand.enc)
			h.Set("Content-Type", contentType)
			h.Set("Content-Encoding", cand.enc)
			appendVary(h, "Accept-Encoding")
			h.Set("ETag", etag)
			if etagMatches(r.Header.Get("If-None-Match"), etag) {
				h.Set("Last-Modified", sinfo.ModTime().UTC().Format(http.TimeFormat))
				w.WriteHeader(http.StatusNotModified)
				return ResultServed
			}
			http.ServeContent(w, r, path.Base(rel), sinfo.ModTime(), sf)
			return ResultServed
		}

		// 2. On-the-fly stdlib gzip for compressible files >= 1 KiB.
		if s.cfg.Compress && acceptsEncoding(r, "gzip") && info.Size() >= minGzipBytes && isCompressibleMIME(contentType) {
			defer f.Close()
			etag := makeETag(info, "gz")
			h.Set("Content-Type", contentType)
			h.Set("Content-Encoding", "gzip")
			appendVary(h, "Accept-Encoding")
			h.Set("ETag", etag)
			h.Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
			if etagMatches(r.Header.Get("If-None-Match"), etag) {
				w.WriteHeader(http.StatusNotModified)
				return ResultServed
			}
			if ims := r.Header.Get("If-Modified-Since"); ims != "" && r.Header.Get("If-None-Match") == "" {
				if t, perr := http.ParseTime(ims); perr == nil && !info.ModTime().Truncate(1e9).After(t) {
					w.WriteHeader(http.StatusNotModified)
					return ResultServed
				}
			}
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodHead {
				return ResultServed
			}
			gw := s.gzPool.Get().(*gzip.Writer)
			gw.Reset(w)
			_, _ = io.Copy(gw, f)
			_ = gw.Close()
			gw.Reset(io.Discard)
			s.gzPool.Put(gw)
			return ResultServed
		}
	}

	// 3. Uncompressed / Range serving via http.ServeContent.
	defer f.Close()
	etag := makeETag(info, "")
	h.Set("Content-Type", contentType)
	if isCompressibleMIME(contentType) {
		appendVary(h, "Accept-Encoding")
	}
	h.Set("ETag", etag)
	if !hasRange && etagMatches(r.Header.Get("If-None-Match"), etag) {
		h.Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusNotModified)
		return ResultServed
	}
	http.ServeContent(w, r, path.Base(rel), info.ModTime(), f)
	return ResultServed
}

func makeETag(info os.FileInfo, enc string) string {
	b := strconv.FormatInt(info.ModTime().Unix(), 16) + "-" + strconv.FormatInt(info.Size(), 16)
	if enc != "" {
		b += "-" + enc
	}
	return `W/"` + b + `"`
}

func etagMatches(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}
	if header == "*" {
		return true
	}
	norm := func(t string) string {
		t = strings.TrimSpace(t)
		t = strings.TrimPrefix(t, "W/")
		return t
	}
	want := norm(etag)
	for _, part := range strings.Split(header, ",") {
		if norm(part) == want {
			return true
		}
	}
	return false
}

func appendVary(h http.Header, token string) {
	for _, existing := range h.Values("Vary") {
		for _, part := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return
			}
		}
	}
	h.Add("Vary", token)
}

func acceptsEncoding(r *http.Request, enc string) bool {
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
			if q > 0 && strings.EqualFold(name, enc) {
				return true
			}
		}
	}
	return false
}

var extraMIMETypes = map[string]string{
	".css":         "text/css; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".cjs":         "text/javascript; charset=utf-8",
	".map":         "application/json; charset=utf-8",
	".json":        "application/json; charset=utf-8",
	".webmanifest": "application/manifest+json; charset=utf-8",
	".svg":         "image/svg+xml",
	".webp":        "image/webp",
	".avif":        "image/avif",
	".ico":         "image/x-icon",
	".woff":        "font/woff",
	".woff2":       "font/woff2",
	".ttf":         "font/ttf",
	".otf":         "font/otf",
	".eot":         "application/vnd.ms-fontobject",
	".wasm":        "application/wasm",
	".mp4":         "video/mp4",
	".webm":        "video/webm",
	".mp3":         "audio/mpeg",
	".m4a":         "audio/mp4",
	".ogg":         "audio/ogg",
	".ogv":         "video/ogg",
	".oga":         "audio/ogg",
	".wav":         "audio/wav",
	".xml":         "application/xml; charset=utf-8",
	".txt":         "text/plain; charset=utf-8",
	".html":        "text/html; charset=utf-8",
	".htm":         "text/html; charset=utf-8",
}

func mimeTypeFor(ext string) string {
	if ct, ok := extraMIMETypes[ext]; ok {
		return ct
	}
	if ct := mime.TypeByExtension(ext); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

func isCompressibleMIME(ct string) bool {
	if semi := strings.IndexByte(ct, ';'); semi >= 0 {
		ct = ct[:semi]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	switch ct {
	case "application/javascript", "application/json", "application/xml",
		"application/manifest+json", "image/svg+xml", "application/wasm":
		return true
	}
	return false
}
