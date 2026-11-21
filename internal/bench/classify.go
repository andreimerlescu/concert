package bench

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
)

// Asset classes the report breaks results down by. These are the file
// types an electronic-commerce site serves.
const (
	ClassHTML     = "html"
	ClassImage    = "image"
	ClassScript   = "script"
	ClassStyle    = "style"
	ClassFont     = "font"
	ClassAudio    = "audio"
	ClassVideo    = "video"
	ClassArchive  = "archive"
	ClassDocument = "document"
	ClassText     = "text"
	ClassData     = "data"
	ClassOther    = "other"
)

var extClasses = map[string]string{
	".png": ClassImage, ".jpg": ClassImage, ".jpeg": ClassImage, ".gif": ClassImage, ".webp": ClassImage,
	".avif": ClassImage, ".svg": ClassImage, ".ico": ClassImage, ".bmp": ClassImage, ".tif": ClassImage, ".tiff": ClassImage,
	".js": ClassScript, ".mjs": ClassScript,
	".css":  ClassStyle,
	".woff": ClassFont, ".woff2": ClassFont, ".ttf": ClassFont, ".otf": ClassFont, ".eot": ClassFont,
	".mp3": ClassAudio, ".ogg": ClassAudio, ".oga": ClassAudio, ".wav": ClassAudio, ".flac": ClassAudio, ".m4a": ClassAudio, ".aac": ClassAudio, ".opus": ClassAudio,
	".mp4": ClassVideo, ".webm": ClassVideo, ".m4v": ClassVideo, ".mov": ClassVideo, ".ogv": ClassVideo, ".m3u8": ClassVideo, ".ts": ClassVideo,
	".zip": ClassArchive, ".gz": ClassArchive, ".tgz": ClassArchive, ".tar": ClassArchive, ".7z": ClassArchive, ".rar": ClassArchive, ".bz2": ClassArchive, ".xz": ClassArchive,
	".pdf": ClassDocument, ".doc": ClassDocument, ".docx": ClassDocument, ".xls": ClassDocument, ".xlsx": ClassDocument, ".ppt": ClassDocument, ".pptx": ClassDocument, ".epub": ClassDocument,
	".txt": ClassText, ".csv": ClassText, ".md": ClassText,
	".json": ClassData, ".xml": ClassData, ".webmanifest": ClassData, ".map": ClassData,
}

// extClass is the class a file extension implies, or "".
func extClass(ext string) string {
	return extClasses[strings.ToLower(ext)]
}

// classify names the class of a response from its Content-Type, falling
// back to the URL's extension.
func classify(contentType, rawURL string) string {
	mt, _, _ := mime.ParseMediaType(contentType)
	switch {
	case mt == "text/html" || mt == "application/xhtml+xml":
		return ClassHTML
	case strings.HasPrefix(mt, "image/"):
		return ClassImage
	case mt == "text/css":
		return ClassStyle
	case mt == "text/javascript" || mt == "application/javascript" || mt == "application/x-javascript" || mt == "module":
		return ClassScript
	case strings.HasPrefix(mt, "font/") || mt == "application/font-woff" || mt == "application/vnd.ms-fontobject":
		return ClassFont
	case strings.HasPrefix(mt, "audio/"):
		return ClassAudio
	case strings.HasPrefix(mt, "video/") || mt == "application/vnd.apple.mpegurl" || mt == "application/x-mpegurl":
		return ClassVideo
	case mt == "application/zip" || mt == "application/gzip" || mt == "application/x-gzip" || mt == "application/x-tar" ||
		mt == "application/x-7z-compressed" || mt == "application/vnd.rar" || mt == "application/x-bzip2" || mt == "application/x-xz":
		return ClassArchive
	case mt == "application/pdf" || strings.HasPrefix(mt, "application/vnd.openxmlformats") || mt == "application/msword" || mt == "application/epub+zip":
		return ClassDocument
	case mt == "application/json" || strings.HasSuffix(mt, "+json") || mt == "application/xml" || mt == "text/xml" || strings.HasSuffix(mt, "+xml"):
		return ClassData
	case strings.HasPrefix(mt, "text/"):
		return ClassText
	}
	if u := strings.SplitN(rawURL, "?", 2)[0]; u != "" {
		if c := extClass(path.Ext(u)); c != "" {
			return c
		}
	}
	return ClassOther
}

// Failure kinds. Every one of these counts against a stage; a load-induced
// failure is exactly what the benchmark is looking for.
const (
	FailTimeout   = "timeout"       // no complete answer within -timeout
	FailRefused   = "conn_refused"  // nothing listening, or backlog full
	FailReset     = "conn_reset"    // the server dropped the connection
	FailDNS       = "dns"           // the host did not resolve
	FailTLS       = "tls"           // TLS handshake failed
	FailTruncated = "truncated"     // fewer bytes than Content-Length, or the body broke off
	FailConnOther = "conn_error"    // any other transport error
	FailThrottled = "throttled_429" // the server refused for load
)

// Findings are reported but do not fail a stage: they are properties of
// the site, not of its load.
const (
	FindNotFound  = "not_found"     // 404 or 410: a broken link
	FindClientErr = "client_error"  // other 4xx: auth walls, bad links
	FindNoRange   = "range_ignored" // media served without byte ranges
)

// failKind classifies a transport error.
func failKind(err error) string {
	var ne net.Error
	var dnsErr *net.DNSError
	var tlsErr *tls.RecordHeaderError
	var certErr *tls.CertificateVerificationError
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return FailTimeout
	case errors.As(err, &ne) && ne.Timeout():
		return FailTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return FailRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return FailReset
	case errors.As(err, &dnsErr):
		return FailDNS
	case errors.As(err, &tlsErr), errors.As(err, &certErr), strings.Contains(err.Error(), "tls:"):
		return FailTLS
	}
	return FailConnOther
}

// statusKind classifies an HTTP status: a failure kind, a finding, or "".
func statusKind(code int) (fail, finding string) {
	switch {
	case code == http.StatusTooManyRequests:
		return FailThrottled, ""
	case code >= 500:
		return "status_" + strconv.Itoa(code), ""
	case code == http.StatusNotFound || code == http.StatusGone:
		return "", FindNotFound
	case code >= 400:
		return "", FindClientErr
	}
	return "", ""
}
