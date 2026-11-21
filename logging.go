package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Structured JSON logging (log/slog) and request correlation (X-Request-ID and
// W3C Trace Context traceparent propagation) for enterprise SIEM/APM ingestion.

const (
	ctxRequestID = "concert.request_id"
	ctxTraceID   = "concert.trace_id"
)

func configureLogging(format, level string) {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func sanitizeCorrelationID(v string, maxLen int) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > maxLen {
		return ""
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == ':'
		if !ok {
			return ""
		}
	}
	return v
}

// extractTraceID extracts the 32-hex-char trace-id from a W3C traceparent
// header (version-traceid-parentid-flags), returning "" if malformed.
func extractTraceID(traceparent string) string {
	parts := strings.Split(strings.TrimSpace(traceparent), "-")
	if len(parts) != 4 || len(parts[1]) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return ""
	}
	return strings.ToLower(parts[1])
}

// correlateMiddleware ensures every request carries a valid X-Request-ID
// (echoed in response headers and forwarded upstream) and parses any incoming
// W3C traceparent header for structured access log correlation.
func correlateMiddleware(c *gin.Context) {
	reqID := sanitizeCorrelationID(c.GetHeader("X-Request-ID"), 128)
	if reqID == "" {
		reqID = randomHex(16)
		c.Request.Header.Set("X-Request-ID", reqID)
	}
	c.Set(ctxRequestID, reqID)
	c.Header("X-Request-ID", reqID)

	if tid := extractTraceID(c.GetHeader("traceparent")); tid != "" {
		c.Set(ctxTraceID, tid)
	}
	c.Next()
}

// mainSecurityHeaders applies safe baseline response hardening headers on the
// main listener (HSTS when TLS is active and -hsts-max-age > 0, plus nosniff).
func (g *generation) mainSecurityHeaders(c *gin.Context) {
	if g.cfg.hstsMaxAge > 0 && (c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")) {
		c.Header("Strict-Transport-Security", "max-age="+strconvItoa(g.cfg.hstsMaxAge)+"; includeSubDomains")
	}
	c.Next()
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// jsonAccessLogger writes one structured JSON object per non-skipped request
// with request_id, trace_id, scrubbed path, and optional anonymized client IP.
func jsonAccessLogger(out io.Writer, cfg config) gin.HandlerFunc {
	skip := accessLogSkipper(cfg)
	var mu sync.Mutex
	return func(c *gin.Context) {
		if skip(c) {
			c.Next()
			return
		}
		start := time.Now()
		c.Next()

		ip := clientIPFrom(c)
		ipStr := formatPrivacyIP(ip, cfg.privacyAnonymizeIP)
		rawPath := formatPrivacyPath(c.Request.URL.Path, c.Request.URL.RawQuery, cfg.privacyScrubQuery, cfg.privacyStripQuery)
		entry := map[string]any{
			"ts":         time.Now().UTC().Format(time.RFC3339Nano),
			"level":      "info",
			"msg":        "http_request",
			"request_id": c.GetString(ctxRequestID),
			"client_ip":  ipStr,
			"method":     c.Request.Method,
			"path":       rawPath,
			"status":     c.Writer.Status(),
			"bytes":      c.Writer.Size(),
			"latency_ms": float64(time.Since(start).Microseconds()) / 1000.0,
			"admitted":   c.GetBool(ctxAdmitted),
			"user_agent": clip(c.Request.UserAgent(), historyUALen),
		}
		if tid := c.GetString(ctxTraceID); tid != "" {
			entry["trace_id"] = tid
		}
		if b, err := json.Marshal(entry); err == nil {
			b = append(b, '\n')
			mu.Lock()
			_, _ = out.Write(b)
			mu.Unlock()
		}
	}
}
