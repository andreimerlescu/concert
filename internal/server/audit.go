package server

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Tamper-evident, hash-chained JSON-lines audit log for administrative and
// security-relevant actions (portal sign-ins, settings changes, bans/unbans,
// queue promotions/kicks, DSAR privacy exports/erasures, and API operations).
//
// Each record links cryptographically to the previous record's hash (using
// HMAC-SHA256 keyed from CONCERT_ADMIT_SECRET when available, or plain SHA-256
// otherwise). Operators and auditors can verify chain integrity offline with:
//
//	concert audit verify /var/lib/concert/data/audit.jsonl

const (
	auditLogName     = "audit.jsonl"
	auditLogMaxBytes = 64 << 20
	auditLogKeep     = 4
	auditGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

type auditEvent struct {
	Seq       uint64         `json:"seq"`
	Timestamp string         `json:"ts"`
	Actor     string         `json:"actor"`
	Role      string         `json:"role,omitempty"`
	Source    string         `json:"source"`
	Action    string         `json:"action"`
	Target    string         `json:"target,omitempty"`
	Outcome   string         `json:"outcome"`
	ClientIP  string         `json:"ip,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
	PrevHash  string         `json:"prev_hash"`
	Hash      string         `json:"hash"`
}

type auditLogger struct {
	mu       sync.Mutex
	path     string
	key      []byte // HMAC key derived from admitSecret; nil uses plain SHA-256
	seq      uint64
	prevHash string
	file     *os.File
	size     int64
	closed   bool

	written atomic.Int64
	errors  atomic.Int64
}

func auditLogPath(cfg config) string {
	v := strings.TrimSpace(cfg.auditLog)
	if strings.EqualFold(v, "off") || strings.EqualFold(v, "none") {
		return ""
	}
	if v != "" {
		return v
	}
	if cfg.dataDir == "" {
		return ""
	}
	return filepath.Join(cfg.dataDir, auditLogName)
}

func deriveAuditKey(secret []byte) []byte {
	if len(secret) == 0 {
		return nil
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("concert/audit/chain-key"))
	return m.Sum(nil)
}

func newAuditLogger(path string, secret []byte) *auditLogger {
	al := &auditLogger{
		path:     path,
		key:      deriveAuditKey(secret),
		prevHash: auditGenesisHash,
	}
	if path == "" {
		return al
	}
	if err := al.resumeChain(); err != nil {
		log.Printf("audit: warning resuming chain from %s: %v", path, err)
	}
	return al
}

// resumeChain reads the last valid line of an existing audit log so the hash
// chain continues unbroken across restarts.
func (a *auditLogger) resumeChain() error {
	f, err := os.Open(a.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err == nil {
		a.size = info.Size()
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var last auditEvent
	var found bool
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev auditEvent
		if err := json.Unmarshal([]byte(line), &ev); err == nil && ev.Hash != "" {
			last = ev
			found = true
		}
	}
	if found {
		a.seq = last.Seq
		a.prevHash = last.Hash
	}
	return sc.Err()
}

func computeAuditHash(ev auditEvent, key []byte) string {
	// Hash canonical JSON with Hash cleared so verification is deterministic.
	ev.Hash = ""
	payload, _ := json.Marshal(ev)
	if len(key) > 0 {
		m := hmac.New(sha256.New, key)
		m.Write(payload)
		return hex.EncodeToString(m.Sum(nil))
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// record writes a single hash-chained audit entry synchronously (for durability
// before an administrative API responds) and emits a structured log line when
// JSON logging is enabled.
func (a *auditLogger) record(ev auditEvent) {
	if a == nil {
		return
	}
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if ev.Outcome == "" {
		ev.Outcome = "allow"
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	a.seq++
	ev.Seq = a.seq
	ev.PrevHash = a.prevHash
	ev.Hash = computeAuditHash(ev, a.key)
	a.prevHash = ev.Hash
	a.written.Add(1)

	if a.path == "" {
		return
	}

	line, err := json.Marshal(ev)
	if err != nil {
		a.errors.Add(1)
		return
	}
	line = append(line, '\n')

	if err := a.writeLocked(line); err != nil {
		a.errors.Add(1)
		log.Printf("audit: write error: %v", err)
	}
}

func (a *auditLogger) writeLocked(line []byte) error {
	if a.file != nil && a.size+int64(len(line)) > auditLogMaxBytes {
		_ = a.file.Sync()
		_ = a.file.Close()
		a.file = nil
		rotateFiles(a.path, auditLogKeep)
		a.size = 0
	}
	if a.file == nil {
		if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if info, err := f.Stat(); err == nil {
			a.size = info.Size()
		}
		a.file = f
	}
	n, err := a.file.Write(line)
	if err != nil {
		_ = a.file.Close()
		a.file = nil
		return err
	}
	a.size += int64(n)
	return a.file.Sync()
}

func (a *auditLogger) close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	if a.file != nil {
		_ = a.file.Sync()
		_ = a.file.Close()
		a.file = nil
	}
}

func (a *auditLogger) describe() string {
	if a == nil || a.path == "" {
		return "memory only (set -audit-log or -data-dir to persist)"
	}
	mode := "SHA-256 chain"
	if len(a.key) > 0 {
		mode = "HMAC-SHA256 chain"
	}
	return fmt.Sprintf("%s (%s, %d events)", a.path, mode, a.written.Load())
}

func rotateFiles(base string, keep int) {
	if keep <= 0 {
		_ = os.Remove(base)
		return
	}
	for i := keep; i >= 1; i-- {
		dst := base + "." + strconv.Itoa(i)
		src := base
		if i > 1 {
			src = base + "." + strconv.Itoa(i-1)
		}
		if _, err := os.Stat(src); err == nil {
			_ = os.Rename(src, dst)
		}
	}
}

// verifyAuditFile validates every entry in an audit.jsonl file, checking
// sequence continuity, prev_hash linkage, and cryptographic hash integrity.
func verifyAuditFile(path string, secret []byte) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	key := deriveAuditKey(secret)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var count int
	var expectedPrev = auditGenesisHash
	var expectedSeq uint64 = 1

	for lineNo := 1; sc.Scan(); lineNo++ {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var ev auditEvent
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			return count, fmt.Errorf("line %d: invalid JSON: %w", lineNo, err)
		}
		if count == 0 && ev.Seq > 1 {
			// Rotated file may start mid-chain; accept its first prev_hash and seq.
			expectedSeq = ev.Seq
			expectedPrev = ev.PrevHash
		}
		if ev.Seq != expectedSeq {
			return count, fmt.Errorf("line %d: sequence gap: got %d, want %d", lineNo, ev.Seq, expectedSeq)
		}
		if ev.PrevHash != expectedPrev {
			return count, fmt.Errorf("line %d: chain break at seq %d: prev_hash mismatch", lineNo, ev.Seq)
		}
		wantHash := computeAuditHash(ev, key)
		if !hmac.Equal([]byte(ev.Hash), []byte(wantHash)) {
			return count, fmt.Errorf("line %d: tampered record at seq %d: hash mismatch", lineNo, ev.Seq)
		}
		expectedPrev = ev.Hash
		expectedSeq++
		count++
	}
	if err := sc.Err(); err != nil {
		return count, err
	}
	return count, nil
}

// runAudit handles the "concert audit verify <file>" CLI subcommand.
func runAudit(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New("usage: concert audit verify <audit.jsonl>")
	}
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return errors.New("usage: concert audit verify <audit.jsonl>")
	}
	secret := []byte(envOrFile("CONCERT_ADMIT_SECRET", ""))
	n, err := verifyAuditFile(rest[0], secret)
	if err != nil {
		return fmt.Errorf("audit verification FAILED: %w", err)
	}
	fmt.Fprintf(stdout, "OK: verified %d chained audit event(s) in %s\n", n, rest[0])
	return nil
}
