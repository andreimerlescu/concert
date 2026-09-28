package gateway

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/andreimerlescu/concert/internal/x402"
)

// Record is one journaled authorization. The latest line for an ID wins.
type Record struct {
	ID       string               `json:"id"`
	Terms    json.RawMessage      `json:"terms"`
	Payload  json.RawMessage      `json:"payload"`
	Payer    string               `json:"payer"`
	State    string               `json:"state"` // pending, settled, unknown
	Response *x402.SettleResponse `json:"response,omitempty"`
	Created  time.Time            `json:"created"`
	Updated  time.Time            `json:"updated"`
}

// Journal is the gateway's durable settlement log: one exclusively locked,
// fsync'd JSON-lines file. An authorization is recorded as pending before
// it is submitted, so a crash can never lead to a second submission.
type Journal struct {
	mu      sync.Mutex
	file    *os.File
	lock    *os.File
	bad     error
	records map[string]Record
}

func OpenJournal(dir string) (*Journal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "settlements.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(lock); err != nil {
		lock.Close()
		return nil, errors.New("settlement journal is already open by another gateway or reconcile process")
	}
	path := filepath.Join(dir, "settlements.jsonl")
	_, statErr := os.Stat(path)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		unlockFile(lock)
		lock.Close()
		return nil, err
	}
	j := &Journal{file: f, lock: lock, records: map[string]Record{}}
	fail := func(err error) (*Journal, error) { j.Close(); return nil, err }
	if os.IsNotExist(statErr) {
		if err := syncDir(dir); err != nil {
			return fail(err)
		}
	}
	// A partial final line might be a settlement; never discard it silently.
	if st, err := f.Stat(); err == nil && st.Size() > 0 {
		var b [1]byte
		if _, err := f.ReadAt(b[:], st.Size()-1); err != nil || b[0] != '\n' {
			return fail(errors.New("incomplete settlement journal; reconciliation required"))
		}
	}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	for s.Scan() {
		var r Record
		if err := json.Unmarshal(s.Bytes(), &r); err != nil || r.ID == "" {
			return fail(fmt.Errorf("invalid settlement journal; restore before startup: %v", err))
		}
		if r.State != "pending" && r.State != "settled" && r.State != "unknown" {
			return fail(errors.New("invalid settlement journal state"))
		}
		if prev, ok := j.records[r.ID]; ok && prev.State == "settled" && r.State != "settled" {
			return fail(errors.New("settlement journal regresses a settled record"))
		}
		j.records[r.ID] = r
	}
	if err := s.Err(); err != nil {
		return fail(err)
	}
	return j, nil
}

// Fingerprint identifies an authorization: network, scheme and the
// canonical payload, so key order or spacing never makes a new one.
func Fingerprint(r x402.Requirements, payload json.RawMessage) (string, error) {
	c, err := x402.Canonical(payload)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append([]byte(r.Network+"/"+r.Scheme+"/"), c...))
	return hex.EncodeToString(h[:]), nil
}

func (j *Journal) Get(id string) (Record, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	r, ok := j.records[id]
	return r, ok
}

// Write durably appends r. Any I/O failure suspends the journal.
func (j *Journal) Write(r Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.bad != nil {
		return j.bad
	}
	if prev, ok := j.records[r.ID]; ok && prev.State == "settled" {
		return errors.New("record already settled")
	}
	r.Updated = time.Now().UTC()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if n, err := j.file.Write(b); err != nil || n != len(b) {
		j.bad = errors.New("settlement journal write failed; settlement suspended")
		return j.bad
	}
	if err := j.file.Sync(); err != nil {
		j.bad = errors.New("settlement journal sync failed; settlement suspended")
		return j.bad
	}
	j.records[r.ID] = r
	return nil
}

func (j *Journal) Close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.bad == nil {
		j.bad = errors.New("settlement journal closed")
	}
	if j.file != nil {
		j.file.Close()
		j.file = nil
	}
	if j.lock != nil {
		unlockFile(j.lock)
		j.lock.Close()
		j.lock = nil
	}
}
