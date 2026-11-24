package fastlane

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Receipt is an append-only ledger record, not a tax return. No private keys or
// signed transactions are logged. Unknown settlement is kept for reconciliation.
type Receipt struct {
	Session      string       `json:"session"`
	Fingerprint  string       `json:"fingerprint"`
	State        string       `json:"state"`
	Kind         string       `json:"kind"`
	Network      string       `json:"network"`
	Payer        string       `json:"payer"`
	Requirements Requirements `json:"requirements"`
	Transaction  string       `json:"transaction,omitempty"`
	PolicyID     string       `json:"policy_id,omitempty"`
	Started      time.Time    `json:"started"`
	Settled      time.Time    `json:"settled,omitempty"`
	Expires      time.Time    `json:"expires,omitempty"`
	Response     *Settlement  `json:"response,omitempty"`
}

type ledger struct {
	mu            sync.Mutex
	dir           string
	file          *os.File
	lock          *os.File
	bad           error
	max           int
	bySession     map[string]Receipt
	byFingerprint map[string]string
	receipts      map[string]Receipt
	byTransaction map[string]string
}

func openLedger(dir string, max int) (*ledger, error) {
	if dir == "" {
		return nil, errors.New("fast lane requires persistent -data-dir")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "fastlane.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockJournal(lock); err != nil {
		lock.Close()
		return nil, errors.New("fastlane journal is already open by another Concert process")
	}
	path := filepath.Join(dir, "fastlane.jsonl")
	_, statErr := os.Stat(path)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		lock.Close()
		return nil, err
	}
	// A receipt synced into a file whose directory entry was lost in a crash
	// is lost too, so persist the entry of a newly created journal.
	if os.IsNotExist(statErr) {
		if err = syncDir(dir); err != nil {
			f.Close()
			lock.Close()
			return nil, err
		}
	}
	l := &ledger{dir: dir, file: f, lock: lock, max: max, bySession: map[string]Receipt{}, byFingerprint: map[string]string{}, receipts: map[string]Receipt{}, byTransaction: map[string]string{}}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 128<<10)
	for s.Scan() {
		var r Receipt
		if err = json.Unmarshal(s.Bytes(), &r); err != nil {
			l.close()
			return nil, fmt.Errorf("invalid payment journal; restore/reconcile before startup: %w", err)
		}
		if err = l.validate(r); err != nil {
			l.close()
			return nil, err
		}
		l.apply(r)
	}
	if err = s.Err(); err != nil {
		l.close()
		return nil, err
	}
	// A partial final line is never silently discarded: it might be a settled payment.
	if st, e := f.Stat(); e == nil && st.Size() > 0 {
		var b [1]byte
		_, e = f.ReadAt(b[:], st.Size()-1)
		if e != nil || b[0] != '\n' {
			l.close()
			return nil, errors.New("incomplete payment journal; reconciliation required")
		}
	}
	return l, nil
}

func (l *ledger) validate(r Receipt) error {
	if r.Session == "" || r.Fingerprint == "" || r.Network == "" {
		return errors.New("incomplete receipt")
	}
	if r.State != "pending" && r.State != "settled" && r.State != "unknown" {
		return errors.New("invalid receipt state")
	}
	if s, ok := l.byFingerprint[r.Fingerprint]; ok && s != r.Session {
		return errors.New("payment replay")
	}
	if r.Transaction != "" {
		if fp, ok := l.byTransaction[r.Network+":"+r.Transaction]; ok && fp != r.Fingerprint {
			return errors.New("transaction already redeemed")
		}
	}
	return nil
}

func (l *ledger) apply(r Receipt) {
	l.bySession[r.Session] = r
	l.byFingerprint[r.Fingerprint] = r.Session
	l.receipts[r.Fingerprint] = r
	if r.Transaction != "" {
		l.byTransaction[r.Network+":"+r.Transaction] = r.Fingerprint
	}
}
func (l *ledger) get(s string) (Receipt, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.bySession[s]
	return r, ok
}
func (l *ledger) write(r Receipt) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.bad != nil {
		return l.bad
	}
	if err := l.validate(r); err != nil {
		return err
	}
	if _, ok := l.byFingerprint[r.Fingerprint]; !ok && len(l.byFingerprint) >= l.max {
		return errors.New("receipt capacity reached; operator archive/migration required")
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if n, e := l.file.Write(data); e != nil || n != len(data) {
		l.bad = errors.New("payment journal write failed; admission suspended")
		return l.bad
	}
	if err = l.file.Sync(); err != nil {
		l.bad = errors.New("payment journal sync failed; admission suspended")
		return l.bad
	}
	l.apply(r)
	return nil
}
func (l *ledger) healthy() bool { l.mu.Lock(); defer l.mu.Unlock(); return l.bad == nil }

// close is safe while a request is still settling: later writes fail closed
// instead of reaching a closed file.
func (l *ledger) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.bad == nil {
		l.bad = errors.New("payment journal closed")
	}
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}
	if l.lock != nil {
		unlockJournal(l.lock)
		l.lock.Close()
		l.lock = nil
	}
}
func (l *ledger) summary() map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := map[string]int{"settled": 0, "pending": 0, "unknown": 0}
	for _, r := range l.bySession {
		n[r.State]++
	}
	used := len(l.byFingerprint)
	pct := 0
	if l.max > 0 {
		pct = (used * 100) / l.max
	}
	return map[string]any{
		"states":       n,
		"receipts":     used,
		"capacity":     l.max,
		"records_used": used,
		"max_records":  l.max,
		"usage_pct":    pct,
		"healthy":      l.bad == nil,
	}
}

func (l *ledger) stats() (used, max, unresolved int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	used = len(l.byFingerprint)
	max = l.max
	for _, r := range l.receipts {
		if r.State == "pending" || r.State == "unknown" {
			unresolved++
		}
	}
	return used, max, unresolved
}

func (l *ledger) unresolved() []Receipt {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Receipt
	for _, r := range l.receipts {
		if r.State == "pending" || r.State == "unknown" {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Started.Equal(out[j].Started) {
			return out[i].Started.Before(out[j].Started)
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

func (l *ledger) fingerprint(fp string) (Receipt, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.receipts[fp]
	return r, ok
}

func (l *ledger) slideExpiry(sessionID string, nextExp time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.bySession[sessionID]
	if !ok || r.State != "settled" || !nextExp.After(r.Expires) {
		return
	}
	r.Expires = nextExp
	l.bySession[sessionID] = r
	l.receipts[r.Fingerprint] = r
}

func (l *ledger) setMax(max int) {
	if max <= 0 {
		return
	}
	l.mu.Lock()
	l.max = max
	l.mu.Unlock()
}

// archiveOnline compacts expired settled receipts older than olderThan while
// Concert stays live, keeping fastlane.lock continuously held under l.mu.
func (l *ledger) archiveOnline(olderThan time.Duration, dryRun bool, now time.Time) (ArchiveReport, error) {
	var rep ArchiveReport
	if olderThan < 0 {
		return rep, errors.New("older_than must be non-negative")
	}
	now = now.UTC()
	cutoff := now.Add(-olderThan)
	rep.DryRun = dryRun
	rep.OlderThan = olderThan.String()
	rep.Cutoff = cutoff

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.bad != nil {
		return rep, l.bad
	}
	order := make([]string, 0, len(l.receipts))
	for fp := range l.receipts {
		order = append(order, fp)
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := l.receipts[order[i]], l.receipts[order[j]]
		if !a.Started.Equal(b.Started) {
			return a.Started.Before(b.Started)
		}
		return a.Fingerprint < b.Fingerprint
	})
	rep.TotalBefore = len(order)
	var kept, archived []Receipt
	for _, fp := range order {
		r := l.receipts[fp]
		if r.State != "settled" {
			kept = append(kept, r)
			rep.KeptUnresolved++
			continue
		}
		if !r.Expires.IsZero() && !r.Expires.Before(now) {
			kept = append(kept, r)
			rep.KeptActive++
			continue
		}
		ref := r.Expires
		if ref.IsZero() {
			ref = r.Settled
		}
		if ref.IsZero() {
			ref = r.Started
		}
		if !ref.Before(cutoff) {
			kept = append(kept, r)
			rep.KeptRecent++
			continue
		}
		archived = append(archived, r)
	}
	rep.Kept = len(kept)
	rep.Archived = len(archived)
	if dryRun || len(archived) == 0 {
		return rep, nil
	}

	archiveName := fmt.Sprintf("fastlane-archive-%s.jsonl", now.Format("20060102T150405Z"))
	archivePath := filepath.Join(l.dir, archiveName)
	if _, err := os.Stat(archivePath); err == nil {
		return rep, fmt.Errorf("archive file %s already exists; wait 1s before retrying", archivePath)
	}
	sum, err := writeReceiptsAtomic(archivePath, archived)
	if err != nil {
		return rep, fmt.Errorf("write archive: %w", err)
	}
	checksumPath := archivePath + ".sha256"
	if err := writeBytesAtomic(checksumPath, []byte(fmt.Sprintf("%s  %s\n", sum, archiveName))); err != nil {
		return rep, fmt.Errorf("write archive checksum: %w", err)
	}
	if err := syncDir(l.dir); err != nil {
		return rep, fmt.Errorf("sync archive dir: %w", err)
	}

	journalPath := filepath.Join(l.dir, "fastlane.jsonl")
	if l.file != nil {
		_ = l.file.Sync()
		_ = l.file.Close()
		l.file = nil
	}
	if _, err := writeReceiptsAtomic(journalPath, kept); err != nil {
		l.bad = fmt.Errorf("online archive rewrite failed: %w", err)
		return rep, l.bad
	}
	if err := syncDir(l.dir); err != nil {
		l.bad = fmt.Errorf("online archive dir sync failed: %w", err)
		return rep, l.bad
	}
	f, err := os.OpenFile(journalPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		l.bad = fmt.Errorf("reopen compacted journal: %w", err)
		return rep, l.bad
	}
	l.file = f
	l.bySession = map[string]Receipt{}
	l.byFingerprint = map[string]string{}
	l.receipts = map[string]Receipt{}
	l.byTransaction = map[string]string{}
	for _, r := range kept {
		l.apply(r)
	}
	rep.ArchiveFile = archivePath
	rep.ChecksumFile = checksumPath
	rep.ArchiveSHA256 = sum
	return rep, nil
}
