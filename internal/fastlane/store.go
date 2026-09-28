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
	Listing      string       `json:"listing,omitempty"`   // NFT listing bought, for Kind "nft_sale"
	Delivered    *time.Time   `json:"delivered,omitempty"` // when the merchant delivered the NFT
}

type ledger struct {
	mu            sync.Mutex
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
	l := &ledger{file: f, lock: lock, max: max, bySession: map[string]Receipt{}, byFingerprint: map[string]string{}, receipts: map[string]Receipt{}, byTransaction: map[string]string{}}
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
	return map[string]any{"states": n, "receipts": len(l.byFingerprint), "capacity": l.max, "healthy": l.bad == nil}
}

func (l *ledger) fingerprint(fp string) (Receipt, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.receipts[fp]
	return r, ok
}

// withKind returns the receipts of the given kinds, oldest first.
func (l *ledger) withKind(kinds ...string) []Receipt {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Receipt
	for _, r := range l.receipts {
		for _, k := range kinds {
			if r.Kind == k {
				out = append(out, r)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out
}
