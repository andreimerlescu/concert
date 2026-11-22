package fastlane

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// ArchiveReport describes what ArchiveReceipts found and (when DryRun is
// false) archived from fastlane.jsonl.
type ArchiveReport struct {
	DryRun         bool      `json:"dry_run"`
	TotalBefore    int       `json:"total_before"`
	Kept           int       `json:"kept"`
	Archived       int       `json:"archived"`
	KeptUnresolved int       `json:"kept_unresolved"`
	KeptActive     int       `json:"kept_active"`
	KeptRecent     int       `json:"kept_recent"`
	ArchiveFile    string    `json:"archive_file,omitempty"`
	ChecksumFile   string    `json:"checksum_file,omitempty"`
	ArchiveSHA256  string    `json:"archive_sha256,omitempty"`
	OlderThan      string    `json:"older_than"`
	Cutoff         time.Time `json:"cutoff"`
}

// ArchiveReceipts compacts fastlane.jsonl offline by moving expired, settled
// receipts older than olderThan into a timestamped 0600 archive file paired
// with a .sha256 checksum file, then atomically rewriting fastlane.jsonl.
//
// Safety invariants:
//   - Acquires fastlane.lock exclusively; refuses to run while Concert holds it.
//   - Fails closed on any truncated or malformed JSONL line.
//   - Never removes pending, unknown, active (unexpired), or recent receipts.
//   - Persists and fsyncs the archive + checksum + directory entry BEFORE
//     atomically swapping fastlane.jsonl, so a crash never loses history.
func ArchiveReceipts(dir string, olderThan time.Duration, dryRun bool, now time.Time) (ArchiveReport, error) {
	var rep ArchiveReport
	if dir == "" {
		return rep, errors.New("archive-receipts requires -data-dir")
	}
	if olderThan < 0 {
		return rep, errors.New("-older-than must be non-negative")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	cutoff := now.Add(-olderThan)
	rep.DryRun = dryRun
	rep.OlderThan = olderThan.String()
	rep.Cutoff = cutoff

	lockPath := filepath.Join(dir, "fastlane.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return rep, err
	}
	if err := lockJournal(lock); err != nil {
		lock.Close()
		return rep, errors.New("fastlane journal is currently open by a running Concert process; stop Concert before archiving")
	}
	defer func() {
		unlockJournal(lock)
		_ = lock.Close()
	}()

	journalPath := filepath.Join(dir, "fastlane.jsonl")
	f, err := os.Open(journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return rep, nil
	}
	if err != nil {
		return rep, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return rep, err
	}
	if st.Size() > 0 {
		var b [1]byte
		if _, err := f.ReadAt(b[:], st.Size()-1); err != nil || b[0] != '\n' {
			f.Close()
			return rep, errors.New("incomplete payment journal; reconciliation required before archiving")
		}
	}

	// Validate every line using the same invariants as openLedger and collapse
	// append-only updates so the latest state per fingerprint wins.
	check := &ledger{
		bySession:     map[string]Receipt{},
		byFingerprint: map[string]string{},
		receipts:      map[string]Receipt{},
		byTransaction: map[string]string{},
	}
	var order []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 128<<10)
	for lineNo := 1; sc.Scan(); lineNo++ {
		var r Receipt
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			f.Close()
			return rep, fmt.Errorf("invalid payment journal at line %d; restore/reconcile before archiving: %w", lineNo, err)
		}
		if err := check.validate(r); err != nil {
			f.Close()
			return rep, fmt.Errorf("invalid payment journal at line %d: %w", lineNo, err)
		}
		check.apply(r)
		if !seen[r.Fingerprint] {
			seen[r.Fingerprint] = true
			order = append(order, r.Fingerprint)
		}
	}
	if err := sc.Err(); err != nil {
		f.Close()
		return rep, err
	}
	_ = f.Close()

	rep.TotalBefore = len(order)
	var kept, archived []Receipt
	for _, fp := range order {
		r := check.receipts[fp]
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
	archivePath := filepath.Join(dir, archiveName)
	if _, err := os.Stat(archivePath); err == nil {
		return rep, fmt.Errorf("archive file %s already exists; wait 1s or move it before retrying", archivePath)
	}

	sum, err := writeReceiptsAtomic(archivePath, archived)
	if err != nil {
		return rep, fmt.Errorf("write archive: %w", err)
	}
	checksumPath := archivePath + ".sha256"
	checksumLine := fmt.Sprintf("%s  %s\n", sum, archiveName)
	if err := writeBytesAtomic(checksumPath, []byte(checksumLine)); err != nil {
		return rep, fmt.Errorf("write archive checksum: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return rep, fmt.Errorf("sync archive directory: %w", err)
	}

	if _, err := writeReceiptsAtomic(journalPath, kept); err != nil {
		return rep, fmt.Errorf("rewrite compacted journal (archive preserved at %s): %w", archivePath, err)
	}
	if err := syncDir(dir); err != nil {
		return rep, fmt.Errorf("sync journal directory: %w", err)
	}

	rep.ArchiveFile = archivePath
	rep.ChecksumFile = checksumPath
	rep.ArchiveSHA256 = sum
	return rep, nil
}

func writeReceiptsAtomic(dst string, records []Receipt) (string, error) {
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	mw := io.MultiWriter(f, h)
	for _, r := range records {
		b, err := json.Marshal(r)
		if err != nil {
			f.Close()
			_ = os.Remove(tmp)
			return "", err
		}
		b = append(b, '\n')
		if _, err := mw.Write(b); err != nil {
			f.Close()
			_ = os.Remove(tmp)
			return "", err
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeBytesAtomic(dst string, data []byte) error {
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
