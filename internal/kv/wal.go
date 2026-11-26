package kv

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	walFileName      = "concert-kv.wal"
	snapshotFileName = "concert-kv.snapshot"

	walMagic      = "WAL1"
	snapshotMagic = "SNP1"

	walHeaderSize      = 4 + 8 + 4 + 4 // magic + seq + crc32 + length
	snapshotHeaderSize = 4 + 4 + 8     // magic + crc32 + length

	maxWALRecordBytes = DefaultMaxBulkBytes*2 + (64 << 10)
	maxSnapshotBytes  = 512 << 20 // 512 MiB safety ceiling (R3)
)

// ErrWALCorrupt is returned when a WAL or snapshot file has an invalid header
// or mid-file checksum mismatch that cannot be explained by a torn tail write.
var ErrWALCorrupt = errors.New("wal or snapshot file is corrupt")

// ReplayStats reports what WAL.Replay loaded during startup recovery.
type ReplayStats struct {
	SnapshotLoaded bool
	SnapshotSeq    uint64
	WALReplayed    int64
	LastSeq        uint64
	TruncatedTail  bool
}

// WAL provides optional append-only command logging and atomic 0600 snapshot
// compaction inside a dedicated data directory. All exported methods are safe
// for concurrent use.
type WAL struct {
	dir         string
	walPath     string
	snapPath    string
	syncOnWrite bool

	// mu serializes appends, compaction, replay, and close. Never acquired
	// while holding any Store shard mutex (lock order is strictly WAL -> Store).
	mu      sync.Mutex
	file    *os.File
	closed  bool
	entries int64
	bytes   int64
}

// OpenWAL creates dataDir (mode 0700) if needed and opens the append-only WAL
// file with mode 0600. Callers must call Replay (if recovering state) and
// Close on shutdown.
//
// # Parameters
//
//   - dataDir: Directory where concert-kv.wal and concert-kv.snapshot are stored;
//     must be non-empty.
//   - syncOnWrite: When true, each Append calls f.Sync() before returning.
//
// # Returns
//
// An initialized *WAL or an OS/validation error.
//
// # Example
//
//	wal, err := kv.OpenWAL(t.TempDir(), true)
//	if err != nil {
//	    return err
//	}
//	defer wal.Close()
func OpenWAL(dataDir string, syncOnWrite bool) (*WAL, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("%w: dataDir must be non-empty", ErrInvalidArg)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create kv data dir %q: %w", dataDir, err)
	}
	walPath := filepath.Join(dataDir, walFileName)
	f, err := os.OpenFile(walPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open wal %q: %w", walPath, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("chmod wal %q: %w", walPath, err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat wal %q: %w", walPath, err)
	}
	return &WAL{
		dir:         dataDir,
		walPath:     walPath,
		snapPath:    filepath.Join(dataDir, snapshotFileName),
		syncOnWrite: syncOnWrite,
		file:        f,
		bytes:       fi.Size(),
	}, nil
}

// Append writes one canonical RESP2 command record tagged with seq and a CRC32
// checksum to the append-only WAL.
//
// # Parameters
//
//   - seq: Monotonic mutation sequence number associated with args.
//   - args: Non-empty canonical command arguments to persist.
//
// # Returns
//
// nil on success, or an encoding/I/O error (including if WAL is closed).
//
// # Example
//
//	if err := wal.Append(1, []string{"SET", "k", "v"}); err != nil {
//	    return err
//	}
func (w *WAL) Append(seq uint64, args []string) error {
	if len(args) == 0 {
		return ErrEmptyCommand
	}
	var payloadBuf bytes.Buffer
	bw := bufio.NewWriter(&payloadBuf)
	if err := WriteCommand(bw, args...); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	payload := payloadBuf.Bytes()
	if len(payload) > maxWALRecordBytes {
		return fmt.Errorf("%w: wal record size %d exceeds %d", ErrBulkTooLarge, len(payload), maxWALRecordBytes)
	}

	frame := make([]byte, walHeaderSize+len(payload))
	copy(frame[0:4], walMagic)
	binary.BigEndian.PutUint64(frame[4:12], seq)
	binary.BigEndian.PutUint32(frame[12:16], crc32.ChecksumIEEE(payload))
	binary.BigEndian.PutUint32(frame[16:20], uint32(len(payload)))
	copy(frame[20:], payload)

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.file == nil {
		return os.ErrClosed
	}
	n, err := w.file.Write(frame)
	if err != nil {
		return fmt.Errorf("write wal record: %w", err)
	}
	if w.syncOnWrite {
		if err := w.file.Sync(); err != nil {
			return fmt.Errorf("sync wal record: %w", err)
		}
	}
	w.entries++
	w.bytes += int64(n)
	return nil
}

// Replay restores store from the latest atomic snapshot (if present) and then
// applies all subsequent valid WAL records. A torn/partial trailing WAL record
// left by a hard crash is safely truncated back to the last valid offset.
//
// # Parameters
//
//   - store: Destination *Store to hydrate; must be non-nil.
//
// # Returns
//
// ReplayStats describing recovered snapshot and WAL records, or an error on
// unreadable or mid-file corrupt data.
//
// # Example
//
//	stats, err := wal.Replay(store)
//	if err != nil {
//	    return err
//	}
//	fmt.Println(stats.SnapshotLoaded, stats.WALReplayed)
func (w *WAL) Replay(store *Store) (ReplayStats, error) {
	if store == nil {
		return ReplayStats{}, fmt.Errorf("%w: nil store", ErrInvalidArg)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ReplayStats{}, os.ErrClosed
	}

	var stats ReplayStats

	// Step 1: Load atomic snapshot if it exists.
	snap, found, err := readSnapshotFile(w.snapPath)
	if err != nil {
		return stats, err
	}
	if found {
		if err := store.LoadSnapshot(snap); err != nil {
			return stats, fmt.Errorf("load snapshot: %w", err)
		}
		stats.SnapshotLoaded = true
		stats.SnapshotSeq = snap.Seq
		stats.LastSeq = snap.Seq
	}

	// Step 2: Replay WAL records sequentially from byte 0.
	rf, err := os.Open(w.walPath)
	if errors.Is(err, os.ErrNotExist) {
		return stats, nil
	}
	if err != nil {
		return stats, fmt.Errorf("open wal for replay: %w", err)
	}
	defer func() { _ = rf.Close() }()

	fi, err := rf.Stat()
	if err != nil {
		return stats, fmt.Errorf("stat wal for replay: %w", err)
	}
	fileSize := fi.Size()

	var offset int64
	hdr := make([]byte, walHeaderSize)
	for offset < fileSize {
		n, err := io.ReadFull(rf, hdr)
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			// Torn trailing header from crash; truncate cleanly to offset.
			stats.TruncatedTail = true
			if err := w.truncateLocked(offset); err != nil {
				return stats, err
			}
			break
		}
		if err != nil {
			return stats, fmt.Errorf("read wal header at %d: %w", offset, err)
		}
		if string(hdr[0:4]) != walMagic {
			return stats, fmt.Errorf("%w: bad wal magic at offset %d", ErrWALCorrupt, offset)
		}
		seq := binary.BigEndian.Uint64(hdr[4:12])
		wantCRC := binary.BigEndian.Uint32(hdr[12:16])
		payloadLen := binary.BigEndian.Uint32(hdr[16:20])
		if int(payloadLen) > maxWALRecordBytes {
			return stats, fmt.Errorf("%w: record length %d exceeds limit at offset %d", ErrWALCorrupt, payloadLen, offset)
		}
		recEnd := offset + int64(n) + int64(payloadLen)
		if recEnd > fileSize {
			// Torn trailing payload from crash; truncate cleanly to offset.
			stats.TruncatedTail = true
			if err := w.truncateLocked(offset); err != nil {
				return stats, err
			}
			break
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(rf, payload); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				stats.TruncatedTail = true
				if err := w.truncateLocked(offset); err != nil {
					return stats, err
				}
				break
			}
			return stats, fmt.Errorf("read wal payload at %d: %w", offset, err)
		}
		if crc32.ChecksumIEEE(payload) != wantCRC {
			if recEnd == fileSize {
				// Partial/corrupted final record at tail: truncate safely.
				stats.TruncatedTail = true
				if err := w.truncateLocked(offset); err != nil {
					return stats, err
				}
				break
			}
			return stats, fmt.Errorf("%w: wal checksum mismatch at offset %d", ErrWALCorrupt, offset)
		}

		args, err := ReadCommand(bufio.NewReader(bytes.NewReader(payload)), ProtocolLimits{
			MaxBulkBytes: maxWALRecordBytes,
			MaxArrayLen:  DefaultMaxArrayLen,
		})
		if err != nil {
			return stats, fmt.Errorf("%w: decode wal command at offset %d: %v", ErrWALCorrupt, offset, err)
		}

		if seq > stats.SnapshotSeq {
			reply, _, _ := store.Execute(args)
			if reply.Kind == KindError {
				// Ignore replay errors only if benign? No: surface corruption
				// unless it's a benign conditional skip. Canonical WAL args
				// never fail on valid state, so surface unexpected errors.
				return stats, fmt.Errorf("replay wal seq %d (%s): %s", seq, args[0], reply.Str)
			}
			stats.WALReplayed++
			if seq > stats.LastSeq {
				stats.LastSeq = seq
			}
		}
		offset = recEnd
	}

	if stats.LastSeq > store.MutationSeq() {
		store.mutations.Store(stats.LastSeq)
	}
	return stats, nil
}

// truncateLocked truncates the open WAL file to size bytes and syncs it.
// Caller must hold w.mu.
//
// # Parameters
//
//   - size: Exact byte offset to truncate the WAL file to.
//
// # Returns
//
// Any truncate, seek, or sync I/O error.
//
// # Example
//
//	if err := w.truncateLocked(validOffset); err != nil {
//	    return err
//	}
func (w *WAL) truncateLocked(size int64) error {
	if w.file == nil {
		return nil
	}
	if err := w.file.Truncate(size); err != nil {
		return fmt.Errorf("truncate wal to %d: %w", size, err)
	}
	if _, err := w.file.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek wal end: %w", err)
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("sync truncated wal: %w", err)
	}
	w.bytes = size
	return nil
}

// Compact writes a consistent snapshot of store atomically to
// concert-kv.snapshot with 0600 permissions (os.CreateTemp + Chmod + Sync +
// Close + Rename) and then truncates the WAL.
//
// # Parameters
//
//   - store: Source *Store to snapshot; must be non-nil.
//
// # Returns
//
// Any serialization or filesystem error. On error, the existing snapshot and
// WAL remain intact.
//
// # Example
//
//	if err := wal.Compact(store); err != nil {
//	    return err
//	}
func (w *WAL) Compact(store *Store) error {
	if store == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidArg)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}

	snap := store.Snapshot()
	raw, err := EncodeSnapshot(snap)
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	if err := writeSnapshotAtomic0600(w.dir, w.snapPath, raw); err != nil {
		return err
	}
	if err := w.truncateLocked(0); err != nil {
		return err
	}
	w.entries = 0
	return nil
}

// Close flushes, syncs, and closes the underlying WAL file handle. Idempotent.
//
// # Parameters
//
// None.
//
// # Returns
//
// Any sync or close error on the first invocation; nil thereafter.
//
// # Example
//
//	if err := wal.Close(); err != nil {
//	    return err
//	}
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.file == nil {
		return nil
	}
	syncErr := w.file.Sync()
	closeErr := w.file.Close()
	w.file = nil
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

// SnapshotPath returns the filesystem path of the compacted snapshot file.
//
// # Parameters
//
// None.
//
// # Returns
//
// Full path to concert-kv.snapshot.
//
// # Example
//
//	fi, err := os.Stat(wal.SnapshotPath())
//	_, _ = fi, err
func (w *WAL) SnapshotPath() string {
	return w.snapPath
}

// WALPath returns the filesystem path of the append-only WAL file.
//
// # Parameters
//
// None.
//
// # Returns
//
// Full path to concert-kv.wal.
//
// # Example
//
//	fi, err := os.Stat(wal.WALPath())
//	_, _ = fi, err
func (w *WAL) WALPath() string {
	return w.walPath
}

// writeSnapshotAtomic0600 writes payload with an SNP1 header and CRC32
// checksum to a 0600 temp file in dir, fsyncs it, closes it, and atomically
// renames it onto destPath.
//
// # Parameters
//
//   - dir: Directory containing destPath (must reside on same filesystem).
//   - destPath: Final target snapshot path.
//   - payload: Encoded snapshot JSON bytes.
//
// # Returns
//
// Any filesystem error; cleans up the temporary file on every failure path.
//
// # Example
//
//	err := writeSnapshotAtomic0600(dir, snapPath, raw)
func writeSnapshotAtomic0600(dir, destPath string, payload []byte) error {
	tmp, err := os.CreateTemp(dir, ".concert-kv.snapshot.*")
	if err != nil {
		return fmt.Errorf("create temp snapshot: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp snapshot: %w", err)
	}

	var hdr [snapshotHeaderSize]byte
	copy(hdr[0:4], snapshotMagic)
	binary.BigEndian.PutUint32(hdr[4:8], crc32.ChecksumIEEE(payload))
	binary.BigEndian.PutUint64(hdr[8:16], uint64(len(payload)))

	if _, err := tmp.Write(hdr[:]); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write snapshot header: %w", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write snapshot payload: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp snapshot: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp snapshot: %w", err)
	}
	if err := os.Rename(tmpName, destPath); err != nil {
		return fmt.Errorf("rename snapshot into place: %w", err)
	}
	cleanup = false

	// Best-effort parent directory fsync for crash durability of the rename.
	if df, err := os.Open(dir); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}
	return nil
}

// readSnapshotFile opens, verifies, and decodes concert-kv.snapshot if it
// exists.
//
// # Parameters
//
//   - path: Filesystem path to the snapshot file.
//
// # Returns
//
// (snap, true, nil) when loaded; (zero, false, nil) when missing; or
// ErrWALCorrupt / I/O error on failure.
//
// # Example
//
//	snap, ok, err := readSnapshotFile(path)
func readSnapshotFile(path string) (SnapshotData, bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return SnapshotData{}, false, nil
	}
	if err != nil {
		return SnapshotData{}, false, fmt.Errorf("open snapshot %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var hdr [snapshotHeaderSize]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return SnapshotData{}, false, fmt.Errorf("%w: truncated snapshot header", ErrWALCorrupt)
	}
	if string(hdr[0:4]) != snapshotMagic {
		return SnapshotData{}, false, fmt.Errorf("%w: bad snapshot magic", ErrWALCorrupt)
	}
	wantCRC := binary.BigEndian.Uint32(hdr[4:8])
	length := binary.BigEndian.Uint64(hdr[8:16])
	if length > maxSnapshotBytes {
		return SnapshotData{}, false, fmt.Errorf("%w: snapshot size %d exceeds limit", ErrWALCorrupt, length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(f, payload); err != nil {
		return SnapshotData{}, false, fmt.Errorf("%w: truncated snapshot body", ErrWALCorrupt)
	}
	if crc32.ChecksumIEEE(payload) != wantCRC {
		return SnapshotData{}, false, fmt.Errorf("%w: snapshot checksum mismatch", ErrWALCorrupt)
	}
	snap, err := DecodeSnapshot(payload)
	if err != nil {
		return SnapshotData{}, false, fmt.Errorf("%w: decode snapshot: %v", ErrWALCorrupt, err)
	}
	return snap, true, nil
}
