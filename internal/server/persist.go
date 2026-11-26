package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/andreimerlescu/concert/internal/opt"
)

// Ban persistence. Bans, including permanent ones, are written to bans.json
// in -data-dir and reloaded at startup, so a restart never lifts a ban.
//
// Strike bans can arrive in bursts, so the registry marks itself dirty and a
// background writer saves at most once per bansSaveEvery. Bans made by an
// administrator are saved before the API responds (app.saveBansNow).
//
// Offense history is saved with the bans, so escalating cooldowns continue
// across restarts. History older than -abuse-max-cooldown is dropped on load,
// exactly as the janitor would have dropped it.

const (
	bansFileName    = "bans.json"
	bansFileVersion = 1
	bansSaveEvery   = time.Second
)

func bansFilePath(dir string) string {
	return filepath.Join(dir, bansFileName)
}

type banSnapshot struct {
	Version int        `json:"version"`
	Saved   time.Time  `json:"saved"`
	Clients []savedBan `json:"clients"`
	Ranges  []savedBan `json:"ranges"`
}

// savedBan is one client (address, or IPv6 /64) or range. Until is the end
// of the current or most recent ban; it is None and omitted via omitzero for
// permanent bans.
type savedBan struct {
	Client    string                `json:"client"`
	Until     opt.Option[time.Time] `json:"until,omitzero"`
	Permanent bool                  `json:"permanent,omitempty"`
	Offenses  int                   `json:"offenses"`
}

// savedBanOf constructs a serializable [savedBan] record from registry state.
// A permanent ban (until == banForever) sets Permanent and leaves Until as
// [opt.None] so bans.json omits the "until" field via omitzero.
//
// # Parameters
//
//   - client: Display address or CIDR string for the banned target.
//   - until: Expiry timestamp in Unix nanoseconds, or banForever for permanent.
//   - offenses: Recorded offense count persisted for escalating cooldowns.
//
// # Returns
//
// A value-type savedBan ready for JSON persistence.
//
// # Example
//
//	sb := savedBanOf("203.0.113.10", banForever, 2)
//
// # Used By
//
// Generated from verified AST symbol references; do not hand-edit.
//
//   - internal/server/history_test.go:540 (direct call)
//   - internal/server/history_test.go:556 (direct call)
//   - internal/server/persist.go:141 (direct call)
//   - internal/server/persist.go:149 (direct call)
//
// Scope: internal/server (including tests and all build tags).
func savedBanOf(client string, until int64, offenses int) savedBan {
	sb := savedBan{Client: client, Offenses: offenses}
	if until == banForever {
		sb.Permanent = true
	} else {
		sb.Until = opt.Some(time.Unix(0, until).UTC())
	}
	return sb
}

// until returns the ban expiry in Unix nanoseconds (or banForever for a
// permanent ban) and whether sb carries a valid expiry.
//
// # Parameters
//
// None. Operates on the value receiver sb.
//
// # Returns
//
// (banForever, true) when Permanent is true, (u.UnixNano(), true) when Until
// is present, or (0, false) when neither Permanent nor Until is set.
//
// # Example
//
//	if exp, ok := sb.until(); ok {
//		_ = exp
//	}
//
// # Used By
//
// Generated from verified AST symbol references; do not hand-edit.
//
//   - internal/server/history_test.go:552 (direct call)
//   - internal/server/history_test.go:568 (direct call)
//   - internal/server/history_test.go:576 (direct call)
//   - internal/server/persist.go:174 (direct call)
//   - internal/server/persist.go:193 (direct call)
//
// Scope: internal/server (including tests and all build tags).
func (sb savedBan) until() (int64, bool) {
	if sb.Permanent {
		return banForever, true
	}
	u, ok := sb.Until.Get()
	if !ok {
		return 0, false
	}
	return u.UnixNano(), true
}

// snapshot captures every client with ban history and every active range.
func (r *abuseRegistry) snapshot(now time.Time) banSnapshot {
	s := banSnapshot{Version: bansFileVersion, Saved: now.UTC(), Clients: []savedBan{}, Ranges: []savedBan{}}
	n := now.UnixNano()
	for i := range r.shards {
		sh := &r.shards[i]
		sh.mu.Lock()
		for k, e := range sh.m {
			if e.offenses > 0 {
				s.Clients = append(s.Clients, savedBanOf(displayKey(k), e.bannedUntil, e.offenses))
			}
		}
		sh.mu.Unlock()
	}
	r.ranges.mu.RLock()
	for p, b := range r.ranges.m {
		if b.until > n {
			s.Ranges = append(s.Ranges, savedBanOf(p.String(), b.until, b.offenses))
		}
	}
	r.ranges.mu.RUnlock()
	sort.Slice(s.Clients, func(i, j int) bool { return s.Clients[i].Client < s.Clients[j].Client })
	sort.Slice(s.Ranges, func(i, j int) bool { return s.Ranges[i].Client < s.Ranges[j].Client })
	return s
}

// restore loads a snapshot into an empty registry. Addresses that are now
// exempt, and history too old to matter, are skipped.
func (r *abuseRegistry) restore(s banSnapshot, now time.Time) int {
	n := now.UnixNano()
	maxNS := int64(r.p().max)
	restored := 0

	for _, sb := range s.Clients {
		t, err := parseBanTarget(sb.Client)
		if err != nil || !t.single {
			continue
		}
		k, ok := r.trackable(t.prefix.Addr())
		if !ok {
			continue
		}
		until, ok := sb.until()
		if !ok || (until != banForever && n-until > maxNS) {
			continue
		}
		sh := r.shard(k)
		sh.mu.Lock()
		if e := r.entryLocked(sh, k, n); e != nil {
			e.bannedUntil, e.offenses, e.strikes, e.windowStart = until, max(sb.Offenses, 1), 0, n
			restored++
		}
		sh.mu.Unlock()
	}

	r.ranges.mu.Lock()
	for _, sb := range s.Ranges {
		t, err := parseBanTarget(sb.Client)
		if err != nil || t.single {
			continue
		}
		until, ok := sb.until()
		if !ok || until <= n {
			continue
		}
		if _, exists := r.ranges.m[t.prefix]; !exists {
			if len(r.ranges.m) >= maxRangeBans {
				continue
			}
			r.ranges.n.Add(1)
		}
		r.ranges.m[t.prefix] = &rangeBan{until: until, offenses: max(sb.Offenses, 1)}
		restored++
	}
	r.ranges.mu.Unlock()
	return restored
}

// loadBans restores bans.json. A missing file is not an error; an unreadable
// or corrupt one is, so permanent bans are never dropped silently.
func (r *abuseRegistry) loadBans(path string, now time.Time) (int, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("bans file %s: %w", path, err)
	}
	var s banSnapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return 0, fmt.Errorf("bans file %s is not valid JSON: %w (fix it, or remove it to start with no bans)", path, err)
	}
	if s.Version > bansFileVersion {
		return 0, fmt.Errorf("bans file %s was written by a newer concert (version %d)", path, s.Version)
	}
	return r.restore(s, now), nil
}

func (r *abuseRegistry) saveBans(path string, now time.Time) error {
	data, err := json.MarshalIndent(r.snapshot(now), "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'))
}

// flush saves bans.json when anything changed since the last save.
func (r *abuseRegistry) flush(path string) {
	r.saveMu.Lock()
	defer r.saveMu.Unlock()
	if !r.dirty.Swap(false) {
		return
	}
	if err := r.saveBans(path, time.Now()); err != nil {
		r.dirty.Store(true)
		if !r.saveFailing.Swap(true) {
			log.Printf("bans: cannot save %s: %v (retrying)", path, err)
		}
		return
	}
	if r.saveFailing.Swap(false) {
		log.Printf("bans: saving %s works again", path)
	}
}

// persistLoop saves changes every interval and once more on stop.
func (r *abuseRegistry) persistLoop(path string, every time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			r.flush(path)
			return
		case <-t.C:
			r.flush(path)
		}
	}
}

// writeFileAtomic replaces path with data so readers only ever see the old
// file or the complete new one. The file is created with mode 0600 and the
// directory, when missing, with 0700.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename

	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Persist the rename itself. Not supported everywhere, so best effort.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
