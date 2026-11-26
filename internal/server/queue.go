package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/andreimerlescu/room"
)

// room's line, as concert uses it beyond admission: removing banned
// visitors, and keeping the line across restarts.
//
// Removal. Every ban (strikes, a ban path, the portal, the admin API) hands
// its address range to queueDrop. A background loop collects the ranges for
// dropBatchDelay and removes every waiting visitor inside any of them with a
// single RemoveTokensFunc pass, because each pass scans the whole line under
// a read lock that briefly holds up status polls, and strike bans can arrive
// in bursts during an attack. Visitors are matched by room's client key,
// which is the address concert resolved in identify. Allowlisted and
// trusted-proxy addresses are never removed, matching range bans.
//
// Persistence. With -data-dir set, Close exports the line after the
// listeners have drained, and newApp imports it after room's settings are
// applied and before anything is served. The ticket TTL and first-poll
// grace in force at import decide which saved tickets are too old to keep.
// Browser cookies keep ageing while concert is down, so a restart should
// finish well within two thirds of the ticket TTL.

const (
	queueFileName  = "queue.snapshot"
	dropBatchDelay = 250 * time.Millisecond
)

func queueFilePath(dir string) string {
	return filepath.Join(dir, queueFileName)
}

// ─── removing banned visitors ────────────────────────────────────────────────

// dropper collects ban ranges until the drop loop removes their visitors.
type dropper struct {
	mu      sync.Mutex
	pending []netip.Prefix
	kick    chan struct{}
}

func newDropper() *dropper {
	return &dropper{kick: make(chan struct{}, 1)}
}

// queueDrop is the abuse registry's ban callback. It never blocks: the
// range is removed from the line by the drop loop moments later.
func (a *app) queueDrop(p netip.Prefix) {
	d := a.drops
	d.mu.Lock()
	d.pending = append(d.pending, p)
	d.mu.Unlock()
	select {
	case d.kick <- struct{}{}:
	default:
	}
}

// dropLoop removes queued ranges in batches until the app stops.
func (a *app) dropLoop() {
	for {
		select {
		case <-a.stop:
			return
		case <-a.drops.kick:
		}
		// Let a burst of bans gather, so one pass over the line removes all
		// of their visitors.
		select {
		case <-a.stop:
			return
		case <-time.After(dropBatchDelay):
		}
		a.drops.mu.Lock()
		batch := a.drops.pending
		a.drops.pending = nil
		a.drops.mu.Unlock()
		if n := a.dropWaiting(batch...); n > 0 {
			log.Printf("queue: bans removed %d waiting visitor(s)", n)
		}
	}
}

// dropWaiting removes every waiting visitor whose client key falls inside
// one of scopes, except exempt addresses, and reports how many it removed.
// room records the resolved address on keyed tickets too, so a ban drops
// an address's agent places with the rest. room runs the predicate with no
// locks held.
func (a *app) dropWaiting(scopes ...netip.Prefix) int {
	if len(scopes) == 0 {
		return 0
	}
	return a.room.RemoveTokensFunc(func(t room.TicketInfo) bool {
		ip, err := netip.ParseAddr(t.ClientKey)
		if err != nil {
			return false
		}
		ip = ip.Unmap()
		if a.abuse.isExempt(ip) {
			return false
		}
		for _, s := range scopes {
			if s.Contains(ip) {
				if t.Key != "" {
					a.agents.forget(t.Key)
				}
				return true
			}
		}
		return false
	})
}

// ─── keeping the line across restarts ────────────────────────────────────────

// restoreQueue imports the line saved by the last Close, then deletes the
// file so a later crash cannot import it twice. A missing file is an empty
// line. An unreadable file is set aside as queue.snapshot.bad and concert
// starts with an empty line: during a live event, starting without the old
// queue beats not starting. Only ErrImportNotEmpty stops startup, because it
// means the queue was imported after traffic arrived.
func (a *app) restoreQueue() error {
	path := a.queuePath
	cfg := a.current().cfg

	if cfg.clearQueueOnStart {
		if err := os.Remove(path); err == nil {
			log.Printf("queue: -clear-queue-on-start set; removed %s and starting with an empty line", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			log.Printf("queue: -clear-queue-on-start could not remove %s: %v", path, err)
		}
		return nil
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		log.Printf("queue: cannot read %s (%v); starting with an empty line", path, err)
		return nil
	}

	var hdr struct {
		ExportedAt time.Time `json:"exported_at"`
	}
	var exportedAt time.Time
	if json.Unmarshal(data, &hdr) == nil && !hdr.ExportedAt.IsZero() {
		exportedAt = hdr.ExportedAt
	} else if info, serr := os.Stat(path); serr == nil {
		exportedAt = info.ModTime()
	}
	if !exportedAt.IsZero() {
		maxAge := cfg.effectiveTokenTTL()
		if age := time.Since(exportedAt); age > maxAge {
			log.Printf("queue: discarding stale snapshot %s (age %s > token-ttl %s)",
				path, age.Round(time.Second), maxAge)
			if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				log.Printf("queue: could not remove stale snapshot %s: %v", path, rerr)
			}
			return nil
		}
	}

	stats, err := a.room.Import(bytes.NewReader(data))
	var notEmpty room.ErrImportNotEmpty
	switch {
	case err == nil:
		log.Printf("queue: restored %d waiting visitor(s) from %s (dropped_stale=%d, passes_restored=%d, passes_expired=%d)",
			stats.Restored, path, stats.DroppedStale, stats.PassesRestored, stats.PassesExpired)
		if maxQ := a.room.MaxQueueDepth(); maxQ > 0 && int64(stats.Restored) >= (maxQ*4)/5 {
			log.Printf("queue: WARNING restored %d/%d waiting visitor(s) (>=80%% of -max-queue); use POST /_room/queue/clear or -clear-queue-on-start if visitors have abandoned",
				stats.Restored, maxQ)
		}
		if err := os.Remove(path); err != nil {
			log.Printf("queue: could not remove %s after restoring it: %v", path, err)
		}
	case errors.As(err, &notEmpty):
		return fmt.Errorf("queue file %s: %w (the queue must be restored before concert serves traffic)", path, err)
	default:
		bad := path + ".bad"
		if rerr := os.Rename(path, bad); rerr != nil {
			log.Printf("queue: could not set aside %s: %v", path, rerr)
		}
		log.Printf("queue: %s could not be restored (%v); starting with an empty line, file kept as %s", path, err, bad)
	}
	return nil
}

// saveQueue exports the line to -data-dir. It runs in Close, after the
// listeners have drained, so nothing joins the line while it is written.
func (a *app) saveQueue() {
	var buf bytes.Buffer
	if err := a.room.Export(&buf); err != nil {
		log.Printf("queue: could not export the line: %v", err)
		return
	}
	if err := writeFileAtomic(a.queuePath, buf.Bytes()); err != nil {
		log.Printf("queue: could not save %s: %v", a.queuePath, err)
		return
	}
	log.Printf("queue: saved %d waiting visitor(s) to %s; restart within %s to keep their places",
		a.room.LiveQueueDepth(), a.queuePath, (a.room.TokenTTL() * 2 / 3).Round(time.Second))
}
