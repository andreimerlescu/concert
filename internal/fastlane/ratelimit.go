package fastlane

import "time"

// rateWindow tracks one client address's (or IPv6 /64's) 1-minute POST budget
// inside rateLimiter's two intrusive doubly-linked LRU lists.
type rateWindow struct {
	key       string
	start     time.Time
	n         int
	throttled bool
	prev      *rateWindow
	next      *rateWindow
}

type rateList struct {
	head *rateWindow // oldest (eviction candidate)
	tail *rateWindow // newest
	len  int
}

func (l *rateList) pushBack(w *rateWindow) {
	w.prev = l.tail
	w.next = nil
	if l.tail != nil {
		l.tail.next = w
	} else {
		l.head = w
	}
	l.tail = w
	l.len++
}

func (l *rateList) remove(w *rateWindow) {
	if w.prev != nil {
		w.prev.next = w.next
	} else {
		l.head = w.next
	}
	if w.next != nil {
		w.next.prev = w.prev
	} else {
		l.tail = w.prev
	}
	w.prev = nil
	w.next = nil
	l.len--
}

func (l *rateList) moveToBack(w *rateWindow) {
	if l.tail == w {
		return
	}
	l.remove(w)
	l.pushBack(w)
}

// rateLimiter is a fixed-capacity, strict-O(1) two-list LRU per-address POST
// limiter. Normal addresses live in active (ordered by LRU touch) and addresses
// that have exhausted their per-minute budget live in throttled (ordered by
// exhaustion time). When full, expired heads are reclaimed first, then the
// oldest active entry is evicted so actively throttled abusers stay pinned
// while legitimate new buyers are never globally locked out.
//
// Callers must hold Service.mu.
type rateLimiter struct {
	entries    map[string]*rateWindow
	active     rateList
	throttled  rateList
	maxEntries int
	limit      int
	window     time.Duration
}

func newRateLimiter(maxEntries, limit int, window time.Duration) *rateLimiter {
	if maxEntries <= 0 {
		maxEntries = maxRateEntries
	}
	if limit <= 0 {
		limit = postsPerMinute
	}
	if window <= 0 {
		window = time.Minute
	}
	return &rateLimiter{
		entries:    make(map[string]*rateWindow),
		maxEntries: maxEntries,
		limit:      limit,
		window:     window,
	}
}

func (rl *rateLimiter) evict(w *rateWindow) {
	if w.throttled {
		rl.throttled.remove(w)
	} else {
		rl.active.remove(w)
	}
	delete(rl.entries, w.key)
}

func (rl *rateLimiter) allow(key string, now time.Time) bool {
	if w, ok := rl.entries[key]; ok {
		if now.Sub(w.start) >= rl.window {
			if w.throttled {
				rl.throttled.remove(w)
				w.throttled = false
				rl.active.pushBack(w)
			} else {
				rl.active.moveToBack(w)
			}
			w.start = now
			w.n = 1
			if w.n >= rl.limit {
				rl.active.remove(w)
				w.throttled = true
				rl.throttled.pushBack(w)
			}
			return w.n <= rl.limit
		}
		w.n++
		if !w.throttled {
			if w.n >= rl.limit {
				rl.active.remove(w)
				w.throttled = true
				rl.throttled.pushBack(w)
			} else {
				rl.active.moveToBack(w)
			}
		}
		return w.n <= rl.limit
	}

	if len(rl.entries) >= rl.maxEntries {
		// Reclaim a bounded batch of expired heads from both tiers in O(1).
		for popped := 0; popped < 4 && rl.active.head != nil && now.Sub(rl.active.head.start) >= rl.window; popped++ {
			rl.evict(rl.active.head)
		}
		for popped := 0; popped < 4 && rl.throttled.head != nil && now.Sub(rl.throttled.head.start) >= rl.window; popped++ {
			rl.evict(rl.throttled.head)
		}
		// Still full: evict the oldest non-throttled address first so active
		// abusers remain pinned until their window expires; only fall back to
		// the oldest throttled address if all maxEntries are throttled.
		if len(rl.entries) >= rl.maxEntries {
			if rl.active.head != nil {
				rl.evict(rl.active.head)
			} else if rl.throttled.head != nil {
				rl.evict(rl.throttled.head)
			}
		}
	}

	w := &rateWindow{key: key, start: now, n: 1}
	rl.entries[key] = w
	if w.n >= rl.limit {
		w.throttled = true
		rl.throttled.pushBack(w)
	} else {
		rl.active.pushBack(w)
	}
	return w.n <= rl.limit
}

func (rl *rateLimiter) len() int {
	return len(rl.entries)
}
