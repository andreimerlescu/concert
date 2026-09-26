package main

import (
	"sync"
	"sync/atomic"
)

// visitorNote is what room does not know about a waiting visitor: the path
// they asked for and their browser. Display only.
type visitorNote struct {
	ua   string
	path string
}

// noteStore keeps notes by ticket, at most max of them. The janitor forgets
// notes for tickets room no longer holds.
type noteStore struct {
	mu      sync.Mutex
	m       map[string]visitorNote
	max     int
	dropped atomic.Int64
}

func newNoteStore(max int) *noteStore {
	return &noteStore{m: map[string]visitorNote{}, max: max}
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *noteStore) add(token, ua, reqPath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[token]; ok {
		return
	}
	if len(s.m) >= s.max {
		s.dropped.Add(1)
		return
	}
	s.m[token] = visitorNote{ua: clip(ua, 256), path: clip(reqPath, 256)}
}

func (s *noteStore) get(token string) (visitorNote, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.m[token]
	return n, ok
}

func (s *noteStore) remove(token string) {
	s.mu.Lock()
	delete(s.m, token)
	s.mu.Unlock()
}

func (s *noteStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// prune forgets every note whose ticket keep rejects. keep is called
// without the store's lock held.
func (s *noteStore) prune(keep func(token string) bool) int {
	s.mu.Lock()
	tokens := make([]string, 0, len(s.m))
	for t := range s.m {
		tokens = append(tokens, t)
	}
	s.mu.Unlock()

	var gone []string
	for _, t := range tokens {
		if !keep(t) {
			gone = append(gone, t)
		}
	}
	if len(gone) == 0 {
		return 0
	}
	s.mu.Lock()
	for _, t := range gone {
		delete(s.m, t)
	}
	s.mu.Unlock()
	return len(gone)
}
