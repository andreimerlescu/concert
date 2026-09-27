package main

import (
	"sync"
	"time"
)

type kickList struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func (k *kickList) add(token string, until time.Time) {
	k.mu.Lock()
	k.m[token] = until
	k.mu.Unlock()
}

func (k *kickList) has(token string, now time.Time) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	until, ok := k.m[token]
	if ok && !now.Before(until) {
		delete(k.m, token)
		return false
	}
	return ok
}

func (k *kickList) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}

func (k *kickList) sweep(now time.Time) {
	k.mu.Lock()
	for t, until := range k.m {
		if !now.Before(until) {
			delete(k.m, t)
		}
	}
	k.mu.Unlock()
}
