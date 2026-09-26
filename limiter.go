package main

import (
	"net/netip"
	"sync"
	"time"
)

type loginState struct {
	fails       int
	first       time.Time
	lockedUntil time.Time
}

type loginLimiter struct {
	mu sync.Mutex
	m  map[netip.Addr]*loginState
}

func (l *loginLimiter) locked(ip netip.Addr, now time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s := l.m[ip]; s != nil && now.Before(s.lockedUntil) {
		return s.lockedUntil.Sub(now), true
	}
	return 0, false
}

func (l *loginLimiter) fail(ip netip.Addr, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.m[ip]
	if s == nil || now.Sub(s.first) > loginWindow {
		s = &loginState{first: now}
		l.m[ip] = s
	}
	s.fails++
	if s.fails >= loginMaxFailures {
		s.lockedUntil = now.Add(loginLockout)
		s.fails = 0
		s.first = now
	}
}

func (l *loginLimiter) reset(ip netip.Addr) {
	l.mu.Lock()
	delete(l.m, ip)
	l.mu.Unlock()
}

func (l *loginLimiter) sweep(now time.Time) {
	l.mu.Lock()
	for ip, s := range l.m {
		if now.After(s.lockedUntil) && now.Sub(s.first) > loginWindow {
			delete(l.m, ip)
		}
	}
	l.mu.Unlock()
}

func (l *loginLimiter) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}
