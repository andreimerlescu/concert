package main

import (
	"net/http"
	"time"

	"github.com/andreimerlescu/sema"
	"github.com/gin-gonic/gin"
)

// Stream paths.
//
// WebSocket and server-sent event connections can stay open for hours. In
// the waiting room each one would hold a page slot for its whole life, so a
// few hundred open streams could shut everyone else out. Paths listed in
// -stream-paths are registered outside the room instead, with two guards of
// their own:
//
//   - a valid admission pass, so only visitors who were already admitted to
//     a page can open a stream, and nobody skips the line through one;
//   - a global semaphore of -stream-cap slots, held for the life of the
//     connection. When it is full, the connection is refused at once with
//     503 and Retry-After rather than kept waiting: stream clients reconnect
//     on their own.
//
// Bans are enforced before any of this, as on every path. A forged pass
// earns the same strike as on the asset tier.

// streamGuard admits stream connections.
type streamGuard struct {
	admit  *admitter
	sem    sema.Semaphore
	stats  *counters
	strike func(*gin.Context, int)
}

// handle checks the admission pass, takes a stream slot for the life of the
// connection, and runs the proxy.
func (s *streamGuard) handle(c *gin.Context) {
	_, status := s.admit.check(c.Writer, c.Request, time.Now())
	if status != passValid {
		if status == passForged {
			s.strike(c, strikeForgedPass)
		}
		s.stats.streamDenied.Add(1)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	if !s.sem.TryAcquire() {
		s.stats.streamThrottled.Add(1)
		c.Header("Retry-After", "5")
		c.AbortWithStatus(http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = s.sem.Release() }()

	s.stats.streamServed.Add(1)
	c.Next() // proxy the connection while the slot is held
}
