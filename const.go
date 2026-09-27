package main

import (
	"math"
	"time"
)

// Context keys.
const (
	// ctxAdmitted is set the moment a request reaches the proxy handler.
	// Anything written before that point was written by room.
	ctxAdmitted = "concert.admitted"
	// ctxClientIP holds the resolved client netip.Addr for the request.
	ctxClientIP = "concert.client_ip"
)

// shutdownGrace bounds how long in-flight requests get to finish on SIGTERM,
// and on the old listener when a listen address changes.
const shutdownGrace = 30 * time.Second

// Admission pass layout:
//
//	id(16) | expiry unix seconds(8) | key id(4) | truncated HMAC-SHA256(16)
//
// base64url encoded without padding. The key id lets a pass signed by a
// different secret be recognised as stale rather than forged.
const (
	admitCookie  = "concert_admit"
	passIDLen    = 16
	passExpLen   = 8
	passKIDLen   = 4
	passMACLen   = 16
	passExpOff   = passIDLen
	passKIDOff   = passExpOff + passExpLen
	passBodyLen  = passKIDOff + passKIDLen
	passRawLen   = passBodyLen + passMACLen
	minSecretLen = 32
)

// Shard counts must be powers of two.
const (
	userShards  = 64
	abuseShards = 64
)

// Strike weights. A client is banned when its strikes within -abuse-window
// reach -abuse-strikes. Ban paths bypass weights and ban immediately.
const (
	strikeForgedPass   = 5 // admission pass with a bad signature under the current key
	strikeAdminAuth    = 5 // wrong admin token
	strikeUserThrottle = 1 // per-pass asset pool exhausted
	strikeTicketChurn  = 1 // queued arrival without a room_ticket cookie
)

// First-poll grace limits. room accepts 10s-24h (0 turns it off). concert
// also keeps it at least twice -retry-after, so an API client that retries
// on schedule instead of polling /queue/status is not reclaimed.
const (
	minFirstPollGrace = 10 * time.Second
	maxFirstPollGrace = 24 * time.Hour
)

// Permanent bans. A client or range whose ban ends at banForever stays
// banned until an administrator lifts it; banned() reports banForeverLeft.
const (
	banForever     = int64(math.MaxInt64)
	banForeverLeft = time.Duration(math.MaxInt64)
)
