package server

import (
	"math"
	"time"
)

// Context keys.
const (
	// ctxAdmitted is set the moment a request reaches the proxy handler.
	// Anything written before that point was written by room.
	ctxAdmitted = "concert.admitted"
	ctxIsStream = "concert.is_stream"
	// ctxClientIP holds the resolved client netip.Addr for the request.
	ctxClientIP = "concert.client_ip"
	// ctxAgentKey holds the room key of a request agentGate identified by
	// its Concert-Session header; see agent.go.
	ctxAgentKey = "concert.agent_key"
	// ctxRoomFull is set by room's FullResponder when rejecting a request
	// because maxQueueDepth was reached, so apiQueueWriter and agentWaitWriter
	// pass the response through untouched.
	ctxRoomFull = "concert.room_full"
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
	strikeAgentPlaces  = 1 // new keyed place past -agent-places for the address
)

// First-poll grace, ready-claim grace, idle-poll TTL, and upstream response
// body idle timeout limits. room accepts 10s-24h for first-poll grace and
// idle-poll TTL, and 5s-10m for ready-claim grace (0 turns each off). concert
// also keeps queue liveness timers at least twice -retry-after and at most the
// effective -token-ttl.
const (
	minFirstPollGrace          = 10 * time.Second
	maxFirstPollGrace          = 24 * time.Hour
	minReadyGrace              = 5 * time.Second
	maxReadyGrace              = 10 * time.Minute
	minIdlePollTTL             = 10 * time.Second
	maxIdlePollTTL             = 24 * time.Hour
	minUpstreamBodyIdleTimeout = 1 * time.Second
	maxUpstreamBodyIdleTimeout = 24 * time.Hour
)

// Permanent bans. A client or range whose ban ends at banForever stays
// banned until an administrator lifts it; banned() reports banForeverLeft.
const (
	banForever     = int64(math.MaxInt64)
	banForeverLeft = time.Duration(math.MaxInt64)
)
