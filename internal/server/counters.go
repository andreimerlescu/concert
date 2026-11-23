package server

import "sync/atomic"

type counters struct {
	queued        atomic.Int64
	evicted       atomic.Int64
	timeouts      atomic.Int64
	promoted      atomic.Int64
	removed       atomic.Int64 // room EventRemove: bans, kicks and removals by concert
	tokenRejected atomic.Int64 // room v1.8.0 EventTokenRejected: failed signed pass/lease verification

	assetServed          atomic.Int64
	assetDenied          atomic.Int64
	assetUserThrottled   atomic.Int64
	assetGlobalThrottled atomic.Int64

	staticServed        atomic.Int64
	staticNotFound      atomic.Int64
	fcgiRequests        atomic.Int64
	fcgiDenied          atomic.Int64
	microCacheHits      atomic.Int64
	microCacheMisses    atomic.Int64
	microCacheBypasses  atomic.Int64
	microCacheCoalesced atomic.Int64

	streamServed    atomic.Int64
	streamDenied    atomic.Int64
	streamThrottled atomic.Int64

	abuseStrikes  atomic.Int64
	abuseBans     atomic.Int64
	abuseRejected atomic.Int64
	abuseDropped  atomic.Int64

	upstream2xx     atomic.Int64
	upstream3xx     atomic.Int64
	upstream4xx     atomic.Int64
	upstream5xx     atomic.Int64
	upstreamUnavail atomic.Int64 // 502-504 (excluding edge leaf backpressure): app not answering
	upstreamErrors  atomic.Int64
	upstreamLatency durationHistogram

	clusterSyncSent     atomic.Int64
	clusterSyncRecv     atomic.Int64
	clusterSyncErrors   atomic.Int64
	emailClusterDeduped atomic.Int64
}
