package main

import "sync/atomic"

type counters struct {
	queued   atomic.Int64
	evicted  atomic.Int64
	timeouts atomic.Int64
	promoted atomic.Int64
	removed  atomic.Int64 // room EventRemove: bans, kicks and removals by concert

	assetServed          atomic.Int64
	assetDenied          atomic.Int64
	assetUserThrottled   atomic.Int64
	assetGlobalThrottled atomic.Int64

	streamServed    atomic.Int64
	streamDenied    atomic.Int64
	streamThrottled atomic.Int64

	abuseStrikes  atomic.Int64
	abuseBans     atomic.Int64
	abuseRejected atomic.Int64
	abuseDropped  atomic.Int64
}
