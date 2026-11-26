//go:build !enterprise || !wordpress

package main

// econcert requires both the "wordpress" and "enterprise" build tags.
// Build with:
//
//	go build -tags "wordpress,enterprise" ./cmd/econcert
//
// or run `make build`.
var _ = econcert_requires_go_build_tags_wordpress_and_enterprise
