//go:build !wordpress

package main

// wpconcert requires the "wordpress" build tag.
// Build with:
//
//	go build -tags wordpress ./cmd/wpconcert
//
// or run `make build`.
var _ = wpconcert_requires_go_build_tags_wordpress
