//go:build enterprise && wordpress

// Command econcert is the full Enterprise edition of Concert: waiting room,
// static assets, FastCGI (php-fpm), micro-cache, Concertfile multi-vhost,
// two-tier edge/leaf hop mesh with mTLS & replay-guarded nonces, Redis HA
// cluster sync, RBAC/SSO + tamper-evident audit logging, transactional alert
// mailer, and x402 Fast-Lane settlement.
package main

import "github.com/andreimerlescu/concert/internal/server"

func main() {
	server.Main()
}
