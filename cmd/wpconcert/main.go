//go:build wordpress

// Command wpconcert is the WordPress & WooCommerce drop-in front-door edition
// of Concert: waiting room, os.Root static asset serving, pure-stdlib FastCGI
// (php-fpm), anonymous GET micro-cache, Concertfile multi-vhost, and WordPress
// doctor/init tooling — with zero blockchain or enterprise mesh dependencies.
package main

import "github.com/andreimerlescu/concert/internal/server"

func main() {
	server.Main()
}
