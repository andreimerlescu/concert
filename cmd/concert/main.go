// Command concert is the FIFO waiting room reverse proxy. Everything it does
// lives in internal/server; see README.md.
package main

import "github.com/andreimerlescu/concert/internal/server"

func main() {
	server.Main()
}
