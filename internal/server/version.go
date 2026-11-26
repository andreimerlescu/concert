package server

import "github.com/andreimerlescu/concert"

// BinaryVersion returns the repository VERSION embedded by the root concert
// package, or v0.0.0 if it is empty. Safe for concurrent use.
func BinaryVersion() string {
	return concert.Version()
}
