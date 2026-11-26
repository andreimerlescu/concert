// Package concert holds the repository's release identity. The server lives
// in internal/server and its binaries in cmd/; this root package exists so
// the VERSION file can be embedded once and shared by every binary.
package concert

import (
	_ "embed"
	"strings"
)

// versionFile holds the repository VERSION file, embedded at build time.
//
//go:embed VERSION
var versionFile string

// Version returns the embedded VERSION, or v0.0.0 if it is empty. It is a
// pure function of an immutable string and safe for concurrent use.
func Version() string {
	if v := strings.TrimSpace(versionFile); v != "" {
		return v
	}
	return "v0.0.0"
}
