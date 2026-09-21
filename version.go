package main

import (
	"embed"
	"strings"
)

// binaryVersionBytes contains the embedded VERSION file's contents
//
//go:embed VERSION
var binaryVersionBytes embed.FS

// binaryCurrentVersion is defined by BinaryVersion() and contains the contents of
// the VERSION file
var binaryCurrentVersion string

const VFN = "VERSION"

// BinaryVersion returns the embedded VERSION file of the repository as a string
// and cache that value into binaryCurrentVersion once os.ReadFile is complete
func BinaryVersion() string {
	if len(binaryCurrentVersion) == 0 {
		versionBytes, err := binaryVersionBytes.ReadFile(VFN)
		if err != nil {
			return "v0.0.0"
		}
		binaryCurrentVersion = strings.TrimSpace(string(versionBytes))
	}
	return binaryCurrentVersion
}
