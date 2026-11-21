// Command bench-concert measures how many concurrent visitors an application
// serves within a latency limit and without errors, by crawling it with
// lemmings: browser-like sessions that follow links up to 14 layers deep and
// load every file each page references. Point it at the application itself
// (not at Concert) to size a leaf, and give it -data-dir to write the
// capacity.json a leaf Concert reads. See internal/bench and
// docs/TOPOLOGY.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/andreimerlescu/concert/internal/bench"
)

func main() {
	if err := bench.CLI(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
