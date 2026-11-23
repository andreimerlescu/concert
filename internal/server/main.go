package server

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/andreimerlescu/concert/internal/bench"
	"github.com/gin-gonic/gin"
)

// Main runs the concert command line: a subcommand when the first argument
// names one, otherwise the server. cmd/concert is a thin wrapper around it.
func Main() {
	if len(os.Args) > 1 {
		sub := os.Args[1]
		var runSub func([]string, io.Writer) error
		switch sub {
		case "bench":
			runSub = func(args []string, out io.Writer) error {
				return bench.CLI(args, out, os.Stderr)
			}
		default:
			if fn := wordpressSubcommand(sub); fn != nil {
				runSub = fn
			} else if fn := enterpriseSubcommand(sub); fn != nil {
				runSub = fn
			}
		}
		if runSub != nil {
			if err := runSub(os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		}
	}
	cfg, showVersion, err := parseConfig(flag.CommandLine, os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	if showVersion {
		fmt.Println(BinaryVersion())
		return
	}

	gin.SetMode(gin.ReleaseMode)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}
