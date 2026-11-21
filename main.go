package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
)

func main() {
	if len(os.Args) > 1 {
		var runSub func([]string, io.Writer) error
		switch os.Args[1] {
		case "reconcile":
			runSub = runReconcile
		case "example":
			runSub = runExample
		case "audit":
			runSub = runAudit
		case "hash-password":
			runSub = runHashPassword
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
