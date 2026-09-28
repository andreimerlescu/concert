package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "reconcile" || os.Args[1] == "example") {
		run := runReconcile
		if os.Args[1] == "example" {
			run = runExample
		}
		if err := run(os.Args[2:], os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
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
