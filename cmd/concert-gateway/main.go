// Command concert-gateway is Concert's chain gateway: a loopback-only,
// token-authenticated service that verifies and settles x402 payments and
// checks NFT ownership for the fast lane.
//
//	concert-gateway                          serve on 127.0.0.1:$CONCERT_GATEWAY_PORT (8402)
//	concert-gateway reconcile <id> [hash]    record a settlement confirmed on-ledger
//
// Never expose the gateway to wallets or the public internet; Concert calls
// it with CONCERT_GATEWAY_TOKEN.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/andreimerlescu/concert/internal/fastlane"
	"github.com/andreimerlescu/concert/internal/gateway"
)

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	networks, err := gateway.LoadNetworks(env("CONCERT_NETWORKS_CONFIG", "examples/networks.testnet.json"))
	if err != nil {
		return err
	}
	dataDir := env("CONCERT_GATEWAY_DATA", "data/gateway")
	if len(args) > 0 && args[0] == "reconcile" {
		return reconcile(args[1:], networks, dataDir)
	}
	if len(args) > 0 {
		return fmt.Errorf("usage: concert-gateway [reconcile <payment fingerprint> [Stellar transaction hash]]")
	}
	cfg, err := fastlane.Load(env("CONCERT_FASTLANE_CONFIG", "examples/fastlane.testnet.json"))
	if err != nil {
		return fmt.Errorf("fast lane configuration: %w", err)
	}
	port, err := strconv.Atoi(env("CONCERT_GATEWAY_PORT", "8402"))
	if err != nil || port < 1 || port > 65535 {
		return errors.New("CONCERT_GATEWAY_PORT must be a TCP port")
	}
	journal, err := gateway.OpenJournal(dataDir)
	if err != nil {
		return err
	}
	defer journal.Close()
	handler, err := gateway.New(cfg, networks, journal, os.Getenv("CONCERT_GATEWAY_TOKEN"), os.Getenv)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errs := make(chan error, 1)
	go func() { errs <- srv.ListenAndServe() }()
	log.Printf("Concert chain gateway listening on %s", srv.Addr)
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	// Let in-flight settlements finish and journal their results; they are
	// bounded by each offer's timeout.
	log.Print("shutting down; waiting for in-flight settlements")
	return srv.Shutdown(context.Background())
}

func reconcile(args []string, networks map[string]gateway.Network, dataDir string) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: concert-gateway reconcile <payment fingerprint> [Stellar transaction hash]")
	}
	hash := ""
	if len(args) == 2 {
		hash = args[1]
	}
	journal, err := gateway.OpenJournal(dataDir)
	if err != nil {
		return fmt.Errorf("%w (stop the gateway while reconciling)", err)
	}
	defer journal.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := gateway.Reconcile(ctx, journal, networks, args[0], hash)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	fmt.Println("Final settlement verified and recorded. Retry the IDENTICAL payment at Concert.")
	return nil
}
