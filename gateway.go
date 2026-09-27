package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/andreimerlescu/concert/internal/fastlane"
	"github.com/andreimerlescu/concert/internal/gateway"
)

// The fast lane's chain gateway runs inside concert: it verifies and settles
// x402 payments and checks NFT ownership. Its settlement journal lives in
// <data-dir>/gateway, beside the fast lane's receipt journal.

func gatewayDir(dataDir string) string { return filepath.Join(dataDir, "gateway") }

// newGateway opens the settlement journal and builds the chain mechanisms
// for every network the fast lane uses. Tests replace it.
var newGateway = func(fc fastlane.Config, c *config) (fastlane.Gateway, error) {
	if c.networksFile == "" {
		return nil, errors.New("set CONCERT_NETWORKS_CONFIG (-networks-config) to the chain endpoints file")
	}
	if c.dataDir == "" {
		return nil, errors.New("the fast lane needs CONCERT_DATA_DIR for its journals")
	}
	networks, err := gateway.LoadNetworks(c.networksFile)
	if err != nil {
		return nil, err
	}
	j, err := gateway.OpenJournal(gatewayDir(c.dataDir))
	if err != nil {
		return nil, err
	}
	s, err := gateway.New(fc, networks, j, os.Getenv)
	if err != nil {
		j.Close()
		return nil, fmt.Errorf("chain gateway: %w", err)
	}
	return s, nil
}

func closeGateway(gw fastlane.Gateway) {
	if c, ok := gw.(interface{ Close() }); ok {
		c.Close()
	}
}

// runReconcile is "concert reconcile <fingerprint> [Stellar transaction
// hash]": operator recovery for a settlement whose outcome is unknown. It
// checks final ledger state and records the settlement; it never signs,
// broadcasts, refunds or moves funds. The journal lock keeps it from running
// beside a live concert, so stop the service first.
func runReconcile(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	dataDir := fs.String("data-dir", os.Getenv("CONCERT_DATA_DIR"), "concert's data directory (CONCERT_DATA_DIR)")
	networksFile := fs.String("networks-config", os.Getenv("CONCERT_NETWORKS_CONFIG"), "chain endpoints file (CONCERT_NETWORKS_CONFIG)")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: concert reconcile [-data-dir DIR] [-networks-config FILE] <payment fingerprint> [Stellar transaction hash]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 || len(rest) > 2 || *dataDir == "" || *networksFile == "" {
		fs.Usage()
		return errors.New("reconcile needs a fingerprint, -data-dir and -networks-config")
	}
	hash := ""
	if len(rest) == 2 {
		hash = rest[1]
	}
	networks, err := gateway.LoadNetworks(*networksFile)
	if err != nil {
		return err
	}
	j, err := gateway.OpenJournal(gatewayDir(*dataDir))
	if err != nil {
		return fmt.Errorf("%w (stop concert while reconciling)", err)
	}
	defer j.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := gateway.Reconcile(ctx, j, networks, rest[0], hash)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Fprintln(stdout, string(out))
	fmt.Fprintln(stdout, "Final settlement verified and recorded. Start concert, then retry the IDENTICAL payment.")
	return nil
}

// Sample configuration, printed by "concert example fastlane|networks" and
// documented key by key in docs/FASTLANE.md. Every value is a well-formed
// placeholder to replace.
//
//go:embed examples/fastlane.json examples/networks.json
var examples embed.FS

func runExample(args []string, stdout io.Writer) error {
	if len(args) != 1 || (args[0] != "fastlane" && args[0] != "networks") {
		return errors.New("usage: concert example fastlane|networks")
	}
	b, err := examples.ReadFile("examples/" + args[0] + ".json")
	if err != nil {
		return err
	}
	_, err = stdout.Write(b)
	return err
}
