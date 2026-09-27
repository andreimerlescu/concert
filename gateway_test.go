package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andreimerlescu/concert/internal/fastlane"
	"github.com/andreimerlescu/concert/internal/gateway"
	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
	"github.com/stellar/go-stellar-sdk/keypair"
)

func TestGatewayNeedsNetworksAndDataDir(t *testing.T) {
	fc := fastlane.Config{Enabled: true}
	if _, err := newGateway(fc, &config{dataDir: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "CONCERT_NETWORKS_CONFIG") {
		t.Fatalf("missing networks file: %v", err)
	}
	if _, err := newGateway(fc, &config{networksFile: "x.json"}); err == nil || !strings.Contains(err.Error(), "CONCERT_DATA_DIR") {
		t.Fatalf("missing data dir: %v", err)
	}
}

func TestReconcileRefusesALiveJournalAndBadArguments(t *testing.T) {
	dir := t.TempDir()
	nets := filepath.Join(dir, "networks.json")
	os.WriteFile(nets, []byte(`{}`), 0o600)
	t.Setenv("CONCERT_DATA_DIR", "")
	t.Setenv("CONCERT_NETWORKS_CONFIG", "")
	if err := runReconcile([]string{strings.Repeat("a", 64)}, io.Discard); err == nil {
		t.Fatal("ran without -data-dir and -networks-config")
	}
	j, err := gateway.OpenJournal(gatewayDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	err = runReconcile([]string{"-data-dir", dir, "-networks-config", nets, strings.Repeat("a", 64)}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "stop concert") {
		t.Fatalf("reconciled beside a live journal: %v", err)
	}
}

// The sample must stay a working template: with "enabled" switched on it
// passes Concert's validation and the gateway's configuration checks.
func TestExamplesAreValidTemplates(t *testing.T) {
	var b strings.Builder
	if err := runExample([]string{"fastlane"}, &b); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fastlane.json")
	os.WriteFile(path, []byte(strings.Replace(b.String(), `"enabled": false`, `"enabled": true`, 1)), 0o600)
	fc, err := fastlane.Load(path)
	if err != nil || !fc.Enabled {
		t.Fatalf("example fastlane.json: %v", err)
	}
	b.Reset()
	if err := runExample([]string{"networks"}, &b); err != nil {
		t.Fatal(err)
	}
	nets := filepath.Join(dir, "networks.json")
	os.WriteFile(nets, []byte(b.String()), 0o600)
	networks, err := gateway.LoadNetworks(nets)
	if err != nil {
		t.Fatal(err)
	}
	hk, _ := hiero.PrivateKeyGenerateEd25519()
	secrets := map[string]string{"CONCERT_STELLAR_FEE_SECRET": keypair.MustRandom().Seed(), "CONCERT_HEDERA_FEE_SECRET": hk.StringDer()}
	j, err := gateway.OpenJournal(gatewayDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	s, err := gateway.New(fc, networks, j, func(k string) string { return secrets[k] })
	if err != nil {
		t.Fatalf("example networks.json: %v", err)
	}
	s.Close()
	if err := runExample([]string{"other"}, io.Discard); err == nil {
		t.Error("printed an unknown example")
	}
}
