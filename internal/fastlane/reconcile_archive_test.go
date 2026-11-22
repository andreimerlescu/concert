package fastlane

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOnlineReconcile_UnlocksPayerSessionAndClearsUnresolved(t *testing.T) {
	h := newHarness(t)
	h.fail.Store(true)

	// Wrap the harness gateway to also handle /reconcile.
	base := h.gateway
	var reconcileCalls int
	h.s.gateway = handlerGateway{http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reconcile" {
			reconcileCalls++
			var in struct {
				ID string `json:"id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			reply(w, 200, Settlement{
				Success:     true,
				Transaction: "reconciled-tx-001",
				Network:     "xrpl:1",
				Payer:       "rPayer",
			})
			return
		}
		base.ServeHTTP(w, r)
	})}

	tok := newSession(t, h.s)
	pay := signedPayment(t, h.cfg.Offers[0].Requirements, "blob-unknown-1")
	w := request(h.s, "/payment", tok, "{}", pay)
	if w.Code != 503 {
		t.Fatalf("expected 503 unknown settlement, got %d %s", w.Code, w.Body.String())
	}

	// Session must not be eligible yet, and unresolved list must expose redacted metadata.
	req := httptest.NewRequest("GET", "/hello", nil)
	req.Header.Set(SessionHeader, tok)
	if h.s.Eligible(req) {
		t.Fatal("session should not be eligible while receipt is unknown")
	}
	unres := h.s.UnresolvedReceipts()
	if len(unres) != 1 {
		t.Fatalf("unresolved count = %d, want 1", len(unres))
	}
	if unres[0].State != "unknown" || unres[0].Network != "xrpl:1" || unres[0].Payer != "rPayer" {
		t.Fatalf("unexpected unresolved view: %+v", unres[0])
	}
	rawJSON, _ := json.Marshal(unres[0])
	if strings.Contains(string(rawJSON), tok) || strings.Contains(string(rawJSON), "blob-unknown-1") {
		t.Fatalf("unresolved view leaked session or payload: %s", rawJSON)
	}

	// Run online reconciliation without restarting Service.
	settled, err := h.s.ReconcileOnline(context.Background(), unres[0].Fingerprint, "")
	if err != nil {
		t.Fatalf("ReconcileOnline: %v", err)
	}
	if !settled.Success || settled.Transaction != "reconciled-tx-001" || reconcileCalls != 1 {
		t.Fatalf("unexpected reconcile result: %+v calls=%d", settled, reconcileCalls)
	}
	if !h.s.Eligible(req) {
		t.Fatal("payer session was not unlocked immediately after online reconciliation")
	}
	if got := len(h.s.UnresolvedReceipts()); got != 0 {
		t.Fatalf("unresolved count after reconcile = %d, want 0", got)
	}
}

func TestCapacityAlerts_FireAt80And95Percent(t *testing.T) {
	h := newHarness(t)
	h.s.Close()
	h.cfg.MaxRecords = 100
	h.open(t)

	var mu sync.Mutex
	var events []int
	h.s.SetOnCapacityWarn(func(used, max, pct int) {
		mu.Lock()
		events = append(events, pct)
		mu.Unlock()
	})

	req := h.cfg.Offers[0].Requirements
	for i := 1; i <= 96; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("cap-fp-%d", i)))
		r := Receipt{
			Session:      fmt.Sprintf("sess-%d", i),
			Fingerprint:  hex.EncodeToString(sum[:]),
			State:        "settled",
			Kind:         "payment",
			Network:      req.Network,
			Payer:        "rPayer",
			Requirements: req,
			Transaction:  fmt.Sprintf("tx-%d", i),
			Started:      h.now,
			Settled:      h.now,
			Expires:      h.now.Add(time.Minute),
		}
		if err := h.s.ledger.write(r); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		h.s.checkCapacityWarn()
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 || events[0] != 80 || events[1] != 95 {
		t.Fatalf("capacity warn pcts = %v, want [80 95]", events)
	}
	used, maxRec, unresolved := h.s.JournalStats()
	if used != 96 || maxRec != 100 || unresolved != 0 {
		t.Fatalf("JournalStats = (%d, %d, %d), want (96, 100, 0)", used, maxRec, unresolved)
	}
}

func TestArchiveReceipts_SafetyAndAtomicity(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	l, err := openLedger(dir, 100)
	if err != nil {
		t.Fatal(err)
	}

	req := Requirements{Scheme: "exact", Network: "xrpl:1", Amount: "100", Asset: "XRP", PayTo: "rDest", MaxTimeoutSeconds: 60}
	fp := func(n int) string {
		sum := sha256.Sum256([]byte(fmt.Sprintf("fp-%d", n)))
		return hex.EncodeToString(sum[:])
	}
	records := []Receipt{
		// 1: old pending -> MUST KEEP
		{Session: "s1", Fingerprint: fp(1), State: "pending", Kind: "payment", Network: "xrpl:1", Payer: "r1", Requirements: req, Started: now.Add(-100 * time.Hour)},
		// 2: old unknown -> MUST KEEP
		{Session: "s2", Fingerprint: fp(2), State: "unknown", Kind: "payment", Network: "xrpl:1", Payer: "r2", Requirements: req, Started: now.Add(-100 * time.Hour)},
		// 3: active settled (expires in future) -> MUST KEEP
		{Session: "s3", Fingerprint: fp(3), State: "settled", Kind: "payment", Network: "xrpl:1", Payer: "r3", Requirements: req, Transaction: "tx3", Started: now.Add(-1 * time.Hour), Settled: now.Add(-1 * time.Hour), Expires: now.Add(1 * time.Hour)},
		// 4: recently expired settled (1h ago < 24h cutoff) -> MUST KEEP
		{Session: "s4", Fingerprint: fp(4), State: "settled", Kind: "payment", Network: "xrpl:1", Payer: "r4", Requirements: req, Transaction: "tx4", Started: now.Add(-2 * time.Hour), Settled: now.Add(-2 * time.Hour), Expires: now.Add(-1 * time.Hour)},
		// 5 & 6: expired settled older than 24h -> ARCHIVE
		{Session: "s5", Fingerprint: fp(5), State: "settled", Kind: "payment", Network: "xrpl:1", Payer: "r5", Requirements: req, Transaction: "tx5", Started: now.Add(-72 * time.Hour), Settled: now.Add(-72 * time.Hour), Expires: now.Add(-48 * time.Hour)},
		{Session: "s6", Fingerprint: fp(6), State: "settled", Kind: "payment", Network: "xrpl:1", Payer: "r6", Requirements: req, Transaction: "tx6", Started: now.Add(-96 * time.Hour), Settled: now.Add(-96 * time.Hour), Expires: now.Add(-72 * time.Hour)},
	}
	for _, r := range records {
		if err := l.write(r); err != nil {
			t.Fatal(err)
		}
	}

	// While Concert holds fastlane.lock, ArchiveReceipts must refuse.
	if _, err := ArchiveReceipts(dir, 24*time.Hour, false, now); err == nil {
		t.Fatal("ArchiveReceipts succeeded while ledger was open")
	}
	l.close()

	// Dry run reports exact counts without modifying files.
	dry, err := ArchiveReceipts(dir, 24*time.Hour, true, now)
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if dry.TotalBefore != 6 || dry.Archived != 2 || dry.Kept != 4 || dry.KeptUnresolved != 2 || dry.KeptActive != 1 || dry.KeptRecent != 1 {
		t.Fatalf("unexpected dry-run report: %+v", dry)
	}
	if dry.ArchiveFile != "" {
		t.Fatalf("dry-run should not set ArchiveFile: %+v", dry)
	}

	// Real archival compacts fastlane.jsonl and writes 0600 archive + .sha256.
	rep, err := ArchiveReceipts(dir, 24*time.Hour, false, now)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	if rep.Archived != 2 || rep.Kept != 4 || rep.ArchiveFile == "" || rep.ChecksumFile == "" {
		t.Fatalf("unexpected archive report: %+v", rep)
	}
	st, err := os.Stat(rep.ArchiveFile)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("archive file mode = %o, want 0600", st.Mode().Perm())
	}
	arcBytes, err := os.ReadFile(rep.ArchiveFile)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(arcBytes)
	if hex.EncodeToString(sum[:]) != rep.ArchiveSHA256 {
		t.Fatalf("archive sha256 mismatch")
	}
	chkBytes, err := os.ReadFile(rep.ChecksumFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(chkBytes), rep.ArchiveSHA256+"  "+filepath.Base(rep.ArchiveFile)) {
		t.Fatalf("unexpected checksum file contents: %q", string(chkBytes))
	}

	// Compacted journal must reopen cleanly with all 4 non-archivable receipts intact.
	l2, err := openLedger(dir, 100)
	if err != nil {
		t.Fatalf("reopen compacted journal: %v", err)
	}
	defer l2.close()
	used, _, unres := l2.stats()
	if used != 4 || unres != 2 {
		t.Fatalf("compacted journal stats: used=%d unres=%d, want 4, 2", used, unres)
	}
	for _, keptIdx := range []int{1, 2, 3, 4} {
		if _, ok := l2.fingerprint(fp(keptIdx)); !ok {
			t.Fatalf("kept receipt %d missing after archive", keptIdx)
		}
	}
	for _, arcIdx := range []int{5, 6} {
		if _, ok := l2.fingerprint(fp(arcIdx)); ok {
			t.Fatalf("archived receipt %d still in live journal", arcIdx)
		}
	}
}

func signedPayment(t *testing.T, req Requirements, blob string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"x402Version": 2,
		"accepted":    req,
		"payload":     map[string]string{"signedTxBlob": blob},
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
