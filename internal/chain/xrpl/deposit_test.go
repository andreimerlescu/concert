package xrpl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestRecentPaymentsKeepsOnlyValidatedXRPPaymentsToTheAccount(t *testing.T) {
	now := time.Now()
	stamp := func(d time.Duration) int64 { return now.Add(d).Unix() - rippleEpoch }
	const acct = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe"
	body := `{"result":{"status":"success","transactions":[
	 {"validated":true,"meta":{"TransactionResult":"tesSUCCESS","delivered_amount":"150"},"tx":{"TransactionType":"Payment","Account":"rA","Destination":"` + acct + `","DestinationTag":42,"hash":"GOOD","date":` + itoa(stamp(-time.Minute)) + `}},
	 {"validated":true,"meta":{"TransactionResult":"tesSUCCESS","delivered_amount":"99"},"tx":{"TransactionType":"Payment","Account":"rB","Destination":"` + acct + `","DestinationTag":42,"hash":"SHORT","date":` + itoa(stamp(-time.Minute)) + `}},
	 {"validated":true,"meta":{"TransactionResult":"tesSUCCESS","delivered_amount":"500"},"tx":{"TransactionType":"Payment","Account":"rC","Destination":"` + acct + `","DestinationTag":43,"hash":"OTHERTAG","date":` + itoa(stamp(-time.Minute)) + `}},
	 {"validated":true,"meta":{"TransactionResult":"tecPATH_DRY","delivered_amount":"500"},"tx":{"TransactionType":"Payment","Account":"rD","Destination":"` + acct + `","DestinationTag":42,"hash":"FAILED","date":` + itoa(stamp(-time.Minute)) + `}},
	 {"validated":true,"meta":{"TransactionResult":"tesSUCCESS","delivered_amount":{"currency":"USD","value":"9"}},"tx":{"TransactionType":"Payment","Account":"rE","Destination":"` + acct + `","DestinationTag":42,"hash":"IOU","date":` + itoa(stamp(-time.Minute)) + `}},
	 {"validated":true,"meta":{"TransactionResult":"tesSUCCESS","delivered_amount":"500"},"tx":{"TransactionType":"Payment","Account":"rF","Destination":"` + acct + `","DestinationTag":42,"hash":"OLD","date":` + itoa(stamp(-3*time.Hour)) + `}}
	]}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
	defer srv.Close()
	got, err := RPC{URL: srv.URL}.RecentPayments(context.Background(), acct, now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var hashes []string
	for _, d := range got {
		hashes = append(hashes, d.Hash)
	}
	// Failed, issued-currency and too-old payments are dropped; the rest keep
	// their tag and delivered amount for the gateway to match.
	if len(got) != 3 || hashes[0] != "GOOD" || hashes[1] != "SHORT" || hashes[2] != "OTHERTAG" {
		t.Fatalf("got %v", hashes)
	}
	if !got[0].HasTag || got[0].Tag != 42 || got[0].Amount.String() != "150" || got[0].Payer != "rA" {
		t.Fatalf("%+v", got[0])
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
