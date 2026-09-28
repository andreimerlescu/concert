package xrpl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestFindDepositsMatchesTagAmountAndSkipsNoise(t *testing.T) {
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
	s := New("xrpl:1", srv.URL, 0)
	got, err := s.FindDeposits(context.Background(), acct, 42, "100", now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Hash != "GOOD" || got[0].Payer != "rA" {
		t.Fatalf("got %+v", got)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
