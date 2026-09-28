package chain_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/hedera"
	"github.com/andreimerlescu/concert/internal/chain/solana"
	"github.com/andreimerlescu/concert/internal/chain/stellar"
)

func serve(t *testing.T, h http.HandlerFunc) string {
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s.URL
}

func TestStellarRecentPayments(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	u := serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"_embedded":{"records":[
		{"type":"payment","asset_type":"native","from":"GA","to":"GME","amount":"0.1000123","transaction_successful":true,"transaction_hash":"H1","created_at":"` + now + `","transaction":{"memo":"CTABC"}},
		{"type":"payment","asset_type":"credit_alphanum4","from":"GB","to":"GME","amount":"5.0000000","transaction_successful":true,"transaction_hash":"H2","created_at":"` + now + `"},
		{"type":"payment","asset_type":"native","from":"GC","to":"GOTHER","amount":"1.0000000","transaction_successful":true,"transaction_hash":"H3","created_at":"` + now + `"},
		{"type":"payment","asset_type":"native","from":"GD","to":"GME","amount":"1.0000000","transaction_successful":false,"transaction_hash":"H4","created_at":"` + now + `"}]}}`))
	})
	got, err := stellar.Horizon{URL: u}.RecentPayments(context.Background(), "GME", time.Now().Add(-time.Hour))
	if err != nil || len(got) != 1 || got[0].Hash != "H1" || got[0].Amount.String() != "1000123" || got[0].Memo != "CTABC" || got[0].Payer != "GA" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestHederaRecentPayments(t *testing.T) {
	u := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "account.id=0.0.900") {
			t.Error("query", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"transactions":[
		{"transaction_id":"0.0.7-1-2","consensus_timestamp":"1700000000.000000001","memo_base64":"Q1RYWVo=","result":"SUCCESS","transfers":[{"account":"0.0.7","amount":-100010123},{"account":"0.0.900","amount":100000123},{"account":"0.0.3","amount":10000}]},
		{"transaction_id":"0.0.8-1-2","consensus_timestamp":"1700000001.000000001","result":"SUCCESS","transfers":[{"account":"0.0.900","amount":-5},{"account":"0.0.8","amount":5}]}]}`))
	})
	got, err := hedera.Mirror{URL: u}.RecentPayments(context.Background(), "0.0.900", time.Unix(1, 0))
	if err != nil || len(got) != 1 || got[0].Payer != "0.0.7" || got[0].Amount.String() != "100000123" || got[0].Memo != "CTXYZ" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestSolanaRecentPayments(t *testing.T) {
	bt := time.Now().Unix()
	u := serve(t, func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 4096)
		n, _ := r.Body.Read(b)
		body := string(b[:n])
		if strings.Contains(body, "getSignaturesForAddress") {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":[{"signature":"SIG1","err":null,"blockTime":` + itoa(bt) + `,"memo":"[5] CTABC"},{"signature":"SIG2","err":{"x":1},"blockTime":` + itoa(bt) + `}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"transaction":{"message":{"instructions":[{"program":"system","parsed":{"type":"transfer","info":{"source":"SRC","destination":"DEST","lamports":1500123}}}]}}}}`))
	})
	got, err := solana.RPC{URL: u}.RecentPayments(context.Background(), "DEST", time.Now().Add(-time.Hour))
	if err != nil || len(got) != 1 || got[0].Payer != "SRC" || got[0].Amount.String() != "1500123" || got[0].Hash != "SIG1" {
		t.Fatalf("%+v %v", got, err)
	}
}

func itoa(n int64) string {
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	return s
}
