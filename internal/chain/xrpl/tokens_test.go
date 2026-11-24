package xrpl

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/x402"
)

type fakeTokenLedger struct {
	fakeLedger
	lines []TrustLine
	txs   []AccountTxEntry
}

func (f *fakeTokenLedger) AccountLines(context.Context, string, string, any) ([]TrustLine, any, error) {
	return f.lines, nil, nil
}

func (f *fakeTokenLedger) AccountTx(context.Context, string, uint32, int) ([]AccountTxEntry, error) {
	return f.txs, nil
}

func TestIOUAmountRoundTrip_RLUSD(t *testing.T) {
	curBytes, canon, err := NormalizeCurrency("RLUSD")
	if err != nil {
		t.Fatalf("NormalizeCurrency(RLUSD): %v", err)
	}
	if canon != "524C555344000000000000000000000000000000" {
		t.Fatalf("unexpected canonical RLUSD currency: %s", canon)
	}
	issuer, err := DecodeAddress("rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De")
	if err != nil {
		t.Fatalf("DecodeAddress: %v", err)
	}
	for _, val := range []string{"0.99", "1", "12.345678", "0.000001", "1000000"} {
		enc, err := EncodeIOUAmount(val, curBytes, issuer)
		if err != nil {
			t.Fatalf("EncodeIOUAmount(%s): %v", val, err)
		}
		got, err := DecodeIOUAmount(enc)
		if err != nil {
			t.Fatalf("DecodeIOUAmount(%s): %v", val, err)
		}
		if got.Native || got.Currency != canon || got.Issuer != issuer {
			t.Fatalf("decoded metadata mismatch for %s: %+v", val, got)
		}
		cmp, err := CompareDecimal(got.Value, val)
		if err != nil || cmp != 0 {
			t.Fatalf("round-trip mismatch for %s: got %q (err=%v)", val, got.Value, err)
		}
	}
}

func TestXRPL_IOU_RLUSD_PaymentVerifyAndSettle(t *testing.T) {
	payerKey, err := KeyFromSeed("sEdTM1uX8pu2do5XvTnutH6HsouMaM2")
	if err != nil {
		t.Fatal(err)
	}
	merchant := "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe"
	issuer := "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De"
	asset := "RLUSD:" + issuer

	l := &fakeTokenLedger{
		fakeLedger: fakeLedger{
			networkID: 1,
			current:   1000,
			info:      AccountInfo{Sequence: 42, Balance: "50000000"},
			simulate:  "tesSUCCESS",
			txAfter:   1,
			txResult:  "tesSUCCESS",
		},
	}
	req := x402.Requirements{
		Scheme:            "exact",
		Network:           "xrpl:1",
		Amount:            "0.99",
		Asset:             asset,
		PayTo:             merchant,
		MaxTimeoutSeconds: 60,
		Extra:             map[string]any{"areFeesSponsored": false, "memo": "concert:abc123"},
	}
	blob, err := NewPaymentBlob(context.Background(), l, payerKey, req)
	if err != nil {
		t.Fatalf("NewPaymentBlob(RLUSD): %v", err)
	}
	tx, err := Decode(blob)
	if err != nil {
		t.Fatalf("Decode(RLUSD blob): %v", err)
	}
	if !tx.HasMemoText("concert:abc123") {
		t.Fatalf("expected decoded memo concert:abc123, got %+v", tx.Memos)
	}
	s := &Scheme{Network: "xrpl:1", Ledger: l, MaxFeeDrops: 50000, Poll: time.Millisecond, pending: map[string]time.Time{}}
	p := x402.Payload{Version: 2, Accepted: req, Payload: json.RawMessage(`{"signedTxBlob":"` + blob + `"}`)}
	v := s.Verify(context.Background(), p, req)
	if !v.Valid || v.Payer != payerKey.Address {
		t.Fatalf("expected valid RLUSD verify, got %+v", v)
	}
	res, err := s.Settle(context.Background(), p, req)
	if err != nil || !res.Success || res.Payer != payerKey.Address {
		t.Fatalf("expected RLUSD settle success, got res=%+v err=%v", res, err)
	}
}

func TestXRPL_TrustlineAndDirectPayment(t *testing.T) {
	issuer := "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De"
	holder := "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe"
	dest := "rQLTGGRoGbQZLK2ErVKio1pxViAR8fvMBT"
	tag := uint32(987654)
	l := &fakeTokenLedger{
		fakeLedger: fakeLedger{networkID: 1, current: 500},
		lines: []TrustLine{
			{Account: issuer, Currency: "524C555344000000000000000000000000000000", Balance: "25.5"},
		},
		txs: []AccountTxEntry{
			{
				Hash:           "DEADBEEF01",
				Validated:      true,
				Result:         "tesSUCCESS",
				TxType:         "Payment",
				Account:        holder,
				Destination:    dest,
				DestinationTag: &tag,
				Memos:          []string{"concert:tag-proof-1"},
				DeliveredDrops: "1",
			},
			{
				Hash:              "DEADBEEF02",
				Validated:         true,
				Result:            "tesSUCCESS",
				TxType:            "Payment",
				Account:           holder,
				Destination:       dest,
				DestinationTag:    &tag,
				Memos:             []string{"concert:rlusd-pay-1"},
				DeliveredCurrency: "524C555344000000000000000000000000000000",
				DeliveredIssuer:   issuer,
				DeliveredValue:    "0.99",
			},
		},
	}
	s := &Scheme{Network: "xrpl:1", Ledger: l, MaxFeeDrops: 50000, pending: map[string]time.Time{}}
	ok, bal, err := s.MeetsMinBalance(context.Background(), holder, "RLUSD:"+issuer, "10")
	if err != nil || !ok || bal != "25.5" {
		t.Fatalf("MeetsMinBalance(10): ok=%v bal=%q err=%v", ok, bal, err)
	}
	ok, _, err = s.MeetsMinBalance(context.Background(), holder, "RLUSD:"+issuer, "50")
	if err != nil || ok {
		t.Fatalf("MeetsMinBalance(50) should be false: ok=%v err=%v", ok, err)
	}
	hash, payer, err := s.FindDirectPayment(context.Background(), holder, dest, "XRP", "1", tag, true, "concert:tag-proof-1", 400)
	if err != nil || hash != "DEADBEEF01" || payer != holder {
		t.Fatalf("FindDirectPayment(1-drop proof): hash=%q payer=%q err=%v", hash, payer, err)
	}
	hash, payer, err = s.FindDirectPayment(context.Background(), holder, dest, "RLUSD:"+issuer, "0.99", tag, true, "concert:rlusd-pay-1", 400)
	if err != nil || hash != "DEADBEEF02" || payer != holder {
		t.Fatalf("FindDirectPayment(0.99 RLUSD): hash=%q payer=%q err=%v", hash, payer, err)
	}
}
