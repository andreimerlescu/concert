package stellar

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/x402"
	"math/big"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// testdata/vectors.json: payloads built with @stellar/stellar-sdk 16.3.0
// (auth entries signed by authorizeEntry, as the x402 client does), each
// judged by @x402/stellar 2.27.0's facilitator against a mock RPC serving
// the recorded simulation. "settle.submitted" is the transaction that
// facilitator rebuilt, sponsor-signed and submitted.
type vectors struct {
	Passphrase      string `json:"passphrase"`
	Asset           string `json:"asset"`
	SponsorSecret   string `json:"sponsorSecret"`
	SponsorSequence string `json:"sponsorSequence"`
	Current         uint32 `json:"current"`
	Cases           []struct {
		Name         string            `json:"name"`
		Transaction  string            `json:"transaction"`
		Requirements x402.Requirements `json:"requirements"`
		Simulation   json.RawMessage   `json:"simulation"`
		Reference    struct {
			Valid  bool   `json:"valid"`
			Reason string `json:"reason"`
			Payer  string `json:"payer"`
		} `json:"reference"`
		Concert struct {
			Valid  bool   `json:"valid"`
			Reason string `json:"reason"`
		} `json:"concert"`
	} `json:"cases"`
	Settle struct {
		Requirements x402.Requirements `json:"requirements"`
		Transaction  string            `json:"transaction"`
		Submitted    string            `json:"submitted"`
	} `json:"settle"`
	SEP53 struct {
		Address, Message, Signature string
	} `json:"sep53"`
}

func load(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

type fakeRPC struct {
	mu        sync.Mutex
	sim       json.RawMessage
	current   uint32
	sequence  string
	submitted []string
	status    string
}

func (f *fakeRPC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     any             `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	defer f.mu.Unlock()
	var result any
	switch req.Method {
	case "simulateTransaction":
		result = f.sim
	case "getLatestLedger":
		result = map[string]any{"sequence": f.current}
	case "getNetwork":
		result = map[string]any{"passphrase": network.TestNetworkPassphrase}
	case "getLedgerEntries":
		var p struct{ Keys []string }
		_ = json.Unmarshal(req.Params, &p)
		var key xdr.LedgerKey
		_ = xdr.SafeUnmarshalBase64(p.Keys[0], &key)
		seq, _ := atoi64(f.sequence)
		entry := xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{AccountId: key.Account.AccountId, SeqNum: xdr.SequenceNumber(seq), Thresholds: xdr.Thresholds{1, 0, 0, 0}}}
		s, _ := xdr.MarshalBase64(entry)
		result = map[string]any{"entries": []any{map[string]any{"xdr": s}}}
	case "sendTransaction":
		var p struct{ Transaction string }
		_ = json.Unmarshal(req.Params, &p)
		f.submitted = append(f.submitted, p.Transaction)
		result = map[string]any{"status": "PENDING", "hash": "ab" + string(bytes.Repeat([]byte("00"), 31))}
	case "getTransaction":
		result = map[string]any{"status": f.status}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
}

func newScheme(t *testing.T, v vectors, f *fakeRPC) *Scheme {
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	s, err := New(Testnet, srv.URL, "", v.SponsorSecret, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.Poll = time.Millisecond
	return s
}

func payload(tx string, r x402.Requirements) x402.Payload {
	return x402.Payload{Version: 2, Accepted: r, Payload: json.RawMessage(`{"transaction":"` + tx + `"}`)}
}

func TestNativeAssetMatchesReference(t *testing.T) {
	v := load(t)
	if got, err := NativeAsset(v.Passphrase); err != nil || got != v.Asset {
		t.Fatalf("%s %v, want %s", got, err, v.Asset)
	}
}

func TestVerifyMatchesReferenceFacilitator(t *testing.T) {
	v := load(t)
	for _, c := range v.Cases {
		s := newScheme(t, v, &fakeRPC{sim: c.Simulation, current: v.Current})
		got := s.Verify(context.Background(), payload(c.Transaction, c.Requirements), c.Requirements)
		if got.Valid != c.Concert.Valid || got.Reason != c.Concert.Reason {
			t.Errorf("%s: got valid=%v %q, want valid=%v %q (reference %v %q)", c.Name, got.Valid, got.Reason, c.Concert.Valid, c.Concert.Reason, c.Reference.Valid, c.Reference.Reason)
		}
		if got.Valid && got.Payer != c.Reference.Payer {
			t.Errorf("%s: payer %s, reference %s", c.Name, got.Payer, c.Reference.Payer)
		}
	}
}

func TestSettlementTransactionMatchesReference(t *testing.T) {
	v := load(t)
	f := &fakeRPC{sim: v.Cases[0].Simulation, current: v.Current, sequence: v.SponsorSequence, status: "SUCCESS"}
	s := newScheme(t, v, f)
	res, err := s.Settle(context.Background(), payload(v.Settle.Transaction, v.Settle.Requirements), v.Settle.Requirements)
	if err != nil || !res.Success || len(f.submitted) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	var got, want xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(f.submitted[0], &got); err != nil {
		t.Fatal(err)
	}
	if err := xdr.SafeUnmarshalBase64(v.Settle.Submitted, &want); err != nil {
		t.Fatal(err)
	}
	g, w := got.V1.Tx, want.V1.Tx
	// Time bounds depend on the clock; everything else must be identical.
	if g.Cond.TimeBounds == nil || g.Cond.TimeBounds.MinTime != 0 || g.Cond.TimeBounds.MaxTime == 0 {
		t.Errorf("time bounds %+v", g.Cond.TimeBounds)
	}
	g.Cond, w.Cond = xdr.Preconditions{}, xdr.Preconditions{}
	gb, _ := xdr.MarshalBase64(g)
	wb, _ := xdr.MarshalBase64(w)
	if gb != wb {
		t.Errorf("rebuilt settlement differs from @x402/stellar's:\n got %s\nwant %s", gb, wb)
	}
	hash, _ := network.HashTransactionInEnvelope(got, v.Passphrase)
	if len(got.V1.Signatures) != 1 || s.Sponsor.Verify(hash[:], got.V1.Signatures[0].Signature) != nil {
		t.Error("settlement is not signed by the sponsor")
	}
}

func TestSettleReportsFailureWhenNotFinal(t *testing.T) {
	v := load(t)
	f := &fakeRPC{sim: v.Cases[0].Simulation, current: v.Current, sequence: v.SponsorSequence, status: "NOT_FOUND"}
	s := newScheme(t, v, f)
	res, err := s.Settle(context.Background(), payload(v.Settle.Transaction, v.Settle.Requirements), v.Settle.Requirements)
	if err != nil || res.Success || res.Transaction == "" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestSEP53MessageSignature(t *testing.T) {
	v := load(t)
	sig, _ := base64.StdEncoding.DecodeString(v.SEP53.Signature)
	if !VerifySEP53(v.SEP53.Address, v.SEP53.Message, sig) || VerifySEP53(v.SEP53.Address, v.SEP53.Message+"x", sig) {
		t.Fatal("SEP-53 signature check")
	}
}

func TestNewPaymentPassesVerification(t *testing.T) {
	v := load(t)
	c := v.Cases[0]
	payer := keypair.MustRandom()
	r := c.Requirements
	// Simulation 1 returns the unsigned payer authorization; simulation 2,
	// with it signed, returns resources and the transfer event.
	from, _ := scAddress(payer.Address())
	to, _ := anyAddress(r.PayTo)
	amt, _ := i128(big.NewInt(1000000))
	contract, _ := contractAddress(r.Asset)
	addr := from.MustAddress()
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddress, Address: &xdr.SorobanAddressCredentials{Address: addr, Nonce: 7, Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid}}},
		RootInvocation: xdr.SorobanAuthorizedInvocation{Function: xdr.SorobanAuthorizedFunction{Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			ContractFn: &xdr.InvokeContractArgs{ContractAddress: contract, FunctionName: "transfer", Args: []xdr.ScVal{from, to, amt}}}},
	}
	eb, _ := xdr.MarshalBase64(entry)
	var sim map[string]any
	_ = json.Unmarshal(c.Simulation, &sim)
	id, _ := decodeContract(r.Asset)
	cid := xdr.ContractId(id)
	sym := xdr.ScSymbol("transfer")
	ev := xdr.DiagnosticEvent{InSuccessfulContractCall: true, Event: xdr.ContractEvent{ContractId: &cid, Type: xdr.ContractEventTypeContract,
		Body: xdr.ContractEventBody{V: 0, V0: &xdr.ContractEventV0{Topics: []xdr.ScVal{{Type: xdr.ScValTypeScvSymbol, Sym: &sym}, from, to}, Data: amt}}}}
	evb, _ := xdr.MarshalBase64(ev)
	sim["events"] = []string{evb}
	sim["results"] = []any{map[string]any{"auth": []string{eb}, "xdr": "AAAAAQ=="}}
	raw, _ := json.Marshal(sim)
	f := &fakeRPC{sim: raw, current: v.Current}
	s := newScheme(t, v, f)
	enc, err := NewPayment(context.Background(), s.RPC, s.Horizon, Testnet, payer, r)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Verify(context.Background(), payload(enc, r), r); !got.Valid || got.Payer != payer.Address() {
		t.Fatalf("%+v", got)
	}
}

func TestSignAuthEntryMatchesAuthorizeEntry(t *testing.T) {
	v := load(t)
	var seed [32]byte
	for i := range seed {
		seed[i] = 1 // the vectors' payer: Keypair.fromRawEd25519Seed(32 × 0x01)
	}
	payer, _ := keypair.FromRawSeed(seed)
	var env xdr.TransactionEnvelope
	_ = xdr.SafeUnmarshalBase64(v.Cases[0].Transaction, &env)
	signed := env.V1.Tx.Operations[0].Body.MustInvokeHostFunctionOp().Auth[0]
	unsigned := signed
	c := *signed.Credentials.Address
	c.Signature = xdr.ScVal{Type: xdr.ScValTypeScvVoid}
	unsigned.Credentials.Address = &c
	got, err := SignAuthEntry(v.Passphrase, unsigned, payer, uint32(signed.Credentials.Address.SignatureExpirationLedger))
	if err != nil {
		t.Fatal(err)
	}
	gb, _ := xdr.MarshalBase64(got)
	wb, _ := xdr.MarshalBase64(signed)
	if gb != wb {
		t.Fatalf("signed entry differs from authorizeEntry:\n got %s\nwant %s", gb, wb)
	}
}
