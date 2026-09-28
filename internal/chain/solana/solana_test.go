package solana

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/base58"
	"github.com/andreimerlescu/concert/internal/x402"
)

// testdata/vectors.json was generated with @solana/web3.js 1.99.0.
type vectors struct {
	Requirements x402.Requirements `json:"requirements"`
	Payer        string            `json:"payer"`
	Cases        []struct {
		Name string `json:"name"`
		Tx   string `json:"tx"`
		OK   bool   `json:"ok"`
	} `json:"cases"`
	Unsigned struct {
		From, To, Lamports, Blockhash, Tx string
	} `json:"unsigned"`
	PDAs []struct {
		Mint, PDA string
	} `json:"pdas"`
	Message struct {
		Address, Message, Signature string
	} `json:"message"`
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

func TestInspectMatchesReferenceTransactions(t *testing.T) {
	v := load(t)
	for _, c := range v.Cases {
		got, err := Inspect(c.Tx, v.Requirements)
		if (err == nil) != c.OK {
			t.Errorf("%s: err=%v want ok=%v", c.Name, err, c.OK)
		}
		if err == nil && got.From.String() != v.Payer {
			t.Errorf("%s: payer %s", c.Name, got.From)
		}
	}
}

func TestNewTransferMatchesReferenceSerialization(t *testing.T) {
	v := load(t)
	from, _ := ParsePublicKey(v.Unsigned.From)
	to, _ := ParsePublicKey(v.Unsigned.To)
	bh, _ := ParsePublicKey(v.Unsigned.Blockhash)
	if got := base64.StdEncoding.EncodeToString(NewTransfer(from, to, 1500000, bh)); got != v.Unsigned.Tx {
		t.Fatalf("unsigned transfer differs from @solana/web3.js:\n got %s\nwant %s", got, v.Unsigned.Tx)
	}
}

func TestProgramAddressesMatchReference(t *testing.T) {
	v := load(t)
	for _, c := range v.PDAs {
		mint, _ := ParsePublicKey(c.Mint)
		got, err := FindProgramAddress([][]byte{[]byte("metadata"), metadataProgram[:], mint[:]}, metadataProgram)
		if err != nil || got.String() != c.PDA {
			t.Errorf("mint %s: %s want %s", c.Mint, got, c.PDA)
		}
	}
}

func TestMessageSignatureMatchesReference(t *testing.T) {
	v := load(t)
	sig, _ := base64.StdEncoding.DecodeString(v.Message.Signature)
	if !VerifyMessage(v.Message.Address, v.Message.Message, sig) || VerifyMessage(v.Message.Address, v.Message.Message+" modified", sig) {
		t.Fatal("message signature check")
	}
}

func TestBase58RoundTrip(t *testing.T) {
	for _, s := range []string{"11111111111111111111111111111111", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "1112"} {
		b, err := base58.Bitcoin.Decode(s)
		if err != nil || base58.Bitcoin.Encode(b) != s {
			t.Errorf("%s: %v", s, err)
		}
	}
}

func TestReadCollectionRequiresVerifiedSameMint(t *testing.T) {
	mint, coll := PublicKey{1}, PublicKey{2}
	str := func(s string) []byte { return append([]byte{byte(len(s)), 0, 0, 0}, s...) }
	var data []byte
	data = append(data, 4)
	data = append(data, make([]byte, 32)...)
	data = append(data, mint[:]...)
	data = append(data, str("NFT")...)
	data = append(data, str("N")...)
	data = append(data, str("https://example.test")...)
	data = append(data, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1)
	data = append(data, coll[:]...)
	c, err := ReadCollection(data, mint)
	if err != nil || !c.Verified || c.Key != coll {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := ReadCollection(data, coll); err == nil {
		t.Fatal("wrong mint accepted")
	}
	if _, err := ReadCollection(data[:75], mint); err == nil {
		t.Fatal("truncated metadata accepted")
	}
	data[len(data)-33] = 0
	if c, _ := ReadCollection(data, mint); c.Verified {
		t.Fatal("unverified collection reported verified")
	}
}

// fakeRPC answers the Solana methods the scheme uses. statuses are successive
// getSignatureStatuses answers; the last repeats.
type fakeRPC struct {
	mu       sync.Mutex
	genesis  string
	statuses []*Status
	calls    int
	sent     int
}

func (f *fakeRPC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     any    `json:"id"`
		Method string `json:"method"`
		Params []json.RawMessage
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	defer f.mu.Unlock()
	ctx := map[string]any{"slot": 1}
	var result any
	switch req.Method {
	case "getGenesisHash":
		result = f.genesis
	case "getSignatureStatuses":
		i := min(f.calls, len(f.statuses)-1)
		f.calls++
		result = map[string]any{"context": ctx, "value": []any{f.statuses[i]}}
	case "isBlockhashValid":
		result = map[string]any{"context": ctx, "value": true}
	case "simulateTransaction":
		result = map[string]any{"context": ctx, "value": map[string]any{"err": nil}}
	case "sendTransaction":
		f.sent++
		var enc string
		_ = json.Unmarshal(req.Params[0], &enc)
		raw, _ := base64.StdEncoding.DecodeString(enc)
		result = base58.Bitcoin.Encode(raw[1:65])
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
}

const devnetGenesis = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1WcaWoxPkrZBG"

func signedTransfer(t *testing.T) (string, x402.Requirements, string) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	to, _, _ := ed25519.GenerateKey(nil)
	var from, dest PublicKey
	copy(from[:], pub)
	copy(dest[:], to)
	raw := Sign(NewTransfer(from, dest, 123, PublicKey{9}), priv)
	req := x402.Requirements{Scheme: SchemeName, Network: Devnet, Asset: "SOL", Amount: "123", PayTo: dest.String(), MaxTimeoutSeconds: 60}
	return base64.StdEncoding.EncodeToString(raw), req, from.String()
}

func payload(tx string) x402.Payload {
	return x402.Payload{Version: 2, Payload: json.RawMessage(`{"transaction":"` + tx + `"}`)}
}

func scheme(f *fakeRPC) (*Scheme, func()) {
	srv := httptest.NewServer(f)
	s := New(Devnet, srv.URL)
	s.PollInterval, s.ConfirmWithin = time.Millisecond, 200*time.Millisecond
	return s, srv.Close
}

func TestVerifyRefusesTransfersAlreadyOnChain(t *testing.T) {
	tx, req, payer := signedTransfer(t)
	for _, st := range []*Status{{ConfirmationStatus: "processed"}, {ConfirmationStatus: "finalized"}} {
		s, done := scheme(&fakeRPC{genesis: devnetGenesis, statuses: []*Status{st}})
		if s.Verify(context.Background(), payload(tx), req).Valid {
			t.Errorf("%s transfer verified as new evidence", st.ConfirmationStatus)
		}
		done()
	}
	s, done := scheme(&fakeRPC{genesis: devnetGenesis, statuses: []*Status{nil}})
	defer done()
	if v := s.Verify(context.Background(), payload(tx), req); !v.Valid || v.Payer != payer {
		t.Fatalf("%+v", v)
	}
}

func TestVerifyRefusesAnotherCluster(t *testing.T) {
	tx, req, _ := signedTransfer(t)
	f := &fakeRPC{genesis: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d", statuses: []*Status{nil}}
	s, done := scheme(f)
	defer done()
	if s.Verify(context.Background(), payload(tx), req).Valid {
		t.Fatal("mainnet RPC accepted for devnet")
	}
	if _, err := s.Settle(context.Background(), payload(tx), req); err == nil || f.sent != 0 {
		t.Fatal("settled on the wrong cluster")
	}
}

func TestSettleBroadcastsOnceAndPollsToFinality(t *testing.T) {
	tx, req, payer := signedTransfer(t)
	f := &fakeRPC{genesis: devnetGenesis, statuses: []*Status{nil, {ConfirmationStatus: "confirmed"}, {ConfirmationStatus: "finalized"}}}
	s, done := scheme(f)
	defer done()
	r, err := s.Settle(context.Background(), payload(tx), req)
	if err != nil || !r.Success || r.Payer != payer || f.sent != 1 {
		t.Fatalf("%+v %v sent=%d", r, err, f.sent)
	}
	landed := &fakeRPC{genesis: devnetGenesis, statuses: []*Status{{ConfirmationStatus: "processed"}, {ConfirmationStatus: "finalized"}}}
	s2, done2 := scheme(landed)
	defer done2()
	if r, err := s2.Settle(context.Background(), payload(tx), req); err != nil || !r.Success || landed.sent != 0 {
		t.Fatalf("already-landing transfer: %+v %v sent=%d", r, err, landed.sent)
	}
}

func TestSettleWithoutFinalityOrWithFailureIsAnError(t *testing.T) {
	tx, req, _ := signedTransfer(t)
	s, done := scheme(&fakeRPC{genesis: devnetGenesis, statuses: []*Status{nil, {ConfirmationStatus: "confirmed"}}})
	defer done()
	if _, err := s.Settle(context.Background(), payload(tx), req); err == nil || !strings.Contains(err.Error(), "finality") {
		t.Fatalf("got %v", err)
	}
	s2, done2 := scheme(&fakeRPC{genesis: devnetGenesis, statuses: []*Status{nil, {ConfirmationStatus: "finalized", Err: map[string]any{"InstructionError": 1}}}})
	defer done2()
	if _, err := s2.Settle(context.Background(), payload(tx), req); err == nil {
		t.Fatal("failed transfer reported as settled")
	}
}
