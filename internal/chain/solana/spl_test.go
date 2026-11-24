package solana

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/x402"
)

func TestSolana_NativeWithComputeBudgetAndMemo(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	destPub, _, _ := ed25519.GenerateKey(nil)
	var from, to, bh PublicKey
	copy(from[:], pub)
	copy(to[:], destPub)
	bh[0] = 7

	unsigned := BuildNativeTransferWithExtras(from, to, 1500000, bh, 200000, 10000, "concert:sol1")
	signed := Sign(unsigned, priv)
	enc := base64.StdEncoding.EncodeToString(signed)

	req := x402.Requirements{
		Scheme:            SchemeName,
		Network:           Devnet,
		Asset:             "SOL",
		Amount:            "1500000",
		PayTo:             to.String(),
		MaxTimeoutSeconds: 60,
		Extra:             map[string]any{"areFeesSponsored": false, "memo": "concert:sol1"},
	}
	got, err := InspectPayment(enc, req)
	if err != nil {
		t.Fatalf("InspectPayment native+ComputeBudget+Memo: %v", err)
	}
	if got.From != from || got.To != to || got.Lamports != 1500000 {
		t.Fatalf("unexpected decoded transfer: %+v", got)
	}
	// Wrong memo must fail
	reqBad := req
	reqBad.Extra = map[string]any{"areFeesSponsored": false, "memo": "concert:other"}
	if _, err := InspectPayment(enc, reqBad); err == nil {
		t.Fatal("expected memo mismatch rejection")
	}
}

func TestSolana_SPLTransferCheckedInspect(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	destPub, _, _ := ed25519.GenerateKey(nil)
	mintPub, _, _ := ed25519.GenerateKey(nil)
	var from, to, mint, bh PublicKey
	copy(from[:], pub)
	copy(to[:], destPub)
	copy(mint[:], mintPub)
	bh[1] = 9

	unsigned, err := BuildSPLTransfer(from, to, mint, tokenProgram, 990000, 6, bh, true, "concert:usdc1")
	if err != nil {
		t.Fatalf("BuildSPLTransfer: %v", err)
	}
	signed := Sign(unsigned, priv)
	enc := base64.StdEncoding.EncodeToString(signed)

	req := x402.Requirements{
		Scheme:            ExactSchemeName,
		Network:           Devnet,
		Asset:             mint.String(),
		Amount:            "990000",
		PayTo:             to.String(),
		MaxTimeoutSeconds: 60,
		Extra:             map[string]any{"areFeesSponsored": false, "memo": "concert:usdc1"},
	}
	got, err := InspectPayment(enc, req)
	if err != nil {
		t.Fatalf("InspectPayment SPL: %v", err)
	}
	if got.From != from || got.To != to || got.Lamports != 990000 {
		t.Fatalf("unexpected decoded SPL transfer: %+v", got)
	}
}

func TestSolana_AutoScanNFT_TokenBalance_DirectPayment(t *testing.T) {
	ownerPub, _, _ := ed25519.GenerateKey(nil)
	destPub, _, _ := ed25519.GenerateKey(nil)
	mintPub, _, _ := ed25519.GenerateKey(nil)
	collPub, _, _ := ed25519.GenerateKey(nil)
	var owner, dest, mint, coll PublicKey
	copy(owner[:], ownerPub)
	copy(dest[:], destPub)
	copy(mint[:], mintPub)
	copy(coll[:], collPub)

	pda, err := FindProgramAddress([][]byte{[]byte("metadata"), metadataProgram[:], mint[:]}, metadataProgram)
	if err != nil {
		t.Fatal(err)
	}
	// Construct valid MetadataV1 bytes with verified collection = coll
	var meta []byte
	meta = append(meta, 4)                   // MetadataV1
	meta = append(meta, make([]byte, 32)...) // update authority
	meta = append(meta, mint[:]...)
	for i := 0; i < 3; i++ {
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], 1)
		meta = append(meta, l[:]...)
		meta = append(meta, 'x')
	}
	meta = append(meta, 0, 0) // seller_fee_basis_points
	meta = append(meta, 0)    // creators = None
	meta = append(meta, 1, 0) // primary_sale, is_mutable
	meta = append(meta, 0)    // edition_nonce = None
	meta = append(meta, 1, 0) // token_standard = Some(NonFungible)
	meta = append(meta, 1, 1) // collection = Some(verified=true)
	meta = append(meta, coll[:]...)

	nowUnix := time.Now().Unix()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var res any
		switch req.Method {
		case "getGenesisHash":
			res = devnetGenesis
		case "getTokenAccountsByOwner":
			res = map[string]any{
				"value": []map[string]any{
					{
						"account": map[string]any{
							"owner": tokenProgram.String(),
							"data": map[string]any{
								"parsed": map[string]any{
									"info": map[string]any{
										"mint":        mint.String(),
										"owner":       owner.String(),
										"tokenAmount": map[string]any{"amount": "1", "decimals": 0},
									},
								},
							},
						},
					},
				},
			}
		case "getAccountInfo":
			var key string
			_ = json.Unmarshal(req.Params[0], &key)
			if key == pda.String() {
				res = map[string]any{"value": map[string]any{"owner": metadataProgram.String(), "data": []string{base64.StdEncoding.EncodeToString(meta), "base64"}}}
			} else {
				res = map[string]any{"value": nil}
			}
		case "getBalance":
			res = map[string]any{"value": uint64(5000000000)}
		case "getSignaturesForAddress":
			res = []map[string]any{{"signature": "sigDirectSol1", "err": nil, "memo": "concert:solproof1", "blockTime": nowUnix}}
		case "getTransaction":
			res = map[string]any{
				"blockTime": nowUnix,
				"meta": map[string]any{
					"err":          nil,
					"preBalances":  []int64{1000000, 500000},
					"postBalances": []int64{994999, 500001},
				},
				"transaction": map[string]any{
					"message": map[string]any{
						"accountKeys": []map[string]any{
							{"pubkey": owner.String(), "signer": true},
							{"pubkey": dest.String(), "signer": false},
						},
						"instructions": []map[string]any{
							{"program": "spl-memo", "programId": memoProgram.String(), "parsed": "concert:solproof1"},
						},
					},
				},
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": res})
	}))
	defer srv.Close()

	s := New(Devnet, srv.URL)
	// Auto-scan NFT WITHOUT providing mint ID!
	foundMint, err := s.FindOwnedNFT(context.Background(), owner.String(), coll.String(), "", "")
	if err != nil || foundMint != mint.String() {
		t.Fatalf("FindOwnedNFT auto-scan: mint=%q err=%v", foundMint, err)
	}
	// Balance check
	ok, bal, err := s.MeetsMinBalance(context.Background(), owner.String(), "SOL", "1000000000")
	if err != nil || !ok || bal != "5000000000" {
		t.Fatalf("MeetsMinBalance SOL: ok=%v bal=%q err=%v", ok, bal, err)
	}
	// Direct 1-lamport memo ownership proof
	sig, payer, err := s.FindDirectPayment(context.Background(), owner.String(), dest.String(), "SOL", "1", "concert:solproof1", time.Now().Add(-time.Minute))
	if err != nil || sig != "sigDirectSol1" || payer != owner.String() {
		t.Fatalf("FindDirectPayment SOL: sig=%q payer=%q err=%v", sig, payer, err)
	}
}
