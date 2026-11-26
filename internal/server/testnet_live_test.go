//go:build enterprise && livetestnet

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/hedera"
	"github.com/andreimerlescu/concert/internal/chain/solana"
	"github.com/andreimerlescu/concert/internal/chain/stellar"
	"github.com/andreimerlescu/concert/internal/chain/xrpl"
	"github.com/andreimerlescu/concert/internal/fastlane"
	"github.com/andreimerlescu/concert/internal/opt"
	"github.com/andreimerlescu/concert/internal/x402"
	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
	"github.com/stellar/go-stellar-sdk/keypair"
)

func liveHTTPClient() *http.Client {
	return &http.Client{Timeout: 60 * time.Second}
}

func fundXRPLTestnetAccount(t *testing.T) (*xrpl.Key, string) {
	t.Helper()
	resp, err := liveHTTPClient().Post("https://faucet.altnet.rippletest.net/accounts", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("XRPL testnet faucet request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("XRPL testnet faucet HTTP %d: %s", resp.StatusCode, body)
	}
	var out struct {
		Account struct {
			ClassicAddress string `json:"classicAddress"`
			Address        string `json:"address"`
			Secret         string `json:"secret"`
		} `json:"account"`
		Seed string `json:"seed"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("XRPL faucet JSON decode: %v (%s)", err, body)
	}
	seed := out.Seed
	if seed == "" {
		seed = out.Account.Secret
	}
	if seed == "" {
		t.Fatalf("XRPL faucet returned no seed: %s", body)
	}
	key, err := xrpl.KeyFromSeed(seed)
	if err != nil {
		t.Fatalf("KeyFromSeed: %v", err)
	}
	// Wait briefly until validated ledger sees the funded account.
	rpc := xrpl.RPC{URL: "https://s.altnet.rippletest.net:51234/"}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		info, err := rpc.AccountInfo(ctx, key.Address)
		cancel()
		if err == nil && info.Sequence > 0 {
			return key, seed
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("XRPL testnet account %s not visible after faucet funding", key.Address)
	return nil, ""
}

func startLiveEconcert(t *testing.T, fc fastlane.Config, nets map[string]any) (*app, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("LIVE-ORIGIN-OK:" + r.URL.Path))
	}))
	t.Cleanup(up.Close)

	dir := t.TempDir()
	fcPath := filepath.Join(dir, "fastlane.json")
	netPath := filepath.Join(dir, "networks.json")

	fcBytes, err := json.Marshal(fc)
	if err != nil {
		t.Fatal(err)
	}
	netBytes, err := json.Marshal(nets)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fcPath, fcBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(netPath, netBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig(up.URL)
	cfg.dataDir = dir
	cfg.admitSecret = []byte("concert-live-testnet-verification-secret-012345")
	cfg.admitSecretGenerated = false
	cfg.capacity = 2
	cfg.priorityCap = 4
	cfg.fastlaneFile = fcPath
	cfg.networksFile = netPath

	a, err := newApp(cfg)
	if err != nil {
		t.Fatalf("newApp (live gateway): %v", err)
	}
	t.Cleanup(a.Close)
	front := httptest.NewServer(a.handler)
	t.Cleanup(front.Close)
	return a, front
}

func livePostJSON(t *testing.T, client *http.Client, url string, headers map[string]string, body any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b
}

func TestLiveTestnet_XRPL(t *testing.T) {
	payer, _ := fundXRPLTestnetAccount(t)
	merchant, _ := fundXRPLTestnetAccount(t)
	t.Logf("XRPL Testnet accounts funded: payer=%s merchant=%s", payer.Address, merchant.Address)

	const rpcURL = "https://s.altnet.rippletest.net:51234/"
	rpc := xrpl.RPC{URL: rpcURL}

	reqOffer := fastlane.Requirements{
		Scheme:            "exact",
		Network:           "xrpl:1",
		Amount:            "100000", // 0.1 XRP
		Asset:             "XRP",
		PayTo:             merchant.Address,
		MaxTimeoutSeconds: 60,
		Extra:             map[string]any{"areFeesSponsored": false},
	}
	fc := fastlane.Config{
		Enabled:          true,
		Origin:           "http://127.0.0.1:8080",
		TestMode:         true,
		Merchant:         "Concert Live Testnet XRPL",
		TermsURL:         "http://127.0.0.1:8080/terms",
		PrivacyURL:       "http://127.0.0.1:8080/privacy",
		RefundURL:        "http://127.0.0.1:8080/refunds",
		PassSeconds:      300,
		PassIdleSeconds:  180,
		PassMaxSeconds:   1800,
		PassSliding:      opt.Some(true),
		NFTPassSeconds:   300,
		DirectPayEnabled: opt.Some(true),
		Offers: []fastlane.Offer{{
			Label:         "0.1 XRP Testnet Pass",
			DisplayAmount: "0.1",
			AssetSymbol:   "XRP",
			AssetDecimals: 6,
			AssetType:     "native",
			Requirements:  reqOffer,
		}},
		TokenGates: []fastlane.TokenGate{{
			ID:               "xrp-holder-10",
			Label:            "10+ XRP Holder",
			Network:          "xrpl:1",
			Asset:            "XRP",
			AssetSymbol:      "XRP",
			AssetDecimals:    6,
			MinAmount:        "10000000",
			DisplayMinAmount: "10",
			Usage:            "entry",
		}},
	}
	nets := map[string]any{
		"xrpl:1": map[string]any{"rpc": rpcURL, "max_fee": "50000"},
	}

	_, front := startLiveEconcert(t, fc, nets)
	hc := liveHTTPClient()

	// Subtest 1A: Live x402 XRP Payment settled end-to-end through econcert.
	t.Run("x402_XRP_Payment", func(t *testing.T) {
		code, body := livePostJSON(t, hc, front.URL+"/_concert/session", nil, map[string]any{})
		if code != 200 {
			t.Fatalf("session: %d %s", code, body)
		}
		var sess struct {
			Session string `json:"session"`
		}
		_ = json.Unmarshal(body, &sess)

		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		xReq := x402.Requirements{
			Scheme: reqOffer.Scheme, Network: reqOffer.Network, Amount: reqOffer.Amount,
			Asset: reqOffer.Asset, PayTo: reqOffer.PayTo, MaxTimeoutSeconds: reqOffer.MaxTimeoutSeconds, Extra: reqOffer.Extra,
		}
		blob, err := xrpl.NewPaymentBlob(ctx, rpc, payer, xReq)
		if err != nil {
			t.Fatalf("xrpl.NewPaymentBlob: %v", err)
		}
		proof, _ := json.Marshal(map[string]any{
			"x402Version": 2,
			"accepted":    reqOffer,
			"payload":     map[string]string{"signedTxBlob": blob},
		})
		code, body = livePostJSON(t, hc, front.URL+"/_concert/payment", map[string]string{
			fastlane.SessionHeader: sess.Session,
			"PAYMENT-SIGNATURE":    base64.StdEncoding.EncodeToString(proof),
		}, map[string]any{})
		if code != 200 {
			t.Fatalf("live XRPL x402 payment failed: %d %s", code, body)
		}
		var out map[string]any
		_ = json.Unmarshal(body, &out)
		if out["eligible"] != true {
			t.Fatalf("expected eligible=true, got %s", body)
		}
		t.Logf("LIVE XRPL x402 PAYMENT SETTLED: %s", body)
	})

	// Subtest 1B: Live 1-drop Destination-Tag + Memo ownership proof for 10+ XRP token gate.
	t.Run("Direct_1Drop_DestTag_Memo_TokenGate_Proof", func(t *testing.T) {
		code, body := livePostJSON(t, hc, front.URL+"/_concert/session", nil, map[string]any{})
		if code != 200 {
			t.Fatalf("session: %d %s", code, body)
		}
		var sess struct {
			Session string `json:"session"`
		}
		_ = json.Unmarshal(body, &sess)

		code, body = livePostJSON(t, hc, front.URL+"/_concert/direct/challenge", map[string]string{
			fastlane.SessionHeader: sess.Session,
		}, map[string]any{
			"kind":      "proof",
			"rule_kind": "token",
			"rule_id":   "xrp-holder-10",
			"address":   payer.Address,
		})
		if code != 200 {
			t.Fatalf("direct/challenge proof failed: %d %s", code, body)
		}
		var ch struct {
			ChallengeID    string `json:"challenge_id"`
			PayTo          string `json:"pay_to"`
			Amount         string `json:"amount"`
			DestinationTag uint32 `json:"destination_tag"`
			Memo           string `json:"memo"`
		}
		_ = json.Unmarshal(body, &ch)
		if ch.DestinationTag == 0 || !strings.HasPrefix(ch.Memo, "concert:") {
			t.Fatalf("unexpected XRPL direct challenge: %s", body)
		}

		// Broadcast real 1-drop XRPL Testnet tx with exact DestinationTag & Memo.
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		blob, err := xrpl.NewPaymentBlob(ctx, rpc, payer, x402.Requirements{
			Scheme: "exact", Network: "xrpl:1", Amount: ch.Amount, Asset: "XRP", PayTo: ch.PayTo, MaxTimeoutSeconds: 60,
			Extra: map[string]any{"destinationTag": ch.DestinationTag, "memo": ch.Memo},
		})
		if err != nil {
			t.Fatalf("xrpl 1-drop blob: %v", err)
		}
		submitHash, err := rpc.Submit(ctx, blob)
		if err != nil {
			t.Fatalf("xrpl 1-drop submit: %v", err)
		}
		t.Logf("XRPL 1-drop proof tx submitted: hash=%s destTag=%d memo=%s", submitHash, ch.DestinationTag, ch.Memo)

		// Poll /_concert/direct/verify until validated on XRPL Testnet.
		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			code, body = livePostJSON(t, hc, front.URL+"/_concert/direct/verify", map[string]string{
				fastlane.SessionHeader: sess.Session,
			}, map[string]string{"challenge_id": ch.ChallengeID})
			if code == 200 && strings.Contains(string(body), `"eligible":true`) {
				t.Logf("LIVE XRPL 1-DROP DEST-TAG/MEMO PROOF VERIFIED: %s", body)
				return
			}
			time.Sleep(3 * time.Second)
		}
		t.Fatalf("XRPL direct proof not confirmed in 45s (last=%d %s)", code, body)
	})
}

func fundStellarFriendbot(t *testing.T) *keypair.Full {
	t.Helper()
	kp, err := keypair.Random()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := liveHTTPClient().Get("https://friendbot.stellar.org/?addr=" + kp.Address())
	if err != nil {
		t.Fatalf("Friendbot request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("Friendbot HTTP %d for %s: %s", resp.StatusCode, kp.Address(), body)
	}
	return kp
}

func TestLiveTestnet_Stellar(t *testing.T) {
	payer := fundStellarFriendbot(t)
	merchant := fundStellarFriendbot(t)
	t.Logf("Stellar Testnet accounts funded via Friendbot: payer=%s merchant=%s", payer.Address(), merchant.Address())

	const horizonURL = "https://horizon-testnet.stellar.org"
	const sorobanURL = "https://soroban-testnet.stellar.org"
	hz := stellar.Horizon{URL: horizonURL}

	reqOffer := fastlane.Requirements{
		Scheme:            "exact",
		Network:           "stellar:testnet",
		Amount:            "1000000", // 0.1 XLM
		Asset:             "XLM",
		PayTo:             merchant.Address(),
		MaxTimeoutSeconds: 60,
		Extra:             map[string]any{"areFeesSponsored": false},
	}
	fc := fastlane.Config{
		Enabled:          true,
		Origin:           "http://127.0.0.1:8080",
		TestMode:         true,
		Merchant:         "Concert Live Testnet Stellar",
		TermsURL:         "http://127.0.0.1:8080/terms",
		PrivacyURL:       "http://127.0.0.1:8080/privacy",
		RefundURL:        "http://127.0.0.1:8080/refunds",
		PassSeconds:      300,
		PassIdleSeconds:  180,
		PassMaxSeconds:   1800,
		PassSliding:      opt.Some(true),
		NFTPassSeconds:   300,
		DirectPayEnabled: opt.Some(true),
		Offers: []fastlane.Offer{{
			Label:         "0.1 XLM Testnet Pass (Zero Hot Keys)",
			DisplayAmount: "0.1",
			AssetSymbol:   "XLM",
			AssetDecimals: 7,
			AssetType:     "native",
			Requirements:  reqOffer,
		}},
		TokenGates: []fastlane.TokenGate{{
			ID:               "xlm-holder-100",
			Label:            "100+ XLM Holder",
			Network:          "stellar:testnet",
			Asset:            "XLM",
			AssetSymbol:      "XLM",
			AssetDecimals:    7,
			MinAmount:        "1000000000",
			DisplayMinAmount: "100",
			Usage:            "entry",
		}},
	}
	// ZERO secret_env — proves zero-hot-key payer-pays-fees Stellar mainnet/testnet operation!
	nets := map[string]any{
		"stellar:testnet": map[string]any{"rpc": sorobanURL, "horizon": horizonURL, "max_fee": "50000"},
	}

	_, front := startLiveEconcert(t, fc, nets)
	hc := liveHTTPClient()

	// Subtest 2A: Live payer-pays-fees Classic XLM x402 payment through econcert.
	t.Run("x402_Classic_XLM_ZeroHotKeys", func(t *testing.T) {
		code, body := livePostJSON(t, hc, front.URL+"/_concert/session", nil, map[string]any{})
		if code != 200 {
			t.Fatalf("session: %d %s", code, body)
		}
		var sess struct {
			Session string `json:"session"`
		}
		_ = json.Unmarshal(body, &sess)

		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		txXDR, err := stellar.NewClassicPayment(ctx, hz, "stellar:testnet", payer, x402.Requirements{
			Scheme: reqOffer.Scheme, Network: reqOffer.Network, Amount: reqOffer.Amount,
			Asset: reqOffer.Asset, PayTo: reqOffer.PayTo, MaxTimeoutSeconds: reqOffer.MaxTimeoutSeconds, Extra: reqOffer.Extra,
		})
		if err != nil {
			t.Fatalf("stellar.NewClassicPayment: %v", err)
		}
		proof, _ := json.Marshal(map[string]any{
			"x402Version": 2,
			"accepted":    reqOffer,
			"payload":     map[string]string{"transaction": txXDR},
		})
		code, body = livePostJSON(t, hc, front.URL+"/_concert/payment", map[string]string{
			fastlane.SessionHeader: sess.Session,
			"PAYMENT-SIGNATURE":    base64.StdEncoding.EncodeToString(proof),
		}, map[string]any{})
		if code != 200 {
			t.Fatalf("live Stellar classic x402 payment failed: %d %s", code, body)
		}
		t.Logf("LIVE STELLAR ZERO-HOT-KEY x402 PAYMENT SETTLED: %s", body)
	})

	// Subtest 2B: Live 1-stroop Memo ownership proof for 100+ XLM balance gate.
	t.Run("Direct_1Stroop_Memo_TokenGate_Proof", func(t *testing.T) {
		code, body := livePostJSON(t, hc, front.URL+"/_concert/session", nil, map[string]any{})
		if code != 200 {
			t.Fatalf("session: %d %s", code, body)
		}
		var sess struct {
			Session string `json:"session"`
		}
		_ = json.Unmarshal(body, &sess)

		code, body = livePostJSON(t, hc, front.URL+"/_concert/direct/challenge", map[string]string{
			fastlane.SessionHeader: sess.Session,
		}, map[string]any{
			"kind":      "proof",
			"rule_kind": "token",
			"rule_id":   "xlm-holder-100",
			"address":   payer.Address(),
		})
		if code != 200 {
			t.Fatalf("stellar direct/challenge failed: %d %s", code, body)
		}
		var ch struct {
			ChallengeID string `json:"challenge_id"`
			PayTo       string `json:"pay_to"`
			Amount      string `json:"amount"`
			Memo        string `json:"memo"`
		}
		_ = json.Unmarshal(body, &ch)

		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		txXDR, err := stellar.NewClassicPayment(ctx, hz, "stellar:testnet", payer, x402.Requirements{
			Scheme: "exact", Network: "stellar:testnet", Amount: ch.Amount, Asset: "XLM", PayTo: ch.PayTo, MaxTimeoutSeconds: 60,
			Extra: map[string]any{"memo": ch.Memo},
		})
		if err != nil {
			t.Fatalf("stellar 1-stroop tx: %v", err)
		}
		txHash, err := hz.Submit(ctx, txXDR)
		if err != nil {
			t.Fatalf("horizon submit 1-stroop proof: %v", err)
		}
		t.Logf("Stellar 1-stroop proof tx submitted: hash=%s memo=%s", txHash, ch.Memo)

		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			code, body = livePostJSON(t, hc, front.URL+"/_concert/direct/verify", map[string]string{
				fastlane.SessionHeader: sess.Session,
			}, map[string]string{"challenge_id": ch.ChallengeID})
			if code == 200 && strings.Contains(string(body), `"eligible":true`) {
				t.Logf("LIVE STELLAR 1-STROOP MEMO PROOF VERIFIED: %s", body)
				return
			}
			time.Sleep(3 * time.Second)
		}
		t.Fatalf("Stellar direct proof not confirmed in 45s (last=%d %s)", code, body)
	})
}

func TestLiveTestnet_Solana(t *testing.T) {
	const devnetID = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	const rpcURL = "https://api.devnet.solana.com"
	rpc := solana.RPC{URL: rpcURL}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gotNet, err := rpc.Network(ctx)
	if err != nil || gotNet != devnetID {
		t.Fatalf("Solana Devnet RPC genesis check failed: got=%q err=%v", gotNet, err)
	}
	bh, err := rpc.LatestBlockhash(ctx)
	if err != nil {
		t.Fatalf("Solana Devnet LatestBlockhash failed: %v", err)
	}
	t.Logf("Solana Devnet RPC live OK: network=%s blockhash=%s", gotNet, bh.String())

	var priv ed25519.PrivateKey
	var from solana.PublicKey
	if envKey := strings.TrimSpace(os.Getenv("CONCERT_TESTNET_SOL_KEY")); envKey != "" {
		raw, err := base64.StdEncoding.DecodeString(envKey)
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			t.Fatalf("invalid CONCERT_TESTNET_SOL_KEY")
		}
		priv = ed25519.PrivateKey(raw)
		copy(from[:], priv.Public().(ed25519.PublicKey))
	} else {
		pub, p, _ := ed25519.GenerateKey(nil)
		priv = p
		copy(from[:], pub)
		// Attempt public Devnet airdrop (may be rate-limited on public endpoint).
		airdropReq := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"requestAirdrop","params":[%q,10000000]}`, from.String())
		resp, err := liveHTTPClient().Post(rpcURL, "application/json", strings.NewReader(airdropReq))
		if err != nil {
			t.Skipf("Solana Devnet live RPC OK, skipping funded tx (airdrop error: %v)", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		var ar struct {
			Result string `json:"result"`
			Error  any    `json:"error"`
		}
		_ = json.Unmarshal(body, &ar)
		if ar.Result == "" {
			t.Skipf("Solana Devnet live RPC/genesis/blockhash OK; public Devnet faucet rate-limited (%s). Provide CONCERT_TESTNET_SOL_KEY to execute funded Solana Devnet settlement.", strings.TrimSpace(string(body)))
		}
		t.Logf("Solana Devnet airdrop requested: sig=%s, waiting for balance…", ar.Result)
		funded := false
		solScheme := solana.New(devnetID, rpcURL)
		for i := 0; i < 15; i++ {
			bctx, bcancel := context.WithTimeout(context.Background(), 10*time.Second)
			bal, berr := solScheme.TokenBalance(bctx, from.String(), "SOL")
			bcancel()
			if berr == nil && bal.Sign() > 0 {
				funded = true
				break
			}
			time.Sleep(2 * time.Second)
		}
		if !funded {
			t.Skip("Solana Devnet airdrop did not confirm within 30s")
		}
	}

	destPub, _, _ := ed25519.GenerateKey(nil)
	var dest solana.PublicKey
	copy(dest[:], destPub)

	reqOffer := fastlane.Requirements{
		Scheme:            solana.SchemeName,
		Network:           devnetID,
		Amount:            "1000000", // 0.001 SOL
		Asset:             "SOL",
		PayTo:             dest.String(),
		MaxTimeoutSeconds: 60,
		Extra:             map[string]any{"areFeesSponsored": false},
	}
	fc := fastlane.Config{
		Enabled: true, Origin: "http://127.0.0.1:8080", TestMode: true, Merchant: "Concert Live Devnet Solana",
		TermsURL: "http://127.0.0.1:8080/terms", PrivacyURL: "http://127.0.0.1:8080/privacy", RefundURL: "http://127.0.0.1:8080/refunds",
		PassSeconds: 300,
		Offers:      []fastlane.Offer{{Label: "SOL Devnet", DisplayAmount: "0.001", AssetSymbol: "SOL", AssetDecimals: 9, Requirements: reqOffer}},
	}
	nets := map[string]any{devnetID: map[string]any{"rpc": rpcURL}}
	_, front := startLiveEconcert(t, fc, nets)
	hc := liveHTTPClient()

	code, body := livePostJSON(t, hc, front.URL+"/_concert/session", nil, map[string]any{})
	if code != 200 {
		t.Fatalf("session: %d %s", code, body)
	}
	var sess struct {
		Session string `json:"session"`
	}
	_ = json.Unmarshal(body, &sess)

	bh2, err := rpc.LatestBlockhash(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Build SOL transfer WITH ComputeBudget priority-fee instruction (proving real Phantom/Solflare compatibility!).
	unsigned := solana.BuildNativeTransferWithExtras(from, dest, 1000000, bh2, 200000, 1000, "concert:devnet-live")
	signed := solana.Sign(unsigned, priv)
	proof, _ := json.Marshal(map[string]any{
		"x402Version": 2,
		"accepted":    reqOffer,
		"payload":     map[string]string{"transaction": base64.StdEncoding.EncodeToString(signed)},
	})
	code, body = livePostJSON(t, hc, front.URL+"/_concert/payment", map[string]string{
		fastlane.SessionHeader: sess.Session,
		"PAYMENT-SIGNATURE":    base64.StdEncoding.EncodeToString(proof),
	}, map[string]any{})
	if code != 200 {
		t.Fatalf("live Solana Devnet ComputeBudget x402 payment failed: %d %s", code, body)
	}
	t.Logf("LIVE SOLANA DEVNET (COMPUTEBUDGET + MEMO) x402 PAYMENT SETTLED: %s", body)
}

func TestLiveTestnet_Hedera(t *testing.T) {
	const mirrorURL = "https://testnet.mirrornode.hedera.com"
	mirror := hedera.Mirror{URL: mirrorURL}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tlsNodes, isTLS, err := mirror.TLSNodes(ctx)
	if err != nil || len(tlsNodes) == 0 || !isTLS {
		t.Fatalf("Hedera Testnet TLS :50212 node discovery failed: len=%d tls=%v err=%v", len(tlsNodes), isTLS, err)
	}
	has50212 := false
	for _, ep := range tlsNodes {
		if strings.HasSuffix(ep, ":50212") {
			has50212 = true
			break
		}
	}
	if !has50212 {
		t.Fatalf("expected at least one :50212 TLS consensus node from Hedera Testnet Mirror Node, got: %v", tlsNodes)
	}
	hScheme, err := hedera.NewUnsponsored("hedera:testnet", mirrorURL, 100000000)
	if err != nil {
		t.Fatalf("hedera.NewUnsponsored: %v", err)
	}
	bal, err := hScheme.TokenBalance(ctx, "0.0.2", "0.0.0")
	if err != nil || bal.Sign() <= 0 {
		t.Fatalf("Hedera Testnet Mirror Node balance check on 0.0.2 failed: bal=%v err=%v", bal, err)
	}
	t.Logf("Hedera Testnet Mirror Node live OK: discovered %d TLS :50212 consensus nodes, 0.0.2 balance=%s tinybars", len(tlsNodes), bal.String())

	acct := strings.TrimSpace(os.Getenv("CONCERT_TESTNET_HBAR_ACCOUNT"))
	keyStr := strings.TrimSpace(os.Getenv("CONCERT_TESTNET_HBAR_KEY"))
	if acct == "" || keyStr == "" {
		t.Logf("Hedera Testnet live TLS discovery & balance verified. Set CONCERT_TESTNET_HBAR_ACCOUNT and CONCERT_TESTNET_HBAR_KEY to also execute a funded Hedera Testnet consensus payment.")
		return
	}
	privKey, err := hiero.PrivateKeyFromStringDer(keyStr)
	if err != nil {
		t.Fatalf("invalid CONCERT_TESTNET_HBAR_KEY: %v", err)
	}
	dest := strings.TrimSpace(os.Getenv("CONCERT_TESTNET_HBAR_PAYTO"))
	if dest == "" {
		dest = "0.0.3"
	}
	reqOffer := fastlane.Requirements{
		Scheme:            "exact",
		Network:           "hedera:testnet",
		Amount:            "10000000", // 0.1 HBAR
		Asset:             "0.0.0",
		PayTo:             dest,
		MaxTimeoutSeconds: 60,
		Extra:             map[string]any{"areFeesSponsored": false},
	}
	fc := fastlane.Config{
		Enabled: true, Origin: "http://127.0.0.1:8080", TestMode: true, Merchant: "Concert Live Testnet Hedera",
		TermsURL: "http://127.0.0.1:8080/terms", PrivacyURL: "http://127.0.0.1:8080/privacy", RefundURL: "http://127.0.0.1:8080/refunds",
		PassSeconds: 300,
		Offers:      []fastlane.Offer{{Label: "HBAR Testnet", DisplayAmount: "0.1", AssetSymbol: "HBAR", AssetDecimals: 8, Requirements: reqOffer}},
	}
	nets := map[string]any{"hedera:testnet": map[string]any{"mirror": mirrorURL, "max_fee_tinybars": "100000000"}}
	_, front := startLiveEconcert(t, fc, nets)
	hc := liveHTTPClient()

	code, body := livePostJSON(t, hc, front.URL+"/_concert/session", nil, map[string]any{})
	if code != 200 {
		t.Fatalf("session: %d %s", code, body)
	}
	var sess struct {
		Session string `json:"session"`
	}
	_ = json.Unmarshal(body, &sess)

	txB64, err := hedera.NewPayment(ctx, mirror, acct, privKey, x402.Requirements{
		Scheme: reqOffer.Scheme, Network: reqOffer.Network, Amount: reqOffer.Amount,
		Asset: reqOffer.Asset, PayTo: reqOffer.PayTo, MaxTimeoutSeconds: reqOffer.MaxTimeoutSeconds, Extra: reqOffer.Extra,
	})
	if err != nil {
		t.Fatalf("hedera.NewPayment: %v", err)
	}
	proof, _ := json.Marshal(map[string]any{
		"x402Version": 2,
		"accepted":    reqOffer,
		"payload":     map[string]string{"transaction": txB64},
	})
	code, body = livePostJSON(t, hc, front.URL+"/_concert/payment", map[string]string{
		fastlane.SessionHeader: sess.Session,
		"PAYMENT-SIGNATURE":    base64.StdEncoding.EncodeToString(proof),
	}, map[string]any{})
	if code != 200 {
		t.Fatalf("live Hedera Testnet TLS x402 payment failed: %d %s", code, body)
	}
	t.Logf("LIVE HEDERA TESTNET TLS :50212 ZERO-HOT-KEY x402 PAYMENT SETTLED: %s", body)
}
