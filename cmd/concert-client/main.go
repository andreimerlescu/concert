// Command concert-client is the reference automated wallet for Concert's
// fast lane. Payer keys stay in this process; Concert and its gateway never
// see them.
//
//	concert-client               pay for a fast-lane pass (CONCERT_ACCEPT_TERMS=yes)
//	concert-client --nft         prove NFT ownership for a fast-lane lease
//	concert-client --direct      create & poll a direct Destination-Tag/Memo challenge
//	concert-client --wait PATH   wait in line for PATH, then print the response
//
// Supports native coins AND issued tokens/stablecoins across all 4 chains:
// XRPL (XRP + IOUs like RLUSD), Stellar (XLM + CODE:ISSUER + Soroban SACs),
// Hedera (HBAR + HTS fungible tokens), and Solana (SOL + SPL / Token-2022).
//
// A signed authorization is saved to the state file before it is sent, and
// the client never signs a second one while the first is unresolved.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/hedera"
	"github.com/andreimerlescu/concert/internal/chain/solana"
	"github.com/andreimerlescu/concert/internal/chain/stellar"
	"github.com/andreimerlescu/concert/internal/chain/xrpl"
	"github.com/andreimerlescu/concert/internal/gateway"
	"github.com/andreimerlescu/concert/internal/x402"
	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
	"github.com/stellar/go-stellar-sdk/keypair"
)

// wallet signs for one network.
type wallet struct {
	address string
	pay     func(context.Context, x402.Requirements) (json.RawMessage, error)
	sign    func(message string) (signature []byte, publicKey string)
}

func family(network string) string { f, _, _ := strings.Cut(network, ":"); return f }

func payload(key, value string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{key: value})
	return b
}

func isSponsored(extra map[string]any) bool {
	if extra == nil {
		return false
	}
	if v, ok := extra["areFeesSponsored"].(bool); ok {
		return v
	}
	if fp, ok := extra["feePayer"].(string); ok && strings.TrimSpace(fp) != "" {
		return true
	}
	return false
}

func walletFromEnvironment(network string, n gateway.Network, getenv func(string) string) (*wallet, error) {
	switch family(network) {
	case "xrpl":
		key, err := xrpl.KeyFromSeed(getenv("CONCERT_CLIENT_XRP_SEED"))
		if err != nil {
			return nil, err
		}
		l := xrpl.RPC{URL: n.RPC}
		return &wallet{
			address: key.Address,
			pay: func(ctx context.Context, r x402.Requirements) (json.RawMessage, error) {
				blob, err := xrpl.NewPaymentBlob(ctx, l, key, r)
				return payload("signedTxBlob", blob), err
			},
			sign: func(m string) ([]byte, string) {
				return key.Sign([]byte(m)), strings.ToUpper(hex.EncodeToString(key.Public))
			},
		}, nil
	case "stellar":
		kp, err := keypair.ParseFull(getenv("CONCERT_CLIENT_XLM_SECRET"))
		if err != nil {
			return nil, errors.New("invalid CONCERT_CLIENT_XLM_SECRET")
		}
		rpc, horizon := stellar.RPC{URL: n.RPC}, stellar.Horizon{URL: n.Horizon}
		return &wallet{
			address: kp.Address(),
			pay: func(ctx context.Context, r x402.Requirements) (json.RawMessage, error) {
				// Use classic payer-pays-fees payment when unsponsored or classic asset (XLM / CODE:ISSUER).
				if !isSponsored(r.Extra) || r.Asset == "XLM" || strings.Contains(r.Asset, ":") {
					tx, err := stellar.NewClassicPayment(ctx, horizon, network, kp, r)
					return payload("transaction", tx), err
				}
				want, err := stellar.Passphrase(network)
				if err != nil {
					return nil, err
				}
				if got, err := rpc.Passphrase(ctx); err != nil || got != want {
					return nil, errors.New("RPC network mismatch")
				}
				tx, err := stellar.NewPayment(ctx, rpc, horizon, network, kp, r)
				return payload("transaction", tx), err
			},
			sign: func(m string) ([]byte, string) {
				sig, _ := kp.Sign(stellar.SEP53Hash(m))
				return sig, ""
			},
		}, nil
	case "hedera":
		key, err := hiero.PrivateKeyFromStringDer(getenv("CONCERT_CLIENT_HBAR_KEY"))
		if err != nil {
			return nil, errors.New("invalid CONCERT_CLIENT_HBAR_KEY")
		}
		account := getenv("CONCERT_CLIENT_HBAR_ACCOUNT")
		if _, err := hiero.AccountIDFromString(account); err != nil {
			return nil, errors.New("invalid CONCERT_CLIENT_HBAR_ACCOUNT")
		}
		mirror := hedera.Mirror{URL: n.Mirror}
		return &wallet{
			address: account,
			pay: func(ctx context.Context, r x402.Requirements) (json.RawMessage, error) {
				tx, err := hedera.NewPayment(ctx, mirror, account, key, r)
				return payload("transaction", tx), err
			},
			sign: func(m string) ([]byte, string) { return key.Sign([]byte(m)), "" },
		}, nil
	case "solana":
		raw, err := base64.StdEncoding.DecodeString(getenv("CONCERT_CLIENT_SOL_KEY"))
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, errors.New("CONCERT_CLIENT_SOL_KEY must be a base64 64-byte secret key")
		}
		priv := ed25519.PrivateKey(raw)
		var from solana.PublicKey
		copy(from[:], priv.Public().(ed25519.PublicKey))
		rpc := solana.RPC{URL: n.RPC}
		return &wallet{
			address: from.String(),
			pay: func(ctx context.Context, r x402.Requirements) (json.RawMessage, error) {
				if got, err := rpc.Network(ctx); err != nil || got != network {
					return nil, errors.New("RPC network mismatch")
				}
				if r.Asset == "SOL" {
					to, err := solana.ParsePublicKey(r.PayTo)
					if err != nil {
						return nil, err
					}
					lamports, ok := new(big.Int).SetString(r.Amount, 10)
					if !ok || !lamports.IsUint64() || lamports.Sign() <= 0 {
						return nil, errors.New("invalid amount")
					}
					bh, err := rpc.LatestBlockhash(ctx)
					if err != nil {
						return nil, err
					}
					tx := solana.Sign(solana.NewTransfer(from, to, lamports.Uint64(), bh), priv)
					return payload("transaction", base64.StdEncoding.EncodeToString(tx)), nil
				}
				// SPL / Token-2022 exact payment: prepare unsigned tx (ATA + TransferChecked) and sign locally.
				unsignedRaw, err := solana.New(network, n.RPC).PreparePayment(ctx, from.String(), r)
				if err != nil {
					return nil, err
				}
				signed := solana.Sign(unsignedRaw, priv)
				return payload("transaction", base64.StdEncoding.EncodeToString(signed)), nil
			},
			sign: func(m string) ([]byte, string) { return ed25519.Sign(priv, []byte(m)), "" },
		}, nil
	}
	return nil, errors.New("unsupported network")
}

// client talks to one Concert origin.
type client struct {
	origin string
	http   *http.Client
	pause  func(context.Context, time.Duration) error // waits between retries in line
}

func newClient(origin string) *client {
	return &client{origin: origin, pause: pause, http: &http.Client{
		Timeout:       55 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are refused") },
	}}
}

// pause waits d or until ctx is done. Tests replace it.
var pause = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *client) request(ctx context.Context, path, session string, body any, headers map[string]string, out any) (int, error) {
	var rd *bytes.Reader
	method := http.MethodGet
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd, method = bytes.NewReader(b), http.MethodPost
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+"/_concert"+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if session != "" {
		req.Header.Set("Concert-Session", session)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	d := json.NewDecoder(io.LimitReader(res.Body, 1<<20))
	d.UseNumber()
	if err := d.Decode(out); err != nil {
		return res.StatusCode, fmt.Errorf("unexpected response (%d)", res.StatusCode)
	}
	return res.StatusCode, nil
}

type failure struct {
	Error string `json:"error"`
}

func (f failure) err(fallback string) error {
	if f.Error != "" {
		return errors.New(f.Error)
	}
	return errors.New(fallback)
}

func withinBudget(network, asset, amountStr, maxStr string) bool {
	amountStr = strings.TrimSpace(amountStr)
	maxStr = strings.TrimSpace(maxStr)
	if amountStr == "" || maxStr == "" {
		return false
	}
	// XRPL IOUs (e.g. "0.99" RLUSD) use exact decimal comparison.
	if family(network) == "xrpl" && asset != "XRP" {
		cmp, err := xrpl.CompareDecimal(amountStr, maxStr)
		if err != nil || cmp > 0 {
			return false
		}
		pos, err := xrpl.CompareDecimal(amountStr, "0")
		return err == nil && pos > 0
	}
	budget, okB := new(big.Int).SetString(maxStr, 10)
	amount, okA := new(big.Int).SetString(amountStr, 10)
	return okB && okA && amount.Sign() > 0 && amount.Cmp(budget) <= 0
}

func allowedScheme(network, asset, scheme string) bool {
	switch family(network) {
	case "solana":
		if asset == "SOL" {
			return scheme == solana.SchemeName || scheme == "exact"
		}
		return scheme == "exact"
	case "xrpl", "stellar", "hedera":
		return scheme == "exact"
	default:
		return false
	}
}

// preparePayment signs one authorization for the offer on network (and optional
// expectedAsset), only if it pays expectedPayTo within the spending budget.
// It never picks another offer or signs a replacement.
func (c *client) preparePayment(ctx context.Context, session, network string, w *wallet, maxAmount, expectedPayTo, expectedAsset string) (string, error) {
	var disc struct {
		failure
		Resource *x402.Resource      `json:"resource"`
		Accepts  []x402.Requirements `json:"accepts"`
	}
	status, err := c.request(ctx, "/payment", session, map[string]any{}, nil, &disc)
	if err != nil {
		return "", err
	}
	if status != http.StatusPaymentRequired {
		if status < 300 {
			return "", errors.New("session already has access")
		}
		return "", disc.err("payment discovery failed")
	}
	var r *x402.Requirements
	for i := range disc.Accepts {
		cand := &disc.Accepts[i]
		if cand.Network != network {
			continue
		}
		if expectedAsset != "" && cand.Asset != expectedAsset {
			continue
		}
		r = cand
		break
	}
	if r == nil || expectedPayTo == "" || r.PayTo != expectedPayTo || !withinBudget(network, r.Asset, r.Amount, maxAmount) {
		return "", errors.New("network, asset, recipient or spending budget mismatch")
	}
	if !allowedScheme(network, r.Asset, r.Scheme) {
		return "", errors.New("unsupported payment scheme for configured asset")
	}
	proof, err := w.pay(ctx, *r)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(x402.Payload{Version: 2, Resource: disc.Resource, Accepted: *r, Payload: proof})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

type state struct {
	Origin  string `json:"origin"`
	Network string `json:"network"`
	Session string `json:"session,omitempty"`
	Payment string `json:"payment,omitempty"`
}

// saveState atomically replaces file: a crash leaves the previous state or
// the complete new one, never a torn file.
func saveState(file string, s state) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(file)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := file + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, file); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func loadState(file, origin, network string) (state, error) {
	b, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return state{Origin: origin, Network: network}, nil
	}
	if err != nil {
		return state{}, err
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		return state{}, err
	}
	if s.Origin != origin || s.Network != network {
		return state{}, errors.New("state file belongs to another origin/network")
	}
	return s, nil
}

func sessionID(token string) string { id, _, _ := strings.Cut(token, "."); return id }

func checkOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return errors.New("invalid CONCERT_ORIGIN")
	}
	if u.Scheme == "https" {
		return nil
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		if u.Scheme == "http" {
			return nil
		}
	}
	return errors.New("HTTPS is required")
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	log.SetFlags(0)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Getenv)
	stop()
	if err != nil {
		log.Fatal(err)
	}
}

const usage = "usage: concert-client [--nft | --direct | --wait PATH [-bid -max-bid USD [-bid-chain xrpl|stellar|hedera|solana] [-bid-asset ASSET] [-bid-poll-interval 1s]]]"

func run(ctx context.Context, args []string, getenv func(string) string) error {
	opts, err := parseCLIArgs(args)
	if err != nil {
		return err
	}
	nft, direct, waitPath := opts.nft, opts.direct, opts.waitPath
	origin := strings.TrimRight(env("CONCERT_ORIGIN", "http://127.0.0.1:8080"), "/")
	if err := checkOrigin(origin); err != nil {
		return err
	}
	network := getenv("CONCERT_CLIENT_NETWORK")
	if network == "" {
		return errors.New("set CONCERT_CLIENT_NETWORK")
	}
	file, err := filepath.Abs(env("CONCERT_CLIENT_STATE", "client-state.json"))
	if err != nil {
		return err
	}
	if waitPath != "" {
		return waitInLineWithBidding(ctx, origin, network, file, opts, getenv, os.Stdout)
	}
	unlock, err := lockState(file)
	if err != nil {
		return err
	}
	defer unlock()

	st, err := loadState(file, origin, network)
	if err != nil {
		return err
	}
	c := newClient(origin)
	if err := c.renew(ctx, file, &st); err != nil {
		return err
	}
	if direct {
		out, err := c.runDirect(ctx, st.Session, getenv, os.Stdout)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		fmt.Println("Session saved. Send it as the Concert-Session header on protected requests.")
		return nil
	}

	networks, err := gateway.LoadNetworks(env("CONCERT_NETWORKS_CONFIG", "examples/networks.json"))
	if err != nil {
		return err
	}
	n, ok := networks[network]
	if !ok {
		return errors.New("network configuration is missing")
	}
	w, err := walletFromEnvironment(network, n, getenv)
	if err != nil {
		return err
	}
	var out any
	if nft {
		out, err = c.proveNFT(ctx, st.Session, w, getenv("CONCERT_NFT_RULE"), getenv("CONCERT_NFT_TOKEN"))
	} else {
		out, err = c.pay(ctx, file, &st, network, w, getenv)
	}
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	fmt.Println("Session saved. Send it as the Concert-Session header on protected requests.")
	return nil
}

// lockState takes the state file's lock; the returned function releases it.
func lockState(file string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(file+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, errors.New("client state is locked; ensure no client is running before removing a stale .lock file")
	}
	return func() { lock.Close(); os.Remove(file + ".lock") }, nil
}

// waitInLine renews the saved session under the state lock, releases the
// lock, and waits in line for path with it, writing progress and then the
// admitted response to out.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadlines.
//   - origin: Validated Concert origin URL.
//   - network: Configured CAIP-2 network string.
//   - file: Absolute path to the client state file.
//   - path: Target path starting with "/".
//   - getenv: Environment variable lookup function.
//   - out: Output writer for progress and admitted response body.
//
// # Returns
//
// nil on admission, or an error on failure or cancellation.
//
// # Example
//
//	// Internal CLI helper called by run when --wait is used without -bid.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func waitInLine(ctx context.Context, origin, network, file, path string, getenv func(string) string, out io.Writer) error {
	return waitInLineWithBidding(ctx, origin, network, file, cliOptions{waitPath: path}, getenv, out)
}

// waitInLineWithBidding renews the saved session under the state lock,
// optionally initializes the local crypto bid signer when -bid is enabled,
// releases the state lock, and runs the waiting-room + bidding loop.
//
// # Parameters
//
//   - ctx: Controls cancellation and deadlines.
//   - origin: Validated Concert origin URL.
//   - network: Configured CAIP-2 network string.
//   - file: Absolute path to the client state file.
//   - opts: Parsed CLI options including waitPath and optional bidding flags.
//   - getenv: Environment variable lookup function.
//   - out: Output writer for progress and admitted response body.
//
// # Returns
//
// nil on admission, or an error on configuration, bidding, or wait failure.
//
// # Example
//
//	// Internal CLI helper called by run when --wait is supplied.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/main.go:466 (direct call)
//   - cmd/concert-client/main.go:466 (function value)
//   - cmd/concert-client/main.go:563 (direct call)
//   - cmd/concert-client/main.go:563 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func waitInLineWithBidding(ctx context.Context, origin, network, file string, opts cliOptions, getenv func(string) string, out io.Writer) error {
	maxWait := time.Hour
	if v := getenv("CONCERT_CLIENT_MAX_WAIT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return errors.New("CONCERT_CLIENT_MAX_WAIT must be a positive duration, for example 30m")
		}
		maxWait = d
	}
	var bcfg bidConfig
	if opts.bidEnabled {
		var err error
		bcfg, err = buildWaitBidConfig(opts, network, getenv)
		if err != nil {
			return err
		}
	}
	unlock, err := lockState(file)
	if err != nil {
		return err
	}
	st, err := loadState(file, origin, network)
	c := newClient(origin)
	if err == nil {
		err = c.renew(ctx, file, &st)
	}
	unlock()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()
	return c.waitWithBidding(ctx, opts.waitPath, st.Session, bcfg, out)
}

// queued is Concert's answer to a client waiting in line.
type queued struct {
	Queued     bool          `json:"queued"`
	Error      string        `json:"error"`
	Position   int64         `json:"position"`
	QueueDepth int64         `json:"queue_depth"`
	StatusURL  string        `json:"status_url"`
	RetryAfter int           `json:"retry_after_seconds"`
	Auction    *auctionOffer `json:"auction,omitempty"`
	FastLane   *struct {
		PaymentURL  string `json:"payment_url"`
		PassSeconds int    `json:"pass_seconds"`
		Offers      []struct {
			Network       string `json:"network"`
			Asset         string `json:"asset"`
			AssetSymbol   string `json:"asset_symbol"`
			Amount        string `json:"amount"`
			DisplayAmount string `json:"display_amount"`
		} `json:"offers"`
	} `json:"fast_lane"`
}

const (
	minRetry     = time.Second
	maxRetry     = time.Minute
	maxPageBytes = 16 << 20
)

func retryDelay(h http.Header, q queued) time.Duration {
	d := 5 * time.Second
	if n, err := strconv.Atoi(strings.TrimSpace(h.Get("Retry-After"))); err == nil {
		d = time.Duration(n) * time.Second
	} else if q.RetryAfter > 0 {
		d = time.Duration(q.RetryAfter) * time.Second
	}
	return min(max(d, minRetry), maxRetry)
}

func (c *client) wait(ctx context.Context, path, session string, out io.Writer) error {
	return c.waitWithBidding(ctx, path, session, bidConfig{}, out)
}

// waitWithBidding polls path holding session until admitted; when bidCfg.Enabled
// is true and a 429 response includes an auction offer, it evaluates -max-bid,
// submits a signed crypto bid, polls bid status, and either retries immediately
// with the settled pass credentials or seamlessly continues waiting in line.
//
// # Parameters
//
//   - ctx: Controls cancellation and overall wait deadline.
//   - path: Protected Concert path starting with "/".
//   - session: Active Concert-Session token.
//   - bidCfg: Agent bidding configuration (disabled when Enabled is false).
//   - out: Output writer for progress logs and the admitted response body.
//
// # Returns
//
// nil once Concert returns a non-429 2xx/3xx response, or an error on refusal,
// cancellation, transport failure, or fatal bidding error.
//
// # Example
//
//	// Internal client wait loop invoked by waitInLineWithBidding and tests.
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - cmd/concert-client/bidding_test.go:321 (direct call)
//   - cmd/concert-client/bidding_test.go:321 (function value)
//   - cmd/concert-client/bidding_test.go:404 (direct call)
//   - cmd/concert-client/bidding_test.go:404 (function value)
//   - cmd/concert-client/bidding_test.go:477 (direct call)
//   - cmd/concert-client/bidding_test.go:477 (function value)
//   - cmd/concert-client/bidding_test.go:546 (direct call)
//   - cmd/concert-client/bidding_test.go:546 (function value)
//   - cmd/concert-client/bidding_test.go:616 (direct call)
//   - cmd/concert-client/bidding_test.go:616 (function value)
//   - cmd/concert-client/bidding_test.go:633 (direct call)
//   - cmd/concert-client/bidding_test.go:633 (function value)
//   - cmd/concert-client/bidding_test.go:660 (direct call)
//   - cmd/concert-client/bidding_test.go:660 (function value)
//   - cmd/concert-client/main.go:631 (direct call)
//   - cmd/concert-client/main.go:631 (function value)
//   - cmd/concert-client/main.go:673 (direct call)
//   - cmd/concert-client/main.go:673 (function value)
//
// Scope: cmd/concert-client package and tests; darwin/arm64, default tags.
// Interface, callback, and external callers are not exhaustive.
func (c *client) waitWithBidding(ctx context.Context, path, session string, bidCfg bidConfig, out io.Writer) error {
	offered := false
	var creds passCredentials
	attemptedAuctions := make(map[string]struct{})
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		attachPassCredentials(req, session, creds)
		res, err := c.http.Do(req)
		if err != nil {
			return err
		}
		if res.StatusCode != http.StatusTooManyRequests {
			fmt.Fprintf(out, "%d %s\n", res.StatusCode, http.StatusText(res.StatusCode))
			_, err := io.Copy(out, io.LimitReader(res.Body, maxPageBytes))
			res.Body.Close()
			if err == nil && res.StatusCode >= http.StatusBadRequest {
				err = fmt.Errorf("Concert answered %d", res.StatusCode)
			}
			return err
		}
		var q queued
		derr := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&q)
		res.Body.Close()
		if derr != nil || !q.Queued {
			return fmt.Errorf("not waiting in line: %s", or(q.Error, "unexpected 429"))
		}
		fmt.Fprintf(out, "In line: position %d of %d. Watch it at %s\n", q.Position, q.QueueDepth, q.StatusURL)
		if q.FastLane != nil && !offered {
			offered = true
			fmt.Fprintf(out, "Concert offers its fast lane (%d s pass) at %s:", q.FastLane.PassSeconds, q.FastLane.PaymentURL)
			for _, o := range q.FastLane.Offers {
				amt, sym := o.Amount, o.Asset
				if o.DisplayAmount != "" && o.AssetSymbol != "" {
					amt, sym = o.DisplayAmount, o.AssetSymbol
				}
				fmt.Fprintf(out, " %s %s on %s;", amt, sym, o.Network)
			}
			fmt.Fprintln(out, " this client does not pay; run concert-client with CONCERT_ACCEPT_TERMS=yes to pay with this session.")
		}

		if bidCfg.Enabled && q.Auction != nil {
			auctionKey := or(strings.TrimSpace(q.Auction.AuctionID), q.Auction.Mode)
			if _, tried := attemptedAuctions[auctionKey]; !tried {
				if len(attemptedAuctions) >= maxAttemptedAuctions {
					clear(attemptedAuctions)
				}
				attemptedAuctions[auctionKey] = struct{}{}
				outcome, berr := c.attemptAuctionBid(ctx, session, *q.Auction, bidCfg, out)
				if berr != nil {
					return berr
				}
				if outcome.settled {
					creds = outcome.creds
					// Immediately retry the target URL with the settled pass credentials.
					continue
				}
			}
		}

		if err := c.pause(ctx, retryDelay(res.Header, q)); err != nil {
			return fmt.Errorf("stopped waiting at position %d: %w", q.Position, err)
		}
	}
}

func (c *client) renew(ctx context.Context, file string, st *state) error {
	var s struct {
		failure
		Session string `json:"session"`
	}
	status, err := c.request(ctx, "/session", st.Session, map[string]any{}, nil, &s)
	if err != nil {
		return err
	}
	if status != http.StatusOK || s.Session == "" {
		return s.err("session failed")
	}
	if st.Session != "" && st.Payment != "" && sessionID(s.Session) != sessionID(st.Session) {
		return errors.New("the saved session expired before its payment was resolved; keep this state file and contact the merchant; do not authorize a new payment")
	}
	st.Session = s.Session
	return saveState(file, *st)
}

func (c *client) pay(ctx context.Context, file string, st *state, network string, w *wallet, getenv func(string) string) (any, error) {
	if st.Payment == "" {
		if getenv("CONCERT_ACCEPT_TERMS") != "yes" {
			return nil, errors.New("review merchant terms and set CONCERT_ACCEPT_TERMS=yes")
		}
		budget := or(getenv("CONCERT_MAX_ATOMIC_AMOUNT"), getenv("CONCERT_MAX_AMOUNT"))
		p, err := c.preparePayment(ctx, st.Session, network, w, budget, getenv("CONCERT_EXPECT_PAY_TO"), getenv("CONCERT_EXPECT_ASSET"))
		if err != nil {
			return nil, err
		}
		st.Payment = p
		if err := saveState(file, *st); err != nil {
			return nil, err
		}
	}
	var out map[string]any
	status, err := c.request(ctx, "/payment", st.Session, map[string]any{}, map[string]string{"PAYMENT-SIGNATURE": st.Payment}, &out)
	if err != nil {
		return nil, fmt.Errorf("%w; retain this state file and do not authorize a new payment", err)
	}
	if status != http.StatusOK {
		msg, _ := out["error"].(string)
		return nil, fmt.Errorf("%s; retain this state file and do not authorize a new payment", or(msg, "payment failed"))
	}
	return out, nil
}

func (c *client) proveNFT(ctx context.Context, session string, w *wallet, rule, token string) (any, error) {
	var ch struct {
		failure
		Nonce   string `json:"nonce"`
		Message string `json:"message"`
	}
	status, err := c.request(ctx, "/nft/challenge", session, map[string]string{"rule": rule, "address": w.address, "token_id": token}, nil, &ch)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, ch.err("challenge failed")
	}
	sig, pub := w.sign(ch.Message)
	var out map[string]any
	status, err = c.request(ctx, "/nft/verify", session, map[string]string{"nonce": ch.Nonce, "signature": base64.StdEncoding.EncodeToString(sig), "public_key": pub}, nil, &out)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		msg, _ := out["error"].(string)
		return nil, errors.New(or(msg, "NFT proof failed"))
	}
	return out, nil
}

// runDirect requests a direct Destination-Tag/Memo challenge (for either a
// paid pass or a 1-drop NFT/Token-Balance proof), prints instructions to out,
// and polls /_concert/direct/verify until confirmed or ctx expires.
func (c *client) runDirect(ctx context.Context, session string, getenv func(string) string, out io.Writer) (any, error) {
	reqBody := map[string]any{}
	if rule := strings.TrimSpace(getenv("CONCERT_TOKEN_RULE")); rule != "" {
		reqBody["kind"] = "proof"
		reqBody["rule_kind"] = "token"
		reqBody["rule_id"] = rule
		reqBody["address"] = strings.TrimSpace(getenv("CONCERT_WALLET_ADDRESS"))
	} else if rule := strings.TrimSpace(getenv("CONCERT_NFT_RULE")); rule != "" {
		reqBody["kind"] = "proof"
		reqBody["rule_kind"] = "nft"
		reqBody["rule_id"] = rule
		reqBody["address"] = strings.TrimSpace(getenv("CONCERT_WALLET_ADDRESS"))
		reqBody["token_id"] = strings.TrimSpace(getenv("CONCERT_NFT_TOKEN"))
	} else {
		idx, _ := strconv.Atoi(or(getenv("CONCERT_DIRECT_OFFER_INDEX"), "0"))
		reqBody["kind"] = "payment"
		reqBody["offer_index"] = idx
		reqBody["address"] = strings.TrimSpace(getenv("CONCERT_WALLET_ADDRESS"))
	}
	var ch struct {
		failure
		ChallengeID    string `json:"challenge_id"`
		Instructions   string `json:"instructions"`
		WalletURI      string `json:"wallet_uri"`
		DestinationTag uint32 `json:"destination_tag"`
		Memo           string `json:"memo"`
		Expires        string `json:"expires"`
	}
	status, err := c.request(ctx, "/direct/challenge", session, reqBody, nil, &ch)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || ch.ChallengeID == "" {
		return nil, ch.err("direct challenge failed")
	}
	fmt.Fprintf(out, "%s\nWallet URI: %s\n", ch.Instructions, ch.WalletURI)
	if ch.DestinationTag > 0 {
		fmt.Fprintf(out, "Destination Tag: %d\n", ch.DestinationTag)
	}
	fmt.Fprintf(out, "Memo: %s\nPolling for on-ledger confirmation (expires %s)…\n", ch.Memo, ch.Expires)

	for {
		var res map[string]any
		st, err := c.request(ctx, "/direct/verify", session, map[string]string{"challenge_id": ch.ChallengeID}, nil, &res)
		if err != nil {
			return nil, err
		}
		if st == http.StatusOK && res["eligible"] == true {
			return res, nil
		}
		if errMsg, _ := res["error"].(string); errMsg == "challenge_expired_or_unknown" {
			return nil, errors.New(errMsg)
		}
		if err := c.pause(ctx, 3*time.Second); err != nil {
			return nil, err
		}
	}
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
