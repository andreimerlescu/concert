// Command concert-client is the reference automated wallet for Concert's
// fast lane. Payer keys stay in this process; Concert and its gateway never
// see them.
//
//	concert-client               pay for a fast-lane pass (CONCERT_ACCEPT_TERMS=yes)
//	concert-client --nft         prove NFT ownership for a short lease
//	concert-client --wait PATH   wait in line for PATH, then print the response
//
// A signed authorization is saved to the state file before it is sent, and
// the client never signs a second one while the first is unresolved.
//
// --wait needs no wallet keys and never pays. It holds a place in Concert's
// line with the saved session (Concert's -agent-queue), retrying as the
// server's Retry-After says, and reports the fast-lane offer when Concert
// makes one; paying stays the explicit default command above. The state
// file is locked only while the session is renewed, so a payment can be
// made with the same session while a --wait runs, and the waiting place is
// then admitted through the fast lane.
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

var nativeAssets = map[string]string{"xrpl": "XRP", "hedera": "0.0.0", "solana": "SOL"}

// preparePayment signs one authorization for the offer on network, only if
// it pays expectedPayTo in the native currency within the budget. It never
// picks another offer or signs a replacement.
func (c *client) preparePayment(ctx context.Context, session, network string, w *wallet, maxAtomic, expectedPayTo string) (string, error) {
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
		if disc.Accepts[i].Network == network {
			r = &disc.Accepts[i]
			break
		}
	}
	budget, okBudget := new(big.Int).SetString(maxAtomic, 10)
	var amount *big.Int
	okAmount := false
	if r != nil {
		amount, okAmount = new(big.Int).SetString(r.Amount, 10)
	}
	if r == nil || !okBudget || !okAmount || expectedPayTo == "" || r.PayTo != expectedPayTo || amount.Cmp(budget) > 0 || amount.Sign() <= 0 {
		return "", errors.New("network, recipient or spending budget mismatch")
	}
	asset, scheme := nativeAssets[family(network)], "exact"
	if family(network) == "stellar" {
		pass, err := stellar.Passphrase(network)
		if err != nil {
			return "", err
		}
		if asset, err = stellar.NativeAsset(pass); err != nil {
			return "", err
		}
	}
	if family(network) == "solana" {
		scheme = solana.SchemeName
	}
	if r.Asset != asset || r.Scheme != scheme {
		return "", errors.New("only the configured native currency scheme is supported")
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

const usage = "usage: concert-client [--nft | --wait PATH]"

func run(ctx context.Context, args []string, getenv func(string) string) error {
	nft, waitPath := false, ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--nft" && !nft && waitPath == "":
			nft = true
		case args[i] == "--wait" && !nft && waitPath == "" && i+1 < len(args) && strings.HasPrefix(args[i+1], "/"):
			waitPath = args[i+1]
			i++
		default:
			return errors.New(usage)
		}
	}
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
		return waitInLine(ctx, origin, network, file, waitPath, getenv, os.Stdout)
	}
	networks, err := gateway.LoadNetworks(env("CONCERT_NETWORKS_CONFIG", "examples/networks.json"))
	if err != nil {
		return err
	}
	n, ok := networks[network]
	if !ok {
		return errors.New("network configuration is missing")
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
	w, err := walletFromEnvironment(network, n, getenv)
	if err != nil {
		return err
	}
	if err := c.renew(ctx, file, &st); err != nil {
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
// admitted response to out. It is bounded by CONCERT_CLIENT_MAX_WAIT
// (default 1h) and by ctx.
func waitInLine(ctx context.Context, origin, network, file, path string, getenv func(string) string, out io.Writer) error {
	maxWait := time.Hour
	if v := getenv("CONCERT_CLIENT_MAX_WAIT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return errors.New("CONCERT_CLIENT_MAX_WAIT must be a positive duration, for example 30m")
		}
		maxWait = d
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
	return c.wait(ctx, path, st.Session, out)
}

// queued is Concert's answer to a client waiting in line.
type queued struct {
	Queued     bool   `json:"queued"`
	Error      string `json:"error"`
	Position   int64  `json:"position"`
	QueueDepth int64  `json:"queue_depth"`
	StatusURL  string `json:"status_url"`
	RetryAfter int    `json:"retry_after_seconds"`
	FastLane   *struct {
		PaymentURL  string `json:"payment_url"`
		PassSeconds int    `json:"pass_seconds"`
		Offers      []struct {
			Network string `json:"network"`
			Asset   string `json:"asset"`
			Amount  string `json:"amount"`
		} `json:"offers"`
	} `json:"fast_lane"`
}

const (
	minRetry     = time.Second
	maxRetry     = time.Minute
	maxPageBytes = 16 << 20
)

// retryDelay is the server's Retry-After, else the body's
// retry_after_seconds, else 5s, bounded to 1s-1m.
func retryDelay(h http.Header, q queued) time.Duration {
	d := 5 * time.Second
	if n, err := strconv.Atoi(strings.TrimSpace(h.Get("Retry-After"))); err == nil {
		d = time.Duration(n) * time.Second
	} else if q.RetryAfter > 0 {
		d = time.Duration(q.RetryAfter) * time.Second
	}
	return min(max(d, minRetry), maxRetry)
}

// wait requests path with session until Concert stops answering "queued",
// then writes that response's status and body to out. It never pays: a
// fast-lane offer is reported once, and paying stays a separate command.
func (c *client) wait(ctx context.Context, path, session string, out io.Writer) error {
	offered := false
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Concert-Session", session)
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
				fmt.Fprintf(out, " %s %s on %s;", o.Amount, o.Asset, o.Network)
			}
			fmt.Fprintln(out, " this client does not pay; run concert-client with CONCERT_ACCEPT_TERMS=yes to pay with this session.")
		}
		if err := c.pause(ctx, retryDelay(res.Header, q)); err != nil {
			return fmt.Errorf("stopped waiting at position %d: %w", q.Position, err)
		}
	}
}

// renew keeps the session ID, and with it any unresolved payment, while
// refreshing the expiry. An expired session yields a new ID instead.
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
		p, err := c.preparePayment(ctx, st.Session, network, w, getenv("CONCERT_MAX_ATOMIC_AMOUNT"), getenv("CONCERT_EXPECT_PAY_TO"))
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

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
