package gateway

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/solana"
	"github.com/andreimerlescu/concert/internal/chain/xrpl"
	"github.com/andreimerlescu/concert/internal/fastlane"
	"github.com/andreimerlescu/concert/internal/x402"
)

const (
	maxBody     = 64 << 10
	maxInFlight = 32
)

// Server is the gateway's HTTP API: GET /supported, POST /verify, /settle,
// /nft/verify and /solana/prepare, all behind a bearer token.
type Server struct {
	cfg     fastlane.Config
	chains  map[string]*chain
	journal *Journal
	token   string

	queueMu sync.Mutex
	queues  map[string]*sync.Mutex
	active  atomic.Int32
}

// New assembles a gateway. getenv supplies sponsor secrets.
func New(cfg fastlane.Config, networks map[string]Network, journal *Journal, token string, getenv func(string) string) (*Server, error) {
	return newServer(cfg, networks, journal, token, getenv, false)
}

func newServer(cfg fastlane.Config, networks map[string]Network, journal *Journal, token string, getenv func(string) string, allowHTTP bool) (*Server, error) {
	if !cfg.Enabled {
		return nil, errors.New("enable and complete the fast lane configuration before starting the gateway")
	}
	if len(token) < 32 {
		return nil, errors.New("CONCERT_GATEWAY_TOKEN must be at least 32 characters")
	}
	chains, err := build(cfg, networks, getenv, allowHTTP)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, chains: chains, journal: journal, token: token, queues: map[string]*sync.Mutex{}}, nil
}

type mechanism interface {
	Verify(context.Context, x402.Payload, x402.Requirements) x402.VerifyResponse
	Settle(context.Context, x402.Payload, x402.Requirements) (x402.SettleResponse, error)
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

var errBadRequest = errors.New("verification_failed")

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) != 1 {
		reply(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/supported" {
		reply(w, http.StatusOK, s.supported())
		return
	}
	routes := map[string]func(context.Context, []byte) (any, error){
		"/verify": s.verify, "/settle": s.settle, "/nft/verify": s.nft, "/solana/prepare": s.prepare,
	}
	handle, ok := routes[r.URL.Path]
	if r.Method != http.MethodPost || !ok {
		reply(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	if s.active.Add(1) > maxInFlight {
		s.active.Add(-1)
		reply(w, http.StatusServiceUnavailable, map[string]string{"error": "busy"})
		return
	}
	defer s.active.Add(-1)
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		reply(w, http.StatusBadRequest, map[string]string{"error": "verification_failed"})
		return
	}
	out, err := handle(r.Context(), body)
	if err != nil {
		// Chain errors may carry endpoint URLs or payloads; never echo them.
		reply(w, http.StatusBadRequest, map[string]string{"error": "verification_failed"})
		return
	}
	reply(w, http.StatusOK, out)
}

func (s *Server) supported() any {
	var kinds []map[string]any
	for _, o := range s.cfg.Offers {
		kinds = append(kinds, map[string]any{"x402Version": 2, "scheme": o.Requirements.Scheme, "network": o.Requirements.Network})
	}
	return map[string]any{"kinds": kinds, "extensions": []string{}, "signers": map[string]any{}}
}

type paymentInput struct {
	Version      int               `json:"x402Version"`
	Payload      x402.Payload      `json:"paymentPayload"`
	Requirements x402.Requirements `json:"paymentRequirements"`
}

func same(a, b any) bool {
	x, err1 := x402.CanonicalValue(a)
	y, err2 := x402.CanonicalValue(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

// validate accepts only configured terms that the payer accepted verbatim.
func (s *Server) validate(body []byte) (paymentInput, mechanism, error) {
	var in paymentInput
	if err := json.Unmarshal(body, &in); err != nil {
		return in, nil, errBadRequest
	}
	p, r := in.Payload, in.Requirements
	if in.Version != 2 || p.Version != 2 || len(p.Payload) == 0 || !same(p.Accepted, r) {
		return in, nil, errBadRequest
	}
	configured := false
	for _, o := range s.cfg.Offers {
		configured = configured || same(toX402(o.Requirements), r)
	}
	if !configured {
		return in, nil, errBadRequest
	}
	if p.Resource != nil && p.Resource.URL != strings.TrimRight(s.cfg.Origin, "/")+"/_concert/payment" {
		return in, nil, errBadRequest
	}
	c := s.chains[r.Network]
	if c == nil || c.pay == nil {
		return in, nil, errBadRequest
	}
	return in, c.pay, nil
}

func toX402(r fastlane.Requirements) x402.Requirements {
	return x402.Requirements{Scheme: r.Scheme, Network: r.Network, Amount: r.Amount, Asset: r.Asset, PayTo: r.PayTo, MaxTimeoutSeconds: r.MaxTimeoutSeconds, Extra: r.Extra}
}

func (s *Server) verify(ctx context.Context, body []byte) (any, error) {
	in, m, err := s.validate(body)
	if err != nil {
		return nil, err
	}
	id, err := Fingerprint(in.Requirements, in.Payload.Payload)
	if err != nil {
		return nil, err
	}
	if rec, ok := s.journal.Get(id); ok {
		// Never re-run preflight on a journaled authorization. Concert only
		// verifies authorizations it has not recorded, so a settled one is a
		// replay (for example after a lost Concert journal).
		if !same(rec.Terms, in.Requirements) {
			return nil, errBadRequest
		}
		if rec.State == "settled" {
			return x402.Invalid("payment_already_settled", rec.Payer), nil
		}
		return x402.Valid(rec.Payer), nil
	}
	return m.Verify(ctx, in.Payload, in.Requirements), nil
}

func (s *Server) queue(network string) *sync.Mutex {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	q, ok := s.queues[network]
	if !ok {
		q = &sync.Mutex{}
		s.queues[network] = q
	}
	return q
}

// settle serializes per network (one sponsor account per network; identical
// payloads share a queue), journals the authorization as pending before
// submitting, and never resubmits a journaled one. Settlement outlives the
// HTTP caller; its result is recorded regardless.
func (s *Server) settle(ctx context.Context, body []byte) (any, error) {
	in, m, err := s.validate(body)
	if err != nil {
		return nil, err
	}
	p, r := in.Payload, in.Requirements
	id, err := Fingerprint(r, p.Payload)
	if err != nil {
		return nil, err
	}
	q := s.queue(r.Network)
	q.Lock()
	defer q.Unlock()
	if rec, ok := s.journal.Get(id); ok {
		if !same(rec.Terms, r) {
			return nil, errors.New("payment reused under different terms")
		}
		if rec.State == "settled" && rec.Response != nil {
			return rec.Response, nil
		}
		return x402.SettleResponse{ErrorReason: "reconciliation_required", Network: r.Network, Payer: rec.Payer}, nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(r.MaxTimeoutSeconds)*time.Second+3*time.Minute)
	defer cancel()
	v := m.Verify(ctx, p, r)
	if !v.Valid || v.Payer == "" {
		return x402.SettleResponse{ErrorReason: "verification_failed", Network: r.Network}, nil
	}
	terms, _ := json.Marshal(r)
	payload, _ := json.Marshal(p)
	rec := Record{ID: id, Terms: terms, Payload: payload, Payer: v.Payer, State: "pending", Created: time.Now().UTC()}
	if err := s.journal.Write(rec); err != nil {
		return nil, err
	}
	res, err := m.Settle(ctx, p, r)
	if err != nil {
		log.Printf("gateway: settlement of %s on %s is unknown", id, r.Network)
		res = x402.SettleResponse{ErrorReason: "settlement_unknown", Network: r.Network, Payer: v.Payer}
	}
	if res.Success && (res.Network != r.Network || res.Payer != v.Payer || res.Transaction == "") {
		res = x402.SettleResponse{ErrorReason: "settlement_response_mismatch", Network: r.Network, Payer: v.Payer}
	}
	rec.State = "unknown"
	if res.Success {
		rec.State = "settled"
	}
	rec.Response = &res
	if err := s.journal.Write(rec); err != nil {
		return nil, err
	}
	return res, nil
}

type nftInput struct {
	Network    string `json:"network"`
	Address    string `json:"address"`
	Collection string `json:"collection"`
	Token      string `json:"token_id"`
	Message    string `json:"message"`
	Signature  string `json:"signature"`
	PublicKey  string `json:"public_key"`
}

func (s *Server) nft(ctx context.Context, body []byte) (any, error) {
	var in nftInput
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, errBadRequest
	}
	configured := false
	for _, c := range s.cfg.Collections {
		configured = configured || (c.Network == in.Network && c.Collection == in.Collection)
	}
	c := s.chains[in.Network]
	if !configured || c == nil {
		return nil, errors.New("unknown collection")
	}
	if len(in.Message) > 4096 || !strings.HasPrefix(in.Message, "Concert NFT admission v1\n") ||
		!strings.Contains(in.Message, "\nNetwork: "+in.Network+"\nWallet: "+in.Address+"\nCollection: "+in.Collection+"\nToken: "+in.Token+"\n") {
		return nil, errors.New("challenge binding mismatch")
	}
	sig, err := base64.StdEncoding.DecodeString(in.Signature)
	if err != nil {
		return nil, err
	}
	var found string
	switch c.family {
	case "solana":
		if !solana.VerifyMessage(in.Address, in.Message, sig) {
			return nil, errors.New("invalid signature")
		}
		found, err = c.sol.OwnsNFT(ctx, in.Address, in.Collection, in.Token)
	case "xrpl":
		if !xrpl.ValidAddress(in.Address) {
			return nil, errors.New("invalid address")
		}
		found, err = c.xrp.OwnsNFT(ctx, in.Address, in.Collection, in.Token, in.PublicKey, in.Message, sig)
	case "stellar":
		found, err = c.xlm.OwnsNFT(ctx, in.Address, in.Collection, in.Token, in.Message, sig)
	case "hedera":
		found, err = c.hbar.OwnsNFT(ctx, in.Address, in.Collection, in.Token, in.Message, sig)
	default:
		err = errors.New("unsupported NFT network")
	}
	if err != nil {
		return nil, err
	}
	if found == "" {
		return nil, errors.New("no matching NFT")
	}
	return map[string]any{"valid": true, "owner": in.Address, "network": in.Network, "collection": in.Collection, "token_id": found}, nil
}

func (s *Server) prepare(ctx context.Context, body []byte) (any, error) {
	var in struct {
		Network string `json:"network"`
		Address string `json:"address"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, errBadRequest
	}
	for _, o := range s.cfg.Offers {
		r := o.Requirements
		if r.Network != in.Network || r.Scheme != solana.SchemeName {
			continue
		}
		tx, err := s.chains[in.Network].sol.Prepare(ctx, in.Address, toX402(r))
		if err != nil {
			return nil, err
		}
		return map[string]string{"transaction": base64.StdEncoding.EncodeToString(tx)}, nil
	}
	return nil, errors.New("network not offered")
}
