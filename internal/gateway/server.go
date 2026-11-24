package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/solana"
	"github.com/andreimerlescu/concert/internal/chain/xrpl"
	"github.com/andreimerlescu/concert/internal/fastlane"
	"github.com/andreimerlescu/concert/internal/x402"
)

type sponsorWindow struct {
	windowStart time.Time
	spent       uint64
}

// Server runs the chain operations inside Concert: "/supported", "/verify",
// "/settle", "/reconcile", "/nft/verify", "/solana/prepare", "/gates/check",
// "/direct/verify", and "/sponsor/status".
type Server struct {
	cfgMu     sync.RWMutex
	cfg       fastlane.Config
	networks  map[string]Network
	getenv    func(string) string
	allowHTTP bool
	chains    map[string]*chain
	journal   *Journal

	dedupeMu         sync.RWMutex
	settlementDedupe func(fp string) (bool, error)

	sponsorMu    sync.Mutex
	sponsorSpend map[string]*sponsorWindow

	queueMu  sync.Mutex
	queues   map[string]*sync.Mutex
	settling sync.WaitGroup
}

// New assembles a gateway around an open journal, which Close closes.
// getenv supplies optional sponsor secrets.
func New(cfg fastlane.Config, networks map[string]Network, journal *Journal, getenv func(string) string) (*Server, error) {
	return newServer(cfg, networks, journal, getenv, false)
}

func newServer(cfg fastlane.Config, networks map[string]Network, journal *Journal, getenv func(string) string, allowHTTP bool) (*Server, error) {
	if !cfg.Enabled {
		return nil, errors.New("enable and complete the fast lane configuration before starting the gateway")
	}
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	chains, err := build(cfg, networks, getenv, allowHTTP)
	if err != nil {
		return nil, err
	}
	netCopy := make(map[string]Network, len(networks))
	for k, v := range networks {
		netCopy[k] = v
	}
	return &Server{
		cfg:          cfg,
		networks:     netCopy,
		getenv:       getenv,
		allowHTTP:    allowHTTP,
		chains:       chains,
		journal:      journal,
		sponsorSpend: map[string]*sponsorWindow{},
		queues:       map[string]*sync.Mutex{},
	}, nil
}

// Reload validates and hot-swaps the gateway's active config and chain clients
// without closing settlements.jsonl or dropping in-flight settlements.
func (s *Server) Reload(cfg fastlane.Config, networks map[string]Network) error {
	if s == nil {
		return errors.New("gateway is nil")
	}
	s.cfgMu.RLock()
	if networks == nil {
		networks = s.networks
	}
	getenv := s.getenv
	allowHTTP := s.allowHTTP
	s.cfgMu.RUnlock()

	if !cfg.Enabled {
		s.cfgMu.Lock()
		s.cfg = cfg
		s.cfgMu.Unlock()
		return nil
	}
	chains, err := build(cfg, networks, getenv, allowHTTP)
	if err != nil {
		return err
	}
	netCopy := make(map[string]Network, len(networks))
	for k, v := range networks {
		netCopy[k] = v
	}
	s.cfgMu.Lock()
	s.cfg = cfg
	s.networks = netCopy
	s.chains = chains
	s.cfgMu.Unlock()
	return nil
}

// SetSettlementDedupe registers an optional cross-edge claim function (e.g.
// Redis SETNX) that returns (true, nil) if this edge won the claim or (false, nil)
// if another edge is already settling or settled this fingerprint.
func (s *Server) SetSettlementDedupe(fn func(fp string) (bool, error)) {
	if s == nil {
		return
	}
	s.dedupeMu.Lock()
	s.settlementDedupe = fn
	s.dedupeMu.Unlock()
}

func (s *Server) snapshot() (fastlane.Config, map[string]Network, map[string]*chain) {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg, s.networks, s.chains
}

// Close waits for settlements in flight to record their results (each is
// bounded by its offer's timeout plus three minutes), then closes the journal.
func (s *Server) Close() {
	s.settling.Wait()
	s.journal.Close()
}

type mechanism interface {
	Verify(context.Context, x402.Payload, x402.Requirements) x402.VerifyResponse
	Settle(context.Context, x402.Payload, x402.Requirements) (x402.SettleResponse, error)
}

var errBadRequest = errors.New("verification_failed")

// Handle runs one operation. Errors may carry endpoint URLs or payloads;
// callers must not show them to visitors.
func (s *Server) Handle(ctx context.Context, op string, body []byte) (any, error) {
	switch op {
	case "/supported":
		return s.supported(), nil
	case "/verify":
		return s.verify(ctx, body)
	case "/settle":
		return s.settle(ctx, body)
	case "/reconcile":
		return s.reconcileOnline(ctx, body)
	case "/nft/verify":
		return s.nft(ctx, body)
	case "/solana/prepare":
		return s.prepare(ctx, body)
	case "/gates/check":
		return s.checkGates(ctx, body)
	case "/direct/verify":
		return s.verifyDirect(ctx, body)
	case "/sponsor/status":
		return s.sponsorStatus(ctx), nil
	}
	return nil, errors.New("unknown gateway operation")
}

func (s *Server) supported() any {
	cfg, _, _ := s.snapshot()
	var kinds []map[string]any
	for _, o := range cfg.Offers {
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
	cfg, _, chains := s.snapshot()
	var in paymentInput
	if err := json.Unmarshal(body, &in); err != nil {
		return in, nil, errBadRequest
	}
	p, r := in.Payload, in.Requirements
	if in.Version != 2 || p.Version != 2 || len(p.Payload) == 0 || !same(p.Accepted, r) {
		return in, nil, errBadRequest
	}
	configured := false
	for _, o := range cfg.Offers {
		configured = configured || same(toX402(o.Requirements), r)
	}
	if !configured {
		return in, nil, errBadRequest
	}
	if p.Resource != nil && p.Resource.URL != strings.TrimRight(cfg.Origin, "/")+"/_concert/payment" {
		return in, nil, errBadRequest
	}
	c := chains[r.Network]
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

func (s *Server) checkSponsorSpendCap(netName string, req x402.Requirements) error {
	_, networks, chains := s.snapshot()
	n, ok := networks[netName]
	if !ok {
		return nil
	}
	c := chains[netName]
	if c == nil {
		return nil
	}
	sponsored := false
	var estFee uint64
	switch c.family {
	case "stellar":
		if sp, _ := req.Extra["areFeesSponsored"].(bool); sp && c.xlm != nil && c.xlm.Sponsor != nil {
			sponsored = true
			estFee = uint64(c.xlm.MaxFee)
		}
	case "hedera":
		if fp, _ := req.Extra["feePayer"].(string); fp != "" && c.hbar != nil && c.hbar.FeePayer != "" {
			sponsored = true
			estFee = c.hbar.MaxFee
		}
	}
	if !sponsored {
		return nil
	}
	capPerMin, err := number(n.MaxSponsorPerMin)
	if err != nil || capPerMin == 0 {
		// Default protective spend cap: 20× per-tx max fee per minute.
		capPerMin = estFee * 20
	}
	if capPerMin == 0 {
		return nil
	}
	s.sponsorMu.Lock()
	defer s.sponsorMu.Unlock()
	now := time.Now()
	w, ok := s.sponsorSpend[netName]
	if !ok || now.Sub(w.windowStart) >= time.Minute {
		w = &sponsorWindow{windowStart: now}
		s.sponsorSpend[netName] = w
	}
	if w.spent+estFee > capPerMin {
		return errors.New("sponsor per-minute fee cap exceeded")
	}
	w.spent += estFee
	return nil
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
	s.settling.Add(1)
	defer s.settling.Done()
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
	s.dedupeMu.RLock()
	dedupeFn := s.settlementDedupe
	s.dedupeMu.RUnlock()
	if dedupeFn != nil {
		if won, derr := dedupeFn(id); derr == nil && !won {
			return x402.SettleResponse{ErrorReason: "duplicate_settlement_other_edge", Network: r.Network}, nil
		}
	}
	if err := s.checkSponsorSpendCap(r.Network, r); err != nil {
		return x402.SettleResponse{ErrorReason: "sponsor_rate_limited", Network: r.Network}, nil
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

type reconcileInput struct {
	ID          string `json:"id"`
	StellarHash string `json:"stellar_hash,omitempty"`
}

func (s *Server) reconcileOnline(ctx context.Context, body []byte) (any, error) {
	_, networks, _ := s.snapshot()
	var in reconcileInput
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, errors.New("invalid reconcile request")
	}
	in.ID = strings.ToLower(strings.TrimSpace(in.ID))
	in.StellarHash = strings.TrimSpace(in.StellarHash)
	if !fingerprintRE.MatchString(in.ID) {
		return nil, errors.New("invalid payment fingerprint: expected 64 lowercase hex characters")
	}
	rec, ok := s.journal.Get(in.ID)
	if !ok {
		return nil, errors.New("receipt not found")
	}
	if rec.State == "settled" && rec.Response != nil {
		return *rec.Response, nil
	}
	var r x402.Requirements
	if err := json.Unmarshal(rec.Terms, &r); err != nil {
		return nil, err
	}
	s.settling.Add(1)
	defer s.settling.Done()
	q := s.queue(r.Network)
	q.Lock()
	defer q.Unlock()
	return reconcile(ctx, s.journal, networks, in.ID, in.StellarHash, s.allowHTTP)
}

type nftInput struct {
	Network    string `json:"network"`
	Address    string `json:"address"`
	Collection string `json:"collection"`
	Issuer     string `json:"issuer,omitempty"`
	Token      string `json:"token_id"`
	Message    string `json:"message"`
	Signature  string `json:"signature"`
	PublicKey  string `json:"public_key"`
}

func (s *Server) nft(ctx context.Context, body []byte) (any, error) {
	cfg, networks, chains := s.snapshot()
	var in nftInput
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, errBadRequest
	}
	configured := false
	for _, c := range cfg.Collections {
		configured = configured || (c.Network == in.Network && c.Collection == in.Collection)
	}
	c := chains[in.Network]
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
		found, err = c.sol.FindOwnedNFT(ctx, in.Address, in.Collection, in.Token, networks[in.Network].DASRPC)
	case "xrpl":
		if !xrpl.ValidAddress(in.Address) {
			return nil, errors.New("invalid address")
		}
		found, err = c.xrp.OwnsNFT(ctx, in.Address, in.Collection, in.Token, in.PublicKey, in.Message, sig)
	case "stellar":
		found, err = c.xlm.OwnsNFT(ctx, in.Address, in.Collection, in.Token, in.Message, sig)
	case "hedera":
		found, err = c.hbar.OwnsNFT(ctx, in.Address, in.Collection, in.Token, in.Message, sig)
		if err == nil && in.Issuer != "" {
			found, err = c.hbar.CheckNFTOwnership(ctx, in.Address, in.Collection, in.Token, in.Issuer)
		}
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
	cfg, _, chains := s.snapshot()
	var in struct {
		Network string `json:"network"`
		Address string `json:"address"`
		Asset   string `json:"asset"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, errBadRequest
	}
	for _, o := range cfg.Offers {
		r := o.Requirements
		if r.Network != in.Network || family(r.Network) != "solana" {
			continue
		}
		if in.Asset != "" && r.Asset != in.Asset {
			continue
		}
		c := chains[in.Network]
		if c == nil || c.sol == nil {
			continue
		}
		tx, err := c.sol.Prepare(ctx, in.Address, toX402(r))
		if err != nil {
			return nil, err
		}
		return map[string]string{"transaction": base64.StdEncoding.EncodeToString(tx)}, nil
	}
	return nil, errors.New("network not offered")
}

// checkGates evaluates NFT collection and/or minimum token/trustline balance
// rules for an address using read-only ledger state (used for direct proof
// pre-checks AND paid-pass purchase prerequisites).
func (s *Server) checkGates(ctx context.Context, body []byte) (any, error) {
	_, networks, chains := s.snapshot()
	var in struct {
		Address string `json:"address"`
		Mode    string `json:"mode"` // "any" | "all"
		Gates   []struct {
			Kind       string `json:"kind"` // "nft" | "token"
			ID         string `json:"id"`
			Network    string `json:"network"`
			Collection string `json:"collection"`
			Issuer     string `json:"issuer"`
			TokenID    string `json:"token_id"`
			Asset      string `json:"asset"`
			MinAmount  string `json:"min_amount"`
		} `json:"gates"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Address == "" || len(in.Gates) == 0 {
		return nil, errBadRequest
	}
	requireAll := in.Mode != "any"
	matched := ""
	passedCount := 0
	for _, g := range in.Gates {
		c := chains[g.Network]
		if c == nil {
			if requireAll {
				return map[string]any{"passed": false, "detail": "network_unavailable"}, nil
			}
			continue
		}
		ok := false
		var matchID string
		switch g.Kind {
		case "nft":
			var err error
			switch c.family {
			case "xrpl":
				matchID, err = c.xrp.CheckNFTOwnership(ctx, in.Address, g.Collection, g.TokenID)
			case "stellar":
				matchID, err = c.xlm.CheckNFTOwnership(ctx, in.Address, g.Collection)
			case "hedera":
				matchID, err = c.hbar.CheckNFTOwnership(ctx, in.Address, g.Collection, g.TokenID, g.Issuer)
			case "solana":
				matchID, err = c.sol.FindOwnedNFT(ctx, in.Address, g.Collection, g.TokenID, networks[g.Network].DASRPC)
			}
			ok = err == nil && matchID != ""
		case "token":
			var err error
			switch c.family {
			case "xrpl":
				ok, matchID, err = c.xrp.MeetsMinBalance(ctx, in.Address, g.Asset, g.MinAmount)
			case "stellar":
				ok, matchID, err = c.xlm.MeetsMinBalance(ctx, in.Address, g.Asset, g.MinAmount)
			case "hedera":
				ok, matchID, err = c.hbar.MeetsMinBalance(ctx, in.Address, g.Asset, g.MinAmount)
			case "solana":
				ok, matchID, err = c.sol.MeetsMinBalance(ctx, in.Address, g.Asset, g.MinAmount)
			}
			if err != nil {
				ok = false
			}
		}
		if ok {
			passedCount++
			if matched == "" {
				matched = matchID
			}
			if !requireAll {
				return map[string]any{"passed": true, "matched": matched}, nil
			}
		} else if requireAll {
			return map[string]any{"passed": false, "detail": "gate_" + g.ID + "_not_met"}, nil
		}
	}
	return map[string]any{"passed": passedCount > 0 && (!requireAll || passedCount == len(in.Gates)), "matched": matched}, nil
}

// verifyDirect checks validated on-chain state for a direct payment or 1-drop
// ownership proof matching Destination Tag / Memo.
func (s *Server) verifyDirect(ctx context.Context, body []byte) (any, error) {
	_, _, chains := s.snapshot()
	var in struct {
		Network        string `json:"network"`
		From           string `json:"from"`
		To             string `json:"to"`
		Asset          string `json:"asset"`
		MinAmount      string `json:"min_amount"`
		DestinationTag uint32 `json:"destination_tag"`
		RequireTag     bool   `json:"require_tag"`
		Memo           string `json:"memo"`
		SinceUnix      int64  `json:"since_unix"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Network == "" || in.To == "" || in.MinAmount == "" {
		return nil, errBadRequest
	}
	c := chains[in.Network]
	if c == nil {
		return nil, errors.New("unknown network")
	}
	var since time.Time
	if in.SinceUnix > 0 {
		since = time.Unix(in.SinceUnix, 0).UTC()
	}
	var txHash, payer string
	var err error
	switch c.family {
	case "xrpl":
		txHash, payer, err = c.xrp.FindDirectPayment(ctx, in.From, in.To, in.Asset, in.MinAmount, in.DestinationTag, in.RequireTag, in.Memo, 0)
	case "stellar":
		txHash, payer, err = c.xlm.FindDirectPayment(ctx, in.From, in.To, in.Asset, in.MinAmount, in.Memo, since)
	case "hedera":
		txHash, payer, err = c.hbar.FindDirectPayment(ctx, in.From, in.To, in.Asset, in.MinAmount, in.Memo, since)
	case "solana":
		txHash, payer, err = c.sol.FindDirectPayment(ctx, in.From, in.To, in.Asset, in.MinAmount, in.Memo, since)
	default:
		return nil, errors.New("unsupported network")
	}
	if err != nil {
		return map[string]any{"found": false}, nil
	}
	return map[string]any{"found": true, "transaction": txHash, "payer": payer}, nil
}

// sponsorStatus checks balances for any configured Stellar/Hedera fee sponsors.
func (s *Server) sponsorStatus(ctx context.Context) map[string]any {
	_, networks, chains := s.snapshot()
	var list []map[string]any
	for netName, c := range chains {
		n := networks[netName]
		minBal, _ := number(n.MinSponsorBalance)
		switch c.family {
		case "stellar":
			if c.xlm != nil && c.xlm.Sponsor != nil {
				if minBal == 0 {
					minBal = 20_000_000 // 2 XLM default low-balance alert threshold
				}
				bal, err := c.xlm.SponsorBalance(ctx)
				entry := map[string]any{"network": netName, "account": c.xlm.Sponsor.Address(), "unit": "stroops", "min_balance": minBal}
				if err != nil {
					entry["error"] = "unavailable"
				} else {
					entry["balance"] = bal
					entry["low"] = uint64(bal) < minBal
				}
				list = append(list, entry)
			}
		case "hedera":
			if c.hbar != nil && c.hbar.FeePayer != "" {
				if minBal == 0 {
					minBal = 500_000_000 // 5 HBAR default low-balance alert threshold
				}
				bal, err := c.hbar.SponsorBalance(ctx)
				entry := map[string]any{"network": netName, "account": c.hbar.FeePayer, "unit": "tinybars", "min_balance": minBal}
				if err != nil {
					entry["error"] = "unavailable"
				} else {
					entry["balance"] = bal
					entry["low"] = uint64(bal) < minBal
				}
				list = append(list, entry)
			}
		}
	}
	return map[string]any{"sponsors": list}
}
