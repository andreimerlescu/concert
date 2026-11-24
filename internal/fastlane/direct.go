package fastlane

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type directChallenge struct {
	ID          string
	Session     string
	Kind        string // "proof" or "payment"
	Network     string
	Address     string // expected sender wallet
	PayTo       string // merchant receiving wallet
	Asset       string
	AssetSymbol string
	Amount      string // atomic units (or XRPL decimal for IOU)
	Display     string // human display price
	DestTag     uint32 // XRPL destination tag (when chain == "xrpl")
	Memo        string // unique per-challenge memo ("concert:<16-hex>")
	RuleID      string // collection or token_gate ID when Kind == "proof"
	RuleKind    string // "nft" or "token"
	OfferIndex  int
	Created     time.Time
	Expires     time.Time
}

func randomDestTag() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	// Keep tag in [100000, 4294967295] so it never looks like 0 or common exchange tags.
	v := binary.BigEndian.Uint32(b[:])
	if v < 100000 {
		v += 100000
	}
	return v, nil
}

func randomMemo() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "concert:" + hex.EncodeToString(b[:]), nil
}

func buildWalletURI(network, payTo, asset, amount, display string, destTag uint32, memo string) string {
	switch chain(network) {
	case "xrpl":
		q := url.Values{}
		if destTag > 0 {
			q.Set("dt", strconv.FormatUint(uint64(destTag), 10))
		}
		if display != "" {
			q.Set("amount", display)
		} else {
			q.Set("amount", amount)
		}
		if memo != "" {
			q.Set("memo", memo)
		}
		return "xrpl:" + payTo + "?" + q.Encode()
	case "stellar":
		q := url.Values{}
		q.Set("destination", payTo)
		if display != "" {
			q.Set("amount", display)
		}
		if asset != "XLM" && !strings.HasPrefix(asset, "C") {
			if code, iss, ok := strings.Cut(asset, ":"); ok {
				q.Set("asset_code", code)
				q.Set("asset_issuer", iss)
			}
		}
		if memo != "" {
			q.Set("memo", memo)
			q.Set("memo_type", "MEMO_TEXT")
		}
		return "web+stellar:pay?" + q.Encode()
	case "solana":
		q := url.Values{}
		if display != "" {
			q.Set("amount", display)
		}
		if asset != "SOL" {
			q.Set("spl-token", asset)
		}
		if memo != "" {
			q.Set("memo", memo)
		}
		return "solana:" + payTo + "?" + q.Encode()
	case "hedera":
		q := url.Values{}
		q.Set("amount", amount)
		if asset != "0.0.0" {
			q.Set("token", asset)
		}
		if memo != "" {
			q.Set("memo", memo)
		}
		return "hedera:" + payTo + "?" + q.Encode()
	}
	return payTo
}

func proofDustForNetwork(network string) (asset, symbol, amount, display string) {
	switch chain(network) {
	case "xrpl":
		return "XRP", "XRP", "1", "0.000001"
	case "stellar":
		return "XLM", "XLM", "1", "0.0000001"
	case "hedera":
		return "0.0.0", "HBAR", "1", "0.00000001"
	case "solana":
		return "SOL", "SOL", "1", "0.000000001"
	}
	return "", "", "1", "1"
}

func (s *Service) resolveVerifyAddress(cfg Config, network string) string {
	if cfg.VerifyAddresses != nil {
		if a := strings.TrimSpace(cfg.VerifyAddresses[network]); a != "" {
			return a
		}
		if a := strings.TrimSpace(cfg.VerifyAddresses[chain(network)]); a != "" {
			return a
		}
	}
	for _, o := range cfg.Offers {
		if o.Requirements.Network == network && o.Requirements.PayTo != "" {
			return o.Requirements.PayTo
		}
	}
	return ""
}

// checkGatesForWallet calls the gateway's /gates/check endpoint to verify NFT
// collection ownership and/or minimum token/trustline balances for address.
func (s *Service) checkGatesForWallet(ctx context.Context, cfg Config, address string, collectionIDs, tokenGateIDs []string, mode string, optionalTokenID string) (bool, string, error) {
	if len(collectionIDs) == 0 && len(tokenGateIDs) == 0 {
		return true, "", nil
	}
	if mode == "" {
		mode = "all"
	}
	type gateItem struct {
		Kind       string `json:"kind"` // "nft" or "token"
		ID         string `json:"id"`
		Network    string `json:"network"`
		Collection string `json:"collection,omitempty"`
		Issuer     string `json:"issuer,omitempty"`
		TokenID    string `json:"token_id,omitempty"`
		Asset      string `json:"asset,omitempty"`
		MinAmount  string `json:"min_amount,omitempty"`
	}
	var items []gateItem
	for _, cid := range collectionIDs {
		for _, c := range cfg.Collections {
			if c.ID == cid {
				items = append(items, gateItem{
					Kind:       "nft",
					ID:         c.ID,
					Network:    c.Network,
					Collection: c.Collection,
					Issuer:     c.Issuer,
					TokenID:    optionalTokenID,
				})
				break
			}
		}
	}
	for _, tid := range tokenGateIDs {
		for _, tg := range cfg.TokenGates {
			if tg.ID == tid {
				items = append(items, gateItem{
					Kind:      "token",
					ID:        tg.ID,
					Network:   tg.Network,
					Asset:     tg.Asset,
					MinAmount: tg.MinAmount,
				})
				break
			}
		}
	}
	if len(items) == 0 {
		return false, "no_matching_gate_rules", nil
	}
	var out struct {
		Passed  bool   `json:"passed"`
		Matched string `json:"matched"`
		Detail  string `json:"detail"`
	}
	err := s.gatewayCall(ctx, callTimeout, "/gates/check", map[string]any{
		"address": address,
		"mode":    mode,
		"gates":   items,
	}, &out)
	if err != nil {
		return false, "gate_check_unavailable", err
	}
	return out.Passed, out.Matched, nil
}

// makeDirectChallenge handles POST /_concert/direct/challenge.
// Supports:
//   - kind="proof": user enters wallet + NFT/token rule -> Concert pre-checks on-chain
//     holdings first -> returns unique Destination Tag + Memo + 1-drop QR/URI.
//   - kind="payment": user selects an Offer (and optional wallet address for gated offers) ->
//     Concert pre-checks any attached NFT/token purchase gates -> returns exact amount +
//     unique Destination Tag + Memo + QR/URI so ANY wallet can pay directly.
func (s *Service) makeDirectChallenge(w http.ResponseWriter, r *http.Request, id string) {
	cfg := s.currentConfig()
	if !cfg.IsDirectPayEnabled() {
		failure(w, 404, "direct_wallet_flow_disabled")
		return
	}
	var in struct {
		Kind       string `json:"kind"` // "proof" or "payment"
		Address    string `json:"address"`
		RuleID     string `json:"rule_id"`
		RuleKind   string `json:"rule_kind"` // "nft" or "token"
		TokenID    string `json:"token_id"`
		OfferIndex *int   `json:"offer_index"`
	}
	if decode(r, &in) != nil {
		failure(w, 400, "invalid_direct_challenge_request")
		return
	}
	in.Address = strings.TrimSpace(in.Address)
	in.Kind = strings.ToLower(strings.TrimSpace(in.Kind))
	if in.Kind != "proof" && in.Kind != "payment" {
		failure(w, 400, "kind_must_be_proof_or_payment")
		return
	}
	var ch directChallenge
	ch.Session = id
	ch.Kind = in.Kind
	ch.Address = in.Address
	ch.Created = s.now().UTC()
	ttlSecs := cfg.DirectChallengeSeconds
	if ttlSecs <= 0 {
		ttlSecs = 600
	}
	ch.Expires = ch.Created.Add(time.Duration(ttlSecs) * time.Second)

	if in.Kind == "proof" {
		if in.Address == "" || len(in.Address) > 100 {
			failure(w, 400, "wallet_address_required")
			return
		}
		var colIDs, tokIDs []string
		if in.RuleKind == "token" {
			found := false
			for _, tg := range cfg.TokenGates {
				if tg.ID == in.RuleID && tg.AllowsEntry() {
					ch.Network = tg.Network
					ch.RuleID = tg.ID
					ch.RuleKind = "token"
					tokIDs = []string{tg.ID}
					found = true
					break
				}
			}
			if !found {
				failure(w, 400, "unknown_token_gate_rule")
				return
			}
		} else {
			found := false
			for _, c := range cfg.Collections {
				if c.ID == in.RuleID && c.AllowsEntry() {
					ch.Network = c.Network
					ch.RuleID = c.ID
					ch.RuleKind = "nft"
					colIDs = []string{c.ID}
					found = true
					break
				}
			}
			if !found {
				failure(w, 400, "unknown_collection_rule")
				return
			}
		}
		if !validAddressForNetwork(ch.Network, in.Address) {
			failure(w, 400, "invalid_wallet_address")
			return
		}
		payTo := s.resolveVerifyAddress(cfg, ch.Network)
		if payTo == "" {
			failure(w, 400, "no_verification_address_configured_for_network")
			return
		}
		// Pre-check on-chain ownership BEFORE asking the user to send even 1 drop!
		ok, _, err := s.checkGatesForWallet(r.Context(), cfg, in.Address, colIDs, tokIDs, "all", strings.TrimSpace(in.TokenID))
		if err != nil {
			failure(w, 503, "onchain_holding_check_unavailable")
			return
		}
		if !ok {
			failure(w, 403, "wallet_does_not_hold_required_asset")
			return
		}
		ch.PayTo = payTo
		ch.Asset, ch.AssetSymbol, ch.Amount, ch.Display = proofDustForNetwork(ch.Network)
	} else {
		// Direct paid pass challenge.
		if in.OfferIndex == nil || *in.OfferIndex < 0 || *in.OfferIndex >= len(cfg.Offers) {
			failure(w, 400, "invalid_offer_index")
			return
		}
		offer := cfg.Offers[*in.OfferIndex]
		req := offer.Requirements
		ch.OfferIndex = *in.OfferIndex
		ch.Network = req.Network
		ch.PayTo = req.PayTo
		ch.Asset = req.Asset
		ch.AssetSymbol = offer.EffectiveSymbol()
		ch.Amount = req.Amount
		ch.Display = offer.EffectiveDisplayAmount()
		if in.Address != "" && !validAddressForNetwork(ch.Network, in.Address) {
			failure(w, 400, "invalid_wallet_address")
			return
		}
		// If the offer requires holding an NFT or minimum token balance, pre-check now!
		if len(offer.RequireCollections) > 0 || len(offer.RequireTokenGates) > 0 {
			if in.Address == "" {
				failure(w, 400, "wallet_address_required_for_gated_offer")
				return
			}
			ok, _, err := s.checkGatesForWallet(r.Context(), cfg, in.Address, offer.RequireCollections, offer.RequireTokenGates, offer.GateMode, "")
			if err != nil {
				failure(w, 503, "onchain_holding_check_unavailable")
				return
			}
			if !ok {
				failure(w, 403, "wallet_does_not_meet_purchase_requirements")
				return
			}
		}
	}

	cid, err := randomID()
	if err != nil {
		failure(w, 503, "entropy_unavailable")
		return
	}
	memo, err := randomMemo()
	if err != nil {
		failure(w, 503, "entropy_unavailable")
		return
	}
	var destTag uint32
	if chain(ch.Network) == "xrpl" {
		destTag, err = randomDestTag()
		if err != nil {
			failure(w, 503, "entropy_unavailable")
			return
		}
	}
	ch.ID = cid
	ch.Memo = memo
	ch.DestTag = destTag

	s.mu.Lock()
	if s.directChallenges == nil {
		s.directChallenges = map[string]directChallenge{}
	}
	now := s.now()
	for k, v := range s.directChallenges {
		if !now.Before(v.Expires) || v.Session == id {
			delete(s.directChallenges, k)
		}
	}
	if len(s.directChallenges) >= 10000 {
		s.mu.Unlock()
		failure(w, 503, "challenge_capacity")
		return
	}
	// Guarantee DestinationTag uniqueness across active XRPL challenges.
	if destTag > 0 {
		for tries := 0; tries < 8; tries++ {
			dup := false
			for _, existing := range s.directChallenges {
				if existing.Network == ch.Network && existing.DestTag == ch.DestTag {
					dup = true
					break
				}
			}
			if !dup {
				break
			}
			if next, derr := randomDestTag(); derr == nil {
				ch.DestTag = next
			}
		}
	}
	s.directChallenges[ch.ID] = ch
	s.mu.Unlock()

	resp := map[string]any{
		"challenge_id":   ch.ID,
		"kind":           ch.Kind,
		"network":        ch.Network,
		"pay_to":         ch.PayTo,
		"from":           ch.Address,
		"asset":          ch.Asset,
		"asset_symbol":   ch.AssetSymbol,
		"amount":         ch.Amount,
		"display_amount": ch.Display,
		"memo":           ch.Memo,
		"expires":        ch.Expires,
		"wallet_uri":     buildWalletURI(ch.Network, ch.PayTo, ch.Asset, ch.Amount, ch.Display, ch.DestTag, ch.Memo),
		"instructions":   directInstructions(ch),
	}
	if ch.DestTag > 0 {
		resp["destination_tag"] = ch.DestTag
	}
	reply(w, 200, resp)
}

func directInstructions(ch directChallenge) string {
	if chain(ch.Network) == "xrpl" {
		return fmt.Sprintf("Send exactly %s %s to %s with Destination Tag %d and Memo %s.", ch.Display, ch.AssetSymbol, ch.PayTo, ch.DestTag, ch.Memo)
	}
	return fmt.Sprintf("Send exactly %s %s to %s with Memo %s.", ch.Display, ch.AssetSymbol, ch.PayTo, ch.Memo)
}

// verifyDirectChallenge handles POST /_concert/direct/verify.
func (s *Service) verifyDirectChallenge(w http.ResponseWriter, r *http.Request, id string) {
	cfg := s.currentConfig()
	var in struct {
		ChallengeID string `json:"challenge_id"`
	}
	if decode(r, &in) != nil || strings.TrimSpace(in.ChallengeID) == "" {
		failure(w, 400, "challenge_id_required")
		return
	}
	s.mu.Lock()
	ch, ok := s.directChallenges[in.ChallengeID]
	s.mu.Unlock()
	if !ok || ch.Session != id || !s.now().Before(ch.Expires) {
		failure(w, 401, "challenge_expired_or_unknown")
		return
	}
	var out struct {
		Found       bool   `json:"found"`
		Transaction string `json:"transaction"`
		Payer       string `json:"payer"`
	}
	err := s.gatewayCall(r.Context(), callTimeout, "/direct/verify", map[string]any{
		"network":         ch.Network,
		"from":            ch.Address,
		"to":              ch.PayTo,
		"asset":           ch.Asset,
		"min_amount":      ch.Amount,
		"destination_tag": ch.DestTag,
		"require_tag":     chain(ch.Network) == "xrpl",
		"memo":            ch.Memo,
		"since_unix":      ch.Created.Unix(),
	}, &out)
	if err != nil {
		failure(w, 503, "ledger_lookup_unavailable")
		return
	}
	if !out.Found || out.Transaction == "" || out.Payer == "" {
		reply(w, 200, map[string]any{"eligible": false, "waiting": true, "expires": ch.Expires})
		return
	}

	// If this was a gated payment and payer was unspecified at challenge time, verify gates against actual payer now.
	if ch.Kind == "payment" && ch.OfferIndex >= 0 && ch.OfferIndex < len(cfg.Offers) {
		offer := cfg.Offers[ch.OfferIndex]
		if len(offer.RequireCollections) > 0 || len(offer.RequireTokenGates) > 0 {
			gateOK, _, gerr := s.checkGatesForWallet(r.Context(), cfg, out.Payer, offer.RequireCollections, offer.RequireTokenGates, offer.GateMode, "")
			if gerr != nil || !gateOK {
				failure(w, 403, "wallet_does_not_meet_purchase_requirements")
				return
			}
		}
	}

	action := "direct_payment"
	if ch.Kind == "proof" {
		action = ch.RuleKind
	}
	policyID, err := s.screenPolicy(r.Context(), r, cfg, ch.Network, out.Payer, action, Requirements{
		Network: ch.Network,
		Asset:   ch.Asset,
		Amount:  ch.Amount,
		PayTo:   ch.PayTo,
	})
	if err != nil {
		failure(w, 403, "policy_not_approved")
		return
	}

	now := s.now().UTC()
	fp := digest([]byte("direct/" + ch.Network + "/" + out.Transaction))
	if ch.Kind == "payment" {
		idleExp, hardExp := s.grantWindow(cfg, passKindPayment, now)
		settled := Settlement{Success: true, Transaction: out.Transaction, Network: ch.Network, Payer: out.Payer}
		rec := Receipt{
			Session:     id,
			Fingerprint: fp,
			State:       "settled",
			Kind:        "payment",
			Network:     ch.Network,
			Payer:       out.Payer,
			Requirements: Requirements{
				Scheme:  "direct",
				Network: ch.Network,
				Asset:   ch.Asset,
				Amount:  ch.Amount,
				PayTo:   ch.PayTo,
			},
			Transaction: out.Transaction,
			PolicyID:    policyID,
			Started:     ch.Created,
			Settled:     now,
			Expires:     idleExp,
			Response:    &settled,
		}
		if err := s.ledger.write(rec); err != nil {
			failure(w, 409, "transaction_already_redeemed")
			return
		}
		s.checkCapacityWarn()
		s.mu.Lock()
		delete(s.directChallenges, ch.ID)
		s.mu.Unlock()
		s.setPassCookie(w, cfg, id, passKindPayment, now, idleExp, hardExp, "")
		reply(w, 200, map[string]any{"eligible": true, "kind": "payment", "expires": idleExp, "hard_expires": hardExp, "transaction": out.Transaction, "payer": out.Payer})
		return
	}

	// Proof (NFT or Token-Balance): still record tx hash in ledger so the 1-drop proof tx can never be replayed by another session!
	passKind := passKindNFT
	if ch.RuleKind == "token" {
		passKind = passKindToken
	}
	idleExp, hardExp := s.grantWindow(cfg, passKind, now)
	settled := Settlement{Success: true, Transaction: out.Transaction, Network: ch.Network, Payer: out.Payer}
	rec := Receipt{
		Session:     id,
		Fingerprint: fp,
		State:       "settled",
		Kind:        ch.RuleKind,
		Network:     ch.Network,
		Payer:       out.Payer,
		Requirements: Requirements{
			Scheme:  "direct_proof",
			Network: ch.Network,
			Asset:   ch.Asset,
			Amount:  ch.Amount,
			PayTo:   ch.PayTo,
		},
		Transaction: out.Transaction,
		PolicyID:    policyID,
		Started:     ch.Created,
		Settled:     now,
		Expires:     idleExp,
		Response:    &settled,
	}
	if err := s.ledger.write(rec); err != nil {
		failure(w, 409, "transaction_already_redeemed")
		return
	}
	s.checkCapacityWarn()
	s.mu.Lock()
	delete(s.directChallenges, ch.ID)
	s.nfts[id] = nftLease{
		Network:     ch.Network,
		Payer:       out.Payer,
		Rule:        ch.RuleID,
		Kind:        ch.RuleKind,
		Issued:      now,
		Expires:     idleExp,
		HardExpires: hardExp,
	}
	s.mu.Unlock()
	s.setPassCookie(w, cfg, id, passKind, now, idleExp, hardExp, "")
	reply(w, 200, map[string]any{"eligible": true, "kind": ch.RuleKind, "expires": idleExp, "hard_expires": hardExp, "transaction": out.Transaction, "payer": out.Payer})
}

func validAddressForNetwork(network, addr string) bool {
	switch chain(network) {
	case "xrpl":
		return xrplAddress.MatchString(addr)
	case "stellar":
		return stellarAccount.MatchString(addr)
	case "hedera":
		return entityID.MatchString(addr)
	case "solana":
		return solAddress.MatchString(addr)
	}
	return false
}
