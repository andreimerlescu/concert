package fastlane

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// Transfer payments: a visitor sends an exact amount to the merchant's
// receiving account and Concert finds that payment on the chain. The amount is
// the price plus a small per-visitor dust that is unique among visitors who
// are waiting, so it identifies them; an XRPL destination tag or a memo (on
// chains that carry one) is a second way to attribute the payment. It suits
// wallets that can send a plain payment but cannot sign an x402 authorization.
// Matching lives in the gateway (/deposit/check); see internal/chain/inbound.

const (
	// Payments are searched this far back, so a deposit sent just before the
	// visitor reopened the page is still found.
	depositLookback = 2 * time.Hour
	// Ledger lookups per session are spaced out; the page polls faster.
	depositPollGap = 4 * time.Second
	maxDepositTags = 100000
)

type depositTag struct {
	session string
	expires time.Time
}

// intent is what one visitor must send: their unique amount, and a reference
// (an XRPL destination tag, or a memo elsewhere) that also identifies them.
type intent struct {
	Amount string
	Tag    uint32
	Memo   string
}

// DepositEnabled reports whether the offer can be paid by a plain transfer.
func DepositEnabled(o Offer) bool {
	r := o.Requirements
	if _, fixed := r.Extra["destinationTag"]; fixed {
		return false
	}
	switch chain(r.Network) {
	case "xrpl", "hedera", "solana":
		return true
	case "stellar":
		return len(r.PayTo) > 0 && r.PayTo[0] == 'G'
	}
	return false
}

func (s *Service) depositOffer(network string) (Offer, bool) {
	for _, o := range s.cfg.Offers {
		if o.Requirements.Network == network && DepositEnabled(o) {
			return o, true
		}
	}
	return Offer{}, false
}

func (s *Service) derive(parts ...string) uint32 {
	raw, err := base64.RawURLEncoding.DecodeString(s.mac("deposit/" + strings.Join(parts, "/")))
	if err != nil || len(raw) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(raw[:4])
}

// intentFor returns the session's payment instructions for an offer. Every
// value is derived from the session, so it survives a restart and needs no
// storage; an amount or tag another live session holds is skipped by counting
// up, which keeps them unique among concurrent visitors.
func (s *Service) intentFor(session string, o Offer, priceAtomic, listing string, exp time.Time) (intent, bool) {
	now := s.now()
	r := o.Requirements
	price, _ := new(big.Int).SetString(priceAtomic, 10)
	dustMax := new(big.Int).Div(price, big.NewInt(20))
	if dustMax.Cmp(big.NewInt(99)) < 0 {
		dustMax.SetInt64(99)
	}
	if dustMax.Cmp(big.NewInt(9999)) > 0 {
		dustMax.SetInt64(9999)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.tags) >= maxDepositTags {
		for k, v := range s.tags {
			if !now.Before(v.expires) {
				delete(s.tags, k)
			}
		}
		if len(s.tags) >= maxDepositTags {
			return intent{}, false
		}
	}
	free := func(key string) bool {
		held, ok := s.tags[key]
		return !ok || held.session == session || !now.Before(held.expires)
	}
	var out intent
	found := false
	for i := 0; i < 256 && !found; i++ {
		dust := new(big.Int).Add(new(big.Int).Mod(new(big.Int).SetUint64(uint64(s.derive(r.Network, session, listing, "dust", strconv.Itoa(i)))), dustMax), big.NewInt(1))
		amount := new(big.Int).Add(price, dust).String()
		if key := "amount/" + r.Network + "/" + amount; free(key) {
			s.tags[key] = depositTag{session, exp}
			out.Amount, found = amount, true
		}
	}
	if !found {
		return intent{}, false
	}
	if chain(r.Network) == "xrpl" {
		for i := 0; i < 64 && out.Tag == 0; i++ {
			tag := s.derive(r.Network, session, listing, "tag", strconv.Itoa(i))
			if key := "tag/" + r.Network + "/" + strconv.FormatUint(uint64(tag), 10); tag != 0 && free(key) {
				s.tags[key] = depositTag{session, exp}
				out.Tag = tag
			}
		}
		if out.Tag == 0 {
			return intent{}, false
		}
	} else {
		out.Memo = "CT" + strings.ToUpper(hex.EncodeToString([]byte(s.mac("memo/" + r.Network + "/" + session + "/" + listing))[:5]))
	}
	return out, true
}

// shown formats atomic units as a decimal amount for display.
func shown(network, amount string) string {
	d := map[string]int{"xrpl": 6, "stellar": 7, "hedera": 8, "solana": 9}[chain(network)]
	n, _ := new(big.Int).SetString(amount, 10)
	if n == nil {
		return amount
	}
	s := n.String()
	for len(s) <= d {
		s = "0" + s
	}
	return s[:len(s)-d] + "." + s[len(s)-d:]
}

// qrContent is what the QR code holds: the receiving address at the least.
// Solana has a standard payment-request URL that wallets read, so it carries
// the amount and memo as well.
func qrContent(r Requirements, in intent) string {
	if chain(r.Network) == "solana" {
		q := url.Values{"amount": {shown(r.Network, in.Amount)}, "memo": {in.Memo}}
		return "solana:" + r.PayTo + "?" + q.Encode()
	}
	return r.PayTo
}

func qrDataURI(content string) (string, error) {
	png, err := qrcode.Encode(content, qrcode.Medium, 320)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

func (s *Service) depositRequest(w http.ResponseWriter, r *http.Request, id string, exp time.Time) {
	var in struct {
		Network string `json:"network"`
		Listing string `json:"listing"`
	}
	if decode(r, &in) != nil {
		failure(w, 400, "invalid_deposit_request")
		return
	}
	o, ok := s.depositOffer(in.Network)
	if !ok {
		failure(w, 400, "deposit_not_offered")
		return
	}
	price, listing, code := s.priceFor(o, in.Network, in.Listing, id)
	if code != "" {
		failure(w, 409, code)
		return
	}
	it, ok := s.intentFor(id, o, price, listing.ID, exp)
	if !ok {
		failure(w, 503, "deposit_capacity")
		return
	}
	content := qrContent(o.Requirements, it)
	qr, err := qrDataURI(content)
	if err != nil {
		failure(w, 503, "qr_unavailable")
		return
	}
	reply(w, 200, map[string]any{"network": in.Network, "address": o.Requirements.PayTo, "amount": it.Amount, "amount_display": shown(in.Network, it.Amount), "price": price, "listing": listing.ID, "tag": it.Tag, "memo": it.Memo, "qr_content": content, "qr": qr, "lookback_seconds": int(depositLookback / time.Second)})
}

func (s *Service) depositCheck(w http.ResponseWriter, r *http.Request, id string, exp time.Time) {
	var in struct {
		Network string `json:"network"`
		Listing string `json:"listing"`
	}
	if decode(r, &in) != nil {
		failure(w, 400, "invalid_deposit_request")
		return
	}
	o, ok := s.depositOffer(in.Network)
	if !ok {
		failure(w, 400, "deposit_not_offered")
		return
	}
	req := o.Requirements
	price, listing, code := s.priceFor(o, in.Network, in.Listing, id)
	if code == "listing_already_sold" {
		// Someone may have paid for this listing after it sold, from an intent
		// shown before the sale. Their money must still be found and flagged,
		// so a sold listing is refused only for new intents (depositRequest),
		// never here.
		if sale, mine := s.ledger.fingerprint(s.soldFingerprint(listing.ID)); mine && sale.Session == id {
			s.receipt(w, sale)
			return
		}
		code = ""
	}
	if code != "" {
		failure(w, 409, code)
		return
	}
	if prior, exists := s.ledger.get(id); listing.ID == "" && exists && prior.State == "settled" && s.now().Before(prior.Expires) {
		s.receipt(w, prior)
		return
	}
	it, ok := s.intentFor(id, o, price, listing.ID, exp)
	if !ok {
		failure(w, 503, "deposit_capacity")
		return
	}
	now := s.now()
	s.mu.Lock()
	if last, seen := s.depositPolls[id]; seen && now.Sub(last) < depositPollGap {
		s.mu.Unlock()
		reply(w, 200, map[string]any{"eligible": false, "waiting": true})
		return
	}
	if len(s.depositPolls) >= maxRateEntries {
		for k, v := range s.depositPolls {
			if now.Sub(v) >= depositPollGap {
				delete(s.depositPolls, k)
			}
		}
	}
	s.depositPolls[id] = now
	s.mu.Unlock()
	var out struct {
		Deposits []struct {
			Transaction string `json:"transaction"`
			Payer       string `json:"payer"`
		} `json:"deposits"`
	}
	err := s.gatewayCall(r.Context(), callTimeout, "/deposit/check", map[string]any{"network": in.Network, "address": req.PayTo, "price": price, "amount": it.Amount, "tag": it.Tag, "memo": it.Memo, "since": now.Add(-depositLookback).Unix()}, &out)
	if err != nil {
		failure(w, 503, "deposit_check_unavailable")
		return
	}
	for _, d := range out.Deposits {
		if d.Transaction == "" || d.Payer == "" {
			continue
		}
		fp := digest([]byte("deposit/" + in.Network + "/" + d.Transaction))
		if _, redeemed := s.ledger.fingerprint(fp); redeemed {
			continue // already bought a pass, for this session or another
		}
		policy, err := s.screen(r.Context(), r, in.Network, d.Payer, "deposit", req)
		if err != nil {
			failure(w, 403, "policy_not_approved")
			return
		}
		settled := Settlement{Success: true, Transaction: d.Transaction, Network: in.Network, Payer: d.Payer}
		x := Receipt{Session: id, Fingerprint: fp, State: "settled", Kind: "deposit", Network: in.Network, Payer: d.Payer, Requirements: req, Transaction: d.Transaction, PolicyID: policy, Started: now, Settled: now, Expires: now.Add(time.Duration(s.cfg.PassSeconds) * time.Second), Response: &settled}
		conflict := false
		if listing.ID != "" {
			// The first payment seen for a listing takes it; a later one keeps
			// its pass and is flagged for the merchant to make right.
			x.Listing = listing.ID
			x.Requirements.Amount = price
			s.mu.Lock()
			if other, taken := s.sold[listing.ID]; taken && other != fp {
				x.Kind, conflict = "nft_sale_conflict", true
			} else {
				x.Kind = "nft_sale"
				s.sold[listing.ID] = fp
			}
			s.mu.Unlock()
		}
		if err = s.ledger.write(x); err != nil {
			if x.Kind == "nft_sale" {
				s.mu.Lock()
				delete(s.sold, listing.ID)
				s.mu.Unlock()
			}
			failure(w, 503, "receipt_not_saved_contact_merchant")
			return
		}
		if conflict {
			w.Header().Set("Concert-Listing-Conflict", "1")
		}
		s.receipt(w, x)
		return
	}
	reply(w, 200, map[string]any{"eligible": false, "waiting": true})
}

// priceFor resolves what a visitor is paying: the offer's price, or a
// listing's. It returns a refusal code when the listing is unknown or sold.
func (s *Service) priceFor(o Offer, network, listingID, session string) (string, Listing, string) {
	if listingID == "" {
		return o.Requirements.Amount, Listing{}, ""
	}
	for _, l := range s.cfg.Listings {
		if l.ID != listingID {
			continue
		}
		if l.Network != network {
			return "", l, "listing_network_mismatch"
		}
		s.mu.Lock()
		_, sold := s.sold[l.ID]
		s.mu.Unlock()
		if sold {
			return l.Price, l, "listing_already_sold"
		}
		return l.Price, l, ""
	}
	return "", Listing{}, "unknown_listing"
}

// soldFingerprint is the receipt fingerprint of the payment that bought a listing.
func (s *Service) soldFingerprint(listing string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sold[listing]
}
