package fastlane

import (
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/url"
	"strconv"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// Deposit access: a visitor sends the offer's price to the merchant's
// receiving account with a destination tag that belongs to their session, and
// Concert matches the tag against validated ledger payments. It suits wallets
// that can send a plain payment but cannot sign an x402 authorization.
//
// Only XRPL has a destination tag the ledger itself records, so only XRPL
// offers take deposits. Offering it elsewhere would tell people to send funds
// that could never be recognized.

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

// DepositEnabled reports whether the offer accepts tagged deposits.
func DepositEnabled(o Offer) bool {
	r := o.Requirements
	_, fixed := r.Extra["destinationTag"]
	return chain(r.Network) == "xrpl" && !fixed
}

func (s *Service) depositOffer(network string) (Offer, bool) {
	for _, o := range s.cfg.Offers {
		if o.Requirements.Network == network && DepositEnabled(o) {
			return o, true
		}
	}
	return Offer{}, false
}

// tagFor returns the session's destination tag: derived from the session and
// network, so it survives a restart and needs no storage. A tag another live
// session already holds is skipped by counting up, which is what makes tags
// unique among concurrent visitors.
func (s *Service) tagFor(session, network string, exp time.Time) (uint32, bool) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.tags) >= maxDepositTags {
		for t, v := range s.tags {
			if !now.Before(v.expires) {
				delete(s.tags, t)
			}
		}
		if len(s.tags) >= maxDepositTags {
			return 0, false
		}
	}
	for i := 0; i < 64; i++ {
		sum := s.mac("deposit-tag/" + network + "/" + session + "/" + strconv.Itoa(i))
		raw, err := base64.RawURLEncoding.DecodeString(sum)
		if err != nil || len(raw) < 4 {
			return 0, false
		}
		tag := binary.BigEndian.Uint32(raw[:4])
		if tag == 0 {
			continue
		}
		if held, ok := s.tags[tag]; ok && held.session != session && now.Before(held.expires) {
			continue
		}
		s.tags[tag] = depositTag{session, exp}
		return tag, true
	}
	return 0, false
}

// depositURI is the payment request a scanning wallet reads. Wallets differ in
// how much of it they honor, so the page also prints the address and tag.
func depositURI(r Requirements, tag uint32) string {
	q := url.Values{"dt": {strconv.FormatUint(uint64(tag), 10)}, "amount": {r.Amount}}
	return "xrpl:" + r.PayTo + "?" + q.Encode()
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
	tag, ok := s.tagFor(id, in.Network, exp)
	if !ok {
		failure(w, 503, "deposit_capacity")
		return
	}
	uri := depositURI(o.Requirements, tag)
	qr, err := qrDataURI(uri)
	if err != nil {
		failure(w, 503, "qr_unavailable")
		return
	}
	reply(w, 200, map[string]any{"network": in.Network, "address": o.Requirements.PayTo, "tag": tag, "amount": o.Requirements.Amount, "uri": uri, "qr": qr, "lookback_seconds": int(depositLookback / time.Second)})
}

func (s *Service) depositCheck(w http.ResponseWriter, r *http.Request, id string, exp time.Time) {
	var in struct {
		Network string `json:"network"`
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
	if prior, exists := s.ledger.get(id); exists && prior.State == "settled" && s.now().Before(prior.Expires) {
		s.receipt(w, prior)
		return
	}
	tag, ok := s.tagFor(id, in.Network, exp)
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
	err := s.gatewayCall(r.Context(), callTimeout, "/deposit/check", map[string]any{"network": in.Network, "address": req.PayTo, "tag": tag, "amount": req.Amount, "since": now.Add(-depositLookback).Unix()}, &out)
	if err != nil {
		failure(w, 503, "deposit_check_unavailable")
		return
	}
	for _, d := range out.Deposits {
		if d.Transaction == "" || d.Payer == "" {
			continue
		}
		fp := digest([]byte("deposit/" + in.Network + "/" + d.Transaction))
		if used, redeemed := s.ledger.fingerprint(fp); redeemed {
			if used.Session != id {
				failure(w, 409, "payment_already_redeemed")
				return
			}
			continue // this payment already bought a pass
		}
		policy, err := s.screen(r.Context(), r, in.Network, d.Payer, "deposit", req)
		if err != nil {
			failure(w, 403, "policy_not_approved")
			return
		}
		settled := Settlement{Success: true, Transaction: d.Transaction, Network: in.Network, Payer: d.Payer}
		x := Receipt{Session: id, Fingerprint: fp, State: "settled", Kind: "deposit", Network: in.Network, Payer: d.Payer, Requirements: req, Transaction: d.Transaction, PolicyID: policy, Started: now, Settled: now, Expires: now.Add(time.Duration(s.cfg.PassSeconds) * time.Second), Response: &settled}
		if err = s.ledger.write(x); err != nil {
			failure(w, 503, "receipt_not_saved_contact_merchant")
			return
		}
		s.receipt(w, x)
		return
	}
	reply(w, 200, map[string]any{"eligible": false, "waiting": true})
}
