package fastlane

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Resource struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}
type Payload struct {
	Version    int                        `json:"x402Version"`
	Resource   *Resource                  `json:"resource,omitempty"`
	Accepted   Requirements               `json:"accepted"`
	Payload    json.RawMessage            `json:"payload"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}
type Settlement struct {
	Success     bool   `json:"success"`
	ErrorReason string `json:"errorReason,omitempty"`
	Transaction string `json:"transaction"`
	Network     string `json:"network"`
	Payer       string `json:"payer,omitempty"`
}
type verification struct {
	Valid  bool   `json:"isValid"`
	Payer  string `json:"payer"`
	Reason string `json:"invalidReason,omitempty"`
}
type assessment struct {
	Decision string    `json:"decision"`
	ID       string    `json:"assessment_id"`
	Expires  time.Time `json:"expires_at"`
}
type challenge struct {
	Session string
	Rule    Collection
	Address string
	Token   string
	Message string
	Expires time.Time
}
type nftLease struct {
	Network string
	Payer   string
	Rule    string
	Expires time.Time
}

type rateWindow struct {
	start time.Time
	n     int
}

const (
	// A session token lives a day and is renewed by POST /session, which keeps
	// its ID (derived from the random nonce), so receipts survive renewal.
	sessionLifetime = 24 * time.Hour
	// Authenticated operations need this much remaining token lifetime. It
	// exceeds the longest pass plus the longest settlement, so a pass never
	// outlives the token that bought it.
	renewBefore = 2 * time.Hour
	// Wallet POSTs per client address (IPv6 per /64) per minute. Sessions are
	// free to create, so this bounds challenge, RPC and verification load.
	postsPerMinute = 60
	maxRateEntries = 100000
	callTimeout    = 45 * time.Second
)

// Gateway runs the chain operations Concert needs: "/supported",
// "/verify", "/settle", "/nft/verify" and "/solana/prepare". Each takes a
// JSON request body and returns a JSON-encodable result. internal/gateway
// implements it inside the Concert process.
type Gateway interface {
	Handle(ctx context.Context, op string, body []byte) (any, error)
}

type Service struct {
	cfg          Config
	key          []byte
	gateway      Gateway
	policyToken  string
	http         *http.Client
	ledger       *ledger
	mu           sync.Mutex
	active       map[string]bool
	challenges   map[string]challenge
	nfts         map[string]nftLease
	limits       map[string]*rateWindow
	tags         map[string]depositTag
	marketCache  map[string]marketEntry
	entries      map[string]entryWindow
	entryTTL     func() time.Duration
	sold         map[string]string // listing id -> fingerprint of the payment that bought it
	depositPolls map[string]time.Time
	work         chan struct{}
	now          func() time.Time
}

func New(c Config, dir string, key []byte, gw Gateway, policyToken string) (*Service, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if !c.Enabled {
		return nil, nil
	}
	if len(key) < 32 {
		return nil, errors.New("stable admission secret must be at least 32 bytes")
	}
	if gw == nil {
		return nil, errors.New("no chain gateway")
	}
	if c.PolicyURL != "" && len(policyToken) < 32 {
		return nil, errors.New("CONCERT_POLICY_TOKEN must be at least 32 bytes")
	}
	l, err := openLedger(dir, c.MaxRecords)
	if err != nil {
		return nil, err
	}
	s := &Service{cfg: c, key: key, gateway: gw, policyToken: policyToken, ledger: l,
		// Every call sets its own deadline: settlement may legitimately outlast
		// an ordinary verification request.
		http:   &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		active: map[string]bool{}, challenges: map[string]challenge{}, nfts: map[string]nftLease{}, limits: map[string]*rateWindow{}, tags: map[string]depositTag{}, sold: map[string]string{}, entries: map[string]entryWindow{}, marketCache: map[string]marketEntry{}, depositPolls: map[string]time.Time{}, work: make(chan struct{}, 32), now: time.Now}
	for _, r := range l.withKind("nft_sale") {
		s.sold[r.Listing] = r.Fingerprint
	}
	var capabilities struct {
		Kinds []struct {
			Version int    `json:"x402Version"`
			Scheme  string `json:"scheme"`
			Network string `json:"network"`
		} `json:"kinds"`
	}
	if err = s.gatewayCall(context.Background(), 10*time.Second, "/supported", nil, &capabilities); err != nil {
		l.close()
		return nil, fmt.Errorf("gateway discovery: %w", err)
	}
	for _, o := range c.Offers {
		if o.DepositOnly {
			continue
		}
		found := false
		for _, k := range capabilities.Kinds {
			if k.Version == 2 && k.Scheme == o.Requirements.Scheme && k.Network == o.Requirements.Network {
				found = true
			}
		}
		if !found {
			l.close()
			return nil, fmt.Errorf("gateway does not support %s on %s", o.Requirements.Scheme, o.Requirements.Network)
		}
	}
	return s, nil
}
func (s *Service) Close()         { s.ledger.close(); s.http.CloseIdleConnections() }
func (s *Service) Config() Config { return s.cfg }

// Shop lists the NFTs for sale with whether each is still available.
func (s *Service) Shop() []map[string]any {
	out := []map[string]any{}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.cfg.Listings {
		_, sold := s.sold[l.ID]
		out = append(out, map[string]any{"id": l.ID, "name": l.Name, "description": l.Description, "image_url": l.ImageURL, "network": l.Network, "token_id": l.Token, "collection": l.Collection, "price": l.Price, "price_display": shown(l.Network, l.Price), "sold": sold})
	}
	return out
}

// Sales lists NFT purchases for the merchant to deliver, newest first.
func (s *Service) Sales() []map[string]any {
	names := map[string]Listing{}
	for _, l := range s.cfg.Listings {
		names[l.ID] = l
	}
	out := []map[string]any{}
	rs := s.ledger.withKind("nft_sale", "nft_sale_conflict")
	for i := len(rs) - 1; i >= 0; i-- {
		r := rs[i]
		l := names[r.Listing]
		out = append(out, map[string]any{"fingerprint": r.Fingerprint, "listing": r.Listing, "name": l.Name, "token_id": l.Token, "network": r.Network, "buyer": r.Payer, "transaction": r.Transaction, "paid": r.Requirements.Amount, "paid_display": shown(r.Network, r.Requirements.Amount), "when": r.Settled, "conflict": r.Kind == "nft_sale_conflict", "delivered": r.Delivered})
	}
	return out
}

// MarkDelivered records that the merchant sent the NFT for a sale.
func (s *Service) MarkDelivered(fingerprint string) error {
	r, ok := s.ledger.fingerprint(fingerprint)
	if !ok || (r.Kind != "nft_sale" && r.Kind != "nft_sale_conflict") {
		return errors.New("unknown sale")
	}
	now := s.now()
	r.Delivered = &now
	return s.ledger.write(r)
}
func (s *Service) Summary() map[string]any {
	v := s.ledger.summary()
	v["enabled"] = true
	v["test_mode"] = s.cfg.TestMode
	v["merchant"] = s.cfg.Merchant
	v["offers"] = s.cfg.Offers
	v["collections"] = s.cfg.Collections
	v["pass_seconds"] = s.cfg.PassSeconds
	v["nft_pass_seconds"] = s.cfg.NFTPassSeconds
	v["listings"] = s.cfg.Listings
	v["sales"] = s.Sales()
	return v
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func (s *Service) mac(data string) string {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte("concert/fastlane/v1/" + data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
func randomID() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// parseToken validates a "nonce.expiry.mac" session token.
func (s *Service) parseToken(t string) (nonce string, exp time.Time, ok bool) {
	parts := strings.Split(t, ".")
	if len(parts) != 3 || len(parts[0]) != 32 {
		return "", time.Time{}, false
	}
	unix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || unix <= s.now().Unix() || unix > s.now().Add(sessionLifetime+time.Hour).Unix() {
		return "", time.Time{}, false
	}
	if !hmac.Equal([]byte(parts[2]), []byte(s.mac(parts[0]+"."+parts[1]))) {
		return "", time.Time{}, false
	}
	return parts[0], time.Unix(unix, 0), true
}

// session returns the stable session ID, the presented token and its expiry.
// The ID hashes only the nonce, so it is unchanged when the token is renewed.
func (s *Service) session(r *http.Request) (id, token string, exp time.Time, ok bool) {
	token = r.Header.Get(SessionHeader)
	if token == "" {
		if c, e := r.Cookie(Cookie); e == nil {
			token = c.Value
		}
	}
	nonce, exp, ok := s.parseToken(token)
	if !ok {
		return "", "", time.Time{}, false
	}
	return digest([]byte("session/" + nonce)), token, exp, true
}

// allow applies the per-address POST limit. RemoteAddr is Concert's canonical
// client address (see registerConcertRoutes), never a client-supplied header.
func (s *Service) allow(remote string, now time.Time) bool {
	key := remote
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		key = ap.Addr().Unmap().String()
	}
	if ip, err := netip.ParseAddr(key); err == nil && ip.Unmap().Is6() {
		key = netip.PrefixFrom(ip, 64).Masked().String()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.limits[key]
	if w == nil || now.Sub(w.start) >= time.Minute {
		if w == nil && len(s.limits) >= maxRateEntries {
			for k, v := range s.limits {
				if now.Sub(v.start) >= time.Minute {
					delete(s.limits, k)
				}
			}
			if len(s.limits) >= maxRateEntries {
				return false
			}
		}
		w = &rateWindow{start: now}
		s.limits[key] = w
	}
	w.n++
	return w.n <= postsPerMinute
}

// entryWindow is the stay a pass holder earned by presenting a grant: from the
// first request that found the grant valid until then plus the entry TTL.
type entryWindow struct {
	grant string // which grant opened it; a new payment or NFT proof opens a new one
	until time.Time
}

// SetEntryTTL sets where the entry window's length comes from. It is read on
// every request, so a settings change applies at once. Without it, or at 0, a
// pass is honored for its own length only.
func (s *Service) SetEntryTTL(f func() time.Duration) {
	s.mu.Lock()
	s.entryTTL = f
	s.mu.Unlock()
}

// grantFor returns the session's current grant, if it is still valid: a
// settled receipt or a live NFT lease, with a key that changes per grant.
// s.mu must not be held; the ledger has its own lock.
func (s *Service) grantFor(id string) (key string, expires time.Time, ok bool) {
	now := s.now()
	if x, has := s.ledger.get(id); has && x.State == "settled" && now.Before(x.Expires) {
		return "pay/" + x.Fingerprint, x.Expires, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if x, has := s.nfts[id]; has && now.Before(x.Expires) {
		return "nft/" + strconv.FormatInt(x.Expires.UnixNano(), 10), x.Expires, true
	}
	return "", time.Time{}, false
}

// admitUntil is when a session's access ends: the later of its grant's own
// expiry and its entry window. The window opens the first time the grant is
// presented, so a visitor who gets in is not sent back to the end of the line
// because the grant lapses while they shop. It reports false when neither
// applies. It records the window it opens.
func (s *Service) admitUntil(id string, open bool) (until time.Time, ok bool) {
	now := s.now()
	key, expires, granted := s.grantFor(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	var ttl time.Duration
	if s.entryTTL != nil {
		ttl = s.entryTTL()
	}
	w, has := s.entries[id]
	if granted && open && ttl > 0 && (!has || w.grant != key) {
		if len(s.entries) >= 100000 {
			for k, v := range s.entries {
				if !now.Before(v.until) {
					delete(s.entries, k)
				}
			}
		}
		if len(s.entries) < 100000 {
			w = entryWindow{grant: key, until: now.Add(ttl)}
			s.entries[id] = w
			has = true
		}
	}
	if has && now.Before(w.until) {
		if granted && expires.After(w.until) {
			return expires, true
		}
		return w.until, true
	}
	if granted {
		return expires, true
	}
	return time.Time{}, false
}

// Eligible reads a durable, unexpired grant, or the entry window that a grant
// opened. Bans and the bounded priority pool still run in Concert. A receipt
// never authorizes an unbounded proxy bypass.
func (s *Service) Eligible(r *http.Request) bool {
	if !s.ledger.healthy() {
		return false
	}
	id, _, _, ok := s.session(r)
	if !ok {
		return false
	}
	_, ok = s.admitUntil(id, true)
	return ok
}

// gatewayCall runs a gateway operation, waiting at most timeout. A
// settlement keeps running (and is journaled by the gateway) after the wait
// ends, exactly as it would behind a network hop.
func (s *Service) gatewayCall(ctx context.Context, timeout time.Duration, op string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body := []byte("{}")
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return e
		}
		body = b
	}
	type result struct {
		v   any
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, e := s.gateway.Handle(ctx, op, body)
		done <- result{v, e}
	}()
	select {
	case <-ctx.Done():
		return errors.New("verification service unavailable")
	case r := <-done:
		if r.err != nil {
			// Chain errors may carry endpoint URLs or payloads; never pass them on.
			return errors.New("verification failed")
		}
		b, e := json.Marshal(r.v)
		if e != nil {
			return errors.New("invalid service response")
		}
		if e = json.Unmarshal(b, out); e != nil {
			return errors.New("invalid service JSON")
		}
		return nil
	}
}

func (s *Service) call(ctx context.Context, timeout time.Duration, endpoint, token string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body io.Reader
	method := http.MethodGet
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return e
		}
		body = bytes.NewReader(b)
		method = http.MethodPost
	}
	r, e := http.NewRequestWithContext(ctx, method, endpoint, body)
	if e != nil {
		return e
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	resp, e := s.http.Do(r)
	if e != nil {
		return errors.New("verification service unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("verification service returned HTTP %d", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return errors.New("invalid service response")
	}
	if e = json.Unmarshal(b, out); e != nil {
		return errors.New("invalid service JSON")
	}
	return nil
}

func (s *Service) screen(ctx context.Context, r *http.Request, network, payer, action string, req Requirements) (string, error) {
	if s.cfg.PolicyURL == "" && s.cfg.TestMode {
		return "test-mode-no-screening", nil
	}
	var a assessment
	err := s.call(ctx, callTimeout, s.cfg.PolicyURL, s.policyToken, map[string]any{"network": network, "payer": payer, "action": action, "requirements": req, "client_ip": r.RemoteAddr, "merchant": s.cfg.Merchant}, &a)
	if err != nil {
		return "", err
	}
	now := s.now()
	if a.Decision != "allow" || a.ID == "" || !a.Expires.After(now) || a.Expires.After(now.Add(10*time.Minute)) {
		return "", errors.New("admission not approved by policy service")
	}
	return a.ID, nil
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter, code int, msg string) {
	reply(w, code, map[string]any{"error": msg})
}
func decode(r *http.Request, v any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, MaxBody+1))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func same(a, b any) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Vary", "Cookie, Concert-Session")
	path := strings.TrimPrefix(r.URL.Path, Prefix)
	if r.Method == http.MethodGet && path == "/config" {
		reply(w, 200, s.PublicConfig())
		return
	}
	if r.Method == http.MethodGet && path == "/market" {
		s.market(w, r)
		return
	}
	if r.Method == http.MethodGet && path == "/shop" {
		reply(w, 200, map[string]any{"listings": s.Shop()})
		return
	}
	if r.Method == http.MethodGet && path == "/status" {
		s.status(w, r)
		return
	}
	if r.Method != http.MethodPost {
		failure(w, 405, "method_not_allowed")
		return
	}
	if (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != s.cfg.Origin) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		failure(w, 403, "origin_rejected")
		return
	}
	if !s.allow(r.RemoteAddr, s.now()) {
		w.Header().Set("Retry-After", "60")
		failure(w, 429, "too_many_wallet_requests")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	if path == "/session" {
		s.startSession(w, r)
		return
	}
	id, t, exp, ok := s.session(r)
	if !ok {
		failure(w, 401, "session_required")
		return
	}
	if r.Header.Get(SessionHeader) == "" && !hmac.Equal([]byte(r.Header.Get(CSRFHeader)), []byte(s.mac("csrf/"+t))) {
		failure(w, 403, "csrf_required")
		return
	}
	// Renewal keeps the session ID, so retrying after renewal is always safe.
	if exp.Sub(s.now()) < renewBefore {
		failure(w, 409, "session_renewal_required")
		return
	}
	select {
	case s.work <- struct{}{}:
		defer func() { <-s.work }()
	default:
		w.Header().Set("Retry-After", "3")
		failure(w, 503, "verification_busy")
		return
	}
	s.mu.Lock()
	if s.active[id] {
		s.mu.Unlock()
		failure(w, 409, "request_in_progress")
		return
	}
	s.active[id] = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.active, id); s.mu.Unlock() }()
	switch path {
	case "/payment":
		s.payment(w, r, id)
	case "/solana/prepare":
		s.prepareSOL(w, r)
	case "/deposit":
		s.depositRequest(w, r, id, exp)
	case "/deposit/check":
		s.depositCheck(w, r, id, exp)
	case "/nft/challenge":
		s.makeChallenge(w, r, id)
	case "/nft/verify":
		s.proveNFT(w, r, id)
	default:
		failure(w, 404, "not_found")
	}
}

// startSession issues a session, or renews a valid one under the same ID with
// a fresh expiry. Renewal preserves receipts and unresolved payments.
func (s *Service) startSession(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get(SessionHeader)
	if token == "" {
		if c, e := r.Cookie(Cookie); e == nil {
			token = c.Value
		}
	}
	nonce, _, ok := s.parseToken(token)
	if !ok {
		var e error
		if nonce, e = randomID(); e != nil {
			failure(w, 503, "entropy_unavailable")
			return
		}
	}
	exp := s.now().Add(sessionLifetime)
	body := nonce + "." + strconv.FormatInt(exp.Unix(), 10)
	t := body + "." + s.mac(body)
	http.SetCookie(w, &http.Cookie{Name: Cookie, Value: t, Path: "/", MaxAge: int(sessionLifetime / time.Second), Secure: strings.HasPrefix(s.cfg.Origin, "https://"), HttpOnly: true, SameSite: http.SameSiteStrictMode})
	reply(w, 200, map[string]any{"session": t, "csrf": s.mac("csrf/" + t), "expires": exp.UTC()})
}
func (s *Service) status(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := s.session(r)
	if !ok {
		reply(w, 200, map[string]any{"eligible": false})
		return
	}
	// The window a presented grant opened counts as access too; asking for
	// status never opens one.
	until, admitted := s.admitUntil(id, false)
	paid, exists := s.ledger.get(id)
	if exists && paid.State == "settled" && s.now().Before(paid.Expires) {
		reply(w, 200, map[string]any{"eligible": s.ledger.healthy(), "state": paid.State, "kind": "payment", "expires": until, "receipt": paid.Response})
		return
	}
	s.mu.Lock()
	nft, hasNFT := s.nfts[id]
	s.mu.Unlock()
	if hasNFT && s.now().Before(nft.Expires) {
		reply(w, 200, map[string]any{"eligible": s.ledger.healthy(), "kind": "nft", "expires": until})
		return
	}
	if admitted {
		reply(w, 200, map[string]any{"eligible": s.ledger.healthy(), "kind": "window", "expires": until})
		return
	}
	if exists {
		reply(w, 200, map[string]any{"eligible": false, "state": paid.State, "kind": paid.Kind, "expires": paid.Expires, "receipt": paid.Response})
		return
	}
	reply(w, 200, map[string]any{"eligible": false})
}

func (s *Service) PublicConfig() map[string]any {
	return map[string]any{"enabled": true, "origin": s.cfg.Origin, "test_mode": s.cfg.TestMode, "merchant": s.cfg.Merchant, "offers": s.cfg.Offers, "collections": s.cfg.Collections, "pass_seconds": s.cfg.PassSeconds, "nft_pass_seconds": s.cfg.NFTPassSeconds, "terms_url": s.cfg.TermsURL, "privacy_url": s.cfg.PrivacyURL, "refund_url": s.cfg.RefundURL, "deposit_networks": s.depositNetworks()}
}

func (s *Service) depositNetworks() []string {
	out := []string{}
	for _, o := range s.cfg.Offers {
		if DepositEnabled(o) {
			out = append(out, o.Requirements.Network)
		}
	}
	return out
}

func (s *Service) prepareSOL(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Network string `json:"network"`
		Address string `json:"address"`
	}
	if decode(r, &in) != nil || !solAddress.MatchString(in.Address) {
		failure(w, 400, "invalid_wallet_address")
		return
	}
	found := false
	for _, o := range s.cfg.Offers {
		if o.Requirements.Network == in.Network && o.Requirements.Scheme == "concert-native-sol" {
			found = true
		}
	}
	if !found {
		failure(w, 400, "network_not_offered")
		return
	}
	var out struct {
		Transaction string `json:"transaction"`
	}
	if err := s.gatewayCall(r.Context(), callTimeout, "/solana/prepare", in, &out); err != nil {
		failure(w, 503, "wallet_preparation_unavailable")
		return
	}
	if out.Transaction == "" || len(out.Transaction) > 2000 {
		failure(w, 503, "invalid_transaction_response")
		return
	}
	reply(w, 200, out)
}

func (s *Service) required(w http.ResponseWriter) {
	accepts := make([]Requirements, 0, len(s.cfg.Offers))
	for _, o := range s.cfg.Offers {
		if o.DepositOnly {
			continue
		}
		accepts = append(accepts, o.Requirements)
	}
	if len(accepts) == 0 {
		failure(w, 404, "payments_disabled")
		return
	}
	body := map[string]any{"x402Version": 2, "resource": Resource{URL: s.cfg.Origin + Prefix + "/payment", Description: fmt.Sprintf("%d seconds of Concert fast-lane eligibility; capacity limits apply", s.cfg.PassSeconds), MimeType: "application/json"}, "accepts": accepts}
	b, _ := json.Marshal(body)
	w.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(b))
	reply(w, 402, body)
}
func (s *Service) receipt(w http.ResponseWriter, x Receipt) {
	b, _ := json.Marshal(x.Response)
	w.Header().Set("PAYMENT-RESPONSE", base64.StdEncoding.EncodeToString(b))
	reply(w, 200, map[string]any{"eligible": s.ledger.healthy() && s.now().Before(x.Expires), "expires": x.Expires, "receipt": x.Response})
}

func (s *Service) payment(w http.ResponseWriter, r *http.Request, id string) {
	prior, exists := s.ledger.get(id)
	if exists && prior.State == "settled" && s.now().Before(prior.Expires) {
		s.receipt(w, prior)
		return
	}
	header := r.Header.Get("PAYMENT-SIGNATURE")
	if header == "" {
		s.required(w)
		return
	}
	if len(header) > MaxBody {
		failure(w, 413, "payment_header_too_large")
		return
	}
	b, e := base64.StdEncoding.Strict().DecodeString(header)
	if e != nil {
		failure(w, 400, "invalid_payment_encoding")
		return
	}
	var p Payload
	if e = json.Unmarshal(b, &p); e != nil || p.Version != 2 || len(p.Payload) == 0 {
		failure(w, 400, "invalid_payment_payload")
		return
	}
	if p.Resource != nil && p.Resource.URL != s.cfg.Origin+Prefix+"/payment" {
		failure(w, 400, "wrong_resource")
		return
	}
	var req Requirements
	found := false
	for _, o := range s.cfg.Offers {
		if !o.DepositOnly && same(p.Accepted, o.Requirements) {
			req = o.Requirements
			found = true
			break
		}
	}
	if !found {
		failure(w, 400, "payment_terms_mismatch")
		return
	}
	// Hash canonical JSON so changing whitespace/object-key order is not a new
	// authorization. Chain transaction IDs provide an independent replay check.
	var canonical any
	d := json.NewDecoder(bytes.NewReader(p.Payload))
	d.UseNumber()
	if d.Decode(&canonical) != nil {
		failure(w, 400, "invalid_payment")
		return
	}
	cb, _ := json.Marshal(canonical)
	fp := digest(append([]byte(req.Network+"/"+req.Scheme+"/"), cb...))
	if used, ok := s.ledger.fingerprint(fp); ok {
		if used.Session != id {
			failure(w, 409, "payment_already_redeemed")
			return
		}
		if used.State == "settled" {
			s.receipt(w, used)
			return
		}
	}
	if exists && prior.Fingerprint == fp && prior.State == "settled" {
		s.receipt(w, prior)
		return
	}
	if exists && prior.State != "settled" && prior.Fingerprint != fp {
		failure(w, 409, "previous_payment_unresolved_do_not_pay_again")
		return
	}
	args := map[string]any{"x402Version": 2, "paymentPayload": p, "paymentRequirements": req}
	x := prior
	if !exists || prior.Fingerprint != fp {
		var v verification
		if e = s.gatewayCall(r.Context(), callTimeout, "/verify", args, &v); e != nil {
			failure(w, 503, "payment_verification_unavailable")
			return
		}
		if !v.Valid || v.Payer == "" {
			failure(w, 402, "payment_not_verified")
			return
		}
		policy, err := s.screen(r.Context(), r, req.Network, v.Payer, "payment", req)
		if err != nil {
			failure(w, 403, "policy_not_approved")
			return
		}
		x = Receipt{Session: id, Fingerprint: fp, State: "pending", Kind: "payment", Network: req.Network, Payer: v.Payer, Requirements: req, PolicyID: policy, Started: s.now()}
		if err = s.ledger.write(x); err != nil {
			failure(w, 409, "payment_reservation_failed")
			return
		}
	} else {
		// Retry only the identical authorization. Native chain replay protection
		// plus the gateway's durable settlement cache prevents another debit.
		if _, err := s.screen(r.Context(), r, req.Network, x.Payer, "payment_retry", req); err != nil {
			failure(w, 403, "policy_not_approved")
			return
		}
	}
	// Settlement is detached from the visitor's connection: a closed tab or
	// client timeout must not turn a payment that settles into an unknown
	// receipt. The gateway may wait for finality for up to maxTimeoutSeconds.
	settleCtx := context.WithoutCancel(r.Context())
	settleWithin := time.Duration(req.MaxTimeoutSeconds)*time.Second + 90*time.Second
	var settled Settlement
	e = s.gatewayCall(settleCtx, settleWithin, "/settle", args, &settled)
	if e != nil || !settled.Success || settled.Transaction == "" || settled.Network != req.Network || settled.Payer != x.Payer {
		x.State = "unknown"
		_ = s.ledger.write(x)
		failure(w, 503, "settlement_unresolved_retry_identical_payment_do_not_pay_again")
		return
	}
	x.State = "settled"
	x.Transaction = settled.Transaction
	x.Settled = s.now()
	x.Expires = x.Settled.Add(time.Duration(s.cfg.PassSeconds) * time.Second)
	x.Response = &settled
	if e = s.ledger.write(x); e != nil {
		failure(w, 503, "receipt_not_saved_contact_merchant_do_not_pay_again")
		return
	}
	s.receipt(w, x)
}

func (s *Service) makeChallenge(w http.ResponseWriter, r *http.Request, id string) {
	var in struct {
		Rule    string `json:"rule"`
		Address string `json:"address"`
		Token   string `json:"token_id"`
	}
	if decode(r, &in) != nil || len(in.Address) < 3 || len(in.Address) > 100 || len(in.Token) > 128 {
		failure(w, 400, "invalid_wallet_request")
		return
	}
	var rule Collection
	found := false
	for _, x := range s.cfg.Collections {
		if x.ID == in.Rule {
			rule = x
			found = true
		}
	}
	if !found {
		failure(w, 400, "unknown_collection_rule")
		return
	}
	// Solana ownership is checked per mint. Stellar's SEP-50 balance() check
	// covers the collection only, so a token there would never be verified.
	switch chain(rule.Network) {
	case "solana":
		if !solAddress.MatchString(in.Token) {
			failure(w, 400, "nft_mint_required")
			return
		}
	case "stellar":
		if in.Token != "" {
			failure(w, 400, "token_not_supported_for_collection")
			return
		}
	}
	for _, v := range []string{in.Address, in.Token} {
		if strings.ContainsAny(v, "\r\n\x00") {
			failure(w, 400, "invalid_wallet_request")
			return
		}
	}
	nonce, e := randomID()
	if e != nil {
		failure(w, 503, "entropy_unavailable")
		return
	}
	now := s.now()
	exp := now.Add(2 * time.Minute)
	msg := fmt.Sprintf("Concert NFT admission v1\nOrigin: %s\nNetwork: %s\nWallet: %s\nCollection: %s\nToken: %s\nSession: %s\nNonce: %s\nIssued: %s\nExpires: %s\nPurpose: prove wallet control for a short fast-lane lease. No payment or transaction authorization.", s.cfg.Origin, rule.Network, in.Address, rule.Collection, in.Token, id, nonce, now.UTC().Format(time.RFC3339), exp.UTC().Format(time.RFC3339))
	s.mu.Lock()
	for k, v := range s.challenges {
		if !now.Before(v.Expires) {
			delete(s.challenges, k)
		}
	}
	for k, v := range s.nfts {
		if !now.Before(v.Expires) {
			delete(s.nfts, k)
		}
	}
	if len(s.challenges) >= 10000 {
		s.mu.Unlock()
		failure(w, 503, "challenge_capacity")
		return
	}
	// At most one outstanding challenge per session.
	for k, v := range s.challenges {
		if v.Session == id {
			delete(s.challenges, k)
		}
	}
	s.challenges[nonce] = challenge{id, rule, in.Address, in.Token, msg, exp}
	s.mu.Unlock()
	reply(w, 200, map[string]any{"nonce": nonce, "message": msg, "expires": exp, "network": rule.Network, "rule": rule.ID})
}
func (s *Service) proveNFT(w http.ResponseWriter, r *http.Request, id string) {
	var in struct {
		Nonce     string `json:"nonce"`
		Signature string `json:"signature"`
		PublicKey string `json:"public_key"`
	}
	if decode(r, &in) != nil || len(in.Signature) > 4096 || len(in.PublicKey) > 256 {
		failure(w, 400, "invalid_proof")
		return
	}
	s.mu.Lock()
	ch, ok := s.challenges[in.Nonce]
	if ok && ch.Session == id {
		delete(s.challenges, in.Nonce)
	}
	s.mu.Unlock()
	if !ok || ch.Session != id || !s.now().Before(ch.Expires) {
		failure(w, 401, "challenge_expired_or_used")
		return
	}
	var proof struct {
		Valid      bool   `json:"valid"`
		Owner      string `json:"owner"`
		Network    string `json:"network"`
		Collection string `json:"collection"`
		Token      string `json:"token_id"`
	}
	err := s.gatewayCall(r.Context(), callTimeout, "/nft/verify", map[string]any{"network": ch.Rule.Network, "address": ch.Address, "collection": ch.Rule.Collection, "token_id": ch.Token, "message": ch.Message, "signature": in.Signature, "public_key": in.PublicKey}, &proof)
	if err != nil {
		failure(w, 503, "nft_verification_unavailable")
		return
	}
	if !proof.Valid || proof.Owner != ch.Address || proof.Network != ch.Rule.Network || proof.Collection != ch.Rule.Collection || (ch.Token != "" && proof.Token != ch.Token) {
		failure(w, 403, "ownership_not_verified")
		return
	}
	if _, err = s.screen(r.Context(), r, ch.Rule.Network, ch.Address, "nft", Requirements{}); err != nil {
		failure(w, 403, "policy_not_approved")
		return
	}
	exp := s.now().Add(time.Duration(s.cfg.NFTPassSeconds) * time.Second)
	s.mu.Lock()
	if len(s.nfts) >= 10000 {
		s.mu.Unlock()
		failure(w, 503, "lease_capacity")
		return
	}
	s.nfts[id] = nftLease{ch.Rule.Network, ch.Address, ch.Rule.ID, exp}
	s.mu.Unlock()
	reply(w, 200, map[string]any{"eligible": true, "kind": "nft", "expires": exp, "token_id": proof.Token})
}
