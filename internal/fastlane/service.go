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
	Network     string
	Payer       string
	Rule        string
	Kind        string // "nft" or "token"
	Issued      time.Time
	Expires     time.Time
	HardExpires time.Time
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
	cfgMu            sync.RWMutex
	cfg              Config
	key              []byte
	prevKey          []byte
	gateway          Gateway
	policyToken      string
	blocklist        blocklistCache
	http             *http.Client
	ledger           *ledger
	mu               sync.Mutex
	active           map[string]bool
	challenges       map[string]challenge
	directChallenges map[string]directChallenge
	nfts             map[string]nftLease
	revoked          map[string]time.Time
	revokedCheck     func(string) bool
	revokedPublish   func(string, time.Duration)
	limits           *rateLimiter
	work             chan struct{}
	now              func() time.Time
	onUnknown        func(network, session string)
	onCapacityWarn   func(used, max, pct int)
	warned80         bool
	warned95         bool
}

func (s *Service) currentConfig() Config {
	s.cfgMu.RLock()
	c := s.cfg
	s.cfgMu.RUnlock()
	return c
}

// UpdateConfig validates and hot-swaps the fast-lane configuration in memory
// without restarting Concert or interrupting in-flight settlements.
func (s *Service) UpdateConfig(c Config) error {
	if s == nil {
		return errors.New("fast lane is not enabled")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if c.EffectivePolicyMode() == PolicyModeWebhook && c.PolicyURL != "" && len(s.policyToken) < 32 {
		return errors.New("CONCERT_POLICY_TOKEN must be at least 32 bytes for webhook policy_mode")
	}
	s.cfgMu.Lock()
	s.cfg = c
	s.cfgMu.Unlock()
	if s.ledger != nil && c.MaxRecords > 0 {
		s.ledger.setMax(c.MaxRecords)
	}
	return nil
}

// ArchiveOnline compacts expired settled receipts older than olderThan while
// Concert stays live and resets latched capacity alerts if usage drops below 80%.
func (s *Service) ArchiveOnline(olderThan time.Duration, dryRun bool) (ArchiveReport, error) {
	if s == nil || s.ledger == nil {
		return ArchiveReport{}, errors.New("fast lane is not enabled")
	}
	rep, err := s.ledger.archiveOnline(olderThan, dryRun, s.now())
	if err != nil {
		return rep, err
	}
	if !dryRun && rep.Archived > 0 {
		used, maxRec, _ := s.ledger.stats()
		if maxRec > 0 && (used*100)/maxRec < 80 {
			s.mu.Lock()
			s.warned80 = false
			s.warned95 = false
			s.mu.Unlock()
		}
	}
	return rep, nil
}

// ReceiptView is the redacted operator-facing view of an unresolved fast-lane
// receipt. It omits raw session tokens and signed payment payloads.
type ReceiptView struct {
	Fingerprint string    `json:"fingerprint"`
	State       string    `json:"state"`
	Network     string    `json:"network"`
	Scheme      string    `json:"scheme"`
	Amount      string    `json:"amount"`
	Asset       string    `json:"asset"`
	Payer       string    `json:"payer"`
	Started     time.Time `json:"started"`
	NeedsHash   bool      `json:"needs_hash,omitempty"`
}

// SetOnUnknown registers an optional observer called whenever a payment
// settlement enters the unresolved "unknown" state requiring reconciliation.
func (s *Service) SetOnUnknown(fn func(network, session string)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.onUnknown = fn
	s.mu.Unlock()
}

// SetOnCapacityWarn registers an optional observer called once when the
// fast-lane receipt journal crosses 80% (warning) and again at 95% (critical)
// of MaxRecords. If the journal is already above a threshold at registration
// time, the callback fires immediately.
func (s *Service) SetOnCapacityWarn(fn func(used, max, pct int)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.onCapacityWarn = fn
	s.mu.Unlock()
	s.checkCapacityWarn()
}

func (s *Service) checkCapacityWarn() {
	if s == nil || s.ledger == nil {
		return
	}
	used, max, _ := s.ledger.stats()
	if max <= 0 {
		return
	}
	pct := (used * 100) / max
	if pct < 80 {
		return
	}
	var cb func(used, max, pct int)
	s.mu.Lock()
	if pct >= 95 && !s.warned95 {
		s.warned95 = true
		s.warned80 = true
		cb = s.onCapacityWarn
	} else if pct >= 80 && !s.warned80 {
		s.warned80 = true
		cb = s.onCapacityWarn
	}
	s.mu.Unlock()
	if cb != nil {
		cb(used, max, pct)
	}
}

// JournalStats returns current receipt counts for metrics and alerts.
func (s *Service) JournalStats() (used, max, unresolved int) {
	if s == nil || s.ledger == nil {
		return 0, 0, 0
	}
	return s.ledger.stats()
}

// UnresolvedReceipts returns redacted metadata for every receipt currently in
// state "pending" or "unknown".
func (s *Service) UnresolvedReceipts() []ReceiptView {
	if s == nil || s.ledger == nil {
		return []ReceiptView{}
	}
	raw := s.ledger.unresolved()
	out := make([]ReceiptView, 0, len(raw))
	for _, r := range raw {
		out = append(out, ReceiptView{
			Fingerprint: r.Fingerprint,
			State:       r.State,
			Network:     r.Network,
			Scheme:      r.Requirements.Scheme,
			Amount:      r.Requirements.Amount,
			Asset:       r.Requirements.Asset,
			Payer:       r.Payer,
			Started:     r.Started,
			NeedsHash:   chain(r.Network) == "stellar",
		})
	}
	return out
}

func isHex64(v string) bool {
	if len(v) != 64 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ReconcileOnline performs zero-downtime operator reconciliation against final
// on-chain state while Concert is live. It asks the in-process gateway to run
// read-only finality checks (serialized under the per-network settlement mutex)
// and, once finality is confirmed, marks the receipt settled in fastlane.jsonl
// so the payer's session immediately regains fast-lane eligibility.
func (s *Service) ReconcileOnline(ctx context.Context, fingerprint, stellarHash string) (Settlement, error) {
	var none Settlement
	if s == nil || s.ledger == nil {
		return none, errors.New("fast lane is not enabled")
	}
	fp := strings.ToLower(strings.TrimSpace(fingerprint))
	stellarHash = strings.TrimSpace(stellarHash)
	if !isHex64(fp) {
		return none, errors.New("invalid payment fingerprint: expected 64 lowercase hex characters")
	}
	rec, ok := s.ledger.fingerprint(fp)
	if !ok {
		return none, errors.New("receipt not found")
	}
	if rec.State == "settled" && rec.Response != nil {
		return *rec.Response, nil
	}
	if chain(rec.Network) == "stellar" && stellarHash == "" {
		return none, errors.New("stellar reconciliation requires the sponsor transaction hash")
	}

	s.mu.Lock()
	if s.active[rec.Session] {
		s.mu.Unlock()
		return none, errors.New("payment request currently in progress for this session; retry shortly")
	}
	s.active[rec.Session] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.active, rec.Session)
		s.mu.Unlock()
	}()

	// Re-read after acquiring the session slot in case an in-flight settle just finished.
	rec, ok = s.ledger.fingerprint(fp)
	if !ok {
		return none, errors.New("receipt not found")
	}
	if rec.State == "settled" && rec.Response != nil {
		return *rec.Response, nil
	}

	reqBody, err := json.Marshal(map[string]string{
		"id":           fp,
		"stellar_hash": stellarHash,
	})
	if err != nil {
		return none, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	rawRes, err := s.gateway.Handle(callCtx, "/reconcile", reqBody)
	if err != nil {
		return none, err
	}
	b, err := json.Marshal(rawRes)
	if err != nil {
		return none, errors.New("invalid reconciliation response")
	}
	var settled Settlement
	if err := json.Unmarshal(b, &settled); err != nil {
		return none, errors.New("invalid reconciliation JSON")
	}
	if !settled.Success || settled.Transaction == "" || settled.Network != rec.Network || settled.Payer != rec.Payer {
		return none, errors.New("reconciliation result did not match receipt")
	}

	rec.State = "settled"
	rec.Transaction = settled.Transaction
	rec.Settled = s.now().UTC()
	rec.Expires = rec.Settled.Add(time.Duration(s.cfg.PassSeconds) * time.Second)
	rec.Response = &settled
	if err := s.ledger.write(rec); err != nil {
		return none, err
	}
	s.checkCapacityWarn()
	return settled, nil
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
	if c.EffectivePolicyMode() == PolicyModeWebhook && c.PolicyURL != "" && len(policyToken) < 32 {
		return nil, errors.New("CONCERT_POLICY_TOKEN must be at least 32 bytes")
	}
	l, err := openLedger(dir, c.MaxRecords)
	if err != nil {
		return nil, err
	}
	s := &Service{cfg: c, key: key, gateway: gw, policyToken: policyToken, ledger: l,
		// Every call sets its own deadline: settlement may legitimately outlast
		// an ordinary verification request.
		http:             &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		active:           map[string]bool{},
		challenges:       map[string]challenge{},
		directChallenges: map[string]directChallenge{},
		nfts:             map[string]nftLease{},
		revoked:          map[string]time.Time{},
		limits:           newRateLimiter(maxRateEntries, postsPerMinute, time.Minute),
		work:             make(chan struct{}, 32),
		now:              time.Now}
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
func (s *Service) Config() Config { return s.currentConfig() }
func (s *Service) Summary() map[string]any {
	cfg := s.currentConfig()
	v := s.ledger.summary()
	v["enabled"] = cfg.Enabled
	v["origin"] = cfg.Origin
	v["test_mode"] = cfg.TestMode
	v["policy_mode"] = cfg.EffectivePolicyMode()
	v["policy_url"] = cfg.PolicyURL
	v["policy_blocklist_file"] = cfg.PolicyBlocklistFile
	v["allow_unscreened_mainnet"] = cfg.AllowUnscreenedMainnet
	v["merchant"] = cfg.Merchant
	v["terms_url"] = cfg.TermsURL
	v["privacy_url"] = cfg.PrivacyURL
	v["refund_url"] = cfg.RefundURL
	v["offers"] = cfg.Offers
	v["collections"] = cfg.Collections
	v["token_gates"] = cfg.TokenGates
	v["verify_addresses"] = cfg.VerifyAddresses
	v["pass_seconds"] = cfg.PassSeconds
	v["pass_idle_seconds"] = cfg.PassIdleSeconds
	v["pass_max_seconds"] = cfg.PassMaxSeconds
	v["pass_sliding"] = cfg.IsSliding()
	v["nft_pass_seconds"] = cfg.NFTPassSeconds
	v["direct_pay_enabled"] = cfg.IsDirectPayEnabled()
	v["direct_challenge_seconds"] = cfg.DirectChallengeSeconds
	v["unresolved"] = s.UnresolvedReceipts()
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

// SessionID returns the stable session ID carried by the Concert-Session
// header, when it holds a valid, unexpired token. It reads only the header,
// never the concert_fastlane cookie: software that waits in line sends the
// header, while a browser carries the cookie and keeps the cookie flow.
// The ID is the one receipts are stored under, and survives renewal. Cost:
// one header read and one HMAC check. Safe for concurrent use.
func (s *Service) SessionID(r *http.Request) (string, bool) {
	token := r.Header.Get(SessionHeader)
	if token == "" {
		return "", false
	}
	nonce, _, ok := s.parseToken(token)
	if !ok {
		return "", false
	}
	return digest([]byte("session/" + nonce)), true
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
	return s.limits.allow(key, now)
}

// Eligible reads a durable, unexpired grant (or valid cross-edge pass cookie).
// Bans and the bounded priority pool still run in Concert.
func (s *Service) Eligible(r *http.Request) bool {
	return s.EligibleAndRefresh(nil, r)
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
	return s.screenPolicy(ctx, r, s.currentConfig(), network, payer, action, req)
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
	if r.Method == http.MethodGet && path == "/status" {
		s.status(w, r)
		return
	}
	if r.Method != http.MethodPost {
		failure(w, 405, "method_not_allowed")
		return
	}
	cfg := s.currentConfig()
	if (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != cfg.Origin) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
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
	case "/nft/challenge":
		s.makeChallenge(w, r, id)
	case "/nft/verify":
		s.proveNFT(w, r, id)
	case "/direct/challenge":
		s.makeDirectChallenge(w, r, id)
	case "/direct/verify":
		s.verifyDirectChallenge(w, r, id)
	default:
		failure(w, 404, "not_found")
	}
}

// startSession issues a session, or renews a valid one under the same ID with
// a fresh expiry. Renewal preserves receipts and unresolved payments.
func (s *Service) startSession(w http.ResponseWriter, r *http.Request) {
	cfg := s.currentConfig()
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
	http.SetCookie(w, &http.Cookie{Name: Cookie, Value: t, Path: "/", MaxAge: int(sessionLifetime / time.Second), Secure: strings.HasPrefix(cfg.Origin, "https://"), HttpOnly: true, SameSite: http.SameSiteStrictMode})
	reply(w, 200, map[string]any{"session": t, "csrf": s.mac("csrf/" + t), "expires": exp.UTC()})
}
func (s *Service) status(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := s.session(r)
	if !ok {
		if ck, err := r.Cookie(PassCookie); err == nil {
			if p, valid := s.verifyPassCookieValue(ck.Value, s.now()); valid && !s.isRevoked("", p.PassID) {
				kind := "payment"
				if p.Kind == passKindNFT {
					kind = "nft"
				} else if p.Kind == passKindToken {
					kind = "token"
				}
				reply(w, 200, map[string]any{"eligible": s.ledger.healthy(), "kind": kind, "expires": p.IdleExp, "hard_expires": p.HardExp})
				return
			}
		}
		reply(w, 200, map[string]any{"eligible": false})
		return
	}
	if s.isRevoked(id, "") {
		reply(w, 200, map[string]any{"eligible": false, "revoked": true})
		return
	}
	paid, exists := s.ledger.get(id)
	if exists && paid.State == "settled" && s.now().Before(paid.Expires) {
		reply(w, 200, map[string]any{"eligible": s.ledger.healthy(), "state": paid.State, "kind": paid.Kind, "expires": paid.Expires, "receipt": paid.Response})
		return
	}
	s.mu.Lock()
	nft, hasNFT := s.nfts[id]
	s.mu.Unlock()
	if hasNFT && s.now().Before(nft.Expires) {
		kind := nft.Kind
		if kind == "" {
			kind = "nft"
		}
		reply(w, 200, map[string]any{"eligible": s.ledger.healthy(), "kind": kind, "expires": nft.Expires, "hard_expires": nft.HardExpires})
		return
	}
	if exists {
		reply(w, 200, map[string]any{"eligible": false, "state": paid.State, "kind": paid.Kind, "expires": paid.Expires, "receipt": paid.Response})
		return
	}
	reply(w, 200, map[string]any{"eligible": false})
}

func (s *Service) PublicConfig() map[string]any {
	cfg := s.currentConfig()
	offersOut := make([]map[string]any, 0, len(cfg.Offers))
	for _, o := range cfg.Offers {
		offersOut = append(offersOut, map[string]any{
			"label":               o.Label,
			"requirements":        o.Requirements,
			"display_amount":      o.EffectiveDisplayAmount(),
			"asset_symbol":        o.EffectiveSymbol(),
			"asset_decimals":      o.EffectiveDecimals(),
			"asset_type":          o.AssetType,
			"require_collections": o.RequireCollections,
			"require_token_gates": o.RequireTokenGates,
			"gate_mode":           o.GateMode,
		})
	}
	entryCols := make([]Collection, 0, len(cfg.Collections))
	for _, c := range cfg.Collections {
		if c.AllowsEntry() {
			entryCols = append(entryCols, c)
		}
	}
	entryTokens := make([]TokenGate, 0, len(cfg.TokenGates))
	for _, tg := range cfg.TokenGates {
		if tg.AllowsEntry() {
			entryTokens = append(entryTokens, tg)
		}
	}
	return map[string]any{
		"enabled":                  cfg.Enabled,
		"test_mode":                cfg.TestMode,
		"merchant":                 cfg.Merchant,
		"offers":                   offersOut,
		"collections":              entryCols,
		"all_collections":          cfg.Collections,
		"token_gates":              entryTokens,
		"all_token_gates":          cfg.TokenGates,
		"pass_seconds":             cfg.PassSeconds,
		"pass_idle_seconds":        cfg.PassIdleSeconds,
		"pass_max_seconds":         cfg.PassMaxSeconds,
		"pass_sliding":             cfg.IsSliding(),
		"nft_pass_seconds":         cfg.NFTPassSeconds,
		"direct_pay_enabled":       cfg.IsDirectPayEnabled(),
		"direct_challenge_seconds": cfg.DirectChallengeSeconds,
		"terms_url":                cfg.TermsURL,
		"privacy_url":              cfg.PrivacyURL,
		"refund_url":               cfg.RefundURL,
	}
}

func (s *Service) prepareSOL(w http.ResponseWriter, r *http.Request) {
	cfg := s.currentConfig()
	var in struct {
		Network string `json:"network"`
		Address string `json:"address"`
		Asset   string `json:"asset"`
	}
	if decode(r, &in) != nil || !solAddress.MatchString(in.Address) {
		failure(w, 400, "invalid_wallet_address")
		return
	}
	found := false
	for _, o := range cfg.Offers {
		if o.Requirements.Network != in.Network || chain(o.Requirements.Network) != "solana" {
			continue
		}
		if in.Asset == "" || o.Requirements.Asset == in.Asset {
			found = true
			if in.Asset == "" {
				in.Asset = o.Requirements.Asset
			}
			break
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
	cfg := s.currentConfig()
	accepts := make([]Requirements, 0, len(cfg.Offers))
	for _, o := range cfg.Offers {
		accepts = append(accepts, o.Requirements)
	}
	if len(accepts) == 0 {
		failure(w, 404, "payments_disabled")
		return
	}
	body := map[string]any{"x402Version": 2, "resource": Resource{URL: cfg.Origin + Prefix + "/payment", Description: fmt.Sprintf("%d seconds of Concert fast-lane eligibility; capacity limits apply", cfg.PassSeconds), MimeType: "application/json"}, "accepts": accepts}
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
	cfg := s.currentConfig()
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
	if p.Resource != nil && p.Resource.URL != cfg.Origin+Prefix+"/payment" {
		failure(w, 400, "wrong_resource")
		return
	}
	var matchedOffer Offer
	var req Requirements
	found := false
	for _, o := range cfg.Offers {
		if same(p.Accepted, o.Requirements) {
			matchedOffer = o
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
		// Enforce NFT / Token-Trustline purchase prerequisites against v.Payer BEFORE charging!
		if len(matchedOffer.RequireCollections) > 0 || len(matchedOffer.RequireTokenGates) > 0 {
			gateOK, _, gerr := s.checkGatesForWallet(r.Context(), cfg, v.Payer, matchedOffer.RequireCollections, matchedOffer.RequireTokenGates, matchedOffer.GateMode, "")
			if gerr != nil {
				failure(w, 503, "gate_check_unavailable")
				return
			}
			if !gateOK {
				failure(w, 403, "wallet_does_not_meet_purchase_requirements")
				return
			}
		}
		policy, err := s.screenPolicy(r.Context(), r, cfg, req.Network, v.Payer, "payment", req)
		if err != nil {
			failure(w, 403, "policy_not_approved")
			return
		}
		x = Receipt{Session: id, Fingerprint: fp, State: "pending", Kind: "payment", Network: req.Network, Payer: v.Payer, Requirements: req, PolicyID: policy, Started: s.now()}
		if err = s.ledger.write(x); err != nil {
			failure(w, 409, "payment_reservation_failed")
			return
		}
		s.checkCapacityWarn()
	} else {
		// Retry only the identical authorization. Native chain replay protection
		// plus the gateway's durable settlement cache prevents another debit.
		if _, err := s.screenPolicy(r.Context(), r, cfg, req.Network, x.Payer, "payment_retry", req); err != nil {
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
		s.mu.Lock()
		cb := s.onUnknown
		s.mu.Unlock()
		if cb != nil {
			cb(x.Network, x.Session)
		}
		failure(w, 503, "settlement_unresolved_retry_identical_payment_do_not_pay_again")
		return
	}
	now := s.now()
	idleExp, hardExp := s.grantWindow(cfg, passKindPayment, now)
	x.State = "settled"
	x.Transaction = settled.Transaction
	x.Settled = now
	x.Expires = idleExp
	x.Response = &settled
	if e = s.ledger.write(x); e != nil {
		failure(w, 503, "receipt_not_saved_contact_merchant_do_not_pay_again")
		return
	}
	if r.Header.Get(SessionHeader) == "" {
		s.setPassCookie(w, cfg, id, passKindPayment, now, idleExp, hardExp, "")
	}
	s.receipt(w, x)
}

func (s *Service) makeChallenge(w http.ResponseWriter, r *http.Request, id string) {
	cfg := s.currentConfig()
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
	for _, x := range cfg.Collections {
		if x.ID == in.Rule && x.AllowsEntry() {
			rule = x
			found = true
		}
	}
	if !found {
		failure(w, 400, "unknown_collection_rule")
		return
	}
	// Solana now auto-scans the wallet's NFTs when token_id is empty, while still
	// validating optional explicit mint addresses.
	switch chain(rule.Network) {
	case "solana":
		if in.Token != "" && !solAddress.MatchString(in.Token) {
			failure(w, 400, "invalid_nft_mint")
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
	msg := fmt.Sprintf("Concert NFT admission v1\nOrigin: %s\nNetwork: %s\nWallet: %s\nCollection: %s\nToken: %s\nSession: %s\nNonce: %s\nIssued: %s\nExpires: %s\nPurpose: prove wallet control for a short fast-lane lease. No payment or transaction authorization.", cfg.Origin, rule.Network, in.Address, rule.Collection, in.Token, id, nonce, now.UTC().Format(time.RFC3339), exp.UTC().Format(time.RFC3339))
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
	cfg := s.currentConfig()
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
	err := s.gatewayCall(r.Context(), callTimeout, "/nft/verify", map[string]any{"network": ch.Rule.Network, "address": ch.Address, "collection": ch.Rule.Collection, "issuer": ch.Rule.Issuer, "token_id": ch.Token, "message": ch.Message, "signature": in.Signature, "public_key": in.PublicKey}, &proof)
	if err != nil {
		failure(w, 503, "nft_verification_unavailable")
		return
	}
	if !proof.Valid || proof.Owner != ch.Address || proof.Network != ch.Rule.Network || proof.Collection != ch.Rule.Collection || (ch.Token != "" && proof.Token != ch.Token) {
		failure(w, 403, "ownership_not_verified")
		return
	}
	if _, err = s.screenPolicy(r.Context(), r, cfg, ch.Rule.Network, ch.Address, "nft", Requirements{}); err != nil {
		failure(w, 403, "policy_not_approved")
		return
	}
	now := s.now()
	idleExp, hardExp := s.grantWindow(cfg, passKindNFT, now)
	s.mu.Lock()
	if len(s.nfts) >= 10000 {
		s.mu.Unlock()
		failure(w, 503, "lease_capacity")
		return
	}
	s.nfts[id] = nftLease{Network: ch.Rule.Network, Payer: ch.Address, Rule: ch.Rule.ID, Kind: "nft", Issued: now, Expires: idleExp, HardExpires: hardExp}
	s.mu.Unlock()
	if r.Header.Get(SessionHeader) == "" {
		s.setPassCookie(w, cfg, id, passKindNFT, now, idleExp, hardExp, "")
	}
	reply(w, 200, map[string]any{"eligible": true, "kind": "nft", "expires": idleExp, "hard_expires": hardExp, "token_id": proof.Token})
}
