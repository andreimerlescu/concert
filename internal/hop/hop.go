// Package hop is Concert's trust chain between an edge instance and the leaf
// instances behind it.
//
// An edge Concert runs the waiting room, the fast lane and every browser
// cookie. When it forwards a request it has admitted, it signs a Claim into
// the Concert-Hop header: who the client is, the rank and payment status the
// edge established, and what class of request it is. A leaf Concert that
// verifies the claim does not queue, issue passes or re-check payment for
// that request; it only enforces its own host capacity and bans. Requests
// that reach a leaf without a valid claim (the public reaching i-01 directly)
// get the leaf's full, ordinary handling.
//
// The claim is bound to the request's method and URI and to a timestamp, and
// signed with HMAC-SHA256 under a key derived from CONCERT_HOP_SECRET. It
// does not cover the request body or the Host header: a load balancer between
// the tiers may rewrite Host, and bodies are streamed. Control-plane requests
// (state and ban sync) also bind a SHA-256 of their body.
//
// A captured header can be replayed for the same method and URI until it
// leaves the skew window, so the link between tiers must be private or TLS
// (see -upstream-ca and the mTLS flags), and leaves accept claims only from
// the peers listed in -hop-peers.
package hop

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Header names used between tiers. None of them ever reaches a browser or
// the application: the edge strips them from responses, the leaf from
// requests.
const (
	// Header carries the signed claim from edge to leaf.
	Header = "Concert-Hop"
	// BackpressureHeader marks a leaf response that refused a hop request
	// for capacity before anything was sent to the application, so the edge
	// may retry it on another leaf.
	BackpressureHeader = "Concert-Backpressure"
	// NodeHeader names the leaf that answered, for the edge's accounting.
	NodeHeader = "Concert-Hop-Node"
)

// MinSecretLen is the shortest CONCERT_HOP_SECRET accepted.
const MinSecretLen = 32

// DefaultMaxSkew is how far a claim's timestamp may be from the verifier's
// clock, in either direction.
const DefaultMaxSkew = 30 * time.Second

// maxHeaderLen bounds the work a malformed header can cause.
const maxHeaderLen = 512

// maxRank is the highest rank a claim can carry (Concert's staff is 6;
// 7 is reserved).
const maxRank = 7

// Class says which of Concert's tiers admitted the request at the edge.
type Class uint8

const (
	ClassPage    Class = iota + 1 // admitted through the room or the priority lane
	ClassAsset                    // asset tier (private or public)
	ClassStream                   // WebSocket or SSE path
	ClassBypass                   // bypass path
	ClassControl                  // edge-to-leaf control plane
)

var classNames = [...]string{"", "page", "asset", "stream", "bypass", "ctl"}

func (c Class) String() string {
	if int(c) < len(classNames) && c != 0 {
		return classNames[c]
	}
	return "invalid"
}

// ParseClass is the inverse of Class.String.
func ParseClass(s string) (Class, bool) {
	for i := 1; i < len(classNames); i++ {
		if classNames[i] == s {
			return Class(i), true
		}
	}
	return 0, false
}

// Claim is what the edge asserts about a request it forwards.
type Claim struct {
	Edge   string     // the signing edge's node ID
	Issued time.Time  // when the edge signed it (millisecond precision)
	Client netip.Addr // the client address the edge resolved
	Rank   uint8      // Concert-Priority rank at the edge, 0 guest to 6 staff
	Paid   bool       // the edge's fast lane found this client eligible
	Class  Class
	Proto  string // client protocol family seen at the edge: "h1", "h2" or ""
	Nonce  string // optional single-use lowercase hex nonce (16-32 chars)
}

// Errors returned by Verify. Callers treat every one as "no claim".
var (
	ErrMissing       = errors.New("hop: no claim")
	ErrMalformed     = errors.New("hop: malformed claim")
	ErrSignature     = errors.New("hop: bad signature")
	ErrSkew          = errors.New("hop: claim outside the clock skew window")
	ErrReplay        = errors.New("hop: replayed claim")
	ErrNonceRequired = errors.New("hop: claim missing nonce")
)

// ValidNodeID reports whether id can name a node: 1 to 32 characters from
// [A-Za-z0-9._-].
func ValidNodeID(id string) bool {
	if id == "" || len(id) > 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func deriveKey(secret []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("concert-hop key v1"))
	return m.Sum(nil)
}

// BodyHash is the digest control-plane requests bind: lowercase hex SHA-256.
func BodyHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Signer signs claims for one edge. Safe for concurrent use.
type Signer struct {
	key  []byte
	edge string
	salt uint64
	seq  atomic.Uint64
	now  func() time.Time
}

// NewSigner returns a signer for edge using secret.
func NewSigner(secret []byte, edge string) (*Signer, error) {
	if len(secret) < MinSecretLen {
		return nil, fmt.Errorf("hop: secret must be at least %d bytes", MinSecretLen)
	}
	if !ValidNodeID(edge) {
		return nil, fmt.Errorf("hop: invalid node id %q", edge)
	}
	var rb [8]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return nil, fmt.Errorf("hop: nonce salt: %w", err)
	}
	return &Signer{
		key:  deriveKey(secret),
		edge: edge,
		salt: binary.BigEndian.Uint64(rb[:]),
		now:  time.Now,
	}, nil
}

// Edge is the node ID the signer puts in every claim.
func (s *Signer) Edge() string { return s.edge }

// nextNonce generates a fast, unique 16-hex-char nonce per call by mixing a
// per-signer random salt with a monotonic atomic counter (zero syscalls on the
// hot path, unique across restarts).
func (s *Signer) nextNonce() string {
	z := (s.seq.Add(1) ^ s.salt) + 0x9e3779b97f4a7c15
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	z = z ^ (z >> 31)
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], z)
	var out [16]byte
	hex.Encode(out[:], raw[:])
	return string(out[:])
}

// Sign returns the Concert-Hop header value for c on a request with the
// given method and URI (path and query exactly as sent on the wire). Edge,
// Issued, and Nonce (when empty) are filled in by the signer. bodyHash is
// BodyHash of the body for control requests and "" otherwise.
func (s *Signer) Sign(c Claim, method, uri, bodyHash string) string {
	c.Edge = s.edge
	c.Issued = s.now()
	if c.Nonce == "" {
		c.Nonce = s.nextNonce()
	}
	fields := encodeFields(c)
	sig := mac(s.key, fields, method, uri, bodyHash)
	return fields + ";s=" + base64.RawURLEncoding.EncodeToString(sig)
}

// encodeFields writes every field except the signature, in fixed order.
func encodeFields(c Claim) string {
	var b strings.Builder
	b.Grow(160)
	b.WriteString("v=1;e=")
	b.WriteString(c.Edge)
	b.WriteString(";t=")
	b.WriteString(strconv.FormatInt(c.Issued.UnixMilli(), 10))
	b.WriteString(";c=")
	b.WriteString(c.Client.String())
	b.WriteString(";r=")
	b.WriteString(strconv.Itoa(int(c.Rank)))
	b.WriteString(";f=")
	if c.Paid {
		b.WriteByte('1')
	} else {
		b.WriteByte('0')
	}
	b.WriteString(";k=")
	b.WriteString(c.Class.String())
	b.WriteString(";p=")
	b.WriteString(c.Proto)
	if c.Nonce != "" {
		b.WriteString(";n=")
		b.WriteString(c.Nonce)
	}
	return b.String()
}

func mac(key []byte, fields, method, uri, bodyHash string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("concert-hop/v1\n"))
	m.Write([]byte(fields))
	m.Write([]byte{'\n'})
	m.Write([]byte(method))
	m.Write([]byte{'\n'})
	m.Write([]byte(uri))
	m.Write([]byte{'\n'})
	m.Write([]byte(bodyHash))
	return m.Sum(nil)
}

// Verifier checks claims. It accepts the current secret and, during a
// rotation, the previous one. Safe for concurrent use.
type Verifier struct {
	keys         [][]byte
	maxSkew      time.Duration
	now          func() time.Time
	replayGuard  atomic.Bool
	requireNonce atomic.Bool
	replay       *replayCache
}

// NewVerifier returns a verifier accepting claims signed with any of
// secrets (empty ones are ignored) whose timestamp is within maxSkew of now.
// maxSkew 0 means DefaultMaxSkew.
func NewVerifier(maxSkew time.Duration, secrets ...[]byte) (*Verifier, error) {
	if maxSkew <= 0 {
		maxSkew = DefaultMaxSkew
	}
	v := &Verifier{
		maxSkew: maxSkew,
		now:     time.Now,
		replay:  newReplayCache(),
	}
	for _, s := range secrets {
		if len(s) == 0 {
			continue
		}
		if len(s) < MinSecretLen {
			return nil, fmt.Errorf("hop: secret must be at least %d bytes", MinSecretLen)
		}
		v.keys = append(v.keys, deriveKey(s))
	}
	if len(v.keys) == 0 {
		return nil, errors.New("hop: no secret")
	}
	return v, nil
}

// SetReplayGuard enables or disables single-use nonce replay rejection and
// whether claims without an n= nonce are refused. Safe for concurrent use.
func (v *Verifier) SetReplayGuard(enabled, requireNonce bool) {
	v.replayGuard.Store(enabled)
	v.requireNonce.Store(requireNonce)
}

// Verify parses header and checks its signature against method, uri and
// bodyHash, its timestamp against the clock, and (when enabled) single-use
// replay protection on its nonce.
func (v *Verifier) Verify(header, method, uri, bodyHash string) (Claim, error) {
	if header == "" {
		return Claim{}, ErrMissing
	}
	c, fields, sig, err := parse(header)
	if err != nil {
		return Claim{}, err
	}
	ok := false
	for _, k := range v.keys {
		if hmac.Equal(sig, mac(k, fields, method, uri, bodyHash)) {
			ok = true
			break
		}
	}
	if !ok {
		return Claim{}, ErrSignature
	}
	now := v.now()
	d := now.Sub(c.Issued)
	if d < 0 {
		d = -d
	}
	if d > v.maxSkew {
		return Claim{}, ErrSkew
	}
	if v.requireNonce.Load() && c.Nonce == "" {
		return Claim{}, ErrNonceRequired
	}
	if v.replayGuard.Load() && c.Nonce != "" {
		ttlMs := (2 * v.maxSkew).Milliseconds()
		if v.replay.seenOrRecord(c.Edge, c.Nonce, now.UnixMilli(), ttlMs) {
			return Claim{}, ErrReplay
		}
	}
	return c, nil
}

func validNonce(s string) bool {
	if len(s) < 16 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// parse splits a header into its claim, the signed field string and the
// signature. It accepts exactly the canonical form Sign writes (with or
// without the optional trailing n= nonce): every key once, in order.
// Anything else is ErrMalformed.
func parse(h string) (Claim, string, []byte, error) {
	var c Claim
	if len(h) > maxHeaderLen {
		return c, "", nil, ErrMalformed
	}
	i := strings.LastIndex(h, ";s=")
	if i < 0 {
		return c, "", nil, ErrMalformed
	}
	fields := h[:i]
	sig, err := base64.RawURLEncoding.DecodeString(h[i+3:])
	if err != nil || len(sig) != sha256.Size {
		return c, "", nil, ErrMalformed
	}
	parts := strings.Split(fields, ";")
	keys := [...]string{"v", "e", "t", "c", "r", "f", "k", "p", "n"}
	if len(parts) != 8 && len(parts) != 9 {
		return c, "", nil, ErrMalformed
	}
	vals := make([]string, len(parts))
	for j, p := range parts {
		k, val, ok := strings.Cut(p, "=")
		if !ok || k != keys[j] {
			return c, "", nil, ErrMalformed
		}
		vals[j] = val
	}
	if vals[0] != "1" {
		return c, "", nil, ErrMalformed
	}
	if !ValidNodeID(vals[1]) {
		return c, "", nil, ErrMalformed
	}
	c.Edge = vals[1]
	ms, err := strconv.ParseInt(vals[2], 10, 64)
	if err != nil || ms <= 0 {
		return c, "", nil, ErrMalformed
	}
	c.Issued = time.UnixMilli(ms)
	if c.Client, err = netip.ParseAddr(vals[3]); err != nil || c.Client.Zone() != "" {
		return c, "", nil, ErrMalformed
	}
	r, err := strconv.Atoi(vals[4])
	if err != nil || r < 0 || r > maxRank || strconv.Itoa(r) != vals[4] {
		return c, "", nil, ErrMalformed
	}
	c.Rank = uint8(r)
	switch vals[5] {
	case "0":
	case "1":
		c.Paid = true
	default:
		return c, "", nil, ErrMalformed
	}
	var ok bool
	if c.Class, ok = ParseClass(vals[6]); !ok {
		return c, "", nil, ErrMalformed
	}
	switch vals[7] {
	case "", "h1", "h2":
		c.Proto = vals[7]
	default:
		return c, "", nil, ErrMalformed
	}
	if len(vals) == 9 {
		if !validNonce(vals[8]) {
			return c, "", nil, ErrMalformed
		}
		c.Nonce = vals[8]
	}
	// The signed string must be exactly what Sign would write for this
	// claim, so two encodings of one claim never both verify.
	if encodeFields(c) != fields {
		return c, "", nil, ErrMalformed
	}
	return c, fields, sig, nil
}
