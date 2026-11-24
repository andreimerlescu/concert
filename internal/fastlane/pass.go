package fastlane

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

const (
	// PassCookie carries a stateless HMAC-signed fast-lane pass recognized across
	// all active-active edges sharing CONCERT_ADMIT_SECRET (and _PREV during rotation).
	PassCookie = "concert_fastlane_pass"

	passCookieVersion = byte(1)
	passKindPayment   = byte(1)
	passKindNFT       = byte(2)
	passKindToken     = byte(3)

	// Wire layout: ver(1) | passID(16) | sessionHash(16) | kind(1) | issued(8) | idleExp(8) | hardExp(8) | hmac(16) = 74 bytes
	passCookieBodyLen = 1 + 16 + 16 + 1 + 8 + 8 + 8
	passCookieMACLen  = 16
	passCookieRawLen  = passCookieBodyLen + passCookieMACLen
)

type parsedPass struct {
	PassID      string
	SessionHash [16]byte
	Kind        byte
	Issued      time.Time
	IdleExp     time.Time
	HardExp     time.Time
	Rotated     bool
}

func derivePassKey(secret []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("concert/fastlane/pass-cookie/v1"))
	return m.Sum(nil)
}

func sessionHash16(sessionID string) [16]byte {
	h := sha256.Sum256([]byte("concert/fastlane/session-bind/" + sessionID))
	var out [16]byte
	copy(out[:], h[:16])
	return out
}

func (s *Service) mintPassCookieValue(passIDBytes [16]byte, sessHash [16]byte, kind byte, issued, idleExp, hardExp time.Time) string {
	var buf [passCookieRawLen]byte
	buf[0] = passCookieVersion
	copy(buf[1:17], passIDBytes[:])
	copy(buf[17:33], sessHash[:])
	buf[33] = kind
	binary.BigEndian.PutUint64(buf[34:42], uint64(issued.Unix()))
	binary.BigEndian.PutUint64(buf[42:50], uint64(idleExp.Unix()))
	binary.BigEndian.PutUint64(buf[50:58], uint64(hardExp.Unix()))
	mac := hmac.New(sha256.New, derivePassKey(s.key))
	mac.Write(buf[:passCookieBodyLen])
	copy(buf[passCookieBodyLen:], mac.Sum(nil)[:passCookieMACLen])
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

func (s *Service) verifyPassCookieValue(val string, now time.Time) (parsedPass, bool) {
	var out parsedPass
	if val == "" || base64.RawURLEncoding.DecodedLen(len(val)) != passCookieRawLen {
		return out, false
	}
	var buf [passCookieRawLen]byte
	n, err := base64.RawURLEncoding.Decode(buf[:], []byte(val))
	if err != nil || n != passCookieRawLen || buf[0] != passCookieVersion {
		return out, false
	}
	verifyWith := func(secret []byte) bool {
		if len(secret) == 0 {
			return false
		}
		mac := hmac.New(sha256.New, derivePassKey(secret))
		mac.Write(buf[:passCookieBodyLen])
		return hmac.Equal(buf[passCookieBodyLen:], mac.Sum(nil)[:passCookieMACLen])
	}
	rotated := false
	if !verifyWith(s.key) {
		s.mu.Lock()
		prev := s.prevKey
		s.mu.Unlock()
		if !verifyWith(prev) {
			return out, false
		}
		rotated = true
	}
	idleExp := time.Unix(int64(binary.BigEndian.Uint64(buf[42:50])), 0)
	hardExp := time.Unix(int64(binary.BigEndian.Uint64(buf[50:58])), 0)
	if !now.Before(idleExp) || !now.Before(hardExp) {
		return out, false
	}
	out.PassID = hex.EncodeToString(buf[1:17])
	copy(out.SessionHash[:], buf[17:33])
	out.Kind = buf[33]
	out.Issued = time.Unix(int64(binary.BigEndian.Uint64(buf[34:42])), 0)
	out.IdleExp = idleExp
	out.HardExp = hardExp
	out.Rotated = rotated
	return out, true
}

func (s *Service) setPassCookie(w http.ResponseWriter, cfg Config, sessionID string, kind byte, issued, idleExp, hardExp time.Time, existingPassID string) {
	if w == nil {
		return
	}
	var pid [16]byte
	if b, err := hex.DecodeString(existingPassID); err == nil && len(b) == 16 {
		copy(pid[:], b)
	} else {
		_, _ = rand.Read(pid[:])
	}
	sh := sessionHash16(sessionID)
	val := s.mintPassCookieValue(pid, sh, kind, issued, idleExp, hardExp)
	maxAge := int(hardExp.Sub(s.now()).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     PassCookie,
		Value:    val,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   strings.HasPrefix(cfg.Origin, "https://"),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) grantWindow(cfg Config, kind byte, now time.Time) (idleExp, hardExp time.Time) {
	idleSecs := cfg.PassIdleSeconds
	if kind == passKindNFT || kind == passKindToken {
		if cfg.NFTPassSeconds > 0 {
			idleSecs = cfg.NFTPassSeconds
		}
	} else if idleSecs <= 0 {
		idleSecs = cfg.PassSeconds
	}
	if idleSecs <= 0 {
		idleSecs = 300
	}
	maxSecs := cfg.PassMaxSeconds
	if maxSecs < idleSecs {
		maxSecs = idleSecs
	}
	if !cfg.IsSliding() {
		// Non-sliding mode: hard cap equals the single fixed window.
		if kind == passKindNFT || kind == passKindToken {
			return now.Add(time.Duration(cfg.NFTPassSeconds) * time.Second), now.Add(time.Duration(cfg.NFTPassSeconds) * time.Second)
		}
		return now.Add(time.Duration(cfg.PassSeconds) * time.Second), now.Add(time.Duration(cfg.PassSeconds) * time.Second)
	}
	return now.Add(time.Duration(idleSecs) * time.Second), now.Add(time.Duration(maxSecs) * time.Second)
}

func (s *Service) isRevoked(sessionID, passID string) bool {
	now := s.now()
	s.mu.Lock()
	var fn func(string) bool
	fn = s.revokedCheck
	for k, exp := range s.revoked {
		if !now.Before(exp) {
			delete(s.revoked, k)
		}
	}
	if sessionID != "" && !s.revoked[sessionID].IsZero() {
		s.mu.Unlock()
		return true
	}
	if passID != "" && !s.revoked[passID].IsZero() {
		s.mu.Unlock()
		return true
	}
	s.mu.Unlock()
	if fn != nil {
		if sessionID != "" && fn(sessionID) {
			return true
		}
		if passID != "" && fn(passID) {
			return true
		}
	}
	return false
}

// RevokeSession immediately invalidates a fast-lane session or pass ID in
// memory and notifies any configured cross-edge Redis hook.
func (s *Service) RevokeSession(target string) {
	if s == nil {
		return
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return
	}
	exp := s.now().Add(24 * time.Hour)
	s.mu.Lock()
	if s.revoked == nil {
		s.revoked = map[string]time.Time{}
	}
	s.revoked[target] = exp
	delete(s.nfts, target)
	pub := s.revokedPublish
	s.mu.Unlock()
	if pub != nil {
		pub(target, 24*time.Hour)
	}
}

// SetRevocationHooks attaches optional cross-edge revocation storage (e.g. Redis).
func (s *Service) SetRevocationHooks(check func(id string) bool, publish func(id string, ttl time.Duration)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.revokedCheck = check
	s.revokedPublish = publish
	s.mu.Unlock()
}

// SetPrevKey configures a previous admission secret for zero-downtime secret rotation.
func (s *Service) SetPrevKey(prev []byte) {
	if s == nil || len(prev) == 0 {
		return
	}
	s.mu.Lock()
	s.prevKey = append([]byte(nil), prev...)
	s.mu.Unlock()
}

// EligibleAndRefresh checks whether r holds an active fast-lane pass (either via
// stateless cross-edge HMAC pass cookie OR local ledger/NFT lease), enforces
// revocations, and transparently slides the idle expiry when sliding passes are
// enabled so active browsers never get kicked out while navigating or refreshing.
func (s *Service) EligibleAndRefresh(w http.ResponseWriter, r *http.Request) bool {
	if s == nil || !s.ledger.healthy() {
		return false
	}
	cfg := s.currentConfig()
	now := s.now()
	sessionID, _, _, hasSession := s.session(r)
	if hasSession && s.isRevoked(sessionID, "") {
		return false
	}

	// 1. Check stateless cross-edge pass cookie first (honored on every active-active edge!).
	if ck, err := r.Cookie(PassCookie); err == nil && ck.Value != "" {
		if p, ok := s.verifyPassCookieValue(ck.Value, now); ok {
			if s.isRevoked(sessionID, p.PassID) {
				return false
			}
			// If session cookie/header is present, bind-check it; otherwise stateless pass stands on its own.
			if !hasSession || p.SessionHash == sessionHash16(sessionID) {
				if w != nil && (p.Rotated || cfg.IsSliding()) {
					idleSecs := cfg.PassIdleSeconds
					if p.Kind == passKindNFT || p.Kind == passKindToken {
						idleSecs = cfg.NFTPassSeconds
					}
					if idleSecs <= 0 {
						idleSecs = cfg.PassSeconds
					}
					idleDur := time.Duration(idleSecs) * time.Second
					if p.Rotated || (cfg.IsSliding() && p.IdleExp.Sub(now) <= idleDur/2) {
						nextIdle := now.Add(idleDur)
						if nextIdle.After(p.HardExp) {
							nextIdle = p.HardExp
						}
						if nextIdle.After(p.IdleExp) || p.Rotated {
							bindID := sessionID
							if bindID == "" {
								// Preserve original session hash directly when sliding without session cookie.
								var pid [16]byte
								if b, err := hex.DecodeString(p.PassID); err == nil && len(b) == 16 {
									copy(pid[:], b)
								}
								val := s.mintPassCookieValue(pid, p.SessionHash, p.Kind, p.Issued, nextIdle, p.HardExp)
								maxAge := int(p.HardExp.Sub(now).Seconds())
								if maxAge < 1 {
									maxAge = 1
								}
								http.SetCookie(w, &http.Cookie{
									Name:     PassCookie,
									Value:    val,
									Path:     "/",
									MaxAge:   maxAge,
									Secure:   strings.HasPrefix(cfg.Origin, "https://"),
									HttpOnly: true,
									SameSite: http.SameSiteLaxMode,
								})
							} else {
								s.setPassCookie(w, cfg, bindID, p.Kind, p.Issued, nextIdle, p.HardExp, p.PassID)
							}
						}
					}
				}
				return true
			}
		}
	}

	if !hasSession {
		return false
	}

	// 2. Check local durable receipt ledger (covers agent Concert-Session headers & fresh payments).
	if x, ok := s.ledger.get(sessionID); ok && x.State == "settled" {
		if now.Before(x.Expires) {
			if cfg.IsSliding() {
				idleSecs := cfg.PassIdleSeconds
				if idleSecs <= 0 {
					idleSecs = cfg.PassSeconds
				}
				maxSecs := cfg.PassMaxSeconds
				if maxSecs < idleSecs {
					maxSecs = idleSecs
				}
				hardExp := x.Settled.Add(time.Duration(maxSecs) * time.Second)
				if hardExp.Before(x.Expires) {
					hardExp = x.Expires
				}
				idleDur := time.Duration(idleSecs) * time.Second
				if x.Expires.Sub(now) <= idleDur/2 && now.Before(hardExp) {
					nextIdle := now.Add(idleDur)
					if nextIdle.After(hardExp) {
						nextIdle = hardExp
					}
					s.ledger.slideExpiry(sessionID, nextIdle)
					x.Expires = nextIdle
				}
				if w != nil && r.Header.Get(SessionHeader) == "" {
					s.setPassCookie(w, cfg, sessionID, passKindPayment, x.Settled, x.Expires, hardExp, "")
				}
			}
			return true
		}
	}

	// 3. Check local NFT / token-balance grants.
	s.mu.Lock()
	nft, hasNFT := s.nfts[sessionID]
	if hasNFT && now.Before(nft.Expires) {
		if cfg.IsSliding() && now.Before(nft.HardExpires) {
			idleDur := time.Duration(cfg.NFTPassSeconds) * time.Second
			if nft.Expires.Sub(now) <= idleDur/2 {
				nextIdle := now.Add(idleDur)
				if nextIdle.After(nft.HardExpires) {
					nextIdle = nft.HardExpires
				}
				nft.Expires = nextIdle
				s.nfts[sessionID] = nft
			}
		}
		s.mu.Unlock()
		if w != nil && r.Header.Get(SessionHeader) == "" {
			kind := passKindNFT
			if nft.Kind == "token" {
				kind = passKindToken
			}
			hardExp := nft.HardExpires
			if hardExp.IsZero() {
				hardExp = nft.Expires
			}
			s.setPassCookie(w, cfg, sessionID, kind, nft.Issued, nft.Expires, hardExp, "")
		}
		return true
	}
	s.mu.Unlock()
	return false
}
