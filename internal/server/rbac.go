package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Enterprise identity, RBAC, MFA (TOTP), SSO reverse-proxy integration,
// named/scoped API tokens, and file-based secret loading (_FILE pattern).

type rbacRole uint8

const (
	roleNone rbacRole = iota
	roleViewer
	roleOperator
	roleAdmin
)

func (r rbacRole) String() string {
	switch r {
	case roleViewer:
		return "viewer"
	case roleOperator:
		return "operator"
	case roleAdmin:
		return "admin"
	default:
		return "none"
	}
}

func parseRole(s string) (rbacRole, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "viewer", "readonly", "read-only", "read":
		return roleViewer, true
	case "operator", "ops", "editor":
		return roleOperator, true
	case "admin", "administrator", "superadmin":
		return roleAdmin, true
	default:
		return roleNone, false
	}
}

func (r rbacRole) allows(required rbacRole) bool {
	return r >= required && required > roleNone
}

type principal struct {
	Actor  string
	Role   rbacRole
	Source string // "password", "user", "sso", "token"
	IP     netip.Addr
}

func (p principal) label() string {
	if p.Actor == "" {
		if p.IP.IsValid() {
			return p.IP.String()
		}
		return "unknown"
	}
	if p.IP.IsValid() {
		return fmt.Sprintf("%s (%s) @ %s", p.Actor, p.Role, p.IP)
	}
	return fmt.Sprintf("%s (%s)", p.Actor, p.Role)
}

// ─── file-backed secrets (_FILE convention) ──────────────────────────────────

// envOrFile resolves a secret from <name>_FILE first (for Kubernetes Secrets,
// Docker Secrets, and Vault Agent sidecars), falling back to <name>, then def.
func envOrFile(name, def string) string {
	if filePath := strings.TrimSpace(os.Getenv(name + "_FILE")); filePath != "" {
		if info, err := os.Stat(filePath); err == nil && info.Mode().Perm()&0o077 != 0 {
			log.Printf("security: secret file %s (%s_FILE) has overly permissive mode %04o; recommend 0600 or 0400",
				filePath, name, info.Mode().Perm())
		}
		b, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("security: failed to read %s_FILE (%s): %v", name, filePath, err)
		} else {
			return strings.TrimRight(string(b), "\r\n")
		}
	}
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

// envLookupForGateway wraps envOrFile so chain sponsor keys can also be loaded
// via CONCERT_STELLAR_FEE_SECRET_FILE and CONCERT_HEDERA_FEE_SECRET_FILE.
func envLookupForGateway(name string) string {
	return envOrFile(name, "")
}

// ─── multi-user portal authentication (Argon2id + optional TOTP MFA) ─────────

type portalUserSpec struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"` // $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>
	Role         string `json:"role"`          // viewer | operator | admin
	TOTPSecret   string `json:"totp_secret,omitempty"`
	Disabled     bool   `json:"disabled,omitempty"`
}

type portalUser struct {
	username   string
	role       rbacRole
	hash       string
	totpSecret []byte
}

type userDirectory struct {
	users map[string]*portalUser
}

func loadPortalUsers(raw string) (*userDirectory, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var data []byte
	if strings.HasPrefix(raw, "@") {
		p := strings.TrimSpace(strings.TrimPrefix(raw, "@"))
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("CONCERT_PORTAL_USERS file %s: %w", p, err)
		}
		data = b
	} else {
		data = []byte(raw)
	}
	var specs []portalUserSpec
	if err := json.Unmarshal(data, &specs); err != nil {
		return nil, fmt.Errorf("CONCERT_PORTAL_USERS invalid JSON: %w", err)
	}
	dir := &userDirectory{users: make(map[string]*portalUser, len(specs))}
	for i, s := range specs {
		u := strings.ToLower(strings.TrimSpace(s.Username))
		if u == "" || strings.ContainsAny(u, " \t\r\n:") {
			return nil, fmt.Errorf("CONCERT_PORTAL_USERS[%d]: invalid username %q", i, s.Username)
		}
		if s.Disabled {
			continue
		}
		role, ok := parseRole(s.Role)
		if !ok {
			return nil, fmt.Errorf("CONCERT_PORTAL_USERS[%d] (%s): invalid role %q (use viewer, operator, or admin)", i, u, s.Role)
		}
		if !strings.HasPrefix(s.PasswordHash, "$argon2id$") {
			return nil, fmt.Errorf("CONCERT_PORTAL_USERS[%d] (%s): password_hash must be an Argon2id PHC string ($argon2id$...)", i, u)
		}
		if _, _, _, _, _, err := parseArgon2idHash(s.PasswordHash); err != nil {
			return nil, fmt.Errorf("CONCERT_PORTAL_USERS[%d] (%s): %w", i, u, err)
		}
		var totp []byte
		if ts := strings.TrimSpace(s.TOTPSecret); ts != "" {
			cleaned := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(ts, " ", ""), "-", ""))
			dec, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(cleaned, "="))
			if err != nil || len(dec) < 10 {
				return nil, fmt.Errorf("CONCERT_PORTAL_USERS[%d] (%s): invalid base32 totp_secret", i, u)
			}
			totp = dec
		}
		if _, dup := dir.users[u]; dup {
			return nil, fmt.Errorf("CONCERT_PORTAL_USERS: duplicate username %q", u)
		}
		dir.users[u] = &portalUser{
			username:   u,
			role:       role,
			hash:       s.PasswordHash,
			totpSecret: totp,
		}
	}
	return dir, nil
}

func (d *userDirectory) authenticate(username, password, totpCode string, now time.Time) (*portalUser, bool) {
	if d == nil {
		return nil, false
	}
	u := d.users[strings.ToLower(strings.TrimSpace(username))]
	if u == nil {
		// Burn constant time against a dummy hash to resist username enumeration.
		_ = verifyArgon2id(password, dummyArgon2idHash)
		return nil, false
	}
	if !verifyArgon2id(password, u.hash) {
		return nil, false
	}
	if len(u.totpSecret) > 0 {
		if !verifyTOTP(u.totpSecret, totpCode, now) {
			return nil, false
		}
	}
	return u, true
}

func (d *userDirectory) count() int {
	if d == nil {
		return 0
	}
	return len(d.users)
}

// ─── Argon2id password hashing (OWASP recommended parameters) ──────────────────

const (
	argonMemory  = 64 * 1024 // 64 MiB
	argonTime    = 3
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

var dummyArgon2idHash = func() string {
	h, _ := hashArgon2id("concert-dummy-timing-guard")
	return h
}()

func hashArgon2id(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

func parseArgon2idHash(encoded string) (memory, iterations uint32, threads uint8, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, errors.New("malformed argon2id hash")
	}
	var ver int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &ver); err != nil || ver != argon2.Version {
		return 0, 0, 0, nil, nil, errors.New("unsupported argon2id version")
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m < 8192 || t < 1 || p < 1 {
		return 0, 0, 0, nil, nil, errors.New("invalid argon2id parameters")
	}
	s, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(s) < 8 {
		return 0, 0, 0, nil, nil, errors.New("invalid argon2id salt")
	}
	k, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(k) < 16 {
		return 0, 0, 0, nil, nil, errors.New("invalid argon2id digest")
	}
	return m, t, p, s, k, nil
}

func verifyArgon2id(password, encoded string) bool {
	m, t, p, salt, want, err := parseArgon2idHash(encoded)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ─── RFC 6238 TOTP MFA (6-digit, 30s period, ±1 step clock skew) ─────────────

func totpCodeAt(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) |
		(uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) |
		uint32(sum[off+3])
	return fmt.Sprintf("%06d", code%1000000)
}

func verifyTOTP(secret []byte, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	step := now.Unix() / 30
	for delta := int64(-1); delta <= 1; delta++ {
		want := totpCodeAt(secret, step+delta)
		if subtle.ConstantTimeCompare([]byte(code), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

// ─── named, role-scoped API tokens ───────────────────────────────────────────

type apiTokenSpec struct {
	Name  string `json:"name"`
	Role  string `json:"role"`
	Token string `json:"token"`
}

type apiTokenEntry struct {
	name   string
	role   rbacRole
	digest [sha256.Size]byte
}

type apiTokenStore struct {
	tokens []apiTokenEntry
}

func loadAPITokens(legacyToken, multiSpec string) (*apiTokenStore, error) {
	store := &apiTokenStore{}
	if legacyToken != "" {
		store.tokens = append(store.tokens, apiTokenEntry{
			name:   "admin-token",
			role:   roleAdmin,
			digest: sha256.Sum256([]byte(legacyToken)),
		})
	}
	multiSpec = strings.TrimSpace(multiSpec)
	if multiSpec == "" {
		return store, nil
	}
	var raw string
	if strings.HasPrefix(multiSpec, "@") {
		p := strings.TrimSpace(strings.TrimPrefix(multiSpec, "@"))
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("CONCERT_ADMIN_TOKENS file %s: %w", p, err)
		}
		raw = strings.TrimSpace(string(b))
	} else {
		raw = multiSpec
	}

	if strings.HasPrefix(raw, "[") {
		var specs []apiTokenSpec
		if err := json.Unmarshal([]byte(raw), &specs); err != nil {
			return nil, fmt.Errorf("CONCERT_ADMIN_TOKENS invalid JSON: %w", err)
		}
		for i, s := range specs {
			if err := store.add(s.Name, s.Role, s.Token); err != nil {
				return nil, fmt.Errorf("CONCERT_ADMIN_TOKENS[%d]: %w", i, err)
			}
		}
		return store, nil
	}

	// Compact format: name:role:token,name2:role2:token2
	for i, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.SplitN(part, ":", 3)
		if len(fields) != 3 {
			return nil, fmt.Errorf("CONCERT_ADMIN_TOKENS[%d]: expected name:role:token", i)
		}
		if err := store.add(fields[0], fields[1], fields[2]); err != nil {
			return nil, fmt.Errorf("CONCERT_ADMIN_TOKENS[%d]: %w", i, err)
		}
	}
	return store, nil
}

func (s *apiTokenStore) add(name, roleStr, tok string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("token name is required")
	}
	role, ok := parseRole(roleStr)
	if !ok {
		return fmt.Errorf("invalid role %q (use viewer, operator, or admin)", roleStr)
	}
	if len(tok) < 16 {
		return fmt.Errorf("token %q must be at least 16 characters", name)
	}
	s.tokens = append(s.tokens, apiTokenEntry{
		name:   name,
		role:   role,
		digest: sha256.Sum256([]byte(tok)),
	})
	return nil
}

func (s *apiTokenStore) enabled() bool {
	return s != nil && len(s.tokens) > 0
}

func (s *apiTokenStore) authenticate(bearer string) (principal, bool) {
	if s == nil || len(s.tokens) == 0 || bearer == "" {
		return principal{}, false
	}
	got := sha256.Sum256([]byte(bearer))
	var matched *apiTokenEntry
	// Constant-time sweep across all configured tokens.
	for i := range s.tokens {
		if subtle.ConstantTimeCompare(got[:], s.tokens[i].digest[:]) == 1 {
			matched = &s.tokens[i]
		}
	}
	if matched == nil {
		return principal{}, false
	}
	return principal{
		Actor:  "api:" + matched.name,
		Role:   matched.role,
		Source: "token",
	}, true
}

// ─── Trusted Identity-Proxy SSO header authentication for the Admin Portal ───

func resolveSSOPrincipal(r *http.Request, pc portalConfig, peer netip.Addr) (principal, bool) {
	if pc.ssoHeader == "" || !peer.IsValid() || len(pc.trustedProxies) == 0 {
		return principal{}, false
	}
	if !containsAddr(pc.trustedProxies, peer) {
		return principal{}, false
	}
	user := strings.TrimSpace(r.Header.Get(pc.ssoHeader))
	if user == "" || len(user) > 256 || strings.ContainsAny(user, "\r\n") {
		return principal{}, false
	}
	role := pc.ssoDefaultRoleParsed
	if pc.ssoRoleHeader != "" {
		if rawRole := strings.TrimSpace(r.Header.Get(pc.ssoRoleHeader)); rawRole != "" {
			role = highestRoleFromHeader(rawRole, role)
		}
	}
	if role == roleNone {
		return principal{}, false
	}
	return principal{
		Actor:  "sso:" + user,
		Role:   role,
		Source: "sso",
		IP:     peer,
	}, true
}

// highestRoleFromHeader parses comma/space-separated roles or group names
// (e.g. "concert-admin, viewers" or "operator") and returns the highest match.
func highestRoleFromHeader(val string, fallback rbacRole) rbacRole {
	best := roleNone
	fields := strings.FieldsFunc(val, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t'
	})
	for _, f := range fields {
		norm := strings.ToLower(strings.TrimSpace(f))
		norm = strings.TrimPrefix(norm, "concert-")
		norm = strings.TrimPrefix(norm, "concert_")
		norm = strings.TrimPrefix(norm, "role:")
		if r, ok := parseRole(norm); ok && r > best {
			best = r
		}
	}
	if best == roleNone {
		return fallback
	}
	return best
}

// runHashPassword is "concert hash-password" to generate an Argon2id PHC hash
// for CONCERT_PORTAL_USERS without external tools.
func runHashPassword(args []string, stdout io.Writer) error {
	if len(args) != 1 || len(args[0]) < minPortalPassLen {
		return fmt.Errorf("usage: concert hash-password <password-at-least-%d-chars>", minPortalPassLen)
	}
	h, err := hashArgon2id(args[0])
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, h)
	return nil
}

// parseDurationOrSeconds is a tiny helper for enterprise flags.
func parseIntAtLeast(s string, minVal int) (int, error) {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || v < minVal {
		return 0, fmt.Errorf("must be an integer >= %d", minVal)
	}
	return v, nil
}
