package server

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
)

//go:embed web/waiting.html web/waiting.css web/waiting.js web/busy.html web/busy.js
var waitingWeb embed.FS

func init() {
	b, err := waitingWeb.ReadFile("web/busy.html")
	if err != nil {
		panic("embedded web/busy.html missing: " + err.Error())
	}
	defaultBusyHTML = b
}

// Gin context keys shared between priorityGate (core) and edgeClaim (enterprise).
const (
	ctxHopRank = "concert.hop_rank"
	ctxHopPaid = "concert.hop_paid"
)

// Core edition types and constants shared by all Concert binaries (concert,
// wpconcert, econcert) without pulling in optional WordPress or Enterprise
// packages.

const (
	roleStandalone = "standalone"
	roleEdge       = "edge"
	roleLeaf       = "leaf"
)

// trafficClass classifies which tier admitted a request. Kept as a core string
// type so router.go does not need to import internal/hop in non-enterprise builds.
type trafficClass string

const (
	classPage   trafficClass = "page"
	classAsset  trafficClass = "asset"
	classStream trafficClass = "stream"
	classBypass trafficClass = "bypass"
)

// Tier header names stripped from upstream responses and outbound requests in
// every edition so clients and origins can never smuggle internal tier headers.
const (
	hopHeaderName             = "Concert-Hop"
	hopBackpressureHeaderName = "Concert-Backpressure"
	hopNodeHeaderName         = "Concert-Hop-Node"
)

// Edition returns the compiled binary edition ("concert", "wpconcert", or
// "econcert") determined by Go build tags.
func Edition() string {
	switch {
	case hasEnterpriseEdition():
		return "econcert"
	case hasWordPressEdition():
		return "wpconcert"
	default:
		return "concert"
	}
}

// ─── core alert abstraction (bridges to internal/mailer in econcert) ─────────

type alertCategory string
type alertSeverity string

const (
	alertCatQueue    alertCategory = "queue"
	alertCatBans     alertCategory = "bans"
	alertCatSecurity alertCategory = "security"
	alertCatSilence  alertCategory = "silence"
	alertCatCapacity alertCategory = "capacity"
	alertCatFastlane alertCategory = "fastlane"

	alertSevInfo     alertSeverity = "info"
	alertSevWarn     alertSeverity = "warn"
	alertSevCritical alertSeverity = "critical"
)

type alertEvent struct {
	Category    alertCategory
	Severity    alertSeverity
	Title       string
	Summary     string
	Fingerprint string
	Details     map[string]string
}

// emailConfig holds administrator email settings. Only active in econcert;
// kept as a plain value struct here so config fields remain uniform.
type emailConfig struct {
	provider           string
	smtpHost           string
	smtpPort           int
	smtpTLS            string
	smtpUser           string
	resendURL          string
	sendPandaURL       string
	fromName           string
	fromAddr           string
	toAddrs            string
	dkimSelector       string
	cadenceMax         int
	cadenceWindowValue int
	cadenceWindowUnit  string
	events             string
	orgName            string
	postalAddress      string
	privacyURL         string
	termsURL           string
	portalURL          string
	publicBaseURL      string
	clusterDedupe      bool

	// Environment / *_FILE only; never written to settings.json.
	smtpPass        string
	resendAPIKey    string
	sendPandaAPIKey string
}

// ─── core RBAC role & principal types ────────────────────────────────────────

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

// auditEvent represents an administrative/security audit record. In econcert
// it is persisted in a hash-chained JSONL log (audit.go); in concert/wpconcert
// recordAudit is a no-op.
type auditEvent struct {
	Seq       uint64         `json:"seq"`
	Timestamp string         `json:"ts"`
	Actor     string         `json:"actor"`
	Role      string         `json:"role,omitempty"`
	Source    string         `json:"source"`
	Action    string         `json:"action"`
	Target    string         `json:"target,omitempty"`
	Outcome   string         `json:"outcome"`
	ClientIP  string         `json:"ip,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
	PrevHash  string         `json:"prev_hash"`
	Hash      string         `json:"hash"`
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

// ─── response header hygiene ─────────────────────────────────────────────────

// stripTierHeaders removes headers only Concert's tiers may set from an
// application's response.
func stripTierHeaders(h http.Header) {
	h.Del(hopBackpressureHeaderName)
	h.Del(hopNodeHeaderName)
}

// stripConcertSetCookies removes Set-Cookie headers naming a Concert cookie.
func stripConcertSetCookies(h http.Header) {
	vals := h.Values("Set-Cookie")
	if len(vals) == 0 {
		return
	}
	keep := vals[:0:0]
	for _, v := range vals {
		name, _, _ := strings.Cut(v, "=")
		name = strings.TrimSpace(name)
		drop := false
		for _, n := range proxyCookies {
			if name == n {
				drop = true
				break
			}
		}
		if !drop {
			keep = append(keep, v)
		}
	}
	h.Del("Set-Cookie")
	for _, v := range keep {
		h.Add("Set-Cookie", v)
	}
}

// ─── edition migration diagnostics ───────────────────────────────────────────

// checkMovedFlags checks raw CLI args for flags that belong to a higher
// edition (wpconcert or econcert) so operators upgrading or running the wrong
// binary get a direct migration hint instead of Go's generic "flag provided
// but not defined".
func checkMovedFlags(args []string) error {
	wp := movedWordPressFlags()
	ent := movedEnterpriseFlags()
	if len(wp) == 0 && len(ent) == 0 {
		return nil
	}
	for _, a := range args {
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			continue
		}
		name := strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		if bin, ok := wp[name]; ok {
			return fmt.Errorf("flag -%s is provided by %s (or econcert); build with: go build -tags wordpress ./cmd/wpconcert", name, bin)
		}
		if bin, ok := ent[name]; ok {
			return fmt.Errorf("flag -%s is provided by %s; build with: go build -tags \"wordpress,enterprise\" ./cmd/econcert", name, bin)
		}
	}
	return nil
}
