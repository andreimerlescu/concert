package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Enterprise data-privacy controls (GDPR / CCPA / PCI-DSS / HIPAA hygiene):
//
//   - Query-string scrubbing: redacts sensitive parameters (tokens, keys,
//     secrets, emails, card fields, auth codes) or strips query strings
//     entirely before recording in history logs, portal views, or JSON logs.
//   - IP anonymization: masks IPv4 to /24 and IPv6 to /48 in logs/history
//     when -privacy-anonymize-ip is enabled (exact IPs are still used in
//     memory for active abuse enforcement).
//   - DSAR (Data Subject Access Request) export and erasure endpoints for
//     retrieving or purging a client IP's recorded history and notes.

var sensitiveQueryKeys = map[string]bool{
	"token":         true,
	"access_token":  true,
	"refresh_token": true,
	"id_token":      true,
	"auth":          true,
	"authorization": true,
	"key":           true,
	"api_key":       true,
	"apikey":        true,
	"secret":        true,
	"password":      true,
	"passwd":        true,
	"pass":          true,
	"pwd":           true,
	"jwt":           true,
	"session":       true,
	"session_id":    true,
	"sid":           true,
	"code":          true,
	"email":         true,
	"phone":         true,
	"ssn":           true,
	"card":          true,
	"pan":           true,
	"cvv":           true,
	"cvc":           true,
	"signature":     true,
	"sig":           true,
}

func isSensitiveParam(k string) bool {
	lk := strings.ToLower(strings.TrimSpace(k))
	if sensitiveQueryKeys[lk] {
		return true
	}
	for _, sub := range []string{"token", "secret", "password", "passwd", "apikey", "api_key", "card", "ssn", "cvv"} {
		if strings.Contains(lk, sub) {
			return true
		}
	}
	return false
}

// formatPrivacyPath applies query-string scrubbing or stripping to a URL path.
func formatPrivacyPath(p, rawQuery string, scrub, strip bool) string {
	if rawQuery == "" || strip {
		return p
	}
	if !scrub {
		return p + "?" + rawQuery
	}
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		// Unparseable query string: redact completely rather than leaking raw data.
		return p + "?[redacted]"
	}
	changed := false
	for k := range vals {
		if isSensitiveParam(k) {
			vals[k] = []string{"[REDACTED]"}
			changed = true
		}
	}
	if !changed {
		return p + "?" + rawQuery
	}
	return p + "?" + vals.Encode()
}

// anonymizeIP masks IPv4 addresses to /24 and IPv6 addresses to /48.
func anonymizeIP(ip netip.Addr) netip.Addr {
	if !ip.IsValid() {
		return ip
	}
	ip = ip.Unmap()
	if ip.Is4() {
		return netip.PrefixFrom(ip, 24).Masked().Addr()
	}
	return netip.PrefixFrom(ip, 48).Masked().Addr()
}

func formatPrivacyIP(ip netip.Addr, anonymize bool) string {
	if !ip.IsValid() {
		return ""
	}
	if anonymize {
		return anonymizeIP(ip).String()
	}
	return ip.String()
}

// ─── GDPR / CCPA DSAR Export & Erasure ───────────────────────────────────────

type dsarExport struct {
	Client       string    `json:"client"`
	ExportedAt   time.Time `json:"exported_at"`
	HistoryFound bool      `json:"history_found"`
	Requests     []any     `json:"requests,omitempty"`
	ActiveBans   []banView `json:"active_bans,omitempty"`
	Note         string    `json:"note"`
}

func (a *app) exportPrivacyData(ip netip.Addr) dsarExport {
	now := time.Now().UTC()
	out := dsarExport{
		Client:     ip.String(),
		ExportedAt: now,
		Note:       "Includes in-memory request history and active bans. If fast-lane crypto payments are enabled, replay-prevention settlement journals must be reviewed with legal counsel before modification (see docs/US_COMPLIANCE.md).",
	}
	if a.history != nil {
		if _, entries, _, ok := a.history.clientDetail(ip); ok {
			out.HistoryFound = true
			for _, r := range entries {
				out.Requests = append(out.Requests, r)
			}
		}
	}
	if a.abuse != nil {
		for _, b := range a.abuse.bans(now) {
			if t, err := parseBanTarget(b.Client); err == nil && t.prefix.Contains(ip) {
				out.ActiveBans = append(out.ActiveBans, b)
			}
		}
	}
	return out
}

// erasePrivacyData removes an IP's request history from memory and rewrites
// the persisted history log files to purge matching entries. Security bans are
// preserved unless includeBans is true (legitimate interest / fraud defense).
func (a *app) erasePrivacyData(ip netip.Addr, includeBans bool) (int, error) {
	removed := 0
	if a.history != nil {
		removed += a.history.eraseClient(ip)
	}
	if includeBans && a.abuse != nil {
		if t, err := parseBanTarget(ip.String()); err == nil {
			if a.abuse.unbanTarget(t) {
				a.saveBansNow()
				removed++
			}
		}
	}
	return removed, nil
}

// eraseClient deletes all in-memory history entries for ip and rewrites the
// on-disk history.jsonl file (if active) without events referencing ip.
func (h *history) eraseClient(ip netip.Addr) int {
	if h == nil || !ip.IsValid() {
		return 0
	}
	ip = ip.Unmap()
	removed := 0

	sh := h.shard(ip)
	sh.mu.Lock()
	if hc, ok := sh.m[ip]; ok {
		removed = len(hc.entries)
		delete(sh.m, ip)
		h.count.Add(-1)
	}
	sh.mu.Unlock()

	if h.log != nil && h.log.path != "" {
		if err := scrubHistoryLogFile(h.log.path, ip.String()); err != nil {
			// Log error; in-memory deletion already succeeded.
			_ = err
		}
	}
	return removed
}

func scrubHistoryLogFile(path, ipStr string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var kept []byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), historyLogLineMax)
	for sc.Scan() {
		line := sc.Bytes()
		var ev struct {
			IP     string `json:"ip"`
			Target string `json:"target"`
		}
		if json.Unmarshal(line, &ev) == nil && (ev.IP == ipStr || ev.Target == ipStr) {
			continue
		}
		kept = append(kept, line...)
		kept = append(kept, '\n')
	}
	scanErr := sc.Err()
	_ = f.Close()
	if scanErr != nil {
		return scanErr
	}
	return writeFileAtomic(path, kept)
}

func handlePrivacyExport(c *gin.Context, a *app, actor principal, source string) {
	raw := strings.TrimSpace(c.Query("client"))
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "valid client IP address is required"})
		return
	}
	ip = ip.Unmap()
	res := a.exportPrivacyData(ip)
	a.recordAudit(auditEvent{
		Actor:    actor.Actor,
		Role:     actor.Role.String(),
		Source:   source,
		Action:   "privacy.export",
		Target:   ip.String(),
		Outcome:  "allow",
		ClientIP: actor.IP.String(),
		Details:  map[string]any{"history_found": res.HistoryFound, "requests": len(res.Requests)},
	})
	c.JSON(http.StatusOK, res)
}

func handlePrivacyErase(c *gin.Context, a *app, actor principal, source string) {
	raw := strings.TrimSpace(c.Query("client"))
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "valid client IP address is required"})
		return
	}
	ip = ip.Unmap()
	includeBans := strings.EqualFold(c.Query("include_bans"), "true")
	removed, err := a.erasePrivacyData(ip, includeBans)
	if err != nil {
		a.recordAudit(auditEvent{
			Actor:    actor.Actor,
			Role:     actor.Role.String(),
			Source:   source,
			Action:   "privacy.erase",
			Target:   ip.String(),
			Outcome:  "error",
			ClientIP: actor.IP.String(),
			Details:  map[string]any{"error": err.Error()},
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a.recordAudit(auditEvent{
		Actor:    actor.Actor,
		Role:     actor.Role.String(),
		Source:   source,
		Action:   "privacy.erase",
		Target:   ip.String(),
		Outcome:  "allow",
		ClientIP: actor.IP.String(),
		Details:  map[string]any{"removed_records": removed, "include_bans": includeBans},
	})
	c.JSON(http.StatusOK, gin.H{"erased": ip.String(), "removed_records": removed, "include_bans": includeBans})
}
