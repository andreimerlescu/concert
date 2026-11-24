package fastlane

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	PolicyModeWebhook   = "webhook"
	PolicyModeBlocklist = "blocklist"
	PolicyModeNone      = "none"
)

type blocklistCache struct {
	mu      sync.Mutex
	path    string
	modTime time.Time
	size    int64
	hash    string
	blocked map[string]bool
}

func (b *blocklistCache) check(path, address string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if strings.TrimSpace(path) == "" {
		return "", errors.New("policy_blocklist_file is required for blocklist policy_mode")
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", errors.New("policy blocklist file unavailable")
	}
	if b.path != path || !b.modTime.Equal(st.ModTime()) || b.size != st.Size() || b.blocked == nil {
		raw, err := os.ReadFile(path)
		if err != nil || len(raw) > 16<<20 {
			return "", errors.New("policy blocklist file unreadable")
		}
		parsed, err := parseBlocklist(raw)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(raw)
		b.path = path
		b.modTime = st.ModTime()
		b.size = st.Size()
		b.hash = hex.EncodeToString(sum[:8])
		b.blocked = parsed
	}
	norm := normalizeAddressForBlocklist(address)
	if norm == "" || b.blocked[norm] || b.blocked[strings.ToLower(norm)] {
		return "", errors.New("wallet address blocked by local policy blocklist")
	}
	return "blocklist:" + b.hash, nil
}

func parseBlocklist(raw []byte) (map[string]bool, error) {
	out := map[string]bool{}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return out, nil
	}
	if trimmed[0] == '[' || trimmed[0] == '{' {
		var list []string
		if err := json.Unmarshal(trimmed, &list); err == nil {
			for _, addr := range list {
				if a := normalizeAddressForBlocklist(addr); a != "" {
					out[a] = true
					out[strings.ToLower(a)] = true
				}
			}
			return out, nil
		}
		var obj struct {
			Addresses []string `json:"addresses"`
			Blocked   []string `json:"blocked"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return nil, errors.New("invalid JSON policy blocklist")
		}
		for _, addr := range append(obj.Addresses, obj.Blocked...) {
			if a := normalizeAddressForBlocklist(addr); a != "" {
				out[a] = true
				out[strings.ToLower(a)] = true
			}
		}
		return out, nil
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if a := normalizeAddressForBlocklist(line); a != "" {
			out[a] = true
			out[strings.ToLower(a)] = true
		}
	}
	return out, sc.Err()
}

func normalizeAddressForBlocklist(s string) string {
	return strings.TrimSpace(s)
}

func (s *Service) screenPolicy(ctx context.Context, r *http.Request, cfg Config, network, payer, action string, req Requirements) (string, error) {
	mode := cfg.EffectivePolicyMode()
	switch mode {
	case PolicyModeNone:
		if cfg.TestMode && cfg.PolicyURL == "" {
			return "test-mode-no-screening", nil
		}
		return "policy-none-acknowledged", nil
	case PolicyModeBlocklist:
		return s.blocklist.check(cfg.PolicyBlocklistFile, payer)
	case PolicyModeWebhook:
		if cfg.PolicyURL == "" && cfg.TestMode {
			return "test-mode-no-screening", nil
		}
		if cfg.PolicyURL == "" {
			return "", errors.New("policy_url is required for webhook policy_mode")
		}
		var a assessment
		err := s.call(ctx, callTimeout, cfg.PolicyURL, s.policyToken, map[string]any{
			"network":      network,
			"payer":        payer,
			"action":       action,
			"requirements": req,
			"client_ip":    r.RemoteAddr,
			"merchant":     cfg.Merchant,
		}, &a)
		if err != nil {
			return "", err
		}
		now := s.now()
		if a.Decision != "allow" || a.ID == "" || !a.Expires.After(now) || a.Expires.After(now.Add(10*time.Minute)) {
			return "", errors.New("admission not approved by policy service")
		}
		return a.ID, nil
	default:
		return "", errors.New("unsupported policy_mode")
	}
}
