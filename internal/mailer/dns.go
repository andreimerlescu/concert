package mailer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

const dnsLookupTimeout = 5 * time.Second

// DNSResolver abstracts net.Resolver for deterministic unit testing.
type DNSResolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Check status constants for VerifyReport.
const (
	CheckPass = "pass"
	CheckWarn = "warn"
	CheckFail = "fail"
)

// VerifyCheck describes one DNS or connectivity verification step.
type VerifyCheck struct {
	Name    string `json:"name"`
	Target  string `json:"target"`
	Status  string `json:"status"` // pass, warn, fail
	Summary string `json:"summary"`
	Detail  string `json:"detail,omitempty"`
}

// VerifyReport aggregates DNS and provider connectivity checks.
type VerifyReport struct {
	OK        bool          `json:"ok"`
	Provider  string        `json:"provider"`
	CheckedAt time.Time     `json:"checked_at"`
	Checks    []VerifyCheck `json:"checks"`
}

// Verify checks sender MX, SPF, DMARC, optional DKIM selector, recipient MX,
// provider host DNS resolution, and live provider handshake/auth.
func Verify(ctx context.Context, cfg Config, sender Sender, resolver DNSResolver) VerifyReport {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	report := VerifyReport{
		OK:        true,
		Provider:  cfg.Provider,
		CheckedAt: time.Now().UTC(),
	}
	add := func(c VerifyCheck) {
		if c.Status == CheckFail {
			report.OK = false
		}
		report.Checks = append(report.Checks, c)
	}

	fromDomain := AddressDomain(cfg.FromAddr)
	if fromDomain == "" {
		add(VerifyCheck{
			Name:    "Sender address",
			Target:  cfg.FromAddr,
			Status:  CheckFail,
			Summary: "From address is missing or invalid",
		})
	} else {
		// 1. Sender domain MX
		add(checkMX(ctx, resolver, "Sender MX", fromDomain, true))

		// 2. SPF
		add(checkSPF(ctx, resolver, fromDomain))

		// 3. DMARC
		add(checkDMARC(ctx, resolver, fromDomain))

		// 4. Optional DKIM selector
		if sel := strings.TrimSpace(cfg.DKIMSelector); sel != "" {
			add(checkDKIM(ctx, resolver, sel, fromDomain))
		}
	}

	// 5. Recipient domain MX (deduplicated)
	rcptDomains := uniqueDomains(cfg.ToAddrs)
	if len(rcptDomains) == 0 {
		add(VerifyCheck{
			Name:    "Recipient MX",
			Target:  "",
			Status:  CheckFail,
			Summary: "No valid recipient email addresses configured",
		})
	} else {
		for _, dom := range rcptDomains {
			add(checkMX(ctx, resolver, "Recipient MX", dom, false))
		}
	}

	// 6. Provider host DNS resolution
	provHost := providerHostname(cfg)
	if provHost != "" {
		add(checkProviderDNS(ctx, resolver, provHost))
	}

	// 7. Live provider connection / auth check
	if sender == nil {
		add(VerifyCheck{
			Name:    "Provider connection",
			Target:  cfg.Provider,
			Status:  CheckFail,
			Summary: "Provider is not configured or missing credentials",
		})
	} else {
		cctx, cancel := context.WithTimeout(ctx, providerHTTPTimeout)
		defer cancel()
		if dv, ok := sender.(DetailVerifier); ok {
			status, summary, detail := dv.VerifyDetail(cctx)
			add(VerifyCheck{
				Name:    "Provider connection",
				Target:  providerTargetLabel(cfg),
				Status:  status,
				Summary: summary,
				Detail:  detail,
			})
		} else {
			if err := sender.VerifyConnection(cctx); err != nil {
				add(VerifyCheck{
					Name:    "Provider connection",
					Target:  providerTargetLabel(cfg),
					Status:  CheckFail,
					Summary: "Connection or authentication failed",
					Detail:  err.Error(),
				})
			} else {
				add(VerifyCheck{
					Name:    "Provider connection",
					Target:  providerTargetLabel(cfg),
					Status:  CheckPass,
					Summary: fmt.Sprintf("%s handshake and authentication succeeded", strings.ToUpper(sender.Name())),
				})
			}
		}
	}

	return report
}

func checkMX(ctx context.Context, r DNSResolver, name, domain string, warnOnEmpty bool) VerifyCheck {
	lctx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()

	mxs, err := r.LookupMX(lctx, domain)
	if err != nil {
		if isDNSNotFound(err) {
			// RFC 5321 §5.1 allows implicit A/AAAA fallback, so check A/AAAA before failing.
			addrs, aerr := r.LookupHost(lctx, domain)
			if aerr == nil && len(addrs) > 0 {
				return VerifyCheck{
					Name:    name,
					Target:  domain,
					Status:  CheckWarn,
					Summary: "No MX records; domain resolves via A/AAAA fallback",
					Detail:  strings.Join(addrs, ", "),
				}
			}
			st := CheckFail
			if warnOnEmpty {
				st = CheckWarn
			}
			return VerifyCheck{
				Name:    name,
				Target:  domain,
				Status:  st,
				Summary: "No MX records found for domain",
				Detail:  err.Error(),
			}
		}
		return VerifyCheck{
			Name:    name,
			Target:  domain,
			Status:  CheckFail,
			Summary: "MX lookup failed",
			Detail:  err.Error(),
		}
	}
	if len(mxs) == 0 {
		st := CheckFail
		if warnOnEmpty {
			st = CheckWarn
		}
		return VerifyCheck{
			Name:    name,
			Target:  domain,
			Status:  st,
			Summary: "No MX records returned",
		}
	}
	sort.Slice(mxs, func(i, j int) bool {
		if mxs[i].Pref != mxs[j].Pref {
			return mxs[i].Pref < mxs[j].Pref
		}
		return mxs[i].Host < mxs[j].Host
	})
	parts := make([]string, 0, len(mxs))
	for _, mx := range mxs {
		parts = append(parts, fmt.Sprintf("%d %s", mx.Pref, strings.TrimSuffix(mx.Host, ".")))
	}
	return VerifyCheck{
		Name:    name,
		Target:  domain,
		Status:  CheckPass,
		Summary: fmt.Sprintf("%d MX record(s) found", len(mxs)),
		Detail:  strings.Join(parts, ", "),
	}
}

func checkSPF(ctx context.Context, r DNSResolver, domain string) VerifyCheck {
	lctx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()

	txts, err := r.LookupTXT(lctx, domain)
	if err != nil {
		if isDNSNotFound(err) {
			return VerifyCheck{
				Name:    "SPF record",
				Target:  domain,
				Status:  CheckWarn,
				Summary: "No SPF TXT record found",
				Detail:  "Publish a v=spf1 TXT record authorizing your SMTP relay, Resend, or SendPanda.",
			}
		}
		return VerifyCheck{
			Name:    "SPF record",
			Target:  domain,
			Status:  CheckFail,
			Summary: "SPF TXT lookup failed",
			Detail:  err.Error(),
		}
	}
	var spf []string
	for _, t := range txts {
		lt := strings.ToLower(strings.TrimSpace(t))
		if strings.HasPrefix(lt, "v=spf1 ") || lt == "v=spf1" {
			spf = append(spf, strings.TrimSpace(t))
		}
	}
	switch len(spf) {
	case 0:
		return VerifyCheck{
			Name:    "SPF record",
			Target:  domain,
			Status:  CheckWarn,
			Summary: "No v=spf1 record found",
			Detail:  "Add a single v=spf1 TXT record for stronger inbox deliverability.",
		}
	case 1:
		return VerifyCheck{
			Name:    "SPF record",
			Target:  domain,
			Status:  CheckPass,
			Summary: "Valid SPF record present",
			Detail:  clipString(spf[0], 240),
		}
	default:
		return VerifyCheck{
			Name:    "SPF record",
			Target:  domain,
			Status:  CheckWarn,
			Summary: fmt.Sprintf("Multiple (%d) SPF records found (RFC 7208 PermError)", len(spf)),
			Detail:  "Merge duplicate v=spf1 TXT records into a single record.",
		}
	}
}

func checkDMARC(ctx context.Context, r DNSResolver, domain string) VerifyCheck {
	lctx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()

	target := "_dmarc." + domain
	txts, err := r.LookupTXT(lctx, target)
	if err != nil {
		if isDNSNotFound(err) {
			return VerifyCheck{
				Name:    "DMARC record",
				Target:  target,
				Status:  CheckWarn,
				Summary: "No DMARC TXT record found",
				Detail:  "Publish a v=DMARC1 record at " + target + " to satisfy Gmail/Yahoo/enterprise sender compliance.",
			}
		}
		return VerifyCheck{
			Name:    "DMARC record",
			Target:  target,
			Status:  CheckFail,
			Summary: "DMARC TXT lookup failed",
			Detail:  err.Error(),
		}
	}
	for _, t := range txts {
		trimmed := strings.TrimSpace(t)
		if strings.HasPrefix(strings.ToLower(trimmed), "v=dmarc1") {
			policy := extractTag(trimmed, "p")
			if policy == "" {
				return VerifyCheck{
					Name:    "DMARC record",
					Target:  target,
					Status:  CheckWarn,
					Summary: "DMARC record missing p= policy tag",
					Detail:  clipString(trimmed, 240),
				}
			}
			summary := fmt.Sprintf("DMARC policy p=%s", policy)
			if strings.EqualFold(policy, "none") {
				summary += " (monitoring only; consider quarantine or reject)"
			}
			return VerifyCheck{
				Name:    "DMARC record",
				Target:  target,
				Status:  CheckPass,
				Summary: summary,
				Detail:  clipString(trimmed, 240),
			}
		}
	}
	return VerifyCheck{
		Name:    "DMARC record",
		Target:  target,
		Status:  CheckWarn,
		Summary: "No v=DMARC1 record found",
		Detail:  "TXT records exist at " + target + " but none starts with v=DMARC1.",
	}
}

func checkDKIM(ctx context.Context, r DNSResolver, selector, domain string) VerifyCheck {
	lctx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()

	target := selector + "._domainkey." + domain
	txts, err := r.LookupTXT(lctx, target)
	if err != nil {
		return VerifyCheck{
			Name:    "DKIM selector",
			Target:  target,
			Status:  CheckFail,
			Summary: "DKIM TXT record not found",
			Detail:  err.Error(),
		}
	}
	for _, t := range txts {
		lower := strings.ToLower(t)
		if strings.Contains(lower, "v=dkim1") || strings.Contains(lower, "p=") {
			return VerifyCheck{
				Name:    "DKIM selector",
				Target:  target,
				Status:  CheckPass,
				Summary: "DKIM public key record found",
				Detail:  clipString(strings.TrimSpace(t), 180),
			}
		}
	}
	return VerifyCheck{
		Name:    "DKIM selector",
		Target:  target,
		Status:  CheckFail,
		Summary: "TXT record found at DKIM selector without v=DKIM1 / p= key",
	}
}

func checkProviderDNS(ctx context.Context, r DNSResolver, host string) VerifyCheck {
	if ip := net.ParseIP(host); ip != nil {
		return VerifyCheck{
			Name:    "Provider host DNS",
			Target:  host,
			Status:  CheckPass,
			Summary: "Literal IP address configured",
			Detail:  ip.String(),
		}
	}
	lctx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()

	addrs, err := r.LookupHost(lctx, host)
	if err != nil || len(addrs) == 0 {
		detail := ""
		if err != nil {
			detail = err.Error()
		}
		return VerifyCheck{
			Name:    "Provider host DNS",
			Target:  host,
			Status:  CheckFail,
			Summary: "Could not resolve provider host",
			Detail:  detail,
		}
	}
	return VerifyCheck{
		Name:    "Provider host DNS",
		Target:  host,
		Status:  CheckPass,
		Summary: fmt.Sprintf("Resolved to %d IP address(es)", len(addrs)),
		Detail:  strings.Join(addrs, ", "),
	}
}

func providerHostname(cfg Config) string {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case ProviderSMTP:
		return strings.TrimSpace(cfg.SMTPHost)
	case ProviderResend:
		if u, err := url.Parse(cfg.EffectiveResendBaseURL()); err == nil {
			return u.Hostname()
		}
	case ProviderSendPanda:
		if u, err := url.Parse(cfg.EffectiveSendPandaBaseURL()); err == nil {
			return u.Hostname()
		}
	}
	return ""
}

func providerTargetLabel(cfg Config) string {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case ProviderSMTP:
		return fmt.Sprintf("%s:%d (%s)", cfg.SMTPHost, cfg.EffectiveSMTPPort(), cfg.EffectiveSMTPTLS())
	case ProviderResend:
		return cfg.EffectiveResendBaseURL()
	case ProviderSendPanda:
		return cfg.EffectiveSendPandaBaseURL()
	default:
		return cfg.Provider
	}
}

func uniqueDomains(addrs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range addrs {
		d := AddressDomain(a)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func extractTag(record, key string) string {
	prefix := strings.ToLower(key) + "="
	for _, part := range strings.Split(record, ";") {
		p := strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(p), prefix) {
			return strings.TrimSpace(p[len(prefix):])
		}
	}
	return ""
}

func isDNSNotFound(err error) bool {
	var de *net.DNSError
	if errors.As(err, &de) && de.IsNotFound {
		return true
	}
	return false
}
