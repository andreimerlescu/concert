package mailer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	unsubKDFDomain = "concert/email/unsub-v1"
	unsubTokenMax  = 512

	// UnsubscribeTokenTTL is how long a signed one-click pause/unsubscribe link remains valid.
	UnsubscribeTokenTTL = 30 * 24 * time.Hour

	// UnsubscribeMainPath is mounted on Concert's main listener under /_concert/.
	UnsubscribeMainPath = "/_concert/email/unsubscribe"

	// UnsubscribePortalPath is mounted on Concert's admin portal listener.
	UnsubscribePortalPath = "/email/unsubscribe"
)

// SignUnsubscribeToken mints a signed, expiring RFC 8058 unsubscribe token bound
// to a specific recipient address and Concert node ID.
func SignUnsubscribeToken(secret []byte, recipient, nodeID string, expiresAt time.Time) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("missing signing secret")
	}
	cleanAddr, err := ValidateAddress(recipient)
	if err != nil {
		return "", fmt.Errorf("recipient: %w", err)
	}
	cleanAddr = strings.ToLower(cleanAddr)
	cleanNode := strings.TrimSpace(nodeID)
	if strings.ContainsAny(cleanAddr, "|\r\n\x00") || strings.ContainsAny(cleanNode, "|\r\n\x00") {
		return "", errors.New("invalid character in unsubscribe token fields")
	}
	payload := fmt.Sprintf("v1|%s|%s|%d", cleanAddr, cleanNode, expiresAt.UTC().Unix())
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := signUnsubMAC(secret, encodedPayload)
	return encodedPayload + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

// VerifyUnsubscribeToken validates token signature (with optional prevSecret
// rotation fallback), canonical payload encoding, and expiration.
func VerifyUnsubscribeToken(secret, prevSecret []byte, token string, now time.Time) (recipient, nodeID string, err error) {
	if len(token) == 0 || len(token) > unsubTokenMax {
		return "", "", errors.New("invalid unsubscribe token length")
	}
	if strings.ContainsAny(token, " \t\r\n\x00") {
		return "", "", errors.New("invalid unsubscribe token characters")
	}
	dot := strings.IndexByte(token, '.')
	if dot <= 0 || dot >= len(token)-1 || strings.IndexByte(token[dot+1:], '.') >= 0 {
		return "", "", errors.New("malformed unsubscribe token")
	}
	encodedPayload := token[:dot]
	encodedMAC := token[dot+1:]

	gotMAC, err := base64.RawURLEncoding.DecodeString(encodedMAC)
	if err != nil || len(gotMAC) != sha256.Size {
		return "", "", errors.New("invalid unsubscribe token signature encoding")
	}
	valid := false
	if len(secret) > 0 && hmac.Equal(gotMAC, signUnsubMAC(secret, encodedPayload)) {
		valid = true
	} else if len(prevSecret) > 0 && hmac.Equal(gotMAC, signUnsubMAC(prevSecret, encodedPayload)) {
		valid = true
	}
	if !valid {
		return "", "", errors.New("unsubscribe token signature mismatch")
	}

	raw, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return "", "", errors.New("invalid unsubscribe token payload")
	}
	// Canonical check: re-encoding raw must exactly match encodedPayload.
	if base64.RawURLEncoding.EncodeToString(raw) != encodedPayload {
		return "", "", errors.New("non-canonical unsubscribe token encoding")
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 4 || parts[0] != "v1" {
		return "", "", errors.New("unsupported unsubscribe token format")
	}
	cleanAddr, err := ValidateAddress(parts[1])
	if err != nil {
		return "", "", errors.New("invalid recipient in unsubscribe token")
	}
	expUnix, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || expUnix <= 0 {
		return "", "", errors.New("invalid expiry in unsubscribe token")
	}
	if now.UTC().Unix() > expUnix {
		return "", "", errors.New("unsubscribe token has expired")
	}
	return strings.ToLower(cleanAddr), parts[2], nil
}

func signUnsubMAC(secret []byte, encodedPayload string) []byte {
	key := deriveKey(secret, unsubKDFDomain)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(encodedPayload))
	return m.Sum(nil)
}

func buildUnsubscribeURL(cfg Config, secret []byte, recipient string, now time.Time) string {
	if len(secret) == 0 {
		return ""
	}
	var base, path string
	if u := strings.TrimRight(strings.TrimSpace(cfg.Compliance.PublicBaseURL), "/"); u != "" {
		base = u
		path = UnsubscribeMainPath
	} else if u := strings.TrimRight(strings.TrimSpace(cfg.Compliance.PortalURL), "/"); u != "" {
		base = u
		path = UnsubscribePortalPath
	} else {
		return ""
	}
	tok, err := SignUnsubscribeToken(secret, recipient, cfg.NodeID, now.Add(UnsubscribeTokenTTL))
	if err != nil {
		return ""
	}
	return base + path + "?token=" + url.QueryEscape(tok)
}

type emailDetailPair struct {
	Key   string
	Value string
}

type digestEventView struct {
	Category string
	Severity string
	BadgeBg  string
	BadgeFg  string
	Title    string
	Summary  string
	Count    int
	FirstAt  string
	LastAt   string
	Details  []emailDetailPair
}

type digestTemplateData struct {
	IsTest         bool
	OrgName        string
	NodeID         string
	Role           string
	Version        string
	GeneratedAt    string
	CadenceText    string
	TotalEvents    int
	UniqueEvents   int
	OverflowCount  int
	CriticalCount  int
	WarnCount      int
	InfoCount      int
	Events         []digestEventView
	PortalURL      string
	PrivacyURL     string
	TermsURL       string
	PostalAddress  string
	UnsubscribeURL string
	Recipient      string
	Provider       string
}

var digestHTMLTmpl = template.Must(template.New("concert_digest").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{if .IsTest}}Concert Test Email{{else}}Concert Operational Digest{{end}}</title>
</head>
<body style="margin:0;padding:0;background-color:#f4f6f9;color:#1f2937;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#f4f6f9;padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:640px;background-color:#ffffff;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden;">
  <tr>
    <td style="background-color:#0f172a;color:#f8fafc;padding:20px 24px;">
      <div style="font-size:12px;letter-spacing:0.08em;text-transform:uppercase;color:#38bdf8;font-weight:600;">CONCERT{{if .OrgName}} · {{.OrgName}}{{end}}</div>
      <h1 style="margin:6px 0 4px 0;font-size:20px;line-height:1.3;color:#ffffff;">{{if .IsTest}}Email Delivery Verification Test{{else}}Operational Alert Digest{{end}}</h1>
      <div style="font-size:12px;color:#cbd5e1;">Node: <strong>{{.NodeID}}</strong> · Role: {{.Role}} · {{.GeneratedAt}}</div>
    </td>
  </tr>
  <tr>
    <td style="padding:22px 24px;">
      {{if .IsTest}}
      <p style="margin:0 0 14px 0;font-size:14px;line-height:1.6;">This is a test message sent from Concert's Admin Portal to verify DNS configuration, transport authentication, compliance headers, and message rendering.</p>
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;margin-bottom:16px;">
        <tr><td style="padding:14px 16px;font-size:13px;line-height:1.6;">
          <div><strong>Provider:</strong> {{.Provider}}</div>
          <div><strong>Recipient:</strong> {{.Recipient}}</div>
          <div><strong>Configured schedule:</strong> {{.CadenceText}}</div>
          <div><strong>Concert version:</strong> {{.Version}}</div>
        </td></tr>
      </table>
      {{else}}
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-bottom:18px;">
        <tr>
          <td style="background-color:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 16px;font-size:13px;">
            <strong>{{.TotalEvents}}</strong> total event(s) across <strong>{{.UniqueEvents}}</strong> distinct item(s)
            {{if gt .CriticalCount 0}} · <span style="color:#b91c1c;font-weight:600;">{{.CriticalCount}} critical</span>{{end}}
            {{if gt .WarnCount 0}} · <span style="color:#b45309;font-weight:600;">{{.WarnCount}} warning</span>{{end}}
            {{if gt .InfoCount 0}} · <span style="color:#0369a1;font-weight:600;">{{.InfoCount}} info</span>{{end}}
            {{if gt .OverflowCount 0}} · <span style="color:#6b7280;">+{{.OverflowCount}} overflow folded</span>{{end}}
          </td>
        </tr>
      </table>
      {{range .Events}}
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border:1px solid #e5e7eb;border-radius:8px;margin-bottom:12px;">
        <tr>
          <td style="padding:12px 14px;">
            <div style="margin-bottom:6px;">
              <span style="display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;text-transform:uppercase;background-color:{{.BadgeBg}};color:{{.BadgeFg}};">{{.Severity}}</span>
              <span style="display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;text-transform:uppercase;background-color:#f1f5f9;color:#334155;margin-left:4px;">{{.Category}}</span>
              {{if gt .Count 1}}<span style="display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;background-color:#e0f2fe;color:#075985;margin-left:4px;">×{{.Count}}</span>{{end}}
            </div>
            <div style="font-size:15px;font-weight:600;color:#111827;margin-bottom:4px;">{{.Title}}</div>
            <div style="font-size:13px;line-height:1.5;color:#374151;margin-bottom:6px;">{{.Summary}}</div>
            {{if .Details}}
            <div style="font-size:12px;color:#4b5563;background-color:#f9fafb;border-radius:6px;padding:8px 10px;margin-bottom:6px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;">
              {{range .Details}}<div><strong>{{.Key}}:</strong> {{.Value}}</div>{{end}}
            </div>
            {{end}}
            <div style="font-size:11px;color:#6b7280;">Last seen: {{.LastAt}}{{if ne .FirstAt .LastAt}} · First seen: {{.FirstAt}}{{end}}</div>
          </td>
        </tr>
      </table>
      {{end}}
      {{end}}
      {{if .PortalURL}}
      <div style="margin-top:18px;">
        <a href="{{.PortalURL}}" style="display:inline-block;background-color:#0284c7;color:#ffffff;text-decoration:none;font-size:13px;font-weight:600;padding:10px 16px;border-radius:6px;">Open Concert Admin Portal</a>
      </div>
      {{end}}
    </td>
  </tr>
  <tr>
    <td style="background-color:#f8fafc;border-top:1px solid #e5e7eb;padding:16px 24px;font-size:12px;line-height:1.6;color:#64748b;">
      <div>Automated operational notification from <strong>{{if .OrgName}}{{.OrgName}} ({{.NodeID}}){{else}}Concert ({{.NodeID}}){{end}}</strong>.</div>
      <div>Delivery cadence enforced: {{.CadenceText}}. Recipient: {{.Recipient}}.</div>
      {{if .PostalAddress}}<div>{{.PostalAddress}}</div>{{end}}
      <div style="margin-top:8px;">
        {{if .PortalURL}}<a href="{{.PortalURL}}" style="color:#0284c7;text-decoration:underline;">Admin Portal</a>{{end}}
        {{if .PrivacyURL}}{{if .PortalURL}} · {{end}}<a href="{{.PrivacyURL}}" style="color:#0284c7;text-decoration:underline;">Privacy Policy</a>{{end}}
        {{if .TermsURL}}{{if or .PortalURL .PrivacyURL}} · {{end}}<a href="{{.TermsURL}}" style="color:#0284c7;text-decoration:underline;">Terms</a>{{end}}
        {{if .UnsubscribeURL}}{{if or .PortalURL .PrivacyURL .TermsURL}} · {{end}}<a href="{{.UnsubscribeURL}}" style="color:#b91c1c;text-decoration:underline;">Pause / Unsubscribe Alerts</a>{{else}}{{if or .PortalURL .PrivacyURL .TermsURL}} · {{end}}Pause alerts anytime in the Concert Admin Portal Email tab.{{end}}
      </div>
    </td>
  </tr>
</table>
</td></tr>
</table>
</body>
</html>
`))

// ComposeDigest builds a compliance-formatted HTML + plain-text digest message
// for one recipient from a batch of queued events.
func ComposeDigest(cfg Config, unsubSecret []byte, recipient string, events []QueuedEvent, overflow int, now time.Time) (Message, error) {
	cleanRcpt, err := ValidateAddress(recipient)
	if err != nil {
		return Message{}, fmt.Errorf("recipient: %w", err)
	}
	sorted := make([]QueuedEvent, len(events))
	copy(sorted, events)
	sort.Slice(sorted, func(i, j int) bool {
		ri, rj := SeverityRank(sorted[i].Severity), SeverityRank(sorted[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return sorted[i].LastAt.After(sorted[j].LastAt)
	})

	data := buildTemplateData(cfg, unsubSecret, cleanRcpt, sorted, overflow, false, now)
	subject := buildDigestSubject(data)
	return renderComposedMessage(cfg, cleanRcpt, subject, data, now)
}

// ComposeTest builds a compliance-formatted verification test message for one recipient.
func ComposeTest(cfg Config, unsubSecret []byte, recipient string, now time.Time) (Message, error) {
	cleanRcpt, err := ValidateAddress(recipient)
	if err != nil {
		return Message{}, fmt.Errorf("recipient: %w", err)
	}
	data := buildTemplateData(cfg, unsubSecret, cleanRcpt, nil, 0, true, now)
	subject := fmt.Sprintf("[Concert · %s] Test email delivery (%s)", data.NodeID, strings.ToUpper(cfg.Provider))
	return renderComposedMessage(cfg, cleanRcpt, subject, data, now)
}

func buildTemplateData(cfg Config, unsubSecret []byte, recipient string, events []QueuedEvent, overflow int, isTest bool, now time.Time) digestTemplateData {
	nodeID := strings.TrimSpace(cfg.NodeID)
	if nodeID == "" {
		nodeID = "concert"
	}
	role := strings.TrimSpace(cfg.Role)
	if role == "" {
		role = "standalone"
	}
	ver := strings.TrimSpace(cfg.Version)
	if ver == "" {
		ver = "dev"
	}

	d := digestTemplateData{
		IsTest:         isTest,
		OrgName:        strings.TrimSpace(cfg.Compliance.OrgName),
		NodeID:         nodeID,
		Role:           role,
		Version:        ver,
		GeneratedAt:    now.UTC().Format(time.RFC3339),
		CadenceText:    cfg.Cadence.String(),
		OverflowCount:  overflow,
		PortalURL:      strings.TrimSpace(cfg.Compliance.PortalURL),
		PrivacyURL:     strings.TrimSpace(cfg.Compliance.PrivacyURL),
		TermsURL:       strings.TrimSpace(cfg.Compliance.TermsURL),
		PostalAddress:  strings.TrimSpace(cfg.Compliance.PostalAddress),
		UnsubscribeURL: buildUnsubscribeURL(cfg, unsubSecret, recipient, now),
		Recipient:      recipient,
		Provider:       cfg.Provider,
	}

	total := overflow
	for _, ev := range events {
		cnt := ev.Count
		if cnt < 1 {
			cnt = 1
		}
		total += cnt
		sev := strings.ToLower(strings.TrimSpace(ev.Severity))
		bg, fg := "#e0f2fe", "#075985"
		switch sev {
		case SevCritical:
			d.CriticalCount += cnt
			bg, fg = "#fee2e2", "#991b1b"
		case SevWarn:
			d.WarnCount += cnt
			bg, fg = "#fef3c7", "#92400e"
		default:
			sev = SevInfo
			d.InfoCount += cnt
		}
		var pairs []emailDetailPair
		if len(ev.Details) > 0 {
			keys := make([]string, 0, len(ev.Details))
			for k := range ev.Details {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				pairs = append(pairs, emailDetailPair{Key: k, Value: ev.Details[k]})
			}
		}
		d.Events = append(d.Events, digestEventView{
			Category: ev.Category,
			Severity: sev,
			BadgeBg:  bg,
			BadgeFg:  fg,
			Title:    ev.Title,
			Summary:  ev.Summary,
			Count:    cnt,
			FirstAt:  ev.FirstAt.UTC().Format(time.RFC3339),
			LastAt:   ev.LastAt.UTC().Format(time.RFC3339),
			Details:  pairs,
		})
	}
	d.TotalEvents = total
	d.UniqueEvents = len(events)
	return d
}

func buildDigestSubject(d digestTemplateData) string {
	var parts []string
	if d.CriticalCount > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", d.CriticalCount))
	}
	if d.WarnCount > 0 {
		parts = append(parts, fmt.Sprintf("%d warning", d.WarnCount))
	}
	if d.InfoCount > 0 && len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d info", d.InfoCount))
	}
	if len(parts) > 0 {
		return fmt.Sprintf("[Concert · %s] Operational digest: %d event(s) (%s)", d.NodeID, d.TotalEvents, strings.Join(parts, ", "))
	}
	return fmt.Sprintf("[Concert · %s] Operational digest: %d event(s)", d.NodeID, d.TotalEvents)
}

func renderComposedMessage(cfg Config, recipient, subject string, d digestTemplateData, now time.Time) (Message, error) {
	var htmlBuf bytes.Buffer
	if err := digestHTMLTmpl.Execute(&htmlBuf, d); err != nil {
		return Message{}, fmt.Errorf("render html email: %w", err)
	}
	textBody := renderPlainText(d)

	headers := map[string]string{
		"Auto-Submitted": "auto-generated",
		"Precedence":     "bulk",
		"X-Concert-Node": d.NodeID,
		"X-Concert-Role": d.Role,
	}
	if d.UnsubscribeURL != "" {
		headers["List-Unsubscribe"] = "<" + d.UnsubscribeURL + ">"
		headers["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
	}

	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%v|%d|%d|%d", d.NodeID, strings.ToLower(recipient), d.IsTest, d.TotalEvents, d.UniqueEvents, now.UTC().Unix())
	for _, ev := range d.Events {
		_, _ = fmt.Fprintf(h, "|%s:%s:%d:%s", ev.Category, ev.Title, ev.Count, ev.LastAt)
	}
	idemKey := "concert-" + hex.EncodeToString(h.Sum(nil)[:16])

	return Message{
		FromName:       strings.TrimSpace(cfg.FromName),
		FromAddr:       strings.TrimSpace(cfg.FromAddr),
		To:             []string{recipient},
		Subject:        subject,
		TextBody:       textBody,
		HTMLBody:       htmlBuf.String(),
		Headers:        headers,
		IdempotencyKey: idemKey,
	}, nil
}

func renderPlainText(d digestTemplateData) string {
	var b strings.Builder
	title := "CONCERT OPERATIONAL DIGEST"
	if d.IsTest {
		title = "CONCERT EMAIL DELIVERY TEST"
	}
	if d.OrgName != "" {
		fmt.Fprintf(&b, "%s — %s\n", title, d.OrgName)
	} else {
		fmt.Fprintf(&b, "%s\n", title)
	}
	fmt.Fprintf(&b, "Node: %s | Role: %s | Time: %s\n", d.NodeID, d.Role, d.GeneratedAt)
	b.WriteString(strings.Repeat("=", 64) + "\n\n")

	if d.IsTest {
		b.WriteString("This is a test email triggered from Concert's Admin Portal to verify DNS,\n")
		b.WriteString("provider authentication, compliance headers, and formatting.\n\n")
		fmt.Fprintf(&b, "Provider:  %s\n", d.Provider)
		fmt.Fprintf(&b, "Recipient: %s\n", d.Recipient)
		fmt.Fprintf(&b, "Schedule:  %s\n", d.CadenceText)
		fmt.Fprintf(&b, "Version:   %s\n", d.Version)
	} else {
		fmt.Fprintf(&b, "Summary: %d total event(s) across %d distinct item(s)", d.TotalEvents, d.UniqueEvents)
		if d.CriticalCount > 0 {
			fmt.Fprintf(&b, " | %d critical", d.CriticalCount)
		}
		if d.WarnCount > 0 {
			fmt.Fprintf(&b, " | %d warning", d.WarnCount)
		}
		if d.InfoCount > 0 {
			fmt.Fprintf(&b, " | %d info", d.InfoCount)
		}
		if d.OverflowCount > 0 {
			fmt.Fprintf(&b, " | +%d overflow folded", d.OverflowCount)
		}
		b.WriteString("\n\n")
		for i, ev := range d.Events {
			fmt.Fprintf(&b, "%d. [%s][%s] %s", i+1, strings.ToUpper(ev.Severity), ev.Category, ev.Title)
			if ev.Count > 1 {
				fmt.Fprintf(&b, " (x%d)", ev.Count)
			}
			b.WriteString("\n")
			if ev.Summary != "" {
				fmt.Fprintf(&b, "   %s\n", ev.Summary)
			}
			for _, pair := range ev.Details {
				fmt.Fprintf(&b, "   - %s: %s\n", pair.Key, pair.Value)
			}
			fmt.Fprintf(&b, "   Last seen: %s", ev.LastAt)
			if ev.FirstAt != ev.LastAt {
				fmt.Fprintf(&b, " (first: %s)", ev.FirstAt)
			}
			b.WriteString("\n\n")
		}
	}

	b.WriteString(strings.Repeat("-", 64) + "\n")
	fmt.Fprintf(&b, "Automated notification from Concert (%s). Cadence: %s.\n", d.NodeID, d.CadenceText)
	if d.OrgName != "" {
		fmt.Fprintf(&b, "Organization: %s\n", d.OrgName)
	}
	if d.PostalAddress != "" {
		fmt.Fprintf(&b, "Address: %s\n", d.PostalAddress)
	}
	if d.PortalURL != "" {
		fmt.Fprintf(&b, "Admin Portal: %s\n", d.PortalURL)
	}
	if d.PrivacyURL != "" {
		fmt.Fprintf(&b, "Privacy Policy: %s\n", d.PrivacyURL)
	}
	if d.TermsURL != "" {
		fmt.Fprintf(&b, "Terms: %s\n", d.TermsURL)
	}
	if d.UnsubscribeURL != "" {
		fmt.Fprintf(&b, "Pause / Unsubscribe: %s\n", d.UnsubscribeURL)
	} else {
		b.WriteString("Manage or pause alerts in the Concert Admin Portal Email tab.\n")
	}
	return b.String()
}
