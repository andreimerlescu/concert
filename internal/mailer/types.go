package mailer

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Supported delivery providers. ProviderOff disables email delivery.
const (
	ProviderOff       = ""
	ProviderSMTP      = "smtp"
	ProviderResend    = "resend"
	ProviderSendPanda = "sendpanda"
)

// SMTP transport security modes.
const (
	TLSStartTLS = "starttls"
	TLSImplicit = "tls"
	TLSNone     = "none"
)

// Default REST API base URLs for HTTP providers.
const (
	DefaultResendBaseURL    = "https://api.resend.com"
	DefaultSendPandaBaseURL = "https://api.sendpanda.email/v1"
)

// Toggleable operational event categories.
const (
	CatSilence  = "silence"
	CatCapacity = "capacity"
	CatBans     = "bans"
	CatFastlane = "fastlane"
	CatQueue    = "queue"
	CatSecurity = "security"
)

// AllCategories lists every supported event category in display order.
var AllCategories = []string{
	CatSilence,
	CatCapacity,
	CatBans,
	CatFastlane,
	CatQueue,
	CatSecurity,
}

// Event severity levels.
const (
	SevInfo     = "info"
	SevWarn     = "warn"
	SevCritical = "critical"
)

// Cadence window units.
const (
	UnitMinutes = "minutes"
	UnitHours   = "hours"
	UnitDays    = "days"
)

// Cadence safety bounds.
const (
	MinCadenceWindow = 15 * time.Minute
	MaxCadenceWindow = 30 * 24 * time.Hour
	MinCadencePace   = time.Minute
	MaxCadenceEmails = 1000
)

// Cadence defines both a rolling hard cap (MaxEmails per Window) and an even
// pacing interval (Window / MaxEmails) enforced by the delivery scheduler.
// Examples:
//   - "send 1 email every 15 minutes"  -> MaxEmails: 1,   WindowValue: 15, WindowUnit: "minutes"
//   - "send 4 emails every 90 minutes" -> MaxEmails: 4,   WindowValue: 90, WindowUnit: "minutes"
//   - "send 333 emails every 28 days"  -> MaxEmails: 333, WindowValue: 28, WindowUnit: "days"
type Cadence struct {
	MaxEmails   int    `json:"max_emails"`
	WindowValue int    `json:"window_value"`
	WindowUnit  string `json:"window_unit"`
}

// DefaultCadence returns the conservative default schedule: 1 email every 15 minutes.
func DefaultCadence() Cadence {
	return Cadence{
		MaxEmails:   1,
		WindowValue: 15,
		WindowUnit:  UnitMinutes,
	}
}

// Window returns the cadence duration after validating its unit and range.
func (c Cadence) Window() (time.Duration, error) {
	if c.WindowValue < 1 {
		return 0, fmt.Errorf("cadence window value %d must be at least 1", c.WindowValue)
	}
	var unit time.Duration
	switch strings.ToLower(strings.TrimSpace(c.WindowUnit)) {
	case UnitMinutes, "minute", "min", "m":
		unit = time.Minute
	case UnitHours, "hour", "hr", "h":
		unit = time.Hour
	case UnitDays, "day", "d":
		unit = 24 * time.Hour
	default:
		return 0, fmt.Errorf("invalid cadence window unit %q: must be minutes, hours, or days", c.WindowUnit)
	}
	// Guard against int64 overflow before multiplying.
	if int64(c.WindowValue) > int64(MaxCadenceWindow/unit) {
		return 0, fmt.Errorf("cadence window %d %s exceeds maximum of 30 days", c.WindowValue, c.WindowUnit)
	}
	w := time.Duration(c.WindowValue) * unit
	if w < MinCadenceWindow {
		return 0, fmt.Errorf("cadence window %s must be at least %s", w, MinCadenceWindow)
	}
	if w > MaxCadenceWindow {
		return 0, fmt.Errorf("cadence window %s must be at most 30 days", w)
	}
	return w, nil
}

// NormalizeUnit canonicalizes a unit string to minutes, hours, or days.
func NormalizeUnit(u string) string {
	switch strings.ToLower(strings.TrimSpace(u)) {
	case UnitMinutes, "minute", "min", "m":
		return UnitMinutes
	case UnitHours, "hour", "hr", "h":
		return UnitHours
	case UnitDays, "day", "d":
		return UnitDays
	default:
		return strings.ToLower(strings.TrimSpace(u))
	}
}

// Validate checks MaxEmails, Window bounds, and minimum inter-email pace.
func (c Cadence) Validate() error {
	if c.MaxEmails < 1 || c.MaxEmails > MaxCadenceEmails {
		return fmt.Errorf("cadence max emails %d must be between 1 and %d", c.MaxEmails, MaxCadenceEmails)
	}
	w, err := c.Window()
	if err != nil {
		return err
	}
	pace := w / time.Duration(c.MaxEmails)
	if pace < MinCadencePace {
		return fmt.Errorf("cadence %d emails per %d %s paces faster than 1 email per minute (%s)",
			c.MaxEmails, c.WindowValue, NormalizeUnit(c.WindowUnit), pace.Round(time.Second))
	}
	return nil
}

// Pace returns the minimum spacing between consecutive digest dispatches.
func (c Cadence) Pace() time.Duration {
	w, err := c.Window()
	if err != nil || c.MaxEmails < 1 {
		return MinCadenceWindow
	}
	p := w / time.Duration(c.MaxEmails)
	if p < MinCadencePace {
		return MinCadencePace
	}
	return p
}

// String renders the cadence as a human-readable phrase.
func (c Cadence) String() string {
	unit := NormalizeUnit(c.WindowUnit)
	if c.WindowValue == 1 {
		unit = strings.TrimSuffix(unit, "s")
	}
	noun := "emails"
	if c.MaxEmails == 1 {
		noun = "email"
	}
	return fmt.Sprintf("%d %s every %d %s", c.MaxEmails, noun, c.WindowValue, unit)
}

// ComplianceConfig holds organization identity and legal links rendered in
// digest footers and RFC 8058 unsubscribe headers.
type ComplianceConfig struct {
	OrgName       string `json:"org_name"`
	PostalAddress string `json:"postal_address"`
	PrivacyURL    string `json:"privacy_url"`
	TermsURL      string `json:"terms_url"`
	PortalURL     string `json:"portal_url"`
	PublicBaseURL string `json:"public_base_url"`
}

// Config holds non-secret delivery, schedule, category, and compliance settings.
type Config struct {
	Provider         string           `json:"provider"`
	SMTPHost         string           `json:"smtp_host"`
	SMTPPort         int              `json:"smtp_port"`
	SMTPTLS          string           `json:"smtp_tls"`
	SMTPUser         string           `json:"smtp_user"`
	ResendBaseURL    string           `json:"resend_base_url"`
	SendPandaBaseURL string           `json:"sendpanda_base_url"`
	FromName         string           `json:"from_name"`
	FromAddr         string           `json:"from_addr"`
	ToAddrs          []string         `json:"to_addrs"`
	DKIMSelector     string           `json:"dkim_selector"`
	Cadence          Cadence          `json:"cadence"`
	Categories       map[string]bool  `json:"categories"`
	Compliance       ComplianceConfig `json:"compliance"`

	// Runtime metadata supplied by Concert.
	Hardened bool   `json:"-"`
	NodeID   string `json:"-"`
	Role     string `json:"-"`
	Version  string `json:"-"`
}

// Enabled reports whether a delivery provider is configured.
func (c Config) Enabled() bool {
	return strings.TrimSpace(c.Provider) != ProviderOff
}

// CategoryEnabled reports whether events in cat are subscribed for queuing.
func (c Config) CategoryEnabled(cat string) bool {
	if len(c.Categories) == 0 {
		return false
	}
	return c.Categories[strings.ToLower(strings.TrimSpace(cat))]
}

// EffectiveResendBaseURL returns the configured Resend endpoint or default.
func (c Config) EffectiveResendBaseURL() string {
	if u := strings.TrimRight(strings.TrimSpace(c.ResendBaseURL), "/"); u != "" {
		return u
	}
	return DefaultResendBaseURL
}

// EffectiveSendPandaBaseURL returns the configured SendPanda endpoint or default.
func (c Config) EffectiveSendPandaBaseURL() string {
	if u := strings.TrimRight(strings.TrimSpace(c.SendPandaBaseURL), "/"); u != "" {
		return u
	}
	return DefaultSendPandaBaseURL
}

// EffectiveSMTPTLS returns the normalized SMTP TLS mode.
func (c Config) EffectiveSMTPTLS() string {
	if m := strings.ToLower(strings.TrimSpace(c.SMTPTLS)); m != "" {
		return m
	}
	return TLSStartTLS
}

// EffectiveSMTPPort returns the configured SMTP port or the mode's default.
func (c Config) EffectiveSMTPPort() int {
	if c.SMTPPort > 0 {
		return c.SMTPPort
	}
	if c.EffectiveSMTPTLS() == TLSImplicit {
		return 465
	}
	return 587
}

// Validate verifies provider, addresses, header safety, cadence, and URLs.
func (c Config) Validate() error {
	p := strings.ToLower(strings.TrimSpace(c.Provider))
	switch p {
	case ProviderOff, ProviderSMTP, ProviderResend, ProviderSendPanda:
	default:
		return fmt.Errorf("invalid email provider %q: must be empty, smtp, resend, or sendpanda", c.Provider)
	}

	if err := c.Cadence.Validate(); err != nil {
		return err
	}

	if _, err := SanitizeHeader(c.FromName); err != nil {
		return fmt.Errorf("from name: %w", err)
	}
	if _, err := SanitizeHeader(c.Compliance.OrgName); err != nil {
		return fmt.Errorf("organization name: %w", err)
	}
	if _, err := SanitizeHeader(c.Compliance.PostalAddress); err != nil {
		return fmt.Errorf("postal address: %w", err)
	}
	if c.DKIMSelector != "" {
		if err := validateDNSLabel(c.DKIMSelector); err != nil {
			return fmt.Errorf("dkim selector: %w", err)
		}
	}

	for label, raw := range map[string]string{
		"privacy_url":     c.Compliance.PrivacyURL,
		"terms_url":       c.Compliance.TermsURL,
		"portal_url":      c.Compliance.PortalURL,
		"public_base_url": c.Compliance.PublicBaseURL,
	} {
		if strings.TrimSpace(raw) != "" {
			if err := ValidateHTTPURL(raw, false); err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
		}
	}

	if c.ResendBaseURL != "" {
		if err := ValidateHTTPURL(c.ResendBaseURL, c.Hardened); err != nil {
			return fmt.Errorf("resend base URL: %w", err)
		}
	}
	if c.SendPandaBaseURL != "" {
		if err := ValidateHTTPURL(c.SendPandaBaseURL, c.Hardened); err != nil {
			return fmt.Errorf("sendpanda base URL: %w", err)
		}
	}

	tlsMode := c.EffectiveSMTPTLS()
	switch tlsMode {
	case TLSStartTLS, TLSImplicit, TLSNone:
	default:
		return fmt.Errorf("invalid SMTP TLS mode %q: must be starttls, tls, or none", c.SMTPTLS)
	}
	if c.SMTPPort < 0 || c.SMTPPort > 65535 {
		return fmt.Errorf("invalid SMTP port %d: must be between 1 and 65535", c.SMTPPort)
	}

	if c.FromAddr != "" {
		if _, err := ValidateAddress(c.FromAddr); err != nil {
			return fmt.Errorf("from address: %w", err)
		}
	}
	for _, to := range c.ToAddrs {
		if _, err := ValidateAddress(to); err != nil {
			return fmt.Errorf("recipient %q: %w", to, err)
		}
	}

	if p == ProviderOff {
		return nil
	}

	if strings.TrimSpace(c.FromAddr) == "" {
		return errors.New("from address is required when email delivery is enabled")
	}
	if len(c.ToAddrs) == 0 {
		return errors.New("at least one recipient email address is required when email delivery is enabled")
	}

	switch p {
	case ProviderSMTP:
		host := strings.TrimSpace(c.SMTPHost)
		if host == "" {
			return errors.New("SMTP host is required when provider is smtp")
		}
		if _, err := SanitizeHeader(host); err != nil || strings.ContainsAny(host, " \t/:") {
			return fmt.Errorf("invalid SMTP host %q", c.SMTPHost)
		}
		if c.Hardened && tlsMode == TLSNone {
			return errors.New("SMTP TLS mode \"none\" is forbidden when enterprise-hardened mode is enabled")
		}
	case ProviderResend:
		if err := ValidateHTTPURL(c.EffectiveResendBaseURL(), c.Hardened); err != nil {
			return fmt.Errorf("resend base URL: %w", err)
		}
	case ProviderSendPanda:
		if err := ValidateHTTPURL(c.EffectiveSendPandaBaseURL(), c.Hardened); err != nil {
			return fmt.Errorf("sendpanda base URL: %w", err)
		}
	}
	return nil
}

// Event is an operational incident or security notice submitted to the mailer queue.
type Event struct {
	Category    string            `json:"category"`
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Summary     string            `json:"summary"`
	Fingerprint string            `json:"fingerprint"`
	Details     map[string]string `json:"details,omitempty"`
	At          time.Time         `json:"at"`
}

// QueuedEvent represents a coalesced pending event waiting for the next digest.
type QueuedEvent struct {
	Event
	Count   int       `json:"count"`
	FirstAt time.Time `json:"first_at"`
	LastAt  time.Time `json:"last_at"`
}

// SeverityRank returns an ordering weight (higher = more severe).
func SeverityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case SevCritical:
		return 3
	case SevWarn:
		return 2
	default:
		return 1
	}
}

// Message is a composed email ready for transmission by a Sender.
type Message struct {
	FromName       string
	FromAddr       string
	To             []string
	Subject        string
	TextBody       string
	HTMLBody       string
	Headers        map[string]string
	IdempotencyKey string
}

// SendResult captures provider confirmation after accepting a message.
type SendResult struct {
	Provider  string    `json:"provider"`
	MessageID string    `json:"message_id,omitempty"`
	SentAt    time.Time `json:"sent_at"`
}

// Sender transmits composed emails and probes provider connectivity.
type Sender interface {
	Name() string
	Send(ctx context.Context, msg Message) (SendResult, error)
	VerifyConnection(ctx context.Context) error
}

// DetailVerifier is optionally implemented by Senders that can provide
// richer diagnostic status ("pass", "warn", "fail") during verification.
type DetailVerifier interface {
	VerifyDetail(ctx context.Context) (status, summary, detail string)
}

// SanitizeHeader rejects control characters that could allow RFC 5322 header injection.
func SanitizeHeader(s string) (string, error) {
	if strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("must not contain CR, LF, or NUL characters")
	}
	return strings.TrimSpace(s), nil
}

// ValidateAddress parses and validates a single email address, returning the
// canonical bare mailbox address (local@domain).
func ValidateAddress(raw string) (string, error) {
	s, err := SanitizeHeader(raw)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", errors.New("email address is empty")
	}
	if len(s) > 254 {
		return "", errors.New("email address exceeds 254 characters")
	}
	parsed, err := mail.ParseAddress(s)
	if err != nil {
		return "", fmt.Errorf("invalid email address: %w", err)
	}
	addr := strings.TrimSpace(parsed.Address)
	if strings.ContainsAny(addr, " \t\r\n\x00") {
		return "", errors.New("email address contains invalid characters")
	}
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at >= len(addr)-1 {
		return "", errors.New("email address must contain local and domain parts")
	}
	domain := addr[at+1:]
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", fmt.Errorf("email domain %q must be a fully qualified domain name", domain)
	}
	return addr, nil
}

// AddressDomain extracts the lowercase domain portion of an email address.
func AddressDomain(addr string) string {
	clean, err := ValidateAddress(addr)
	if err != nil {
		return ""
	}
	at := strings.LastIndex(clean, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(clean[at+1:])
}

// ParseAddressList splits a comma-separated list of email addresses,
// validates each one, and removes case-insensitive duplicates.
func ParseAddressList(spec string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		addr, err := ValidateAddress(part)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", part, err)
		}
		key := strings.ToLower(addr)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, addr)
	}
	return out, nil
}

// ParseCategoryList parses a comma-separated list of event categories.
// Empty string defaults to all categories; "none" disables all categories.
func ParseCategoryList(spec string) (map[string]bool, error) {
	s := strings.TrimSpace(spec)
	out := make(map[string]bool, len(AllCategories))
	if s == "" {
		for _, cat := range AllCategories {
			out[cat] = true
		}
		return out, nil
	}
	if strings.EqualFold(s, "none") {
		return out, nil
	}
	for _, part := range strings.Split(s, ",") {
		cat := strings.ToLower(strings.TrimSpace(part))
		if cat == "" {
			continue
		}
		if !slices.Contains(AllCategories, cat) {
			return nil, fmt.Errorf("unknown email event category %q (valid: %s)", cat, strings.Join(AllCategories, ", "))
		}
		out[cat] = true
	}
	return out, nil
}

// FormatCategoryList returns a deterministic comma-separated category list.
func FormatCategoryList(cats map[string]bool) string {
	var enabled []string
	for _, cat := range AllCategories {
		if cats[cat] {
			enabled = append(enabled, cat)
		}
	}
	if len(enabled) == 0 {
		return "none"
	}
	return strings.Join(enabled, ",")
}

// ValidateHTTPURL checks that raw is a clean http(s) URL without control chars.
func ValidateHTTPURL(raw string, requireHTTPS bool) error {
	s, err := SanitizeHeader(raw)
	if err != nil {
		return err
	}
	if len(s) > 2048 || strings.ContainsAny(s, " \t\"<>") {
		return errors.New("URL contains invalid characters or is too long")
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return errors.New("must be a valid URL with scheme and host")
	}
	scheme := strings.ToLower(u.Scheme)
	if requireHTTPS {
		if scheme != "https" {
			return errors.New("must use https:// when enterprise-hardened mode is enabled")
		}
		return nil
	}
	if scheme != "http" && scheme != "https" {
		return errors.New("must use http:// or https://")
	}
	return nil
}

func validateDNSLabel(s string) error {
	if _, err := SanitizeHeader(s); err != nil {
		return err
	}
	if len(s) > 63 {
		return errors.New("must be at most 63 characters")
	}
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
		if !ok {
			return fmt.Errorf("invalid character %q in DNS selector", r)
		}
	}
	return nil
}
