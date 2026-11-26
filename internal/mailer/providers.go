package mailer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	providerHTTPTimeout  = 15 * time.Second
	providerMaxBodyBytes = 64 << 10
)

// NewSender builds the configured provider Sender.
func NewSender(cfg Config, sec Secrets, httpClient *http.Client) (Sender, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	p := strings.ToLower(strings.TrimSpace(cfg.Provider))
	switch p {
	case ProviderOff:
		return nil, errors.New("email delivery is disabled")
	case ProviderSMTP:
		return &SMTPSender{
			Host:     strings.TrimSpace(cfg.SMTPHost),
			Port:     cfg.EffectiveSMTPPort(),
			TLSMode:  cfg.EffectiveSMTPTLS(),
			User:     strings.TrimSpace(cfg.SMTPUser),
			Pass:     sec.SMTPPass,
			FromAddr: strings.TrimSpace(cfg.FromAddr),
			NodeID:   cfg.NodeID,
		}, nil
	case ProviderResend:
		if strings.TrimSpace(sec.ResendAPIKey) == "" {
			return nil, errors.New("Resend API key is not configured (set CONCERT_RESEND_API_KEY or save it in the Email tab)")
		}
		return &ResendSender{
			BaseURL:  cfg.EffectiveResendBaseURL(),
			APIKey:   strings.TrimSpace(sec.ResendAPIKey),
			FromAddr: strings.TrimSpace(cfg.FromAddr),
			Version:  cfg.Version,
			Client:   httpClientOrDefault(httpClient),
		}, nil
	case ProviderSendPanda:
		if strings.TrimSpace(sec.SendPandaAPIKey) == "" {
			return nil, errors.New("SendPanda API key is not configured (set CONCERT_SENDPANDA_API_KEY or save it in the Email tab)")
		}
		return &SendPandaSender{
			BaseURL:  cfg.EffectiveSendPandaBaseURL(),
			APIKey:   strings.TrimSpace(sec.SendPandaAPIKey),
			FromAddr: strings.TrimSpace(cfg.FromAddr),
			Version:  cfg.Version,
			Client:   httpClientOrDefault(httpClient),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported email provider %q", cfg.Provider)
	}
}

func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: providerHTTPTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		// Never follow redirects on provider API calls so Bearer API keys cannot leak.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are disabled for email provider API requests")
		},
	}
}

func httpClientOrDefault(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return defaultHTTPClient()
}

func userAgent(version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		v = "dev"
	}
	return "concert/" + v
}

// ─── SMTP Sender ─────────────────────────────────────────────────────────────

// SMTPSender delivers RFC 5322 multipart/alternative emails via SMTP.
type SMTPSender struct {
	Host      string
	Port      int
	TLSMode   string
	User      string
	Pass      string
	FromAddr  string
	NodeID    string
	TLSConfig *tls.Config // optional override for tests
}

func (s *SMTPSender) Name() string { return ProviderSMTP }

func (s *SMTPSender) tlsConfig() *tls.Config {
	if s.TLSConfig != nil {
		tc := s.TLSConfig.Clone()
		if tc.MinVersion == 0 {
			tc.MinVersion = tls.VersionTLS12
		}
		if tc.ServerName == "" {
			tc.ServerName = s.Host
		}
		return tc
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: s.Host,
	}
}

func (s *SMTPSender) dial(ctx context.Context) (*smtp.Client, net.Conn, error) {
	port := s.Port
	if port <= 0 {
		if s.TLSMode == TLSImplicit {
			port = 465
		} else {
			port = 587
		}
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: providerHTTPTimeout}

	var conn net.Conn
	var err error
	mode := strings.ToLower(strings.TrimSpace(s.TLSMode))
	if mode == "" {
		mode = TLSStartTLS
	}

	if mode == TLSImplicit {
		td := &tls.Dialer{NetDialer: dialer, Config: s.tlsConfig()}
		conn, err = td.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("smtp dial %s: %w", addr, err)
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(providerHTTPTimeout))
	}

	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("smtp greeting %s: %w", addr, err)
	}

	helo := sanitizeHELO(s.NodeID, s.FromAddr)
	if err := c.Hello(helo); err != nil {
		_ = c.Close()
		return nil, nil, fmt.Errorf("smtp EHLO: %w", err)
	}

	if mode == TLSStartTLS {
		ok, _ := c.Extension("STARTTLS")
		if !ok {
			_ = c.Close()
			return nil, nil, errors.New("smtp server does not advertise STARTTLS (refusing plaintext downgrade)")
		}
		if err := c.StartTLS(s.tlsConfig()); err != nil {
			_ = c.Close()
			return nil, nil, fmt.Errorf("smtp STARTTLS: %w", err)
		}
	}

	if s.User != "" || s.Pass != "" {
		auth, err := s.chooseAuth(c, mode)
		if err != nil {
			_ = c.Close()
			return nil, nil, err
		}
		if err := c.Auth(auth); err != nil {
			_ = c.Close()
			return nil, nil, fmt.Errorf("smtp auth failed: %w", err)
		}
	}
	return c, conn, nil
}

func (s *SMTPSender) chooseAuth(c *smtp.Client, mode string) (smtp.Auth, error) {
	ok, param := c.Extension("AUTH")
	if !ok {
		return nil, errors.New("smtp server does not advertise AUTH")
	}
	mechs := strings.Fields(strings.ToUpper(param))
	allowPlaintext := mode == TLSNone
	hasMech := func(target string) bool {
		for _, m := range mechs {
			if m == target {
				return true
			}
		}
		return false
	}
	if hasMech("PLAIN") || len(mechs) == 0 {
		return &concertPlainAuth{
			user:           s.User,
			pass:           s.Pass,
			host:           s.Host,
			allowPlaintext: allowPlaintext,
		}, nil
	}
	if hasMech("LOGIN") {
		return &concertLoginAuth{
			user:           s.User,
			pass:           s.Pass,
			host:           s.Host,
			allowPlaintext: allowPlaintext,
		}, nil
	}
	return nil, fmt.Errorf("smtp server offers unsupported AUTH mechanisms (%s); need PLAIN or LOGIN", param)
}

func (s *SMTPSender) Send(ctx context.Context, msg Message) (SendResult, error) {
	fromAddr, err := ValidateAddress(msg.FromAddr)
	if err != nil {
		return SendResult{}, fmt.Errorf("invalid from address: %w", err)
	}
	if len(msg.To) == 0 {
		return SendResult{}, errors.New("message has no recipients")
	}
	recipients := make([]string, 0, len(msg.To))
	for _, rcpt := range msg.To {
		clean, err := ValidateAddress(rcpt)
		if err != nil {
			return SendResult{}, fmt.Errorf("invalid recipient %q: %w", rcpt, err)
		}
		recipients = append(recipients, clean)
	}

	raw, msgID, err := buildRFC5322Message(msg, fromAddr, recipients, time.Now().UTC())
	if err != nil {
		return SendResult{}, err
	}

	c, _, err := s.dial(ctx)
	if err != nil {
		return SendResult{}, err
	}
	defer func() { _ = c.Close() }()

	if err := c.Mail(fromAddr); err != nil {
		return SendResult{}, fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	for _, rcpt := range recipients {
		if err := c.Rcpt(rcpt); err != nil {
			return SendResult{}, fmt.Errorf("smtp RCPT TO %s: %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return SendResult{}, fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		_ = w.Close()
		return SendResult{}, fmt.Errorf("smtp write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return SendResult{}, fmt.Errorf("smtp commit DATA: %w", err)
	}
	_ = c.Quit()
	return SendResult{
		Provider:  ProviderSMTP,
		MessageID: msgID,
		SentAt:    time.Now().UTC(),
	}, nil
}

func (s *SMTPSender) VerifyConnection(ctx context.Context) error {
	c, _, err := s.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if err := c.Noop(); err != nil {
		return fmt.Errorf("smtp NOOP: %w", err)
	}
	_ = c.Quit()
	return nil
}

type concertPlainAuth struct {
	user, pass, host string
	allowPlaintext   bool
}

func (a *concertPlainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS && !a.allowPlaintext && !isLocalHost(server.Name) {
		return "", nil, errors.New("refusing SMTP PLAIN auth over unencrypted connection")
	}
	if server.Name != a.host {
		return "", nil, errors.New("SMTP server hostname mismatch")
	}
	resp := []byte("\x00" + a.user + "\x00" + a.pass)
	return "PLAIN", resp, nil
}

func (a *concertPlainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected SMTP PLAIN challenge")
	}
	return nil, nil
}

type concertLoginAuth struct {
	user, pass, host string
	allowPlaintext   bool
}

func (a *concertLoginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS && !a.allowPlaintext && !isLocalHost(server.Name) {
		return "", nil, errors.New("refusing SMTP LOGIN auth over unencrypted connection")
	}
	if server.Name != a.host {
		return "", nil, errors.New("SMTP server hostname mismatch")
	}
	return "LOGIN", nil, nil
}

func (a *concertLoginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	prompt := strings.ToLower(strings.TrimSpace(string(fromServer)))
	switch {
	case strings.Contains(prompt, "user"):
		return []byte(a.user), nil
	case strings.Contains(prompt, "pass"):
		return []byte(a.pass), nil
	default:
		return nil, fmt.Errorf("unexpected SMTP LOGIN prompt %q", string(fromServer))
	}
}

func isLocalHost(name string) bool {
	return name == "localhost" || name == "127.0.0.1" || name == "::1"
}

func sanitizeHELO(nodeID, fromAddr string) string {
	for _, cand := range []string{AddressDomain(fromAddr), nodeID, "concert.local"} {
		cand = strings.TrimSpace(cand)
		if cand == "" || strings.ContainsAny(cand, " \t\r\n\x00") {
			continue
		}
		return cand
	}
	return "concert.local"
}

func formatMailbox(name, addr string) (string, error) {
	cleanAddr, err := ValidateAddress(addr)
	if err != nil {
		return "", err
	}
	cleanName, err := SanitizeHeader(name)
	if err != nil {
		return "", err
	}
	if cleanName == "" {
		return cleanAddr, nil
	}
	return (&mail.Address{Name: cleanName, Address: cleanAddr}).String(), nil
}

func buildRFC5322Message(msg Message, fromAddr string, recipients []string, now time.Time) ([]byte, string, error) {
	fromHeader, err := formatMailbox(msg.FromName, fromAddr)
	if err != nil {
		return nil, "", fmt.Errorf("from header: %w", err)
	}
	subj, err := SanitizeHeader(msg.Subject)
	if err != nil {
		return nil, "", fmt.Errorf("subject header: %w", err)
	}

	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, "", err
	}
	boundary := "concert-" + hex.EncodeToString(rnd[:12])
	domain := AddressDomain(fromAddr)
	if domain == "" {
		domain = "concert.local"
	}
	msgID := fmt.Sprintf("<%s.%d@%s>", hex.EncodeToString(rnd[8:]), now.UnixNano(), domain)

	var buf bytes.Buffer
	writeHdr := func(k, v string) error {
		ck, err := SanitizeHeader(k)
		if err != nil || ck == "" || strings.ContainsAny(ck, ": \t") {
			return fmt.Errorf("invalid header name %q", k)
		}
		cv, err := SanitizeHeader(v)
		if err != nil {
			return fmt.Errorf("header %s: %w", ck, err)
		}
		buf.WriteString(ck)
		buf.WriteString(": ")
		buf.WriteString(cv)
		buf.WriteString("\r\n")
		return nil
	}

	if err := writeHdr("From", fromHeader); err != nil {
		return nil, "", err
	}
	if err := writeHdr("To", strings.Join(recipients, ", ")); err != nil {
		return nil, "", err
	}
	if err := writeHdr("Subject", mime.QEncoding.Encode("utf-8", subj)); err != nil {
		return nil, "", err
	}
	if err := writeHdr("Date", now.Format(time.RFC1123Z)); err != nil {
		return nil, "", err
	}
	if err := writeHdr("Message-ID", msgID); err != nil {
		return nil, "", err
	}
	if err := writeHdr("MIME-Version", "1.0"); err != nil {
		return nil, "", err
	}

	reserved := map[string]bool{
		"from": true, "to": true, "cc": true, "bcc": true,
		"subject": true, "date": true, "message-id": true,
		"mime-version": true, "content-type": true, "content-transfer-encoding": true,
	}
	hdrKeys := make([]string, 0, len(msg.Headers))
	for k := range msg.Headers {
		hdrKeys = append(hdrKeys, k)
	}
	sort.Strings(hdrKeys)
	for _, k := range hdrKeys {
		if reserved[strings.ToLower(strings.TrimSpace(k))] {
			continue
		}
		if err := writeHdr(k, msg.Headers[k]); err != nil {
			return nil, "", err
		}
	}

	if err := writeHdr("Content-Type", fmt.Sprintf("multipart/alternative; boundary=%q", boundary)); err != nil {
		return nil, "", err
	}
	buf.WriteString("\r\n")

	// Plain-text part
	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	qpw := quotedprintable.NewWriter(&buf)
	_, _ = qpw.Write([]byte(msg.TextBody))
	_ = qpw.Close()
	buf.WriteString("\r\n")

	// HTML part
	if strings.TrimSpace(msg.HTMLBody) != "" {
		buf.WriteString("--" + boundary + "\r\n")
		buf.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		qpw = quotedprintable.NewWriter(&buf)
		_, _ = qpw.Write([]byte(msg.HTMLBody))
		_ = qpw.Close()
		buf.WriteString("\r\n")
	}

	buf.WriteString("--" + boundary + "--\r\n")
	return buf.Bytes(), msgID, nil
}

// ─── Resend Sender ───────────────────────────────────────────────────────────

// ResendSender delivers emails via the Resend REST API.
type ResendSender struct {
	BaseURL  string
	APIKey   string
	FromAddr string
	Version  string
	Client   *http.Client
}

func (s *ResendSender) Name() string { return ProviderResend }

func (s *ResendSender) Send(ctx context.Context, msg Message) (SendResult, error) {
	return sendRESTEmail(ctx, ProviderResend, s.Client, s.BaseURL+"/emails", s.APIKey, s.Version, msg)
}

func (s *ResendSender) VerifyConnection(ctx context.Context) error {
	status, summary, detail := s.VerifyDetail(ctx)
	if status == "fail" {
		if detail != "" {
			return fmt.Errorf("%s: %s", summary, detail)
		}
		return errors.New(summary)
	}
	return nil
}

func (s *ResendSender) VerifyDetail(ctx context.Context) (status, summary, detail string) {
	endpoint := strings.TrimRight(s.BaseURL, "/") + "/domains"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "fail", "Invalid Resend endpoint", err.Error()
	}
	req.Header.Set("Authorization", "Bearer "+s.APIKey)
	req.Header.Set("User-Agent", userAgent(s.Version))
	req.Header.Set("Accept", "application/json")

	resp, err := httpClientOrDefault(s.Client).Do(req)
	if err != nil {
		return "fail", "Could not reach Resend API", err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, providerMaxBodyBytes))

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Resend send-only keys return 401 with "restricted to only send emails".
		lower := strings.ToLower(string(body))
		if strings.Contains(lower, "restricted") && strings.Contains(lower, "send") {
			return "warn", "Resend API reachable (send-only key)", "Key is restricted to sending only so /domains could not be inspected; use Send Test Email to verify."
		}
		return "fail", fmt.Sprintf("Resend authentication failed (HTTP %d)", resp.StatusCode), extractAPIError(body)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "fail", fmt.Sprintf("Resend API returned HTTP %d", resp.StatusCode), extractAPIError(body)
	}

	fromDomain := AddressDomain(s.FromAddr)
	if fromDomain == "" {
		return "pass", "Resend API authenticated", "HTTP 200 from /domains"
	}
	var parsed struct {
		Data []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &parsed) == nil && len(parsed.Data) > 0 {
		for _, d := range parsed.Data {
			if strings.EqualFold(d.Name, fromDomain) {
				if strings.EqualFold(d.Status, "verified") {
					return "pass", fmt.Sprintf("Resend authenticated; domain %s is verified", fromDomain), ""
				}
				return "warn", fmt.Sprintf("Resend authenticated; domain %s status is %q", fromDomain, d.Status), "Verify the sender domain in Resend before relying on production delivery."
			}
		}
		return "warn", fmt.Sprintf("Resend authenticated; domain %s not listed in account", fromDomain), "Add and verify this From domain in your Resend dashboard."
	}
	return "pass", "Resend API authenticated", "HTTP 200 from /domains"
}

// ─── SendPanda Sender ────────────────────────────────────────────────────────

// SendPandaSender delivers emails via the SendPanda (sendpanda.email) REST API.
type SendPandaSender struct {
	BaseURL  string
	APIKey   string
	FromAddr string
	Version  string
	Client   *http.Client
}

func (s *SendPandaSender) Name() string { return ProviderSendPanda }

func (s *SendPandaSender) Send(ctx context.Context, msg Message) (SendResult, error) {
	return sendRESTEmail(ctx, ProviderSendPanda, s.Client, strings.TrimRight(s.BaseURL, "/")+"/emails", s.APIKey, s.Version, msg)
}

func (s *SendPandaSender) VerifyConnection(ctx context.Context) error {
	status, summary, detail := s.VerifyDetail(ctx)
	if status == "fail" {
		if detail != "" {
			return fmt.Errorf("%s: %s", summary, detail)
		}
		return errors.New(summary)
	}
	return nil
}

func (s *SendPandaSender) VerifyDetail(ctx context.Context) (status, summary, detail string) {
	endpoint := strings.TrimRight(s.BaseURL, "/") + "/domains"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "fail", "Invalid SendPanda endpoint", err.Error()
	}
	req.Header.Set("Authorization", "Bearer "+s.APIKey)
	req.Header.Set("User-Agent", userAgent(s.Version))
	req.Header.Set("Accept", "application/json")

	resp, err := httpClientOrDefault(s.Client).Do(req)
	if err != nil {
		return "fail", "Could not reach SendPanda API", err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, providerMaxBodyBytes))

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return "fail", fmt.Sprintf("SendPanda authentication failed (HTTP %d)", resp.StatusCode), extractAPIError(body)
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		fromDomain := AddressDomain(s.FromAddr)
		var parsed struct {
			Data []struct {
				Name   string `json:"name"`
				Domain string `json:"domain"`
				Status string `json:"status"`
			} `json:"data"`
		}
		if fromDomain != "" && json.Unmarshal(body, &parsed) == nil && len(parsed.Data) > 0 {
			for _, d := range parsed.Data {
				name := d.Name
				if name == "" {
					name = d.Domain
				}
				if strings.EqualFold(name, fromDomain) {
					if strings.EqualFold(d.Status, "verified") || strings.EqualFold(d.Status, "active") {
						return "pass", fmt.Sprintf("SendPanda authenticated; domain %s is %s", fromDomain, d.Status), ""
					}
					return "warn", fmt.Sprintf("SendPanda authenticated; domain %s status is %q", fromDomain, d.Status), "Verify the sender domain in SendPanda before production delivery."
				}
			}
		}
		return "pass", "SendPanda API authenticated", "HTTP 200 from /domains"
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed:
		return "warn", fmt.Sprintf("SendPanda API reachable (HTTP %d on /domains)", resp.StatusCode), "TLS connectivity confirmed; send a Test Email to verify full API key and domain authorization."
	default:
		return "fail", fmt.Sprintf("SendPanda API returned HTTP %d", resp.StatusCode), extractAPIError(body)
	}
}

// ─── Shared REST Email Dispatch ──────────────────────────────────────────────

type restEmailPayload struct {
	From    string            `json:"from"`
	To      []string          `json:"to"`
	Subject string            `json:"subject"`
	HTML    string            `json:"html,omitempty"`
	Text    string            `json:"text,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

func sendRESTEmail(ctx context.Context, provider string, client *http.Client, endpoint, apiKey, version string, msg Message) (SendResult, error) {
	fromHeader, err := formatMailbox(msg.FromName, msg.FromAddr)
	if err != nil {
		return SendResult{}, fmt.Errorf("invalid from address: %w", err)
	}
	if len(msg.To) == 0 {
		return SendResult{}, errors.New("message has no recipients")
	}
	to := make([]string, 0, len(msg.To))
	for _, rcpt := range msg.To {
		clean, err := ValidateAddress(rcpt)
		if err != nil {
			return SendResult{}, fmt.Errorf("invalid recipient %q: %w", rcpt, err)
		}
		to = append(to, clean)
	}
	subj, err := SanitizeHeader(msg.Subject)
	if err != nil {
		return SendResult{}, fmt.Errorf("invalid subject: %w", err)
	}

	cleanHeaders := map[string]string{}
	for k, v := range msg.Headers {
		ck, err := SanitizeHeader(k)
		if err != nil || ck == "" {
			return SendResult{}, fmt.Errorf("invalid header name %q", k)
		}
		cv, err := SanitizeHeader(v)
		if err != nil {
			return SendResult{}, fmt.Errorf("header %s: %w", ck, err)
		}
		cleanHeaders[ck] = cv
	}

	payload := restEmailPayload{
		From:    fromHeader,
		To:      to,
		Subject: subj,
		HTML:    msg.HTMLBody,
		Text:    msg.TextBody,
		Headers: cleanHeaders,
	}
	rawBody, err := json.Marshal(payload)
	if err != nil {
		return SendResult{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(rawBody))
	if err != nil {
		return SendResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent(version))
	if ik, err := SanitizeHeader(msg.IdempotencyKey); err == nil && ik != "" {
		req.Header.Set("Idempotency-Key", ik)
	}

	resp, err := httpClientOrDefault(client).Do(req)
	if err != nil {
		return SendResult{}, fmt.Errorf("%s request failed: %w", provider, err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, providerMaxBodyBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := extractAPIError(respBytes)
		if detail != "" {
			return SendResult{}, fmt.Errorf("%s API error (HTTP %d): %s", provider, resp.StatusCode, detail)
		}
		return SendResult{}, fmt.Errorf("%s API error (HTTP %d)", provider, resp.StatusCode)
	}

	var parsed struct {
		ID   string `json:"id"`
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(respBytes, &parsed)
	msgID := parsed.ID
	if msgID == "" {
		msgID = parsed.Data.ID
	}
	return SendResult{
		Provider:  provider,
		MessageID: msgID,
		SentAt:    time.Now().UTC(),
	}, nil
}

func extractAPIError(body []byte) string {
	var obj struct {
		Message string `json:"message"`
		Error   any    `json:"error"`
	}
	if json.Unmarshal(body, &obj) == nil {
		if obj.Message != "" {
			return clipString(obj.Message, 240)
		}
		switch e := obj.Error.(type) {
		case string:
			if e != "" {
				return clipString(e, 240)
			}
		case map[string]any:
			if m, ok := e["message"].(string); ok && m != "" {
				return clipString(m, 240)
			}
		}
	}
	s := strings.TrimSpace(string(body))
	return clipString(s, 240)
}

func clipString(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…"
}
