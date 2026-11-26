package mailer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreimerlescu/concert/internal/opt"
)

const (
	// QueueFileName is the durable queue and cadence budget file in -data-dir.
	QueueFileName = "email-queue.json"

	queueFileVersion   = 1
	maxPendingEvents   = 500
	defaultTickEvery   = 15 * time.Second
	minEnqueueSaveGap  = time.Second
	maxSendHistoryKeep = MaxCadenceEmails + 64
)

var backoffSchedule = []time.Duration{
	1 * time.Minute,
	5 * time.Minute,
	15 * time.Minute,
	1 * time.Hour,
}

// DeliveryRecord captures the outcome of the most recent digest send attempt.
type DeliveryRecord struct {
	At         time.Time `json:"at"`
	Provider   string    `json:"provider"`
	Recipients int       `json:"recipients"`
	EventCount int       `json:"event_count"`
	MessageID  string    `json:"message_id,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// StatusSnapshot is the read-only view served by the Admin Portal /api/email.
// NextEligibleAt and BackoffUntil use opt.Option[time.Time] with json omitzero
// so absent timestamps are omitted from JSON while present timestamps marshal
// as RFC 3339 strings without heap-allocated pointers.
type StatusSnapshot struct {
	Enabled             bool                  `json:"enabled"`
	Provider            string                `json:"provider"`
	Paused              bool                  `json:"paused"`
	Unsubscribed        map[string]time.Time  `json:"unsubscribed"`
	Cadence             Cadence               `json:"cadence"`
	CadenceText         string                `json:"cadence_text"`
	WindowSeconds       int64                 `json:"window_seconds"`
	PaceSeconds         int64                 `json:"pace_seconds"`
	SentInWindow        int                   `json:"sent_in_window"`
	RemainingInWindow   int                   `json:"remaining_in_window"`
	NextEligibleAt      opt.Option[time.Time] `json:"next_eligible_at,omitzero"`
	QueuedUnique        int                   `json:"queued_unique"`
	QueuedTotal         int                   `json:"queued_total"`
	OverflowCount       int                   `json:"overflow_count"`
	Pending             []QueuedEvent         `json:"pending"`
	SentTotal           int64                 `json:"sent_total"`
	ErrorTotal          int64                 `json:"error_total"`
	ConsecutiveFailures int                   `json:"consecutive_failures"`
	BackoffUntil        opt.Option[time.Time] `json:"backoff_until,omitzero"`
	LastDelivery        *DeliveryRecord       `json:"last_delivery,omitempty"`
	Secrets             SecretStatus          `json:"secrets"`
}

type queueDiskDoc struct {
	Version             int                  `json:"version"`
	Paused              bool                 `json:"paused"`
	Unsubscribed        map[string]time.Time `json:"unsubscribed,omitempty"`
	SentAt              []time.Time          `json:"sent_at,omitempty"`
	Pending             []QueuedEvent        `json:"pending,omitempty"`
	OverflowCount       int                  `json:"overflow_count,omitempty"`
	ConsecutiveFailures int                  `json:"consecutive_failures,omitempty"`
	BackoffUntil        time.Time            `json:"backoff_until,omitempty"`
	LastDelivery        *DeliveryRecord      `json:"last_delivery,omitempty"`
	SentTotal           int64                `json:"sent_total,omitempty"`
	ErrorTotal          int64                `json:"error_total,omitempty"`
}

// SenderFactory creates a Sender for the given Config and Secrets.
type SenderFactory func(cfg Config, sec Secrets) (Sender, error)

// ServiceOptions configures a Service instance.
type ServiceOptions struct {
	DataDir         string
	Config          Config
	Secrets         *SecretStore
	UnsubSecret     []byte
	UnsubSecretPrev []byte
	HTTPClient      *http.Client
	SenderFactory   SenderFactory
	Resolver        DNSResolver
	Now             func() time.Time
	TickInterval    time.Duration
}

// Service owns the durable event queue, cadence enforcer, and digest scheduler.
type Service struct {
	path            string
	secrets         *SecretStore
	unsubSecret     []byte
	unsubSecretPrev []byte
	httpClient      *http.Client
	senderFactory   SenderFactory
	resolver        DNSResolver
	now             func() time.Time
	tickEvery       time.Duration

	sendMu sync.Mutex // serializes outbound digest deliveries

	mu                  sync.Mutex
	cfg                 Config
	paused              bool
	unsubscribed        map[string]time.Time
	sentAt              []time.Time
	pending             []QueuedEvent
	pendingIdx          map[string]int // fingerprint -> index in pending
	overflowCount       int
	consecutiveFailures int
	backoffUntil        time.Time
	lastDelivery        *DeliveryRecord
	dirty               bool
	lastSave            time.Time

	sentTotal  atomic.Int64
	errorTotal atomic.Int64

	wake     chan struct{}
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewService constructs a Service and restores email-queue.json from DataDir if present.
func NewService(opts ServiceOptions) *Service {
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	tick := opts.TickInterval
	if tick <= 0 {
		tick = defaultTickEvery
	}
	httpClient := httpClientOrDefault(opts.HTTPClient)
	factory := opts.SenderFactory
	if factory == nil {
		factory = func(cfg Config, sec Secrets) (Sender, error) {
			return NewSender(cfg, sec, httpClient)
		}
	}
	if opts.Config.Cadence.WindowUnit == "" && opts.Config.Cadence.MaxEmails == 0 {
		opts.Config.Cadence = DefaultCadence()
	}

	s := &Service{
		secrets:         opts.Secrets,
		unsubSecret:     append([]byte(nil), opts.UnsubSecret...),
		unsubSecretPrev: append([]byte(nil), opts.UnsubSecretPrev...),
		httpClient:      httpClient,
		senderFactory:   factory,
		resolver:        opts.Resolver,
		now:             nowFn,
		tickEvery:       tick,
		cfg:             cloneConfig(opts.Config),
		unsubscribed:    map[string]time.Time{},
		pendingIdx:      map[string]int{},
		wake:            make(chan struct{}, 1),
		stop:            make(chan struct{}),
	}
	if opts.DataDir != "" {
		s.path = filepath.Join(opts.DataDir, QueueFileName)
		s.loadDisk()
	}
	return s
}

// Start launches the background digest scheduler loop.
func (s *Service) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.loop()
	}()
}

// Close stops the background scheduler and flushes any dirty queue state to disk.
func (s *Service) Close() {
	s.stopOnce.Do(func() {
		close(s.stop)
		s.wg.Wait()
		s.mu.Lock()
		if s.dirty {
			s.persistLocked()
		}
		s.mu.Unlock()
	})
}

func (s *Service) loop() {
	t := time.NewTicker(s.tickEvery)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-s.wake:
			s.tick()
		case <-t.C:
			s.tick()
		}
	}
}

func (s *Service) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Service) tick() {
	s.mu.Lock()
	if s.dirty {
		s.persistLocked()
	}
	hasWork := s.cfg.Enabled() && !s.paused && (len(s.pending) > 0 || s.overflowCount > 0)
	s.mu.Unlock()
	if !hasWork {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = s.dispatch(ctx, false)
}

// UpdateConfig hot-reloads non-secret email settings.
func (s *Service) UpdateConfig(cfg Config) {
	if cfg.Cadence.WindowUnit == "" && cfg.Cadence.MaxEmails == 0 {
		cfg.Cadence = DefaultCadence()
	}
	s.mu.Lock()
	s.cfg = cloneConfig(cfg)
	s.mu.Unlock()
	s.signal()
}

// Config returns a copy of the active email configuration.
func (s *Service) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneConfig(s.cfg)
}

// Secrets returns the Service's secret store.
func (s *Service) Secrets() *SecretStore {
	return s.secrets
}

// Enqueue records an operational event if email delivery is enabled and the
// event's category is subscribed. Events sharing a Fingerprint coalesce into
// one queued entry with an incremented counter.
func (s *Service) Enqueue(ev Event) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.cfg.Enabled() {
		return false
	}
	cat := strings.ToLower(strings.TrimSpace(ev.Category))
	if !s.cfg.CategoryEnabled(cat) {
		return false
	}
	ev.Category = cat
	if ev.Severity == "" {
		ev.Severity = SevInfo
	}
	now := s.now().UTC()
	if ev.At.IsZero() {
		ev.At = now
	} else {
		ev.At = ev.At.UTC()
	}
	fp := strings.TrimSpace(ev.Fingerprint)
	if fp == "" {
		fp = cat + ":" + strings.TrimSpace(ev.Title)
	}
	ev.Fingerprint = fp

	if idx, ok := s.pendingIdx[fp]; ok {
		cur := &s.pending[idx]
		cur.Count++
		if ev.At.After(cur.LastAt) {
			cur.LastAt = ev.At
		}
		if SeverityRank(ev.Severity) > SeverityRank(cur.Severity) {
			cur.Severity = ev.Severity
		}
		if ev.Title != "" {
			cur.Title = ev.Title
		}
		if ev.Summary != "" {
			cur.Summary = ev.Summary
		}
		if len(ev.Details) > 0 {
			if cur.Details == nil {
				cur.Details = make(map[string]string, len(ev.Details))
			}
			for k, v := range ev.Details {
				cur.Details[k] = v
			}
		}
	} else {
		if len(s.pending) >= maxPendingEvents {
			s.evictLowestLocked()
		}
		qe := QueuedEvent{
			Event:   cloneEvent(ev),
			Count:   1,
			FirstAt: ev.At,
			LastAt:  ev.At,
		}
		s.pendingIdx[fp] = len(s.pending)
		s.pending = append(s.pending, qe)
	}

	s.dirty = true
	if s.lastSave.IsZero() || now.Sub(s.lastSave) >= minEnqueueSaveGap {
		s.persistLocked()
	}
	return true
}

func (s *Service) evictLowestLocked() {
	if len(s.pending) == 0 {
		return
	}
	dropIdx := 0
	dropRank := SeverityRank(s.pending[0].Severity)
	dropTime := s.pending[0].LastAt
	for i := 1; i < len(s.pending); i++ {
		r := SeverityRank(s.pending[i].Severity)
		if r < dropRank || (r == dropRank && s.pending[i].LastAt.Before(dropTime)) {
			dropIdx = i
			dropRank = r
			dropTime = s.pending[i].LastAt
		}
	}
	s.overflowCount += max(1, s.pending[dropIdx].Count)
	s.pending = append(s.pending[:dropIdx], s.pending[dropIdx+1:]...)
	s.rebuildPendingIndexLocked()
}

func (s *Service) rebuildPendingIndexLocked() {
	s.pendingIdx = make(map[string]int, len(s.pending))
	for i := range s.pending {
		s.pendingIdx[s.pending[i].Fingerprint] = i
	}
}

// CanSendAt reports whether the cadence scheduler allows a digest dispatch at
// now, along with the earliest eligible timestamp when throttled.
func (s *Service) CanSendAt(now time.Time) (bool, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.canSendLocked(now.UTC())
}

func (s *Service) canSendLocked(now time.Time) (bool, time.Time) {
	window, err := s.cfg.Cadence.Window()
	if err != nil {
		window = MinCadenceWindow
	}
	pace := s.cfg.Cadence.Pace()
	maxEmails := s.cfg.Cadence.MaxEmails
	if maxEmails < 1 {
		maxEmails = 1
	}

	s.pruneSentAtLocked(now, window)

	var earliest time.Time
	if len(s.sentAt) >= maxEmails {
		capReady := s.sentAt[0].Add(window)
		if capReady.After(earliest) {
			earliest = capReady
		}
	}
	if len(s.sentAt) > 0 {
		paceReady := s.sentAt[len(s.sentAt)-1].Add(pace)
		if paceReady.After(earliest) {
			earliest = paceReady
		}
	}
	if !s.backoffUntil.IsZero() && s.backoffUntil.After(earliest) {
		earliest = s.backoffUntil
	}
	if earliest.IsZero() || !now.Before(earliest) {
		return true, now
	}
	return false, earliest
}

func (s *Service) pruneSentAtLocked(now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	keep := s.sentAt[:0]
	for _, ts := range s.sentAt {
		if ts.After(cutoff) {
			keep = append(keep, ts)
		}
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].Before(keep[j]) })
	if len(keep) > maxSendHistoryKeep {
		keep = keep[len(keep)-maxSendHistoryKeep:]
	}
	s.sentAt = keep
}

// FlushNow attempts to dispatch queued events immediately. When bypassCadence is
// false, the configured cadence and backoff limits are enforced.
func (s *Service) FlushNow(ctx context.Context, bypassCadence bool) (DeliveryRecord, error) {
	return s.dispatch(ctx, bypassCadence)
}

var (
	errNotDue     = errors.New("cadence limit not yet elapsed")
	errQueueEmpty = errors.New("no queued events to deliver")
	errPaused     = errors.New("email delivery is paused")
	errNoActiveTo = errors.New("all configured recipients are unsubscribed")
	errDisabled   = errors.New("email delivery is disabled")
)

func (s *Service) dispatch(ctx context.Context, bypassCadence bool) (DeliveryRecord, error) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	now := s.now().UTC()

	s.mu.Lock()
	cfg := cloneConfig(s.cfg)
	if !cfg.Enabled() {
		s.mu.Unlock()
		return DeliveryRecord{}, errDisabled
	}
	if s.paused && !bypassCadence {
		s.mu.Unlock()
		return DeliveryRecord{}, errPaused
	}
	if len(s.pending) == 0 && s.overflowCount == 0 {
		s.mu.Unlock()
		return DeliveryRecord{}, errQueueEmpty
	}
	if !bypassCadence {
		ok, nextAt := s.canSendLocked(now)
		if !ok {
			s.mu.Unlock()
			return DeliveryRecord{}, fmt.Errorf("%w (next eligible at %s)", errNotDue, nextAt.UTC().Format(time.RFC3339))
		}
	}
	recipients := s.activeRecipientsLocked(cfg.ToAddrs)
	if len(recipients) == 0 {
		s.mu.Unlock()
		return DeliveryRecord{}, errNoActiveTo
	}

	snapshot := make([]QueuedEvent, len(s.pending))
	for i := range s.pending {
		snapshot[i] = cloneQueuedEvent(s.pending[i])
	}
	snapOverflow := s.overflowCount
	s.mu.Unlock()

	totalEvents := snapOverflow
	for _, ev := range snapshot {
		totalEvents += max(1, ev.Count)
	}

	var sec Secrets
	if s.secrets != nil {
		sec = s.secrets.Resolve()
	}
	sender, err := s.senderFactory(cfg, sec)
	if err != nil {
		rec := s.recordFailure(now, cfg.Provider, totalEvents, err)
		return rec, err
	}

	var sentCount int
	var lastMsgID string
	var sendErrs []string
	for _, rcpt := range recipients {
		msg, err := ComposeDigest(cfg, s.unsubSecret, rcpt, snapshot, snapOverflow, now)
		if err != nil {
			sendErrs = append(sendErrs, fmt.Sprintf("%s: %v", rcpt, err))
			continue
		}
		res, err := sender.Send(ctx, msg)
		if err != nil {
			sendErrs = append(sendErrs, fmt.Sprintf("%s: %v", rcpt, err))
			continue
		}
		sentCount++
		if res.MessageID != "" {
			lastMsgID = res.MessageID
		}
	}

	if sentCount == 0 {
		combined := errors.New(strings.Join(sendErrs, "; "))
		rec := s.recordFailure(now, cfg.Provider, totalEvents, combined)
		return rec, combined
	}

	// Delivery succeeded for at least one recipient: drain only the exact
	// snapshot counts so any concurrent arrivals during Send are preserved.
	rec := DeliveryRecord{
		At:         now,
		Provider:   cfg.Provider,
		Recipients: sentCount,
		EventCount: totalEvents,
		MessageID:  lastMsgID,
	}
	if len(sendErrs) > 0 {
		rec.Error = "partial failure: " + strings.Join(sendErrs, "; ")
	}

	s.mu.Lock()
	sentCounts := make(map[string]int, len(snapshot))
	for _, ev := range snapshot {
		sentCounts[ev.Fingerprint] = max(1, ev.Count)
	}
	remaining := s.pending[:0]
	for i := range s.pending {
		cur := s.pending[i]
		if n, ok := sentCounts[cur.Fingerprint]; ok {
			cur.Count -= n
			if cur.Count <= 0 {
				continue
			}
		}
		remaining = append(remaining, cur)
	}
	s.pending = remaining
	s.rebuildPendingIndexLocked()
	s.overflowCount -= snapOverflow
	if s.overflowCount < 0 {
		s.overflowCount = 0
	}

	s.sentAt = append(s.sentAt, now)
	if w, err := s.cfg.Cadence.Window(); err == nil {
		s.pruneSentAtLocked(now, w)
	}
	s.consecutiveFailures = 0
	s.backoffUntil = time.Time{}
	cp := rec
	s.lastDelivery = &cp
	s.sentTotal.Add(1)
	s.dirty = true
	s.persistLocked()
	s.mu.Unlock()

	return rec, nil
}

func (s *Service) recordFailure(now time.Time, provider string, eventCount int, err error) DeliveryRecord {
	rec := DeliveryRecord{
		At:         now,
		Provider:   provider,
		EventCount: eventCount,
		Error:      clipString(err.Error(), 300),
	}
	s.mu.Lock()
	s.consecutiveFailures++
	idx := s.consecutiveFailures - 1
	if idx >= len(backoffSchedule) {
		idx = len(backoffSchedule) - 1
	}
	s.backoffUntil = now.Add(backoffSchedule[idx])
	cp := rec
	s.lastDelivery = &cp
	s.errorTotal.Add(1)
	s.dirty = true
	s.persistLocked()
	s.mu.Unlock()
	return rec
}

// SendTest dispatches a single compliance-formatted test email immediately
// without consuming queued events or cadence budget.
func (s *Service) SendTest(ctx context.Context, toOverride string) (SendResult, error) {
	cfg := s.Config()
	if !cfg.Enabled() {
		return SendResult{}, errDisabled
	}
	rcpt := strings.TrimSpace(toOverride)
	if rcpt == "" {
		if len(cfg.ToAddrs) == 0 {
			return SendResult{}, errors.New("no recipient address configured or provided")
		}
		rcpt = cfg.ToAddrs[0]
	}
	cleanRcpt, err := ValidateAddress(rcpt)
	if err != nil {
		return SendResult{}, fmt.Errorf("test recipient: %w", err)
	}
	var sec Secrets
	if s.secrets != nil {
		sec = s.secrets.Resolve()
	}
	sender, err := s.senderFactory(cfg, sec)
	if err != nil {
		return SendResult{}, err
	}
	now := s.now().UTC()
	msg, err := ComposeTest(cfg, s.unsubSecret, cleanRcpt, now)
	if err != nil {
		return SendResult{}, err
	}
	return sender.Send(ctx, msg)
}

// Verify runs DNS checks (MX, SPF, DMARC, optional DKIM, recipient MX, provider DNS)
// and a live provider authentication/handshake probe.
func (s *Service) Verify(ctx context.Context) VerifyReport {
	cfg := s.Config()
	var sec Secrets
	if s.secrets != nil {
		sec = s.secrets.Resolve()
	}
	var sender Sender
	if cfg.Enabled() {
		var err error
		sender, err = s.senderFactory(cfg, sec)
		if err != nil {
			// Pass a failing synthetic sender so the report includes DNS results
			// alongside the exact configuration/credential error.
			sender = &failedSender{name: cfg.Provider, err: err}
		}
	}
	return Verify(ctx, cfg, sender, s.resolver)
}

type failedSender struct {
	name string
	err  error
}

func (f *failedSender) Name() string                                      { return f.name }
func (f *failedSender) Send(context.Context, Message) (SendResult, error) { return SendResult{}, f.err }
func (f *failedSender) VerifyConnection(context.Context) error            { return f.err }

// SetPaused pauses or resumes scheduled digest delivery globally.
func (s *Service) SetPaused(paused bool) error {
	s.mu.Lock()
	s.paused = paused
	s.dirty = true
	err := s.persistLocked()
	s.mu.Unlock()
	if !paused {
		s.signal()
	}
	return err
}

// Unsubscribe pauses alert deliveries to recipient (e.g. via RFC 8058 one-click).
func (s *Service) Unsubscribe(recipient string) error {
	clean, err := ValidateAddress(recipient)
	if err != nil {
		return err
	}
	key := strings.ToLower(clean)
	s.mu.Lock()
	s.unsubscribed[key] = s.now().UTC()
	s.dirty = true
	err = s.persistLocked()
	s.mu.Unlock()
	return err
}

// Resubscribe removes recipient from the paused/unsubscribed map.
func (s *Service) Resubscribe(recipient string) error {
	clean, err := ValidateAddress(recipient)
	if err != nil {
		return err
	}
	key := strings.ToLower(clean)
	s.mu.Lock()
	delete(s.unsubscribed, key)
	s.dirty = true
	err = s.persistLocked()
	s.mu.Unlock()
	s.signal()
	return err
}

// VerifyUnsubscribe validates an RFC 8058 unsubscribe token using the service's keys.
func (s *Service) VerifyUnsubscribe(token string) (recipient, nodeID string, err error) {
	return VerifyUnsubscribeToken(s.unsubSecret, s.unsubSecretPrev, token, s.now().UTC())
}

// EraseIP removes pending queued events that reference ip (GDPR/CCPA DSAR erasure).
func (s *Service) EraseIP(ip string) int {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	kept := s.pending[:0]
	for _, ev := range s.pending {
		if queuedEventContainsIP(ev, ip) {
			removed++
			continue
		}
		kept = append(kept, ev)
	}
	if removed > 0 {
		s.pending = kept
		s.rebuildPendingIndexLocked()
		s.dirty = true
		_ = s.persistLocked()
	}
	return removed
}

func queuedEventContainsIP(ev QueuedEvent, ip string) bool {
	if containsIPToken(ev.Fingerprint, ip) || containsIPToken(ev.Title, ip) || containsIPToken(ev.Summary, ip) {
		return true
	}
	for k, v := range ev.Details {
		if containsIPToken(k, ip) || containsIPToken(v, ip) {
			return true
		}
	}
	return false
}

func containsIPToken(haystack, ip string) bool {
	if haystack == "" || ip == "" {
		return false
	}
	start := 0
	for {
		idx := strings.Index(haystack[start:], ip)
		if idx < 0 {
			return false
		}
		pos := start + idx
		end := pos + len(ip)
		leftOK := pos == 0 || !isIPChar(haystack[pos-1])
		rightOK := end == len(haystack) || !isIPChar(haystack[end])
		if leftOK && rightOK {
			return true
		}
		start = pos + 1
	}
}

func isIPChar(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') || b == '.' || b == ':'
}

// Status returns a snapshot of configuration, cadence budget, queue contents,
// and delivery metrics.
//
// # Parameters
//
// None. Safe for concurrent calls; copies queue slices, maps, and delivery
// metadata while holding s.mu before querying secrets outside the lock.
//
// # Returns
//
// A [StatusSnapshot] value whose NextEligibleAt is present only while cadence
// or backoff throttles dispatch, and whose BackoffUntil is present only while
// an active failure backoff extends past the current clock instant.
//
// # Example
//
//	snap := svc.Status()
//	if until, ok := snap.BackoffUntil.Get(); ok {
//		fmt.Println("backed off until:", until.Format(time.RFC3339))
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/mailer/mailer_test.go:1014 (direct call)
//   - internal/mailer/mailer_test.go:1039 (direct call)
//   - internal/mailer/mailer_test.go:1066 (direct call)
//   - internal/mailer/mailer_test.go:1106 (direct call)
//   - internal/mailer/mailer_test.go:1157 (direct call)
//   - internal/mailer/mailer_test.go:1163 (direct call)
//
// Scope: internal/mailer (including tests); darwin/arm64, default tags. Interface/runtime/external callers outside internal/mailer are not exhaustive.
func (s *Service) Status() StatusSnapshot {
	now := s.now().UTC()
	s.mu.Lock()
	window, err := s.cfg.Cadence.Window()
	if err != nil {
		window = MinCadenceWindow
	}
	pace := s.cfg.Cadence.Pace()
	ok, nextAt := s.canSendLocked(now)

	pending := make([]QueuedEvent, len(s.pending))
	totalQueued := s.overflowCount
	for i := range s.pending {
		pending[i] = cloneQueuedEvent(s.pending[i])
		totalQueued += max(1, s.pending[i].Count)
	}
	unsub := make(map[string]time.Time, len(s.unsubscribed))
	for k, v := range s.unsubscribed {
		unsub[k] = v
	}
	var lastDel *DeliveryRecord
	if s.lastDelivery != nil {
		cp := *s.lastDelivery
		lastDel = &cp
	}
	var backoffUntil opt.Option[time.Time]
	if !s.backoffUntil.IsZero() && now.Before(s.backoffUntil) {
		backoffUntil = opt.Some(s.backoffUntil)
	}
	var nextEligibleAt opt.Option[time.Time]
	if !ok {
		nextEligibleAt = opt.Some(nextAt)
	}

	remaining := s.cfg.Cadence.MaxEmails - len(s.sentAt)
	if remaining < 0 {
		remaining = 0
	}
	snap := StatusSnapshot{
		Enabled:             s.cfg.Enabled(),
		Provider:            s.cfg.Provider,
		Paused:              s.paused,
		Unsubscribed:        unsub,
		Cadence:             s.cfg.Cadence,
		CadenceText:         s.cfg.Cadence.String(),
		WindowSeconds:       int64(window / time.Second),
		PaceSeconds:         int64(pace / time.Second),
		SentInWindow:        len(s.sentAt),
		RemainingInWindow:   remaining,
		NextEligibleAt:      nextEligibleAt,
		QueuedUnique:        len(pending),
		QueuedTotal:         totalQueued,
		OverflowCount:       s.overflowCount,
		Pending:             pending,
		SentTotal:           s.sentTotal.Load(),
		ErrorTotal:          s.errorTotal.Load(),
		ConsecutiveFailures: s.consecutiveFailures,
		BackoffUntil:        backoffUntil,
		LastDelivery:        lastDel,
	}
	s.mu.Unlock()

	if s.secrets != nil {
		snap.Secrets = s.secrets.Status()
	}
	sort.Slice(snap.Pending, func(i, j int) bool {
		ri, rj := SeverityRank(snap.Pending[i].Severity), SeverityRank(snap.Pending[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return snap.Pending[i].LastAt.After(snap.Pending[j].LastAt)
	})
	return snap
}

// Metrics returns compact atomic counters for Prometheus exposition.
func (s *Service) Metrics() (queued int, sent int64, errs int64) {
	s.mu.Lock()
	q := s.overflowCount
	for _, ev := range s.pending {
		q += max(1, ev.Count)
	}
	s.mu.Unlock()
	return q, s.sentTotal.Load(), s.errorTotal.Load()
}

func (s *Service) activeRecipientsLocked(toAddrs []string) []string {
	var active []string
	for _, a := range toAddrs {
		clean, err := ValidateAddress(a)
		if err != nil {
			continue
		}
		if _, unsub := s.unsubscribed[strings.ToLower(clean)]; unsub {
			continue
		}
		active = append(active, clean)
	}
	return active
}

func (s *Service) loadDisk() {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		log.Printf("mailer: read %s: %v", s.path, err)
		return
	}
	var doc queueDiskDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		log.Printf("mailer: ignore corrupt %s: %v", s.path, err)
		return
	}
	if doc.Version > queueFileVersion {
		log.Printf("mailer: ignore %s written by newer version %d", s.path, doc.Version)
		return
	}
	s.paused = doc.Paused
	if doc.Unsubscribed != nil {
		s.unsubscribed = doc.Unsubscribed
	}
	s.sentAt = doc.SentAt
	s.pending = doc.Pending
	if len(s.pending) > maxPendingEvents {
		s.pending = s.pending[:maxPendingEvents]
	}
	s.rebuildPendingIndexLocked()
	s.overflowCount = doc.OverflowCount
	s.consecutiveFailures = doc.ConsecutiveFailures
	s.backoffUntil = doc.BackoffUntil
	s.lastDelivery = doc.LastDelivery
	s.sentTotal.Store(doc.SentTotal)
	s.errorTotal.Store(doc.ErrorTotal)
	if w, err := s.cfg.Cadence.Window(); err == nil {
		s.pruneSentAtLocked(s.now().UTC(), w)
	}
}

func (s *Service) persistLocked() error {
	if s.path == "" {
		s.dirty = false
		return nil
	}
	doc := queueDiskDoc{
		Version:             queueFileVersion,
		Paused:              s.paused,
		Unsubscribed:        s.unsubscribed,
		SentAt:              s.sentAt,
		Pending:             s.pending,
		OverflowCount:       s.overflowCount,
		ConsecutiveFailures: s.consecutiveFailures,
		BackoffUntil:        s.backoffUntil,
		LastDelivery:        s.lastDelivery,
		SentTotal:           s.sentTotal.Load(),
		ErrorTotal:          s.errorTotal.Load(),
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic0600(s.path, append(data, '\n')); err != nil {
		log.Printf("mailer: write %s: %v", s.path, err)
		return err
	}
	s.dirty = false
	s.lastSave = s.now().UTC()
	return nil
}

func cloneConfig(c Config) Config {
	out := c
	if len(c.ToAddrs) > 0 {
		out.ToAddrs = append([]string(nil), c.ToAddrs...)
	}
	if c.Categories != nil {
		out.Categories = make(map[string]bool, len(c.Categories))
		for k, v := range c.Categories {
			out.Categories[k] = v
		}
	}
	return out
}

func cloneEvent(ev Event) Event {
	out := ev
	if len(ev.Details) > 0 {
		out.Details = make(map[string]string, len(ev.Details))
		for k, v := range ev.Details {
			out.Details[k] = v
		}
	}
	return out
}

func cloneQueuedEvent(qe QueuedEvent) QueuedEvent {
	out := qe
	out.Event = cloneEvent(qe.Event)
	return out
}
