//go:build enterprise

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/acme"
	"github.com/andreimerlescu/concert/internal/bidding"
	"github.com/andreimerlescu/concert/internal/capacity"
	"github.com/andreimerlescu/concert/internal/drop"
	"github.com/andreimerlescu/concert/internal/fastlane"
	"github.com/andreimerlescu/concert/internal/gateway"
	"github.com/andreimerlescu/concert/internal/hop"
	"github.com/andreimerlescu/concert/internal/mailer"
	"github.com/andreimerlescu/concert/internal/x402"
	"github.com/andreimerlescu/room"
	"github.com/gin-gonic/gin"
)

func hasEnterpriseEdition() bool { return true }

func init() {
	if hopHeaderName != hop.Header || hopBackpressureHeaderName != hop.BackpressureHeader || hopNodeHeaderName != hop.NodeHeader {
		panic("edition_core hop header constants out of sync with internal/hop")
	}
}

// enterpriseAppState holds the enterprise-only subsystems embedded in app.
type enterpriseAppState struct {
	fastlane     *fastlane.Service
	fastlaneGW   fastlane.Gateway
	gatewayClose func()
	audit        *auditLogger
	cluster      *clusterSync
	topo         *topology
	mailer       *mailer.Service
	unsubLimit   *emailRateLimiter
}

func toHopClass(c trafficClass) hop.Class {
	switch c {
	case classBypass:
		return hop.ClassBypass
	case classAsset:
		return hop.ClassAsset
	case classStream:
		return hop.ClassStream
	default:
		return hop.ClassPage
	}
}

func (t *topology) recordEdgeBackpressure() {
	if t.isEdge() {
		t.edge.backpressure.Add(1)
	}
}

func (t *topology) recordEdgeRetry() {
	if t.isEdge() {
		t.edge.retries.Add(1)
	}
}

func hopInClientIP(ctx context.Context) (netip.Addr, bool) {
	if claim, ok := hopInFrom(ctx); ok {
		return claim.Client, true
	}
	return netip.Addr{}, false
}

func (g *generation) wrapForwardPage(fn gin.HandlerFunc) gin.HandlerFunc {
	if g.a.topo.isLeaf() {
		return g.gateDirect(fn)
	}
	return fn
}

func (c *config) normalizeEnterprise() error {
	if err := c.normalizeTopology(); err != nil {
		return err
	}
	if c.hasFastCGI && c.role == roleEdge {
		return errors.New("edge nodes cannot use fcgi:// or fcgi+unix:// upstreams directly; run php-fpm behind a standalone or leaf node")
	}
	if err := c.normalizeEmail(); err != nil {
		return err
	}
	if c.hardened {
		if err := c.validateHardened(); err != nil {
			return err
		}
	}
	return nil
}

// validateHardened enforces baseline enterprise security controls when
// -enterprise-hardened (CONCERT_HARDENED=true) is enabled.
func (c *config) validateHardened() error {
	var errs []string
	if c.admitSecretGenerated {
		errs = append(errs, "CONCERT_ADMIT_SECRET (or _FILE) must be explicitly configured")
	}
	if !c.secureCookie {
		errs = append(errs, "-secure-cookie must be true")
	}
	if !c.statsAuth {
		errs = append(errs, "-stats-auth must be true so /_room/stats and /_room/metrics require authentication")
	}
	if !c.apiTokens.enabled() {
		errs = append(errs, "CONCERT_ADMIN_TOKEN or CONCERT_ADMIN_TOKENS must be configured")
	}
	if strings.EqualFold(strings.TrimSpace(c.auditLog), "off") || strings.EqualFold(strings.TrimSpace(c.auditLog), "none") {
		errs = append(errs, "-audit-log cannot be disabled")
	}
	if c.dataDir == "" && strings.TrimSpace(c.auditLog) == "" {
		errs = append(errs, "-audit-log or -data-dir must be set so tamper-evident audit logs persist")
	}
	if c.portal.enabled() && c.portal.tlsCert == "" && !c.portal.secureCookie && len(c.portal.trustedProxies) == 0 {
		errs = append(errs, "admin portal requires -portal-tls-cert/-portal-tls-key or -portal-secure-cookie behind a trusted TLS proxy")
	}
	if c.portal.users != nil && c.portal.users.count() > 0 && c.portal.pass != "" {
		errs = append(errs, "CONCERT_PORTAL_PASS must not be set alongside CONCERT_PORTAL_USERS in enterprise-hardened mode")
	}
	if c.role == roleLeaf && (!c.hopReplayGuard || !c.hopRequireNonce) {
		errs = append(errs, "leaf nodes require -hop-replay-guard=true and -hop-require-nonce=true in enterprise-hardened mode")
	}
	if len(errs) > 0 {
		return fmt.Errorf("enterprise-hardened checks failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (a *app) initEnterpriseEarly(cfg config) error {
	a.audit = newAuditLogger(auditLogPath(cfg), cfg.admitSecret)
	a.unsubLimit = newEmailRateLimiter(30, time.Minute)
	a.onClose(a.audit.close)
	topo, err := newTopology(cfg)
	if err != nil {
		a.audit.close()
		return err
	}
	a.topo = topo
	return nil
}

func (a *app) initEnterpriseFastlane(cfg config, wr *room.WaitingRoom) error {
	if cfg.fastlaneFile == "" || cfg.skipFastlaneInit {
		return nil
	}
	fc, err := fastlane.Load(cfg.fastlaneFile)
	if err == nil && fc.Enabled && cfg.admitSecretGenerated {
		err = fmt.Errorf("fast lane requires a stable CONCERT_ADMIT_SECRET")
	}
	if err == nil && fc.Enabled && cfg.hardened && !fc.TestMode && fc.EffectivePolicyMode() == fastlane.PolicyModeNone && !fc.AllowUnscreenedMainnet {
		err = fmt.Errorf("policy_mode \"none\" on mainnet is refused in -enterprise-hardened mode unless allow_unscreened_mainnet is true")
	}
	var gw fastlane.Gateway
	if err == nil && fc.Enabled {
		gw, err = newGateway(fc, &cfg)
	}
	if err == nil {
		a.fastlane, err = fastlane.New(fc, cfg.dataDir, cfg.admitSecret, gw, envOrFile("CONCERT_POLICY_TOKEN", ""))
		if err != nil {
			closeGateway(gw)
		} else if gw != nil {
			a.fastlaneGW = gw
			a.gatewayClose = func() { closeGateway(gw) }
		}
	}
	if err != nil {
		return fmt.Errorf("fast lane: %w", err)
	}
	a.attachFastlaneCallbacks(cfg, wr)
	return nil
}

func (a *app) attachFastlaneCallbacks(cfg config, wr *room.WaitingRoom) {
	if a.fastlane == nil {
		return
	}
	if len(cfg.admitSecretPrev) > 0 {
		a.fastlane.SetPrevKey(cfg.admitSecretPrev)
	}
	if wr != nil {
		wr.SetStatusBaseURL(a.fastlane.Config().Origin + "/queue/status/")
	}
	a.agentOffer.Store(newAgentOffer(a.fastlane))
	a.fastlane.SetOnUnknown(func(network, session string) {
		prefix := session
		if len(prefix) > 8 {
			prefix = prefix[:8]
		}
		a.notifyEvent(mailer.Event{
			Category:    mailer.CatFastlane,
			Severity:    mailer.SevCritical,
			Title:       "Unresolved fast-lane payment settlement",
			Summary:     fmt.Sprintf("A payment on network %s entered state \"unknown\" and requires reconciliation.", network),
			Fingerprint: "fastlane:unknown:" + network,
			Details:     map[string]string{"network": network, "session_prefix": prefix},
		})
	})
	a.fastlane.SetOnCapacityWarn(func(used, max, pct int) {
		sev := mailer.SevWarn
		tier := "80"
		if pct >= 95 {
			sev = mailer.SevCritical
			tier = "95"
		}
		a.notifyEvent(mailer.Event{
			Category:    mailer.CatFastlane,
			Severity:    sev,
			Title:       fmt.Sprintf("Fast-lane receipt journal at %d%% capacity", pct),
			Summary:     fmt.Sprintf("Fast-lane journal holds %d of %d records (%d%%). Compact expired receipts live in the Admin Portal or with `econcert archive-receipts` before reaching 100%%.", used, max, pct),
			Fingerprint: "fastlane:capacity:" + tier,
			Details: map[string]string{
				"records_used": fmt.Sprintf("%d", used),
				"max_records":  fmt.Sprintf("%d", max),
				"usage_pct":    fmt.Sprintf("%d", pct),
			},
		})
	})
}

func validateFastlaneReloadConfig(cfg config) error {
	if cfg.fastlaneFile == "" {
		return nil
	}
	fc, err := fastlane.Load(cfg.fastlaneFile)
	if err != nil {
		return err
	}
	if fc.Enabled && cfg.hardened && !fc.TestMode && fc.EffectivePolicyMode() == fastlane.PolicyModeNone && !fc.AllowUnscreenedMainnet {
		return errors.New("policy_mode \"none\" on mainnet is refused in -enterprise-hardened mode unless allow_unscreened_mainnet is true")
	}
	if fc.Enabled && cfg.networksFile != "" {
		if _, err := gateway.LoadNetworks(cfg.networksFile); err != nil {
			return err
		}
	}
	return nil
}

// transferFastlaneFrom hot-reloads prev's live fast-lane service and gateway
// from disk and hands ownership to a without releasing journal locks.
func (a *app) transferFastlaneFrom(prev *app, cfg config) error {
	if prev == nil || prev.fastlane == nil {
		return nil
	}
	fc, err := fastlane.Load(cfg.fastlaneFile)
	if err != nil {
		return err
	}
	var nets map[string]gateway.Network
	if cfg.networksFile != "" {
		if nets, err = gateway.LoadNetworks(cfg.networksFile); err != nil {
			return err
		}
	}
	if gwSrv, ok := prev.fastlaneGW.(*gateway.Server); ok {
		if err := gwSrv.Reload(fc, nets); err != nil {
			return err
		}
	}
	if err := prev.fastlane.UpdateConfig(fc); err != nil {
		return err
	}
	// Hand ownership cleanly to a so prev.Close() does not close transferred journals.
	a.fastlane = prev.fastlane
	a.fastlaneGW = prev.fastlaneGW
	a.gatewayClose = prev.gatewayClose
	prev.fastlane = nil
	prev.fastlaneGW = nil
	prev.gatewayClose = nil
	a.attachFastlaneCallbacks(cfg, a.room)
	a.wireFastlaneClusterHooks()
	return nil
}

func (a *app) wireFastlaneClusterHooks() {
	if a.cluster == nil || a.fastlane == nil {
		return
	}
	a.fastlane.SetRevocationHooks(a.cluster.isFastlaneRevoked, a.cluster.publishFastlaneRevoke)
	if gwSrv, ok := a.fastlaneGW.(*gateway.Server); ok {
		gwSrv.SetSettlementDedupe(a.cluster.claimFastlaneSettlement)
	}
}

func (a *app) initEnterpriseServices(cfg config) {
	a.mailer = a.initMailer(cfg)
	if addr := cfg.effectiveKVAddr(); addr != "" {
		scope := cfg.siteHost
		if scope == "" {
			scope = cfg.roomScope
		}
		a.cluster = newClusterSync(clusterConfig{
			addr:        addr,
			password:    cfg.effectiveKVPassword(),
			useTLS:      cfg.effectiveKVTLS(),
			prefix:      cfg.effectiveKVPrefix(),
			sharedQueue: cfg.kvSharedQueue,
			queueScope:  scope,
		}, a.abuse, a.stats, a.queueDrop)
		if a.cluster != nil {
			a.onClose(a.cluster.close)
			a.wireFastlaneClusterHooks()
		}
	}
}

func (a *app) recordSharedQueueJoin(ticket, clientKey string, ttl time.Duration) {
	if a != nil && a.cluster != nil {
		a.cluster.recordQueueJoinAsync(ticket, clientKey, ttl)
	}
}

func (a *app) purgeSharedQueue(ctx context.Context, mode string) {
	if a != nil && a.cluster != nil {
		a.cluster.purgeSharedQueue(ctx, mode)
	}
}

func (a *app) acmeKVSync() acme.KVBundleSync {
	if a != nil && a.cluster != nil {
		return a.cluster.acmeBundleSync()
	}
	return nil
}

func (a *app) dropKVSync() drop.StateSync {
	if a != nil && a.cluster != nil {
		return a.cluster.dropStateSync()
	}
	return nil
}

func (a *app) biddingClusterSync() bidding.ClusterSync {
	if a != nil && a.cluster != nil {
		return a.cluster.biddingClusterSync()
	}
	return nil
}

// gatewayBiddingSettler adapts Concert's internal/gateway (fastlane.Gateway)
// to internal/bidding.PaymentSettler: off-chain /verify on submit, on-chain
// /settle exclusively on winners (losers pay $0).
type gatewayBiddingSettler struct {
	gw fastlane.Gateway
}

func (s gatewayBiddingSettler) Verify(ctx context.Context, bid bidding.BidSubmission) (bidding.VerifyReceipt, error) {
	if s.gw == nil {
		return bidding.VerifyReceipt{Valid: false, InvalidReason: "gateway_not_configured"}, nil
	}
	raw, err := s.gw.Handle(ctx, "/verify", bid.PaymentPayload)
	if err != nil {
		return bidding.VerifyReceipt{Valid: false, InvalidReason: "verification_failed"}, err
	}
	var vr x402.VerifyResponse
	switch v := raw.(type) {
	case x402.VerifyResponse:
		vr = v
	case *x402.VerifyResponse:
		if v != nil {
			vr = *v
		}
	default:
		b, merr := json.Marshal(raw)
		if merr != nil {
			return bidding.VerifyReceipt{Valid: false, InvalidReason: "invalid_verify_response"}, merr
		}
		if uerr := json.Unmarshal(b, &vr); uerr != nil {
			return bidding.VerifyReceipt{Valid: false, InvalidReason: "invalid_verify_response"}, uerr
		}
	}
	return bidding.VerifyReceipt{
		Valid:         vr.Valid,
		Payer:         vr.Payer,
		InvalidReason: vr.Reason,
	}, nil
}

func (s gatewayBiddingSettler) Settle(ctx context.Context, bid bidding.BidSubmission) (bidding.SettleReceipt, error) {
	if s.gw == nil {
		return bidding.SettleReceipt{Settled: false, ErrorReason: "gateway_not_configured"}, bidding.ErrSettlementFailed
	}
	raw, err := s.gw.Handle(ctx, "/settle", bid.PaymentPayload)
	if err != nil {
		return bidding.SettleReceipt{Settled: false, ErrorReason: "settlement_failed"}, err
	}
	var sr x402.SettleResponse
	switch v := raw.(type) {
	case x402.SettleResponse:
		sr = v
	case *x402.SettleResponse:
		if v != nil {
			sr = *v
		}
	default:
		b, merr := json.Marshal(raw)
		if merr != nil {
			return bidding.SettleReceipt{Settled: false, ErrorReason: "invalid_settle_response"}, merr
		}
		if uerr := json.Unmarshal(b, &sr); uerr != nil {
			return bidding.SettleReceipt{Settled: false, ErrorReason: "invalid_settle_response"}, uerr
		}
	}
	return bidding.SettleReceipt{
		Settled:     sr.Success,
		Transaction: sr.Transaction,
		Network:     sr.Network,
		Payer:       sr.Payer,
		ErrorReason: sr.ErrorReason,
	}, nil
}

func (a *app) newBiddingSettler() bidding.PaymentSettler {
	if a != nil && a.fastlaneGW != nil {
		return gatewayBiddingSettler{gw: a.fastlaneGW}
	}
	return failClosedBiddingSettler{}
}

func (a *app) startEnterpriseLoops() {
	switch {
	case a.topo.isEdge():
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			a.runEdge()
		}()
	case a.topo.isLeaf():
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			a.runLeafMonitor()
		}()
	}
	if a.fastlane != nil {
		// Closers run newest first: the fast lane stops, then the gateway
		// lets settlements in flight journal their results.
		if a.gatewayClose != nil {
			a.onClose(a.gatewayClose)
		}
		a.onClose(a.fastlane.Close)
	}
}

func (a *app) closeEnterpriseOnStartupErr() {
	if a.mailer != nil {
		a.mailer.Close()
	}
	if a.fastlane != nil {
		a.fastlane.Close()
		if a.gatewayClose != nil {
			a.gatewayClose()
		}
	}
}

func (a *app) maybeBenchOnStart(ctx context.Context, cfg config) {
	if a.topo.isLeaf() && cfg.benchOnStart {
		a.benchOnStart(ctx)
	}
}

func (a *app) notifyAlert(ev alertEvent) {
	var cat string
	switch ev.Category {
	case alertCatQueue:
		cat = mailer.CatQueue
	case alertCatBans:
		cat = mailer.CatBans
	case alertCatSecurity:
		cat = mailer.CatSecurity
	case alertCatSilence:
		cat = mailer.CatSilence
	case alertCatCapacity:
		cat = mailer.CatCapacity
	case alertCatFastlane:
		cat = mailer.CatFastlane
	default:
		cat = string(ev.Category)
	}
	var sev string
	switch ev.Severity {
	case alertSevWarn:
		sev = mailer.SevWarn
	case alertSevCritical:
		sev = mailer.SevCritical
	default:
		sev = mailer.SevInfo
	}
	a.notifyEvent(mailer.Event{
		Category:    cat,
		Severity:    sev,
		Title:       ev.Title,
		Summary:     ev.Summary,
		Fingerprint: ev.Fingerprint,
		Details:     ev.Details,
	})
	a.dispatchChatOps(ev)
}

func (a *app) recordAudit(ev auditEvent) {
	if a != nil && a.audit != nil {
		a.audit.record(ev)
	}
}

func (a *app) publishClusterBan(t banTarget, until int64, offenses int) {
	if a != nil && a.cluster != nil {
		a.cluster.publishBan(t, until, offenses)
	}
}

func (a *app) publishClusterUnban(t banTarget) {
	if a != nil && a.cluster != nil {
		a.cluster.publishUnban(t)
	}
}

func (a *app) eraseMailerIP(ip netip.Addr, anon string) int {
	if a == nil || a.mailer == nil {
		return 0
	}
	removed := a.mailer.EraseIP(ip.Unmap().String())
	if anon != "" && anon != ip.Unmap().String() {
		removed += a.mailer.EraseIP(anon)
	}
	return removed
}

func (a *app) applyEnterpriseReload(cfg config) {
	if a.topo.isLeaf() {
		a.topo.leaf.applyConfig(cfg)
		if a.topo.verifier != nil {
			a.topo.verifier.SetReplayGuard(cfg.hopReplayGuard, cfg.hopRequireNonce)
		}
	}
	if a.mailer != nil {
		if mcfg, merr := cfg.mailerConfig(); merr == nil {
			a.mailer.UpdateConfig(mcfg)
		}
	}
}

func untrackedEnterprisePaths() []pathRule {
	return []pathRule{{path: mailer.UnsubscribeMainPath}}
}

func (a *app) fastlaneEligible(r *http.Request) bool {
	return a != nil && a.fastlane != nil && a.fastlane.Eligible(r)
}

func (a *app) fastlaneEligibleAndRefresh(w http.ResponseWriter, r *http.Request) bool {
	return a != nil && a.fastlane != nil && a.fastlane.EligibleAndRefresh(w, r)
}

func (a *app) fastlaneSessionID(r *http.Request) (string, bool) {
	if a == nil || a.fastlane == nil {
		return "", false
	}
	return a.fastlane.SessionID(r)
}

func (a *app) fastlaneEnabled() bool {
	return a != nil && a.fastlane != nil
}

func (a *app) populateOverviewEnterprise(h gin.H) {
	h["edition"] = Edition()
	if a.mailer != nil {
		st := a.mailer.Status()
		h["email_enabled"] = st.Enabled
		h["email_paused"] = st.Paused
		h["email_queued"] = st.QueuedTotal
		h["email_sent_total"] = st.SentTotal
		h["email_errors_total"] = st.ErrorTotal
	}
	if a.topo != nil {
		h["role"] = a.topo.role
		h["node"] = a.topo.node
		switch {
		case a.topo.isEdge():
			h["edge"] = a.edgeView()
		case a.topo.isLeaf():
			h["leaf"] = a.leafView(time.Now())
		}
	}
}

func (a *app) populateStatsEnterprise(out gin.H) {
	out["edition"] = Edition()
	if a.cluster != nil && a.cluster.cfg.sharedQueue {
		st, ok := a.cluster.sharedQueueStats(context.Background())
		out["kv_shared_queue"] = gin.H{
			"enabled":  true,
			"degraded": !ok || st.Degraded,
			"waiting":  st.Waiting,
			"claimed":  st.Claimed,
		}
	}
	if a.topo == nil {
		return
	}
	out["role"] = a.topo.role
	out["node"] = a.topo.node
	switch {
	case a.topo.isEdge():
		out["edge"] = a.edgeView()
	case a.topo.isLeaf():
		out["leaf"] = a.leafView(time.Now())
	}
}

func (a *app) writeEnterpriseMetrics(b *strings.Builder, stats *counters) {
	var auditEvents, auditErrors int64
	if a.audit != nil {
		auditEvents = a.audit.written.Load()
		auditErrors = a.audit.errors.Load()
	}
	writePromMetric(b, "concert_audit_events_total", "counter", "Total tamper-evident audit log events written.", auditEvents)
	writePromMetric(b, "concert_audit_errors_total", "counter", "Total audit log write errors.", auditErrors)
	writePromMetric(b, "concert_cluster_sync_sent_total", "counter", "Total cluster ban sync events published.", stats.clusterSyncSent.Load())
	writePromMetric(b, "concert_cluster_sync_received_total", "counter", "Total cluster ban sync events applied from peers.", stats.clusterSyncRecv.Load())
	writePromMetric(b, "concert_cluster_sync_errors_total", "counter", "Total cluster state synchronization errors.", stats.clusterSyncErrors.Load())

	var emailQueued int
	var emailSent, emailErrs int64
	if a.mailer != nil {
		emailQueued, emailSent, emailErrs = a.mailer.Metrics()
	}
	writePromMetric(b, "concert_email_queued_events", "gauge", "Pending operational events queued for scheduled administrator email digest.", emailQueued)
	writePromMetric(b, "concert_email_sent_total", "counter", "Total administrator digest emails successfully delivered.", emailSent)
	writePromMetric(b, "concert_email_errors_total", "counter", "Total administrator digest email delivery failures.", emailErrs)
	writePromMetric(b, "concert_email_cluster_deduped_total", "counter", "Shared cluster alert events deduplicated via Redis peer lease.", stats.emailClusterDeduped.Load())

	if a.fastlane != nil {
		used, maxRec, unresolved := a.fastlane.JournalStats()
		writePromMetric(b, "concert_fastlane_records_used", "gauge", "Fast-lane receipt records currently stored in fastlane.jsonl.", used)
		writePromMetric(b, "concert_fastlane_records_max", "gauge", "Configured max_records ceiling for fastlane.jsonl.", maxRec)
		writePromMetric(b, "concert_fastlane_unresolved", "gauge", "Unresolved fast-lane receipts in pending or unknown state awaiting reconciliation.", unresolved)
	}

	a.writeTierMetrics(b)
}

func (a *app) writeTierMetrics(b *strings.Builder) {
	t := a.topo
	if t == nil {
		return
	}
	fmt.Fprintf(b, "# HELP concert_node_info Node role and ID.\n# TYPE concert_node_info gauge\nconcert_node_info{role=%q,node=%q} 1\n", t.role, t.node)
	switch {
	case t.isEdge():
		e := t.edge
		if p := e.lastPlan.Load(); p != nil {
			writePromMetric(b, "concert_edge_leaves_usable", "gauge", "Leaves counted in the last capacity plan.", p.Leaves)
			writePromMetric(b, "concert_edge_leaf_slots", "gauge", "Page slots the leaves offer this edge.", p.Total)
			writePromMetric(b, "concert_edge_planned_cap", "gauge", "Room capacity planned from the leaves.", p.Cap)
		}
		writePromMetric(b, "concert_edge_leaf_backpressure_total", "counter", "Leaf answers refusing a request for capacity.", e.backpressure.Load())
		writePromMetric(b, "concert_edge_upstream_retries_total", "counter", "Requests re-sent to another upstream.", e.retries.Load())
		writePromMetric(b, "concert_edge_leaf_poll_errors_total", "counter", "Failed leaf state reads.", e.pollErrors.Load())
		writePromMetric(b, "concert_edge_ban_push_errors_total", "counter", "Failed ban snapshot pushes.", e.pushErrors.Load())
	case t.isLeaf():
		l := t.leaf
		writePromMetric(b, "concert_leaf_host_cap", "gauge", "Page requests the host serves at once.", l.gate.Cap())
		writePromMetric(b, "concert_leaf_hop_in_flight", "gauge", "Edge page requests holding host slots.", l.gate.InUse(capacity.HopPriority)+l.gate.InUse(capacity.Hop))
		writePromMetric(b, "concert_leaf_direct_in_flight", "gauge", "Direct page requests holding host slots.", l.gate.InUse(capacity.Direct))
		writePromMetric(b, "concert_leaf_hop_accepted_total", "counter", "Verified hop claims.", l.accepted.Load())
		writePromMetric(b, "concert_leaf_hop_rejected_total", "counter", "Refused hop claims.", l.rejected.Load())
		writePromMetric(b, "concert_leaf_hop_replayed_total", "counter", "Hop claims refused as replayed nonces.", l.replayed.Load())
		writePromMetric(b, "concert_leaf_hop_replay_evictions_total", "counter", "Hop replay cache unexpired nonce evictions or hardened-mode saturations.", l.replayEvictions.Load())
		writePromMetric(b, "concert_leaf_hop_mtls_rejected_total", "counter", "Hop claims refused for missing verified mTLS client certificate.", l.mtlsRejected.Load())
		writePromMetric(b, "concert_leaf_hop_backpressure_total", "counter", "Hop requests refused for capacity.", l.backpressed.Load())
		writePromMetric(b, "concert_leaf_rebench_total", "counter", "Completed drained on-demand capacity re-benchmarks.", l.rebenchTotal.Load())
		silent := 0
		if _, r := l.monitor.view(); r != nil && r.Recovered.IsZero() {
			silent = 1
		}
		writePromMetric(b, "concert_leaf_app_silent", "gauge", "1 while the application is silent.", silent)
	}
}

func (a *app) describeEnterpriseSecrets(cfg config, out map[string]string) {
	clusterDesc := "standalone (in-memory)"
	if addr := cfg.effectiveKVAddr(); addr != "" {
		if cfg.kvSharedQueue {
			clusterDesc = "KV sync + shared queue (" + addr + ")"
		} else {
			clusterDesc = "KV sync (" + addr + ")"
		}
	}
	emailSecretsDesc := "none configured"
	if a.mailer != nil && a.mailer.Secrets() != nil {
		st := a.mailer.Secrets().Status()
		emailSecretsDesc = fmt.Sprintf("SMTP=%s, Resend=%s, SendPanda=%s", st.SMTPPass, st.ResendAPIKey, st.SendPandaAPIKey)
	}
	out["Edition"] = Edition()
	out["Email secrets"] = emailSecretsDesc
	out["Audit log"] = a.audit.describe()
	out["Cluster sync"] = clusterDesc
}

func (a *app) logEnterpriseStartup(c config) {
	if a.fastlane != nil {
		fc := a.fastlane.Config()
		mode := "live networks"
		if fc.TestMode {
			mode = "test networks only"
		}
		log.Printf("fast lane: %s, %d payment offer(s), %d NFT rule(s), %ds pass, chain endpoints %s, settlement journal %s",
			mode, len(fc.Offers), len(fc.Collections), fc.PassSeconds, c.networksFile, gatewayDir(c.dataDir))
		if fc.GatewayURL != "" {
			log.Printf("fast lane: gateway_url is ignored; the chain gateway runs inside concert")
		}
	} else if c.fastlaneFile != "" {
		log.Printf("fast lane: %s has \"enabled\": false; wallet access is off", c.fastlaneFile)
	}
	switch {
	case a.topo.isEdge():
		log.Printf("edge %s: signing hop claims; polling %d leaf(s) every %s; room sized from leaves: %v (at most -cap %d)",
			a.topo.node, len(c.controlURLs()), c.hopPoll, c.hopAutoCap, c.capacity)
	case a.topo.isLeaf():
		log.Printf("leaf %s: accepting hop claims from %s; host capacity %d (%s)",
			a.topo.node, c.hopPeers, a.topo.leaf.gate.Cap(), a.topo.leaf.capSource)
	}
}

func (p *portal) registerEnterprisePortalRoutes(r *gin.Engine, api *gin.RouterGroup) {
	r.GET(mailer.UnsubscribePortalPath, p.a.handleEmailUnsubscribe)
	r.POST(mailer.UnsubscribePortalPath, p.a.handleEmailUnsubscribe)
	api.POST("/topology/rebench", p.requireRole(roleAdmin), p.apiTopologyRebench)
	api.GET("/fastlane", p.requireRole(roleViewer), p.apiFastlaneGet)
	api.POST("/fastlane/config", p.requireRole(roleAdmin), p.apiFastlaneConfigSave)
	api.POST("/fastlane/reconcile", p.requireRole(roleAdmin), p.apiFastlaneReconcile)
	api.POST("/fastlane/archive", p.requireRole(roleAdmin), p.apiFastlaneArchive)
	api.POST("/fastlane/revoke", p.requireRole(roleAdmin), p.apiFastlaneRevoke)
	api.GET("/email", p.requireRole(roleViewer), p.apiEmail)
	api.POST("/email/config", p.requireRole(roleAdmin), p.apiEmailConfigSave)
	api.DELETE("/email/secrets", p.requireRole(roleAdmin), p.apiEmailSecretDelete)
	api.POST("/email/pause", p.requireRole(roleAdmin), p.apiEmailPause)
	api.POST("/email/verify", p.requireRole(roleAdmin), p.apiEmailVerify)
	api.POST("/email/test", p.requireRole(roleAdmin), p.apiEmailTest)
	api.POST("/email/flush", p.requireRole(roleAdmin), p.apiEmailFlush)
}

func registerEnterpriseOpsRoutes(r *gin.Engine, g *generation) {
	a := g.a
	r.POST("/_room/rebench", func(c *gin.Context) {
		actor, ok := g.requireRole(c, roleAdmin)
		if !ok {
			return
		}
		handleRebench(c, a, actor, "api")
	})
	r.POST("/_room/fastlane/reconcile", func(c *gin.Context) {
		actor, ok := g.requireRole(c, roleAdmin)
		if !ok {
			return
		}
		handleFastlaneReconcile(c, a, actor, "api")
	})
	r.POST("/_room/fastlane/archive", func(c *gin.Context) {
		actor, ok := g.requireRole(c, roleAdmin)
		if !ok {
			return
		}
		handleFastlaneArchive(c, a, actor, "api")
	})
	r.POST("/_room/fastlane/revoke", func(c *gin.Context) {
		actor, ok := g.requireRole(c, roleAdmin)
		if !ok {
			return
		}
		handleFastlaneRevoke(c, a, actor, "api")
	})
}

func (p *portal) apiTopologyRebench(c *gin.Context) {
	handleRebench(c, p.a, portalPrincipal(c), "portal")
}

func handleRebench(c *gin.Context, a *app, actor principal, source string) {
	var body struct {
		Leaf             string `json:"leaf"`
		Force            bool   `json:"force"`
		DrainWaitSeconds int    `json:"drain_wait_seconds"`
	}
	if c.Request.ContentLength != 0 {
		if err := json.NewDecoder(io.LimitReader(c.Request.Body, 4096)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON payload"})
			return
		}
	}
	drainWait := time.Duration(body.DrainWaitSeconds) * time.Second
	var (
		res    any
		status int
		err    error
		target string
	)
	switch {
	case a.topo.isLeaf():
		target = a.topo.node
		res, status, err = a.rebenchLeaf(c.Request.Context(), drainWait)
	case a.topo.isEdge():
		target = body.Leaf
		res, status, err = a.triggerLeafRebench(c.Request.Context(), body.Leaf, body.Force, drainWait)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "drained re-benchmarking is only available on edge or leaf nodes"})
		return
	}
	if err != nil {
		a.recordAudit(auditEvent{
			Actor:    actor.Actor,
			Role:     actor.Role.String(),
			Source:   source,
			Action:   "topology.rebench",
			Target:   target,
			Outcome:  "error",
			ClientIP: actor.IP.String(),
			Details:  map[string]any{"force": body.Force, "error": err.Error()},
		})
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	a.recordAudit(auditEvent{
		Actor:    actor.Actor,
		Role:     actor.Role.String(),
		Source:   source,
		Action:   "topology.rebench",
		Target:   target,
		Outcome:  "allow",
		ClientIP: actor.IP.String(),
		Details:  map[string]any{"force": body.Force},
	})
	c.JSON(http.StatusOK, res)
}

func (p *portal) apiFastlaneReconcile(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown site"})
		return
	}
	handleFastlaneReconcile(c, a, portalPrincipal(c), "portal")
}

func handleFastlaneReconcile(c *gin.Context, a *app, actor principal, source string) {
	if a.fastlane == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "fast lane is not enabled"})
		return
	}
	var body struct {
		Fingerprint string `json:"fingerprint"`
		StellarHash string `json:"stellar_hash"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	fp := strings.ToLower(strings.TrimSpace(body.Fingerprint))
	if fp == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "fingerprint is required"})
		return
	}
	res, err := a.fastlane.ReconcileOnline(c.Request.Context(), fp, body.StellarHash)
	if err != nil {
		a.recordAudit(auditEvent{
			Actor:    actor.Actor,
			Role:     actor.Role.String(),
			Source:   source,
			Action:   "fastlane.reconcile",
			Target:   fp,
			Outcome:  "error",
			ClientIP: actor.IP.String(),
			Details:  map[string]any{"error": err.Error()},
		})
		status := http.StatusConflict
		msg := err.Error()
		if strings.Contains(msg, "invalid payment fingerprint") || strings.Contains(msg, "stellar reconciliation requires") {
			status = http.StatusBadRequest
		} else if strings.Contains(msg, "receipt not found") {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": msg})
		return
	}
	a.recordAudit(auditEvent{
		Actor:    actor.Actor,
		Role:     actor.Role.String(),
		Source:   source,
		Action:   "fastlane.reconcile",
		Target:   fp,
		Outcome:  "allow",
		ClientIP: actor.IP.String(),
		Details:  map[string]any{"network": res.Network, "transaction": res.Transaction, "payer": res.Payer},
	})
	c.JSON(http.StatusOK, gin.H{
		"reconciled": true,
		"settlement": res,
		"fastlane":   a.fastlane.Summary(),
	})
}

func (p *portal) apiFastlaneGet(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown site"})
		return
	}
	cfg := a.current().cfg
	if a.fastlane == nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled":             false,
			"destinations_locked": cfg.fastlaneLockDestinations,
			"hardened":            cfg.hardened,
			"can_edit":            cfg.fastlaneFile != "",
		})
		return
	}
	out := a.fastlane.Summary()
	out["destinations_locked"] = cfg.fastlaneLockDestinations
	out["hardened"] = cfg.hardened
	out["can_edit"] = true
	if a.fastlaneGW != nil {
		if raw, err := a.fastlaneGW.Handle(c.Request.Context(), "/sponsor/status", nil); err == nil {
			out["sponsor_status"] = raw
		}
	}
	c.JSON(http.StatusOK, out)
}

func destinationsDiff(oldCfg, newCfg fastlane.Config) (changed bool, oldDests, newDests []string) {
	collect := func(c fastlane.Config) map[string]string {
		m := map[string]string{}
		for _, o := range c.Offers {
			key := o.Requirements.Network + ":" + o.Requirements.Asset
			m[key] = o.Requirements.PayTo
		}
		for k, v := range c.VerifyAddresses {
			m["verify:"+k] = v
		}
		return m
	}
	om, nm := collect(oldCfg), collect(newCfg)
	if len(om) != len(nm) {
		changed = true
	}
	for k, ov := range om {
		if nv, ok := nm[k]; !ok || nv != ov {
			changed = true
			oldDests = append(oldDests, k+"="+ov)
		}
	}
	for k, nv := range nm {
		if ov, ok := om[k]; !ok || ov != nv {
			changed = true
			newDests = append(newDests, k+"="+nv)
		}
	}
	return changed, oldDests, newDests
}

func (p *portal) apiFastlaneConfigSave(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown site"})
		return
	}
	cfg := a.current().cfg
	actor := portalPrincipal(c)
	if a.fastlane == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "fast lane is not initialized (configure -fastlane-config and -networks-config first)"})
		return
	}
	var payload struct {
		Config  fastlane.Config `json:"config"`
		MFACode string          `json:"mfa_code,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(c.Request.Body, 512<<10)).Decode(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON configuration payload"})
		return
	}
	next := payload.Config
	if err := next.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if next.Enabled && cfg.hardened && !next.TestMode && next.EffectivePolicyMode() == fastlane.PolicyModeNone && !next.AllowUnscreenedMainnet {
		c.JSON(http.StatusForbidden, gin.H{"error": "policy_mode \"none\" on mainnet is blocked in -enterprise-hardened mode unless allow_unscreened_mainnet is explicitly true"})
		return
	}
	prevCfg := a.fastlane.Config()
	destChanged, oldDests, newDests := destinationsDiff(prevCfg, next)
	if destChanged {
		if cfg.fastlaneLockDestinations {
			a.recordAudit(auditEvent{
				Actor: actor.Actor, Role: actor.Role.String(), Source: "portal",
				Action: "fastlane.config.update", Outcome: "deny", ClientIP: actor.IP.String(),
				Details: map[string]any{"reason": "destinations_locked"},
			})
			c.JSON(http.StatusForbidden, gin.H{"error": "receiving wallet destinations are locked by -fastlane-lock-destinations"})
			return
		}
		if cfg.hardened && actor.Source != "sso" {
			mfaOK := false
			if cfg.portal.users != nil {
				if u := cfg.portal.users.users[actor.Actor]; u != nil && len(u.totpSecret) > 0 {
					if payload.MFACode != "" {
						mfaOK = verifyTOTP(u.totpSecret, payload.MFACode, time.Now())
					} else {
						// User already passed TOTP MFA at login for this session.
						mfaOK = actor.Source == "user"
					}
				}
			}
			if !mfaOK {
				a.recordAudit(auditEvent{
					Actor: actor.Actor, Role: actor.Role.String(), Source: "portal",
					Action: "fastlane.config.update", Outcome: "deny", ClientIP: actor.IP.String(),
					Details: map[string]any{"reason": "mfa_required_for_payto_change"},
				})
				c.JSON(http.StatusForbidden, gin.H{"error": "changing receiving wallet addresses in -enterprise-hardened mode requires an MFA-verified admin account or SSO"})
				return
			}
		}
	}

	var nets map[string]gateway.Network
	if cfg.networksFile != "" {
		var err error
		if nets, err = gateway.LoadNetworks(cfg.networksFile); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "networks_config load failed: " + err.Error()})
			return
		}
	}
	if gwSrv, ok := a.fastlaneGW.(*gateway.Server); ok {
		if err := gwSrv.Reload(next, nets); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "gateway reload failed: " + err.Error()})
			return
		}
	}
	if err := a.fastlane.UpdateConfig(next); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if cfg.fastlaneFile != "" {
		if err := fastlane.SaveAtomic(cfg.fastlaneFile, next); err != nil {
			// Roll back in-memory state if disk persistence failed.
			_ = a.fastlane.UpdateConfig(prevCfg)
			if gwSrv, ok := a.fastlaneGW.(*gateway.Server); ok {
				_ = gwSrv.Reload(prevCfg, nets)
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist fastlane config: " + err.Error()})
			return
		}
	}
	a.agentOffer.Store(newAgentOffer(a.fastlane))
	a.recordAudit(auditEvent{
		Actor: actor.Actor, Role: actor.Role.String(), Source: "portal",
		Action: "fastlane.config.update", Outcome: "allow", ClientIP: actor.IP.String(),
		Details: map[string]any{
			"offers":               len(next.Offers),
			"collections":          len(next.Collections),
			"token_gates":          len(next.TokenGates),
			"policy_mode":          next.EffectivePolicyMode(),
			"destinations_changed": destChanged,
			"old_destinations":     oldDests,
			"new_destinations":     newDests,
		},
	})
	if destChanged {
		a.notifyEvent(mailer.Event{
			Category:    mailer.CatFastlane,
			Severity:    mailer.SevCritical,
			Title:       "Fast-lane receiving wallet destination changed",
			Summary:     fmt.Sprintf("Administrator %s modified fast-lane receiving wallet destination(s) live in the Admin Portal.", actor.label()),
			Fingerprint: "fastlane:payto:" + strings.Join(newDests, ","),
			Details: map[string]string{
				"actor":            actor.label(),
				"client_ip":        actor.IP.String(),
				"old_destinations": strings.Join(oldDests, "; "),
				"new_destinations": strings.Join(newDests, "; "),
			},
		})
	}
	c.JSON(http.StatusOK, gin.H{"saved": true, "destinations_changed": destChanged, "fastlane": a.fastlane.Summary()})
}

func (p *portal) apiFastlaneArchive(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown site"})
		return
	}
	handleFastlaneArchive(c, a, portalPrincipal(c), "portal")
}

func handleFastlaneArchive(c *gin.Context, a *app, actor principal, source string) {
	if a.fastlane == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "fast lane is not enabled"})
		return
	}
	var body struct {
		OlderThan string `json:"older_than"`
		DryRun    bool   `json:"dry_run"`
	}
	if c.Request.ContentLength != 0 {
		if err := json.NewDecoder(io.LimitReader(c.Request.Body, 4096)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
	}
	older := 720 * time.Hour
	if strings.TrimSpace(body.OlderThan) != "" {
		d, err := time.ParseDuration(strings.TrimSpace(body.OlderThan))
		if err != nil || d < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid older_than duration"})
			return
		}
		older = d
	}
	rep, err := a.fastlane.ArchiveOnline(older, body.DryRun)
	if err != nil {
		a.recordAudit(auditEvent{
			Actor: actor.Actor, Role: actor.Role.String(), Source: source,
			Action: "fastlane.archive", Outcome: "error", ClientIP: actor.IP.String(),
			Details: map[string]any{"error": err.Error()},
		})
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	if !rep.DryRun && rep.Archived > 0 {
		a.recordAudit(auditEvent{
			Actor: actor.Actor, Role: actor.Role.String(), Source: source,
			Action: "fastlane.archive", Target: rep.ArchiveFile, Outcome: "allow", ClientIP: actor.IP.String(),
			Details: map[string]any{"archived": rep.Archived, "kept": rep.Kept, "archive_sha256": rep.ArchiveSHA256},
		})
	}
	c.JSON(http.StatusOK, gin.H{"report": rep, "fastlane": a.fastlane.Summary()})
}

func (p *portal) apiFastlaneRevoke(c *gin.Context) {
	a, ok := p.targetApp(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown site"})
		return
	}
	handleFastlaneRevoke(c, a, portalPrincipal(c), "portal")
}

func handleFastlaneRevoke(c *gin.Context, a *app, actor principal, source string) {
	if a.fastlane == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "fast lane is not enabled"})
		return
	}
	var body struct {
		Target  string `json:"target"`  // session ID or pass ID
		Session string `json:"session"` // alias for target
		PassID  string `json:"pass_id"` // alias for target
	}
	if err := json.NewDecoder(io.LimitReader(c.Request.Body, 4096)).Decode(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target session or pass ID is required"})
		return
	}
	target := strings.TrimSpace(body.Target)
	if target == "" {
		target = strings.TrimSpace(body.Session)
	}
	if target == "" {
		target = strings.TrimSpace(body.PassID)
	}
	if target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target session or pass ID is required"})
		return
	}
	a.fastlane.RevokeSession(target)
	a.recordAudit(auditEvent{
		Actor: actor.Actor, Role: actor.Role.String(), Source: source,
		Action: "fastlane.revoke", Target: target, Outcome: "allow", ClientIP: actor.IP.String(),
	})
	c.JSON(http.StatusOK, gin.H{"revoked": true, "target": target})
}

func newAgentOffer(s *fastlane.Service) *agentOffer {
	if s == nil {
		return nil
	}
	cfg := s.Config()
	if !cfg.Enabled || len(cfg.Offers) == 0 {
		return nil
	}
	list := make([]gin.H, 0, len(cfg.Offers))
	for _, o := range cfg.Offers {
		entry := gin.H{
			"network":        o.Requirements.Network,
			"scheme":         o.Requirements.Scheme,
			"asset":          o.Requirements.Asset,
			"asset_symbol":   o.EffectiveSymbol(),
			"amount":         o.Requirements.Amount,
			"display_amount": o.EffectiveDisplayAmount(),
		}
		if len(o.RequireCollections) > 0 {
			entry["require_collections"] = o.RequireCollections
		}
		if len(o.RequireTokenGates) > 0 {
			entry["require_token_gates"] = o.RequireTokenGates
		}
		list = append(list, entry)
	}
	u := cfg.Origin + fastlane.Prefix + "/payment"
	return &agentOffer{paymentURL: u, body: gin.H{"payment_url": u, "pass_seconds": cfg.PassSeconds, "offers": list}}
}

func enterpriseSubcommand(name string) func([]string, io.Writer) error {
	switch name {
	case "reconcile":
		return runReconcile
	case "archive-receipts":
		return runArchiveReceipts
	case "example":
		return runExample
	case "audit":
		return runAudit
	case "hash-password":
		return runHashPassword
	}
	return nil
}

func movedEnterpriseFlags() map[string]string { return nil }

func checkEmailProvider(v any) error {
	switch strings.ToLower(strings.TrimSpace(v.(string))) {
	case mailer.ProviderOff, mailer.ProviderSMTP, mailer.ProviderResend, mailer.ProviderSendPanda:
		return nil
	default:
		return errors.New("must be empty (disabled), smtp, resend, or sendpanda")
	}
}

func checkSMTPTLS(v any) error {
	switch strings.ToLower(strings.TrimSpace(v.(string))) {
	case "", mailer.TLSStartTLS, mailer.TLSImplicit, mailer.TLSNone:
		return nil
	default:
		return errors.New("must be starttls, tls, or none")
	}
}

func checkCadenceUnit(v any) error {
	switch strings.ToLower(strings.TrimSpace(v.(string))) {
	case mailer.UnitMinutes, mailer.UnitHours, mailer.UnitDays:
		return nil
	default:
		return errors.New("must be minutes, hours, or days")
	}
}

func checkOptionalEmail(v any) error {
	s := strings.TrimSpace(v.(string))
	if s == "" {
		return nil
	}
	_, err := mailer.ValidateAddress(s)
	return err
}

func checkEmailList(v any) error {
	_, err := mailer.ParseAddressList(v.(string))
	return err
}

func checkEmailEvents(v any) error {
	_, err := mailer.ParseCategoryList(v.(string))
	return err
}

func checkOptionalHTTPURL(v any) error {
	s := strings.TrimSpace(v.(string))
	if s == "" {
		return nil
	}
	return mailer.ValidateHTTPURL(s, false)
}

func enterpriseSettingDefs() []settingDef {
	return []settingDef{
		// ---- Fast-Lane x402 / NFT ----
		{key: "fastlane_config", flag: "fastlane-config", env: "CONCERT_FASTLANE_CONFIG", group: groupSkip, label: "x402 / NFT configuration file", restart: true,
			def: "", usage: "fast lane JSON (x402 offers and NFT rules; see docs/FASTLANE.md), empty turns wallet access off (flag or CONCERT_FASTLANE_CONFIG only; takes a restart)", ptr: func(c *config) any { return &c.fastlaneFile }},
		{key: "networks_config", flag: "networks-config", env: "CONCERT_NETWORKS_CONFIG", group: groupSkip, label: "Chain endpoints file", restart: true,
			def: "", usage: "chain endpoints JSON for the fast lane's payment networks (see docs/FASTLANE.md); optional sponsor keys come from CONCERT_STELLAR_FEE_SECRET and CONCERT_HEDERA_FEE_SECRET (flag or CONCERT_NETWORKS_CONFIG only; takes a restart)", ptr: func(c *config) any { return &c.networksFile }},
		{key: "fastlane_lock_destinations", flag: "fastlane-lock-destinations", env: "CONCERT_FASTLANE_LOCK_DESTINATIONS", group: groupSkip, label: "Lock fast-lane receiving wallets", restart: true,
			def: false, usage: "prevent Admin Portal edits from changing payTo or verify_addresses wallet destinations (restart to change)", ptr: func(c *config) any { return &c.fastlaneLockDestinations }},

		// ---- Enterprise TLS mTLS ----
		{key: "tls_client_ca", flag: "tls-client-ca", env: "CONCERT_TLS_CLIENT_CA", group: groupTLS, label: "Client CA bundle (mTLS)", restart: true,
			def: "", usage: "PEM CA bundle used to verify TLS client certificates on -listen (required by -hop-require-mtls and -tls-require-client-cert; restart to change)",
			ptr: func(c *config) any { return &c.tlsClientCA }},
		{key: "tls_require_client_cert", flag: "tls-require-client-cert", env: "CONCERT_TLS_REQUIRE_CLIENT_CERT", group: groupTLS, label: "Require client cert for all TLS", restart: true,
			def: false, usage: "require a verified client certificate from -tls-client-ca on every TLS connection to -listen (strict mTLS; leave false for leaves serving public browsers alongside -hop-require-mtls)",
			ptr: func(c *config) any { return &c.tlsRequireClientCert }},

		// ---- Enterprise Portal SSO ----
		{key: "portal_sso_header", flag: "portal-sso-header", env: "CONCERT_PORTAL_SSO_HEADER", group: groupPortal, label: "SSO identity header", restart: true,
			def: "", usage: "header set by a trusted SSO proxy (e.g. X-Forwarded-Email) identifying the signed-in user",
			ptr: func(c *config) any { return &c.portal.ssoHeader }},
		{key: "portal_sso_role_header", flag: "portal-sso-role-header", env: "CONCERT_PORTAL_SSO_ROLE_HEADER", group: groupPortal, label: "SSO role/group header", restart: true,
			def: "", usage: "header set by a trusted SSO proxy carrying RBAC roles/groups (viewer, operator, admin)",
			ptr: func(c *config) any { return &c.portal.ssoRoleHeader }},
		{key: "portal_sso_default_role", flag: "portal-sso-default-role", env: "CONCERT_PORTAL_SSO_DEFAULT_ROLE", group: groupPortal, label: "SSO default role", restart: true,
			def: "viewer", usage: "default RBAC role for SSO users when no role header matches (viewer, operator, admin)",
			ptr: func(c *config) any { return &c.portal.ssoDefaultRole }},
		{key: "portal_trusted_proxies", flag: "portal-trusted-proxies", env: "CONCERT_PORTAL_TRUSTED_PROXIES", group: groupPortal, label: "Portal trusted SSO proxies", restart: true,
			def: "", usage: "comma-separated CIDRs of identity proxies trusted to set SSO headers",
			ptr: func(c *config) any { return &c.portal.trustedProxiesSpec }, check: checkCIDRList},

		// ---- Enterprise Hardening & Audit ----
		{key: "hardened", flag: "enterprise-hardened", env: "CONCERT_HARDENED", group: groupEnterprise, label: "Enterprise hardened preset", restart: true,
			def: false, usage: "enforce baseline enterprise security requirements at startup (explicit secrets, secure cookies, stats auth, audit log)",
			ptr: func(c *config) any { return &c.hardened }},
		{key: "audit_log", flag: "audit-log", env: "CONCERT_AUDIT_LOG", group: groupEnterprise, label: "Tamper-evident audit log", restart: true,
			def: "", usage: "hash-chained JSONL audit log path; empty means audit.jsonl in -data-dir, off disables persistence",
			ptr: func(c *config) any { return &c.auditLog }},

		// ---- Cluster sync; see cluster.go ----
		{key: "kv_addr", flag: "kv-addr", env: "CONCERT_KV_ADDR", group: groupCluster, label: "concert-kv address", restart: true,
			def: "", usage: "host:port or unix:///path of concert-kv (or Redis/Valkey) for multi-node HA ban sync and optional shared queue (empty disables)",
			ptr: func(c *config) any { return &c.kvAddr }},
		{key: "kv_tls", flag: "kv-tls", env: "CONCERT_KV_TLS", group: groupCluster, label: "concert-kv TLS", restart: true,
			def: false, usage: "use TLS 1.2+ when connecting to concert-kv",
			ptr: func(c *config) any { return &c.kvTLS }},
		{key: "kv_prefix", flag: "kv-prefix", env: "CONCERT_KV_PREFIX", group: groupCluster, label: "concert-kv key prefix", restart: true,
			def: "concert", usage: "key and pubsub channel prefix for cluster state in concert-kv",
			ptr: func(c *config) any { return &c.kvPrefix }},
		{key: "kv_shared_queue", flag: "kv-shared-queue", env: "CONCERT_KV_SHARED_QUEUE", group: groupCluster, label: "Shared waiting-room queue in concert-kv", restart: true,
			def: false, usage: "mirror waiting-room queue state in concert-kv via CQ.* commands with fail-open fallback to local room",
			ptr: func(c *config) any { return &c.kvSharedQueue }},
		{key: "redis_addr", flag: "redis-addr", env: "CONCERT_REDIS_ADDR", group: groupCluster, label: "Redis/Valkey address (alias for kv-addr)", restart: true,
			def: "", usage: "backward-compatible alias for -kv-addr: host:port of Redis/Valkey/concert-kv for multi-node HA sync",
			ptr: func(c *config) any { return &c.redisAddr }},
		{key: "redis_tls", flag: "redis-tls", env: "CONCERT_REDIS_TLS", group: groupCluster, label: "Redis TLS (alias for kv-tls)", restart: true,
			def: false, usage: "backward-compatible alias for -kv-tls: use TLS 1.2+ when connecting to Redis/Valkey/concert-kv",
			ptr: func(c *config) any { return &c.redisTLS }},
		{key: "redis_prefix", flag: "redis-prefix", env: "CONCERT_REDIS_PREFIX", group: groupCluster, label: "Redis key prefix (alias for kv-prefix)", restart: true,
			def: "concert", usage: "backward-compatible alias for -kv-prefix: key and pubsub channel prefix for cluster state",
			ptr: func(c *config) any { return &c.redisPrefix }},

		// ---- Edge and leaf tiers; see topology.go and docs/TOPOLOGY.md ----
		{key: "role", flag: "role", env: "CONCERT_ROLE", group: groupTopology, label: "Node role", restart: true,
			def: roleStandalone, usage: "standalone (one tier), edge (waiting room in front of leaf Concerts) or leaf (protects one host behind an edge)",
			ptr: func(c *config) any { return &c.role }, check: checkRole},
		{key: "node_id", flag: "node-id", env: "CONCERT_NODE_ID", group: groupTopology, label: "Node ID", restart: true,
			def: "", usage: "this node's ID in trust-chain claims and leaf reports, 1-32 of [A-Za-z0-9._-] (empty derives one from the hostname)",
			ptr: func(c *config) any { return &c.nodeID }, check: checkNodeID},
		{key: "hop_peers", flag: "hop-peers", env: "CONCERT_HOP_PEERS", group: groupTopology, label: "Hop peers (leaf)",
			def: "", usage: "leaf: CIDRs whose connections may present Concert-Hop claims: the edges, or the load balancer between tiers; required with -role leaf",
			ptr: func(c *config) any { return &c.hopPeers }, check: checkCIDRList, list: listCIDRs},
		{key: "hop_max_skew", flag: "hop-max-skew", env: "CONCERT_HOP_MAX_SKEW", group: groupTopology, label: "Hop clock skew", restart: true,
			def: hop.DefaultMaxSkew, usage: "leaf: how far a claim's timestamp may be from this clock, 1s-5m",
			ptr: func(c *config) any { return &c.hopMaxSkew }, check: durationBetween(time.Second, 5*time.Minute)},
		{key: "hop_wait", flag: "hop-wait", env: "CONCERT_HOP_WAIT", group: groupTopology, label: "Hop host-slot wait (leaf)",
			def: 2 * time.Second, usage: "leaf: how long an edge's page request waits for a host slot before 503 backpressure, 0s-30s",
			ptr: func(c *config) any { return &c.hopWait }, check: durationBetween(0, 30*time.Second)},
		{key: "hop_replay_guard", flag: "hop-replay-guard", env: "CONCERT_HOP_REPLAY_GUARD", group: groupTopology, label: "Hop nonce replay guard (leaf)",
			def: true, usage: "leaf: reject replayed single-use Concert-Hop nonces within 2x -hop-max-skew",
			ptr: func(c *config) any { return &c.hopReplayGuard }},
		{key: "hop_replay_max", flag: "hop-replay-max", env: "CONCERT_HOP_REPLAY_MAX", group: groupTopology, label: "Hop replay cache capacity (leaf)", restart: true,
			def: hop.DefaultReplayMax, usage: "leaf: maximum tracked single-use Concert-Hop nonces across 256 shards (1024-16777216; takes a restart)",
			ptr: func(c *config) any { return &c.hopReplayMax }, check: intBetween(hop.MinReplayMax, hop.MaxReplayMax)},
		{key: "hop_require_nonce", flag: "hop-require-nonce", env: "CONCERT_HOP_REQUIRE_NONCE", group: groupTopology, label: "Require hop nonces (leaf)",
			def: false, usage: "leaf: reject legacy Concert-Hop claims without a single-use nonce (required in -enterprise-hardened mode)",
			ptr: func(c *config) any { return &c.hopRequireNonce }},
		{key: "hop_require_mtls", flag: "hop-require-mtls", env: "CONCERT_HOP_REQUIRE_MTLS", group: groupTopology, label: "Require mTLS for hop claims (leaf)",
			def: false, usage: "leaf: require a verified TLS client certificate (-tls-client-ca) on Concert-Hop claims and /_room/hop/* while still allowing direct public browsers on HTTPS",
			ptr: func(c *config) any { return &c.hopRequireMTLS }},
		{key: "host_cap", flag: "host-cap", env: "CONCERT_HOST_CAP", group: groupTopology, label: "Host capacity (leaf)",
			def: 0, usage: "leaf: page requests this host serves at once from every source; 0 uses capacity.json from the benchmark, then -cap",
			ptr: func(c *config) any { return &c.hostCap }, check: intAtLeast(0)},
		{key: "hop_leaves", flag: "hop-leaves", env: "CONCERT_HOP_LEAVES", group: groupTopology, label: "Leaf control URLs (edge)",
			def: "", usage: "edge: comma-separated base URLs of the leaf Concerts to poll and sync bans to; empty means the -upstream targets (no load balancer between tiers)",
			ptr: func(c *config) any { return &c.hopLeaves }, check: checkURLList},
		{key: "hop_poll", flag: "hop-poll", env: "CONCERT_HOP_POLL", group: groupTopology, label: "Leaf poll interval (edge)",
			def: 2 * time.Second, usage: "edge: how often each leaf's capacity is read and bans are synced, 500ms-1m",
			ptr: func(c *config) any { return &c.hopPoll }, check: durationBetween(500*time.Millisecond, time.Minute)},
		{key: "hop_auto_cap", flag: "hop-auto-cap", env: "CONCERT_HOP_AUTO_CAP", group: groupTopology, label: "Size room from leaves (edge)",
			def: true, usage: "edge: set the room's capacity to what healthy leaves report, never above -cap",
			ptr: func(c *config) any { return &c.hopAutoCap }},
		{key: "bench_on_start", flag: "bench-on-start", env: "CONCERT_BENCH_ON_START", group: groupTopology, label: "Benchmark on first start (leaf)", restart: true,
			def: false, usage: "leaf: before serving, crawl the upstream with the capacity benchmark when capacity.json is missing, and use its result as the host capacity",
			ptr: func(c *config) any { return &c.benchOnStart }},
		{key: "bench_p95", flag: "bench-p95", env: "CONCERT_BENCH_P95", group: groupTopology, label: "Benchmark p95 limit", restart: true,
			def: 2 * time.Second, usage: "the p95 latency the startup benchmark holds the application to, 100ms-1m",
			ptr: func(c *config) any { return &c.benchP95 }, check: durationBetween(100*time.Millisecond, time.Minute)},
		{key: "bench_max_lemmings", flag: "bench-max-lemmings", env: "CONCERT_BENCH_MAX_LEMMINGS", group: groupTopology, label: "Benchmark lemming ceiling", restart: true,
			def: 1024, usage: "the most concurrent lemmings the startup benchmark tries, 1-100000",
			ptr: func(c *config) any { return &c.benchMaxLemmings }, check: intBetween(1, 100000)},

		// ---- Email delivery; see mailer.go and internal/mailer ----
		{key: "email_provider", flag: "email-provider", env: "CONCERT_EMAIL_PROVIDER", group: groupEmail, label: "Delivery provider",
			def: "", usage: "administrator alert delivery provider: empty (disabled), smtp, resend, or sendpanda",
			ptr: func(c *config) any { return &c.email.provider }, check: checkEmailProvider},
		{key: "email_smtp_host", flag: "email-smtp-host", env: "CONCERT_EMAIL_SMTP_HOST", group: groupEmail, label: "SMTP host",
			def: "", usage: "SMTP relay hostname (for -email-provider smtp)",
			ptr: func(c *config) any { return &c.email.smtpHost }},
		{key: "email_smtp_port", flag: "email-smtp-port", env: "CONCERT_EMAIL_SMTP_PORT", group: groupEmail, label: "SMTP port",
			def: 587, usage: "SMTP port (587 for STARTTLS, 465 for implicit TLS)",
			ptr: func(c *config) any { return &c.email.smtpPort }, check: intBetween(0, 65535)},
		{key: "email_smtp_tls", flag: "email-smtp-tls", env: "CONCERT_EMAIL_SMTP_TLS", group: groupEmail, label: "SMTP TLS mode",
			def: mailer.TLSStartTLS, usage: "SMTP transport security: starttls, tls (implicit SMTPS), or none (local relay only)",
			ptr: func(c *config) any { return &c.email.smtpTLS }, check: checkSMTPTLS},
		{key: "email_smtp_user", flag: "email-smtp-user", env: "CONCERT_EMAIL_SMTP_USER", group: groupEmail, label: "SMTP username",
			def: "", usage: "SMTP authentication username (password comes from CONCERT_SMTP_PASS or encrypted email-secrets.json)",
			ptr: func(c *config) any { return &c.email.smtpUser }},
		{key: "email_resend_url", flag: "email-resend-url", env: "CONCERT_EMAIL_RESEND_URL", group: groupEmail, label: "Resend API base URL",
			def: "", usage: "Resend REST API base URL (empty uses https://api.resend.com)",
			ptr: func(c *config) any { return &c.email.resendURL }, check: checkOptionalHTTPURL},
		{key: "email_sendpanda_url", flag: "email-sendpanda-url", env: "CONCERT_EMAIL_SENDPANDA_URL", group: groupEmail, label: "SendPanda API base URL",
			def: "", usage: "SendPanda REST API base URL (empty uses https://api.sendpanda.email/v1)",
			ptr: func(c *config) any { return &c.email.sendPandaURL }, check: checkOptionalHTTPURL},
		{key: "email_from_name", flag: "email-from-name", env: "CONCERT_EMAIL_FROM_NAME", group: groupEmail, label: "Sender display name",
			def: "Concert", usage: "display name on outgoing administrator digest emails",
			ptr: func(c *config) any { return &c.email.fromName }},
		{key: "email_from_addr", flag: "email-from-addr", env: "CONCERT_EMAIL_FROM_ADDR", group: groupEmail, label: "Sender email address",
			def: "", usage: "From email address on outgoing digests (e.g. alerts@example.com)",
			ptr: func(c *config) any { return &c.email.fromAddr }, check: checkOptionalEmail},
		{key: "email_to", flag: "email-to", env: "CONCERT_EMAIL_TO", group: groupEmail, label: "Administrator recipients",
			def: "", usage: "comma-separated administrator email addresses to receive scheduled digests",
			ptr: func(c *config) any { return &c.email.toAddrs }, check: checkEmailList},
		{key: "email_dkim_selector", flag: "email-dkim-selector", env: "CONCERT_EMAIL_DKIM_SELECTOR", group: groupEmail, label: "DKIM selector",
			def: "", usage: "optional DKIM DNS selector verified under <selector>._domainkey.<from-domain>",
			ptr: func(c *config) any { return &c.email.dkimSelector }},
		{key: "email_cadence_max", flag: "email-cadence-max", env: "CONCERT_EMAIL_CADENCE_MAX", group: groupEmail, label: "Max emails per window",
			def: 1, usage: "maximum digest emails delivered per cadence window (1-1000, paced evenly at window / max)",
			ptr: func(c *config) any { return &c.email.cadenceMax }, check: intBetween(1, mailer.MaxCadenceEmails)},
		{key: "email_cadence_window", flag: "email-cadence-window", env: "CONCERT_EMAIL_CADENCE_WINDOW", group: groupEmail, label: "Cadence window value",
			def: 15, usage: "numeric length of the digest cadence window (combined with -email-cadence-unit, 15m to 30d)",
			ptr: func(c *config) any { return &c.email.cadenceWindowValue }, check: intAtLeast(1)},
		{key: "email_cadence_unit", flag: "email-cadence-unit", env: "CONCERT_EMAIL_CADENCE_UNIT", group: groupEmail, label: "Cadence window unit",
			def: mailer.UnitMinutes, usage: "unit for the digest cadence window: minutes, hours, or days",
			ptr: func(c *config) any { return &c.email.cadenceWindowUnit }, check: checkCadenceUnit},
		{key: "email_events", flag: "email-events", env: "CONCERT_EMAIL_EVENTS", group: groupEmail, label: "Subscribed event categories",
			def: "", usage: "comma-separated event categories to queue (empty = all; none = disabled; silence,capacity,bans,fastlane,queue,security)",
			ptr: func(c *config) any { return &c.email.events }, check: checkEmailEvents},
		{key: "email_org_name", flag: "email-org-name", env: "CONCERT_EMAIL_ORG_NAME", group: groupEmail, label: "Organization name",
			def: "", usage: "sender organization name displayed in compliance email headers and footers",
			ptr: func(c *config) any { return &c.email.orgName }},
		{key: "email_postal_address", flag: "email-postal-address", env: "CONCERT_EMAIL_POSTAL_ADDRESS", group: groupEmail, label: "Physical postal address",
			def: "", usage: "organization physical mailing address included in compliance email footers (CAN-SPAM)",
			ptr: func(c *config) any { return &c.email.postalAddress }},
		{key: "email_privacy_url", flag: "email-privacy-url", env: "CONCERT_EMAIL_PRIVACY_URL", group: groupEmail, label: "Privacy policy URL",
			def: "", usage: "link to your privacy policy included in compliance email footers",
			ptr: func(c *config) any { return &c.email.privacyURL }, check: checkOptionalHTTPURL},
		{key: "email_terms_url", flag: "email-terms-url", env: "CONCERT_EMAIL_TERMS_URL", group: groupEmail, label: "Terms URL",
			def: "", usage: "link to your terms or operational notice included in compliance email footers",
			ptr: func(c *config) any { return &c.email.termsURL }, check: checkOptionalHTTPURL},
		{key: "email_portal_url", flag: "email-portal-url", env: "CONCERT_EMAIL_PORTAL_URL", group: groupEmail, label: "Admin portal link URL",
			def: "", usage: "URL linked in digest emails so administrators can jump directly to this Concert portal",
			ptr: func(c *config) any { return &c.email.portalURL }, check: checkOptionalHTTPURL},
		{key: "email_public_base_url", flag: "email-public-base-url", env: "CONCERT_EMAIL_PUBLIC_BASE_URL", group: groupEmail, label: "Public base URL (unsubscribe)",
			def: "", usage: "public origin URL used to build signed RFC 8058 one-click /_concert/email/unsubscribe links",
			ptr: func(c *config) any { return &c.email.publicBaseURL }, check: checkOptionalHTTPURL},
		{key: "email_cluster_dedupe", flag: "email-cluster-dedupe", env: "CONCERT_EMAIL_CLUSTER_DEDUPE", group: groupEmail, label: "Cluster alert deduplication",
			def: true, usage: "when -redis-addr is set, deduplicate shared cluster alert fingerprints across peers via fail-open Redis leases",
			ptr: func(c *config) any { return &c.email.clusterDedupe }},
	}
}
