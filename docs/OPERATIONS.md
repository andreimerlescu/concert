# Concert Operations & Queue Recovery Runbook

This runbook covers production configuration baselines, host-protection guardrails, capacity calibration, live waiting-room recovery, active cache purging, scheduled drops, and monitoring/alerting for the complete Concert Suite (`concert`, `wpconcert`, `econcert`, `concert-kv`, `concert-cache`, `concert-watchdog`, `bench-concert`, and `concert-client`).

> **Related guides:** [6 Production Deployment Tutorials](tutorials/README.md) · [Enterprise Hardening Guide](ENTERPRISE.md) · [Official Client SDKs](../clients/)

---

## 1. Production Baselines

Concert's default waiting-room liveness timers and upstream stall bounds are chosen so abandoned visitors and hung origins cannot lock out the queue with persistent `503 Service Unavailable` responses:

| Control | Recommended Production Value | Why It Matters |
|---|---|---|
| `-ready-grace` / `CONCERT_READY_GRACE` | `30s` (default) | Reclaims a ticket inside the serving window if the browser never comes back to claim its slot (`5s`–`10m`, `>= 2 * retry-after`, `<= token-ttl`, `0` disables). |
| `-idle-poll-ttl` / `CONCERT_IDLE_POLL_TTL` | `45s` (default) | Evicts queued visitors that stop polling `/queue/status` or retrying (`10s`–`24h`, `>= 2 * retry-after`, `<= token-ttl`, `0` disables). |
| `-reaper` / `CONCERT_REAPER` | `10s` (default) | Sweeps expired, unpolled, idle, and unclaimed-ready tickets promptly (`5s`–`24h`). |
| `-upstream-body-idle-timeout` / `CONCERT_UPSTREAM_BODY_IDLE_TIMEOUT` | `30s` (default) | Aborts stalled non-stream upstream responses that stop sending body bytes after headers, releasing the room slot cleanly on H1/H2/H3 and FastCGI. Automatically exempts `-stream-paths`, SSE (`text/event-stream`), and HTTP `101` upgrades. |
| `-upstream-cb-failures` / `CONCERT_UPSTREAM_CB_FAILURES` | `5` | Trips the upstream circuit breaker after 5 consecutive transport/502–504/body-stall failures so broken origins fail fast instead of pinning room slots. |
| `-upstream-cb-cooldown` / `CONCERT_UPSTREAM_CB_COOLDOWN` | `15s` | Cool-off period before probing a tripped backend again. |
| `-upstream-health-path` / `CONCERT_UPSTREAM_HEALTH_PATH` | `/healthz` | Active origin health probe (even on single-backend origins, an unhealthy active probe fails live traffic fast with `503` and marks `/_room/readyz` unready). |
| `-admit-session-continuity` / `CONCERT_ADMIT_SESSION_CONTINUITY` | `true` (default) | Allows active `concert_admit` holders to continue browsing without queue re-entry (bounded per pass, sliding expiry/Max-Age), while explicitly clearing stale passes with `Set-Cookie: concert_admit=; Max-Age=0` on requeue. |
| `-max-queue-per-ip` / `-allow-max-queue-per-ip` | `4` / `24` | Caps concurrent waiting-room tickets per client IP (or IPv6 `/64`) and per `-abuse-allow` CIDR so a single flood source cannot starve `-max-queue`. |
| `-host-max-mem-mb` / `-host-max-fds` / `-host-max-conns` | Host-sized (e.g. `768` / `32768` / `20000`) | Sheds excess arrivals cleanly with `503` + `Retry-After` before kernel OOM or FD exhaustion can take down Concert. |
| `-challenge-mode` / `-challenge-pow-bits` | `pow` / `16` (or `turnstile`) | Optional pre-ticket bot challenge stopping headless cookie-less floods before waiting-room tickets are allocated. |

### Standalone (`concert`)

```sh
concert \
  -listen :443 \
  -tls-http-listen :80 \
  -tls-domains shop.example.com \
  -tls-email ops@example.com \
  -upstream http://127.0.0.1:3000 \
  -cap 50 \
  -priority-cap 12 \
  -max-queue 500 \
  -ready-grace 30s \
  -idle-poll-ttl 45s \
  -reaper 10s \
  -upstream-timeout 60s \
  -upstream-body-idle-timeout 30s \
  -upstream-cb-failures 5 \
  -upstream-cb-cooldown 15s \
  -upstream-health-path /healthz \
  -secure-cookie \
  -data-dir /var/lib/concert/data
```

### WordPress / PHP-FPM (`wpconcert`)

Keep `-cap + -priority-cap <= pm.max_children` so PHP-FPM never thrashes under spikes. Run `wpconcert init` and `wpconcert doctor` to verify pool sizing (see [docs/WORDPRESS.md](WORDPRESS.md)).

```sh
wpconcert \
  -listen :443 \
  -tls-http-listen :80 \
  -tls-domains shop.example.com \
  -tls-email ops@example.com \
  -wp-preset \
  -static-root /var/www/shop \
  -upstream fcgi+unix:///run/php/php8.3-fpm.sock \
  -cap 12 \
  -priority-cap 4 \
  -max-queue 400 \
  -micro-cache-ttl 15s \
  -ready-grace 30s \
  -idle-poll-ttl 45s \
  -reaper 10s \
  -upstream-timeout 90s \
  -upstream-body-idle-timeout 30s \
  -upstream-cb-failures 5 \
  -upstream-cb-cooldown 15s \
  -secure-cookie \
  -data-dir /var/lib/concert/data
```

### Multi-Vhost Declarative `Concertfile`

Every room timer and upstream resilience guardrail can be set globally or overridden per site in `Concertfile` (use `off` or `0` to disable an individual duration):

```text
{
    listen :443
    http_listen :80
    tls_email ops@example.com
    tls_cache /var/lib/concert/acme
    hsts_max_age 31536000
    http3 on
    data_dir /var/lib/concert/data

    ready_grace 30s
    idle_poll_ttl 45s
    reaper 10s
    retry_after 5
    upstream_timeout 60s
    upstream_body_idle_timeout 30s
    upstream_cb_failures 5
    upstream_cb_cooldown 15s
    upstream_health_path /healthz
    upstream_health_interval 10s
}

shop.example.com, www.shop.example.com {
    preset wordpress
    root /var/www/shop
    upstream fcgi+unix:///run/php/php8.3-fpm-shop.sock
    cap 12
    priority_cap 4
    max_queue 400
    micro_cache 15s
    upstream_timeout 90s
    upstream_health_path off
    secure_cookie on
}

api.example.com {
    upstream http://127.0.0.1:4000
    cap 40
    priority_cap 10
    max_queue 600
    token_ttl 3m
    first_poll_grace 20s
    ready_grace 20s
    idle_poll_ttl 30s
    secure_cookie on
}
```

Reload cleanly with `kill -HUP $(pidof concert)` or **Reload config** in the Admin Portal (`POST /api/reload`). Live config reloads swap site runtimes atomically without writing orphaned `queue.snapshot` files from the replaced generation.

### Two-Tier `econcert` (Edge + Leaf)

In two-tier deployments (see [docs/TOPOLOGY.md](TOPOLOGY.md)), the **edge** owns the public waiting room and dynamically sizes its room capacity from healthy leaf shares minus its own priority lane (`min(-cap, sum(shares) - effectivePriorityCap)`):

- **Edge:** configure `-role edge`, `-ready-grace 30s -idle-poll-ttl 45s -reaper 10s -upstream-body-idle-timeout 30s -upstream-cb-failures 5 -upstream-cb-cooldown 15s`, and set `-priority-cap` explicitly so `effectivePriorityCap` stays well below total healthy leaf slots (avoiding priority-lane collapse that clamps the general room cap to `1`).
- **Leaf:** configure `-role leaf`, `-bench-on-start` (or explicit `-host-cap` / `capacity.json`), `-upstream-cb-failures 5 -upstream-cb-cooldown 15s -upstream-health-path /healthz -upstream-body-idle-timeout 30s`, and `-hop-require-mtls=true -hop-require-nonce=true` under `-enterprise-hardened=true`.

---

## 2. Calibrating `-cap` and `-priority-cap`

Concert's default `-cap 434` (with `-priority-cap 0`, which adds `cap / 4 = 108` priority slots — **542 max concurrent upstream page requests**) is intentionally permissive for compatibility, not a safe production default for most single origins.

At startup, Concert logs safety diagnostics whenever:
- `-cap >= 400` on a non-edge node with no `capacity.json`, no `-upstream-cb-failures`, and no `-upstream-health-path` configured.
- `-max-queue > 0` while either `-ready-grace=0` or `-idle-poll-ttl=0` (warning that abandoned tickets may occupy the queue until `-token-ttl`).
- An edge node receives a capacity plan where `effectivePriorityCap() >= TotalLeafSlots`.

### Measuring Origin Capacity with `bench-concert` / `-bench-on-start`

Use Concert's built-in capacity benchmark to measure the highest concurrency your origin sustains with p95 under 2s and zero load-induced failures:

```sh
bench-concert -target http://127.0.0.1:3000/ -out /var/lib/concert/data/bench-report.json -data-dir /var/lib/concert/data
```

This writes `capacity.json` into `-data-dir`. Set `-cap` to ~80% of the measured ceiling and `-priority-cap` to the remaining ~20% (or let leaf nodes run `-bench-on-start` on first boot and recalibrate live via `POST /_room/rebench` or Portal **Drain & re-benchmark**).

### Stress-Testing & Verifying Recovery with `bench-concert` (`soak-100k`) & `lemmings` v2.0.0

Validate 100k-connection flood isolation, zero re-queuing of admitted human sessions (`concert_admit` continuity), and Lemmings waiting-room signal headers (`X-Concert-Queue: 1`, `X-Concert-Position`, `Retry-After`, `Cache-Control: no-store`) using Concert's built-in soak harness:

```sh
bench-concert \
  -target https://staging.example.com/ \
  -profile soak-100k \
  -mix-real-and-flood \
  -soak-duration 5m \
  -soak-connections 100000 \
  -humans 200 \
  -flood 1000 \
  -max-requeues 0 \
  -max-human-5xx 0 \
  -p95 2s \
  -out ./soak-100k-report.json
```

You can also validate saturation, branded `503` overflow behavior, and automatic post-burst self-healing with `lemmings` v2.0.0 against a staging Concert instance:

```sh
./bin/lemmings \
  -p=12 -t=33 -l=434 -r=90s -u=90s \
  -tmin=600ms -tmax=6s -mpg=33 \
  -c=true -cd=3 -assets \
  -hit http://127.0.0.1:18081/
```

What to verify:
1. **Peak saturation:** Once queued visitors reach `-max-queue`, excess browsers receive Concert's branded `503` busy page (with `Retry-After` and jittered auto-retry via `/_concert/busy.js`), API/agent clients receive JSON `503`, and `concert_room_rejected_503_total` increments.
2. **Automatic self-heal:** Within `<= ready_grace + 5s` after the burst ends (or after interrupting `lemmings` mid-queue with `Ctrl-C`), `occupancy` and `live_queue_depth` return to `0`, and a fresh visitor receives `200 OK` without restarting Concert.
3. **Regression gating:** Reconcile `lemmings`'s JSON report against `/_room/stats` and `/_room/metrics`, and use `lemmings compare` across releases.

---

## 3. Live Queue Recovery Runbook

### Step 1: Triage via `/_room/stats` or Portal Overview

```sh
curl -fsS https://shop.example.com/_room/stats \
  -H "Authorization: Bearer $CONCERT_ADMIN_TOKEN" | jq '{
    cap, occupancy, live_queue_depth, queue_depth, max_queue_depth,
    ready_grace, idle_poll_ttl, reaper,
    rejected_503_total, cleared_total, upstream_body_idle_timeouts_total,
    upstream_backends, upstream_healthy
  }'
```

- **`upstream_healthy == 0` or rising `upstream_body_idle_timeouts_total`:** Your origin is stalled or unhealthy; fix/restart the upstream first so admitted slots drain.
- **`live_queue_depth` stuck near `max_queue_depth` while `rejected_503_total` climbs:** Check whether tickets are genuinely active or idle/abandoned in the Portal **Queue** tab (idle rows are highlighted once idle longer than `clamp(idle_poll_ttl/3, 5s, 15s)`).

### Step 2: Flush Stale Tickets (Non-Disruptive)

Remove only abandoned/idle tickets while keeping actively polling visitors in line:

```sh
# Uses the room's configured idle_poll_ttl (or 30s if idle_poll_ttl is 0)
curl -X POST https://shop.example.com/_room/queue/clear \
  -H "Authorization: Bearer $CONCERT_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"stale"}'

# Or specify an explicit idle threshold in seconds
curl -X POST https://shop.example.com/_room/queue/clear \
  -H "Authorization: Bearer $CONCERT_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"stale","max_idle_seconds":15}'
```

In the Admin Portal, select the site (in multi-vhost `-config` mode), open the **Queue** tab, and click **Flush stale** (`POST /api/queue/clear` with `{"mode":"stale"}`).

### Step 3: Clear Entire Queue (Emergency Live Recovery)

If a misbehaving wave or broken incident left the line full and you need an immediate clean slate without restarting Concert:

```sh
curl -X POST https://shop.example.com/_room/queue/clear \
  -H "Authorization: Bearer $CONCERT_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"all"}'
```

Response (`200 OK`):

```json
{
  "mode": "all",
  "removed": 369,
  "live_queue_depth": 0,
  "queue_depth": 0
}
```

Or click **Clear queue** in the Portal **Queue** tab (`POST /api/queue/clear`).

Key behavioral guarantees of queue clear:
- **No false `403` storm:** Cleared tickets are **not** added to the kick blocklist (`p.kicked`). Visitors whose tickets were cleared transparently re-admit (if slots are free) or rejoin at the back of the line on their next reload.
- **In-flight requests untouched:** Only waiting tickets are removed; active requests, leases, and VIP passes remain intact.
- **Auxiliary state cleaned immediately:** Keyed `Concert-Session` agent places are reconciled (`a.agents.reconcile`) and Portal visitor notes are pruned immediately.
- **RBAC & Audit:** Requires `operator` role (or higher) on both `POST /_room/queue/clear` (Bearer token) and `POST /api/queue/clear` (Portal session + CSRF). Every clear records a `queue.clear` event in `audit.jsonl` (audit-only; does not send alert email).
- **Local scope:** Queue clear operates strictly on the targeted instance (and targeted vhost via `Host:` on `/_room/queue/clear` or `?site=<host>` on `/api/queue/clear`). On an `econcert` edge node, clearing the queue immediately updates reported `?demand=` on the next `-hop-poll` tick so leaf weighted shares rebalance promptly.

### Step 4: Startup Queue Snapshot Guardrails & `-clear-queue-on-start`

When Concert starts with `-data-dir` set:
1. If `-clear-queue-on-start` (`CONCERT_CLEAR_QUEUE_ON_START=true`) is set, Concert deletes any existing `queue.snapshot` and boots with an empty waiting room. Use this as a one-shot emergency recovery flag if restarting after an extended outage, then set it back to `false`.
2. If `queue.snapshot` is older than `effectiveTokenTTL()` (`-token-ttl`, or room's `5m` default), Concert discards it automatically instead of shifting expired tickets forward.
3. On import, `room v1.9.0` drops tickets already past `-idle-poll-ttl` or `-ready-grace` and logs `dropped_stale=<n>`.
4. If the restored queue depth is `>= 80%` of `-max-queue`, Concert logs an explicit startup warning so operators know the line is starting near saturation.

---

## 4. Monitoring & Alerting Reference

### Key Prometheus Metrics (`GET /_room/metrics`)

| Metric | Type | Meaning & Recommended Action |
|---|---|---|
| `concert_room_rejected_503_total` | counter | Visitors refused with `503` because the queue hit `-max-queue`. Any sustained increase indicates queue saturation; check origin latency, `occupancy`, and `live_queue_depth`. |
| `concert_room_cleared_total` | counter | Total waiting-room tickets cleared by operators (`mode: stale` or `mode: all`). Correlate spikes with `audit.jsonl` (`action="queue.clear"`). |
| `concert_upstream_body_idle_timeouts_total` | counter | Non-stream upstream responses aborted after stalling mid-body for `-upstream-body-idle-timeout`. Indicates hung backend workers, deadlocked DB queries, or slow PHP-FPM flushes. |
| `concert_room_occupancy` / `concert_room_cap` | gauge | Current active page slots vs cap. Sustained `occupancy == cap` with rising `concert_room_live_queue_depth` means the origin is at capacity. |
| `concert_room_live_queue_depth` / `concert_room_max_queue_depth` | gauge | Active waiting visitors vs configured `503` breaker ceiling. Alert when `live_queue_depth / max_queue_depth > 0.8`. |
| `concert_upstream_backends_healthy` / `concert_ready` | gauge | Healthy upstream count and readiness state (`0` when draining or all backends are unhealthy). |
| `concert_guard_quota_rejected_total` / `concert_guard_shed_total` | counter | Arrivals rejected by per-IP queue quotas or shed with `503` by host RSS/FD/connection ceilings. Alert immediately on `concert_guard_shed_total > 0`. |
| `concert_guard_challenge_passed_total` / `concert_guard_challenge_failed_total` | counter | Pre-ticket PoW / Turnstile challenge outcomes. |
| `concert_bidding_submitted_total` / `concert_bidding_settled_total` / `concert_bidding_rejected_total` | counter | 4-chain non-custodial AI Agent Pass Bidding lifecycle counters. |

### Production Prometheus Alert Rules, Grafana Dashboard, OTLP & ChatOps

Apply the maintained production ruleset and Grafana dashboard directly from [`deploy/observability/`](../deploy/observability/):

- [`deploy/observability/prometheus-rules.yaml`](../deploy/observability/prometheus-rules.yaml) — Ready-to-apply `PrometheusRule` covering `HighQueueDepth`, `CapacityBreakerActive`, `OriginUnhealthy`, `UpstreamBodyIdleTimeouts`, `GuardHostShedding`, `FastLaneSettlementFailure`, and `FastLaneJournalNearCapacity`.
- [`deploy/observability/grafana-dashboard.json`](../deploy/observability/grafana-dashboard.json) — Prebuilt Grafana dashboard for Waiting Room, Guardrails, Upstream Health, Fast-Lane, and Bidding.
- **ChatOps Alerts (`internal/notify`):** Set `CONCERT_NOTIFY_SLACK_URL_FILE`, `CONCERT_NOTIFY_DISCORD_URL_FILE`, `CONCERT_NOTIFY_TEAMS_URL_FILE`, `CONCERT_NOTIFY_WEBHOOK_URL_FILE` (+ `CONCERT_NOTIFY_WEBHOOK_SECRET_FILE`), or `CONCERT_NOTIFY_PAGERDUTY_KEY_FILE` for async, coalesced real-time alerts alongside email digests.
- **Distributed Tracing (`internal/telemetry`):** Set `-otlp-endpoint`, `-otlp-sample-rate`, and `CONCERT_OTLP_AUTH_HEADER_FILE` for pure-stdlib OTLP/HTTP JSON span export and W3C `traceparent` propagation.
- **External Supervision (`concert-watchdog`):** Supervise Concert on Linux hosts via `installer.sh` with `CONCERT_WATCHDOG=1` (or systemd parent mode; see [Tutorial 01](tutorials/01-single-host-vps.md)). `concert-watchdog` inspects `concert_upstream_backends_healthy` so origin outages never trigger pointless Concert restarts.

### Example Prometheus Alert Rules

```yaml
groups:
  - name: concert-queue-health
    rules:
      - alert: ConcertQueueRejecting503
        expr: increase(concert_room_rejected_503_total[2m]) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Concert waiting room is rejecting visitors with 503"
          description: "Queue hit -max-queue on {{ $labels.instance }}. Inspect /_room/stats and consider Flush stale or scaling origin capacity."

      - alert: ConcertQueueNearSaturation
        expr: concert_room_max_queue_depth > 0 and (concert_room_live_queue_depth / concert_room_max_queue_depth) >= 0.8
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Concert queue depth >= 80% of max-queue"

      - alert: ConcertUpstreamBodyIdleStalls
        expr: increase(concert_upstream_body_idle_timeouts_total[5m]) >= 5
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Upstream responses are stalling mid-body on {{ $labels.instance }}"
```

### Built-In Email Alerts (`econcert`)

When `queue` alerts are enabled in `-email-events` / the Portal **Email** tab:
- **`queue:breaker-503`** (`severity: critical`, `category: queue`): emitted directly from `room.EventReject` whenever the queue-full breaker refuses a visitor with `503`. Includes current `occupancy` and `live` queue depth, coalesces repeated rejections into paced digest emails, and deduplicates across Redis-backed multi-edge clusters (`-email-cluster-dedupe=true`).

### Custom Busy `503` Page (`-busy-html`)

When `-max-queue` is exceeded:
- Browsers (`Accept: text/html`) receive HTTP `503`, `Retry-After: <retry-after>`, strict CSP (`script-src 'self'`), and Concert's built-in `web/busy.html` (which loads `/_concert/busy.js` to count down with 0–20% jitter and auto-reload).
- API clients (`-api-json=true`) and keyed `Concert-Session` agents receive JSON `503` (`{"queued":false,"error":"waiting room is full","retry_after_seconds":N}`) with `Retry-After`.
- Override the HTML page with `-busy-html /path/to/busy.html` (`CONCERT_BUSY_HTML`, hot-reloadable). Concert replaces `{{.RetryAfter}}` on serve; avoid inline `<script>` or `<style>` tags so strict CSP stays intact.
