# Concert Enterprise Hardening & Compliance Guide

> **Edition Note (`v0.3.0`+):** All enterprise features documented in this guide (RBAC/MFA/SSO, hash-chained audit logs, `-enterprise-hardened`, Redis HA ban sync, edge/leaf mesh + mTLS, email digests, and x402 Fast-Lane) ship in the **`econcert`** binary (`go build -tags "wordpress,enterprise" ./cmd/econcert`). Core `concert` and `wpconcert` compile without these packages or their transitive dependencies.

This guide documents Concert's enterprise security, observability, high-availability, and privacy controls and maps them to common enterprise frameworks (SOC 2 Type II, ISO/IEC 27001, PCI DSS v4.0.1, HIPAA, GDPR/CCPA, and FIPS 140-3).

---

## 1. Enterprise Hardened Preset (`-enterprise-hardened`)

Enable `-enterprise-hardened` (`CONCERT_HARDENED=true`) in production to fail closed at startup unless baseline controls are satisfied:

- Explicit `CONCERT_ADMIT_SECRET` (or `CONCERT_ADMIT_SECRET_FILE`) ≥ 32 bytes (no ephemeral random secret)
- `-secure-cookie=true`
- `-stats-auth=true` (locks down `/_room/stats` and `/_room/metrics` behind bearer RBAC tokens)
- `CONCERT_ADMIN_TOKEN` or `CONCERT_ADMIN_TOKENS` configured
- Tamper-evident `-audit-log` persisted (cannot be `off`)
- Admin portal served over native TLS (`-portal-tls-cert`/`-portal-tls-key`) or `-portal-secure-cookie` behind trusted proxies
- `CONCERT_PORTAL_PASS` must not be set alongside `CONCERT_PORTAL_USERS` (startup fails closed; outside hardened mode `CONCERT_PORTAL_USERS` still unconditionally disables the shared password and logs a startup warning)
- On leaf nodes (`-role leaf`), `-hop-replay-guard=true` and `-hop-require-nonce=true` (enforcing single-use `Concert-Hop` nonces with fail-closed saturation protection rather than evicting unexpired nonces)

For immutable / GitOps deployments, also enable `-read-only-settings` (`CONCERT_READ_ONLY_SETTINGS=true`) so neither the portal nor `/_room/cap` can mutate `settings.json` at runtime.

---

## 2. Identity, RBAC, MFA & SSO

### Roles

| Role | Permissions |
| --- | --- |
| `viewer` | Read-only overview, queue, bans, history, settings, `/_room/stats`, `/_room/metrics` (internal `upstream` URL is hidden when `-stats-auth=true`) |
| `operator` | All `viewer` permissions + queue promote/kick (`POST /_room/promote`), capacity updates (`POST /_room/cap`), temporary single-IP bans, lifting bans |
| `admin` | All `operator` permissions + permanent bans, CIDR range bans, live settings changes, drained leaf re-benchmarking (`POST /_room/rebench`, `POST /api/topology/rebench`), zero-downtime fast-lane reconciliation (`POST /_room/fastlane/reconcile`, `POST /api/fastlane/reconcile`), GDPR/CCPA DSAR export & erasure |

### Multi-User Portal Accounts with Argon2id + TOTP MFA

Generate an OWASP Argon2id password hash:

```sh
econcert hash-password "your-strong-passphrase"
```

Configure `CONCERT_PORTAL_USERS` (inline JSON or `@/etc/concert/portal_users.json` or `CONCERT_PORTAL_USERS_FILE`):

```json
[
  {
    "username": "alice@corp.example",
    "password_hash": "$argon2id$v=19$m=65536,t=3,p=2$...",
    "role": "admin",
    "totp_secret": "JBSWY3DPEHPK3PXP"
  },
  {
    "username": "oncall@corp.example",
    "password_hash": "$argon2id$v=19$m=65536,t=3,p=2$...",
    "role": "operator"
  }
]
```

### Enterprise SSO Reverse-Proxy Integration (OIDC / SAML)

Place OAuth2 Proxy, Pomerium, Envoy/Keycloak, Okta, or Cloudflare Access in front of the portal and configure:

```sh
CONCERT_PORTAL_TRUSTED_PROXIES=10.0.1.0/24
CONCERT_PORTAL_SSO_HEADER=X-Forwarded-Email
CONCERT_PORTAL_SSO_ROLE_HEADER=X-Forwarded-Groups
CONCERT_PORTAL_SSO_DEFAULT_ROLE=viewer
```

Group names matching `viewer`, `operator`, or `admin` (with optional `concert-`, `concert_`, or `role:` prefixes) automatically grant the highest matching role.

### Scoped Named API Tokens

Use `CONCERT_ADMIN_TOKENS` (or `CONCERT_ADMIN_TOKENS_FILE`) instead of a single shared token:

```sh
CONCERT_ADMIN_TOKENS="prometheus:viewer:<token1>,autoscaler:operator:<token2>,secops:admin:<token3>"
```

---

## 3. Tamper-Evident Hash-Chained Audit Logging

All administrative actions (sign-ins, denied auth attempts, settings changes, promotions, kicks, bans/unbans, DSAR exports/erasures) are synchronously written to `audit.jsonl` (mode `0600`, rotating at 64 MB). Each record chains cryptographically to `prev_hash` via HMAC-SHA256 derived from `CONCERT_ADMIT_SECRET`.

Verify chain integrity offline at any time:

```sh
CONCERT_ADMIT_SECRET_FILE=/run/secrets/concert/admit_secret \
  econcert audit verify /var/lib/concert/data/audit.jsonl
```

---

## 4. Secrets Management, Rotation, Custom TLS & FIPS 140-3

- **File-backed secrets (`_FILE`):** Every secret environment variable supports a `*_FILE` sibling (`CONCERT_ADMIT_SECRET_FILE`, `CONCERT_ADMIT_SECRET_PREV_FILE`, `CONCERT_ADMIN_TOKEN_FILE`, `CONCERT_ADMIN_TOKENS_FILE`, `CONCERT_PORTAL_PASS_FILE`, `CONCERT_PORTAL_USERS_FILE`, `CONCERT_POLICY_TOKEN_FILE`, `CONCERT_REDIS_PASSWORD_FILE`, `CONCERT_SMTP_PASS_FILE`, `CONCERT_RESEND_API_KEY_FILE`, `CONCERT_SENDPANDA_API_KEY_FILE`, `CONCERT_STELLAR_FEE_SECRET_FILE`, `CONCERT_HEDERA_FEE_SECRET_FILE`) for Kubernetes Secrets, Docker Secrets, and Vault Agent sidecars.
- **Zero-downtime secret rotation:** Set `CONCERT_ADMIT_SECRET` to the new secret and `CONCERT_ADMIT_SECRET_PREV` to the outgoing secret for one `-admit-ttl` / priority-grant window. Concert validates cookies, signed email unsubscribe links, and AES-256-GCM encrypted `email-secrets.json` under either key and re-encrypts/re-signs under the new key on next write.
- **Enterprise PKI, Portal HTTPS, Companion `:80` Redirect & Native Leaf mTLS:** Use `-tls-cert` / `-tls-key` (main listener) and `-portal-tls-cert` / `-portal-tls-key` (admin portal) for hot-reloading PEM certificates with AEAD-only TLS 1.2+ or `-tls-min-version=1.3` and `-hsts-max-age=31536000`. Add `-tls-http-listen=:80` for ACME HTTP-01 and strict-`Host` HTTP→HTTPS redirects (`301`/`308`). Add `-tls-client-ca` with `-hop-require-mtls=true` on leaf nodes to require verified edge client certificates for `Concert-Hop` claims and `/_room/hop/*` while still allowing direct public browsers on the same port (`tls.VerifyClientCertIfGiven`), or set `-tls-require-client-cert=true` for strict mTLS on every connection.
- **Confined Static Offload & FastCGI Hardening:** `-static-root`, `-static-mounts`, `-fcgi-deny-paths`, `-tls-http-listen`, and `fcgi+unix://` socket paths are locked against live HTTP Portal mutation; `internal/static` and `internal/fcgi` use kernel-enforced `os.Root` containment, fail-closed safe-extension allowlists, dotfile/secret rejection, httpoxy `Proxy` header stripping, underscore request header dropping (matching nginx `underscores_in_headers off`), authentic right-to-left `REMOTE_ADDR` propagation, upload/slowloris body deadlines (`-body-read-idle-timeout`, `-max-upload-time`), and default PHP execution denial on `/wp-content/uploads/*` and `/wp-config.php`.
- **Single-Use Hop Nonces:** `-hop-replay-guard=true` (default) blocks captured `Concert-Hop` header replays via a bounded 256-shard `O(1)` FIFO ring cache (`-hop-replay-max`, default `1,048,576`, range `1024..16777216`, lazily allocated). Saturation increments `concert_leaf_hop_replay_evictions_total` and emits a rate-limited warning; under `-enterprise-hardened=true`, leaves fail closed (`ErrReplaySaturated`, degrading new claims to direct traffic without awarding strikes) rather than evicting unexpired nonces. Set `-hop-require-nonce=true` after rolling upgrades to reject nonceless legacy claims.
- **Upstream mTLS & Custom CA:** Set `-upstream-ca`, `-upstream-client-cert`, and `-upstream-client-key` to enforce mutual TLS to internal origins or leaves.
- **FIPS 140-3:** Build with `make build-fips` (sets `GOFIPS140=v1.0.0` using Go's native FIPS 140-3 cryptographic module).

---

## 5. High Availability, Resilience & Observability

- **Multi-Upstream Load Balancing & Circuit Breaker:** Pass comma-separated URLs to `-upstream`, configure active health checks (`-upstream-health-path=/healthz`, `-upstream-health-interval=10s`), and enable circuit breaking (`-upstream-cb-failures=5`, `-upstream-cb-cooldown=15s`).
- **Kubernetes Readiness & Graceful Drain:** Point `livenessProbe` at `/_room/healthz` and `readinessProbe` at `/_room/readyz` (returns `503` immediately on `SIGTERM` drain or when all upstreams are unhealthy). See `deploy/k8s/deployment.yaml`.
- **Multi-Node Ban Synchronization & Alert Deduplication:** Set `-redis-addr`, `-redis-tls=true`, and `CONCERT_REDIS_PASSWORD_FILE` to replicate bans/unbans in real time via Redis/Valkey Pub/Sub + state hydration and deduplicate shared cluster email alerts (`-email-cluster-dedupe=true`, default; counter `concert_email_cluster_deduped_total`) via non-blocking fail-open `SET NX PX` leases.
- **Prometheus Metrics:** Scrape `/_room/metrics` (with a `viewer` bearer token when `-stats-auth=true`) for gauges, counters, and upstream latency histograms (`concert_upstream_duration_seconds`, `concert_room_cap_draining`, `concert_leaf_hop_replayed_total`, `concert_leaf_hop_replay_evictions_total`, `concert_leaf_hop_mtls_rejected_total`, `concert_leaf_rebench_total`, `concert_fastlane_records_used`, `concert_fastlane_records_max`, `concert_fastlane_unresolved`, `concert_email_cluster_deduped_total`).
- **Structured JSON Logging & Tracing:** Set `-log-format=json` for SIEM-ready access logs carrying `request_id` (`X-Request-ID`) and W3C `trace_id` (`traceparent`).

---

## 6. Privacy (GDPR / CCPA / PCI-DSS / HIPAA)

- **Query Scrubbing:** Enabled by default (`-privacy-scrub-query=true`), redacting tokens, keys, secrets, passwords, emails, SSNs, and card parameters before writing to logs or history. Use `-privacy-strip-query=true` in PCI/HIPAA environments to omit all query strings.
- **IP Anonymization:** Set `-privacy-anonymize-ip=true` to mask non-banned client IPs to `/24` (IPv4) and `/48` (IPv6) in logs and history while preserving exact IPs for active abuse enforcement.
- **Configurable Retention:** Adjust `-history-retention` between `1h` and `720h` (default `72h`).
- **DSAR Export & Erasure (`admin` role):**
  - `GET /_room/privacy/export?client=203.0.113.55`
  - `DELETE /_room/privacy/erase?client=203.0.113.55` (add `&include_bans=true` to also lift an individual ban; also purges matching pending events from `email-queue.json`; all DSAR actions are recorded in `audit.jsonl`)

---

## 7. Administrator Email Delivery, DNS Verification & Scheduled Digests

Off by default (`-email-provider ""`). Managed through the Admin Portal **Email** tab (RBAC `admin` + CSRF + hash-chained audit trail) or flags / `CONCERT_*` environment variables:

- **Providers (`-email-provider smtp|resend|sendpanda`):**
  - **SMTP:** `-email-smtp-host`, `-email-smtp-port` (default `587`), `-email-smtp-tls` (`starttls`, `tls`, or `none`; `none` is rejected when `-enterprise-hardened=true`), `-email-smtp-user`, and password via `CONCERT_SMTP_PASS` (`*_FILE`) or write-only encrypted portal storage.
  - **Resend:** Bearer API key via `CONCERT_RESEND_API_KEY` (`*_FILE`) or encrypted portal vault; optional `-email-resend-url` (default `https://api.resend.com`, HTTPS required under `-enterprise-hardened=true`).
  - **SendPanda (`sendpanda.email`):** Bearer API key via `CONCERT_SENDPANDA_API_KEY` (`*_FILE`) or encrypted portal vault; editable `-email-sendpanda-url` (default `https://api.sendpanda.email/v1`, HTTPS required under `-enterprise-hardened=true`).
- **Encrypted Secret Vault (`email-secrets.json`, `0600`):** Portal-entered SMTP passwords and API keys are never written to `settings.json`, never returned by `GET` APIs, and never logged. They are encrypted with AES-256-GCM using a key derived from `CONCERT_ADMIT_SECRET` (requiring a stable `CONCERT_ADMIT_SECRET`). Environment variables (`CONCERT_*` / `*_FILE`) always take precedence and remain the sole mechanism in `-read-only-settings` GitOps mode.
- **DNS Connectivity & Test Delivery (`POST /api/email/verify`, `POST /api/email/test`):** Checks sender domain MX, SPF, DMARC, optional DKIM selector (`-email-dkim-selector`), recipient domain MX, provider host DNS, and live SMTP/API authentication, plus on-demand test email sending.
- **Coalescing Event Queue & Paced Cadence (`email-queue.json`, `0600`):** Queues toggleable runtime events across six categories (`silence`, `capacity`, `bans`, `fastlane`, `queue`, `security`) configured by `-email-events`, respects `-privacy-anonymize-ip`, and enforces both a rolling hard cap (`-email-cadence-max`, `1..1000`) over the configured window (`-email-cadence-window` + `-email-cadence-unit` `minutes|hours|days`, `15m..30d`) and even pacing (`window / max >= 1m`) — e.g. `1 email every 15 minutes`, `4 emails every 90 minutes`, `1 email every 7 days`, or `333 emails every 28 days`. Failed sends back off exponentially without dropping events or consuming cadence slots.
- **Compliance Headers, Footers & RFC 8058 One-Click Pause:** Every digest and test email includes HTML + plain-text (`multipart/alternative`), `Auto-Submitted: auto-generated`, `Precedence: bulk`, organization name (`-email-org-name`), physical postal address (`-email-postal-address`), Privacy/Terms/Portal links (`-email-privacy-url`, `-email-terms-url`, `-email-portal-url`), and HMAC-SHA256 signed `List-Unsubscribe` / `List-Unsubscribe-Post: List-Unsubscribe=One-Click` links routed to `/_concert/email/unsubscribe` (main listener) and `/email/unsubscribe` (portal). `GET` renders a confirmation button (immune to automated mail link-scanners); `POST` pauses alerts for that recipient and logs `email.unsubscribe` to `audit.jsonl`.
- **Prometheus Metrics:** `concert_email_queued_events`, `concert_email_sent_total`, and `concert_email_errors_total`.

---

## 8. Compliance Control Mapping

| Framework | Key Concert Controls |
| --- | --- |
| **SOC 2 / ISO 27001** | Per-user Argon2id + TOTP MFA / SSO RBAC, hash-chained `audit.jsonl`, `-read-only-settings` GitOps mode, CycloneDX SBOM (`make sbom`), `govulncheck` (`make vulncheck`) |
| **PCI DSS v4.0.1** | TLS 1.2/1.3 AEAD ciphers, HSTS, upstream mTLS, `-privacy-strip-query`, MFA/SSO for admin access, `-stats-auth`, centralized JSON SIEM logs |
| **HIPAA** | Encryption in transit (TLS + upstream mTLS), unique operator identities, audit controls, query stripping to prevent ePHI in URLs, encrypted volume for `-data-dir` |
| **GDPR / CCPA** | `-privacy-scrub-query`, `-privacy-anonymize-ip`, configurable `-history-retention`, DSAR export/erasure APIs, HttpOnly/Secure cookies |
| **FedRAMP / FIPS** | `make build-fips` (`GOFIPS140=v1.0.0`), SELinux enforcing installer (`installer.sh`), distroless non-root container (`Dockerfile`) |
| **OFAC / FinCEN (Fast-Lane)** | Authenticated `policy_url` fail-closed screening, cryptographic payer checks, settlement journal export & reconciliation (see `docs/US_COMPLIANCE.md`) |
