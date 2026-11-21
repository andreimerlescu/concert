# Concert Enterprise Hardening & Compliance Guide

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

For immutable / GitOps deployments, also enable `-read-only-settings` (`CONCERT_READ_ONLY_SETTINGS=true`) so neither the portal nor `/_room/cap` can mutate `settings.json` at runtime.

---

## 2. Identity, RBAC, MFA & SSO

### Roles

| Role | Permissions |
| --- | --- |
| `viewer` | Read-only overview, queue, bans, history, settings, `/_room/stats`, `/_room/metrics` (internal `upstream` URL is hidden when `-stats-auth=true`) |
| `operator` | All `viewer` permissions + queue promote/kick (`POST /_room/promote`), capacity updates (`POST /_room/cap`), temporary single-IP bans, lifting bans |
| `admin` | All `operator` permissions + permanent bans, CIDR range bans, live settings changes, GDPR/CCPA DSAR export & erasure |

### Multi-User Portal Accounts with Argon2id + TOTP MFA

Generate an OWASP Argon2id password hash:

```sh
concert hash-password "your-strong-passphrase"
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
  concert audit verify /var/lib/concert/data/audit.jsonl
```

---

## 4. Secrets Management, Rotation, Custom TLS & FIPS 140-3

- **File-backed secrets (`_FILE`):** Every secret environment variable supports a `*_FILE` sibling (`CONCERT_ADMIT_SECRET_FILE`, `CONCERT_ADMIT_SECRET_PREV_FILE`, `CONCERT_ADMIN_TOKEN_FILE`, `CONCERT_ADMIN_TOKENS_FILE`, `CONCERT_PORTAL_PASS_FILE`, `CONCERT_PORTAL_USERS_FILE`, `CONCERT_POLICY_TOKEN_FILE`, `CONCERT_REDIS_PASSWORD_FILE`, `CONCERT_STELLAR_FEE_SECRET_FILE`, `CONCERT_HEDERA_FEE_SECRET_FILE`) for Kubernetes Secrets, Docker Secrets, and Vault Agent sidecars.
- **Zero-downtime secret rotation:** Set `CONCERT_ADMIT_SECRET` to the new secret and `CONCERT_ADMIT_SECRET_PREV` to the outgoing secret for one `-admit-ttl` / priority-grant window. Concert validates cookies signed by either key and automatically re-signs them under the new key.
- **Enterprise PKI & Portal HTTPS:** Use `-tls-cert` / `-tls-key` (main listener) and `-portal-tls-cert` / `-portal-tls-key` (admin portal) for hot-reloading PEM certificates with AEAD-only TLS 1.2+ or `-tls-min-version=1.3` and `-hsts-max-age=31536000`.
- **Upstream mTLS & Custom CA:** Set `-upstream-ca`, `-upstream-client-cert`, and `-upstream-client-key` to enforce mutual TLS to internal origins.
- **FIPS 140-3:** Build with `make build-fips` (sets `GOFIPS140=v1.0.0` using Go's native FIPS 140-3 cryptographic module).

---

## 5. High Availability, Resilience & Observability

- **Multi-Upstream Load Balancing & Circuit Breaker:** Pass comma-separated URLs to `-upstream`, configure active health checks (`-upstream-health-path=/healthz`, `-upstream-health-interval=10s`), and enable circuit breaking (`-upstream-cb-failures=5`, `-upstream-cb-cooldown=15s`).
- **Kubernetes Readiness & Graceful Drain:** Point `livenessProbe` at `/_room/healthz` and `readinessProbe` at `/_room/readyz` (returns `503` immediately on `SIGTERM` drain or when all upstreams are unhealthy). See `deploy/k8s/deployment.yaml`.
- **Multi-Node Ban Synchronization:** Set `-redis-addr`, `-redis-tls=true`, and `CONCERT_REDIS_PASSWORD_FILE` to replicate bans and unbans across Concert instances in real time via Redis/Valkey Pub/Sub + state hydration (fails open gracefully if Redis is unreachable).
- **Prometheus Metrics:** Scrape `/_room/metrics` (with a `viewer` bearer token when `-stats-auth=true`) for gauges, counters, and upstream latency histograms (`concert_upstream_duration_seconds`).
- **Structured JSON Logging & Tracing:** Set `-log-format=json` for SIEM-ready access logs carrying `request_id` (`X-Request-ID`) and W3C `trace_id` (`traceparent`).

---

## 6. Privacy (GDPR / CCPA / PCI-DSS / HIPAA)

- **Query Scrubbing:** Enabled by default (`-privacy-scrub-query=true`), redacting tokens, keys, secrets, passwords, emails, SSNs, and card parameters before writing to logs or history. Use `-privacy-strip-query=true` in PCI/HIPAA environments to omit all query strings.
- **IP Anonymization:** Set `-privacy-anonymize-ip=true` to mask non-banned client IPs to `/24` (IPv4) and `/48` (IPv6) in logs and history while preserving exact IPs for active abuse enforcement.
- **Configurable Retention:** Adjust `-history-retention` between `1h` and `720h` (default `72h`).
- **DSAR Export & Erasure (`admin` role):**
  - `GET /_room/privacy/export?client=203.0.113.55`
  - `DELETE /_room/privacy/erase?client=203.0.113.55` (add `&include_bans=true` to also lift an individual ban; all DSAR actions are recorded in `audit.jsonl`)

---

## 7. Compliance Control Mapping

| Framework | Key Concert Controls |
| --- | --- |
| **SOC 2 / ISO 27001** | Per-user Argon2id + TOTP MFA / SSO RBAC, hash-chained `audit.jsonl`, `-read-only-settings` GitOps mode, CycloneDX SBOM (`make sbom`), CI `govulncheck` |
| **PCI DSS v4.0.1** | TLS 1.2/1.3 AEAD ciphers, HSTS, upstream mTLS, `-privacy-strip-query`, MFA/SSO for admin access, `-stats-auth`, centralized JSON SIEM logs |
| **HIPAA** | Encryption in transit (TLS + upstream mTLS), unique operator identities, audit controls, query stripping to prevent ePHI in URLs, encrypted volume for `-data-dir` |
| **GDPR / CCPA** | `-privacy-scrub-query`, `-privacy-anonymize-ip`, configurable `-history-retention`, DSAR export/erasure APIs, HttpOnly/Secure cookies |
| **FedRAMP / FIPS** | `make build-fips` (`GOFIPS140=v1.0.0`), SELinux enforcing installer (`installer.sh`), distroless non-root container (`Dockerfile`) |
| **OFAC / FinCEN (Fast-Lane)** | Authenticated `policy_url` fail-closed screening, cryptographic payer checks, settlement journal export & reconciliation (see `docs/US_COMPLIANCE.md`) |
