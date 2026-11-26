# Concert Deployment Tutorials

Six production deployment tutorials designed for both **senior infrastructure engineers** and **autonomous deployment agents**. Every tutorial is self-contained, copy-pasteable, and idempotent: it includes a topology diagram, prerequisites, `*_FILE` secret provisioning (zero hardcoded secrets), complete `Concertfile` / systemd / Kubernetes manifests, explicit verification commands with expected outputs, and rollback procedures.

> **100% Open-Source & Crypto-Only:** Every binary in the Concert Suite (`concert`, `wpconcert`, `econcert`, `concert-kv`, `concert-cache`, `concert-watchdog`, `bench-concert`, `concert-client`) is licensed under **Apache-2.0** with **zero license keys**. Fast-Lane payments and AI Agent Pass Bidding are **100% non-custodial crypto-only** across **XRPL**, **Stellar**, **Hedera**, and **Solana**.

---

## Choose Your Deployment Guide

| # | Tutorial | Binaries Used | Best For | Key Capabilities Covered |
| --- | --- | --- | --- | --- |
| **01** | [Single-Host Linux VPS + Watchdog](01-single-host-vps.md) | `concert`, `concert-watchdog` | Protecting a single origin on RHEL/Rocky/Alma/Fedora or Debian/Ubuntu | `installer.sh` with `CONCERT_WATCHDOG=1`, ACME HTTPS + HTTP/3, systemd + SELinux, host-protection guardrails (`-max-queue-per-ip`, `-allow-max-queue-per-ip`, `-host-max-mem-mb`, `-challenge-mode pow`) |
| **02** | [WordPress & WooCommerce Stack](02-wordpress-woocommerce-stack.md) | `wpconcert`, `concert-cache`, `concert-watchdog` | Replacing Nginx/Caddy/Apache in front of PHP-FPM for WordPress & WooCommerce | `wpconcert init`/`doctor`, `preset wordpress`, `fcgi+unix://`, external `concert-cache` daemon (`-cache-addr`), [`clients/wordpress`](../../clients/wordpress/) plugin auto-priority & cache purge |
| **03** | [High-Traffic 100k-Connection Edge/Leaf Mesh](03-high-traffic-100k-mesh.md) | `econcert`, `concert-kv`, `concert-cache`, `concert-watchdog`, `bench-concert` | Multi-node launches, viral drops, and 100k-connection flood resilience | L4 LB + Multi-Edge + Leaf `econcert` (`Concert-Hop` mTLS + nonces), `concert-kv` primary/replica HA (`-kv-shared-queue`), `concert-cache`, `bench-concert -profile soak-100k -mix-real-and-flood` |
| **04** | [Kubernetes Production Cluster](04-kubernetes-production.md) | `econcert`, `concert-kv` | Cloud-native GitOps clusters with full observability and alerting | `StatefulSet` + per-pod PVCs (`audit.jsonl`, `waitingroom.json`), `concert-kv` HA, [`prometheus-rules.yaml`](../../deploy/observability/prometheus-rules.yaml), [`grafana-dashboard.json`](../../deploy/observability/grafana-dashboard.json), pure-stdlib OTLP tracing, ChatOps (`internal/notify`) |
| **05** | [Wildcard TLS (DNS-01) & Multi-Tenant Drops](05-wildcard-private-dns01.md) | `econcert`, `concert-kv` | Multi-tenant SaaS, private origins without port 80, and scheduled product drops | Pure-stdlib ACME DNS-01 (`*.example.com`, Cloudflare or webhook) + AES-256-GCM `concert-kv` cert sync, path `route {}` blocks, `header` & `redirect` rules, scheduled drops (`drop_lobby_at`/`drop_open_at`) |
| **06** | [Crypto API Routing, Agent Pass Bidding & Studio](06-crypto-api-agent-bidding.md) | `econcert`, `concert-client` | High-traffic APIs, AI shopping/trading agents, and global branded launches | Path-routed APIs, 4-chain (`XRPL`, `Stellar`, `Hedera`, `Solana`) Fast-Lane & non-custodial AI Agent Pass Bidding (`/_concert/bids`, `concert-client --bid --max-bid`), [`clients/{go,node,python}`](../../clients/), Waiting Room Studio (`youtube` layout + 19 locales incl. RTL) |

---

## Execution Conventions (Human & AI-Agent Friendly)

1. **Secrets always live in `0600` (or Kubernetes `0400`) files referenced by `*_FILE` environment variables.** Never pass secrets on the command line or commit them into `Concertfile` / Git manifests.
2. **Every command block uses explicit environment variables** at the top of the tutorial (`DOMAIN`, `ORIGIN`, `ADMIN_EMAIL`, etc.) so both engineers and deployment agents can parameterize the run cleanly.
3. **Every deployment ends with deterministic checks** (`/_room/healthz`, `/_room/readyz`, `/_room/metrics`, `X-Concert-Queue`, `concert_admit`, and `audit verify`) plus a documented rollback procedure.
4. **Production readiness sign-off:** After completing your tutorial, validate your deployment against the 33-point [Production Readiness Scorecard](../../todo/PRODUCTION-33.md) and the [Operations & Queue Recovery Runbook](../OPERATIONS.md).

---

## Related Documentation

- [Main README](../../README.md) — Suite overview, configuration flags, and architecture
- [Operations & Queue Recovery Runbook](../OPERATIONS.md) — Production baselines, `lemmings` testing, live queue recovery, Prometheus alerting
- [Enterprise Hardening & Compliance Guide](../ENTERPRISE.md) — `-enterprise-hardened`, RBAC/MFA/SSO, hash-chained audit logs, FIPS 140-3, GDPR/CCPA
- [WordPress Direct FastCGI Guide](../WORDPRESS.md) — Deep dive into `wpconcert` + PHP-FPM
- [Edge & Leaf Topology Guide](../TOPOLOGY.md) — Two-tier `Concert-Hop` protocol and leaf benchmarking
- [Crypto Fast-Lane Reference](../FASTLANE.md) — XRPL, Stellar, Hedera, and Solana payment & NFT/token gating
- [Client SDKs](../../clients/) — Official integrations for WordPress, PHP, Go, Node.js/TypeScript, Python, and Ruby
