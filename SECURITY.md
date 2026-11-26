# Security Policy

Concert is a security-critical reverse proxy, waiting-room gateway, and non-custodial crypto Fast-Lane / AI agent pass-bidding suite. We take vulnerability reports seriously and appreciate responsible disclosure.

## Supported Versions

| Version | Supported |
|---|---|
| `v0.3.x` (current release series) | Yes |
| `< v0.3.0` | No — upgrade to the latest `v0.3.x` release |

All editions (`concert`, `wpconcert`, `econcert`), companion daemons (`concert-kv`, `concert-cache`, `concert-watchdog`), CLI tools (`bench-concert`, `concert-client`), and official client SDKs under `clients/` are covered under this policy.

## Reporting a Vulnerability

**Do not open a public GitHub issue or pull request for security vulnerabilities.**

Please report suspected vulnerabilities privately via **GitHub Security Advisories** on this repository:

- `https://github.com/andreimerlescu/concert/security/advisories/new`

Include as much detail as possible so we can reproduce and verify the issue quickly:

1. Affected binary, edition build tags (`concert`, `wpconcert`, `econcert`, `concert-kv`, `concert-cache`, `concert-watchdog`, or client SDK) and `VERSION` / commit SHA.
2. Relevant flags, environment variable names (with **secret values redacted**), or `Concertfile` snippet.
3. Step-by-step reproduction or minimal proof of concept.
4. Impact assessment (e.g., auth/RBAC bypass, queue/admission bypass, SSRF, CSP bypass, secret disclosure, DoS, or crypto settlement replay/spoofing).

### Response Targets

- **Initial acknowledgment:** within 48 hours
- **Triage & severity assessment:** within 5 business days
- **Coordinated disclosure:** once a fix is verified and release binaries, FIPS 140-3 builds, CycloneDX 1.5 SBOMs, and `SHA256SUMS.txt` manifests are published

## Security Architecture & Verification Baselines

Production deployments should follow the controls documented in [docs/ENTERPRISE.md](docs/ENTERPRISE.md) and [docs/OPERATIONS.md](docs/OPERATIONS.md):

- **Fail-closed hardened mode:** Enable `-enterprise-hardened` (`CONCERT_HARDENED=true`) in `econcert` to require strong secrets, Portal RBAC/MFA, and persistent hash-chained `audit.jsonl`.
- **File-delivered secrets (`*_FILE`):** Always inject secrets (`CONCERT_ADMIT_SECRET_FILE`, `CONCERT_HOP_SECRET_FILE`, `CONCERT_KV_PASSWORD_FILE`, `CONCERT_CACHE_SECRET_FILE`, `CONCERT_DNS_API_TOKEN_FILE`, etc.) from `0600` files — never CLI arguments or committed configs.
- **Non-custodial crypto settlement:** Fast-Lane and AI Agent Pass Bidding (`XRPL`, `Stellar`, `Hedera`, `Solana`) verify payment authorizations off-chain and never custody user funds or private keys on the server; losing bids are dropped unsettled (`$0` charged).
- **Strict Waiting Room CSP:** `frame-src 'none'` on every layout except `youtube` with a validated 11-character video ID (`frame-src https://www.youtube-nocookie.com`).
- **Verifiable releases:** Verify downloaded release tarballs and binaries against `SHA256SUMS.txt` and inspect the per-binary CycloneDX 1.5 SBOM (`*-sbom.cdx.json`) before deploying. Linux FIPS 140-3 (`GOFIPS140=v1.0.0`) builds are provided for `concert`, `wpconcert`, and `econcert`.
