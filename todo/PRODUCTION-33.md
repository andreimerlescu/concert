# PRODUCTION-33: Concert Production Readiness Scorecard

> **Purpose:** The permanent, deterministic **33-point pass/fail gate** for Concert (`v0.3.0`).
> Every future *"Is Concert production ready?"* audit runs these exact 33 checks—zero guesswork, zero hand-waving.
>
> **Status Legend:**
> - `[x]` **Verified in Repository** — Implemented, tested, and deterministically checkable from source/CI.
> - `[ ]` **Operator Staging Sign-Off Required** — Code/tooling exists in repo, but requires live environment execution or external asset publication before flipping to `[x]`.

---

## Executive Summary Tally

| # | Pillar | Criteria Range | Repo Verified | Operator Sign-Off Pending |
|---|---|---|---|---|
| 1 | Architecture & Blast-Radius Isolation | `#1` – `#5` | 5 / 5 | 0 |
| 2 | Concurrency, Fairness & 100k-Connection Scale | `#6` – `#10` | 4 / 5 | 1 (`#10` live `toktail.app` 100k soak) |
| 3 | Security, Secrets & Supply Chain | `#11` – `#15` | 5 / 5 | 0 |
| 4 | Crypto-Only Commerce & Settlement | `#16` – `#20` | 5 / 5 | 0 |
| 5 | Resilience, Recovery & Multi-Tenant Operations | `#21` – `#25` | 5 / 5 | 0 |
| 6 | Experience, Global Reach & Ecosystem | `#26` – `#29` | 3 / 4 | 1 (`#28` official 3:33 YouTube demo upload) |
| 7 | Observability, Runbooks & Release Discipline | `#30` – `#33` | 4 / 4 | 0 |
| **Total** | **All 7 Pillars** | **`#1` – `#33`** | **31 / 33** | **2 / 33** |

---

## Pillar 1: Architecture & Blast-Radius Isolation (`#1` – `#5`)

| ID | Requirement | Exact Verification Command / Check | Status |
|---|---|---|---|
| **#1** | **Pure-stdlib `concert-kv` daemon:** 64-shard concurrent store, bounded RESP2 protocol, Pub/Sub, CRC32 WAL + atomic `0600` compaction, primary→replica streaming sync, `CQ.*` queue/auction commands, zero external Go dependencies. | `go test -race -count=1 ./internal/kv ./cmd/concert-kv && go test -run '^$' -fuzz FuzzRESP2Parse -fuzztime 5s ./internal/kv` | `[x]` |
| **#2** | **External `concert-cache` daemon:** Standalone micro-cache server & pooled client over Unix (`0600`) or TCP/TLS/mTLS with authenticated `CONCERT_CACHE_SECRET[_FILE]` and active URL/prefix/tag purge. | `go test -race -count=1 ./internal/cache ./cmd/concert-cache && go test -run '^$' -fuzz Fuzz -fuzztime 5s ./internal/cache` | `[x]` |
| **#3** | **Independent `concert-watchdog` supervisor:** Separate process binary supervising Concert liveness, metrics, and restart policy, wired into `installer.sh` (`CONCERT_WATCHDOG=1`). | `go test -race -count=1 ./internal/watchdog ./cmd/concert-watchdog && grep -q 'CONCERT_WATCHDOG' installer.sh` | `[x]` |
| **#4** | **Zero Redis external dependency:** No Redis client libraries in `go.mod` or `go.sum`; shared queue/cluster state runs natively on `concert-kv` (with legacy `CONCERT_REDIS_*` env fallback preserved for smooth migration). | `! grep -i 'redis' go.mod go.sum` | `[x]` |
| **#5** | **Single-host zero-dependency fallback:** `concert`, `wpconcert`, and `econcert` boot cleanly with zero external daemons when `-kv-addr` and `-cache-addr` are unset (built-in in-process store & micro-cache, plus `FailOpen` degraded mode on KV faults). | `go test -race -count=1 -tags "wordpress,enterprise" ./internal/server -run 'TestWave1|TestFrontDoor'` | `[x]` |

---

## Pillar 2: Concurrency, Fairness & 100k-Connection Scale (`#6` – `#10`)

| ID | Requirement | Exact Verification Command / Check | Status |
|---|---|---|---|
| **#6** | **Lemmings host-protection quotas:** Per-IP queue caps enforced for both untrusted clients (`-max-queue-per-ip`) **and** allowlisted IPs (`-allow-max-queue-per-ip` / `CONCERT_ALLOW_MAX_QUEUE_PER_IP`), paired with configurable PoW challenge guardrails (`internal/guard`). | `go test -race -count=1 ./internal/guard && grep -q 'allow-max-queue-per-ip' internal/server/settings.go` | `[x]` |
| **#7** | **Memory RSS & FD pressure shedder:** Deterministic host backpressure (`internal/guard/shedder.go`, `-host-max-mem-mb`, `-host-max-fd-pct`) sheds excess load cleanly before kernel OOM-kill or EMFILE exhaustion. | `go test -race -count=1 ./internal/guard -run 'Test.*Shed'` | `[x]` |
| **#8** | **Waiting-room signal headers:** Every queued waiting-room response emits `X-Concert-Queue: 1`, `X-Concert-Position`, `Retry-After`, and `Cache-Control: no-store` (plus `X-Concert-Status-Url` when non-default); **never** emitted on admitted upstream responses, capacity-breaker 503s, or 403/429 guard rejections. | `go test -race -count=1 ./internal/server -run 'TestWaitingRoomSignalHeaders'` | `[x]` |
| **#9** | **`concert_admit` sliding session continuity & clean clearance:** Active admitted visitors browse without premature re-queuing (bounded per-pass page cap), and expired/re-queued passes receive an explicit `concert_admit=; Max-Age=0` clear cookie alongside `room_ticket`. | `go test -race -count=1 ./internal/server -run 'TestConcertAdmit'` | `[x]` |
| **#10** | **100k-connection mixed human + flood soak verification:** `bench-concert -profile soak-100k` harness passes unit/race verification in repo **and** completes a live staging soak against `toktail.app` with `0` admitted-human re-queues, `0` human upstream 5xx, and human p95 latency within target. | Repo harness: `go test -race -count=1 ./internal/bench ./cmd/bench-concert`<br>Staging sign-off: `bench-concert -profile soak-100k -url https://toktail.app -duration 10m` | `[ ]` |

---

## Pillar 3: Security, Secrets & Supply Chain (`#11` – `#15`)

| ID | Requirement | Exact Verification Command / Check | Status |
|---|---|---|---|
| **#11** | **`S1`–`S10` security posture & redacting `Secret` types:** All sensitive credentials across `kv`, `cache`, `guard`, `acme`, `watchdog`, `notify`, `telemetry`, and `server` use redacting `Secret` wrappers emitting `[REDACTED]` across `fmt`/`json`/`slog`, constant-time comparisons, bounded reads (`R3`), and same-origin SSRF guards (`S9`). | `go test -race -count=1 ./internal/kv ./internal/cache ./internal/guard ./internal/acme ./internal/watchdog ./internal/notify ./internal/telemetry -run 'Test.*Secret\|Test.*Redact'` | `[x]` |
| **#12** | **File-delivered secrets (`*_FILE`) & atomic `0600` state writes:** All runtime secrets support `*_FILE` loading with regular-file/permission/64 KiB checks; persisted state (`waitingroom.json`, WAL compaction, ACME files) uses `CreateTemp` + `Chmod(0600)` + `Sync` + `Close` + `Rename`. | `go test -race -count=1 ./internal/waitingroom ./internal/kv ./internal/acme && grep -rn 'envOrFile\|SecretFromFile' internal/` | `[x]` |
| **#13** | **Strict Waiting Room CSP scoping:** Waiting-room HTML emits `script-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`, `base-uri 'none'`, and `frame-src 'none'` on every layout **except** `layout: youtube` with a validated 11-char ID (`frame-src https://www.youtube-nocookie.com`). | `go test -race -count=1 ./internal/waitingroom -run 'TestContentSecurityPolicy\|TestCSP'` | `[x]` |
| **#14** | **Zero vulnerabilities & zero committed secrets:** `go mod verify`, `govulncheck` across all 3 editions (`concert`, `wpconcert`, `econcert`) and helper binaries report 0 vulnerabilities, and `secret-scan.sh` reports 0 findings across the entire repository. | `go mod verify && make vulncheck && bash /Users/andrei/friends_of/knowledge/agent/skills/secure-code-standards/scripts/secret-scan.sh` | `[x]` |
| **#15** | **FIPS 140-3 builds, CycloneDX 1.5 SBOMs & SHA-256 manifests:** Reproducible Linux builds (`-trimpath -buildvcs=false`), `GOFIPS140=v1.0.0` binaries (`concert-fips`, `wpconcert-fips`, `econcert-fips`), CycloneDX 1.5 SBOMs, and `SHA256SUMS.txt` build cleanly and verify. | `make build-fips sbom checksums && (cd bin && shasum -a 256 -c SHA256SUMS.txt)` | `[x]` |

---

## Pillar 4: Crypto-Only Commerce & Settlement (`#16` – `#20`)

| ID | Requirement | Exact Verification Command / Check | Status |
|---|---|---|---|
| **#16** | **4-chain crypto-only settlement (`XRPL`, `Stellar`, `Hedera`, `Solana`):** Fast-Lane payments, chain gateway, and agent bidding support all 4 ledgers natively with **zero** fiat/Stripe SDKs, endpoints, or billing dependencies. | `go test -race -count=1 -tags "wordpress,enterprise" ./internal/chain ./internal/fastlane ./internal/gateway ./internal/x402 && ! grep -rni 'stripe' go.mod cmd/ internal/` | `[x]` |
| **#17** | **Replay-window enforcement (`since_unix`):** Direct payment challenges and gateway verifiers enforce `since_unix` timestamps so historical on-chain transactions cannot be replayed for free passes. | `grep -rn 'since_unix' internal/fastlane/ internal/gateway/ && go test -race -count=1 ./internal/fastlane ./internal/gateway` | `[x]` |
| **#18** | **Non-custodial AI Agent Pass Bidding (losers pay `$0`):** Sealed-bid and instant-buy pass auctions (`/_concert/bids`, `cmd/concert-client -bid -max-bid`) use exact integer micro-USD arithmetic (zero `float64`), run off-chain `/verify` at submission, and invoke on-chain `/settle` **only** for winning bids while losers pay `$0` and seamlessly continue waiting. | `go test -race -count=5 ./internal/bidding ./cmd/concert-client && go test -race -count=1 -tags "wordpress,enterprise" ./internal/server -run 'TestWave2.*Bid\|TestBidding'` | `[x]` |
| **#19** | **NFT VIP gating & stream-preserving Fast-Lane drawer:** Eligible NFT holders unlock zero-payment VIP bypass; waiting visitors can access both crypto Fast-Lane offers and NFT VIP verification inside `#fastlane-drawer` without leaving the waiting room or YouTube stream. | `grep -q 'id="fastlane-drawer"' internal/server/web/waiting.html && go test -race -count=1 ./internal/fastlane ./internal/server -run 'TestFastLane\|TestNFT'` | `[x]` |
| **#20** | **Zero license keys (100% Apache-2.0 open source):** All editions (`concert`, `wpconcert`, `econcert`) operate with zero license-key gates, zero phone-home license checks, and uniform Apache-2.0 licensing. | `head -n 5 LICENSE && ! grep -rni 'license_key\|licenseKey\|CONCERT_LICENSE' cmd/ internal/` | `[x]` |

---

## Pillar 5: Resilience, Recovery & Multi-Tenant Operations (`#21` – `#25`)

| ID | Requirement | Exact Verification Command / Check | Status |
|---|---|---|---|
| **#21** | **Watchdog origin-vs-Concert fault differentiation:** `concert-watchdog` distinguishes upstream origin outages from local Concert stalls/hangs so healthy Concert instances are never restart-looped while protecting a degraded origin. | `go test -race -count=1 ./internal/watchdog -run 'Test.*Origin\|Test.*Policy\|Test.*Supervisor'` | `[x]` |
| **#22** | **Pure-stdlib ACME DNS-01 wildcard TLS:** Automated `*.example.com` certificate issuance and renewal via Cloudflare and generic webhook DNS-01 providers, with encrypted `concert-kv` certificate bundle sync (`CONCERT_ACME_KV_SECRET`). | `go test -race -count=1 ./internal/acme` | `[x]` |
| **#23** | **Multi-tenant path routing, headers & redirects:** Longest-prefix `route {}` blocks in `Concertfile` with dedicated upstream pools, `strip_prefix`, per-route `cap`/`rate_limit`, `bypass`, `agent_bidding`, validated `301`/`302`/`307`/`308` redirects, and safe `header` (`set`/`add`/`remove`) rules that never weaken security headers on waiting-room/error responses. | `go test -race -count=1 ./internal/configfile && go test -race -count=1 -tags "wordpress,enterprise" ./internal/server -run 'TestWave2.*Route\|TestRoute'` | `[x]` |
| **#24** | **Scheduled CSPRNG drops:** Per-site drop lifecycle (`idle` → `lobby` → `open` → `paused` → `sold_out` returning `410 Gone`) with cryptographically random lobby shuffling at `drop_open_at`, `/_room/drop` + Portal `/api/drop` operator controls, and `/queue/status` countdown enrichment. | `go test -race -count=5 ./internal/drop && go test -race -count=1 -tags "wordpress,enterprise" ./internal/server -run 'TestWave2.*Drop\|TestDrop'` | `[x]` |
| **#25** | **Active cache purge API:** Authenticated `POST /_room/cache/purge` and Admin Portal `POST /api/cache/purge` (RBAC `roleOperator` + CSRF + audit log) supporting URL, prefix, tag, and full invalidation across in-process and external `concert-cache`. | `grep -q '/_room/cache/purge' internal/server/generation.go && grep -q '/cache/purge' internal/server/portal.go && go test -race -count=1 ./internal/microcache ./internal/cache` | `[x]` |

---

## Pillar 6: Experience, Global Reach & Ecosystem (`#26` – `#29`)

| ID | Requirement | Exact Verification Command / Check | Status |
|---|---|---|---|
| **#26** | **Waiting Room Studio (5 layouts & 10 WCAG themes + `system`):** All 5 layouts (`default`, `youtube`, `drop-countdown`, `minimal-brand`, `split-stage`) and all 10 Portal WCAG palettes (including `high-contrast` WCAG AAA) plus `system` auto-theme render cleanly with zero external CDNs. | `go test -race -count=5 ./internal/waitingroom && node --check internal/server/web/waiting.js && node --check internal/server/templates/js/portal.js` | `[x]` |
| **#27** | **19 embedded locales including 4 RTL scripts:** Complete embedded translation catalogs for 19 locales (`en`, `es`, `es-MX`, `fr`, `fr-CA`, `ro`, `ru`, `tr`, `de`, `it`, `ja`, `zh-CN`, `hi`, `pl`, `sr`, plus RTL `ar`, `he`, `fa`, `arc` Syriac/Aramaic) with `dir="rtl"`, BCP-47 negotiation, and CSS logical properties. | `go test -race -count=5 ./internal/i18n && grep -q '"arc"' internal/i18n/i18n.go` | `[x]` |
| **#28** | **Live EWMA ETA, operator broadcasts & default YouTube demo video:** Live EWMA wait estimation (`eta_seconds`, `admissions_per_minute`, `eta_confidence`) and `<=280`-rune live operator broadcasts are verified in repo; **final operator sign-off requires uploading the `3:33` video (`todo/THREE-MINUTE-STORY.md`) to YouTube and configuring its validated 11-char ID as the default `youtube` showcase.** | Repo check: `go test -race -count=1 ./internal/waitingroom ./internal/server -run 'TestWaitingRoom\|TestWave2'`<br>Operator sign-off: Set validated 11-char ID in Admin Portal **Waiting Room** tab (`layout: youtube`) and verify `frame-src https://www.youtube-nocookie.com` | `[ ]` |
| **#29** | **6 client SDKs & `.gitattributes` linguist hygiene:** Zero-bloat client libraries under `clients/{wordpress,php,go,node,python,ruby}` (each with `{docs/,src/,README.md,CHANGELIST.md,LICENSE}`) plus root `.gitattributes` marking `clients/** linguist-vendored` and `docs/**`/`todo/** linguist-documentation`. | `test -f .gitattributes && ls -d clients/wordpress clients/php clients/go clients/node clients/python clients/ruby && (cd clients/go/src && go test -race ./...) && node --test clients/node/src/tests/* && PYTHONPATH=clients/python/src python3 -m unittest discover -s clients/python/src/tests && ruby -Iclients/ruby/src/lib clients/ruby/src/test/concert_client_test.rb` | `[x]` |

---

## Pillar 7: Observability, Runbooks & Release Discipline (`#30` – `#33`)

| ID | Requirement | Exact Verification Command / Check | Status |
|---|---|---|---|
| **#30** | **ChatOps incident webhooks:** Pure-stdlib `internal/notify` dispatches structured alerts (queue depth, circuit breaker, watchdog restarts, shedder trips) to Slack, Discord, Microsoft Teams, PagerDuty Events v2, and HMAC-signed generic webhooks with `*_FILE` secret redaction and bounded retries. | `go test -race -count=5 ./internal/notify` | `[x]` |
| **#31** | **Pure-stdlib OTLP tracing + Grafana & Prometheus rules:** W3C TraceContext + OTLP/HTTP trace exporter (`internal/telemetry`, zero external OTel SDK bloat), valid `deploy/observability/grafana-dashboard.json`, and `deploy/observability/prometheus-rules.yaml` alert definitions. | `go test -race -count=5 ./internal/telemetry && python3 -m json.tool deploy/observability/grafana-dashboard.json > /dev/null && test -s deploy/observability/prometheus-rules.yaml` | `[x]` |
| **#32** | **6 human + AI-agent followable deployment tutorials:** Complete runbooks under `docs/tutorials/` (`01-single-host-vps.md` through `06-crypto-api-agent-bidding.md` + `README.md` index) with topology diagrams, `*_FILE` secret steps, verification commands, and rollback playbooks. | `ls docs/tutorials/README.md docs/tutorials/01-*.md docs/tutorials/02-*.md docs/tutorials/03-*.md docs/tutorials/04-*.md docs/tutorials/05-*.md docs/tutorials/06-*.md` | `[x]` |
| **#33** | **Zero root `.go` drift, clean race suite & reproducible `make dist`:** Root directory contains only `version.go`; `gofmt`, `make lint`, `make test-race`, and `make dist` succeed cleanly across all 8 binaries + 3 FIPS builds with verified `dist/SHA256SUMS.txt`. | `test -z "$(find . -maxdepth 1 -name '*.go' ! -name version.go)" && make lint && make test-race && make dist && (cd dist && shasum -a 256 -c SHA256SUMS.txt)` | `[x]` |

---

## Operator Release Sign-Off Protocol

Before tagging a production release as **33 / 33 GREEN**:

1. Execute the automated repository gate (`#1`–`#9`, `#11`–`#27`, `#29`–`#33`) on the exact release commit SHA.
2. Run **Item `#10`** (`bench-concert -profile soak-100k`) against the live `toktail.app` staging environment and archive the JSON report (verifying `requeue_after_admit == 0`, `human_upstream_5xx == 0`, and `human_p95 <= 2s`).
3. Complete **Item `#28`** by generating and uploading the `3:33` Waiting Room video (`todo/THREE-MINUTE-STORY.md`), confirming `youtube-nocookie.com` playback on desktop/mobile/RTL locales, and recording the official 11-character YouTube ID in the release notes.
4. Flip `#10` and `#28` from `[ ]` to `[x]` only after both staging artifacts are attached to the release ticket.
