# v0.2.0 cleanup

- **Stray Go files removed from the repository root.** Source update 003 carried fifteen `package main` files at the root beside the root `concert` package, so `go build ./...` failed with "found packages concert and main". Fourteen were pre-v0.2.0 copies of what is now `internal/server` (byte-identical to the 002 sources). `mesh.go` and `mesh_test.go` were an earlier draft of the edge and leaf tiers that never compiled; v0.2.0's `internal/hop` and `internal/server/topology.go` implement the feature. The root now holds only `version.go`.
- **No GitHub workflows.** The project has none and keeps none: `.github/` is ignored, and the docs no longer mention CI.
- `.gitignore` also excludes macOS `._*` metadata files.

# v0.2.0: edge and leaf tiers, capacity benchmark

## Behaviour changes

- **The source moved.** The server is `internal/server` and the binary is built from `./cmd/concert`: `go install github.com/andreimerlescu/concert/cmd/concert@latest`. `make` and the Dockerfile build the new paths. The embedded templates, web pages and examples moved with the code to `internal/server/`. `VERSION` stays at the root and is embedded by the root `concert` package.
- **Accept-Encoding passes through.** Concert's upstream transport no longer asks the origin for gzip on the browser's behalf and unzips it in the proxy. Before, a browser that did not ask for gzip still got the right bytes, but without `Content-Length` (no download progress), and Concert spent CPU decompressing. Browsers that accept gzip get the origin's encoding unchanged, as before.
- **Bodyless requests are retried on another upstream** (`-upstream-retries`, default 1) when the first refused the connection. This applies only with several upstreams and only to requests without a body; a request with a body is never re-sent.

## New, off by default

- **Edge and leaf tiers (`-role edge|leaf`).** One site served by several hosts runs an edge Concert (waiting room, fast lane, cookies, bans) in front of a leaf Concert per host, with or without haproxy between them. The edge signs a `Concert-Hop` claim (HMAC-SHA256 under `CONCERT_HOP_SECRET`, bound to method, URI, time and the client the edge resolved) into each request it admitted. A leaf that verifies it, from `-hop-peers` only, serves it in its own lane:
  - no room, pass, fast lane or per-visitor pool, about 1.3 µs of verification;
  - a slot in the host gate, where edge traffic comes before direct traffic, and paid or lane-ranked edge traffic first;
  - no cookies, and the application's `Concert-Priority` passed back for the edge to grant.

  Direct traffic to a leaf gets a full, ordinary Concert, including its own fast lane if configured. See [TOPOLOGY.md](TOPOLOGY.md).
- **Backpressure and redispatch.** A full leaf answers `503` with `Concert-Backpressure: full` before anything reaches its application. An edge balancing the leaves itself retries a bodyless request on another leaf, routes by each leaf's free slots, and briefly avoids a leaf that pushed back.
- **Capacity from the leaves (`-hop-auto-cap`).** An edge polls every leaf (`-hop-poll`) and sizes its room to `min(-cap, Σ healthy shares − priority lane)`. Drops apply at once and rises after two agreeing rounds. A silent leaf fades out over 3 to 15 polls. The room is never shrunk below what it has in flight. `/_room/readyz` answers 503 until a leaf has reported.
- **Bans follow the edge.** The edge pushes its full ban list to every leaf whose applied version differs, at once on a new ban. Leaves mirror it, lift what the edge lifts, keep their own bans, and ignore snapshots older than the last applied.
- **Capacity benchmark.** `bench-concert` (or `concert bench`) crawls an application with lemmings to find the largest concurrency with a page p95 under `-p95` and no load-induced failures. Lemmings are browser sessions that follow links up to 14 deep, visit each page at most 14 times per stage, and load every file type a shop serves, checking byte ranges on audio and video. The run doubles, then bisects. It writes a JSON report that explains the first failure second by second, by URL and by file type, and `capacity.json` for a leaf. A leaf with `-bench-on-start` measures its application on first start, before listening.
- **Silence reports.** A leaf records the load it carried when its application stopped answering, to the log, `silence.jsonl` and its state, and stops counting toward the edge's capacity until the application recovers.
- **Metrics.** `/_room/stats` gains `role`, `node` and an `edge` or `leaf` section; `/_room/metrics` gains `concert_node_info`, `concert_edge_*` and `concert_leaf_*`.

## Fixes found by the new tests

- The edge counted a leaf's backpressure only when it reached the browser, missing every refusal it retried successfully.
- Two control rounds overlapping could store an older leaf report over a newer one, or deliver an older ban snapshot after a newer one. Rounds are serialized, and both sides keep only the newest.

# v0.0.9: room v1.5.0

## Behaviour changes

- **Go 1.27.3 is required to build.** room v1.5.0 declares `go 1.27.3`, and a module cannot declare a lower Go version than its dependencies, so Concert's `go.mod` moves from 1.26.1 to 1.27.3.
- **The line is ordered by rank, by default.** Visitors the origin ranks below `-priority-lane-rank` (`member`, `prospect`) used to wait in arrival order. They are now placed ahead of every lower rank, in arrival order within a rank, through room's `SetTicketRank`: a `member` who arrives after three guests waits ahead of them. `priority_placed_total` counts the moves. Operators who depend on strict arrival order set `-priority-order-line=false` (`CONCERT_PRIORITY_ORDER_LINE`); the portal's Queue tab then shows no ranks, because the rank now lives on room's ticket instead of a Concert-side map.
- **`/queue/status/{id}` is a new reserved path.** room now serves a keyed ticket's public place there. `-bypass`, `-assets`, `-asset-public`, `-stream-paths` and `-ban-paths` entries under `/queue/status/` are refused at startup with the usual "reserved by concert" error, because gin would panic on the route conflict. Successful views stay out of the access log and the history, like `/queue/status`.

## New, off by default

- **AI agents can wait in line (`-agent-queue`).** With wallet access configured, a request carrying a valid `Concert-Session` header is identified to room by its session (room's keyed tickets): it keeps one place across retries and renewals, gets no cookies, and earns no churn strikes. One client address (IPv6: its /64) may hold `-agent-places` (default 4) such places; past that it gets 429 and a strike (`strikeAgentPlaces`, weight 1). Bans drop an address's agent places with its other tickets. The portal's Queue tab marks them **agent** with the first 8 characters of the session ID. Browsers carry the `concert_fastlane` cookie, not the header, and are unaffected.
- **A queued agent is offered the fast lane.** A waiting agent gets Concert's API contract, `429` with `Retry-After: -retry-after` (not room's keyed default of `503` and `Retry-After: 3`), with its `position`, the `queue_depth`, an absolute `status_url` (`/queue/status/{id}` under the fast lane's `origin`) a person can watch, and, when payment offers are configured, a `fast_lane` object and a `Link: <…/_concert/payment>; rel="payment"` header. Paying stays an explicit act subject to the usual policy screening. Cookie API clients and browsers get exactly the responses they got before, and the queue-depth breaker still answers `503` "waiting room is full".

- **`concert-client --wait PATH` waits in line.** It renews the saved session, then requests `PATH` with that `Concert-Session` until Concert stops answering `queued`, printing the position and `status_url` and sleeping for `Retry-After` (bounded to 1s–1m, `CONCERT_CLIENT_MAX_WAIT` overall, default 1h; Ctrl-C stops it). It needs no wallet keys and never pays: it reports a fast-lane offer once, and paying stays the explicit `concert-client` command with its amount and recipient checks. The state file is locked only while renewing, so that command can pay with the same session while `--wait` runs.

## Portal

- **A theme picker replaces the light/dark toggle.** The palette button in the portal's top bar offers graphicle.dev's ten themes: Paper, Solarized Light, GitHub Light and High contrast (light), and Synthwave '84, Solarized Dark, Nord, Dracula, Gruvbox Dark and GitHub Dark (dark), plus Match system (Paper or Synthwave '84, following the OS setting; the default). The choice is kept in the browser's `localStorage` (`concert.portal.theme`), follows across open tabs, and is applied from `<head>` by `js/theme.js` so pages no longer flash the default theme. A saved `dark` becomes Synthwave '84 and a saved `light` becomes GitHub Light, the nearest matches to the old two. `css/portal-themes.css` replaces `css/portal-dark.css`. Coloured history and ban-log rows are now tints of the page in every theme, and the overview's capacity bars show their green, amber and red states, which the old gradient covered.

## Fixes

- **Shutdown no longer races room's reaper.** `Close` stops the waiting room before it saves the queue. room v1.5.0's `Stop` waits for its reaper to exit, so no reaper pass can remove a ticket while the line is being written.

# Source update: v0.1.0

## Admission and payment

- Added `internal/fastlane` for x402 v2 discovery, signed sessions, CSRF/origin validation, policy decisions, NFT challenges and persistent receipt recovery.
- Connected eligible requests to the existing bounded priority lane and customer-rank metrics. Full paid lanes return a retriable error without sending the POST upstream or charging again.
- Added a chain gateway built into Concert (`internal/gateway`) implementing the official XRP/XLM/HBAR x402 `exact` schemes and the documented native SOL extension, plus chain-specific NFT verification.
- Added durable gateway settlement caching, an explicit reconciliation command (`concert reconcile`), a reference automated client for all four chains (`concert-client`), and exact-unit accounting exports.
- Stripped payment credentials before upstream forwarding and suppressed request-header dumps during panic recovery.

## Experience

- Replaced the default waiting page with a responsive synthwave queue experience, live FIFO status and optional wallet access.
- Restyled the portal around #660099 and #116699, retained its existing controls, and added an authenticated fast-lane status tab.
- Added a consent-based payment/ownership page, Wallet Standard Solana support, adapter hooks and signed-payload recovery after interruption.
- Preserved custom waiting templates and the legacy skip URL. Restored local Bootstrap assets and icon fonts from their upstream packages.

## Operations and review

- Added disabled test-network examples, explicit production policy requirements, deployment/recovery instructions, a U.S. operator guide, third-party notices and a validation report.
- Added 15 Go tests with the archive. Existing Go tests continue to pass.
- No network was funded, no mainnet transaction was sent, and no service was deployed. Read `FASTLANE.md` and `VALIDATION.md` for compatibility and remaining production gates.

## Integration review corrections

The update was integrated into this repository selectively: the original banner, vendored assets (`animate.css`, `mousetrap`, the WOFF icon font), ignore rules and `make all` targets were kept. An independent review then corrected the following.

Payments and settlement:

- **Hedera: every settlement after the first failed.** The SDK's submit helper closes its client after each submission, but the gateway shared one client, so later HBAR payments ran on a closed client and ended as unknown receipts needing reconciliation. Each submission now gets its own client.
- **Hedera: sponsor fee exposure was unbounded.** A payer chose the `maxTransactionFee` the sponsor signs for. Payloads above `max_fee_tinybars` (default 1 HBAR, what the official client sets) are refused.
- **Native SOL: a transfer already on chain could be claimed by anyone for 60 seconds.** Signed transfers are public once broadcast; accepting a recent finalized one as new evidence let an observer redeem another payer's transfer. Only transactions unknown to the network are accepted, and settlement of a journaled one polls for finality instead of depending on a WebSocket subscription.
- **Native SOL: trailing bytes gave one signature a second payload fingerprint.** Encodings must now be canonical.
- **XRPL: the endpoint's network was never checked.** Mainnet, Testnet and Devnet transactions carry no `NetworkID`, so a mis-pointed endpoint could settle a test offer on another network. Payments, NFT proofs and reconciliation now check `server_info`.
- **A closed tab turned a settling payment into an unknown receipt.** Settlement was cancelled with the visitor's request and bounded by a fixed 45-second timeout. It is now detached from the connection and allowed `maxTimeoutSeconds` plus 90 seconds.
- **Settlements were serialized across all chains.** One slow chain delayed every payment; queues are now per network.
- **The gateway re-verified settled authorizations as valid.** It now refuses them, so a lost Concert journal cannot turn one settled payment into a new pass while the gateway journal survives.

Sessions, NFT access and the proxy:

- **A pass could outlive its session.** Sessions expired 24 hours after creation regardless of a pass bought late in that window, and could not be renewed without losing their receipts. Session IDs now derive from the random nonce, `POST /_concert/session` renews expiry under the same ID, and wallet operations ask for renewal when less than two hours remain.
- **NFT token rules were not enforced end to end.** A requested token ID was not compared with the one proved, Stellar silently ignored token IDs its collection-balance check cannot verify, and Solana rules without a mint failed only after signing. All three are now checked.
- **Wallet endpoints had no per-client limit.** Free sessions could fill the challenge table or drive gateway RPC load. POSTs are limited to 60 per minute per address (IPv6 per /64).
- **`/_concert` was not a reserved path.** Naming it in a path list made the router panic at startup or on a live settings change; such lists are now rejected.
- **A paid page request with a full priority lane got a raw JSON 503.** It now joins the ordinary line; forms still get 503, with the existing HTML page for browsers.
- **Open redirect on the access page.** `?return=/%09/evil.example` passed the path check and the browser stripped the tab, producing `//evil.example`. Return targets are resolved against the origin.
- The payment journal now fsyncs its directory when created and fails closed if a request finishes after shutdown closed it. Recipients are validated per chain and the Hedera sponsor must differ from the recipient.
- The built-in waiting page shows the room's position immediately, offers paid skipping only with a price and no existing pass (as room's page does), and tolerates the room's poll-rate limit; the access page tells a visitor when their free-queue turn arrives.

## Node.js removed

The archive's chain gateway, reference client and reconciliation utility were Node.js programs (283 npm packages, 481 MB installed), and the wallet page loaded a 1.99.0 web3.js bundle. All of it is now Go or plain browser JavaScript; the repository has no `package.json`.

- The XRPL, Stellar and Hedera `exact` facilitator rules from `@x402/xrpl`, `@x402/stellar` and `@x402/hedera` 2.27.0 are ported check for check into `internal/chain/{xrpl,stellar,hedera}`, with the same `invalidReason` strings. The x402 Go SDK covers only EVM and SVM, so there was nothing to reuse. Vectors generated with the TypeScript facilitators are committed and the Go code must reproduce their verdicts; see [VALIDATION.md](VALIDATION.md). XRPL's binary codec and key derivation are implemented directly and byte-compared with xrpl.js; Stellar and Hedera use their official Go SDKs.
- `internal/gateway` replaces `server.mjs` and runs inside the `concert` process: Concert calls it directly, so there is no second service, loopback port or `CONCERT_GATEWAY_TOKEN`. The replay rules and per-network settlement queues are unchanged. Its settlement journal is an exclusively locked, fsync'd JSON-lines file in `<data-dir>/gateway/` instead of SQLite, chain endpoints come from `CONCERT_NETWORKS_CONFIG` (`-networks-config`), sponsor keys from Concert's environment, and a `gateway_url` in `fastlane.json` is ignored. On shutdown Concert waits for settlements in flight to journal their results.
- `concert reconcile` replaces `reconcile.mjs` and takes the journal lock, so it cannot run beside a live Concert. `concert-client` replaces `client.mjs` with the same environment variables and state-file rules.
- The wallet page speaks the Wallet Standard (`solana:signTransaction`, `solana:signMessage`) and decodes the prepared transfer itself; it also refuses a signed transaction whose message the wallet changed. `web/solana-web3.min.js`, its route and its license notice are removed.
- XRPL endpoints are rippled JSON-RPC over HTTPS (`rpc`); `ws` entries are rejected with a message saying so.
- Stricter than the reference: the Stellar payer's authorization signature is verified locally against the payer's key (`@x402/stellar` reported an entry signed by another key as valid, leaving the network to reject it after the sponsor submits it), Stellar `AddressV2` credentials and restore-requiring simulations are refused, and XRPL fields the codec cannot interpret are refused.
- `examples/fastlane.json` and `examples/networks.json` are complete samples with well-formed placeholder values, embedded in the binary (`concert example fastlane|networks`) and documented key by key in [FASTLANE.md](FASTLANE.md#configuration-reference). A test keeps them passing Concert's and the gateway's checks.
- `installer.sh` installs `fastlane.json` and `networks.json` (given as `CONCERT_FASTLANE_CONFIG`/`CONCERT_NETWORKS_CONFIG`, or already in `/etc/concert`) as root-owned copies with the `concert_etc_t` label, so SELinux lets Concert read them. A file moved in from a home directory would keep `user_home_t` and be denied. It also verifies that the concert user can read them, sets the paths in `concert.env`, labels the chain endpoint ports concert connects to (XRPL 51234, Hedera 50211, the `policy_url` port), restarts concert when either file changes, writes the samples to `/etc/concert/*.example.json`, and gives settlements in flight time to finish on stop.
- hiero-sdk-go v2.84.0 ships corrupted built-in address books, so the gateway reads Hedera consensus nodes from the configured mirror node.