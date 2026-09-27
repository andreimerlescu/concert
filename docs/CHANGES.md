# Source update: v0.1.0

## Admission and payment

- Added `internal/fastlane` for x402 v2 discovery, signed sessions, CSRF/origin validation, policy decisions, NFT challenges and persistent receipt recovery.
- Connected eligible requests to the existing bounded priority lane and customer-rank metrics. Full paid lanes return a retriable error without sending the POST upstream or charging again.
- Added a Go chain gateway (`concert-gateway`) implementing the official XRP/XLM/HBAR x402 `exact` schemes and the documented native SOL extension, plus chain-specific NFT verification.
- Added durable gateway settlement caching, an explicit reconciliation command (`concert-gateway reconcile`), a reference automated client for all four chains (`concert-client`), and exact-unit accounting exports.
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
- `internal/gateway` replaces `server.mjs` with the same HTTP API, bearer token, limits and replay rules. Its settlement journal is an exclusively locked, fsync'd JSON-lines file instead of SQLite (`CONCERT_GATEWAY_DATA` replaces `CONCERT_GATEWAY_DB`).
- `concert-gateway reconcile` replaces `reconcile.mjs` and takes the journal lock, so it cannot run beside a live gateway. `concert-client` replaces `client.mjs` with the same environment variables and state-file rules.
- The wallet page speaks the Wallet Standard (`solana:signTransaction`, `solana:signMessage`) and decodes the prepared transfer itself; it also refuses a signed transaction whose message the wallet changed. `web/solana-web3.min.js`, its route and its license notice are removed.
- XRPL endpoints are rippled JSON-RPC over HTTPS (`rpc`); `ws` entries are rejected with a message saying so.
- Stricter than the reference: the Stellar payer's authorization signature is verified locally against the payer's key (`@x402/stellar` reported an entry signed by another key as valid, leaving the network to reject it after the sponsor submits it), Stellar `AddressV2` credentials and restore-requiring simulations are refused, and XRPL fields the codec cannot interpret are refused.
- hiero-sdk-go v2.84.0 ships corrupted built-in address books, so the gateway reads Hedera consensus nodes from the configured mirror node.
