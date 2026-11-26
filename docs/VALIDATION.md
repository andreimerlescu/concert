# Validation report

Checks performed September 27, 2026, after integrating the fast-lane source update into this repository, correcting the defects listed in [CHANGES.md](CHANGES.md), and porting the chain gateway and reference client from Node.js to Go. Toolchain: Go 1.26.1, and Chromium through Playwright 1.56.1 on Linux for the browser harness only. Concert, its gateway and its client need no Node.js.

The update arrived as a source archive with its own report: 175 Go tests and 11 Node gateway tests passing, and three moderate npm advisories. Both test counts were reproduced before any change. The results below are for the current code.

## Automated checks

| Check | Result |
| --- | --- |
| `gofmt -l .` | No files. |
| `go vet ./...` | Passed. |
| `make dist` (Linux release packaging) | Passed: 10 static Linux binaries + 6 Linux FIPS 140-3 binaries packaged as `.tar.gz` tarballs in `dist/` with per-edition CycloneDX 1.5 SBOMs and `SHA256SUMS.txt`. |
| `go test -race -count=1 ./...` | Passed: 230 top-level Go tests (272 with subtests). |
| `go mod verify` | All modules verified. |
| `govulncheck ./...` | **Not run.** The build environment's egress policy denied `vuln.go.dev` (HTTP 403). Run it before deployment. |
| Accounting export | Exact units beyond JavaScript's safe-integer range, spreadsheet-formula escaping, exclusion of unresolved receipts and blank USD columns checked with `scripts/export-payments.py`. |

The Concert suite covers the x402 challenge, exact offer matching, settlement, historical and cross-session replay rejection, concurrent submission of one authorization from many sessions, restart recovery, unknown results, settlement that completes after the visitor disconnects, session renewal, policy denial, CSRF/origin checks, per-address rate limiting, one-time NFT challenges, token-specific NFT rules, wrong-owner responses, recipient and sponsor validation, corrupted, closed and exclusively locked journals, and the reserved `/_concert` path. Proxy integration checks a full standard queue, paid access through the priority lane, the shared capacity ceiling, refusal of a paid POST when the lane is full, a paid page request joining the line instead, and stripping of payment and session credentials before forwarding.

### Parity with the official x402 facilitators

The XRPL, Stellar and Hedera `exact` verifiers were ported from `@x402/xrpl`, `@x402/stellar` and `@x402/hedera` 2.27.0. To prove the port, the TypeScript facilitators themselves (with xrpl.js 4.6.0, `@stellar/stellar-sdk` 16.3.0 and `@hiero-ledger/sdk` 2.85.0) were run once, outside the repository, over signed payloads for every rule, and their verdicts were committed as `internal/chain/*/testdata/vectors.json`. The Go tests replay those payloads against the same mocked ledger state and must reach the same `isValid`/`invalidReason`:

| Chain | Reference cases | Also checked against the reference SDK |
| --- | --- | --- |
| XRPL | 28 | ripple-keypairs seed derivation (Ed25519 and secp256k1), byte-identical signed Payment blobs, message signatures |
| Stellar | 18 | byte-identical `authorizeEntry` output, the sponsor's rebuilt settlement envelope (identical to the one the TypeScript facilitator submits except time bounds), SEP-53 signatures |
| Hedera | 12 | transaction IDs, message signatures |
| Solana (`concert-native-sol`) | 8 web3.js transactions | byte-identical unsigned transfer, Metaplex metadata PDAs, message signatures |

Stellar and Hedera vectors record the reference verdict and the Concert verdict side by side; they differ only where Concert is deliberately stricter: a Stellar authorization signed by a key other than the payer's is refused, and Hedera payloads may debit one payer and authorize at most the configured sponsor fee. XRPL's stricter refusals (fields the codec cannot interpret, non-XRP assets) are covered by separate tests.

### Gateway and client

Gateway tests cover bearer authentication, request limits, the configured-terms allowlist, refusal to re-verify a settled authorization, one submission under concurrent retries, restart with settled and unknown records, key-order-independent fingerprints, per-network settlement queues, journal locking, torn final lines, settled-record regression and corruption, NFT challenge binding, and configuration validation (HTTPS-only endpoints, no credentials in URLs, the Stellar native asset, the Hedera sponsor, fee caps and unknown fields). One test drives the real native SOL scheme through the HTTP API against a local JSON-RPC server: prepare, verify, a settlement whose finality is not observed (recorded as unknown, never rebroadcast), then `reconcile` once the ledger shows finality.

Chain tests also cover SOL transfer amount, recipient, signatures, extra instructions and non-canonical encodings, refusal of transfers already on chain as new evidence, polling to finality, XRPL settlement to a validated result or past `LastLedgerSequence`, XRPL endpoint network checks, Hedera single-payer enforcement, the sponsor fee cap and mirror-node node discovery, and Stellar simulation, event and fee checks.

Client tests run `concert-client` against a fake Concert and Solana RPC: the signed authorization is saved before it is sent and resent unchanged after a failure, budget, recipient, terms and lock guards stop it before signing, an expired session with an unresolved payment stops it, and an NFT proof signs the exact challenge. Each chain's payer builder is verified by that chain's own verifier.

Ledger responses are mocked; a passing fixture is not evidence of a funded on-chain settlement.

## Browser verification

A local harness ran the real `concert` binary, with its built-in chain gateway, against a mock Solana JSON-RPC server on loopback HTTPS; Concert trusted the harness's certificate through `SSL_CERT_FILE`. No other process ran beside it, and the settlement journal appeared in `<data-dir>/gateway/`. XRP, XLM and HBAR offers used throwaway, unfunded sponsor keys and were displayed but not settled. A fake origin held the only page slot so visitors queued. A Wallet Standard test wallet registered in the page kept its key in the test process and signed only what the page asked it to sign. NFT ownership went through the gateway's real Metaplex and SPL checks against the mock RPC.

All 52 checks passed at 1440×900 and 390×844:

- The waiting page showed a live FIFO position while the room was full, offered wallet access, and kept the legacy skip card hidden without a price.
- The access page listed four networks, formatted exact native prices, required consent, and showed test-network mode.
- A browser SOL payment prepared, was decoded and checked in the page, signed, verified, broadcast once, polled to finality and granted a pass; the pass was then admitted through the priority lane while the room was full, and the receipt was recovered on a fresh page load.
- A payment request dropped after signing kept the signed payload, blocked a second signature after reload, and settled exactly once on the identical retry.
- An NFT proof with the wallet's message signature granted a lease; a Solana proof without a mint was refused before signing.
- Return links stayed on the origin for tab-injected, protocol-relative, absolute and backslash targets.
- The portal's Fast lane tab showed configuration, journal health and receipt counts.
- No script, CSP, asset or horizontal-overflow errors. The only filtered console entries were Chrome's log of the expected x402 `402` challenge and the portal's pre-existing missing favicon.

Against the same stack, `concert-client` refused an offer above its budget, paid a SOL pass, and proved NFT ownership, and reconciliation refused to open the journal while it was held. The previews in this directory are test fixtures, not production receipts.

## Dependency review

The Node gateway, its 283 npm packages (481 MB installed) and the 1.99.0 web3.js browser bundle are gone, and with them the npm advisory chain the archive reported (`@solana/web3.js` → `jayson` → `stream-json`). The browser decodes the one transaction shape it needs in about 20 lines of `access.js`.

The Go gateway adds five direct modules: `filippo.io/edwards25519` (Solana program-address curve checks), `github.com/decred/dcrd/dcrec/secp256k1/v4` (XRPL and Hedera ECDSA), `github.com/stellar/go-stellar-sdk` (Stellar XDR, strkeys and keypairs), `github.com/hiero-ledger/hiero-sdk-go/v2` (Hedera protobufs and submission) and `google.golang.org/protobuf`. XRPL's binary codec and key derivation are implemented in Concert and byte-compared with xrpl.js. Adding them raised `github.com/gorilla/schema` and `google.golang.org/genproto` through minimal version selection.

hiero-sdk-go v2.84.0 embeds corrupted address books (`addressbook/*.pb` contain U+FFFD replacement bytes, so `ClientForTestnet` came up with no nodes here). The gateway does not use them: it reads consensus nodes from the configured mirror node and builds its client from those. Report this upstream before relying on the SDK's built-in networks.

The gateway accepts only authenticated, bounded requests from Concert and uses configured chain endpoints. That reduces exposure but does not protect against a compromised provider or a future advisory. Re-run `govulncheck` and a dependency review before deployment; `go.sum` is a reproducibility aid, not a permanent assessment.

## Still requires deployment validation

- Funded test-network payments, finality and recovery for every enabled chain not yet exercised with funded keys in your deployment (specifically funded Solana Devnet with `CONCERT_TESTNET_SOL_KEY` and funded Hedera Testnet with `CONCERT_TESTNET_HBAR_ACCOUNT` / `CONCERT_TESTNET_HBAR_KEY`), followed by a controlled production rollout.
- Real injected wallet approvals in your target browser extensions (Phantom, Solflare, Backpack, GemWallet, Crossmark, Freighter, HashPack) and mobile QR scans (Xaman, Lobstr, Phantom Mobile, HashPack Mobile).
- Live NFT ownership, key rotation and transfer tests for each enabled collection format, including indexer lag.
- An independent security review of your production deployment topology.
- The operator's policy service or blocklist curation, up-to-date sanctions inputs, relevant identity checks, business-model/legal review, accounting, and support/refund procedures.
- Operational load limits, RPC availability, optional sponsor balances, fee ceilings, backups and journal recovery on the deployment filesystem.

## v0.3.0 Mainnet Crypto Readiness & Live Testnet Verification

Verified before the `v0.3.0` release across all three editions (`concert`, `wpconcert`, `econcert`), `bench-concert`, and `concert-client`:

| Check | Result |
| --- | --- |
| `gofmt -l .` | Clean (0 unformatted files). |
| `make lint` (`go vet` across all 3 editions) | Passed. |
| `make test` & `make test-race` (all 3 editions) | Passed (0 failures, 0 data races). |
| 10× `-race` stress (`chain`, `fastlane`, `gateway`, `configfile`, `concert-client`) | Passed 10/10 runs across all 8 packages. |
| `make vulncheck` (`govulncheck` across all 3 editions) | **No vulnerabilities found.** |
| Standing invariant `internal/chain/solana/tx.go` | Untouched (`git diff --stat` empty). |

### Live Public Testnet Runs (`make test-testnet` / `internal/server/testnet_live_test.go`)

Executed against a real live `econcert` instance with its real in-process `gateway.Server` (zero mocks):

1. **XRPL Testnet (`xrpl:1`, `https://s.altnet.rippletest.net:51234/`):**
   - Funded live payer (`rKRsGGsjLj8bqU19oL792pDRthhBkH7812`) and merchant (`rPpktv6nyBYnqKh1LhsNKZZFvpU69gX9Dh`) via the XRPL Testnet faucet.
   - **Live x402 XRP Payment:** Settled on-ledger and granted fast-lane pass — tx `B578E64DA442D5B3AC487F19AE74235DBEE56F9E218220AFCCCEA5FE40D47870`.
   - **Live 1-Drop Destination Tag + Memo Token-Gate Proof:** Pre-checked live balance, issued unique Destination Tag `3668548999` + Memo `concert:95491cb0b69542e2`, verified on-ledger, and granted sliding fast-lane pass — tx `CBCF209D89705DCF551ECB874BAA95ECC3EDD26CAE61A0BFDFFB3A438EFED63E`.
2. **Stellar Testnet (`stellar:testnet`, `https://horizon-testnet.stellar.org` — Zero Hot Keys):**
   - Funded live payer (`GBDVLH6E6MMHAGLKUED5I6UCRAH4A4T32PIR65HDIIYFYDFOLTGXAMYM`) and merchant (`GBMBNVQOLRMCNQTXJX773STJPUQJXASOCAFV663PZMFUNNYEBOE46ZQ5`) via Friendbot.
   - **Live Payer-Pays-Fees Classic XLM x402 Payment (zero hot keys on Concert):** Settled on Horizon and granted fast-lane pass — tx `c4b1cbc08de99b8cef1dfd3842bb09841cd56eece7b298bc62177bc5abc19c51`.
   - **Live 1-Stroop Memo Token-Gate Proof:** Pre-checked live Horizon balance, issued Memo `concert:6d63f4621d0ee109`, verified on-ledger, and granted sliding fast-lane pass — tx `7a0c3ee7f4d52b0a1075d24bd981774024384a25e0b579fefa8fdb15bf72c170`.
3. **Solana Devnet (`solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1`, `https://api.devnet.solana.com`):**
   - Live RPC genesis-hash network check and `LatestBlockhash` succeeded (`HSk5G3eu74VEahVkv1Ux1LuWYPxY9VyibMg5GFo2pY7D`).
   - Public RPC `requestAirdrop` returned HTTP 410 (`The RPC faucet is closed on this cluster. Request test SOL at https://faucet.solana.com`); funded Solana Devnet settlement is exercised automatically when `CONCERT_TESTNET_SOL_KEY` is provided.
4. **Hedera Testnet (`hedera:testnet`, `https://testnet.mirrornode.hedera.com`):**
   - Live Mirror Node TLS `:50212` node discovery succeeded (discovered 7 live TLS `:50212` consensus nodes `0.0.3`–`0.0.9`) and live Mirror Node balance verification succeeded (`0.0.2`).
   - Funded Hedera Testnet consensus payment over TLS `:50212` is exercised automatically when `CONCERT_TESTNET_HBAR_ACCOUNT` and `CONCERT_TESTNET_HBAR_KEY` are provided.

See [FASTLANE.md](FASTLANE.md) for the full multi-token, direct QR/Destination-Tag/Memo, NFT/token-gate, and live Admin Portal specification.
