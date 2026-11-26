# Concert Enterprise Fast-Lane (`econcert`)

`econcert` can sell a time-limited fast-lane pass in any native coin or issued token/stablecoin across **XRPL**, **Stellar**, **Hedera**, and **Solana**, or admit verified **NFT collection** and **token/trustline balance** holders — while keeping the standard FIFO waiting room always open.

An eligible request shares Concert's bounded priority lane. Eligibility bypasses the waiting room queue; it does not reserve an exclusive upstream slot, authenticate an upstream account, or pay for products inside the origin application unless the operator chooses to price access accordingly.

Concert handles sessions, x402 v2 challenges, universal on-ledger Destination-Tag/Memo flows, policy screening, durable receipts, and cross-edge sliding pass cookies inside one Go binary (`econcert`). Payer private keys stay in the payer's wallet. **By default (`areFeesSponsored: false`), Concert holds zero hot keys on all four chains** — payers pay their own network fees.

## Implemented payment schemes & multi-token assets

| Chain | Native coin | Issued tokens / stablecoins | Scheme(s) | Payer / sponsor fees |
| --- | --- | --- | --- | --- |
| **XRPL** | `XRP` (6 decimals, drops) | Any IOU trustline (`CURRENCY:ISSUER`, e.g. `RLUSD:rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De`, 3-char or 40-hex currency codes) | x402 `exact` + Direct QR / Destination Tag + Memo | Payer (zero hot keys) |
| **Stellar** | `XLM` (7 decimals, stroops) | Classic issued assets (`CODE:ISSUER`, e.g. `USDC:GA5Z...`) and Soroban SACs (`C...`) | x402 `exact` (classic payer-paid or optional sponsored Soroban) + Direct QR / Memo | Payer by default; optional dedicated sponsor with balance alerts & per-minute caps |
| **Hedera** | `0.0.0` (`HBAR`, 8 decimals, tinybars) | Any HTS fungible token (`0.0.N`, e.g. `0.0.456858` USDC) | x402 `exact` (TLS `:50212` consensus nodes) + Direct QR / Memo | Payer by default; optional dedicated sponsor (`extra.feePayer`) with spend caps |
| **Solana** | `SOL` (9 decimals, lamports) | Any SPL or Token-2022 mint (e.g. `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` USDC) | `concert-native-sol` (SOL), x402 `exact` (SPL/Token-2022 with `ComputeBudget` priority fee tolerance) + Direct QR / Memo | Payer (zero hot keys) |

| Chain | Mainnet CAIP-2 ID | Testnet / Devnet CAIP-2 ID |
| --- | --- | --- |
| XRPL | `xrpl:0` | `xrpl:1` (Testnet), `xrpl:2` (Devnet) |
| Stellar | `stellar:pubnet` | `stellar:testnet` |
| Hedera | `hedera:mainnet` | `hedera:testnet` |
| Solana | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` | `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` (Devnet) |

XRPL Mainnet, Testnet, and Devnet transactions carry no `NetworkID`, so the gateway checks the rippled endpoint's `server_info` network ID before every verification, NFT/token check, and reconciliation (and verifies `delivered_amount` on IOU payments so partial-payment exploits are impossible). Hedera prefers TLS gRPC consensus endpoints (`:50212`) with transport security enabled.

## Two ways visitors & AI agents enter the fast lane

### 1. Universal Direct QR + Destination Tag / Memo Flow (Any Mobile, Hardware, or Desktop Wallet)

Works with **any** wallet on earth (Xaman/Xumm, Ledger, Lobstr, Freighter, Phantom Mobile, Solflare, HashPack) without browser extensions or hot keys:

- **Direct Paid Pass (`POST /_concert/direct/challenge` with `kind: "payment"`):** Visitor picks an offer (e.g., `0.99 RLUSD` or `0.99 USDC`), Concert pre-checks any attached NFT/token purchase prerequisites, and displays a strict-CSP inline SVG QR code, wallet deep link (`xrpl:`, `web+stellar:`, `solana:`, `hedera:`), exact amount, receiving address, unique XRPL Destination Tag, and unique `concert:<16-hex>` Memo. The page auto-polls `POST /_concert/direct/verify` until confirmed on-ledger, records the transaction hash durably to prevent replay, and issues the fast-lane pass cookie immediately.
- **1-Drop / Memo Ownership Proof (`POST /_concert/direct/challenge` with `kind: "proof"`):** Visitor enters their public wallet address for an NFT collection or Token/Trustline balance rule. Concert **checks their on-chain holdings first** (so non-holders never waste a single drop), then issues a unique Destination Tag + Memo for the chain's minimum dust (`1 drop` / `1 stroop` / `1 tinybar` / `1 lamport`). Once the transaction appears on-ledger, Concert grants the fast-lane pass and records the proof tx hash against replay.

### 2. Browser Wallet Extensions & x402 v2 Automated Agents (`PAYMENT-SIGNATURE`)

- **Browser Extensions:** Built-in Wallet Standard support for Solana (Phantom, Solflare, Backpack — tolerating wallet-injected `ComputeBudget` priority-fee instructions and SPL/Token-2022 `TransferChecked`), plus native adapters in `internal/server/web/wallet-adapters.js` for XRPL (GemWallet, Crossmark), Stellar (Freighter), and Hedera (HashPack).
- **AI Agents & Automated Software (`concert-client`):** Queued agents sending `Concert-Session` receive a structured `429` JSON response with `fast_lane.offers` including `display_amount` and `asset_symbol` (e.g., `"0.99"` `"RLUSD"`), pay via `POST /_concert/payment` with `PAYMENT-SIGNATURE`, and immediately take the priority lane on their next request.

## NFT Collection & Token/Trustline Gating

Both **NFT collections** (`collections[]`) and **Token/Trustline minimum balances** (`token_gates[]`) support three explicit `usage` modes:

- `"entry"` (**Hold to Enter**): Holders receive a free fast-lane pass upon proving wallet ownership.
- `"purchase_gate"` (**Hold to Buy**): Attached to one or more paid `offers[]` via `require_collections` / `require_token_gates` (`gate_mode: "all"` or `"any"`). The paying wallet must satisfy the prerequisite before Concert accepts or settles the pass payment.
- `"both"`: Works as either a free entry rule or a purchase prerequisite.

| Chain | NFT `collection` format | Token/Trustline `asset` format | Notes |
| --- | --- | --- | --- |
| **XRPL** | `issuer:taxon` or `issuer:*` (any taxon from issuer) | `XRP` or `CURRENCY:ISSUER` (e.g. `RLUSD:rMx...`) | Paginated `account_nfts` & `account_lines`; optional `issuer` double-check |
| **Stellar** | Soroban SEP-50 `C...` or classic `CODE:ISSUER` | `XLM`, `CODE:ISSUER`, or Soroban SAC `C...` | Verified via Horizon balances & Soroban simulation |
| **Hedera** | HTS NFT token ID `0.0.N` | `0.0.0` (HBAR) or HTS fungible `0.0.N` | Optional `issuer` checks token `treasury_account_id` on Mirror Node |
| **Solana** | Verified Metaplex collection mint | `SOL`, SPL mint, or Token-2022 mint | **Auto-scans wallet NFTs** across SPL Token, Token-2022, and optional DAS (`das_rpc`) — visitors never need to look up a mint ID! |

## Sliding Passes, Slow PHP Checkouts & Active-Active Multi-Edge Cookies

- **Sliding idle pass (`pass_sliding: true`):** Every active click or refresh refreshes the visitor's pass by `pass_idle_seconds` (default `180s`) up to a hard ceiling `pass_max_seconds` (default `1800s`), for both paid passes and NFT/token holders (`nft_pass_seconds` configurable up to `3600s`).
- **In-flight safety:** Once a request is admitted to the upstream, Concert never interrupts it mid-flight. Default `upstream_timeout` is **60s** (**90s** in the WordPress preset, configurable in `Concertfile`) so 45-second checkout scripts finish cleanly.
- **Cross-edge stateless pass cookie (`concert_fastlane_pass`):** Authenticated with HMAC-SHA256 derived from `CONCERT_ADMIT_SECRET` (supporting seamless rotation via `CONCERT_ADMIT_SECRET_PREV`). Any active-active edge sharing the secret honors the pass immediately, strips both `concert_fastlane` and `concert_fastlane_pass` before proxying upstream, and syncs live revocations & settlement deduplication over Redis when configured.

## Live Admin Portal Editor & Security Guards

Administrators can configure every aspect of the fast lane live in the Admin Portal **Fast lane** tab (multi-vhost `?site=` aware via `Concertfile`):

- Enable/disable chains and add presets (`XRPL RLUSD`, `XRP`, `Stellar USDC`, `XLM`, `Solana USDC`, `SOL`, `Hedera USDC`, `HBAR`).
- Edit human prices (`0.99 RLUSD`), receiving wallets (`payTo`), NFT collections, token/trustline rules, pass timing, and mainnet screening policy (`blocklist`, `webhook`, or explicit `none`).
- **Zero-downtime persistence:** Changes validate fail-closed, hot-reload both `gateway.Server` and `fastlane.Service` in memory, persist atomically (`0600`) to `fastlane.json`, update `agentOffer` immediately, and append a hash-chained `fastlane.config.update` audit record.
- **Destination protection:**
  - Any `payTo` or `verify_addresses` change immediately fires a **Critical email alert** (`mailer.CatFastlane`).
  - `-fastlane-lock-destinations` (or `fastlane_lock_destinations on` in `Concertfile`) locks receiving wallets read-only in the Portal while still allowing live price, NFT, and token rule edits.
  - In `-enterprise-hardened` mode, modifying receiving wallets requires an MFA-verified admin account (TOTP) or SSO, and `policy_mode: "none"` on mainnet is refused unless `allow_unscreened_mainnet: true` is explicitly set.

## Multi-Vhost `Concertfile` Support

Configure fast-lane per virtual host in `Concertfile` with zero-downtime `SIGHUP` lock handoff (no `fastlane.lock` collision during reload):

```text
{
    listen :443
    upstream_timeout 60s
    fastlane_lock_destinations on
}

shop.example.com {
    preset wordpress
    upstream fcgi+unix:///run/php/php8.3-fpm.sock
    cap 12
    priority_cap 4
    fastlane_config /etc/concert/shop-fastlane.json
    networks_config /etc/concert/networks.json
}
```

## Durability, Live Archival, Reconciliation & Revocation

- **Zero-downtime online reconciliation:** Reconcile `pending`/`unknown` receipts live from the Portal **Fast lane** tab (`POST /api/fastlane/reconcile`) or Admin API (`POST /_room/fastlane/reconcile`), or offline with `econcert reconcile`.
- **Zero-downtime online receipt archival:** Compact expired `settled` receipts live from the Portal **Fast lane** tab (`POST /api/fastlane/archive`) or Admin API (`POST /_room/fastlane/archive`) while preserving all active, pending, unknown, and recent records, writing an atomic `0600` archive + `.sha256` checksum and audit log entry. Offline archival remains available via `econcert archive-receipts`.
- **Live administrative revocation:** Revoke any active session or pass ID immediately in the Portal (`POST /api/fastlane/revoke`) or Admin API (`POST /_room/fastlane/revoke`), propagating across all Redis-connected edges.
- **Headroom & sponsor monitoring:** Journal headroom alerts fire at 80% (`warn`) and 95% (`critical`). Optional Stellar/Hedera fee-sponsor accounts expose balance health and per-minute spend limits via `/api/fastlane` (`sponsor_status`).

## Automated Client (`concert-client`)

```sh
# Pay 0.99 RLUSD on XRPL mainnet
export CONCERT_ORIGIN='https://shop.example.com'
export CONCERT_CLIENT_NETWORK='xrpl:0'
export CONCERT_NETWORKS_CONFIG='/etc/concert/networks.json'
export CONCERT_CLIENT_XRP_SEED='s...'
export CONCERT_EXPECT_ASSET='RLUSD:rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De'
export CONCERT_MAX_AMOUNT='1.00'
export CONCERT_EXPECT_PAY_TO='rMerchantAddress...'
export CONCERT_ACCEPT_TERMS='yes'
concert-client

# Prove NFT ownership (token ID optional on all 4 chains including Solana)
CONCERT_NFT_RULE='xrpl-founders' concert-client --nft

# Request a direct Destination-Tag / Memo challenge & poll until confirmed
CONCERT_TOKEN_RULE='xrpl-rlusd-holders' CONCERT_WALLET_ADDRESS='rUser...' concert-client --direct

# Wait in line as an agent without paying
concert-client --wait /drop
```

## Protocol references

- [x402 v2 specification](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md)
- [Exact XRPL](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_xrpl.md), [Exact Stellar](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_stellar.md), [Exact Hedera](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_hedera.md), [Exact SVM](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_svm.md)
- [Stellar SEP-50 NFT interface](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0050.md), [SEP-53 message signing](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md)
- [XRPL account_nfts](https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_nfts) & [account_lines](https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_lines)
