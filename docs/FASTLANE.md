# Concert wallet access

Concert can sell a time-limited fast-lane pass or admit a verified NFT holder. The standard FIFO queue remains available. An eligible request shares Concert's bounded priority lane; eligibility does not reserve capacity, authenticate an upstream account, or guarantee delivery of the upstream service.

The Go proxy handles sessions, x402 challenges, policy decisions, durable receipts and admission. A separate, authenticated Go chain gateway (`concert-gateway`) verifies and settles payments and checks NFT ownership. Neither process needs Node.js or any JavaScript toolchain. Payer keys stay in the payer's wallet. Only Stellar and Hedera fee sponsor keys belong on the gateway.

## Implemented payment schemes

| Currency | Scheme | Asset identifier | Atomic units per coin | Payer / sponsor fees |
| --- | --- | --- | --- | --- |
| XRP | x402 `exact` (XRPL) | `XRP` | 1,000,000 drops | Payer |
| XLM | x402 `exact` (Stellar) | Canonical native Stellar Asset Contract | 10,000,000 stroops | Dedicated sponsor |
| HBAR | x402 `exact` (Hedera) | `0.0.0` | 100,000,000 tinybars | Dedicated sponsor |
| SOL | `concert-native-sol` extension | `SOL` | 1,000,000,000 lamports | Payer |

The XRPL, Stellar and Hedera `exact` rules are ported from the official x402 TypeScript facilitators (`@x402/xrpl`, `@x402/stellar`, `@x402/hedera` 2.27.0) into Go, check for check and with the same `invalidReason` strings. Test vectors generated with those facilitators and their chain SDKs are committed under `internal/chain/*/testdata`, and the Go verifiers must reach the same verdicts. Concert is deliberately stricter in a few places: it refuses XRPL fields its codec cannot interpret and non-XRP assets, verifies the Stellar payer's authorization signature against the payer's own account key (so multisignature Stellar payers and `AddressV2` credentials are refused), refuses Stellar simulations that need a state restore, and accepts one debited Hedera payer with a capped sponsor fee.

Native SOL is **not** the standard x402 SPL-token `exact` scheme. Its wire format and restrictions are in [NATIVE_SOL_SCHEME.md](NATIVE_SOL_SCHEME.md). A generic x402 wallet must explicitly implement the advertised chain scheme. An x402 connection alone does not supply an NFT ownership proof or guarantee message-signing support.

| Chain | Main network | Test network |
| --- | --- | --- |
| XRPL | `xrpl:0` | `xrpl:1` (Testnet), `xrpl:2` (Devnet) |
| Stellar | `stellar:pubnet` | `stellar:testnet` |
| Hedera | `hedera:mainnet` | `hedera:testnet` |
| Solana | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` | `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` (Devnet) |

Concert validates recipients per chain at startup: an XRPL classic `r…` address, a Stellar `G…`/`C…` address, a numeric Hedera account, or a base58 Solana account. An HBAR offer must name a numeric `extra.feePayer` sponsor that differs from `payTo`. The gateway additionally refuses a Hedera payload whose `maxTransactionFee` exceeds the network's `max_fee_tinybars` (default 100,000,000 tinybars, the 1 HBAR the official x402 Hedera client authorizes), because the sponsor pays it.

XRPL Mainnet, Testnet and Devnet transactions carry no `NetworkID`, so the endpoint alone decides where a payment lands. The gateway therefore checks the XRPL endpoint's `server_info` network ID before every verification, NFT proof and reconciliation, and the reference client does so before signing. A mismatch is refused. XRPL endpoints are rippled JSON-RPC URLs over HTTPS (`rpc`, for example `https://s.altnet.rippletest.net:51234/`); WebSocket `ws` entries are no longer used and are rejected.

XLM payments use the native asset through Soroban. This is not a classic Stellar payment operation. Canonical native contracts are `CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA` on public network and `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC` on testnet. The gateway derives and checks the contract against the network passphrase.

## Run a test deployment

Requires Go 1.26.1 or later, nothing else. Wallet access adds a second Go binary, `concert-gateway`; ordinary Concert deployments without wallet access need only `concert`.

1. Copy `examples/fastlane.testnet.json`, `examples/networks.testnet.json` and `examples/concert.env.example` to private configuration files outside the source checkout. The example starts **disabled**. Replace every placeholder for networks you keep; remove unused offers, collections and network entries. Set merchant, terms, privacy and refund URLs to real, reachable pages. Set `enabled` to `true` only after configuration is complete. Keep `test_mode: true` for testing; it rejects mainnet identifiers.
2. Configure a native receiving address for each offer. XRP receiving addresses must accept a direct payment without a required destination tag. Use a numeric Hedera receiving account and a separate funded Hedera sponsor. Fund the dedicated Stellar sponsor on the selected network. The gateway does not custody payer funds or need a recipient's private key.
3. Set stable, distinct random `CONCERT_ADMIT_SECRET`, `CONCERT_GATEWAY_TOKEN` and portal password; the first two must be at least 32 characters. A production policy service also needs `CONCERT_POLICY_TOKEN` of at least 32 characters. Use a secrets manager or mode-0600 environment file. Never put sponsor or payer secrets in JSON, source control, URLs or browser code. Both Concert and the gateway receive the same gateway token and fast-lane configuration file.
4. Build from the source directory:

   ```sh
   go test ./...
   go build -trimpath -buildvcs=false -o bin/concert .
   go build -trimpath -buildvcs=false -o bin/concert-gateway ./cmd/concert-gateway
   ```

5. In a gateway process with the configured environment (`CONCERT_FASTLANE_CONFIG`, `CONCERT_NETWORKS_CONFIG`, `CONCERT_GATEWAY_TOKEN`, `CONCERT_GATEWAY_DATA` and any sponsor secrets), run `./bin/concert-gateway`. It listens on `127.0.0.1:8402` only (`CONCERT_GATEWAY_PORT` changes the port) and finishes in-flight settlements before exiting on SIGTERM. In a second process, start the proxy (from the source directory):

   ```sh
   ./bin/concert -listen 127.0.0.1:8080 \
     -portal-listen 127.0.0.1:8081 \
     -upstream http://127.0.0.1:3000 \
     -data-dir /var/lib/concert/data \
     -fastlane-config /etc/concert/fastlane.json \
     -cap 100 -priority-cap 10
   ```

   Adjust these paths to your installation. The environment variables in the example can provide the config/data paths instead. The gateway must be available before Concert starts: Concert checks its supported schemes. `CONCERT_GATEWAY_DATA` must point to persistent local storage; the gateway keeps an exclusively locked, fsync'd `settlements.jsonl` there. Both service processes should run as an unprivileged account with restricted filesystem permissions.
6. Open `http://127.0.0.1:8080/_concert/access`. The portal's **Fast lane** tab shows enabled offers, NFT rules and receipt counts. Config changes require restarting the gateway and Concert. The portal does not accept private keys or edit payment destinations.

For production, use HTTPS, set `origin` to the public origin, configure mainnet endpoints and explicitly set `test_mode: false`. Configure a real policy service using [US_COMPLIANCE.md](US_COMPLIANCE.md). Put the portal behind private network/authentication controls. Protect the gateway with loopback isolation or an authenticated TLS tunnel; its token is not a public facilitator credential. Configure `-trusted-proxies` narrowly so policy receives the real client IP. Serve terms/privacy/refunds from an always-available external origin or deliberately add those exact routes to Concert's `-bypass` list. Concert reserves `/_concert` and everything under it for the wallet pages and API; path lists that name it are rejected.

The primary page request ceiling is the ordinary page capacity plus the priority lane capacity. Existing asset and streaming pools have separate limits. Paid and NFT access uses customer rank and the same priority semaphore as existing privileged requests. When the priority lane stays full, a paid page request (GET or HEAD) joins the ordinary FIFO line like any other ranked visitor, and its pass stays valid. A paid form or API submission is refused with `503` and `Retry-After` instead of being queued, which would lose its body: browsers get Concert's existing "form not sent" page, other clients JSON with `fast_lane_busy`, `submitted: false` and `charged_again: false`. A refused request is never sent upstream, and a full lane never buys another pass.

## Collection identifiers and wallet proof

Use the `collections` array in the fast-lane JSON. Each entry needs a unique local `id`, a display `label`, the exact `network`, and its chain-specific `collection`. No collection display name, URL or ticker is treated as proof.

| Chain | Administrator's collection ID | Ownership proof and supported scope |
| --- | --- | --- |
| XRPL | `issuerClassicAddress:NFTokenTaxon` | Validated `account_nfts`; authorized master key or active RegularKey signs the message. Optional NFTokenID narrows the match. Multisignature account proofs are not implemented. |
| Stellar | SEP-50 Soroban NFT contract `C…` | Signed SEP-53 message from a `G…` account with sufficient current master-key weight; read-only simulation of `balance(address) > 0`. Administrator must verify that the allowlisted contract actually implements a nonfungible collection. Contract wallets and general multisignature proofs are not implemented. |
| Hedera | HTS nonfungible token ID `0.0.…` | Mirror-node account key and NFT ownership; optional serial number. Single Ed25519 or secp256k1 account keys only. Threshold and contract-key message proofs fail closed. |
| Solana | Verified Metaplex collection mint | Wallet's Ed25519 message signature, finalized SPL token ownership, one-supply zero-decimal mint and verified collection metadata. The NFT mint is required. Supports conventional Token Metadata NFTs; compressed NFTs, Metaplex Core and Token-2022 are not implemented. |

Stellar rules cannot name a token: `balance()` proves collection membership only, so a token-specific Stellar request is refused rather than reported as verified. When a request names a token, the gateway's proof must name that same token.

The challenge binds origin, session, nonce, address, network, collection and optional token. It expires after two minutes and is consumed once. Ownership is checked again for each new grant. A grant defaults to 30 seconds, configurable from 5 to 60 seconds; transfer or key changes within that window do not revoke an already-issued grant. RPC correctness and mirror-node lag are trust assumptions. Indexer/RPC failures deny admission. XRPL enumeration is bounded to 100 pages of 400 NFTs.

NFT admission does not request an NFT transfer, approval, listing, trustline or payment. The browser visibly distinguishes a payment from an ownership signature.

## Automated client

`concert-client` (`go build -o bin/concert-client ./cmd/concert-client`) is a runnable reference client that signs locally for all four chains. It requires `CONCERT_CLIENT_NETWORK`, `CONCERT_ORIGIN`, `CONCERT_NETWORKS_CONFIG` and one set of wallet credentials:

| Chain | Client-only environment |
| --- | --- |
| XRP | `CONCERT_CLIENT_XRP_SEED` |
| XLM | `CONCERT_CLIENT_XLM_SECRET` |
| HBAR | `CONCERT_CLIENT_HBAR_ACCOUNT`, `CONCERT_CLIENT_HBAR_KEY` (DER private key string) |
| SOL | `CONCERT_CLIENT_SOL_KEY` (base64 of the 64-byte keypair secret) |

Use isolated test keys first. These variables belong on the **payer's machine**, not the merchant's proxy. The client checks an explicit maximum atomic amount and exact recipient before signing:

```sh
export CONCERT_CLIENT_NETWORK='xrpl:1'
export CONCERT_ORIGIN='http://127.0.0.1:8080'
export CONCERT_CLIENT_STATE='/private/client-state.json'
export CONCERT_MAX_ATOMIC_AMOUNT='100000'
export CONCERT_EXPECT_PAY_TO='YOUR_TESTNET_MERCHANT_CLASSIC_ADDRESS'
export CONCERT_ACCEPT_TERMS='yes'
concert-client
```

Load the client secret from your secret store before running this example. To prove NFT ownership instead, set `CONCERT_NFT_RULE` to the configured local rule ID, set `CONCERT_NFT_TOKEN` when needed, and run `concert-client --nft`. Keep the state file private and send its session as the `Concert-Session` header on subsequent protected requests.

For XRP the client builds the Payment as `@x402/xrpl`'s client does (current `Sequence`, network fee, the widest accepted `LastLedgerSequence`, and `InvoiceID`, `DestinationTag` or `NetworkID` when required); it supports the `sequence` transfer method and never creates tickets. It also checks that each RPC endpoint is on the requested network before signing.

The client renews its saved session on every run; renewal keeps the session ID, so a saved payment stays attached to it. If the saved session expired before its payment was resolved, the client stops instead of presenting the payment under a new session. The client saves and flushes the signed authorization before submission and locks its state file against concurrent runs. Rerunning uses the **same** authorization. A crash can leave a `.lock`; confirm that the old process has stopped before removing that lock, and retain the JSON state. An intentional later purchase needs a new state file after the old payment is resolved. Never delete state to get around an uncertain payment.

## HTTP flow and browser adapters

1. `POST /_concert/session` returns a session, its CSRF token and expiry; browsers also get an HttpOnly, SameSite=Strict cookie. Calling it again with a valid session renews the 24-hour expiry under the same session ID, so receipts and unresolved payments carry over. Authenticated wallet requests answer `409 session_renewal_required` when less than two hours remain (more than the longest pass plus settlement time, so a pass never outlives its session); renew and repeat the request, which never changes a payment. Wallet POSTs are limited to 60 per minute per client address (IPv6 per /64); excess requests get `429` with `Retry-After`.
2. `POST /_concert/payment` without a payment header returns HTTP 402 with x402 v2 JSON and base64 `PAYMENT-REQUIRED`. It describes the **pass resource**, not the upstream URL. Generic x402 clients should purchase this resource and retain the session before requesting a queued upstream resource.
3. Sign a selected `accepts` entry and send base64 JSON `{x402Version:2, resource, accepted, payload}` as `PAYMENT-SIGNATURE` on the same POST with the same session. Browser POSTs include `X-Concert-CSRF`; automated clients use `Concert-Session`.
4. Concert verifies the actual payer, requests a policy decision, reserves the authorization durably and asks the gateway to settle. Settlement is detached from the visitor's connection: Concert waits up to `maxTimeoutSeconds` plus 90 seconds for the gateway and records the result even if the tab closes. Only confirmed settlement plus a durable receipt creates eligibility. HTTP 200 includes `PAYMENT-RESPONSE` and the pass expiration.
5. `GET /_concert/status` recovers status without charging. Subsequent protected requests carry the cookie or session header. Session and payment headers/cookies are stripped before proxying to the origin.

The shipped browser supports Solana wallets through the [Wallet Standard](https://github.com/wallet-standard/wallet-standard) (`standard:connect`, `solana:signTransaction`, `solana:signMessage`), which Phantom, Solflare, Backpack and other current wallets implement. No Solana SDK is loaded: `access.js` decodes the unsigned native SOL transfer from Concert, checks payer, recipient and amount against the displayed price, asks the wallet to sign it, and refuses a signed transaction whose message the wallet changed. The automated browser test uses a Wallet Standard test wallet; approval in a real wallet extension has not been exercised in this environment.

For other wallets, bundle a compatible adapter in `web/wallet-adapters.js` and rebuild the binary. The registration contract is:

```js
window.concertWallets['xrpl:1'] = {
  connect: async () => /* public wallet address */,
  signMessage: async (message, network) => /* {signature: BASE64, public_key?: HEX} */,
  createPaymentPayload: async ({paymentRequired, requirements, session}) =>
    /* {x402Version: 2, resource: paymentRequired.resource,
         accepted: requirements, payload: chainSpecificSignedPayload} */
};
```

The snippet describes an interface; wire it to the chosen wallet SDK. NFT signatures are raw challenge bytes for XRPL's `ripple-keypairs` algorithm, SEP-53 for Stellar, account-key signatures for Hedera and Ed25519 for Solana. A wallet that cannot sign the specified message format cannot use that proof route. No WalletConnect project ID or universal XRPL/XLM/HBAR browser connector is bundled. The signed-payment and signed-message forms also accept externally generated proofs.

The browser retains a pending signed payment in `sessionStorage` and exposes an explicit identical-payload retry. Keep that tab open until the payment is resolved. A new tab can recover server status with its session cookie; an expired/deleted session or lost authorization may require merchant assistance. Automated clients have stronger disk-backed recovery and are preferable for unattended purchases.

## Durability, recovery and operational limits

`fastlane.jsonl` contains Concert's receipt history; the gateway's `settlements.jsonl` contains its signed authorization and settlement records. The gateway journal is append-only JSON lines, fsync'd per record and locked against a second writer; a torn final line or a settled record that regresses stops startup instead of being discarded. Preserve both, along with the stable admission secret. Use consistent, encrypted backups. The service fails closed on journal corruption or I/O failure. Do not run multiple Concert processes against one journal or clone journals into independently charging deployments. This release uses a single-writer architecture, not distributed transactional storage.

Identical authorizations are deduplicated by canonical payload hash and settled transaction ID. A consumed payment never renews a pass. A journaled but unconfirmed result blocks a different payment for that session. Any settlement outcome other than confirmed success is recorded as unknown, including a gateway that rejected the authorization when re-verifying it just before submission; in that case the gateway has no record for the fingerprint and never submitted it. The gateway does not rebroadcast a transaction after an uncertain process restart. Client timeouts do not imply chain failure.

The gateway settles one authorization at a time per network, so a slow chain never delays another and one sponsor account never races itself. It refuses to re-verify an authorization it already settled, so while its journal survives, a lost or restored Concert journal cannot turn a settled payment into a new pass.

For an unresolved payment:

1. Keep the original signed payload, client session and both journals. Check `/_concert/status`; retry the identical signed authorization if the gateway completed in the background.
2. If the gateway's durable record remains `pending` or `unknown`, stop the gateway, back up its data directory, and find the payment's fingerprint (`id`) in `settlements.jsonl`. Do not export signed payloads into public logs/support channels.
3. With the same gateway environment, run `concert-gateway reconcile <fingerprint>`. For Stellar, add the sponsor's finalized transaction hash as the second argument. The command takes the journal lock, so it refuses to run while the gateway is up. It validates ledger state against the saved authorization before recording success; it never broadcasts, signs, refunds or transfers funds. It refuses ambiguous data, including Hedera mirror amounts that are not exact 64-bit integers.
4. Restart the gateway and retry the identical payment through Concert. If settlement cannot be proved, keep the receipt unresolved and follow the merchant's reviewed support/refund procedure. No automatic release, re-signing or refund is provided.

Payment eligibility begins when Concert durably records successful settlement, including after reconciliation. Set an explicit refund/support policy for delayed or unavailable service. Native transfers are not bound to a web origin at the ledger level; the local receipt journal is essential, and different independent merchants sharing one receiving address cannot rely on it for global replay prevention.

Receipt deduplication records are not automatically pruned. `max_records` defaults to 100,000 and is a hard fail-closed ceiling; arrange a reviewed migration/archival strategy before reaching it. Backups, key rotation, redemptions across replicas, administrative pass revocation and automated refunds are not implemented. Short pass lifetimes bound ordinary admission risk but do not replace incident response.

## Protocol references

Reviewed September 27, 2026. Go dependencies are pinned in `go.mod` and `go.sum`.

- [x402 v2 specification](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md)
- [Exact XRPL](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_xrpl.md), [Exact Stellar](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_stellar.md), [Exact Hedera](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_hedera.md), [Exact SVM](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_svm.md)
- [Stellar SEP-50 NFT interface](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0050.md), [SEP-53 message signing](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md)
- [XRPL account_nfts](https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_nfts)
