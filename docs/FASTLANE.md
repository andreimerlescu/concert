# Concert wallet access

Concert can sell a time-limited fast-lane pass or admit a verified NFT holder. The standard FIFO queue remains available. An eligible request shares Concert's bounded priority lane; eligibility does not reserve capacity, authenticate an upstream account, or guarantee delivery of the upstream service.

Concert handles sessions, x402 challenges, policy decisions, durable receipts and admission, and its built-in chain gateway (`internal/gateway`) verifies and settles payments and checks NFT ownership. It is one Go binary; nothing else runs beside it, and no Node.js or JavaScript toolchain is involved. Payer keys stay in the payer's wallet. The only keys Concert holds are the Stellar and Hedera fee sponsors', from its environment.

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

Requires Go 1.26.1 or later, nothing else. Wallet access is part of the `concert` binary.

1. Start from the samples: `concert example fastlane > fastlane.json` and `concert example networks > networks.json` (the files are also in `examples/`, and `installer.sh` writes them to `/etc/concert/*.example.json`). Every value in them is a well-formed placeholder: replace each one using the [configuration reference](#configuration-reference) below, and remove the offers, collections and networks you do not use. Keep `test_mode: true` for testing; it rejects mainnet identifiers. Set `enabled` to `true` only after configuration is complete. Keep both files private, mode 0640, readable by the account Concert runs as. Under SELinux, install them with `installer.sh`, which applies the `concert_etc_t` label Concert needs to read them.
2. Configure a native receiving address for each offer. XRP receiving addresses must accept a direct payment without a required destination tag. Use a numeric Hedera receiving account and a separate funded Hedera sponsor. Fund the dedicated Stellar sponsor on the selected network. Concert does not custody payer funds or need a recipient's private key.
3. Set a stable random `CONCERT_ADMIT_SECRET` of at least 32 characters and a portal password. A production policy service also needs `CONCERT_POLICY_TOKEN` of at least 32 characters. Sponsor keys go in `CONCERT_STELLAR_FEE_SECRET` (an `S…` seed) and `CONCERT_HEDERA_FEE_SECRET` (a DER private key), or in the variables a network's `secret_env` names. Use a secrets manager or mode-0600 environment file. Never put sponsor or payer secrets in JSON, source control, URLs or browser code.
4. Build and start Concert from the source directory:

   ```sh
   go test ./...
   go build -trimpath -buildvcs=false -o bin/concert .
   ./bin/concert -listen 127.0.0.1:8080 \
     -portal-listen 127.0.0.1:8081 \
     -upstream http://127.0.0.1:3000 \
     -data-dir /var/lib/concert/data \
     -fastlane-config /etc/concert/fastlane.json \
     -networks-config /etc/concert/networks.json \
     -cap 100 -priority-cap 10
   ```

   `CONCERT_FASTLANE_CONFIG`, `CONCERT_NETWORKS_CONFIG` and `CONCERT_DATA_DIR` can provide the same paths. The data directory must be persistent local storage: it holds the receipt journal `fastlane.jsonl` and, under `gateway/`, the settlement journal. On SIGTERM Concert lets settlements in flight journal their results before exiting, which can take up to an offer's `maxTimeoutSeconds` plus three minutes; give the service manager that long to stop. `installer.sh` installs the configuration files with the SELinux label Concert needs (see its header).
5. Open `http://127.0.0.1:8080/_concert/access`. The portal's **Fast lane** tab shows enabled offers, NFT rules and receipt counts. Configuration changes require a restart. The portal does not accept private keys or edit payment destinations.

For production, use HTTPS, set `origin` to the public origin, configure mainnet endpoints and explicitly set `test_mode: false`. Configure a real policy service using [US_COMPLIANCE.md](US_COMPLIANCE.md). Put the portal behind private network/authentication controls. Configure `-trusted-proxies` narrowly so policy receives the real client IP. Serve terms/privacy/refunds from an always-available external origin or deliberately add those exact routes to Concert's `-bypass` list. Concert reserves `/_concert` and everything under it for the wallet pages and API; path lists that name it are rejected.

The primary page request ceiling is the ordinary page capacity plus the priority lane capacity. Existing asset and streaming pools have separate limits. Paid and NFT access uses customer rank and the same priority semaphore as existing privileged requests. When the priority lane stays full, a paid page request (GET or HEAD) joins the ordinary FIFO line like any other ranked visitor, and its pass stays valid. A paid form or API submission is refused with `503` and `Retry-After` instead of being queued, which would lose its body: browsers get Concert's existing "form not sent" page, other clients JSON with `fast_lane_busy`, `submitted: false` and `charged_again: false`. A refused request is never sent upstream, and a full lane never buys another pass.

## Configuration reference

Wallet access reads two JSON files and a few environment variables. The samples (`examples/fastlane.json`, `examples/networks.json`, or `concert example fastlane|networks`) contain every key below. Their values are invented but correctly formatted, so a sample with `"enabled": true` passes Concert's checks; the addresses in it belong to nobody you know, so **a payment sent to a sample address is lost**. Replace them all.

Amounts are always integer strings in the chain's smallest unit: 1 XRP = 1,000,000 drops, 1 XLM = 10,000,000 stroops, 1 HBAR = 100,000,000 tinybars, 1 SOL = 1,000,000,000 lamports.

### fastlane.json: top level

| Key | Sample value | Your real value |
| --- | --- | --- |
| `enabled` | `false` | `true` once every other value is real. `false` keeps wallet access off; only the file's JSON syntax and key names are checked (an unknown key stops startup). |
| `origin` | `"https://queue.example.com"` | The public address visitors type to reach Concert: scheme, host and optional port, no path or trailing slash. It must equal the browser's `Origin` header exactly (`https://www.example.com` and `https://example.com` differ). HTTPS; `http://127.0.0.1:8080` is allowed only in test mode. |
| `policy_url` | `""` | Your screening service's decision endpoint (see [US_COMPLIANCE.md](US_COMPLIANCE.md)), HTTPS or loopback HTTP. Optional in test mode, **required** when `test_mode` is `false`. Its bearer token goes in `CONCERT_POLICY_TOKEN`. |
| `test_mode` | `true` | `true` accepts only test networks (the `:1`, `:2`, `testnet` and Devnet identifiers below) and skips screening when `policy_url` is empty. `false` for real money; mainnet identifiers then work and `policy_url` is required. |
| `pass_seconds` | `300` | How long a paid pass grants priority, 30–3600 seconds (default 300). |
| `nft_pass_seconds` | `30` | How long one NFT ownership proof grants priority, 5–60 seconds (default 30). |
| `max_records` | `100000` | Receipt records kept before wallet access fails closed, 100–1,000,000 (default 100,000). |
| `merchant` | `"Example Tickets LLC"` | Your legal business name as payers should see it, 1–120 characters. |
| `terms_url`, `privacy_url`, `refund_url` | `"https://www.example.com/terms"`, `…/privacy`, `…/refunds` | Your published terms, privacy policy and refund policy. HTTPS, and reachable while the queue is full: host them elsewhere or list them in `-bypass`. |
| `offers` | four offers, one per chain | 0–8 payment offers, at most one per currency and network (below). |
| `collections` | four rules, one per chain | 0–32 NFT rules (below). `offers` and `collections` together need at least one entry. |
| `gateway_url` | not present | Leave it out. Earlier versions ran the gateway separately; Concert now ignores this key. |

### fastlane.json: an offer

```json
{"label": "XRP · Testnet", "requirements": {"scheme": "exact", "network": "xrpl:1", "amount": "100000", "asset": "XRP",
  "payTo": "rQLTGGRoGbQZLK2ErVKio1pxViAR8fvMBT", "maxTimeoutSeconds": 60, "extra": {"areFeesSponsored": false}}}
```

`label` is the text in the payment-network menu. `maxTimeoutSeconds` (30–300; the sample uses 60) is how long a signed payment stays valid and how long settlement may wait for finality. The other fields depend on the chain:

| Field | XRP | XLM | HBAR | SOL |
| --- | --- | --- | --- | --- |
| `scheme` | `"exact"` | `"exact"` | `"exact"` | `"concert-native-sol"` |
| `network` (sample → mainnet) | `"xrpl:1"` Testnet (`"xrpl:2"` Devnet) → `"xrpl:0"` | `"stellar:testnet"` → `"stellar:pubnet"` | `"hedera:testnet"` → `"hedera:mainnet"` | `"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"` Devnet → `"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"` |
| `amount` (sample) | `"100000"` = 0.1 XRP | `"1000000"` = 0.1 XLM | `"10000000"` = 0.1 HBAR | `"1500000"` = 0.0015 SOL |
| `asset` | `"XRP"` | Native XLM contract: testnet `"CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"` (the sample's, already real), pubnet `"CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA"` | `"0.0.0"` | `"SOL"` |
| `payTo` sample | `"rQLTGGRoGbQZLK2ErVKio1pxViAR8fvMBT"` | `"GAJCHOYDKVA34FOL4NTDILX6T7XIEQXWJZ7ZT4PV2RSUVVXCHW4CC5LA"` | `"0.0.4815162"` | `"HnsoZ8ePhw43Zf3vSpTt71LGbdRG3NzFepQWxXBosRWo"` |
| `payTo`: yours | Your receiving account's classic address (`r…`), from your wallet's Receive screen (Xaman, Ledger Live) or, for Testnet, the [XRPL faucet](https://xrpl.org/resources/dev-tools/xrp-faucets). It must accept a payment with no destination tag: not an exchange deposit address. | Your receiving account (`G…`, from Freighter, Lobstr or [Stellar Lab](https://lab.stellar.org/)) or a contract (`C…`). The account must already exist on the network. | Your receiving account ID (`0.0.N`, shown in HashPack or [HashScan](https://hashscan.io/); testnet accounts come from the [Hedera portal](https://portal.hedera.com/)). | Your wallet address (base58, 32–44 characters, from Phantom's or Solflare's Receive screen). |
| `extra` | `{"areFeesSponsored": false}`, required. Optional: `"assetTransferMethod": "sequence"`, `"invoiceId"`, `"destinationTag"` (an integer the payment must carry). | `{"areFeesSponsored": true}`, required: your Stellar sponsor pays network fees. | `{"feePayer": "0.0.4815342"}`, required: your Hedera sponsor account (`0.0.N`), different from `payTo` and equal to `fee_payer` in networks.json. Its key goes in `CONCERT_HEDERA_FEE_SECRET`. | `{"areFeesSponsored": false}`, required. |

### fastlane.json: an NFT rule

```json
{"id": "xrpl-founders", "label": "Founders Club (XRPL)", "network": "xrpl:1", "collection": "rN1ZgJLAwHdVCZL3vY5nqudgEsCc5sEyZX:42"}
```

`id` is your own unique slug (up to 64 characters), which automated clients pass as `CONCERT_NFT_RULE`. `label` is the text in the collection menu. `network` uses the same identifiers as offers. `collection` depends on the chain:

| Chain | Sample `collection` | Your real value and where to find it |
| --- | --- | --- |
| XRPL | `"rN1ZgJLAwHdVCZL3vY5nqudgEsCc5sEyZX:42"` | `issuer:taxon`: the account that minted the NFTs and their NFTokenTaxon. Both are on any NFT of the collection in an explorer ([XRPL explorer](https://livenet.xrpl.org/), [testnet](https://testnet.xrpl.org/)), under Issuer and Taxon. |
| Stellar | `"CAR6LMNBSEDJ7EJPZ5GM2STC5ZGN7AVTPA6UALCUCPQQ2L4PHDVJJAXM"` | The SEP-50 NFT contract address (`C…`), from the collection's publisher or [stellar.expert](https://stellar.expert/). |
| Hedera | `"0.0.2233445"` | The HTS non-fungible token ID (`0.0.N`), shown on [HashScan](https://hashscan.io/) for any NFT in the collection. |
| Solana | `"EBiEQxgHYcCBPN8zoUSZxbEsKd46TBPtphdcQQd28Ey"` | The verified Metaplex collection mint: the mint address of the collection's parent NFT, shown as Collection on an NFT's page in [Solscan](https://solscan.io/) or Magic Eden. Visitors also enter the mint of the NFT they hold. |

### networks.json

One entry per network that an offer or collection uses, keyed by the same network identifier. Endpoints must be HTTPS. Public endpoints are rate limited; for production, use a provider's endpoint.

| Network | Key | Sample value | Your real value |
| --- | --- | --- | --- |
| XRPL | `rpc` | `"https://s.altnet.rippletest.net:51234/"` (Testnet, real) | rippled JSON-RPC over HTTPS. Devnet `https://s.devnet.rippletest.net:51234/`; mainnet `https://xrplcluster.com/`, `https://s1.ripple.com:51234/` or a provider. WebSocket URLs are refused. |
| | `max_fee` | `"1000"` | The highest network fee in drops a payer's transaction may carry (default 1000). |
| Stellar | `rpc` | `"https://soroban-testnet.stellar.org"` (real) | A Stellar RPC server. SDF runs only the testnet one; for pubnet pick one from the [RPC providers list](https://developers.stellar.org/docs/data/apis/rpc/providers). |
| | `horizon` | `"https://horizon-testnet.stellar.org"` (real) | Horizon for the same network; pubnet `https://horizon.stellar.org`. |
| | `secret_env` | `"CONCERT_STELLAR_FEE_SECRET"` | The environment variable that holds the sponsor's secret seed (default `CONCERT_STELLAR_FEE_SECRET`). |
| | `max_fee` | `"50000"` | The most the sponsor pays per payment, in stroops (default 50,000 = 0.005 XLM). |
| Hedera | `mirror` | `"https://testnet.mirrornode.hedera.com"` (real) | A mirror node; mainnet `https://mainnet-public.mirrornode.hedera.com` or a provider. Concert also learns the consensus nodes (port 50211) from it. |
| | `fee_payer` | `"0.0.4815342"` | Your sponsor account ID; it must equal the offer's `extra.feePayer`. |
| | `secret_env` | `"CONCERT_HEDERA_FEE_SECRET"` | The environment variable that holds the sponsor's private key (default `CONCERT_HEDERA_FEE_SECRET`). |
| | `max_fee_tinybars` | `"100000000"` | The highest transaction fee the sponsor signs for, in tinybars (default 100,000,000 = 1 HBAR). |
| Solana | `rpc` | `"https://api.devnet.solana.com"` (real) | Solana JSON-RPC; mainnet `https://api.mainnet-beta.solana.com` (heavily rate limited) or a provider. |

### Environment

| Variable | Sample | Your real value |
| --- | --- | --- |
| `CONCERT_FASTLANE_CONFIG`, `CONCERT_NETWORKS_CONFIG` | empty | Paths of the two files; `installer.sh` sets them to `/etc/concert/fastlane.json` and `/etc/concert/networks.json`. |
| `CONCERT_ADMIT_SECRET` | generated by the installer | A stable random string of at least 32 characters. Changing it invalidates every session and pass. |
| `CONCERT_STELLAR_FEE_SECRET` | empty | The Stellar sponsor account's secret seed (`S…`, 56 characters). Create a dedicated account in [Stellar Lab](https://lab.stellar.org/) (fund it with Friendbot on testnet) and keep a small balance. Needed only with an XLM offer. |
| `CONCERT_HEDERA_FEE_SECRET` | empty | The Hedera sponsor account's DER-encoded private key (hex starting `302e…` for Ed25519 or `3030…` for ECDSA), from the [Hedera portal](https://portal.hedera.com/) for testnet or your wallet's key export. Needed only with an HBAR offer. |
| `CONCERT_POLICY_TOKEN` | empty | The bearer token for `policy_url`, at least 32 characters. |

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
2. If the gateway's durable record remains `pending` or `unknown`, stop Concert, back up its data directory, and find the payment's fingerprint (`id`) in `<data-dir>/gateway/settlements.jsonl`. Do not export signed payloads into public logs/support channels.
3. As the account Concert runs as, run `concert reconcile -data-dir <data-dir> -networks-config <networks.json> <fingerprint>` (the flags default to `CONCERT_DATA_DIR` and `CONCERT_NETWORKS_CONFIG`). For Stellar, add the sponsor's finalized transaction hash as the second argument. The command takes the journal lock, so it refuses to run while Concert is up. It validates ledger state against the saved authorization before recording success; it never broadcasts, signs, refunds or transfers funds. It refuses ambiguous data, including Hedera mirror amounts that are not exact 64-bit integers.
4. Start Concert and retry the identical payment. If settlement cannot be proved, keep the receipt unresolved and follow the merchant's reviewed support/refund procedure. No automatic release, re-signing or refund is provided.

Payment eligibility begins when Concert durably records successful settlement, including after reconciliation. Set an explicit refund/support policy for delayed or unavailable service. Native transfers are not bound to a web origin at the ledger level; the local receipt journal is essential, and different independent merchants sharing one receiving address cannot rely on it for global replay prevention.

Receipt deduplication records are not automatically pruned. `max_records` defaults to 100,000 and is a hard fail-closed ceiling; arrange a reviewed migration/archival strategy before reaching it. Backups, key rotation, redemptions across replicas, administrative pass revocation and automated refunds are not implemented. Short pass lifetimes bound ordinary admission risk but do not replace incident response.

## Protocol references

Reviewed September 27, 2026. Go dependencies are pinned in `go.mod` and `go.sum`.

- [x402 v2 specification](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md)
- [Exact XRPL](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_xrpl.md), [Exact Stellar](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_stellar.md), [Exact Hedera](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_hedera.md), [Exact SVM](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_svm.md)
- [Stellar SEP-50 NFT interface](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0050.md), [SEP-53 message signing](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md)
- [XRPL account_nfts](https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_nfts)

