# concert-client

`concert-client` is the reference automated wallet for Concert's fast lane. It buys a fast-lane pass with a native XRP, XLM, HBAR or SOL payment, or proves that a wallet holds an eligible NFT, and saves the resulting Concert session for your scripts to use.

It runs on the **payer's** machine. Concert never receives the payer's key: the client signs locally and sends Concert only the signed x402 payment or the signed ownership message. Nothing here belongs on the server that runs Concert.

```
concert-client          pay for a fast-lane pass
concert-client --nft    prove NFT ownership for a short lease
```

## Build

Go 1.26.1 or later:

```sh
go build -trimpath -o bin/concert-client ./cmd/concert-client
# or, without a checkout (from the branch or tag that contains cmd/concert-client):
go install github.com/andreimerlescu/concert/cmd/concert-client@x402
```

## Quick start (XRP on Testnet)

```sh
concert example networks > networks.json   # or copy examples/networks.json; keep only your network

export CONCERT_ORIGIN='https://queue.example.com'          # the Concert site you are paying
export CONCERT_NETWORKS_CONFIG="$PWD/networks.json"
export CONCERT_CLIENT_NETWORK='xrpl:1'
export CONCERT_CLIENT_XRP_SEED='sEd…'                       # load from your secret store
export CONCERT_CLIENT_STATE="$HOME/.concert/queue.example.com-xrpl.json"
export CONCERT_MAX_ATOMIC_AMOUNT='100000'                   # at most 0.1 XRP, in drops
export CONCERT_EXPECT_PAY_TO='rMerchantClassicAddress…'     # the merchant's published address
export CONCERT_ACCEPT_TERMS='yes'                           # after reading the merchant's terms

bin/concert-client
```

On success it prints Concert's JSON answer (eligibility, pass expiry and the settlement receipt) and saves the session in the state file. Send that session as the `Concert-Session` header on requests to the protected site:

```sh
SESSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["session"])' "$CONCERT_CLIENT_STATE")
curl -H "Concert-Session: $SESSION" https://queue.example.com/
```

Use isolated test keys and a test network first.

## Configuration

Everything comes from environment variables. Set exactly one set of wallet credentials, the one for `CONCERT_CLIENT_NETWORK`.

| Variable | Required | Meaning |
| --- | --- | --- |
| `CONCERT_ORIGIN` | yes | The Concert site, e.g. `https://queue.example.com`. HTTPS, except `http://localhost`, `http://127.0.0.1` or `http://[::1]` for local testing. Default `http://127.0.0.1:8080`. |
| `CONCERT_CLIENT_NETWORK` | yes | The network to pay or prove on (table below). It must be one the site offers. |
| `CONCERT_NETWORKS_CONFIG` | yes | A networks file with an entry for that network (see [Networks file](#networks-file)). Default `examples/networks.json`. |
| `CONCERT_CLIENT_STATE` | yes | Where the session and any signed payment are kept. Default `client-state.json` in the current directory. Use one file per site, network and purchase. |
| `CONCERT_MAX_ATOMIC_AMOUNT` | to pay | The most you will pay, as an integer in the chain's smallest unit. The client refuses a higher price. |
| `CONCERT_EXPECT_PAY_TO` | to pay | The recipient you expect, exactly as the site offers it. The client refuses any other recipient. |
| `CONCERT_ACCEPT_TERMS` | to pay | `yes` once you have read the merchant's terms and refund policy. Needed only to sign a new payment. |
| `CONCERT_NFT_RULE` | `--nft` | The site's NFT rule ID (the `id` of a collection in its fast-lane configuration). |
| `CONCERT_NFT_TOKEN` | `--nft` | The NFT you hold: required for Solana (its mint), optional for XRPL (NFTokenID) and Hedera (serial number), not accepted for Stellar. |

### Networks and wallet credentials

| Chain | `CONCERT_CLIENT_NETWORK` | Credentials | Unit for `CONCERT_MAX_ATOMIC_AMOUNT` | Network fee paid by |
| --- | --- | --- | --- | --- |
| XRP | `xrpl:1` Testnet, `xrpl:2` Devnet, `xrpl:0` Mainnet | `CONCERT_CLIENT_XRP_SEED`: the account's family seed, `sEd…` (Ed25519) or `s…` (secp256k1). Recovery phrases are not accepted. | drops (1 XRP = 1,000,000) | you |
| XLM | `stellar:testnet`, `stellar:pubnet` | `CONCERT_CLIENT_XLM_SECRET`: the account's secret seed, `S…` | stroops (1 XLM = 10,000,000) | the merchant's sponsor |
| HBAR | `hedera:testnet`, `hedera:mainnet` | `CONCERT_CLIENT_HBAR_ACCOUNT` (`0.0.N`) and `CONCERT_CLIENT_HBAR_KEY`, the account's DER-encoded private key (hex, Ed25519 or ECDSA secp256k1) | tinybars (1 HBAR = 100,000,000) | the merchant's sponsor |
| SOL | `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` Devnet, `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` Mainnet | `CONCERT_CLIENT_SOL_KEY`: the 64-byte secret key, base64-encoded | lamports (1 SOL = 1,000,000,000) | you |

A Solana CLI keypair file is a JSON array of 64 bytes. Convert it with:

```sh
python3 -c 'import base64,json,sys; print(base64.b64encode(bytes(json.load(open(sys.argv[1])))).decode())' ~/.config/solana/id.json
```

### Networks file

The client uses the same file format as Concert (documented in [docs/FASTLANE.md](../../docs/FASTLANE.md#networksjson)) but only the entry for `CONCERT_CLIENT_NETWORK`, and only its endpoints:

| Network | Keys the client uses | Used for |
| --- | --- | --- |
| XRPL | `rpc` | account sequence, ledger index and fee for the Payment |
| Stellar | `rpc`, `horizon` | simulating the transfer and estimating ledger close time |
| Hedera | `mirror` | choosing the consensus nodes the transaction is frozen for |
| Solana | `rpc` | a recent blockhash |

`fee_payer`, `secret_env` and the fee caps are merchant settings; the client ignores them. Endpoints must be HTTPS.

## What it checks before signing

A payment is signed only when all of these hold:

1. The site answers `/_concert/payment` with an x402 `402` offer for `CONCERT_CLIENT_NETWORK`. The client never picks another network's offer.
2. The offer pays exactly `CONCERT_EXPECT_PAY_TO`, and its amount is positive and no more than `CONCERT_MAX_ATOMIC_AMOUNT`.
3. It is the chain's native currency under the expected scheme: `exact` with `XRP`, the native XLM Stellar Asset Contract, or `0.0.0` for HBAR, and `concert-native-sol` with `SOL`.
4. The configured endpoint is on the requested network: XRPL `server_info`, the Stellar RPC passphrase, the Solana genesis hash. A misconfigured endpoint could otherwise put a test payment on mainnet.
5. `CONCERT_ACCEPT_TERMS=yes`.

What gets signed matches what the official x402 clients produce:

- **XRP:** a Payment for the exact amount with the current `Sequence`, the network fee, and the latest `LastLedgerSequence` the offer's timeout allows. It also carries `InvoiceID`, `DestinationTag` or `NetworkID` when the offer requires them. Only the `sequence` transfer method is supported; the client never creates tickets.
- **XLM:** a native-asset transfer whose single Soroban authorization, signed by your key, expires within the offer's timeout. The merchant's sponsor submits it and pays the fee.
- **HBAR:** a transfer from your account whose transaction ID, and so fee payer, is the merchant's sponsor from the offer's `extra.feePayer`. It is frozen for up to three consensus nodes.
- **SOL:** a single System Program transfer to the recipient, signed by your key, with a recent blockhash.

## The state file and retries

The state file holds the site, the network, the Concert session and, once signed, the payment:

```json
{"origin": "https://queue.example.com", "network": "xrpl:1", "session": "…", "payment": "…base64 PAYMENT-SIGNATURE…"}
```

It is written atomically with mode 0600 in a 0700 directory and flushed to disk before the payment is sent. Treat it like a wallet file: it holds a signed payment and a live session.

- **One authorization per purchase.** The signed payment is saved before it is sent. Every later run re-sends that same authorization and never signs another while it is unresolved. `CONCERT_ACCEPT_TERMS` is not needed to re-send.
- **A failure is not a refusal.** A timeout, a dropped connection or an error ending in "retain this state file and do not authorize a new payment" can mean settlement is still finishing. Concert may take the offer's `maxTimeoutSeconds` plus 90 seconds, longer than the client's 55-second request timeout. Run the client again with the same state file: it re-presents the same payment, and Concert answers with the recorded result. Never delete the file to get around an uncertain payment.
- **Sessions are renewed on every run.** Renewal keeps the session ID, so a saved payment stays attached to it. If the session expired before its payment was resolved, the client stops and says so. Keep the file and contact the merchant: the payment may have settled.
- **A finished purchase stays in the file.** Running again re-presents it and never buys a second pass. For a new purchase after the first is resolved, use a new state file.
- **One run at a time.** A run holds `<state file>.lock` and removes it when it exits. After a crash the lock can remain; confirm no client is running, then delete only the `.lock` file.
- The state file is tied to its site and network. Using it with another `CONCERT_ORIGIN` or `CONCERT_CLIENT_NETWORK` is refused.

## NFT mode

```sh
export CONCERT_NFT_RULE='solana-season'
export CONCERT_NFT_TOKEN='MintAddressOfYourNFT…'
bin/concert-client --nft
```

The client asks Concert for a one-time challenge bound to the site, the session, your address, the collection and the token. It signs the challenge with the wallet key and sends back the signature. No payment, transfer or approval is signed. The signature format depends on the chain:

| Chain | Signature |
| --- | --- |
| XRPL | the raw challenge bytes with the account key (ripple-keypairs); the public key is sent as well, and must be the master key or the active regular key |
| Stellar | SEP-53 (`SHA-256("Stellar Signed Message:\n" + message)`) with the account key; collection rules only, no token |
| Hedera | the raw challenge bytes with the account key; single-key accounts only |
| Solana | Ed25519 over the raw challenge bytes |

An NFT grant lasts only seconds (the site's `nft_pass_seconds`), and ownership is checked again on each proof.

## Errors

The client exits with status 1 and a one-line message:

| Message | Meaning |
| --- | --- |
| `network, recipient or spending budget mismatch` | No offer on your network, the recipient differs from `CONCERT_EXPECT_PAY_TO`, the price exceeds `CONCERT_MAX_ATOMIC_AMOUNT`, or one of them is unset. Nothing was signed. |
| `only the configured native currency scheme is supported` | The offer is not a native-currency offer this client can sign. Nothing was signed. |
| `review merchant terms and set CONCERT_ACCEPT_TERMS=yes` | Nothing was signed. |
| `RPC network mismatch` / `XRPL endpoint is not on <network>` | Your networks file points at a different network than `CONCERT_CLIENT_NETWORK`. Nothing was signed. |
| `session already has access` | The session already holds a pass. |
| `… retain this state file and do not authorize a new payment` | The payment's outcome is not confirmed yet. Run again with the same state file. |
| `the saved session expired before its payment was resolved …` | See [The state file and retries](#the-state-file-and-retries). |
| `client state is locked …` | Another run holds the lock, or a crash left it behind. |
| `state file belongs to another origin/network` | Use a separate state file per site and network. |

## Tests

```sh
go test ./cmd/concert-client
```

The tests run the client against a fake Concert and Solana RPC. They cover:

- the payment is saved before it is sent and re-sent unchanged after a failure
- the budget, recipient, terms and lock checks stop it before signing
- an expired session with an unresolved payment stops it
- `--nft` signs the exact challenge

Each chain's payment builder is also checked against that chain's own verifier in `internal/chain`.
