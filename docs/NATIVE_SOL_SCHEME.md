# `concert-native-sol`, version 1

This is a Concert-specific scheme carried in the x402 v2 HTTP envelope. It is not a claim of registration, certification, or compatibility with wallets implementing only x402's standard `exact` SPL-token scheme.

## Requirements

```json
{
  "scheme": "concert-native-sol",
  "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
  "asset": "SOL",
  "amount": "1000000",
  "payTo": "MERCHANT_PUBLIC_KEY",
  "maxTimeoutSeconds": 60,
  "extra": {"areFeesSponsored": false, "paymentFlow": "upfront"}
}
```

`amount` is a positive decimal integer string in lamports, restricted by Concert to a signed 64-bit maximum. No decimal floating-point price is accepted. `network` is the supported CAIP-2 identifier derived from the cluster's genesis hash. `payTo` is the native SOL receiving account.

## Payment payload

The x402 `payload` object is `{"transaction":"BASE64_SIGNED_LEGACY_TRANSACTION"}`. The accepted transaction has precisely one signature and one instruction: a System Program `Transfer` from the fee payer to `payTo`, for exactly `amount` lamports. The sender must differ from the recipient. Its instruction contains the canonical 12-byte transfer data and two account references. The transaction uses a recent blockhash and the sender pays network fees.

Versioned transactions, address lookup tables, durable nonce instructions, compute-budget instructions, split transfers, token transfers, extra account signers and arbitrary program instructions are rejected. The wallet must sign the exact prepared message without injecting other instructions.

## Verification and settlement

The gateway checks the genesis hash, canonical base64, canonical transaction encoding (re-serializing the transaction must reproduce its bytes exactly, so one signature has one payload fingerprint), transaction size, Ed25519 signature, account privileges, recipient and integer amount.

A new authorization must be unknown to the network (no signature status at any commitment), carry a valid blockhash and pass signature-checked simulation. A transaction already on chain is never accepted as new payment evidence: its bytes are public once broadcast, and accepting it would let anyone who observed it claim the payer's pass. A payer who broadcasts the transfer themselves, outside this flow, therefore cannot redeem it through Concert and needs merchant support.

Settlement runs only after the gateway has journaled the authorization. It broadcasts the saved signed bytes once, or does not rebroadcast if the transfer is already landing, then polls the signature status until the transaction is finalized. A failed transfer, or no finality within the 120-second confirmation window, is recorded as unknown and left for reconciliation rather than treated as a failed payment. The signature identifies the transaction.

A known successful authorization is returned from the durable cache with its existing receipt. None of these checks guarantees priority capacity after settlement.

## Clients

The shipped automated client and injected Solana browser path implement this extension. Browser preparation is a session/CSRF-protected `POST /_concert/solana/prepare` with `network` and public `address`; the server returns unsigned transaction bytes and does not hold the payer's key. The browser validates the transfer before asking its wallet to sign. No on-chain program deployment is required.

The transfer does not cryptographically bind a URL/session on-chain. Replay protection is local to the preserved merchant journals. If a deployment needs globally unique resource-bound authorizations, design and review a separate scheme rather than treating this extension as that guarantee.
