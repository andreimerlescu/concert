# Concert Node.js / TypeScript Client (`clients/node`)

Zero-dependency TypeScript + ESM client for integrating Express apps, Next.js (App Router & Middleware), Web Fetch handlers, API clients, and crypto AI agents with [Concert](../../README.md) virtual waiting rooms.

## Features

- **Zero runtime npm dependencies**: Built strictly on Node.js built-ins (`node:crypto` for Ed25519 `rm1` signing/verification and built-in `fetch` / `AbortSignal.timeout`).
- **`Concert-Priority` middleware**: Ready-to-use adapters for **Express** (`expressPriorityMiddleware`), **Next.js App Router & Middleware** (`createNextPriorityMiddleware`, `withPriorityResponse`), and standard Web Fetch `Request`/`Response` (`withFetchPriority`).
- **Stateless Ed25519 `rm1` passes & leases**: Pure `node:crypto` issuer (`signRM1`, `mintRM1Pass`, `mintRM1Lease`) and security-first verifier (`verifyRM1`) with multi-key rotation helpers (`formatVerifyKeysFlag`, `decodeEd25519PublicKey`), wire-compatible with Go `room v1.8+` and Concert.
- **Waiting-room signal parser**: `parseWaitingRoomSignal(headers)` and `isQueuedResponse(response)` for `X-Concert-Queue`, `X-Concert-Position`, `Retry-After`, and `X-Concert-Status-Url`.
- **Active cache purge client**: Authenticated `CachePurgeClient` (`purgeUrl`, `purgePrefix`, `purgeTag`, `purgeAll`) calling `POST /_room/cache/purge`, holding the Bearer token inside a redacting `Secret` (`#value` private field, `[REDACTED]` on `toString`, `toJSON`, and `util.inspect`).
- **Crypto-only AI agent bidding**: `AgentBidClient` (`submitBid`, `getBidStatus`) and `parseAuctionOffer` across **XRPL**, **Stellar**, **Hedera**, and **Solana** (`xrpl`, `stellar`, `hedera`, `solana`). Concert is 100% crypto-only — losing bids pay `$0`.

## Quick Verification

Requires Node.js 22.18+ (native TypeScript execution and `node:test`):

```bash
cd clients/node
npm test
```

## Documentation

- [Quickstart](docs/quickstart.md)
- [Express Integration](docs/express.md)
- [Next.js App Router & Middleware Integration](docs/nextjs.md)
- [Active Page Cache Purge (`POST /_room/cache/purge`)](docs/cache-purge.md)
- [Crypto-Only AI Agent Bidding (`xrpl`, `stellar`, `hedera`, `solana`)](docs/agent-bidding.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE).
