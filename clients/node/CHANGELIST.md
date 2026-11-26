# Changelog — Concert Node.js / TypeScript Client

## v0.3.0 (2026-11-26)

### Added

- Zero-dependency TypeScript + ESM package (`clients/node/package.json`, `clients/node/tsconfig.json`).
- `src/priority.ts`: `Concert-Priority` helpers for Express (`expressPriorityMiddleware`), Next.js App Router & Middleware (`createNextPriorityMiddleware`, `withPriorityResponse`), and standard Web Fetch `Request`/`Response` (`withFetchPriority`).
- `src/rm1.ts`: Pure `node:crypto` Ed25519 `rm1` pass and lease signer (`signRM1`, `mintRM1Pass`, `mintRM1Lease`), security-first verifier (`verifyRM1`), and key rotation helpers (`decodeEd25519PublicKey`, `exportRawEd25519PublicKey`, `formatVerifyKeysFlag`).
- `src/signals.ts`: `parseWaitingRoomSignal` and `isQueuedResponse` for `X-Concert-Queue`, `X-Concert-Position`, `Retry-After`, and `X-Concert-Status-Url`.
- `src/purge.ts`: Redacting `Secret` class and `CachePurgeClient` (`purgeUrl`, `purgePrefix`, `purgeTag`, `purgeAll`, `purge`) calling `POST /_room/cache/purge` with bounded response reads and redirect blocking.
- `src/bidding.ts`: Crypto-only (`xrpl`, `stellar`, `hedera`, `solana`) `AgentBidClient` (`submitBid`, `getBidStatus`) and `parseAuctionOffer`.
- `src/tests/concert.test.ts`: Automated `node --test` suite exercising all modules against a local `node:http` server.
- Documentation suite under `docs/` (`quickstart.md`, `express.md`, `nextjs.md`, `cache-purge.md`, `agent-bidding.md`).
