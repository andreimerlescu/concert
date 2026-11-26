# Changelog — Concert Go Client

## v0.3.0 (2026-11-26)

### Added

- Standalone zero-dependency Go module `github.com/andreimerlescu/concert/clients/go/src` (`go 1.24`).
- `priority.go`: `PriorityTier` constants (`guest`, `member`, `prospect`, `customer`, `subscriber`, `checkout`, `staff`), `FormatPriorityHeader`, `SetPriority`, `PriorityMiddleware`, `PriorityHandlerFunc`, and Gin-compatible `GinPriorityAdapter`.
- `rm1.go`: Pure-stdlib `crypto/ed25519` `SignRM1`, `MintRM1Pass`, `MintRM1Lease`, `VerifyRM1`, `DecodeEd25519PublicKey`, and `FormatVerifyKeysFlag`, wire-compatible with `room v1.8+` split verify-only mode.
- `signals.go`: `ParseWaitingRoomSignal` and `IsQueuedResponse` for `X-Concert-Queue`, `X-Concert-Position`, `Retry-After`, and `X-Concert-Status-Url`.
- `purge.go`: Redacting `Secret` type and `CachePurgeClient` (`PurgeURL`, `PurgePrefix`, `PurgeTag`, `PurgeAll`, `Purge`) calling `POST /_room/cache/purge` with bounded response reads and cross-host redirect credential stripping.
- `bidding.go`: Crypto-only (`xrpl`, `stellar`, `hedera`, `solana`) `AgentBidClient` (`SubmitBid`, `GetBidStatus`) and `ParseAuctionOffer` for Concert `429` auction responses.
- `concert_test.go`: Unit, race-checked (`-race`), redaction, and executable `Example` tests backed by `httptest.Server`.
- Documentation suite under `docs/` (`quickstart.md`, `http-and-gin.md`, `rm1-key-rotation.md`, `cache-purge.md`, `agent-bidding.md`).
