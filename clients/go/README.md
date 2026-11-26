# Concert Go Client (`clients/go`)

Zero-dependency Go standard library client for integrating origin servers, API clients, and autonomous crypto AI agents with [Concert](../../README.md) virtual waiting rooms.

## Features

- **Zero external dependencies**: Pure Go standard library (`go 1.24+`), isolated module at `github.com/andreimerlescu/concert/clients/go/src`.
- **`Concert-Priority` middleware**: Standard `net/http` middleware (`PriorityMiddleware`), `http.HandlerFunc` (`PriorityHandlerFunc`), and zero-dependency Gin adapter (`GinPriorityAdapter`) supporting `staff`, `checkout`, `subscriber`, `customer`, `prospect`, `member`, and `guest` (clear).
- **Stateless Ed25519 `rm1` passes & leases**: Pure-stdlib `crypto/ed25519` issuer (`SignRM1`, `MintRM1Pass`, `MintRM1Lease`) and security-first verifier (`VerifyRM1`) with multi-key zero-downtime rotation (`FormatVerifyKeysFlag`, `DecodeEd25519PublicKey`), wire-compatible with `github.com/andreimerlescu/room` v1.8+.
- **Waiting-room signal parser**: Strict parser (`ParseWaitingRoomSignal`, `IsQueuedResponse`) for `X-Concert-Queue`, `X-Concert-Position`, `Retry-After`, and `X-Concert-Status-Url`.
- **Active cache purge client**: Authenticated `CachePurgeClient` (`PurgeURL`, `PurgePrefix`, `PurgeTag`, `PurgeAll`) targeting `POST /_room/cache/purge`, with a redacting `Secret` type (`[REDACTED]` on every `fmt`, `json`, `text`, and `slog` path), bounded reads, and cross-host redirect protection.
- **Crypto-only AI agent bidding**: `AgentBidClient` (`SubmitBid`, `GetBidStatus`) and `ParseAuctionOffer` for `429` auction offers across **XRPL**, **Stellar**, **Hedera**, and **Solana** (`xrpl`, `stellar`, `hedera`, `solana`). Concert is 100% crypto-only — losing bids pay `$0`.

## Installation

```bash
go get github.com/andreimerlescu/concert/clients/go/src
```

```go
import concert "github.com/andreimerlescu/concert/clients/go/src"
```

## Documentation

- [Quickstart](docs/quickstart.md)
- [`net/http` & Gin Priority Integration](docs/http-and-gin.md)
- [Stateless `rm1` Ed25519 Key Rotation](docs/rm1-key-rotation.md)
- [Active Page Cache Purge (`POST /_room/cache/purge`)](docs/cache-purge.md)
- [Crypto-Only AI Agent Bidding (`xrpl`, `stellar`, `hedera`, `solana`)](docs/agent-bidding.md)

## Verification

```bash
cd clients/go/src
go vet ./...
go test -race -count=5 ./...
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
