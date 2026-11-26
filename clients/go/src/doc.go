// Package concert provides a zero-dependency Go client library for origin
// servers, API clients, and autonomous AI agents integrating with Concert
// virtual waiting rooms.
//
// All functionality is implemented exclusively with the Go standard library:
//
//   - Priority signaling (Concert-Priority response header middleware for
//     net/http and Gin-compatible handlers).
//   - Stateless Ed25519 rm1 signed VIP pass and lease issuance and
//     verification, wire-compatible with github.com/andreimerlescu/room v1.8+.
//   - Waiting-room response header parsing (X-Concert-Queue,
//     X-Concert-Position, Retry-After, X-Concert-Status-Url).
//   - Authenticated active page-cache purging (POST /_room/cache/purge) with
//     redacting Secret handling and bounded response reads.
//   - Crypto-only AI agent pass bidding (POST /_concert/bids,
//     GET /_concert/bids/status, and 429 auction offer parsing) across XRPL,
//     Stellar, Hedera, and Solana.
package concert
