# Changelist

## 0.3.0 (2026-11-26)

- Initial release of the official zero-dependency Ruby Concert client SDK (`concert_client`).
- Added `ConcertClient::Secret`: redacting credential wrapper with `0600` file-mode validation (`from_file`, `from_env_or_file`).
- Added `ConcertClient::Priority`: `Concert-Priority` validation, `RackMiddleware`, `ControllerConcern`, `RailsHelper`, and guarded `Rails::Railtie`.
- Added `ConcertClient::Signals`: waiting-room header parser for `X-Concert-Queue`, `X-Concert-Position`, `Retry-After`, and `X-Concert-Status-Url` (supporting standard HTTP headers and Rack `HTTP_*` env keys).
- Added `ConcertClient::Rm1`: pure-Ruby `rm1` envelope codec plus OpenSSL Ed25519 `Ed25519Signer`, `Ed25519Verifier`, and `TokenIssuer` (with runtime OpenSSL Ed25519 detection and pluggable signer/verifier hooks).
- Added `ConcertClient::CachePurgeClient`: stdlib `Net::HTTP` client for `POST /_room/cache/purge` (`url`, `prefix`, `tag`, `all`) with strict timeouts, bounded reads, and secret redaction.
- Added `ConcertClient::AgentBidClient`: 100% crypto-only (`xrpl`, `stellar`, `hedera`, `solana`) AI agent bidding client with `429` auction offer parsing, exact integer `max_bid_micro_usd` enforcement, same-origin SSRF protection, `POST /_concert/bids`, and `GET /_concert/bids/status` polling.
- Added standalone `minitest` suite against a local `TCPServer` stub and documentation under `docs/`.
