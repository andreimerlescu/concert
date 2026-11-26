# Changelist

## 0.3.0 (2026-11-26)

- Initial release of the official zero-dependency Python 3.10+ Concert client SDK (`concert-client`).
- Added `concert_client.priority`: validated `Concert-Priority` ranks (`staff`, `checkout`, `subscriber`, `customer`, `prospect`, `member`, `guest`), `ConcertPriorityASGIMiddleware` (FastAPI/Starlette/ASGI), and `ConcertPriorityWSGIMiddleware` (Flask/Django/WSGI).
- Added `concert_client.signals`: waiting-room signal header parser for `X-Concert-Queue`, `X-Concert-Position`, `Retry-After` (delta seconds and HTTP-date), and `X-Concert-Status-Url`.
- Added `concert_client.rm1`: deterministic pure-Python `rm1` envelope codec plus optional `cryptography`-backed Ed25519 `Ed25519Signer`, `Ed25519Verifier`, and `TokenIssuer` matching Concert's `room v1.8.0+` wire format.
- Added `concert_client.purge`: stdlib `CachePurgeClient` for `POST /_room/cache/purge` (`url`, `prefix`, `tag`, `all`) with strict timeouts, bounded response reads, `0600` secret file validation, and redacting secret wrappers.
- Added `concert_client.bidding`: 100% crypto-only (`xrpl`, `stellar`, `hedera`, `solana`) `AgentBidClient` for `429` auction offer parsing, strict exact-integer `max_bid_micro_usd` enforcement, same-origin SSRF protection, `POST /_concert/bids`, and `GET /_concert/bids/status` polling.
- Added complete `unittest` suite against a local `ThreadingHTTPServer` and integration guides under `docs/`.
