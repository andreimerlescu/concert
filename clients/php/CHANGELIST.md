# Changelog — Concert PHP SDK

All notable changes to `clients/php` are documented in this file.

## [0.3.0] - 2026-11-26

### Added
- Composer-ready PSR-7/PSR-15 library (`composer.json`, namespace `Concert\`).
- `Secret` redacting credential container supporting `fromEnv()` and `fromFile()` (rejecting world-readable secret files).
- `EndpointValidator` enforcing HTTPS or loopback endpoints and preventing header injection.
- `PriorityHeader` for `Concert-Priority` ranking, TTL clamping, native PHP header emission, and PSR-7 response mutation.
- `Rm1Signer` for Ed25519 `rm1` pass and lease signing/verification via PHP `ext-sodium` (`sodium_crypto_sign_detached`), compatible with Concert `room v1.9.0`.
- `CachePurgeClient` for authenticated `POST /_room/cache/purge` (`url`, `prefix`, `tag`, `all`).
- `WaitingRoomSignal` parser for `X-Concert-Queue`, `X-Concert-Position`, `Retry-After`, and `X-Concert-Status-Url`.
- `AgentBidClient` for crypto-only (`xrpl`, `stellar`, `hedera`, `solana`) non-custodial agent pass bidding (`POST /_concert/bids`, `GET /_concert/bids/status`).
- `Middleware\PriorityMiddleware` and framework adapters (`SlimAdapter`, `CakePhpAdapter`, `LaminasAdapter`, `InvisionAdapter`, `PhpBbAdapter`, `VanillaPhpAdapter`).
- Standalone PHP CLI test suite (`src/Tests/run.php`) and complete framework integration guides under `docs/`.
