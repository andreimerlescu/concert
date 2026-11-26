# Concert Ruby Client (`concert_client`)

Official **zero-dependency** Ruby client SDK for the [Concert](https://github.com/andreimerlescu/concert) waiting-room reverse proxy.

Built purely on Ruby's standard library (`net/http`, `json`, `openssl`, `uri`, `base64`, `time`) with **zero runtime gem dependencies**.

Concert is **100% crypto-only** (`xrpl`, `stellar`, `hedera`, `solana`) — zero fiat rails anywhere.

## Features

- **`ConcertClient::Priority`**: Validated `Concert-Priority` ranks (`staff`, `checkout`, `subscriber`, `customer`, `prospect`, `member`, `guest`), pure **Rack middleware** (`RackMiddleware`), **Rails Railtie** (`Railtie`), `ControllerConcern`, and `RailsHelper`.
- **`ConcertClient::Signals`**: Case-insensitive parser for `X-Concert-Queue`, `X-Concert-Position`, `Retry-After` (seconds or HTTP-date), and `X-Concert-Status-Url`.
- **`ConcertClient::Rm1`**: Pure-Ruby deterministic `rm1` envelope encoder/parser plus OpenSSL Ed25519 `Ed25519Signer`, `Ed25519Verifier`, and `TokenIssuer` compatible with Concert's `room v1.8.0+` verify-only split mode.
- **`ConcertClient::CachePurgeClient`**: Authenticated `POST /_room/cache/purge` (`url`, `prefix`, `tag`, `all`) over `Net::HTTP` with strict timeouts, TLS `VERIFY_PEER`, bounded response reads, `0600` secret file validation, and redacting `inspect`/`to_s`.
- **`ConcertClient::AgentBidClient`**: 100% crypto-only (`xrpl`, `stellar`, `hedera`, `solana`) bidding client for `429` auction offer parsing, exact integer `max_bid_micro_usd` enforcement, same-origin SSRF protection, `POST /_concert/bids`, and `GET /_concert/bids/status` polling.

## Installation

Add to your `Gemfile` pointing at the local path or built gem:

```ruby
gem "concert_client", path: "clients/ruby"
```

Or add `clients/ruby/src/lib` to `$LOAD_PATH` directly.

## Quick Example

```ruby
require "concert_client"

# 1. Rack middleware
use ConcertClient::Priority::RackMiddleware, default_ttl: 1800 do |env|
  env["PATH_INFO"].start_with?("/checkout") ? "checkout" : nil
end

# 2. Parse waiting-room headers
signal = ConcertClient::Signals.parse(http_response)
if signal.queued?
  puts "Queued at position #{signal.position}; retry in #{signal.retry_after}s"
end

# 3. Authenticated cache purge (reads CONCERT_URL + CONCERT_ADMIN_TOKEN_FILE)
purge = ConcertClient::CachePurgeClient.from_env
res = purge.purge_prefix("/products/", host: "shop.example.com")
puts "Purged #{res.purged} entries"
```

## Running Tests

```bash
ruby -Iclients/ruby/src/lib clients/ruby/src/test/concert_client_test.rb
```

## Documentation

- [Quickstart](docs/quickstart.md)
- [Rack & Rails Integration](docs/rack-and-rails.md)
- [Active Cache Purge](docs/cache-purge.md)
- [Crypto-Only AI Agent Bidding](docs/agent-bidding.md)

## Security

- Secrets have no defaults and are wrapped in `ConcertClient::Secret`, which redacts values across `to_s`, `inspect`, `pretty_print`, and `to_json`.
- `CONCERT_ADMIN_TOKEN_FILE` enforces POSIX mode `0600` or stricter.
- TLS peer verification is always enabled; plain `http://` is restricted to loopback hosts unless explicitly enabled.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
