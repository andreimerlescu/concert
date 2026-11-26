# Concert Python Client (`concert-client`)

Official **zero-dependency** Python 3.10+ client SDK for the [Concert](https://github.com/andreimerlescu/concert) waiting-room reverse proxy.

Concert is **100% crypto-only** (`xrpl`, `stellar`, `hedera`, `solana`) — zero fiat rails anywhere.

## Features

- **`concert_client.priority`**: Validated `Concert-Priority` header builder (`staff`, `checkout`, `subscriber`, `customer`, `prospect`, `member`, `guest`) + pure **ASGI / FastAPI** middleware (`ConcertPriorityASGIMiddleware`) + pure **WSGI / Flask** middleware (`ConcertPriorityWSGIMiddleware`).
- **`concert_client.signals`**: Case-insensitive parser for Concert waiting-room signal headers (`X-Concert-Queue`, `X-Concert-Position`, `Retry-After`, `X-Concert-Status-Url`).
- **`concert_client.rm1`**: Pure-Python deterministic `rm1` envelope encoder/parser + optional Ed25519 signing/verification (`Ed25519Signer`, `Ed25519Verifier`, `TokenIssuer`) compatible with Concert's `room v1.8.0+` verify-only split mode.
- **`concert_client.purge`**: Authenticated `CachePurgeClient` (`POST /_room/cache/purge`, modes `url` / `prefix` / `tag` / `all`) built on stdlib `urllib.request` with strict timeouts, TLS verification, bounded response reads, and redacting credentials.
- **`concert_client.bidding`**: Crypto-only (`xrpl`, `stellar`, `hedera`, `solana`) `AgentBidClient` with `429` auction offer parsing, exact integer micro-USD `max_bid_micro_usd` cap enforcement, same-origin SSRF protection, `POST /_concert/bids`, and `GET /_concert/bids/status` polling.

## Installation

Pure stdlib (zero required runtime dependencies):

```bash
pip install ./clients/python
```

With optional Ed25519 `rm1` signing/verification support:

```bash
pip install "./clients/python[crypto]"
```

## Quick Example

```python
from concert_client import (
    CachePurgeClient,
    ConcertPriorityASGIMiddleware,
    parse_waiting_room_headers,
)

# 1. FastAPI / ASGI middleware
app = ConcertPriorityASGIMiddleware(
    fastapi_app,
    resolver=lambda scope: ("checkout", 1800) if scope["path"].startswith("/checkout") else None,
)

# 2. Parse waiting-room signal headers on an HTTP client response
signal = parse_waiting_room_headers(response.headers)
if signal.queued:
    print(f"Queued at position {signal.position}, retry in {signal.retry_after}s")

# 3. Authenticated page-cache purge (reads CONCERT_URL + CONCERT_ADMIN_TOKEN_FILE)
purge = CachePurgeClient.from_env()
result = purge.purge_prefix("/products/", host="shop.example.com")
print(f"Purged {result.purged} entries")
```

## Running Tests

```bash
PYTHONPATH=clients/python/src python3 -m unittest discover -s clients/python/src/tests -v
```

## Documentation

- [Quickstart](docs/quickstart.md)
- [FastAPI / ASGI Integration](docs/fastapi-asgi.md)
- [Flask / WSGI Integration](docs/flask-wsgi.md)
- [Active Cache Purge](docs/cache-purge.md)
- [Crypto-Only AI Agent Bidding](docs/agent-bidding.md)

## Security

- Secrets are never hardcoded and have no defaults.
- `SecretString` and `SecretBytes` redact values in `str()`, `repr()`, and `format()`.
- File-based credentials (`CONCERT_ADMIN_TOKEN_FILE`) enforce mode `0600` or stricter on POSIX systems.
- TLS verification is always enabled; plain `http://` is restricted to loopback hosts unless explicitly opted in.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
