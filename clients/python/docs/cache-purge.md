# Active Cache Purge (`POST /_room/cache/purge`)

`CachePurgeClient` invalidates Concert's built-in micro-cache or external `concert-cache` daemon via `POST /_room/cache/purge` using pure Python stdlib `urllib.request`.

## Supplying Credentials Safely

Supply the operator/admin Bearer token via a `0600`-protected secret file (preferred) or environment variable — **never** hardcode tokens in source code or pass them as CLI arguments:

```bash
export CONCERT_URL="https://edge.example.com"
export CONCERT_ADMIN_TOKEN_FILE="/run/secrets/concert_admin_token"
chmod 600 /run/secrets/concert_admin_token
```

`CachePurgeClient.from_env()` fails closed if the secret is missing, empty, or readable by group/other (`mode & 0o077 != 0`).

## Purge Modes

```python
from concert_client import CachePurgeClient

client = CachePurgeClient.from_env(timeout=5.0)

# 1. Exact URL / path
client.purge_url("/products/limited-edition", host="shop.example.com")

# 2. Path prefix
client.purge_prefix("/blog/", host="shop.example.com")

# 3. Cache tag (Surrogate-Key / Cache-Tag)
client.purge_tag("sku:42", host="shop.example.com")

# 4. Purge all entries for a host (or all hosts when host="")
result = client.purge_all(host="shop.example.com")
print(result.purged, result.mode)
```

## Security Properties

- **Redaction**: `repr(client)` and `str(client)` print `[REDACTED]` for the token.
- **Transport**: TLS certificate verification is always enabled; plain `http://` is restricted to loopback addresses (`127.0.0.1`, `localhost`, `::1`) unless `allow_insecure_http=True` is explicitly set.
- **Bounds**: Every request uses a strict timeout and bounded response read (`max_response_bytes`, default 64 KiB).
