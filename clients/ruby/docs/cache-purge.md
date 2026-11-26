# Active Cache Purge (`POST /_room/cache/purge`)

`ConcertClient::CachePurgeClient` purges Concert's built-in micro-cache or external `concert-cache` daemon via `POST /_room/cache/purge` using pure Ruby `Net::HTTP`.

## Supplying Credentials Safely

Supply the operator/admin Bearer token via a `0600`-protected secret file (preferred) or environment variable:

```bash
export CONCERT_URL="https://edge.example.com"
export CONCERT_ADMIN_TOKEN_FILE="/run/secrets/concert_admin_token"
chmod 600 /run/secrets/concert_admin_token
```

`CachePurgeClient.from_env` fails closed if the token is missing, empty, or world/group-readable.

## Usage

```ruby
require "concert_client"

client = ConcertClient::CachePurgeClient.from_env(timeout: 5.0)

# Exact URL / path
client.purge_url("/products/limited-drop", host: "shop.example.com")

# Prefix
client.purge_prefix("/blog/", host: "shop.example.com")

# Cache tag
client.purge_tag("sku:42", host: "shop.example.com")

# Entire host (or all hosts when host: "")
res = client.purge_all(host: "shop.example.com")
puts "Purged #{res.purged} entries (mode=#{res.mode})"
```

## Security Properties

- **Redaction**: `client.inspect` and `client.to_s` output `[REDACTED]` instead of the Bearer token.
- **TLS & Bounds**: Enforces `OpenSSL::SSL::VERIFY_PEER`, strict `open_timeout`/`read_timeout`/`write_timeout`, bounded response body reads, and restricts plain `http://` to loopback hosts unless `allow_insecure_http: true` is passed.
