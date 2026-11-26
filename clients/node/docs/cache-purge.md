# Active Page Cache Purge (`POST /_room/cache/purge`)

`CachePurgeClient` calls Concert's authenticated page-cache purge endpoint (`POST /_room/cache/purge`) using built-in `fetch`.

## Secret Hygiene

Load your operator/admin Bearer token at runtime from a `0600` secret file or environment variable — never from a hardcoded literal. `CachePurgeClient` wraps the token in `Secret`:

- The raw token lives inside an ECMAScript `#value` private field.
- `String(secret)`, `JSON.stringify(client)`, and `util.inspect(client)` always print `[REDACTED]`.
- Empty strings and placeholder literals (`changeme`, `your-token`, etc.) throw immediately on construction.
- Automatic redirects are disabled (`redirect: "error"`) so the `Authorization` header can never be leaked to a different host.

## Usage

```ts
import { readFileSync } from "node:fs";
import { CachePurgeClient, Secret, ConcertAPIError } from "@concert/client";

const token = new Secret(readFileSync("/run/secrets/concert_operator_token", "utf8"));
const purger = new CachePurgeClient({
  baseUrl: "https://edge.example.com",
  token,
  timeoutMs: 10_000,
  maxResponseBytes: 64 * 1024,
});

try {
  await purger.purgeUrl("/products/drop-01", "shop.example.com");
  await purger.purgePrefix("/products/", "shop.example.com");
  await purger.purgeTag("drop-2026", "shop.example.com");
  await purger.purgeAll("shop.example.com");
} catch (err) {
  if (err instanceof ConcertAPIError) {
    console.error("Purge failed:", err.statusCode, err.message);
  } else {
    throw err;
  }
}
```
