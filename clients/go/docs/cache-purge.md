# Active Page Cache Purge (`POST /_room/cache/purge`)

`CachePurgeClient` calls Concert's operator-authenticated micro-cache / `concert-cache` purge endpoint (`POST /_room/cache/purge`).

## Secret Handling

Load the operator/admin Bearer token at runtime from a secret file (`0600`) or environment variable — never from a source literal or CLI flag default. Wrap it in `concert.Secret` via `concert.NewValidatedSecret`:

- Every formatting, JSON, text, and `log/slog` path prints `[REDACTED]`.
- Empty strings and common placeholder literals (`changeme`, `your-token`, etc.) fail closed before any network call.
- Cross-host redirects strip the `Authorization` header and refuse HTTPS-to-HTTP downgrades.

## Usage

```go
rawToken, err := os.ReadFile("/run/secrets/concert_operator_token")
if err != nil {
	return err
}
tok, err := concert.NewValidatedSecret(string(rawToken))
if err != nil {
	return err
}

purger, err := concert.NewCachePurgeClient(concert.CachePurgeConfig{
	BaseURL:          "https://edge.example.com",
	Token:            tok,
	Timeout:          10 * time.Second,
	MaxResponseBytes: 64 << 10,
})
if err != nil {
	return err
}

ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

// 1. Purge one exact URL path
res, err := purger.PurgeURL(ctx, "shop.example.com", "/products/sneaker-01")
// 2. Purge by path prefix
res, err = purger.PurgePrefix(ctx, "shop.example.com", "/products/")
// 3. Purge by surrogate/cache tag
res, err = purger.PurgeTag(ctx, "shop.example.com", "drop-2026")
// 4. Purge all cached pages for a virtual host
res, err = purger.PurgeAll(ctx, "shop.example.com")
```

## Error Handling

Non-200 responses return `*concert.APIError` (`StatusCode`, `Message`) without echoing the Bearer token:

```go
var apiErr *concert.APIError
if errors.As(err, &apiErr) {
	log.Printf("purge rejected: status=%d reason=%s", apiErr.StatusCode, apiErr.Message)
}
```
