# Active Cache Purge Setup

`wpconcert` and external `concert-cache` daemons expose an authenticated active purge endpoint:

```http
POST /_room/cache/purge
Authorization: Bearer <operator-or-admin-token>
Content-Type: application/json

{"mode":"url"|"prefix"|"tag"|"all","host":"shop.example.com","target":"/product/concert-tee/"}
```

## Automatic WordPress & WooCommerce Purges

The plugin automatically calls `POST /_room/cache/purge` when content or inventory changes:

| WordPress / WooCommerce Hook | Purge Actions |
|---|---|
| `save_post` (published posts only; skips autosaves & revisions) | `url` (post permalink path), `url` (`/`), `tag` (`post:<id>`) |
| `woocommerce_product_set_stock` | `url` (product permalink path), `prefix` (`/shop/`), `tag` (`product:<id>`) |
| `woocommerce_update_product` | `url` (product permalink path), `prefix` (`/shop/`), `tag` (`product:<id>`) |

## Manual Purge from the WP Admin Bar

Users with the `manage_options` capability see a **Purge Concert Cache** button in the top WordPress Admin Bar. Clicking it sends a nonce-protected request to `admin-post.php?action=concert_purge_cache&mode=all&_wpnonce=...`, which triggers `{"mode":"all","host":"<site-host>","target":""}` server-side and redirects safely back to the current screen.

## Programmatic Purges

You can also invoke `CachePurger` directly from custom plugins or WP-CLI commands:

```php
$purger = new \Concert\WordPress\CachePurger(
    CONCERT_ENDPOINT_URL,
    \Concert\WordPress\Secret::fromEnvironment(),
    'shop.example.com'
);

$purger->purgeUrl('/drop/spring-2026/');
$purger->purgePrefix('/category/releases/');
$purger->purgeTag('product:42');
$purger->purgeAll();
```

## Concert Token Permissions

Ensure the Bearer token supplied via `CONCERT_ADMIN_TOKEN_FILE` or `CONCERT_ADMIN_TOKEN` belongs to a Concert principal with at least the `operator` role (required by `POST /_room/cache/purge`).
