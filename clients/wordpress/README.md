# Concert for WordPress & WooCommerce

Official WordPress and WooCommerce integration plugin for [Concert](../../README.md) (`wpconcert` and `concert-cache`).

## Features

- **Automatic `Concert-Priority` classification**: Sets the `Concert-Priority` origin response header (`staff`, `checkout`, `subscriber`, `customer`, `prospect`, `member`, `guest`) based on WordPress roles and WooCommerce cart/checkout/order/subscription state, and clears the rank on logout.
- **Waiting-room signal awareness**: Inspects `X-Concert-Queue`, `X-Concert-Position`, and `Retry-After` headers when WordPress communicates with Concert-fronted APIs or loops back through Concert.
- **Active cache purging (`POST /_room/cache/purge`)**: Automatically purges `wpconcert` / `concert-cache` entries (`url`, `prefix`, `tag`, `all`) on `save_post`, `woocommerce_product_set_stock`, and `woocommerce_update_product`, plus an Admin Bar **Purge Concert Cache** action.
- **Security-first secret handling (`S1`–`S9`)**:
  - Reads the admin Bearer token **exclusively** from the `CONCERT_ADMIN_TOKEN` PHP constant, `CONCERT_ADMIN_TOKEN_FILE` (mode `0600`), or the `CONCERT_ADMIN_TOKEN` environment variable.
  - Never stores secrets in `wp_options`, never echoes tokens into HTML forms, and never exposes tokens to browser JavaScript.
  - Enforces strict `wp_verify_nonce()` + `current_user_can('manage_options')` checks and HTTPS-or-loopback endpoint validation.

## Quick Start

1. Copy `src/` into `wp-content/plugins/concert-wp/` (or zip `src/` and upload via **Plugins → Add New → Upload Plugin**).
2. Define your Concert endpoint and admin token in `wp-config.php` (never commit secrets to version control):

```php
define('CONCERT_ENDPOINT_URL', 'https://127.0.0.1:8080');
// Preferred: load from a 0600 secret file managed by systemd/Docker/K8s:
define('CONCERT_ADMIN_TOKEN_FILE', '/run/secrets/concert_admin_token');
// Or pass via environment variable CONCERT_ADMIN_TOKEN (set in PHP-FPM pool).
```

3. Activate **Concert Waiting Room & Cache for WordPress** in **WP Admin → Plugins**.

## Running Standalone Tests

Tests run directly with the PHP 8.1+ CLI without requiring WordPress core:

```bash
php clients/wordpress/src/tests/run.php
```

## Documentation

- [Installation & Configuration](docs/installation.md)
- [WooCommerce Checkout Protection](docs/woocommerce-checkout.md)
- [Active Cache Purge Setup](docs/cache-purge.md)
- [Security Architecture](docs/security.md)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
