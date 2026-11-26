# Changelog — Concert for WordPress & WooCommerce

All notable changes to `clients/wordpress` are documented in this file.

## [0.3.0] - 2026-11-26

### Added
- Initial installable WordPress + WooCommerce plugin (`src/concert-wp.php` and OOP classes in `src/includes/`).
- `PriorityClassifier` setting `Concert-Priority` across `staff`, `checkout`, `subscriber`, `customer`, `prospect`, `member`, and `guest` ranks, plus logout rank clearing and waiting-room header parsing (`X-Concert-Queue`, `X-Concert-Position`, `Retry-After`).
- `CachePurger` executing authenticated `POST /_room/cache/purge` (`url`, `prefix`, `tag`, `all`) on `save_post`, `woocommerce_product_set_stock`, `woocommerce_update_product`, and manual Admin Bar clicks.
- `AdminBar` with strict `current_user_can('manage_options')` and `wp_verify_nonce()` protection, plus read-only diagnostics page that never echoes secret values.
- `Secret` redacting token container (`CONCERT_ADMIN_TOKEN` constant/env or `CONCERT_ADMIN_TOKEN_FILE` with `0600` permission checks) and `UrlValidator` enforcing HTTPS or loopback endpoints.
- Standalone PHP CLI test suite (`src/tests/run.php`) and complete documentation under `docs/`.
