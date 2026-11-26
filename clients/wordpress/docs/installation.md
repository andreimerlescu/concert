# Installation & Configuration

## Requirements

- WordPress 6.0+ (WooCommerce 7.0+ optional for checkout/cart/stock hooks)
- PHP 8.1+
- `wpconcert` or `concert` / `econcert` sitting in front of WordPress

## Install the Plugin

1. Copy `clients/wordpress/src/` into `wp-content/plugins/concert-wp/`:

```bash
cp -R clients/wordpress/src /var/www/html/wp-content/plugins/concert-wp
```

Or create a ZIP archive of `src/` and upload it in **WP Admin → Plugins → Add New → Upload Plugin**.

2. Activate **Concert Waiting Room & Cache for WordPress** from **WP Admin → Plugins** or via WP-CLI:

```bash
wp plugin activate concert-wp
```

## Configure Concert Endpoint & Admin Token

For active cache purging (`POST /_room/cache/purge`), supply the endpoint URL and operator/admin Bearer token via runtime configuration outside the WordPress database.

### Option A: Secret File (Recommended)

Provision a `0600`-mode secret file readable only by the PHP-FPM user (for example via systemd `LoadCredential`, Docker/Kubernetes Secrets, or root-owned deployment tooling):

```bash
sudo install -m 0600 -o www-data -g www-data /dev/null /run/secrets/concert_admin_token
# Populate /run/secrets/concert_admin_token without placing the token in shell history.
```

Then point WordPress to the file path in `wp-config.php`:

```php
define('CONCERT_ENDPOINT_URL', 'https://127.0.0.1:8080');
define('CONCERT_ADMIN_TOKEN_FILE', '/run/secrets/concert_admin_token');
```

### Option B: PHP-FPM Environment Variables

In your PHP-FPM pool configuration (e.g. `/etc/php/8.3/fpm/pool.d/www.conf`):

```ini
env[CONCERT_ENDPOINT_URL] = "http://127.0.0.1:8080"
env[CONCERT_ADMIN_TOKEN_FILE] = "/run/secrets/concert_admin_token"
```

### Option C: `CONCERT_ADMIN_TOKEN` Constant or Env Var

```php
// wp-config.php (outside webroot, chmod 0600, never committed to VCS)
define('CONCERT_ENDPOINT_URL', 'https://edge.example.com');
define('CONCERT_ADMIN_TOKEN', getenv('CONCERT_ADMIN_TOKEN') ?: '');
```

> **Note:** `http://` is permitted **only** for loopback targets (`localhost`, `127.0.0.1`, `::1`). Remote Concert endpoints must use `https://`.

## Verify Installation

1. Open **WP Admin → Settings → Concert** and confirm:
   - **Endpoint URL** shows your normalized Concert address.
   - **Admin Bearer Token** shows `Configured (constant:...)`, `Configured (file:...)`, or `Configured (env:...)`.
2. Verify `Concert-Priority` is emitted on origin responses (Concert strips this header before sending to browsers):

```bash
curl -s -D - -o /dev/null http://127.0.0.1:9000/ | grep -i concert-priority
```
