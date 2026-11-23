# Running WordPress & WooCommerce Directly on `wpconcert` + PHP-FPM (Zero Caddy / Nginx / Apache)

`wpconcert` (built with `go build -tags wordpress ./cmd/wpconcert`, or included inside `econcert`) is Concert `v0.3.0`'s dedicated **complete front-door web server** for WordPress & WooCommerce hosts directly in front of `php-fpm`—with **zero** blockchain, gRPC, or enterprise mesh bloat.

```text
Internet (:80)   ──▶ wpconcert HTTP Redirect + ACME HTTP-01 (http_listen :80)
Internet (:443)  ──▶ wpconcert HTTPS (ACME/PEM, TLS 1.2/1.3, HTTP/2 + opt-in HTTP/3 QUIC)
                       ├─ Multi-vhost SNI & Host dispatch (Concertfile / .json, SIGHUP hot-reload)
                       ├─ Bans & scanners (/xmlrpc.php, /.env, /.git/*) ──▶ 429/403 (0 PHP load)
                       ├─ Static assets (/wp-content/*, /wp-includes/*, /robots.txt)
                       │    └─ internal/static (os.Root jail, .br/.gz sidecars, gzip, ETag, Range)
                       │         ──▶ served straight from disk (0 PHP-FPM load)
                       ├─ Anonymous GET micro-cache (internal/microcache, singleflight collapse)
                       │    └─ <1 ms cache hit + fresh concert_admit pass (0 PHP-FPM load)
                       │         (strictly bypassed on wordpress_logged_in_*, woocommerce_*, POST, /checkout)
                       ├─ Blocked PHP (/wp-content/uploads/*.php, /wp-config.php) ──▶ 403 (0 PHP load)
                       ├─ Missing *.php probes (/shell.php) ──▶ 404 (0 PHP load)
                       └─ Admitted dynamic pages, carts & checkout (capped to pm.max_children)
                            └─ internal/fcgi (try_files → index.php) ──▶ php-fpm Unix socket
```

---

## 0. One-Command Setup with `wpconcert init` & `wpconcert doctor`

Generate a `Concertfile` automatically sized to your server's local `php-fpm` `pm.max_children` pool:

```sh
wpconcert init --domain shop.example.com --root /var/www/shop --tls-email ops@example.com --http3 --out /etc/concert/Concertfile
wpconcert doctor --config /etc/concert/Concertfile
wpconcert -config /etc/concert/Concertfile
```

Example multi-site `/etc/concert/Concertfile` (reload cleanly with `kill -HUP $(pidof wpconcert)` or via the Portal **Reload config** button):

```text
{
    listen :443
    http_listen :80
    tls_email ops@example.com
    tls_cache /var/lib/concert/acme
    hsts_max_age 31536000
    http3 on
    data_dir /var/lib/concert/data
}

shop.example.com, www.shop.example.com {
    preset wordpress
    root /var/www/shop
    upstream fcgi+unix:///run/php/php8.3-fpm.sock
    cap 12
    priority_cap 4
    micro_cache 15s
    secure_cookie on
}

blog.example.com {
    preset wordpress
    root /var/www/blog
    upstream fcgi+unix:///run/php/php8.3-fpm-blog.sock
    cap 6
    micro_cache 30s
    secure_cookie on
}
```

> [!NOTE]
> **Security invariant:** Client cookies like `woocommerce_items_in_cart` and `wordpress_logged_in_*` trigger **micro-cache bypass** (so carts and logged-in users always hit fresh PHP through the waiting room), while **priority-lane promotion** remains strictly gated on the origin-signed `Concert-Priority` response header so attackers cannot forge cookies to jump the queue.

---

## 1. Why Concert + PHP-FPM Beats a Traditional Web Server Under Load

A small VPS running WordPress typically has 8–20 `php-fpm` workers (`pm.max_children`). Under a traffic spike or viral link:

- **Traditional web servers (Caddy / Nginx / Apache)** forward every request straight into `php-fpm` until workers saturate, CPU thrashes, MySQL stalls, and customers (including buyers mid-checkout) see `502`/`504` timeouts.
- **Concert + PHP-FPM**:
  1. Serves 80–95% of requests (CSS, JS, images, fonts, video) straight off disk through Go's `os.Root`-confined static engine—never waking a PHP worker—while keeping `/wp-content/*` and `/wp-includes/*` gated behind a valid `concert_admit` pass so un-admitted scrapers cannot flood bandwidth.
  2. Caps concurrent PHP executions strictly (`-cap + -priority-cap <= pm.max_children`) so `php-fpm` stays in its fast zone while excess visitors wait in an orderly FIFO waiting room with live position updates.
  3. Reserves a priority lane (`Concert-Priority`) so logged-in shoppers, carts, and WooCommerce `/checkout` bypass anonymous surges.
  4. Fast-rejects scanner probes (`/nonexistent.php` → `404`), blocks uploaded webshells (`/wp-content/uploads/*.php` → `403`), and auto-bans exploit scanners (`-ban-paths /xmlrpc.php,/.env,/.git/*`) before PHP ever runs.

---

## 2. Production `concert.env` for WordPress / WooCommerce

```sh
# ── Listeners & Automatic HTTPS ──────────────────────────────────────────────
CONCERT_LISTEN=:443
CONCERT_TLS_HTTP_LISTEN=:80
CONCERT_TLS_DOMAINS=shop.example.com,www.shop.example.com
CONCERT_TLS_EMAIL=ops@example.com
CONCERT_TLS_CACHE=/var/lib/concert/acme
CONCERT_HSTS_MAX_AGE=31536000
CONCERT_SECURE_COOKIE=true

# ── PHP-FPM FastCGI & Local Static Root ──────────────────────────────────────
CONCERT_UPSTREAM=fcgi+unix:///run/php-fpm/www.sock
CONCERT_STATIC_ROOT=/var/www/html
CONCERT_FCGI_INDEX=index.php
CONCERT_FCGI_DENY_PATHS=/wp-content/uploads/*,/wp-config.php
CONCERT_STATIC_CACHE_CONTROL="public, max-age=86400"
CONCERT_COMPRESS=true

# ── Waiting Room Sized to php-fpm pm.max_children ────────────────────────────
# Example: pm.max_children = 16 -> 12 waiting-room slots + 4 priority lane slots
CONCERT_CAPACITY=12
CONCERT_PRIORITY_CAP=4
CONCERT_PRIORITY_LANE_RANK=3
CONCERT_PRIORITY_FORMS=true
CONCERT_MAX_QUEUE=500

# ── WordPress Asset, Bypass & Abuse Rules ────────────────────────────────────
CONCERT_ASSETS=/wp-content/*,/wp-includes/*
CONCERT_ASSET_PUBLIC=/favicon.ico,/robots.txt,/sitemap.xml,/wp-sitemap.xml
# Keep payment webhooks and background cron out of the waiting room:
CONCERT_BYPASS=/wp-json/wc-stripe/*,/wc-api/*,/wp-cron.php
CONCERT_BAN_PATHS=/xmlrpc.php,/readme.html,/.env,/.git/*,/wp-config.php.bak

# ── Persistence, Secrets & Admin Portal ──────────────────────────────────────
CONCERT_DATA_DIR=/var/lib/concert/data
CONCERT_ADMIT_SECRET=<openssl rand -base64 48>
CONCERT_PORTAL_LISTEN=127.0.0.1:8081
CONCERT_PORTAL_ALLOW=127.0.0.1/32,::1/128
CONCERT_PORTAL_PASS=<openssl rand -hex 24>
```

> [!IMPORTANT]
> **Security invariant:** `-static-root`, `-static-mounts`, `-fcgi-deny-paths`, `-tls-http-listen`, and `fcgi+unix://` socket paths are locked to flags and `CONCERT_*` environment variables—they cannot be changed from the Admin Portal HTTP UI.

---

## 3. Sizing `php-fpm` (`pm.max_children`) vs Concert (`-cap`)

Always keep `CONCERT_CAPACITY + CONCERT_PRIORITY_CAP <= pm.max_children` so `php-fpm` never queues behind saturated workers or triggers OOM kills:

| Small Host RAM | Typical WP PHP Worker RSS | `pm.max_children` (`pm = static`) | Recommended `-cap` | Recommended `-priority-cap` |
| --- | --- | --- | --- | --- |
| 1 GB VPS | ~60 MB | `8` | `6` | `2` |
| 2 GB VPS | ~65 MB | `16` | `12` | `4` |
| 4 GB VPS | ~75 MB | `32` | `24` | `8` |

You can measure the true sustainable concurrency of your exact plugins/theme with Concert's built-in benchmark:

```sh
concert bench -target https://shop.example.com/ -data-dir /var/lib/concert/data
```

---

## 4. WordPress & WooCommerce Integration Tips

### A. HTTPS detection in `wp-config.php`
Concert sets `HTTPS=on` and `X-Forwarded-Proto: https` automatically in FastCGI `FCGI_PARAMS`, so WordPress's built-in `is_ssl()` works out of the box.

### B. Priority Checkout & Customer Grants (`mu-plugin`)
Drop a tiny file at `/var/www/html/wp-content/mu-plugins/concert-priority.php` so paying shoppers and staff receive signed `Concert-Priority` grants (stripped before reaching the browser):

```php
<?php
add_action('send_headers', function () {
    if (is_user_logged_in() && current_user_can('manage_options')) {
        header('Concert-Priority: staff');
        return;
    }
    if (function_exists('is_checkout') && (is_checkout() || is_cart())) {
        header('Concert-Priority: checkout');
        return;
    }
    if (is_user_logged_in()) {
        header('Concert-Priority: customer');
    }
});
```

### C. Precompress Static Theme & Plugin Assets (Zero-CPU Brotli/Gzip)
Concert automatically serves `.br` (preferred) and `.gz` sidecars alongside static files in `-static-root` whenever a client sends `Accept-Encoding: br, gzip` (and falls back to on-the-fly stdlib `gzip` for files ≥ 1 KiB when no sidecar exists):

```sh
find /var/www/html/wp-content -type f \( -name '*.css' -o -name '*.js' -o -name '*.svg' \) -exec gzip -9 -k -f {} +
```

---

## 5. Systemd, Socket Permissions & SELinux

1. **Bind ports 80 & 443 without running as root:** Add `AmbientCapabilities=CAP_NET_BIND_SERVICE` and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` to `concert.service`.
2. **PHP-FPM Unix socket permissions:** Add the `concert` service user to the PHP-FPM socket group (`SupplementaryGroups=www-data` on Debian/Ubuntu or `SupplementaryGroups=apache` on RHEL/Alma/Rocky) and verify `listen.mode = 0660` in `/etc/php-fpm.d/www.conf`.
3. **Read-only access to WordPress files:** Concert only needs read/execute traversal (`0755` dirs, `0644` files) on `/var/www/html`. On SELinux-enforcing RHEL/Rocky/Fedora hosts, keep `/var/www/html` labeled `httpd_sys_content_t` and grant the confined Concert policy read access to `httpd_sys_content_t` and stream-connect access to `httpd_var_run_t` (the PHP-FPM socket).
4. **Static file security guarantees built into Concert:**
   - Every static root and mount is opened with Go's `os.OpenRoot`, preventing `../` path traversal and symlink escapes out of `/var/www/html`.
   - Dotfiles (`.env`, `.htaccess`, `.git/*`), directory listings, and dangerous extensions (`.php*`, `.sql`, `.bak`, `.log`, `.ini`, `.conf`, `.key`, `.pem`) are hard-blocked from disk serving.
   - Missing files under `-assets` or `-static-mounts` return a fast `404` without waking `php-fpm` (opt in to `-static-fallback=true` only if an app generates assets dynamically on 404).
