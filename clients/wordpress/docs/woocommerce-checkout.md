# WooCommerce Checkout Protection

When traffic surges during a flash sale or product drop, Concert keeps PHP-FPM and MariaDB/MySQL healthy by queuing excess arrivals in the waiting room while letting high-intent shoppers finish checkout uninterrupted.

## Automatic Priority Classification

On every page response (`send_headers`), `PriorityClassifier` inspects the WordPress and WooCommerce session state and emits a single `Concert-Priority` header. Concert strips this header before the response reaches the browser and records the rank in a signed `concert_priority` cookie bound to the visitor's `concert_admit` pass.

| Rank | WordPress / WooCommerce Condition | Default TTL |
|---|---|---|
| `staff` | User has `manage_options`, `edit_others_posts`, or `manage_woocommerce` | 8 hours |
| `checkout` | `is_checkout()` or `is_checkout_pay_page()` | 30 minutes |
| `subscriber` | Active WooCommerce Subscription (`wcs_user_has_subscription`) | 8 hours |
| `customer` | Logged-in user with at least one prior order (`wc_get_customer_order_count() > 0`) | 8 hours |
| `prospect` | Non-empty WooCommerce cart, or viewing cart / product / shop pages | 30 minutes |
| `member` | Logged-in WordPress user (`is_user_logged_in()`) | 8 hours |
| `guest` | Anonymous visitor (no header sent; emitted as `guest` on `wp_logout` to clear grants) | — |

The highest matching rank always wins (`staff > checkout > subscriber > customer > prospect > member > guest`).

## Recommended Concert Settings

Configure `wpconcert` so `customer` and above enter the priority lane while `prospect` and `member` queue ahead of anonymous guests:

```bash
wpconcert \
  -priority-lane-rank=3 \
  -priority-cap=16 \
  -priority-forms=true
```

Enabling `-priority-forms=true` ensures WooCommerce checkout `POST` submissions (`/?wc-ajax=checkout`) from visitors holding a valid admission pass use the priority lane instead of being intercepted by the HTML waiting room.

## Respecting Waiting-Room Signal Headers

If custom WordPress code, webhooks, or server-to-server background workers call a Concert-fronted endpoint, use `PriorityClassifier::parseWaitingRoomHeaders()` to detect `X-Concert-Queue`, `X-Concert-Position`, `Retry-After`, and `X-Concert-Status-Url`:

```php
$response = wp_remote_get('https://api.example.com/inventory');
$signal = \Concert\WordPress\PriorityClassifier::parseWaitingRoomHeaders(
    wp_remote_retrieve_headers($response)->getAll()
);

if ($signal['queued']) {
    // Back off for $signal['retry_after'] seconds instead of hammering the queue.
    $delay = $signal['retry_after'] ?? 5;
}
```
