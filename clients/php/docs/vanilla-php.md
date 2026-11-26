# Vanilla PHP Integration Guide

`Concert\Adapters\VanillaPhpAdapter` is the drop-in OOP replacement for the deprecated root [`concert.php`](../../../concert.php) snippet.

## Usage

Call `sync()` after `session_start()` and before sending any HTML output:

```php
<?php
declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';

use Concert\Adapters\VanillaPhpAdapter;

session_start();

$concert = new VanillaPhpAdapter();
$now = time();

if (basename($_SERVER['SCRIPT_NAME'] ?? '') === 'buy.php') {
    $_SESSION['concert_prospect_until'] = $now + 1800;
}

$concert->sync([
    'staff'      => !empty($_SESSION['is_staff']),
    'checkout'   => ($_SESSION['checkout_started_at'] ?? 0) > $now - 1800,
    'subscriber' => !empty($_SESSION['subscription_active']),
    'customer'   => !empty($_SESSION['purchase_ids']),
    'prospect'   => ($_SESSION['concert_prospect_until'] ?? 0) > $now || !empty($_SESSION['cart']),
    'member'     => !empty($_SESSION['user_id']),
], $_SESSION);
```

## Logout

Clear the signed rank cookie before destroying the PHP session:

```php
$concert->clear($_SESSION);
session_destroy();
```

## Verify Locally

```bash
curl -s -D - -o /dev/null http://127.0.0.1:8080/index.php | grep -i concert-priority
```
