# Concert PHP SDK (`concert/concert-php`)

Official Composer-ready PSR-7/PSR-15 PHP 8.1+ SDK for [Concert](../../README.md).

Concert is **100% open-source (Apache-2.0)** and **100% crypto-only** (`xrpl`, `stellar`, `hedera`, `solana`).

## Features

- **`Concert\PriorityHeader`**: Computes visitor ranks (`guest`, `member`, `prospect`, `customer`, `subscriber`, `checkout`, `staff`), formats/parses `Concert-Priority` headers with clamped TTL (`60`–`86400`s), and attaches headers to native PHP or PSR-7 responses.
- **`Concert\Rm1Signer`**: Mints and verifies stateless Ed25519 `rm1` VIP pass (`X-Room-Pass`) and lease (`X-Room-Lease`) envelopes using PHP's built-in `ext-sodium` (`sodium_crypto_sign_detached`), byte-for-byte compatible with Concert's `room v1.9.0` verify-only replicas.
- **`Concert\CachePurgeClient`**: Calls Concert's authenticated `POST /_room/cache/purge` API (`url`, `prefix`, `tag`, `all`) with strict TLS verification, HTTPS-or-loopback endpoint validation, and redacting `Secret` Bearer credentials.
- **`Concert\WaitingRoomSignal`**: Parses `X-Concert-Queue`, `X-Concert-Position`, `Retry-After`, and `X-Concert-Status-Url` from PSR-7 responses or header arrays.
- **`Concert\AgentBidClient`**: Crypto-only (`xrpl`, `stellar`, `hedera`, `solana`) client for Concert's non-custodial AI agent pass bidding endpoints (`POST /_concert/bids` and `GET /_concert/bids/status`) with client-side `maxBidMicroUsd` budget guards.
- **Framework Adapters**: Ready-to-use adapters and guides for **Slim 4**, **CakePHP**, **Zend/Laminas**, **Invision Power Board (IPB)**, **phpBB**, and **vanilla PHP**.

## Quick Start

```php
<?php
declare(strict_types=1);

use Concert\CachePurgeClient;
use Concert\PriorityHeader;
use Concert\Rm1Signer;
use Concert\Secret;

// 1. Emit Concert-Priority for the current visitor
$rank = PriorityHeader::rank([
    'staff'      => !empty($_SESSION['is_staff']),
    'checkout'   => !empty($_SESSION['checkout_active']),
    'subscriber' => !empty($_SESSION['sub_active']),
    'customer'   => !empty($_SESSION['order_count']),
    'prospect'   => !empty($_SESSION['cart_items']),
    'member'     => !empty($_SESSION['user_id']),
]);
PriorityHeader::send($rank, 1800);

// 2. Mint an Ed25519 rm1 VIP pass for multi-replica verify-only Concert edges
$signer = Rm1Signer::fromSecretKey('k1', Secret::fromFile('/run/secrets/concert_ed25519_key'));
$passToken = $signer->mintPass('shop.example.com', 'user:42', 300);

// 3. Actively purge Concert's page cache
$purger = new CachePurgeClient('https://127.0.0.1:8080', Secret::fromEnv('CONCERT_ADMIN_TOKEN'));
$purger->purgeUrl('/products/concert-pass', 'shop.example.com');
```

## Running Standalone Tests

```bash
php clients/php/src/Tests/run.php
```

## Framework Guides & Documentation

- [Slim 4 Integration](docs/slim.md)
- [CakePHP Integration](docs/cakephp.md)
- [Zend / Laminas Integration](docs/laminas.md)
- [Invision Power Board (IPB) Integration](docs/invision-ipb.md)
- [phpBB Integration](docs/phpbb.md)
- [Vanilla PHP Integration](docs/vanilla-php.md)
- [Ed25519 `rm1` Signing, Cache Purge, Signals & Crypto Bidding](docs/rm1-and-bidding.md)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
