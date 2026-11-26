# Ed25519 `rm1` Signing, Active Cache Purge, Signals & Crypto Agent Bidding

## 1. Stateless Ed25519 `rm1` VIP Passes & Leases (`Rm1Signer`)

In multi-replica Concert deployments (`-room-verify-keys="k1=<base64url-pubkey>"`), serving replicas stay verify-only while your PHP checkout or control plane mints short-lived `rm1` tokens with `ext-sodium`:

```php
<?php
declare(strict_types=1);

use Concert\Rm1Signer;
use Concert\Secret;

// Load 32-byte seed or 64-byte Ed25519 private key from a chmod 0600 file:
$signer = Rm1Signer::fromSecretKey('k1', Secret::fromFile('/run/secrets/concert_rm1_ed25519'));

// Print "<kid>=<base64url-pubkey>" for Concert's -room-verify-keys flag:
echo $signer->verifyKeySpec() . PHP_EOL;

// Mint a 5-minute VIP pass (sent via X-Room-Pass header or room_pass cookie):
$pass = $signer->mintPass(scope: 'shop.example.com', clientKey: '', ttlSeconds: 300);

// Mint a key-bound signed lease (sent via X-Room-Lease header):
$lease = $signer->mintLease(scope: 'api.example.com', clientKey: 'agent:42', ttlSeconds: 180);
```

Wire format matches `github.com/andreimerlescu/room` v1.9.0 byte-for-byte:

```text
rm1.<base64url(json({"kid","kind","scope","key"?,"iat","exp"}))>.<base64url(ed25519_sig)>
```

## 2. Active Cache Purging (`CachePurgeClient`)

```php
<?php
declare(strict_types=1);

use Concert\CachePurgeClient;
use Concert\Secret;

$purger = new CachePurgeClient(
    endpoint: 'https://127.0.0.1:8080',
    adminToken: Secret::fromFile('/run/secrets/concert_admin_token')
);

$purger->purgeUrl('/products/limited-drop', 'shop.example.com');
$purger->purgePrefix('/products/', 'shop.example.com');
$purger->purgeTag('product:42', 'shop.example.com');
$purger->purgeAll('shop.example.com');
```

## 3. Waiting-Room Signal Parsing (`WaitingRoomSignal`)

```php
<?php
declare(strict_types=1);

use Concert\WaitingRoomSignal;

$signal = WaitingRoomSignal::fromResponse($psrResponse);
if ($signal->isQueued()) {
    $waitSeconds = $signal->retryAfterSeconds() ?? 5;
    $position = $signal->position();
    $statusPath = $signal->statusUrl() ?? '/queue/status';
}
```

## 4. 100% Crypto-Only AI Agent Pass Bidding (`AgentBidClient`)

Concert's non-custodial pass bidding supports **crypto-only** rails: `xrpl`, `stellar`, `hedera`, and `solana`. Submitted payment authorizations are verified off-chain; **only winning bids settle on-chain** (losers pay `$0`).

```php
<?php
declare(strict_types=1);

use Concert\AgentBidClient;

// Enforce a strict $5.00 (5_000_000 micro-USD) client-side ceiling:
$bidding = new AgentBidClient(
    endpoint: 'https://api.example.com',
    maxBidMicroUsd: 5_000_000
);

$submit = $bidding->submitBid(
    chain: 'solana',
    asset: 'USDC',
    amountAtomic: '2500000',
    paymentPayload: $signedX402Payload,
    options: [
        'scope'               => 'api.example.com',
        'estimated_micro_usd' => 2_500_000,
    ]
);

if ($submit['ok'] && !$submit['pass_issued']) {
    // Poll GET /_concert/bids/status?bid_id=... until epoch clears:
    $status = $bidding->getBidStatus($submit['bid_id']);
    if ($status['pass_issued']) {
        $priorityPass = $status['priority_pass'];
    }
}
```
