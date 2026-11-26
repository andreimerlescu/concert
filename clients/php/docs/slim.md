# Slim 4 Integration Guide

`Concert\Adapters\SlimAdapter` plugs directly into Slim 4's PSR-15 middleware stack to emit `Concert-Priority` headers on origin responses.

## 1. Install

```bash
composer require concert/concert-php
```

Or add the path repository in `composer.json` pointing to `clients/php`.

## 2. Register Middleware

```php
<?php
declare(strict_types=1);

use Concert\Adapters\SlimAdapter;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;

$app = AppFactory::create();

$app->add(new SlimAdapter(
    static function (ServerRequestInterface $request): array {
        $user = $request->getAttribute('user');
        $path = $request->getUri()->getPath();

        return [
            'staff'      => !empty($user['is_staff']),
            'checkout'   => str_starts_with($path, '/checkout'),
            'subscriber' => !empty($user['subscription_active']),
            'customer'   => !empty($user['has_orders']),
            'prospect'   => !empty($_SESSION['cart']),
            'member'     => !empty($user['id']),
        ];
    }
));

// Clear Concert-Priority rank on logout
$app->post('/logout', static function (ServerRequestInterface $req, ResponseInterface $res): ResponseInterface {
    session_destroy();
    return SlimAdapter::clearOnResponse($res->withStatus(302)->withHeader('Location', '/'));
});

$app->run();
```

## 3. Verify

Concert strips `Concert-Priority` before forwarding responses to browsers. Verify directly against the upstream PHP-FPM/Slim origin:

```bash
curl -s -D - -o /dev/null http://127.0.0.1:8000/checkout | grep -i concert-priority
# Concert-Priority: checkout; ttl=1800
```
