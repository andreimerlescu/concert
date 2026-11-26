# CakePHP 4 / 5 Integration Guide

`Concert\Adapters\CakePhpAdapter` integrates with CakePHP's PSR-15 `MiddlewareQueue` and Authentication plugin (`$request->getAttribute('identity')`).

## 1. Register in `src/Application.php`

Place `CakePhpAdapter` **after** `AuthenticationMiddleware` so the authenticated `identity` attribute is populated on the request:

```php
<?php
declare(strict_types=1);

namespace App;

use Authentication\Middleware\AuthenticationMiddleware;
use Cake\Http\BaseApplication;
use Cake\Http\MiddlewareQueue;
use Concert\Adapters\CakePhpAdapter;

class Application extends BaseApplication
{
    public function middleware(MiddlewareQueue $middlewareQueue): MiddlewareQueue
    {
        $middlewareQueue
            ->add(new AuthenticationMiddleware($this))
            ->add(new CakePhpAdapter(
                factsResolver: null, // uses identity + Concert.* session keys automatically
                staffRoles: ['admin', 'staff', 'operator']
            ));

        return $middlewareQueue;
    }
}
```

## 2. Optional Custom Facts Resolver

```php
$middlewareQueue->add(new CakePhpAdapter(
    factsResolver: static function ($request): array {
        $identity = $request->getAttribute('identity');
        $session = $request->getAttribute('session');
        return [
            'staff'      => $identity && $identity->get('role') === 'admin',
            'checkout'   => (bool) $session->read('Checkout.active'),
            'subscriber' => $identity && (bool) $identity->get('plan_active'),
            'customer'   => $identity && ((int) $identity->get('orders_count') > 0),
            'prospect'   => ((int) $session->read('Cart.count')) > 0,
            'member'     => $identity !== null,
        ];
    }
));
```

## 3. Clear Rank on Logout

In your `UsersController::logout()`:

```php
$this->Authentication->logout();
return CakePhpAdapter::clearOnResponse($this->redirect(['action' => 'login']));
```
