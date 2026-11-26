# Zend Framework / Laminas Integration Guide

`Concert\Adapters\LaminasAdapter` supports both **Laminas Mezzio** (PSR-15) and **Laminas MVC / Zend Framework 3** (`Laminas\Http\Response`).

## Option A: Laminas Mezzio (PSR-15)

Register the adapter in `config/pipeline.php` after authentication middleware:

```php
<?php
declare(strict_types=1);

use Concert\Adapters\LaminasAdapter;
use Mezzio\Authentication\UserInterface;
use Psr\Http\Message\ServerRequestInterface;

$app->pipe(new LaminasAdapter(
    static function (ServerRequestInterface $request): array {
        /** @var UserInterface|null $user */
        $user = $request->getAttribute(UserInterface::class);
        $roles = $user ? iterator_to_array($user->getRoles()) : [];

        return [
            'staff'      => in_array('admin', $roles, true) || in_array('operator', $roles, true),
            'checkout'   => str_starts_with($request->getUri()->getPath(), '/checkout'),
            'subscriber' => in_array('subscriber', $roles, true),
            'customer'   => in_array('customer', $roles, true),
            'member'     => $user !== null,
        ];
    }
));
```

## Option B: Laminas MVC / Zend Framework 3

Attach an `MvcEvent::EVENT_FINISH` listener in `module/Application/src/Module.php`:

```php
<?php
declare(strict_types=1);

namespace Application;

use Concert\Adapters\LaminasAdapter;
use Laminas\Mvc\MvcEvent;

class Module
{
    public function onBootstrap(MvcEvent $e): void
    {
        $eventManager = $e->getApplication()->getEventManager();
        $eventManager->attach(MvcEvent::EVENT_FINISH, static function (MvcEvent $event): void {
            $response = $event->getResponse();
            $auth = $event->getApplication()->getServiceManager()->get('AuthService');
            $identity = $auth->hasIdentity() ? $auth->getIdentity() : null;

            LaminasAdapter::applyToResponse($response, [
                'staff'      => !empty($identity['is_staff']),
                'subscriber' => !empty($identity['subscription_active']),
                'customer'   => !empty($identity['has_orders']),
                'member'     => $identity !== null,
            ]);
        }, 100);
    }
}
```
