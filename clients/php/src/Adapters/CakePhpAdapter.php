<?php
declare(strict_types=1);

namespace Concert\Adapters;

use Concert\Middleware\PriorityMiddleware;
use Concert\PriorityHeader;

/**
 * CakePHP 4/5 PSR-15 middleware adapter for Concert-Priority.
 *
 * Reads CakePHP's authentication `identity` request attribute (if present) or
 * invokes a custom fact resolver, and attaches Concert-Priority to the response.
 */
final class CakePhpAdapter
{
    private PriorityMiddleware $middleware;

    /**
     * @param callable(object): array<string, mixed>|null $factsResolver Optional custom resolver.
     * @param array<int, string>                          $staffRoles    Identity roles treated as 'staff'.
     */
    public function __construct(
        ?callable $factsResolver = null,
        array $staffRoles = ['admin', 'staff', 'operator'],
        ?int $ttlSeconds = null
    ) {
        $resolver = $factsResolver ?? static function (object $request) use ($staffRoles): array {
            $identity = method_exists($request, 'getAttribute') ? $request->getAttribute('identity') : null;
            $session = method_exists($request, 'getAttribute') ? $request->getAttribute('session') : null;

            $isMember = $identity !== null;
            $isStaff = false;
            $isSubscriber = false;
            $isCustomer = false;

            if (is_object($identity) && method_exists($identity, 'get')) {
                $role = strtolower((string) $identity->get('role'));
                $isStaff = in_array($role, $staffRoles, true) || !empty($identity->get('is_staff'));
                $isSubscriber = !empty($identity->get('subscription_active'));
                $isCustomer = !empty($identity->get('has_orders')) || ((int) $identity->get('order_count')) > 0;
            } elseif (is_array($identity)) {
                $role = strtolower((string) ($identity['role'] ?? ''));
                $isStaff = in_array($role, $staffRoles, true) || !empty($identity['is_staff']);
                $isSubscriber = !empty($identity['subscription_active']);
                $isCustomer = !empty($identity['has_orders']) || ((int) ($identity['order_count'] ?? 0)) > 0;
            }

            $isCheckout = false;
            $isProspect = false;
            if (is_object($session) && method_exists($session, 'read')) {
                $isCheckout = !empty($session->read('Concert.checkout_active'));
                $isProspect = !empty($session->read('Concert.cart_count'));
            }

            return [
                'staff'      => $isStaff,
                'checkout'   => $isCheckout,
                'subscriber' => $isSubscriber,
                'customer'   => $isCustomer,
                'prospect'   => $isProspect,
                'member'     => $isMember,
            ];
        };

        $this->middleware = new PriorityMiddleware($resolver, $ttlSeconds, false);
    }

    public function process(object $request, object $handler): object
    {
        return $this->middleware->process($request, $handler);
    }

    /**
     * @template T of object
     * @param T $response
     * @return T
     */
    public static function clearOnResponse(object $response): object
    {
        return PriorityHeader::withPriority($response, 'guest');
    }
}
