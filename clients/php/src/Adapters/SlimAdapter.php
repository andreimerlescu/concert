<?php
declare(strict_types=1);

namespace Concert\Adapters;

use Concert\Middleware\PriorityMiddleware;
use Concert\PriorityHeader;

/**
 * Slim 4 PSR-15 middleware adapter for Concert-Priority.
 *
 * Register via:
 *   $app->add(new \Concert\Adapters\SlimAdapter(fn($req) => [...]));
 */
final class SlimAdapter
{
    private PriorityMiddleware $middleware;

    /**
     * @param callable(object): array<string, mixed> $factsResolver
     */
    public function __construct(callable $factsResolver, ?int $ttlSeconds = null, bool $emitGuest = false)
    {
        $this->middleware = new PriorityMiddleware($factsResolver, $ttlSeconds, $emitGuest);
    }

    /**
     * Slim 4 supports callable middleware with ($request, $handler) signature.
     */
    public function __invoke(object $request, object $handler): object
    {
        return $this->middleware->process($request, $handler);
    }

    /**
     * PSR-15 process() entrypoint.
     */
    public function process(object $request, object $handler): object
    {
        return $this->middleware->process($request, $handler);
    }

    /**
     * Helper for Slim logout routes to emit "Concert-Priority: guest".
     *
     * @template T of object
     * @param T $response
     * @return T
     */
    public static function clearOnResponse(object $response): object
    {
        return PriorityHeader::withPriority($response, 'guest');
    }
}
