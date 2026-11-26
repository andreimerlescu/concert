<?php
declare(strict_types=1);

namespace Concert\Middleware;

use Concert\PriorityHeader;
use InvalidArgumentException;

/**
 * PSR-15 compatible middleware that evaluates a caller-supplied fact resolver
 * for each incoming PSR-7 ServerRequestInterface and attaches the
 * Concert-Priority header to the outgoing PSR-7 ResponseInterface.
 *
 * Works with Slim 4, CakePHP 4/5, Laminas Mezzio, and any PSR-15 dispatcher
 * without forcing a hard vendor dependency on psr/http-server-middleware.
 */
final class PriorityMiddleware
{
    /** @var callable(object): array<string, mixed> */
    private $factsResolver;
    private ?int $ttlSeconds;
    private bool $emitGuest;

    /**
     * @param callable(object): array<string, mixed> $factsResolver Returns Concert rank facts keyed by rank name.
     * @param int|null                               $ttlSeconds    Optional TTL override (clamped 60..86400s).
     * @param bool                                   $emitGuest     Set true to emit "Concert-Priority: guest" (e.g. on logout routes).
     */
    public function __construct(callable $factsResolver, ?int $ttlSeconds = null, bool $emitGuest = false)
    {
        $this->factsResolver = $factsResolver;
        $this->ttlSeconds = $ttlSeconds;
        $this->emitGuest = $emitGuest;
    }

    /**
     * PSR-15 process($request, $handler) entrypoint.
     */
    public function process(object $request, object $handler): object
    {
        if (!method_exists($handler, 'handle')) {
            throw new InvalidArgumentException('Handler must implement PSR-15 RequestHandlerInterface::handle().');
        }

        $response = $handler->handle($request);
        $facts = ($this->factsResolver)($request);
        $rank = PriorityHeader::rank(is_array($facts) ? $facts : []);

        if ($rank === 'guest' && !$this->emitGuest) {
            return $response;
        }

        $ttl = $this->ttlSeconds ?? (PriorityHeader::DEFAULT_TTLS[$rank] ?? null);
        return PriorityHeader::withPriority($response, $rank, $ttl);
    }
}
