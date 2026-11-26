<?php
declare(strict_types=1);

namespace Concert\Adapters;

use Concert\Middleware\PriorityMiddleware;
use Concert\PriorityHeader;
use InvalidArgumentException;

/**
 * Zend / Laminas adapter supporting both:
 *   1. Laminas Mezzio (PSR-15 middleware via process($request, $handler))
 *   2. Laminas MVC / Zend Framework 3 (Laminas\Http\Response header attachment)
 */
final class LaminasAdapter
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
     * Mezzio / PSR-15 pipeline entrypoint.
     */
    public function process(object $request, object $handler): object
    {
        return $this->middleware->process($request, $handler);
    }

    /**
     * Laminas MVC / Zend Framework helper attaching Concert-Priority onto a
     * Laminas\Http\Response (which exposes getHeaders()->addHeaderLine()) or
     * a PSR-7 ResponseInterface.
     *
     * @param array<string, mixed> $facts
     */
    public static function applyToResponse(object $response, array $facts, ?int $ttlSeconds = null, bool $emitGuest = false): object
    {
        $rank = PriorityHeader::rank($facts);
        if ($rank === 'guest' && !$emitGuest) {
            return $response;
        }
        $ttl = $ttlSeconds ?? (PriorityHeader::DEFAULT_TTLS[$rank] ?? null);
        $headerVal = PriorityHeader::format($rank, $ttl);

        if (method_exists($response, 'withHeader')) {
            return $response->withHeader(PriorityHeader::HEADER_NAME, $headerVal);
        }

        if (method_exists($response, 'getHeaders')) {
            $headers = $response->getHeaders();
            if (is_object($headers) && method_exists($headers, 'addHeaderLine')) {
                $headers->addHeaderLine(PriorityHeader::HEADER_NAME, $headerVal);
                return $response;
            }
        }

        throw new InvalidArgumentException('Unsupported Laminas/PSR-7 response object.');
    }
}
