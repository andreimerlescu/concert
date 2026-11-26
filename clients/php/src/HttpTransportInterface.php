<?php
declare(strict_types=1);

namespace Concert;

/**
 * Minimal HTTP transport abstraction so SDK clients work with zero third-party
 * dependencies and remain deterministically testable.
 */
interface HttpTransportInterface
{
    /**
     * Executes an HTTP request with TLS verification enabled and redirects disabled.
     *
     * @param array<string, string> $headers
     * @return array{status: int, headers: array<string, string>, body: string, error?: string}
     */
    public function send(
        string $method,
        string $url,
        array $headers = [],
        ?string $body = null,
        int $timeoutSeconds = 5
    ): array;
}
