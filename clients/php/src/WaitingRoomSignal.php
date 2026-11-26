<?php
declare(strict_types=1);

namespace Concert;

use InvalidArgumentException;

/**
 * Parses Concert's explicit waiting-room signal headers:
 *   - X-Concert-Queue ("1")
 *   - X-Concert-Position (non-negative integer)
 *   - Retry-After (integer seconds or HTTP-date)
 *   - X-Concert-Status-Url (optional non-default status path)
 */
final class WaitingRoomSignal
{
    public const HEADER_QUEUE = 'x-concert-queue';
    public const HEADER_POSITION = 'x-concert-position';
    public const HEADER_RETRY_AFTER = 'retry-after';
    public const HEADER_STATUS_URL = 'x-concert-status-url';

    private bool $queued;
    private ?int $position;
    private ?int $retryAfterSeconds;
    private ?string $statusUrl;

    public function __construct(
        bool $queued,
        ?int $position = null,
        ?int $retryAfterSeconds = null,
        ?string $statusUrl = null
    ) {
        $this->queued = $queued;
        $this->position = $position;
        $this->retryAfterSeconds = $retryAfterSeconds;
        $this->statusUrl = $statusUrl;
    }

    /**
     * Parses a case-insensitive associative array of HTTP response headers.
     *
     * @param array<string, string|array<int, string>> $headers
     */
    public static function fromHeaders(array $headers, ?int $now = null): self
    {
        $norm = [];
        foreach ($headers as $k => $v) {
            $key = strtolower(trim((string) $k));
            if (is_array($v)) {
                $v = (string) ($v[0] ?? '');
            }
            $norm[$key] = trim((string) $v);
        }

        $q = strtolower($norm[self::HEADER_QUEUE] ?? '');
        $queued = $q === '1' || $q === 'true';

        $position = null;
        if (isset($norm[self::HEADER_POSITION]) && preg_match('/^\d+$/', $norm[self::HEADER_POSITION]) === 1) {
            $position = (int) $norm[self::HEADER_POSITION];
        }

        $retryAfter = null;
        if (isset($norm[self::HEADER_RETRY_AFTER]) && $norm[self::HEADER_RETRY_AFTER] !== '') {
            $rawRetry = $norm[self::HEADER_RETRY_AFTER];
            if (preg_match('/^\d+$/', $rawRetry) === 1) {
                $retryAfter = max(1, (int) $rawRetry);
            } else {
                $ts = strtotime($rawRetry);
                if ($ts !== false) {
                    $retryAfter = max(1, $ts - ($now ?? time()));
                }
            }
        }

        $statusUrl = null;
        if (isset($norm[self::HEADER_STATUS_URL]) && $norm[self::HEADER_STATUS_URL] !== '') {
            $candidate = $norm[self::HEADER_STATUS_URL];
            if (preg_match('/[\r\n\x00]/', $candidate) !== 1) {
                $statusUrl = $candidate;
            }
        }

        return new self($queued, $position, $retryAfter, $statusUrl);
    }

    /**
     * Parses headers from any PSR-7 ResponseInterface (duck-typed).
     */
    public static function fromResponse(object $response, ?int $now = null): self
    {
        if (!method_exists($response, 'getHeaders')) {
            throw new InvalidArgumentException('Response object must implement PSR-7 ResponseInterface::getHeaders().');
        }
        /** @var array<string, string|array<int, string>> $headers */
        $headers = $response->getHeaders();
        return self::fromHeaders($headers, $now);
    }

    public function isQueued(): bool
    {
        return $this->queued;
    }

    public function position(): ?int
    {
        return $this->position;
    }

    public function retryAfterSeconds(): ?int
    {
        return $this->retryAfterSeconds;
    }

    public function statusUrl(): ?string
    {
        return $this->statusUrl;
    }

    public function shouldBackoff(): bool
    {
        return $this->queued || $this->retryAfterSeconds !== null;
    }

    /**
     * @return array{queued: bool, position: ?int, retry_after_seconds: ?int, status_url: ?string}
     */
    public function toArray(): array
    {
        return [
            'queued'              => $this->queued,
            'position'            => $this->position,
            'retry_after_seconds' => $this->retryAfterSeconds,
            'status_url'          => $this->statusUrl,
        ];
    }
}
