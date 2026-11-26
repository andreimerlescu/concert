<?php
declare(strict_types=1);

namespace Concert;

use InvalidArgumentException;

/**
 * Computes, formats, parses, and attaches Concert's Concert-Priority response header.
 *
 * Ranks (lowest to highest, matching internal/server/priority.go):
 *   guest < member < prospect < customer < subscriber < checkout < staff
 */
final class PriorityHeader
{
    public const HEADER_NAME = 'Concert-Priority';
    public const MIN_TTL_SECONDS = 60;
    public const MAX_TTL_SECONDS = 86400;

    public const RANKS = [
        'guest',
        'member',
        'prospect',
        'customer',
        'subscriber',
        'checkout',
        'staff',
    ];

    public const DEFAULT_TTLS = [
        'guest'      => null,
        'member'     => 28800,
        'prospect'   => 1800,
        'customer'   => 28800,
        'subscriber' => 28800,
        'checkout'   => 1800,
        'staff'      => 28800,
    ];

    /**
     * Returns the highest rank whose boolean fact is truthy, or 'guest'.
     *
     * @param array<string, mixed> $facts
     */
    public static function rank(array $facts): string
    {
        for ($i = count(self::RANKS) - 1; $i > 0; $i--) {
            $name = self::RANKS[$i];
            if (!empty($facts[$name])) {
                return $name;
            }
        }
        return 'guest';
    }

    /**
     * Formats a Concert-Priority header value ("<rank>" or "<rank>; ttl=<seconds>").
     *
     * @throws InvalidArgumentException on unknown rank.
     */
    public static function format(string $rank, ?int $ttlSeconds = null): string
    {
        $rank = strtolower(trim($rank));
        if (!in_array($rank, self::RANKS, true)) {
            throw new InvalidArgumentException("Unknown Concert-Priority rank: {$rank}");
        }
        if ($rank === 'guest' || $ttlSeconds === null) {
            return $rank;
        }
        $clamped = max(self::MIN_TTL_SECONDS, min(self::MAX_TTL_SECONDS, $ttlSeconds));
        return "{$rank}; ttl={$clamped}";
    }

    /**
     * Parses a Concert-Priority header value ("checkout; ttl=30m" or "customer; ttl=600").
     *
     * @return array{rank: string, ttl: ?int}
     * @throws InvalidArgumentException
     */
    public static function parse(string $headerValue): array
    {
        $headerValue = EndpointValidator::assertCleanHeaderValue($headerValue, self::HEADER_NAME);
        $parts = explode(';', $headerValue);
        $rank = strtolower(trim($parts[0]));
        if (!in_array($rank, self::RANKS, true)) {
            throw new InvalidArgumentException("Unknown Concert-Priority rank: {$rank}");
        }

        $ttl = self::DEFAULT_TTLS[$rank];
        for ($i = 1; $i < count($parts); $i++) {
            $segment = trim($parts[$i]);
            if ($segment === '' || !str_contains($segment, '=')) {
                continue;
            }
            [$k, $v] = explode('=', $segment, 2);
            if (strtolower(trim($k)) !== 'ttl') {
                continue;
            }
            $v = strtolower(trim($v));
            if (preg_match('/^\d+$/', $v) === 1) {
                $ttl = (int) $v;
            } elseif (preg_match('/^(\d+)([smh])$/', $v, $m) === 1) {
                $mult = match ($m[2]) {
                    's' => 1,
                    'm' => 60,
                    'h' => 3600,
                };
                $ttl = ((int) $m[1]) * $mult;
            } else {
                throw new InvalidArgumentException("Invalid Concert-Priority ttl: {$v}");
            }
        }

        if ($rank === 'guest') {
            $ttl = null;
        } elseif ($ttl !== null) {
            $ttl = max(self::MIN_TTL_SECONDS, min(self::MAX_TTL_SECONDS, $ttl));
        }

        return ['rank' => $rank, 'ttl' => $ttl];
    }

    /**
     * Emits the Concert-Priority header using native PHP header().
     */
    public static function send(string $rank, ?int $ttlSeconds = null): bool
    {
        $value = self::format($rank, $ttlSeconds);
        if (headers_sent()) {
            return false;
        }
        header(self::HEADER_NAME . ': ' . $value, true);
        return true;
    }

    /**
     * Clears any granted Concert-Priority rank by emitting 'Concert-Priority: guest'.
     */
    public static function clear(): bool
    {
        return self::send('guest');
    }

    /**
     * Attaches Concert-Priority to any PSR-7 ResponseInterface (duck-typed so
     * psr/http-message is optional at runtime).
     *
     * @template T of object
     * @param T $response
     * @return T
     */
    public static function withPriority(object $response, string $rank, ?int $ttlSeconds = null): object
    {
        if (!method_exists($response, 'withHeader')) {
            throw new InvalidArgumentException('Response object must implement PSR-7 ResponseInterface::withHeader().');
        }
        $value = self::format($rank, $ttlSeconds);
        return $response->withHeader(self::HEADER_NAME, $value);
    }
}
