<?php
declare(strict_types=1);

namespace Concert\Adapters;

use Concert\PriorityHeader;

/**
 * Vanilla PHP session-aware adapter (direct OOP upgrade path from legacy root concert.php).
 *
 * Tracks the last emitted rank in the session array so:
 *   - Ranked visitors renew their grant on every page response.
 *   - Visitors dropping from a rank back to guest emit one "guest" clear header.
 *   - Anonymous visitors who were never ranked emit no header at all.
 */
final class VanillaPhpAdapter
{
    public const SESSION_KEY = 'concert_rank';

    private string $sessionKey;

    /** @var callable(string): bool */
    private $headerEmitter;

    /**
     * @param callable(string): bool|null $headerEmitter Optional test emitter receiving the header value.
     */
    public function __construct(string $sessionKey = self::SESSION_KEY, ?callable $headerEmitter = null)
    {
        $this->sessionKey = $sessionKey;
        $this->headerEmitter = $headerEmitter ?? static function (string $value): bool {
            if (headers_sent()) {
                return false;
            }
            header(PriorityHeader::HEADER_NAME . ': ' . $value, true);
            return true;
        };
    }

    /**
     * Synchronizes the visitor's rank against the provided session array (usually $_SESSION).
     *
     * @param array<string, mixed> $facts
     * @param array<string, mixed> $session Passed by reference so the adapter records last emitted rank.
     */
    public function sync(array $facts, array &$session, ?int $ttlSeconds = null): string
    {
        $rank = PriorityHeader::rank($facts);
        $last = isset($session[$this->sessionKey]) && is_string($session[$this->sessionKey])
            ? $session[$this->sessionKey]
            : 'guest';

        if ($rank === 'guest' && $last === 'guest') {
            return 'guest';
        }

        $ttl = $rank === 'guest' ? null : ($ttlSeconds ?? (PriorityHeader::DEFAULT_TTLS[$rank] ?? null));
        $formatted = PriorityHeader::format($rank, $ttl);
        if (($this->headerEmitter)($formatted)) {
            $session[$this->sessionKey] = $rank;
        }
        return $rank;
    }

    /**
     * Clears the visitor's Concert-Priority rank on logout.
     *
     * @param array<string, mixed> $session
     */
    public function clear(array &$session): void
    {
        ($this->headerEmitter)('guest');
        unset($session[$this->sessionKey]);
    }
}
