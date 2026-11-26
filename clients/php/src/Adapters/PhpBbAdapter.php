<?php
declare(strict_types=1);

namespace Concert\Adapters;

use Concert\PriorityHeader;

/**
 * phpBB 3.3+ integration adapter.
 *
 * Maps phpBB's $user->data and $auth ACL checks to Concert-Priority ranks:
 *   - Administrators (a_) / Global Moderators (m_) -> staff
 *   - Configured supporter group IDs               -> subscriber
 *   - Registered non-bot members                   -> member
 *   - Anonymous visitors / bots (user_id === 1)    -> guest
 */
final class PhpBbAdapter
{
    public const ANONYMOUS_USER_ID = 1;

    /** @var array<int, int> */
    private array $subscriberGroupIds;

    /**
     * @param array<int, int> $subscriberGroupIds Optional phpBB group_ids mapped to 'subscriber'.
     */
    public function __construct(array $subscriberGroupIds = [])
    {
        $this->subscriberGroupIds = array_map('intval', $subscriberGroupIds);
    }

    /**
     * Classifies a phpBB visitor from $user->data and an optional $auth object.
     *
     * @param array<string, mixed> $userData   Typically $this->user->data
     * @param object|null          $auth       Typically $this->auth (supports acl_get('a_') / acl_get('m_'))
     * @param array<string, mixed> $extraFacts Optional overrides (e.g. ['checkout' => true])
     */
    public function classifyUser(array $userData, ?object $auth = null, array $extraFacts = []): string
    {
        $userId = (int) ($userData['user_id'] ?? self::ANONYMOUS_USER_ID);
        $isBot = !empty($userData['is_bot']);
        $isRegistered = !empty($userData['is_registered']) || ($userId > self::ANONYMOUS_USER_ID && !$isBot);
        $groupId = (int) ($userData['group_id'] ?? 0);

        $isAdmin = false;
        $isMod = false;
        if ($auth !== null && method_exists($auth, 'acl_get')) {
            $isAdmin = (bool) $auth->acl_get('a_');
            $isMod = (bool) $auth->acl_get('m_');
        }

        $facts = array_merge([
            'staff'      => $isRegistered && ($isAdmin || $isMod),
            'subscriber' => $isRegistered && in_array($groupId, $this->subscriberGroupIds, true),
            'member'     => $isRegistered && !$isBot,
        ], $extraFacts);

        return PriorityHeader::rank($facts);
    }

    /**
     * Emits Concert-Priority for a phpBB page response (wire to core.page_header_after).
     *
     * @param array<string, mixed>       $userData
     * @param object|null                $auth
     * @param callable(string):void|null $emitter Optional test emitter.
     */
    public function emitForPage(array $userData, ?object $auth = null, ?int $ttlSeconds = null, ?callable $emitter = null): string
    {
        $rank = $this->classifyUser($userData, $auth);
        if ($rank === 'guest') {
            return 'guest';
        }
        $ttl = $ttlSeconds ?? (PriorityHeader::DEFAULT_TTLS[$rank] ?? null);
        $formatted = PriorityHeader::format($rank, $ttl);
        if ($emitter !== null) {
            $emitter(PriorityHeader::HEADER_NAME . ': ' . $formatted);
        } else {
            PriorityHeader::send($rank, $ttl);
        }
        return $rank;
    }

    /**
     * Emits "Concert-Priority: guest" on phpBB logout (wire to core.session_kill_after).
     */
    public function clearOnLogout(?callable $emitter = null): void
    {
        if ($emitter !== null) {
            $emitter(PriorityHeader::HEADER_NAME . ': guest');
            return;
        }
        PriorityHeader::clear();
    }
}
