<?php
declare(strict_types=1);

namespace Concert\Adapters;

use Concert\CachePurgeClient;
use Concert\PriorityHeader;

/**
 * Invision Power Board (IPB / IPS Community Suite 4.x/5.x) integration adapter.
 *
 * Maps IPS member group IDs, ACP/moderator flags, and IPS Commerce cart/invoice/
 * subscription state to Concert-Priority ranks, and offers helpers to purge
 * Concert page caches on topic/post updates.
 */
final class InvisionAdapter
{
    /** @var array<int, int> */
    private array $staffGroupIds;
    /** @var array<int, int> */
    private array $subscriberGroupIds;

    /**
     * @param array<int, int> $staffGroupIds      IPS group IDs granted 'staff' (default: [4] Administrators, [6] Moderators)
     * @param array<int, int> $subscriberGroupIds IPS group IDs granted 'subscriber' (e.g. paid supporter tiers)
     */
    public function __construct(array $staffGroupIds = [4, 6], array $subscriberGroupIds = [])
    {
        $this->staffGroupIds = array_map('intval', $staffGroupIds);
        $this->subscriberGroupIds = array_map('intval', $subscriberGroupIds);
    }

    /**
     * Classifies an IPS member snapshot (from \IPS\Member::loggedIn()) and
     * optional Commerce/checkout flags into a Concert-Priority rank.
     *
     * @param array<string, mixed> $member   e.g. ['member_id' => 42, 'member_group_id' => 3, 'mgroup_others' => '7,9', 'is_acp' => false, 'is_mod' => false]
     * @param array<string, mixed> $commerce e.g. ['checkout_active' => false, 'has_subscription' => false, 'has_orders' => false, 'cart_items' => 0]
     */
    public function classifyMember(array $member, array $commerce = []): string
    {
        $memberId = (int) ($member['member_id'] ?? 0);
        $primaryGroup = (int) ($member['member_group_id'] ?? 0);
        $otherGroups = [];
        if (!empty($member['mgroup_others']) && is_string($member['mgroup_others'])) {
            foreach (explode(',', $member['mgroup_others']) as $gid) {
                $gid = trim($gid);
                if ($gid !== '' && ctype_digit($gid)) {
                    $otherGroups[] = (int) $gid;
                }
            }
        }
        $allGroups = array_unique(array_merge([$primaryGroup], $otherGroups));

        $isStaff = !empty($member['is_acp'])
            || !empty($member['is_mod'])
            || count(array_intersect($allGroups, $this->staffGroupIds)) > 0;

        $isSubscriber = !empty($commerce['has_subscription'])
            || count(array_intersect($allGroups, $this->subscriberGroupIds)) > 0;

        return PriorityHeader::rank([
            'staff'      => $isStaff,
            'checkout'   => !empty($commerce['checkout_active']),
            'subscriber' => $isSubscriber,
            'customer'   => !empty($commerce['has_orders']),
            'prospect'   => ((int) ($commerce['cart_items'] ?? 0)) > 0 || !empty($commerce['viewing_store']),
            'member'     => $memberId > 0,
        ]);
    }

    /**
     * Emits Concert-Priority for an IPS member using native header() or a custom emitter.
     *
     * @param array<string, mixed>      $member
     * @param array<string, mixed>      $commerce
     * @param callable(string):void|null $emitter Optional test emitter receiving the full header line.
     */
    public function emitForMember(array $member, array $commerce = [], ?int $ttlSeconds = null, ?callable $emitter = null): string
    {
        $rank = $this->classifyMember($member, $commerce);
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
     * Purges a forum topic URL and tag after an IPS post or moderation event.
     *
     * @return array<string, array<string, mixed>>
     */
    public static function purgeTopic(CachePurgeClient $client, string $topicPath, int $topicId, string $host = ''): array
    {
        return [
            'url' => $client->purgeUrl($topicPath, $host),
            'tag' => $client->purgeTag('ipb-topic:' . $topicId, $host),
        ];
    }
}
