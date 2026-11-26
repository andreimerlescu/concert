<?php
declare(strict_types=1);

namespace Concert\WordPress;

use InvalidArgumentException;

/**
 * Classifies WordPress and WooCommerce visitors into Concert-Priority ranks
 * and parses Concert waiting-room response headers.
 */
final class PriorityClassifier
{
    /** Ordered from lowest to highest priority, matching Concert's server/priority.go. */
    public const RANKS = [
        'guest',
        'member',
        'prospect',
        'customer',
        'subscriber',
        'checkout',
        'staff',
    ];

    public const MIN_TTL_SECONDS = 60;
    public const MAX_TTL_SECONDS = 86400;

    /** Default TTLs in seconds, matching Concert's rankDefaultTTL. */
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
     * @param array<string, bool> $facts
     */
    public static function classifyFacts(array $facts): string
    {
        for ($i = count(self::RANKS) - 1; $i > 0; $i--) {
            $rank = self::RANKS[$i];
            if (!empty($facts[$rank])) {
                return $rank;
            }
        }
        return 'guest';
    }

    /**
     * Classifies a visitor from structured WordPress & WooCommerce context flags.
     *
     * Supported keys:
     *   - is_staff (bool): manage_options / edit_others_posts / manage_woocommerce
     *   - is_checkout (bool): is_checkout() / order-pay endpoint / active checkout
     *   - is_subscriber (bool): active WooCommerce Subscription or membership
     *   - is_customer (bool): prior completed/processing WooCommerce order
     *   - is_prospect (bool): non-empty WooCommerce cart or viewing cart/product/shop
     *   - is_member (bool): is_user_logged_in()
     *
     * @param array<string, mixed> $context
     */
    public static function classifyWordPressContext(array $context): string
    {
        return self::classifyFacts([
            'staff'      => !empty($context['is_staff']),
            'checkout'   => !empty($context['is_checkout']),
            'subscriber' => !empty($context['is_subscriber']),
            'customer'   => !empty($context['is_customer']),
            'prospect'   => !empty($context['is_prospect']),
            'member'     => !empty($context['is_member']),
        ]);
    }

    /**
     * Formats a valid Concert-Priority header value ("<rank>" or "<rank>; ttl=<seconds>").
     *
     * @throws InvalidArgumentException on unknown rank.
     */
    public static function formatHeader(string $rank, ?int $ttlSeconds = null): string
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
     * Detects WordPress + WooCommerce visitor context using live WP/WC globals
     * when running inside WordPress.
     *
     * @return array<string, bool>
     */
    public static function detectWordPressContext(): array
    {
        $loggedIn = function_exists('is_user_logged_in') && (bool) is_user_logged_in();
        $isStaff = $loggedIn && function_exists('current_user_can') && (
            (bool) current_user_can('manage_options')
            || (bool) current_user_can('edit_others_posts')
            || (bool) current_user_can('manage_woocommerce')
        );

        $isCheckout = false;
        if (function_exists('is_checkout') && is_checkout()) {
            $isCheckout = true;
        } elseif (function_exists('is_checkout_pay_page') && is_checkout_pay_page()) {
            $isCheckout = true;
        }

        $userId = ($loggedIn && function_exists('get_current_user_id')) ? (int) get_current_user_id() : 0;

        $isSubscriber = false;
        if ($userId > 0 && function_exists('wcs_user_has_subscription')) {
            $isSubscriber = (bool) wcs_user_has_subscription($userId, '', 'active');
        }

        $isCustomer = false;
        if ($userId > 0 && function_exists('wc_get_customer_order_count')) {
            $isCustomer = ((int) wc_get_customer_order_count($userId)) > 0;
        }

        $isProspect = false;
        if (function_exists('WC')) {
            $wc = WC();
            if (is_object($wc) && isset($wc->cart) && is_object($wc->cart) && method_exists($wc->cart, 'get_cart_contents_count')) {
                $isProspect = ((int) $wc->cart->get_cart_contents_count()) > 0;
            }
        }
        if (!$isProspect) {
            if (
                (function_exists('is_cart') && is_cart())
                || (function_exists('is_product') && is_product())
                || (function_exists('is_shop') && is_shop())
            ) {
                $isProspect = true;
            }
        }

        return [
            'is_staff'      => $isStaff,
            'is_checkout'   => $isCheckout,
            'is_subscriber' => $isSubscriber,
            'is_customer'   => $isCustomer,
            'is_prospect'   => $isProspect,
            'is_member'     => $loggedIn,
        ];
    }

    /**
     * Parses Concert waiting-room signal headers (X-Concert-Queue,
     * X-Concert-Position, Retry-After, X-Concert-Status-Url) case-insensitively.
     *
     * @param array<string, string|array<int, string>> $headers
     * @return array{queued: bool, position: ?int, retry_after: ?int, status_url: ?string}
     */
    public static function parseWaitingRoomHeaders(array $headers): array
    {
        $normalized = [];
        foreach ($headers as $k => $v) {
            $key = strtolower(trim((string) $k));
            if (is_array($v)) {
                $v = (string) ($v[0] ?? '');
            }
            $normalized[$key] = trim((string) $v);
        }

        $queueVal = $normalized['x-concert-queue'] ?? '';
        $queued = $queueVal === '1' || strtolower($queueVal) === 'true';

        $position = null;
        if (isset($normalized['x-concert-position']) && preg_match('/^\d+$/', $normalized['x-concert-position']) === 1) {
            $position = (int) $normalized['x-concert-position'];
        }

        $retryAfter = null;
        if (isset($normalized['retry-after']) && $normalized['retry-after'] !== '') {
            if (preg_match('/^\d+$/', $normalized['retry-after']) === 1) {
                $retryAfter = max(1, (int) $normalized['retry-after']);
            } else {
                $ts = strtotime($normalized['retry-after']);
                if ($ts !== false) {
                    $retryAfter = max(1, $ts - time());
                }
            }
        }

        $statusUrl = null;
        if (isset($normalized['x-concert-status-url']) && $normalized['x-concert-status-url'] !== '') {
            $candidate = $normalized['x-concert-status-url'];
            if (preg_match('/[\r\n\x00]/', $candidate) !== 1) {
                $statusUrl = $candidate;
            }
        }

        return [
            'queued'      => $queued,
            'position'    => $position,
            'retry_after' => $retryAfter,
            'status_url'  => $statusUrl,
        ];
    }
}
