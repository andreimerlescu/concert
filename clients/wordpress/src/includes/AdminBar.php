<?php
declare(strict_types=1);

namespace Concert\WordPress;

/**
 * WordPress Admin Bar "Purge Concert Cache" action and read-only status page.
 *
 * Security invariants:
 *   - Every privileged action requires current_user_can('manage_options') AND
 *     a valid wp_verify_nonce(..., self::NONCE_ACTION).
 *   - CONCERT_ADMIN_TOKEN is NEVER echoed into HTML, form inputs, URLs, or JS.
 */
final class AdminBar
{
    public const NONCE_ACTION = 'concert_purge_cache';
    public const ADMIN_POST_ACTION = 'concert_purge_cache';
    public const REQUIRED_CAPABILITY = 'manage_options';

    private ?CachePurger $purger;
    private ?string $configError;

    public function __construct(?CachePurger $purger, ?string $configError = null)
    {
        $this->purger = $purger;
        $this->configError = $configError;
    }

    /**
     * Registers the "Purge Concert Cache" menu button in the WP Admin Bar.
     *
     * @param object $wpAdminBar Instance of WP_Admin_Bar (duck-typed for testability).
     */
    public function addAdminBarNode(object $wpAdminBar): void
    {
        if (!$this->currentUserAuthorized()) {
            return;
        }
        if (!method_exists($wpAdminBar, 'add_node')) {
            return;
        }

        $baseUrl = function_exists('admin_url')
            ? (string) admin_url('admin-post.php?action=' . self::ADMIN_POST_ACTION . '&mode=all')
            : '/wp-admin/admin-post.php?action=' . self::ADMIN_POST_ACTION . '&mode=all';

        $nonceUrl = function_exists('wp_nonce_url')
            ? (string) wp_nonce_url($baseUrl, self::NONCE_ACTION, '_wpnonce')
            : $baseUrl;

        $wpAdminBar->add_node([
            'id'    => 'concert-purge-cache',
            'title' => 'Purge Concert Cache',
            'href'  => $nonceUrl,
            'meta'  => [
                'title' => 'Purge all cached pages in wpconcert / concert-cache',
            ],
        ]);
    }

    /**
     * Handles POST/GET requests to admin-post.php?action=concert_purge_cache.
     *
     * @param array<string, mixed> $request Usually $_REQUEST.
     * @return array{allowed: bool, status_code: int, message: string, result?: array<string, mixed>}
     */
    public function handlePurgeRequest(array $request): array
    {
        if (!$this->currentUserAuthorized()) {
            return [
                'allowed'     => false,
                'status_code' => 403,
                'message'     => 'Forbidden: manage_options capability is required.',
            ];
        }

        $nonce = isset($request['_wpnonce']) && is_string($request['_wpnonce'])
            ? $request['_wpnonce']
            : '';

        if (!$this->verifyNonce($nonce)) {
            return [
                'allowed'     => false,
                'status_code' => 403,
                'message'     => 'Forbidden: invalid or expired WordPress nonce.',
            ];
        }

        if ($this->purger === null) {
            return [
                'allowed'     => true,
                'status_code' => 500,
                'message'     => $this->configError ?? 'Concert cache purger is not configured.',
            ];
        }

        $mode = isset($request['mode']) && is_string($request['mode'])
            ? strtolower(trim($request['mode']))
            : 'all';
        if (!in_array($mode, CachePurger::VALID_MODES, true)) {
            $mode = 'all';
        }
        $target = isset($request['target']) && is_string($request['target'])
            ? trim($request['target'])
            : '';

        $result = $this->purger->purge($mode, $target);
        return [
            'allowed'     => true,
            'status_code' => $result['ok'] ? 200 : 502,
            'message'     => $result['ok']
                ? sprintf('Purged %d cached entries (%s).', $result['purged'], $result['mode'])
                : 'Concert cache purge failed: ' . ($result['error'] ?? 'unknown error'),
            'result'      => $result,
        ];
    }

    /**
     * Renders the read-only Concert status page HTML.
     * Never prints CONCERT_ADMIN_TOKEN or renders a token input field (S5/S6).
     */
    public function renderStatusPage(): string
    {
        $esc = static function (string $value): string {
            if (function_exists('esc_html')) {
                return (string) esc_html($value);
            }
            return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        };

        $endpoint = $this->purger !== null ? $this->purger->endpoint() : 'Not configured';
        $tokenState = ($this->purger !== null && $this->purger->hasToken())
            ? 'Configured (' . $this->purger->tokenSource() . ')'
            : 'Not configured (fail-closed)';
        $errorNotice = $this->configError !== null
            ? '<div class="notice notice-error"><p>' . $esc($this->configError) . '</p></div>'
            : '';

        return '<div class="wrap">'
            . '<h1>Concert Waiting Room &amp; Cache</h1>'
            . $errorNotice
            . '<p>Secrets are supplied strictly via <code>CONCERT_ADMIN_TOKEN_FILE</code>, '
            . '<code>CONCERT_ADMIN_TOKEN</code> (constant or PHP-FPM environment), and are never stored in '
            . '<code>wp_options</code> or rendered in HTML/JavaScript.</p>'
            . '<table class="widefat striped" style="max-width:720px">'
            . '<tbody>'
            . '<tr><th>Endpoint URL</th><td><code>' . $esc($endpoint) . '</code></td></tr>'
            . '<tr><th>Admin Bearer Token</th><td>' . $esc($tokenState) . '</td></tr>'
            . '<tr><th>Priority Ranks</th><td><code>staff &gt; checkout &gt; subscriber &gt; customer &gt; prospect &gt; member &gt; guest</code></td></tr>'
            . '</tbody>'
            . '</table>'
            . '</div>';
    }

    private function currentUserAuthorized(): bool
    {
        return function_exists('current_user_can') && (bool) current_user_can(self::REQUIRED_CAPABILITY);
    }

    private function verifyNonce(string $nonce): bool
    {
        if ($nonce === '' || !function_exists('wp_verify_nonce')) {
            return false;
        }
        return (bool) wp_verify_nonce($nonce, self::NONCE_ACTION);
    }
}
