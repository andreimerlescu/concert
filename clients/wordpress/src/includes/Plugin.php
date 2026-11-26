<?php
declare(strict_types=1);

namespace Concert\WordPress;

use Throwable;

/**
 * Main WordPress & WooCommerce plugin coordinator.
 */
final class Plugin
{
    private ?CachePurger $purger = null;
    private ?string $configError = null;
    private AdminBar $adminBar;

    public function __construct(?CachePurger $purger = null, ?string $configError = null)
    {
        $this->purger = $purger;
        $this->configError = $configError;
        $this->adminBar = new AdminBar($this->purger, $this->configError);
    }

    /**
     * Bootstraps the plugin from wp-config.php constants / environment variables
     * and attaches all WordPress and WooCommerce hooks.
     */
    public static function bootstrap(): self
    {
        $purger = null;
        $error = null;

        $endpoint = self::resolveEndpointUrl();
        if ($endpoint !== '') {
            try {
                $token = Secret::fromEnvironment();
                $host = self::resolveSiteHost();
                $purger = new CachePurger($endpoint, $token, $host);
            } catch (Throwable $e) {
                $error = $e->getMessage();
            }
        }

        $plugin = new self($purger, $error);
        $plugin->registerHooks();
        return $plugin;
    }

    public function registerHooks(): void
    {
        if (!function_exists('add_action')) {
            return;
        }

        // Priority header emission and logout rank clear.
        add_action('send_headers', [$this, 'onSendHeaders'], 20);
        add_action('wp_logout', [$this, 'onLogout'], 10);

        // Active cache purge on WordPress content & WooCommerce stock/product updates.
        add_action('save_post', [$this, 'onSavePost'], 20, 3);
        add_action('woocommerce_product_set_stock', [$this, 'onWooProductStock'], 20, 1);
        add_action('woocommerce_update_product', [$this, 'onWooUpdateProduct'], 20, 1);

        // Admin Bar manual purge button + settings diagnostics page.
        add_action('admin_bar_menu', [$this->adminBar, 'addAdminBarNode'], 90);
        add_action('admin_post_' . AdminBar::ADMIN_POST_ACTION, [$this, 'onAdminPostPurge']);
        add_action('admin_menu', [$this, 'onAdminMenu']);
    }

    /**
     * Emits the Concert-Priority origin response header for ranked visitors.
     */
    public function onSendHeaders(): void
    {
        if (headers_sent()) {
            return;
        }
        $context = PriorityClassifier::detectWordPressContext();
        $rank = PriorityClassifier::classifyWordPressContext($context);
        if ($rank === 'guest') {
            return;
        }
        $ttl = PriorityClassifier::DEFAULT_TTLS[$rank] ?? null;
        header('Concert-Priority: ' . PriorityClassifier::formatHeader($rank, $ttl), true);
    }

    /**
     * Clears any Concert-Priority grant on WordPress logout.
     */
    public function onLogout(): void
    {
        if (headers_sent()) {
            return;
        }
        header('Concert-Priority: guest', true);
    }

    /**
     * Purges the saved post URL, homepage, and post tag on publish/update.
     *
     * @param int         $postId
     * @param object|null $post
     * @param bool        $update
     */
    public function onSavePost(int $postId, ?object $post = null, bool $update = false): void
    {
        if ($this->purger === null || $postId <= 0) {
            return;
        }
        if (function_exists('wp_is_post_revision') && wp_is_post_revision($postId)) {
            return;
        }
        if (function_exists('wp_is_post_autosave') && wp_is_post_autosave($postId)) {
            return;
        }
        if (is_object($post) && isset($post->post_status) && $post->post_status !== 'publish') {
            return;
        }

        $path = $this->permalinkPath($postId);
        if ($path !== null) {
            $this->purger->purgeUrl($path);
        }
        $this->purger->purgeUrl('/');
        $this->purger->purgeTag('post:' . $postId);
    }

    /**
     * Purges product page, shop prefix, and product tag when WooCommerce stock changes.
     *
     * @param mixed $product WC_Product instance or product ID.
     */
    public function onWooProductStock(mixed $product): void
    {
        $productId = $this->extractProductId($product);
        if ($productId > 0) {
            $this->purgeProduct($productId);
        }
    }

    /**
     * Purges product page, shop prefix, and product tag when a WooCommerce product updates.
     */
    public function onWooUpdateProduct(int $productId): void
    {
        if ($productId > 0) {
            $this->purgeProduct($productId);
        }
    }

    public function onAdminPostPurge(): void
    {
        $outcome = $this->adminBar->handlePurgeRequest($_REQUEST);
        if (!$outcome['allowed']) {
            if (function_exists('wp_die')) {
                wp_die($outcome['message'], 'Concert Cache Purge', ['response' => $outcome['status_code']]);
            }
            return;
        }

        $referer = function_exists('wp_get_referer') ? (string) wp_get_referer() : '';
        $fallback = function_exists('admin_url') ? (string) admin_url() : '/wp-admin/';
        $dest = $referer !== '' ? $referer : $fallback;
        $flag = ($outcome['status_code'] === 200) ? 'concert_purged=1' : 'concert_purge_error=1';
        $sep = str_contains($dest, '?') ? '&' : '?';

        if (function_exists('wp_safe_redirect')) {
            wp_safe_redirect($dest . $sep . $flag);
            exit;
        }
    }

    public function onAdminMenu(): void
    {
        if (!function_exists('add_options_page')) {
            return;
        }
        add_options_page(
            'Concert Waiting Room',
            'Concert',
            AdminBar::REQUIRED_CAPABILITY,
            'concert-wp',
            function (): void {
                echo $this->adminBar->renderStatusPage();
            }
        );
    }

    public function purger(): ?CachePurger
    {
        return $this->purger;
    }

    public function adminBar(): AdminBar
    {
        return $this->adminBar;
    }

    private function purgeProduct(int $productId): void
    {
        if ($this->purger === null) {
            return;
        }
        $path = $this->permalinkPath($productId);
        if ($path !== null) {
            $this->purger->purgeUrl($path);
        }
        $this->purger->purgePrefix('/shop/');
        $this->purger->purgeTag('product:' . $productId);
    }

    private function extractProductId(mixed $product): int
    {
        if (is_int($product)) {
            return $product;
        }
        if (is_object($product) && method_exists($product, 'get_id')) {
            return (int) $product->get_id();
        }
        return 0;
    }

    private function permalinkPath(int $postId): ?string
    {
        if (!function_exists('get_permalink')) {
            return null;
        }
        $permalink = get_permalink($postId);
        if (!is_string($permalink) || $permalink === '') {
            return null;
        }
        $parsed = parse_url($permalink);
        if (!is_array($parsed) || empty($parsed['path'])) {
            return '/';
        }
        return (string) $parsed['path'];
    }

    private static function resolveEndpointUrl(): string
    {
        if (defined('CONCERT_ENDPOINT_URL') && is_string(constant('CONCERT_ENDPOINT_URL'))) {
            return trim((string) constant('CONCERT_ENDPOINT_URL'));
        }
        $env = getenv('CONCERT_ENDPOINT_URL');
        return is_string($env) ? trim($env) : '';
    }

    private static function resolveSiteHost(): string
    {
        if (function_exists('home_url')) {
            $home = (string) home_url();
            $host = parse_url($home, PHP_URL_HOST);
            if (is_string($host) && $host !== '') {
                return strtolower($host);
            }
        }
        return '';
    }
}
