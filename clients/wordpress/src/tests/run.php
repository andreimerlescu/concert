<?php
declare(strict_types=1);

/**
 * Standalone unit test suite for Concert WordPress & WooCommerce plugin.
 * Runs directly via PHP CLI without WordPress core installed:
 *   php clients/wordpress/src/tests/run.php
 */

// ── Minimal WordPress test stubs (global namespace) ──────────────────────────
namespace {
    $GLOBALS['__wp_test_caps'] = [];
    $GLOBALS['__wp_test_valid_nonces'] = [];
    $GLOBALS['__wp_test_permalinks'] = [];
    $GLOBALS['__wp_test_revisions'] = [];
    $GLOBALS['__wp_test_autosaves'] = [];

    function current_user_can(string $capability): bool
    {
        return !empty($GLOBALS['__wp_test_caps'][$capability]);
    }

    function wp_verify_nonce(string $nonce, string $action): int|false
    {
        $expected = $GLOBALS['__wp_test_valid_nonces'][$action] ?? null;
        return ($expected !== null && hash_equals($expected, $nonce)) ? 1 : false;
    }

    function admin_url(string $path = ''): string
    {
        return 'https://shop.example.test/wp-admin/' . ltrim($path, '/');
    }

    function wp_nonce_url(string $actionUrl, string $action, string $name = '_wpnonce'): string
    {
        $nonce = $GLOBALS['__wp_test_valid_nonces'][$action] ?? 'stub-nonce';
        $sep = str_contains($actionUrl, '?') ? '&' : '?';
        return $actionUrl . $sep . rawurlencode($name) . '=' . rawurlencode($nonce);
    }

    function esc_html(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    function get_permalink(int $postId): string|false
    {
        return $GLOBALS['__wp_test_permalinks'][$postId] ?? false;
    }

    function wp_is_post_revision(int $postId): bool
    {
        return !empty($GLOBALS['__wp_test_revisions'][$postId]);
    }

    function wp_is_post_autosave(int $postId): bool
    {
        return !empty($GLOBALS['__wp_test_autosaves'][$postId]);
    }
}

namespace Concert\WordPress\Tests {
    require_once __DIR__ . '/../includes/Secret.php';
    require_once __DIR__ . '/../includes/UrlValidator.php';
    require_once __DIR__ . '/../includes/PriorityClassifier.php';
    require_once __DIR__ . '/../includes/CachePurger.php';
    require_once __DIR__ . '/../includes/AdminBar.php';
    require_once __DIR__ . '/../includes/Plugin.php';

    use Concert\WordPress\AdminBar;
    use Concert\WordPress\CachePurger;
    use Concert\WordPress\Plugin;
    use Concert\WordPress\PriorityClassifier;
    use Concert\WordPress\Secret;
    use Concert\WordPress\UrlValidator;
    use InvalidArgumentException;
    use RuntimeException;

    $passed = 0;
    $failed = 0;

    $assert = static function (bool $cond, string $message) use (&$passed, &$failed): void {
        if ($cond) {
            $passed++;
            return;
        }
        $failed++;
        fwrite(STDERR, "FAIL: {$message}\n");
    };

    $assertThrows = static function (string $expectedClass, callable $fn, string $message) use (&$passed, &$failed): void {
        try {
            $fn();
        } catch (\Throwable $e) {
            if ($e instanceof $expectedClass) {
                $passed++;
                return;
            }
            $failed++;
            fwrite(STDERR, "FAIL: {$message} (expected {$expectedClass}, got " . get_class($e) . ": {$e->getMessage()})\n");
            return;
        }
        $failed++;
        fwrite(STDERR, "FAIL: {$message} (did not throw {$expectedClass})\n");
    };

    // 1. Priority classification & precedence
    $assert(PriorityClassifier::classifyWordPressContext([]) === 'guest', 'empty context -> guest');
    $assert(PriorityClassifier::classifyWordPressContext(['is_member' => true]) === 'member', 'logged in -> member');
    $assert(PriorityClassifier::classifyWordPressContext(['is_member' => true, 'is_prospect' => true]) === 'prospect', 'cart -> prospect');
    $assert(PriorityClassifier::classifyWordPressContext(['is_prospect' => true, 'is_customer' => true]) === 'customer', 'order history -> customer');
    $assert(PriorityClassifier::classifyWordPressContext(['is_customer' => true, 'is_subscriber' => true]) === 'subscriber', 'subscription -> subscriber');
    $assert(PriorityClassifier::classifyWordPressContext(['is_subscriber' => true, 'is_checkout' => true]) === 'checkout', 'checkout -> checkout');
    $assert(PriorityClassifier::classifyWordPressContext(['is_checkout' => true, 'is_staff' => true]) === 'staff', 'staff beats checkout');

    // Header formatting & TTL clamping
    $assert(PriorityClassifier::formatHeader('guest', 600) === 'guest', 'guest omits ttl');
    $assert(PriorityClassifier::formatHeader('checkout', 10) === 'checkout; ttl=60', 'ttl clamps to min 60');
    $assert(PriorityClassifier::formatHeader('staff', 999999) === 'staff; ttl=86400', 'ttl clamps to max 86400');
    $assert(PriorityClassifier::formatHeader('customer', 1800) === 'customer; ttl=1800', 'exact ttl formatted');
    $assertThrows(InvalidArgumentException::class, static fn() => PriorityClassifier::formatHeader('vip'), 'unknown rank throws');

    // Waiting-room signal header parsing
    $sig = PriorityClassifier::parseWaitingRoomHeaders([
        'x-concert-queue'      => '1',
        'X-Concert-Position'   => '42',
        'Retry-After'          => '7',
        'X-Concert-Status-Url' => '/custom/status',
    ]);
    $assert($sig['queued'] === true && $sig['position'] === 42 && $sig['retry_after'] === 7 && $sig['status_url'] === '/custom/status', 'waiting-room headers parsed');
    $sigNone = PriorityClassifier::parseWaitingRoomHeaders(['Content-Type' => 'text/html']);
    $assert($sigNone['queued'] === false && $sigNone['position'] === null && $sigNone['retry_after'] === null, 'non-queued headers');

    // 2. Endpoint URL validation (S9)
    $assert(UrlValidator::validateEndpoint('https://edge.example.test:8443/') === 'https://edge.example.test:8443', 'https accepted & normalized');
    $assert(UrlValidator::validateEndpoint('http://127.0.0.1:8080/') === 'http://127.0.0.1:8080', 'loopback IPv4 http accepted');
    $assert(UrlValidator::validateEndpoint('http://localhost:8080') === 'http://localhost:8080', 'localhost http accepted');
    $assert(UrlValidator::validateEndpoint('http://[::1]:8080') === 'http://[::1]:8080', 'loopback IPv6 http accepted');
    $assertThrows(InvalidArgumentException::class, static fn() => UrlValidator::validateEndpoint('http://remote.example.test:8080'), 'remote http rejected');
    $userinfoUrl = implode('', ['https://', 'example-user', ':', 'not-real', '@edge.example.test']);
    $assertThrows(InvalidArgumentException::class, static fn() => UrlValidator::validateEndpoint($userinfoUrl), 'userinfo rejected');
    $assertThrows(InvalidArgumentException::class, static fn() => UrlValidator::validateEndpoint('ftp://edge.example.test'), 'non-http scheme rejected');
    $assertThrows(InvalidArgumentException::class, static fn() => UrlValidator::validateEndpoint("https://edge.example.test\r\nX: y"), 'CRLF rejected');

    // 3. Purge payload formatting & transport verification
    $fakeTokenValue = 'unit-test-ephemeral-token-' . bin2hex(random_bytes(8));
    $secret = Secret::fromString($fakeTokenValue, 'env:CONCERT_ADMIN_TOKEN');

    $captured = [];
    $mockTransport = static function (string $url, array $args) use (&$captured): array {
        $captured[] = ['url' => $url, 'args' => $args];
        $decoded = json_decode((string) $args['body'], true);
        return [
            'status'  => 200,
            'body'    => json_encode(['purged' => 3, 'mode' => $decoded['mode']]),
            'headers' => ['Cache-Control' => 'no-store'],
        ];
    };

    $purger = new CachePurger('https://edge.example.test', $secret, 'shop.example.test', 5, $mockTransport);
    $res = $purger->purgeUrl('/product/limited-vinyl');
    $assert($res['ok'] === true && $res['purged'] === 3 && $res['mode'] === 'url', 'purgeUrl succeeds');
    $assert(count($captured) === 1, 'transport invoked once');
    $assert($captured[0]['url'] === 'https://edge.example.test/_room/cache/purge', 'exact purge endpoint');
    $assert($captured[0]['args']['sslverify'] === true, 'sslverify enabled');
    $assert($captured[0]['args']['headers']['Authorization'] === 'Bearer ' . $fakeTokenValue, 'Bearer token sent');
    $bodyData = json_decode($captured[0]['args']['body'], true);
    $assert($bodyData === ['mode' => 'url', 'host' => 'shop.example.test', 'target' => '/product/limited-vinyl'], 'exact purge JSON payload');

    $assertThrows(InvalidArgumentException::class, static fn() => CachePurger::buildPayload('url', ''), 'url mode requires target');
    $assertThrows(InvalidArgumentException::class, static fn() => CachePurger::buildPayload('bogus', '/'), 'invalid mode rejected');
    $assert(CachePurger::buildPayload('all', 'ignored', 'shop.example.test')['target'] === '', 'all mode clears target');

    // Fail-closed when token is missing
    $noTokenPurger = new CachePurger('http://127.0.0.1:8080', null, 'shop.example.test', 5, $mockTransport);
    $failRes = $noTokenPurger->purgeAll();
    $assert($failRes['ok'] === false && str_contains((string) $failRes['error'], 'fail-closed'), 'missing token fails closed');

    // Error message scrubbing (S5)
    $leakyTransport = static function (string $url, array $args) use ($fakeTokenValue): array {
        return ['status' => 502, 'body' => '', 'error' => 'Upstream rejected Bearer ' . $fakeTokenValue];
    };
    $scrubPurger = new CachePurger('https://edge.example.test', $secret, 'shop.example.test', 5, $leakyTransport);
    $scrubRes = $scrubPurger->purgeAll();
    $assert($scrubRes['ok'] === false && !str_contains((string) $scrubRes['error'], $fakeTokenValue), 'error scrubs raw token');
    $assert(str_contains((string) $scrubRes['error'], Secret::REDACTED), 'error replaces token with REDACTED');

    // 4. WordPress & WooCommerce hooks
    $captured = [];
    $GLOBALS['__wp_test_permalinks'][101] = 'https://shop.example.test/hello-world/';
    $GLOBALS['__wp_test_permalinks'][202] = 'https://shop.example.test/product/concert-tee/';
    $GLOBALS['__wp_test_revisions'][102] = true;
    $plugin = new Plugin($purger);

    // Revision is skipped
    $plugin->onSavePost(102, (object) ['post_status' => 'publish'], true);
    $assert(count($captured) === 0, 'save_post skips revisions');

    // Draft is skipped
    $plugin->onSavePost(101, (object) ['post_status' => 'draft'], true);
    $assert(count($captured) === 0, 'save_post skips drafts');

    // Published post purges permalink, '/', and post tag
    $plugin->onSavePost(101, (object) ['post_status' => 'publish'], true);
    $assert(count($captured) === 3, 'save_post dispatches 3 purge calls');
    $p0 = json_decode($captured[0]['args']['body'], true);
    $p1 = json_decode($captured[1]['args']['body'], true);
    $p2 = json_decode($captured[2]['args']['body'], true);
    $assert($p0['mode'] === 'url' && $p0['target'] === '/hello-world/', 'save_post purges permalink');
    $assert($p1['mode'] === 'url' && $p1['target'] === '/', 'save_post purges home');
    $assert($p2['mode'] === 'tag' && $p2['target'] === 'post:101', 'save_post purges post tag');

    // WooCommerce stock update purges product URL, /shop/ prefix, and product tag
    $captured = [];
    $fakeProduct = new class {
        public function get_id(): int
        {
            return 202;
        }
    };
    $plugin->onWooProductStock($fakeProduct);
    $assert(count($captured) === 3, 'woocommerce_product_set_stock dispatches 3 purge calls');
    $w0 = json_decode($captured[0]['args']['body'], true);
    $w1 = json_decode($captured[1]['args']['body'], true);
    $w2 = json_decode($captured[2]['args']['body'], true);
    $assert($w0['mode'] === 'url' && $w0['target'] === '/product/concert-tee/', 'WC stock purges product URL');
    $assert($w1['mode'] === 'prefix' && $w1['target'] === '/shop/', 'WC stock purges /shop/ prefix');
    $assert($w2['mode'] === 'tag' && $w2['target'] === 'product:202', 'WC stock purges product tag');

    // 5. Admin Bar capability & nonce gating
    $adminBar = new AdminBar($purger);
    $GLOBALS['__wp_test_valid_nonces'][AdminBar::NONCE_ACTION] = 'valid-nonce-xyz';

    // Non-admin user denied even with valid nonce
    $GLOBALS['__wp_test_caps'] = [];
    $denyCap = $adminBar->handlePurgeRequest(['_wpnonce' => 'valid-nonce-xyz', 'mode' => 'all']);
    $assert($denyCap['allowed'] === false && $denyCap['status_code'] === 403, 'non-admin rejected with 403');

    // Admin with missing or bad nonce denied
    $GLOBALS['__wp_test_caps'] = ['manage_options' => true];
    $denyNonce = $adminBar->handlePurgeRequest(['_wpnonce' => 'wrong-nonce', 'mode' => 'all']);
    $assert($denyNonce['allowed'] === false && $denyNonce['status_code'] === 403, 'bad nonce rejected with 403');

    // Admin Bar node hidden from non-admins, shown with nonce to admins
    $nodes = [];
    $stubBar = new class($nodes) {
        /** @var array<int, array<string, mixed>> */
        public array $nodes;
        public function __construct(array &$nodes)
        {
            $this->nodes = &$nodes;
        }
        public function add_node(array $node): void
        {
            $this->nodes[] = $node;
        }
    };
    $GLOBALS['__wp_test_caps'] = [];
    $adminBar->addAdminBarNode($stubBar);
    $assert(count($nodes) === 0, 'admin bar button hidden from non-admin');

    $GLOBALS['__wp_test_caps'] = ['manage_options' => true];
    $adminBar->addAdminBarNode($stubBar);
    $assert(count($nodes) === 1 && str_contains((string) $nodes[0]['href'], '_wpnonce=valid-nonce-xyz'), 'admin bar button shown with nonce');
    $assert(!str_contains((string) $nodes[0]['href'], $fakeTokenValue), 'admin bar href never contains token');

    // Admin with valid nonce succeeds
    $captured = [];
    $okAdmin = $adminBar->handlePurgeRequest(['_wpnonce' => 'valid-nonce-xyz', 'mode' => 'all']);
    $assert($okAdmin['allowed'] === true && $okAdmin['status_code'] === 200 && count($captured) === 1, 'admin with valid nonce purges cache');

    // 6. Secret redaction & non-disclosure (S1/S5/S6/S7/S8)
    $assert((string) $secret === Secret::REDACTED, 'Secret::__toString redacts');
    $assert(!str_contains(print_r($secret, true), $fakeTokenValue), 'Secret::__debugInfo redacts');
    $assert(json_encode($secret) === '"' . Secret::REDACTED . '"', 'Secret::jsonSerialize redacts');
    $assertThrows(InvalidArgumentException::class, static fn() => Secret::fromString('changeme'), 'placeholder token rejected');
    $assertThrows(InvalidArgumentException::class, static fn() => Secret::fromString('   '), 'empty token rejected');

    // Status page HTML never leaks secret
    $html = $adminBar->renderStatusPage();
    $assert(!str_contains($html, $fakeTokenValue), 'status page HTML never discloses token');
    $assert(str_contains($html, 'env:CONCERT_ADMIN_TOKEN'), 'status page shows non-sensitive source');

    // Secret::fromFile permission enforcement (0644 rejected, 0600 accepted)
    $tmpDir = sys_get_temp_dir() . '/concert-wp-test-' . bin2hex(random_bytes(4));
    mkdir($tmpDir, 0700, true);
    $secretFile = $tmpDir . '/admin_token';
    file_put_contents($secretFile, $fakeTokenValue . "\n");
    chmod($secretFile, 0644);
    $assertThrows(RuntimeException::class, static fn() => Secret::fromFile($secretFile), '0644 token file rejected');
    chmod($secretFile, 0600);
    $loaded = Secret::fromFile($secretFile);
    $assert($loaded->reveal() === $fakeTokenValue, '0600 token file loaded');
    @unlink($secretFile);
    @rmdir($tmpDir);

    echo "WordPress plugin tests: {$passed} passed, {$failed} failed\n";
    exit($failed > 0 ? 1 : 0);
}
