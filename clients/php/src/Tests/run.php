<?php
declare(strict_types=1);

/**
 * Standalone CLI test suite for concert/concert-php SDK.
 * Runs with zero Composer dependencies:
 *   php clients/php/src/Tests/run.php
 */

require_once __DIR__ . '/../Secret.php';
require_once __DIR__ . '/../EndpointValidator.php';
require_once __DIR__ . '/../HttpTransportInterface.php';
require_once __DIR__ . '/../CurlHttpTransport.php';
require_once __DIR__ . '/../PriorityHeader.php';
require_once __DIR__ . '/../Rm1Signer.php';
require_once __DIR__ . '/../WaitingRoomSignal.php';
require_once __DIR__ . '/../CachePurgeClient.php';
require_once __DIR__ . '/../AgentBidClient.php';
require_once __DIR__ . '/../Middleware/PriorityMiddleware.php';
require_once __DIR__ . '/../Adapters/SlimAdapter.php';
require_once __DIR__ . '/../Adapters/CakePhpAdapter.php';
require_once __DIR__ . '/../Adapters/LaminasAdapter.php';
require_once __DIR__ . '/../Adapters/InvisionAdapter.php';
require_once __DIR__ . '/../Adapters/PhpBbAdapter.php';
require_once __DIR__ . '/../Adapters/VanillaPhpAdapter.php';

use Concert\Adapters\CakePhpAdapter;
use Concert\Adapters\InvisionAdapter;
use Concert\Adapters\LaminasAdapter;
use Concert\Adapters\PhpBbAdapter;
use Concert\Adapters\SlimAdapter;
use Concert\Adapters\VanillaPhpAdapter;
use Concert\AgentBidClient;
use Concert\CachePurgeClient;
use Concert\EndpointValidator;
use Concert\HttpTransportInterface;
use Concert\PriorityHeader;
use Concert\Rm1Signer;
use Concert\Secret;
use Concert\WaitingRoomSignal;

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

$assertThrows = static function (string $expectedClass, callable $fn, string $message, ?string $expectedSubstr = null) use (&$passed, &$failed): void {
    try {
        $fn();
    } catch (\Throwable $e) {
        if ($e instanceof $expectedClass && ($expectedSubstr === null || str_contains($e->getMessage(), $expectedSubstr))) {
            $passed++;
            return;
        }
        $failed++;
        fwrite(STDERR, "FAIL: {$message} (got " . get_class($e) . ": {$e->getMessage()})\n");
        return;
    }
    $failed++;
    fwrite(STDERR, "FAIL: {$message} (did not throw {$expectedClass})\n");
};

// Lightweight PSR-7 / PSR-15 test doubles
$makeResponse = static function (array $initialHeaders = []): object {
    return new class($initialHeaders) {
        /** @var array<string, array<int, string>> */
        private array $headers;
        public function __construct(array $h)
        {
            $this->headers = $h;
        }
        public function withHeader(string $name, string $value): self
        {
            $clone = clone $this;
            $clone->headers[$name] = [$value];
            return $clone;
        }
        public function getHeaderLine(string $name): string
        {
            return isset($this->headers[$name]) ? implode(', ', $this->headers[$name]) : '';
        }
        public function getHeaders(): array
        {
            return $this->headers;
        }
    };
};

$makeHandler = static function (object $response): object {
    return new class($response) {
        private object $resp;
        public function __construct(object $resp)
        {
            $this->resp = $resp;
        }
        public function handle(object $request): object
        {
            return $this->resp;
        }
    };
};

// ── 1. PriorityHeader ────────────────────────────────────────────────────────
$assert(PriorityHeader::rank([]) === 'guest', 'empty facts -> guest');
$assert(PriorityHeader::rank(['member' => true, 'checkout' => true]) === 'checkout', 'checkout beats member');
$assert(PriorityHeader::rank(['checkout' => true, 'staff' => true]) === 'staff', 'staff beats checkout');
$assert(PriorityHeader::format('checkout', 1800) === 'checkout; ttl=1800', 'format checkout ttl');
$assert(PriorityHeader::format('member', 10) === 'member; ttl=60', 'ttl min clamp');
$assert(PriorityHeader::format('member', 100000) === 'member; ttl=86400', 'ttl max clamp');
$assert(PriorityHeader::format('guest', 600) === 'guest', 'guest omits ttl');
$assert(PriorityHeader::parse('checkout; ttl=30m') === ['rank' => 'checkout', 'ttl' => 1800], 'parse 30m');
$assert(PriorityHeader::parse('staff; ttl=2h') === ['rank' => 'staff', 'ttl' => 7200], 'parse 2h');
$assert(PriorityHeader::parse('guest') === ['rank' => 'guest', 'ttl' => null], 'parse guest');
$assertThrows(InvalidArgumentException::class, static fn() => PriorityHeader::format('bogus'), 'unknown rank rejected');

$psrResp = PriorityHeader::withPriority($makeResponse(), 'subscriber', 3600);
$assert($psrResp->getHeaderLine('Concert-Priority') === 'subscriber; ttl=3600', 'PSR-7 withPriority attaches header');

// ── 2. Rm1Signer (Ed25519 via ext-sodium matching room v1.9.0) ───────────────
$now = 1760000000;
$signer = Rm1Signer::generate('k1', 600, static fn(): int => $now);
$passTok = $signer->mintPass('shop.example.test', '', 300);

// Inspect wire format rm1.<b64url>.<b64url>
$parts = explode('.', $passTok);
$assert(count($parts) === 3 && $parts[0] === 'rm1', 'rm1 wire format has 3 segments with rm1 prefix');
$decodedClaims = json_decode(EndpointValidator::base64UrlDecodeStrict($parts[1]), true);
$assert($decodedClaims['kid'] === 'k1', 'claims kid=k1');
$assert($decodedClaims['kind'] === 'pass', 'claims kind=pass');
$assert($decodedClaims['scope'] === 'shop.example.test', 'claims scope matches');
$assert(!array_key_exists('key', $decodedClaims), 'anonymous pass omits empty key (Go omitempty)');
$assert($decodedClaims['iat'] === $now && $decodedClaims['exp'] === $now + 300, 'claims iat/exp exact');

// Verify pass succeeds
$verified = $signer->verifyOwn($passTok, 'shop.example.test', Rm1Signer::KIND_PASS, '', $now + 10);
$assert($verified['kid'] === 'k1' && $verified['scope'] === 'shop.example.test', 'verifyOwn pass succeeds');

// Verify key-bound lease succeeds & anonymous lease rejected
$leaseTok = $signer->mintLease('shop.example.test', 'agent:42', 120);
$verifiedLease = $signer->verifyOwn($leaseTok, 'shop.example.test', Rm1Signer::KIND_LEASE, 'agent:42', $now + 10);
$assert($verifiedLease['key'] === 'agent:42' && $verifiedLease['kind'] === 'lease', 'verifyOwn lease succeeds');
$assertThrows(InvalidArgumentException::class, static fn() => $signer->mintLease('shop.example.test', '', 120), 'empty lease key rejected');

// Security-first rejection checks matching room/token.go
$tampered = substr($passTok, 0, -4) . 'AAAA';
$assertThrows(RuntimeException::class, static fn() => $signer->verifyOwn($tampered, 'shop.example.test', Rm1Signer::KIND_PASS, '', $now + 10), 'tampered sig rejected', 'invalid_signature');
$assertThrows(RuntimeException::class, static fn() => $signer->verifyOwn($passTok, 'other.example.test', Rm1Signer::KIND_PASS, '', $now + 10), 'wrong scope rejected', 'wrong_scope');
$assertThrows(RuntimeException::class, static fn() => $signer->verifyOwn($passTok, 'shop.example.test', Rm1Signer::KIND_LEASE, 'agent:42', $now + 10), 'wrong kind rejected', 'wrong_kind');
$assertThrows(RuntimeException::class, static fn() => $signer->verifyOwn($leaseTok, 'shop.example.test', Rm1Signer::KIND_LEASE, 'agent:99', $now + 10), 'key mismatch rejected', 'key_mismatch');
$assertThrows(RuntimeException::class, static fn() => $signer->verifyOwn($passTok, 'shop.example.test', Rm1Signer::KIND_PASS, '', $now + 300), 'expired token rejected', 'expired');
$assertThrows(RuntimeException::class, static fn() => $signer->verifyOwn($passTok, 'shop.example.test', Rm1Signer::KIND_PASS, '', $now - 60), 'future issued rejected', 'future_issued');

// Import from 32-byte seed & 64-byte secret key across raw, hex, and base64url (Go crypto/ed25519 compatibility)
$seed = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
$kp = sodium_crypto_sign_seed_keypair($seed);
$sk64 = sodium_crypto_sign_secretkey($kp);
$expectedPk = sodium_crypto_sign_publickey($kp);

$fromSeedRaw = Rm1Signer::fromSecretKey('k-sraw', Secret::fromRawBytes($seed), 600, static fn(): int => $now);
$fromSeedHex = Rm1Signer::fromSecretKey('k-seed', Secret::fromString(bin2hex($seed), 'test:seed'), 600, static fn(): int => $now);
$fromSeedB64 = Rm1Signer::fromSecretKey('k-sb64', Secret::fromString(EndpointValidator::base64UrlEncode($seed), 'test:sb64'), 600, static fn(): int => $now);
$fromSk64Raw = Rm1Signer::fromSecretKey('k-kraw', Secret::fromRawBytes($sk64), 600, static fn(): int => $now);
$fromSk64Hex = Rm1Signer::fromSecretKey('k-khex', Secret::fromString(bin2hex($sk64), 'test:khex'), 600, static fn(): int => $now);
$fromSk64B64 = Rm1Signer::fromSecretKey('k-sk64', Secret::fromString(EndpointValidator::base64UrlEncode($sk64), 'test:sk64'), 600, static fn(): int => $now);

$assert($fromSeedRaw->publicKeyRaw() === $expectedPk, 'raw 32-byte seed derives exact Ed25519 pubkey');
$assert($fromSeedHex->publicKeyRaw() === $expectedPk, 'hex 32-byte seed derives exact Ed25519 pubkey');
$assert($fromSeedB64->publicKeyRaw() === $expectedPk, 'base64url 32-byte seed derives exact Ed25519 pubkey');
$assert($fromSk64Raw->publicKeyRaw() === $expectedPk, 'raw 64-byte secret key derives exact Ed25519 pubkey');
$assert($fromSk64Hex->publicKeyRaw() === $expectedPk, 'hex 64-byte secret key derives exact Ed25519 pubkey');
$assert($fromSk64B64->publicKeyRaw() === $expectedPk, 'base64url 64-byte secret key derives exact Ed25519 pubkey');
$assert(str_starts_with($fromSeedHex->verifyKeySpec(), 'k-seed='), 'verifyKeySpec formats kid=pubkey');

// ── 3. WaitingRoomSignal ─────────────────────────────────────────────────────
$sig = WaitingRoomSignal::fromHeaders([
    'X-Concert-Queue'      => '1',
    'X-Concert-Position'   => '17',
    'Retry-After'          => '4',
    'X-Concert-Status-Url' => '/_status',
]);
$assert($sig->isQueued() && $sig->position() === 17 && $sig->retryAfterSeconds() === 4 && $sig->statusUrl() === '/_status' && $sig->shouldBackoff(), 'WaitingRoomSignal parses all headers');

$psrQueued = $makeResponse([
    'x-concert-queue'    => ['1'],
    'x-concert-position' => ['0'],
    'retry-after'        => ['2'],
]);
$sigFromPsr = WaitingRoomSignal::fromResponse($psrQueued);
$assert($sigFromPsr->isQueued() && $sigFromPsr->position() === 0 && $sigFromPsr->retryAfterSeconds() === 2, 'WaitingRoomSignal parses PSR-7 response');

// ── 4. CachePurgeClient ──────────────────────────────────────────────────────
$fakeAdminTok = 'php-sdk-unit-token-' . bin2hex(random_bytes(8));
$mockTransport = new class implements HttpTransportInterface {
    /** @var array<int, array<string, mixed>> */
    public array $requests = [];
    /** @var callable(string, string, array<string, string>, ?string): array<string, mixed> */
    public $responder;

    public function send(string $method, string $url, array $headers = [], ?string $body = null, int $timeoutSeconds = 5): array
    {
        $this->requests[] = ['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $body, 'timeout' => $timeoutSeconds];
        return ($this->responder)($method, $url, $headers, $body);
    }
};

$mockTransport->responder = static function (string $method, string $url, array $headers, ?string $body): array {
    $data = json_decode((string) $body, true);
    return [
        'status'  => 200,
        'headers' => ['Cache-Control' => 'no-store'],
        'body'    => json_encode(['purged' => 5, 'mode' => $data['mode']]),
    ];
};

$purgeClient = new CachePurgeClient('https://edge.example.test', Secret::fromString($fakeAdminTok), $mockTransport);
$pRes = $purgeClient->purgePrefix('/products/', 'shop.example.test');
$assert($pRes['ok'] === true && $pRes['purged'] === 5 && $pRes['mode'] === 'prefix', 'CachePurgeClient::purgePrefix succeeds');
$assert($mockTransport->requests[0]['url'] === 'https://edge.example.test/_room/cache/purge', 'exact purge path');
$assert($mockTransport->requests[0]['headers']['Authorization'] === 'Bearer ' . $fakeAdminTok, 'Bearer header sent');
$assertThrows(InvalidArgumentException::class, static fn() => new CachePurgeClient('http://remote.example.test', Secret::fromString($fakeAdminTok), $mockTransport), 'remote http endpoint rejected');

// Scrub token on transport failure
$mockTransport->responder = static fn() => ['status' => 502, 'headers' => [], 'body' => '', 'error' => 'failed with ' . $fakeAdminTok];
$pErr = $purgeClient->purgeAll();
$assert($pErr['ok'] === false && !str_contains((string) $pErr['error'], $fakeAdminTok), 'CachePurgeClient scrubs token from errors');

// ── 5. AgentBidClient (100% CRYPTO-ONLY) ─────────────────────────────────────
$mockTransport->requests = [];
$mockTransport->responder = static function (string $method, string $url, array $headers, ?string $body): array {
    if ($method === 'POST' && str_ends_with($url, '/_concert/bids')) {
        return [
            'status'  => 202,
            'headers' => ['Cache-Control' => 'no-store'],
            'body'    => json_encode([
                'bid_id'     => 'bid-sol-1',
                'status'     => 'pending',
                'status_url' => '/_concert/bids/status?bid_id=bid-sol-1',
            ]),
        ];
    }
    return [
        'status'  => 200,
        'headers' => ['Cache-Control' => 'no-store'],
        'body'    => json_encode([
            'bid_id'        => 'bid-sol-1',
            'status'        => 'settled',
            'pass_issued'   => true,
            'priority_pass' => 'signed-priority-token-placeholder',
        ]),
    ];
};

$bidClient = new AgentBidClient('https://edge.example.test', $mockTransport, 5_000_000);
$subRes = $bidClient->submitBid(
    'solana',
    'USDC',
    '2500000',
    ['scheme' => 'exact', 'network' => 'solana:mainnet', 'payload' => ['tx' => 'base64tx']],
    ['scope' => 'api.example.test', 'estimated_micro_usd' => 2_500_000]
);
$assert($subRes['ok'] === true && $subRes['status_code'] === 202 && $subRes['bid_id'] === 'bid-sol-1' && $subRes['status'] === 'pending', 'AgentBidClient submits crypto bid');

$stRes = $bidClient->getBidStatus('bid-sol-1');
$assert($stRes['ok'] === true && $stRes['status'] === 'settled' && $stRes['pass_issued'] === true && $stRes['priority_pass'] !== null, 'AgentBidClient polls bid status & receives pass');

// Reject unsupported / non-crypto chains and over-budget bids
$assertThrows(InvalidArgumentException::class, static fn() => $bidClient->submitBid('credit_card', 'USD', '100', ['x' => 1]), 'non-crypto chain rejected');
$assertThrows(InvalidArgumentException::class, static fn() => $bidClient->submitBid('xrpl', 'XRP', '9000000', ['x' => 1], ['estimated_micro_usd' => 9_000_000]), 'bid exceeding maxBidMicroUsd rejected');
$assertThrows(InvalidArgumentException::class, static fn() => $bidClient->submitBid('hedera', 'HBAR', '0', ['x' => 1]), 'zero amount_atomic rejected');

// Verify all 4 crypto chains are accepted
foreach (['xrpl', 'stellar', 'hedera', 'solana'] as $chain) {
    $r = $bidClient->submitBid($chain, 'NATIVE', '1000', ['sig' => 'ok'], ['estimated_micro_usd' => 1_000_000]);
    $assert($r['ok'] === true, "crypto chain {$chain} accepted");
}

// ── 6. Framework Adapters ────────────────────────────────────────────────────
$reqWithAttrs = new class {
    /** @var array<string, mixed> */
    public array $attrs = [];
    public function getAttribute(string $name, mixed $default = null): mixed
    {
        return $this->attrs[$name] ?? $default;
    }
};

// Slim 4
$slim = new SlimAdapter(static fn(object $r): array => ['checkout' => true]);
$slimOut = $slim($reqWithAttrs, $makeHandler($makeResponse()));
$assert($slimOut->getHeaderLine('Concert-Priority') === 'checkout; ttl=1800', 'SlimAdapter sets Concert-Priority');

// CakePHP
$reqWithAttrs->attrs['identity'] = ['role' => 'admin'];
$cake = new CakePhpAdapter();
$cakeOut = $cake->process($reqWithAttrs, $makeHandler($makeResponse()));
$assert($cakeOut->getHeaderLine('Concert-Priority') === 'staff; ttl=28800', 'CakePhpAdapter maps admin identity to staff');

// Laminas (PSR-7 + Laminas\Http\Response style)
$laminas = new LaminasAdapter(static fn(object $r): array => ['customer' => true]);
$lamPsr = $laminas->process($reqWithAttrs, $makeHandler($makeResponse()));
$assert($lamPsr->getHeaderLine('Concert-Priority') === 'customer; ttl=28800', 'LaminasAdapter Mezzio PSR-15');
$lamMvcHeaders = new class {
    /** @var array<string, string> */
    public array $lines = [];
    public function addHeaderLine(string $name, string $val): void
    {
        $this->lines[$name] = $val;
    }
};
$lamMvcResp = new class($lamMvcHeaders) {
    private object $h;
    public function __construct(object $h)
    {
        $this->h = $h;
    }
    public function getHeaders(): object
    {
        return $this->h;
    }
};
LaminasAdapter::applyToResponse($lamMvcResp, ['subscriber' => true], 3600);
$assert(($lamMvcHeaders->lines['Concert-Priority'] ?? '') === 'subscriber; ttl=3600', 'LaminasAdapter MVC response header');

// Invision Power Board (IPB)
$ipb = new InvisionAdapter([4, 6], [9]);
$assert($ipb->classifyMember(['member_id' => 10, 'member_group_id' => 4]) === 'staff', 'IPB admin -> staff');
$assert($ipb->classifyMember(['member_id' => 11, 'member_group_id' => 3, 'mgroup_others' => '9']) === 'subscriber', 'IPB supporter group -> subscriber');
$assert($ipb->classifyMember(['member_id' => 12, 'member_group_id' => 3], ['checkout_active' => true]) === 'checkout', 'IPB commerce checkout -> checkout');
$assert($ipb->classifyMember(['member_id' => 0]) === 'guest', 'IPB guest -> guest');

// phpBB
$phpbb = new PhpBbAdapter([8]);
$adminAuth = new class {
    public function acl_get(string $perm): bool
    {
        return $perm === 'a_';
    }
};
$assert($phpbb->classifyUser(['user_id' => 2, 'is_registered' => true, 'group_id' => 5], $adminAuth) === 'staff', 'phpBB admin -> staff');
$assert($phpbb->classifyUser(['user_id' => 5, 'is_registered' => true, 'group_id' => 8]) === 'subscriber', 'phpBB supporter group -> subscriber');
$assert($phpbb->classifyUser(['user_id' => 6, 'is_registered' => true, 'group_id' => 2]) === 'member', 'phpBB registered -> member');
$assert($phpbb->classifyUser(['user_id' => 1, 'is_registered' => false]) === 'guest', 'phpBB anonymous -> guest');

// Vanilla PHP
$emitted = [];
$vanilla = new VanillaPhpAdapter('concert_rank', static function (string $val) use (&$emitted): bool {
    $emitted[] = $val;
    return true;
});
$sess = [];
$vanilla->sync([], $sess);
$assert($emitted === [], 'VanillaPhpAdapter emits nothing for unranked guest');
$vanilla->sync(['prospect' => true], $sess, 1200);
$assert($emitted === ['prospect; ttl=1200'] && $sess['concert_rank'] === 'prospect', 'VanillaPhpAdapter emits prospect');
$vanilla->sync([], $sess);
$assert($emitted === ['prospect; ttl=1200', 'guest'] && $sess['concert_rank'] === 'guest', 'VanillaPhpAdapter emits single guest clear');
$vanilla->clear($sess);
$assert(!isset($sess['concert_rank']), 'VanillaPhpAdapter clears session key');

// ── 7. Secret redaction & 0600 file enforcement ──────────────────────────────
$sec = Secret::fromString($fakeAdminTok, 'test:secret');
$assert((string) $sec === Secret::REDACTED, 'Secret __toString redacts');
$assert(!str_contains(print_r($sec, true), $fakeAdminTok), 'Secret __debugInfo redacts');
$assert(json_encode($sec) === '"' . Secret::REDACTED . '"', 'Secret jsonSerialize redacts');

$tmpDir = sys_get_temp_dir() . '/concert-php-test-' . bin2hex(random_bytes(4));
mkdir($tmpDir, 0700, true);
$file = $tmpDir . '/token';
file_put_contents($file, $fakeAdminTok . "\n");
chmod($file, 0644);
$assertThrows(RuntimeException::class, static fn() => Secret::fromFile($file), '0644 secret file rejected');
chmod($file, 0600);
$assert(Secret::fromFile($file)->reveal() === $fakeAdminTok, '0600 secret file loaded');
@unlink($file);
@rmdir($tmpDir);

echo "PHP SDK tests: {$passed} passed, {$failed} failed\n";
exit($failed > 0 ? 1 : 0);
