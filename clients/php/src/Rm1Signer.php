<?php
declare(strict_types=1);

namespace Concert;

use InvalidArgumentException;
use JsonException;
use RuntimeException;

/**
 * Stateless Ed25519 signer and verifier for Concert's `rm1` VIP pass and lease
 * envelopes (compatible with github.com/andreimerlescu/room v1.9.0).
 *
 * Wire format:
 *   rm1.<base64url(json(claims))>.<base64url(ed25519_sig)>
 *
 * Signing input:
 *   "rm1." . base64url(json(claims))
 *
 * Claims JSON:
 *   {"kid":"<kid>","kind":"pass"|"lease","scope":"<scope>","key":"<optional>","iat":<unix>,"exp":<unix>}
 *   Note: "key" is omitted when empty (matching Go's `json:"key,omitempty"`).
 */
final class Rm1Signer
{
    public const WIRE_PREFIX = 'rm1';
    public const KIND_PASS = 'pass';
    public const KIND_LEASE = 'lease';
    public const MIN_TTL_SECONDS = 1;
    public const DEFAULT_MAX_TTL_SECONDS = 600;
    public const HARD_MAX_TTL_SECONDS = 3600;
    public const MAX_KEY_ID_LEN = 64;
    public const MAX_SCOPE_LEN = 255;
    public const MAX_TOKEN_LEN = 2048;

    private string $keyId;
    private Secret $secretKey64;
    private string $publicKey32;
    private int $maxTtlSeconds;

    /** @var callable(): int */
    private $clock;

    private function __construct(
        string $keyId,
        Secret $secretKey64,
        string $publicKey32,
        int $maxTtlSeconds = self::DEFAULT_MAX_TTL_SECONDS,
        ?callable $clock = null
    ) {
        self::assertSodiumAvailable();
        self::validateKeyId($keyId);
        if ($maxTtlSeconds < self::MIN_TTL_SECONDS || $maxTtlSeconds > self::HARD_MAX_TTL_SECONDS) {
            throw new InvalidArgumentException(
                sprintf('maxTtlSeconds must be between %d and %d.', self::MIN_TTL_SECONDS, self::HARD_MAX_TTL_SECONDS)
            );
        }
        $this->keyId = $keyId;
        $this->secretKey64 = $secretKey64;
        $this->publicKey32 = $publicKey32;
        $this->maxTtlSeconds = $maxTtlSeconds;
        $this->clock = $clock ?? static fn(): int => time();
    }

    /**
     * Generates a fresh ephemeral Ed25519 keypair (useful for tests or short-lived issuers).
     */
    public static function generate(
        string $keyId,
        int $maxTtlSeconds = self::DEFAULT_MAX_TTL_SECONDS,
        ?callable $clock = null
    ): self {
        self::assertSodiumAvailable();
        $kp = sodium_crypto_sign_keypair();
        $sk = sodium_crypto_sign_secretkey($kp);
        $pk = sodium_crypto_sign_publickey($kp);
        return new self($keyId, Secret::fromRawBytes($sk, 'generated:ed25519'), $pk, $maxTtlSeconds, $clock);
    }

    /**
     * Creates a signer from an Ed25519 private key wrapped in Secret.
     *
     * Accepts either a 64-byte Ed25519 secret key (Go/libsodium format) or a
     * 32-byte Ed25519 seed, supplied as raw bytes, hex, base64url, or standard base64.
     */
    public static function fromSecretKey(
        string $keyId,
        Secret $secret,
        int $maxTtlSeconds = self::DEFAULT_MAX_TTL_SECONDS,
        ?callable $clock = null
    ): self {
        self::assertSodiumAvailable();
        $raw = self::decodePrivateKeyMaterial($secret->reveal());

        if (strlen($raw) === SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            $kp = sodium_crypto_sign_seed_keypair($raw);
            $sk = sodium_crypto_sign_secretkey($kp);
            $pk = sodium_crypto_sign_publickey($kp);
        } elseif (strlen($raw) === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            $sk = $raw;
            $pk = sodium_crypto_sign_publickey_from_secretkey($sk);
        } else {
            throw new InvalidArgumentException(
                sprintf(
                    'Ed25519 private key must decode to %d-byte seed or %d-byte secret key.',
                    SODIUM_CRYPTO_SIGN_SEEDBYTES,
                    SODIUM_CRYPTO_SIGN_SECRETKEYBYTES
                )
            );
        }

        return new self(
            $keyId,
            Secret::fromRawBytes($sk, $secret->source()),
            $pk,
            $maxTtlSeconds,
            $clock
        );
    }

    public function keyId(): string
    {
        return $this->keyId;
    }

    public function publicKeyRaw(): string
    {
        return $this->publicKey32;
    }

    public function publicKeyBase64Url(): string
    {
        return EndpointValidator::base64UrlEncode($this->publicKey32);
    }

    public function publicKeyHex(): string
    {
        return bin2hex($this->publicKey32);
    }

    /**
     * Returns "<kid>=<base64url-pubkey>" ready for Concert's -room-verify-keys flag.
     */
    public function verifyKeySpec(): string
    {
        return $this->keyId . '=' . $this->publicKeyBase64Url();
    }

    /**
     * Mints a signed `rm1` VIP pass envelope (for X-Room-Pass header or room_pass cookie).
     * Pass $clientKey = '' for an anonymous browser pass, or a client key for an API pass.
     */
    public function mintPass(string $scope, string $clientKey = '', int $ttlSeconds = 300): string
    {
        return $this->mintEnvelope($scope, self::KIND_PASS, $clientKey, $ttlSeconds);
    }

    /**
     * Mints a signed `rm1` lease envelope (for X-Room-Lease header).
     * Requires a non-empty client key (matching room/token.go MintLease).
     */
    public function mintLease(string $scope, string $clientKey, int $ttlSeconds = 300): string
    {
        if (trim($clientKey) === '') {
            throw new InvalidArgumentException('Lease token requires a non-empty client key.');
        }
        return $this->mintEnvelope($scope, self::KIND_LEASE, $clientKey, $ttlSeconds);
    }

    /**
     * Verifies an `rm1` token against a map of kid => 32-byte raw Ed25519 public keys,
     * following the exact security-first order from room/token.go:
     *   1. Framing & strict base64url + JSON decode
     *   2. Ed25519 signature verification
     *   3. Scope, kind, and key binding
     *   4. Issued-at skew and expiry
     *
     * @param array<string, string> $publicKeysByKid Map of kid => 32-byte raw public key
     * @return array{kid: string, kind: string, scope: string, key: string, iat: int, exp: int}
     * @throws InvalidArgumentException|RuntimeException
     */
    public static function verify(
        string $token,
        array $publicKeysByKid,
        string $expectedScope,
        string $expectedKind,
        string $expectedKey = '',
        ?int $now = null,
        int $maxSkewSeconds = 30
    ): array {
        self::assertSodiumAvailable();
        if ($expectedScope === '') {
            throw new InvalidArgumentException('missing_scope');
        }
        if ($publicKeysByKid === []) {
            throw new InvalidArgumentException('no_verifier');
        }
        if ($token === '' || strlen($token) > self::MAX_TOKEN_LEN) {
            throw new RuntimeException('malformed');
        }

        $parts = explode('.', $token);
        if (count($parts) !== 3 || $parts[0] !== self::WIRE_PREFIX || $parts[1] === '' || $parts[2] === '') {
            throw new RuntimeException('malformed');
        }

        try {
            $payloadJson = EndpointValidator::base64UrlDecodeStrict($parts[1]);
            $sig = EndpointValidator::base64UrlDecodeStrict($parts[2]);
            $claims = json_decode($payloadJson, true, 8, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            throw new RuntimeException('malformed');
        }

        if (!is_array($claims)) {
            throw new RuntimeException('malformed');
        }

        // Disallow unknown fields (matches Go json.Decoder.DisallowUnknownFields()).
        $allowedKeys = ['kid', 'kind', 'scope', 'key', 'iat', 'exp'];
        foreach (array_keys($claims) as $k) {
            if (!in_array((string) $k, $allowedKeys, true)) {
                throw new RuntimeException('malformed');
            }
        }

        $kid = isset($claims['kid']) && is_string($claims['kid']) ? $claims['kid'] : '';
        $kind = isset($claims['kind']) && is_string($claims['kind']) ? $claims['kind'] : '';
        $scope = isset($claims['scope']) && is_string($claims['scope']) ? $claims['scope'] : '';
        $key = isset($claims['key']) && is_string($claims['key']) ? $claims['key'] : '';
        $iat = isset($claims['iat']) && is_int($claims['iat']) ? $claims['iat'] : 0;
        $exp = isset($claims['exp']) && is_int($claims['exp']) ? $claims['exp'] : 0;

        if ($kid === '' || $scope === '' || $iat <= 0 || $exp <= $iat) {
            throw new RuntimeException('malformed');
        }
        if ($kind !== self::KIND_PASS && $kind !== self::KIND_LEASE) {
            throw new RuntimeException('malformed');
        }

        if (!isset($publicKeysByKid[$kid])) {
            throw new RuntimeException('unknown_key');
        }
        $pubKey = $publicKeysByKid[$kid];
        if (strlen($pubKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new RuntimeException('invalid_signature');
        }

        $signingInput = $parts[0] . '.' . $parts[1];
        if (!sodium_crypto_sign_verify_detached($sig, $signingInput, $pubKey)) {
            throw new RuntimeException('invalid_signature');
        }

        if ($scope !== $expectedScope) {
            throw new RuntimeException('wrong_scope');
        }
        if ($kind !== $expectedKind) {
            throw new RuntimeException('wrong_kind');
        }
        if ($expectedKind === self::KIND_LEASE) {
            if ($key === '') {
                throw new RuntimeException('malformed');
            }
            if (!hash_equals($expectedKey, $key)) {
                throw new RuntimeException('key_mismatch');
            }
        } elseif ($key !== '' && !hash_equals($expectedKey, $key)) {
            throw new RuntimeException('key_mismatch');
        }

        $current = $now ?? time();
        if ($iat > $current + max(0, $maxSkewSeconds)) {
            throw new RuntimeException('future_issued');
        }
        if ($current >= $exp) {
            throw new RuntimeException('expired');
        }

        return [
            'kid'   => $kid,
            'kind'  => $kind,
            'scope' => $scope,
            'key'   => $key,
            'iat'   => $iat,
            'exp'   => $exp,
        ];
    }

    /**
     * Convenience wrapper verifying a token using this signer's own public key.
     *
     * @return array{kid: string, kind: string, scope: string, key: string, iat: int, exp: int}
     */
    public function verifyOwn(
        string $token,
        string $expectedScope,
        string $expectedKind,
        string $expectedKey = '',
        ?int $now = null
    ): array {
        return self::verify(
            $token,
            [$this->keyId => $this->publicKey32],
            $expectedScope,
            $expectedKind,
            $expectedKey,
            $now ?? ($this->clock)()
        );
    }

    private function mintEnvelope(string $scope, string $kind, string $clientKey, int $ttlSeconds): string
    {
        $scope = trim($scope);
        if ($scope === '' || strlen($scope) > self::MAX_SCOPE_LEN) {
            throw new InvalidArgumentException('Scope must be between 1 and 255 bytes.');
        }
        if ($ttlSeconds < self::MIN_TTL_SECONDS || $ttlSeconds > $this->maxTtlSeconds) {
            throw new InvalidArgumentException(
                sprintf('Token TTL must be between %d and %d seconds.', self::MIN_TTL_SECONDS, $this->maxTtlSeconds)
            );
        }
        if ($clientKey !== '') {
            EndpointValidator::assertCleanHeaderValue($clientKey, 'client key');
        }

        $iat = ($this->clock)();
        $exp = $iat + $ttlSeconds;
        if ($exp <= $iat) {
            $exp = $iat + 1;
        }

        $claims = [
            'kid'   => $this->keyId,
            'kind'  => $kind,
            'scope' => $scope,
        ];
        if ($clientKey !== '') {
            $claims['key'] = $clientKey;
        }
        $claims['iat'] = $iat;
        $claims['exp'] = $exp;

        try {
            $json = json_encode($claims, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException $e) {
            throw new RuntimeException('Failed to encode rm1 claims.', 0, $e);
        }

        $payloadB64 = EndpointValidator::base64UrlEncode($json);
        $signingInput = self::WIRE_PREFIX . '.' . $payloadB64;
        $sig = sodium_crypto_sign_detached($signingInput, $this->secretKey64->reveal());

        return $signingInput . '.' . EndpointValidator::base64UrlEncode($sig);
    }

    private static function validateKeyId(string $kid): void
    {
        if ($kid === '' || strlen($kid) > self::MAX_KEY_ID_LEN) {
            throw new InvalidArgumentException('Key ID must be between 1 and 64 bytes.');
        }
        EndpointValidator::assertCleanHeaderValue($kid, 'kid');
    }

    private static function assertSodiumAvailable(): void
    {
        if (!function_exists('sodium_crypto_sign_detached')) {
            throw new RuntimeException('PHP ext-sodium is required for Ed25519 rm1 signing.');
        }
    }

    private static function decodePrivateKeyMaterial(string $input): string
    {
        $trimmed = trim($input);

        // 1. Hex encoding (64 hex chars = 32-byte seed; 128 hex chars = 64-byte secret key).
        if ((strlen($trimmed) === 64 || strlen($trimmed) === 128) && ctype_xdigit($trimmed)) {
            $bin = hex2bin($trimmed);
            if (is_string($bin)) {
                return $bin;
            }
        }

        // 2. Base64url or standard Base64 (43/44 chars = 32-byte seed; 86/88 chars = 64-byte secret key).
        $tLen = strlen($trimmed);
        if (in_array($tLen, [43, 44, 86, 88], true) && preg_match('/^[A-Za-z0-9+\/_-]+={0,2}$/', $trimmed) === 1) {
            $b64 = strtr($trimmed, '-_', '+/');
            $mod = strlen($b64) % 4;
            if ($mod !== 0) {
                $b64 .= str_repeat('=', 4 - $mod);
            }
            $decoded = base64_decode($b64, true);
            if (is_string($decoded) && (strlen($decoded) === SODIUM_CRYPTO_SIGN_SEEDBYTES || strlen($decoded) === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES)) {
                return $decoded;
            }
        }

        // 3. Raw binary bytes (32-byte seed or 64-byte Go/libsodium Ed25519 secret key).
        $rawLen = strlen($input);
        if ($rawLen === SODIUM_CRYPTO_SIGN_SEEDBYTES || $rawLen === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            return $input;
        }

        throw new InvalidArgumentException('Unsupported Ed25519 private key encoding (expected raw, hex, base64url, or base64).');
    }
}
