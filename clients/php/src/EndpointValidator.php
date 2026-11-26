<?php
declare(strict_types=1);

namespace Concert;

use InvalidArgumentException;

/**
 * Shared boundary validation and encoding helpers (S9).
 */
final class EndpointValidator
{
    private const LOOPBACK_HOSTS = [
        'localhost',
        '127.0.0.1',
        '::1',
        '[::1]',
    ];

    /**
     * Validates a Concert base URL: allows https:// anywhere and http:// only
     * on loopback addresses (localhost, 127.0.0.1, ::1).
     */
    public static function validateEndpoint(string $url): string
    {
        $url = trim($url);
        if ($url === '' || strlen($url) > 2048) {
            throw new InvalidArgumentException('Concert endpoint URL must be between 1 and 2048 bytes.');
        }
        if (preg_match('/[\x00-\x1F\x7F\s]/', $url) === 1) {
            throw new InvalidArgumentException('Concert endpoint URL contains control characters or whitespace.');
        }

        $parts = parse_url($url);
        if (!is_array($parts)) {
            throw new InvalidArgumentException('Concert endpoint URL is malformed.');
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new InvalidArgumentException('Concert endpoint URL must not contain embedded credentials.');
        }
        if (isset($parts['query']) || isset($parts['fragment'])) {
            throw new InvalidArgumentException('Concert endpoint URL must not include query strings or fragments.');
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));
        if ($host === '') {
            throw new InvalidArgumentException('Concert endpoint URL requires a host.');
        }

        if ($scheme === 'https') {
            // Permitted for any host.
        } elseif ($scheme === 'http') {
            if (!in_array($host, self::LOOPBACK_HOSTS, true)) {
                throw new InvalidArgumentException(
                    'Concert endpoint URL must use https:// (http:// is allowed only for localhost, 127.0.0.1, or ::1).'
                );
            }
        } else {
            throw new InvalidArgumentException('Concert endpoint URL scheme must be https or loopback http.');
        }

        if (isset($parts['port'])) {
            $port = (int) $parts['port'];
            if ($port < 1 || $port > 65535) {
                throw new InvalidArgumentException('Concert endpoint URL port is out of range.');
            }
        }

        return rtrim($url, '/');
    }

    public static function assertCleanHeaderValue(string $value, string $field): string
    {
        if (preg_match('/[\r\n\x00]/', $value) === 1) {
            throw new InvalidArgumentException("Forbidden control character in {$field}.");
        }
        return trim($value);
    }

    /**
     * RFC 4648 base64url encoding without '=' padding (matches Go base64.RawURLEncoding).
     */
    public static function base64UrlEncode(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * Strict RFC 4648 base64url decoding (unpadded, rejects non-canonical trailing bits).
     */
    public static function base64UrlDecodeStrict(string $encoded): string
    {
        if ($encoded === '' || preg_match('/^[A-Za-z0-9_-]+$/', $encoded) !== 1) {
            throw new InvalidArgumentException('Malformed base64url encoding.');
        }
        $mod = strlen($encoded) % 4;
        if ($mod === 1) {
            throw new InvalidArgumentException('Invalid base64url length.');
        }
        $padded = $encoded . str_repeat('=', (4 - $mod) % 4);
        $decoded = base64_decode(strtr($padded, '-_', '+/'), true);
        if (!is_string($decoded)) {
            throw new InvalidArgumentException('Base64url decode failed.');
        }
        // Strict canonical check matching Go's base64.RawURLEncoding.Strict().
        if (self::base64UrlEncode($decoded) !== $encoded) {
            throw new InvalidArgumentException('Non-canonical base64url encoding.');
        }
        return $decoded;
    }
}
