<?php
declare(strict_types=1);

namespace Concert\WordPress;

use InvalidArgumentException;

/**
 * Strict boundary validator for Concert endpoint URLs and HTTP header values (S9).
 *
 * Allows https:// for any host, and http:// strictly for loopback addresses
 * (localhost, 127.0.0.1, ::1) so local wpconcert daemons work without relaxing
 * transport security for remote origins.
 */
final class UrlValidator
{
    private const LOOPBACK_HOSTS = [
        'localhost',
        '127.0.0.1',
        '::1',
        '[::1]',
    ];

    /**
     * Validates and normalizes a Concert base endpoint URL (without trailing slash).
     *
     * @throws InvalidArgumentException when the URL fails policy checks.
     */
    public static function validateEndpoint(string $url): string
    {
        $url = trim($url);
        if ($url === '' || strlen($url) > 2048) {
            throw new InvalidArgumentException('Concert endpoint URL must be between 1 and 2048 bytes.');
        }
        if (preg_match('/[\x00-\x1F\x7F\s]/', $url) === 1) {
            throw new InvalidArgumentException('Concert endpoint URL contains whitespace or control characters.');
        }

        $parts = parse_url($url);
        if (!is_array($parts)) {
            throw new InvalidArgumentException('Concert endpoint URL is malformed.');
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new InvalidArgumentException('Concert endpoint URL must not embed credentials.');
        }
        if (isset($parts['query']) || isset($parts['fragment'])) {
            throw new InvalidArgumentException('Concert endpoint URL must not contain query strings or fragments.');
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));
        if ($host === '') {
            throw new InvalidArgumentException('Concert endpoint URL requires a host.');
        }

        if ($scheme === 'https') {
            // Allowed for any host.
        } elseif ($scheme === 'http') {
            if (!in_array($host, self::LOOPBACK_HOSTS, true)) {
                throw new InvalidArgumentException(
                    'Concert endpoint URL must use https:// (http:// is permitted only for localhost, 127.0.0.1, or ::1).'
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

    /**
     * Ensures a header or JSON string input contains no CR/LF/NUL control bytes.
     *
     * @throws InvalidArgumentException
     */
    public static function assertCleanHeaderValue(string $value, string $fieldName): string
    {
        if (preg_match('/[\r\n\x00]/', $value) === 1) {
            throw new InvalidArgumentException("Forbidden control character in {$fieldName}.");
        }
        return trim($value);
    }
}
