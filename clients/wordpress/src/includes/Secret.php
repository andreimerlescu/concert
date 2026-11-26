<?php
declare(strict_types=1);

namespace Concert\WordPress;

use InvalidArgumentException;
use JsonSerializable;
use RuntimeException;

/**
 * Redacting secret container for Concert admin Bearer tokens (S3/S5/S6/S7).
 *
 * The raw token is read exclusively from runtime configuration (PHP constant,
 * mode-0600 secret file, or environment variable), never defaulted, and never
 * exposed via string casting, var_dump/print_r, or JSON encoding.
 */
final class Secret implements JsonSerializable
{
    public const REDACTED = '[REDACTED]';

    private const PLACEHOLDER_PATTERNS = [
        'changeme',
        'changeme-not-real',
        'your-token',
        'your_token',
        'your_token_here',
        'replace-me',
        'redacted',
        'example-token',
        'todo',
    ];

    private string $value;
    private string $source;

    private function __construct(string $value, string $source)
    {
        $trimmed = trim($value);
        if ($trimmed === '') {
            throw new InvalidArgumentException('Concert admin token must not be empty.');
        }
        if (preg_match('/[\r\n\x00]/', $trimmed) === 1) {
            throw new InvalidArgumentException('Concert admin token contains forbidden control characters.');
        }
        $lower = strtolower($trimmed);
        foreach (self::PLACEHOLDER_PATTERNS as $placeholder) {
            if ($lower === $placeholder) {
                throw new InvalidArgumentException('Concert admin token must not use a placeholder value.');
            }
        }
        $this->value = $trimmed;
        $this->source = $source;
    }

    /**
     * Constructs a Secret from an explicit runtime string (intended for tests
     * or custom secret managers).
     */
    public static function fromString(string $value, string $source = 'runtime'): self
    {
        return new self($value, $source);
    }

    /**
     * Loads a Secret from a file path, rejecting unreadable or world-readable
     * files on POSIX systems (S7/S8).
     */
    public static function fromFile(string $path, string $source = 'file'): self
    {
        $path = trim($path);
        if ($path === '' || !is_file($path) || !is_readable($path)) {
            throw new RuntimeException('Concert admin token file is missing or unreadable.');
        }
        if (DIRECTORY_SEPARATOR === '/') {
            $perms = @fileperms($path);
            if ($perms === false) {
                throw new RuntimeException('Unable to inspect Concert admin token file permissions.');
            }
            // Reject group-readable or world-readable files (require 0600 or stricter).
            if (($perms & 0077) !== 0) {
                throw new RuntimeException('Concert admin token file permissions are too open; require chmod 0600.');
            }
        }
        $raw = @file_get_contents($path);
        if (!is_string($raw)) {
            throw new RuntimeException('Unable to read Concert admin token file.');
        }
        return new self($raw, $source);
    }

    /**
     * Resolves the Concert admin Bearer token from the approved runtime
     * channels in order:
     *   1. PHP constant CONCERT_ADMIN_TOKEN
     *   2. PHP constant CONCERT_ADMIN_TOKEN_FILE or env CONCERT_ADMIN_TOKEN_FILE
     *   3. Environment variable CONCERT_ADMIN_TOKEN
     *
     * Returns null when unconfigured (fail-closed at call site).
     */
    public static function fromEnvironment(?callable $envReader = null): ?self
    {
        $getenv = $envReader ?? static function (string $name): string|false {
            return getenv($name);
        };

        if (defined('CONCERT_ADMIN_TOKEN')) {
            $constVal = constant('CONCERT_ADMIN_TOKEN');
            if (is_string($constVal) && trim($constVal) !== '') {
                return new self($constVal, 'constant:CONCERT_ADMIN_TOKEN');
            }
        }

        if (defined('CONCERT_ADMIN_TOKEN_FILE')) {
            $fileConst = constant('CONCERT_ADMIN_TOKEN_FILE');
            if (is_string($fileConst) && trim($fileConst) !== '') {
                return self::fromFile($fileConst, 'constant:CONCERT_ADMIN_TOKEN_FILE');
            }
        }

        $envFile = $getenv('CONCERT_ADMIN_TOKEN_FILE');
        if (is_string($envFile) && trim($envFile) !== '') {
            return self::fromFile($envFile, 'env:CONCERT_ADMIN_TOKEN_FILE');
        }

        $envVal = $getenv('CONCERT_ADMIN_TOKEN');
        if (is_string($envVal) && trim($envVal) !== '') {
            return new self($envVal, 'env:CONCERT_ADMIN_TOKEN');
        }

        return null;
    }

    /**
     * Returns the non-sensitive channel name describing where the token came from.
     */
    public function source(): string
    {
        return $this->source;
    }

    /**
     * Explicit raw accessor — call ONLY at the single Authorization header sink.
     */
    public function reveal(): string
    {
        return $this->value;
    }

    public function __toString(): string
    {
        return self::REDACTED;
    }

    /**
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return [
            'value'  => self::REDACTED,
            'source' => $this->source,
        ];
    }

    public function jsonSerialize(): string
    {
        return self::REDACTED;
    }
}
