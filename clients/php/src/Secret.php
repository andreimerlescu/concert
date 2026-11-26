<?php
declare(strict_types=1);

namespace Concert;

use InvalidArgumentException;
use JsonSerializable;
use RuntimeException;

/**
 * Redacting secret container (S3/S5/S6/S7/S8).
 *
 * Prevents credentials and Ed25519 private keys from leaking through string
 * interpolation, var_dump/print_r, logs, or JSON serialization.
 */
final class Secret implements JsonSerializable
{
    public const REDACTED = '[REDACTED]';

    private const PLACEHOLDERS = [
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

    private function __construct(string $value, string $source, bool $binary = false)
    {
        if ($binary) {
            if ($value === '') {
                throw new InvalidArgumentException('Secret binary key must not be empty.');
            }
            $this->value = $value;
            $this->source = $source;
            return;
        }

        $trimmed = trim($value);
        if ($trimmed === '') {
            throw new InvalidArgumentException('Secret value must not be empty.');
        }
        if (preg_match('/[\r\n\x00]/', $trimmed) === 1) {
            throw new InvalidArgumentException('Secret value contains forbidden control characters.');
        }
        if (in_array(strtolower($trimmed), self::PLACEHOLDERS, true)) {
            throw new InvalidArgumentException('Secret value must not be a placeholder.');
        }
        $this->value = $trimmed;
        $this->source = $source;
    }

    public static function fromString(string $value, string $source = 'runtime'): self
    {
        return new self($value, $source, false);
    }

    public static function fromRawBytes(string $bytes, string $source = 'runtime:binary'): self
    {
        return new self($bytes, $source, true);
    }

    /**
     * Loads a secret from an environment variable; fails closed if absent or empty.
     */
    public static function fromEnv(string $envName, ?callable $envReader = null): self
    {
        $reader = $envReader ?? static fn(string $name): string|false => getenv($name);
        $val = $reader($envName);
        if (!is_string($val) || trim($val) === '') {
            throw new RuntimeException("Required environment variable {$envName} is missing or empty.");
        }
        return new self($val, 'env:' . $envName, false);
    }

    /**
     * Loads a secret from a file path, rejecting world/group-readable files on POSIX (0600 max).
     */
    public static function fromFile(string $path, bool $binary = false): self
    {
        $path = trim($path);
        if ($path === '' || !is_file($path) || !is_readable($path)) {
            throw new RuntimeException('Secret file is missing or unreadable.');
        }
        if (DIRECTORY_SEPARATOR === '/') {
            $perms = @fileperms($path);
            if ($perms === false) {
                throw new RuntimeException('Unable to inspect secret file permissions.');
            }
            if (($perms & 0077) !== 0) {
                throw new RuntimeException('Secret file permissions are too open; require chmod 0600.');
            }
        }
        $raw = @file_get_contents($path);
        if (!is_string($raw)) {
            throw new RuntimeException('Unable to read secret file.');
        }
        return new self($raw, 'file:' . basename($path), $binary);
    }

    public function source(): string
    {
        return $this->source;
    }

    /**
     * Explicit raw accessor — call only at the exact cryptographic or HTTP header sink.
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
