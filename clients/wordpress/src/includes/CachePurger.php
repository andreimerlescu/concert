<?php
declare(strict_types=1);

namespace Concert\WordPress;

use InvalidArgumentException;
use JsonException;

/**
 * Authenticated active cache purge client for wpconcert / concert-cache.
 *
 * Calls POST /_room/cache/purge with JSON payload:
 *   {"mode":"url"|"prefix"|"tag"|"all","host":"...","target":"..."}
 *
 * Enforces strict endpoint URL validation, TLS verification, timeouts, and
 * secret redaction (S5/S6/S7/S9).
 */
final class CachePurger
{
    public const VALID_MODES = ['url', 'prefix', 'tag', 'all'];
    public const PURGE_PATH = '/_room/cache/purge';
    public const DEFAULT_TIMEOUT_SECONDS = 5;

    private string $endpoint;
    private ?Secret $token;
    private string $defaultHost;
    private int $timeoutSeconds;

    /** @var callable(string, array<string, mixed>): array{status: int, body: string, headers?: array<string, string>, error?: string} */
    private $transport;

    /**
     * @param callable|null $transport Injectable HTTP POST transport for testing.
     */
    public function __construct(
        string $endpoint,
        ?Secret $token,
        string $defaultHost = '',
        int $timeoutSeconds = self::DEFAULT_TIMEOUT_SECONDS,
        ?callable $transport = null
    ) {
        $this->endpoint = UrlValidator::validateEndpoint($endpoint);
        $this->token = $token;
        $this->defaultHost = UrlValidator::assertCleanHeaderValue($defaultHost, 'host');
        $this->timeoutSeconds = max(1, min(30, $timeoutSeconds));
        $this->transport = $transport ?? [$this, 'wpTransport'];
    }

    /**
     * Builds and validates the JSON payload expected by Concert's POST /_room/cache/purge.
     *
     * @return array{mode: string, host: string, target: string}
     * @throws InvalidArgumentException
     */
    public static function buildPayload(string $mode, string $target = '', string $host = ''): array
    {
        $mode = strtolower(trim($mode));
        if (!in_array($mode, self::VALID_MODES, true)) {
            throw new InvalidArgumentException('Purge mode must be one of: url, prefix, tag, all.');
        }

        $host = UrlValidator::assertCleanHeaderValue($host, 'host');
        $target = UrlValidator::assertCleanHeaderValue($target, 'target');

        if ($mode !== 'all' && $target === '') {
            throw new InvalidArgumentException("Purge target is required for mode '{$mode}'.");
        }
        if ($mode === 'all') {
            $target = '';
        }

        return [
            'mode'   => $mode,
            'host'   => $host,
            'target' => $target,
        ];
    }

    /**
     * Executes a purge request. Fails closed when the admin token is absent.
     *
     * @return array{ok: bool, status: int, purged: int, mode: string, error: ?string, waiting_room?: array<string, mixed>}
     */
    public function purge(string $mode, string $target = '', ?string $host = null): array
    {
        if ($this->token === null) {
            return [
                'ok'     => false,
                'status' => 0,
                'purged' => 0,
                'mode'   => strtolower(trim($mode)),
                'error'  => 'CONCERT_ADMIN_TOKEN is not configured; cache purge refused (fail-closed).',
            ];
        }

        $effectiveHost = $host !== null ? $host : $this->defaultHost;
        $payload = self::buildPayload($mode, $target, $effectiveHost);

        try {
            $jsonBody = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException $e) {
            return [
                'ok'     => false,
                'status' => 0,
                'purged' => 0,
                'mode'   => $payload['mode'],
                'error'  => 'Failed to encode purge payload.',
            ];
        }

        $url = $this->endpoint . self::PURGE_PATH;
        $rawToken = $this->token->reveal();

        $response = ($this->transport)($url, [
            'method'      => 'POST',
            'timeout'     => $this->timeoutSeconds,
            'redirection' => 0,
            'sslverify'   => true,
            'headers'     => [
                'Content-Type'  => 'application/json',
                'Accept'        => 'application/json',
                'Authorization' => 'Bearer ' . $rawToken,
            ],
            'body'        => $jsonBody,
        ]);

        $status = (int) ($response['status'] ?? 0);
        $body = (string) ($response['body'] ?? '');
        $headers = is_array($response['headers'] ?? null) ? $response['headers'] : [];
        $signal = PriorityClassifier::parseWaitingRoomHeaders($headers);

        if (!empty($response['error'])) {
            return [
                'ok'           => false,
                'status'       => $status,
                'purged'       => 0,
                'mode'         => $payload['mode'],
                'error'        => $this->scrubSecret((string) $response['error'], $rawToken),
                'waiting_room' => $signal,
            ];
        }

        $decoded = json_decode($body, true);
        if ($status >= 200 && $status < 300) {
            return [
                'ok'           => true,
                'status'       => $status,
                'purged'       => is_array($decoded) ? (int) ($decoded['purged'] ?? 0) : 0,
                'mode'         => is_array($decoded) ? (string) ($decoded['mode'] ?? $payload['mode']) : $payload['mode'],
                'error'        => null,
                'waiting_room' => $signal,
            ];
        }

        $errMsg = is_array($decoded) && isset($decoded['error'])
            ? (string) $decoded['error']
            : "HTTP {$status}";

        return [
            'ok'           => false,
            'status'       => $status,
            'purged'       => 0,
            'mode'         => $payload['mode'],
            'error'        => $this->scrubSecret($errMsg, $rawToken),
            'waiting_room' => $signal,
        ];
    }

    /**
     * @return array{ok: bool, status: int, purged: int, mode: string, error: ?string, waiting_room?: array<string, mixed>}
     */
    public function purgeUrl(string $path, ?string $host = null): array
    {
        return $this->purge('url', $path, $host);
    }

    /**
     * @return array{ok: bool, status: int, purged: int, mode: string, error: ?string, waiting_room?: array<string, mixed>}
     */
    public function purgePrefix(string $prefix, ?string $host = null): array
    {
        return $this->purge('prefix', $prefix, $host);
    }

    /**
     * @return array{ok: bool, status: int, purged: int, mode: string, error: ?string, waiting_room?: array<string, mixed>}
     */
    public function purgeTag(string $tag, ?string $host = null): array
    {
        return $this->purge('tag', $tag, $host);
    }

    /**
     * @return array{ok: bool, status: int, purged: int, mode: string, error: ?string, waiting_room?: array<string, mixed>}
     */
    public function purgeAll(?string $host = null): array
    {
        return $this->purge('all', '', $host);
    }

    public function endpoint(): string
    {
        return $this->endpoint;
    }

    public function hasToken(): bool
    {
        return $this->token !== null;
    }

    public function tokenSource(): string
    {
        return $this->token !== null ? $this->token->source() : 'unconfigured';
    }

    /**
     * Default WordPress HTTP API transport.
     *
     * @param array<string, mixed> $args
     * @return array{status: int, body: string, headers: array<string, string>, error?: string}
     */
    private function wpTransport(string $url, array $args): array
    {
        if (!function_exists('wp_remote_post')) {
            return [
                'status'  => 0,
                'body'    => '',
                'headers' => [],
                'error'   => 'WordPress HTTP API (wp_remote_post) is unavailable.',
            ];
        }

        $res = wp_remote_post($url, $args);
        if (function_exists('is_wp_error') && is_wp_error($res)) {
            $msg = method_exists($res, 'get_error_message') ? (string) $res->get_error_message() : 'HTTP request failed';
            return [
                'status'  => 0,
                'body'    => '',
                'headers' => [],
                'error'   => $msg,
            ];
        }

        $status = function_exists('wp_remote_retrieve_response_code')
            ? (int) wp_remote_retrieve_response_code($res)
            : 0;
        $body = function_exists('wp_remote_retrieve_body')
            ? (string) wp_remote_retrieve_body($res)
            : '';
        $rawHeaders = function_exists('wp_remote_retrieve_headers')
            ? wp_remote_retrieve_headers($res)
            : [];

        $headers = [];
        if (is_array($rawHeaders) || $rawHeaders instanceof \Traversable) {
            foreach ($rawHeaders as $k => $v) {
                $headers[(string) $k] = is_array($v) ? (string) ($v[0] ?? '') : (string) $v;
            }
        }

        return [
            'status'  => $status,
            'body'    => $body,
            'headers' => $headers,
        ];
    }

    private function scrubSecret(string $message, string $rawToken): string
    {
        if ($rawToken === '') {
            return $message;
        }
        return str_replace($rawToken, Secret::REDACTED, $message);
    }
}
