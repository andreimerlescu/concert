<?php
declare(strict_types=1);

namespace Concert;

use InvalidArgumentException;
use JsonException;

/**
 * Authenticated client for Concert's POST /_room/cache/purge endpoint.
 */
final class CachePurgeClient
{
    public const PURGE_PATH = '/_room/cache/purge';
    public const VALID_MODES = ['url', 'prefix', 'tag', 'all'];

    private string $endpoint;
    private Secret $adminToken;
    private HttpTransportInterface $transport;
    private int $timeoutSeconds;

    public function __construct(
        string $endpoint,
        Secret $adminToken,
        ?HttpTransportInterface $transport = null,
        int $timeoutSeconds = 5
    ) {
        $this->endpoint = EndpointValidator::validateEndpoint($endpoint);
        $this->adminToken = $adminToken;
        $this->transport = $transport ?? new CurlHttpTransport();
        $this->timeoutSeconds = max(1, min(30, $timeoutSeconds));
    }

    /**
     * @return array{mode: string, host: string, target: string}
     */
    public static function buildPayload(string $mode, string $target = '', string $host = ''): array
    {
        $mode = strtolower(trim($mode));
        if (!in_array($mode, self::VALID_MODES, true)) {
            throw new InvalidArgumentException('Purge mode must be one of: url, prefix, tag, all.');
        }

        $host = EndpointValidator::assertCleanHeaderValue($host, 'host');
        $target = EndpointValidator::assertCleanHeaderValue($target, 'target');

        if ($mode !== 'all' && $target === '') {
            throw new InvalidArgumentException("Target is required for purge mode '{$mode}'.");
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
     * Executes POST /_room/cache/purge and returns a secret-free result array.
     *
     * @return array{ok: bool, status: int, purged: int, mode: string, error: ?string, waiting_room: WaitingRoomSignal}
     */
    public function purge(string $mode, string $target = '', string $host = ''): array
    {
        $payload = self::buildPayload($mode, $target, $host);
        try {
            $json = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException) {
            return [
                'ok'           => false,
                'status'       => 0,
                'purged'       => 0,
                'mode'         => $payload['mode'],
                'error'        => 'Failed to JSON-encode purge request.',
                'waiting_room' => WaitingRoomSignal::fromHeaders([]),
            ];
        }

        $rawToken = $this->adminToken->reveal();
        $resp = $this->transport->send(
            'POST',
            $this->endpoint . self::PURGE_PATH,
            [
                'Content-Type'  => 'application/json',
                'Accept'        => 'application/json',
                'Authorization' => 'Bearer ' . $rawToken,
            ],
            $json,
            $this->timeoutSeconds
        );

        $status = (int) ($resp['status'] ?? 0);
        $headers = is_array($resp['headers'] ?? null) ? $resp['headers'] : [];
        $signal = WaitingRoomSignal::fromHeaders($headers);

        if (!empty($resp['error'])) {
            return [
                'ok'           => false,
                'status'       => $status,
                'purged'       => 0,
                'mode'         => $payload['mode'],
                'error'        => str_replace($rawToken, Secret::REDACTED, (string) $resp['error']),
                'waiting_room' => $signal,
            ];
        }

        $decoded = json_decode((string) ($resp['body'] ?? ''), true);
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

        $err = is_array($decoded) && isset($decoded['error']) ? (string) $decoded['error'] : "HTTP {$status}";
        return [
            'ok'           => false,
            'status'       => $status,
            'purged'       => 0,
            'mode'         => $payload['mode'],
            'error'        => str_replace($rawToken, Secret::REDACTED, $err),
            'waiting_room' => $signal,
        ];
    }

    /**
     * @return array{ok: bool, status: int, purged: int, mode: string, error: ?string, waiting_room: WaitingRoomSignal}
     */
    public function purgeUrl(string $path, string $host = ''): array
    {
        return $this->purge('url', $path, $host);
    }

    /**
     * @return array{ok: bool, status: int, purged: int, mode: string, error: ?string, waiting_room: WaitingRoomSignal}
     */
    public function purgePrefix(string $prefix, string $host = ''): array
    {
        return $this->purge('prefix', $prefix, $host);
    }

    /**
     * @return array{ok: bool, status: int, purged: int, mode: string, error: ?string, waiting_room: WaitingRoomSignal}
     */
    public function purgeTag(string $tag, string $host = ''): array
    {
        return $this->purge('tag', $tag, $host);
    }

    /**
     * @return array{ok: bool, status: int, purged: int, mode: string, error: ?string, waiting_room: WaitingRoomSignal}
     */
    public function purgeAll(string $host = ''): array
    {
        return $this->purge('all', '', $host);
    }
}
