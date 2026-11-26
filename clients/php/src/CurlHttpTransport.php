<?php
declare(strict_types=1);

namespace Concert;

use RuntimeException;

/**
 * Production HTTP transport backed by ext-curl with strict TLS verification,
 * disabled redirects, bounded response reads, and timeouts (S9).
 */
final class CurlHttpTransport implements HttpTransportInterface
{
    public const MAX_RESPONSE_BYTES = 1048576; // 1 MiB

    private int $maxResponseBytes;

    public function __construct(int $maxResponseBytes = self::MAX_RESPONSE_BYTES)
    {
        $this->maxResponseBytes = max(1024, $maxResponseBytes);
    }

    /**
     * @param array<string, string> $headers
     * @return array{status: int, headers: array<string, string>, body: string, error?: string}
     */
    public function send(
        string $method,
        string $url,
        array $headers = [],
        ?string $body = null,
        int $timeoutSeconds = 5
    ): array {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('PHP ext-curl is required by CurlHttpTransport.');
        }

        $ch = curl_init($url);
        if ($ch === false) {
            return ['status' => 0, 'headers' => [], 'body' => '', 'error' => 'Failed to initialize curl handle.'];
        }

        $headerLines = [];
        foreach ($headers as $name => $value) {
            $cleanName = EndpointValidator::assertCleanHeaderValue((string) $name, 'header name');
            $cleanVal = EndpointValidator::assertCleanHeaderValue((string) $value, 'header value');
            $headerLines[] = "{$cleanName}: {$cleanVal}";
        }

        $respHeaders = [];
        $respBody = '';
        $overflow = false;
        $limit = $this->maxResponseBytes;

        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST  => strtoupper($method),
            CURLOPT_HTTPHEADER     => $headerLines,
            CURLOPT_TIMEOUT        => max(1, min(60, $timeoutSeconds)),
            CURLOPT_CONNECTTIMEOUT => min(5, max(1, $timeoutSeconds)),
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$respHeaders): int {
                $len = strlen($line);
                $pos = strpos($line, ':');
                if ($pos !== false) {
                    $k = strtolower(trim(substr($line, 0, $pos)));
                    $v = trim(substr($line, $pos + 1));
                    if ($k !== '') {
                        $respHeaders[$k] = $v;
                    }
                }
                return $len;
            },
            CURLOPT_WRITEFUNCTION  => static function ($curl, string $chunk) use (&$respBody, &$overflow, $limit): int {
                $len = strlen($chunk);
                if (strlen($respBody) + $len > $limit) {
                    $overflow = true;
                    return 0;
                }
                $respBody .= $chunk;
                return $len;
            },
        ]);

        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = $ok === false ? curl_error($ch) : '';
        curl_close($ch);

        if ($overflow) {
            return [
                'status'  => $status,
                'headers' => $respHeaders,
                'body'    => '',
                'error'   => 'Response body exceeded maximum allowed size.',
            ];
        }
        if ($ok === false) {
            return [
                'status'  => $status,
                'headers' => $respHeaders,
                'body'    => $respBody,
                'error'   => $err !== '' ? $err : 'HTTP transport error.',
            ];
        }

        return [
            'status'  => $status,
            'headers' => $respHeaders,
            'body'    => $respBody,
        ];
    }
}
