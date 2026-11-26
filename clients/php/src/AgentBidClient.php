<?php
declare(strict_types=1);

namespace Concert;

use InvalidArgumentException;
use JsonException;

/**
 * 100% CRYPTO-ONLY client for Concert's non-custodial AI agent pass bidding API:
 *   - POST /_concert/bids
 *   - GET  /_concert/bids/status?bid_id=<id>
 *
 * Supported crypto chains ONLY: xrpl, stellar, hedera, solana.
 * Off-chain verification occurs on submit; on-chain settlement happens ONLY
 * for winning bids (losers pay $0).
 */
final class AgentBidClient
{
    public const SUBMIT_PATH = '/_concert/bids';
    public const STATUS_PATH = '/_concert/bids/status';
    public const SUPPORTED_CHAINS = ['xrpl', 'stellar', 'hedera', 'solana'];

    private string $endpoint;
    private HttpTransportInterface $transport;
    private ?int $maxBidMicroUsd;
    private int $timeoutSeconds;

    public function __construct(
        string $endpoint,
        ?HttpTransportInterface $transport = null,
        ?int $maxBidMicroUsd = null,
        int $timeoutSeconds = 10
    ) {
        $this->endpoint = EndpointValidator::validateEndpoint($endpoint);
        $this->transport = $transport ?? new CurlHttpTransport();
        if ($maxBidMicroUsd !== null && $maxBidMicroUsd <= 0) {
            throw new InvalidArgumentException('maxBidMicroUsd must be a positive integer when provided.');
        }
        $this->maxBidMicroUsd = $maxBidMicroUsd;
        $this->timeoutSeconds = max(1, min(60, $timeoutSeconds));
    }

    /**
     * Submits a signed crypto payment authorization bid to POST /_concert/bids.
     *
     * @param array<string, mixed>|string $paymentPayload Signed x402 v2 crypto authorization (array or raw JSON)
     * @param array<string, mixed>        $options        Optional keys: bid_id, agent_key, scope, queued_at, estimated_micro_usd, session_id, payment_signature
     * @return array{ok: bool, status_code: int, bid_id: string, status: string, pass_issued: bool, priority_pass: ?string, status_url: ?string, waiting_room: WaitingRoomSignal, raw: mixed, error: ?string}
     */
    public function submitBid(
        string $chain,
        string $asset,
        string $amountAtomic,
        array|string $paymentPayload,
        array $options = []
    ): array {
        $chain = strtolower(trim($chain));
        if (!in_array($chain, self::SUPPORTED_CHAINS, true)) {
            throw new InvalidArgumentException(
                'Unsupported chain "' . $chain . '". Concert is 100% crypto-only: xrpl, stellar, hedera, solana.'
            );
        }

        $asset = EndpointValidator::assertCleanHeaderValue($asset, 'asset');
        if ($asset === '') {
            throw new InvalidArgumentException('Crypto asset identifier is required.');
        }

        $amountAtomic = trim($amountAtomic);
        if (preg_match('/^[1-9]\d*$/', $amountAtomic) !== 1) {
            throw new InvalidArgumentException('amount_atomic must be a positive base-10 integer string.');
        }

        if ($this->maxBidMicroUsd !== null && isset($options['estimated_micro_usd'])) {
            $est = (int) $options['estimated_micro_usd'];
            if ($est <= 0 || $est > $this->maxBidMicroUsd) {
                throw new InvalidArgumentException(
                    sprintf('Bid estimated_micro_usd (%d) exceeds configured maxBidMicroUsd (%d).', $est, $this->maxBidMicroUsd)
                );
            }
        }

        if (is_string($paymentPayload)) {
            $decodedPayload = json_decode($paymentPayload, true);
            if (!is_array($decodedPayload)) {
                throw new InvalidArgumentException('payment_payload JSON string must decode to an object/array.');
            }
            $payloadObj = $decodedPayload;
        } else {
            if ($paymentPayload === []) {
                throw new InvalidArgumentException('payment_payload must not be empty.');
            }
            $payloadObj = $paymentPayload;
        }

        $body = [
            'chain'           => $chain,
            'asset'           => $asset,
            'amount_atomic'   => $amountAtomic,
            'payment_payload' => $payloadObj,
        ];

        foreach (['bid_id', 'agent_key', 'scope', 'queued_at'] as $optKey) {
            if (isset($options[$optKey]) && is_string($options[$optKey]) && trim($options[$optKey]) !== '') {
                $body[$optKey] = EndpointValidator::assertCleanHeaderValue($options[$optKey], $optKey);
            }
        }

        try {
            $json = json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException $e) {
            throw new InvalidArgumentException('Failed to encode bid submission JSON.', 0, $e);
        }

        $headers = [
            'Content-Type' => 'application/json',
            'Accept'       => 'application/json',
        ];
        if (isset($options['session_id']) && is_string($options['session_id']) && trim($options['session_id']) !== '') {
            $headers['Concert-Session'] = EndpointValidator::assertCleanHeaderValue($options['session_id'], 'session_id');
        }
        if (isset($options['payment_signature']) && is_string($options['payment_signature']) && trim($options['payment_signature']) !== '') {
            $headers['PAYMENT-SIGNATURE'] = EndpointValidator::assertCleanHeaderValue($options['payment_signature'], 'payment_signature');
        }

        $resp = $this->transport->send('POST', $this->endpoint . self::SUBMIT_PATH, $headers, $json, $this->timeoutSeconds);
        return $this->parseBidResponse($resp);
    }

    /**
     * Queries GET /_concert/bids/status?bid_id=<id> to check epoch clearing and retrieve
     * the signed Priority + Admission pass when settled.
     *
     * @return array{ok: bool, status_code: int, bid_id: string, status: string, pass_issued: bool, priority_pass: ?string, status_url: ?string, waiting_room: WaitingRoomSignal, raw: mixed, error: ?string}
     */
    public function getBidStatus(string $bidId, ?string $sessionId = null): array
    {
        $bidId = EndpointValidator::assertCleanHeaderValue($bidId, 'bid_id');
        if ($bidId === '') {
            throw new InvalidArgumentException('bid_id is required.');
        }

        $headers = ['Accept' => 'application/json'];
        if ($sessionId !== null && trim($sessionId) !== '') {
            $headers['Concert-Session'] = EndpointValidator::assertCleanHeaderValue($sessionId, 'session_id');
        }

        $url = $this->endpoint . self::STATUS_PATH . '?bid_id=' . rawurlencode($bidId);
        $resp = $this->transport->send('GET', $url, $headers, null, $this->timeoutSeconds);
        return $this->parseBidResponse($resp);
    }

    /**
     * @param array{status: int, headers: array<string, string>, body: string, error?: string} $resp
     * @return array{ok: bool, status_code: int, bid_id: string, status: string, pass_issued: bool, priority_pass: ?string, status_url: ?string, waiting_room: WaitingRoomSignal, raw: mixed, error: ?string}
     */
    private function parseBidResponse(array $resp): array
    {
        $code = (int) ($resp['status'] ?? 0);
        $headers = is_array($resp['headers'] ?? null) ? $resp['headers'] : [];
        $signal = WaitingRoomSignal::fromHeaders($headers);

        if (!empty($resp['error'])) {
            return [
                'ok'            => false,
                'status_code'   => $code,
                'bid_id'        => '',
                'status'        => '',
                'pass_issued'   => false,
                'priority_pass' => null,
                'status_url'    => null,
                'waiting_room'  => $signal,
                'raw'           => null,
                'error'         => (string) $resp['error'],
            ];
        }

        $decoded = json_decode((string) ($resp['body'] ?? ''), true);
        $ok = $code >= 200 && $code < 300;
        $bidId = is_array($decoded) ? (string) ($decoded['bid_id'] ?? '') : '';
        $status = is_array($decoded) ? (string) ($decoded['status'] ?? '') : '';
        $passIssued = is_array($decoded) && !empty($decoded['pass_issued']);
        $priorityPass = is_array($decoded) && isset($decoded['priority_pass']) && is_string($decoded['priority_pass']) && $decoded['priority_pass'] !== ''
            ? $decoded['priority_pass']
            : null;
        $statusUrl = is_array($decoded) && isset($decoded['status_url']) && is_string($decoded['status_url'])
            ? $decoded['status_url']
            : null;
        $err = !$ok
            ? (is_array($decoded) && isset($decoded['error']) ? (string) $decoded['error'] : "HTTP {$code}")
            : null;

        return [
            'ok'            => $ok,
            'status_code'   => $code,
            'bid_id'        => $bidId,
            'status'        => $status,
            'pass_issued'   => $passIssued,
            'priority_pass' => $priorityPass,
            'status_url'    => $statusUrl,
            'waiting_room'  => $signal,
            'raw'           => $decoded,
            'error'         => $err,
        ];
    }
}
