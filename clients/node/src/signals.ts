export const HEADER_CONCERT_QUEUE = "x-concert-queue";
export const HEADER_CONCERT_POSITION = "x-concert-position";
export const HEADER_RETRY_AFTER = "retry-after";
export const HEADER_CONCERT_STATUS_URL = "x-concert-status-url";
export const DEFAULT_QUEUE_STATUS_URL = "/queue/status";

export type HeaderSource =
  | Headers
  | Record<string, string | readonly string[] | undefined>;

export interface WaitingRoomSignal {
  queued: boolean;
  position: number | null;
  retryAfterSeconds: number | null;
  statusUrl: string | null;
}

function getHeaderCaseInsensitive(source: HeaderSource, targetLower: string): string | undefined {
  if (source instanceof Headers) {
    return source.get(targetLower) ?? undefined;
  }
  for (const [key, value] of Object.entries(source)) {
    if (key.toLowerCase() !== targetLower) {
      continue;
    }
    if (Array.isArray(value)) {
      return value[0];
    }
    return value;
  }
  return undefined;
}

function parseRetryAfterSeconds(raw: string | undefined, nowMs: number): number | null {
  if (raw === undefined) {
    return null;
  }
  const trimmed = raw.trim();
  if (trimmed === "") {
    return null;
  }
  if (/^\d+$/.test(trimmed)) {
    const secs = Number(trimmed);
    return Number.isSafeInteger(secs) && secs >= 0 ? secs : null;
  }
  const parsedDateMs = Date.parse(trimmed);
  if (!Number.isNaN(parsedDateMs)) {
    return Math.max(0, Math.ceil((parsedDateMs - nowMs) / 1000));
  }
  return null;
}

/**
 * Parses Concert's waiting-room response headers (`X-Concert-Queue`,
 * `X-Concert-Position`, `Retry-After`, `X-Concert-Status-Url`).
 *
 * `queued` is true strictly when `X-Concert-Queue` equals `"1"`, matching
 * Concert's guardrail that plain rate-limit 429s or upstream 503s never emit
 * `X-Concert-Queue: 1`.
 */
export function parseWaitingRoomSignal(
  headers: HeaderSource | null | undefined,
  nowMs: number = Date.now(),
): WaitingRoomSignal {
  if (!headers) {
    return { queued: false, position: null, retryAfterSeconds: null, statusUrl: null };
  }

  const queueVal = getHeaderCaseInsensitive(headers, HEADER_CONCERT_QUEUE)?.trim();
  const queued = queueVal === "1";

  let position: number | null = null;
  const rawPos = getHeaderCaseInsensitive(headers, HEADER_CONCERT_POSITION)?.trim();
  if (rawPos !== undefined && /^\d+$/.test(rawPos)) {
    const parsedPos = Number(rawPos);
    if (Number.isSafeInteger(parsedPos) && parsedPos >= 0) {
      position = parsedPos;
    }
  }

  const retryAfterSeconds = parseRetryAfterSeconds(
    getHeaderCaseInsensitive(headers, HEADER_RETRY_AFTER),
    nowMs,
  );

  const rawStatusUrl = getHeaderCaseInsensitive(headers, HEADER_CONCERT_STATUS_URL)?.trim();
  let statusUrl: string | null = null;
  if (rawStatusUrl && rawStatusUrl.length > 0) {
    statusUrl = rawStatusUrl;
  } else if (queued) {
    // Concert omits X-Concert-Status-Url when using its default /queue/status path.
    statusUrl = DEFAULT_QUEUE_STATUS_URL;
  }

  return { queued, position, retryAfterSeconds, statusUrl };
}

/**
 * Reports whether a Web Fetch Response carries Concert's `X-Concert-Queue: 1` header.
 */
export function isQueuedResponse(response: Pick<Response, "headers"> | null | undefined): boolean {
  if (!response) {
    return false;
  }
  return parseWaitingRoomSignal(response.headers).queued;
}
