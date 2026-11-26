export const REDACTED_PLACEHOLDER = "[REDACTED]";
export const CACHE_PURGE_PATH = "/_room/cache/purge";
export const DEFAULT_HTTP_TIMEOUT_MS = 10_000;
export const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024;

export type PurgeMode = "url" | "prefix" | "tag" | "all";

export interface PurgeRequest {
  mode: PurgeMode;
  host?: string;
  target?: string;
}

export interface PurgeResult {
  purged: number;
  mode: string;
}

export interface CachePurgeClientConfig {
  baseUrl: string;
  token: string | Secret;
  timeoutMs?: number;
  maxResponseBytes?: number;
  fetchImpl?: typeof fetch;
}

const PLACEHOLDER_SECRETS = new Set([
  "changeme",
  "change-me",
  "replace-me",
  "your-api-key",
  "your_api_key",
  "your-token",
  "your_token",
  "xxx",
  "todo",
  "tbd",
  "none",
  "null",
  "<redacted>",
  "[redacted]",
]);

const INSPECT_CUSTOM = Symbol.for("nodejs.util.inspect.custom");

/**
 * Redacting credential wrapper (S6). Prevents accidental disclosure in logs,
 * console.log / util.inspect, template strings, and JSON.stringify.
 */
export class Secret {
  readonly #value: string;

  constructor(raw: string) {
    const trimmed = raw.trim();
    if (trimmed.length === 0) {
      throw new Error("concert: secret token must not be empty");
    }
    if (PLACEHOLDER_SECRETS.has(trimmed.toLowerCase())) {
      throw new Error("concert: secret token looks like a placeholder");
    }
    this.#value = trimmed;
  }

  /**
   * Returns the raw secret value. Call only at the single wire header site.
   */
  reveal(): string {
    return this.#value;
  }

  toString(): string {
    return REDACTED_PLACEHOLDER;
  }

  toJSON(): string {
    return REDACTED_PLACEHOLDER;
  }

  [INSPECT_CUSTOM](): string {
    return `Secret(${REDACTED_PLACEHOLDER})`;
  }
}

export class ConcertAPIError extends Error {
  readonly statusCode: number;

  constructor(statusCode: number, message: string) {
    super(message ? `concert: HTTP ${statusCode}: ${message}` : `concert: HTTP ${statusCode}`);
    this.name = "ConcertAPIError";
    this.statusCode = statusCode;
  }
}

export function normalizeBaseUrl(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    throw new Error("concert: baseUrl must not be empty");
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error("concert: invalid baseUrl");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("concert: baseUrl protocol must be http: or https:");
  }
  if (parsed.username !== "" || parsed.password !== "") {
    throw new Error("concert: baseUrl must not contain embedded credentials");
  }
  if (parsed.search !== "" || parsed.hash !== "") {
    throw new Error("concert: baseUrl must not contain query or hash");
  }
  return `${parsed.origin}${parsed.pathname.replace(/\/+$/, "")}`;
}

export async function readBoundedText(response: Response, maxBytes: number): Promise<string> {
  if (!response.body) {
    return "";
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error(`concert: response body exceeds limit of ${maxBytes} bytes`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c.buffer, c.byteOffset, c.byteLength))).toString("utf8");
}

export function parseApiError(statusCode: number, bodyText: string): ConcertAPIError {
  try {
    const parsed = JSON.parse(bodyText) as { error?: unknown };
    if (typeof parsed.error === "string" && parsed.error.trim().length > 0) {
      return new ConcertAPIError(statusCode, parsed.error.trim());
    }
  } catch {
    // Fall back to bounded plain text.
  }
  return new ConcertAPIError(statusCode, bodyText.trim().slice(0, 256));
}

/**
 * Authenticated client for Concert's active page-cache purge endpoint
 * (`POST /_room/cache/purge`). The Bearer token is held inside a private
 * redacting Secret and never logged or serialized.
 */
export class CachePurgeClient {
  readonly #baseUrl: string;
  readonly #token: Secret;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  readonly #fetchImpl: typeof fetch;

  constructor(config: CachePurgeClientConfig) {
    this.#baseUrl = normalizeBaseUrl(config.baseUrl);
    this.#token = config.token instanceof Secret ? config.token : new Secret(config.token);
    this.#timeoutMs = config.timeoutMs && config.timeoutMs > 0 ? config.timeoutMs : DEFAULT_HTTP_TIMEOUT_MS;
    this.#maxResponseBytes =
      config.maxResponseBytes && config.maxResponseBytes > 0
        ? config.maxResponseBytes
        : DEFAULT_MAX_RESPONSE_BYTES;
    this.#fetchImpl = config.fetchImpl ?? globalThis.fetch;
  }

  toJSON(): Record<string, string> {
    return { baseUrl: this.#baseUrl, token: REDACTED_PLACEHOLDER };
  }

  [INSPECT_CUSTOM](): string {
    return `CachePurgeClient { baseUrl: ${JSON.stringify(this.#baseUrl)}, token: ${REDACTED_PLACEHOLDER} }`;
  }

  async purgeUrl(target: string, host = "", signal?: AbortSignal): Promise<PurgeResult> {
    return this.purge({ mode: "url", host, target }, signal);
  }

  async purgePrefix(prefix: string, host = "", signal?: AbortSignal): Promise<PurgeResult> {
    return this.purge({ mode: "prefix", host, target: prefix }, signal);
  }

  async purgeTag(tag: string, host = "", signal?: AbortSignal): Promise<PurgeResult> {
    return this.purge({ mode: "tag", host, target: tag }, signal);
  }

  async purgeAll(host = "", signal?: AbortSignal): Promise<PurgeResult> {
    return this.purge({ mode: "all", host }, signal);
  }

  async purge(req: PurgeRequest, signal?: AbortSignal): Promise<PurgeResult> {
    const mode = req.mode.trim().toLowerCase() as PurgeMode;
    const host = (req.host ?? "").trim();
    const target = (req.target ?? "").trim();

    if (mode !== "url" && mode !== "prefix" && mode !== "tag" && mode !== "all") {
      throw new RangeError(`concert: unsupported purge mode ${JSON.stringify(req.mode)}`);
    }
    if (mode !== "all" && target.length === 0) {
      throw new RangeError(`concert: target is required for purge mode ${JSON.stringify(mode)}`);
    }

    const timeoutSignal = AbortSignal.timeout(this.#timeoutMs);
    const combinedSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;

    // Disallow automatic redirects so Authorization headers can never be
    // forwarded to a different host or downgraded scheme.
    const resp = await this.#fetchImpl(`${this.#baseUrl}${CACHE_PURGE_PATH}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${this.#token.reveal()}`,
      },
      body: JSON.stringify({ mode, host, target }),
      redirect: "error",
      signal: combinedSignal,
    });

    const bodyText = await readBoundedText(resp, this.#maxResponseBytes);
    if (resp.status !== 200) {
      throw parseApiError(resp.status, bodyText);
    }

    const parsed = JSON.parse(bodyText) as { purged?: unknown; mode?: unknown };
    if (typeof parsed.purged !== "number" || typeof parsed.mode !== "string") {
      throw new Error("concert: invalid cache purge response JSON");
    }
    return { purged: parsed.purged, mode: parsed.mode };
  }
}
