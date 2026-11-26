export const PRIORITY_HEADER = "Concert-Priority";
export const PRIORITY_MIN_TTL_SECONDS = 60;
export const PRIORITY_MAX_TTL_SECONDS = 24 * 60 * 60;

export const PRIORITY_TIERS = [
  "guest",
  "member",
  "prospect",
  "customer",
  "subscriber",
  "checkout",
  "staff",
] as const;

export type PriorityTier = (typeof PRIORITY_TIERS)[number];

export interface PriorityDecision {
  tier: PriorityTier;
  ttlSeconds?: number;
}

export type PriorityResolver<TRequest> = (
  req: TRequest,
) => PriorityDecision | null | undefined | Promise<PriorityDecision | null | undefined>;

export interface ExpressLikeResponse {
  setHeader(name: string, value: string): unknown;
}

export type ExpressNextFunction = (err?: unknown) => void;

const TIER_SET: ReadonlySet<string> = new Set(PRIORITY_TIERS);

/**
 * Checks whether a value is a canonical Concert priority tier.
 */
export function isValidPriorityTier(value: string): value is PriorityTier {
  return TIER_SET.has(value);
}

/**
 * Normalizes and validates a Concert priority tier name.
 */
export function parsePriorityTier(raw: string): PriorityTier {
  const normalized = raw.trim().toLowerCase();
  if (!isValidPriorityTier(normalized)) {
    throw new RangeError(`concert: invalid priority tier ${JSON.stringify(raw)}`);
  }
  return normalized;
}

/**
 * Formats a Concert-Priority response header value (e.g. "checkout; ttl=30m").
 * Positive ttlSeconds values are clamped to Concert's [60s, 86400s] bounds.
 * Passing ttlSeconds === 0 or undefined omits the ttl directive so Concert
 * applies its per-tier default. Passing tier === "guest" always omits ttl.
 */
export function formatPriorityHeader(tier: PriorityTier | string, ttlSeconds?: number): string {
  const norm = parsePriorityTier(tier);
  if (ttlSeconds === undefined || ttlSeconds === 0) {
    return norm;
  }
  if (!Number.isFinite(ttlSeconds) || ttlSeconds < 0) {
    throw new RangeError(`concert: invalid priority ttlSeconds ${String(ttlSeconds)}`);
  }
  if (norm === "guest") {
    return norm;
  }
  const clamped = Math.min(
    PRIORITY_MAX_TTL_SECONDS,
    Math.max(PRIORITY_MIN_TTL_SECONDS, Math.trunc(ttlSeconds)),
  );
  return `${norm}; ttl=${formatDurationSeconds(clamped)}`;
}

function formatDurationSeconds(secs: number): string {
  if (secs % 3600 === 0) {
    return `${secs / 3600}h`;
  }
  if (secs % 60 === 0) {
    return `${secs / 60}m`;
  }
  return `${secs}s`;
}

/**
 * Express-compatible middleware that resolves a Concert-Priority grant for
 * each request and sets the Concert-Priority response header before calling
 * next(). Supports both synchronous and asynchronous resolvers.
 */
export function expressPriorityMiddleware<TReq = unknown, TRes extends ExpressLikeResponse = ExpressLikeResponse>(
  resolve: PriorityResolver<TReq>,
): (req: TReq, res: TRes, next: ExpressNextFunction) => void {
  return (req: TReq, res: TRes, next: ExpressNextFunction): void => {
    Promise.resolve()
      .then(() => resolve(req))
      .then((decision) => {
        if (decision) {
          try {
            res.setHeader(PRIORITY_HEADER, formatPriorityHeader(decision.tier, decision.ttlSeconds));
          } catch {
            // Best-effort: never fail an origin response on bad priority metadata.
          }
        }
        next();
      })
      .catch((err) => next(err));
  };
}

/**
 * Attaches a Concert-Priority header to a standard Web Fetch Response or
 * Next.js NextResponse. If the response's headers are immutable, returns a
 * cloned Response carrying the new header.
 */
export function withPriorityResponse<TResponse extends Response>(
  response: TResponse,
  tier: PriorityTier | string,
  ttlSeconds?: number,
): TResponse {
  const headerValue = formatPriorityHeader(tier, ttlSeconds);
  try {
    response.headers.set(PRIORITY_HEADER, headerValue);
    return response;
  } catch {
    const headers = new Headers(response.headers);
    headers.set(PRIORITY_HEADER, headerValue);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    }) as TResponse;
  }
}

/**
 * Wraps a standard Web Fetch / Next.js App Router route handler
 * `(req: Request) => Response | Promise<Response>` to attach Concert-Priority
 * based on `resolve(req)`.
 */
export function withFetchPriority<TRequest extends Request = Request, TResponse extends Response = Response>(
  handler: (req: TRequest) => TResponse | Promise<TResponse>,
  resolve: PriorityResolver<TRequest>,
): (req: TRequest) => Promise<TResponse> {
  return async (req: TRequest): Promise<TResponse> => {
    const [decision, response] = await Promise.all([
      Promise.resolve().then(() => resolve(req)),
      Promise.resolve().then(() => handler(req)),
    ]);
    if (!decision) {
      return response;
    }
    try {
      return withPriorityResponse(response, decision.tier, decision.ttlSeconds);
    } catch {
      return response;
    }
  };
}

/**
 * Next.js Middleware helper (`middleware.ts` / `proxy.ts`) that creates a
 * pass-through Response (via `createNextResponse`, e.g. `NextResponse.next`)
 * and stamps the resolved Concert-Priority header onto it.
 */
export function createNextPriorityMiddleware<
  TRequest extends Request = Request,
  TResponse extends Response = Response,
>(
  resolve: PriorityResolver<TRequest>,
  createNextResponse: () => TResponse = () => new Response(null, { status: 200 }) as TResponse,
): (req: TRequest) => Promise<TResponse> {
  return async (req: TRequest): Promise<TResponse> => {
    const response = createNextResponse();
    const decision = await resolve(req);
    if (!decision) {
      return response;
    }
    try {
      return withPriorityResponse(response, decision.tier, decision.ttlSeconds);
    } catch {
      return response;
    }
  };
}
