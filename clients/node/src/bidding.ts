import {
  DEFAULT_HTTP_TIMEOUT_MS,
  normalizeBaseUrl,
  parseApiError,
  readBoundedText,
} from "./purge.ts";

export const BID_SUBMIT_PATH = "/_concert/bids";
export const BID_STATUS_PATH = "/_concert/bids/status";
export const DEFAULT_MAX_BID_RESPONSE_BYTES = 128 * 1024;

/**
 * Concert is 100% crypto-only. Only these four settlement chains are supported.
 */
export const SUPPORTED_CHAINS = ["xrpl", "stellar", "hedera", "solana"] as const;
export type SupportedChain = (typeof SUPPORTED_CHAINS)[number];

export type BidStatus =
  | "pending"
  | "won"
  | "lost"
  | "rejected"
  | "settled"
  | "settlement_failed";

export interface AuctionOffer {
  mode: "instant" | "auction";
  auction_id?: string;
  scope: string;
  floor_micro_usd: number;
  closes_at?: string;
  slots: number;
  min_wait_seconds: number;
  bid_url: string;
  status_url: string;
  supported_chains: SupportedChain[];
}

export interface BidSubmission {
  bid_id?: string;
  agent_key?: string;
  scope?: string;
  chain: SupportedChain | string;
  asset: string;
  amount_atomic: string;
  payment_payload: unknown;
  queued_at?: string;
}

export interface BidRecord {
  bid_id: string;
  auction_id?: string;
  agent_key: string;
  scope: string;
  chain: SupportedChain;
  asset: string;
  amount_atomic: string;
  normalized_micro_usd: number;
  status: BidStatus;
  payer?: string;
  transaction?: string;
  policy_id?: string;
  reason?: string;
  wait_duration?: number;
  queued_at?: string;
  received_at?: string;
  updated_at?: string;
}

export interface BidResponse {
  bid: BidRecord;
  bid_id: string;
  status: BidStatus;
  status_url?: string;
  pass_issued?: boolean;
  priority_pass?: string;
  pass_token?: string;
}

export interface AgentBidClientConfig {
  baseUrl: string;
  concertSession?: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  fetchImpl?: typeof fetch;
}

const CHAIN_SET: ReadonlySet<string> = new Set(SUPPORTED_CHAINS);
const POSITIVE_ATOMIC_RE = /^[1-9]\d*$/;

/**
 * Reports whether chain is one of Concert's four crypto chains
 * (`xrpl`, `stellar`, `hedera`, `solana`).
 */
export function isSupportedChain(chain: string): chain is SupportedChain {
  return CHAIN_SET.has(chain.trim().toLowerCase());
}

/**
 * Parses and validates a crypto-only `AuctionOffer` from a Concert `429` JSON
 * response body (either the `{ queued: true, auction: {...} }` wrapper or a
 * standalone offer object).
 */
export function parseAuctionOffer(input: string | Uint8Array | Record<string, unknown>): AuctionOffer {
  let rawObj: unknown;
  if (typeof input === "string") {
    if (Buffer.byteLength(input, "utf8") > DEFAULT_MAX_BID_RESPONSE_BYTES) {
      throw new RangeError(`concert: auction offer exceeds ${DEFAULT_MAX_BID_RESPONSE_BYTES} bytes`);
    }
    rawObj = JSON.parse(input);
  } else if (input instanceof Uint8Array) {
    if (input.byteLength > DEFAULT_MAX_BID_RESPONSE_BYTES) {
      throw new RangeError(`concert: auction offer exceeds ${DEFAULT_MAX_BID_RESPONSE_BYTES} bytes`);
    }
    rawObj = JSON.parse(Buffer.from(input.buffer, input.byteOffset, input.byteLength).toString("utf8"));
  } else {
    rawObj = input;
  }

  if (rawObj === null || typeof rawObj !== "object" || Array.isArray(rawObj)) {
    throw new Error("concert: invalid auction offer JSON");
  }
  const envelope = rawObj as Record<string, unknown>;
  const candidate =
    envelope.auction !== undefined && envelope.auction !== null && typeof envelope.auction === "object"
      ? (envelope.auction as Record<string, unknown>)
      : envelope;

  if (typeof candidate.mode !== "string") {
    throw new Error("concert: no auction offer present in response");
  }
  const mode = candidate.mode.trim().toLowerCase();
  if (mode !== "instant" && mode !== "auction") {
    throw new RangeError(`concert: unsupported auction mode ${JSON.stringify(candidate.mode)}`);
  }
  if (
    typeof candidate.floor_micro_usd !== "number" ||
    !Number.isSafeInteger(candidate.floor_micro_usd) ||
    candidate.floor_micro_usd <= 0
  ) {
    throw new RangeError("concert: floor_micro_usd must be a positive integer");
  }
  if (!Array.isArray(candidate.supported_chains) || candidate.supported_chains.length === 0) {
    throw new RangeError("concert: supported_chains must be a non-empty array");
  }

  const normalizedChains: SupportedChain[] = [];
  for (const entry of candidate.supported_chains) {
    if (typeof entry !== "string" || !isSupportedChain(entry)) {
      throw new RangeError(
        `concert: unsupported crypto chain ${JSON.stringify(entry)} (allowed: xrpl, stellar, hedera, solana)`,
      );
    }
    normalizedChains.push(entry.trim().toLowerCase() as SupportedChain);
  }

  return {
    mode,
    auction_id: typeof candidate.auction_id === "string" ? candidate.auction_id : undefined,
    scope: typeof candidate.scope === "string" ? candidate.scope : "",
    floor_micro_usd: candidate.floor_micro_usd,
    closes_at: typeof candidate.closes_at === "string" ? candidate.closes_at : undefined,
    slots: typeof candidate.slots === "number" ? candidate.slots : 1,
    min_wait_seconds: typeof candidate.min_wait_seconds === "number" ? candidate.min_wait_seconds : 0,
    bid_url:
      typeof candidate.bid_url === "string" && candidate.bid_url.trim().length > 0
        ? candidate.bid_url.trim()
        : BID_SUBMIT_PATH,
    status_url:
      typeof candidate.status_url === "string" && candidate.status_url.trim().length > 0
        ? candidate.status_url.trim()
        : BID_STATUS_PATH,
    supported_chains: normalizedChains,
  };
}

/**
 * Crypto-only AI agent bidding client for Concert (`POST /_concert/bids` and
 * `GET /_concert/bids/status`). Supports `xrpl`, `stellar`, `hedera`, and
 * `solana` exclusively.
 */
export class AgentBidClient {
  readonly #baseUrl: string;
  readonly #concertSession: string;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  readonly #fetchImpl: typeof fetch;

  constructor(config: AgentBidClientConfig) {
    this.#baseUrl = normalizeBaseUrl(config.baseUrl);
    this.#concertSession = (config.concertSession ?? "").trim();
    this.#timeoutMs = config.timeoutMs && config.timeoutMs > 0 ? config.timeoutMs : DEFAULT_HTTP_TIMEOUT_MS;
    this.#maxResponseBytes =
      config.maxResponseBytes && config.maxResponseBytes > 0
        ? config.maxResponseBytes
        : DEFAULT_MAX_BID_RESPONSE_BYTES;
    this.#fetchImpl = config.fetchImpl ?? globalThis.fetch;
  }

  async submitBid(submission: BidSubmission, signal?: AbortSignal): Promise<BidResponse> {
    const chain = submission.chain.trim().toLowerCase();
    if (!isSupportedChain(chain)) {
      throw new RangeError(
        `concert: unsupported crypto chain ${JSON.stringify(submission.chain)} (allowed: xrpl, stellar, hedera, solana)`,
      );
    }
    const asset = submission.asset.trim();
    if (asset.length === 0) {
      throw new RangeError("concert: asset is required");
    }
    const amountAtomic = submission.amount_atomic.trim();
    if (!POSITIVE_ATOMIC_RE.test(amountAtomic)) {
      throw new RangeError("concert: amount_atomic must be a positive base-10 integer string");
    }
    if (submission.payment_payload === undefined || submission.payment_payload === null) {
      throw new RangeError("concert: payment_payload is required");
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (this.#concertSession !== "") {
      headers["Concert-Session"] = this.#concertSession;
    }

    const timeoutSignal = AbortSignal.timeout(this.#timeoutMs);
    const combinedSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;

    const resp = await this.#fetchImpl(`${this.#baseUrl}${BID_SUBMIT_PATH}`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        bid_id: submission.bid_id?.trim() || undefined,
        agent_key: submission.agent_key?.trim() || undefined,
        scope: submission.scope?.trim() || undefined,
        chain,
        asset,
        amount_atomic: amountAtomic,
        payment_payload: submission.payment_payload,
        queued_at: submission.queued_at?.trim() || undefined,
      }),
      redirect: "error",
      signal: combinedSignal,
    });

    const bodyText = await readBoundedText(resp, this.#maxResponseBytes);
    if (resp.status !== 200 && resp.status !== 202) {
      throw parseApiError(resp.status, bodyText);
    }
    return JSON.parse(bodyText) as BidResponse;
  }

  async getBidStatus(bidId: string, signal?: AbortSignal): Promise<BidResponse> {
    const id = bidId.trim();
    if (id.length === 0) {
      throw new RangeError("concert: bid_id is required");
    }

    const headers: Record<string, string> = {
      Accept: "application/json",
    };
    if (this.#concertSession !== "") {
      headers["Concert-Session"] = this.#concertSession;
    }

    const timeoutSignal = AbortSignal.timeout(this.#timeoutMs);
    const combinedSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;

    const url = `${this.#baseUrl}${BID_STATUS_PATH}?bid_id=${encodeURIComponent(id)}`;
    const resp = await this.#fetchImpl(url, {
      method: "GET",
      headers,
      redirect: "error",
      signal: combinedSignal,
    });

    const bodyText = await readBoundedText(resp, this.#maxResponseBytes);
    if (resp.status !== 200) {
      throw parseApiError(resp.status, bodyText);
    }
    return JSON.parse(bodyText) as BidResponse;
  }
}
