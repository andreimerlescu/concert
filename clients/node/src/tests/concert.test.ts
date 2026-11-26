import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, it } from "node:test";
import { inspect } from "node:util";

import {
  AgentBidClient,
  BID_STATUS_PATH,
  BID_SUBMIT_PATH,
  CACHE_PURGE_PATH,
  CachePurgeClient,
  ConcertAPIError,
  DEFAULT_QUEUE_STATUS_URL,
  PRIORITY_HEADER,
  REDACTED_PLACEHOLDER,
  RM1Error,
  SUPPORTED_CHAINS,
  Secret,
  createNextPriorityMiddleware,
  decodeEd25519PublicKey,
  exportRawEd25519PublicKey,
  expressPriorityMiddleware,
  formatPriorityHeader,
  formatVerifyKeysFlag,
  isQueuedResponse,
  isSupportedChain,
  mintRM1Lease,
  mintRM1Pass,
  parseAuctionOffer,
  parseWaitingRoomSignal,
  signRM1,
  verifyRM1,
  withFetchPriority,
  withPriorityResponse,
  type BidRecord,
} from "../index.ts";

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? (JSON.parse(text) as Record<string, unknown>) : {};
}

async function startLocalServer(
  handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>,
): Promise<{ url: string; close: () => Promise<void> }> {
  const server = createServer((req, res) => {
    Promise.resolve(handler(req, res)).catch((err) => {
      res.statusCode = 500;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ error: String(err) }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${addr.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))),
  };
}

describe("priority helpers (Express, Next.js, Web Fetch)", () => {
  it("formats, clamps, and validates all Concert priority tiers", () => {
    assert.equal(formatPriorityHeader("staff"), "staff");
    assert.equal(formatPriorityHeader("checkout", 1800), "checkout; ttl=30m");
    assert.equal(formatPriorityHeader("subscriber", 7200), "subscriber; ttl=2h");
    assert.equal(formatPriorityHeader("customer", 90), "customer; ttl=90s");
    assert.equal(formatPriorityHeader("prospect", 10), "prospect; ttl=1m");
    assert.equal(formatPriorityHeader("member", 172800), "member; ttl=24h");
    assert.equal(formatPriorityHeader("guest", 600), "guest");
    assert.throws(() => formatPriorityHeader("platinum", 300), RangeError);
    assert.throws(() => formatPriorityHeader("checkout", -5), RangeError);
  });

  it("sets Concert-Priority in Express middleware (sync and async)", async () => {
    const mw = expressPriorityMiddleware<{ path: string }>(async (req) => {
      if (req.path === "/checkout") {
        return { tier: "checkout", ttlSeconds: 1800 };
      }
      if (req.path === "/logout") {
        return { tier: "guest" };
      }
      return null;
    });

    const headers = new Map<string, string>();
    const res = {
      setHeader(name: string, value: string) {
        headers.set(name, value);
      },
    };

    await new Promise<void>((resolve, reject) => {
      mw({ path: "/checkout" }, res, (err) => (err ? reject(err) : resolve()));
    });
    assert.equal(headers.get(PRIORITY_HEADER), "checkout; ttl=30m");

    headers.clear();
    await new Promise<void>((resolve, reject) => {
      mw({ path: "/logout" }, res, (err) => (err ? reject(err) : resolve()));
    });
    assert.equal(headers.get(PRIORITY_HEADER), "guest");

    headers.clear();
    await new Promise<void>((resolve, reject) => {
      mw({ path: "/public" }, res, (err) => (err ? reject(err) : resolve()));
    });
    assert.equal(headers.has(PRIORITY_HEADER), false);
  });

  it("sets Concert-Priority in Next.js Middleware and Web Fetch handlers", async () => {
    const nextMw = createNextPriorityMiddleware((req) => {
      const url = new URL(req.url);
      if (url.pathname.startsWith("/admin")) {
        return { tier: "staff", ttlSeconds: 28800 };
      }
      return null;
    });

    const adminResp = await nextMw(new Request("https://shop.example.com/admin/orders"));
    assert.equal(adminResp.headers.get(PRIORITY_HEADER), "staff; ttl=8h");

    const publicResp = await nextMw(new Request("https://shop.example.com/"));
    assert.equal(publicResp.headers.get(PRIORITY_HEADER), null);

    const wrapped = withFetchPriority(
      () => new Response("ok", { status: 200 }),
      () => ({ tier: "subscriber", ttlSeconds: 3600 }),
    );
    const fetchResp = await wrapped(new Request("https://shop.example.com/articles"));
    assert.equal(fetchResp.headers.get(PRIORITY_HEADER), "subscriber; ttl=1h");

    // Immutable Response (e.g. Response.redirect) is safely cloned with the header.
    const redirected = withPriorityResponse(
      Response.redirect("https://shop.example.com/pay", 302),
      "checkout",
      1800,
    );
    assert.equal(redirected.status, 302);
    assert.equal(redirected.headers.get(PRIORITY_HEADER), "checkout; ttl=30m");
  });
});

describe("rm1 Ed25519 signing, verification, and key rotation", () => {
  it("mints, verifies, rotates keys, and enforces security-first ordering", () => {
    const kp1 = generateKeyPairSync("ed25519");
    const kp2 = generateKeyPairSync("ed25519");
    const now = 1_795_651_200;

    const rawPub1 = exportRawEd25519PublicKey(kp1.publicKey);
    const rawPub2 = exportRawEd25519PublicKey(kp2.publicKey);

    const verifyKeys = {
      k1: rawPub1.toString("base64url"),
      k2: rawPub2.toString("hex"),
    };

    // Pass signed with k1 verifies via base64url raw pubkey.
    const tok1 = signRM1(kp1.privateKey, {
      kid: "k1",
      kind: "pass",
      scope: "shop.example.com",
      iat: now,
      exp: now + 300,
    });
    assert.ok(tok1.startsWith("rm1."));
    assert.equal(tok1.split(".").length, 3);

    const verified1 = verifyRM1(tok1, verifyKeys, {
      scope: "shop.example.com",
      kind: "pass",
      nowSeconds: now + 60,
    });
    assert.equal(verified1.kid, "k1");
    assert.equal(verified1.scope, "shop.example.com");

    // Pass and lease signed with k2 (zero-downtime rotation).
    const pass2 = mintRM1Pass(kp2.privateKey, "k2", "shop.example.com", "agent-7", 300, now);
    const verified2 = verifyRM1(pass2, verifyKeys, {
      scope: "shop.example.com",
      kind: "pass",
      key: "agent-7",
      nowSeconds: now,
    });
    assert.equal(verified2.key, "agent-7");

    const lease2 = mintRM1Lease(kp2.privateKey, "k2", "shop.example.com", "agent-7", 300, now);
    const verifiedLease = verifyRM1(lease2, verifyKeys, {
      scope: "shop.example.com",
      kind: "lease",
      key: "agent-7",
      nowSeconds: now,
    });
    assert.equal(verifiedLease.kind, "lease");

    // Security-first ordering: tampered expired token MUST report invalid_signature.
    const tokParts = tok1.split(".");
    const sigBuf = Buffer.from(tokParts[2], "base64url");
    sigBuf[0] ^= 0x01;
    const tampered = `${tokParts[0]}.${tokParts[1]}.${sigBuf.toString("base64url")}`;
    assert.throws(
      () =>
        verifyRM1(tampered, verifyKeys, {
          scope: "shop.example.com",
          kind: "pass",
          nowSeconds: now + 9999,
        }),
      (err: unknown) => err instanceof RM1Error && err.code === "invalid_signature",
    );

    // Wrong scope, wrong kind, key mismatch, unknown kid, future iat, expired.
    assert.throws(
      () => verifyRM1(tok1, verifyKeys, { scope: "blog.example.com", kind: "pass", nowSeconds: now }),
      (err: unknown) => err instanceof RM1Error && err.code === "wrong_scope",
    );
    assert.throws(
      () => verifyRM1(tok1, verifyKeys, { scope: "shop.example.com", kind: "lease", key: "agent-7", nowSeconds: now }),
      (err: unknown) => err instanceof RM1Error && err.code === "wrong_kind",
    );
    assert.throws(
      () => verifyRM1(lease2, verifyKeys, { scope: "shop.example.com", kind: "lease", key: "other", nowSeconds: now }),
      (err: unknown) => err instanceof RM1Error && err.code === "key_mismatch",
    );
    assert.throws(
      () => verifyRM1(tok1, { k2: kp2.publicKey }, { scope: "shop.example.com", kind: "pass", nowSeconds: now }),
      (err: unknown) => err instanceof RM1Error && err.code === "unknown_key",
    );
    assert.throws(
      () =>
        verifyRM1(tok1, verifyKeys, {
          scope: "shop.example.com",
          kind: "pass",
          nowSeconds: now - 120,
          maxClockSkewSeconds: 30,
        }),
      (err: unknown) => err instanceof RM1Error && err.code === "future_issued",
    );
    assert.throws(
      () => verifyRM1(tok1, verifyKeys, { scope: "shop.example.com", kind: "pass", nowSeconds: now + 300 }),
      (err: unknown) => err instanceof RM1Error && err.code === "expired",
    );

    // Reject TTL > 1h and empty lease key at sign time.
    assert.throws(
      () => mintRM1Pass(kp1.privateKey, "k1", "shop.example.com", "", 7200, now),
      (err: unknown) => err instanceof RM1Error && err.code === "invalid_claims",
    );
    assert.throws(
      () => mintRM1Lease(kp1.privateKey, "k1", "shop.example.com", "", 300, now),
      (err: unknown) => err instanceof RM1Error && err.code === "invalid_claims",
    );

    // Format verify keys flag and decode round-trip.
    const flagSpec = formatVerifyKeysFlag({ k2: kp2.publicKey, k1: kp1.publicKey });
    assert.equal(flagSpec, `k1=${rawPub1.toString("base64url")},k2=${rawPub2.toString("base64url")}`);
    assert.deepEqual(exportRawEd25519PublicKey(decodeEd25519PublicKey(rawPub1.toString("hex"))), rawPub1);
  });
});

describe("parseWaitingRoomSignal", () => {
  it("parses queued headers, HTTP-date Retry-After, and non-queued guardrails", () => {
    const h = new Headers({
      "X-Concert-Queue": "1",
      "X-Concert-Position": "17",
      "Retry-After": "5",
    });
    assert.deepEqual(parseWaitingRoomSignal(h), {
      queued: true,
      position: 17,
      retryAfterSeconds: 5,
      statusUrl: DEFAULT_QUEUE_STATUS_URL,
    });
    assert.equal(isQueuedResponse(new Response(null, { status: 429, headers: h })), true);

    // Custom status URL overrides default.
    const custom = parseWaitingRoomSignal({
      "x-concert-queue": "1",
      "x-concert-position": "0",
      "x-concert-status-url": "/custom/status",
      "retry-after": new Date(1_795_651_230_000).toUTCString(),
    }, 1_795_651_200_000);
    assert.deepEqual(custom, {
      queued: true,
      position: 0,
      retryAfterSeconds: 30,
      statusUrl: "/custom/status",
    });

    // Plain 429/503 without X-Concert-Queue: 1 is NOT treated as queued.
    const rateLimited = parseWaitingRoomSignal({ "Retry-After": "12" });
    assert.deepEqual(rateLimited, {
      queued: false,
      position: null,
      retryAfterSeconds: 12,
      statusUrl: null,
    });
    assert.equal(isQueuedResponse(new Response(null, { status: 429 })), false);
  });
});

describe("Secret redaction and CachePurgeClient (against local HTTP server)", () => {
  it("redacts Secret in toString, JSON.stringify, and util.inspect", () => {
    const sentinel = `op-runtime-${randomBytes(8).toString("hex")}`;
    const secret = new Secret(sentinel);

    assert.equal(secret.reveal(), sentinel);
    assert.equal(String(secret), REDACTED_PLACEHOLDER);
    assert.equal(JSON.stringify({ token: secret }), `{"token":"${REDACTED_PLACEHOLDER}"}`);
    assert.equal(inspect(secret).includes(sentinel), false);
    assert.equal(inspect(secret).includes(REDACTED_PLACEHOLDER), true);

    assert.throws(() => new Secret("   "), /must not be empty/);
    assert.throws(() => new Secret("changeme"), /placeholder/);
  });

  it("executes purgeUrl, purgePrefix, purgeTag, purgeAll and enforces auth/bounds", async () => {
    const runtimeToken = `op-runtime-${randomBytes(8).toString("hex")}`;
    let counter = 0;

    const srv = await startLocalServer(async (req, res) => {
      if (req.method !== "POST" || req.url !== CACHE_PURGE_PATH) {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: "not found" }));
        return;
      }
      if (req.headers.authorization !== `Bearer ${runtimeToken}`) {
        res.statusCode = 401;
        res.end(JSON.stringify({ error: "unauthorized" }));
        return;
      }
      const body = await readJsonBody(req);
      if (body.target === "/forbidden") {
        res.statusCode = 403;
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ error: "viewer token cannot purge" }));
        return;
      }
      if (body.target === "/oversized") {
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json");
        res.end("x".repeat(2048));
        return;
      }
      counter += 1;
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ purged: counter, mode: body.mode }));
    });

    try {
      const client = new CachePurgeClient({
        baseUrl: srv.url,
        token: new Secret(runtimeToken),
        timeoutMs: 5000,
        maxResponseBytes: 1024,
      });

      // Inspect and JSON serialization of client never leak token.
      assert.equal(inspect(client).includes(runtimeToken), false);
      assert.equal(JSON.stringify(client).includes(runtimeToken), false);

      assert.deepEqual(await client.purgeUrl("/products/1", "shop.example.com"), { purged: 1, mode: "url" });
      assert.deepEqual(await client.purgePrefix("/products/", "shop.example.com"), { purged: 2, mode: "prefix" });
      assert.deepEqual(await client.purgeTag("sku-1", "shop.example.com"), { purged: 3, mode: "tag" });
      assert.deepEqual(await client.purgeAll("shop.example.com"), { purged: 4, mode: "all" });

      await assert.rejects(() => client.purgeUrl("", "shop.example.com"), RangeError);

      await assert.rejects(
        () => client.purgeUrl("/forbidden", "shop.example.com"),
        (err: unknown) =>
          err instanceof ConcertAPIError &&
          err.statusCode === 403 &&
          !err.message.includes(runtimeToken),
      );

      await assert.rejects(() => client.purgeUrl("/oversized", "shop.example.com"), /exceeds limit/);
    } finally {
      await srv.close();
    }
  });
});

describe("AgentBidClient and parseAuctionOffer (100% crypto-only)", () => {
  it("parses crypto-only 429 auction offers and rejects fiat chains", () => {
    const raw429 = JSON.stringify({
      queued: true,
      position: 4,
      status_url: "/queue/status",
      retry_after_seconds: 5,
      auction: {
        mode: "auction",
        auction_id: "auc-2026-01",
        scope: "shop.example.com:/drop",
        floor_micro_usd: 1_000_000,
        closes_at: "2026-11-26T18:05:00Z",
        slots: 2,
        min_wait_seconds: 3,
        bid_url: "/_concert/bids",
        status_url: "/_concert/bids/status",
        supported_chains: ["xrpl", "stellar", "hedera", "solana"],
      },
    });

    const offer = parseAuctionOffer(raw429);
    assert.equal(offer.mode, "auction");
    assert.equal(offer.floor_micro_usd, 1_000_000);
    assert.deepEqual(offer.supported_chains, ["xrpl", "stellar", "hedera", "solana"]);

    assert.equal(isSupportedChain("xrpl"), true);
    assert.equal(isSupportedChain("stellar"), true);
    assert.equal(isSupportedChain("hedera"), true);
    assert.equal(isSupportedChain("solana"), true);
    assert.equal(isSupportedChain("stripe"), false);
    assert.equal(isSupportedChain("usd"), false);

    assert.throws(
      () =>
        parseAuctionOffer({
          queued: true,
          auction: {
            mode: "instant",
            scope: "shop",
            floor_micro_usd: 1_000_000,
            supported_chains: ["stripe"],
          },
        }),
      RangeError,
    );
  });

  it("submits bids across xrpl/stellar/hedera/solana and polls status against local HTTP server", async () => {
    const store = new Map<string, BidRecord>();
    let seq = 0;

    const srv = await startLocalServer(async (req, res) => {
      res.setHeader("Content-Type", "application/json");
      const url = new URL(req.url ?? "/", "http://127.0.0.1");

      if (req.method === "POST" && url.pathname === BID_SUBMIT_PATH) {
        const body = await readJsonBody(req);
        if (body.amount_atomic === "1") {
          res.statusCode = 402;
          res.end(JSON.stringify({ error: "bidding: bid below floor micro-USD" }));
          return;
        }
        seq += 1;
        const bidId = `bid-${seq}`;
        const instant = body.scope === "instant";
        const status = instant ? "settled" : "pending";
        const rec: BidRecord = {
          bid_id: bidId,
          agent_key: String(body.agent_key ?? "agent-1"),
          scope: String(body.scope ?? "shop.example.com"),
          chain: body.chain as BidRecord["chain"],
          asset: String(body.asset),
          amount_atomic: String(body.amount_atomic),
          normalized_micro_usd: 1_500_000,
          status,
        };
        store.set(bidId, rec);
        res.statusCode = instant ? 200 : 202;
        res.end(
          JSON.stringify({
            bid: rec,
            bid_id: bidId,
            status,
            status_url: `${BID_STATUS_PATH}?bid_id=${bidId}`,
            pass_issued: instant,
            priority_pass: instant ? "priority-pass-instant" : undefined,
            pass_token: instant ? "priority-pass-instant" : undefined,
          }),
        );
        return;
      }

      if (req.method === "GET" && url.pathname === BID_STATUS_PATH) {
        const bidId = url.searchParams.get("bid_id") ?? "";
        const rec = store.get(bidId);
        if (!rec) {
          res.statusCode = 404;
          res.end(JSON.stringify({ error: "bid_not_found" }));
          return;
        }
        const settled: BidRecord = { ...rec, status: "settled", transaction: `tx-${bidId}` };
        store.set(bidId, settled);
        res.statusCode = 200;
        res.end(
          JSON.stringify({
            bid: settled,
            bid_id: bidId,
            status: "settled",
            pass_issued: true,
            priority_pass: `pass-${bidId}`,
            pass_token: `pass-${bidId}`,
          }),
        );
        return;
      }

      res.statusCode = 404;
      res.end(JSON.stringify({ error: "not found" }));
    });

    try {
      const client = new AgentBidClient({
        baseUrl: srv.url,
        concertSession: "agent-sess-node-1",
        timeoutMs: 5000,
      });

      const samplePayload = { x402Version: 2, payload: { tx: "signed-blob" } };

      // Reject fiat/non-crypto chains before sending network traffic.
      for (const badChain of ["stripe", "usd", "card", "fiat", ""]) {
        await assert.rejects(
          () =>
            client.submitBid({
              chain: badChain,
              asset: "USDC",
              amount_atomic: "1500000",
              payment_payload: samplePayload,
            }),
          RangeError,
        );
      }

      // Reject non-integer or non-positive amounts.
      for (const badAmount of ["0", "-5", "1.25", "abc"]) {
        await assert.rejects(
          () =>
            client.submitBid({
              chain: "solana",
              asset: "USDC",
              amount_atomic: badAmount,
              payment_payload: samplePayload,
            }),
          RangeError,
        );
      }

      // Instant-buy settlement on XRPL.
      const instant = await client.submitBid({
        scope: "instant",
        chain: "xrpl",
        asset: "XRP",
        amount_atomic: "2000000",
        payment_payload: samplePayload,
      });
      assert.equal(instant.status, "settled");
      assert.equal(instant.pass_issued, true);
      assert.equal(instant.pass_token, "priority-pass-instant");

      // Submit & poll status for all 4 crypto chains.
      for (const chain of SUPPORTED_CHAINS) {
        const submitted = await client.submitBid({
          scope: "shop.example.com:/drop",
          chain,
          asset: "USDC",
          amount_atomic: "1500000",
          payment_payload: samplePayload,
        });
        assert.equal(submitted.status, "pending");
        const status = await client.getBidStatus(submitted.bid_id);
        assert.equal(status.status, "settled");
        assert.equal(status.pass_issued, true);
        assert.equal(status.pass_token, `pass-${submitted.bid_id}`);
      }

      // 402 under-floor surfaces as ConcertAPIError(402).
      await assert.rejects(
        () =>
          client.submitBid({
            chain: "hedera",
            asset: "HBAR",
            amount_atomic: "1",
            payment_payload: samplePayload,
          }),
        (err: unknown) => err instanceof ConcertAPIError && err.statusCode === 402,
      );
    } finally {
      await srv.close();
    }
  });
});
