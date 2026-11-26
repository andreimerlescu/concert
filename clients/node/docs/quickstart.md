# Quickstart — Concert Node.js / TypeScript Client

`@concert/client` (`clients/node`) has **zero runtime npm dependencies** and uses Node.js's built-in `node:crypto` and `fetch` APIs.

## 1. Import

```ts
import {
  formatPriorityHeader,
  parseWaitingRoomSignal,
  mintRM1Pass,
  verifyRM1,
  CachePurgeClient,
  AgentBidClient,
} from "@concert/client";
```

## 2. Detect Concert Waiting-Room Responses

Concert guarantees `X-Concert-Queue: 1` is emitted **only** on genuine waiting-room responses (never on abuse rate limits or upstream 503s):

```ts
const resp = await fetch("https://shop.example.com/api/drop");
const signal = parseWaitingRoomSignal(resp.headers);
if (signal.queued) {
  console.log("Queued at position", signal.position, "statusUrl:", signal.statusUrl);
  // Wait signal.retryAfterSeconds before polling signal.statusUrl
}
```

## 3. Issue & Verify Stateless `rm1` Ed25519 Passes

Load your Ed25519 private key at runtime from a secret manager or `0600` file (never hardcode private keys in source):

```ts
import { readFileSync } from "node:fs";
import { mintRM1Pass, verifyRM1, HEADER_ROOM_PASS } from "@concert/client";

const privPem = readFileSync("/run/secrets/concert_rm1_k1.pem", "utf8");
const pass = mintRM1Pass(privPem, "k1", "shop.example.com", "", 300);

// Forward to Concert via X-Room-Pass (Concert strips X-Room-Pass before reaching origin).
const headers = { [HEADER_ROOM_PASS]: pass };
```

## Next Steps

- [Express priority middleware](express.md)
- [Next.js App Router & Middleware](nextjs.md)
- [Authenticated cache purge](cache-purge.md)
- [Crypto-only AI agent bidding](agent-bidding.md)
