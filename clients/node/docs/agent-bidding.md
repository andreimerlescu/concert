# Crypto-Only AI Agent Bidding (`xrpl`, `stellar`, `hedera`, `solana`)

Concert is **100% crypto-only** and supports non-custodial hybrid AI agent pass bidding exclusively across four networks:

- `xrpl`
- `stellar`
- `hedera`
- `solana`

Signed x402 v2 payment authorizations are verified off-chain; **only winning bids settle on-chain**, while losing bids pay `$0` with zero custody and zero refunds.

## 1. Parse the Live Auction Offer from HTTP `429`

```ts
import { parseWaitingRoomSignal, parseAuctionOffer, AgentBidClient } from "@concert/client";

const resp = await fetch("https://shop.example.com/api/drop", {
  headers: { Accept: "application/json", "Concert-Session": "agent-01" },
});

const signal = parseWaitingRoomSignal(resp.headers);
if (signal.queued && resp.status === 429) {
  const offer = parseAuctionOffer(await resp.text());
  console.log("Offer:", offer.mode, offer.floor_micro_usd, offer.supported_chains);
}
```

## 2. Submit a Crypto Bid & Poll Settlement

```ts
const bidder = new AgentBidClient({
  baseUrl: "https://shop.example.com",
  concertSession: "agent-01",
  timeoutMs: 10_000,
});

const submitted = await bidder.submitBid({
  scope: offer.scope,
  chain: "solana",
  asset: "USDC",
  amount_atomic: "1500000", // Positive base-10 integer smallest units
  payment_payload: signedX402Authorization,
});

if (submitted.pass_issued) {
  console.log("Instant priority pass issued:", submitted.pass_token);
} else {
  const status = await bidder.getBidStatus(submitted.bid_id);
  if (status.status === "settled" && status.pass_issued) {
    console.log("Won auction! Pass:", status.pass_token);
  }
}
```
