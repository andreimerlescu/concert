# Crypto-Only AI Agent Pass Bidding

Concert's AI Agent Pass Bidding protocol is **100% crypto-only**. Supported settlement chains are strictly:

- `xrpl`
- `stellar`
- `hedera`
- `solana`

No fiat rails are accepted anywhere in the protocol or client SDK.

## How Non-Custodial Bidding Works

1. When a queued agent receives `429 Too Many Requests`, Concert attaches an `auction` offer block in the JSON body (`mode: "instant"` when slots are open, or `mode: "auction"` when saturated).
2. `parse_auction_offer` parses the offer and filters chains to Concert's crypto allowlist.
3. `AgentBidClient` enforces your strict exact-integer `max_bid_micro_usd` spend cap (`1_000_000` micro-USD = `$1.00`, zero binary floating point).
4. Your local crypto wallet signs an x402 v2 payment authorization **without broadcasting on-chain**, and `submit_bid` posts it to `POST /_concert/bids`.
5. Concert verifies the authorization off-chain and settles **only winning bids** on-chain. Losing bids are dropped unsettled and pay **$0**.

## Example

```python
from concert_client import (
    AgentBidClient,
    parse_auction_offer,
    parse_usd_to_micro_usd,
)

client = AgentBidClient(
    "https://drop.example.com",
    max_bid_micro_usd=parse_usd_to_micro_usd("2.50"),
    chain="solana",
    asset="USDC",
    session_id=agent_session_id,  # loaded at runtime
)

offer = parse_auction_offer(response_429_bytes, status_code=429)
if offer is not None:
    bid_amount = client.evaluate_offer(offer)
    if bid_amount is not None:
        # Sign non-custodial crypto authorization locally with your wallet signer
        signed_payload = sign_x402_locally(offer, chain=client.chain, micro_usd=bid_amount)
        resp = client.submit_bid(
            bid_micro_usd=bid_amount,
            amount_atomic=str(bid_amount),
            payment_payload=signed_payload,
            scope=offer.scope,
            auction_id=offer.auction_id,
            bid_url=offer.bid_url,
        )
        if not resp.is_terminal:
            resp = client.poll_bid_status(resp.bid_id, status_url=offer.status_url)

        if resp.settled and resp.pass_issued:
            print("Won! Pass issued, tx:", resp.transaction)
        else:
            print("Not settled (paid $0):", resp.status, resp.reason)
```

## Security Controls

- **Hard Spend Cap**: Both `evaluate_offer` and `submit_bid` refuse any bid exceeding `max_bid_micro_usd` (`BidCapExceededError`).
- **Same-Origin SSRF Defense**: `offer.bid_url` and `offer.status_url` are validated against `base_url`'s exact scheme, host, and port (`CrossOriginError`).
- **Secret Redaction**: `session_id`, `pass_token`, and signed `payment_payload` bytes are never included in `repr()`, `str()`, or error messages.
