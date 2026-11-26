# Crypto-Only AI Agent Pass Bidding

Concert's AI Agent Pass Bidding protocol is **100% crypto-only**. Supported settlement chains are strictly:

- `xrpl`
- `stellar`
- `hedera`
- `solana`

No fiat rails are accepted anywhere in the protocol or client SDK.

## Example Flow

```ruby
require "concert_client"

client = ConcertClient::AgentBidClient.new(
  "https://drop.example.com",
  max_bid_micro_usd: ConcertClient::AgentBidClient.parse_usd_to_micro_usd("2.50"),
  chain: "solana",
  asset: "USDC",
  session_id: ENV.fetch("CONCERT_AGENT_SESSION")
)

offer = ConcertClient::AgentBidClient.parse_auction_offer(response_429_body, status_code: 429)
if offer
  bid_amount = client.evaluate_offer(offer)
  if bid_amount
    # Sign non-custodial crypto x402 authorization locally without broadcasting on-chain
    signed_payload = sign_x402_locally(offer, chain: client.chain, micro_usd: bid_amount)

    resp = client.submit_bid(
      bid_micro_usd: bid_amount,
      amount_atomic: bid_amount.to_s,
      payment_payload: signed_payload,
      scope: offer.scope,
      auction_id: offer.auction_id,
      bid_url: offer.bid_url
    )
    resp = client.poll_bid_status(resp.bid_id, status_url: offer.status_url) unless resp.terminal?

    if resp.settled? && resp.pass_issued?
      puts "Won! Settled tx=#{resp.transaction}"
    else
      puts "Not settled ($0 charged): status=#{resp.status} reason=#{resp.reason}"
    end
  end
end
```

## Security Controls

- **Exact Integer Caps**: `parse_usd_to_micro_usd` uses integer math (no binary floating point), and both `evaluate_offer` and `submit_bid` strictly enforce `max_bid_micro_usd` (`ConcertClient::BidCapExceededError`).
- **Same-Origin SSRF Protection**: `offer.bid_url` and `offer.status_url` must match `base_url`'s scheme, host, and port (`ConcertClient::CrossOriginError`).
- **Secret Redaction**: `session_id` and `pass_token` are redacted from `inspect` and `to_s`.
