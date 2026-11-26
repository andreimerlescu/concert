# Crypto-Only AI Agent Bidding (`xrpl`, `stellar`, `hedera`, `solana`)

Concert supports non-custodial hybrid AI agent pass bidding over **four crypto networks only**:

- `xrpl` (XRP Ledger)
- `stellar` (Stellar)
- `hedera` (Hedera)
- `solana` (Solana)

Concert is **100% crypto-only** — there is no fiat or card processing. Signed x402 v2 payment authorizations are verified off-chain; **only winning bids settle on-chain**, while losing bids are dropped unsettled (`$0` paid, zero custody, zero refunds).

## 1. Parse the `429` Auction Offer

When an AI agent receives an HTTP `429` queued response with `X-Concert-Queue: 1`, parse the live auction offer from the JSON body:

```go
sig := concert.ParseWaitingRoomSignal(resp.Header)
if sig.Queued {
	offer, err := concert.ParseAuctionOffer(bodyBytes)
	if err == nil {
		log.Printf("mode=%s floor=%d micro-USD chains=%v", offer.Mode, offer.FloorMicroUSD, offer.SupportedChains)
	}
}
```

`ParseAuctionOffer` validates that every advertised chain is one of `xrpl`, `stellar`, `hedera`, or `solana`.

## 2. Submit a Signed Crypto Bid

Create an `AgentBidClient` (sharing an `*http.Client` with a `cookiejar.Jar` if you want Concert's `concert_admit` and `concert_priority` cookies saved automatically):

```go
jar, _ := cookiejar.New(nil)
bidder, err := concert.NewAgentBidClient(concert.AgentBidConfig{
	BaseURL:        "https://shop.example.com",
	ConcertSession: "my-agent-session-id",
	HTTPClient:     &http.Client{Jar: jar, Timeout: 10 * time.Second},
})
if err != nil {
	return err
}

subResp, err := bidder.SubmitBid(ctx, concert.BidSubmission{
	Scope:          offer.Scope,
	Chain:          concert.ChainSolana,
	Asset:          "USDC",
	AmountAtomic:   "1500000", // integer smallest units — never float64
	PaymentPayload: signedX402PayloadJSON,
})
if err != nil {
	return err
}
```

- When `offer.Mode == "instant"`, Concert settles immediately and returns HTTP `200` with `subResp.PassIssued == true` and `subResp.PassToken`.
- When `offer.Mode == "auction"`, Concert returns HTTP `202` with `subResp.Status == concert.BidStatusPending`.

## 3. Poll Settlement Status

```go
statResp, err := bidder.GetBidStatus(ctx, subResp.BidID)
if err != nil {
	return err
}
switch statResp.Status {
case concert.BidStatusSettled:
	// statResp.PassIssued == true; retry your target route using the issued cookies / pass.
case concert.BidStatusLost:
	// Unsettled — $0 paid. You may re-bid in the next epoch or stay in the free queue.
}
```
