package xrpl

import (
	"context"
	"errors"
	"math/big"
	"sort"
	"sync"
	"time"
)

// Sale is one NFT with an open public sell offer for XRP.
type Sale struct {
	TokenID string `json:"token_id"`
	Offer   string `json:"offer"`
	Seller  string `json:"seller"`
	Drops   string `json:"price"`
	URI     string `json:"uri,omitempty"` // hex, as minted
}

const (
	maxMarketTokens = 60
	marketWorkers   = 6
)

// CollectionSales lists NFTs of issuer:taxon that hold an open, public sell
// offer priced in XRP, cheapest first. It needs a server that answers
// nfts_by_issuer (Clio, which the public clusters run); on one that does not,
// it returns an error and the caller shows nothing for sale.
func (c RPC) CollectionSales(ctx context.Context, issuer string, taxon uint32) ([]Sale, error) {
	var listing struct {
		NFTs []struct {
			ID     string `json:"nft_id"`
			Owner  string `json:"owner"`
			Burned bool   `json:"is_burned"`
			URI    string `json:"uri"`
		} `json:"nfts"`
	}
	if err := c.call(ctx, "nfts_by_issuer", map[string]any{"issuer": issuer, "nft_taxon": taxon, "limit": maxMarketTokens}, &listing); err != nil {
		return nil, err
	}
	var (
		mu    sync.Mutex
		sales []Sale
		wg    sync.WaitGroup
		sem   = make(chan struct{}, marketWorkers)
		now   = time.Now()
	)
	for _, n := range listing.NFTs {
		if n.Burned || n.ID == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(id, owner, uri string) {
			defer wg.Done()
			defer func() { <-sem }()
			var offers struct {
				Offers []struct {
					Index       string `json:"nft_offer_index"`
					Amount      any    `json:"amount"`
					Owner       string `json:"owner"`
					Destination string `json:"destination"`
					Expiration  int64  `json:"expiration"`
				} `json:"offers"`
			}
			err := c.call(ctx, "nft_sell_offers", map[string]any{"nft_id": id, "ledger_index": "validated"}, &offers)
			var re *rpcError
			if err != nil || errors.As(err, &re) {
				return
			}
			var best *Sale
			var bestDrops *big.Int
			for _, o := range offers.Offers {
				drops, isXRP := o.Amount.(string)
				if !isXRP || o.Destination != "" || o.Owner != owner || (o.Expiration != 0 && o.Expiration+rippleEpoch <= now.Unix()) {
					continue
				}
				d, ok := new(big.Int).SetString(drops, 10)
				if !ok || d.Sign() <= 0 {
					continue
				}
				if bestDrops == nil || d.Cmp(bestDrops) < 0 {
					bestDrops = d
					best = &Sale{TokenID: id, Offer: o.Index, Seller: o.Owner, Drops: drops, URI: uri}
				}
			}
			if best != nil {
				mu.Lock()
				sales = append(sales, *best)
				mu.Unlock()
			}
		}(n.ID, n.Owner, n.URI)
	}
	wg.Wait()
	sortSales(sales)
	return sales, nil
}

func sortSales(s []Sale) {
	sort.Slice(s, func(i, j int) bool {
		x, _ := new(big.Int).SetString(s[i].Drops, 10)
		y, _ := new(big.Int).SetString(s[j].Drops, 10)
		if c := x.Cmp(y); c != 0 {
			return c < 0
		}
		return s[i].TokenID < s[j].TokenID
	})
}
