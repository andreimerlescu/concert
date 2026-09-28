package fastlane

import (
	"net/http"
	"strings"
	"time"
)

// The XRP Ledger has a built-in NFT market. The access page lists a
// collection's open sell offers so a visitor can see what is for sale; buying
// happens in the visitor's own wallet or marketplace, and the purchase then
// proves itself through the ordinary NFT ownership check.

const marketTTL = time.Minute

type marketEntry struct {
	at    time.Time
	sales any
}

// marketURL is where the given token can be viewed and bought.
func marketURL(network, token string) string {
	host := map[string]string{"xrpl:0": "bithomp.com", "xrpl:1": "test.bithomp.com", "xrpl:2": "dev.bithomp.com"}[network]
	if host == "" {
		return ""
	}
	return "https://" + host + "/nft/" + token
}

func (s *Service) market(w http.ResponseWriter, r *http.Request) {
	rule := r.URL.Query().Get("rule")
	var col Collection
	found := false
	for _, c := range s.cfg.Collections {
		if c.ID == rule && chain(c.Network) == "xrpl" {
			col, found = c, true
		}
	}
	if !found {
		failure(w, 404, "no_market_for_collection")
		return
	}
	now := s.now()
	s.mu.Lock()
	e, ok := s.marketCache[rule]
	s.mu.Unlock()
	if ok && now.Sub(e.at) < marketTTL {
		reply(w, 200, e.sales)
		return
	}
	var out struct {
		Sales []struct {
			TokenID string `json:"token_id"`
			Offer   string `json:"offer"`
			Seller  string `json:"seller"`
			Price   string `json:"price"`
			URI     string `json:"uri"`
		} `json:"sales"`
	}
	if err := s.gatewayCall(r.Context(), callTimeout, "/market/sales", map[string]any{"network": col.Network, "collection": col.Collection}, &out); err != nil {
		if ok {
			reply(w, 200, e.sales) // stale beats empty
			return
		}
		reply(w, 200, map[string]any{"sales": []any{}, "unavailable": true})
		return
	}
	items := make([]map[string]any, 0, len(out.Sales))
	for _, x := range out.Sales {
		if len(x.TokenID) != 64 || strings.Trim(x.TokenID, "0123456789ABCDEFabcdef") != "" {
			continue
		}
		items = append(items, map[string]any{"token_id": x.TokenID, "seller": x.Seller, "price": x.Price, "price_display": shown(col.Network, x.Price), "buy_url": marketURL(col.Network, x.TokenID)})
	}
	body := map[string]any{"sales": items, "network": col.Network}
	s.mu.Lock()
	if len(s.marketCache) > 64 {
		s.marketCache = map[string]marketEntry{}
	}
	s.marketCache[rule] = marketEntry{now, body}
	s.mu.Unlock()
	reply(w, 200, body)
}
