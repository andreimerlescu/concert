package xrpl

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCollectionSalesKeepsCheapestPublicXRPOffer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string           `json:"method"`
			Params []map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Method {
		case "nfts_by_issuer":
			_, _ = w.Write([]byte(`{"result":{"status":"success","nfts":[
			 {"nft_id":"A1","owner":"rOwnerA","is_burned":false,"uri":"AB"},
			 {"nft_id":"B2","owner":"rOwnerB","is_burned":false},
			 {"nft_id":"C3","owner":"rOwnerC","is_burned":true},
			 {"nft_id":"D4","owner":"rOwnerD","is_burned":false}]}}`))
		case "nft_sell_offers":
			switch req.Params[0]["nft_id"] {
			case "A1":
				_, _ = w.Write([]byte(`{"result":{"status":"success","offers":[
				 {"nft_offer_index":"O1","amount":"9000000","owner":"rOwnerA"},
				 {"nft_offer_index":"O2","amount":"5000000","owner":"rOwnerA"},
				 {"nft_offer_index":"O3","amount":"1000000","owner":"rOwnerA","destination":"rPrivate"},
				 {"nft_offer_index":"O4","amount":{"currency":"USD","value":"1"},"owner":"rOwnerA"},
				 {"nft_offer_index":"O5","amount":"100","owner":"rSomeoneElse"}]}}`))
			case "B2":
				_, _ = w.Write([]byte(`{"result":{"status":"error","error":"objectNotFound"}}`))
			default:
				_, _ = w.Write([]byte(`{"result":{"status":"success","offers":[{"nft_offer_index":"O9","amount":"2000000","owner":"rOwnerD","expiration":1}]}}`))
			}
		}
	}))
	defer srv.Close()
	got, err := RPC{URL: srv.URL}.CollectionSales(context.Background(), "rIssuer", 7)
	if err != nil || len(got) != 1 || got[0].TokenID != "A1" || got[0].Drops != "5000000" || got[0].Offer != "O2" {
		t.Fatalf("%+v %v", got, err)
	}
}
