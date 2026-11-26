# Quickstart — Concert Go Client

The Concert Go client (`github.com/andreimerlescu/concert/clients/go/src`) uses only the Go standard library (`go 1.24+`) and has zero third-party dependencies.

## 1. Install

```bash
go get github.com/andreimerlescu/concert/clients/go/src
```

## 2. Emit `Concert-Priority` from Your Origin

Concert reads the `Concert-Priority` response header emitted by your origin, strips it before the browser sees it, and binds a signed `concert_priority` cookie to the visitor's admission pass:

```go
package main

import (
	"net/http"
	"time"

	concert "github.com/andreimerlescu/concert/clients/go/src"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/checkout", func(w http.ResponseWriter, r *http.Request) {
		_ = concert.SetPriority(w, concert.PriorityCheckout, 30*time.Minute)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("checkout"))
	})

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	_ = srv.ListenAndServe()
}
```

## 3. Detect Queued Responses in API Clients

Concert guarantees `X-Concert-Queue: 1` is sent **only** on genuine waiting-room responses (never on abuse bans, rate limits, or upstream errors):

```go
sig := concert.ParseWaitingRoomSignal(resp.Header)
if sig.Queued {
	// Wait sig.RetryAfter before polling sig.StatusURL (defaults to "/queue/status").
	log.Printf("queued at position %d; retry in %s", sig.Position, sig.RetryAfter)
}
```

## Next Steps

- [`net/http` & Gin middleware](http-and-gin.md)
- [Stateless `rm1` Ed25519 passes & key rotation](rm1-key-rotation.md)
- [Authenticated cache purge](cache-purge.md)
- [Crypto-only AI agent pass bidding](agent-bidding.md)
