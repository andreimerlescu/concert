# `net/http` and Gin Priority Integration

Concert lets your origin rank visitors by emitting a `Concert-Priority` response header on page responses. Concert strips the header before forwarding to the client and issues a signed `concert_priority` cookie bound to the visitor's `concert_admit` pass.

## Supported Priority Tiers

| Constant | Header Value | Default Concert TTL | Behavior Under Load |
| --- | --- | --- | --- |
| `concert.PriorityStaff` | `staff` | `8h` | Priority lane (highest) |
| `concert.PriorityCheckout` | `checkout` | `30m` | Priority lane (payment in progress) |
| `concert.PrioritySubscriber` | `subscriber` | `8h` | Priority lane |
| `concert.PriorityCustomer` | `customer` | `8h` | Priority lane |
| `concert.PriorityProspect` | `prospect` | `30m` | Ranked ahead of members |
| `concert.PriorityMember` | `member` | `8h` | Ranked ahead of guests |
| `concert.PriorityGuest` | `guest` | clears cookie | Clears grant (e.g. on logout) |

Passing `ttl == 0` omits `; ttl=...` so Concert uses its per-tier default. Positive TTLs are clamped to `[1m, 24h]`.

## Standard `net/http` Middleware

```go
resolve := func(r *http.Request) (concert.PriorityTier, time.Duration, bool) {
	switch {
	case isStaffSession(r):
		return concert.PriorityStaff, 8 * time.Hour, true
	case strings.HasPrefix(r.URL.Path, "/checkout"):
		return concert.PriorityCheckout, 30 * time.Minute, true
	case r.URL.Path == "/logout":
		return concert.PriorityGuest, 0, true
	case isLoggedInMember(r):
		return concert.PriorityMember, 0, true
	default:
		return "", 0, false
	}
}

handler := concert.PriorityMiddleware(resolve)(mux)
```

## Gin Integration (Zero Gin Dependency)

The Go client intentionally does not import `github.com/gin-gonic/gin`. Two one-line adapters are provided:

### Option A: `GinPriorityAdapter`

```go
adapter := concert.GinPriorityAdapter(resolve)

router.Use(func(c *gin.Context) {
	adapter(c.Writer, c.Request, c.Next)
})
```

### Option B: `gin.WrapF` with `PriorityHandlerFunc`

```go
router.Use(gin.WrapF(concert.PriorityHandlerFunc(resolve)))
```

Both options set `Concert-Priority` before downstream handlers write response headers.
