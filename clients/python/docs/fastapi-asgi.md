# FastAPI / ASGI Integration

`ConcertPriorityASGIMiddleware` is a pure ASGI 3.0 middleware that works with FastAPI, Starlette, Quart, and Litestar without importing any framework packages.

## Wrapping a FastAPI App

```python
from fastapi import FastAPI, Response
from concert_client import (
    ConcertPriorityASGIMiddleware,
    highest_rank,
    set_priority_header,
)

api = FastAPI()

@api.post("/logout")
async def logout(response: Response):
    # Explicitly clear the visitor's priority grant on logout.
    set_priority_header(response.headers, "guest")
    return {"ok": True}

async def resolve_priority(scope):
    path = scope.get("path", "")
    # Derive facts from your own auth/session layer.
    facts = {
        "checkout": path.startswith("/checkout"),
        "prospect": path.startswith("/cart"),
    }
    rank = highest_rank(facts)
    if rank == "guest":
        return None
    ttl = 1800 if rank in ("checkout", "prospect") else 28800
    return (rank, ttl)

# Export `app` to uvicorn / hypercorn:
app = ConcertPriorityASGIMiddleware(api, resolve_priority)
```

## Behavior Notes

- Both `async def` and plain synchronous `def` resolvers are supported.
- Returning `None` skips setting the header (recommended for anonymous visitors who were never granted a rank).
- Non-HTTP scopes (`lifespan`, `websocket`) pass through untouched.
- Existing `Concert-Priority` headers are replaced cleanly without duplicates.
- Concert strips `Concert-Priority` before forwarding responses to browsers.
