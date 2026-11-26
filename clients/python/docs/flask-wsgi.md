# Flask / WSGI Integration

`ConcertPriorityWSGIMiddleware` is a pure PEP 3333 WSGI middleware compatible with Flask, Django WSGI, Bottle, and Pyramid.

## Wrapping a Flask App

```python
from flask import Flask, make_response
from concert_client import (
    ConcertPriorityWSGIMiddleware,
    set_priority_header,
)

flask_app = Flask(__name__)

@flask_app.post("/logout")
def logout():
    resp = make_response({"ok": True})
    set_priority_header(resp.headers, "guest")
    return resp

def resolve_rank(environ):
    path = environ.get("PATH_INFO", "")
    if path.startswith("/admin"):
        return ("staff", 28800)
    if path.startswith("/checkout"):
        return ("checkout", 1800)
    return None

flask_app.wsgi_app = ConcertPriorityWSGIMiddleware(flask_app.wsgi_app, resolve_rank)
```

## Per-Route Helper

When your priority decision depends on Flask's session or `g` object inside a route or `after_request` hook, use `set_priority_header` directly:

```python
from flask import g
from concert_client import highest_rank, set_priority_header

@flask_app.after_request
def attach_concert_priority(response):
    rank = highest_rank({
        "staff": getattr(g, "is_staff", False),
        "subscriber": getattr(g, "has_subscription", False),
        "customer": getattr(g, "has_orders", False),
        "member": getattr(g, "user_id", None) is not None,
    })
    if rank != "guest":
        set_priority_header(response.headers, rank)
    return response
```
