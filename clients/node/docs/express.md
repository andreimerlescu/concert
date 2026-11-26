# Express Integration

Use `expressPriorityMiddleware` to emit Concert's `Concert-Priority` response header on page responses. Concert strips `Concert-Priority` before the browser receives it and binds the grant to the visitor's signed `concert_admit` cookie.

## Setup

```ts
import express from "express";
import { expressPriorityMiddleware } from "@concert/client";

const app = express();

app.use(
  expressPriorityMiddleware((req) => {
    if (req.user?.role === "staff") {
      return { tier: "staff", ttlSeconds: 8 * 3600 };
    }
    if (req.path.startsWith("/checkout")) {
      return { tier: "checkout", ttlSeconds: 30 * 60 };
    }
    if (req.path === "/logout") {
      // Clears any previously granted concert_priority cookie.
      return { tier: "guest" };
    }
    if (req.user?.isSubscriber) {
      return { tier: "subscriber" }; // Uses Concert's default 8h TTL.
    }
    if (req.user?.id) {
      return { tier: "member" };
    }
    return null;
  }),
);
```

## Async Resolvers

`expressPriorityMiddleware` supports `async` resolvers (for example, checking a session store or subscription flag). Any rejected promise is forwarded to Express's `next(err)` error handler.
