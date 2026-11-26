# Next.js App Router & Middleware Integration

`@concert/client` works directly with Web Fetch `Request`/`Response` and Next.js `NextRequest`/`NextResponse` without importing `next`.

## 1. Next.js Middleware (`middleware.ts`)

```ts
import { NextResponse, type NextRequest } from "next/server";
import { createNextPriorityMiddleware } from "@concert/client";

const concertPriority = createNextPriorityMiddleware(
  (req: NextRequest) => {
    if (req.nextUrl.pathname.startsWith("/checkout")) {
      return { tier: "checkout", ttlSeconds: 30 * 60 };
    }
    if (req.cookies.get("session_role")?.value === "staff") {
      return { tier: "staff", ttlSeconds: 8 * 3600 };
    }
    return null;
  },
  () => NextResponse.next(),
);

export function middleware(req: NextRequest) {
  return concertPriority(req);
}
```

## 2. Next.js App Router Route Handlers (`app/**/route.ts`)

Wrap a route handler with `withFetchPriority`, or stamp a single response with `withPriorityResponse`:

```ts
import { withFetchPriority, withPriorityResponse } from "@concert/client";

export const GET = withFetchPriority(
  async () => {
    return Response.json({ status: "ok" });
  },
  (req) => {
    if (req.headers.get("x-subscriber") === "1") {
      return { tier: "subscriber", ttlSeconds: 3600 };
    }
    return null;
  },
);

export async function POST() {
  return withPriorityResponse(Response.json({ started: true }), "checkout", 1800);
}
```

If a `Response` has immutable headers (such as `Response.redirect(...)`), `withPriorityResponse` transparently clones it with the `Concert-Priority` header added.
