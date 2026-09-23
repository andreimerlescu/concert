# Concert

[![Go Reference](https://pkg.go.dev/badge/github.com/andreimerlescu/concert.svg)](https://pkg.go.dev/github.com/andreimerlescu/concert)
[![Latest Release](https://img.shields.io/github/v/release/andreimerlescu/concert?sort=semver)](https://github.com/andreimerlescu/concert/releases/latest)
[![Go Version](https://img.shields.io/github/go-mod/go-version/andreimerlescu/concert)](https://github.com/andreimerlescu/concert/blob/main/go.mod)
[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/andreimerlescu/concert/blob/main/LICENSE)
[![Built on room](https://img.shields.io/badge/built%20on-room-00d4ff)](https://github.com/andreimerlescu/room)
[![GitHub Stars](https://img.shields.io/github/stars/andreimerlescu/concert?style=social)](https://github.com/andreimerlescu/concert/stargazers)

![Concert — FIFO Waiting Room Reverse Proxy](/concert.jpg)

A FIFO waiting room reverse proxy. Put Concert in front of any HTTP origin, such as a PHP site, a WordPress install, or a legacy app that falls over under load. When traffic exceeds what the origin can handle, visitors wait in an orderly queue with a live position instead of getting 502s and timeouts. Admitted visitors load their page's assets through a separate tier that queued and denied visitors can't reach, and clients that misbehave are blocked for an escalating cooldown.

Concert is a single Go binary built on [room](https://github.com/andreimerlescu/room), a FIFO waiting room middleware for Gin, and [sema](https://github.com/andreimerlescu/sema), a resizable semaphore.

## Why

A PHP-FPM pool has a fixed number of workers (`pm.max_children`). When every worker is busy, new requests pile up in the web server's backlog until they time out. Users see 502 or 504 errors, hit refresh, and make the spike worse.

Concert caps the number of concurrent page requests that reach your origin. Everyone past that cap is shown a waiting room page with their queue position, and they are admitted automatically, in arrival order, as slots free up. Your origin only ever sees the load you chose.

## How it works

    browser ──▶ TLS terminator ──▶ concert :8080 ──▶ origin :3000
                                      │
              every request ──────────┼─▶ client banned? ──▶ 429 until the cooldown ends
                                      │   ban path? ──────▶ ban now, 429
                                      │
              page requests ──────────┼─▶ room: slot free?
                                      │     yes ──▶ proxied, concert_admit pass issued
                                      │     no  ──▶ waiting room page, polls /queue/status
                                      │
              asset requests ─────────┼─▶ valid concert_admit pass?
                                      │     no  ──▶ 403
                                      │     yes ──▶ per-user semaphore (HTTP/1.1 or HTTP/2 rule)
                                      │               ──▶ global asset semaphore ──▶ proxied
                                      │
              bypass paths ───────────┴─▶ proxied, no guard

**Every request** is first matched to a client address. Banned clients are rejected before anything else runs.

**Pages** go through room. A request whose ticket falls inside the serving window takes a slot, is proxied, and releases the slot when its response has been fully delivered. Other requests get a `room_ticket` cookie and the waiting room page, which polls `/queue/status` and reloads when the visitor's turn arrives. `-cap` is the maximum number of page requests in flight to your origin.

**Admitted page responses** also carry `concert_admit`, a signed, HttpOnly pass that slides forward as the visitor keeps browsing.

**Assets** don't queue. A stylesheet or image can't run the waiting room's JavaScript, so making one wait is the same as failing it. Instead, asset paths require a valid pass, and each pass has its own small concurrency pool. One visitor can't monopolise the asset tier, and visitors who were never admitted can't touch it at all. A global semaphore across all passes protects the host.

## Install

    go install github.com/andreimerlescu/concert@latest

Or build from source:

    git clone https://github.com/andreimerlescu/concert.git
    cd concert
    make build

`make build` writes static binaries for Linux, macOS and Windows on amd64 and arm64 to `bin/`. Requires Go 1.22 or newer.

## Quick start

Start something to protect. PHP's built-in server is enough for a demo:

    php -S 127.0.0.1:3000 -t /var/www/html

Put Concert in front of it with a deliberately small capacity:

    concert -upstream http://127.0.0.1:3000 -cap 5 -assets "/css/*,/js/*,/images/*"

Open `http://127.0.0.1:8080/` in a browser, then generate load from another terminal:

    ab -c 100 -n 2000 http://127.0.0.1:8080/

Refresh the browser while the load test runs and you'll land in the waiting room, then be admitted automatically as slots open.

## Configuration

Every option can be set with a flag or an environment variable. A flag overrides its environment variable, and the environment variable overrides the built-in default.

| Flag | Environment | Default | Description |
|---|---|---|---|
| `-listen` | `CONCERT_LISTEN` | `:8080` | Address to listen on |
| `-upstream` | `CONCERT_UPSTREAM` | `http://127.0.0.1:3000` | Origin to proxy to (`http` or `https`) |
| `-cap` | `CONCERT_CAPACITY` | `500` | Max concurrent page requests allowed through to the origin |
| `-max-queue` | `CONCERT_MAX_QUEUE` | `10000` | Reject new arrivals with 503 beyond this queue depth (0 = unlimited) |
| `-reaper` | `CONCERT_REAPER` | `30s` | How often abandoned tickets are cleaned up |
| `-token-ttl` | `CONCERT_TOKEN_TTL` | `0` (room default, 5m) | Sliding lifetime of a queued ticket, 30s–24h |
| `-secure-cookie` | `CONCERT_SECURE_COOKIE` | `false` | Mark cookies `Secure` (only if browsers reach you over HTTPS) |
| `-cookie-path` | `CONCERT_COOKIE_PATH` | `/` | Path attribute of cookies |
| `-cookie-domain` | `CONCERT_COOKIE_DOMAIN` | *(empty)* | Domain attribute of cookies |
| `-preserve-host` | `CONCERT_PRESERVE_HOST` | `true` | Forward the client's `Host` header to the origin |
| `-trusted-proxies` | `CONCERT_TRUSTED_PROXIES` | `127.0.0.1/32,::1/128` | CIDRs whose `X-Forwarded-For` and `X-Forwarded-Proto` are trusted |
| `-bypass` | `CONCERT_BYPASS` | `/favicon.ico` | Paths that skip every guard; suffix `/*` for a prefix |
| `-assets` | `CONCERT_ASSETS` | *(empty)* | Asset paths that require an admission pass; suffix `/*` for a prefix |
| `-asset-public` | `CONCERT_ASSET_PUBLIC` | *(empty)* | Asset paths served without a pass, still under the global asset cap |
| `-asset-cap` | `CONCERT_ASSET_CAP` | `0` (derived) | Global concurrent asset requests; 0 means `cap × asset-user-cap-h2` |
| `-asset-wait` | `CONCERT_ASSET_WAIT` | `2s` | Max wait for a global asset slot before 503 |
| `-asset-user-cap-h1` | `CONCERT_ASSET_USER_CAP_H1` | `8` | Concurrent asset requests per pass over HTTP/1.x |
| `-asset-user-cap-h2` | `CONCERT_ASSET_USER_CAP_H2` | `128` | Concurrent asset requests per pass over HTTP/2 and HTTP/3 |
| `-asset-user-wait` | `CONCERT_ASSET_USER_WAIT` | `2s` | Max wait for a per-pass asset slot before 429 |
| `-admit-ttl` | `CONCERT_ADMIT_TTL` | `10m` | Sliding lifetime of the admission pass (minimum 30s) |
| `-client-proto-header` | `CONCERT_CLIENT_PROTO_HEADER` | *(empty)* | Header from a trusted TLS terminator carrying the client's HTTP protocol |
| `-abuse` | `CONCERT_ABUSE` | `true` | Enable the abuse registry |
| `-abuse-strikes` | `CONCERT_ABUSE_STRIKES` | `20` | Strike total within the window that triggers a ban |
| `-abuse-window` | `CONCERT_ABUSE_WINDOW` | `1m` | Window over which strikes accumulate |
| `-abuse-cooldown` | `CONCERT_ABUSE_COOLDOWN` | `5m` | First ban length; doubles with each repeat ban |
| `-abuse-max-cooldown` | `CONCERT_ABUSE_MAX_COOLDOWN` | `24h` | Longest ban; also how long ban history is remembered |
| `-abuse-max-entries` | `CONCERT_ABUSE_MAX_ENTRIES` | `100000` | Max clients tracked at once |
| `-abuse-allow` | `CONCERT_ABUSE_ALLOW` | *(empty)* | CIDRs that are never struck or banned |
| `-ban-paths` | `CONCERT_BAN_PATHS` | *(empty)* | Paths that ban the client on first hit; suffix `/*` for a prefix |
| `-access-log` | `CONCERT_ACCESS_LOG` | `true` | Write an access log line per non-asset request |
| `-html` | `CONCERT_HTML_FILE` | *(empty)* | Custom waiting room HTML file |
| `-skip-url` | `CONCERT_SKIP_URL` | *(empty)* | Payment page URL for the skip-the-line card (see limitations) |
| `-rate` | `CONCERT_RATE` | `0` | Base price per queue position (0 disables skip-the-line) |
| `-surge` | `CONCERT_SURGE` | `0` | Extra price per position for each client in the queue |
| `-pass` | `CONCERT_PASS_DURATION` | `0` | VIP pass lifetime after paying to skip (0 disables passes) |
| `-upstream-timeout` | `CONCERT_UPSTREAM_TIMEOUT` | `30s` | How long to wait for the origin's response headers |
| `-api-json` | `CONCERT_API_JSON` | `true` | Answer queued non-browser clients with JSON 429 instead of HTML |
| `-retry-after` | `CONCERT_RETRY_AFTER` | `5` | `Retry-After` seconds sent to queued API clients |
| `-version` | | | Print the version and exit |
| | `CONCERT_ADMIN_TOKEN` | *(empty)* | Bearer token for the admin endpoints; they are disabled when unset |
| | `CONCERT_ADMIT_SECRET` | *(random)* | Key that signs admission passes; at least 32 bytes |

Both secrets are environment-only on purpose: command-line arguments are visible in `ps` output and shell history.

When `CONCERT_ADMIT_SECRET` is unset, Concert generates a random key at startup. Passes then stop working on restart, and a second instance won't accept the first instance's passes. Set it explicitly in production:

    openssl rand -base64 48

## Choosing a page capacity

`-cap` counts concurrent page requests, not users. A slot is held from the moment a request is admitted until the last byte of the origin's response has been sent to the client.

For a PHP-FPM origin, start with `-cap` at or slightly below the pool's `pm.max_children`. Concert then admits only as many requests as there are workers to run them, and the backlog lives in Concert's queue, where users can see their position, instead of in a socket buffer where they can't.

Throughput follows from Little's law: requests admitted per second ≈ `cap` ÷ average time a slot is held. With `-cap 50` and a 200 ms average response, Concert admits about 250 requests per second. If the origin slows down under load, admissions slow down with it, which is exactly the protection you want.

Page capacity can be changed at runtime without a restart; see `POST /_room/cap` below.

## Client addresses and trusted proxies

Behind nginx or a load balancer, every connection to Concert comes from the proxy. `-trusted-proxies` lists the addresses Concert should look past.

When a connection comes from a trusted proxy, Concert reads `X-Forwarded-For` from right to left and takes the first address that isn't itself a trusted proxy. Addresses further left were written by the client and are ignored. When a connection comes from anywhere else, its own address is the client, and any forwarded headers it sent are discarded.

The same rule decides what the origin sees. For trusted hops, Concert appends to the incoming `X-Forwarded-For` chain and keeps `X-Forwarded-Proto`, so your application gets real client IPs and knows the visitor used HTTPS. From untrusted peers, both are replaced.

The default trusts loopback only. That is safe even when Concert faces the internet directly, because internet connections never arrive from loopback. Add your load balancer's range if it runs on another host:

    -trusted-proxies "127.0.0.1/32,::1/128,10.0.0.0/8"

## Persistent settings and bans

Concert keeps two files in `-data-dir` (default `/var/lib/concert/data`), created with mode `0600`:

| File | Holds |
|---|---|
| `settings.json` | Settings changed in the admin portal or with `POST /_room/cap` |
| `bans.json` | Every ban, permanent bans, and offense history |

Each setting takes the first value it finds, in this order:

    settings.json  >  command-line flag  >  CONCERT_* environment variable  >  built-in default

`settings.json` only holds values an operator changed, so everything else keeps following your flags and `concert.env`. **Reset** in the portal removes a value from the file. Every change is validated by building a throwaway copy of Concert before it is written, so a saved file always starts. If you edit the file by hand and Concert refuses to start, the error names the file: fix it or delete it.

Page slots, queue depth, ticket TTL, pricing, the skip URL and VIP pass lifetime apply immediately. Every other setting is saved at once and takes effect on the next `systemctl restart concert`; the portal marks those as *pending restart*. Secrets (`CONCERT_ADMIN_TOKEN`, `CONCERT_ADMIT_SECRET`, `CONCERT_PORTAL_PASS`) and `-data-dir` itself are never stored in the file.

Bans are restored at startup. Administrator bans are written before the API answers; automatic bans within a second. Addresses added to `-abuse-allow` since a ban was made are not restored as banned. A corrupt `bans.json` stops startup rather than silently lifting permanent bans. Set `-data-dir ""` to keep everything in memory as before.

### Permanent bans

The portal's ban dialog has a **Permanent** switch, for single addresses and ranges alike. A permanently banned client gets `403 Forbidden` with `{"error":"blocked","permanent":true}`, or a short HTML notice in a browser, until someone unbans it.

### Bans drop waiting visitors

Any new ban, whether from the portal, a ban path or strikes, removes that address's or range's visitors from the line at once. Their next `/queue/status` poll returns `ready:true`, so the waiting room page reloads straight into the block notice, and their `room_ticket` is invalidated so an unban means rejoining at the back. room's internal `queue_depth` keeps counting the old ticket until the reaper removes it; `live_queue_depth` and the portal are accurate immediately.

## Assets

List the paths that hold your stylesheets, scripts, fonts and images in `-assets`:

    concert -upstream http://127.0.0.1:3000 \
            -assets "/wp-content/themes/*,/wp-content/plugins/*,/wp-includes/*" \
            -asset-public "/wp-content/uploads/*"

### The admission pass

Every page response that room admits carries `concert_admit`: an HttpOnly cookie holding a random ID, an expiry, a key identifier and an HMAC signature. Checking it costs one HMAC and no lookup, so any instance sharing `CONCERT_ADMIT_SECRET` accepts it.

The pass slides. It is re-signed once it is past half of `-admit-ttl`, on either a page load or an asset request. Visitors who keep browsing stay admitted, while most responses carry no `Set-Cookie` header and stay cacheable.

An asset request without a valid pass gets `403 Forbidden` immediately. It never waits and never reaches your origin.

A pass signed with a different key is treated as stale, not forged. After a restart or a secret rotation, returning visitors get 403 on assets until their next page load issues a fresh pass, but they never earn abuse strikes for it.

### Per-user concurrency: HTTP/1.1 and HTTP/2

Each pass gets its own semaphores, so one visitor can have at most a fixed number of asset requests in flight. Browsers behave very differently on each protocol, so there are two rules.

**HTTP/1.1** browsers open about 6 connections per host, so their natural concurrency is about 6. The default `-asset-user-cap-h1 8` leaves a little slack.

**HTTP/2 and HTTP/3** browsers send every request at once over one connection, up to the server's stream limit (nginx's `http2_max_concurrent_streams` defaults to 128). The default `-asset-user-cap-h2 128` matches that.

A request that finds its pool full waits up to `-asset-user-wait`, then gets `429 Too Many Requests` with `Retry-After: 1`. Each pass keeps a separate pool per protocol family, created on first use.

**Behind a TLS terminator, Concert can't see the client's protocol.** Browsers only speak HTTP/2 over TLS, and the terminator talks to Concert over HTTP/1.1 no matter what the browser used. Have the terminator pass the protocol in a header, and name that header with `-client-proto-header`:

    proxy_set_header X-Client-Proto $server_protocol;

    concert -client-proto-header X-Client-Proto ...

Values starting with `HTTP/1` use the HTTP/1.1 rule, and `HTTP/2` or `HTTP/3` use the HTTP/2 rule. Anything else falls back to the protocol of Concert's own connection. Only enable this when a terminator you control sets the header, since it overwrites whatever the client sent.

### Global asset concurrency

After its per-user check, every asset request takes a slot from one global semaphore. By default its size is `cap × asset-user-cap-h2`: with `-cap 1200` and `-asset-user-cap-h2 200`, the asset cap is 240,000. Set `-asset-cap` to override it with a number that reflects what your asset tier can actually serve. A request that can't get a global slot within `-asset-wait` gets `503 Service Unavailable` with `Retry-After: 1`.

The per-user check runs first, so a client over its own limit is rejected before it can take a global slot.

The asset cap is fixed at startup. `POST /_room/cap` changes only the page cap.

### Public assets

Some assets are fetched by things that never loaded a page first:

- link-preview crawlers from Slack, iMessage, Facebook and LinkedIn fetching your `og:image`
- email clients rendering newsletter images
- RSS readers
- other sites embedding your images

List those paths in `-asset-public`. They skip the pass check but still count against the global asset semaphore.

### Logging

The asset path writes no log lines; activity is counted in `/_room/stats`. Asset paths, `/queue/status` and `/_room/healthz` are also left out of the access log, and `-access-log=false` turns the access log off entirely.

## Abuse registry

Concert keeps a registry of clients that misbehave. Each abusive act adds weighted strikes to the client's address. When a client's strikes within `-abuse-window` reach `-abuse-strikes`, it is banned for a cooldown. While banned, every request from it gets:

    HTTP/1.1 429 Too Many Requests
    Retry-After: 300
    Content-Type: application/json; charset=utf-8
    Cache-Control: no-store

    {"error":"temporarily blocked","retry_after_seconds":300}

Enforcement happens before anything else: before the queue, the asset tier, the operations endpoints and the access log. It is a single map lookup, and banned requests are not logged.

### What earns strikes

| Behaviour | Strikes | Why it signals abuse |
|---|---|---|
| Admission pass with a bad signature | 5 | Browsers never alter the pass; someone is tampering with it |
| Wrong admin token | 5 | Someone is guessing `CONCERT_ADMIN_TOKEN` |
| Per-user asset pool exhausted | 1 | One pass is sending far more concurrent requests than a browser would |
| Queued without a `room_ticket` cookie | 1 | A script is discarding cookies to take fresh places in line |

With the defaults, 20 strikes within one minute trigger a ban. That is four forged passes, four wrong admin tokens, or twenty cookie-less queue arrivals.

These never earn strikes: missing passes (link-preview crawlers), expired or stale passes (idle visitors, restarts), and the global asset limit (not any one client's fault). Queued visitors who keep their `room_ticket` cookie never earn churn strikes, however long they wait.

### Ban paths

`-ban-paths` lists paths no legitimate visitor to your site ever requests. A client that requests one is banned immediately, without accumulating strikes. On a PHP site these are typically vulnerability scanners probing for secrets and admin tools:

    -ban-paths "/.env,/.git/*,/.aws/*,/.DS_Store,/phpmyadmin/*,/pma/*,/wp-config.php.bak,/server-status"

Only list paths your site genuinely never serves. Don't list `/wp-login.php` or `/xmlrpc.php` on WordPress: real users and plugins such as Jetpack use them. A path may not appear in both `-ban-paths` and any other path flag.

### Escalating cooldowns

The first ban lasts `-abuse-cooldown`. Each later ban of the same client doubles it, up to `-abuse-max-cooldown`: with the defaults, 5 minutes, then 10, 20, 40, and so on to 24 hours. A client whose last ban ended more than `-abuse-max-cooldown` ago, with no strikes since, is forgotten and starts from the beginning.

### Who is never banned

Addresses in `-abuse-allow` and in `-trusted-proxies` are never struck or banned. List your monitoring systems, your office, and your own address there, so an operator mistake can't lock you out of the admin endpoints. Trusted proxies are exempt because they only appear as the client when a request carries no forwarding headers, such as nginx's own health checks.

Think carefully about shared addresses. Behind carrier-grade NAT or a large office network, thousands of real people can share one IPv4 address, and their strikes add up together. If you expect heavy traffic from such networks, add their ranges to `-abuse-allow` or raise `-abuse-strikes`.

IPv6 clients are tracked by their `/64` prefix, because a single IPv6 host can rotate through billions of addresses in its own `/64`.

### Memory

At most `-abuse-max-entries` clients are tracked. When the table is full, a new client replaces an unbanned entry if one is available; otherwise its strikes are dropped and counted in `abuse_dropped_total`. Existing bans are never evicted to make room.

## Bypass paths

`-bypass` sends matching paths straight to the origin with no pass, no queue and no semaphore. Banned clients are still rejected. Use it only for traffic that has no admitted visitor behind it and can't tolerate a queue:

    -bypass "/favicon.ico,/robots.txt,/.well-known/acme-challenge/*,/webhooks/*"

That covers payment-provider webhooks, certificate renewal challenges and uptime checks. Bypassed paths are otherwise unprotected, so never bypass anything that runs expensive application code.

A path may appear in only one of `-bypass`, `-assets`, `-asset-public` and `-ban-paths`. Overlapping or conflicting entries are rejected at startup.

## API and non-browser clients

Browsers get the HTML waiting room. Any request whose `Accept` header does not include `text/html` gets a machine-readable response instead:

    HTTP/1.1 429 Too Many Requests
    Content-Type: application/json; charset=utf-8
    Retry-After: 5
    Set-Cookie: room_ticket=…; Path=/; HttpOnly; SameSite=Lax

    {"hint":"keep the room_ticket cookie and retry to hold your position","queued":true,"retry_after_seconds":5,"status_url":"/queue/status"}

A client that keeps cookies holds its place in line across retries:

    curl -c jar -b jar https://example.com/api/orders      # 429, ticket issued
    curl -c jar -b jar https://example.com/queue/status    # {"ready":false,"position":12,...}
    curl -c jar -b jar https://example.com/api/orders      # 200 once ready

A client that discards cookies takes a new ticket on every retry and earns a churn strike each time. With the defaults, twenty retries within a minute ban it.

When `-max-queue` is reached, new arrivals receive `503 Service Unavailable` with a JSON body and a `Retry-After` header.

Set `-api-json=false` to serve the HTML page to every client regardless of `Accept`.

## Operations endpoints

These are never queued, so they keep answering even when the room is full. Banned clients are rejected here too.

| Endpoint | Purpose |
|---|---|
| `GET /_room/healthz` | Liveness check; returns `ok` |
| `GET /_room/stats` | Page, asset and abuse counters |
| `POST /_room/cap` | Change page capacity at runtime (admin) |
| `GET /_room/abuse` | List banned clients (admin) |
| `DELETE /_room/abuse?client=…` | Unban a client and forget its history (admin) |

Admin endpoints require `Authorization: Bearer $CONCERT_ADMIN_TOKEN` and return 404 when the token is unset. Wrong tokens earn strikes.

Example stats output:

    {
      "abuse_bans_total": 7,
      "abuse_dropped_total": 0,
      "abuse_enabled": true,
      "abuse_rejected_total": 1893,
      "abuse_strikes_total": 164,
      "abuse_tracked": 41,
      "asset_cap": 64000,
      "asset_denied_total": 312,
      "asset_global_throttled_total": 0,
      "asset_in_flight": 214,
      "asset_served_total": 48211,
      "asset_user_cap_h1": 8,
      "asset_user_cap_h2": 128,
      "asset_user_throttled_total": 9,
      "asset_users": 1180,
      "cap": 500,
      "evicted_total": 3,
      "live_queue_depth": 118,
      "max_queue_depth": 10000,
      "occupancy": 500,
      "promoted_total": 0,
      "queue_depth": 121,
      "queued_total": 412,
      "timeouts_total": 0,
      "token_ttl": "5m0s",
      "upstream": "http://127.0.0.1:3000",
      "utilization": 0.98
    }

`live_queue_depth` counts only clients still holding a ticket, so it is the better number for dashboards than `queue_depth`, which briefly includes abandoned tickets. `asset_users` is the number of passes with an active per-user pool.

Listing and lifting bans:

    curl https://example.com/_room/abuse \
         -H "Authorization: Bearer $CONCERT_ADMIN_TOKEN"

    {"bans":[{"client":"203.0.113.9","until":"2026-09-21T18:04:11Z","remaining_seconds":243,"offenses":1}],"tracked":41}

    curl -X DELETE "https://example.com/_room/abuse?client=203.0.113.9" \
         -H "Authorization: Bearer $CONCERT_ADMIN_TOKEN"

IPv6 clients appear and are unbanned as their `/64`, for example `client=2001:db8:1:2::/64`.

Raising page capacity during an event:

    curl -X POST https://example.com/_room/cap \
         -H "Authorization: Bearer $CONCERT_ADMIN_TOKEN" \
         -H "Content-Type: application/json" \
         -d '{"cap": 80}'

Expose `/_room/*` only on a trusted network, or block it at your TLS terminator.

## Reserved paths

Concert answers these paths itself, and they never reach your origin:

    /queue/status
    /_room/healthz
    /_room/stats
    /_room/cap
    /_room/abuse

## Cookies

Concert removes all of these from requests before forwarding to the origin, so your application never sees them.

| Cookie | Purpose |
|---|---|
| `room_ticket` | HttpOnly. Identifies a queued visitor's place in line |
| `room_pass` | HttpOnly. VIP pass after paying to skip the line |
| `room_probe` | Readable by JavaScript. Lets the waiting room page detect whether cookies work; carries no secret |
| `concert_admit` | HttpOnly. Signed admission pass for the asset tier |

A browser that refuses cookies can't hold a place in line. Instead of reloading forever, the waiting room page detects this and tells the visitor that cookies are required.

The same message appears when cookies are misconfigured. The most common cause is setting `-secure-cookie` while browsers reach Concert over plain HTTP. A wrong `-cookie-domain` produces it too.

## Custom waiting room page

Replace the built-in page with `-html /path/to/waiting_room.html`. The file may use these placeholders:

| Placeholder | Replaced with |
|---|---|
| `{{.Position}}` | The visitor's queue position |
| `{{.SkipURL}}` | The skip-the-line URL, or an empty string |

Your page's JavaScript is responsible for the whole client side of the queue:

- Poll `GET /queue/status` every few seconds.
- Reload the page when the response contains `"ready": true`.
- Treat `"cookies_required": true` as final: stop polling and show an error.
- Check `document.cookie` for `room_probe` before the first poll. If it is missing, show the cookie error immediately rather than polling.
- Read `position`, and optionally `skip_cost`, `rate_per_pos` and `has_pass`, to update the display.

The waiting room page loads before the visitor has an admission pass. Any stylesheet, script or image it uses must come from a `-bypass` or `-asset-public` path, or be inlined.

## Production deployment

A typical layout keeps TLS at the edge and Concert on localhost:

    internet ──▶ nginx :443 (TLS) ──▶ concert 127.0.0.1:8080 ──▶ php-fpm site 127.0.0.1:3000

nginx:

    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }

    server {
        listen 443 ssl http2;
        server_name example.com;

        ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

        location / {
            proxy_pass         http://127.0.0.1:8080;
            proxy_http_version 1.1;
            proxy_set_header   Host $host;
            proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;
            proxy_set_header   X-Client-Proto $server_protocol;
            proxy_set_header   Upgrade $http_upgrade;
            proxy_set_header   Connection $connection_upgrade;
            proxy_buffering    off;
            proxy_read_timeout 3600s;
        }
    }

Put the `map` block in the `http` section. `X-Forwarded-For` is what lets Concert identify and ban individual clients; without it every request appears to come from nginx, which is exempt. Turning `proxy_buffering` off lets streamed responses reach clients immediately.

systemd unit (`/etc/systemd/system/concert.service`):

    [Unit]
    Description=Concert waiting room proxy
    After=network-online.target
    Wants=network-online.target

    [Service]
    ExecStart=/usr/local/bin/concert
    Environment=CONCERT_LISTEN=127.0.0.1:8080
    Environment=CONCERT_UPSTREAM=http://127.0.0.1:3000
    Environment=CONCERT_CAPACITY=50
    Environment=CONCERT_SECURE_COOKIE=true
    Environment=CONCERT_CLIENT_PROTO_HEADER=X-Client-Proto
    Environment=CONCERT_ASSETS=/wp-content/themes/*,/wp-content/plugins/*,/wp-includes/*
    Environment=CONCERT_ASSET_PUBLIC=/wp-content/uploads/*
    Environment=CONCERT_BYPASS=/favicon.ico,/robots.txt,/.well-known/acme-challenge/*
    Environment=CONCERT_BAN_PATHS=/.env,/.git/*,/.aws/*,/phpmyadmin/*,/wp-config.php.bak
    Environment=CONCERT_ABUSE_ALLOW=198.51.100.10
    Environment=CONCERT_ACCESS_LOG=false
    EnvironmentFile=/etc/concert/secrets.env
    Restart=on-failure
    DynamicUser=yes
    NoNewPrivileges=yes

    [Install]
    WantedBy=multi-user.target

`/etc/concert/secrets.env`, mode `0600`:

    CONCERT_ADMIT_SECRET=…
    CONCERT_ADMIN_TOKEN=…

On `SIGTERM` Concert stops accepting new connections and gives in-flight requests up to 30 seconds to finish.

## Limitations

**One instance, one queue, one registry.** Queue state, asset semaphores and the abuse registry live in the process's memory. Two Concert instances are two independent waiting rooms: the origin sees up to twice `-cap`, a visitor's place in line exists only on the instance that issued their ticket, and a client banned on one instance is not banned on the other. If you must run more than one, divide `-cap` by the number of instances and enable sticky sessions at the load balancer. Use a cookie the load balancer inserts itself, because `room_ticket` is only issued once a visitor is queued. Admission passes work across instances as long as they share `CONCERT_ADMIT_SECRET`.

**A pass limits concurrency, not request rate.** A pass holder can have at most its per-user cap of asset requests in flight, but fast assets finish quickly, so a single pass can still generate many requests per second. The global semaphore bounds the total load on the host regardless. Volumetric attacks from many addresses belong at a CDN or WAF in front of Concert; the abuse registry handles individual misbehaving clients.

**Long-lived connections hold slots.** WebSockets and server-sent event streams keep their page slot until they close. With `-cap 50` and 50 open sockets, nobody else gets in. Run a separate Concert instance for long-lived paths.

**Skip the line is not wired end to end.** `-rate`, `-surge`, `-skip-url`, and `-pass` enable the pricing card on the waiting room page. But promoting a paid visitor requires calling room's in-process API after payment, and Concert does not yet expose an endpoint your payment flow can call. Leave `-rate` at `0` in production for now.

## Development

    make all                    # vet, clean, test, race tests, benchmarks, cross-platform build
    make build                  # binaries for linux, darwin, windows × amd64, arm64 in bin/
    go test -race -count=1 ./...

The test suite runs the real waiting room, asset tier and abuse registry against a fake origin. It covers:

- configuration precedence and validation
- client address resolution through trusted and untrusted proxies
- admission pass signing, tampering, staleness, expiry and refresh
- per-user HTTP/1.1 and HTTP/2 limits, and the global asset limit
- every strike source, ban paths, escalating cooldowns, allowlists, IPv6 /64 grouping, and the admin ban endpoints
- queueing for browsers and API clients, the queue-depth breaker, and cookie-jar resume
- bypass routing, streaming, and forwarded-header handling
- graceful shutdown

## License

Copyright 2026 Andrei Merlescu

Licensed under the Apache License, Version 2.0. You may not use this project except in compliance with the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
