# Concert

[![Go Reference](https://pkg.go.dev/badge/github.com/andreimerlescu/concert.svg)](https://pkg.go.dev/github.com/andreimerlescu/concert)
[![Go Report Card](https://goreportcard.com/badge/github.com/andreimerlescu/concert)](https://goreportcard.com/report/github.com/andreimerlescu/concert)
[![Latest Release](https://img.shields.io/github/v/release/andreimerlescu/concert?sort=semver)](https://github.com/andreimerlescu/concert/releases/latest)
[![Go Version](https://img.shields.io/github/go-mod/go-version/andreimerlescu/concert)](https://github.com/andreimerlescu/concert/blob/main/go.mod)
[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/andreimerlescu/concert/blob/main/LICENSE)
[![Built on room](https://img.shields.io/badge/built%20on-room-00d4ff)](https://github.com/andreimerlescu/room)
[![GitHub Stars](https://img.shields.io/github/stars/andreimerlescu/concert?style=social)](https://github.com/andreimerlescu/concert/stargazers)

![Concert — FIFO Waiting Room Reverse Proxy](/concert.jpg)

A FIFO waiting room reverse proxy. Put Concert in front of any HTTP origin, such as a PHP site, a WordPress install, or a legacy app that falls over under load. When traffic exceeds what the origin can handle, visitors wait in an orderly queue with a live position instead of getting 502s and timeouts.

Concert is a single Go binary built on [room](https://github.com/andreimerlescu/room), a FIFO waiting room middleware for Gin.

## Why

A PHP-FPM pool has a fixed number of workers (`pm.max_children`). When every worker is busy, new requests pile up in the web server's backlog until they time out. Users see 502 or 504 errors, hit refresh, and make the spike worse.

Concert caps the number of concurrent requests that reach your origin. Everyone past that cap is shown a waiting room page with their queue position, and they are admitted automatically, in arrival order, as slots free up. Your origin only ever sees the load you chose.

## How it works

    browser ──▶ TLS terminator ──▶ concert :8080 ──▶ origin :3000
                (nginx, Caddy,        │
                 load balancer)       ├─ slot free?  yes ──▶ proxied to origin
                                      │
                                      └─ no ──▶ waiting room page
                                                polls /queue/status every ~3s
                                                reloads when admitted

Every request that is not on a bypass path gets a ticket. A request whose ticket falls inside the serving window acquires a slot, is proxied to the origin, and releases its slot when the response has been fully delivered. Any other request gets a `room_ticket` cookie and the waiting room page. The page polls `/queue/status` and reloads once the ticket's turn arrives.

`-cap` is therefore the maximum number of requests in flight to your origin at any moment.

## Install

    go install github.com/andreimerlescu/concert@latest

Or build from source:

    git clone https://github.com/andreimerlescu/concert.git
    cd concert
    go build -o concert .

Requires Go 1.22 or newer.

## Quick start

Start something to protect. PHP's built-in server is enough for a demo:

    php -S 127.0.0.1:3000 -t /var/www/html

Put Concert in front of it with a deliberately small capacity:

    concert -upstream http://127.0.0.1:3000 -cap 5

Open `http://127.0.0.1:8080/` in a browser, then generate load from another terminal:

    ab -c 100 -n 2000 http://127.0.0.1:8080/

Refresh the browser while the load test runs and you'll land in the waiting room, then be admitted automatically as slots open.

## Configuration

Every option can be set with a flag or an environment variable. A flag overrides its environment variable, and the environment variable overrides the built-in default.

| Flag | Environment | Default | Description |
|---|---|---|---|
| `-listen` | `CONCERT_LISTEN` | `:8080` | Address to listen on |
| `-upstream` | `CONCERT_UPSTREAM` | `http://127.0.0.1:3000` | Origin to proxy to (`http` or `https`) |
| `-cap` | `CONCERT_CAPACITY` | `500` | Max concurrent requests allowed through to the origin |
| `-max-queue` | `CONCERT_MAX_QUEUE` | `10000` | Reject new arrivals with 503 beyond this queue depth (0 = unlimited) |
| `-reaper` | `CONCERT_REAPER` | `30s` | How often abandoned tickets are cleaned up |
| `-token-ttl` | `CONCERT_TOKEN_TTL` | `0` (room default, 5m) | Sliding lifetime of a queued ticket, 30s–24h |
| `-secure-cookie` | `CONCERT_SECURE_COOKIE` | `false` | Mark room cookies `Secure` (only if browsers reach you over HTTPS) |
| `-cookie-path` | `CONCERT_COOKIE_PATH` | `/` | Path attribute of room cookies |
| `-cookie-domain` | `CONCERT_COOKIE_DOMAIN` | *(empty)* | Domain attribute of room cookies |
| `-preserve-host` | `CONCERT_PRESERVE_HOST` | `true` | Forward the client's `Host` header to the origin |
| `-bypass` | `CONCERT_BYPASS` | `/favicon.ico` | Comma-separated paths that skip the queue; suffix `/*` for a prefix |
| `-html` | `CONCERT_HTML_FILE` | *(empty)* | Custom waiting room HTML file |
| `-skip-url` | `CONCERT_SKIP_URL` | *(empty)* | Payment page URL for the skip-the-line card (see limitations) |
| `-rate` | `CONCERT_RATE` | `0` | Base price per queue position (0 disables skip-the-line) |
| `-surge` | `CONCERT_SURGE` | `0` | Extra price per position for each client in the queue |
| `-pass` | `CONCERT_PASS_DURATION` | `0` | VIP pass lifetime after paying to skip (0 disables passes) |
| `-upstream-timeout` | `CONCERT_UPSTREAM_TIMEOUT` | `30s` | How long to wait for the origin's response headers |
| `-api-json` | `CONCERT_API_JSON` | `true` | Answer queued non-browser clients with JSON 429 instead of HTML |
| `-retry-after` | `CONCERT_RETRY_AFTER` | `5` | `Retry-After` seconds sent to queued API clients |
| `-version` | | | Print the version and exit |
| | `CONCERT_ADMIN_TOKEN` | *(empty)* | Bearer token for `POST /_room/cap`; the endpoint is disabled when unset |

The admin token is environment-only on purpose: command-line arguments are visible in `ps` output and shell history.

## Choosing a capacity

`-cap` counts concurrent requests, not users. A slot is held from the moment a request is admitted until the last byte of the origin's response has been sent to the client.

For a PHP-FPM origin, start with `-cap` at or slightly below the pool's `pm.max_children`. Concert then admits only as many requests as there are workers to run them, and the backlog lives in Concert's queue, where users can see their position, instead of in a socket buffer where they can't.

Throughput follows from Little's law: requests admitted per second ≈ `cap` ÷ average time a slot is held. With `-cap 50` and a 200 ms average response, Concert admits about 250 requests per second. If the origin slows down under load, admissions slow down with it, which is exactly the protection you want.

Capacity can be changed at runtime without a restart; see `POST /_room/cap` below.

## Static assets and bypass paths

A page load is not one request. The browser fetches the HTML, then every stylesheet, script, font, and image, each of which gets its own ticket and uses a slot.

Only the top-level page can run the waiting room's JavaScript. A queued image or stylesheet has no way to poll and reload; it simply fails, leaving an admitted visitor with a broken page. Send assets around the queue:

    concert -upstream http://127.0.0.1:3000 \
            -bypass "/wp-content/*,/wp-includes/*,/assets/*,/favicon.ico,/robots.txt"

`/prefix/*` bypasses everything under a prefix; a path without `/*` bypasses that exact path. Bypassed requests are completely unprotected, so only bypass paths that are cheap for your origin to serve, ideally static files or anything behind a CDN.

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

When `-max-queue` is reached, new arrivals receive `503 Service Unavailable` with a JSON body and a `Retry-After` header.

A client that does not keep cookies gets a new ticket on every retry. Each unused ticket expires after `-token-ttl`, so lower it toward `30s` if much of your gated traffic is scripts.

Set `-api-json=false` to serve the HTML page to every client regardless of `Accept`.

## Operations endpoints

These are never queued, so they keep answering even when the room is full.

| Endpoint | Purpose |
|---|---|
| `GET /_room/healthz` | Liveness check; returns `ok` |
| `GET /_room/stats` | Current capacity, occupancy, queue depth, and event counters |
| `POST /_room/cap` | Change capacity at runtime (requires `CONCERT_ADMIN_TOKEN`) |

Example stats output:

    {
      "cap": 50,
      "evicted_total": 3,
      "live_queue_depth": 118,
      "max_queue_depth": 10000,
      "occupancy": 50,
      "promoted_total": 0,
      "queue_depth": 121,
      "queued_total": 412,
      "timeouts_total": 0,
      "token_ttl": "5m0s",
      "upstream": "http://127.0.0.1:3000",
      "utilization": 0.98
    }

`queue_depth` is derived from the ticket counter and briefly includes tickets whose holders have left. `live_queue_depth` counts only clients still holding a ticket, so it is the better number for dashboards.

Raising capacity during an event:

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

If your origin serves any of these paths, Concert will shadow them.

## Cookies

Concert, through room, sets up to three cookies. It removes all of them from requests before forwarding to the origin, so your application never sees them.

| Cookie | Purpose |
|---|---|
| `room_ticket` | HttpOnly. Identifies a queued visitor's place in line |
| `room_pass` | HttpOnly. VIP pass after paying to skip the line |
| `room_probe` | Readable by JavaScript. Lets the waiting room page detect whether cookies work; carries no secret |

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

A page that ignores `cookies_required` won't loop any more, but it will poll silently forever.

## Production deployment

A typical layout keeps TLS at the edge and Concert on localhost:

    internet ──▶ nginx :443 (TLS) ──▶ concert 127.0.0.1:8080 ──▶ php-fpm site 127.0.0.1:3000

nginx:

    server {
        listen 443 ssl http2;
        server_name example.com;

        ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

        location / {
            proxy_pass         http://127.0.0.1:8080;
            proxy_http_version 1.1;
            proxy_set_header   Host $host;
            proxy_set_header   Upgrade $http_upgrade;
            proxy_set_header   Connection $connection_upgrade;
            proxy_buffering    off;
            proxy_read_timeout 3600s;
        }
    }

The `$connection_upgrade` variable needs the standard `map $http_upgrade $connection_upgrade { default upgrade; '' close; }` block in the `http` section. Turning `proxy_buffering` off lets streamed responses reach clients immediately.

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
    Environment=CONCERT_BYPASS=/wp-content/*,/wp-includes/*,/favicon.ico,/robots.txt
    EnvironmentFile=-/etc/concert/secrets.env
    Restart=on-failure
    DynamicUser=yes
    NoNewPrivileges=yes

    [Install]
    WantedBy=multi-user.target

Put `CONCERT_ADMIN_TOKEN=…` in `/etc/concert/secrets.env` with mode `0600`.

On `SIGTERM` Concert stops accepting new connections and gives in-flight requests up to 30 seconds to finish.

## Limitations

**One instance, one queue.** All queue state lives in the process's memory. Two Concert instances are two independent waiting rooms: the origin sees up to twice `-cap`, and a visitor's place in line exists only on the instance that issued their ticket. If you must run more than one, divide `-cap` by the number of instances and enable sticky sessions at the load balancer. Use a cookie the load balancer inserts itself, because `room_ticket` is only issued once a visitor is queued.

**Long-lived connections hold slots.** WebSockets and server-sent event streams keep their slot until they close. With `-cap 50` and 50 open sockets, nobody else gets in. Run a separate Concert instance for long-lived paths, or bypass them if the origin limits them itself.

**Client address headers.** Concert sets `X-Forwarded-For` to the address its own connection came from, and `X-Forwarded-Proto` to the scheme Concert itself received. Behind a TLS terminator, the origin therefore sees the terminator's address as the client and `http` as the scheme. Applications that log client IPs, rate-limit by IP, or build absolute URLs from the forwarded scheme (WordPress's HTTPS detection, for example) need to account for this.

**Skip the line is not wired end to end.** `-rate`, `-surge`, `-skip-url`, and `-pass` enable the pricing card on the waiting room page. But promoting a paid visitor requires calling room's in-process API after payment, and Concert does not yet expose an endpoint your payment flow can call. Leave `-rate` at `0` in production for now.

## Development

    make all                    # vet, test, race tests, benchmarks
    go test -race -count=1 ./...

The test suite runs the real waiting room against a fake origin. It covers configuration precedence, proxy header handling, cookie stripping, queueing for browsers and API clients, the queue-depth breaker, cookie-jar resume, bypass routing, streaming, the operations endpoints, and graceful shutdown.

## License

Copyright 2026 Andrei Merlescu

Licensed under the Apache License, Version 2.0. You may not use this project except in compliance with the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
