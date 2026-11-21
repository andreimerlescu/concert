# Edge and leaf tiers

One Concert in front of one application is a **standalone** node, and nothing in this document changes it. When one public site is served by several application hosts, the same binary runs as two tiers:

```
                    x402 agents   browsers
                           \       /
  www.mysite.com ──▶  edge Concert  (waiting room, fast lane, passes, bans: the source of truth)
                           │
                 (haproxy, optional)
                    ┌──────┴──────┐
  i-01.mysite.com ─▶ leaf Concert   leaf Concert ◀─ i-02.mysite.com
                    │               │
                   app (32 GB)     app (128 GB)
```

- The **edge** owns everything a browser sees: the waiting room, the fast lane (x402 and NFT access), admission passes, priority grants and the ban list. It forwards admitted requests to the leaves, balancing across them itself or through a load balancer.
- A **leaf** protects one host. Requests the edge admitted pass straight through it in their own lane. Requests that reach it directly (the public typing `i-01.mysite.com`) get a full, ordinary Concert: its own waiting room, its own passes and, if configured, its own fast lane.
- The red dotted arrows in the design are the **control plane**. Every `-hop-poll` the edge reads each leaf's capacity and state, sizes its own room from them, and pushes its ban list to every leaf.

## The trust chain

When the edge forwards a request it admitted, it adds one header:

```
Concert-Hop: v=1;e=www;t=1795000000123;c=203.0.113.9;r=5;f=1;k=page;p=h2;s=<HMAC-SHA256>
```

| Field | Meaning |
|---|---|
| `e` | the edge's node ID (`-node-id`) |
| `t` | when it was signed, Unix milliseconds |
| `c` | the client address the edge resolved, after its own `-trusted-proxies` |
| `r` | the visitor's Concert-Priority rank at the edge, 0 guest to 6 staff |
| `f` | 1 when the edge's fast lane found the visitor eligible (paid or NFT) |
| `k` | which tier admitted it: `page`, `asset`, `stream` or `bypass` |
| `p` | the client's protocol family at the edge, `h1` or `h2` |
| `s` | HMAC-SHA256 over every field above plus the request's **method and URI** |

The key is derived from `CONCERT_HOP_SECRET` (at least 32 bytes, the same on every edge and leaf). During a rotation set the new value in `CONCERT_HOP_SECRET` and the old one in `CONCERT_HOP_SECRET_PREV` on the leaves first, then change the edges, then remove `_PREV`.

A leaf accepts a claim only when **all** of these hold:

1. the connection comes from `-hop-peers`: the edges, or the load balancer between the tiers;
2. the signature verifies for this request's method and exact URI;
3. the timestamp is within `-hop-max-skew` (default 30s) of the leaf's clock.

Verifying costs about 1.3 µs. A claim from outside `-hop-peers` is ignored and earns the presenting client a forged-pass strike. A bad signature, a skewed clock or a claim for another URI is ignored and counted in `hop_rejected_total`. In every case the request is then served as direct traffic, so a broken trust chain degrades to ordinary Concert, never to an open door.

The claim does **not** cover the body or the `Host` header (a load balancer may rewrite Host; bodies are streamed). A captured header can be replayed for the same method and URI until it leaves the skew window. Keep the link between tiers on a private network or use TLS with the upstream mTLS settings (`-upstream-ca`, `-upstream-client-cert`, `-upstream-client-key`).

Every node removes `Concert-Hop` from what it receives before anything else runs, so a client can never send one through an edge, and the application never sees it.

## What a leaf does with a verified claim

| Class | Leaf work | When full |
|---|---|---|
| `page` | a slot in the **host gate**, waiting up to `-hop-wait` (default 2s) | `503` with `Concert-Backpressure: full` |
| `asset` | a slot in the leaf's global asset pool, up to `-asset-wait` | `503` with backpressure |
| `stream` | a slot under `-stream-cap` | `503` with backpressure |
| `bypass` | nothing | — |

It skips its waiting room, admission pass, priority gate, agent gate and per-visitor asset pools: the edge already did all of that. It still enforces bans. It sets **no cookies** on these responses, and it leaves the application's `Concert-Priority` header in place, so the edge turns it into the visitor's grant, bound to the edge's pass. The application receives `X-Forwarded-For` starting with the client from the claim.

### The host gate

The host gate is the leaf's hard ceiling on page requests reaching its application, from every source:

1. `HopPriority`: edge traffic ranked at or above `-priority-lane-rank` (customer by default) or paid at the edge;
2. `Hop`: other edge traffic;
3. `Direct`: the leaf's own room and lane traffic.

A freed slot goes to the longest-waiting request of the highest class. Direct traffic gets whatever the edge's traffic leaves, waits in the leaf's own room (with its waiting page) when there is nothing left, and is never refused by the gate before `-upstream-timeout`.

The ceiling (`host_cap`) comes from the first of:

1. `-host-cap`;
2. `capacity.json` in `-data-dir`, written by the benchmark ([below](#measuring-capacity));
3. `-cap`.

## What the edge does

**Signing.** Every forwarded request is signed again for each attempt, so a retry to another leaf carries a claim for that leaf's URL.

**Cookies.** The edge removes every Concert cookie a leaf tries to set and the tier headers, so the browser only ever holds the edge's cookies.

**Retries.** With several upstreams, a request **without a body** is sent to another upstream (`-upstream-retries`, default 1) when the first refused the connection or answered with a leaf's backpressure `503`. In both cases nothing reached the application. Requests with a body are never retried. A leaf that pushed back is avoided for one second while another has room. Backpressure is not a circuit-breaker failure.

**Routing.** When the edge balances across leaves itself and every healthy leaf reports its share, it sends each request to the leaf with the most free slots (`share − in flight`). Otherwise it uses fewest in flight.

**Capacity.** With `-hop-auto-cap` (the default for an edge), the edge's room capacity becomes:

```
min(-cap, Σ healthy leaves' share − edge priority lane)
```

so the leaves never see more than they can serve, even counting the edge's priority lane. A leaf's **share** is its `host_cap` divided by the number of edges it has heard from in the last minute, so two edges sharing the leaves don't each plan on all of it.

- A drop applies at the next round. A rise applies only after two rounds agree, so a flapping leaf cannot thrash the room.
- A leaf whose reports stop fades out linearly between 3 and 15 polls (6s to 30s at the default `-hop-poll 2s`), so a brief control-link drop does not collapse capacity, and a dead leaf stops counting within 30s.
- Draining or unhealthy leaves (all of their upstreams unhealthy, or their application silent) stop counting at once.
- Until a leaf has reported, the edge admits one request at a time, and `/_room/readyz` answers 503 `no usable leaf`. **Start the leaves first.**
- The room's capacity is never set below what it has in flight. `room`'s semaphore loses its in-flight accounting when shrunk below current use, so the edge steps down as requests finish instead.

## Bans: the edge is the source of truth

Every round the edge compares its ban list's version with what each leaf reports having applied, and sends the full list to any leaf that differs. A new ban triggers a round at once. The leaf:

- applies every listed ban (single clients, IPv6 /64s, ranges, permanent bans) not already in force for at least as long;
- lifts every ban the same edge listed before and no longer lists, unless the leaf has since banned that client itself for a different time;
- skips its own `-abuse-allow` and `-trusted-proxies`;
- ignores a snapshot older than the last one it applied from that edge, so a delayed push cannot undo a newer one;
- persists everything in its own `bans.json`.

So a bot banned on `www.mysite.com` is already banned when it moves to `i-01.mysite.com`. Bans a leaf makes itself, from direct traffic, stay local to that leaf. The Redis cluster sync (`-redis-addr`) still works alongside this for peers of the same tier.

## The fast lane in two tiers

The edge runs wallet access (x402 payments, NFT proofs, the policy screen and the settlement journal) for everything that enters through it. A paid visitor's claim carries `f=1`, and the leaf serves it in `HopPriority` without seeing the payment.

A leaf may also run its own fast lane for its direct traffic, with its own `fastlane.json`, its own `-data-dir` and its own settlement journal. Two cautions:

- Each journal is single-writer and independent. A payment made on `i-01` creates eligibility only on `i-01`.
- Concert's replay protection is per journal. If the edge and the leaves advertise the **same** `payTo` address, a signed authorization settled at one cannot be refused as a duplicate by another's journal. The chain rejects re-submission of the same transaction, but give each tier its own receiving address, or keep wallet access on the edge only.

## Measuring capacity

Maximum connections alone are not capacity: a 128 GB host that runs work the 32 GB host offloads to it may serve fewer visitors, not more. Concert measures each host instead.

```sh
bench-concert -target http://127.0.0.1:3000/ -data-dir /var/lib/concert/data
# or
concert bench -target http://127.0.0.1:3000/ -data-dir /var/lib/concert/data
```

Point it at the **application**, not at Concert. Each lemming is one browser session with its own cookie jar and asset cache. It starts at the root, loads the page and what it references (stylesheets and the fonts and images they load, scripts, images, audio, video, downloads), follows a random link to a page that has not yet had `-page-hits` (14) visits this stage, and repeats up to `-depth` (14) links deep before starting over. Pages with nothing new send it to another open page, so the whole site is walked.

The run doubles the number of lemmings from `-start` until a stage fails, then bisects. A stage fails when:

- the page p95 exceeds `-p95` (2s), or
- any request fails for load: timeouts, refused or reset connections, truncated bodies, 5xx and 429.

Broken links and media served without byte ranges are reported as findings, not failures. The result is the largest passing number of lemmings. `capacity.json` gets `host_cap = lemmings × -safety (0.9)`.

The report (`-out`) explains the first failing stage:

- the failures by kind;
- a second-by-second timeline showing when trouble began and whether latency climbed first;
- the slowest and most-failing URLs;
- a breakdown by file type (html, image, script, style, font, audio, video, archive, document, text, data), including whether audio and video honoured byte ranges.

A leaf started with `-bench-on-start` and no `capacity.json` runs the benchmark against its upstream **before it starts listening**, so the benchmark is the only load the application sees. It then saves `capacity.json` and `bench-report.json` and serves with the result. It is off by default: it loads the application hard on purpose. Delete `capacity.json` to measure again. `-bench-p95` and `-bench-max-lemmings` tune it.

## When the application goes silent

A leaf samples its upstream every second. If every upstream is unhealthy, or three or more requests failed with none succeeding, the leaf records a **silence report**:

- the host slots in use by edge and direct traffic, and the queue;
- the requests in flight to the application;
- the recent mean latency;
- the upstream error counters;
- the last healthy moment.

It logs the report, appends it to `silence.jsonl` in `-data-dir`, returns it in its state (and so in the edge's `/_room/stats`), and stops counting toward the edge's capacity until the application answers again. On bare metal this separates "the host fell over carrying 40 requests" from "the host failed with nothing running".

## Configuration

| Flag | Environment | Default | Description |
|---|---|---|---|
| `-role` | `CONCERT_ROLE` | `standalone` | `standalone`, `edge` or `leaf` (restart to change) |
| `-node-id` | `CONCERT_NODE_ID` | from the hostname | ID in claims and reports, 1-32 of `[A-Za-z0-9._-]` |
| `-hop-peers` | `CONCERT_HOP_PEERS` | *(empty)* | Leaf: CIDRs that may present claims. **Required** for a leaf |
| `-hop-max-skew` | `CONCERT_HOP_MAX_SKEW` | `30s` | Leaf: clock skew a claim may carry, 1s-5m |
| `-hop-wait` | `CONCERT_HOP_WAIT` | `2s` | Leaf: how long an edge page request waits for a host slot |
| `-host-cap` | `CONCERT_HOST_CAP` | `0` | Leaf: host ceiling; 0 means `capacity.json`, then `-cap` |
| `-hop-leaves` | `CONCERT_HOP_LEAVES` | *(empty)* | Edge: leaf base URLs for the control plane; empty means the `-upstream` targets |
| `-hop-poll` | `CONCERT_HOP_POLL` | `2s` | Edge: control round interval, 500ms-1m |
| `-hop-auto-cap` | `CONCERT_HOP_AUTO_CAP` | `true` | Edge: size the room from the leaves, never above `-cap` |
| `-upstream-retries` | `CONCERT_UPSTREAM_RETRIES` | `1` | Retries of bodyless requests on another upstream, 0-5 |
| `-bench-on-start` | `CONCERT_BENCH_ON_START` | `false` | Leaf: benchmark the upstream before serving when `capacity.json` is missing |
| `-bench-p95` | `CONCERT_BENCH_P95` | `2s` | p95 limit for the startup benchmark |
| `-bench-max-lemmings` | `CONCERT_BENCH_MAX_LEMMINGS` | `1024` | Most lemmings the startup benchmark tries |
| | `CONCERT_HOP_SECRET` | *(none)* | Trust-chain secret, at least 32 bytes; required for edge and leaf |
| | `CONCERT_HOP_SECRET_PREV` | *(none)* | Previous secret, accepted by leaves during a rotation |

### Example: the edge balances across the leaves (no haproxy)

`www` (edge), `/etc/concert/concert.env`:

```sh
CONCERT_ROLE=edge
CONCERT_NODE_ID=www
CONCERT_UPSTREAM=https://10.0.1.11:8443,https://10.0.1.12:8443
CONCERT_UPSTREAM_CA=/etc/concert/tier-ca.pem
CONCERT_UPSTREAM_CLIENT_CERT=/etc/concert/www.pem
CONCERT_UPSTREAM_CLIENT_KEY=/etc/concert/www-key.pem
CONCERT_UPSTREAM_HEALTH_PATH=/_room/readyz
CONCERT_CAPACITY=2000            # never admit more than this, whatever the leaves offer
CONCERT_PRIORITY_CAP=50
CONCERT_FASTLANE_CONFIG=/etc/concert/fastlane.json
CONCERT_NETWORKS_CONFIG=/etc/concert/networks.json
CONCERT_ASSETS=/static/*,/media/*,/downloads/*
CONCERT_HOP_SECRET=…             # same on every node
CONCERT_ADMIT_SECRET=…
```

`i-01` (leaf, 32 GB). `i-02` is the same with its own ID and data:

```sh
CONCERT_ROLE=leaf
CONCERT_NODE_ID=i-01
CONCERT_LISTEN=:8443
CONCERT_TLS_CERT=/etc/concert/i-01.pem
CONCERT_TLS_KEY=/etc/concert/i-01-key.pem
CONCERT_UPSTREAM=http://127.0.0.1:3000
CONCERT_HOP_PEERS=10.0.1.10/32   # the edge
CONCERT_TRUSTED_PROXIES=127.0.0.1/32,::1/128
CONCERT_BENCH_ON_START=true      # measure the app on first start
CONCERT_ASSETS=/static/*,/media/*,/downloads/*
CONCERT_HOP_SECRET=…
CONCERT_ADMIT_SECRET=…           # its own; i-01's passes are its own
```

Requests for `i-01.mysite.com` reach this leaf directly and are served as an ordinary Concert, with its own waiting room. In this layout the leaf terminates TLS for the edge and for the public alike. The edge verifies the leaf's certificate (`-upstream-ca`) and presents its own; Concert's listener does not itself require client certificates, so the trust chain rests on `CONCERT_HOP_SECRET` and `-hop-peers`. If the link must also be mutually authenticated, terminate it in front of the leaf with a proxy that requires client certificates, and list that proxy in `-hop-peers`.

### Example: haproxy between the tiers

The edge forwards to haproxy and polls the leaves directly:

```sh
CONCERT_UPSTREAM=http://10.0.1.5:8080            # haproxy
CONCERT_HOP_LEAVES=https://10.0.1.11:8443,https://10.0.1.12:8443
```

The leaves trust haproxy's address as the peer that presents claims:

```sh
CONCERT_HOP_PEERS=10.0.1.5/32
```

```
backend leaves
  balance leastconn
  option httpchk GET /_room/readyz
  option forwardfor
  # Concert keeps visitor state at the edge: no stickiness needed.
  server i-01 10.0.1.11:8443 ssl verify required ca-file /etc/haproxy/tier-ca.pem check
  server i-02 10.0.1.12:8443 ssl verify required ca-file /etc/haproxy/tier-ca.pem check
  retries 1
  option redispatch
  retry-on conn-failure empty-response
```

With haproxy in between, the edge sees one upstream, so a leaf's backpressure `503` reaches the browser instead of being retried on the other leaf: haproxy cannot tell a leaf's capacity refusal from the application's own 503 (retrying that could submit a form twice). The edge's capacity planning still keeps that rare. Removing haproxy and letting the edge balance gives you backpressure-aware retries and slot-aware routing.

## Observability

`/_room/stats` adds `role` and `node`, and:

- on an edge, `edge`: usable leaves, leaf slots, planned cap, retries, backpressure, poll and push errors, and each leaf's state;
- on a leaf, `leaf`: host cap and its source, hop and direct in flight and waiting, accepted, rejected and backpressured claims, edges seen, application health, and the last silence report.

`/_room/metrics` adds `concert_node_info`, the `concert_edge_*` and `concert_leaf_*` series.

## Limitations

- **One edge is a single point of failure.** Several edges can share leaves (shares divide by edges seen), but each edge has its own waiting room and its own settlement journal. Run one active edge with a standby, as for standalone Concert.
- **Shares across several edges are approximate.** They divide evenly by the number of edges seen, not by each edge's traffic.
- **Replay inside the skew window.** See [The trust chain](#the-trust-chain).
- **A leaf's own room capacity is static.** Its direct traffic is shaped by the host gate, not by resizing its room.
- **The startup benchmark measures the application as it is at that moment.** Re-run it after hardware or application changes.
