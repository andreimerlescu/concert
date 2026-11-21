# Handoff: Concert after v0.2.0

This file briefs the next agent working on Concert in Antigravity. Read it fully before changing anything. It says what v0.2.0 did, what is left, in what order, and the standard of work expected. When this file and the code disagree, the code and its tests are the truth. Say so in your report.

## 1. Where things stand

v0.2.0 makes Concert work as **two tiers**: an edge Concert (waiting room, fast lane, cookies, bans) in front of a leaf Concert per application host, with or without haproxy between them. It also adds a **capacity benchmark**. The design, every setting and the limitations are in [docs/TOPOLOGY.md](docs/TOPOLOGY.md), and the change list is in [docs/CHANGES.md](docs/CHANGES.md).

| Path | What it is |
|---|---|
| `version.go` (root package `concert`) | embeds `VERSION`; **the only Go file allowed at the root** |
| `cmd/concert` | the server binary; a one-line wrapper around `server.Main` |
| `cmd/bench-concert` | the benchmark binary; a wrapper around `bench.CLI` |
| `cmd/concert-client` | unchanged reference x402 client |
| `internal/server` | **everything that was the root `package main`** (≈24k lines), plus the tier wiring: `topology.go`, `hop_control.go`, `silence.go` |
| `internal/hop` | the trust chain: `Concert-Hop` claims, signing, verification, control-plane types |
| `internal/capacity` | the leaf's host `Gate`, the edge's `Planner`, `capacity.json` |
| `internal/bench` | lemmings: crawl, ramp and bisect, failure classification, report, CLI |
| `internal/testsite` | a deterministic fake shop with every e-commerce file type, for tests |
| `internal/fastlane`, `internal/gateway`, `internal/chain/*`, `internal/x402` | unchanged |

### The Go toolchain

`go.mod` already declares `go 1.27.3`, as it did before v0.2.0 (room v1.5.0 requires it). Nothing was downgraded. v0.2.0 was built and tested with Go 1.27.3, compiled from the `go1.27.3` tag using Go 1.24.7 as the bootstrap. Go 1.24.7 itself cannot build this module: gin, golang.org/x/*, hiero and room all declare newer versions.

So the "upgrade to 1.27.3" task is a **verification** task, not a migration: confirm the Dockerfile (`GO_VERSION=1.27`) and your local toolchain both resolve to 1.27.3 or later, then run section 3 and report.

The build environment that produced v0.2.0 had no access to `proxy.golang.org`. It used a `go.work` outside the repository with directory `replace`s for the golang.org/x, google.golang.org and other vanity-path modules, cloned from their GitHub mirrors. **Nothing of that is in the repository**, and you need none of it. `go.sum` is unchanged except where noted below.

`go.mod` change in v0.2.0: `golang.org/x/net` moved from indirect to direct (the crawler uses its HTML tokenizer). Run `go mod tidy` on a networked machine and commit the result only if it changes nothing else. If it does change more, report the diff instead of committing it.

## 2. What is left, in order

Do these one at a time. Each one ends with section 3 green and a report (section 5). Do not start the next one in the same change.

### Repository rules

- **The only Go file at the repository root is `version.go`** (package `concert`). Binaries live in `cmd/<name>/main.go`, everything else in `internal/<package>/`. A `package main` file at the root breaks the build ("found packages concert and main"). v0.2.0's source update 003 shipped fifteen of them: fourteen pre-v0.2.0 copies of what is now `internal/server`, and a `mesh.go` draft that never compiled (it used config fields, app fields and pool methods that exist nowhere). The cleanup patch removed them all. When you move code, use `git mv` so nothing is left behind, and check with:

  ```sh
  find . -name '*.go' ! -path './internal/*' ! -path './cmd/*' ! -name version.go   # expect no output
  ```

- **No GitHub workflows, ever.** Do not add `.github/`, CI configuration or any hosted pipeline; `.gitignore` excludes `.github/`. Verification is the commands in section 3, run by you, with the output in your report. `make all`, `make vulncheck` and `make sbom` are the local equivalents.
- **No macOS metadata in archives.** Create tarballs with `COPYFILE_DISABLE=1 tar …` so `._*` files are not added; `.gitignore` excludes them.
- **Ideas from the `mesh.go` draft are not lost**, and none of them is adopted. If the owner wants them, they belong on the v0.2.0 trust chain (`internal/hop`, `internal/server/topology.go`), not as a second one:
  - sticky routing by admission pass;
  - a signed leaf-to-edge ban signal;
  - leaf state in a response header between polls;
  - a hot-upstream admin API.

  Propose before building, and recover the draft from the cleanup patch (`git apply -R` shows it).

### T1: verify v0.2.0 on a real toolchain and network

- Run section 3 in full and attach the real output.
- Run `govulncheck ./...` (`make vulncheck`) and report findings by package.
- Build every platform with `make build` and run `bin/concert-linux-amd64 -version` (expect `v0.2.0`).
- Run the three-process smoke in section 4.

**Done when:** all of it passes, or every failure is reported with its output and a diagnosis. Do not fix and re-run silently.

### T2: domain-driven decomposition of `internal/server`

The repository owner wants every domain in its own `internal/<package>`. v0.2.0 moved the code into one package and gave the new domains (hop, capacity, bench) packages of their own. The old code is still one package. Split it in this order, **one package per change**, each leaving behaviour identical:

| Order | Package | From `internal/server` | Notes |
|---|---|---|---|
| 1 | `internal/netaddr` | `net_ip.go`, `ranges.go` (parsing parts), `clientIP`, `remoteAddr`, `containsAddr`, `parsePrefixes` | pure functions; easiest first |
| 2 | `internal/abuse` | `abuse.go`, `ranges.go` (bans), `persist.go` | the registry; expose `Registry`, `Target`, `View`; keep the `onBan` hook |
| 3 | `internal/admission` | `pass.go`, the `assetGuard`, `stream.go` | admission passes and the asset and stream tiers |
| 4 | `internal/priority` | `priority.go` | grants, the ranked semaphore, the lane |
| 5 | `internal/upstream` | `upstream.go` | the pool, transport, retries; takes a `Signer` interface instead of `*topology` |
| 6 | `internal/settings` | `settings.go`, `config.go` | the setting table and config; the biggest coupling point, so do it late |
| 7 | `internal/history`, `internal/audit`, `internal/portal` | `history*.go`, `audit.go`, `portal.go`, `fragments.go`, `api.go` portal parts, `rbac.go` | the portal last |
| 8 | `internal/cluster` | `cluster.go` | Redis sync |

`internal/server` keeps only composition: `app`, `generation`, `router`, reload, and the tier wiring.

Rules for T2:

- **No behaviour change.** No renamed flags, env vars, JSON keys, metric names, log messages or HTTP responses. If a split seems to need one, stop and report it instead.
- Tests move with their code. Package-internal tests stay internal (`package abuse`), and cross-domain tests stay in `internal/server`.
- Export the smallest surface that compiles. Prefer an interface at the consumer over exporting a struct's fields.
- No import cycles. If one appears, the split is wrong: report the cycle and the dependency that caused it.
- Each step: `git mv` first (so history follows), then edits; section 3 green; one commit.

**Done when:** `internal/server` has no file over 600 lines except the router and app composition, every package has a doc comment saying what domain it owns, and section 3 is green after every step.

### T3: dead code

`newProxy` in `internal/server/api.go` and `forwardTo` / `forwardToPool` in `router.go` are unused since the upstream pool replaced them. Remove them. `newProxy` also lacks `DisableCompression`, so it must not come back into use. Done when they are removed and section 3 is green.

### T4: room capacity shrink

`room.SetCap` delegates to `sema.SetCap`. When the new cap is below the current use, sema **drains** its channel: in-flight requests stop being counted, and up to old use plus the new cap can run at once.

v0.2.0 works around this on the edge with `capacity.SafeShrink`, which never sets the cap below `room.Len()` and steps down as requests finish. The portal's and `/_room/cap`'s manual changes still hit the drain.

Fix it upstream in `github.com/andreimerlescu/sema`: shrinking keeps the in-flight count and grants nothing until use is under the new cap, as `capacity.Gate` does. Then release, bump room, bump Concert, remove the workaround, and add a test that shrinks under load and asserts the ceiling.

### T5: haproxy in a real lab

TOPOLOGY.md recommends `retry-on conn-failure empty-response` and **not** retrying 503, because haproxy cannot tell a leaf's backpressure from the application's own 503. Verify against the haproxy version the owner runs:

- whether `retry-on 503` can be limited to idempotent requests;
- whether an `http-response` rule can match `Concert-Backpressure`.

Report what is safe, and update TOPOLOGY.md only with what you observed.

### T6: portal views for the tiers

Show `/_room/stats`' `edge` and `leaf` sections in the admin portal's Overview, and the last silence report on a leaf. Follow the existing fragment and theme patterns. Every new view needs a test in the style of `portal_test.go`.

### T7: lemmings

The standalone lemmings project has open enhancement issues. When the owner says so, port the relevant ones into `internal/bench`, keeping its rules: lemmings hold one page each, findings never fail a stage, and the report explains failures. Each ported issue needs a test against `internal/testsite`.

### T8: several edges

Leaves divide their capacity evenly by the edges heard from in the last minute. If the owner runs several active edges, propose (do not implement without approval) a share that follows each edge's traffic.

## 3. Verification

Run all of it from the repository root and paste the real output into your report:

```sh
go version                       # expect go1.27.3 or later
gofmt -l .                       # expect no output
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...
# concurrency-sensitive tests, repeated:
go test -race -count=10 -run 'TestTier|TestAssets_|TestTransportRetries|TestPickSlot' ./internal/server
go test -race -count=5 ./internal/capacity ./internal/hop
go test -race -count=3 ./internal/bench
go test -run '^$' -fuzz FuzzVerify -fuzztime 60s ./internal/hop
```

At v0.2.0 all of these pass on Go 1.27.3 / linux amd64. The hop fuzzer ran about 2 million inputs without a finding. A test that fails only sometimes is a failure: report it with the seed or count that reproduced it. Never raise a timeout or loosen an assertion to make a test pass without explaining, in the report, why the old one was wrong.

## 4. Smoke test with real processes

```sh
go build -o /tmp/c/concert ./cmd/concert && go build -o /tmp/c/bench-concert ./cmd/bench-concert
cd /tmp/c && mkdir -p www d1 d2 de && echo '<a href="/">home</a>' > www/index.html
(cd www && python3 -m http.server 3101 &) ; (cd www && python3 -m http.server 3102 &)
export CONCERT_HOP_SECRET=$(openssl rand -hex 24) CONCERT_ADMIT_SECRET=$(openssl rand -hex 24)
CONCERT_ROLE=leaf ./concert -listen 127.0.0.1:8201 -portal-listen "" -upstream http://127.0.0.1:3101 -hop-peers 127.0.0.1/32 -host-cap 6 -node-id i-01 -data-dir d1 &
CONCERT_ROLE=leaf ./concert -listen 127.0.0.1:8202 -portal-listen "" -upstream http://127.0.0.1:3102 -hop-peers 127.0.0.1/32 -host-cap 4 -node-id i-02 -data-dir d2 &
sleep 1
./concert -role edge -listen 127.0.0.1:8200 -portal-listen "" -upstream http://127.0.0.1:8201,http://127.0.0.1:8202 -node-id www -cap 100 -priority-cap 2 -hop-poll 1s -data-dir de &
sleep 3
curl -s http://127.0.0.1:8200/                                      # the page, through the edge
curl -s http://127.0.0.1:8200/_room/stats | jq '.cap, .edge.leaf_slots'   # 8, 10
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8201/_room/hop/state   # 401
kill %2   # stop i-02: within ~20s the edge's .cap falls to 4 and pages still load
./bench-concert -target http://127.0.0.1:3101/ -stage 1s -cooldown 300ms -max 16 -data-dir bench
```

v0.2.0 produced exactly these results. Report any difference.

## 5. Expected level of output

The repository owner relies on Concert for paid traffic, and wants it to meet the standard haproxy met before the industry trusted it. Work to that standard:

- **Evidence, not assertions.** Every claim of "passes", "fixed" or "faster" comes with the command and its real output. If you did not run something, say "not run" and why. Never summarize a run you did not see.
- **Tests carry the weight.** Every behaviour change has a test that fails without it.
  - Security-relevant code (hop claims, bans, the control plane, payments, passes) needs negative tests: forged, replayed, stale, malformed, wrong peer, wrong secret.
  - Every parser of untrusted input needs a fuzz target.
  - Concurrency needs a stress test that asserts the invariant (a ceiling never exceeded, no leaked slot), and must pass with `-race -count=10`.
- **Compliance.** Keep every guarantee in docs/US_COMPLIANCE.md and docs/ENTERPRISE.md:
  - secrets come only from the environment or `*_FILE`, never from logs, settings.json, URLs or errors;
  - administrative actions write audit events;
  - every new flag is in `settingDefs` (`TestSettingDefs_CoverEveryFlag` enforces it), with a default that keeps standalone Concert unchanged;
  - data written to `-data-dir` uses mode 0600, through an atomic rename.
- **Docs move with code.** README's tables, TOPOLOGY.md and CHANGES.md change in the same commit as the behaviour they describe. Write plainly, for an operator: what it does, what to set, what can go wrong.
- **Small, reviewable changes.** One concern per commit. A refactor commit contains no behaviour change, and a behaviour commit contains no refactor.
- **Stop and ask** before:
  - changing a public flag, header, cookie, endpoint, JSON shape or metric;
  - touching payment settlement or the journals;
  - weakening a check;
  - adding a dependency.

### Report format

End every task with:

```
Task: T<n> <name>
Result: done | partial | blocked
Changed: <files, one line each, with why>
Verification: <commands and their real output, trimmed to the relevant lines>
Not done / open questions: <anything left, anything you were unsure of>
```

## 6. Known limits at v0.2.0

All of these are documented in TOPOLOGY.md, and none is a bug to fix silently:

- a captured claim can be replayed within the skew window;
- a single active edge;
- shares across several edges are approximate;
- a leaf's room capacity is static;
- haproxy cannot retry leaf backpressure;
- the startup benchmark measures the application only at that moment.
