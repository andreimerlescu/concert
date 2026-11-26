# Contributing to Concert

Thank you for your interest in contributing to **Concert**. Concert is 100% open source under the [Apache License 2.0](LICENSE) with zero license keys and a strong focus on lean, verifiable Go standard-library engineering.

## Engineering Principles

1. **Standard library first, minimal dependencies:** Do not introduce heavy third-party libraries when a few hundred lines of Go standard library solve the exact requirement cleanly. Companion daemons (`concert-kv`, `concert-cache`, `concert-watchdog`) have **zero external Go dependencies**.
2. **Domain boundaries & value semantics:** Keep new subsystems in clean domain packages under `internal/<domain>/` with inward-pointing ports. Use [`internal/opt.Option[T]`](internal/opt/opt.go) (with Go's `json:",omitzero"`) instead of raw scalar/time pointer struct fields (`*int`, `*bool`, `*string`, `*time.Time`) so structs stay copy-safe, zero-allocation, and nil-panic-free.
3. **Bounded resources & explicit lifecycles:** Every goroutine, queue, buffer, HTTP body read, and cache must be strictly bounded and shut down cleanly on context cancellation.
4. **Fail-closed security:** Sensitive values use redacting `Secret` types (rendering `[REDACTED]` in logs/JSON/`fmt`), load from `*_FILE` (`0600`) or environment variables (never CLI flags), and write state atomically (`0600` temp + `Sync` + `Rename`).
5. **100% crypto-only commerce:** Fast-Lane and AI Agent Pass Bidding support `XRPL`, `Stellar`, `Hedera`, and `Solana` non-custodially. Do not add fiat/Stripe billing or commercial license keys.

## Repository Rules

- **Root Go file rule:** Only [`version.go`](version.go) may exist as a `.go` file at the repository root. Place binaries under `cmd/` and packages under `internal/`.
- **No `.github/` workflows:** Do not commit `.github/` automation files.
- **Client SDKs:** Multi-language integrations live under `clients/<name>/{docs/,src/,README.md,CHANGELIST.md,LICENSE}` and are marked `linguist-vendored` in [`.gitattributes`](.gitattributes) so Go repository language statistics remain accurate.

## Local Development & Verification

Requires **Go 1.27+**. Before opening a pull request, run the full verification suite across all three editions (`concert`, `wpconcert`, `econcert`) and companion daemons:

```sh
gofmt -l internal cmd clients/go/src   # must be empty
make lint                              # go vet across all editions & daemons
make test-race                         # full -race suite across all 3 build-tag sets
make vulncheck                         # govulncheck across all binaries (zero vulns)
go mod verify                          # verify module checksums
```

If you modify client SDKs under `clients/`, also run the corresponding test runner(s):

```sh
(cd clients/go/src && go vet ./... && go test -race ./...)
(cd clients/node && node --test src/tests/concert.test.ts)
PYTHONPATH=clients/python/src python3 -m unittest discover -s clients/python/src/tests -v
ruby -Iclients/ruby/src/lib clients/ruby/src/test/concert_client_test.rb
php clients/wordpress/src/tests/run.php
php clients/php/src/Tests/run.php
```

### Testing Standards

- Never synchronize concurrent tests with `time.Sleep`; use channels, `sync.WaitGroup`, barriers, injected clocks, or `testing/synctest`.
- Add regression tests for every bug fix and verify under `-race`.
- Keep unit tests self-contained (never read host `NADDR_DATA` or require external network access; live testnet checks belong behind `-tags livetestnet`).

## Pull Request Checklist

- [ ] Code formatted with `gofmt` and documented with clear GoDoc comments
- [ ] Zero new raw scalar/time pointer struct fields (use `internal/opt.Option[T]`)
- [ ] `make lint`, `make test-race`, and `make vulncheck` pass cleanly
- [ ] No real secrets, private hostnames, or local filesystem paths in diffs
- [ ] Documentation / tutorials updated when flags, environment variables, or `Concertfile` directives change

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) — please report security issues privately via GitHub Security Advisories rather than opening a public issue or PR.
