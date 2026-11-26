# Ruby Quickstart

## Requirements

- Ruby 2.6 or newer (Ruby 3.0+ with OpenSSL 1.1.1+/3.x for native Ed25519 `rm1` signing/verification)
- Zero required runtime gem dependencies (pure Ruby stdlib)

## 1. Validate & Format `Concert-Priority`

```ruby
require "concert_client"

rank = ConcertClient::Priority.highest_rank(member: true, checkout: true)
header_value = ConcertClient::Priority.format_header(rank, ttl_seconds: 1800)
# => "checkout; ttl=1800"
```

Valid ranks (lowest to highest): `guest`, `member`, `prospect`, `customer`, `subscriber`, `checkout`, `staff`.

## 2. Parse Waiting-Room Signal Headers

Concert sets `X-Concert-Queue: 1` exclusively on queued waiting-room responses (never on capacity-breaker 503s or rate-limit 429s):

```ruby
signal = ConcertClient::Signals.parse(http_response)
if signal.queued?
  puts "Position: #{signal.position}"
  puts "Retry-After: #{signal.retry_after}s"
  puts "Status URL: #{signal.effective_status_url}"
end
```

## 3. Stateless `rm1` Ed25519 Pass & Lease Tokens

On Ruby runtimes linked against OpenSSL 1.1.1+ / 3.x (`ConcertClient::Rm1.ed25519_supported? == true`):

```ruby
seed_hex = File.read("/run/secrets/concert_rm1_k1_seed").strip
signer = ConcertClient::Rm1::Ed25519Signer.new("k1", seed_hex)
issuer = ConcertClient::Rm1::TokenIssuer.new("shop.example.com", signer, max_ttl_seconds: 600)

pass_token = issuer.mint_pass(ttl_seconds: 300)
# Forward to Concert via header: X-Room-Pass: <pass_token>

verifier = ConcertClient::Rm1::Ed25519Verifier.new({ "k1" => signer.public_key_bytes })
claims = verifier.verify(pass_token, expected_scope: "shop.example.com")
puts "#{claims.kid} #{claims.kind} exp=#{claims.exp}"
```

On older LibreSSL runtimes without native Ed25519, `Ed25519Signer` raises `ConcertClient::Rm1::UnsupportedCryptoError` clearly (or accepts a custom `sign_proc` / `verify_proc` for KMS/HSM backends).
