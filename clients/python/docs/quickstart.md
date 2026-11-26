# Python Quickstart

## Requirements

- Python 3.10 or newer
- Zero required third-party packages (pure standard library)
- Optional: `cryptography>=41.0` for Ed25519 `rm1` pass/lease signing and verification

## Install

```bash
# Core library (zero dependencies)
pip install ./clients/python

# With optional Ed25519 rm1 cryptography extra
pip install "./clients/python[crypto]"
```

## 1. Signal Visitor Priority (`Concert-Priority`)

Concert inspects the `Concert-Priority` response header emitted by your origin, strips it before forwarding to browsers, and stores the rank in a signed `concert_priority` cookie bound to the visitor's admission pass.

Valid ranks (lowest to highest):

| Rank | Meaning |
| --- | --- |
| `guest` | Anonymous visitor (or clears an existing grant on logout) |
| `member` | Signed-in user |
| `prospect` | Viewing a buying page or items in cart |
| `customer` | Past purchaser |
| `subscriber` | Active subscription |
| `checkout` | Payment in progress |
| `staff` | Operators and support |

```python
from concert_client import format_priority_header, highest_rank

rank = highest_rank({"member": True, "checkout": True})
header_value = format_priority_header(rank, ttl_seconds=1800)
# "checkout; ttl=1800"
```

## 2. Parse Waiting-Room Signal Headers

Concert emits `X-Concert-Queue: 1` **only** on real waiting-room responses (never on capacity-breaker 503s or rate-limit 429s):

```python
from concert_client import parse_waiting_room_headers

signal = parse_waiting_room_headers(resp.headers)
if signal.queued:
    print("Position:", signal.position)
    print("Retry after (s):", signal.retry_after)
    print("Status URL:", signal.effective_status_url)
```

## 3. Mint & Verify Stateless `rm1` Ed25519 Tokens

With `concert-client[crypto]` installed, external checkout or control-plane services can mint short-lived `rm1` tokens that verify-only Concert replicas validate locally with zero shared Redis:

```python
from pathlib import Path
from concert_client import Ed25519Signer, Ed25519Verifier, TokenIssuer

# Load Ed25519 seed from a 0600-protected secret file (never hardcode keys)
seed_hex = Path("/run/secrets/concert_rm1_k1_seed").read_text(encoding="utf-8").strip()
signer = Ed25519Signer("k1", seed_hex)
issuer = TokenIssuer("shop.example.com", signer, max_ttl_seconds=600)

pass_token = issuer.mint_pass(ttl_seconds=300)
# Send via header: X-Room-Pass: <pass_token>

verifier = Ed25519Verifier({"k1": signer.public_key_bytes()})
claims = verifier.verify(pass_token, expected_scope="shop.example.com")
print(claims.kid, claims.kind, claims.exp)
```
