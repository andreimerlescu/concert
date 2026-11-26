"""Comprehensive stdlib unittest suite for concert_client."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import http.server
import json
import os
import secrets
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlparse

from concert_client import (
    ALL_RANKS,
    AgentBidClient,
    BidCapExceededError,
    BiddingError,
    CachePurgeClient,
    CachePurgeError,
    ConcertPriorityASGIMiddleware,
    ConcertPriorityWSGIMiddleware,
    CrossOriginError,
    Ed25519Signer,
    Ed25519Verifier,
    GRANT_RANKS,
    InvalidPriorityRankError,
    KIND_LEASE,
    KIND_PASS,
    REDACTED,
    Rm1Error,
    Rm1VerificationError,
    SUPPORTED_CHAINS,
    SecretBytes,
    SecretError,
    SecretString,
    TokenClaims,
    TokenIssuer,
    UnsupportedChainError,
    UnsupportedCryptoError,
    assemble_envelope,
    encode_signing_input,
    format_micro_usd,
    format_priority_header,
    highest_rank,
    is_queued,
    load_secret_from_env_or_file,
    load_secret_from_file,
    normalize_chain,
    parse_auction_offer,
    parse_envelope,
    parse_usd_to_micro_usd,
    parse_waiting_room_headers,
    resolve_same_origin_url,
    set_priority_header,
    sign_pass,
    validate_rank,
    verify_pass,
)
from concert_client.rm1 import (
    REJECT_EXPIRED,
    REJECT_FUTURE_ISSUED,
    REJECT_INVALID_SIGNATURE,
    REJECT_KEY_MISMATCH,
    REJECT_MALFORMED,
    REJECT_UNKNOWN_KEY,
    REJECT_WRONG_KIND,
    REJECT_WRONG_SCOPE,
)


class _StubConcertState:
    def __init__(self, expected_token: str) -> None:
        self.expected_token = expected_token
        self.purge_requests: list[dict] = []
        self.bid_requests: list[dict] = []
        self.status_calls: int = 0
        self.bid_statuses: dict[str, list[dict]] = {}
        self.force_oversized_purge = False


def _make_stub_handler(state: _StubConcertState):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return

        def _send_json(self, code: int, payload: dict, extra_headers: dict[str, str] | None = None) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b"{}"
            body = json.loads(raw.decode("utf-8"))

            if self.path == "/_room/cache/purge":
                auth = self.headers.get("Authorization", "")
                if auth != f"Bearer {state.expected_token}":
                    self._send_json(401, {"error": "unauthorized"})
                    return
                if state.force_oversized_purge:
                    big = b"{" + b" " * 1024 + b"}"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(big)))
                    self.end_headers()
                    self.wfile.write(big)
                    return
                state.purge_requests.append(body)
                mode = body.get("mode")
                purged = 42 if mode == "all" else (7 if mode == "prefix" else 1)
                self._send_json(200, {"purged": purged, "mode": mode})
                return

            if self.path == "/_concert/bids":
                state.bid_requests.append(
                    {
                        "body": body,
                        "session": self.headers.get("Concert-Session", ""),
                    }
                )
                bid_id = body.get("bid_id") or "bid-test-1"
                if body.get("scope") == "instant.example":
                    stub_pass = "stub-" + secrets.token_hex(6)
                    self._send_json(
                        200,
                        {
                            "bid_id": bid_id,
                            "status": "settled",
                            "pass_issued": True,
                            "pass_token": stub_pass,
                            "priority_pass": stub_pass,
                            "transaction": "tx-instant-001",
                            "status_url": f"/_concert/bids/status?bid_id={bid_id}",
                        },
                        extra_headers={"Set-Cookie": "concert_admit=stub-admit; HttpOnly; Path=/"},
                    )
                    return
                self._send_json(
                    202,
                    {
                        "bid_id": bid_id,
                        "status": "pending",
                        "pass_issued": False,
                        "status_url": f"/_concert/bids/status?bid_id={bid_id}",
                    },
                )
                return

            self._send_json(404, {"error": "not found"})

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/_concert/bids/status":
                qs = parse_qs(parsed.query)
                bid_id = (qs.get("bid_id") or [""])[0]
                state.status_calls += 1
                seq = state.bid_statuses.get(bid_id)
                if not seq:
                    self._send_json(404, {"error": "bid_not_found"})
                    return
                idx = min(state.status_calls - 1, len(seq) - 1)
                self._send_json(200, seq[idx])
                return
            self._send_json(404, {"error": "not found"})

    return Handler


class TestSecrets(unittest.TestCase):
    def test_secret_string_redacts_every_representation(self) -> None:
        raw = "fake-credential-for-tests-" + secrets.token_hex(8)
        s = SecretString(raw)
        self.assertEqual(str(s), REDACTED)
        self.assertIn(REDACTED, repr(s))
        self.assertEqual(f"{s}", REDACTED)
        self.assertNotIn(raw, str(s))
        self.assertNotIn(raw, repr(s))
        self.assertEqual(s.reveal(), raw)

    def test_secret_string_rejects_empty_and_crlf(self) -> None:
        with self.assertRaises(SecretError):
            SecretString("")
        with self.assertRaises(SecretError):
            SecretString("   ")
        with self.assertRaises(SecretError):
            SecretString("fake-val\r\nX-Injected: 1")

    def test_secret_bytes_redacts(self) -> None:
        raw = secrets.token_bytes(32)
        sb = SecretBytes(raw)
        self.assertEqual(str(sb), REDACTED)
        self.assertIn(REDACTED, repr(sb))
        self.assertEqual(sb.reveal(), raw)
        with self.assertRaises(SecretError):
            SecretBytes(b"")

    def test_load_secret_from_file_enforces_0600(self) -> None:
        raw = "fake-file-secret-" + secrets.token_hex(8)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "token")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(raw + "\n")
            os.chmod(path, 0o644)
            with self.assertRaises(SecretError):
                load_secret_from_file(path)

            os.chmod(path, 0o600)
            loaded = load_secret_from_file(path)
            self.assertEqual(loaded.reveal(), raw)
            self.assertEqual(str(loaded), REDACTED)

            env_loaded = load_secret_from_env_or_file(
                "CONCERT_ADMIN_TOKEN",
                "CONCERT_ADMIN_TOKEN_FILE",
                environ={"CONCERT_ADMIN_TOKEN_FILE": path},
            )
            self.assertEqual(env_loaded.reveal(), raw)

        with self.assertRaises(SecretError):
            load_secret_from_env_or_file("CONCERT_ADMIN_TOKEN", "CONCERT_ADMIN_TOKEN_FILE", environ={})


class TestPriority(unittest.TestCase):
    def test_ranks_and_formatting(self) -> None:
        self.assertEqual(
            GRANT_RANKS,
            ("member", "prospect", "customer", "subscriber", "checkout", "staff"),
        )
        for rank in ALL_RANKS:
            self.assertEqual(validate_rank(f"  {rank.upper()} "), rank)

        self.assertEqual(format_priority_header("checkout", 1800), "checkout; ttl=1800")
        self.assertEqual(format_priority_header("staff", 10), "staff; ttl=60")
        self.assertEqual(format_priority_header("staff", 200000), "staff; ttl=86400")
        self.assertEqual(format_priority_header("guest", 600), "guest")
        self.assertEqual(highest_rank({"member": True, "checkout": True, "customer": True}), "checkout")
        self.assertEqual(highest_rank({"member": False}), "guest")

        with self.assertRaises(InvalidPriorityRankError):
            validate_rank("vip")
        with self.assertRaises(InvalidPriorityRankError):
            format_priority_header("staff\r\nX-Evil: 1")
        with self.assertRaises(InvalidPriorityRankError):
            format_priority_header("checkout", 0)
        with self.assertRaises(InvalidPriorityRankError):
            format_priority_header("checkout", True)  # type: ignore[arg-type]

        headers: dict[str, str] = {}
        self.assertEqual(set_priority_header(headers, "subscriber", ttl_seconds=3600), "subscriber; ttl=3600")
        self.assertEqual(headers["Concert-Priority"], "subscriber; ttl=3600")

    def test_asgi_middleware_sync_and_async_resolvers(self) -> None:
        sent: list[dict] = []

        async def app(scope, receive, send):
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/plain"), (b"concert-priority", b"member")],
                }
            )
            await send({"type": "http.response.body", "body": b"ok"})

        async def async_resolver(scope):
            if scope["path"] == "/checkout":
                return ("checkout", 1800)
            return None

        mw = ConcertPriorityASGIMiddleware(app, async_resolver)

        async def receive():
            return {"type": "http.request", "body": b""}

        async def send(msg):
            sent.append(msg)

        asyncio.run(mw({"type": "http", "path": "/checkout"}, receive, send))
        start_headers = dict(sent[0]["headers"])
        self.assertEqual(start_headers[b"concert-priority"], b"checkout; ttl=1800")

        # Non-HTTP scope passes straight through untouched.
        sent.clear()
        asyncio.run(mw({"type": "lifespan"}, receive, send))
        self.assertEqual(dict(sent[0]["headers"])[b"concert-priority"], b"member")

    def test_wsgi_middleware(self) -> None:
        captured: list[tuple[str, list[tuple[str, str]]]] = []

        def wsgi_app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/html"), ("Concert-Priority", "member")])
            return [b"hello"]

        def start_response(status, headers, exc_info=None):
            captured.append((status, headers))

        mw = ConcertPriorityWSGIMiddleware(
            wsgi_app,
            lambda env: "staff" if env.get("REMOTE_USER") == "ops" else None,
            default_ttl=7200,
        )
        body = list(mw({"REMOTE_USER": "ops"}, start_response))
        self.assertEqual(body, [b"hello"])
        hdrs = dict(captured[0][1])
        self.assertEqual(hdrs["Concert-Priority"], "staff; ttl=7200")


class TestSignals(unittest.TestCase):
    def test_parse_queued_and_non_queued_headers(self) -> None:
        sig = parse_waiting_room_headers(
            {
                "x-concert-queue": "1",
                "X-Concert-Position": "17",
                "Retry-After": "5",
                "X-Concert-Status-Url": "/custom/status",
            }
        )
        self.assertTrue(sig.queued)
        self.assertEqual(sig.position, 17)
        self.assertEqual(sig.retry_after, 5)
        self.assertEqual(sig.status_url, "/custom/status")
        self.assertEqual(sig.effective_status_url, "/custom/status")
        self.assertTrue(is_queued({"X-Concert-Queue": "1"}))

        # Default status URL when header omitted.
        sig_default = parse_waiting_room_headers([("X-Concert-Queue", "1"), ("Retry-After", "3")])
        self.assertTrue(sig_default.queued)
        self.assertEqual(sig_default.effective_status_url, "/queue/status")

        # HTTP-date Retry-After parsing.
        now = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)
        sig_date = parse_waiting_room_headers(
            {"X-Concert-Queue": "1", "Retry-After": "Thu, 26 Nov 2026 12:00:15 GMT"},
            now=now,
        )
        self.assertEqual(sig_date.retry_after, 15)

        # Guard/breaker 503 carries Retry-After without X-Concert-Queue.
        sig_503 = parse_waiting_room_headers({"Retry-After": "30"})
        self.assertFalse(sig_503.queued)
        self.assertEqual(sig_503.retry_after, 30)

        # Unsafe status URL schemes rejected.
        sig_xss = parse_waiting_room_headers(
            {"X-Concert-Queue": "1", "X-Concert-Status-Url": "javascript:alert(1)"}
        )
        self.assertIsNone(sig_xss.status_url)


class TestRm1(unittest.TestCase):
    def test_pure_python_envelope_codec_and_validation(self) -> None:
        claims = TokenClaims(
            kid="k1",
            kind=KIND_PASS,
            scope="shop.example.test",
            key="agent-42",
            iat=1700000000,
            exp=1700000300,
        )
        signing_input = encode_signing_input(claims)
        self.assertTrue(signing_input.startswith(b"rm1."))
        fake_sig = b"\x11" * 64
        token = assemble_envelope(claims, fake_sig)
        parsed = parse_envelope(token)
        self.assertEqual(parsed.claims, claims)
        self.assertEqual(parsed.signing_input, signing_input)
        self.assertEqual(parsed.signature, fake_sig)

        # Reject unknown fields in JSON payload.
        bad_payload = (
            b'{"kid":"k1","kind":"pass","scope":"s","iat":1,"exp":2,"extra":"nope"}'
        )
        import base64

        p_b64 = base64.urlsafe_b64encode(bad_payload).rstrip(b"=").decode("ascii")
        s_b64 = base64.urlsafe_b64encode(fake_sig).rstrip(b"=").decode("ascii")
        with self.assertRaises(Rm1VerificationError) as ctx:
            parse_envelope(f"rm1.{p_b64}.{s_b64}")
        self.assertEqual(ctx.exception.reason, REJECT_MALFORMED)

        # Reject wrong prefix or padded base64.
        with self.assertRaises(Rm1VerificationError):
            parse_envelope("rm2.abc.def")
        with self.assertRaises(Rm1VerificationError):
            parse_envelope("rm1.abc=.def=")

    def test_ed25519_sign_verify_rotation_and_security_order(self) -> None:
        seed1 = secrets.token_bytes(32)
        seed2 = secrets.token_bytes(32)
        signer1 = Ed25519Signer("k1", seed1)
        signer2 = Ed25519Signer("k2", seed2)
        self.assertIn(REDACTED, repr(signer1))
        self.assertNotIn(seed1.hex(), repr(signer1))

        pub1 = signer1.public_key_bytes()
        pub2 = signer2.public_key_bytes()
        verifier = Ed25519Verifier({"k1": pub1, "k2": pub2.hex()})

        now_ts = 1700000000
        issuer1 = TokenIssuer("shop.example.test", signer1, clock=lambda: now_ts)
        issuer2 = TokenIssuer("shop.example.test", signer2, clock=lambda: now_ts)

        pass_k1 = issuer1.mint_pass(ttl_seconds=300)
        verified = verifier.verify(pass_k1, expected_scope="shop.example.test", now=now_ts + 10)
        self.assertEqual(verified.kid, "k1")
        self.assertEqual(verified.kind, KIND_PASS)

        # Key rotation with k2 (loaded from hex).
        lease_k2 = issuer2.mint_lease("agent-9", ttl_seconds=120)
        v_lease = verifier.verify(
            lease_k2,
            expected_scope="shop.example.test",
            expected_kind=KIND_LEASE,
            expected_key="agent-9",
            now=now_ts + 5,
        )
        self.assertEqual(v_lease.key, "agent-9")

        # Convenience helpers round-trip.
        quick = sign_pass(scope="api.test", key_id="k1", private_key=seed1.hex(), ttl_seconds=60, now=now_ts)
        quick_claims = verify_pass(quick, expected_scope="api.test", public_keys={"k1": pub1}, now=now_ts + 1)
        self.assertEqual(quick_claims.scope, "api.test")

        # Tampered token -> invalid_signature even if expired.
        tampered = pass_k1[:-4] + ("AAAA" if not pass_k1.endswith("AAAA") else "BBBB")
        with self.assertRaises(Rm1VerificationError) as ctx:
            verifier.verify(tampered, expected_scope="shop.example.test", now=now_ts + 9999)
        self.assertEqual(ctx.exception.reason, REJECT_INVALID_SIGNATURE)

        # Wrong scope -> wrong_scope.
        with self.assertRaises(Rm1VerificationError) as ctx:
            verifier.verify(pass_k1, expected_scope="blog.example.test", now=now_ts + 10)
        self.assertEqual(ctx.exception.reason, REJECT_WRONG_SCOPE)

        # Wrong kind (pass presented as lease) -> wrong_kind.
        with self.assertRaises(Rm1VerificationError) as ctx:
            verifier.verify(
                pass_k1,
                expected_scope="shop.example.test",
                expected_kind=KIND_LEASE,
                expected_key="agent-9",
                now=now_ts + 10,
            )
        self.assertEqual(ctx.exception.reason, REJECT_WRONG_KIND)

        # Key mismatch on lease -> key_mismatch.
        with self.assertRaises(Rm1VerificationError) as ctx:
            verifier.verify(
                lease_k2,
                expected_scope="shop.example.test",
                expected_kind=KIND_LEASE,
                expected_key="other-agent",
                now=now_ts + 10,
            )
        self.assertEqual(ctx.exception.reason, REJECT_KEY_MISMATCH)

        # Expired -> expired.
        with self.assertRaises(Rm1VerificationError) as ctx:
            verifier.verify(pass_k1, expected_scope="shop.example.test", now=now_ts + 301)
        self.assertEqual(ctx.exception.reason, REJECT_EXPIRED)

        # Future issued beyond skew -> future_issued.
        with self.assertRaises(Rm1VerificationError) as ctx:
            verifier.verify(pass_k1, expected_scope="shop.example.test", now=now_ts - 120)
        self.assertEqual(ctx.exception.reason, REJECT_FUTURE_ISSUED)

        # Unknown kid -> unknown_key.
        v_only_k2 = Ed25519Verifier({"k2": pub2})
        with self.assertRaises(Rm1VerificationError) as ctx:
            v_only_k2.verify(pass_k1, expected_scope="shop.example.test", now=now_ts + 10)
        self.assertEqual(ctx.exception.reason, REJECT_UNKNOWN_KEY)

        # TTL bounds enforced.
        with self.assertRaises(Rm1Error):
            issuer1.mint_pass(ttl_seconds=0)
        with self.assertRaises(Rm1Error):
            issuer1.mint_pass(ttl_seconds=901)

    def test_missing_cryptography_raises_clear_runtime_error(self) -> None:
        seed = secrets.token_bytes(32)
        signer = Ed25519Signer("k1", seed)
        with mock.patch.dict(sys.modules, {"cryptography": None, "cryptography.hazmat": None, "cryptography.hazmat.primitives": None, "cryptography.hazmat.primitives.asymmetric": None}):
            with self.assertRaises(UnsupportedCryptoError) as ctx:
                signer.sign(b"rm1.test")
            self.assertIn("cryptography", str(ctx.exception))


class TestHTTPClients(unittest.TestCase):
    def setUp(self) -> None:
        self.token = "fake-admin-token-" + secrets.token_hex(12)
        self.state = _StubConcertState(self.token)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_stub_handler(self.state))
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def test_cache_purge_modes_auth_redaction_and_bounds(self) -> None:
        client = CachePurgeClient(self.base_url, self.token, timeout=5.0)
        self.assertIn(REDACTED, repr(client))
        self.assertNotIn(self.token, repr(client))
        self.assertNotIn(self.token, str(client))

        r_url = client.purge_url("/product/42", host="shop.example")
        self.assertEqual(r_url.purged, 1)
        self.assertEqual(r_url.mode, "url")

        r_prefix = client.purge_prefix("/blog/")
        self.assertEqual(r_prefix.purged, 7)

        r_tag = client.purge_tag("post:42")
        self.assertEqual(r_tag.purged, 1)

        r_all = client.purge_all(host="shop.example")
        self.assertEqual(r_all.purged, 42)
        self.assertEqual(len(self.state.purge_requests), 4)
        self.assertEqual(self.state.purge_requests[0], {"mode": "url", "host": "shop.example", "target": "/product/42"})

        # Unauthorized error never leaks token.
        bad_token = "fake-wrong-token-" + secrets.token_hex(8)
        bad_client = CachePurgeClient(self.base_url, bad_token)
        with self.assertRaises(CachePurgeError) as ctx:
            bad_client.purge_all()
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertNotIn(bad_token, str(ctx.exception))

        # Bounded response read rejects oversized body.
        self.state.force_oversized_purge = True
        small_client = CachePurgeClient(self.base_url, self.token, max_response_bytes=256)
        with self.assertRaises(CachePurgeError):
            small_client.purge_all()

        # Non-loopback http:// rejected unless allow_insecure_http=True.
        with self.assertRaises(ValueError):
            CachePurgeClient("http://example.com", self.token)
        # Credentials in URL rejected.
        cred_url = "https://" + "u" + ":" + "p" + "@example.com"
        with self.assertRaises(ValueError):
            CachePurgeClient(cred_url, self.token)
        # Empty mode target rejected.
        with self.assertRaises(ValueError):
            client.purge("url", target="")

    def test_agent_bidding_crypto_only_and_end_to_end(self) -> None:
        self.assertEqual(SUPPORTED_CHAINS, ("xrpl", "stellar", "hedera", "solana"))
        for chain in SUPPORTED_CHAINS:
            self.assertEqual(normalize_chain(chain.upper()), chain)

        # Reject fiat / non-crypto rails explicitly.
        for bad_chain in ("stripe", "usd", "visa", "card", "fiat", "paypal", "ethereum"):
            with self.assertRaises(UnsupportedChainError):
                normalize_chain(bad_chain)

        # Exact integer micro-USD parsing (no floats).
        self.assertEqual(parse_usd_to_micro_usd("1.25"), 1_250_000)
        self.assertEqual(parse_usd_to_micro_usd("0.000001"), 1)
        self.assertEqual(format_micro_usd(1_500_000), "$1.50")
        self.assertEqual(format_micro_usd(50_000), "$0.05")
        with self.assertRaises(ValueError):
            parse_usd_to_micro_usd("-1.00")
        with self.assertRaises(ValueError):
            parse_usd_to_micro_usd("0")

        # 429 auction offer parsing (filters any unexpected chain out).
        offer_json = json.dumps(
            {
                "queued": True,
                "position": 5,
                "auction": {
                    "mode": "auction",
                    "auction_id": "auc-1",
                    "scope": "drop.example",
                    "floor_micro_usd": 1_000_000,
                    "slots": 2,
                    "bid_url": "/_concert/bids",
                    "status_url": "/_concert/bids/status",
                    "supported_chains": ["solana", "xrpl", "stellar", "hedera"],
                },
            }
        )
        offer = parse_auction_offer(offer_json, status_code=429)
        assert offer is not None
        self.assertEqual(offer.mode, "auction")
        self.assertEqual(offer.floor_micro_usd, 1_000_000)
        self.assertEqual(offer.supported_chains, ("solana", "xrpl", "stellar", "hedera"))
        self.assertIsNone(parse_auction_offer(offer_json, status_code=200))

        # Client enforces strict max_bid_micro_usd cap and redacts session_id.
        fake_session = "fake-session-" + secrets.token_hex(8)
        client = AgentBidClient(
            self.base_url,
            max_bid_micro_usd=2_000_000,
            chain="solana",
            asset="USDC",
            session_id=fake_session,
        )
        self.assertNotIn(fake_session, repr(client))
        self.assertEqual(client.evaluate_offer(offer), 2_000_000)

        # Low-cap client skips offers whose floor exceeds cap.
        low_cap = AgentBidClient(self.base_url, max_bid_micro_usd=500_000, chain="solana")
        self.assertIsNone(low_cap.evaluate_offer(offer))
        with self.assertRaises(BidCapExceededError):
            low_cap.submit_bid(
                bid_micro_usd=1_000_000,
                amount_atomic="1000000",
                payment_payload={"scheme": "exact", "sig": "fake-sig"},
            )

        # Cross-origin SSRF protection on bid_url / status_url.
        with self.assertRaises(CrossOriginError):
            resolve_same_origin_url(self.base_url, "https://evil.example/_concert/bids")
        with self.assertRaises(CrossOriginError):
            client.submit_bid(
                bid_micro_usd=1_000_000,
                amount_atomic="1000000",
                payment_payload={"scheme": "exact"},
                bid_url="https://evil.example/_concert/bids",
            )

        # 1. Instant-buy settlement returns pass credentials immediately.
        instant_resp = client.submit_bid(
            bid_micro_usd=1_000_000,
            amount_atomic="1000000",
            payment_payload={"scheme": "exact", "network": "solana:mainnet"},
            scope="instant.example",
            bid_id="bid-instant-1",
        )
        self.assertTrue(instant_resp.settled)
        self.assertTrue(instant_resp.pass_issued)
        self.assertTrue(instant_resp.pass_token.startswith("stub-"))
        self.assertIn(REDACTED, repr(instant_resp))
        self.assertNotIn(instant_resp.pass_token, repr(instant_resp))
        self.assertTrue(any("concert_admit=" in c for c in instant_resp.set_cookies))

        # 2. Sealed-bid auction submits pending, then polls until settled.
        winner_stub = "stub-win-" + secrets.token_hex(4)
        self.state.bid_statuses["bid-auc-1"] = [
            {"bid_id": "bid-auc-1", "status": "pending", "pass_issued": False},
            {
                "bid_id": "bid-auc-1",
                "status": "settled",
                "pass_issued": True,
                "pass_token": winner_stub,
                "transaction": "tx-sol-999",
            },
        ]
        pending = client.submit_bid(
            bid_micro_usd=1_500_000,
            amount_atomic="1500000",
            payment_payload={"scheme": "exact", "network": "solana:mainnet"},
            scope="drop.example",
            bid_id="bid-auc-1",
        )
        self.assertEqual(pending.status, "pending")
        self.assertFalse(pending.is_terminal)

        final = client.poll_bid_status(
            "bid-auc-1",
            poll_interval=0.05,
            max_attempts=5,
            sleep_fn=lambda _: None,
        )
        self.assertTrue(final.settled)
        self.assertTrue(final.pass_issued)
        self.assertEqual(final.transaction, "tx-sol-999")

        # 3. Sealed-bid loss pays $0 and terminates cleanly.
        self.state.status_calls = 0
        self.state.bid_statuses["bid-lost-1"] = [
            {"bid_id": "bid-lost-1", "status": "lost", "pass_issued": False, "reason": "outbid"}
        ]
        lost = client.get_bid_status("bid-lost-1")
        self.assertEqual(lost.status, "lost")
        self.assertTrue(lost.is_terminal)
        self.assertFalse(lost.settled)
        self.assertFalse(lost.pass_issued)

        # Missing bid_id returns BiddingError with status_code 404.
        with self.assertRaises(BiddingError) as ctx:
            client.get_bid_status("bid-missing")
        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
