"""Concert/room ``rm1`` Ed25519 pass and lease token envelope codec, signer, and verifier.

Wire format (compatible with ``github.com/andreimerlescu/room`` v1.8.0+):

    rm1.<base64url-nopad(claims-json)>.<base64url-nopad(ed25519-signature)>

where the signed message is the ASCII bytes of ``rm1.<base64url-nopad(claims-json)>``.

Envelope encoding and parsing use pure Python stdlib with zero dependencies.
Ed25519 signing and verification use the optional ``cryptography`` package
(``pip install "concert-client[crypto]"``) and raise :class:`UnsupportedCryptoError`
if ``cryptography`` is not installed.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
import re
import time
from typing import Any

from .secrets import REDACTED, SecretBytes

TOKEN_WIRE_PREFIX = "rm1"
HEADER_ROOM_PASS = "X-Room-Pass"
HEADER_ROOM_LEASE = "X-Room-Lease"

KIND_PASS = "pass"
KIND_LEASE = "lease"
VALID_KINDS: tuple[str, ...] = (KIND_PASS, KIND_LEASE)

MIN_TTL_SECONDS = 1
DEFAULT_MAX_TTL_SECONDS = 900       # 15 minutes
MAX_SIGNED_TTL_SECONDS = 3600       # 1 hour hard ceiling
DEFAULT_MAX_CLOCK_SKEW_SECONDS = 30
MAX_KEY_ID_LEN = 64
MAX_SCOPE_LEN = 256
MAX_SIGNED_TOKEN_LEN = 4096

ED25519_SEED_SIZE = 32
ED25519_PRIVATE_KEY_SIZE = 64  # Go ed25519.PrivateKey = seed(32) || pub(32)
ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64

# Rejection reason constants aligned with room/token.go.
REJECT_MISSING_SCOPE = "missing_scope"
REJECT_NO_VERIFIER = "no_verifier"
REJECT_MALFORMED = "malformed"
REJECT_UNKNOWN_KEY = "unknown_key"
REJECT_INVALID_SIGNATURE = "invalid_signature"
REJECT_EXPIRED = "expired"
REJECT_FUTURE_ISSUED = "future_issued"
REJECT_WRONG_SCOPE = "wrong_scope"
REJECT_WRONG_KIND = "wrong_kind"
REJECT_KEY_MISMATCH = "key_mismatch"

_ALLOWED_CLAIM_KEYS = frozenset({"kid", "kind", "scope", "key", "iat", "exp"})
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class Rm1Error(ValueError):
    """Base error for ``rm1`` token encoding, signing, or key validation."""


class UnsupportedCryptoError(RuntimeError):
    """Raised when Ed25519 signing/verification requires the optional ``cryptography`` extra."""


class Rm1VerificationError(Rm1Error):
    """Raised when ``rm1`` token verification fails, carrying Concert's reason code."""

    def __init__(self, reason: str, message: str | None = None) -> None:
        self.reason = reason
        super().__init__(message or f"rm1 token verification failed: {reason}")


@dataclass(frozen=True)
class TokenClaims:
    """Authenticated payload inside an ``rm1`` signed pass or lease token."""

    kid: str
    kind: str
    scope: str
    iat: int
    exp: int
    key: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize claims to canonical JSON-ready dict (omitting empty ``key``)."""
        data: dict[str, Any] = {
            "kid": self.kid,
            "kind": self.kind,
            "scope": self.scope,
        }
        if self.key:
            data["key"] = self.key
        data["iat"] = self.iat
        data["exp"] = self.exp
        return data


@dataclass(frozen=True)
class ParsedEnvelope:
    """Unverified parsed components of an ``rm1`` token envelope."""

    claims: TokenClaims
    signing_input: bytes
    signature: bytes


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode_strict(segment: str) -> bytes:
    """Decode strict unpadded base64url, rejecting padding or non-canonical bits."""
    if not segment or "=" in segment or not _B64URL_RE.match(segment):
        raise Rm1VerificationError(REJECT_MALFORMED, "invalid base64url segment")
    rem = len(segment) % 4
    if rem == 1:
        raise Rm1VerificationError(REJECT_MALFORMED, "invalid base64url length")
    padded = segment + ("=" * ((4 - rem) % 4))
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise Rm1VerificationError(REJECT_MALFORMED, "failed to decode base64url") from exc
    if _b64url_encode(raw) != segment:
        raise Rm1VerificationError(REJECT_MALFORMED, "non-canonical base64url encoding")
    return raw


def _validate_key_id(kid: str) -> None:
    if not isinstance(kid, str) or not kid:
        raise Rm1Error("key ID must not be empty")
    if len(kid.encode("utf-8")) > MAX_KEY_ID_LEN:
        raise Rm1Error(f"key ID exceeds {MAX_KEY_ID_LEN} bytes")
    if "\r" in kid or "\n" in kid or "\x00" in kid:
        raise Rm1Error("key ID contains control characters")


def _validate_scope(scope: str) -> None:
    if not isinstance(scope, str) or not scope:
        raise Rm1Error("scope must not be empty")
    if len(scope.encode("utf-8")) > MAX_SCOPE_LEN:
        raise Rm1Error(f"scope exceeds {MAX_SCOPE_LEN} bytes")
    if "\r" in scope or "\n" in scope or "\x00" in scope:
        raise Rm1Error("scope contains control characters")


def _validate_key_binding(key: str, *, required: bool) -> None:
    if not isinstance(key, str):
        raise Rm1Error("key must be a string")
    if required and not key:
        raise Rm1Error("lease tokens require a non-empty key binding")
    if key and ("\r" in key or "\n" in key or "\x00" in key or len(key.encode("utf-8")) > 256):
        raise Rm1Error("invalid token key binding")


def encode_claims(claims: TokenClaims) -> str:
    """Deterministically encode ``TokenClaims`` to compact JSON bytes and base64url."""
    _validate_key_id(claims.kid)
    _validate_scope(claims.scope)
    if claims.kind not in VALID_KINDS:
        raise Rm1Error(f"unknown token kind {claims.kind!r}")
    _validate_key_binding(claims.key, required=(claims.kind == KIND_LEASE))
    if isinstance(claims.iat, bool) or not isinstance(claims.iat, int) or claims.iat <= 0:
        raise Rm1Error("iat must be a positive integer Unix timestamp")
    if isinstance(claims.exp, bool) or not isinstance(claims.exp, int) or claims.exp <= claims.iat:
        raise Rm1Error("exp must be an integer Unix timestamp strictly greater than iat")
    raw_json = json.dumps(claims.to_dict(), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return _b64url_encode(raw_json)


def encode_signing_input(claims: TokenClaims) -> bytes:
    """Return the canonical ``rm1.<payload_b64>`` ASCII bytes signed by Ed25519."""
    payload_b64 = encode_claims(claims)
    return f"{TOKEN_WIRE_PREFIX}.{payload_b64}".encode("ascii")


def assemble_envelope(claims: TokenClaims, signature: bytes) -> str:
    """Combine claims and raw signature bytes into an ``rm1`` token string."""
    if not isinstance(signature, (bytes, bytearray)) or not signature:
        raise Rm1Error("signature must be non-empty bytes")
    signing_input = encode_signing_input(claims).decode("ascii")
    return f"{signing_input}.{_b64url_encode(bytes(signature))}"


def parse_envelope(token: str) -> ParsedEnvelope:
    """Pure-Python parser for an ``rm1`` token envelope (no cryptographic verification).

    Enforces strict envelope framing, strict unpadded base64url, strict JSON
    object decoding with zero unknown fields, and claim structural invariants.
    """
    if not isinstance(token, str) or not token or len(token) > MAX_SIGNED_TOKEN_LEN:
        raise Rm1VerificationError(REJECT_MALFORMED, "token empty or exceeds maximum length")

    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_WIRE_PREFIX or not parts[1] or not parts[2]:
        raise Rm1VerificationError(REJECT_MALFORMED, "invalid rm1 envelope framing")

    payload_b64, sig_b64 = parts[1], parts[2]
    payload_bytes = _b64url_decode_strict(payload_b64)
    sig_bytes = _b64url_decode_strict(sig_b64)
    if not sig_bytes:
        raise Rm1VerificationError(REJECT_MALFORMED, "empty signature")

    try:
        parsed = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Rm1VerificationError(REJECT_MALFORMED, "invalid JSON payload") from exc

    if not isinstance(parsed, dict):
        raise Rm1VerificationError(REJECT_MALFORMED, "claims payload must be a JSON object")

    unknown_keys = set(parsed.keys()) - _ALLOWED_CLAIM_KEYS
    if unknown_keys:
        raise Rm1VerificationError(REJECT_MALFORMED, "claims contain unknown fields")

    kid = parsed.get("kid")
    kind = parsed.get("kind")
    scope = parsed.get("scope")
    key = parsed.get("key", "")
    iat = parsed.get("iat")
    exp = parsed.get("exp")

    if not isinstance(kid, str) or not kid or len(kid.encode("utf-8")) > MAX_KEY_ID_LEN:
        raise Rm1VerificationError(REJECT_MALFORMED, "invalid kid claim")
    if not isinstance(scope, str) or not scope or len(scope.encode("utf-8")) > MAX_SCOPE_LEN:
        raise Rm1VerificationError(REJECT_MALFORMED, "invalid scope claim")
    if kind not in VALID_KINDS:
        raise Rm1VerificationError(REJECT_MALFORMED, "invalid kind claim")
    if not isinstance(key, str):
        raise Rm1VerificationError(REJECT_MALFORMED, "invalid key claim")
    if isinstance(iat, bool) or not isinstance(iat, int) or iat <= 0:
        raise Rm1VerificationError(REJECT_MALFORMED, "invalid iat claim")
    if isinstance(exp, bool) or not isinstance(exp, int) or exp <= iat:
        raise Rm1VerificationError(REJECT_MALFORMED, "invalid exp claim")

    claims = TokenClaims(kid=kid, kind=kind, scope=scope, iat=iat, exp=exp, key=key)
    signing_input = f"{TOKEN_WIRE_PREFIX}.{payload_b64}".encode("ascii")
    return ParsedEnvelope(claims=claims, signing_input=signing_input, signature=sig_bytes)


def decode_key_material(raw: bytes | bytearray | str, *, expected_lengths: tuple[int, ...]) -> bytes:
    """Decode raw bytes, hex, or base64url key material into exact-length bytes."""
    if isinstance(raw, (bytes, bytearray)):
        data = bytes(raw)
        if len(data) in expected_lengths:
            return data
        raise Rm1Error(f"invalid raw key length {len(data)}; expected one of {expected_lengths}")

    if not isinstance(raw, str):
        raise Rm1Error("key material must be bytes or string")
    text = raw.strip()
    if not text:
        raise Rm1Error("key material must not be empty")

    # Try hex first if length matches an expected byte length * 2.
    if _HEX_RE.match(text) and (len(text) // 2) in expected_lengths and len(text) % 2 == 0:
        return bytes.fromhex(text)

    # Try base64url / standard base64 (with or without padding).
    pad = "=" * ((4 - len(text) % 4) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            decoded = decoder((text + pad).encode("ascii"))
        except (ValueError, TypeError):
            continue
        if len(decoded) in expected_lengths:
            return decoded

    raise Rm1Error("key material is neither valid hex nor base64url of expected Ed25519 length")


def _load_ed25519_module(crypto_backend: Any | None = None) -> Any:
    if crypto_backend is not None:
        return crypto_backend
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # type: ignore[import-not-found]
    except ImportError as exc:
        raise UnsupportedCryptoError(
            "Ed25519 signing/verification requires the optional 'cryptography' package. "
            "Install it with: pip install 'concert-client[crypto]'"
        ) from exc
    return ed25519


class Ed25519Signer:
    """Signs ``rm1`` envelopes with an Ed25519 private key.

    Accepts a 32-byte Ed25519 seed, a 64-byte Go ``ed25519.PrivateKey``
    (``seed || pub``), or hex/base64url encoded seed/private key. Never exposes
    key material in ``str()`` or ``repr()``.
    """

    def __init__(
        self,
        key_id: str,
        private_key: bytes | bytearray | str | SecretBytes,
        *,
        crypto_backend: Any | None = None,
        sign_fn: Callable[[bytes], bytes] | None = None,
    ) -> None:
        _validate_key_id(key_id)
        self._key_id = key_id
        self._sign_fn = sign_fn
        self._crypto_backend = crypto_backend

        if isinstance(private_key, SecretBytes):
            raw = decode_key_material(
                private_key.reveal(),
                expected_lengths=(ED25519_SEED_SIZE, ED25519_PRIVATE_KEY_SIZE),
            )
        else:
            raw = decode_key_material(
                private_key,
                expected_lengths=(ED25519_SEED_SIZE, ED25519_PRIVATE_KEY_SIZE),
            )
        # Normalize 64-byte Go private key to its 32-byte RFC 8032 seed.
        self._seed = SecretBytes(raw[:ED25519_SEED_SIZE], name="ed25519 private seed")

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, signing_input: bytes) -> bytes:
        """Sign canonical ``rm1.<payload_b64>`` bytes and return the 64-byte Ed25519 signature."""
        if self._sign_fn is not None:
            sig = self._sign_fn(signing_input)
            if not isinstance(sig, (bytes, bytearray)) or len(sig) != ED25519_SIGNATURE_SIZE:
                raise Rm1Error("custom sign_fn must return a 64-byte signature")
            return bytes(sig)
        ed25519 = _load_ed25519_module(self._crypto_backend)
        key = ed25519.Ed25519PrivateKey.from_private_bytes(self._seed.reveal())
        return bytes(key.sign(signing_input))

    def public_key_bytes(self) -> bytes:
        """Derive and return the 32-byte raw Ed25519 public key."""
        ed25519 = _load_ed25519_module(self._crypto_backend)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # type: ignore[import-not-found]

        key = ed25519.Ed25519PrivateKey.from_private_bytes(self._seed.reveal())
        return bytes(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    def __repr__(self) -> str:
        return f"Ed25519Signer(key_id={self._key_id!r}, private_key={REDACTED})"

    def __str__(self) -> str:
        return repr(self)


class Ed25519Verifier:
    """Verifies ``rm1`` envelopes against a key ring of Ed25519 public keys.

    Supports zero-downtime key rotation via ``keys={kid: pubkey}`` where each
    public key may be raw 32 bytes, base64url, or hex (matching Concert's
    ``-room-verify-keys`` format).
    """

    def __init__(
        self,
        keys: Mapping[str, bytes | bytearray | str],
        *,
        crypto_backend: Any | None = None,
        verify_fn: Callable[[bytes, bytes, bytes], bool] | None = None,
    ) -> None:
        if not keys:
            raise Rm1Error("at least one verification public key is required")
        cleaned: dict[str, bytes] = {}
        for kid, pub in keys.items():
            _validate_key_id(kid)
            cleaned[kid] = decode_key_material(pub, expected_lengths=(ED25519_PUBLIC_KEY_SIZE,))
        self._keys = cleaned
        self._crypto_backend = crypto_backend
        self._verify_fn = verify_fn

    def verify_signature(self, key_id: str, signing_input: bytes, signature: bytes) -> None:
        """Verify raw Ed25519 signature bytes for ``key_id``."""
        pub = self._keys.get(key_id)
        if pub is None:
            raise Rm1VerificationError(REJECT_UNKNOWN_KEY, f"unknown key ID {key_id!r}")
        if len(signature) != ED25519_SIGNATURE_SIZE:
            raise Rm1VerificationError(REJECT_INVALID_SIGNATURE, "invalid Ed25519 signature length")

        if self._verify_fn is not None:
            if not self._verify_fn(pub, signing_input, signature):
                raise Rm1VerificationError(REJECT_INVALID_SIGNATURE, "invalid signature")
            return

        ed25519 = _load_ed25519_module(self._crypto_backend)
        pub_obj = ed25519.Ed25519PublicKey.from_public_bytes(pub)
        try:
            pub_obj.verify(signature, signing_input)
        except Exception as exc:  # cryptography.exceptions.InvalidSignature
            raise Rm1VerificationError(REJECT_INVALID_SIGNATURE, "invalid Ed25519 signature") from exc

    def verify(
        self,
        token: str,
        *,
        expected_scope: str,
        expected_kind: str = KIND_PASS,
        expected_key: str = "",
        now: int | None = None,
        max_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    ) -> TokenClaims:
        """Verify an ``rm1`` token in Concert/room's security-first order.

        1. Config preconditions (non-empty ``expected_scope``)
        2. Envelope framing & strict JSON decoding
        3. Cryptographic signature verification
        4. Scope, kind, and key binding checks
        5. Clock skew (``iat``) and expiration (``exp``)
        """
        if not expected_scope:
            raise Rm1VerificationError(REJECT_MISSING_SCOPE, "expected_scope must not be empty")
        if expected_kind not in VALID_KINDS:
            raise Rm1Error(f"unknown expected_kind {expected_kind!r}")

        env = parse_envelope(token)
        claims = env.claims

        # 3. Signature check before scope/expiry so forged tokens never masquerade as expired.
        self.verify_signature(claims.kid, env.signing_input, env.signature)

        # 4. Scope, kind, and key binding checks.
        if claims.scope != expected_scope:
            raise Rm1VerificationError(REJECT_WRONG_SCOPE, "token scope mismatch")
        if claims.kind != expected_kind:
            raise Rm1VerificationError(REJECT_WRONG_KIND, "token kind mismatch")
        if expected_kind == KIND_LEASE:
            if not claims.key:
                raise Rm1VerificationError(REJECT_MALFORMED, "lease token missing key binding")
            if claims.key != expected_key:
                raise Rm1VerificationError(REJECT_KEY_MISMATCH, "lease token key mismatch")
        elif claims.key and claims.key != expected_key:
            raise Rm1VerificationError(REJECT_KEY_MISMATCH, "pass token key mismatch")

        # 5. Clock skew and expiry.
        now_ts = int(time.time()) if now is None else int(now)
        if claims.iat > now_ts + max(0, int(max_skew_seconds)):
            raise Rm1VerificationError(REJECT_FUTURE_ISSUED, "token issued in the future")
        if now_ts >= claims.exp:
            raise Rm1VerificationError(REJECT_EXPIRED, "token expired")

        return claims


class TokenIssuer:
    """Standalone ``rm1`` pass and lease issuer bound to a scope and Ed25519Signer."""

    def __init__(
        self,
        scope: str,
        signer: Ed25519Signer,
        *,
        max_ttl_seconds: int = DEFAULT_MAX_TTL_SECONDS,
        clock: Callable[[], int] | None = None,
    ) -> None:
        _validate_scope(scope)
        if not isinstance(signer, Ed25519Signer):
            raise Rm1Error("signer must be an Ed25519Signer")
        if isinstance(max_ttl_seconds, bool) or not isinstance(max_ttl_seconds, int):
            raise Rm1Error("max_ttl_seconds must be an integer")
        if max_ttl_seconds < MIN_TTL_SECONDS or max_ttl_seconds > MAX_SIGNED_TTL_SECONDS:
            raise Rm1Error(
                f"max_ttl_seconds must be between {MIN_TTL_SECONDS} and {MAX_SIGNED_TTL_SECONDS}"
            )
        self._scope = scope
        self._signer = signer
        self._max_ttl = max_ttl_seconds
        self._clock = clock or (lambda: int(time.time()))

    @property
    def scope(self) -> str:
        return self._scope

    @property
    def max_ttl_seconds(self) -> int:
        return self._max_ttl

    def _mint(self, kind: str, key: str, ttl_seconds: int) -> str:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
            raise Rm1Error("ttl_seconds must be an integer")
        if ttl_seconds < MIN_TTL_SECONDS or ttl_seconds > self._max_ttl:
            raise Rm1Error(f"ttl_seconds must be between {MIN_TTL_SECONDS} and {self._max_ttl}")
        _validate_key_binding(key, required=(kind == KIND_LEASE))
        iat = int(self._clock())
        exp = iat + ttl_seconds
        claims = TokenClaims(
            kid=self._signer.key_id,
            kind=kind,
            scope=self._scope,
            key=key,
            iat=iat,
            exp=exp,
        )
        signing_input = encode_signing_input(claims)
        sig = self._signer.sign(signing_input)
        return assemble_envelope(claims, sig)

    def mint_pass(self, *, key: str = "", ttl_seconds: int = 300) -> str:
        """Mint a signed ``rm1`` VIP pass envelope (for ``X-Room-Pass``)."""
        return self._mint(KIND_PASS, key, ttl_seconds)

    def mint_lease(self, key: str, *, ttl_seconds: int = 300) -> str:
        """Mint a signed ``rm1`` key-bound lease envelope (for ``X-Room-Lease``)."""
        return self._mint(KIND_LEASE, key, ttl_seconds)


def sign_pass(
    *,
    scope: str,
    key_id: str,
    private_key: bytes | bytearray | str | SecretBytes,
    ttl_seconds: int = 300,
    key: str = "",
    now: int | None = None,
) -> str:
    """Convenience helper to mint a single ``rm1`` pass token."""
    signer = Ed25519Signer(key_id, private_key)
    issuer = TokenIssuer(
        scope,
        signer,
        max_ttl_seconds=MAX_SIGNED_TTL_SECONDS,
        clock=(lambda: int(now)) if now is not None else None,
    )
    return issuer.mint_pass(key=key, ttl_seconds=ttl_seconds)


def verify_pass(
    token: str,
    *,
    expected_scope: str,
    public_keys: Mapping[str, bytes | bytearray | str],
    expected_key: str = "",
    now: int | None = None,
    max_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS,
) -> TokenClaims:
    """Convenience helper to verify a single ``rm1`` pass token."""
    verifier = Ed25519Verifier(public_keys)
    return verifier.verify(
        token,
        expected_scope=expected_scope,
        expected_kind=KIND_PASS,
        expected_key=expected_key,
        now=now,
        max_skew_seconds=max_skew_seconds,
    )
