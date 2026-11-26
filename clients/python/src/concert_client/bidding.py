"""100% Crypto-Only AI Agent Pass Bidding client for Concert.

Supported settlement chains ONLY: ``xrpl``, ``stellar``, ``hedera``, ``solana``.
Concert is strictly crypto-only (zero fiat rails).

Features:
- Parses Concert ``429 Too Many Requests`` waiting-room auction offers.
- Enforces strict exact-integer ``max_bid_micro_usd`` spend caps (no binary float).
- Posts non-custodial signed payment authorizations to ``POST /_concert/bids``.
- Polls ``GET /_concert/bids/status?bid_id=...`` until terminal outcome
  (winners settle on-chain and receive signed pass credentials; losers pay $0).
- Enforces same-origin URL validation (S9 SSRF defense), bounded reads, strict
  timeouts, and secret redaction (S5/S6).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
import ssl
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import HTTPSHandler, OpenerDirector, Request, build_opener

from .secrets import REDACTED, SecretString

SUPPORTED_CHAINS: tuple[str, ...] = ("xrpl", "stellar", "hedera", "solana")
_SUPPORTED_CHAIN_SET = frozenset(SUPPORTED_CHAINS)

DEFAULT_BID_PATH = "/_concert/bids"
DEFAULT_STATUS_PATH = "/_concert/bids/status"

MODE_INSTANT = "instant"
MODE_AUCTION = "auction"

STATUS_PENDING = "pending"
STATUS_WON = "won"
STATUS_LOST = "lost"
STATUS_REJECTED = "rejected"
STATUS_SETTLED = "settled"
STATUS_SETTLEMENT_FAILED = "settlement_failed"
TERMINAL_STATUSES = frozenset(
    {STATUS_WON, STATUS_LOST, STATUS_REJECTED, STATUS_SETTLED, STATUS_SETTLEMENT_FAILED}
)

DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_TIMEOUT_SECONDS = 120.0
DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024  # 1 MiB
MAX_MICRO_USD = (1 << 63) - 1
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class BiddingError(RuntimeError):
    """Base error for Concert AI agent bidding operations."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        self.status_code = status_code
        super().__init__(message)


class UnsupportedChainError(ValueError):
    """Raised when a chain is outside Concert's crypto-only allowlist."""


class BidCapExceededError(ValueError):
    """Raised when a bid or auction floor exceeds ``max_bid_micro_usd``."""


class CrossOriginError(ValueError):
    """Raised when an auction ``bid_url`` or ``status_url`` leaves Concert's origin (S9)."""


def normalize_chain(chain: str) -> str:
    """Validate and normalize a Concert crypto settlement chain."""
    if not isinstance(chain, str):
        raise UnsupportedChainError("chain must be a string")
    norm = chain.strip().lower()
    if norm not in _SUPPORTED_CHAIN_SET:
        allowed = ", ".join(SUPPORTED_CHAINS)
        raise UnsupportedChainError(
            f"unsupported chain {chain!r}; Concert is 100% crypto-only and accepts only: {allowed}"
        )
    return norm


def parse_usd_to_micro_usd(raw: str) -> int:
    """Convert a positive decimal USD string (up to 6 decimal places) into exact integer micro-USD."""
    if not isinstance(raw, str):
        raise ValueError("USD amount must be a string")
    s = raw.strip()
    if not s or s[0] in ("+", "-"):
        raise ValueError("USD amount must be strictly positive")
    if s.count(".") > 1:
        raise ValueError("USD amount contains multiple decimal points")
    if "." in s:
        int_part, frac_part = s.split(".", 1)
    else:
        int_part, frac_part = s, ""
    if not int_part and not frac_part:
        raise ValueError("USD amount must not be empty")
    if not int_part:
        int_part = "0"
    if len(frac_part) > 6:
        if frac_part[6:].rstrip("0"):
            raise ValueError("USD amount supports at most 6 fractional digits")
        frac_part = frac_part[:6]
    frac_part = frac_part.ljust(6, "0")
    digits = int_part + frac_part
    if not digits.isdigit():
        raise ValueError("USD amount contains non-digit characters")
    value = int(digits)
    if value <= 0 or value > MAX_MICRO_USD:
        raise ValueError("USD amount must be positive and within int64 micro-USD bounds")
    return value


def format_micro_usd(micro_usd: int) -> str:
    """Render an exact integer micro-USD value as a USD string (e.g. ``1500000 -> '$1.50'``)."""
    if isinstance(micro_usd, bool) or not isinstance(micro_usd, int) or micro_usd <= 0:
        return "$0.00"
    dollars = micro_usd // 1_000_000
    frac = f"{micro_usd % 1_000_000:06d}"
    trimmed = frac.rstrip("0")
    if len(trimmed) < 2:
        trimmed = frac[:2]
    return f"${dollars}.{trimmed}"


def _validate_base_url(base_url: str, *, allow_insecure_http: bool = False) -> str:
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("base_url must not be empty")
    raw = base_url.strip().rstrip("/")
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("base_url must be a valid http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("base_url must not embed credentials (S4)")
    if scheme == "http" and not allow_insecure_http and parsed.hostname.lower() not in _LOOPBACK_HOSTS:
        raise ValueError("insecure http:// base_url is restricted to localhost/loopback")
    return raw


def resolve_same_origin_url(base_url: str, candidate: str) -> str:
    """Resolve ``candidate`` against ``base_url`` and verify exact scheme/host/port match (S9)."""
    if not isinstance(candidate, str) or not candidate.strip():
        raise CrossOriginError("URL must not be empty")
    cand = candidate.strip()
    if "\r" in cand or "\n" in cand or "\x00" in cand:
        raise CrossOriginError("URL contains control characters")
    base = urlparse(base_url)
    resolved = urlparse(urljoin(base_url + "/", cand))
    if resolved.scheme.lower() != base.scheme.lower() or resolved.netloc.lower() != base.netloc.lower():
        raise CrossOriginError(
            f"auction URL origin {resolved.scheme}://{resolved.netloc} does not match Concert origin {base.scheme}://{base.netloc}"
        )
    if resolved.username or resolved.password:
        raise CrossOriginError("auction URL must not embed credentials")
    return resolved.geturl()


@dataclass(frozen=True)
class AuctionOffer:
    """Parsed auction offer from a Concert ``429`` queued agent response."""

    mode: str
    scope: str
    floor_micro_usd: int
    slots: int
    bid_url: str
    status_url: str
    supported_chains: tuple[str, ...]
    auction_id: str = ""
    closes_at: str = ""
    min_wait_seconds: int = 0


@dataclass(frozen=True)
class BidStatusResponse:
    """Normalized response from ``POST /_concert/bids`` or ``GET /_concert/bids/status``."""

    bid_id: str
    status: str
    pass_issued: bool = False
    pass_token: str = ""
    priority_pass: str = ""
    pass_cookie: str = ""
    session: str = ""
    transaction: str = ""
    reason: str = ""
    status_url: str = ""
    set_cookies: tuple[str, ...] = ()

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    @property
    def settled(self) -> bool:
        return self.status == STATUS_SETTLED

    def __repr__(self) -> str:
        return (
            f"BidStatusResponse(bid_id={self.bid_id!r}, status={self.status!r}, "
            f"pass_issued={self.pass_issued!r}, transaction={self.transaction!r}, "
            f"pass_token={REDACTED if self.pass_token else ''!r})"
        )


def parse_auction_offer(
    payload: bytes | str | Mapping[str, Any],
    *,
    status_code: int = 429,
) -> AuctionOffer | None:
    """Parse an :class:`AuctionOffer` from a Concert ``429`` JSON waiting-room response.

    Returns ``None`` when ``status_code != 429`` or the response carries no
    ``auction`` block. Filters ``supported_chains`` strictly to Concert's
    crypto-only chains (``xrpl``, ``stellar``, ``hedera``, ``solana``).
    """
    if status_code != 429:
        return None
    if isinstance(payload, (bytes, bytearray)):
        try:
            obj = json.loads(bytes(payload).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BiddingError("invalid JSON in 429 auction response") from exc
    elif isinstance(payload, str):
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise BiddingError("invalid JSON in 429 auction response") from exc
    elif isinstance(payload, Mapping):
        obj = dict(payload)
    else:
        raise BiddingError("unsupported 429 payload type")

    if not isinstance(obj, dict):
        return None
    raw_offer = obj.get("auction") if "auction" in obj else (obj if "floor_micro_usd" in obj else None)
    if not isinstance(raw_offer, dict):
        return None

    mode = str(raw_offer.get("mode", "")).strip().lower()
    if mode not in (MODE_INSTANT, MODE_AUCTION):
        raise BiddingError(f"unsupported auction offer mode {mode!r}")

    floor = raw_offer.get("floor_micro_usd")
    if isinstance(floor, bool) or not isinstance(floor, int) or floor <= 0:
        raise BiddingError("auction offer missing positive integer floor_micro_usd")

    raw_chains = raw_offer.get("supported_chains", [])
    if not isinstance(raw_chains, list):
        raise BiddingError("auction offer supported_chains must be a list")
    chains: list[str] = []
    for item in raw_chains:
        if isinstance(item, str):
            low = item.strip().lower()
            if low in _SUPPORTED_CHAIN_SET and low not in chains:
                chains.append(low)

    slots = raw_offer.get("slots", 1)
    if isinstance(slots, bool) or not isinstance(slots, int) or slots < 0:
        slots = 1
    min_wait = raw_offer.get("min_wait_seconds", 0)
    if isinstance(min_wait, bool) or not isinstance(min_wait, int) or min_wait < 0:
        min_wait = 0

    return AuctionOffer(
        mode=mode,
        auction_id=str(raw_offer.get("auction_id", "")),
        scope=str(raw_offer.get("scope", "")),
        floor_micro_usd=floor,
        closes_at=str(raw_offer.get("closes_at", "")),
        slots=slots,
        min_wait_seconds=min_wait,
        bid_url=str(raw_offer.get("bid_url", DEFAULT_BID_PATH)) or DEFAULT_BID_PATH,
        status_url=str(raw_offer.get("status_url", DEFAULT_STATUS_PATH)) or DEFAULT_STATUS_PATH,
        supported_chains=tuple(chains),
    )


def _read_bounded(stream: Any, limit: int) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise BiddingError(f"bidding response exceeded maximum size ({limit} bytes)")
    return bytes(data)


class AgentBidClient:
    """Crypto-only AI agent bidding client for Concert.

    Enforces a strict positive ``max_bid_micro_usd`` spend cap and allows only
    Concert's supported crypto chains (``xrpl``, ``stellar``, ``hedera``,
    ``solana``).
    """

    def __init__(
        self,
        base_url: str,
        *,
        max_bid_micro_usd: int,
        chain: str,
        asset: str = "",
        session_id: str | SecretString | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        allow_insecure_http: bool = False,
        ssl_context: ssl.SSLContext | None = None,
        opener: OpenerDirector | None = None,
    ) -> None:
        self._base_url = _validate_base_url(base_url, allow_insecure_http=allow_insecure_http)
        if isinstance(max_bid_micro_usd, bool) or not isinstance(max_bid_micro_usd, int) or max_bid_micro_usd <= 0 or max_bid_micro_usd > MAX_MICRO_USD:
            raise ValueError("max_bid_micro_usd must be a positive integer within int64 bounds")
        self._max_bid_micro_usd = max_bid_micro_usd
        self._chain = normalize_chain(chain)
        self._asset = asset.strip() if isinstance(asset, str) else ""
        if session_id is None:
            self._session_id: SecretString | None = None
        elif isinstance(session_id, SecretString):
            self._session_id = session_id
        else:
            self._session_id = SecretString(session_id, name="session_id")

        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > MAX_TIMEOUT_SECONDS:
            raise ValueError(f"timeout must be between 0 and {MAX_TIMEOUT_SECONDS} seconds")
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or max_response_bytes < 256:
            raise ValueError("max_response_bytes must be an integer >= 256")

        self._timeout = float(timeout)
        self._max_response_bytes = max_response_bytes
        if opener is not None:
            self._opener = opener
        else:
            ctx = ssl_context if ssl_context is not None else ssl.create_default_context()
            self._opener = build_opener(HTTPSHandler(context=ctx))

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def max_bid_micro_usd(self) -> int:
        return self._max_bid_micro_usd

    @property
    def chain(self) -> str:
        return self._chain

    @property
    def asset(self) -> str:
        return self._asset

    def evaluate_offer(self, offer: AuctionOffer) -> int | None:
        """Decide the micro-USD bid amount for ``offer``, or ``None`` to keep waiting.

        Never exceeds ``self.max_bid_micro_usd`` and returns ``None`` if the
        offer's floor exceeds the cap or does not support ``self.chain``.
        """
        if self._chain not in offer.supported_chains:
            return None
        if offer.floor_micro_usd > self._max_bid_micro_usd:
            return None
        if offer.mode == MODE_INSTANT:
            return offer.floor_micro_usd
        return self._max_bid_micro_usd

    def submit_bid(
        self,
        *,
        bid_micro_usd: int,
        amount_atomic: str,
        payment_payload: Mapping[str, Any] | bytes | str,
        chain: str | None = None,
        asset: str | None = None,
        scope: str = "",
        auction_id: str = "",
        bid_id: str = "",
        agent_key: str = "",
        bid_url: str = DEFAULT_BID_PATH,
    ) -> BidStatusResponse:
        """Post a signed crypto bid to ``POST /_concert/bids``.

        Strictly enforces ``bid_micro_usd <= max_bid_micro_usd``, crypto-only
        chain validation, and same-origin ``bid_url`` checks. ``payment_payload``
        is treated as sensitive signed material and never logged or echoed in
        error messages.
        """
        if isinstance(bid_micro_usd, bool) or not isinstance(bid_micro_usd, int) or bid_micro_usd <= 0:
            raise ValueError("bid_micro_usd must be a positive integer")
        if bid_micro_usd > self._max_bid_micro_usd:
            raise BidCapExceededError(
                f"bid {format_micro_usd(bid_micro_usd)} exceeds configured max_bid_micro_usd "
                f"({format_micro_usd(self._max_bid_micro_usd)})"
            )

        active_chain = normalize_chain(self._chain if chain is None else chain)
        active_asset = (self._asset if asset is None else asset).strip()
        if not isinstance(amount_atomic, str) or not amount_atomic.strip().isdigit() or int(amount_atomic.strip()) <= 0:
            raise ValueError("amount_atomic must be a positive integer string")

        parsed_payload = _coerce_payment_payload(payment_payload)
        target_url = resolve_same_origin_url(self._base_url, bid_url)

        body: dict[str, Any] = {
            "chain": active_chain,
            "asset": active_asset,
            "amount_atomic": amount_atomic.strip(),
            "bid_micro_usd": bid_micro_usd,
            "payment_payload": parsed_payload,
        }
        if bid_id:
            body["bid_id"] = bid_id.strip()
        if auction_id:
            body["auction_id"] = auction_id.strip()
        if scope:
            body["scope"] = scope.strip()
        if agent_key:
            body["agent_key"] = agent_key.strip()

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self._session_id is not None:
            headers["Concert-Session"] = self._session_id.reveal()

        req = Request(
            url=target_url,
            data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers=headers,
        )
        return self._execute_bid_request(req)

    def get_bid_status(
        self,
        bid_id: str,
        *,
        status_url: str = DEFAULT_STATUS_PATH,
    ) -> BidStatusResponse:
        """Query ``GET /_concert/bids/status?bid_id=<id>``."""
        if not isinstance(bid_id, str) or not bid_id.strip():
            raise ValueError("bid_id must not be empty")
        base_status = resolve_same_origin_url(self._base_url, status_url)
        sep = "&" if "?" in base_status else "?"
        full_url = f"{base_status}{sep}{urlencode({'bid_id': bid_id.strip()})}"

        headers = {"Accept": "application/json"}
        if self._session_id is not None:
            headers["Concert-Session"] = self._session_id.reveal()

        req = Request(url=full_url, method="GET", headers=headers)
        return self._execute_bid_request(req)

    def poll_bid_status(
        self,
        bid_id: str,
        *,
        status_url: str = DEFAULT_STATUS_PATH,
        poll_interval: float = 1.0,
        max_attempts: int = 30,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> BidStatusResponse:
        """Poll ``GET /_concert/bids/status`` until a terminal bid status is reached."""
        if max_attempts < 1 or max_attempts > 300:
            raise ValueError("max_attempts must be between 1 and 300")
        clamped_interval = max(0.05, min(30.0, float(poll_interval)))

        last = self.get_bid_status(bid_id, status_url=status_url)
        for _ in range(max_attempts - 1):
            if last.is_terminal:
                return last
            sleep_fn(clamped_interval)
            last = self.get_bid_status(bid_id, status_url=status_url)
        return last

    def _execute_bid_request(self, req: Request) -> BidStatusResponse:
        try:
            with self._opener.open(req, timeout=self._timeout) as resp:
                status = getattr(resp, "status", resp.getcode())
                raw_body = _read_bounded(resp, self._max_response_bytes)
                set_cookies = tuple(resp.headers.get_all("Set-Cookie") or ())
        except HTTPError as exc:
            try:
                detail = _extract_safe_error(exc, self._max_response_bytes)
            finally:
                try:
                    exc.close()
                except Exception:
                    pass
            raise BiddingError(
                f"bidding request failed with HTTP {exc.code}: {detail}",
                status_code=exc.code,
            ) from None
        except URLError as exc:
            raise BiddingError(f"bidding transport error: {exc.reason}") from None

        if status not in (200, 202):
            raise BiddingError(f"unexpected HTTP status {status} from bidding endpoint", status_code=status)

        try:
            data = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BiddingError("bidding endpoint returned invalid JSON") from exc

        if not isinstance(data, dict):
            raise BiddingError("bidding endpoint returned non-object JSON")

        bid_obj = data.get("bid") if isinstance(data.get("bid"), dict) else {}
        bid_id = str(data.get("bid_id") or bid_obj.get("bid_id") or "")
        bid_status = str(data.get("status") or bid_obj.get("status") or "")
        transaction = str(data.get("transaction") or bid_obj.get("transaction") or "")
        reason = str(data.get("reason") or bid_obj.get("reason") or "")
        return BidStatusResponse(
            bid_id=bid_id,
            status=bid_status,
            pass_issued=bool(data.get("pass_issued", False)),
            pass_token=str(data.get("pass_token", "")),
            priority_pass=str(data.get("priority_pass", "")),
            pass_cookie=str(data.get("pass_cookie", "")),
            session=str(data.get("session", "")),
            transaction=transaction,
            reason=reason,
            status_url=str(data.get("status_url", "")),
            set_cookies=set_cookies,
        )

    def __repr__(self) -> str:
        sess = REDACTED if self._session_id is not None else None
        return (
            f"AgentBidClient(base_url={self._base_url!r}, chain={self._chain!r}, "
            f"max_bid_micro_usd={self._max_bid_micro_usd!r}, session_id={sess!r})"
        )

    def __str__(self) -> str:
        return repr(self)


def _coerce_payment_payload(payload: Mapping[str, Any] | bytes | str) -> Any:
    if isinstance(payload, Mapping):
        if not payload:
            raise ValueError("payment_payload must not be empty")
        return dict(payload)
    if isinstance(payload, (bytes, bytearray)):
        raw = bytes(payload)
        if not raw:
            raise ValueError("payment_payload must not be empty")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("payment_payload bytes must be valid JSON") from exc
    if isinstance(payload, str):
        if not payload.strip():
            raise ValueError("payment_payload must not be empty")
        try:
            return json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("payment_payload string must be valid JSON") from exc
    raise ValueError("payment_payload must be a mapping, JSON string, or UTF-8 JSON bytes")


def _extract_safe_error(exc: HTTPError, limit: int) -> str:
    try:
        raw = exc.read(min(limit, 4096))
        obj = json.loads(raw.decode("utf-8"))
        if isinstance(obj, dict) and isinstance(obj.get("error"), str):
            return obj["error"][:256]
    except Exception:
        pass
    return "request rejected"
