"""Parser for Concert waiting-room signal headers.

Concert attaches machine-readable waiting-room headers ONLY to queued responses
(never to guard rejections, capacity-breaker 503s, or upstream 503s):

- ``X-Concert-Queue``: ``1`` when the visitor/client is queued in the waiting room.
- ``X-Concert-Position``: non-negative integer queue position (when known).
- ``Retry-After``: integer delay in seconds (or RFC 7231 HTTP-date).
- ``X-Concert-Status-Url``: custom queue status endpoint when non-default
  (omitted by Concert when using the default ``/queue/status``).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import math
from urllib.parse import urlparse

HEADER_QUEUE = "X-Concert-Queue"
HEADER_POSITION = "X-Concert-Position"
HEADER_RETRY_AFTER = "Retry-After"
HEADER_STATUS_URL = "X-Concert-Status-Url"
DEFAULT_STATUS_URL = "/queue/status"

_MAX_URL_LENGTH = 2048


@dataclass(frozen=True)
class WaitingRoomSignal:
    """Structured view of Concert waiting-room headers from an HTTP response."""

    queued: bool
    position: int | None = None
    retry_after: int | None = None
    status_url: str | None = None

    @property
    def effective_status_url(self) -> str:
        """Return explicit ``X-Concert-Status-Url`` or Concert's default ``/queue/status``."""
        return self.status_url or DEFAULT_STATUS_URL


def _normalize_headers(
    headers: Mapping[str, str] | Iterable[tuple[str | bytes, str | bytes]],
) -> dict[str, str]:
    normalized: dict[str, str] = {}
    items = headers.items() if isinstance(headers, Mapping) else headers
    for raw_k, raw_v in items:
        k = raw_k.decode("latin-1") if isinstance(raw_k, bytes) else str(raw_k)
        v = raw_v.decode("latin-1") if isinstance(raw_v, bytes) else str(raw_v)
        normalized[k.strip().lower()] = v.strip()
    return normalized


def _parse_non_negative_int(value: str | None) -> int | None:
    if not value:
        return None
    if value.isdigit():
        return int(value)
    return None


def _parse_retry_after(value: str | None, *, now: datetime | None = None) -> int | None:
    if not value:
        return None
    if value.isdigit():
        return int(value)
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    ref = datetime.now(timezone.utc) if now is None else now
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    delta = (dt - ref).total_seconds()
    return max(0, int(math.ceil(delta)))


def _sanitize_status_url(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) > _MAX_URL_LENGTH or "\r" in value or "\n" in value or "\x00" in value:
        return None
    if value.startswith("/") and not value.startswith("//"):
        return value
    parsed = urlparse(value)
    if parsed.scheme.lower() in ("http", "https") and parsed.netloc:
        return value
    return None


def parse_waiting_room_headers(
    headers: Mapping[str, str] | Iterable[tuple[str | bytes, str | bytes]],
    *,
    now: datetime | None = None,
) -> WaitingRoomSignal:
    """Parse Concert waiting-room signal headers from any mapping or header pairs."""
    norm = _normalize_headers(headers)
    raw_queue = norm.get(HEADER_QUEUE.lower(), "").lower()
    queued = raw_queue in ("1", "true")
    position = _parse_non_negative_int(norm.get(HEADER_POSITION.lower()))
    retry_after = _parse_retry_after(norm.get(HEADER_RETRY_AFTER.lower()), now=now)
    status_url = _sanitize_status_url(norm.get(HEADER_STATUS_URL.lower()))
    return WaitingRoomSignal(
        queued=queued,
        position=position,
        retry_after=retry_after,
        status_url=status_url,
    )


def is_queued(
    headers: Mapping[str, str] | Iterable[tuple[str | bytes, str | bytes]],
) -> bool:
    """Return ``True`` when the response carries ``X-Concert-Queue: 1``."""
    return parse_waiting_room_headers(headers).queued
