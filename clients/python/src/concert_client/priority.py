"""Concert-Priority header validation and ASGI (FastAPI) / WSGI (Flask) middleware."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Iterable, Mapping
from typing import Any

PRIORITY_HEADER = "Concert-Priority"
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 86400

# Ranks ordered lowest to highest, matching Concert's internal/server/priority.go.
ALL_RANKS: tuple[str, ...] = (
    "guest",
    "member",
    "prospect",
    "customer",
    "subscriber",
    "checkout",
    "staff",
)

# Non-guest ranks that elevate a visitor in the queue or priority lane.
GRANT_RANKS: tuple[str, ...] = (
    "member",
    "prospect",
    "customer",
    "subscriber",
    "checkout",
    "staff",
)

_RANK_ORDER: dict[str, int] = {rank: idx for idx, rank in enumerate(ALL_RANKS)}


class InvalidPriorityRankError(ValueError):
    """Raised when a Concert-Priority rank or TTL is invalid."""


def validate_rank(rank: str) -> str:
    """Normalize and validate a Concert priority rank.

    Accepts ``guest``, ``member``, ``prospect``, ``customer``, ``subscriber``,
    ``checkout``, and ``staff`` (case-insensitive, trimmed).
    """
    if not isinstance(rank, str):
        raise InvalidPriorityRankError("Concert priority rank must be a string")
    normalized = rank.strip().lower()
    if normalized not in _RANK_ORDER:
        allowed = ", ".join(ALL_RANKS)
        raise InvalidPriorityRankError(
            f"unknown Concert priority rank {rank!r}; expected one of: {allowed}"
        )
    return normalized


def highest_rank(facts: Mapping[str, Any]) -> str:
    """Return the highest Concert rank whose boolean fact is truthy, or ``guest``."""
    for rank in reversed(ALL_RANKS[1:]):
        if facts.get(rank):
            return rank
    return "guest"


def format_priority_header(rank: str, ttl_seconds: int | None = None) -> str:
    """Build a validated ``Concert-Priority`` header value.

    For non-guest ranks, ``ttl_seconds`` (when provided) is validated as an
    integer and clamped to Concert's ``[60, 86400]`` second bounds.
    """
    normalized = validate_rank(rank)
    if ttl_seconds is None or normalized == "guest":
        return normalized
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise InvalidPriorityRankError("ttl_seconds must be an integer")
    if ttl_seconds <= 0:
        raise InvalidPriorityRankError("ttl_seconds must be positive")
    clamped = max(MIN_TTL_SECONDS, min(MAX_TTL_SECONDS, ttl_seconds))
    return f"{normalized}; ttl={clamped}"


def _coerce_resolved_priority(
    result: str | tuple[str, int | None] | None,
    default_ttl: int | None,
) -> str | None:
    if result is None:
        return None
    if isinstance(result, tuple):
        if len(result) != 2:
            raise InvalidPriorityRankError("priority resolver tuple must be (rank, ttl_seconds)")
        rank, ttl = result
        return format_priority_header(rank, ttl if ttl is not None else default_ttl)
    return format_priority_header(result, default_ttl)


ASGIResolver = Callable[
    [Mapping[str, Any]],
    str | tuple[str, int | None] | None | Awaitable[str | tuple[str, int | None] | None],
]


class ConcertPriorityASGIMiddleware:
    """Pure-ASGI middleware for FastAPI, Starlette, Quart, or Litestar.

    Calls ``resolver(scope)`` (sync or async) for each HTTP request and injects
    a validated ``Concert-Priority`` response header on ``http.response.start``.
    Concert strips ``Concert-Priority`` before forwarding responses to browsers
    and binds the rank to a signed ``concert_priority`` cookie.
    """

    def __init__(
        self,
        app: Callable[..., Awaitable[Any]],
        resolver: ASGIResolver,
        *,
        default_ttl: int | None = None,
    ) -> None:
        if default_ttl is not None and (isinstance(default_ttl, bool) or not isinstance(default_ttl, int) or default_ttl <= 0):
            raise InvalidPriorityRankError("default_ttl must be a positive integer")
        self.app = app
        self.resolver = resolver
        self.default_ttl = default_ttl

    async def __call__(
        self,
        scope: Mapping[str, Any],
        receive: Callable[[], Awaitable[Mapping[str, Any]]],
        send: Callable[[Mapping[str, Any]], Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        resolved = self.resolver(scope)
        if inspect.isawaitable(resolved):
            resolved = await resolved
        header_value = _coerce_resolved_priority(resolved, self.default_ttl)
        if header_value is None:
            await self.app(scope, receive, send)
            return

        header_bytes = header_value.encode("ascii")
        header_key_lower = PRIORITY_HEADER.lower().encode("ascii")

        async def send_wrapper(message: Mapping[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                raw_headers = list(message.get("headers", []))
                filtered = [
                    (k, v) for (k, v) in raw_headers if k.lower() != header_key_lower
                ]
                filtered.append((header_key_lower, header_bytes))
                updated = dict(message)
                updated["headers"] = filtered
                await send(updated)
                return
            await send(message)

        await self.app(scope, receive, send_wrapper)


WSGIResolver = Callable[[Mapping[str, Any]], str | tuple[str, int | None] | None]


class ConcertPriorityWSGIMiddleware:
    """Pure-WSGI middleware for Flask, Django WSGI, Bottle, or Pyramid.

    Calls ``resolver(environ)`` and attaches a validated ``Concert-Priority``
    header when the WSGI application invokes ``start_response``.
    """

    def __init__(
        self,
        app: Callable[..., Iterable[bytes]],
        resolver: WSGIResolver,
        *,
        default_ttl: int | None = None,
    ) -> None:
        if default_ttl is not None and (isinstance(default_ttl, bool) or not isinstance(default_ttl, int) or default_ttl <= 0):
            raise InvalidPriorityRankError("default_ttl must be a positive integer")
        self.app = app
        self.resolver = resolver
        self.default_ttl = default_ttl

    def __call__(
        self,
        environ: Mapping[str, Any],
        start_response: Callable[..., Any],
    ) -> Iterable[bytes]:
        header_value = _coerce_resolved_priority(self.resolver(environ), self.default_ttl)
        if header_value is None:
            return self.app(environ, start_response)

        def wrapped_start_response(
            status: str,
            headers: list[tuple[str, str]],
            exc_info: Any = None,
        ) -> Any:
            filtered = [
                (k, v) for (k, v) in headers if k.lower() != PRIORITY_HEADER.lower()
            ]
            filtered.append((PRIORITY_HEADER, header_value))
            return start_response(status, filtered, exc_info)

        return self.app(environ, wrapped_start_response)


def set_priority_header(
    headers: Any,
    rank: str,
    *,
    ttl_seconds: int | None = None,
) -> str:
    """Set ``Concert-Priority`` on any mutable response headers mapping (e.g. Flask/FastAPI).

    Returns the formatted header value written.
    """
    value = format_priority_header(rank, ttl_seconds)
    headers[PRIORITY_HEADER] = value
    return value
