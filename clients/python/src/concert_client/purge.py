"""Authenticated Concert page-cache purge client (``POST /_room/cache/purge``).

Uses pure Python stdlib ``urllib.request`` with strict timeouts, TLS
verification enabled, bounded response reads, HTTPS-or-localhost enforcement,
and redacting credential storage (S1-S9).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import os
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import OpenerDirector, Request, build_opener, HTTPSHandler

from .secrets import REDACTED, SecretString, load_secret_from_env_or_file

PURGE_PATH = "/_room/cache/purge"
VALID_PURGE_MODES: tuple[str, ...] = ("url", "prefix", "tag", "all")
ENV_BASE_URL = "CONCERT_URL"
ENV_ADMIN_AUTH = "CONCERT_ADMIN_TOKEN"
ENV_ADMIN_AUTH_FILE = "CONCERT_ADMIN_TOKEN_FILE"

DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_TIMEOUT_SECONDS = 120.0
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024  # 64 KiB
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class CachePurgeError(RuntimeError):
    """Raised when a Concert cache purge request fails or returns an HTTP error."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        self.status_code = status_code
        super().__init__(message)


@dataclass(frozen=True)
class PurgeResult:
    """Response from ``POST /_room/cache/purge``."""

    purged: int
    mode: str


def _validate_base_url(base_url: str, *, allow_insecure_http: bool = False) -> str:
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("base_url must not be empty")
    raw = base_url.strip().rstrip("/")
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("base_url must use https:// (or http:// for loopback)")
    if not parsed.hostname:
        raise ValueError("base_url must include a host")
    if parsed.username or parsed.password:
        raise ValueError("base_url must not embed credentials (S4)")
    if scheme == "http" and not allow_insecure_http and parsed.hostname.lower() not in _LOOPBACK_HOSTS:
        raise ValueError(
            "insecure http:// base_url is restricted to localhost/loopback; "
            "use https:// or explicitly set allow_insecure_http=True"
        )
    return raw


def _read_bounded(stream: Any, limit: int) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise CachePurgeError(f"response body exceeded maximum allowed size ({limit} bytes)")
    return bytes(data)


class CachePurgeClient:
    """Client for Concert's authenticated ``POST /_room/cache/purge`` endpoint.

    Secrets are wrapped in :class:`SecretString` and never appear in ``repr()``,
    ``str()``, or error messages.
    """

    def __init__(
        self,
        base_url: str,
        token: str | SecretString,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        allow_insecure_http: bool = False,
        ssl_context: ssl.SSLContext | None = None,
        opener: OpenerDirector | None = None,
    ) -> None:
        self._base_url = _validate_base_url(base_url, allow_insecure_http=allow_insecure_http)
        self._token = token if isinstance(token, SecretString) else SecretString(token, name="admin token")

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

    @classmethod
    def from_env(
        cls,
        *,
        url_env: str = ENV_BASE_URL,
        token_env: str | None = None,
        token_file_env: str | None = None,
        environ: Mapping[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        allow_insecure_http: bool = False,
    ) -> CachePurgeClient:
        """Construct a client from environment variables / secret file (mode 0600)."""
        env = os.environ if environ is None else environ
        base_url = env.get(url_env, "").strip()
        if not base_url:
            raise ValueError(f"missing required environment variable: {url_env}")
        auth_var = ENV_ADMIN_AUTH if token_env is None else token_env
        auth_file_var = ENV_ADMIN_AUTH_FILE if token_file_env is None else token_file_env
        secret = load_secret_from_env_or_file(auth_var, auth_file_var, environ=env)
        return cls(
            base_url,
            secret,
            timeout=timeout,
            allow_insecure_http=allow_insecure_http,
        )

    @property
    def base_url(self) -> str:
        return self._base_url

    def purge(self, mode: str, *, target: str = "", host: str = "") -> PurgeResult:
        """Execute ``POST /_room/cache/purge`` for ``url``, ``prefix``, ``tag``, or ``all``."""
        if not isinstance(mode, str):
            raise ValueError("mode must be a string")
        norm_mode = mode.strip().lower()
        if norm_mode not in VALID_PURGE_MODES:
            raise ValueError(f"mode must be one of: {', '.join(VALID_PURGE_MODES)}")

        norm_target = target.strip() if isinstance(target, str) else ""
        norm_host = host.strip() if isinstance(host, str) else ""
        if norm_mode in ("url", "prefix", "tag") and not norm_target:
            raise ValueError(f"target is required for purge mode {norm_mode!r}")

        payload = json.dumps(
            {"mode": norm_mode, "host": norm_host, "target": norm_target},
            separators=(",", ":"),
        ).encode("utf-8")

        req = Request(
            url=f"{self._base_url}{PURGE_PATH}",
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._token.reveal()}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

        try:
            with self._opener.open(req, timeout=self._timeout) as resp:
                status = getattr(resp, "status", resp.getcode())
                raw_body = _read_bounded(resp, self._max_response_bytes)
        except HTTPError as exc:
            err_body = b""
            try:
                err_body = exc.read(min(self._max_response_bytes, 4096))
            except Exception:
                pass
            finally:
                try:
                    exc.close()
                except Exception:
                    pass
            detail = _extract_error_detail(err_body)
            raise CachePurgeError(
                f"cache purge failed with HTTP {exc.code}: {detail}",
                status_code=exc.code,
            ) from None
        except URLError as exc:
            raise CachePurgeError(f"cache purge transport error: {exc.reason}") from None

        if status < 200 or status >= 300:
            raise CachePurgeError(f"cache purge failed with HTTP {status}", status_code=status)

        try:
            parsed = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CachePurgeError("cache purge returned invalid JSON") from exc

        if not isinstance(parsed, dict) or not isinstance(parsed.get("purged"), int) or isinstance(parsed.get("purged"), bool):
            raise CachePurgeError("cache purge response missing integer 'purged' field")

        resp_mode = str(parsed.get("mode", norm_mode))
        return PurgeResult(purged=parsed["purged"], mode=resp_mode)

    def purge_url(self, url: str, *, host: str = "") -> PurgeResult:
        """Purge a single cached URL/path."""
        return self.purge("url", target=url, host=host)

    def purge_prefix(self, prefix: str, *, host: str = "") -> PurgeResult:
        """Purge all cached entries whose path begins with ``prefix``."""
        return self.purge("prefix", target=prefix, host=host)

    def purge_tag(self, tag: str, *, host: str = "") -> PurgeResult:
        """Purge all cached entries tagged with ``tag``."""
        return self.purge("tag", target=tag, host=host)

    def purge_all(self, *, host: str = "") -> PurgeResult:
        """Purge all cached entries (optionally scoped to ``host``)."""
        return self.purge("all", host=host)

    def __repr__(self) -> str:
        return (
            f"CachePurgeClient(base_url={self._base_url!r}, "
            f"token={REDACTED}, timeout={self._timeout!r})"
        )

    def __str__(self) -> str:
        return repr(self)


def _extract_error_detail(body: bytes) -> str:
    if not body:
        return "no error body"
    try:
        obj = json.loads(body.decode("utf-8"))
        if isinstance(obj, dict) and isinstance(obj.get("error"), str):
            return obj["error"][:256]
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    return "unexpected error response"
