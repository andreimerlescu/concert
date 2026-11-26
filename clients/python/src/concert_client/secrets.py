"""Secret-handling redacting wrappers for Concert Python SDK (S1-S8)."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Mapping

REDACTED = "[REDACTED]"


class SecretError(ValueError):
    """Raised when a required secret is missing, empty, or insecurely stored."""


class SecretString:
    """Redacting wrapper for string credentials (e.g. Bearer admin tokens).

    ``str()``, ``repr()``, and ``format()`` always return ``[REDACTED]``.
    Call :meth:`reveal` only at the single point of outbound use.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str, *, name: str = "secret") -> None:
        if not isinstance(value, str):
            raise SecretError(f"{name} must be a string")
        cleaned = value.strip()
        if not cleaned:
            raise SecretError(f"{name} must not be empty")
        if "\r" in cleaned or "\n" in cleaned or "\x00" in cleaned:
            raise SecretError(f"{name} contains forbidden control characters")
        self._value = cleaned

    def reveal(self) -> str:
        """Return the raw secret value for outbound request construction."""
        return self._value

    def __str__(self) -> str:
        return REDACTED

    def __repr__(self) -> str:
        return f"SecretString({REDACTED})"

    def __format__(self, format_spec: str) -> str:
        return REDACTED

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return True


class SecretBytes:
    """Redacting wrapper for binary key material (e.g. Ed25519 private keys)."""

    __slots__ = ("_value",)

    def __init__(self, value: bytes | bytearray, *, name: str = "secret key") -> None:
        if not isinstance(value, (bytes, bytearray)):
            raise SecretError(f"{name} must be bytes")
        raw = bytes(value)
        if not raw:
            raise SecretError(f"{name} must not be empty")
        self._value = raw

    def reveal(self) -> bytes:
        """Return a copy of the raw secret bytes."""
        return bytes(self._value)

    def __str__(self) -> str:
        return REDACTED

    def __repr__(self) -> str:
        return f"SecretBytes({REDACTED})"

    def __format__(self, format_spec: str) -> str:
        return REDACTED

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return True


def load_secret_from_file(path: str | os.PathLike[str], *, name: str = "secret") -> SecretString:
    """Read a secret from a file, enforcing mode 0600 or stricter on POSIX."""
    p = Path(path)
    if not p.is_file():
        raise SecretError(f"{name} file not found: {p}")
    if os.name == "posix":
        st = p.stat()
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o077:
            raise SecretError(
                f"{name} file {p} has overly permissive mode {oct(mode)}; expected 0600 or stricter"
            )
    try:
        data = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise SecretError(f"failed to read {name} file {p}: {exc}") from exc
    return SecretString(data, name=name)


def load_secret_from_env_or_file(
    env_var: str,
    file_env_var: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> SecretString:
    """Load a secret from ``file_env_var`` (preferred) or ``env_var``, failing closed."""
    env = os.environ if environ is None else environ
    file_path = env.get(file_env_var, "").strip()
    if file_path:
        return load_secret_from_file(file_path, name=file_env_var)
    raw = env.get(env_var, "")
    if raw.strip():
        return SecretString(raw, name=env_var)
    raise SecretError(f"missing required secret: set {file_env_var} or {env_var}")
