"""Variable-level debugging helpers with centralized secret redaction.

This module is the single place where redaction happens. The HTTP wrapper and
all call sites route values through :func:`redact_value` / :func:`redact_headers`
before logging so secret values never appear in output at any level.
"""

from __future__ import annotations

import pprint
from collections.abc import Mapping, Sequence, Set
from typing import Any

from app.logging import TRACE, get_logger

MASK = "*" * 12

_SECRET_NAME_PATTERNS: tuple[str, ...] = (
    "token",
    "password",
    "passwd",
    "authorization",
    "auth",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "bearer",
)

_SUMMARY_TYPES = (Mapping, Set)


def _is_secret_name(name: str) -> bool:
    lowered = name.lower()
    return any(pattern in lowered for pattern in _SECRET_NAME_PATTERNS)


def redact_value(name: str, value: Any) -> Any:
    """Return a redacted representation of ``value`` if ``name`` looks secret.

    For an ``Authorization`` style header we preserve the scheme (e.g. ``Bearer``)
    and mask the credential so logs remain useful without leaking secrets.
    """
    if not _is_secret_name(name):
        return value

    if isinstance(value, str):
        parts = value.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() in {"bearer", "token", "basic"}:
            return f"{parts[0]} {MASK}"
    return MASK


def redact_headers(headers: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a copy of ``headers`` with sensitive values masked."""
    if not headers:
        return {}
    return {key: redact_value(key, val) for key, val in headers.items()}


def _summarize(value: Any) -> str:
    """Produce a concise summary for collections and large scalars."""
    if isinstance(value, (bytes, bytearray)):
        return f"<{type(value).__name__} {len(value)} bytes>"
    if isinstance(value, str):
        if len(value) > 120:
            return f"<str len={len(value)}> {value[:100]!r}..."
        return repr(value)
    if isinstance(value, Mapping):
        return f"<dict keys={len(value)}: {sorted(map(str, value.keys()))}>"
    if isinstance(value, Set):
        return f"<{type(value).__name__} size={len(value)}>"
    if isinstance(value, Sequence):
        return f"<{type(value).__name__} len={len(value)}>"
    return repr(value)


def log_variable(name: str, value: Any) -> None:
    """Log a named variable at DEBUG level, redacted and summarized.

    - Secret-looking names are masked.
    - Collections and large values are summarized rather than dumped whole.
    """
    logger = get_logger()
    if not logger.isEnabledFor(10):  # logging.DEBUG
        return

    if _is_secret_name(name):
        rendered = redact_value(name, value if isinstance(value, str) else MASK)
        if not isinstance(value, str):
            rendered = MASK
    else:
        rendered = _summarize(value)
    logger.debug("%s: %s", name, rendered)


def log_object(value: Any, *, name: str | None = None) -> None:
    """Pretty-print an object at TRACE level.

    Mappings have secret-looking keys redacted before printing.
    """
    logger = get_logger()
    if not logger.isEnabledFor(TRACE):
        return

    to_print: Any = value
    if isinstance(value, Mapping):
        to_print = {key: redact_value(str(key), val) for key, val in value.items()}
    rendered = pprint.pformat(to_print, indent=2, width=100, sort_dicts=True)
    if name:
        logger.trace("%s:\n%s", name, rendered)  # type: ignore[attr-defined]
    else:
        logger.trace("%s", rendered)  # type: ignore[attr-defined]
