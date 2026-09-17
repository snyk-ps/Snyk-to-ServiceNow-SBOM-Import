"""Validation helpers for configuration and API responses."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

_TRUTHY = {"true", "1", "yes", "on", "y", "t"}


def parse_bool(value: str | None, *, default: bool = False) -> bool:
    """Parse a truthy string (case-insensitive) into a bool."""
    if value is None:
        return default
    return value.strip().lower() in _TRUTHY


def missing_keys(source: Mapping[str, str | None], required: Iterable[str]) -> list[str]:
    """Return the required keys that are absent or empty in ``source``."""
    missing: list[str] = []
    for key in required:
        val = source.get(key)
        if val is None or str(val).strip() == "":
            missing.append(key)
    return missing


def is_nonempty_bytes(data: Any) -> bool:
    """True if ``data`` is a non-empty bytes-like or string payload."""
    if isinstance(data, (bytes, bytearray)):
        return len(data) > 0
    if isinstance(data, str):
        return len(data.strip()) > 0
    return False
