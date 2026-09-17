"""Reusable HTTP wrapper.

Provides a single ``request`` entry point that applies a timeout, records
timing, logs request/response detail (with redacted headers), and translates
transport errors and non-2xx responses into a standardized :class:`HttpError`.

Retry/backoff and correlation IDs are intentionally deferred; hook points are
noted in the code and the design doc.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import requests

from app.errors import HttpError
from app.logging import get_logger
from app.utils import debug


@dataclass
class HttpResponse:
    """Normalized HTTP response returned by :func:`request`."""

    status: int
    headers: dict[str, str]
    content: bytes
    url: str
    elapsed_ms: float

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        """Parse the body as JSON, raising ``HttpError`` on malformed content."""
        import json as _json

        try:
            return _json.loads(self.content.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise HttpError(
                "Malformed response body (expected JSON).",
                url=self.url,
                status=self.status,
                parsed_message=str(exc),
                next_step="Verify the endpoint returns JSON and the API version is correct.",
            ) from exc


def _parse_error_message(content: bytes) -> str | None:
    """Best-effort extraction of an error message from a response body."""
    import json as _json

    try:
        payload = _json.loads(content.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        text = content.decode("utf-8", errors="replace").strip()
        return text[:500] or None

    if isinstance(payload, Mapping):
        for key in ("error", "message", "detail", "title"):
            if key in payload and payload[key]:
                return str(payload[key])
        if "errors" in payload and payload["errors"]:
            return str(payload["errors"])
    return None


def request(
    method: str,
    url: str,
    *,
    operation: str,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | None = None,
    data: bytes | str | None = None,
    json_body: Any = None,
    timeout: float = 60.0,
    verify: bool | str = True,
) -> HttpResponse:
    """Perform an HTTP request and return a normalized response.

    Args:
        verify: Passed through to ``requests`` — ``True``/``False`` or a path to
            a CA bundle. TLS verification uses the OS trust store when it has
            been enabled via :mod:`app.tls`.

    Raises:
        HttpError: on transport failure, timeout, or a non-2xx status.
    """
    logger = get_logger()
    logger.debug("HTTP %s %s", method.upper(), url)
    debug.log_variable("Request Headers", debug.redact_headers(headers))
    if params:
        debug.log_variable("Query Params", dict(params))
    # TRACE: full request detail (body redaction is the caller's responsibility
    # for secret payloads; SBOM bodies are not secret).
    logger.trace("Request body bytes: %s", len(data) if data else 0)  # type: ignore[attr-defined]

    start = time.perf_counter()
    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=dict(headers) if headers else None,
            params=dict(params) if params else None,
            data=data,
            json=json_body,
            timeout=timeout,
            verify=verify,
        )
    except requests.Timeout as exc:
        raise HttpError(
            "Request timed out.",
            operation=operation,
            url=url,
            parsed_message=str(exc),
            next_step=f"Increase HTTP_TIMEOUT_SECONDS (current {timeout}s) or check connectivity.",
        ) from exc
    except requests.RequestException as exc:
        raise HttpError(
            "HTTP transport error.",
            operation=operation,
            url=url,
            parsed_message=str(exc),
            next_step="Verify network connectivity and the target URL.",
        ) from exc

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    normalized = HttpResponse(
        status=resp.status_code,
        headers=dict(resp.headers),
        content=resp.content,
        url=resp.url,
        elapsed_ms=elapsed_ms,
    )

    logger.debug("HTTP %s -> %s (%.1f ms)", method.upper(), resp.status_code, elapsed_ms)
    debug.log_variable("Response Headers", normalized.headers)
    logger.trace("Response body:\n%s", normalized.text[:2000])  # type: ignore[attr-defined]

    if not (200 <= resp.status_code < 300):
        raise HttpError(
            f"HTTP request failed with status {resp.status_code}.",
            operation=operation,
            url=normalized.url,
            status=resp.status_code,
            parsed_message=_parse_error_message(normalized.content),
            next_step="Inspect the status and detail above; verify credentials and request shape.",
        )

    return normalized
