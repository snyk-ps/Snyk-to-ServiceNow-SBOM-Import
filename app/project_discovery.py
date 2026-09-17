"""Discover Snyk projects for the configured processing scope.

Uses the Snyk REST API (versioned, paginated) via the shared HTTP wrapper. The
functions here only enumerate resources; SBOM generation/upload is unchanged and
handled by the existing workflow.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from app.config import Config
from app.errors import AuthError, HttpError, SbomGenerationError
from app.logging import get_logger
from app.utils import debug, http

_PAGE_LIMIT = 100
_MAX_PAGES = 1000  # safety valve against pathological pagination loops


@dataclass(frozen=True)
class Project:
    """A discovered Snyk project."""

    org_id: str
    target_id: str
    project_id: str
    name: str


@dataclass(frozen=True)
class Target:
    """A discovered Snyk target."""

    target_id: str
    name: str


def _headers(config: Config) -> dict[str, str]:
    return {
        "Authorization": f"token {config.snyk_api_token}",
        "Accept": "application/vnd.api+json",
    }


def _api_host(config: Config) -> str:
    parts = urlsplit(config.snyk_base_url)
    return f"{parts.scheme}://{parts.netloc}"


def _next_url(host: str, links: Any) -> str | None:
    """Resolve the ``links.next`` cursor (relative or absolute) to a full URL."""
    if not isinstance(links, dict):
        return None
    nxt = links.get("next")
    if not nxt or not isinstance(nxt, str):
        return None
    if nxt.startswith("http://") or nxt.startswith("https://"):
        return nxt
    return host + ("" if nxt.startswith("/") else "/") + nxt


def _paginate(config: Config, path: str, params: dict[str, str], operation: str) -> list[dict]:
    """Fetch every page of a Snyk REST list endpoint, returning all data items.

    Args:
        path: Path appended to the configured base URL for the first request
            (e.g. ``/orgs/<org>/projects``).
        params: Query parameters for the first request; subsequent pages follow
            the ``links.next`` cursor which already carries its own query.

    Raises:
        AuthError: on 401/403 (fatal).
        SbomGenerationError: on other discovery HTTP or parsing failures.
    """
    logger = get_logger()
    host = _api_host(config)
    base = config.snyk_base_url.rstrip("/")
    url: str | None = f"{base}{path}"
    first_params: dict[str, str] | None = dict(params)

    items: list[dict] = []
    pages = 0
    while url and pages < _MAX_PAGES:
        pages += 1
        try:
            resp = http.request(
                "GET",
                url,
                operation=operation,
                headers=_headers(config),
                params=first_params,
                timeout=config.http_timeout_seconds,
                verify=config.tls_verify,
            )
            payload = resp.json()
        except HttpError as exc:
            if exc.status in (401, 403):
                raise AuthError(
                    "Snyk authentication failed during discovery.",
                    operation=exc.operation or operation,
                    url=exc.url or url,
                    status=exc.status,
                    parsed_message=exc.parsed_message,
                    next_step="Verify SNYK_API_TOKEN and that it can access SNYK_ORG_ID.",
                ) from exc
            raise SbomGenerationError(
                "Failed to enumerate Snyk resources.",
                operation=exc.operation or operation,
                url=exc.url or url,
                status=exc.status,
                parsed_message=exc.parsed_message,
                next_step="Verify SNYK_ORG_ID / SNYK_TARGET_ID and the Snyk REST API version.",
            ) from exc

        data = payload.get("data", []) if isinstance(payload, dict) else []
        if isinstance(data, list):
            items.extend(d for d in data if isinstance(d, dict))

        url = _next_url(host, payload.get("links") if isinstance(payload, dict) else None)
        first_params = None  # the next link already includes query params

    logger.debug("Discovery %s returned %d item(s) over %d page(s)", operation, len(items), pages)
    return items


def _project_from_item(config: Config, item: dict) -> Project:
    attrs = item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {}
    project_id = str(item.get("id", ""))
    name = str(attrs.get("name") or project_id)

    target_id = ""
    rels = item.get("relationships")
    if isinstance(rels, dict):
        target = rels.get("target")
        if isinstance(target, dict):
            tdata = target.get("data")
            if isinstance(tdata, dict):
                target_id = str(tdata.get("id", ""))

    return Project(
        org_id=config.snyk_org_id,
        target_id=target_id or config.snyk_target_id,
        project_id=project_id,
        name=name,
    )


def discover_project(config: Config) -> list[Project]:
    """Return exactly the single configured project (no API call)."""
    return [
        Project(
            org_id=config.snyk_org_id,
            target_id=config.snyk_target_id,
            project_id=config.snyk_project_id,
            name=config.snyk_project_id,
        )
    ]


def _project_list_params(config: Config, *, target_id: str | None = None) -> dict[str, str]:
    params: dict[str, str] = {"limit": str(_PAGE_LIMIT)}
    if config.snyk_rest_api_version:
        params["version"] = config.snyk_rest_api_version
    if target_id:
        params["target_id"] = target_id
    return params


def discover_projects_for_target(config: Config) -> list[Project]:
    """Enumerate every project associated with ``SNYK_TARGET_ID``."""
    debug.log_variable("SNYK_TARGET_ID", config.snyk_target_id)
    items = _paginate(
        config,
        f"/orgs/{config.snyk_org_id}/projects",
        _project_list_params(config, target_id=config.snyk_target_id),
        operation="snyk.discover_projects_for_target",
    )
    return [_project_from_item(config, i) for i in items]


def discover_projects_for_org(config: Config) -> list[Project]:
    """Enumerate every project across all targets in ``SNYK_ORG_ID``."""
    items = _paginate(
        config,
        f"/orgs/{config.snyk_org_id}/projects",
        _project_list_params(config),
        operation="snyk.discover_projects_for_org",
    )
    return [_project_from_item(config, i) for i in items]


def discover_targets(config: Config) -> list[Target]:
    """Enumerate every target in ``SNYK_ORG_ID`` (used for summary counts)."""
    params: dict[str, str] = {"limit": str(_PAGE_LIMIT)}
    if config.snyk_rest_api_version:
        params["version"] = config.snyk_rest_api_version
    items = _paginate(
        config,
        f"/orgs/{config.snyk_org_id}/targets",
        params,
        operation="snyk.discover_targets",
    )
    targets: list[Target] = []
    for item in items:
        attrs = item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {}
        name = str(attrs.get("display_name") or attrs.get("displayName") or attrs.get("url") or item.get("id", ""))
        targets.append(Target(target_id=str(item.get("id", "")), name=name))
    return targets
