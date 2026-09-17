"""Load, validate, and expose runtime configuration.

Configuration is sourced from the process environment, with a ``.env`` file
loaded as a fallback (process environment takes precedence). All required
variables are validated before any network operation is attempted.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

from dotenv import dotenv_values

from app.errors import ConfigError
from app.utils.validators import missing_keys, parse_bool

# Run mode: how the SBOM is obtained.
MODE_API: Final[str] = "SNYK_API"
MODE_CLI: Final[str] = "SNYK_CLI"
VALID_RUN_MODES: Final[tuple[str, ...]] = (MODE_API, MODE_CLI)
DEFAULT_RUN_MODE: Final[str] = MODE_API

# Processing scope: how many Snyk projects a single run covers (API mode only).
SCOPE_PROJECT: Final[str] = "SNYK_PROJECT"
SCOPE_TARGET: Final[str] = "SNYK_TARGET"
SCOPE_ORG: Final[str] = "SNYK_ORG"
VALID_SCOPES: Final[tuple[str, ...]] = (SCOPE_PROJECT, SCOPE_TARGET, SCOPE_ORG)
DEFAULT_SCOPE: Final[str] = SCOPE_PROJECT

# ServiceNow variables are required in every run mode (they are the upload target).
SNOW_REQUIRED_VARS: Final[tuple[str, ...]] = (
    "SNOW_INSTANCE_SUBDOMAIN",
    "SNOW_ACCESS_TOKEN",
    "SNOW_BUSINESS_APPLICATION_ID",
)

# Snyk API variables are required only in SNYK_API mode.
API_REQUIRED_VARS: Final[tuple[str, ...]] = (
    "SNYK_API_TOKEN",
    "SNYK_ORG_ID",
)

# Additional Snyk identifiers required per scope (SNYK_API mode only).
SCOPE_REQUIRED_VARS: Final[dict[str, tuple[str, ...]]] = {
    SCOPE_PROJECT: ("SNYK_TARGET_ID", "SNYK_PROJECT_ID"),
    SCOPE_TARGET: ("SNYK_TARGET_ID",),
    SCOPE_ORG: (),
}

DEFAULT_SBOM_FORMAT: Final[str] = "cyclonedx1.6+json"
DEFAULT_SNYK_BASE_URL: Final[str] = "https://api.snyk.io/rest"
DEFAULT_DEBUG_LEVEL: Final[str] = "INFO"
DEFAULT_HTTP_TIMEOUT: Final[float] = 60.0

# Values copied straight from .env.example still carry this prefix. Running with
# them almost always means the .env was not filled in (or not saved), so we fail
# fast with a clear message instead of emitting a confusing upstream 404/401.
PLACEHOLDER_PREFIX: Final[str] = "MY_"


@dataclass(frozen=True)
class Config:
    """Immutable runtime configuration."""

    snyk_api_token: str
    snyk_org_id: str
    snyk_target_id: str
    snyk_project_id: str
    snyk_base_url: str
    snyk_rest_api_version: str | None
    snyk_sbom_format: str

    snow_instance_subdomain: str
    snow_access_token: str
    snow_business_application_id: str
    snow_application_scope: str

    run_mode: str

    debug_level: str
    api_dry_run: bool
    http_timeout_seconds: float

    ssl_verify: bool
    ca_bundle: str | None

    @property
    def snow_base_url(self) -> str:
        return f"https://{self.snow_instance_subdomain}.service-now.com"

    @property
    def sbom_source(self) -> str:
        """The ServiceNow ``sbomSource`` query value for the current run mode."""
        return "SnykCLI" if self.run_mode == MODE_CLI else "SnykAPI"

    @property
    def tls_verify(self) -> bool | str:
        """The value to pass to ``requests`` as ``verify``.

        A CA bundle path takes precedence; otherwise a boolean toggle. TLS
        verification defaults to on (and uses the OS trust store when enabled
        via :mod:`app.tls`).
        """
        if self.ca_bundle:
            return self.ca_bundle
        return self.ssl_verify


def _merged_env() -> dict[str, str | None]:
    """Merge ``.env`` values with the process environment (env wins)."""
    merged: dict[str, str | None] = dict(dotenv_values())
    for key, value in os.environ.items():
        merged[key] = value
    return merged


def _get(source: dict[str, str | None], key: str, default: str | None = None) -> str | None:
    value = source.get(key)
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip()


def load_config() -> Config:
    """Load configuration, validating required variables and applying defaults.

    Raises:
        ConfigError: if any required variable is missing/empty or a numeric
            option cannot be parsed.
    """
    source = _merged_env()

    run_mode = (_get(source, "RUN_MODE", DEFAULT_RUN_MODE) or DEFAULT_RUN_MODE).upper()
    if run_mode not in VALID_RUN_MODES:
        raise ConfigError(
            f"Invalid RUN_MODE: {run_mode!r}.",
            operation="load_config",
            next_step="Set RUN_MODE to one of: " + ", ".join(VALID_RUN_MODES) + ".",
        )

    scope = (_get(source, "SNOW_APPLICATION_SCOPE", DEFAULT_SCOPE) or DEFAULT_SCOPE).upper()
    if scope not in VALID_SCOPES:
        raise ConfigError(
            f"Invalid SNOW_APPLICATION_SCOPE: {scope!r}.",
            operation="load_config",
            next_step="Set SNOW_APPLICATION_SCOPE to one of: " + ", ".join(VALID_SCOPES) + ".",
        )

    # ServiceNow variables are always required; Snyk API + scope variables are
    # only required in SNYK_API mode (SNYK_CLI uploads a provided file instead).
    required = SNOW_REQUIRED_VARS
    if run_mode == MODE_API:
        required = required + API_REQUIRED_VARS + SCOPE_REQUIRED_VARS[scope]
    missing = missing_keys(source, required)
    if missing:
        raise ConfigError(
            f"Missing required configuration variable(s) for RUN_MODE {run_mode}"
            + (f" / scope {scope}" if run_mode == MODE_API else "")
            + ": " + ", ".join(missing),
            operation="load_config",
            next_step=(
                "Set the listed variable(s) in your .env file or environment. "
                "See .env.example for the full list."
            ),
        )

    timeout_raw = _get(source, "HTTP_TIMEOUT_SECONDS")
    try:
        http_timeout = float(timeout_raw) if timeout_raw else DEFAULT_HTTP_TIMEOUT
    except ValueError as exc:
        raise ConfigError(
            f"HTTP_TIMEOUT_SECONDS must be a number, got: {timeout_raw!r}",
            operation="load_config",
            next_step="Set HTTP_TIMEOUT_SECONDS to a numeric value (seconds).",
        ) from exc

    config = Config(
        snyk_api_token=_get(source, "SNYK_API_TOKEN") or "",
        snyk_org_id=_get(source, "SNYK_ORG_ID") or "",
        snyk_target_id=_get(source, "SNYK_TARGET_ID") or "",
        snyk_project_id=_get(source, "SNYK_PROJECT_ID") or "",
        snyk_base_url=_get(source, "SNYK_BASE_URL", DEFAULT_SNYK_BASE_URL) or DEFAULT_SNYK_BASE_URL,
        snyk_rest_api_version=_get(source, "SNYK_REST_API_VERSION"),
        snyk_sbom_format=_get(source, "SNYK_SBOM_FORMAT", DEFAULT_SBOM_FORMAT) or DEFAULT_SBOM_FORMAT,
        snow_instance_subdomain=_get(source, "SNOW_INSTANCE_SUBDOMAIN") or "",
        snow_access_token=_get(source, "SNOW_ACCESS_TOKEN") or "",
        snow_business_application_id=_get(source, "SNOW_BUSINESS_APPLICATION_ID") or "",
        snow_application_scope=scope,
        run_mode=run_mode,
        debug_level=_get(source, "DEBUG_LEVEL", DEFAULT_DEBUG_LEVEL) or DEFAULT_DEBUG_LEVEL,
        api_dry_run=parse_bool(_get(source, "API_DRY_RUN"), default=False),
        http_timeout_seconds=http_timeout,
        ssl_verify=parse_bool(_get(source, "SSL_VERIFY"), default=True),
        ca_bundle=_get(source, "CA_BUNDLE"),
    )

    _reject_placeholders(config)
    return config


def _reject_placeholders(config: Config) -> None:
    """Fail fast when configuration still holds ``.env.example`` placeholders.

    Only variables actually used by the current run mode are checked: the Snyk
    API credentials (and scope identifiers) are checked only in SNYK_API mode,
    while the ServiceNow credentials are checked whenever an upload will occur
    (always in CLI mode; in API mode unless it is a dry run).
    """
    checks: list[tuple[str, str]] = []
    if config.run_mode == MODE_API:
        checks.extend(
            [
                ("SNYK_API_TOKEN", config.snyk_api_token),
                ("SNYK_ORG_ID", config.snyk_org_id),
            ]
        )
        scope_vars = {
            "SNYK_TARGET_ID": config.snyk_target_id,
            "SNYK_PROJECT_ID": config.snyk_project_id,
        }
        for name in SCOPE_REQUIRED_VARS[config.snow_application_scope]:
            checks.append((name, scope_vars[name]))

    upload_will_happen = not (config.run_mode == MODE_API and config.api_dry_run)
    if upload_will_happen:
        checks.extend(
            [
                ("SNOW_INSTANCE_SUBDOMAIN", config.snow_instance_subdomain),
                ("SNOW_ACCESS_TOKEN", config.snow_access_token),
                ("SNOW_BUSINESS_APPLICATION_ID", config.snow_business_application_id),
            ]
        )

    placeholders = [name for name, value in checks if value.startswith(PLACEHOLDER_PREFIX)]
    if placeholders:
        raise ConfigError(
            "Configuration still contains placeholder value(s): " + ", ".join(placeholders),
            operation="load_config",
            next_step=(
                "Replace the placeholder(s) in your .env with real values and SAVE the file. "
                "Unsaved editor changes are not read from disk."
            ),
        )
