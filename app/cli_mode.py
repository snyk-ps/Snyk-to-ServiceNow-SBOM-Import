"""SNYK_CLI run mode: upload an SBOM file produced by the Snyk CLI.

The user runs the Snyk CLI themselves to produce an SBOM file and passes its
path via ``--sbom-file-path``. This module validates that file and uploads it
directly to ServiceNow, reusing the existing upload client. No Snyk API calls,
discovery, scope, or file persistence occur in this mode.
"""

from __future__ import annotations

from pathlib import Path

from app.config import Config
from app.errors import AppError, ConfigError, ExitCode
from app.logging import get_logger
from app.servicenow_client import ServiceNowClient


def _validate_sbom_file(sbom_file_path: str | None) -> Path:
    """Validate the provided SBOM file path before any network call.

    Raises:
        ConfigError: if the path is missing, does not exist, is not a file, is
            empty, or is unreadable (exit code 1).
    """
    if not sbom_file_path:
        raise ConfigError(
            "SNYK_CLI mode requires --sbom-file-path.",
            operation="cli_mode",
            next_step="Provide the path to the Snyk CLI SBOM file: --sbom-file-path <file>.",
        )

    path = Path(sbom_file_path).expanduser()
    if not path.exists():
        raise ConfigError(
            f"SBOM file not found: {path}",
            operation="cli_mode",
            next_step="Provide an existing SBOM file path via --sbom-file-path.",
        )
    if not path.is_file():
        raise ConfigError(
            f"SBOM path is not a file: {path}",
            operation="cli_mode",
            next_step="Provide a path to a regular SBOM file, not a directory.",
        )
    try:
        size = path.stat().st_size
        with path.open("rb"):
            pass
    except OSError as exc:
        raise ConfigError(
            f"SBOM file is not readable: {path}",
            operation="cli_mode",
            parsed_message=str(exc),
            next_step="Verify file permissions for the SBOM file.",
        ) from exc
    if size == 0:
        raise ConfigError(
            f"SBOM file is empty: {path}",
            operation="cli_mode",
            next_step="Provide a non-empty SBOM file produced by the Snyk CLI.",
        )
    return path


def run_cli_upload(config: Config, sbom_file_path: str | None) -> int:
    """Validate and upload a Snyk CLI SBOM file to ServiceNow.

    Returns a process exit code (0 success, 1 config, 2 auth, 4 upload).
    """
    logger = get_logger()
    path = _validate_sbom_file(sbom_file_path)

    if config.api_dry_run:
        logger.warning("API_DRY_RUN is ignored in SNYK_CLI mode; proceeding with upload.")

    logger.info("Uploading Snyk CLI SBOM file: %s", path)
    try:
        ServiceNowClient(config).upload_sbom(path)
    except AppError as exc:
        logger.error("%s\n%s", exc.__class__.__name__, exc.format_report())
        return exc.exit_code

    logger.info("Complete: SBOM %s uploaded to ServiceNow.", path)
    return ExitCode.SUCCESS
