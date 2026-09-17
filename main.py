"""Entrypoint: export an SBOM from Snyk and upload it to ServiceNow.

Usage:
    python main.py

All configuration comes from environment variables / a .env file. See
.env.example for the full list. Exit codes:

    0  Success
    1  Configuration Error
    2  Authentication Failure
    3  SBOM Generation Failure
    4  ServiceNow Upload Failure
    5  Unexpected Exception
"""

from __future__ import annotations

import argparse
import sys

from app import __version__
from app.cli_mode import run_cli_upload
from app.config import MODE_CLI, load_config
from app.errors import AppError, ExitCode
from app.logging import configure_logging
from app.scope_manager import run_scope
from app.tls import enable_system_trust


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="snyk_sbom_to_servicenow",
        description="Export a Snyk SBOM (API mode) or upload a Snyk CLI SBOM file, "
        "then push it to ServiceNow.",
    )
    parser.add_argument(
        "--sbom-file-path",
        dest="sbom_file_path",
        default=None,
        help="Path to the SBOM file to upload (required when RUN_MODE=SNYK_CLI).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser.parse_args(argv)


def run(argv: list[str] | None = None) -> int:
    """Execute the full workflow and return a process exit code."""
    args = _parse_args(argv)

    # Bootstrap logging at INFO until config tells us the desired level.
    logger = configure_logging("INFO")

    try:
        config = load_config()
    except AppError as exc:
        logger.error("Configuration error:\n%s", exc.format_report())
        return exc.exit_code

    logger = configure_logging(config.debug_level)
    if config.ssl_verify and not config.ca_bundle:
        enable_system_trust()

    try:
        if config.run_mode == MODE_CLI:
            logger.info("Starting SBOM upload (mode=SNYK_CLI)")
            return run_cli_upload(config, args.sbom_file_path)

        logger.info(
            "Starting SBOM export (mode=SNYK_API, scope=%s, org=%s, format=%s, api_dry_run=%s)",
            config.snow_application_scope,
            config.snyk_org_id,
            config.snyk_sbom_format,
            config.api_dry_run,
        )
        summary = run_scope(config)
    except AppError as exc:
        logger.error("%s\n%s", exc.__class__.__name__, exc.format_report())
        return exc.exit_code
    except Exception as exc:  # noqa: BLE001 - map any unexpected error to code 5
        logger.exception("Unexpected error: %s", exc)
        return ExitCode.UNEXPECTED

    return summary.exit_code


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
