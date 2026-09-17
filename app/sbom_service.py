"""Coordinates the generate -> persist -> upload workflow."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app import sbom_file
from app.config import Config
from app.logging import get_logger
from app.servicenow_client import ServiceNowClient
from app.snyk_client import SbomDocument, SnykClient


@dataclass
class RunResult:
    """Outcome of a full run."""

    document: SbomDocument
    sbom_path: Path
    uploaded: bool
    skipped_reason: str | None = None
    response: dict | None = None


class SbomService:
    """Orchestrates SBOM export from Snyk and upload to ServiceNow."""

    def __init__(
        self,
        config: Config,
        snyk_client: SnykClient | None = None,
        servicenow_client: ServiceNowClient | None = None,
    ) -> None:
        self._config = config
        self._logger = get_logger()
        self._snyk = snyk_client or SnykClient(config)
        self._servicenow = servicenow_client or ServiceNowClient(config)

    def run(self) -> RunResult:
        """Generate the SBOM, persist it to a file, then upload it (unless dry-run)."""
        document = self._snyk.generate_sbom()
        sbom_path = sbom_file.write_sbom(document, self._config.snyk_project_id)

        if self._config.api_dry_run:
            reason = "API_DRY_RUN enabled: skipping ServiceNow upload."
            self._logger.info(reason)
            return RunResult(
                document=document,
                sbom_path=sbom_path,
                uploaded=False,
                skipped_reason=reason,
            )

        response = self._servicenow.upload_sbom(sbom_path)
        return RunResult(
            document=document,
            sbom_path=sbom_path,
            uploaded=True,
            response=response,
        )
