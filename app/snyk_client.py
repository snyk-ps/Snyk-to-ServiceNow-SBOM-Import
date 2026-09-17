"""Snyk REST API client for SBOM generation."""

from __future__ import annotations

from dataclasses import dataclass

from app.config import Config
from app.errors import AuthError, HttpError, SbomGenerationError, SbomUnsupportedError
from app.logging import get_logger
from app.utils import debug, http
from app.utils.validators import is_nonempty_bytes


@dataclass
class SbomDocument:
    """A generated SBOM held in memory for upload."""

    content: bytes
    content_type: str
    sbom_format: str

    @property
    def size(self) -> int:
        return len(self.content)


class SnykClient:
    """Thin client over the Snyk REST SBOM endpoint."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._logger = get_logger()

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"token {self._config.snyk_api_token}",
            "Accept": "application/vnd.api+json",
        }

    def _sbom_url(self) -> str:
        base = self._config.snyk_base_url.rstrip("/")
        return (
            f"{base}/orgs/{self._config.snyk_org_id}"
            f"/projects/{self._config.snyk_project_id}/sbom"
        )

    def generate_sbom(self) -> SbomDocument:
        """Generate an SBOM for the configured project.

        Raises:
            AuthError: on 401/403 from Snyk.
            SbomGenerationError: on other failures or an empty/malformed body.
        """
        url = self._sbom_url()
        params: dict[str, str] = {"format": self._config.snyk_sbom_format}
        if self._config.snyk_rest_api_version:
            params["version"] = self._config.snyk_rest_api_version

        self._logger.info("Generating SBOM")
        debug.log_variable("SNYK_ORG_ID", self._config.snyk_org_id)
        debug.log_variable("SNYK_PROJECT_ID", self._config.snyk_project_id)
        debug.log_variable("SBOM_FORMAT", self._config.snyk_sbom_format)

        try:
            resp = http.request(
                "GET",
                url,
                operation="snyk.generate_sbom",
                headers=self._headers(),
                params=params,
                timeout=self._config.http_timeout_seconds,
                verify=self._config.tls_verify,
            )
        except HttpError as exc:
            if exc.status in (401, 403):
                raise AuthError(
                    "Snyk authentication failed.",
                    operation=exc.operation,
                    url=exc.url,
                    status=exc.status,
                    parsed_message=exc.parsed_message,
                    next_step="Verify SNYK_API_TOKEN and that it can access SNYK_ORG_ID.",
                ) from exc
            if exc.status == 404:
                raise SbomUnsupportedError(
                    "SBOM is not supported for this project (HTTP 404).",
                    operation=exc.operation,
                    url=exc.url,
                    status=exc.status,
                    parsed_message=exc.parsed_message,
                    next_step=(
                        "This project type does not support SBOM export; it will be skipped. "
                        "If unexpected, verify SNYK_PROJECT_ID is correct."
                    ),
                ) from exc
            raise SbomGenerationError(
                "Failed to generate SBOM from Snyk.",
                operation=exc.operation,
                url=exc.url,
                status=exc.status,
                parsed_message=exc.parsed_message,
                next_step=(
                    "Verify SNYK_PROJECT_ID, SNYK_SBOM_FORMAT, and SNYK_REST_API_VERSION "
                    "are valid for this org."
                ),
            ) from exc

        if not is_nonempty_bytes(resp.content):
            raise SbomGenerationError(
                "Snyk returned an empty SBOM document.",
                operation="snyk.generate_sbom",
                url=resp.url,
                status=resp.status,
                next_step="Confirm the project has been scanned and supports SBOM generation.",
            )

        content_type = resp.headers.get("Content-Type", "application/octet-stream")
        document = SbomDocument(
            content=resp.content,
            content_type=content_type,
            sbom_format=self._config.snyk_sbom_format,
        )

        self._logger.info("SBOM generated (%s, %d bytes)", document.sbom_format, document.size)
        debug.log_variable("SBOM Content-Type", content_type)
        debug.log_variable("Payload Size", document.size)
        return document
