"""ServiceNow client for uploading a generated SBOM.

The SBOM is uploaded to the ServiceNow SBOM ingestion API:

    POST https://<subdomain>.service-now.com/api/sbom/core/upload
         ?businessApplicationId=<id>&sbomSource=<SnykAPI|SnykCLI>

with ``Authorization: Bearer <token>`` and ``Content-Type: application/json``.
The request body is the raw bytes of the persisted SBOM file, mirroring
``curl --data-binary @<file>``.
"""

from __future__ import annotations

from pathlib import Path

from app.config import Config
from app.errors import AuthError, HttpError, UploadError
from app.logging import get_logger
from app.utils import debug, http

UPLOAD_PATH = "api/sbom/core/upload"


class ServiceNowClient:
    """Thin client over the ServiceNow SBOM upload API."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._logger = get_logger()

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._config.snow_access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _upload_url(self) -> str:
        return f"{self._config.snow_base_url}/{UPLOAD_PATH}"

    def upload_sbom(self, sbom_path: Path) -> dict:
        """Upload the persisted SBOM file to ServiceNow.

        The file bytes are sent unmodified (``--data-binary @file``).

        Raises:
            AuthError: on 401/403 from ServiceNow.
            UploadError: if the file cannot be read, or on other failures /
                malformed responses.
        """
        url = self._upload_url()
        params = {
            "businessApplicationId": self._config.snow_business_application_id,
            "sbomSource": self._config.sbom_source,
        }

        try:
            payload = Path(sbom_path).read_bytes()
        except OSError as exc:
            raise UploadError(
                "Failed to read the persisted SBOM file for upload.",
                operation="servicenow.upload_sbom",
                url=str(sbom_path),
                parsed_message=str(exc),
                next_step="Verify the SBOM file exists and is readable.",
            ) from exc

        self._logger.info("Uploading SBOM to ServiceNow")
        debug.log_variable("Upload URL", url)
        debug.log_variable("SNOW_BUSINESS_APPLICATION_ID", self._config.snow_business_application_id)
        debug.log_variable("SBOM File", str(sbom_path))
        debug.log_variable("Payload Size", len(payload))

        try:
            resp = http.request(
                "POST",
                url,
                operation="servicenow.upload_sbom",
                headers=self._headers(),
                params=params,
                data=payload,
                timeout=self._config.http_timeout_seconds,
                verify=self._config.tls_verify,
            )
        except HttpError as exc:
            if exc.status in (401, 403):
                raise AuthError(
                    "ServiceNow authentication failed.",
                    operation=exc.operation,
                    url=exc.url,
                    status=exc.status,
                    parsed_message=exc.parsed_message,
                    next_step="Verify SNOW_ACCESS_TOKEN and that it has SBOM upload permission.",
                ) from exc
            raise UploadError(
                "Failed to upload SBOM to ServiceNow.",
                operation=exc.operation,
                url=exc.url,
                status=exc.status,
                parsed_message=exc.parsed_message,
                next_step=(
                    "Verify SNOW_INSTANCE_SUBDOMAIN and SNOW_BUSINESS_APPLICATION_ID."
                ),
            ) from exc

        try:
            body = resp.json() if resp.content else {}
        except HttpError:
            # A non-JSON 2xx response is acceptable for some endpoints.
            body = {"raw": resp.text[:500]}

        self._logger.info("SBOM uploaded to ServiceNow (status %s)", resp.status)
        debug.log_object(body, name="ServiceNow Response")
        return body if isinstance(body, dict) else {"response": body}
