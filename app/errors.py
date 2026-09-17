"""Exception hierarchy and process exit codes for the utility.

Each domain error maps to a documented exit code so ``main`` can translate a
failure into a deterministic process result. Errors carry structured context
(operation, url, status, parsed_message, next_step) so the message printed to
the user is actionable.
"""

from __future__ import annotations


class ExitCode:
    """Documented process exit codes."""

    SUCCESS = 0
    CONFIG_ERROR = 1
    AUTH_FAILURE = 2
    SBOM_GENERATION_FAILURE = 3
    UPLOAD_FAILURE = 4
    UNEXPECTED = 5


class AppError(Exception):
    """Base class for all expected utility errors.

    Attributes carry enough context to produce an actionable message without
    leaking secrets (callers must never place secret values in these fields).
    """

    exit_code: int = ExitCode.UNEXPECTED

    def __init__(
        self,
        message: str,
        *,
        operation: str | None = None,
        url: str | None = None,
        status: int | None = None,
        parsed_message: str | None = None,
        next_step: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.operation = operation
        self.url = url
        self.status = status
        self.parsed_message = parsed_message
        self.next_step = next_step

    def format_report(self) -> str:
        """Render a multi-line, human-readable error report."""
        lines = [self.message]
        if self.operation:
            lines.append(f"  Operation: {self.operation}")
        if self.url:
            lines.append(f"  URL: {self.url}")
        if self.status is not None:
            lines.append(f"  HTTP Status: {self.status}")
        if self.parsed_message:
            lines.append(f"  Detail: {self.parsed_message}")
        if self.next_step:
            lines.append(f"  Next step: {self.next_step}")
        return "\n".join(lines)


class ConfigError(AppError):
    """Missing or invalid configuration."""

    exit_code = ExitCode.CONFIG_ERROR


class AuthError(AppError):
    """Authentication/authorization failure against Snyk or ServiceNow."""

    exit_code = ExitCode.AUTH_FAILURE


class SbomGenerationError(AppError):
    """The SBOM could not be generated or the response was malformed."""

    exit_code = ExitCode.SBOM_GENERATION_FAILURE


class SbomUnsupportedError(AppError):
    """The project does not support SBOM export (Snyk returns HTTP 404).

    This is a distinct, non-fatal outcome: the orchestration layer records it as
    *skipped* rather than a failure so unsupported project types (SAST, IaC,
    container, ...) do not inflate the failure count or drive a failure exit code.
    """

    exit_code = ExitCode.SBOM_GENERATION_FAILURE


class UploadError(AppError):
    """The SBOM could not be uploaded to ServiceNow."""

    exit_code = ExitCode.UPLOAD_FAILURE


class HttpError(AppError):
    """Transport-level or non-2xx HTTP failure raised by the HTTP wrapper.

    Clients translate this into the appropriate domain error (e.g. ``AuthError``
    for 401/403) so orchestration can map it to the correct exit code.
    """

    exit_code = ExitCode.UNEXPECTED
