"""Persist a generated SBOM to a timestamped file on disk.

The file is written to the current working directory (documented to be the
repository root) using the pattern ``<timestamp>-snyk-<project_id>-sbom.json``.
That exact file is what the ServiceNow uploader sends (``curl --data-binary``).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from app.errors import SbomGenerationError
from app.logging import get_logger
from app.snyk_client import SbomDocument


def _timestamp() -> str:
    """Return a filename-safe UTC timestamp: ``YYYYMMDDTHHMMSSZ``."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def build_filename(project_id: str, *, timestamp: str | None = None) -> str:
    """Build the SBOM filename ``<timestamp>-snyk-<project_id>-sbom.json``."""
    ts = timestamp or _timestamp()
    return f"{ts}-snyk-{project_id}-sbom.json"


def write_sbom(document: SbomDocument, project_id: str, root: Path | None = None) -> Path:
    """Write the SBOM bytes, unmodified, to a timestamped file in ``root``.

    Args:
        document: The generated SBOM to persist.
        project_id: Snyk project id, embedded in the filename.
        root: Target directory (defaults to the current working directory).

    Returns:
        The absolute path of the written file.

    Raises:
        SbomGenerationError: if the file cannot be written.
    """
    logger = get_logger()
    target_dir = (root or Path.cwd()).resolve()
    path = target_dir / build_filename(project_id)

    try:
        path.write_bytes(document.content)
    except OSError as exc:
        raise SbomGenerationError(
            "Failed to write SBOM file to disk.",
            operation="sbom_file.write_sbom",
            url=str(path),
            parsed_message=str(exc),
            next_step="Verify write permissions and available disk space for the target directory.",
        ) from exc

    logger.info("SBOM written to %s (%d bytes)", path, document.size)
    return path
