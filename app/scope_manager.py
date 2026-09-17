"""Orchestration layer: turn a processing scope into per-project SBOM runs.

Determines which Snyk projects to process for ``SNOW_APPLICATION_SCOPE``,
discovers them, and drives each through the existing (unchanged) SBOM
generate -> persist -> upload workflow. Per-project failures are isolated;
only fatal configuration/authentication errors abort the whole run.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace

from app import project_discovery
from app.config import SCOPE_ORG, SCOPE_PROJECT, SCOPE_TARGET, Config
from app.errors import AppError, ExitCode, SbomUnsupportedError
from app.logging import get_logger
from app.project_discovery import Project
from app.sbom_service import SbomService


@dataclass
class ProjectResult:
    """Outcome of processing a single project."""

    project: Project
    generated: bool
    uploaded: bool
    ok: bool
    elapsed_s: float
    skipped: bool = False
    error: str | None = None


@dataclass
class ScopeSummary:
    """Aggregate outcome of a scoped run."""

    scope: str
    dry_run: bool
    projects_discovered: int
    sboms_generated: int
    succeeded: int
    failed: int
    elapsed_s: float
    skipped: int = 0
    targets_discovered: int | None = None

    @property
    def exit_code(self) -> int:
        """Exit 4 only for genuine failures; skips never trigger a failure code."""
        return ExitCode.SUCCESS if self.failed == 0 else ExitCode.UPLOAD_FAILURE

    def format_report(self) -> str:
        def fmt_elapsed(seconds: float) -> str:
            minutes, secs = divmod(int(seconds), 60)
            return f"{minutes}m {secs}s" if minutes else f"{secs}s"

        lines = [
            "Processing summary:",
            f"  Scope: {self.scope}",
        ]
        if self.targets_discovered is not None:
            lines.append(f"  Targets discovered: {self.targets_discovered}")
        lines.extend(
            [
                f"  Projects discovered: {self.projects_discovered}",
                f"  SBOMs generated: {self.sboms_generated}",
                f"  {'Skipped (dry-run)' if self.dry_run else 'Successful uploads'}: {self.succeeded}",
                f"  Skipped (unsupported): {self.skipped}",
                f"  Failed: {self.failed}",
                f"  Elapsed time: {fmt_elapsed(self.elapsed_s)}",
            ]
        )
        return "\n".join(lines)


def _discover(config: Config) -> tuple[list[Project], int | None]:
    """Discover projects for the scope; returns (projects, targets_discovered)."""
    scope = config.snow_application_scope
    if scope == SCOPE_PROJECT:
        return project_discovery.discover_project(config), None
    if scope == SCOPE_TARGET:
        return project_discovery.discover_projects_for_target(config), 1
    # SCOPE_ORG
    targets = project_discovery.discover_targets(config)
    projects = project_discovery.discover_projects_for_org(config)
    return projects, len(targets)


def _process_one(config: Config, project: Project) -> ProjectResult:
    """Run the existing SBOM workflow for a single project.

    Re-raises fatal errors (configuration/authentication). Non-fatal per-project
    errors are captured in the returned :class:`ProjectResult`.
    """
    logger = get_logger()
    project_config = replace(
        config,
        snyk_org_id=project.org_id,
        snyk_target_id=project.target_id,
        snyk_project_id=project.project_id,
    )
    start = time.perf_counter()
    try:
        result = SbomService(project_config).run()
    except SbomUnsupportedError as exc:
        elapsed = time.perf_counter() - start
        logger.info(
            "Project %s skipped: %s", project.project_id, exc.message
        )
        return ProjectResult(
            project=project,
            generated=False,
            uploaded=False,
            ok=False,
            skipped=True,
            elapsed_s=elapsed,
            error=exc.message,
        )
    except AppError as exc:
        if exc.exit_code in (ExitCode.CONFIG_ERROR, ExitCode.AUTH_FAILURE):
            raise  # fatal: abort the whole run
        elapsed = time.perf_counter() - start
        generated = exc.exit_code != ExitCode.SBOM_GENERATION_FAILURE
        logger.error("Project %s failed: %s", project.project_id, exc.message)
        return ProjectResult(
            project=project,
            generated=generated,
            uploaded=False,
            ok=False,
            elapsed_s=elapsed,
            error=exc.message,
        )

    elapsed = time.perf_counter() - start
    return ProjectResult(
        project=project,
        generated=True,
        uploaded=result.uploaded,
        ok=True,
        elapsed_s=elapsed,
    )


def run_scope(config: Config) -> ScopeSummary:
    """Discover and process all projects for the configured scope."""
    logger = get_logger()
    started = time.perf_counter()

    projects, targets_discovered = _discover(config)
    total = len(projects)
    logger.info(
        "Scope %s: discovered %d project(s)%s",
        config.snow_application_scope,
        total,
        f" across {targets_discovered} target(s)" if targets_discovered is not None else "",
    )

    results: list[ProjectResult] = []
    for index, project in enumerate(projects, start=1):
        logger.info(
            "Processing Project %d of %d | project=%s (%s) | target=%s",
            index,
            total,
            project.name,
            project.project_id,
            project.target_id or "-",
        )
        result = _process_one(config, project)
        if result.skipped:
            status = "SKIPPED (unsupported)"
        elif not result.ok:
            status = f"FAILED ({result.error})"
        elif config.api_dry_run:
            status = "OK (dry-run, upload skipped)"
        else:
            status = "OK"
        logger.info(
            "Result: %s | format=%s | elapsed=%.1fs",
            status,
            config.snyk_sbom_format,
            result.elapsed_s,
        )
        results.append(result)

    summary = ScopeSummary(
        scope=config.snow_application_scope,
        dry_run=config.api_dry_run,
        projects_discovered=total,
        sboms_generated=sum(1 for r in results if r.generated),
        succeeded=sum(1 for r in results if r.ok),
        skipped=sum(1 for r in results if r.skipped),
        failed=sum(1 for r in results if not r.ok and not r.skipped),
        elapsed_s=time.perf_counter() - started,
        targets_discovered=targets_discovered,
    )
    logger.info("%s", summary.format_report())
    return summary
