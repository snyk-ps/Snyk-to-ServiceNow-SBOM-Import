## Context

The utility currently runs a fixed pipeline: `main.py` → `SbomService.run()` → `SnykClient.generate_sbom()` (reads `config.snyk_project_id`) → persist file → `ServiceNowClient.upload_sbom(path)`. `Config` is a frozen dataclass loaded once from env/`.env`. The archived specs cover `configuration`, `snyk-sbom-export`, `sbom-file-persistence`, `servicenow-sbom-upload`, `http-client`, and `observability`.

This change adds an orchestration layer above the existing single-project workflow so one run can cover a Project, a Target, or an entire Organization. The existing generate/persist/upload code must not change.

## Goals / Non-Goals

**Goals:**
- Add `SNOW_APPLICATION_SCOPE` (`SNYK_PROJECT` default, `SNYK_TARGET`, `SNYK_ORG`).
- Discover projects via the Snyk REST API and drive the existing workflow once per project.
- Reuse `SbomService`/`SnykClient`/`ServiceNowClient` unchanged.
- Isolate per-project failures; summarize results.

**Non-Goals:**
- Parallelism, retries, SBOM aggregation/dedup, incremental/batched uploads, checkpointing, filtering. (All listed as future enhancements.)
- Changes to SBOM generation, file persistence, or the ServiceNow upload contract.

## Decisions

### Reuse the existing workflow via a per-project config copy
`SnykClient.generate_sbom()` reads `config.snyk_project_id`. To process many projects without touching that code, the orchestrator creates a per-project `Config` with `dataclasses.replace(base_config, snyk_org_id=..., snyk_project_id=...)` and runs a fresh `SbomService(project_config).run()` for each discovered project. Rationale: zero changes to existing generate/persist/upload logic; `Config` is already immutable so copies are safe. Alternative considered: add a `project_id` parameter to `generate_sbom()` — rejected because it modifies the existing, archived `snyk-sbom-export` behavior/signature.

### New modules
- `app/project_discovery.py`: `Project` dataclass (`org_id`, `target_id`, `project_id`, `name`) and functions `discover_project(config)`, `discover_projects_for_target(config)`, `discover_targets(config)`, `discover_projects_for_org(config)`. Uses the existing `http.request` wrapper + `SNYK_API_TOKEN` auth (same header as `SnykClient`).
- `app/scope_manager.py`: `Scope` enum/constants; `run_scope(config)` that validates scope, calls the right discovery routine, loops projects, invokes `SbomService`, records `ProjectResult`s, and returns a `ScopeSummary`.
- `main.py`: delegates to `scope_manager.run_scope(config)` instead of calling `SbomService` directly.

### Snyk discovery endpoints (REST, versioned + paginated)
- List projects for a target: `GET {base}/orgs/{org_id}/projects?version=<v>&target_id=<target_id>&limit=100`
- List all projects for an org: `GET {base}/orgs/{org_id}/projects?version=<v>&limit=100`
- List targets for an org: `GET {base}/orgs/{org_id}/targets?version=<v>&limit=100`

Pagination follows the JSON:API `links.next` cursor until absent. `SNYK_ORG` uses the org-wide projects listing directly and separately counts targets for the summary (avoids N+1 per-target project calls); the `target_id` on each project associates it back to its target. Project `name` comes from `data[].attributes.name`; `target_id` from `data[].relationships.target.data.id` (fallbacks handled defensively).

### Validation location
Scope parsing and scope-dependent required-variable checks live in `config.py` (extending `load_config`/`_reject_placeholders`) so failures surface as `ConfigError` (exit 1) before any network call, consistent with existing behavior.

### Exit codes
Reuse existing codes. Single fatal auth error during discovery → 2. Any config problem → 1. After processing: all uploads OK → 0; one or more per-project upload failures (no fatal error) → 4. This keeps the documented code set unchanged.

### Logging & summary
Use the existing logger. Per project: `Processing Project N of M`, org/target/project/name, SBOM format, upload status, elapsed. At the end, a `ScopeSummary` prints scope, targets discovered, projects discovered, SBOMs generated, successful/failed uploads, and total elapsed time. `DEBUG_LEVEL` continues to control verbosity (note: `WARN` resolves to `WARNING`).

## Risks / Trade-offs

- [Large orgs → many sequential API calls and uploads (slow)] → Acceptable for v1; parallelism is a documented future enhancement. Progress logging keeps runs observable.
- [Many SBOM files written to the repo root] → Existing `.gitignore` pattern `*-snyk-*-sbom.json` already covers them; filenames include project id + timestamp so they don't collide.
- [Snyk REST response shape assumptions (relationships/target id)] → Isolate parsing in `project_discovery.py` with defensive fallbacks; a shape change is a one-file edit.
- [Partial-failure exit semantics] → Chose exit 4 when any upload fails so CI can detect incomplete runs, while still processing everything and printing a summary.
- [`replace()` per project creates many Config copies] → Negligible; dataclass copies are cheap.

## Migration Plan

Additive and backward compatible: default scope `SNYK_PROJECT` reproduces today's behavior. Update `.env.example`/`README`. Validate with `DRY_RUN=True` at `SNYK_TARGET`/`SNYK_ORG` scope to confirm discovery + per-project file generation without uploading, then run for real.

## Open Questions

- Confirm the exact Snyk REST field for a project's target association (`relationships.target.data.id`) and default page `limit` for the org's API version; adjust the parser if the tenant returns a different shape.
