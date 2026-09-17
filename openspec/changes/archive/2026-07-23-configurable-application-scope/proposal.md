## Why

Today the utility processes exactly one Snyk project per run. In the most common deployment, a single ServiceNow Business Application represents an entire Snyk Organization made up of many repositories (Targets) and Projects. Operators need to upload SBOMs for all of those projects without running the tool once per project or changing code. Adding a configurable processing scope lets one run cover a Project, a Target, or a whole Organization while reusing the existing SBOM generation and upload logic unchanged.

## What Changes

- Add a new environment variable `SNOW_APPLICATION_SCOPE` with values `SNYK_PROJECT` (default), `SNYK_TARGET`, and `SNYK_ORG`; any other value is a configuration error.
- Add scope-dependent required-variable validation:
  - `SNYK_PROJECT` → `SNYK_ORG_ID`, `SNYK_TARGET_ID`, `SNYK_PROJECT_ID`
  - `SNYK_TARGET` → `SNYK_ORG_ID`, `SNYK_TARGET_ID`
  - `SNYK_ORG` → `SNYK_ORG_ID`
- Add an orchestration layer (`scope_manager.py`) that determines scope, validates config, invokes discovery, and drives the existing per-project workflow.
- Add a discovery layer (`project_discovery.py`) that enumerates Snyk Targets/Projects via the Snyk REST API (paginated) and returns Project objects.
- Process each discovered project through the **existing, unmodified** SBOM generate → validate → upload workflow, uploading each SBOM independently to the same ServiceNow Business Application.
- Continue on per-project failures (log and record), aborting only on fatal configuration/authentication errors; print a processing summary and per-project progress.

The existing SBOM generation (`snyk-sbom-export`), file persistence (`sbom-file-persistence`), and ServiceNow upload (`servicenow-sbom-upload`) behavior is unchanged.

## Capabilities

### New Capabilities
- `project-discovery`: Enumerate Snyk resources for the configured scope — a single project, all projects for a target, or all targets and their projects for an organization — returning Project objects (with org/target/project identifiers and a display name).
- `scope-orchestration`: Read and validate `SNOW_APPLICATION_SCOPE`, dispatch the correct discovery routine, iterate discovered projects through the existing workflow, tolerate per-project failures, emit progress, and produce a final summary.

### Modified Capabilities
- `configuration`: Add `SNOW_APPLICATION_SCOPE` (default `SNYK_PROJECT`, three accepted values) and make required-variable validation depend on the selected scope; `SNYK_TARGET_ID` becomes required for `SNYK_PROJECT`/`SNYK_TARGET` scopes.

## Impact

- New code: `app/scope_manager.py`, `app/project_discovery.py`; discovery calls added to (or alongside) `app/snyk_client.py`. `main.py` delegates to the scope manager.
- Existing `app/sbom_service.py` and `app/servicenow_client.py` remain unchanged; per-project runs are driven by supplying the project id (immutable per-project config copy).
- Config/docs: `.env`, `.env.example`, `README.md` updated for `SNOW_APPLICATION_SCOPE` and scope-based requirements.
- Consumes additional Snyk REST endpoints: list targets, list projects (with `target_id` filter), both paginated.
- No new third-party dependencies.
