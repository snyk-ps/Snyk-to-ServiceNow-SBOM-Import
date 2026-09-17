## 1. Configuration

- [x] 1.1 Add `snow_application_scope` to `Config` and parse `SNOW_APPLICATION_SCOPE` (default `SNYK_PROJECT`)
- [x] 1.2 Reject any scope value not in {`SNYK_PROJECT`, `SNYK_TARGET`, `SNYK_ORG`} with a `ConfigError` listing valid values
- [x] 1.3 Make required-variable validation scope-dependent (add `SNYK_TARGET_ID` for PROJECT/TARGET; `SNYK_PROJECT_ID` for PROJECT only); keep always-required Snyk/ServiceNow vars
- [x] 1.4 Add `snyk_target_id` to `Config` and update placeholder checks for scope-relevant vars
- [x] 1.5 Update `.env.example` and `README.md` for `SNOW_APPLICATION_SCOPE` and the scope-based requirements table

## 2. Project discovery

- [x] 2.1 Add `app/project_discovery.py` with a `Project` dataclass (`org_id`, `target_id`, `project_id`, `name`)
- [x] 2.2 Implement `discover_project(config)` returning the single configured project (no API call)
- [x] 2.3 Implement paginated Snyk REST helpers (follow `links.next`) using the shared HTTP wrapper + token auth
- [x] 2.4 Implement `discover_projects_for_target(config)` (list projects filtered by `target_id`)
- [x] 2.5 Implement `discover_targets(config)` and `discover_projects_for_org(config)` (org-wide projects + target count)
- [x] 2.6 Map discovery 401/403 to `AuthError` (fatal, exit 2); parse project `name` and `target_id` defensively

## 3. Scope orchestration

- [x] 3.1 Add `app/scope_manager.py` with a scope constant/enum and `run_scope(config) -> ScopeSummary`
- [x] 3.2 Dispatch to the correct discovery routine based on scope
- [x] 3.3 For each project, build a per-project `Config` via `dataclasses.replace` and run the existing `SbomService`
- [x] 3.4 Record a `ProjectResult` per project; isolate per-project failures (log + continue), abort only on fatal config/auth errors
- [x] 3.5 Emit per-project progress (position N of M, org/target/project/name, format, status, elapsed)
- [x] 3.6 Build and print the final `ScopeSummary` (scope, targets, projects, generated, succeeded, failed, elapsed)

## 4. Entry point & exit codes

- [x] 4.1 Update `main.py` to call `scope_manager.run_scope(config)` instead of `SbomService` directly
- [x] 4.2 Map outcome to exit codes: all success → 0; any per-project upload failure → 4; fatal config → 1; fatal auth → 2; unexpected → 5

## 5. Verification

- [x] 5.1 `SNYK_PROJECT` scope reproduces prior single-project behavior (one SBOM generated + uploaded)
- [x] 5.2 `SNYK_TARGET` scope with `DRY_RUN=True` discovers all target projects and writes one file per project (no upload)
- [x] 5.3 `SNYK_ORG` scope discovers all targets/projects and processes each; summary counts are correct
- [x] 5.4 A simulated per-project upload failure is logged, does not stop the run, and yields exit code 4
- [x] 5.5 Invalid `SNOW_APPLICATION_SCOPE` and missing scope-required vars both exit 1 before any API call
