## Context

A live `SNYK_ORG` dry-run discovered 77 projects; 55 returned HTTP 404 from `GET /orgs/{org}/projects/{project}/sbom` because those project types (SAST, IaC, container) don't support SBOM export. The current code maps any non-2xx to `SbomGenerationError`, so those 55 count as failures and the run exits 4. This change reclassifies the 404 case as "unsupported / skipped".

This builds on `configurable-application-scope` (the `scope-orchestration` capability). That change must be archived first so `openspec/specs/scope-orchestration/spec.md` exists before this change is archived.

## Goals / Non-Goals

**Goals:**
- Treat SBOM-endpoint 404 as a distinct, non-fatal "unsupported" outcome.
- Report skipped-unsupported separately in the summary; exclude them from the failure exit code.
- Preserve existing behavior for all other errors.

**Non-Goals:**
- Filtering projects before generation (e.g. by type) to avoid the 404 entirely — a future enhancement.
- Changing discovery, upload, or file persistence.

## Decisions

### New error type for the unsupported case
Add `SbomUnsupportedError(AppError)` in `app/errors.py`. It reuses exit code 3 as its `exit_code` (so single-project semantics remain sensible), but the orchestrator treats it specially as a skip. Rationale: a dedicated type lets `scope_manager` distinguish 404 from real generation failures via `except SbomUnsupportedError` without string-matching. Alternative considered: inspect `exc.status == 404` on `SbomGenerationError` — rejected as brittle (status isn't always populated and conflates concerns).

### Raise on 404 in the Snyk client
In `snyk_client.generate_sbom`, when the wrapped `HttpError.status == 404`, raise `SbomUnsupportedError` (message: "SBOM is not supported for this project (404)."); all other non-2xx and empty/malformed bodies continue to raise `SbomGenerationError`. This is the only behavioral change to `snyk-sbom-export`.

### Orchestrator handling and counters
`ProjectResult` gains a `skipped: bool`. In `_process_one`, catch `SbomUnsupportedError` before the generic `AppError` branch and return a result with `skipped=True, ok=False, generated=False` and a clear reason. `ScopeSummary` gains `skipped: int`; `failed` now counts only genuine failures (`not ok and not skipped`). `exit_code` returns 4 only when `failed > 0`; skips never trigger 4. Progress log shows `SKIPPED (unsupported)`.

### Single-project scope
For `SNYK_PROJECT` scope, if the one project is unsupported, the summary has `failed == 0` and thus exits 0, with a WARNING logged that the project doesn't support SBOM export. Documented trade-off: a genuinely wrong project id that Snyk answers with 404 is indistinguishable from an unsupported type and will also exit 0 with the warning (rather than the previous exit 3).

### Summary wording
Add a "Skipped (unsupported): N" line. Keep "Failed: N" for genuine failures only.

## Risks / Trade-offs

- [404 masks a bad project id] → Accept and document; the warning names the project so operators can spot a typo. A future `--strict` mode could restore hard-fail.
- [Base spec (`scope-orchestration`) not yet archived] → Must archive `configurable-application-scope` before this change; noted in the proposal and archive step.
- [Other "not available" Snyk responses use a different status] → Only 404 is reclassified; if Snyk uses 422/400 for unsupported, revisit. Current live evidence shows 404.

## Migration Plan

Additive/behavioral. After implementing, re-run the `SNYK_ORG` dry-run: the summary should show ~22 generated, ~55 skipped, 0 failed, exit 0. No config changes required.

## Open Questions

- None blocking. Confirm over time that Snyk consistently uses 404 (not 403/422) for unsupported project types across origins.
