## Why

When processing a Target or Organization, Snyk's SBOM endpoint returns HTTP 404 for projects whose type does not support SBOM export (e.g. SAST/code, IaC, and container projects). Today these are counted as failures, so a healthy org-wide run can report "55 of 77 failed" and exit with code 4 even though nothing is actually wrong. This obscures real failures and misleads CI. Unsupported projects should be reported as *skipped*, not failed.

## What Changes

- Treat an HTTP 404 from the Snyk SBOM endpoint as **"SBOM not supported for this project"** — a distinct, non-fatal outcome — rather than a generic generation failure.
- In multi-project runs, count unsupported projects as **skipped** (separately from failures), keep processing, and do not let skips drive a failure exit code.
- Add "SBOM unsupported (skipped)" to the processing summary counts.
- Exit code: a run exits `4` only when there are real failures; a run whose non-successful projects are all skipped-unsupported exits `0` (with a warning noting how many were skipped).
- Other SBOM errors (invalid format, empty/malformed body, 5xx, etc.) remain generation failures as before.

Note: this builds on the `scope-orchestration` and `project-discovery` capabilities introduced by `configurable-application-scope`, which must be archived first so its specs exist in `openspec/specs/`.

## Capabilities

### Modified Capabilities
- `snyk-sbom-export`: Distinguish a 404 from the SBOM endpoint (project does not support SBOM) as an "unsupported" outcome, separate from other generation failures.
- `scope-orchestration`: Record unsupported projects as skipped (not failed), include a skipped count in the summary, and exclude skips from the failure-driven exit code.

## Impact

- Code: add an `SbomUnsupportedError` (or equivalent signal) in `app/errors.py`; raise it on 404 in `app/snyk_client.py`; handle it as "skipped" in `app/scope_manager.py` (new `skipped` counter in `ScopeSummary`/`ProjectResult`).
- Behavior change: a single-project run (`SNYK_PROJECT`) whose one project is unsupported now exits `0` with a warning instead of `3`; genuinely bad project ids that Snyk answers with 404 are indistinguishable from unsupported types and will also be treated as skipped (documented trade-off).
- Docs: `README.md` summary/exit-code notes updated.
- No new dependencies; no changes to the ServiceNow upload or SBOM file persistence.
