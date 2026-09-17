## Why

Some teams generate SBOMs with the **Snyk CLI** (e.g. `snyk sbom ...`) rather than the Snyk REST API — for offline/local scans, monorepos, or CI where the CLI already produces an SBOM file. Today the utility can only obtain an SBOM by calling the Snyk API. Adding a `RUN_MODE` lets the same uploader consume an already-produced SBOM file from the CLI and push it to ServiceNow, while keeping the existing API-driven discovery/generation flow intact.

## What Changes

- Add a `RUN_MODE` environment variable with values `SNYK_API` (default) and `SNYK_CLI`; any other value is a configuration error.
- Add a `--sbom-file-path` command-line argument used in `SNYK_CLI` mode.
- **`SNYK_CLI` mode**: require and validate `--sbom-file-path` (exists, is a readable, non-empty file) **before** any other work, then upload that file directly to ServiceNow. No Snyk API calls, no discovery, no scope, no file persistence. `API_DRY_RUN` does not apply.
- **`SNYK_API` mode**: unchanged behavior — validate the Snyk API variables (token, org, scope-dependent ids) and run discovery → generate → persist → upload.
- **BREAKING**: rename `DRY_RUN` → `API_DRY_RUN` (dry-run only makes sense when the utility itself generates the SBOM, i.e. API mode).
- Make required-variable validation depend on `RUN_MODE`: ServiceNow variables are always required; Snyk API variables are required only in `SNYK_API` mode; `--sbom-file-path` is required only in `SNYK_CLI` mode.

## Capabilities

### New Capabilities
- `run-mode`: Select between `SNYK_API` and `SNYK_CLI`; in `SNYK_CLI` mode validate a provided SBOM file path and upload it directly to ServiceNow, bypassing Snyk API discovery/generation.

### Modified Capabilities
- `configuration`: Add `RUN_MODE` (default `SNYK_API`, invalid → config error), add the `--sbom-file-path` CLI argument, rename `DRY_RUN` → `API_DRY_RUN`, and make required-variable validation `RUN_MODE`-dependent.
- `servicenow-sbom-upload`: The upload `sbomSource` query parameter reflects the run mode (`SnykAPI` in API mode, `SnykCLI` in CLI mode), replacing the fixed `Snyk`; the dry-run behavior is renamed to `API_DRY_RUN` and applies only in `SNYK_API` mode.
- `scope-orchestration`: Clarify that scope discovery/generation runs only in `SNYK_API` mode; the dry-run reference is renamed to `API_DRY_RUN`.

## Impact

- Code: `app/config.py` (RUN_MODE, `api_dry_run`, mode-based validation), `main.py` (argparse for `--sbom-file-path`, dispatch on `RUN_MODE`), new `app/cli_mode.py` (validate file + upload via the existing `ServiceNowClient`). `scope_manager.py` referenced only in API mode.
- Config/docs: `.env`, `.env.example`, `README.md` updated for `RUN_MODE`, `API_DRY_RUN`, and the CLI argument.
- Behavior: `DRY_RUN` is no longer recognized (replaced by `API_DRY_RUN`); update any `.env` files.
- No new third-party dependencies (argparse is stdlib).
