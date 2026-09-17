## Context

The utility is fully env-driven with no CLI arguments today. `main.py` loads `Config`, enables TLS trust, and calls `scope_manager.run_scope(config)`, which discovers projects and drives generate → persist → upload. `ServiceNowClient.upload_sbom(sbom_path: Path)` already uploads a file's bytes to `POST /api/sbom/core/upload`. Config is a frozen dataclass; `dry_run` is read from `DRY_RUN`.

This change introduces a second way to obtain the SBOM: the Snyk CLI produces a file, and the utility just uploads it. `RUN_MODE` selects the path.

## Goals / Non-Goals

**Goals:**
- `RUN_MODE` (`SNYK_API` default, `SNYK_CLI`); invalid → config error.
- `SNYK_CLI`: validate `--sbom-file-path` (exists, readable, non-empty) before any network call, then upload it via the existing `ServiceNowClient`.
- Rename `DRY_RUN` → `API_DRY_RUN`; only meaningful in API mode.
- Mode-dependent required-variable validation.

**Non-Goals:**
- Invoking the Snyk CLI ourselves (the user runs it and passes the file).
- Scope/discovery in CLI mode; multiple files per CLI run; persisting a copy of the provided file.
- Backward-compatible `DRY_RUN` alias (intentional breaking rename).

## Decisions

### First CLI argument via argparse
Add a minimal `argparse` parser in `main.py` for `--sbom-file-path`. It is only required/used in `SNYK_CLI` mode; in `SNYK_API` mode it is ignored. Rationale: a file path is inherently a per-invocation input, not environment config, so a CLI flag is the natural fit and matches the requested interface. The parsed value is passed into the dispatch, not stored on the env-loaded `Config`.

### Config additions and rename
- Add `run_mode: str` (validated against `{SNYK_API, SNYK_CLI}`; invalid → `ConfigError`).
- Rename `dry_run` → `api_dry_run`, read from `API_DRY_RUN`; drop `DRY_RUN`. Update all readers (`scope_manager`, `sbom_service`).
- Mode-dependent required-variable validation in `load_config`: always require the ServiceNow trio; in `SNYK_API` additionally require `SNYK_API_TOKEN`, `SNYK_ORG_ID`, and the scope identifiers; in `SNYK_CLI` require none of the Snyk API vars.
- `--sbom-file-path` validation is not part of `load_config` (it isn't env). It is validated in the CLI dispatch as a configuration error (exit 1) before upload.

### Dispatch in main
`main.run()`:
1. Parse args; load config (mode + rename + mode-based env validation).
2. Configure logging; enable system trust.
3. If `run_mode == SNYK_CLI`: call `cli_mode.run_cli_upload(config, sbom_file_path)`.
4. Else: `scope_manager.run_scope(config)` (unchanged), return `summary.exit_code`.

### New module `app/cli_mode.py`
`run_cli_upload(config, sbom_file_path) -> int`:
- Validate `sbom_file_path` is provided, exists, is a file, readable, non-empty → else raise `ConfigError` (exit 1).
- If `api_dry_run` is set, log that dry-run is ignored in CLI mode.
- Call `ServiceNowClient(config).upload_sbom(Path(sbom_file_path))` (reused unchanged). Map `AuthError`→2, `UploadError`→4, success→0.
Rationale: keeps CLI-mode orchestration separate and tiny; reuses the upload client verbatim.

### Exit codes
Unchanged set. CLI-mode file problems → 1 (configuration), auth → 2, upload → 4, success → 0.

## Risks / Trade-offs

- [Breaking rename of `DRY_RUN`] → Documented; `.env`/`.env.example`/README updated. A stale `DRY_RUN` silently has no effect; acceptable and explicit (a legacy scenario documents this).
- [CLI file not actually a valid SBOM] → We validate existence/readability/non-empty, not schema; ServiceNow will reject malformed content with an upload error (exit 4). Schema validation is a future enhancement.
- [`--sbom-file-path` given in API mode] → Ignored; documented. Could warn.
- [Two dry-run readers] → Ensure every `dry_run` reference is renamed to `api_dry_run` to avoid a stale attribute (config, scope_manager, sbom_service).

## Migration Plan

Additive plus a rename. Update `.env`: `DRY_RUN` → `API_DRY_RUN`; optionally set `RUN_MODE`. For CLI mode: `RUN_MODE=SNYK_CLI` then `python main.py --sbom-file-path ./my-sbom.json`. API mode unchanged.

## Decisions (cont.)

### Mode-specific `sbomSource`
The ServiceNow upload query parameter `sbomSource` reflects the run mode: `SnykAPI` in `SNYK_API` mode and `SnykCLI` in `SNYK_CLI` mode (replacing the previous fixed `Snyk`). This lets ServiceNow distinguish API-generated from CLI-generated SBOMs. Implementation: `ServiceNowClient` derives the value from `config.run_mode` (constant map), so both paths use the same upload code.

## Open Questions

- None outstanding.
