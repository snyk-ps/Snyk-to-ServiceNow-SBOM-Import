## 1. Configuration

- [x] 1.1 Add `run_mode` to `Config`; parse `RUN_MODE` (default `SNYK_API`); reject values outside {`SNYK_API`, `SNYK_CLI`} with a `ConfigError` listing valid values
- [x] 1.2 Rename `Config.dry_run` → `api_dry_run`, read from `API_DRY_RUN`; remove `DRY_RUN` handling
- [x] 1.3 Make required-variable validation `RUN_MODE`-dependent: always require the ServiceNow trio; require Snyk API + scope vars only in `SNYK_API` mode
- [x] 1.4 Update placeholder checks to skip Snyk API vars in `SNYK_CLI` mode
- [x] 1.5 Update `.env`, `.env.example`, and `README.md` for `RUN_MODE`, `API_DRY_RUN`, and `--sbom-file-path`

## 2. CLI mode

- [x] 2.1 Add `app/cli_mode.py` with `run_cli_upload(config, sbom_file_path) -> int`
- [x] 2.2 Validate `--sbom-file-path` (provided, exists, is a file, readable, non-empty) → `ConfigError` (exit 1) before any network call
- [x] 2.3 Upload the file via the existing `ServiceNowClient.upload_sbom(Path)`; map AuthError→2, UploadError→4, success→0
- [x] 2.4 Log that `API_DRY_RUN` is ignored when set in CLI mode
- [x] 2.5 Make `ServiceNowClient` derive `sbomSource` from `config.run_mode` (`SnykAPI` for API mode, `SnykCLI` for CLI mode)

## 3. Entry point

- [x] 3.1 Add an `argparse` parser in `main.py` for `--sbom-file-path`
- [x] 3.2 Dispatch on `config.run_mode`: `SNYK_CLI` → `cli_mode.run_cli_upload`; `SNYK_API` → existing `scope_manager.run_scope`
- [x] 3.3 Rename all `dry_run` readers to `api_dry_run` (`scope_manager.py`, `sbom_service.py`, `main.py` log line)

## 4. Verification

- [x] 4.1 `RUN_MODE=SNYK_CLI` with a valid `--sbom-file-path` uploads the file (mock upload) and exits 0
- [x] 4.2 CLI mode with missing/nonexistent/empty file path exits 1 before any network call
- [x] 4.3 CLI mode does not require Snyk API vars; `API_DRY_RUN` truthy is ignored (upload still attempted)
- [x] 4.4 Invalid `RUN_MODE` exits 1; `SNYK_API` mode still runs scope discovery and honors `API_DRY_RUN`
- [x] 4.5 Confirm no remaining references to `DRY_RUN`/`dry_run` in code or docs
- [x] 4.6 Confirm the upload query param is `sbomSource=SnykAPI` in API mode and `sbomSource=SnykCLI` in CLI mode
