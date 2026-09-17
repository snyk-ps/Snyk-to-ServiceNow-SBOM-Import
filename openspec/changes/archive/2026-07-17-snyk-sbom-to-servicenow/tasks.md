## 1. Project setup

- [x] 1.1 Add `requirements.txt` with `requests` and `python-dotenv` (pinned versions)
- [x] 1.2 Create the module tree: `main.py`, `config.py`, `logging.py`, `snyk_client.py`, `servicenow_client.py`, `sbom_service.py`, and `utils/{__init__.py,debug.py,http.py,validators.py}`
- [x] 1.3 Add `.env.example` documenting all required and optional variables with defaults
- [x] 1.4 Add a README describing configuration, usage (`python main.py`), dry-run, and exit codes

## 2. Configuration

- [x] 2.1 Implement `.env` loading with `python-dotenv` and process-env precedence
- [x] 2.2 Implement an immutable `Config` dataclass with required and optional fields
- [x] 2.3 Validate required vars (`SNYK_API_TOKEN`, `SNYK_ORG_ID`, `SNYK_PROJECT_ID`, `SNOW_INSTANCE_SUBDOMAIN`, `SNOW_ACCESS_TOKEN`, `SNOW_APPLICATION_SYS_ID`); raise `ConfigError` naming missing vars
- [x] 2.4 Apply defaults (`SNYK_SBOM_FORMAT=cyclonedx1.6+json`, `SNYK_BASE_URL=https://api.snyk.io/rest`, `DEBUG_LEVEL=INFO`, `DRY_RUN=false`) and parse `DRY_RUN` truthy values

## 3. Observability & debugging

- [x] 3.1 Configure leveled logging in `logging.py`, registering a custom `TRACE` level below DEBUG
- [x] 3.2 Implement timestamped log formatting matching the required format
- [x] 3.3 Implement centralized secret redaction (token/password/authorization/secret patterns, case-insensitive)
- [x] 3.4 Implement `debug.log_variable(name, value)` with collection/size summarization and redaction
- [x] 3.5 Implement `debug.log_object(value)` with pretty-printing

## 4. HTTP client & errors

- [x] 4.1 Define exception hierarchy (`ConfigError`, `AuthError`, `SbomGenerationError`, `UploadError`, `HttpError`) carrying operation/url/status/parsed_message/next_step
- [x] 4.2 Implement `utils/http.py` `request()` wrapper with timeout, timing, and request/response logging (redacted)
- [x] 4.3 Translate non-2xx and malformed responses into standardized errors; add TRACE-level full request/response logging

## 5. Snyk SBOM export

- [x] 5.1 Implement `snyk_client.py` token auth and Snyk SBOM endpoint URL/params construction (org, project, version, format)
- [x] 5.2 Invoke the SBOM endpoint via the HTTP wrapper and return raw SBOM bytes + content type
- [x] 5.3 Map 401/403 to `AuthError`; map generation/format errors and empty/malformed bodies to `SbomGenerationError`; log format and payload size on success

## 6. ServiceNow upload

- [x] 6.1 Implement `servicenow_client.py` bearer-token auth and upload URL construction from `SNOW_INSTANCE_SUBDOMAIN` + `SNOW_APPLICATION_SYS_ID`
- [x] 6.2 Upload the SBOM unmodified via the HTTP wrapper and validate the response
- [x] 6.3 Map 401/403 to `AuthError` and other failures/malformed responses to `UploadError`
- [x] 6.4 Honor `DRY_RUN`: skip upload, log skip reason, and exit success

## 7. Orchestration & exit codes

- [x] 7.1 Implement `sbom_service.py` to coordinate generate → validate → upload
- [x] 7.2 Implement `main.py` flow: load config → validate → Snyk auth/generate → validate → ServiceNow auth/upload → complete
- [x] 7.3 Map outcomes to exit codes (0/1/2/3/4/5) and print actionable error messages with next steps

## 8. Verification

- [ ] 8.1 Run `python main.py` with `DRY_RUN=True` against a real Snyk project and confirm SBOM generation + skipped upload
- [ ] 8.2 Run a full run with `DRY_RUN=False` and confirm a successful ServiceNow upload
- [x] 8.3 Verify no secrets appear in output at any log level (including TRACE)
- [x] 8.4 Verify each failure scenario returns its documented exit code and message
