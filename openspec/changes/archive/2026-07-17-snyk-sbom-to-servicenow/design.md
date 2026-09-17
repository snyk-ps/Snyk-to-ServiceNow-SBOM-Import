## Context

The repo already contains a `.env` describing the integration's runtime inputs for Snyk (`SNYK_ORG_ID`, `SNYK_PROJECT_ID`, `SNYK_API_TOKEN`, `SNYK_BASE_URL`, `SNYK_REST_API_VERSION`, `SNYK_SBOM_FORMAT`, `SNYK_PLATFORM_DOMAIN`) and ServiceNow (`SNOW_INSTANCE_SUBDOMAIN`, `SNOW_ACCESS_TOKEN`, `SNOW_APPLICATION_SYS_ID`), plus operational flags (`DRY_RUN`, `DEBUG_LEVEL`). This design turns that configuration into a single-run CLI utility that exports one project's SBOM from Snyk and uploads it to ServiceNow Vulnerability Response. The utility is greenfield Python and is intended to be the reusable base for future Enterprise Migration/ServiceNow work, so modularity and debuggability are first-class concerns.

Snyk's SBOM endpoint lives under the versioned REST API (`GET /orgs/{org_id}/projects/{project_id}/sbom?version={version}&format={format}`) and requires the `version` query parameter and token auth. ServiceNow exposes an SBOM upload API on the instance (`https://{subdomain}.service-now.com/...`) that accepts the SBOM document and associates it with an application `sys_id`, authenticated via a bearer token.

## Goals / Non-Goals

**Goals:**
- Single-command execution driven entirely by environment variables; no code edits for normal use.
- Clean module boundaries matching the proposed architecture so future features slot in with minimal refactor.
- Verbose, variable-level debugging with guaranteed secret redaction.
- Deterministic exit codes and actionable error messages.
- `DRY_RUN` path that validates everything up to (but excluding) the ServiceNow write.

**Non-Goals:**
- Multi-project or org-wide export, project discovery, parallelism.
- Retries/backoff, caching, local archival, delta comparison, compression (future).
- Modifying or validating SBOM contents beyond confirming a successful response.
- Scheduling/CI wiring and structured JSON logging (future).

## Decisions

### Language & dependencies
- Python 3.12+ (the repo `.venv` is 3.14; target >=3.12 for compatibility). Use `requests` for HTTP and `python-dotenv` for `.env` loading. Rationale: minimal, ubiquitous, well understood; avoids heavier frameworks for a small utility. Alternative considered: `httpx` (async) — rejected as unnecessary for a synchronous single-run tool. Standard-library `logging` is used as the logging backbone, wrapped by our `logging.py`/`utils/debug.py`.

### Module layout
Mirror the proposed structure:
- `main.py` — orchestrates the flow and maps outcomes to exit codes.
- `config.py` — loads `.env`, validates required vars, applies defaults, exposes a typed `Config` object.
- `logging.py` — configures leveled logging (ERROR/WARNING/INFO/DEBUG/TRACE) and formatting.
- `snyk_client.py` — builds/executes the Snyk SBOM request; returns raw SBOM bytes + content type.
- `servicenow_client.py` — builds/executes the ServiceNow upload; honors dry-run.
- `sbom_service.py` — coordinates generate→validate→upload; keeps clients decoupled from orchestration.
- `utils/debug.py` — `log_variable`, `log_object`, collection summarization, redaction hooks.
- `utils/http.py` — reusable HTTP wrapper (timeout, logging, timing, standardized errors).
- `utils/validators.py` — config/response validation helpers.

Rationale: the boundary between `*_client.py` (transport specifics) and `sbom_service.py` (workflow) is what lets future multi-project/parallel features be added without touching orchestration.

### Configuration model
`config.py` returns an immutable dataclass. Required vs optional handled per the `configuration` spec. A custom `add_TRACE` level (numeric 5, below DEBUG) is registered so TRACE is a real logging level. `DRY_RUN` parsed via a truthy set `{true,1,yes,on}` (case-insensitive).

### Secret redaction strategy
Redaction is centralized in `utils/debug.py`: a set of key-name patterns (`token`, `password`, `authorization`, `secret`, `access_token`) is matched case-insensitively; matched values are masked to a fixed pattern preserving nothing of the secret. The HTTP wrapper always passes headers through the redactor before logging. This guarantees redaction happens in one place rather than at each call site.

### Error handling & exit codes
A small exception hierarchy: `ConfigError(1)`, `AuthError(2)`, `SbomGenerationError(3)`, `UploadError(4)`, and a catch-all mapped to `5`. Each carries `operation`, `url`, `status`, `parsed_message`, `next_step`. `main.py` catches these and returns the associated code. The HTTP wrapper raises a transport-level `HttpError` that clients translate into the appropriate domain error (401/403 → `AuthError`, etc.).

### HTTP wrapper
`utils/http.py` exposes `request(method, url, *, headers, params, data, timeout)` returning a normalized response object and logging method/URL/redacted-headers/status/elapsed at DEBUG, full detail at TRACE. Timeout default (e.g. 60s) configurable later. Retry/backoff and correlation IDs are explicitly deferred (documented hook points only).

## Risks / Trade-offs

- [Snyk/ServiceNow API shape drift] → Keep endpoint construction isolated in the client modules and version-pinned via `SNYK_REST_API_VERSION`; a shape change is a one-file edit.
- [Large SBOMs held fully in memory] → Acceptable for single-project scope; note streaming as a future enhancement. Log payload size to surface unusually large documents.
- [Secret leakage in logs] → Centralized redactor + always redact headers in the HTTP wrapper; add a test asserting secrets never appear in captured output.
- [ServiceNow auth model variance (token vs OAuth vs basic)] → This design commits to bearer-token (`SNOW_ACCESS_TOKEN`) matching the current `.env`; OAuth is listed as a future enhancement and isolated in `servicenow_client.py`.
- [TRACE verbosity accidentally enabled in shared environments] → Redaction guarantees no secrets leak even at TRACE; default level is INFO.

## Migration Plan

Greenfield addition; no data migration. Deploy by installing `requirements.txt` into the existing `.venv`, populating `.env`, and running `python main.py`. Rollback is deletion of the added files. Validate first with `DRY_RUN=True` to confirm Snyk export + config without writing to ServiceNow.

## Open Questions

- Exact ServiceNow SBOM upload endpoint path and expected content-type/wrapping (multipart vs raw JSON body) for the target instance — to be confirmed against ServiceNow Vulnerability Response API docs during implementation.
- Whether `SNYK_REST_API_VERSION` should be required (currently optional with the value from `.env`); confirm the SBOM endpoint's minimum supported version.
