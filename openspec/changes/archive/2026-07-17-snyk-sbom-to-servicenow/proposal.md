## Why

Security and platform teams need a repeatable, hands-off way to move a Software Bill of Materials (SBOM) from Snyk into ServiceNow Vulnerability Response. Doing this manually (export from Snyk, then upload to ServiceNow) is error-prone and does not scale. This utility provides a simple, reliable, environment-variable-driven bridge between the two systems and establishes a modular foundation for future Enterprise Migration and ServiceNow integration work.

## What Changes

- Add a Python command-line utility that exports an SBOM from a single Snyk project and uploads it to ServiceNow Vulnerability Response in one run.
- Read all configuration from a `.env` file; no code changes required for normal operation.
- Authenticate to the Snyk REST API using a token and generate an SBOM in any Snyk-supported format (default `cyclonedx1.6+json`).
- Authenticate to ServiceNow using a bearer access token and upload the SBOM to the SBOM upload API against a configured application `sys_id`.
- Provide variable-level debug logging (`log_variable`, `log_object`) with automatic redaction of secrets and collection/size summarization.
- Provide a reusable HTTP wrapper (timeouts, standardized error handling, request/response logging, timing).
- Support a `DRY_RUN` mode that generates the SBOM and validates configuration/auth without performing the ServiceNow upload.
- Return meaningful exit codes (0 success, 1 config, 2 auth, 3 SBOM generation, 4 upload, 5 unexpected) with actionable error messages.

Note: this change aligns to the existing repo `.env` conventions (`SNYK_BASE_URL`, `SNYK_REST_API_VERSION`, `SNYK_SBOM_FORMAT`, `SNOW_INSTANCE_SUBDOMAIN`, `SNOW_ACCESS_TOKEN`, `SNOW_APPLICATION_SYS_ID`, `DRY_RUN`, `DEBUG_LEVEL`) rather than the illustrative names in the original write-up.

## Capabilities

### New Capabilities
- `configuration`: Load, validate, and expose runtime settings from environment variables (`.env`), enforcing required variables and defaults.
- `snyk-sbom-export`: Authenticate to Snyk and generate an SBOM for a configured project in a configurable format via the Snyk REST API.
- `servicenow-sbom-upload`: Authenticate to ServiceNow and upload the generated SBOM (unmodified) to the SBOM upload API, honoring dry-run mode.
- `observability`: Variable-level and object debug logging, leveled logging (ERROR/WARNING/INFO/DEBUG/TRACE), and automatic secret redaction.
- `http-client`: Reusable HTTP wrapper providing timeouts, standardized error handling, request/response logging, and request timing.

### Modified Capabilities
<!-- None: this is a greenfield utility; no existing specs change. -->

## Impact

- New Python package/module tree: `main.py`, `config.py`, `logging.py`, `snyk_client.py`, `servicenow_client.py`, `sbom_service.py`, and `utils/{debug.py,http.py,validators.py}`.
- New dependency management file (`requirements.txt`) and README.
- Consumes external APIs: Snyk REST SBOM endpoint and ServiceNow SBOM upload endpoint.
- Reads secrets from `.env` (Snyk API token, ServiceNow access token); these must never be logged.
