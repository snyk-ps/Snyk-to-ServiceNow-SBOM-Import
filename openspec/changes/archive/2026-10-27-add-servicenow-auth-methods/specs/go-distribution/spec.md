## MODIFIED Requirements

### Requirement: Behavioral parity with the reference implementation

The Go implementation SHALL reproduce the behavior defined by the existing capability specs — `configuration`, `run-mode`, `scope-orchestration`, `snyk-sbom-export`, `project-discovery`, `sbom-file-persistence`, `servicenow-sbom-upload`, and `observability` — without changing that behavior. It MUST read the same environment variables and `.env` file, accept the same `--sbom-file-path` and `--buildid` arguments, write the same `<timestamp>-snyk-<project_id>-sbom.json` files, and call the same Snyk and ServiceNow endpoints.

#### Scenario: Same configuration inputs

- **WHEN** the Go binary is run with supported `.env` or process-environment configuration
- **THEN** it validates `RUN_MODE`, `SNOW_APPLICATION_SCOPE`, `SNOW_AUTH_METHOD`, method-specific ServiceNow credentials, and mode/scope-dependent Snyk variables according to the capability specs
- **AND** it fails before network activity when any selected-method requirement is invalid or missing

#### Scenario: Same run modes and scope

- **WHEN** `RUN_MODE=SNYK_API` with a given `SNOW_APPLICATION_SCOPE`
- **THEN** the Go binary discovers and processes the same set of projects (project, target, or organization) and uploads one SBOM per project to the configured Business Application
- **AND** `RUN_MODE=SNYK_CLI` uploads a validated `--sbom-file-path` file directly

#### Scenario: Same ServiceNow authentication

- **WHEN** an SBOM is uploaded
- **THEN** the Go binary authenticates with `Authorization: Bearer <SNOW_ACCESS_TOKEN>` when `SNOW_AUTH_METHOD=BEARER`
- **AND** it authenticates with standards-compliant Basic authorization derived from `SNOW_USERNAME` and `SNOW_PASSWORD` when `SNOW_AUTH_METHOD=BASIC`

#### Scenario: Same ServiceNow request

- **WHEN** an SBOM is uploaded
- **THEN** the request targets `POST /api/sbom/core/upload?businessApplicationId=<id>&sbomSource=<SnykAPI|SnykCLI>` with the selected authorization scheme and `Content-Type: application/json`
- **AND** it conditionally includes the existing URL-encoded `buildId` query parameter and sends the SBOM file bytes unmodified

#### Scenario: Same skip/failure semantics

- **WHEN** a project's SBOM endpoint returns HTTP 404
- **THEN** that project is recorded as skipped (unsupported), not failed, and does not drive a failure exit code
