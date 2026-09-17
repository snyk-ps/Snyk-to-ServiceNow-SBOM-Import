## ADDED Requirements

### Requirement: Run mode configuration

The utility SHALL read `RUN_MODE` (default `SNYK_API`; accepted values `SNYK_API`, `SNYK_CLI`) and, in `SNYK_CLI` mode, accept a `--sbom-file-path` command-line argument identifying the SBOM file to upload. An invalid `RUN_MODE` MUST terminate with exit code 1 (Configuration Error).

#### Scenario: Default run mode

- **WHEN** `RUN_MODE` is not set
- **THEN** the mode is `SNYK_API`

#### Scenario: CLI file path argument accepted

- **WHEN** `RUN_MODE=SNYK_CLI` and `--sbom-file-path <path>` is provided
- **THEN** the utility uses `<path>` as the SBOM to upload

## MODIFIED Requirements

### Requirement: Required configuration validation

The utility SHALL validate that all required configuration variables are present and non-empty before performing any network operation. The ServiceNow variables `SNOW_INSTANCE_SUBDOMAIN`, `SNOW_ACCESS_TOKEN`, and `SNOW_BUSINESS_APPLICATION_ID` are always required. The remaining required inputs depend on `RUN_MODE`:

- `SNYK_API` mode: additionally requires `SNYK_API_TOKEN` and `SNYK_ORG_ID`, plus the scope-dependent identifiers per `SNOW_APPLICATION_SCOPE` (`SNYK_PROJECT` → `SNYK_TARGET_ID`, `SNYK_PROJECT_ID`; `SNYK_TARGET` → `SNYK_TARGET_ID`; `SNYK_ORG` → none).
- `SNYK_CLI` mode: additionally requires a valid `--sbom-file-path` (existing, readable, non-empty file); the Snyk API variables and `SNOW_APPLICATION_SCOPE` are not required.

#### Scenario: Missing required variable

- **WHEN** any variable required for the selected run mode (and, in API mode, scope) is missing or empty
- **THEN** the utility terminates with exit code 1 (Configuration Error)
- **AND** the error message names the specific missing variable(s) and the recommended next step

#### Scenario: All required variables present

- **WHEN** every variable required for the selected run mode is present and non-empty
- **THEN** validation passes and execution continues

#### Scenario: CLI mode does not require Snyk API variables

- **WHEN** `RUN_MODE=SNYK_CLI`, the ServiceNow variables are set, and `--sbom-file-path` is a valid file
- **THEN** validation passes even though `SNYK_API_TOKEN` / `SNYK_ORG_ID` / scope identifiers are absent

#### Scenario: Scope-dependent requirements (API mode)

- **WHEN** `RUN_MODE=SNYK_API`, `SNOW_APPLICATION_SCOPE` is `SNYK_ORG`, and only `SNYK_ORG_ID` (plus the always-required variables) is set
- **THEN** validation passes even though `SNYK_TARGET_ID` and `SNYK_PROJECT_ID` are absent

#### Scenario: Renamed business application variable

- **WHEN** the ServiceNow target application is configured
- **THEN** it is read from `SNOW_BUSINESS_APPLICATION_ID`
- **AND** the former name `SNOW_APPLICATION_SYS_ID` is no longer recognized

### Requirement: Optional configuration with defaults

The utility SHALL support optional configuration variables and apply documented defaults when they are not provided. Optional variables include `SNYK_SBOM_FORMAT` (default `cyclonedx1.6+json`), `SNYK_BASE_URL` (default `https://api.snyk.io/rest`), `SNYK_REST_API_VERSION`, `DEBUG_LEVEL` (default `INFO`), and `API_DRY_RUN` (default `false`; applies only in `SNYK_API` mode). The former `DRY_RUN` variable is no longer recognized.

#### Scenario: Default SBOM format applied

- **WHEN** `SNYK_SBOM_FORMAT` is not set
- **THEN** the utility uses `cyclonedx1.6+json` as the SBOM format

#### Scenario: API_DRY_RUN flag parsed

- **WHEN** `API_DRY_RUN` is set to a truthy value (e.g. `true`, `True`, `1`) in `SNYK_API` mode
- **THEN** the utility treats the run as a dry run and skips the ServiceNow upload

#### Scenario: Legacy DRY_RUN not recognized

- **WHEN** only the old `DRY_RUN` variable is set
- **THEN** it has no effect (the utility reads `API_DRY_RUN`)
