## ADDED Requirements

### Requirement: Environment-driven configuration

The utility SHALL read all runtime configuration from environment variables, loaded from a `.env` file when present. The utility MUST NOT require any code modification to run under normal operation.

#### Scenario: Load configuration from .env

- **WHEN** the utility starts and a `.env` file is present in the working directory
- **THEN** the utility loads the variables from `.env` into the runtime configuration before validation

#### Scenario: Environment overrides .env

- **WHEN** a variable is defined both in the process environment and in `.env`
- **THEN** the process environment value takes precedence

### Requirement: Required configuration validation

The utility SHALL validate that all required configuration variables are present and non-empty before performing any network operation. Required variables are: `SNYK_API_TOKEN`, `SNYK_ORG_ID`, `SNYK_PROJECT_ID`, `SNOW_INSTANCE_SUBDOMAIN`, `SNOW_ACCESS_TOKEN`, and `SNOW_APPLICATION_SYS_ID`.

#### Scenario: Missing required variable

- **WHEN** any required variable is missing or empty
- **THEN** the utility terminates with exit code 1 (Configuration Error)
- **AND** the error message names the specific missing variable(s) and the recommended next step

#### Scenario: All required variables present

- **WHEN** every required variable is present and non-empty
- **THEN** validation passes and execution continues to authentication

### Requirement: Optional configuration with defaults

The utility SHALL support optional configuration variables and apply documented defaults when they are not provided. Optional variables include `SNYK_SBOM_FORMAT` (default `cyclonedx1.6+json`), `SNYK_BASE_URL` (default `https://api.snyk.io/rest`), `SNYK_REST_API_VERSION`, `DEBUG_LEVEL` (default `INFO`), and `DRY_RUN` (default `false`).

#### Scenario: Default SBOM format applied

- **WHEN** `SNYK_SBOM_FORMAT` is not set
- **THEN** the utility uses `cyclonedx1.6+json` as the SBOM format

#### Scenario: Dry-run flag parsed

- **WHEN** `DRY_RUN` is set to a truthy value (e.g. `true`, `True`, `1`)
- **THEN** the utility treats the run as a dry run and skips the ServiceNow upload
