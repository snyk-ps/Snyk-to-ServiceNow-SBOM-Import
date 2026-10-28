# configuration Specification

## Purpose
TBD - created by archiving change snyk-sbom-to-servicenow. Update Purpose after archive.
## Requirements
### Requirement: Environment-driven configuration

The utility SHALL read all runtime configuration from environment variables, loaded from a `.env` file when present. The utility MUST NOT require any code modification to run under normal operation.

#### Scenario: Load configuration from .env

- **WHEN** the utility starts and a `.env` file is present in the working directory
- **THEN** the utility loads the variables from `.env` into the runtime configuration before validation

#### Scenario: Environment overrides .env

- **WHEN** a variable is defined both in the process environment and in `.env`
- **THEN** the process environment value takes precedence

### Requirement: ServiceNow authentication method selection

The utility SHALL read `SNOW_AUTH_METHOD` to select ServiceNow REST API authentication. It MUST accept exactly `BEARER` and `BASIC` after trimming whitespace and normalizing case, and MUST default to `BEARER` when the variable is unset or empty. Any unsupported value MUST terminate execution with exit code 1 (Configuration Error) before any network request.

#### Scenario: Authentication method defaults to bearer

- **WHEN** `SNOW_AUTH_METHOD` is unset, empty, or whitespace-only
- **THEN** the utility selects `BEARER`

#### Scenario: Authentication method is case-insensitive

- **WHEN** `SNOW_AUTH_METHOD` is `bearer`, `Bearer`, `basic`, or `Basic`
- **THEN** the utility normalizes it to the corresponding `BEARER` or `BASIC` method

#### Scenario: Unsupported authentication method is rejected

- **WHEN** `SNOW_AUTH_METHOD` is any value other than `BEARER` or `BASIC`
- **THEN** the utility terminates with exit code 1 before any network request
- **AND** the error identifies `SNOW_AUTH_METHOD` and lists the accepted values

### Requirement: Required configuration validation

The utility SHALL validate that all required configuration variables are present and non-empty before performing any network operation. The ServiceNow variables `SNOW_INSTANCE_SUBDOMAIN` and `SNOW_BUSINESS_APPLICATION_ID` are always required. ServiceNow credentials depend on `SNOW_AUTH_METHOD`:

- `BEARER`: requires `SNOW_ACCESS_TOKEN`; `SNOW_USERNAME` and `SNOW_PASSWORD` are not required.
- `BASIC`: requires `SNOW_USERNAME` and `SNOW_PASSWORD`; `SNOW_ACCESS_TOKEN` is not required.

The remaining required inputs depend on `RUN_MODE`:

- `SNYK_API` mode: additionally requires `SNYK_API_TOKEN` and `SNYK_ORG_ID`, plus the scope-dependent identifiers per `SNOW_APPLICATION_SCOPE` (`SNYK_PROJECT` → `SNYK_TARGET_ID`, `SNYK_PROJECT_ID`; `SNYK_TARGET` → `SNYK_TARGET_ID`; `SNYK_ORG` → none).
- `SNYK_CLI` mode: additionally requires a valid `--sbom-file-path` (existing, readable, non-empty file); the Snyk API variables and `SNOW_APPLICATION_SCOPE` are not required.

#### Scenario: Missing required variable

- **WHEN** any variable required for the selected authentication method, run mode, or API scope is missing or empty
- **THEN** the utility terminates with exit code 1 (Configuration Error)
- **AND** the error message names the specific missing variable(s) and the recommended next step

#### Scenario: All required variables present

- **WHEN** every variable required for the selected authentication method and run mode is present and non-empty
- **THEN** validation passes and execution continues

#### Scenario: Bearer authentication validates token only

- **WHEN** `SNOW_AUTH_METHOD=BEARER`, `SNOW_ACCESS_TOKEN` is non-empty, and the common required variables are set
- **THEN** ServiceNow credential validation passes without `SNOW_USERNAME` or `SNOW_PASSWORD`

#### Scenario: Basic authentication validates username and password only

- **WHEN** `SNOW_AUTH_METHOD=BASIC`, `SNOW_USERNAME` and `SNOW_PASSWORD` are non-empty, and the common required variables are set
- **THEN** ServiceNow credential validation passes without `SNOW_ACCESS_TOKEN`

#### Scenario: Missing bearer token is rejected

- **WHEN** `SNOW_AUTH_METHOD=BEARER` and `SNOW_ACCESS_TOKEN` is missing or empty
- **THEN** the utility terminates with exit code 1 before any network request
- **AND** the error identifies `SNOW_ACCESS_TOKEN`

#### Scenario: Missing Basic credential is rejected

- **WHEN** `SNOW_AUTH_METHOD=BASIC` and either `SNOW_USERNAME` or `SNOW_PASSWORD` is missing or empty
- **THEN** the utility terminates with exit code 1 before any network request
- **AND** the error identifies each missing selected-method credential

#### Scenario: Inactive credentials do not affect validation

- **WHEN** all credentials required by the selected authentication method are valid and credentials for the inactive method are absent, empty, or contain placeholders
- **THEN** validation ignores the inactive credentials

#### Scenario: CLI mode does not require Snyk API variables

- **WHEN** `RUN_MODE=SNYK_CLI`, the selected ServiceNow credentials and common ServiceNow variables are set, and `--sbom-file-path` is a valid file
- **THEN** validation passes even though `SNYK_API_TOKEN`, `SNYK_ORG_ID`, and scope identifiers are absent

#### Scenario: Scope-dependent requirements in API mode

- **WHEN** `RUN_MODE=SNYK_API`, `SNOW_APPLICATION_SCOPE=SNYK_ORG`, `SNYK_ORG_ID` and `SNYK_API_TOKEN` are set, and the selected ServiceNow authentication configuration is valid
- **THEN** validation passes even though `SNYK_TARGET_ID` and `SNYK_PROJECT_ID` are absent

#### Scenario: Renamed business application variable

- **WHEN** the ServiceNow target application is configured
- **THEN** it is read from `SNOW_BUSINESS_APPLICATION_ID`
- **AND** the former name `SNOW_APPLICATION_SYS_ID` is not recognized

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

### Requirement: Optional ServiceNow build ID configuration

The utility SHALL accept an optional ServiceNow build ID from the `BUILD_ID` environment variable and the `--buildid` command-line argument. When `--buildid` is present, its value MUST take precedence over `BUILD_ID`, including when the command-line value is explicitly empty. When `--buildid` is absent, the utility SHALL use `BUILD_ID` when set. A missing, empty, or whitespace-only effective value SHALL be treated as unavailable and MUST NOT cause configuration validation to fail.

#### Scenario: Neither build ID input is provided

- **WHEN** neither `BUILD_ID` nor `--buildid` is provided
- **THEN** configuration validation succeeds without an effective build ID

#### Scenario: Environment build ID is used

- **WHEN** `BUILD_ID` is non-empty and `--buildid` is absent
- **THEN** the effective build ID is the value of `BUILD_ID`

#### Scenario: Command-line build ID is used

- **WHEN** `--buildid` is provided with a non-empty value and `BUILD_ID` is absent
- **THEN** the effective build ID is the command-line value

#### Scenario: Command-line build ID overrides environment

- **WHEN** both `BUILD_ID` and a non-empty `--buildid` value are provided
- **THEN** the effective build ID is the command-line value

#### Scenario: Explicitly empty command-line value overrides environment

- **WHEN** `BUILD_ID` is non-empty and `--buildid` is explicitly provided with an empty value
- **THEN** the effective build ID is empty
- **AND** the environment value is not used

#### Scenario: Empty environment value is optional

- **WHEN** `BUILD_ID` is unset, empty, or whitespace-only and `--buildid` is absent
- **THEN** configuration validation succeeds without an effective build ID

#### Scenario: Existing ServiceNow requirement remains mandatory

- **WHEN** build ID configuration is missing or empty
- **THEN** `SNOW_BUSINESS_APPLICATION_ID` remains required and is validated using the existing rules

### Requirement: Application scope selection

The utility SHALL read `SNOW_APPLICATION_SCOPE` to determine how many Snyk projects to process. It MUST accept exactly the values `SNYK_PROJECT`, `SNYK_TARGET`, and `SNYK_ORG`, defaulting to `SNYK_PROJECT` when unset. Any other value MUST terminate execution with exit code 1 (Configuration Error) before any API call.

#### Scenario: Default scope

- **WHEN** `SNOW_APPLICATION_SCOPE` is not set
- **THEN** the scope is `SNYK_PROJECT`

#### Scenario: Valid scope accepted

- **WHEN** `SNOW_APPLICATION_SCOPE` is one of `SNYK_PROJECT`, `SNYK_TARGET`, or `SNYK_ORG`
- **THEN** the utility proceeds with that scope

#### Scenario: Invalid scope rejected

- **WHEN** `SNOW_APPLICATION_SCOPE` is any other value
- **THEN** the utility terminates with exit code 1 (Configuration Error)
- **AND** the error message lists the accepted values

### Requirement: Run mode configuration

The utility SHALL read `RUN_MODE` (default `SNYK_CLI`; accepted values `SNYK_API`, `SNYK_CLI`) and, in `SNYK_CLI` mode, accept a `--sbom-file-path` command-line argument identifying the SBOM file to upload. An invalid `RUN_MODE` MUST terminate with exit code 1 (Configuration Error).

#### Scenario: Default run mode

- **WHEN** `RUN_MODE` is not set
- **THEN** the mode is `SNYK_CLI`

#### Scenario: CLI file path argument accepted

- **WHEN** `RUN_MODE=SNYK_CLI` and `--sbom-file-path <path>` is provided
- **THEN** the utility uses `<path>` as the SBOM to upload

