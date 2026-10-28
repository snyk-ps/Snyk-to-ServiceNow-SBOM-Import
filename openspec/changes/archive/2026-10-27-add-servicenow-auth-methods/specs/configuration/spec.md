## ADDED Requirements

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

## MODIFIED Requirements

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
