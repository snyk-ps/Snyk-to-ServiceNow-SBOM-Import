## ADDED Requirements

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

## MODIFIED Requirements

### Requirement: Required configuration validation

The utility SHALL validate that all required configuration variables are present and non-empty before performing any network operation. The ServiceNow variables `SNOW_INSTANCE_SUBDOMAIN`, `SNOW_ACCESS_TOKEN`, and `SNOW_BUSINESS_APPLICATION_ID`, plus `SNYK_API_TOKEN` and `SNYK_ORG_ID`, are always required. The remaining Snyk identifiers are required based on `SNOW_APPLICATION_SCOPE`:

- `SNYK_PROJECT`: additionally requires `SNYK_TARGET_ID` and `SNYK_PROJECT_ID`
- `SNYK_TARGET`: additionally requires `SNYK_TARGET_ID`
- `SNYK_ORG`: no additional identifiers

#### Scenario: Missing required variable

- **WHEN** any variable required for the selected scope is missing or empty
- **THEN** the utility terminates with exit code 1 (Configuration Error)
- **AND** the error message names the specific missing variable(s) and the recommended next step

#### Scenario: All required variables present

- **WHEN** every variable required for the selected scope is present and non-empty
- **THEN** validation passes and execution continues to authentication

#### Scenario: Scope-dependent requirements

- **WHEN** `SNOW_APPLICATION_SCOPE` is `SNYK_ORG` and only `SNYK_ORG_ID` (plus the always-required variables) is set
- **THEN** validation passes even though `SNYK_TARGET_ID` and `SNYK_PROJECT_ID` are absent

#### Scenario: Renamed business application variable

- **WHEN** the ServiceNow target application is configured
- **THEN** it is read from `SNOW_BUSINESS_APPLICATION_ID`
- **AND** the former name `SNOW_APPLICATION_SYS_ID` is no longer recognized
