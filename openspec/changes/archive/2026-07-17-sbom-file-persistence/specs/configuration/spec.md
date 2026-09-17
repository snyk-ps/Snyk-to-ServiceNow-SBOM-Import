## MODIFIED Requirements

### Requirement: Required configuration validation

The utility SHALL validate that all required configuration variables are present and non-empty before performing any network operation. Required variables are: `SNYK_API_TOKEN`, `SNYK_ORG_ID`, `SNYK_PROJECT_ID`, `SNOW_INSTANCE_SUBDOMAIN`, `SNOW_ACCESS_TOKEN`, and `SNOW_BUSINESS_APPLICATION_ID`.

#### Scenario: Missing required variable

- **WHEN** any required variable is missing or empty
- **THEN** the utility terminates with exit code 1 (Configuration Error)
- **AND** the error message names the specific missing variable(s) and the recommended next step

#### Scenario: All required variables present

- **WHEN** every required variable is present and non-empty
- **THEN** validation passes and execution continues to authentication

#### Scenario: Renamed business application variable

- **WHEN** the ServiceNow target application is configured
- **THEN** it is read from `SNOW_BUSINESS_APPLICATION_ID`
- **AND** the former name `SNOW_APPLICATION_SYS_ID` is no longer recognized
