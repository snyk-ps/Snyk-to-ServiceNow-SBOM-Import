## ADDED Requirements

### Requirement: Snyk authentication

The utility SHALL authenticate to the Snyk REST API using `SNYK_API_TOKEN`, scoped by `SNYK_ORG_ID`. Authentication MUST use the token mechanism required by the current Snyk REST API. Interactive authentication MUST NOT be supported.

#### Scenario: Valid token

- **WHEN** a valid `SNYK_API_TOKEN` is provided
- **THEN** requests to the Snyk REST API are authorized and proceed

#### Scenario: Authentication failure

- **WHEN** the Snyk API rejects the token (HTTP 401/403)
- **THEN** the utility terminates with exit code 2 (Authentication Failure)
- **AND** the error message includes the operation, URL, HTTP status, and parsed error message

### Requirement: Configurable SBOM format

The utility SHALL allow the SBOM format to be configured via `SNYK_SBOM_FORMAT` and MUST support any format offered by the Snyk API without code modification. The default format SHALL be `cyclonedx1.6+json`.

#### Scenario: Custom format honored

- **WHEN** `SNYK_SBOM_FORMAT` is set to a Snyk-supported value (e.g. `spdx2.3+json`)
- **THEN** the utility requests the SBOM in that format

#### Scenario: Format rejected by Snyk

- **WHEN** the configured format is not accepted by the Snyk API
- **THEN** the utility terminates with exit code 3 (SBOM Generation Failure) and surfaces the API error

### Requirement: SBOM generation

The utility SHALL invoke the Snyk SBOM endpoint for the configured project, receive the SBOM document, and validate that a successful response was returned before proceeding.

#### Scenario: Successful generation

- **WHEN** the Snyk SBOM endpoint returns a successful response with an SBOM body
- **THEN** the utility retains the SBOM in memory for upload and logs a summary (format, payload size)

#### Scenario: Generation failure

- **WHEN** the SBOM endpoint returns an error or an empty/malformed body
- **THEN** the utility terminates with exit code 3 (SBOM Generation Failure) and does not attempt the ServiceNow upload
