## ADDED Requirements

### Requirement: ServiceNow authentication

The utility SHALL authenticate to the target ServiceNow instance (`SNOW_INSTANCE_SUBDOMAIN`) using the bearer access token `SNOW_ACCESS_TOKEN`. Interactive authentication MUST NOT be supported.

#### Scenario: Valid access token

- **WHEN** a valid `SNOW_ACCESS_TOKEN` is provided
- **THEN** requests to the ServiceNow SBOM upload API are authorized

#### Scenario: Authentication failure

- **WHEN** ServiceNow rejects the token (HTTP 401/403)
- **THEN** the utility terminates with exit code 2 (Authentication Failure)
- **AND** the error message includes the operation, URL, HTTP status, and parsed error message

### Requirement: SBOM upload

After a successful SBOM generation, the utility SHALL upload the SBOM document unmodified to the ServiceNow SBOM upload API, associated with the configured application `SNOW_APPLICATION_SYS_ID`, and validate the response.

#### Scenario: Successful upload

- **WHEN** the ServiceNow SBOM upload API returns a success response
- **THEN** the utility logs success details and terminates with exit code 0

#### Scenario: Upload failure

- **WHEN** the upload API returns an error or a malformed response
- **THEN** the utility terminates with exit code 4 (ServiceNow Upload Failure)
- **AND** the error message includes the operation, URL, HTTP status, and parsed error message

#### Scenario: SBOM content not modified

- **WHEN** the SBOM is uploaded
- **THEN** the payload sent to ServiceNow is byte-for-byte the SBOM received from Snyk

### Requirement: Dry-run mode

When `DRY_RUN` is truthy, the utility SHALL perform configuration validation, Snyk authentication, and SBOM generation, but MUST NOT perform the ServiceNow upload.

#### Scenario: Dry run skips upload

- **WHEN** `DRY_RUN` is enabled and SBOM generation succeeds
- **THEN** the utility logs that the upload was skipped due to dry-run and terminates with exit code 0
- **AND** no write request is sent to ServiceNow
