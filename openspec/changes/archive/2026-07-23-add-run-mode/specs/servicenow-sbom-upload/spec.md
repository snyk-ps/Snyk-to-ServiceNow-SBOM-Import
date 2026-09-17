## MODIFIED Requirements

### Requirement: SBOM upload

After a successful SBOM generation and file persistence (API mode) or after validating a provided SBOM file (CLI mode), the utility SHALL upload the SBOM file to the ServiceNow SBOM ingestion API and validate the response. The request MUST be:

- Method/Path: `POST https://<SNOW_INSTANCE_SUBDOMAIN>.service-now.com/api/sbom/core/upload`
- Query parameters: `businessApplicationId=<SNOW_BUSINESS_APPLICATION_ID>` and `sbomSource=<source>`, where `<source>` is `SnykAPI` when `RUN_MODE=SNYK_API` and `SnykCLI` when `RUN_MODE=SNYK_CLI`
- Headers: `Authorization: Bearer <SNOW_ACCESS_TOKEN>` and `Content-Type: application/json`
- Body: the raw bytes of the SBOM file (equivalent to `curl --data-binary @<file>`)

#### Scenario: Successful upload

- **WHEN** the ServiceNow SBOM upload API returns a success response
- **THEN** the utility logs success details and terminates with exit code 0

#### Scenario: Source reflects run mode

- **WHEN** `RUN_MODE=SNYK_API`
- **THEN** the upload uses `sbomSource=SnykAPI`
- **AND** when `RUN_MODE=SNYK_CLI` the upload uses `sbomSource=SnykCLI`

#### Scenario: Upload failure

- **WHEN** the upload API returns an error or a malformed response
- **THEN** the utility terminates with exit code 4 (ServiceNow Upload Failure)
- **AND** the error message includes the operation, URL, HTTP status, and parsed error message

#### Scenario: SBOM content not modified

- **WHEN** the SBOM is uploaded
- **THEN** the payload sent to ServiceNow is byte-for-byte the SBOM file being uploaded

### Requirement: Dry-run mode

When `API_DRY_RUN` is truthy in `SNYK_API` mode, the utility SHALL perform configuration validation, Snyk authentication, and SBOM generation, but MUST NOT perform the ServiceNow upload. `API_DRY_RUN` has no effect in `SNYK_CLI` mode (the provided SBOM file is still uploaded).

#### Scenario: Dry run skips upload

- **WHEN** `API_DRY_RUN` is enabled in `SNYK_API` mode and SBOM generation succeeds
- **THEN** the utility logs that the upload was skipped due to dry-run and terminates with exit code 0
- **AND** no write request is sent to ServiceNow

#### Scenario: Dry run ignored in CLI mode

- **WHEN** `RUN_MODE=SNYK_CLI` and `API_DRY_RUN` is truthy
- **THEN** the SBOM file is uploaded normally (dry-run does not apply)
