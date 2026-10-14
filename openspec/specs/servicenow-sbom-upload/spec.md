# servicenow-sbom-upload Specification

## Purpose
TBD - created by archiving change snyk-sbom-to-servicenow. Update Purpose after archive.
## Requirements
### Requirement: SBOM upload

After a successful SBOM generation and file persistence (API mode) or after validating a provided SBOM file (CLI mode), the utility SHALL upload the SBOM file to the ServiceNow SBOM ingestion API and validate the response. The request MUST be:

- Method/Path: `POST https://<SNOW_INSTANCE_SUBDOMAIN>.service-now.com/api/sbom/core/upload`
- Required query parameters: `businessApplicationId=<SNOW_BUSINESS_APPLICATION_ID>` and `sbomSource=<source>`, where `<source>` is `SnykAPI` when `RUN_MODE=SNYK_API` and `SnykCLI` when `RUN_MODE=SNYK_CLI`
- Optional query parameter: `buildId=<effective-build-id>`, included only when the effective build ID is non-empty and encoded using Go's standard URL query encoding
- Headers: `Authorization: Bearer <SNOW_ACCESS_TOKEN>` and `Content-Type: application/json`
- Body: the raw bytes of the SBOM file (equivalent to `curl --data-binary @<file>`)

#### Scenario: Successful upload

- **WHEN** the ServiceNow SBOM upload API returns a success response
- **THEN** the utility logs success details and terminates with exit code 0

#### Scenario: Source reflects run mode

- **WHEN** `RUN_MODE=SNYK_API`
- **THEN** the upload uses `sbomSource=SnykAPI`
- **AND** when `RUN_MODE=SNYK_CLI` the upload uses `sbomSource=SnykCLI`

#### Scenario: Neither build ID input is provided

- **WHEN** neither `BUILD_ID` nor `--buildid` is provided
- **THEN** the upload proceeds without a `buildId` query parameter

#### Scenario: Environment build ID is uploaded

- **WHEN** only `BUILD_ID` is set to a non-empty value
- **THEN** the upload includes that value as the `buildId` query parameter

#### Scenario: Command-line build ID is uploaded

- **WHEN** only `--buildid` is provided with a non-empty value
- **THEN** the upload includes that value as the `buildId` query parameter

#### Scenario: Command-line build ID takes precedence

- **WHEN** both `BUILD_ID` and `--buildid` are provided with non-empty values
- **THEN** the upload includes the command-line value as the `buildId` query parameter

#### Scenario: Effective build ID is empty

- **WHEN** the effective build ID is empty or whitespace-only
- **THEN** the upload proceeds without a `buildId` query parameter

#### Scenario: Explicitly empty command-line build ID suppresses environment value

- **WHEN** `BUILD_ID` is non-empty and `--buildid` is explicitly provided with an empty value
- **THEN** the upload proceeds without a `buildId` query parameter

#### Scenario: Build ID is URL encoded

- **WHEN** the effective build ID contains spaces or URL-reserved characters
- **THEN** the request URL encodes the `buildId` query value using Go's standard URL query encoding
- **AND** ServiceNow receives a decoded `buildId` value equal to the effective build ID

#### Scenario: Existing required query parameters are preserved

- **WHEN** an upload is constructed with or without an effective build ID
- **THEN** `SNOW_BUSINESS_APPLICATION_ID` is sent unchanged as `businessApplicationId`
- **AND** `sbomSource` continues to be selected from `RUN_MODE`

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

