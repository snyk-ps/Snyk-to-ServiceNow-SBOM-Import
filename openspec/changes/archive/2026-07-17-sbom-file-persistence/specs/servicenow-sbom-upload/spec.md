## MODIFIED Requirements

### Requirement: SBOM upload

After a successful SBOM generation and file persistence, the utility SHALL upload the persisted SBOM file to the ServiceNow SBOM ingestion API and validate the response. The request MUST be:

- Method/Path: `POST https://<SNOW_INSTANCE_SUBDOMAIN>.service-now.com/api/sbom/core/upload`
- Query parameters: `businessApplicationId=<SNOW_BUSINESS_APPLICATION_ID>` and `sbomSource=Snyk`
- Headers: `Authorization: Bearer <SNOW_ACCESS_TOKEN>` and `Content-Type: application/json`
- Body: the raw bytes of the persisted SBOM file (equivalent to `curl --data-binary @<file>`)

#### Scenario: Successful upload

- **WHEN** the ServiceNow SBOM upload API returns a success response
- **THEN** the utility logs success details and terminates with exit code 0

#### Scenario: Upload failure

- **WHEN** the upload API returns an error or a malformed response
- **THEN** the utility terminates with exit code 4 (ServiceNow Upload Failure)
- **AND** the error message includes the operation, URL, HTTP status, and parsed error message

#### Scenario: SBOM content not modified

- **WHEN** the SBOM is uploaded
- **THEN** the payload sent to ServiceNow is byte-for-byte the persisted SBOM file (which itself is byte-for-byte the SBOM received from Snyk)

## REMOVED Requirements

### Requirement: ServiceNow authentication

**Reason**: Folded into the updated "SBOM upload" requirement, which now fully specifies the authenticated request (Bearer token, endpoint, query params). The standalone auth requirement is redundant.
**Migration**: No action needed; `SNOW_ACCESS_TOKEN` continues to be used as the Bearer token on the upload request.
