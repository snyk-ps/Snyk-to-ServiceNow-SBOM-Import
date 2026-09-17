## MODIFIED Requirements

### Requirement: SBOM generation

The utility SHALL invoke the Snyk SBOM endpoint for the configured project, receive the SBOM document, and validate that a successful response was returned before proceeding. A response of HTTP 404 from the SBOM endpoint MUST be interpreted as "SBOM is not supported for this project" — a distinct *unsupported* outcome — rather than a generic generation failure. Other error responses and empty/malformed bodies remain generation failures.

#### Scenario: Successful generation

- **WHEN** the Snyk SBOM endpoint returns a successful response with an SBOM body
- **THEN** the utility retains the SBOM in memory for upload and logs a summary (format, payload size)

#### Scenario: Unsupported project (404)

- **WHEN** the Snyk SBOM endpoint returns HTTP 404 for the project
- **THEN** the utility signals an "unsupported" outcome (distinct from a generation failure)
- **AND** in a single-project run this is treated as skipped, exiting 0 with a warning that the project does not support SBOM export

#### Scenario: Generation failure

- **WHEN** the SBOM endpoint returns a non-404 error, or an empty/malformed body
- **THEN** the utility treats it as an SBOM Generation Failure (exit code 3 for a single-project run) and does not attempt the ServiceNow upload
