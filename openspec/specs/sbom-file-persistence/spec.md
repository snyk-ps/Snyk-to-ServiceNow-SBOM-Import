# sbom-file-persistence Specification

## Purpose
TBD - created by archiving change sbom-file-persistence. Update Purpose after archive.
## Requirements
### Requirement: Persist SBOM to a timestamped file

After a successful SBOM generation, the utility SHALL write the SBOM bytes, unmodified, to a file in the repository root. The filename MUST follow the pattern `<timestamp>-snyk-<project_id>-sbom.json`, where `<timestamp>` is a UTC timestamp safe for filenames.

#### Scenario: File written on successful generation

- **WHEN** Snyk returns a valid SBOM document
- **THEN** the utility writes the bytes to `<timestamp>-snyk-<project_id>-sbom.json` in the repository root
- **AND** logs the absolute path and byte size of the written file

#### Scenario: Filename includes timestamp and project id

- **WHEN** the SBOM file is created
- **THEN** the filename contains a UTC timestamp and the configured `SNYK_PROJECT_ID`
- **AND** two runs at different times produce distinct filenames

#### Scenario: Write failure is reported

- **WHEN** the SBOM file cannot be written (e.g. permission or disk error)
- **THEN** the utility terminates with exit code 3 (SBOM Generation Failure)
- **AND** the error message includes the target path and the underlying reason

### Requirement: Uploader consumes the persisted file

The ServiceNow upload SHALL read the SBOM from the persisted file (equivalent to `curl --data-binary @file`) rather than an in-memory buffer, so the uploaded content is exactly what was written to disk.

#### Scenario: Upload uses file bytes

- **WHEN** the upload step runs after the SBOM file is written
- **THEN** the bytes sent to ServiceNow are read from the persisted file and are byte-for-byte identical to the file contents

