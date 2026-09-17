## ADDED Requirements

### Requirement: Run mode selection

The utility SHALL read `RUN_MODE` to decide how it obtains the SBOM. It MUST accept exactly the values `SNYK_API` and `SNYK_CLI`, defaulting to `SNYK_API` when unset. Any other value MUST terminate execution with exit code 1 (Configuration Error) before any other work.

#### Scenario: Default run mode

- **WHEN** `RUN_MODE` is not set
- **THEN** the mode is `SNYK_API`

#### Scenario: Valid run mode accepted

- **WHEN** `RUN_MODE` is `SNYK_API` or `SNYK_CLI`
- **THEN** the utility proceeds in that mode

#### Scenario: Invalid run mode rejected

- **WHEN** `RUN_MODE` is any other value
- **THEN** the utility terminates with exit code 1 (Configuration Error)
- **AND** the error message lists the accepted values

### Requirement: Snyk CLI mode upload

In `SNYK_CLI` mode the utility SHALL require a `--sbom-file-path` command-line argument, validate that it points to an existing, readable, non-empty file **before** any network call, and then upload that file's bytes unmodified to ServiceNow using the existing SBOM upload endpoint with `sbomSource=SnykCLI`. The utility MUST NOT call the Snyk API, perform discovery, apply a scope, or persist a new SBOM file in this mode.

#### Scenario: Valid SBOM file uploaded

- **WHEN** `RUN_MODE=SNYK_CLI` and `--sbom-file-path` points to a readable, non-empty file
- **THEN** the utility uploads that file to ServiceNow with `sbomSource=SnykCLI` and exits 0 on success

#### Scenario: Missing or invalid SBOM file path

- **WHEN** `RUN_MODE=SNYK_CLI` and `--sbom-file-path` is absent, or the path does not exist / is empty / is unreadable
- **THEN** the utility terminates with exit code 1 (Configuration Error) before any network call
- **AND** the error message identifies the problem with the path

#### Scenario: No Snyk API calls in CLI mode

- **WHEN** running in `SNYK_CLI` mode
- **THEN** no request is made to the Snyk API and no scope discovery is performed

### Requirement: API_DRY_RUN not applicable in CLI mode

`API_DRY_RUN` SHALL have no effect in `SNYK_CLI` mode. If it is set truthy while `RUN_MODE=SNYK_CLI`, the utility SHALL proceed with the upload and MAY log that dry-run is ignored in CLI mode.

#### Scenario: Dry-run ignored in CLI mode

- **WHEN** `RUN_MODE=SNYK_CLI` and `API_DRY_RUN` is truthy
- **THEN** the SBOM file is still uploaded (dry-run is ignored)
