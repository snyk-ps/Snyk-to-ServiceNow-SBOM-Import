# scope-orchestration Specification

## Purpose
TBD - created by archiving change configurable-application-scope. Update Purpose after archive.
## Requirements
### Requirement: Scope-driven orchestration

In `SNYK_API` mode the utility SHALL, after configuration validation, dispatch to the discovery routine for the selected `SNOW_APPLICATION_SCOPE` and then process each discovered project through the existing SBOM generate → persist → validate → upload workflow, unchanged. Each SBOM is uploaded independently to the same configured ServiceNow Business Application. Scope discovery and generation do not run in `SNYK_CLI` mode.

#### Scenario: Project scope processes one project

- **WHEN** `RUN_MODE=SNYK_API` and the scope is `SNYK_PROJECT`
- **THEN** exactly one SBOM is generated and uploaded (identical to the prior single-project behavior)

#### Scenario: Target/Org scope processes many projects

- **WHEN** `RUN_MODE=SNYK_API` and the scope is `SNYK_TARGET` or `SNYK_ORG`
- **THEN** the utility generates and uploads one SBOM per discovered project
- **AND** every upload targets the same `SNOW_BUSINESS_APPLICATION_ID`

#### Scenario: Dry run across scope

- **WHEN** `API_DRY_RUN` is enabled in `SNYK_API` mode
- **THEN** each discovered project's SBOM is generated and persisted but not uploaded

#### Scenario: Scope not applied in CLI mode

- **WHEN** `RUN_MODE=SNYK_CLI`
- **THEN** no scope discovery or SBOM generation is performed

### Requirement: Per-project failure isolation

Processing of one project MUST NOT stop processing of the remaining projects. Per-project generation or upload failures SHALL be logged and recorded, and the run continues. A project whose SBOM is unsupported (Snyk returns HTTP 404) SHALL be recorded as *skipped* rather than failed. Only fatal configuration or authentication errors terminate the whole run.

#### Scenario: One project fails, others continue

- **WHEN** a project's SBOM generation or upload fails
- **THEN** the failure is logged and recorded
- **AND** the utility continues with the remaining projects

#### Scenario: Unsupported project is skipped, not failed

- **WHEN** a project's SBOM endpoint returns HTTP 404 (unsupported)
- **THEN** the project is recorded as skipped (not failed) and logged as unsupported
- **AND** the utility continues with the remaining projects

#### Scenario: Fatal error aborts

- **WHEN** a configuration error or an authentication failure occurs
- **THEN** the utility terminates immediately with the corresponding exit code (1 or 2)

### Requirement: Progress and summary reporting

While processing multiple projects the utility SHALL emit progress for each project (including organization, target, project, SBOM format, upload status, and elapsed time) and, at completion, SHALL print a summary including the scope, counts of targets discovered, projects discovered, SBOMs generated, successful uploads, skipped (unsupported) projects, failed projects, and total elapsed time.

#### Scenario: Progress per project

- **WHEN** multiple projects are processed
- **THEN** each project logs its position (e.g. "Processing Project 7 of 42"), identity, and result (success, skipped, or failed)

#### Scenario: Final summary

- **WHEN** processing completes
- **THEN** a summary of scope, discovered targets/projects, generated SBOMs, successful uploads, skipped (unsupported) projects, failed projects, and elapsed time is displayed

### Requirement: Exit code with partial failures

When at least one project is processed and one or more projects genuinely fail (generation errors other than unsupported, or upload failures), the utility SHALL exit with code 4 (ServiceNow Upload Failure). Skipped (unsupported) projects MUST NOT contribute to the failure exit code. When every processed project either succeeds or is skipped as unsupported, the utility SHALL exit 0.

#### Scenario: Some projects fail

- **WHEN** processing finishes with one or more genuine failures and no fatal error
- **THEN** the utility exits with code 4 after printing the summary

#### Scenario: Only skips and successes

- **WHEN** every non-successful project was skipped as unsupported (no genuine failures)
- **THEN** the utility exits with code 0
- **AND** the summary reports how many projects were skipped as unsupported

#### Scenario: All uploads succeed

- **WHEN** every discovered project uploads successfully
- **THEN** the utility exits with code 0

