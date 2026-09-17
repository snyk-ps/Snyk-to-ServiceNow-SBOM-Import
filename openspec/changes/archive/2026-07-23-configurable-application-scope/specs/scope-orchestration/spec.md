## ADDED Requirements

### Requirement: Scope-driven orchestration

The utility SHALL, after configuration validation, dispatch to the discovery routine for the selected `SNOW_APPLICATION_SCOPE` and then process each discovered project through the existing SBOM generate → persist → validate → upload workflow, unchanged. Each SBOM is uploaded independently to the same configured ServiceNow Business Application.

#### Scenario: Project scope processes one project

- **WHEN** the scope is `SNYK_PROJECT`
- **THEN** exactly one SBOM is generated and uploaded (identical to the prior single-project behavior)

#### Scenario: Target/Org scope processes many projects

- **WHEN** the scope is `SNYK_TARGET` or `SNYK_ORG`
- **THEN** the utility generates and uploads one SBOM per discovered project
- **AND** every upload targets the same `SNOW_BUSINESS_APPLICATION_ID`

#### Scenario: Dry run across scope

- **WHEN** `DRY_RUN` is enabled
- **THEN** each discovered project's SBOM is generated and persisted but not uploaded

### Requirement: Per-project failure isolation

Processing of one project MUST NOT stop processing of the remaining projects. Per-project generation or upload failures SHALL be logged and recorded, and the run continues. Only fatal configuration or authentication errors terminate the whole run.

#### Scenario: One project fails, others continue

- **WHEN** a project's SBOM generation or upload fails
- **THEN** the failure is logged and recorded
- **AND** the utility continues with the remaining projects

#### Scenario: Fatal error aborts

- **WHEN** a configuration error or an authentication failure occurs
- **THEN** the utility terminates immediately with the corresponding exit code (1 or 2)

### Requirement: Progress and summary reporting

While processing multiple projects the utility SHALL emit progress for each project (including organization, target, project, SBOM format, upload status, and elapsed time) and, at completion, SHALL print a summary including the scope, counts of targets discovered, projects discovered, SBOMs generated, successful uploads, failed uploads, and total elapsed time.

#### Scenario: Progress per project

- **WHEN** multiple projects are processed
- **THEN** each project logs its position (e.g. "Processing Project 7 of 42"), identity, and result

#### Scenario: Final summary

- **WHEN** processing completes
- **THEN** a summary of scope, discovered targets/projects, generated SBOMs, successful and failed uploads, and elapsed time is displayed

### Requirement: Exit code with partial failures

When at least one project is processed but one or more uploads fail, the utility SHALL exit with code 4 (ServiceNow Upload Failure). When all processed projects succeed, it SHALL exit 0.

#### Scenario: Some uploads fail

- **WHEN** processing finishes with one or more failed uploads and no fatal error
- **THEN** the utility exits with code 4 after printing the summary

#### Scenario: All uploads succeed

- **WHEN** every discovered project uploads successfully
- **THEN** the utility exits with code 0
