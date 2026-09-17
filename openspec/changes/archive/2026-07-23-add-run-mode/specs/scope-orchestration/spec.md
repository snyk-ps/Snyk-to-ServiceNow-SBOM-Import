## MODIFIED Requirements

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
