## ADDED Requirements

### Requirement: Project object

Discovery routines SHALL return Project objects, each carrying at least the Snyk organization id, target id, project id, and a human-readable project name, so the orchestration layer and logs can identify each processed project.

#### Scenario: Project fields populated

- **WHEN** a project is discovered
- **THEN** its org id, target id, project id, and name are available for processing and logging

### Requirement: Single-project discovery

For scope `SNYK_PROJECT`, discovery SHALL return exactly the one project identified by `SNYK_PROJECT_ID` without calling any Snyk listing endpoint.

#### Scenario: One project returned

- **WHEN** the scope is `SNYK_PROJECT`
- **THEN** discovery returns a single Project built from the configured `SNYK_ORG_ID`, `SNYK_TARGET_ID`, and `SNYK_PROJECT_ID`

### Requirement: Target-scoped discovery

For scope `SNYK_TARGET`, discovery SHALL enumerate every project associated with `SNYK_TARGET_ID` via the Snyk REST API, following pagination until all projects are retrieved.

#### Scenario: All projects for a target

- **WHEN** the scope is `SNYK_TARGET`
- **THEN** discovery returns every project belonging to the target
- **AND** additional pages are fetched until no next page remains

#### Scenario: Target has no projects

- **WHEN** the target has no projects
- **THEN** discovery returns an empty collection and the utility reports that zero projects were found

### Requirement: Organization-scoped discovery

For scope `SNYK_ORG`, discovery SHALL enumerate every target in `SNYK_ORG_ID` and every project beneath each target via the Snyk REST API, following pagination for both targets and projects.

#### Scenario: All projects for an organization

- **WHEN** the scope is `SNYK_ORG`
- **THEN** discovery returns every project across all targets in the organization
- **AND** the count of discovered targets and projects is available for the summary

### Requirement: Discovery authentication and error handling

Discovery SHALL authenticate with `SNYK_API_TOKEN`. Authentication failures (HTTP 401/403) during discovery MUST terminate execution with exit code 2 (Authentication Failure).

#### Scenario: Discovery auth failure is fatal

- **WHEN** a Snyk listing request returns 401 or 403
- **THEN** the utility terminates with exit code 2 (Authentication Failure)
- **AND** no projects are processed
