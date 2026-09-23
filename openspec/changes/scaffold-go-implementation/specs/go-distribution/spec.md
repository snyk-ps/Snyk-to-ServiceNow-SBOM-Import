## ADDED Requirements

### Requirement: Go module and package structure

The project SHALL include a Go module that builds a single command-line binary. The Go sources MUST live in a dedicated tree that does not interfere with the Python implementation, and MUST be organized so each behavioral concern maps to its own package.

#### Scenario: Module builds

- **WHEN** `go build ./...` is run in the Go module directory
- **THEN** it compiles without errors and produces the CLI binary

#### Scenario: Packages mirror concerns

- **WHEN** the source tree is inspected
- **THEN** there is a `main` entrypoint plus separate packages for configuration, logging, Snyk SBOM generation, project/target discovery, SBOM file persistence, ServiceNow upload, scope orchestration, CLI-mode upload, and an HTTP helper

### Requirement: Standalone binary distribution

The Go build SHALL produce a statically linked, self-contained executable that runs without a Python interpreter or any separate dependency installation, and MUST be cross-compilable for macOS, Linux, and Windows (amd64/arm64).

#### Scenario: Runs without a runtime

- **WHEN** the compiled binary is copied to a host with no Python and no Go toolchain
- **THEN** it runs using only the binary itself

#### Scenario: Cross-compilation

- **WHEN** the binary is built with a target `GOOS`/`GOARCH` (e.g. `GOOS=linux GOARCH=amd64`)
- **THEN** a working executable for that platform is produced

### Requirement: Behavioral parity with the reference implementation

The Go implementation SHALL reproduce the behavior defined by the existing capability specs — `configuration`, `run-mode`, `scope-orchestration`, `snyk-sbom-export`, `project-discovery`, `sbom-file-persistence`, `servicenow-sbom-upload`, and `observability` — without changing that behavior. It MUST read the same environment variables and `.env` file, accept the same `--sbom-file-path` argument, write the same `<timestamp>-snyk-<project_id>-sbom.json` files, and call the same Snyk and ServiceNow endpoints.

#### Scenario: Same configuration inputs

- **WHEN** the Go binary is run with a `.env`/environment that the Python tool accepts
- **THEN** it validates `RUN_MODE`, `SNOW_APPLICATION_SCOPE`, and the mode/scope-dependent required variables the same way, failing fast on invalid or missing values

#### Scenario: Same run modes and scope

- **WHEN** `RUN_MODE=SNYK_API` with a given `SNOW_APPLICATION_SCOPE`
- **THEN** the Go binary discovers and processes the same set of projects (project / target / org) and uploads one SBOM per project to the configured Business Application
- **AND** `RUN_MODE=SNYK_CLI` uploads a validated `--sbom-file-path` file directly

#### Scenario: Same ServiceNow request

- **WHEN** an SBOM is uploaded
- **THEN** the request targets `POST /api/sbom/core/upload?businessApplicationId=<id>&sbomSource=<SnykAPI|SnykCLI>` with a Bearer token and `Content-Type: application/json`, sending the file bytes unmodified

#### Scenario: Same skip/failure semantics

- **WHEN** a project's SBOM endpoint returns HTTP 404
- **THEN** that project is recorded as skipped (unsupported), not failed, and does not drive a failure exit code

### Requirement: Exit-code parity

The Go binary SHALL use the same process exit codes as the reference implementation: 0 success, 1 configuration error, 2 authentication failure, 3 SBOM generation failure, 4 ServiceNow upload failure, 5 unexpected error.

#### Scenario: Documented exit codes

- **WHEN** a given failure category occurs
- **THEN** the process exits with the corresponding documented code

### Requirement: TLS trust and secret redaction

The Go implementation SHALL verify TLS against the operating system trust store by default (Go's crypto/x509 uses the system roots), and SHALL support an equivalent to `CA_BUNDLE` and `SSL_VERIFY`. It MUST redact secrets (tokens, passwords, `Authorization` headers) in all log output.

#### Scenario: Secrets never logged

- **WHEN** requests or configuration are logged at any level
- **THEN** tokens and `Authorization` header values are masked

#### Scenario: Custom CA bundle honored

- **WHEN** a CA bundle path is configured
- **THEN** TLS verification uses that bundle
