# Snyk SBOM → ServiceNow Upload Utility

**Go release:** 1.0.0

A standalone Go command that exports Software Bills of Materials from Snyk and
uploads them to ServiceNow Vulnerability Response. Customer deployments receive
a single native executable: no Python, Go toolchain, or package installation is
required on the target host.

## Features

- `SNYK_API` and `SNYK_CLI` run modes
- Project, target, and organization API scopes
- Timestamped JSON SBOM files
- ServiceNow `sbomSource=SnykAPI` / `SnykCLI`
- Paginated Snyk discovery
- Unsupported project types are skipped rather than failed
- OS trust-store TLS, custom CA bundles, and secret-redacted logging
- Static binaries for Linux, macOS, and Windows (amd64/arm64)

## Requirements

Customer runtime:

- The platform-specific executable only (no Python, Go, or package installation)
- Network access to the configured Snyk and ServiceNow endpoints
- A populated `.env` file or equivalent process environment variables

Development/build:

- Go 1.22 or newer
- `make` for the provided convenience targets

## Customer deployment

Select the executable matching the customer platform from `go/dist/`:

```text
snyk-sbom-to-servicenow-linux-amd64
snyk-sbom-to-servicenow-linux-arm64
snyk-sbom-to-servicenow-darwin-amd64
snyk-sbom-to-servicenow-darwin-arm64
snyk-sbom-to-servicenow-windows-amd64.exe
snyk-sbom-to-servicenow-windows-arm64.exe
```

Copy the executable and `.env.example` to the deployment directory, rename
`.env.example` to `.env`, and populate the required values. Run from that
directory so the binary finds `.env` and writes generated SBOM files there.

```bash
chmod +x snyk-sbom-to-servicenow-linux-amd64
./snyk-sbom-to-servicenow-linux-amd64 --version
./snyk-sbom-to-servicenow-linux-amd64
```

Windows:

```powershell
.\snyk-sbom-to-servicenow-windows-amd64.exe --version
.\snyk-sbom-to-servicenow-windows-amd64.exe
```

## Build from source

Build/test requires Go 1.22 or newer. Runtime hosts do not need Go.

```bash
cd go
make check
make build
./bin/snyk-sbom-to-servicenow --version
```

Build the complete customer release matrix:

```bash
cd go
make cross-compile VERSION=1.0.0
```

Release artifacts are written to `go/dist/`. Use `--version` for the embedded
semantic version and `--help` for the available command-line flags.

## Jenkins pipeline

The repository-root `Jenkinsfile` provides a parameterized Declarative Pipeline
for both run modes. It checks out the repository, validates parameters, runs
`gofmt`/`go vet`/`go test`, builds a static binary, executes it, and archives
the binary plus generated SBOM files.

Jenkins agent requirements:

- Go 1.22 or newer
- Network access to the selected Snyk and ServiceNow endpoints
- Jenkins Credentials Binding plugin
- Secret Text credentials for the Snyk API token and ServiceNow access token.
  The Jenkinsfile defaults to credential IDs `snyk-api-token` and
  `servicenow-access-token`; edit `SNYK_TOKEN_CREDENTIAL_ID` and
  `SNOW_TOKEN_CREDENTIAL_ID` in its `environment` block if your IDs differ.

Create a Pipeline or Multibranch Pipeline job using **Pipeline script from
SCM** and leave the script path as `Jenkinsfile`. Configure the job parameters
on the first run:

- `RUN_MODE`: `SNYK_API` or `SNYK_CLI`
- `SNOW_APPLICATION_SCOPE`: project, target, or org (API mode)
- Snyk/ServiceNow IDs
- `API_DRY_RUN` (defaults to true)
- `SBOM_FILE_PATH` (required for CLI mode; file must exist in the workspace)

Tokens are bound with fixed `withCredentials` IDs (not build parameters), shell
tracing is disabled during execution, application logs redact authorization
values, and endpoint parameters are validated to prevent credential forwarding
to arbitrary hosts. Restrict job configuration/build permissions as usual for
credentialed pipelines.

## Run modes

### SNYK_API

The default mode discovers projects and generates SBOMs through the Snyk REST
API.

```bash
RUN_MODE=SNYK_API ./snyk-sbom-to-servicenow
```

`SNOW_APPLICATION_SCOPE` controls processing:

| Value | Required Snyk identifiers | Behavior |
| --- | --- | --- |
| `SNYK_PROJECT` | `SNYK_ORG_ID`, `SNYK_TARGET_ID`, `SNYK_PROJECT_ID` | One project |
| `SNYK_TARGET` | `SNYK_ORG_ID`, `SNYK_TARGET_ID` | All projects in a target |
| `SNYK_ORG` | `SNYK_ORG_ID` | All projects in an organization |

Set `API_DRY_RUN=true` to generate/persist files without uploading them.

### SNYK_CLI

Generate a JSON SBOM with the native
[`snyk sbom`](https://docs.snyk.io/developer-tools/snyk-cli/snyk-cli/commands/sbom)
command, then provide it to the Go binary:

```bash
snyk sbom --format=cyclonedx1.6+json --all-projects > sbom.json
RUN_MODE=SNYK_CLI ./snyk-sbom-to-servicenow --sbom-file-path ./sbom.json
```

The file is validated before any network request and uploaded unmodified with
`sbomSource=SnykCLI`. `API_DRY_RUN` is intentionally ignored in CLI mode.

## Configuration

Environment variables override values from `.env`.

Always required:

- `SNOW_INSTANCE_SUBDOMAIN`
- `SNOW_ACCESS_TOKEN`
- `SNOW_BUSINESS_APPLICATION_ID`

Additionally required in API mode:

- `SNYK_API_TOKEN`
- `SNYK_ORG_ID`
- Scope-dependent target/project identifiers from the table above

Optional defaults:

| Variable | Default |
| --- | --- |
| `RUN_MODE` | `SNYK_API` |
| `SNOW_APPLICATION_SCOPE` | `SNYK_PROJECT` |
| `SNYK_BASE_URL` | `https://api.snyk.io/rest` |
| `SNYK_SBOM_FORMAT` | `cyclonedx1.6+json` |
| `DEBUG_LEVEL` | `INFO` |
| `API_DRY_RUN` | `false` |
| `HTTP_TIMEOUT_SECONDS` | `60` |
| `SSL_VERIFY` | `true` |
| `CA_BUNDLE` | unset |

## ServiceNow request

```text
POST https://<instance>.service-now.com/api/sbom/core/upload
     ?businessApplicationId=<id>&sbomSource=<SnykAPI|SnykCLI>
Authorization: Bearer <SNOW_ACCESS_TOKEN>
Content-Type: application/json
Body: unmodified SBOM file bytes
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Configuration error |
| 2 | Authentication failure |
| 3 | SBOM generation failure |
| 4 | ServiceNow upload / partial project failure |
| 5 | Unexpected error |

## Development layout

```text
go/
├── cmd/snyk-sbom-to-servicenow/  executable entrypoint
├── internal/
│   ├── apperr/                   typed errors and exit codes
│   ├── climode/                  SNYK_CLI orchestration
│   ├── config/                   .env loading, defaults, validation
│   ├── httpx/                    HTTP/TLS wrapper
│   ├── logging/                  leveled logging
│   ├── redact/                   secret redaction
│   ├── sbomfile/                 timestamped file persistence
│   ├── scope/                    API scope orchestration and summary
│   ├── servicenow/               ServiceNow upload client
│   └── snyk/                     Snyk SBOM and discovery clients
├── Makefile                      build/test/cross-compile targets
└── go.mod                        Go module definition
```

The historical Python implementation is preserved on the `legacy-python`
branch. The `go-implementation` branch contains the active Go port.
