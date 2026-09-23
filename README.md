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
├── cmd/snyk-sbom-to-servicenow/
├── internal/
│   ├── apperr/
│   ├── climode/
│   ├── config/
│   ├── httpx/
│   ├── logging/
│   ├── redact/
│   ├── sbomfile/
│   ├── scope/
│   ├── servicenow/
│   └── snyk/
├── Makefile
└── go.mod
```

The historical Python implementation is preserved on the `legacy-python`
branch. The `go-implementation` branch contains the active Go port.
