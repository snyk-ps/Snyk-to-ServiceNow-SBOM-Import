## Context

The reference implementation was a single-file / `app/`-package Python tool whose behavior is captured by the archived specs (`configuration`, `run-mode`, `scope-orchestration`, `snyk-sbom-export`, `project-discovery`, `sbom-file-persistence`, `servicenow-sbom-upload`, `observability`, `http-client`). This change ports that behavior to Go on the `go-implementation` branch and ships a single static binary. The Python snapshot is preserved on `legacy-python`; after parity verification it is removed from this active branch.

## Goals / Non-Goals

**Goals:**
- Establish the Go module + package layout and the build/test workflow.
- Define the mapping from Python modules to Go packages so implementation is mechanical.
- Preserve behavior exactly: same env vars, `.env`, `RUN_MODE`, scope, endpoints, filenames, exit codes, redaction, TLS.
- Produce a cross-compilable, dependency-free binary.

**Non-Goals:**
- Changing any behavior or the ServiceNow/Snyk request contracts.
- New features beyond parity (future work).

## Decisions

### Repository placement
Put the Go module in a top-level `go/` directory. Module path: `module github.com/snyk-ps/snyk-sbom-to-servicenow` (adjust to the final repo path). Binary name: `snyk-sbom-to-servicenow`.

### Layout (standard Go project conventions)

```
go/
├── go.mod
├── go.sum
├── Makefile                         # build / vet / test / cross-compile targets
├── cmd/
│   └── snyk-sbom-to-servicenow/
│       └── main.go                  # flag parsing (--sbom-file-path, --version), dispatch, exit codes
└── internal/
    ├── config/     config.go        # env + .env load, RUN_MODE/scope validation, defaults, placeholder guard
    ├── logging/    logging.go       # leveled logger (ERROR..TRACE) + timestamped format
    ├── redact/     redact.go        # secret redaction helpers (tokens/authorization)
    ├── httpx/      client.go        # HTTP wrapper: timeout, timing, logging, standardized errors, verify/CA bundle
    ├── snyk/       sbom.go          # SBOM generation (GET .../sbom); 404 -> unsupported
    │               discovery.go     # list projects/targets, pagination (links.next)
    ├── sbomfile/   sbomfile.go      # timestamped file write (<ts>-snyk-<project_id>-sbom.json)
    ├── servicenow/ client.go        # POST /api/sbom/core/upload, mode-based sbomSource
    ├── scope/      scope.go         # discover -> per-project generate/persist/upload, summary, exit mapping
    ├── climode/    climode.go       # SNYK_CLI: validate --sbom-file-path, upload
    └── apperr/     errors.go        # error types carrying exit codes (Config/Auth/SbomGen/Unsupported/Upload)
```

### Python → Go mapping

| Python | Go package | Notes |
| --- | --- | --- |
| `errors.py` (`AppError`, `ExitCode`) | `internal/apperr` | Go error types implementing an `ExitCode() int`; sentinel-style with `errors.As` |
| `logging.py` | `internal/logging` | `log/slog` with a custom TRACE level, or a thin leveled wrapper |
| `utils/debug.py` (redaction) | `internal/redact` + logging | Redact before logging; mask `Authorization`, token/password keys |
| `utils/validators.py` | `internal/config` helpers | `parseBool`, required-key checks |
| `utils/http.py` | `internal/httpx` | `net/http` client with `http.Client{Timeout}`, `tls.Config` |
| `config.py` | `internal/config` | `Config` struct; `os.Getenv` + `.env` parse |
| `snyk_client.py` | `internal/snyk/sbom.go` | `SbomDocument` struct; 404 → `ErrUnsupported` |
| `project_discovery.py` | `internal/snyk/discovery.go` | `Project`/`Target` structs; JSON:API pagination |
| `sbom_file.py` | `internal/sbomfile` | UTC `YYYYMMDDTHHMMSSZ` filename |
| `servicenow_client.py` | `internal/servicenow` | `sbomSource` from run mode |
| `sbom_service.py` + `scope_manager.py` | `internal/scope` | per-project loop, `ProjectResult`/`Summary`, exit code from failures |
| `cli_mode.py` | `internal/climode` | file validation + upload |
| `main.py` | `cmd/.../main.go` | `flag` parsing, dispatch, `os.Exit(code)` |

### Dependencies
Prefer the **standard library** to keep the binary dependency-free and auditable:
- HTTP: `net/http`; JSON: `encoding/json`; TLS: `crypto/tls` + `crypto/x509` (system roots by default; `SystemCertPool` + optional `CA_BUNDLE` file).
- Flags: `flag` (stdlib). Logging: `log/slog` (stdlib, Go 1.21+).
- `.env` parsing: a tiny hand-rolled parser (matching python-dotenv semantics: `KEY='value'`, `#` comments, process env wins) to avoid a third-party dep — or `github.com/joho/godotenv` if preferred. Default to hand-rolled to keep zero external deps.

Target **Go 1.22+**.

### TLS parity
Go's `net/http` already validates against the OS trust store by default, which is the behavior `truststore` gives Python. `SSL_VERIFY=false` → `tls.Config{InsecureSkipVerify: true}` (documented, discouraged). `CA_BUNDLE` → load the PEM into a `*x509.CertPool` set on `tls.Config.RootCAs`.

### Exit codes
Define constants mirroring `ExitCode`; each error type exposes its code; `main` does `os.Exit(code)`. In `SNYK_API` scope runs, the summary computes the code (0, or 4 if any genuine failure; skips don't count) exactly like the Python `ScopeSummary`.

## Risks / Trade-offs

- [Behavioral drift between Python and Go] → The specs are the shared contract; add a parity checklist and, where feasible, table-driven Go tests mirroring the Python verification (config validation, scope exit codes, 404-skip, sbomSource). → Mitigation: keep both green against the same specs.
- [Snyk JSON:API pagination/shape parsing in Go] → Isolate in `internal/snyk/discovery.go` with defensive decoding; unit-test with sample payloads.
- [`.env` parser divergence] → Hand-rolled parser must match the subset actually used (quoted values, comments, env precedence); cover with tests, or adopt `godotenv` if edge cases appear.
- [Two implementations to maintain] → Acceptable during transition; `legacy-python` branch preserves Python, and `main` can adopt Go once at parity.

## Migration Plan

Implement on the `go-implementation` branch. Scaffold the module + packages with compiling stubs and a working `--version`/config-validation path first, then port package-by-package (config → httpx → snyk → servicenow → scope/climode → main), validate against the specs, and remove the Python implementation from this branch. Merge into `main` via PR when at parity; keep `legacy-python` as the archived Python snapshot.

## Open Questions

- Final Go module path (depends on the canonical repo URL / org).
- Whether to keep zero external dependencies (hand-rolled `.env`) or allow `godotenv` — defaulting to zero-dep.
- Distribution: raw `go build` binaries vs. GoReleaser + checksums/signing for customer delivery (can be decided when wiring CI).
