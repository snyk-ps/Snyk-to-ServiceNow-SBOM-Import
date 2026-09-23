## Why

The Python utility requires a Python 3.12+ interpreter (or `uv`/`pipx`) on the target host. Some customer environments prefer a **single, statically-linked binary** with no runtime or dependency install — especially locked-down/air-gapped hosts. Go compiles to exactly that: one self-contained executable per OS/arch, no interpreter, no `pip`. This change scaffolds a Go implementation on the `go-implementation` branch that mirrors the existing, proven behavior so it can eventually be merged into `main` alongside (or ahead of) the Python version, which is preserved on the `legacy-python` branch.

## What Changes

- Add a Go module (`go.mod`) and package layout that reproduces the current tool's behavior — no behavioral changes to what the tool does, only a new implementation and distribution format.
- Mirror the existing capabilities in Go: environment/`.env` configuration, `RUN_MODE` (`SNYK_API` / `SNYK_CLI`), `SNOW_APPLICATION_SCOPE` (`SNYK_PROJECT` / `SNYK_TARGET` / `SNYK_ORG`), Snyk SBOM generation + project/target discovery, timestamped SBOM file persistence, ServiceNow upload (mode-tagged `sbomSource`), leveled logging with secret redaction, and the documented exit-code contract.
- Produce a single static binary (cross-compilable for macOS/Linux/Windows) as the Go deliverable.
- Remove the Python implementation and virtual environment from the active Go
  branch after parity is established; the snapshot remains available on the
  `legacy-python` branch.

This proposal covers **scaffolding + the parity contract**; the full Go implementation is completed during apply and subsequent work.

## Capabilities

### New Capabilities
- `go-distribution`: A Go implementation of the utility, delivered as a standalone binary, that reproduces the existing behavior (configuration, run modes, scope, SBOM generation/discovery, file persistence, ServiceNow upload, logging/redaction, exit codes) and defines the Go module/package structure.

### Modified Capabilities
<!-- None. The behavioral specs (configuration, run-mode, scope-orchestration,
     snyk-sbom-export, project-discovery, sbom-file-persistence,
     servicenow-sbom-upload, observability, http-client) are unchanged; the Go
     port MUST satisfy them identically. -->

## Impact

- New `go/` code tree containing `go.mod`, `cmd/snyk-sbom-to-servicenow/main.go`, and `internal/` packages (`config`, `logging`, `snyk`, `servicenow`, `sbomfile`, `scope`, `climode`, `httpx`).
- New build tooling: `go build` / `go vet` / `go test`; optional cross-compilation matrix and a `Makefile` or CI workflow.
- The Python package/runtime are removed from this branch after the Go parity
  checks; `openspec/specs/` and the documented behavior remain unchanged.
- Consumes the same external APIs (Snyk REST, ServiceNow SBOM upload) and the same environment variables, so `.env` files are interchangeable between the two implementations.
