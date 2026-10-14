## 1. Module & tooling scaffold

- [x] 1.1 Create `go/` with `go.mod` (`module github.com/snyk-ps/snyk-sbom-to-servicenow`, Go 1.22+)
- [x] 1.2 Add `cmd/snyk-sbom-to-servicenow/main.go` with `--sbom-file-path` and `--version` flags (compiles, prints version)
- [x] 1.3 Add a `Makefile` with `build`, `vet`, `test`, and cross-compile (`GOOS`/`GOARCH`) targets
- [x] 1.4 Add a Go `.gitignore` section (built binaries, `*-snyk-*-sbom.json`) and a short `go/README.md`
- [x] 1.5 Remove the legacy Python source/runtime from this branch after Go parity; retain it on `legacy-python`

## 2. Foundations (errors, logging, redaction, http)

- [x] 2.1 `internal/apperr`: error types carrying exit codes (Config=1, Auth=2, SbomGen=3, Upload=4, Unexpected=5) + an `Unsupported` marker
- [x] 2.2 `internal/logging`: leveled logger (ERROR..TRACE) with timestamped format
- [x] 2.3 `internal/redact`: mask tokens/passwords/`Authorization`; wire into logging
- [x] 2.4 `internal/httpx`: `net/http` wrapper with timeout, timing, request/response logging (redacted), standardized errors, and `verify`/`CA_BUNDLE` TLS config

## 3. Configuration

- [x] 3.1 `internal/config`: `Config` struct + env load with `.env` fallback (process env wins)
- [x] 3.2 Parse/validate `RUN_MODE` (default `SNYK_CLI`) and `SNOW_APPLICATION_SCOPE` (default `SNYK_PROJECT`); invalid → exit 1
- [x] 3.3 Mode/scope-dependent required-variable validation (ServiceNow always; Snyk API + scope vars only in API mode) + placeholder (`MY_`) guard
- [x] 3.4 Defaults + `API_DRY_RUN`, `SSL_VERIFY`, `CA_BUNDLE`, `HTTP_TIMEOUT_SECONDS`; `sbomSource` derived from run mode

## 4. Snyk + persistence + ServiceNow

- [x] 4.1 `internal/snyk/sbom.go`: generate SBOM (GET `.../projects/<id>/sbom`); 401/403 → Auth, 404 → Unsupported, else → SbomGen
- [x] 4.2 `internal/snyk/discovery.go`: list projects (by target / org) and targets, following `links.next` pagination
- [x] 4.3 `internal/sbomfile`: write `<YYYYMMDDTHHMMSSZ>-snyk-<project_id>-sbom.json` (unmodified bytes)
- [x] 4.4 `internal/servicenow`: `POST /api/sbom/core/upload?businessApplicationId=<id>&sbomSource=<SnykAPI|SnykCLI>`, Bearer + `application/json`, file bytes

## 5. Orchestration & entrypoint

- [x] 5.1 `internal/scope`: discover → per-project generate/persist/upload; isolate failures; skip 404-unsupported; build summary + exit code (4 only on genuine failure)
- [x] 5.2 `internal/climode`: validate `--sbom-file-path` (exists/file/readable/non-empty → exit 1) then upload
- [x] 5.3 `cmd/.../main.go`: dispatch on `RUN_MODE`, enable system trust/CA config, map outcomes to exit codes

## 6. Tests & verification

- [x] 6.1 Table-driven tests: config validation (invalid RUN_MODE/scope, missing vars, placeholders) → exit 1
- [x] 6.2 Tests: scope exit-code mapping (all-ok → 0, any failure → 4, skips don't fail); 404 → skipped
- [x] 6.3 Tests: `sbomSource` = `SnykAPI`/`SnykCLI`; CLI-mode file validation; redaction never leaks secrets
- [x] 6.4 `go vet ./...` and `go build ./...` clean; cross-compile smoke (`GOOS=linux GOARCH=amd64`)
- [x] 6.5 Parity check against a real Snyk org in `API_DRY_RUN` and a `SNYK_CLI` upload (matches Python results)
  - API parity passed: 11 targets, 77 projects, 22 generated, 55 unsupported/skipped, 0 failed, exit 0.
  - CLI request reached the expected ServiceNow endpoint with `sbomSource=SnykCLI` and completed with HTTP 200.
