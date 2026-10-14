## 1. Configuration and Command-Line Resolution

- [x] 1.1 Add optional `BUILD_ID` loading to `config.Config` without including it in required-variable or placeholder validation.
- [x] 1.2 Add the `--buildid` flag and preserve whether it was explicitly provided so its value, including empty, overrides `BUILD_ID` before client construction.
- [x] 1.3 Add focused configuration and command tests for missing inputs, environment-only input, command-line-only input, command-line precedence, and explicit-empty command-line suppression.

## 2. ServiceNow Upload Query

- [x] 2.1 Conditionally add non-empty effective build IDs to the existing ServiceNow `url.Values` query as `buildId`.
- [x] 2.2 Extend HTTP upload tests to verify omission for unavailable values, environment and command-line values, precedence, explicit-empty behavior, and URL encoding of spaces and reserved characters.
- [x] 2.3 Add regression assertions that `SNOW_BUSINESS_APPLICATION_ID` validation, `businessApplicationId`, run-mode-specific `sbomSource`, headers, and unmodified SBOM payload behavior remain unchanged.

## 3. Documentation and Verification

- [x] 3.1 Update `.env.example` and retained customer-facing README documentation with optional `BUILD_ID`, `--buildid` precedence, omission semantics, and environment/flag/explicit-empty examples.
- [x] 3.2 Run `gofmt` on changed Go files, `go test ./...`, `go vet ./...`, and the existing build target; resolve any regressions.
