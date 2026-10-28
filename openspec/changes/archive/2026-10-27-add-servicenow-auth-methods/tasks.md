## 1. Authentication Configuration

- [x] 1.1 Add `BEARER` / `BASIC` authentication constants, a bearer default, and ServiceNow auth method, username, and password fields to `config.Config`.
- [x] 1.2 Normalize and validate `SNOW_AUTH_METHOD`, rejecting unsupported non-empty values before network activity.
- [x] 1.3 Refactor required-variable and placeholder validation so common ServiceNow fields plus only the selected method's credentials are required.
- [x] 1.4 Add table-driven configuration tests for the bearer default, case normalization, invalid methods, method-specific missing values, inactive credentials, and existing run-mode/scope rules.

## 2. ServiceNow Authorization

- [x] 2.1 Add ServiceNow authorization-header construction for bearer tokens and standard Base64-encoded Basic username/password credentials.
- [x] 2.2 Use only the selected authentication method while preserving the upload endpoint, query parameters, headers, and byte-for-byte SBOM body.
- [x] 2.3 Make HTTP 401/403 guidance name the selected method's credential variables without including credential values.
- [x] 2.4 Extend ServiceNow client tests to assert exact Bearer and Basic headers, selected-method precedence, unchanged request content, and exit-code/error guidance for authentication failures.

## 3. Secret Redaction

- [x] 3.1 Extend sensitive-key handling for ServiceNow Basic-authentication usernames while retaining token, password, and authorization-header masking.
- [x] 3.2 Add leak-focused tests proving raw bearer tokens, Basic usernames/passwords, and Base64-encoded Basic credentials never appear in logged header summaries or diagnostics.

## 4. Customer and Jenkins Configuration

- [x] 4.1 Update `.env.example` with the bearer default, method-specific variables, and placeholder-only credential examples.
- [x] 4.2 Update the root and Go README guidance with required variables, Bearer/Basic examples, migration behavior, TLS guidance, and authentication troubleshooting.
- [x] 4.3 Add a Jenkins `SNOW_AUTH_METHOD` choice and conditionally bind either the existing Secret Text token or a username/password credential without exposing secrets as normal parameters.

## 5. Verification

- [x] 5.1 Run `gofmt` on changed Go files and run focused configuration, ServiceNow, redaction, and Jenkins syntax checks.
- [x] 5.2 Run `go test ./...`, `go vet ./...`, the existing build target, strict OpenSpec validation, and diff/lint checks; resolve any regressions.
