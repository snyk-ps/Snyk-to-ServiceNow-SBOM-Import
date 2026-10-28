## Why

ServiceNow deployments do not all expose the SBOM REST API through the same authentication scheme: some require a bearer access token while others require username/password Basic authentication. The utility currently hard-codes bearer authentication, preventing customers with Basic-authenticated ServiceNow instances from using the supported upload workflow.

## What Changes

- Add `SNOW_AUTH_METHOD` with the accepted values `BEARER` and `BASIC`, normalized case-insensitively and defaulting to `BEARER` for backward compatibility.
- Continue using `SNOW_ACCESS_TOKEN` and the existing `Authorization: Bearer ...` header when bearer authentication is selected.
- Use `SNOW_USERNAME` and `SNOW_PASSWORD` to construct a standards-compliant `Authorization: Basic ...` header when Basic authentication is selected.
- Validate only the credentials required by the selected authentication method, while keeping `SNOW_INSTANCE_SUBDOMAIN` and `SNOW_BUSINESS_APPLICATION_ID` required.
- Reject unsupported authentication methods with a configuration error before any network request.
- Preserve the ServiceNow endpoint, query parameters, payload, run modes, scope behavior, and exit-code mapping.
- Keep bearer tokens, Basic credentials, and complete authorization headers redacted at every log level.
- Update customer configuration, usage documentation, examples, and the Jenkins pipeline for both credential types without placing secrets in source-controlled values or build parameters.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `configuration`: Add ServiceNow authentication-method selection, backward-compatible defaults, and method-specific credential validation.
- `servicenow-sbom-upload`: Build the ServiceNow `Authorization` header from the selected bearer or Basic credentials while preserving the upload contract.
- `observability`: Explicitly require redaction coverage for both Bearer and Basic authorization headers and username/password secrets.
- `go-distribution`: Update the Go behavior-parity contract so distributed binaries support the selected ServiceNow authentication method rather than bearer-only uploads.

## Impact

- Affected Go code: configuration loading/validation, ServiceNow authorization-header construction, authentication error guidance, and related tests.
- Affected security behavior: password and authorization values remain secret; Basic credentials are encoded for transport, not logged or persisted.
- Affected customer interfaces: `.env.example`, root/Go documentation, and Jenkins credential binding.
- External API: the ServiceNow endpoint and request body remain unchanged; only the supported `Authorization` schemes expand.
- Dependencies: no new third-party dependency is required; Go standard-library encoding is sufficient.
