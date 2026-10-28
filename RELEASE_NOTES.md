# v2.2.0 — ServiceNow Basic Authentication

This backward-compatible release adds selectable Bearer or Basic
authentication for ServiceNow SBOM uploads. Existing deployments continue to
use Bearer authentication when `SNOW_AUTH_METHOD` is unset.

## Changes

- Add `SNOW_AUTH_METHOD` with case-insensitive `BEARER` and `BASIC` values.
- Keep `BEARER` as the default and continue using `SNOW_ACCESS_TOKEN`.
- Add Basic authentication using `SNOW_USERNAME` and `SNOW_PASSWORD`.
- Validate only the credentials required by the selected authentication method
  before making a network request.
- Generate the standard HTTP Basic authorization value from
  `username:password`.
- Keep authorization headers, usernames, passwords, and tokens redacted from
  logs and diagnostics.
- Provide method-specific guidance for ServiceNow HTTP 401/403 responses.
- Add a Jenkins authentication-method choice that conditionally binds either a
  Secret Text bearer token or a username/password credential.

The ServiceNow upload endpoint, query parameters, SBOM payload, build ID
behavior, and Snyk API/CLI workflows are unchanged.

## Configuration

Bearer authentication remains the default:

```dotenv
SNOW_AUTH_METHOD=BEARER
SNOW_ACCESS_TOKEN=your-access-token
```

To use Basic authentication:

```dotenv
SNOW_AUTH_METHOD=BASIC
SNOW_USERNAME=your-service-account
SNOW_PASSWORD=your-service-account-password
```

Basic authentication encodes credentials but does not encrypt them. Keep
`SSL_VERIFY=true` and configure `CA_BUNDLE` when ServiceNow uses a private
corporate certificate authority.

## Validation

- Bearer authentication was successfully tested against the staging
  environment.
- Basic authentication configuration, exact authorization-header generation,
  credential selection, error guidance, and secret redaction are covered by
  automated tests.
- Basic authentication was not exercised against a live ServiceNow environment
  because an appropriate test environment was not available for this release.
- Go formatting, vetting, unit tests, cross-compilation, and strict OpenSpec
  validation passed.

## Distribution

The release includes static binaries and SHA-256 checksums for:

- Linux amd64/arm64
- macOS amd64/arm64
- Windows amd64/arm64

No Python or Go runtime is required on customer hosts.