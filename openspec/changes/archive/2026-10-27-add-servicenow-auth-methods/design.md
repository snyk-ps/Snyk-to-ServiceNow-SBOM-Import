## Context

The Go configuration currently treats `SNOW_ACCESS_TOKEN` as an always-required ServiceNow variable, and the ServiceNow client always constructs `Authorization: Bearer <token>`. The HTTP wrapper accepts an arbitrary header map and already redacts both `Bearer` and `Basic` authorization schemes, so authentication selection can remain inside the ServiceNow domain without changing the shared HTTP transport.

This change crosses configuration, request construction, error reporting, redaction tests, documentation, and Jenkins credential binding. It must preserve existing bearer deployments while ensuring Basic credentials never appear in logs, examples, command arguments, or source-controlled pipeline parameters.

## Goals / Non-Goals

**Goals:**

- Select `BEARER` or `BASIC` ServiceNow authentication through `SNOW_AUTH_METHOD`.
- Keep an unset authentication method fully backward compatible with current bearer behavior.
- Validate only the credentials required by the selected method before network activity.
- Construct standards-compliant Basic and Bearer authorization headers.
- Preserve existing upload URLs, query parameters, request bodies, failure categories, run modes, and project scopes.
- Keep all ServiceNow credentials and authorization values redacted.
- Support secure credential binding for either method in the included Jenkins pipeline.

**Non-Goals:**

- ServiceNow OAuth token acquisition, refresh, or interactive login.
- Automatic authentication-method discovery or fallback after a failed request.
- Authentication changes for the Snyk API.
- Persisting, rotating, or transforming customer credentials outside request-header construction.
- Relaxing TLS verification defaults or changing `SSL_VERIFY` / `CA_BUNDLE` behavior.

## Decisions

### Normalize a two-value authentication enum with a bearer default

Add configuration constants for `BEARER`, `BASIC`, and the `BEARER` default. `SNOW_AUTH_METHOD` will be trimmed and uppercased before validation, matching the existing handling of run mode and application scope. A non-empty unsupported value fails with exit code 1 before any client is created.

Defaulting to `BEARER` means existing `.env` files containing only `SNOW_ACCESS_TOKEN` continue to work unchanged.

**Alternative considered:** Require `SNOW_AUTH_METHOD` immediately. This was rejected because it would break all existing deployments for no functional benefit.

### Validate common and method-specific ServiceNow inputs separately

Split the current ServiceNow requirements into:

- Common: `SNOW_INSTANCE_SUBDOMAIN`, `SNOW_BUSINESS_APPLICATION_ID`
- Bearer: `SNOW_ACCESS_TOKEN`
- Basic: `SNOW_USERNAME`, `SNOW_PASSWORD`

Only the selected credential set participates in missing-value and placeholder validation. Inactive credentials are ignored, even if empty or placeholder-valued, so customers can keep templates containing both sets. Existing run-mode and scope validation remains unchanged.

**Alternative considered:** Require all three credential variables regardless of method. This was rejected because it defeats method selection and encourages customers to provision unused secrets.

### Build the Authorization header in the ServiceNow client

Add the selected method and both credential shapes to `config.Config`. The ServiceNow client will derive one authorization-header value:

- Bearer: `"Bearer " + token`
- Basic: `"Basic " + base64(username + ":" + password)`

The Basic credential bytes will be encoded with Go's standard `encoding/base64` package. The shared `httpx` request remains authentication-agnostic and receives only the completed `Authorization` header.

**Alternative considered:** Add Basic-auth fields to `httpx.Request` or teach the shared HTTP wrapper about ServiceNow. This was rejected because it couples a reusable transport to one domain's authentication policy.

### Make authentication errors method-aware

Convert ServiceNow upload error mapping to use client configuration when producing the recommended next step. HTTP 401/403 remains an authentication failure (exit code 2), but guidance names `SNOW_ACCESS_TOKEN` for bearer or `SNOW_USERNAME` / `SNOW_PASSWORD` for Basic without including values.

No automatic retry with the alternate method will occur; fallback could send credentials unexpectedly and obscure configuration errors.

### Treat both Basic credential fields and authorization values as sensitive

The existing header redactor already masks both `Bearer` and `Basic` scheme values while preserving the scheme name. Extend sensitive-key coverage and tests so `SNOW_USERNAME` and `SNOW_PASSWORD` are also masked if variable-level logging is introduced or expanded. Logging may include the selected method because it is not a secret.

Tests will assert that raw tokens, passwords, usernames, and Base64-encoded Basic credentials never appear in header summaries or error logs.

### Bind Jenkins credentials according to the selected method

Add a `SNOW_AUTH_METHOD` choice parameter defaulting to `BEARER`. Keep bearer tokens in the existing Secret Text credential. Add a configurable Jenkins username/password credential ID for Basic authentication and bind it to `SNOW_USERNAME` / `SNOW_PASSWORD` only for Basic runs.

Neither username nor password will be a normal Jenkins string parameter. Shell tracing remains disabled around execution, and only the selected credential binding is made available to the process.

### Document opt-in Basic authentication with placeholder-only examples

Update `.env.example`, the root README, and Go/Jenkins guidance with:

- The bearer default and method-specific required variables
- Bearer and Basic examples using non-secret placeholders
- A warning that Basic is Base64 encoding rather than encryption and therefore requires verified HTTPS
- Authentication-specific troubleshooting and credential-binding instructions

Any literal username or password currently present in a local example must be replaced with unmistakable non-secret placeholders before that file is committed.

## Risks / Trade-offs

- **Basic credentials are only Base64 encoded** → Keep HTTPS mandatory, retain certificate verification by default, and document the risk of `SSL_VERIFY=false`.
- **Credentials could leak through diagnostics** → Centralize header construction, preserve authorization redaction, add direct leak assertions for both schemes, and never log credential fields.
- **A typo could silently select bearer through a fallback** → Default only when unset/empty; reject every non-empty unsupported value.
- **Both credential sets may be configured** → Use only the explicitly selected method and test that inactive credentials never affect the request.
- **Jenkins could expose credentials through parameters or shell tracing** → Use credential bindings only and retain `set +x` during execution.
- **Method-specific error guidance could drift from request behavior** → Derive both from the same normalized configuration value and cover 401/403 for each method.

## Migration Plan

Existing bearer deployments require no change because `SNOW_AUTH_METHOD` defaults to `BEARER`.

To adopt Basic authentication:

1. Set `SNOW_AUTH_METHOD=BASIC`.
2. Set `SNOW_USERNAME` and `SNOW_PASSWORD` through the environment, `.env`, or an approved secret manager.
3. Remove `SNOW_ACCESS_TOKEN` if it is no longer needed.
4. In Jenkins, configure the documented username/password credential ID.

Rollback is safe for bearer deployments. Basic deployments must restore a valid `SNOW_ACCESS_TOKEN` and remove or change `SNOW_AUTH_METHOD` before running a version without this capability.

## Open Questions

None.
