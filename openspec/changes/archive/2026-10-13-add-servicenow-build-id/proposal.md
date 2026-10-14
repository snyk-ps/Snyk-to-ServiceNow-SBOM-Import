## Why

ServiceNow can associate an uploaded SBOM with a specific software build when the upload request includes a `buildId`. The utility currently has no way to provide that optional identifier, so users must choose between losing build-level traceability and constructing the upload request outside the utility.

## What Changes

- Accept an optional build ID from the `BUILD_ID` environment variable.
- Accept an optional `--buildid` command-line argument using the utility's existing flag syntax.
- Give an explicitly provided command-line value precedence over `BUILD_ID`, including an explicitly empty command-line value.
- Add `buildId` to the ServiceNow upload query only when the effective value is non-empty.
- Encode the optional query parameter through Go's URL query facilities so spaces and special characters are transmitted correctly.
- Document the optional configuration, precedence, empty-value behavior, and invocation examples.
- Preserve all existing required ServiceNow configuration, `businessApplicationId` mapping, `sbomSource` selection, and upload behavior.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `configuration`: Add the optional `BUILD_ID` environment variable and `--buildid` command-line override, including precedence and explicit-empty semantics.
- `servicenow-sbom-upload`: Conditionally include the effective build ID as the URL-encoded `buildId` upload query parameter without changing existing query parameters or validation.

## Impact

- Affected Go code: command-line parsing, runtime configuration, and ServiceNow upload query construction.
- Affected documentation: the project README's configuration and usage examples.
- Affected tests: configuration/override resolution, upload query construction, omission behavior, URL encoding, and regression coverage for existing ServiceNow parameters.
- External API: the existing ServiceNow SBOM upload endpoint receives one additional optional query parameter; no dependencies, required settings, or existing interfaces are removed.

## Acceptance Criteria

- With neither input provided, upload proceeds without `buildId`.
- With only `BUILD_ID` set, its value is sent as `buildId`.
- With only `--buildid` provided, its value is sent as `buildId`.
- With both inputs provided, the command-line value is sent.
- An empty effective value omits `buildId`; an explicitly empty command-line value suppresses `BUILD_ID`.
- Build IDs containing spaces or special characters are correctly URL encoded and received without value loss.
- Existing `SNOW_BUSINESS_APPLICATION_ID` validation, `businessApplicationId` mapping, `sbomSource` selection, and all other upload behavior remain unchanged.
