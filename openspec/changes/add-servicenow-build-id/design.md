## Context

The Go command currently loads environment configuration into `config.Config`, parses `--sbom-file-path` and `--version` with `flag.FlagSet`, and constructs the ServiceNow upload query with `url.Values`. The query always contains `businessApplicationId` and the run-mode-derived `sbomSource`.

The new build ID is optional, but its precedence rule requires distinguishing an absent `--buildid` flag from an explicitly supplied empty value such as `--buildid=`. A plain string value cannot represent that distinction by itself.

## Goals / Non-Goals

**Goals:**

- Resolve one optional effective build ID from `BUILD_ID` and `--buildid`.
- Preserve command-line presence information so an explicit empty value suppresses `BUILD_ID`.
- Conditionally add the effective value to every ServiceNow upload in the run.
- Use the existing URL query encoder and preserve all current upload behavior.
- Cover resolution, omission, encoding, and existing-query regression behavior with focused tests.

**Non-Goals:**

- Making build ID required or validating it against a ServiceNow format.
- Discovering build IDs automatically.
- Supporting a different build ID for each project during one organization- or target-scope run.
- Changing SBOM generation, persistence, upload payloads, authentication, scope processing, or dry-run behavior.

## Decisions

### Store the environment value in runtime configuration and preserve CLI presence separately

Add an optional build ID field to `config.Config` and populate it from `BUILD_ID` without adding it to required-variable validation. Register `--buildid` on the existing `flag.FlagSet`, then use parsed-flag presence (for example, `FlagSet.Visit`) in addition to the parsed string.

After configuration loading:

1. If `--buildid` was present, use its value even when that value is empty.
2. Otherwise, retain the value loaded from `BUILD_ID`.
3. Normalize an empty or whitespace-only effective value to unavailable.

Internal spaces and special characters remain unchanged. Resolution occurs before constructing the ServiceNow client so all uploads receive the same finalized configuration.

**Alternative considered:** Default the flag value directly from `BUILD_ID`. This was rejected because an absent flag and an explicitly empty flag would become indistinguishable, violating the suppression requirement.

**Alternative considered:** Read `BUILD_ID` directly in the ServiceNow client. This was rejected because input precedence belongs at the configuration boundary and would be harder to test or reuse.

### Add the query parameter conditionally through `url.Values`

Keep the existing `url.Values` entries for `businessApplicationId` and `sbomSource`. Call `Set("buildId", effectiveValue)` only when the effective value is non-empty. The existing HTTP wrapper serializes the values with `Values.Encode()`, providing standard escaping for spaces and URL-reserved characters.

No raw query-string concatenation will be introduced.

**Alternative considered:** Append `&buildId=` to the URL manually. This was rejected because it risks invalid requests, incorrect escaping, and query injection for values containing reserved characters.

### Keep one build ID for the complete invocation

The effective build ID is invocation-level configuration. In target or organization scope, each discovered project's independent upload receives the same build ID. This matches the environment/command-line input model and does not alter project orchestration.

### Test at configuration, command, and HTTP boundaries

Focused tests will cover:

- Environment-only, command-line-only, both-input, missing-input, and explicitly empty command-line resolution.
- Empty and whitespace-only effective values.
- ServiceNow request query contents through an HTTP test server.
- A build ID containing spaces and reserved characters, checking both encoded request form and decoded round-trip value.
- Preservation of `businessApplicationId`, `sbomSource`, payload bytes, and existing required configuration validation.

### Document both input forms and explicit-empty syntax

The README will list `BUILD_ID` as optional, document that `--buildid` takes precedence, and show environment, command-line, and `--buildid=` suppression examples. If both repository README files remain customer-facing, their shared configuration and invocation guidance will be kept consistent.

## Risks / Trade-offs

- **Flag presence is accidentally discarded** → Add explicit tests for `--buildid=` with a non-empty `BUILD_ID`.
- **Manual query construction could mishandle reserved characters** → Reuse `url.Values` exclusively and verify encoded and decoded request values.
- **A single build ID may not describe every project in a multi-project run** → Document invocation-level behavior; per-project build metadata remains a future enhancement.
- **Documentation copies may drift** → Update all retained customer-facing README locations in the same change.

## Migration Plan

This is additive and requires no configuration migration. Existing invocations produce the same request because `buildId` is omitted by default. Users can opt in by setting `BUILD_ID` or passing `--buildid`.

Rollback consists of deploying the preceding binary. `BUILD_ID` will then be ignored; callers passing `--buildid` must remove that argument because preceding versions do not recognize it.

## Open Questions

None.
