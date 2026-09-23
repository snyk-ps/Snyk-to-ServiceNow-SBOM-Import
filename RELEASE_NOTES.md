# v2.0.1 — CLI-First Default

This patch release changes the default `RUN_MODE` from `SNYK_API` to
`SNYK_CLI`. The safer default requires callers to provide an explicit SBOM file
and prevents an unset `RUN_MODE` from initiating Snyk API discovery.

## Changes

- `RUN_MODE` now defaults to `SNYK_CLI`.
- `SNYK_API` remains fully supported and must now be selected explicitly.
- Jenkins defaults to `SNYK_CLI`.
- Customer and Go developer documentation now use CLI-first examples.
- Embedded binary/build version updated to 2.0.1.

## Default usage

Generate a JSON SBOM using the native Snyk CLI, then upload it:

```bash
snyk sbom --format=cyclonedx1.6+json --all-projects > sbom.json

./snyk-sbom-to-servicenow \
  --sbom-file-path ./sbom.json
```

Select API mode explicitly when discovery/generation through Snyk REST is
required:

```bash
RUN_MODE=SNYK_API ./snyk-sbom-to-servicenow
```

## Distribution

The release includes static binaries and SHA-256 checksums for:

- Linux amd64/arm64
- macOS amd64/arm64
- Windows amd64/arm64

No Python or Go runtime is required on customer hosts.