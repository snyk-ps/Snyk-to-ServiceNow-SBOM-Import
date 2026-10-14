# v2.1.0 — Optional ServiceNow Build ID

This release adds an optional ServiceNow `buildId` to SBOM upload requests so
uploads from multiple repositories can be associated with the same build.

## Changes

- Accept an optional build ID from the `BUILD_ID` environment variable.
- Accept an optional `--buildid` command-line argument in both Snyk API and
  Snyk CLI modes.
- Give `--buildid` precedence over `BUILD_ID`, including an explicitly empty
  `--buildid=` value.
- Omit `buildId` when neither input supplies a non-empty value, preserving
  compatibility with existing deployments.
- URL-encode spaces and reserved characters in build IDs.
- Preserve the existing `businessApplicationId`, `sbomSource`, authentication,
  and SBOM payload behavior.

## Usage

Use an environment variable:

```bash
RUN_MODE=SNYK_API BUILD_ID='release 2026.10.13 / build #42' \
  ./snyk-sbom-to-servicenow
```

Or pass the command-line argument:

```bash
./snyk-sbom-to-servicenow \
  --sbom-file-path ./sbom.json \
  --buildid='release 2026.10.13 / build #42'
```

When both inputs are present, the command-line value wins. Use `--buildid=` to
explicitly suppress an environment-provided value.

## Distribution

The release includes static binaries and SHA-256 checksums for:

- Linux amd64/arm64
- macOS amd64/arm64
- Windows amd64/arm64

No Python or Go runtime is required on customer hosts.