## Why

The current utility holds the generated SBOM only in memory and posts it to a placeholder ServiceNow endpoint. Persisting the SBOM to a timestamped file on disk gives an auditable artifact, makes troubleshooting easy (the exact bytes sent can be inspected/replayed), and matches how the proven ServiceNow upload works (`--data-binary @file`). We also now know the real ServiceNow SBOM ingestion endpoint and the correct business-application identifier, so the upload path must be corrected.

## What Changes

- Write the SBOM returned by Snyk to a timestamped JSON file in the repository root, named `<timestamp>-snyk-<project_id>-sbom.json` (e.g. `20260716T191500Z-snyk-08310a59-...-sbom.json`).
- Upload to ServiceNow by reading that file (equivalent to `curl --data-binary @file`), rather than uploading an in-memory buffer.
- Correct the ServiceNow upload endpoint to `POST /api/sbom/core/upload` with query params `businessApplicationId=<id>` and `sbomSource=Snyk`.
- **BREAKING**: Rename the configuration variable `SNOW_APPLICATION_SYS_ID` → `SNOW_BUSINESS_APPLICATION_ID`. `SNOW_SBOM_UPLOAD_PATH` is no longer used (the path is now fixed by the API contract).
- Keep dry-run behavior: still generate and persist the SBOM file, but skip the ServiceNow upload.

## Capabilities

### New Capabilities
- `sbom-file-persistence`: Persist the generated SBOM to a timestamped `.json` file in the repository root and expose its path to the uploader.

### Modified Capabilities
- `configuration`: Rename the required variable `SNOW_APPLICATION_SYS_ID` to `SNOW_BUSINESS_APPLICATION_ID`; drop the now-unused `SNOW_SBOM_UPLOAD_PATH`.
- `servicenow-sbom-upload`: Upload the persisted SBOM file to `POST /api/sbom/core/upload?businessApplicationId=<id>&sbomSource=Snyk` with `Authorization: Bearer <token>` and `Content-Type: application/json`, sending the file bytes.

## Impact

- Code: `app/config.py` (var rename), `app/sbom_service.py` (write file, pass path), `app/servicenow_client.py` (endpoint + file body), new `app/sbom_file.py` (or helper) for writing/naming; `app/snyk_client.py` unchanged except returning bytes already suitable for file write.
- Config/docs: `.env`, `.env.example`, `README.md` updated for the renamed variable and new endpoint.
- Filesystem: writes a `*-snyk-*-sbom.json` file to the repo root on each run (candidate for `.gitignore`).
- No new third-party dependencies.
