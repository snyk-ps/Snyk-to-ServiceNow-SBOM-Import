## 1. Configuration rename

- [x] 1.1 Rename `Config.snow_application_sys_id` to `snow_business_application_id` and read from `SNOW_BUSINESS_APPLICATION_ID`
- [x] 1.2 Update `REQUIRED_VARS` and the placeholder check to use `SNOW_BUSINESS_APPLICATION_ID`
- [x] 1.3 Remove `SNOW_SBOM_UPLOAD_PATH` config field/default (no longer used)
- [x] 1.4 Update `.env.example` and `README.md` for the renamed variable and fixed endpoint

## 2. SBOM file persistence

- [x] 2.1 Add `app/sbom_file.py` with `write_sbom(document, project_id, root=Path.cwd())` returning the written `Path`
- [x] 2.2 Generate a filename-safe UTC timestamp and build `<timestamp>-snyk-<project_id>-sbom.json`
- [x] 2.3 Write SBOM bytes unmodified; on write failure raise `SbomGenerationError` with the target path and reason
- [x] 2.4 Log the absolute file path and byte size after writing
- [x] 2.5 Add `*-snyk-*-sbom.json` to `.gitignore`

## 3. ServiceNow upload changes

- [x] 3.1 Change the upload URL to `POST /api/sbom/core/upload` (drop `SNOW_SBOM_UPLOAD_PATH`)
- [x] 3.2 Set query params `businessApplicationId=<SNOW_BUSINESS_APPLICATION_ID>` and `sbomSource=Snyk`
- [x] 3.3 Read the persisted file bytes and send as the raw request body with `Content-Type: application/json`
- [x] 3.4 Keep `Authorization: Bearer <SNOW_ACCESS_TOKEN>`; map 401/403 to `AuthError`, other failures to `UploadError`

## 4. Orchestration

- [x] 4.1 In `sbom_service.py`, write the SBOM file after generation and pass its `Path` to the uploader
- [x] 4.2 Include the file path in `RunResult`; honor `DRY_RUN` (write file, skip upload) and log the skip
- [x] 4.3 Ensure `main.py` completion logs reference the written file path

## 5. Verification

- [ ] 5.1 Run with `DRY_RUN=True`: confirm `<timestamp>-snyk-<project_id>-sbom.json` is created and upload is skipped
- [ ] 5.2 Run with `DRY_RUN=False`: confirm POST to `/api/sbom/core/upload?...&sbomSource=Snyk` succeeds (exit 0)
- [x] 5.3 Confirm no reference to `SNOW_APPLICATION_SYS_ID` or `SNOW_SBOM_UPLOAD_PATH` remains in code/docs
- [x] 5.4 Confirm uploaded bytes equal the persisted file bytes
