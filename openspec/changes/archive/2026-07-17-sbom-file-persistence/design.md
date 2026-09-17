## Context

The initial utility (`snyk-sbom-to-servicenow`) generates an SBOM and posts an in-memory buffer to a placeholder ServiceNow path. We now have the confirmed working ServiceNow endpoint (from a verified curl) and the correct identifier. The `.env` already renamed `SNOW_APPLICATION_SYS_ID` to `SNOW_BUSINESS_APPLICATION_ID`. This change persists the SBOM to disk and aligns the uploader with the proven request shape.

Confirmed working requests (from `.env` comments):

```
# Snyk
GET https://api.snyk.io/rest/orgs/<org>/projects/<project>/sbom?version=2026-03-25&format=cyclonedx1.6%2Bjson

# ServiceNow (proven)
POST https://<subdomain>.service-now.com/api/sbom/core/upload?businessApplicationId=<id>&sbomSource=Snyk
  -H "Authorization: Bearer <token>"
  -H "Content-Type: application/json"
  --data-binary @<file>.json
```

## Goals / Non-Goals

**Goals:**
- Write the SBOM to `<timestamp>-snyk-<project_id>-sbom.json` in the repo root.
- Upload that exact file to the correct ServiceNow endpoint with the proven query params/headers.
- Rename the config variable with no lingering references to the old name.
- Preserve dry-run: still write the file, skip only the upload.

**Non-Goals:**
- Configurable output directory or filename template (root + fixed pattern for now).
- Cleanup/rotation of old SBOM files.
- Streaming uploads or multipart form encoding (raw `--data-binary` body only).
- Changing Snyk generation behavior.

## Decisions

### Timestamp and filename
Use UTC compact ISO basic format `YYYYMMDDTHHMMSSZ` (filename-safe, sortable) to avoid `:` characters. Filename: `f"{ts}-snyk-{project_id}-sbom.json"`. Rationale: sortable, no illegal path chars, unambiguous. Alternative considered: epoch seconds — rejected as less human-readable.

### Where writing happens
Add a small `app/sbom_file.py` with `write_sbom(document, project_id, root) -> Path`. `sbom_service.py` calls it after generation and passes the resulting `Path` to the ServiceNow client. Rationale: keeps file concerns out of the transport clients and out of orchestration logic; matches the existing module-boundary style. The write is treated as part of "SBOM generation" for exit-code purposes (failures → code 3), since a persisted file is a precondition for upload.

### Root directory resolution
"Repository root" = the process working directory (where `python main.py` is run), resolved via `Path.cwd()`. The utility is documented to run from the repo root. Rationale: matches the proven curl workflow (`@test-sbom.json` in cwd) and avoids guessing VCS roots. A future enhancement can add `SBOM_OUTPUT_DIR`.

### ServiceNow client changes
- Endpoint path is now fixed: `/api/sbom/core/upload`. Drop `SNOW_SBOM_UPLOAD_PATH`.
- Query params: `businessApplicationId=<SNOW_BUSINESS_APPLICATION_ID>`, `sbomSource=Snyk`.
- Body: read bytes from the persisted file and send as `data=` (raw), Content-Type `application/json`. This mirrors `--data-binary @file`.
- Auth unchanged: `Authorization: Bearer <SNOW_ACCESS_TOKEN>`.

### Config rename
`Config.snow_application_sys_id` → `Config.snow_business_application_id`; read from `SNOW_BUSINESS_APPLICATION_ID`; update `REQUIRED_VARS`, placeholder checks, `.env.example`, and README. No backward-compat alias (BREAKING, and the `.env` is already migrated).

## Risks / Trade-offs

- [SBOM files accumulate in the repo root] → Add `*-snyk-*-sbom.json` to `.gitignore`; document that files are not auto-pruned.
- [Large SBOM written then re-read for upload] → Minor extra I/O; acceptable and improves auditability/replayability. Reading the file for upload guarantees "upload exactly what was persisted."
- [Working directory is not the repo root] → Documented requirement to run from repo root; `Path.cwd()` keeps behavior predictable and matches the curl workflow.
- [Secrets in `.env` comments] → The `.env` contains real tokens in example comments; ensure `.env` is git-ignored (out of scope here but worth flagging).

## Migration Plan

1. Rename the variable in `.env` (already done) and `.env.example`.
2. Deploy code; run with `DRY_RUN=True` to confirm the file is written and upload is skipped.
3. Run with `DRY_RUN=False` to confirm upload to `/api/sbom/core/upload` succeeds.
Rollback: revert the change; the old in-memory upload path returns (but the placeholder endpoint was never functional).

## Open Questions

- Does `/api/sbom/core/upload` return JSON on success, or an empty/202 body? The client will tolerate a non-JSON 2xx response (already handled) and log status.
