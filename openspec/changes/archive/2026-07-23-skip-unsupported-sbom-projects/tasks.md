## 1. Unsupported outcome

- [x] 1.1 Add `SbomUnsupportedError(AppError)` to `app/errors.py` (exit_code 3)
- [x] 1.2 In `app/snyk_client.py`, raise `SbomUnsupportedError` when the SBOM response is HTTP 404; keep `SbomGenerationError` for other non-2xx and empty/malformed bodies

## 2. Orchestration handling

- [x] 2.1 Add `skipped: bool` to `ProjectResult` and `skipped: int` to `ScopeSummary`
- [x] 2.2 In `_process_one`, catch `SbomUnsupportedError` before the generic `AppError` branch and return a skipped result (log as unsupported)
- [x] 2.3 Compute `failed` as genuine failures only (`not ok and not skipped`); make `exit_code` return 4 only when `failed > 0`
- [x] 2.4 Add "Skipped (unsupported)" to `ScopeSummary.format_report` and the per-project progress status

## 3. Docs

- [x] 3.1 Update `README.md` summary/exit-code notes to describe skipped-unsupported behavior

## 4. Verification

- [x] 4.1 Multi-project run with mixed results reports generated/succeeded/skipped/failed correctly; skips don't cause exit 4
- [x] 4.2 A run whose only non-success is a 404 exits 0 with a warning; a genuine (non-404) failure still exits 4
- [x] 4.3 Live `SNYK_ORG` dry-run shows ~55 skipped, 0 failed, exit 0
