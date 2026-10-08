-- 011: Remove uploaded source files from stored scan metadata
--
-- Before the CLI/API contract fix, POST /v1/scan-enhanced stored the request's
-- metadata as scans.metadata_json, including the source files that
-- `sigil scan --enhanced` uploads for LLM analysis (`file_contents`, or the
-- single-file `content`). GET /v1/scans/{id} returns metadata_json to the
-- account and its team. The API no longer stores those keys
-- (_UPLOADED_SOURCE_KEYS in api/routers/scan.py); this removes the copies
-- already stored. Every other metadata key is kept.
--
-- JSON_MODIFY with a NULL value deletes the key (lax mode, the default). Rows
-- are picked with OPENJSON, which lists the top-level keys whatever their
-- size: JSON_VALUE returns NULL for a value over 4000 characters and would
-- miss large files. Idempotent: a second run matches no row.
--
-- Not run in CI: the API tests use the in-memory store, not MSSQL.
-- Apply: SIGIL_ALLOW_SCHEMA_WRITES=1 python -m api.migrations.apply_prod_migration \
--            --apply api/migrations/011_remove_uploaded_files_from_scan_metadata.sql

UPDATE scans
SET metadata_json = JSON_MODIFY(
        JSON_MODIFY(metadata_json, '$.file_contents', NULL),
        '$.content', NULL)
WHERE ISJSON(metadata_json) = 1
  AND EXISTS (
        SELECT 1
        FROM OPENJSON(scans.metadata_json)
        WHERE [key] IN (N'file_contents', N'content')
  );
GO
