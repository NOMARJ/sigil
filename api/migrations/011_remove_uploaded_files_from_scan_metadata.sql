-- 011: Remove uploaded source files from stored scan metadata
--
-- Before the CLI/API contract fix, POST /v1/scan-enhanced stored the request's
-- metadata as scans.metadata_json, including the source files that
-- `sigil scan --enhanced` uploads for LLM analysis (`file_contents`, or the
-- single-file `content`). Every scan endpoint that returns a stored scan
-- returns metadata_json with it: the detail endpoint (GET /v1/scans/{id}) and
-- the list endpoints (GET /scans, GET /v1/scans), to the account and its
-- team. The API no longer stores those files (_STORED_ENHANCED_METADATA_KEYS
-- in api/routers/scan.py keeps an allow-list of keys for /v1/scan-enhanced);
-- this removes the copies already stored. Every other metadata key is kept.
--
-- Scope: `$.file_contents` and `$.content` are removed from EVERY stored scan
-- that has them as a top-level key, not only from scans made through
-- /v1/scan-enhanced. /v1/scan stores the request's metadata as sent, so a
-- client that put one of those keys there loses it too.
--
-- JSON_MODIFY with a NULL value deletes the key (lax mode, the default). Rows
-- are picked with OPENJSON, which lists the top-level keys whatever their
-- size: JSON_VALUE returns NULL for a value over 4000 characters and would
-- miss large files. T-SQL does not promise to evaluate WHERE predicates left
-- to right, so ISJSON is checked inside the OPENJSON argument (a CASE is
-- evaluated in order) and OPENJSON never sees text that is not JSON.
-- Idempotent: a second run matches no row.
--
-- Not run in CI: the API tests use the in-memory store, not MSSQL, and this
-- file has not been executed against MSSQL. Dry-run it first: run the SELECT
-- below against a copy of the production data (or inside a transaction you
-- roll back), compare the count with what you expect, then apply.
--
--   SELECT COUNT(*) FROM scans
--   WHERE EXISTS (
--         SELECT 1
--         FROM OPENJSON(CASE WHEN ISJSON(scans.metadata_json) = 1
--                            THEN scans.metadata_json ELSE N'{}' END)
--         WHERE [key] IN (N'file_contents', N'content')
--   );
--
-- Apply: SIGIL_ALLOW_SCHEMA_WRITES=1 python -m api.migrations.apply_prod_migration \
--            --apply api/migrations/011_remove_uploaded_files_from_scan_metadata.sql

UPDATE scans
SET metadata_json = JSON_MODIFY(
        JSON_MODIFY(metadata_json, '$.file_contents', NULL),
        '$.content', NULL)
WHERE EXISTS (
        SELECT 1
        FROM OPENJSON(CASE WHEN ISJSON(scans.metadata_json) = 1
                           THEN scans.metadata_json ELSE N'{}' END)
        WHERE [key] IN (N'file_contents', N'content')
  );
GO
