-- 009: Indexes for GET /scans list queries (B-4: scope=all took ~30s then 500)
--
-- The scans list endpoint fetches, per request:
--   TOP 500 of scans WHERE user_id = ? ORDER BY created_at DESC
--   TOP 500 of public_scans ORDER BY scanned_at DESC
-- selecting only the slim list columns (the router no longer SELECTs the
-- NVARCHAR(MAX) LOB columns). Without these indexes the per-user branch
-- sorts every row of the user's partition through idx_scans_user, and the
-- public branch either sorts the whole table or does 500 key lookups
-- through idx_public_scans_scanned_at.
--
-- idx_scans_user_created serves the per-user branch in index order.
-- idx_public_scans_scanned_cover serves the public branch entirely from
-- the index (INCLUDE keeps it off the base table and away from the
-- NVARCHAR(MAX) LOB columns), mirroring migration 008 for /registry.
--
-- ONLINE = ON: safe to run against the live database (no table lock).

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_scans_user_created')
    CREATE INDEX idx_scans_user_created
        ON scans (user_id, created_at DESC)
        INCLUDE (target_type, files_scanned, risk_score, verdict)
        WITH (ONLINE = ON);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_public_scans_scanned_cover')
    CREATE INDEX idx_public_scans_scanned_cover
        ON public_scans (scanned_at DESC)
        INCLUDE (id, ecosystem, package_name, risk_score, verdict,
                 findings_count, files_scanned, created_at)
        WITH (ONLINE = ON);
GO
