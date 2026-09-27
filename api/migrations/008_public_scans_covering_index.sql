-- 008: Covering index for /registry/{ecosystem} list queries (NOM: 2026-07-19 P1 follow-up)
--
-- The ecosystem list endpoint dedups with
--   ROW_NUMBER() OVER (PARTITION BY package_name, package_version ORDER BY scanned_at DESC)
-- filtered by ecosystem. Without a supporting index this sorts the whole
-- ecosystem partition per request. The covering index serves the partition
-- scan in index order and the INCLUDE columns keep the query off the base
-- table (and away from the NVARCHAR(MAX) LOB columns) entirely.
--
-- ONLINE = ON: safe to run against the live database (no table lock).

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_public_scans_eco_pkg_scanned')
    CREATE INDEX idx_public_scans_eco_pkg_scanned
        ON public_scans (ecosystem, package_name, package_version, scanned_at DESC)
        INCLUDE (id, risk_score, verdict, findings_count, files_scanned, created_at)
        WITH (ONLINE = ON);
GO
