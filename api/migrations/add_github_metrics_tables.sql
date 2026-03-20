-- GitHub traffic and repository metrics tables
-- Migration: add_github_metrics_tables
-- Azure SQL Database (T-SQL)
--
-- Stores daily GitHub traffic data (clones, views, referrers, repo snapshots)
-- and release download counts. All tables are date-keyed for time-series analysis.

-- Daily clone activity (total clones + unique cloners per day)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'github_traffic_clones')
BEGIN
    CREATE TABLE github_traffic_clones (
        date            DATE NOT NULL,
        total_clones    INT NOT NULL DEFAULT 0,
        unique_cloners  INT NOT NULL DEFAULT 0,
        created_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_github_traffic_clones PRIMARY KEY (date)
    );
END
GO

-- Daily page view activity (total views + unique visitors per day)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'github_traffic_views')
BEGIN
    CREATE TABLE github_traffic_views (
        date             DATE NOT NULL,
        total_views      INT NOT NULL DEFAULT 0,
        unique_visitors  INT NOT NULL DEFAULT 0,
        created_at       DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_github_traffic_views PRIMARY KEY (date)
    );
END
GO

-- Daily referrer breakdown (one row per referrer per day)
-- [unique] is a T-SQL reserved word and requires brackets
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'github_traffic_referrers')
BEGIN
    CREATE TABLE github_traffic_referrers (
        date        DATE NOT NULL,
        referrer    NVARCHAR(255) NOT NULL,
        total       INT NOT NULL DEFAULT 0,
        [unique]    INT NOT NULL DEFAULT 0,
        created_at  DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_github_traffic_referrers PRIMARY KEY (date, referrer)
    );
END
GO

-- Daily repository snapshot (stars, forks, open issues, watchers)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'github_repo_snapshots')
BEGIN
    CREATE TABLE github_repo_snapshots (
        date         DATE NOT NULL,
        stars        INT NOT NULL DEFAULT 0,
        forks        INT NOT NULL DEFAULT 0,
        open_issues  INT NOT NULL DEFAULT 0,
        watchers     INT NOT NULL DEFAULT 0,
        created_at   DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_github_repo_snapshots PRIMARY KEY (date)
    );
END
GO

-- Daily download counts per source (US-008: GitHub Releases + future sources)
-- PRIMARY KEY on (date, source) supports multi-source aggregation without re-migration
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'github_download_counts')
BEGIN
    CREATE TABLE github_download_counts (
        date            DATE NOT NULL,
        source          NVARCHAR(50) NOT NULL DEFAULT 'github_releases',
        download_count  INT NOT NULL DEFAULT 0,
        created_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_github_download_counts PRIMARY KEY (date, source)
    );
END
GO

-- Indexes for time-series range queries
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_github_traffic_clones_date')
    CREATE INDEX idx_github_traffic_clones_date ON github_traffic_clones (date DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_github_traffic_views_date')
    CREATE INDEX idx_github_traffic_views_date ON github_traffic_views (date DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_github_traffic_referrers_date')
    CREATE INDEX idx_github_traffic_referrers_date ON github_traffic_referrers (date DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_github_traffic_referrers_referrer')
    CREATE INDEX idx_github_traffic_referrers_referrer ON github_traffic_referrers (referrer);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_github_repo_snapshots_date')
    CREATE INDEX idx_github_repo_snapshots_date ON github_repo_snapshots (date DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_github_download_counts_date')
    CREATE INDEX idx_github_download_counts_date ON github_download_counts (date DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_github_download_counts_source')
    CREATE INDEX idx_github_download_counts_source ON github_download_counts (source);
GO

PRINT 'Migration add_github_metrics_tables applied successfully.';
GO
