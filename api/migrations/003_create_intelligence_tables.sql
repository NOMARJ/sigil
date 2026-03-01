-- Sigil Bot — Intelligence Schema (T-SQL)
-- Proprietary analytics layer (NOMARK internal — never exposed publicly)
--
-- Stores market intelligence signals extracted from scan metadata.
-- Separate from public scan data.

-- Package intelligence records (one per scan)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'intel_packages')
BEGIN
    CREATE TABLE intel_packages (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        ecosystem       NVARCHAR(100) NOT NULL,
        package_name    NVARCHAR(400) NOT NULL,
        package_version NVARCHAR(255) NOT NULL DEFAULT '',
        categories      NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        providers       NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        infrastructure  NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        author          NVARCHAR(MAX) NOT NULL DEFAULT '',
        description     NVARCHAR(MAX) NOT NULL DEFAULT '',
        keywords        NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        risk_score      REAL NOT NULL DEFAULT 0,
        verdict         NVARCHAR(50) NOT NULL DEFAULT 'LOW_RISK',
        findings_count  INT NOT NULL DEFAULT 0,
        scanned_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        created_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT CK_intel_packages_categories CHECK (categories IS NULL OR ISJSON(categories) = 1),
        CONSTRAINT CK_intel_packages_providers CHECK (providers IS NULL OR ISJSON(providers) = 1),
        CONSTRAINT CK_intel_packages_infrastructure CHECK (infrastructure IS NULL OR ISJSON(infrastructure) = 1),
        CONSTRAINT CK_intel_packages_keywords CHECK (keywords IS NULL OR ISJSON(keywords) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_intel_packages_ecosystem')
    CREATE INDEX idx_intel_packages_ecosystem ON intel_packages (ecosystem);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_intel_packages_scanned')
    CREATE INDEX idx_intel_packages_scanned ON intel_packages (scanned_at DESC);
GO

-- Aggregated category trends (populated by weekly rollup)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'intel_category_trends')
BEGIN
    CREATE TABLE intel_category_trends (
        id          UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        week        NVARCHAR(50) NOT NULL,           -- ISO week: "2026-W09"
        category    NVARCHAR(255) NOT NULL,
        ecosystem   NVARCHAR(100) NOT NULL DEFAULT 'all',
        new_count   INT NOT NULL DEFAULT 0,
        total_count INT NOT NULL DEFAULT 0,
        created_at  DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT UQ_intel_category_trends UNIQUE (week, category, ecosystem)
    );
END
GO

-- Provider usage trends (populated by weekly rollup)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'intel_provider_trends')
BEGIN
    CREATE TABLE intel_provider_trends (
        id          UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        week        NVARCHAR(50) NOT NULL,
        provider    NVARCHAR(255) NOT NULL,
        ecosystem   NVARCHAR(100) NOT NULL DEFAULT 'all',
        usage_count INT NOT NULL DEFAULT 0,
        created_at  DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT UQ_intel_provider_trends UNIQUE (week, provider, ecosystem)
    );
END
GO

-- Publisher profiles (aggregated from scan data)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'intel_publishers')
BEGIN
    CREATE TABLE intel_publishers (
        id                UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        author            NVARCHAR(255) NOT NULL UNIQUE,
        total_packages    INT NOT NULL DEFAULT 0,
        avg_risk_score    REAL NOT NULL DEFAULT 0,
        high_risk_count   INT NOT NULL DEFAULT 0,
        ecosystems        NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        categories        NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        first_seen        DATETIMEOFFSET,
        last_active       DATETIMEOFFSET,
        updated_at        DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT CK_intel_publishers_ecosystems CHECK (ecosystems IS NULL OR ISJSON(ecosystems) = 1),
        CONSTRAINT CK_intel_publishers_categories CHECK (categories IS NULL OR ISJSON(categories) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_intel_publishers_author')
    CREATE INDEX idx_intel_publishers_author ON intel_publishers (author);
GO
