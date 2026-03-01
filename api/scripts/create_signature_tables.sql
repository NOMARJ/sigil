-- Sigil Threat Signature Tables (T-SQL)
-- Run this SQL in Azure SQL Database to create extended signature and malware family tables

-- Extended signatures table with additional metadata
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'signatures')
BEGIN
    CREATE TABLE signatures (
        id NVARCHAR(128) PRIMARY KEY,
        phase NVARCHAR(50) NOT NULL,
        pattern NVARCHAR(MAX) NOT NULL,
        severity NVARCHAR(50) NOT NULL,
        description NVARCHAR(MAX) NOT NULL,
        updated_at DATETIMEOFFSET DEFAULT SYSDATETIMEOFFSET(),

        -- Extended fields
        category NVARCHAR(100) DEFAULT 'unknown',
        weight DECIMAL(4,1) DEFAULT 1.0,
        language NVARCHAR(MAX) DEFAULT '["*"]',
        cve NVARCHAR(MAX) DEFAULT '[]',
        malware_families NVARCHAR(MAX) DEFAULT '[]',
        false_positive_likelihood NVARCHAR(50) DEFAULT 'unknown',
        created DATE DEFAULT CAST(GETUTCDATE() AS DATE),

        CONSTRAINT CK_signatures_language CHECK (language IS NULL OR ISJSON(language) = 1),
        CONSTRAINT CK_signatures_cve CHECK (cve IS NULL OR ISJSON(cve) = 1),
        CONSTRAINT CK_signatures_malware_families CHECK (malware_families IS NULL OR ISJSON(malware_families) = 1)
    );
END
GO

-- Malware families metadata table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'malware_families')
BEGIN
    CREATE TABLE malware_families (
        id NVARCHAR(128) PRIMARY KEY,
        name NVARCHAR(255) NOT NULL,
        first_seen NVARCHAR(100),
        ecosystem NVARCHAR(100),
        severity NVARCHAR(50) DEFAULT 'HIGH',
        description NVARCHAR(MAX),
        iocs NVARCHAR(MAX) DEFAULT '[]',
        signature_ids NVARCHAR(MAX) DEFAULT '[]',
        updated_at DATETIMEOFFSET DEFAULT SYSDATETIMEOFFSET(),

        CONSTRAINT CK_malware_families_iocs CHECK (iocs IS NULL OR ISJSON(iocs) = 1),
        CONSTRAINT CK_malware_families_signature_ids CHECK (signature_ids IS NULL OR ISJSON(signature_ids) = 1)
    );
END
GO

-- Indexes for performance
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_signatures_category')
    CREATE INDEX idx_signatures_category ON signatures(category);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_signatures_severity')
    CREATE INDEX idx_signatures_severity ON signatures(severity);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_signatures_phase')
    CREATE INDEX idx_signatures_phase ON signatures(phase);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_signatures_updated')
    CREATE INDEX idx_signatures_updated ON signatures(updated_at DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_malware_families_ecosystem')
    CREATE INDEX idx_malware_families_ecosystem ON malware_families(ecosystem);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_malware_families_severity')
    CREATE INDEX idx_malware_families_severity ON malware_families(severity);
GO
