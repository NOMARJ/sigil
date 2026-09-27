-- Migration 010: Website Change Monitoring Queue
-- Creates tables for polling watched upstream URLs (MCP server repos, registry
-- listing pages, package pages, marketplaces) and recording real content change.
--
-- Why this exists: when the content at a URL we previously scanned changes, the
-- artifact users receive today is not the artifact we vetted. That divergence is
-- a supply-chain signal and should trigger a rescan.
--
-- Re-runnable: every object is created behind an IF NOT EXISTS guard.

-- Table for the watched URLs themselves
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'monitored_sources')
BEGIN
    CREATE TABLE monitored_sources (
        id NVARCHAR(32) PRIMARY KEY,
        -- NVARCHAR(450) = 900 bytes, the widest value that is safe as a unique
        -- index key on every supported Azure SQL compatibility level.
        url NVARCHAR(450) NOT NULL,
        source_type NVARCHAR(50) NOT NULL DEFAULT 'other', -- mcp_server, registry_listing, package_page, marketplace, other
        ref_id NVARCHAR(200) NULL, -- logical link, e.g. mcp_servers.repo_name or "npm:left-pad@1.3.0"
        enabled BIT NOT NULL DEFAULT 1,
        check_interval_minutes INT NOT NULL DEFAULT 360, -- base poll interval; backoff multiplies this
        last_checked_at DATETIMEOFFSET NULL, -- NULL means never polled -> always due
        last_changed_at DATETIMEOFFSET NULL, -- last time the normalised content hash actually moved
        last_status_code INT NULL, -- HTTP status of the most recent poll (304 is a normal outcome)
        content_hash NVARCHAR(64) NULL, -- sha256 hex of the NORMALISED response body
        etag NVARCHAR(200) NULL, -- verbatim ETag, replayed as If-None-Match
        last_modified NVARCHAR(100) NULL, -- verbatim HTTP-date, replayed as If-Modified-Since
        consecutive_failures INT NOT NULL DEFAULT 0, -- drives exponential backoff; reset to 0 on any success
        metadata_json NVARCHAR(MAX) NULL, -- JSON blob for per-source extras
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT UQ_monitored_sources_url UNIQUE (url),
        CONSTRAINT CK_monitored_sources_source_type CHECK (source_type IN ('mcp_server', 'registry_listing', 'package_page', 'marketplace', 'other')),
        CONSTRAINT CK_monitored_sources_interval CHECK (check_interval_minutes >= 1),
        CONSTRAINT CK_monitored_sources_failures CHECK (consecutive_failures >= 0),
        CONSTRAINT CK_monitored_sources_content_hash CHECK (content_hash IS NULL OR LEN(content_hash) = 64),
        CONSTRAINT CK_monitored_sources_metadata_json CHECK (metadata_json IS NULL OR ISJSON(metadata_json) = 1)
    );
END
GO

-- Due-selection query path: WHERE enabled = 1 ORDER BY last_checked_at ASC.
-- The INCLUDE columns let the due predicate and the backoff calculation be
-- satisfied from the index alone, without touching the base table.
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_monitored_sources_due')
    CREATE INDEX idx_monitored_sources_due ON monitored_sources(enabled, last_checked_at) INCLUDE (check_interval_minutes, consecutive_failures);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_monitored_sources_source_type')
    CREATE INDEX idx_monitored_sources_source_type ON monitored_sources(source_type);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_monitored_sources_ref_id')
    CREATE INDEX idx_monitored_sources_ref_id ON monitored_sources(ref_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_monitored_sources_last_changed')
    CREATE INDEX idx_monitored_sources_last_changed ON monitored_sources(last_changed_at DESC);
GO

-- Table for observed change events (the audit trail and the rescan queue)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'source_change_events')
BEGIN
    CREATE TABLE source_change_events (
        id NVARCHAR(32) PRIMARY KEY,
        source_id NVARCHAR(32) NOT NULL, -- logical reference to monitored_sources.id
        detected_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        previous_hash NVARCHAR(64) NULL, -- content_hash before this observation (NULL on first_seen)
        new_hash NVARCHAR(64) NULL, -- content_hash after this observation (NULL on gone/error)
        change_kind NVARCHAR(20) NOT NULL, -- content, etag, first_seen, gone, error, unchanged
        http_status INT NULL,
        bytes_before INT NULL, -- normalised byte length previously observed, when known
        bytes_after INT NULL, -- normalised byte length observed now
        notes NVARCHAR(1000) NULL, -- plain-text detail (error text, redirect target, reason)
        queued_for_rescan BIT NOT NULL DEFAULT 0, -- 1 = still waiting in the rescan queue
        rescan_enqueued_at DATETIMEOFFSET NULL, -- set when a worker drained this event
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT CK_source_change_events_kind CHECK (change_kind IN ('content', 'etag', 'first_seen', 'gone', 'error', 'unchanged')),
        CONSTRAINT CK_source_change_events_bytes_before CHECK (bytes_before IS NULL OR bytes_before >= 0),
        CONSTRAINT CK_source_change_events_bytes_after CHECK (bytes_after IS NULL OR bytes_after >= 0),
        CONSTRAINT CK_source_change_events_previous_hash CHECK (previous_hash IS NULL OR LEN(previous_hash) = 64),
        CONSTRAINT CK_source_change_events_new_hash CHECK (new_hash IS NULL OR LEN(new_hash) = 64)
    );
END
GO

-- History query path: "what happened to this source, newest first"
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_source_change_events_source')
    CREATE INDEX idx_source_change_events_source ON source_change_events(source_id, detected_at DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_source_change_events_kind')
    CREATE INDEX idx_source_change_events_kind ON source_change_events(change_kind, detected_at DESC);
GO

-- Rescan queue drain path. Filtered so the index stays small: rows leave the
-- queue by flipping queued_for_rescan back to 0, so this index only ever holds
-- the outstanding backlog rather than the whole event history.
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_source_change_events_pending_rescan')
    CREATE INDEX idx_source_change_events_pending_rescan ON source_change_events(detected_at) INCLUDE (source_id) WHERE queued_for_rescan = 1;
GO

PRINT 'Migration 010_create_change_monitor applied successfully.';
GO
