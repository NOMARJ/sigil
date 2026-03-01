-- Migration: Add signed attestation columns to public_scans
-- Database: Azure SQL Database (T-SQL)
-- Date: 2026-03-01
--
-- Purpose: Enable Sigstore/in-toto attestation signing for public scan results
--
-- Columns:
--   - attestation: DSSE envelope (JSON string) containing signed statement
--   - content_digest: SHA-256 hex digest of canonical scan JSON (for verification)
--   - log_entry_id: Transparency log entry ID (e.g., Rekor UUID)
--
-- Indexes:
--   - idx_scans_content_digest: Enables lookup by content digest
--   - idx_scans_log_entry_id: Enables transparency log cross-reference

-- Add attestation column (stores DSSE envelope as JSON string)
-- Using NVARCHAR(MAX) since DSSE envelopes can be large (includes signatures, certs)
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('public_scans') AND name = 'attestation')
BEGIN
    ALTER TABLE public_scans ADD attestation NVARCHAR(MAX) NULL;
    PRINT 'Added column: attestation (NVARCHAR(MAX))';
END
ELSE
BEGIN
    PRINT 'Column attestation already exists, skipping.';
END;
GO

-- Add content digest column (SHA-256 hex of canonical scan JSON)
-- Using NVARCHAR(128) — bounded for indexing
-- SHA-256 produces 64 hex chars, allowing prefix like "sha256:" (71 chars total)
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('public_scans') AND name = 'content_digest')
BEGIN
    ALTER TABLE public_scans ADD content_digest NVARCHAR(128) NULL;
    PRINT 'Added column: content_digest (NVARCHAR(128))';
END
ELSE
BEGIN
    PRINT 'Column content_digest already exists, skipping.';
END;
GO

-- Add transparency log entry ID
-- Using NVARCHAR(128) for Rekor UUIDs or other log entry identifiers
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('public_scans') AND name = 'log_entry_id')
BEGIN
    ALTER TABLE public_scans ADD log_entry_id NVARCHAR(128) NULL;
    PRINT 'Added column: log_entry_id (NVARCHAR(128))';
END
ELSE
BEGIN
    PRINT 'Column log_entry_id already exists, skipping.';
END;
GO

-- Create index for content_digest lookups
-- Filtered index (WHERE ... IS NOT NULL) for sparse columns improves performance
-- This enables verification queries: SELECT * FROM public_scans WHERE content_digest = 'sha256:abc123...'
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_scans_content_digest' AND object_id = OBJECT_ID('public_scans'))
BEGIN
    CREATE INDEX idx_scans_content_digest ON public_scans (content_digest)
    WHERE content_digest IS NOT NULL;
    PRINT 'Created index: idx_scans_content_digest';
END
ELSE
BEGIN
    PRINT 'Index idx_scans_content_digest already exists, skipping.';
END;
GO

-- Create index for log_entry_id lookups
-- This enables transparency log cross-reference: SELECT * FROM public_scans WHERE log_entry_id = 'rekor-uuid-...'
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_scans_log_entry_id' AND object_id = OBJECT_ID('public_scans'))
BEGIN
    CREATE INDEX idx_scans_log_entry_id ON public_scans (log_entry_id)
    WHERE log_entry_id IS NOT NULL;
    PRINT 'Created index: idx_scans_log_entry_id';
END
ELSE
BEGIN
    PRINT 'Index idx_scans_log_entry_id already exists, skipping.';
END;
GO

-- Migration complete
PRINT 'Migration 003_add_attestation_columns.sql completed successfully.';
GO
