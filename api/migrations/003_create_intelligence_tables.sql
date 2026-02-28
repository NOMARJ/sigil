-- Sigil Bot — Intelligence Schema
-- Proprietary analytics layer (NOMARK internal — never exposed publicly)
--
-- Stores market intelligence signals extracted from scan metadata.
-- Separate from public scan data.

-- Package intelligence records (one per scan)
CREATE TABLE IF NOT EXISTS intel_packages (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    ecosystem       TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    package_version TEXT NOT NULL DEFAULT '',
    categories      TEXT[] NOT NULL DEFAULT '{}',
    providers       TEXT[] NOT NULL DEFAULT '{}',
    infrastructure  TEXT[] NOT NULL DEFAULT '{}',
    author          TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    keywords        TEXT[] NOT NULL DEFAULT '{}',
    risk_score      REAL NOT NULL DEFAULT 0,
    verdict         TEXT NOT NULL DEFAULT 'LOW_RISK',
    findings_count  INTEGER NOT NULL DEFAULT 0,
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_intel_packages_ecosystem
    ON intel_packages (ecosystem);
CREATE INDEX IF NOT EXISTS idx_intel_packages_categories
    ON intel_packages USING GIN (categories);
CREATE INDEX IF NOT EXISTS idx_intel_packages_providers
    ON intel_packages USING GIN (providers);
CREATE INDEX IF NOT EXISTS idx_intel_packages_scanned
    ON intel_packages (scanned_at DESC);

-- Aggregated category trends (populated by weekly rollup)
CREATE TABLE IF NOT EXISTS intel_category_trends (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    week        TEXT NOT NULL,           -- ISO week: "2026-W09"
    category    TEXT NOT NULL,
    ecosystem   TEXT NOT NULL DEFAULT 'all',
    new_count   INTEGER NOT NULL DEFAULT 0,
    total_count INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (week, category, ecosystem)
);

-- Provider usage trends (populated by weekly rollup)
CREATE TABLE IF NOT EXISTS intel_provider_trends (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    week        TEXT NOT NULL,
    provider    TEXT NOT NULL,
    ecosystem   TEXT NOT NULL DEFAULT 'all',
    usage_count INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (week, provider, ecosystem)
);

-- Publisher profiles (aggregated from scan data)
CREATE TABLE IF NOT EXISTS intel_publishers (
    id                TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    author            TEXT NOT NULL UNIQUE,
    total_packages    INTEGER NOT NULL DEFAULT 0,
    avg_risk_score    REAL NOT NULL DEFAULT 0,
    high_risk_count   INTEGER NOT NULL DEFAULT 0,
    ecosystems        TEXT[] NOT NULL DEFAULT '{}',
    categories        TEXT[] NOT NULL DEFAULT '{}',
    first_seen        TIMESTAMPTZ,
    last_active       TIMESTAMPTZ,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_intel_publishers_author
    ON intel_publishers (author);
