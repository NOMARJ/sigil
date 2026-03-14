# Sigil Database Schemas

Reference for the three core schema domains: **Scans**, **Public Scans**, and **Forge**.

All tables use Azure SQL Database (T-SQL) with `UNIQUEIDENTIFIER` primary keys, `DATETIMEOFFSET` timestamps, and `ISJSON()` check constraints on JSON columns.

---

## Scans

User-initiated scan results. Each scan belongs to a user and optionally a team.

**Source:** `api/schema.sql`

### Table: `scans`

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `UNIQUEIDENTIFIER` | `NEWID()` | Primary key |
| `user_id` | `UNIQUEIDENTIFIER` | — | FK → `users(id)` ON DELETE SET NULL |
| `team_id` | `UNIQUEIDENTIFIER` | — | FK → `teams(id)` ON DELETE SET NULL |
| `target` | `NVARCHAR(MAX)` | — | Scan target (path, URL, package name) |
| `target_type` | `NVARCHAR(50)` | `'directory'` | Type: directory, git, pip, npm |
| `files_scanned` | `INT` | `0` | Number of files analyzed |
| `risk_score` | `FLOAT` | `0.0` | Computed risk score |
| `verdict` | `NVARCHAR(50)` | `'LOW_RISK'` | Verdict classification |
| `findings_json` | `NVARCHAR(MAX)` | `'[]'` | JSON array of finding objects |
| `metadata_json` | `NVARCHAR(MAX)` | `'{}'` | JSON metadata |
| `created_at` | `DATETIMEOFFSET` | `SYSDATETIMEOFFSET()` | Creation timestamp |

**Constraints:**
- `CK_scans_findings_json` — validates `ISJSON(findings_json)`
- `CK_scans_metadata_json` — validates `ISJSON(metadata_json)`

**Indexes:**
- `idx_scans_user` — `(user_id)`
- `idx_scans_team` — `(team_id)`
- `idx_scans_verdict` — `(verdict)`
- `idx_scans_created` — `(created_at DESC)`
- `idx_scans_risk_score` — `(risk_score DESC)`
- `idx_scans_team_risk` — `(team_id, risk_score DESC, created_at DESC)`

**API Endpoints:**
- `POST /v1/scan` — Submit scan results
- `GET /scans` — List user scans
- `GET /scans/{id}` — Get scan detail

---

## Public Scans

Public package scan database for the registry and distribution layer. Deduplicated by ecosystem + package + version.

**Source:** `api/schema.sql`

### Table: `public_scans`

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `UNIQUEIDENTIFIER` | `NEWID()` | Primary key |
| `ecosystem` | `NVARCHAR(100)` | — | Package ecosystem: clawhub, pypi, npm, github, mcp |
| `package_name` | `NVARCHAR(400)` | — | Package identifier |
| `package_version` | `NVARCHAR(255)` | `''` | Specific version scanned |
| `risk_score` | `FLOAT` | `0.0` | Computed risk score |
| `verdict` | `NVARCHAR(50)` | `'LOW_RISK'` | Verdict classification |
| `findings_count` | `INT` | `0` | Number of findings |
| `files_scanned` | `INT` | `0` | Number of files analyzed |
| `findings_json` | `NVARCHAR(MAX)` | `'[]'` | JSON array of finding objects |
| `metadata_json` | `NVARCHAR(MAX)` | `'{}'` | JSON metadata |
| `scanned_at` | `DATETIMEOFFSET` | `SYSDATETIMEOFFSET()` | When the scan was performed |
| `created_at` | `DATETIMEOFFSET` | `SYSDATETIMEOFFSET()` | Record creation timestamp |

**Constraints:**
- `UQ_public_scans_ecosystem_package` — `UNIQUE(ecosystem, package_name, package_version)`
- `CK_public_scans_findings_json` — validates `ISJSON(findings_json)`
- `CK_public_scans_metadata_json` — validates `ISJSON(metadata_json)`

**Indexes:**
- `idx_public_scans_ecosystem` — `(ecosystem)`
- `idx_public_scans_package` — `(ecosystem, package_name)`
- `idx_public_scans_verdict` — `(verdict)`
- `idx_public_scans_risk_score` — `(risk_score DESC)`
- `idx_public_scans_scanned_at` — `(scanned_at DESC)`
- `idx_public_scans_ecosystem_verdict` — `(ecosystem, verdict)`

**API Endpoints:**
- `GET /registry/search` — Search public scan database
- `GET /registry/{ecosystem}` — List scanned packages by ecosystem
- `GET /registry/{ecosystem}/{name}/{version}` — Get specific package scan

---

## Forge

Classification, capabilities, matching, and premium features for the Sigil Forge tool marketplace.

**Source:** `archive/migrations/004_create_forge_classification.sql`, `008_forge_premium_features.sql`, `009_forge_tool_metrics.sql`, `add_forge_security.sql`, `add_forge_analytics.sql`

### Table: `forge_classification`

Main classification data for each scanned package/tool.

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `UNIQUEIDENTIFIER` | `NEWID()` | Primary key |
| `ecosystem` | `NVARCHAR(100)` | — | clawhub, mcp, npm, pypi |
| `package_name` | `NVARCHAR(400)` | — | Package identifier |
| `package_version` | `NVARCHAR(255)` | `''` | Version string |
| `category` | `NVARCHAR(100)` | — | Primary category (Database, API Integration, etc.) |
| `subcategory` | `NVARCHAR(100)` | `''` | Secondary category |
| `confidence_score` | `FLOAT` | `0.0` | Classification confidence 0.0–1.0 |
| `description_summary` | `NVARCHAR(MAX)` | `''` | Cleaned/summarized description |
| `environment_vars` | `NVARCHAR(MAX)` | `'[]'` | JSON array of env var patterns |
| `network_protocols` | `NVARCHAR(MAX)` | `'[]'` | JSON array of protocols |
| `file_patterns` | `NVARCHAR(MAX)` | `'[]'` | JSON array of file types accessed |
| `import_patterns` | `NVARCHAR(MAX)` | `'[]'` | JSON array of key imports |
| `risk_indicators` | `NVARCHAR(MAX)` | `'[]'` | JSON array of risk patterns |
| `classified_at` | `DATETIMEOFFSET` | `SYSDATETIMEOFFSET()` | Classification timestamp |
| `updated_at` | `DATETIMEOFFSET` | `SYSDATETIMEOFFSET()` | Last update |
| `classifier_version` | `NVARCHAR(50)` | `'v1.0'` | Classifier version used |
| `metadata_json` | `NVARCHAR(MAX)` | `'{}'` | Additional metadata |

**Constraints:**
- `UQ_forge_classification_package` — `UNIQUE(ecosystem, package_name, package_version)`
- JSON check constraints on all JSON columns

**Indexes:**
- `idx_forge_classification_ecosystem` — `(ecosystem)`
- `idx_forge_classification_package` — `(ecosystem, package_name)`
- `idx_forge_classification_category` — `(category)`
- `idx_forge_classification_subcategory` — `(category, subcategory)`
- `idx_forge_classification_confidence` — `(confidence_score DESC)`
- `idx_forge_classification_updated` — `(updated_at DESC)`

---

### Table: `forge_capabilities`

Capability tags detected for each classified package.

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `UNIQUEIDENTIFIER` | `NEWID()` | Primary key |
| `classification_id` | `UNIQUEIDENTIFIER` | — | FK → `forge_classification(id)` CASCADE |
| `capability` | `NVARCHAR(100)` | — | e.g. reads_files, makes_network_calls |
| `confidence` | `FLOAT` | `1.0` | Detection confidence |
| `evidence` | `NVARCHAR(MAX)` | `''` | Evidence from scan |
| `created_at` | `DATETIMEOFFSET` | `SYSDATETIMEOFFSET()` | Creation timestamp |

---

### Table: `forge_matches`

Compatible tool pairings based on shared env vars, protocols, or complementary functionality.

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `UNIQUEIDENTIFIER` | `NEWID()` | Primary key |
| `primary_classification_id` | `UNIQUEIDENTIFIER` | — | FK → `forge_classification(id)` CASCADE |
| `secondary_classification_id` | `UNIQUEIDENTIFIER` | — | FK → `forge_classification(id)` NO ACTION |
| `match_type` | `NVARCHAR(50)` | — | env_vars, protocols, complementary, category |
| `compatibility_score` | `FLOAT` | `0.0` | How well they work together (0.0–1.0) |
| `shared_elements` | `NVARCHAR(MAX)` | `'[]'` | JSON array of shared elements |
| `match_reason` | `NVARCHAR(MAX)` | `''` | Human-readable explanation |
| `trust_score_combined` | `FLOAT` | `0.0` | Combined trust score |
| `created_at` | `DATETIMEOFFSET` | `SYSDATETIMEOFFSET()` | Creation timestamp |
| `updated_at` | `DATETIMEOFFSET` | `SYSDATETIMEOFFSET()` | Last update |

**Constraints:**
- `CK_forge_matches_different_packages` — primary and secondary must differ

---

### Table: `forge_categories`

Predefined category taxonomy with 13 built-in categories.

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `UNIQUEIDENTIFIER` | `NEWID()` | Primary key |
| `category` | `NVARCHAR(100)` | — | Unique category key |
| `display_name` | `NVARCHAR(200)` | — | Human-readable name |
| `description` | `NVARCHAR(MAX)` | `''` | Category description |
| `parent_category` | `NVARCHAR(100)` | — | For hierarchical categories |
| `sort_order` | `INT` | `0` | Display ordering |
| `is_active` | `BIT` | `1` | Whether category is active |

**Built-in categories:** Database, API Integration, Code Tools, File System, AI/LLM, Security, DevOps, Communication, Data Pipeline, Testing, Search, Monitoring, Uncategorized

---

### Table: `forge_tool_metrics`

Tool usage metrics tracked over time.

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `BIGINT IDENTITY` | — | Primary key |
| `tool_id` | `NVARCHAR(255)` | — | Tool identifier |
| `date` | `DATE` | — | Metric date |
| `downloads` | `BIGINT` | `0` | Download count |
| `stars` | `BIGINT` | `0` | Star count |
| `version` | `NVARCHAR(50)` | — | Current version |
| `forks` | `BIGINT` | `0` | Fork count |
| `issues_open` | `BIGINT` | `0` | Open issue count |
| `issues_closed` | `BIGINT` | `0` | Closed issue count |
| `trust_score` | `DECIMAL(5,2)` | `0` | Trust score 0–100 |

**Constraints:**
- `UK_forge_tool_metrics_tool_date` — `UNIQUE(tool_id, date)`
- Check constraints on downloads >= 0, stars >= 0, trust_score 0–100

**View:** `forge_tool_metrics_latest` — latest metrics per tool (uses `ROW_NUMBER()`)

---

### Table: `forge_trending_cache`

Pre-calculated trending data for the Forge marketplace.

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `BIGINT IDENTITY` | — | Primary key |
| `tool_id` | `NVARCHAR(255)` | — | Tool identifier |
| `timeframe` | `NVARCHAR(10)` | — | 24h, 7d, or 30d |
| `ecosystem` | `NVARCHAR(50)` | `'all'` | Ecosystem filter |
| `category` | `NVARCHAR(100)` | `'all'` | Category filter |
| `rank_position` | `INT` | — | Current rank |
| `previous_rank` | `INT` | — | Previous rank |
| `rank_change` | `INT` | `0` | Rank delta |
| `growth_percentage` | `DECIMAL(10,4)` | `0` | Growth rate |
| `direction` | `NVARCHAR(10)` | `'stable'` | up, down, stable, new |
| `composite_score` | `DECIMAL(10,4)` | `0` | Composite trending score |
| `downloads_current` | `BIGINT` | `0` | Current period downloads |
| `downloads_previous` | `BIGINT` | `0` | Previous period downloads |
| `downloads_growth` | `DECIMAL(10,4)` | `0` | Download growth rate |
| `stars_current` | `BIGINT` | `0` | Current period stars |
| `stars_previous` | `BIGINT` | `0` | Previous period stars |
| `stars_growth` | `DECIMAL(10,4)` | `0` | Star growth rate |
| `trust_score_current` | `DECIMAL(5,2)` | `0` | Current trust score |
| `cache_key` | `NVARCHAR(255)` | — | Unique cache key |
| `expires_at` | `DATETIME2` | — | Cache expiration |

**Stored procedure:** `sp_cleanup_trending_cache` — removes expired entries

---

### Table: `forge_user_tools`

User tool tracking and preferences (premium feature).

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `UNIQUEIDENTIFIER` | `NEWID()` | Primary key |
| `user_id` | `UNIQUEIDENTIFIER` | — | FK → `users(id)` CASCADE |
| `tool_id` | `NVARCHAR(255)` | — | Package name |
| `ecosystem` | `NVARCHAR(50)` | — | pip, npm, mcp, etc. |
| `tracked_at` | `DATETIMEOFFSET` | `SYSDATETIMEOFFSET()` | When user started tracking |
| `is_starred` | `BIT` | `0` | Starred by user |
| `custom_tags` | `NVARCHAR(MAX)` | — | JSON array of user tags |
| `notes` | `NVARCHAR(MAX)` | — | User notes |

**Constraint:** `UNIQUE(user_id, tool_id, ecosystem)`

---

### Table: `forge_stacks`

User-created tool combinations (stacks).

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `UNIQUEIDENTIFIER` | `NEWID()` | Primary key |
| `user_id` | `UNIQUEIDENTIFIER` | — | FK → `users(id)` CASCADE |
| `team_id` | `UNIQUEIDENTIFIER` | — | FK → `teams(id)` SET NULL |
| `name` | `NVARCHAR(255)` | — | Stack name |
| `description` | `NVARCHAR(MAX)` | — | Stack description |
| `tools` | `NVARCHAR(MAX)` | `'[]'` | JSON array of tools |
| `is_public` | `BIT` | `0` | Public visibility |
| `created_at` | `DATETIMEOFFSET` | `SYSDATETIMEOFFSET()` | Creation timestamp |
| `updated_at` | `DATETIMEOFFSET` | `SYSDATETIMEOFFSET()` | Last update |

---

### Table: `forge_trust_score_history`

Historical trust score tracking per tool. Auto-populated via trigger on `public_scans`.

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `UNIQUEIDENTIFIER` | `NEWID()` | Primary key |
| `tool_id` | `NVARCHAR(255)` | — | Tool identifier |
| `ecosystem` | `NVARCHAR(50)` | — | Ecosystem |
| `tool_name` | `NVARCHAR(255)` | — | Display name |
| `trust_score` | `FLOAT` | — | Calculated trust score |
| `previous_score` | `FLOAT` | — | Previous trust score |
| `scan_id` | `UNIQUEIDENTIFIER` | — | FK → `public_scans(id)` SET NULL |
| `change_reason` | `NVARCHAR(500)` | — | Reason for score change |
| `recorded_at` | `DATETIMEOFFSET` | `SYSDATETIMEOFFSET()` | Record timestamp |

**Trigger:** `tr_public_scans_trust_score_update` — auto-inserts history on `public_scans` INSERT/UPDATE

---

## Entity Relationships

```
users ──┬── scans (user_id)
        ├── public_scans (via registry, no direct FK)
        ├── forge_user_tools (user_id)
        └── forge_stacks (user_id)

teams ──┬── scans (team_id)
        └── forge_stacks (team_id)

forge_classification ──┬── forge_capabilities (classification_id)
                       └── forge_matches (primary/secondary_classification_id)

public_scans ── forge_trust_score_history (scan_id)
```
