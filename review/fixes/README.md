# Code Fixes Applied

All fixes are applied directly to the codebase (not as patch files) for easier review.

## P0 Fixes Applied

### 1. Dashboard Type Alignment (`dashboard/src/lib/types.ts`)
- **Verdict enum:** Changed from `"LOW" | "MEDIUM" | "HIGH"` to `"LOW_RISK" | "MEDIUM_RISK" | "HIGH_RISK"` to match API `Verdict` enum
- **Scan interface:** Changed from `{package_name, source, score, status, ...}` to `{target, target_type, risk_score, threat_hits, metadata, ...}` to match API `ScanListItem`
- **DashboardStats interface:** Changed from `{scans_today, trend_scans, trend_threats}` to `{scans_trend, threats_trend, approved_trend, critical_trend}` to match API
- **PaginatedResponse:** Changed from `{has_more}` to `{upgrade_message}` to match API `ScanListResponse`

### 2. VerdictBadge Component (`dashboard/src/components/VerdictBadge.tsx`)
- Updated style records to use `LOW_RISK`, `MEDIUM_RISK`, `HIGH_RISK` keys
- Added `verdictLabel()` to strip `_RISK` suffix for display
- Added fallback styles for unknown verdicts
- Accepts `Verdict | string` to handle edge cases

### 3. ScanTable Component (`dashboard/src/components/ScanTable.tsx`)
- Changed from `scan.package_name` → `scan.target`
- Changed from `scan.source` → `scan.target_type` (with `targetTypeLabel` helper)
- Changed from `scan.score` → `scan.risk_score`
- Updated column headers: "Package" → "Target", "Source" → "Type"

### 4. Dashboard Page (`dashboard/src/app/page.tsx`)
- Changed `stats.trend_scans` → `stats.scans_trend`
- Changed `stats.trend_threats` → `stats.threats_trend`

### 5. Scan Detail Page (`dashboard/src/app/scans/[id]/page.tsx`)
- Updated header to use `scan.target` instead of `scan.package_name`
- Updated type/score references
- Updated approved status to check `scan.metadata.approved`
- Replaced quarantine section with threat hits section
- Updated severity order map to handle both old and new enum values

### 6. Scans List Page (`dashboard/src/app/scans/page.tsx`)
- Updated verdict filter options to use `_RISK` suffixed values
- Changed `data.has_more` → computed from `data.total > page * PER_PAGE`

### 7. Threats Page (`dashboard/src/app/threats/page.tsx`)
- Updated severity options and form defaults to use `_RISK` suffixed values
- Updated select dropdown options

### 8. Settings Page (`dashboard/src/app/settings/page.tsx`)
- Updated verdict levels array to use `_RISK` suffixed values
- Updated default channel severity

### 9. API: Remove PRO Gate from Dashboard Stats (`api/routers/scan.py`)
- Removed `require_plan(PlanTier.PRO)` dependency from `get_dashboard_stats`
- Stats are now available to all authenticated users (they're just aggregate numbers)

### 10. API: Give FREE Users Limited Scan Preview (`api/routers/scan.py`)
- Changed from returning empty list for FREE users to showing last 5 scans
- Added `upgrade_message` for FREE users explaining the limit

### 11. API: JWT Secret Startup Warning (`api/main.py`)
- Added CRITICAL log message on startup if default JWT secret is still in use

### 12. API: Tightened CORS (`api/main.py`)
- Changed from `allow_methods=["*"], allow_headers=["*"]` to explicit whitelist

### 13. API: Updated `.env.example` (`api/.env.example`)
- Added `SIGIL_SUPABASE_JWT_SECRET` with documentation
- Added warning comment about JWT secret

### 14. Dashboard: Created `.env.example` (`dashboard/.env.example`)
- New file documenting all required Supabase env vars for OAuth
