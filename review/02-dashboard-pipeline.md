# Phase 2: Dashboard Data Pipeline

**Severity: P0 — Fix Second**

---

## Root Cause Analysis: Why Dashboard Shows No Data

There are **9 cascading failures** preventing data from appearing in the dashboard. Even fixing one or two won't resolve the issue — all must be addressed.

### Failure Chain

```
User loads dashboard
  → AuthGuard checks auth → Likely fails (Supabase null) → Shows login
  → Even if logged in:
    → getDashboardStats() calls GET /dashboard/stats
      → require_plan(PRO) dependency → User is FREE → 403 Forbidden
      → Even if PRO: API returns {scans_trend, threats_trend, ...}
        → Frontend expects {trend_scans, trend_threats, scans_today}
        → Field mismatch → StatsCard shows undefined/NaN
    → listScans() calls GET /scans
      → FREE tier check → Returns {items: [], total: 0}
      → Even if PRO: API returns ScanListItem{target, target_type, risk_score}
        → Frontend expects Scan{package_name, source, score, status}
        → Field mismatch → ScanTable renders empty cells
```

---

## Issue 1: DashboardStats Type Mismatch

**Frontend expects** (`dashboard/src/lib/types.ts:201-209`):
```typescript
interface DashboardStats {
  total_scans: number;
  threats_blocked: number;
  packages_approved: number;
  critical_findings: number;
  scans_today: number;      // ← NOT in API
  trend_scans: number;      // ← API calls this "scans_trend"
  trend_threats: number;    // ← API calls this "threats_trend"
}
```

**API returns** (`api/models.py:516-527`):
```python
class DashboardStats(BaseModel):
    total_scans: int = 0
    threats_blocked: int = 0
    packages_approved: int = 0
    critical_findings: int = 0
    scans_trend: float = 0.0      # ← Frontend expects "trend_scans"
    threats_trend: float = 0.0    # ← Frontend expects "trend_threats"
    approved_trend: float = 0.0   # ← Frontend doesn't use
    critical_trend: float = 0.0   # ← Frontend doesn't use
```

**Fix:** Align the API model to match frontend, OR update frontend types to match API. We fix the frontend to match the API (less risky).

---

## Issue 2: Scan List Returns Empty for FREE Tier

**File:** `api/routers/scan.py:295-307`
```python
if current_tier == PlanTier.FREE:
    return ScanListResponse(
        items=[],
        total=0,
        ...
        upgrade_message="Scan history is available on the Pro plan..."
    )
```

**Impact:** Every new user is FREE (no subscription provisioned). They see nothing.

**Fix:** Allow FREE users to see their last 5 scans (limited preview), or provision trial Pro plan on signup.

---

## Issue 3: Dashboard Stats Requires PRO Plan

**File:** `api/routers/scan.py:478`
```python
_: Annotated[None, Depends(require_plan(PlanTier.PRO))],
```

**Impact:** FREE users get 403, dashboard shows error.

**Fix:** Allow stats for all plans (it's just aggregate numbers). Gate the detailed scan history instead.

---

## Issue 4: Frontend Scan Type vs API ScanListItem

**Frontend** (`types.ts:36-51`):
| Field | Type |
|-------|------|
| `package_name` | string |
| `package_version` | string |
| `source` | ScanSource |
| `verdict` | Verdict |
| `score` | number |
| `status` | string |
| `quarantine_path` | string \| null |

**API** (`models.py:473-485`):
| Field | Type |
|-------|------|
| `target` | string |
| (missing) | - |
| `target_type` | string |
| `verdict` | string |
| `risk_score` | float |
| (missing) | - |
| (missing) | - |

**Fix:** Update frontend `Scan` type to match API `ScanListItem`, or add API aliases.

---

## Issue 5: Verdict Enum Values Don't Match

**Frontend:** `"CLEAN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"`
**API:** `"CLEAN" | "LOW_RISK" | "MEDIUM_RISK" | "HIGH_RISK" | "CRITICAL"`

The VerdictBadge component will never match "LOW_RISK", "MEDIUM_RISK", or "HIGH_RISK".

**Fix:** Update frontend Verdict type to match API enum values.

---

## Issue 6: Threats Count Uses Wrong String

**File:** `api/routers/scan.py:487-489`
```python
threats_blocked = sum(
    1 for r in rows if r.get("verdict") in ("HIGH_RISK", "CRITICAL")
)
```

This is actually correct — the verdict stored in DB uses enum values like "HIGH_RISK". But the **frontend** uses shortened versions. The real issue is the frontend-backend enum mismatch.

---

## Issue 7: PaginatedResponse Missing `has_more`

**Frontend expects** (`types.ts:212-218`):
```typescript
interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  has_more: boolean;  // ← NOT in API response
}
```

**API returns** (`models.py:488-497`):
```python
class ScanListResponse(BaseModel):
    items: list[ScanListItem]
    total: int
    page: int
    per_page: int
    upgrade_message: str | None  # ← NOT in frontend type
```

**Fix:** Add `has_more` computation to API or remove from frontend type.

---

## Issue 8: Empty Database

Even with all type issues fixed, if no scans have been submitted, the dashboard shows nothing.

**Fix:** Create seed data script and document how to populate test data.

---

## Issue 9: Auth Chain Blocks API Calls

If auth fails (Issue from Phase 1), all API calls return 401, dashboard shows error state.

**Fix:** Resolve Phase 1 auth issues first.

---

## Fixes Applied

See `review/fixes/` for:
1. Updated `dashboard/src/lib/types.ts` — aligned with API models
2. Updated `api/routers/scan.py` — removed PRO gate from stats, gave FREE users limited scan preview
3. Updated `dashboard/src/components/ScanTable.tsx` — uses correct field names
4. Updated `dashboard/src/components/VerdictBadge.tsx` — handles both enum formats
