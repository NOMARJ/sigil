# US-103 Evidence: Pro-Gated Route Inventory

**Feature:** F-003 Pro Billing + Tier Gating Verification
**Story:** STORY-103
**Status:** DONE
**Captured:** 2026-05-03 (autopilot session)
**Verifier:** Claude Code (Opus 4.7) — autonomous, no operator action required

---

## Reproducibility Command

```bash
grep -rn "require_plan(PlanTier.PRO)" /Users/reecefrazier/CascadeProjects/sigil/api/routers/
```

Hit count: **33** (PRD floor was ≥18 — comfortably exceeded).

## Method + Path Resolution

The grep gives line numbers; resolving each line back to the `@router.{verb}(path)` decorator above it (using `python3` to walk both `@router.` and `@dashboard_router.` decorators) produces:

| File:Line | Decorator | Method | Resolved Path |
|-----------|-----------|--------|---------------|
| api/routers/billing.py:605 | @router.post L591 | POST | `/v1/billing/purchase-credits` |
| api/routers/scan.py:857 | @dashboard_router.get L844 | GET | `/scans/{scan_id}` |
| api/routers/scan.py:877 | @dashboard_router.get L864 | GET | `/scans/{scan_id}/findings` |
| api/routers/scan.py:903 | @dashboard_router.post L890 | POST | `/scans/{scan_id}/approve` |
| api/routers/scan.py:943 | @dashboard_router.post L930 | POST | `/scans/{scan_id}/reject` |
| api/routers/threat.py:89 | @router.get L76 | GET | `/v1/threat/{package_hash}` |
| api/routers/threat.py:117 | @router.get L110 | GET | `/v1/threats` |
| api/routers/threat.py:149 | @router.get L141 | GET | `/v1/signatures` |
| api/routers/threat.py:173 | @router.post L164 | POST | `/v1/signatures` |
| api/routers/threat.py:196 | @router.delete L187 | DELETE | `/v1/signatures/{sig_id}` |
| api/routers/threat.py:220 | @router.get L213 | GET | `/v1/threat-reports` |
| api/routers/threat.py:241 | @router.get L233 | GET | `/v1/threat-reports/{report_id}` |
| api/routers/threat.py:262 | @router.patch L253 | PATCH | `/v1/threat-reports/{report_id}` |
| api/routers/interactive.py:186 | @router.post L172 | POST | `/v1/interactive/investigate` |
| api/routers/interactive.py:262 | @router.post L248 | POST | `/v1/interactive/false-positive` |
| api/routers/interactive.py:330 | @router.post L316 | POST | `/v1/interactive/remediate` |
| api/routers/interactive.py:406 | @router.post L393 | POST | `/v1/interactive/sessions` |
| api/routers/interactive.py:481 | @router.get L470 | GET | `/v1/interactive/sessions` |
| api/routers/interactive.py:551 | @router.get L538 | GET | `/v1/interactive/sessions/{session_id}` |
| api/routers/interactive.py:644 | @router.get L633 | GET | `/v1/interactive/credits` |
| api/routers/interactive.py:693 | @router.post L680 | POST | `/v1/interactive/compliance` |
| api/routers/interactive.py:796 | @router.post L784 | POST | `/v1/interactive/compliance/export` |
| api/routers/interactive.py:911 | @router.post L898 | POST | `/v1/interactive/sessions/{session_id}/continue` |
| api/routers/interactive.py:984 | @router.post L972 | POST | `/v1/interactive/routing/preview` |
| api/routers/interactive.py:1042 | @router.get L1031 | GET | `/v1/interactive/routing/stats` |
| api/routers/interactive.py:1089 | @router.post L1077 | POST | `/v1/interactive/bulk/group` |
| api/routers/interactive.py:1150 | @router.post L1137 | POST | `/v1/interactive/bulk/analyze` |
| api/routers/interactive.py:1417 | @router.get L1407 | GET | `/v1/interactive/feedback/accuracy` |
| api/routers/policies.py:105 | @router.get L97 | GET | `/v1/policies` |
| api/routers/policies.py:131 | @router.post L121 | POST | `/v1/policies` |
| api/routers/policies.py:199 | @router.put L185 | PUT | `/v1/policies/{policy_id}` |
| api/routers/policies.py:238 | @router.delete L229 | DELETE | `/v1/policies/{policy_id}` |
| api/routers/policies.py:262 | @router.post L253 | POST | `/v1/policies/evaluate` |

**Distribution by router:**
- `interactive.py` (`/v1/interactive`): 15
- `threat.py` (`/v1`): 8
- `policies.py` (`/v1`): 5
- `scan.py` (`dashboard_router`, no prefix): 4
- `billing.py` (`/v1/billing`): 1

## Findings

### F1 — PRD figure correction (informational, not a defect)
PRD intro states "18 Pro endpoints gated by `require_plan(PlanTier.PRO)` in `api/routers/interactive.py`". Actual count in `interactive.py` is **15**. Total across all routers is **33**. The PRD figure is stale by ~3 routes; suggest updating PRD intro for accuracy. Not a blocker.

### F2 — `scan.py` Pro-gated routes are NOT under `/v1` prefix
The 4 Pro-gated scan routes live on `dashboard_router` (registered at `app.include_router(scan.dashboard_router)` in `api/main.py:382`), which has NO `prefix` argument. So they answer at:
- `GET /scans/{scan_id}`
- `GET /scans/{scan_id}/findings`
- `POST /scans/{scan_id}/approve`
- `POST /scans/{scan_id}/reject`

The legacy `GET /v1/scans/{scan_id}` (`api/routers/scan.py:831`) is NOT Pro-gated. So a Pro feature inadvertently routes through dashboard-side paths only. Worth documenting in feature copy and Stripe portal upgrade messaging — Pro upsell pointers should reference dashboard URLs, not API URLs.

### F3 — Canary recommendation: `POST /v1/interactive/investigate`
Recommended canary for STORY-105 round-trip evidence:

- **Path:** `/v1/interactive/investigate`
- **Method:** POST
- **Decorator:** `api/routers/interactive.py:172`
- **Gate:** `require_plan(PlanTier.PRO)` at line 186
- **Rationale:**
  1. Matches PRD §US-001 acceptance criterion 6 verbatim ("any `require_plan(PlanTier.PRO)` route").
  2. POST with body — exercises both auth gate and request parsing.
  3. AI-backed (LLM) — proves credit system + Pro feature path end-to-end, not just gate bypass.
  4. First Pro endpoint listed in `interactive.py` (line order = canonical).
  5. Returns structured JSON (LLM body) — STORY-105 §"Pro route 200 with real LLM body" requires this.

Alternatives that also work but are weaker:
- `POST /v1/billing/purchase-credits` — narrower (billing-only, less representative of feature surface).
- `GET /v1/interactive/credits` — read-only, doesn't exercise LLM/credit consumption path.

## Verdict

PASS. STORY-103 acceptance criteria met:
- [x] `grep -rn "require_plan(PlanTier.PRO)" api/routers/` output captured (33 hits).
- [x] HTTP method + path resolved per line (table above).
- [x] Recommended canary named with rationale (`POST /v1/interactive/investigate`).
- [x] ≥18 floor met (33 ≥ 18).
