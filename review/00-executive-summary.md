# Sigil — Executive Summary: Full Production & Go-to-Market Review

**Date:** 2026-02-25
**Reviewer:** Cross-functional product launch team
**Repository:** https://github.com/NOMARJ/sigil

---

## Overall Production Readiness Score: 5.5 / 10

**Justification:** The CLI core is production-quality (9/10). The API backend is architecturally sound but has critical auth and data pipeline bugs. The dashboard is non-functional due to type mismatches, plan gating, and broken OAuth. Billing is real (Stripe). Plugins are complete. The gap between "advertised" and "working end-to-end" is the story.

---

## P0 Blockers — Must fix before any paid user touches this

| # | Issue | Component | Impact |
|---|-------|-----------|--------|
| 1 | **Dashboard shows no data** — DashboardStats type mismatch (frontend expects `trend_scans`/`trend_threats`/`scans_today`, API returns `scans_trend`/`threats_trend`/`approved_trend`/`critical_trend`) | Dashboard ↔ API | Dashboard crashes or shows empty |
| 2 | **Scan list returns empty for FREE tier** — `list_scans` returns `items: []` for FREE users; all new users default to FREE since no Stripe/subscription is provisioned | API `scan.py:297` | Every new user sees nothing |
| 3 | **Dashboard stats requires PRO plan** — `GET /dashboard/stats` has `require_plan(PlanTier.PRO)` dependency; FREE users get 403 | API `scan.py:478` | Dashboard overview blank for all new users |
| 4 | **Frontend `Scan` type doesn't match API `ScanListItem`** — Frontend expects `package_name`, `source`, `score`, `status`; API returns `target`, `target_type`, `risk_score` | Dashboard types.ts ↔ API models.py | Scan table renders empty cells |
| 5 | **Frontend `Verdict` enum mismatch** — Dashboard uses `"LOW"`, `"MEDIUM"`, `"HIGH"`; API uses `"LOW_RISK"`, `"MEDIUM_RISK"`, `"HIGH_RISK"` | Dashboard types.ts ↔ API models.py | Verdict badges never match |
| 6 | **Supabase OAuth completely broken** — Dashboard `.env.production` has no `NEXT_PUBLIC_SUPABASE_URL` or `NEXT_PUBLIC_SUPABASE_ANON_KEY`; supabase client is `null` | Dashboard auth | GitHub/Google login crashes |
| 7 | **Hardcoded default JWT secret** — `config.py:49` defaults to `"changeme-generate-a-real-secret"` | API security | Attacker can forge JWTs if env var not set |
| 8 | **API URL mismatch** — CLI uses `api.sigil.nomark.dev`, dashboard uses `api.sigilsec.ai` | Cross-component | Requests go to wrong endpoint |
| 9 | **Threats count uses wrong verdict string** — `scan.py:488` checks for `"HIGH_RISK"` but verdict values stored use enum `.value` which is correct, yet the comparison is inconsistent with frontend | API stats | Threats count always wrong |
| 10 | **OAuth callback URL mismatch** — Dashboard hardcodes `app.sigilsec.ai/auth/callback` but GitHub OAuth configured for Supabase callback URL | Dashboard ↔ GitHub OAuth | OAuth flow fails on redirect |

---

## P1 Critical — Must fix within first week of launch

| # | Issue | Component |
|---|-------|-----------|
| 11 | No token revocation — logout doesn't invalidate JWT; tokens valid for 60 minutes | API auth |
| 12 | No rate limiting on login endpoint — brute force possible | API auth |
| 13 | Refresh tokens identical to access tokens — no real refresh flow | API auth |
| 14 | `install.sh` doesn't verify checksums/GPG signatures on binary downloads | CLI security |
| 15 | Email service not implemented — password reset emails fail silently | API notifications |
| 16 | CORS allows all methods and all headers (`allow_methods=["*"]`, `allow_headers=["*"]`) | API security |
| 17 | Plan tier gating disabled on threat endpoints (commented-out TODO) | API `threat.py:88` |
| 18 | `PaginatedResponse` frontend type expects `has_more` field; API `ScanListResponse` doesn't return it | Dashboard ↔ API |

---

## P2 Important — Should fix within first month

| # | Issue | Component |
|---|-------|-----------|
| 19 | No account lockout after failed login attempts | API auth |
| 20 | No JWKS support for Supabase JWT verification — uses deprecated static secret | API auth |
| 21 | Scan history retention not enforced (90-day Pro, 1-year Team) | API |
| 22 | Supabase project ID hardcoded in deploy scripts | deploy-api-supabase.sh |
| 23 | Dashboard `scans_today` field not computed by API | API stats |
| 24 | No audit log API endpoint exposed | API |
| 25 | API `app_version` still says `0.1.0` while CLI is at `1.0.5` | API config |
| 26 | "Coming soon" in some docs for features that are actually ready | Docs |
| 27 | JetBrains plugin at `0.1.0` vs CLI at `1.0.5` — confusing to users | Plugin versioning |

---

## P3 Nice to Have — Backlog

| # | Issue | Component |
|---|-------|-----------|
| 28 | MFA/2FA support | API auth |
| 29 | Session management (concurrent login limits) | API |
| 30 | Docker/OCI image scanning | CLI scanner |
| 31 | Go/Cargo ecosystem scanning | CLI scanner |
| 32 | Custom scan rules (YAML DSL) | CLI |
| 33 | Enterprise SSO/SAML | API auth |
| 34 | Comment-aware regex scanning (avoid matching in comments) | CLI scanner |
| 35 | Binary payload detection | CLI scanner |
| 36 | Transitive dependency scanning | CLI scanner |

---

## Recommended Launch Sequence

### Phase 1: CLI Open Source (Ready NOW)
- The CLI is production-quality: all 6 scan phases work, scoring is correct, offline mode works
- Ship as free open-source tool immediately
- Available via: npm, Homebrew, cargo install, curl, Docker
- **Prerequisite:** Fix `install.sh` signature verification (P1-14)

### Phase 2: Pro Tier with Dashboard (2-3 weeks of fixes)
- Fix all P0 issues (dashboard data pipeline, auth, type mismatches)
- Fix P1 auth issues (token revocation, rate limiting)
- Configure Supabase OAuth with correct callback URLs
- Set production JWT secrets
- Deploy API with proper env vars
- **Prerequisite:** All P0s resolved, P1-11 through P1-16 resolved

### Phase 3: Team Tier + Plugins (1-2 weeks after Phase 2)
- Team management already works
- Policies and alerts already work
- Push VS Code + JetBrains to marketplaces
- Re-enable plan gating on threat endpoints
- **Prerequisite:** Phase 2 stable, marketplace approvals

---

## Honest Assessment

**Is this product ready for paying customers?** No. Not today.

**What's actually good:**
- The CLI scan engine is genuinely excellent — all 6 phases work, the scoring is correct, the pattern library is comprehensive (247 signatures), and it detected real-world attacks (OpenClaw, Shai-Hulud)
- The architecture is sound — FastAPI + Next.js + Supabase is a solid stack
- The plugin ecosystem is remarkably complete — VS Code, JetBrains, Claude Code, and MCP server all work
- Billing is real Stripe integration, not a stub
- Documentation is comprehensive (27 public docs)

**What's broken:**
- The dashboard is completely non-functional for the use case of "sign up, scan, see results"
- Auth is half Supabase OAuth (broken), half custom JWT (works for CLI only)
- Type mismatches between frontend and backend mean even if auth worked, data would render wrong
- Plan gating blocks all features for new (FREE) users, but there's no working upgrade path until Stripe is configured

**Minimum viable path to paying customers:**
1. Fix the 10 P0 items (primarily type alignment and plan gating)
2. Choose ONE auth strategy (recommend: Supabase OAuth for dashboard + custom JWT for CLI, with API accepting both)
3. Provision new users with a trial Pro plan (7 or 14 days) so they can actually see the dashboard
4. Deploy with correct environment variables
5. Test the full flow: sign up → scan → see results → upgrade → pay

**Estimated effort to reach MVP:** 2-3 focused engineering weeks for one full-stack developer.

---

## Component Scores

| Component | Score | Notes |
|-----------|-------|-------|
| CLI Scan Engine | 9/10 | Production-ready, comprehensive detection |
| CLI UX/DX | 9/10 | Good help, error messages, exit codes, offline mode |
| API Architecture | 7/10 | Well-structured, proper dependency injection, but bugs |
| API Auth | 4/10 | Custom JWT works, Supabase broken, no revocation |
| Dashboard UI | 7/10 | Well-designed components, loading states, dark theme |
| Dashboard Data | 2/10 | Shows nothing — type mismatches, plan gating, broken auth |
| Plugins | 9/10 | All 4 plugins functional and well-documented |
| Infrastructure | 8/10 | Docker, CI/CD, multi-platform builds all solid |
| Documentation | 8/10 | Comprehensive, mostly accurate, some domain inconsistencies |
| Billing | 7/10 | Real Stripe integration, but default is FREE with no trial |
| Security Posture | 6/10 | Good patterns, but hardcoded secret defaults, no signature verification |
| GTM Readiness | 5/10 | Comparison table accurate, but can't deliver on paid features today |
