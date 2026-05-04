# PRD: Brand v1.0 Rollout

**Feature:** F-006
**Epic:** EP-004 — Brand & Identity System
**Status:** approved
**Created:** 2026-05-04
**Approved:** 2026-05-04
**Source brief:** `dashboard/public/brand/Sigil Brand Brief.html` (v1.0)
**First-principles plan:** `docs/plans/2026-05-04-brand-rollout-first-principles.md`

---

## Introduction

A canonical Brand Brief v1.0 has been authored at `dashboard/public/brand/Sigil Brand Brief.html`. It defines a complete identity system: two marks (Brace primary + Seal attestation), a black-mode-first surface palette, a fixed brand-green scale, a three-state verdict family, type pairing (Inter + JetBrains Mono), and explicit "do / don't" rules.

The brief ships with 20 finished SVG assets in `dashboard/public/brand/` — but those files are currently untracked, no code references them, and the dashboard runs an ad-hoc emerald-on-blue theme that diverges from the brief on every dimension (surface tones, brand-green hex values, missing JetBrains Mono, hardcoded `S` letter mark in the sidebar that violates the brief's "don't trace" rule).

This PRD aligns the dashboard surfaces with the brief without breaking working components. It is a **visual / token alignment** rollout, not a behaviour change. The 4-tier per-finding severity taxonomy (LOW/MEDIUM/HIGH/CRITICAL_RISK) is a different domain from the brief's 3-state Seal verdict and is preserved as-is. The `sigil` CLI is not visually rebranded — its ANSI output already matches the brief's "CLI Unicode fallback" pattern.

---

## Goals

- Make the brand brief enforceable in code: tokens, fonts, marks, and favicon all flow from the brief
- Land the Brace SVG on the primary chrome surface (sidebar) so users see the real mark, not a traced letter
- Land the Seal SVG on attestation surfaces (scan detail) via a dedicated `SealVerdict` component paired with text labels
- Commit the brand asset directory to the repo (currently untracked)
- Preserve the existing 4-tier per-finding severity taxonomy — the brief does not address per-finding severity, only scan-level attestation

---

## Non-goals

- Rewriting every component to consume `--sigil-*` tokens directly (incremental — values are aligned, refactor follows over time)
- Changing CLI verdict-word semantics (LOW_RISK → CLEAN, etc.) — that touches exit codes; separate ADR
- Marketing site / docs site styling (separate repos)
- Email templates, README badge generator, partner badge endpoints (later — they live on `sigilsec.ai`, not in this dashboard)
- Replacing or sunsetting `VerdictBadge.tsx` (per-finding severity stays)
- Building dark/light theme switching — the brief is black-mode-first; light variants exist as SVG mono-light files for inversions only

---

## User Stories

### US-001: Surface palette and brand greens match the brief

**Description:** As a designer cross-checking the live dashboard against the brand brief, I want every surface tone, brand-green value, and verdict colour in the live app to match the brief's hex codes exactly so that the brief is enforceable, not aspirational.

**Acceptance Criteria:**
- [ ] `dashboard/src/app/globals.css` `--color-bg-primary` value is `#0A0A0A`
- [ ] `--color-bg-secondary` is `#161616`, `--color-bg-tertiary` is `#1C1C1C`, `--color-border` is `#262626`
- [ ] `--color-accent` is `#3FB950` (replacing the previous emerald `#10b981`); accent-hover `#56D364`; accent-muted `#238636`; accent-dark `#196C2E`
- [ ] `--color-success` is `#22C55E` (brief's `clean` verdict); `--color-warning` is `#EAB308` (brief's `quarantine`); `--color-danger` is `#EF4444` (brief's `risk`)
- [ ] `--sigil-*` token aliases per brief §09 added to `:root` (sigil-black, sigil-surface, sigil-elevated, sigil-border, sigil-gray, sigil-light, sigil-offwhite, sigil-white, sigil-green, sigil-green-mid, sigil-green-deep, sigil-green-soft, sigil-clean, sigil-warn, sigil-risk, sigil-mono, sigil-sans)
- [ ] Verify: `grep -c "#0A0A0A\|#161616\|#1C1C1C\|#262626\|#3FB950\|#56D364\|#238636\|#196C2E\|#22C55E\|#EAB308\|#EF4444" dashboard/src/app/globals.css` returns ≥ 11

**Priority:** 1
**Files:**
- `dashboard/src/app/globals.css` (modify)

---

### US-002: Tailwind palette aligns to the brief

**Description:** As a frontend developer using Tailwind utility classes, I want `bg-brand-500`, `border-surface-border`, and `text-verdict-risk` to render the brief's exact hex values so that I can write component code without hand-rolling raw CSS.

**Acceptance Criteria:**
- [ ] `tailwind.config.ts` `colors.brand.500` is `#3FB950` (was `#10b981`)
- [ ] `colors.brand` scale is `{deep:#196C2E, mid:#238636, 500:#3FB950, soft:#56D364}` plus the existing 50-950 ramp regenerated around `#3FB950`
- [ ] A new `colors.surface` palette is added with keys matching the brief: `black:#0A0A0A, surface:#161616, elevated:#1C1C1C, border:#262626, muted:#404040, gray:#787878, light:#A3A3A3, offwhite:#E5E5E5, white:#FAFAFA`
- [ ] A new `colors.verdict` palette is added: `{clean:#22C55E, warn:#EAB308, risk:#EF4444}`
- [ ] `theme.extend.fontFamily.mono` lists `'JetBrains Mono'` first
- [ ] Verify: build succeeds (`cd dashboard && npm run build`) without Tailwind config errors

**Priority:** 1
**Files:**
- `dashboard/tailwind.config.ts` (modify)
- `dashboard/src/app/globals.css` (cross-reference for token consistency)

---

### US-003: JetBrains Mono is loaded alongside Inter

**Description:** As a designer applying the brief's typography spec (display/mono surfaces use JetBrains Mono), I want the JetBrains Mono webfont actually loaded in the document so that mono surfaces render in the brand typeface, not in the OS fallback.

**Acceptance Criteria:**
- [ ] `dashboard/src/app/layout.tsx` `<head>` includes a `<link>` to `https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap` (or equivalent — both families in one request)
- [ ] Verify in browser DevTools Network tab: `JetBrains+Mono` font file requested on page load
- [ ] Verify: any element styled `font-family: var(--sigil-mono)` or Tailwind `font-mono` renders in JetBrains Mono (visual check on `/scans` page)

**Priority:** 1
**Files:**
- `dashboard/src/app/layout.tsx` (modify)

---

### US-004: Favicon points to the brand SVG

**Description:** As a user with the dashboard pinned in a browser tab, I want to see the Brace mark in the tab favicon so that the product is recognisable at 16px alongside other open tabs.

**Acceptance Criteria:**
- [ ] `dashboard/src/app/layout.tsx` `metadata.icons.icon` points to `/brand/favicon/favicon.svg`
- [ ] `metadata.icons` also exposes `/brand/favicon/favicon-dark.svg` via `media: '(prefers-color-scheme: light)'` for the inverted variant
- [ ] `viewport.themeColor` updated to `#0A0A0A` (was `#111827`)
- [ ] Verify: `curl -sI http://localhost:3000/brand/favicon/favicon.svg` returns `200 OK` with `content-type: image/svg+xml`
- [ ] Verify: opening the dashboard in a fresh browser tab shows the Brace favicon

**Priority:** 1
**Files:**
- `dashboard/src/app/layout.tsx` (modify)

---

### US-005: Sidebar header uses the Brace SVG, not a CSS letter

**Description:** As a brand-conscious operator, I want the sidebar mark to render the actual Brace SVG so that the dashboard does not violate the brief's "Don't regenerate or trace" rule with its current hardcoded `<div>S</div>`.

**Acceptance Criteria:**
- [ ] `dashboard/src/components/Sidebar.tsx` lines 188-200 (the brand block) replace the `<div>S</div>` letter with `<img src="/brand/brace/sigil-brace.svg" alt="Sigil" width="36" height="36" />`
- [ ] The "Sigil" wordmark text next to it uses JetBrains Mono Bold (Tailwind `font-mono font-bold`) per brief §03
- [ ] The "SECURITY" eyebrow stays in the existing mono uppercase style
- [ ] Verify: `grep -A2 "Brand" dashboard/src/components/Sidebar.tsx` shows `<img src="/brand/brace/sigil-brace.svg"` and no `>S<` letter mark
- [ ] Visual: sidebar at 1440×900 renders the Brace mark + "SIGIL" wordmark; mark does not appear pixelated or stretched

**Priority:** 1
**Files:**
- `dashboard/src/components/Sidebar.tsx` (modify)

---

### US-006: SealVerdict component exists and is reusable

**Description:** As a frontend developer rendering scan-level attestation, I want a single `SealVerdict` component that resolves the correct Seal SVG variant and pairs it with a text label so that scan-detail pages, future package pages, and badge surfaces can all consume the same primitive.

**Acceptance Criteria:**
- [ ] `dashboard/src/components/SealVerdict.tsx` exists
- [ ] Props: `verdict: "clean" | "quarantine" | "risk"`, `size?: "sm" | "md" | "lg"`, `phasesPassed?: number`
- [ ] Renders `<img src="/brand/seal/sigil-seal-{clean|quarantine|risk}.svg" />` matching the verdict prop
- [ ] At `size="sm"` (≤24px) renders `sigil-seal-small.svg` regardless of verdict (per brief: dots and inner ring removed for legibility)
- [ ] Always renders a paired text label (`CLEAN` / `QUARANTINE` / `HIGH RISK`) — never colour alone (brief §06 hard rule)
- [ ] Label colour uses the matching verdict CSS token (`--sigil-clean | --sigil-warn | --sigil-risk`)
- [ ] Optional `phasesPassed` prop renders `{n}/8 phases` muted-grey suffix
- [ ] Verify: unit test in `dashboard/src/__tests__/SealVerdict.test.tsx` covers all three verdicts + small-variant switch + label-pairing assertion

**Priority:** 2
**Files:**
- `dashboard/src/components/SealVerdict.tsx` (new)
- `dashboard/src/__tests__/SealVerdict.test.tsx` (new)

---

### US-007: SealVerdict is mounted on the scan-detail page

**Description:** As a user reviewing a scan result, I want the Seal mark visible at the top of the scan detail so that the attestation artefact has a real product home and the Seal SVGs are not orphaned design assets.

**Acceptance Criteria:**
- [ ] Scan-detail page (under `dashboard/src/app/scans/`) renders a `<SealVerdict>` in its header region
- [ ] Verdict mapping rule documented in the page: scan with `severity=LOW_RISK` and zero CRITICAL/HIGH findings → `clean`; scan with at least one CRITICAL finding → `risk`; everything else → `quarantine`
- [ ] `phasesPassed` prop passes the count of phases that completed without findings (max 8)
- [ ] Verify: open `/scans/<id>` for a known clean scan — clean Seal renders with `8/8 phases` suffix
- [ ] Verify: open `/scans/<id>` for a known critical scan — risk Seal renders with the verdict label `HIGH RISK`

**Priority:** 2
**Files:**
- `dashboard/src/app/scans/[id]/page.tsx` (or whichever scan detail page is canonical — confirm during build) (modify)

---

### US-008: Brand asset directory is tracked in git

**Description:** As a teammate cloning the repo, I want the brand SVGs and the brand brief HTML to be in the repo so that the build does not depend on assets sitting on one machine.

**Acceptance Criteria:**
- [ ] `git ls-files dashboard/public/brand/` returns the 20 SVGs + the brand brief HTML (21 files total)
- [ ] `dashboard/public/brand/.DS_Store` is NOT tracked (verify gitignore covers it — already confirmed at PRD authoring time)
- [ ] No binary `.docx`/`.pdf`/`.pptx` files smuggled in (per CLAUDE.md docs rule)

**Priority:** 1
**Files:**
- `dashboard/public/brand/**/*.svg` (new — staged)
- `dashboard/public/brand/Sigil Brand Brief.html` (new — staged)

---

### US-009: No regression in existing 4-tier severity badge

**Description:** As a security analyst reading scan findings, I want the per-finding severity badges (LOW / MEDIUM / HIGH / CRITICAL) to keep working with brief-aligned colours so that the rollout doesn't silently change semantics.

**Acceptance Criteria:**
- [ ] `dashboard/src/components/VerdictBadge.tsx` still exports the 4-tier component
- [ ] LOW_RISK badge colour now sources `--sigil-clean` / `var(--color-success)` (`#22C55E` post-rollout)
- [ ] CRITICAL_RISK badge colour now sources `--color-danger` (`#EF4444` post-rollout)
- [ ] MEDIUM_RISK and HIGH_RISK colours remain in the orange/yellow band — no brief value to map to, but updated to brief's `--sigil-warn` (`#EAB308`) for MEDIUM and a darker amber for HIGH so the 4-tier remains visually distinguishable
- [ ] Verify: snapshot or visual test shows all four badges render with distinct colours and clear labels

**Priority:** 3
**Files:**
- `dashboard/src/components/VerdictBadge.tsx` (modify)

---

### US-010: Build, typecheck, and lint pass after rollout

**Description:** As the deploy operator, I want CI to be green after the rollout so that the brand changes can ship without blocking unrelated work.

**Acceptance Criteria:**
- [ ] `cd dashboard && npm run build` succeeds with exit code 0
- [ ] `cd dashboard && npx tsc --noEmit` reports no new errors introduced by the rollout
- [ ] `cd dashboard && npm run lint` (if configured) reports no new errors introduced by the rollout
- [ ] Existing test suite (`npm test`) passes — no regressions from the colour token swap or component changes
- [ ] Manual smoke: `/`, `/scans`, `/threats`, `/pricing` all render without console errors after the rollout

**Priority:** 1 (gates US-001 through US-009 closing)
**Files:**
- N/A (verification only)

---

## Out of scope (explicit)

- CLI verdict-word semantic refactor (`LOW_RISK → CLEAN` etc. would change exit codes — separate ADR, not this rollout)
- Marketing site (`sigilsec.ai`) — separate repo
- Email templates, README badge generator endpoint, partner badges
- Cutover of every existing component to consume `--sigil-*` tokens directly (incremental; values are aligned at the source so legacy `--color-*` tokens render brief-correct values transparently)
- Light-mode theming (brief is black-mode-first)
- Replacement of the 4-tier per-finding severity taxonomy with the 3-state Seal verdict — they represent different things and both stay

---

## Dependencies

- Brand brief HTML at `dashboard/public/brand/Sigil Brand Brief.html` (v1.0) is the canonical source — any conflict between this PRD and the brief is resolved in favour of the brief
- 20 brand SVGs in `dashboard/public/brand/` already exist on disk; US-008 commits them
- No blocking external dependencies — this is a pure dashboard rollout

---

## Open decisions (resolved at PRD approval)

- **Sidebar mark:** Brace SVG only (not the horizontal lockup) — confirmed 2026-05-04
- **Brand asset commit:** part of this PRD (US-008) — confirmed 2026-05-04
- **CLI rebrand:** out of scope — confirmed 2026-05-04
- **4-tier severity taxonomy:** preserved — confirmed 2026-05-04 in first-principles plan §3
