# PRD: Brand v1.0 Rollout

**Feature:** F-006
**Epic:** EP-004 — Brand & Identity System
**Status:** approved (revised)
**Created:** 2026-05-04
**Approved:** 2026-05-04
**Revised:** 2026-05-04 — directive expanded the verdict family from 3-tier to 5-tier, added a strict liability stance, and broadened scope to all surfaces in this repo (CLI, API email, docs, brief HTML).
**Source directive:** owner message 2026-05-04 ("SIGIL BRAND v1.0 — APPLY TO THIS SURFACE")
**Reference brief (subordinate):** `dashboard/public/brand/Sigil Brand Brief.html` v1.0 — directive overrides §06 demo copy
**First-principles plan:** `docs/plans/2026-05-04-brand-rollout-first-principles.md`

---

## Introduction

Brand v1.0 was re-locked on 2026-05-04. The owner issued a directive expanding the verdict family from 3-tier (clean / quarantine / risk) to **5-tier** (clean / low / medium / high / critical) and introducing a **strict liability stance** that forbids "Safe to install", "Verified safe", "Sigil guarantees", and "Malware-free" wording anywhere in product, docs, or marketing. The directive also enumerates explicit blue→green hex replacements (`#3B82F6 → #3FB950`, `#2563EB → #56D364`, `#1D4ED8 → #196C2E`).

This PRD rolls Brand v1.0 across every surface in this repo: dashboard (Next.js), CLI (`bin/sigil`), API email templates, public docs, and the brand brief HTML itself. The 4-tier per-finding severity taxonomy (`LOW_RISK / MEDIUM_RISK / HIGH_RISK / CRITICAL_RISK`) collapses cleanly into the new 5-tier scale by adding `CLEAN` for score 0 — they are now the same taxonomy, not separate domains.

Four Seal SVG variants required by the new verdict family (`sigil-seal-low.svg`, `sigil-seal-medium.svg`, `sigil-seal-high.svg`, `sigil-seal-critical.svg`) do not yet exist on disk. Stories that depend on them (US-006, US-007) are blocked until those assets are produced. All other stories are unblocked.

---

## Goals

- Tokens, fonts, marks, and favicon flow from the directive — brief is enforceable in code
- Brace SVG renders on every chrome surface (sidebar, favicon)
- 5-tier verdict family rendered consistently in dashboard and CLI; per-finding severity uses the same taxonomy
- Strict liability copy enforced — every "Safe to install"-style phrase replaced with attestation-only wording
- Every blue accent in active code paths replaced with brand greens
- CLI banner and ANSI output align with the directive §6 (status glyphs paired with verdict words)
- API email templates use brand greens
- Brand brief HTML self-corrects: §06 demo copy and §09 file index updated to match the directive

---

## Non-goals

- Updating NOMARK org surfaces — separate scope, owned elsewhere
- Producing the four missing Seal SVG variants — that's a design task, not engineering
- Light-mode theming — brief is black-mode-first
- Changing CLI exit-code semantics — verdict words shift visually but exit codes stay (`SEVERITY_*` constants in `bin/sigil` remain)
- Refactoring every dashboard component to consume `--sigil-*` tokens directly — values are aligned at the source so legacy `--color-*` tokens render brief-correct values transparently
- Touching `archive/`, `packs/` template placeholders, or `docs/internal/flowbite-ui-files/` — those are illustrative or third-party

---

## User Stories

### US-001: Surface palette, brand greens, and 5-tier verdict tokens match the directive

**Description:** As a designer cross-checking the live dashboard against the brand directive, I want every surface tone, brand-green value, and verdict colour in `globals.css` to match the directive's hex codes exactly.

**Acceptance Criteria:**
- [ ] `dashboard/src/app/globals.css` surface tokens: `--color-bg-primary:#0A0A0A`, `--color-bg-secondary:#161616`, `--color-bg-tertiary:#1C1C1C`, `--color-border:#262626`
- [ ] Accent: `--color-accent:#3FB950` (was `#10b981`), `--color-accent-hover:#56D364`, `--color-accent-muted:#238636`, `--color-accent-dark:#196C2E`
- [ ] 5-tier verdict tokens added: `--color-clean:#22C55E`, `--color-low:#EAB308`, `--color-medium:#F97316`, `--color-high:#EF4444`, `--color-critical:#DC2626`
- [ ] Legacy `--color-success:#22C55E`, `--color-warning:#EAB308`, `--color-danger:#EF4444` kept as aliases for backward compatibility
- [ ] `--sigil-*` token aliases added per directive §2 (sigil-black, sigil-surface, sigil-elevated, sigil-border, sigil-gray, sigil-light, sigil-offwhite, sigil-white, sigil-green-deep, sigil-green-mid, sigil-green, sigil-green-soft, sigil-clean, sigil-low, sigil-medium, sigil-high, sigil-critical, sigil-mono, sigil-sans)
- [ ] No `#3b82f6`, `#2563eb`, `#1d4ed8`, or `rgba(59, 130, 246, *)` remains in `globals.css` (verifiable via grep)
- [ ] Verify: `grep -ic "#3b82f6\|#2563eb\|#1d4ed8\|rgba(59, ?130, ?246" dashboard/src/app/globals.css` returns `0`

**Priority:** 1
**Files:** `dashboard/src/app/globals.css`

---

### US-002: Tailwind palette aligns to the directive

**Acceptance Criteria:**
- [ ] `dashboard/tailwind.config.ts` `colors.brand.500 = "#3FB950"` (was `#10b981`); the 50-950 ramp regenerated around `#3FB950`
- [ ] `colors.brand.deep`, `.mid`, `.soft` exposed as named keys for `#196C2E`, `#238636`, `#56D364`
- [ ] New `colors.surface` palette: `black:#0A0A0A, surface:#161616, elevated:#1C1C1C, border:#262626, muted:#404040, gray:#787878, light:#A3A3A3, offwhite:#E5E5E5, white:#FAFAFA`
- [ ] New `colors.verdict` palette: `clean:#22C55E, low:#EAB308, medium:#F97316, high:#EF4444, critical:#DC2626`
- [ ] `colors.info.500` no longer `#3b82f6` — either removed or remapped to a non-brand neutral (e.g., gray) since blue is no longer in the system
- [ ] `theme.extend.fontFamily.mono` lists `'JetBrains Mono'` first
- [ ] Verify: `cd dashboard && npm run build` succeeds; `grep -E '#3[bB]82[fF]6|#2563[eE][bB]|#1[dD]4[eE][dD]8' dashboard/tailwind.config.ts` returns nothing

**Priority:** 1
**Files:** `dashboard/tailwind.config.ts`

---

### US-003: JetBrains Mono is loaded alongside Inter

**Acceptance Criteria:**
- [ ] `dashboard/src/app/layout.tsx` `<head>` requests both `Inter:wght@400;500;600;700;800` and `JetBrains+Mono:wght@400;500;700` from Google Fonts
- [ ] Verify: any element styled `font-mono` renders in JetBrains Mono on `/scans` (visual check)

**Priority:** 1
**Files:** `dashboard/src/app/layout.tsx`

---

### US-004: Favicon points to the brand SVG

**Acceptance Criteria:**
- [ ] `dashboard/src/app/layout.tsx` `metadata.icons.icon` is `/brand/favicon/favicon.svg`
- [ ] `viewport.themeColor` is `#0A0A0A` (was `#111827`)
- [ ] Verify: `curl -sI http://localhost:3000/brand/favicon/favicon.svg` returns `200 OK`

**Priority:** 1
**Files:** `dashboard/src/app/layout.tsx`

---

### US-005: Sidebar header renders the Brace SVG

**Acceptance Criteria:**
- [ ] `dashboard/src/components/Sidebar.tsx` brand block (around lines 188-200) replaces the `<div>S</div>` letter with `<img src="/brand/brace/sigil-brace.svg" alt="Sigil" width="36" height="36" />`
- [ ] "Sigil" wordmark uses Tailwind `font-mono font-bold` per directive §1 (lockup wordmark = JetBrains Mono Bold)
- [ ] Verify: `grep -A5 "/\* Brand \*/" dashboard/src/components/Sidebar.tsx` shows the `<img src="/brand/brace/sigil-brace.svg"` line and no `>S<` letter mark

**Priority:** 1
**Files:** `dashboard/src/components/Sidebar.tsx`

---

### US-006: SealVerdict component (5-tier) — **BLOCKED**

**Description:** Component to render scan-level attestation Seal + verdict label. Blocked until four missing Seal SVGs are produced.

**Blocker:** `dashboard/public/brand/seal/sigil-seal-low.svg`, `sigil-seal-medium.svg`, `sigil-seal-high.svg`, `sigil-seal-critical.svg` do not exist. Owner action required to produce or commission.

**Acceptance Criteria (when unblocked):**
- [ ] `dashboard/src/components/SealVerdict.tsx` exists
- [ ] Props: `verdict: "clean" | "low" | "medium" | "high" | "critical"`, `size?: "sm" | "md" | "lg"`, `phasesPassed?: number`, `score?: number`
- [ ] Renders `<img src="/brand/seal/sigil-seal-{verdict}.svg" />`; at `size="sm"` (≤24px) renders `sigil-seal-small.svg` regardless of verdict
- [ ] Always pairs with text label (`CLEAN` / `LOW RISK` / `MEDIUM RISK` / `HIGH RISK` / `CRITICAL`) — never colour alone
- [ ] Label colour uses matching `--color-{clean,low,medium,high,critical}` token
- [ ] Optional `phasesPassed` renders `{n}/8 phases` muted suffix; when verdict is `clean`, label reads "8/8 phases passed" (per directive §4 strict-liability rule — never "Safe to install")
- [ ] Unit test in `dashboard/src/__tests__/SealVerdict.test.tsx` covers all 5 verdicts + small-variant + label-pairing + the strict-liability label assertion

**Priority:** 2 (blocked)
**Files:** `dashboard/src/components/SealVerdict.tsx` (new), `dashboard/src/__tests__/SealVerdict.test.tsx` (new)

---

### US-007: Mount SealVerdict on scan-detail page — **BLOCKED**

**Blocker:** depends on US-006.

**Acceptance Criteria (when unblocked):**
- [ ] Scan-detail page renders `<SealVerdict>` in its header
- [ ] Verdict mapping rule: `score=0 → clean`; `1-9 → low`; `10-24 → medium`; `25-49 → high`; `50+ → critical`
- [ ] `phasesPassed` passes the count of phases that completed without findings (max 8)
- [ ] Verify: a known clean scan renders with "8/8 phases passed" suffix; a known critical scan renders with `CRITICAL` label

**Priority:** 2 (blocked)
**Files:** `dashboard/src/app/scans/[id]/page.tsx` (or canonical scan-detail path)

---

### US-008: Brand asset directory tracked in git ✓ DONE

Closed in commit `4c9a46b` (2026-05-04). 21 files added: 20 SVGs + brand brief HTML.

---

### US-009: VerdictBadge consumes the unified 5-tier scale

**Description:** Per-finding severity already uses `LOW_RISK / MEDIUM_RISK / HIGH_RISK / CRITICAL_RISK`. The directive collapses this into the unified 5-tier verdict family by adding `CLEAN` (score 0) and re-mapping colours.

**Acceptance Criteria:**
- [ ] `dashboard/src/components/VerdictBadge.tsx` colour map updated:
    - `LOW_RISK` → `#EAB308` (was green `bg-green-500/10 text-green-400`)
    - `MEDIUM_RISK` → `#F97316` (was yellow)
    - `HIGH_RISK` → `#EF4444` (was orange)
    - `CRITICAL_RISK` → `#DC2626` (was red)
    - new `CLEAN` (or `NO_FINDINGS`) state → `#22C55E`
- [ ] Existing usages of `VerdictBadge` continue to compile and render (verified via build)
- [ ] No regression — the `_RISK` suffix label-stripping in `verdictLabel()` preserved

**Priority:** 2
**Files:** `dashboard/src/components/VerdictBadge.tsx`

---

### US-010: Build, typecheck, and lint pass

**Acceptance Criteria:**
- [ ] `cd dashboard && npm run build` exit 0
- [ ] `cd dashboard && npx tsc --noEmit` no new errors
- [ ] No regressions in existing test suite

**Priority:** 1 (gates closing)
**Files:** verification only

---

### US-011: Strict-liability copy scrubbed across the repo

**Description:** The directive §4 forbids "Safe to install", "Verified safe", "Sigil guarantees…", "Malware-free". Replace with attestation phrasing: "8/8 phases passed", "No findings detected", "Sigil verified · clean", "Attestation: clean".

**Found at PRD revision time:**
- `plugins/claude-code/README.md:271` — "Safe to install"
- `docs/claude-code-security-integration.md:61` — "✅ Safe to install"
- `docs/ai-security-stack-integration.md:137` — "✅ Safe to install"
- `dashboard/public/brand/Sigil Brand Brief.html:391` — "All 8 phases passed. Safe to install."

**Acceptance Criteria:**
- [ ] All four occurrences replaced with attestation phrasing per directive §4
- [ ] No new occurrences introduced — verify: `grep -rIin -E "safe to install|verified safe|sigil guarantees|malware-free" /Users/reecefrazier/CascadeProjects/sigil --include="*.tsx" --include="*.ts" --include="*.md" --include="*.json" --include="*.py" --include="*.html" --include="*.sh" 2>/dev/null | grep -v node_modules | grep -v archive/ | grep -v docs/internal/flowbite-ui-files/` returns nothing

**Priority:** 1
**Files:** the four files listed above + the brand brief HTML

---

### US-012: Blue accent hexes replaced with brand greens

**Description:** Directive §2 mandates replacing every blue accent with the matching brand green. Replacements: `#3B82F6 → #3FB950`, `#2563EB → #56D364`, `#1D4ED8 → #196C2E`, `rgba(59,130,246,*) → rgba(63,185,80,*)`.

**Found at PRD revision time (active code paths only — excludes archive/, packs/ placeholders, third-party flowbite):**
- `dashboard/tailwind.config.ts:68-69` — info palette `#3b82f6, #2563eb`
- `dashboard/src/app/globals.css:51` — `--color-low: #3b82f6`
- `dashboard/src/app/globals.css:373, 378` — `rgba(59, 130, 246, *)` glow rules
- `dashboard/src/components/docs/ScanPhaseCard.tsx:39` — `rgba(59,130,246,0.1)` glow
- `api/templates/email/base.html:139-140` — `border: 1px solid #3b82f6; color: #1d4ed8`

**Acceptance Criteria:**
- [ ] All 5 active-path occurrences replaced per the directive's mapping
- [ ] Verify: `grep -rIin -E "#3[bB]82[fF]6|#2563[eE][bB]|#1[dD]4[eE][dD]8|rgba\(59, ?130, ?246" dashboard/src/ dashboard/tailwind.config.ts api/templates/ bin/sigil 2>/dev/null` returns nothing
- [ ] Build still passes after the swap

**Priority:** 1
**Files:** the 5 files listed

---

### US-013: CLI (`bin/sigil`) banner and verdict glyphs align with directive §6

**Description:** Directive §6 enumerates ANSI codes per verdict and status glyphs (●/◐/○) that must pair with the verdict word.

**Acceptance Criteria:**
- [ ] `bin/sigil` exports verdict-pretty-print helpers using:
    - `CLEAN` → `\x1b[32m`, glyph `●`
    - `LOW RISK` → `\x1b[33m`, glyph `◐`
    - `MEDIUM RISK` → `\x1b[33m`, glyph `◐`
    - `HIGH RISK` → `\x1b[31m`, glyph `◐`
    - `CRITICAL` → `\x1b[31;1m`, glyph `○`
- [ ] Existing scan output paths use the helpers — verify by running `./bin/sigil scan .` and seeing `●` paired with `CLEAN`
- [ ] Banner in CLI `--help` output keeps the existing "by NOMARK / A protective mark for every line of code" tagline (already brand-aligned)
- [ ] No exit-code semantics changed — `SEVERITY_*` constants stay
- [ ] No "Safe to install" output anywhere in CLI

**Priority:** 2
**Files:** `bin/sigil`

---

### US-014: API email templates use brand greens

**Acceptance Criteria:**
- [ ] `api/templates/email/base.html` lines 139-140 replace `#3b82f6` and `#1d4ed8` with `#3FB950` and `#196C2E`
- [ ] Any other `#3b82f6 / #2563eb / #1d4ed8` occurrences in `api/templates/email/` replaced per directive §2 mapping
- [ ] No "Safe to install"-style copy in any email template — verify via grep

**Priority:** 2
**Files:** `api/templates/email/base.html` (and other email templates if present)

---

### US-015: Brand brief HTML self-corrects to the new directive

**Description:** The brand brief HTML at `dashboard/public/brand/Sigil Brand Brief.html` is itself part of the brand surface. Its §06 demo copy ("Safe to install") and 3-tier verdict family contradict the directive.

**Acceptance Criteria:**
- [ ] §06 verdict family expanded from 3-tier to 5-tier (CLEAN / LOW / MEDIUM / HIGH / CRITICAL) with directive hex codes
- [ ] §06 "Safe to install. All 8 phases passed." replaced with "8/8 phases passed."
- [ ] §09 file index lists the four new Seal SVG paths (`sigil-seal-low.svg`, `-medium.svg`, `-high.svg`, `-critical.svg`) with a "pending design" note where the SVG is not yet on disk
- [ ] §07 demo blocks updated: any "Safe to install" / "Verified safe" copy in the package-page or badge demos replaced with attestation phrasing
- [ ] Header eyebrow updated: "Sigil · Brand brief · v1.0 (revised 2026-05-04)"

**Priority:** 1
**Files:** `dashboard/public/brand/Sigil Brand Brief.html`

---

## Out of scope (explicit)

- NOMARK org surfaces (separate scope)
- CLI verdict-word semantic refactor that changes exit codes (CLI verdict glyphs/colours align, exit codes don't)
- Marketing site (`sigilsec.ai`)
- Generating the four missing Seal SVGs (design task)
- Email templates beyond `base.html` if no other templates use blue accents (verified at PRD time)
- Light-mode theming
- README badge generator endpoints (live elsewhere)

---

## Dependencies

- Owner directive 2026-05-04 is canonical
- Four Seal SVG variants (low / medium / high / critical) gate US-006 and US-007 — no engineering dependency, but design dependency
- Brand asset directory committed in `4c9a46b` (US-008 closed)

---

## Decisions resolved at revision

- **Verdict taxonomy unified:** 4-tier finding severity collapses into 5-tier (adding CLEAN for score 0) — confirmed 2026-05-04
- **Liability stance:** strict; "Safe to install" / "Verified safe" / "Sigil guarantees" / "Malware-free" forbidden everywhere — confirmed 2026-05-04
- **Blue → green:** explicit hex map in directive §2; applied to active code paths only
- **Sidebar mark:** Brace SVG only (not lockup) — confirmed 2026-05-04
- **CLI rebrand:** in scope (visual only — exit codes preserved) — revised 2026-05-04
- **Light-mode:** out of scope
- **NOMARK surfaces:** out of scope (different repo)
