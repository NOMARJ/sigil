# US-006 — Next.js Upgrade Assessment (HIGH-001)

**Story:** F-007 / US-006 · **Linear:** NOM-1074 · **Executor:** agent (buildable, assessment only)
**Date:** 2026-06-08

> **Data Source:** Real `npm audit` run + real source survey of `dashboard/` (not production runtime)
> **Sample Size:** Full `dashboard/` tree; audit over production deps (`--omit=dev`)
> **Limitations:** This is an ASSESSMENT only. `npm audit fix --force` was **not** run (operator-gated
> execution → US-007). Breaking-change items tagged [code] (confirmed from this repo) vs [guide]
> (from the official Next.js upgrade guides, to be confirmed during execution).

## 1. Audit output (verbatim, `cd dashboard && npm audit --audit-level=high --omit=dev`)

```
# npm audit report

next  9.3.4-canary.0 - 16.3.0-canary.5
Severity: high
  GHSA-9g9p-9gw9-jx7f  DoS via Image Optimizer remotePatterns
  GHSA-h25m-26qc-wcjf  HTTP request deserialization DoS (insecure RSC)
  GHSA-ggv3-7p47-pfv8  HTTP request smuggling in rewrites
  GHSA-3x4c-7xq6-9pq8  Unbounded next/image disk cache growth
  GHSA-q4gf-8mx6-v5v3  DoS with Server Components
  GHSA-8h8q-6873-q5fj  DoS with Server Components
  GHSA-3g8h-86w9-wvmq  Middleware/Proxy redirect cache poisoning
  GHSA-ffhc-5mcf-pf4q  XSS in App Router with CSP nonces
  GHSA-vfv6-92ff-j949  Cache poisoning via RSC cache-busting collisions
  GHSA-gx5p-jg67-6x7h  XSS in beforeInteractive scripts
  GHSA-h64f-5h5j-jqjh  DoS in Image Optimization API
  GHSA-c4j6-fc7j-m34r  SSRF via WebSocket upgrades
  GHSA-wfc6-r584-vfw7  Cache poisoning in RSC responses
  GHSA-36qx-fr4f-26g5  Middleware/Proxy bypass (Pages Router i18n)
  Depends on vulnerable versions of postcss
  fix available via `npm audit fix --force`
  Will install next@16.2.7, which is a breaking change

postcss  <8.5.10  (moderate)  GHSA-qx2v-qp2m-jg93  XSS via unescaped </style>
  fix available via `npm audit fix --force` — Will install next@16.2.7

2 vulnerabilities (1 moderate, 1 high)
```

**Current versions** [code]: `next ^14.2.35` (installed 14.2.35), `react ^18.3.1`,
`react-dom ^18.3.1`, `eslint-config-next ^14.2.5`, `eslint ^8.57.1`, `@types/react ^18.3.3`.
**Target** (npm-recommended, matches PRD): **`next@16.2.7`** — a 14→16 major migration. postcss is
transitive under next and resolves with the bump.

## 2. Blast-radius mapping (Next 14 → 16 against actual dashboard usage)

| Breaking change | Source | Dashboard impact |
|-----------------|--------|------------------|
| **React 19 required** (Next 15+) | [guide] | `react`/`react-dom` 18.3.1 → 19.x and `@types/react` 18→19 must bump together. Highest-risk item — affects every component. RTL is already React-19-ready (see testing below). |
| **Async request APIs** — `cookies()`, `headers()`, `params`, `searchParams` become async | [guide] | **6 files** use this surface and must `await` them: `src/app/settings/page.tsx`, `src/app/scans/page.tsx`, `src/app/threats/page.tsx`, `src/app/scans/[id]/page.tsx`, `src/app/onboarding/pro/page.tsx`, `src/lib/api.ts`. The `@next/codemod` `next-async-request-api` handles most. [code] |
| **Caching defaults** — `fetch`/GET route handlers no longer cached by default | [guide] | `src/app/api/auth/[auth0]/route.ts`, `src/lib/api.ts`, `src/lib/auth.ts` use revalidate/cache options — review for behavior change. [code] |
| **Image Optimizer / remotePatterns** advisories | [code] | `next/image` is used in **0** source files and no `remotePatterns`/`images` block in `next.config.*` → low functional impact; patch still applies. |
| **Middleware redirect cache poisoning / Pages-Router i18n bypass** | [code] | No `middleware.ts`/`src/middleware.ts` present; advisory surface minimal. One Pages-Router page exists (`pages/security-timeline.tsx`) — confirm no i18n config relies on the patched path. |
| **CSP-nonce / beforeInteractive XSS** | [code] | No `nonce` usage in `src` → low impact; patch still applies. |
| **eslint-config-next major + ESLint 9 flat config** | [guide] | `eslint-config-next ^14.2.5` → `^16.2.7`; `next lint` is deprecated in 16 (migrate to ESLint CLI / `@next/eslint-plugin-next`). May require `eslint` 8→9. |
| **Node >= 18.18 / 20+** | [code] | Local Node is v24.7.0 — satisfies. Confirm CI/Container image Node ≥ 20. |

## 3. Testing surface (informs US-007 `npm test`)

[code] `@testing-library/react ^16.3.2` (React-19 compatible), `@testing-library/jest-dom ^6.9.1`,
`jest ^30.2.0`, `jest-environment-jsdom ^30.2.0`, `typescript ^5.5.3`. RTL 16 already supports
React 19, so the Jest suite is the lower-risk part of this upgrade. `@types/react` must move to 19
to avoid type errors under `tsc`/build. Scripts available: `build`, `test` (jest), `test:ci`, `lint`.

## 4. Recommended execution plan (for US-007 operator)

1. Branch from current `main`/feature head.
2. Run the official codemod: `cd dashboard && npx @next/codemod@latest upgrade latest`
   (handles next/react/eslint-config-next bumps + `next-async-request-api` + caching codemods).
   If it under-resolves, pin explicitly: `npm i next@16.2.7 react@19 react-dom@19` and
   `npm i -D eslint-config-next@16.2.7 @types/react@19 @types/react-dom@19`.
3. Manually review the 6 async-API files (§2) and the 3 caching files for behavior changes.
4. Confirm the Pages-Router page `pages/security-timeline.tsx` still builds.
5. Verify (commands below). Document any deviation from this assessment.

## 5. Verification commands (operator must see all pass)

```
cd dashboard
npm audit --audit-level=high --omit=dev      # AC: exit 0
npm test -- --runInBand                       # or: npm run test:ci  (jest, React 19)
npm run build                                 # next build compiles
npx tsc --noEmit                              # types clean under @types/react 19
```

## 6. Rollback plan

- The upgrade is isolated to `dashboard/package.json` + `dashboard/package-lock.json` (+ codemod
  edits to the 6 async-API files). Rollback = `git checkout -- dashboard/package.json
  dashboard/package-lock.json && git restore dashboard/src` (or revert the US-007 commit) then
  `npm ci` to restore the 14.2.35 lockfile state.
- No infra/runtime change is implied by the assessment; production deploy of the upgraded build is
  a separate operator step (Vercel) gated behind passing §5.
- Residual risk if rolled back: the 14 high + 1 moderate advisories remain open (DoS/cache-poisoning
  /XSS/SSRF on a self-hosted/Vercel Next 14.2.35). HIGH-001 stays open until US-007 lands.

## AC verification

- [x] Captures `npm audit --audit-level=high --omit=dev` output and advisory IDs (§1)
- [x] Breaking-change surface enumerated and mapped to dashboard usage (§2, [code] vs [guide])
- [x] Rollback plan and verification commands listed for the operator (§5, §6)
- [x] Does **not** run `npm audit fix --force` (operator-gated → US-007)
