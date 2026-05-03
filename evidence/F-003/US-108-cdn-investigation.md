# US-108 Evidence: CDN Cache Investigation — `age: ~21 days` on www.sigilsec.ai/pricing

**Feature:** F-003 Pro Billing + Tier Gating Verification
**Story:** STORY-108
**Status:** DONE (investigation only — fix is STORY-112)
**Captured:** 2026-05-03 (autopilot session)
**Verifier:** Claude Code (Opus 4.7) — autonomous, no operator action required

---

## Reproducibility — Probe 1: Pricing page headers

```
$ curl -sS -I https://www.sigilsec.ai/pricing
```

```
HTTP/2 200
accept-ranges: bytes
access-control-allow-origin: *
age: 1881183
cache-control: public, max-age=0, must-revalidate
content-disposition: inline
content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://va.vercel-scripts.com https://vercel.live https://www.googletagmanager.com https://app.posthog.com https://us.i.posthog.com https://us-assets.i.posthog.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://*.cakewalk.ai https://cw-ai-prod.s3.us-west-1.amazonaws.com https://www.google-analytics.com https://*.googletagmanager.com; connect-src 'self' https://vitals.vercel-insights.com https://vercel.live https://api.cakewalk.ai https://www.google-analytics.com https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com https://app.posthog.com https://us.i.posthog.com https://us-assets.i.posthog.com; frame-src https://vercel.live https://www.youtube.com https://www.youtube-nocookie.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; report-uri /api/csp-report
content-type: text/html; charset=utf-8
date: Sun, 03 May 2026 08:01:09 GMT
etag: "8f3abbb21c8553968d617ec9161b49ce"
permissions-policy: camera=(), microphone=(), geolocation=(), interest-cohort=()
referrer-policy: strict-origin-when-cross-origin
server: Vercel
strict-transport-security: max-age=63072000; includeSubDomains; preload
vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch
x-content-type-options: nosniff
x-frame-options: DENY
x-matched-path: /pricing
x-nextjs-prerender: 1
x-nextjs-stale-time: 300
x-vercel-cache: HIT
x-vercel-id: syd1::575pc-1777795269082-ddaf3aa45df4
content-length: 73155
```

`age: 1881183` seconds = **21.77 days**.
`x-vercel-cache: HIT` (Vercel edge serving cached response).
`etag: "8f3abbb21c8553968d617ec9161b49ce"`.
Edge: `syd1` (Sydney).

## Reproducibility — Probe 2: Cache-buster query

```
$ curl -sS -I "https://www.sigilsec.ai/pricing?cb=$(date +%s)"
```

```
age: 1881221
cache-control: public, max-age=0, must-revalidate
etag: "8f3abbb21c8553968d617ec9161b49ce"
x-nextjs-prerender: 1
x-nextjs-stale-time: 300
x-vercel-cache: HIT
x-vercel-id: syd1::849cj-1777795308084-33b74b5e816f
```

Vercel **ignored the cache-buster query string** — same ETag, same HIT, same age (38 seconds older = real-time elapsed). Confirms Vercel ISR is keying on path only, not query string.

## Reproducibility — Probe 3: Root path

```
$ curl -sS -I https://www.sigilsec.ai/
```

```
age: 0
cache-control: private, no-cache, no-store, max-age=0, must-revalidate
x-vercel-cache: MISS
x-vercel-id: syd1::iad1::hmvz4-1777795308214-009154c0392e
```

Root `/` is **not** stale (age 0, MISS, no-cache). The staleness is **page-specific** to `/pricing`, not site-wide.

## Reproducibility — Probe 4: Content sanity check

```
$ curl -sS https://www.sigilsec.ai/pricing | grep -oE '<title>[^<]+</title>' | head -1
```

```
<title>Pricing — Sigil | Sigil</title>
```

The HTML body **is** the Sigil pricing page (not a foreign deployment). Build asset URLs use deployment ID `dpl_CeWkbnTSfbFuPMpSyY1UsYFZDF4Z` (e.g. `/_next/static/chunks/b2876a4e028da53a.js?dpl=dpl_CeWkbnTSfbFuPMpSyY1UsYFZDF4Z`). This is the deployment artefact that has been frozen at the edge for 21 days.

## Findings

### F1 — Vercel ISR background regeneration appears to have stalled or never fired

Headers show:
- `x-nextjs-prerender: 1` — page is a Next.js incremental static regeneration (ISR) prerender.
- `x-nextjs-stale-time: 300` — stale-while-revalidate window of 300 seconds (5 min).
- `cache-control: public, max-age=0, must-revalidate` — public CDN cache, no client-side max-age, must revalidate.
- `x-vercel-cache: HIT` — Vercel edge is serving the prerendered build artefact, not regenerating.

The `x-nextjs-stale-time: 300` says: serve stale up to 5 minutes after generation, then revalidate. Twenty-one days = 6,048 stale-time windows. Either:
- (a) Vercel never received a request fresh enough to trigger background regeneration (unlikely — even one request after the 5-min window should kick off regen).
- (b) Background regeneration is firing but the regen call is failing silently and Vercel keeps serving the cached version (per Next.js ISR fallback behaviour).
- (c) The pricing page is statically exported (not ISR) and `x-nextjs-stale-time` is a non-binding header — true revalidation only happens on rebuild/redeploy.

**Most likely:** (c) — the pricing page is `revalidate: 0` (or no `revalidate` exported), making it fully static. The headers `x-nextjs-prerender: 1` + `x-nextjs-stale-time: 300` are emitted by default but the actual `revalidate` setting on the page route may be missing, so Vercel never re-renders until a new deployment lands.

**Confirmed via source-file inspection:**

```
$ grep -nE 'export const (revalidate|dynamic|fetchCache|runtime)' dashboard/src/app/pricing/page.tsx
(no matches)

$ head -1 dashboard/src/app/pricing/page.tsx
"use client";
```

The pricing page is a `"use client"` component with no `export const revalidate`, no `export const dynamic`. Next.js still server-renders the initial HTML shell at build time and Vercel caches that artefact. There is **no ISR background-regeneration configured**, so the only way to refresh the edge is a redeploy. The 5-min `x-nextjs-stale-time: 300` header is emitted as a Next.js default but is non-binding without `revalidate`. **High-confidence root cause confirmed.**

### F2 — Side finding: CSP includes foreign domains (cakewalk.ai)

The Content-Security-Policy header includes:
- `img-src ... https://*.cakewalk.ai https://cw-ai-prod.s3.us-west-1.amazonaws.com`
- `connect-src ... https://api.cakewalk.ai`

These are **not** Sigil domains. Likely cause: the dashboard project was forked from a Cakewalk template (or the CSP env var was inherited from another Vercel project linked to the same domain), and the CSP was never scrubbed. Not a CDN issue — but a **separate config-hygiene defect**. Recommend filing a follow-up to scrub `cakewalk.ai` and `cw-ai-prod.s3.us-west-1.amazonaws.com` from CSP and any inherited Vercel project settings. Out of scope for STORY-108; in scope for a "production launch hygiene" sweep.

### F3 — `vary` header lists Next.js-specific tokens, not user-agent or accept-encoding

```
vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch
```

Confirms this is a Next.js App Router prerender. RSC payload is part of cache key. No user-agent variance, so curl/browser get the same cache.

## Named Root Cause

**Most-likely cause (high confidence):** The `/pricing` route in `dashboard/src/app/pricing/page.tsx` is statically prerendered at build time (no `export const revalidate = N` or default of 0/static), so Vercel only updates the edge artefact when a **new deployment lands**. The last deployment for the live site appears to have been ~21 days ago (matching the `age` header). The `x-nextjs-stale-time: 300` header is emitted by Next.js but is **non-binding** for fully static routes.

**Secondary contributor (medium confidence):** Even if the pricing page IS ISR-enabled with `revalidate: 300`, the background regen may be failing silently — Next.js falls back to serving the previous artefact and does not surface the failure on the response. This would also produce the observed signature.

**Ruled out:**
- DNS/CDN routing wrong project (probe 4 shows correct Sigil HTML).
- User-agent or query-string keying (probe 2 shows Vercel ignores query; no UA-keyed vary header).
- Site-wide cache freeze (probe 3 shows `/` is fresh).

## Recommended Fix (sized for STORY-112)

**Tier-1 (cheapest, highest information):**
Trigger a new Vercel deployment for the dashboard project. If the pricing route is fully static, a redeploy is the only way to refresh the artefact. Post-deploy, re-probe `age` — should drop to <60s for the first hit, then increase monotonically.

```
# Operator action (Vercel CLI or Dashboard):
vercel --prod --cwd /Users/reecefrazier/CascadeProjects/sigil/dashboard
# or push a no-op commit to the dashboard's main branch
```

**Tier-2 (only if Tier-1 doesn't fix it):**
Add `export const revalidate = 300;` (or appropriate window) to `dashboard/src/app/pricing/page.tsx` so Vercel ISR background-regenerates the page every 5 minutes. Redeploy. Sized at ~5 min.

**Tier-3 (only if Tier-2 doesn't fix it):**
Investigate Vercel ISR background regen failures via Vercel project logs. Likely indicates a server-side error during regen (env-var missing at build, runtime exception during data fetch). Sized at 30 min — open-ended.

## Verdict

PASS — investigation criteria met:
- [x] Full curl headers captured (probe 1).
- [x] Cache-buster query probe captured (probe 2).
- [x] Root-path probe captured (probe 3) — confirms staleness is page-specific.
- [x] Content fetched to verify HTML is correct project (probe 4).
- [x] Named root cause: static prerender + no redeploy in 21 days (high confidence).
- [x] Recommended fix sized: Tier-1 redeploy first; Tier-2 add `revalidate`; Tier-3 dig into ISR logs.

**Open for STORY-112:** Operator runs Tier-1 (redeploy), then re-probes `age` — should see drop to <3600s.

## Side Finding: STORY-107 Free-Trial Copy De-Risked

While checking the deployed pricing HTML for the trial CTA referenced in PRD US-005 / STORY-107:

```
$ curl -sS https://www.sigilsec.ai/pricing | grep -ioE 'free trial|trial|trialing' | sort | uniq -c
   2 Free Trial
   1 free trial
  10 trial
```

**Deployed HTML contains "Free Trial" copy.** But the **current source** does NOT:

```
$ grep -nE 'free trial|trial' dashboard/src/app/pricing/page.tsx
43:  const isActive = subscription?.status === "active" || subscription?.status === "trialing";
```

Source has only one match — `subscription?.status === "trialing"` — which is internal state-checking code, not user-facing CTA copy. **No "free trial" string exists in the page source.**

**Implication for STORY-107 (CORRECTED 2026-05-03 post-redeploy):** The free-trial copy is not in `dashboard/src/app/pricing/page.tsx` and (verified later via aggressive grep) is not anywhere in the local `dashboard/` source tree. Initial reading: STORY-107 Branch A (REMOVE) was already taken in source.

**Revision after STORY-112 redeploy revealed more nuance:** The redeploy used `vercel redeploy <prior-url>` which **rebuilds the previous deployment's frozen source** (23 days old) — not current main. The deployed HTML still shows "30-day free trial" because the build is from the 23-day-old git ref, in which the copy DID exist somewhere (since refactored away). To verify the current-source state on production, a fresh build from current `main` HEAD is required (`git push origin main` per operator's standard flow, or `vercel deploy --prod --yes` from `dashboard/`). See `evidence/F-003/US-112-cdn-fix-verification.md` §"Critical Finding: Content Currency" for the full picture.

**Net for STORY-107:** Source-level removal is verified (free-trial copy not in current main `dashboard/` source). Production state cannot be confirmed until a current-source deploy lands. The owner ADR (Branch A) is still required, ideally after a fresh deploy proves the production HTML matches.

## Limitations / Out of Scope

- Did NOT do a second-region probe via different geographic edge (would require running curl from non-au IP). Sydney edge cache state may not match other regions, but `x-vercel-id: syd1::` is consistent across probes 1–3 from the autopilot session — adequate for primary diagnosis.
- Did NOT inspect Vercel project settings or build logs (no Vercel CLI access from autopilot session). Operator should confirm in Vercel Dashboard during STORY-112.
- Did NOT inspect `dashboard/src/app/pricing/page.tsx` for `revalidate` export. Recommend operator check this as part of fix verification.
