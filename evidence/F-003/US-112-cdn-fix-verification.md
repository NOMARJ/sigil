# US-112 Evidence: CDN Cache Fix Verification

**Feature:** F-003 Pro Billing + Tier Gating Verification
**Story:** STORY-112
**Status:** PARTIAL — TDD anchor met (cache freshness), but content currency exposed a separate issue (see findings)
**Captured:** 2026-05-03 (autopilot session, user-approved unblock)
**Verifier:** Claude Code (Opus 4.7) via Vercel CLI

---

## Pre-fix State (corroborates STORY-108 root cause)

```
$ vercel ls --prod | head -3
Age     Deployment                                       Status      Environment
23d     https://sigilsec-jfkpdhor8-nomark.vercel.app     ● Ready     Production
23d     https://sigilsec-hewpeyhhs-nomark.vercel.app     ● Ready     Production
44d     https://sigilsec-15usaa6tp-nomark.vercel.app     ● Ready     Production
```

Last production deploy was **23 days ago** — directly corroborates the 21.78-day edge cache age observed in STORY-108. (The ~1.5-day gap = time between deploy completion and first cache fill at the Sydney edge.)

```
$ curl -sS -I https://www.sigilsec.ai/pricing | grep -iE '^(age|x-vercel-cache|etag|x-vercel-id)'
age: 1882275
etag: "8f3abbb21c8553968d617ec9161b49ce"
x-vercel-cache: HIT
x-vercel-id: syd1::fmftc-1777796361884-7d746f470954
```

## Remediation Action

```
$ vercel redeploy https://sigilsec-jfkpdhor8-nomark.vercel.app --target production
> Redeploying project dpl_CeWkbnTSfbFuPMpSyY1UsYFZDF4Z
> Production: https://sigilsec-12hpzefd5-nomark.vercel.app [4s]
> Building → Completing
```

New deployment ID: `dpl_FPs7JJR1ijAcnTWHKxVVMgUeGAN1`. Aliases promoted to production:
```
$ vercel inspect https://sigilsec-12hpzefd5-nomark.vercel.app | grep Aliases -A6
  Aliases
    ╶ https://www.sigilsec.ai
    ╶ https://sigilsec.vercel.app
    ╶ https://sigilsec-nomark.vercel.app
    ╶ https://sigilsec-git-main-nomark.vercel.app
    ╶ https://sigilsec.ai
```

## Post-fix Probe — TDD Anchor

```
$ curl -sS -I https://www.sigilsec.ai/pricing | grep -iE '^(age|x-vercel-cache|etag|x-vercel-id|date)'
age: 0
date: Sun, 03 May 2026 08:20:58 GMT
etag: "b08afad47d118f7d6049e26224c7bb6d"
x-vercel-cache: PRERENDER
x-vercel-id: syd1::bcqdt-1777796457649-3325e4459b1b
```

**TDD anchor:** `age < 3600` → **0 < 3600 ✓ PASS**.
ETag changed (`8f3abbb...` → `b08afad...`), confirming a fresh artefact at the edge.
`x-vercel-cache: PRERENDER` (was `HIT` — this is a fresh prerender being served, not a stale cache hit).

## Critical Finding: Content Currency Is NOT Resolved

The cache flush is verified, but probing the deployed HTML reveals a problem:

```
$ curl -sS https://www.sigilsec.ai/pricing | grep -ioE '.{0,30}free trial.{0,30}|.{0,20}30-day.{0,20}' | head -5
text-small text-brand-gray mt-1">30-day free trial • then $29/mo
"30-day trial?","acceptedAnswer
n-colors" href="/trial">Start Free Trial</a>
s" href="/early-access">Start Free Trial</a>
"30-day trial?</dt>
```

The deployed HTML contains "30-day free trial", "Start Free Trial" CTAs, and `/trial` / `/early-access` hrefs. **None of these strings exist in the local `dashboard/` source tree:**

```
$ cd dashboard && grep -rln '30-day' . 2>/dev/null | grep -vE 'node_modules|\.next|\.git|\.vercel'
(no matches)

$ grep -rln 'text-brand-gray' . 2>/dev/null | grep -vE 'node_modules|\.next|\.git|\.vercel'
(no matches)

$ grep -rln 'then \$29' . 2>/dev/null | grep -vE 'node_modules|\.next|\.git|\.vercel'
(no matches)
```

### Root cause of the content mismatch

`vercel redeploy <url> --target production` **rebuilds the previous deployment using its original source ref** (frozen at the time of the original deploy). It does NOT use current `main` HEAD. So:

- The redeploy successfully refreshed the **edge cache** (TDD anchor met).
- But the **build content** is still the 23-day-old artefact, faithfully rebuilt from the 23-day-old git ref.
- "30-day free trial" copy was in the source 23 days ago. It has since been removed/refactored from `dashboard/`. The deployed site still shows the old copy because the rebuild used the old source.

### What's required for true content currency

To actually serve the **current** source state of `dashboard/` at production, a fresh build from current `main` HEAD is required. Two paths:

1. **Standard (operator-confirmed flow):** `git push origin main` — Vercel auto-deploys from `main` on push.
   - Currently 1 unpushed commit on local main: `7f874b6 docs(F-003): autopilot evidence ...` (docs-only, no `dashboard/` changes).
   - Pushing would trigger a Vercel deploy that rebuilds from current main HEAD source — including any `dashboard/` source evolution since the 23-day-old commit.
   - This is the intended deploy mechanism per operator clarification.

2. **CLI alternative:** `vercel deploy --prod --yes` from inside `dashboard/`.
   - Builds and deploys the current local working tree directly.
   - Bypasses GitHub — does not record the deploy against a git commit.

**Both have NOT been executed in this autopilot session — the content currency fix awaits operator decision.**

## STORY-107 Implications (correction to my earlier finding)

In `evidence/F-003/US-108-cdn-investigation.md` §"Side Finding: STORY-107 Free-Trial Copy De-Risked", I claimed: *"the free-trial copy was already removed from source"*. **This claim was based on grep of `dashboard/src/app/pricing/page.tsx` only.** The current state is more nuanced:

- The free-trial copy is NOT in `dashboard/src/app/pricing/page.tsx`.
- The free-trial copy is NOT anywhere in the local `dashboard/` source tree (verified via aggressive grep).
- The deployed HTML contains the copy because the deployment was built from a git ref where the copy DID exist (somewhere in `dashboard/`, since refactored away).
- A current-source build (path 1 or 2 above) would test whether the live copy still has free-trial messaging from current source.

**Net effect on STORY-107:** Source-level removal appears complete (correct claim). But the production state cannot be verified until a current-source deploy lands. STORY-107's ratify-via-ADR path is still the right action, but it should follow a confirmed clean-source deploy — not be claimed against this redeploy.

## Verdict

**PARTIAL PASS:**
- [x] Pre-fix stale curl captured.
- [x] Exact remediation command + timestamp captured.
- [x] Post-fix curl showing `age` < 3600 (specifically `age: 0`).
- [x] ETag changed, confirming fresh artefact.
- [ ] **Second probe ≥5 minutes later showing monotonically increasing age** — not captured (autopilot constraint: cannot reliably wait 5 min in foreground).
- [ ] **Content currency**: deployed HTML is 23-day-old build content, not current source. Awaits operator-driven fresh deploy.

## Recommended Next Action (operator)

If the goal is to also ship current content (not just flush the cache):
- Push `7f874b6` to `origin/main` and let Vercel auto-deploy. (Operator-described standard flow.)
- After deploy completes, re-probe `curl -sS https://www.sigilsec.ai/pricing | grep -ioE 'free trial'` — if zero, STORY-107 Branch A is verifiable; if non-zero, free-trial copy still lives in current main source somewhere we haven't found.

## Limitations

- Did NOT capture monotonic-age probe at +5min — autopilot cannot wait reliably in foreground.
- Did NOT push the unmerged commit (CHARTER scope: pushing requires explicit operator authorization for the push action specifically; "approved to unblock" was interpreted as covering the redeploy only).
- Did NOT execute `vercel deploy --prod --yes` — same reason (separate authorization warranted).
- Did NOT investigate why the 23-day-old build's source contained "30-day free trial" while current main source does not — could be a refactor between commits, an intentional copy change, or a CMS-injected build that has since been removed. Investigating requires `git log -S` walks against the deployed deployment's git SHA — possible but out of scope for the freshness fix.
