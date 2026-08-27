# Paid-Ads Launch Checklist

Date: 2026-08-27 · Source: commercial-readiness audit of this repo + the live
site/API. Items below are ordered: everything in "Before the first ad
impression" must be done before spending a dollar.

## Before the first ad impression

### In this repo — DONE (this PR)

- [x] Stripe price IDs: fabricated `price_1QQQ...` defaults removed from
      `api/config.py` and `api/routers/billing.py`. Paid checkout now fails
      loudly (503 + CRITICAL startup log) instead of sending fake IDs to
      Stripe. Env vars documented in `.env.example` and `docs/deployment.md`.
- [x] Privacy claims scoped to the truth (`docs/data-handling.md`, README,
      `docs/architecture.md`): "no code leaves your machine" is true only for
      the unauthenticated CLI; authenticated scans upload flagged source
      lines; Pro uploads relevant source files to an LLM provider.
- [x] First-scan false-positive framing: CLI MEDIUM/HIGH verdicts now explain
      that these patterns occur in legitimate code and point to
      `sigil explain` / `sigil approve` (`cli/src/output.rs`). Measured FP
      rates published in README ("Detection Accuracy").
- [x] Pricing page Subscribe button starts Stripe Checkout directly instead
      of linking to /settings, and discloses Pro data handling
      (`dashboard/src/app/pricing/page.tsx`).
- [x] Optional Sentry error tracking, enabled by `SIGIL_SENTRY_DSN`
      (`api/main.py`), with request bodies and local variables never sent.

### In production config — OPERATOR ACTION REQUIRED

- [ ] Create the live Stripe Products/Prices and set all four
      `SIGIL_STRIPE_PRICE_*` subscription env vars (plus the
      `SIGIL_STRIPE_PRICE_CREDITS_*` vars if credit packs are sold).
      **Verify against the startup log — missing IDs are reported at
      CRITICAL.**
- [ ] Run one real end-to-end checkout in Stripe test mode: subscribe,
      webhook fires, entitlement flips, portal cancel works. This is the
      open High item in `docs/known-risks.md` ("Paid billing journeys
      remain unverified").
- [ ] Set `SIGIL_SENTRY_DSN` (and add `sentry-sdk[fastapi]` to the deployed
      image — it is now in `api/requirements.txt`).
- [ ] Confirm GST treatment for AU sales (Stripe Tax or accountant sign-off).

### On the marketing site (separate repo — sigilsec.ai) — REQUIRED

The site is the ad destination; these lines are on it today and conflict
with `docs/data-handling.md` rule 1–3 or are unsourced:

- [ ] "Your code stays on your machine … No source code is transmitted" and
      "Fully offline — No code is ever uploaded": scope both to the
      open-source/unauthenticated tier; the same page sells Pro, which
      uploads source files for AI analysis.
- [ ] "290,851 Packages Scanned": the live registry reports 290,851 *scans*
      across 102,764 *packages* — relabel as scans.
- [ ] "30% of scans go interactive" and "Average 5 questions per session":
      no measurement backs these anywhere in the repo or live API — remove
      or replace with sourced numbers.
- [ ] "4,700+ Known Threats": repo data has `threat_count: 133`
      (`api/data/known_threats.json`); the live registry's threats_found is
      110,255. Reconcile to a sourced figure.
- [ ] schema.org `softwareVersion` says 1.0.5; latest release is v1.2.1 and
      `cli/Cargo.toml` is 1.3.0 — update after the next release.

## First week of spend

- [ ] Cut a v1.3.0 GitHub release so `install.sh` serves the current CLI
      (it installs the latest release tag, currently v1.2.1).
- [ ] Publish `@nomark/sigil-mcp-server` to npm (README and `llms.txt`
      currently carry "not yet published" caveats to keep instructions
      honest — remove them once live).
- [ ] FP-narrowing pass on the ≥ High rules (tracked as High item 0 in
      `docs/known-risks.md`).
- [ ] Uptime alerting on `api.sigilsec.ai/health` and the dashboard.

## Claims-safety rules for ad copy

Every quantitative claim in an ad or on the landing page must satisfy the
CLAUDE.md disclosure rules: sourced from a real measurement, with the data
source named. Safe, sourced claims as of this audit:

- "96.87% recall on a real malicious-package dataset" —
  `evaluation_results/honest_detection_eval.md` (cite the dataset and its
  selection-bias caveat in fine print).
- "50% fewer false positives with Pro AI adjudication (70% → 30% measured)"
  — `evidence/F-009/fp-adjudication-eval.md`.
- "290,851 scans across 102,764 packages" — live `/registry/stats`.
- "Scans in under 3 seconds" — reproduced locally (540 ms on the test repo).

Do not use: unverifiable guarantees ("blocks all malware"), the unsourced
usage stats above, or any figure whose source you cannot name in one line.
