# Launch Readiness Report

Date: 2026-06-08

Reassessed: 2026-06-09 01:05 UTC

## Launch Verdict

NOT READY

## Summary

Sigil is not production-launch-ready, but the prior public acquisition blockers are now cleared in live probes and the high-severity dashboard dependency audit blocker is now closed. The dashboard now builds on Next.js 16.2.7, React 19.2.1, and Auth0 SDK 4.22.0; component tests pass; the full API suite passes locally; the Rust CLI test suite passes locally; production API health is online; `/signup` no longer 404s; public pricing matches the billing API; and the public installer now redirects to the real GitHub installer. The remaining launch blockers are incomplete credentialed browser journey validation and owner-gated Stripe test/live round trips.

## Critical Blockers

No active critical blocker remains from the public-route probes in this reassessment.

## High Blockers

### CLEARED HIGH-001: Dashboard production dependency audit has no high findings

Evidence:

```bash
$ npm ls next react react-dom @auth0/nextjs-auth0 eslint eslint-config-next --depth=0
@auth0/nextjs-auth0@4.22.0
eslint-config-next@16.2.7
eslint@9.39.4
next@16.2.7
react-dom@19.2.1
react@19.2.1
```

```bash
$ npm audit --audit-level=high --omit=dev
exit 0
```

Verification:

```bash
$ npm ci
added 797 packages, and audited 798 packages

$ npm run lint
0 errors, 5 warnings

$ npx tsc --noEmit
exit 0

$ npm test -- --runInBand
4 passed, 43 tests passed

$ npm run build
Next.js 16.2.7 ... Compiled successfully ... 32/32 static pages
```

Status: closed after owner-approved Auth0 v3 to v4 migration. Residual dependency risk remains at moderate severity because Next.js 16.2.7 still bundles vulnerable PostCSS according to npm audit.

### HIGH-002: Browser and billing journeys are not fully verified

Evidence gathered this reassessment proves public unauthenticated paths, but does not complete credentialed login, checkout, webhook, portal cancel, or live payment/refund loops.

Status: owner/operator-gated.

## Cleared In Reassessment

### CLEARED-001: Public signup no longer 404s

```bash
$ curl -sS -I https://app.sigilsec.ai/signup
HTTP/2 200
```

Playwright browser probe:

```json
{
  "requested": "https://app.sigilsec.ai/signup",
  "status": 200,
  "finalUrl": "https://app.sigilsec.ai/login",
  "title": "Sigil — Security Audit Dashboard",
  "textSample": "Sign in to Sigil..."
}
```

### CLEARED-002: Public pricing now matches billing API

```bash
$ curl -sS -i https://api.sigilsec.ai/v1/billing/plans | sed -n '1,120p'
HTTP/2 200
...
{"tier":"team","name":"Team","price_monthly":99.0,...}
```

```json
{
  "requested": "https://www.sigilsec.ai/pricing",
  "status": 200,
  "has30DayTrial": false,
  "has14DayTrial": true,
  "hasStartFreeTrial": true,
  "hasTeam199": false,
  "hasTeam99": true
}
```

### CLEARED-003: Public installer no longer serves private-development copy

Without following redirects, Vercel returns a redirect:

```bash
$ curl -sS -I https://www.sigilsec.ai/install.sh
HTTP/2 307
location: https://raw.githubusercontent.com/NOMARJ/sigil/main/install.sh
```

With `-L`, the real installer is served:

```bash
$ curl -sSL https://www.sigilsec.ai/install.sh | sed -n '1,4p'
#!/usr/bin/env sh
# Sigil installer
```

## Fixed This Session

### FIXED-001: Local CLI wrapper version drift

Before:

```bash
$ ./bin/sigil --version
Sigil 1.0.5
```

After:

```bash
$ ./bin/sigil --version
Sigil 1.1.2
Automated Security Auditing for AI Agent Code
https://sigilsec.ai
```

Root package metadata now matches:

```json
{
  "package": "1.1.2",
  "lock": "1.1.2",
  "root": "1.1.2"
}
```

### FIXED-002: Non-forced dashboard audit fixes applied

`npm audit fix` removed the protobufjs and brace-expansion advisories without forcing the breaking Next.js upgrade.

Post-fix dashboard verification:

```bash
$ npm test -- --runInBand
Test Suites: 3 passed, 3 total
Tests:       41 passed, 41 total

$ npm run build
✓ Compiled successfully
✓ Generating static pages (32/32)
```

Reassessment evidence:

```bash
$ npm test -- --runInBand
Test Suites: 4 passed, 4 total
Tests:       43 passed, 43 total

$ npm run build
✓ Compiled successfully
✓ Generating static pages (33/33)

$ npm audit --audit-level=high --omit=dev
2 vulnerabilities (1 moderate, 1 high)

$ ./bin/sigil --version
Sigil 1.1.2
Automated Security Auditing for AI Agent Code
https://sigilsec.ai
```

### FIXED-003: Full API suite restored

The scanner, monitoring, metrics content-type, and scoring regressions from reassessment were fixed.

```bash
$ python3 -m pytest api/tests -q
223 passed, 339 skipped, 6 warnings in 2.43s
```

Targeted failure-slice verification:

```bash
$ python3 -m pytest api/tests/test_method_detection.py api/tests/test_novel_vectors.py api/tests/test_scoring.py api/tests/test_monitoring.py::TestMetrics::test_prometheus_metrics_endpoint api/tests/test_monitoring.py::TestMetrics::test_endpoint_categorization api/tests/test_monitoring.py::TestAlerts::test_email_channel -q
61 passed, 3 warnings in 1.24s
```

### FIXED-004: Rust CLI local verification restored

```bash
$ cargo test --manifest-path cli/Cargo.toml
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## Passing Checks

```bash
$ npm ci --ignore-scripts
up to date, audited 1 package in 219ms
found 0 vulnerabilities

$ npm view @nomarj/sigil version
1.1.2

$ curl -sS -i https://api.sigilsec.ai/health
HTTP/2 200
{"status":"ok","version":"0.1.0","database_connected":true,"redis_connected":true}

$ curl -sS -i -X POST https://api.sigilsec.ai/v1/interactive/investigate -H 'Content-Type: application/json' -d '{}'
HTTP/2 401
{"detail":"Bad request: not authenticated"}
```

## Governance Notes

- Trust score is `0`, autonomy level is `probation`.
- No autonomous subagent dispatch was used.
- Auth, authorization, database, and CI/CD configuration edits were not made.
- `.nomark/resources.json` was updated with verified public host entries before this report wrote those URLs.
- `.nomark/metrics/trust/ledger.jsonl` is missing; the mandated cold-start command failed because `.nomark/schemas/mee-event.schema.json` is missing.
