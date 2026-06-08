# Launch Readiness Report

Date: 2026-06-08

Reassessed: 2026-06-08 03:33 UTC

## Launch Verdict

NOT READY

## Summary

Sigil is not production-launch-ready. The dashboard builds and its component tests pass, the full API suite now passes locally, the Rust CLI test suite passes locally, and the production API health check is online. The remaining launch blockers are public acquisition paths that are broken or stale, plus a high-severity Next.js dependency audit finding that requires a planned framework upgrade.

## Critical Blockers

### CRITICAL-001: Public signup CTA target returns 404

Evidence:

```bash
$ curl -sS -I https://app.sigilsec.ai/signup | sed -n '1,80p'
HTTP/2 404
cache-control: private, no-cache, no-store, max-age=0, must-revalidate
```

Existing Auth0 login path is alive:

```bash
$ curl -sS -I 'https://app.sigilsec.ai/api/auth/login?screen_hint=signup' | sed -n '1,100p'
HTTP/2 302
location: https://auth.sigilsec.ai/authorize?client_id=...
```

Status: owner-gated. Fix changes the auth entry flow.

### CRITICAL-002: Public pricing page is stale and contradicts billing API

Evidence:

```bash
$ curl -sS -i https://api.sigilsec.ai/v1/billing/plans | sed -n '1,120p'
HTTP/2 200
...
{"tier":"team","name":"Team","price_monthly":99.0,...}
```

Browser probe:

```json
{
  "url": "https://www.sigilsec.ai/pricing",
  "status": 200,
  "has30DayTrial": true,
  "hasStartFreeTrial": true,
  "hasTeam199": true,
  "hasTeam99": false
}
```

Screenshots:

- `evidence/launch-readiness/www-pricing-2026-06-08.png`
- `evidence/launch-readiness/www-pricing-mobile-2026-06-08.png`

Status: owner/operator-gated deployment or marketing surface repair.

### CRITICAL-003: Public installer URL serves private-development copy

Evidence:

```bash
$ curl -sS https://www.sigilsec.ai/install.sh | sed -n '1,80p'
echo "  Sigil is currently in private development."
echo "  The public CLI beta is coming soon."
```

GitHub `main` has the real installer:

```bash
$ curl -sS https://raw.githubusercontent.com/NOMARJ/sigil/main/install.sh | sed -n '1,20p'
#!/usr/bin/env sh
# Sigil installer
```

Status: owner/operator-gated deployment or web asset repair.

## High Blockers

### HIGH-001: Dashboard production dependency audit is not clean

Evidence after non-forced `npm audit fix`:

```bash
$ npm audit --audit-level=high --omit=dev
2 vulnerabilities (1 moderate, 1 high)
next ... Severity: high
postcss <8.5.10 Severity: moderate
fix available via `npm audit fix --force`
Will install next@16.2.7, which is a breaking change
```

Status: requires planned Next.js upgrade, not forced under probation.

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
Test Suites: 3 passed, 3 total
Tests:       41 passed, 41 total

$ npm run build
✓ Compiled successfully
✓ Generating static pages (32/32)

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
223 passed, 339 skipped, 6 warnings in 13.72s
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
