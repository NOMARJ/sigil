# Launch Readiness Report

Date: 2026-06-08

## Launch Verdict

NOT READY

## Summary

Sigil is not production-launch-ready. The dashboard builds and its component tests pass, and the production API health check is online. However, live public acquisition paths are broken or stale, the API test suite is failing, dashboard dependencies still have high-severity Next.js advisories, and the Rust CLI cannot be verified locally because no Rust toolchain is configured.

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

### CRITICAL-004: Full API test suite fails

Evidence:

```bash
$ python3 -m pytest api/tests -q
25 failed, 167 passed, 339 skipped, 6 warnings, 31 errors in 15.10s
```

Representative failures:

- `RuntimeError: ... got Future ... attached to a different loop` in `api/database.py`
- Legacy auth tests expect 200 but endpoints now return 410 after Auth0 migration
- `/v1/report` tests return 500 from SQL `uniqueidentifier` conversion

Status: protected. Fixes touch auth and database behavior.

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

### HIGH-002: Rust CLI cannot be verified locally

Evidence:

```bash
$ cargo --version
error: rustup could not choose a version of cargo to run, because one wasn't specified explicitly, and no default is configured.

$ rustup toolchain list && rustup default
no installed toolchains
error: no default toolchain is configured
```

Status: environment/toolchain blocker.

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
