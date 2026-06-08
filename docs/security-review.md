# Security Review

Date: 2026-06-08

## Verdict

NOT READY

## Findings

### CRITICAL: Auth acquisition path is broken

`https://app.sigilsec.ai/signup` returns 404. Public CTAs on `www.sigilsec.ai` point users at signup paths, so new-account conversion is broken.

Owner-gated fix: add or redirect signup to the existing Auth0 login endpoint with signup intent.

### HIGH: Dependency audit still has high-severity Next.js advisory

After non-forced remediation:

```bash
$ npm audit --audit-level=high --omit=dev
2 vulnerabilities (1 moderate, 1 high)
```

Remaining remediation requires a breaking Next.js upgrade to `16.2.7` according to npm. Do not force this as a drive-by launch fix.

### HIGH: API test suite is failing across auth and database paths

Representative failure classes:

- Legacy auth tests still expect password login/register success after Auth0 migration.
- Async database fixture failures produce event-loop errors.
- Threat report submission fails SQL `uniqueidentifier` conversion.

These are protected auth/database areas under `CHARTER II.5`.

### MEDIUM: CSP allows legacy foreign domains

Live `www.sigilsec.ai` CSP still includes `https://*.cakewalk.ai`, `https://cw-ai-prod.s3.us-west-1.amazonaws.com`, and `https://api.cakewalk.ai`. Confirm whether those are still required before launch.

### MEDIUM: Build emits React hook and image/font warnings

Dashboard build succeeds but reports:

- `components/BulkInvestigator.tsx`: missing `estimateCredits` dependency.
- Several `<img>` warnings where Next `<Image />` may be preferred.
- Custom font warning in `src/app/layout.tsx`.

## Controls Verified

```bash
$ curl -sS -i https://api.sigilsec.ai/health
HTTP/2 200
... security headers present ...
{"status":"ok","version":"0.1.0","database_connected":true,"redis_connected":true}
```

```bash
$ curl -sS -i -X POST https://api.sigilsec.ai/v1/interactive/investigate -H 'Content-Type: application/json' -d '{}'
HTTP/2 401
{"detail":"Bad request: not authenticated"}
```

```bash
$ curl -sS -i https://auth.sigilsec.ai/.well-known/openid-configuration
HTTP/2 200
{"issuer":"https://auth.sigilsec.ai/", ...}
```
