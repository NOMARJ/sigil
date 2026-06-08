# Security Review

Date: 2026-06-08

Reassessed: 2026-06-08 03:33 UTC

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

### MEDIUM: CSP allows legacy foreign domains

Live `www.sigilsec.ai` CSP still includes `https://*.cakewalk.ai`, `https://cw-ai-prod.s3.us-west-1.amazonaws.com`, and `https://api.cakewalk.ai`. Confirm whether those are still required before launch.

### MEDIUM: Build emits image/font warnings

Dashboard build succeeds but reports:

- Several `<img>` warnings where Next `<Image />` may be preferred.
- Custom font warning in `src/app/layout.tsx`.

## Cleared In Reassessment

### API suite passes

```bash
$ python3 -m pytest api/tests -q
223 passed, 339 skipped, 6 warnings in 13.72s
```

### Rust CLI tests pass

```bash
$ cargo test --manifest-path cli/Cargo.toml
test result: ok. 6 passed; 0 failed
```

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
