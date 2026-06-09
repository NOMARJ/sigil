# Security Review

Date: 2026-06-08

Reassessed: 2026-06-09 01:05 UTC

## Verdict

NOT READY

## Findings

### CLEARED HIGH: Dependency audit no longer has high-severity findings

After the owner-approved Auth0 v4 and Next.js 16 migration:

```bash
$ npm audit --audit-level=high --omit=dev
exit 0
```

Verification also passed:

```bash
$ npm ci
$ npm run lint
$ npx tsc --noEmit
$ npm test -- --runInBand
$ npm run build
```

The dashboard now resolves `next@16.2.7`, `react@19.2.1`, `react-dom@19.2.1`, and `@auth0/nextjs-auth0@4.22.0`.

### MEDIUM: Dependency audit still reports PostCSS via Next.js

`npm audit` still reports 2 moderate PostCSS findings nested under Next.js 16.2.7. `npm audit fix --force` proposes an invalid downgrade to `next@9.3.3`; do not apply it.

### MEDIUM: CSP allows legacy foreign domains

Live `www.sigilsec.ai` CSP still includes `https://*.cakewalk.ai`, `https://cw-ai-prod.s3.us-west-1.amazonaws.com`, and `https://api.cakewalk.ai`. Confirm whether those are still required before launch.

### MEDIUM: Build emits image/font warnings

Dashboard build succeeds but reports:

- Several `<img>` warnings where Next `<Image />` may be preferred.
- Custom font warning in `src/app/layout.tsx`.

### MEDIUM: Governance telemetry is incomplete

`.nomark/metrics/trust/ledger.jsonl` is missing. The mandated cold-start command failed because `.nomark/schemas/mee-event.schema.json` is missing.

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

### Public signup path no longer 404s

```bash
$ curl -sS -I https://app.sigilsec.ai/signup
HTTP/2 200
```

Playwright lands on `https://app.sigilsec.ai/login` and renders the sign-in screen.

### Public pricing copy matches API-visible price state

```text
30-day free trial=False
14-day free trial=True
$199=False
$99=True
$29=True
```

### Public installer redirects to real installer

```bash
$ curl -sS -I https://www.sigilsec.ai/install.sh
HTTP/2 307
location: https://raw.githubusercontent.com/NOMARJ/sigil/main/install.sh
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
