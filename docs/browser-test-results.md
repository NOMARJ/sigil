# Browser Test Results

Date: 2026-06-08

## Tooling

Vercel Agent Browser was requested but is not available in this harness. Playwright Chromium was installed and used as the substitute browser tool.

Install evidence:

```bash
$ npx playwright install chromium
Chrome for Testing 145.0.7632.6 ... downloaded
Chrome Headless Shell 145.0.7632.6 ... downloaded
```

## Persona Coverage

### First-time visitor

Route: `https://www.sigilsec.ai/pricing`

Result: FAIL

Evidence:

```json
{
  "status": 200,
  "has30DayTrial": true,
  "hasStartFreeTrial": true,
  "hasTeam199": true,
  "hasTeam99": false
}
```

Screenshot: `evidence/launch-readiness/www-pricing-2026-06-08.png`

### Mobile user

Route: `https://www.sigilsec.ai/pricing`

Result: FAIL

Evidence:

```json
{
  "status": 200,
  "has30DayTrial": true,
  "hasStartFreeTrial": true
}
```

Screenshot: `evidence/launch-readiness/www-pricing-mobile-2026-06-08.png`

### New account signup

Route: `https://app.sigilsec.ai/signup`

Result: FAIL

Evidence:

```bash
$ curl -sS -I https://app.sigilsec.ai/signup
HTTP/2 404
```

Existing Auth0 login route:

```bash
$ curl -sS -I 'https://app.sigilsec.ai/api/auth/login?screen_hint=signup'
HTTP/2 302
location: https://auth.sigilsec.ai/authorize?client_id=...
```

### Returning user

Route: `https://app.sigilsec.ai/login`

Result: PARTIAL

Evidence:

```bash
$ curl -sS -I https://app.sigilsec.ai/login
HTTP/2 200
```

Full credentialed login was not completed in this session.

### Malicious / invalid input user

Route: `https://api.sigilsec.ai/v1/interactive/investigate`

Result: PASS for unauthenticated protection baseline.

Evidence:

```bash
$ curl -sS -i -X POST https://api.sigilsec.ai/v1/interactive/investigate -H 'Content-Type: application/json' -d '{}'
HTTP/2 401
{"detail":"Bad request: not authenticated"}
```

## Console Findings

Pricing page produced one observed console log:

```text
[Session Recording] Waiting for cookie consent
```

No page errors were captured in the Playwright pricing-page probes.
