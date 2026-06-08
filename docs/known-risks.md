# Known Risks

Date: 2026-06-08

## Critical

1. Public signup route returns 404.
   - Evidence: `curl -I https://app.sigilsec.ai/signup` -> `HTTP/2 404`.
   - Approval: owner required because this touches auth flow.

2. Public pricing page is stale and contradicts billing API.
   - Evidence: browser probe shows 30-day trial and `$199` Team, while `/v1/billing/plans` returns Team `$99`.
   - Approval: operator/owner deployment required.

3. Public installer URL serves private-development script.
   - Evidence: `curl https://www.sigilsec.ai/install.sh` prints "public CLI beta is coming soon".
   - Approval: operator/owner deployment required.

4. API tests fail.
   - Evidence: `25 failed, 167 passed, 339 skipped, 31 errors`.
   - Approval: owner required for auth/database fixes.

## High

1. Dashboard dependency audit remains high due to Next.js advisories.
   - Evidence: `npm audit --audit-level=high --omit=dev` exits 1.
   - Approval: planned framework upgrade required.

2. Rust CLI cannot be verified locally.
   - Evidence: `no installed toolchains`.
   - Approval: environment setup or CI verification required.

## Medium

1. Live CSP still references legacy Cakewalk domains.
2. Dashboard build emits lint/performance warnings.
3. `brew info sigil` resolves to an unrelated ebook-editor cask unless the tap-qualified `nomarj/tap/sigil` formula is used.
