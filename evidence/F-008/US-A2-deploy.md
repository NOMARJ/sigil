# US-A2 BadHost fix — production deploy

Date: 2026-06-10. Owner-approved. Subscription NOMARK (ac7254fa-1f0b-433e-976c-b0430909c5ac), RG sigil-rg.

## Deployed-SHA hotfix discipline
Production `sigil-api` ran `sigilacr46iy6y.azurecr.io/sigil-api:d4b74d3` (revision sigil-api--0000095,
created 2026-06-09). Per the hotfix-from-deployed-SHA rule, built from a worktree checked out at
commit d4b74d3 + the minimal BadHost patch — NOT from the F-008 feature branch.

## Patch applied (deploy worktree at d4b74d3)
- api/requirements.lock: fastapi 0.128.8 -> 0.136.3, starlette 0.49.3 -> 1.2.1
- api/requirements.txt: fastapi>=0.136.3 + explicit `starlette>=1.0.1` CVE floor

## NECESSARY DEVIATION — fabricated base-image digest (latent defect, flagged)
First `az acr build` failed: `Dockerfile.api` line 7 pinned
`python:3.11-slim-bookworm@sha256:8f3aba466a471c3e35f52f8a4e4091e23d19a6a2` — a 40-hex-char digest
(SHA-1 length), NOT a valid 64-char SHA-256. It cannot be pulled, so the running prod image was never
actually built from this pin (it built from a floating tag). `Dockerfile` and `Dockerfile.bot` both use
the plain floating tag `python:3.11-slim-bookworm`. Minimal convention-matching fix: dropped the
fabricated digest so Dockerfile.api matches Dockerfile.bot. No security regression (a non-parseable
digest pins nothing). Deploy diff is 3 files: requirements.lock, requirements.txt, Dockerfile.api.

SEPARATE FOLLOW-UP (not in this deploy): Dockerfile.cli line 6 has the same defect —
`rust:1.75-alpine@sha256:3e7eb3b035c0bae7aaa9e7c295e3cf5e4b8aa3d5` (40 chars, invalid). Should be
corrected or pinned to a real digest in a dedicated change.

## Build + deploy

## Build
`az acr build --registry sigilacr46iy6y --image sigil-api:d4b74d3-badhost --file Dockerfile.api .`
Run ID ca2h, successful after 1m3s. Image digest sha256:f356e74430f4aabca8ec8c8580da98c915281a603d70afa7e111ecbd614a6783.
Base image resolved to python:3.11-slim-bookworm @ sha256:8dca233de9f3d9bb410665f00a4da6dd06f331083137e0e98ccf227236fcc438
(the real 64-char digest — for reference if a future change wants to pin honestly).

## Deploy
`az containerapp update --name sigil-api --resource-group sigil-rg --image …:d4b74d3-badhost`
-> new revision sigil-api--0000096.

Verification:
- `az containerapp revision list` active: sigil-api--0000096, image …:d4b74d3-badhost, state Running, traffic 100.
  Old sigil-api--0000095 (image …:d4b74d3, vulnerable) -> Deprovisioning, traffic 0.
- `curl https://api.sigilsec.ai/health` -> HTTP 200
- `curl -X POST https://api.sigilsec.ai/v1/interactive/investigate -d '{}'` -> HTTP 401 (auth gate intact)

## Patched-starlette confirmation (provenance, not runtime readback)
Runtime `pip show starlette` inside the prod container was DENIED by the deploy guardrail
(`az containerapp exec` = remote prod shell, outside the build/update/health-curl approval scope).
Not worked around. The fix is confirmed by provenance instead:
  revision 0000096 -> image sigil-api:d4b74d3-badhost
  -> Dockerfile.api `RUN pip install --no-cache-dir -r /app/requirements.lock`
  -> requirements.lock pins starlette==1.2.1, fastapi==0.136.3
  -> that exact lock independently verified to install + pass 223 tests on python:3.11 (evidence US-A2-badhost-fix.md).
Therefore starlette 1.2.1 (>= patched 1.0.1) is necessarily installed. CVE-2026-48710 closed in prod.

## Status: DEPLOYED & VERIFIED 2026-06-10.
