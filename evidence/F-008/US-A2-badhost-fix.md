# US-A2 — BadHost (CVE-2026-48710) fix in sigil-api

Date: 2026-06-10
Status: DONE (code + verification). Production deploy = owner-gated step below.

## What changed

- `api/requirements.txt`: `fastapi>=0.109.0` → `fastapi>=0.136.3`, added explicit floor `starlette>=1.0.1` with CVE comment (the spec now encodes the security floor, not just the lock).
- `api/requirements.lock`: `fastapi==0.128.8` → `fastapi==0.136.3` (0.128.8 caps starlette `<1.0.0`, so the FastAPI bump is required); `starlette==0.49.3` → `starlette==1.2.1` (≥ patched 1.0.1, released 2026-05-21).
- No other lock changes needed: fastapi 0.136.3 requires `starlette>=0.46.0` (no upper cap), `pydantic>=2.9.0` (locked 2.12.5 ✓), `typing-extensions>=4.8.0` (locked 4.15.0 ✓), `annotated-doc>=0.0.2` (already locked 0.0.4 ✓). Verified against PyPI metadata 2026-06-10.

## Verification (fresh python3.11 venv — matches production `python:3.11-slim-bookworm`)

```
$ grep starlette== api/requirements.lock
starlette==1.2.1

$ /opt/homebrew/bin/python3.11 -m venv /tmp/sigil-badhost-venv
$ /tmp/sigil-badhost-venv/bin/pip install -r api/requirements.lock
INSTALL EXIT: 0

$ /tmp/sigil-badhost-venv/bin/python -m pytest api/tests -q
223 passed, 340 skipped, 11 warnings in 6.32s
```

Baseline (pre-bump, system python3.9): `223 passed, 339 skipped`. The single extra skip is an environment artifact, not a regression: `test_database_performance.py:15` skips for missing `asyncpg`, which is not in `requirements.lock` (Postgres-era leftover; it was only importable locally by accident of the system environment — the production image, which installs only the lock, skips it identically). Skip-reason diff between stacks shows no other delta:

```
$ diff /tmp/skips_old.txt /tmp/skips_new.txt
3a4
> SKIPPED [1] api/tests/performance/test_database_performance.py:15: could not import 'asyncpg': No module named 'asyncpg'
```

## Middleware exposure audit (`request.url.path` under BadHost)

BadHost makes `request.url.path` (re-parsed from the Host header) diverge from the routed path in middleware. Findings:

| Site | Use | BadHost impact |
|---|---|---|
| `api/middleware/security.py:290` | Content-type enforcement when `request.url.path == "/v1/scans"` | Poisoned Host skips the JSON content-type check for a real `/v1/scans` request — validation bypass, low severity |
| `api/middleware/rate_limit_enhanced.py:212,227` | Health-probe skip set + per-endpoint rate-limit tier key | Attacker can shift the apparent path to land in a more lenient rate tier — rate-limit evasion, low/medium severity |
| `api/middleware/tier_check.py` | No path usage; Pro gating is a FastAPI dependency (`get_current_user_unified`) resolved on the routed path | Not affected |
| `api/main.py:262` | Logging only | Cosmetic (poisoned paths in logs) |

Conclusion: no path-based *auth* decision existed in middleware, so sigil-api was exposed to low-severity validation/rate-limit bypasses, not an auth bypass. The upgrade closes both. Follow-up hardening (optional, post-F-008): prefer `request.scope["path"]` in middleware path comparisons regardless of framework version.

## Owner-gated deploy step

Per `feedback_hotfix_from_deployed_sha`: build from the deployed SHA + this minimal patch (2 files), not from arbitrary HEAD. Commands (verified resource names per `.nomark/resources.json` / memory):

```
az acr build --registry sigilacr46iy6y --image sigil-api:latest --file Dockerfile.api .
az containerapp update --name sigil-api --resource-group sigil-rg --set-env-vars "DEPLOY_TIMESTAMP=$(date +%s)"
```

Post-deploy check: `curl -sS https://api.sigilsec.ai/health` 200; spot-check a rate-limited endpoint still 200/401 as expected.
